// Handler for intercepted IKeystoreService transactions (Android 10/11).
//
// Full simulation via the reference TA: a target app's key never touches the real
// keymaster. generateKey always mints in the TA (teesim_km_generate_key) so the
// callback KeyCharacteristics are the TA's software/tee lists, not a replay of
// the request. A11 GMS generateKey has no challenge; attestKey re-issues the
// chain on that blob. The daemon-supplied AttestationApplicationId is attached
// when the caller's own blob was dropped by this hook. The TA blob backs
// begin/update/finish/abort. Non-target callers are forwarded.
//
// The service methods deliver their results by transacting back on a callback
// binder passed in the request; the transaction's own reply is just a status.

#include <binder/Binder.h>
#include <binder/IBinder.h>
#include <binder/IPCThreadState.h>
#include <binder/Parcel.h>

#include <openssl/bytestring.h>
#include <openssl/mem.h>
#include <openssl/x509.h>

#include <algorithm>
#include <ctime>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <vector>

#include "control.h"
// The subsystem every line from this file is stamped with; see injector/include/logging.hpp.
#define LOG_SUB "ks1"
#include "logging.hpp"
#include "km_names.h"
#include "teesim_km.h"

using namespace android;

// IKeystoreService transaction codes. The interface is otherwise identical across
// Android 10 and 11, but R dropped reset() (ordinal 7 on Q) from the AIDL, so every
// later method — all the ones we intercept — shifts down by one. Picking the wrong
// table silently hijacks the neighbouring method: on an R device the Q codes make us
// answer getKeyCharacteristics as if it were generateKey while the real generateKey
// (one ordinal lower) runs untouched in keystore. Selected from the API level below.
struct TxCodes {
  // del/exist sit before reset() in the AIDL, so their ordinals do not shift on R.
  uint32_t del, exist, generateKey, getKeyCharacteristics, exportKey, attestKey, begin, update,
      finish, abort;
};
constexpr TxCodes kTxQ = {4, 5, 18, 19, 21, 29, 22, 23, 24, 25};  // Android 10 (API 29)
constexpr TxCodes kTxR = {4, 5, 17, 18, 20, 28, 21, 22, 23, 24};  // Android 11 (API 30)

// True on Android 11+. Besides the ordinal shift, R inserted a `byte[] input` before
// `signature` in finish(), so the two releases also parse that request differently.
bool IsAndroidR() {
  static const bool is_r = teesim_android_api() >= 30;
  return is_r;
}

const TxCodes& Codes() {
  static const TxCodes& codes = IsAndroidR() ? kTxR : kTxQ;
  return codes;
}

// The IKeystoreService method a transaction code names on this release, for the log.
const char* TxName(uint32_t code) {
  const TxCodes& tx = Codes();
  if (code == tx.del) return "del";
  if (code == tx.exist) return "exist";
  if (code == tx.generateKey) return "generateKey";
  if (code == tx.getKeyCharacteristics) return "getKeyCharacteristics";
  if (code == tx.exportKey) return "exportKey";
  if (code == tx.attestKey) return "attestKey";
  if (code == tx.begin) return "begin";
  if (code == tx.update) return "update";
  if (code == tx.finish) return "finish";
  if (code == tx.abort) return "abort";
  return "?";
}

// KeyPurpose by name (keymaster and KeyMint share the numbering).
const char* PurposeName(int32_t purpose) {
  switch (purpose) {
    case 0: return "ENCRYPT";
    case 1: return "DECRYPT";
    case 2: return "SIGN";
    case 3: return "VERIFY";
    case 5: return "WRAP_KEY";
    case 6: return "AGREE_KEY";
    case 7: return "ATTEST_KEY";
    default: return "?";
  }
}

// KeyMint/Keymaster tag values (shared) and enum constants we need.
enum {
  TAG_PURPOSE = 0x20000001,
  TAG_ALGORITHM = 0x10000002,
  TAG_KEY_SIZE = 0x30000003,
  TAG_DIGEST = 0x20000005,
  TAG_EC_CURVE = 0x1000000a,
  TAG_CREATION_DATETIME = 0x600002bd,            // 0x60000000 | 701
  TAG_ATTESTATION_CHALLENGE = 0x900002c4,        // 0x90000000 | 708
  TAG_ATTESTATION_APPLICATION_ID = 0x900002c5,   // 0x90000000 | 709
  TAG_ORIGIN = 0x100002be,                       // KM_ENUM | 702
  ALGORITHM_RSA = 1,
  ALGORITHM_EC = 3,
  ALGORITHM_AES = 32,
  ALGORITHM_TRIPLE_DES = 33,
  ALGORITHM_HMAC = 128,
  KS_NO_ERROR = 1,
  KS_SYSTEM_ERROR = 4,
  KS_UID_SELF = -1,
  KM_SEC_SOFTWARE = 0,
  KM_SEC_KEYSTORE = 100,  // KeyMint SecurityLevel::Keystore; Keystore1 reports these as software
};

// The algorithm a log line names, so a forwarded key says what it was rather than a bare number.
const char* AlgorithmName(int64_t algorithm) {
  switch (algorithm) {
    case ALGORITHM_RSA: return "RSA";
    case ALGORITHM_EC: return "EC";
    case ALGORITHM_AES: return "AES";
    case ALGORITHM_TRIPLE_DES: return "3DES";
    case ALGORITHM_HMAC: return "HMAC";
    default: return "unknown-algorithm";
  }
}

namespace {

const String16 kServiceDescriptor("android.security.keystore.IKeystoreService");

// A simulated key, keyed by (uid, alias).
struct PendingKey {
  std::vector<uint8_t> spki;    // public key, SubjectPublicKeyInfo DER
  std::vector<uint8_t> ta_blob; // key imported into the TA, for signing operations
  std::vector<std::vector<uint8_t>> certs;  // attestation chain from the single mint
  std::vector<KmParam> params;  // key parameters from generateKey
  // Owns the bytes of every byte-array (BYTES/BIGNUM) parameter, in the order those parameters
  // appear in `params`. A KmParam only holds a raw `blob` pointer, so this storage must outlive the
  // key and the pointers must be rebound into it after any copy or move (RebindParamBlobs) — otherwise
  // they dangle into the caller's transient read buffer or into the source object.
  std::vector<std::vector<uint8_t>> param_blobs;
  // TA-minted KeyCharacteristics. sw = SOFTWARE, hw = TEE/STRONGBOX. Empty until the first mint.
  std::vector<KmParam> sw_chars;
  std::vector<KmParam> hw_chars;
  std::vector<std::vector<uint8_t>> char_blobs;

  // Point each byte-array parameter's `blob` at this object's own `param_blobs`. `params` and
  // `param_blobs` were built in lockstep, so the k-th byte-array parameter uses param_blobs[k].
  void RebindParamBlobs() {
    size_t k = 0;
    for (auto& kp : params) {
      if (teesim_km_tag_value_kind(kp.tag) != KM_VALUE_BYTES) continue;  // not a BIGNUM/BYTES param
      if (k >= param_blobs.size()) {
        kp.blob = nullptr;
        kp.blob_len = 0;
        continue;
      }
      kp.blob = param_blobs[k].data();
      kp.blob_len = param_blobs[k].size();
      ++k;
    }
  }
};

// A TA is reference-counted so an in-flight operation keeps its profile's TA
// alive even if a config reload swaps or drops that profile underneath it.
using TaPtr = std::shared_ptr<Ta>;
TaPtr WrapTa(Ta* ta) {
  return TaPtr(ta, [](Ta* t) {
    if (t) teesim_km_destroy(t);
  });
}

// A configured profile: its TA, the target uids, and each uid's package name (for the log) plus
// the daemon-supplied AttestationApplicationId DER, which keystore1 cannot rebuild downstream of
// this hook.
struct Profile {
  std::string id;
  TaPtr ta;
  std::map<int, std::string> uids;           // uid -> package name
  std::map<int, std::vector<uint8_t>> app_ids;  // uid -> official ApplicationId DER
};

// Live routing, swapped atomically by teesim_cfg_commit under g_cfg_mutex.
std::mutex g_cfg_mutex;
std::vector<Profile> g_profiles;
TaPtr g_default_ta;  // serves ops on our blobs; any profile's TA decrypts them

// Staging state built up by teesim_cfg_begin/add_profile before the swap.
std::vector<Profile> g_staging;
std::vector<uint8_t> g_stage_vb_key;
std::vector<uint8_t> g_stage_vb_hash;
bool g_stage_locked = true;
int32_t g_stage_vb_state = 0;
int32_t g_stage_attest_version_tee = 400;
int32_t g_stage_attest_version_strongbox = 400;

std::mutex g_keys_mutex;
std::map<std::string, PendingKey> g_keys;

// An in-flight crypto operation. The token returned to the caller identifies the
// TA operation handle and the TA it runs on, for follow-up update/finish/abort.
class OpToken : public BBinder {};
struct Operation {
  sp<IBinder> token;  // keeps the token binder alive while the operation runs
  int64_t op_handle;
  TaPtr ta;
};
std::mutex g_ops_mutex;
std::map<IBinder*, Operation> g_ops;

// The profile TA serving this uid, or null if the uid is not a target.
TaPtr ProfileForUid(int uid) {
  std::lock_guard<std::mutex> lk(g_cfg_mutex);
  for (const auto& prof : g_profiles) {
    if (prof.uids.count(uid)) return prof.ta;
  }
  return nullptr;
}

// The TA used for operations on an existing blob of ours.
TaPtr DefaultTa() {
  std::lock_guard<std::mutex> lk(g_cfg_mutex);
  return g_default_ta;
}

bool IsTarget(int uid) { return ProfileForUid(uid) != nullptr; }

std::string PackageForUid(int uid) {
  std::lock_guard<std::mutex> lk(g_cfg_mutex);
  for (const auto& prof : g_profiles) {
    auto it = prof.uids.find(uid);
    if (it != prof.uids.end()) return it->second;
  }
  return std::string();
}

std::vector<uint8_t> AppIdForUid(int uid) {
  std::lock_guard<std::mutex> lk(g_cfg_mutex);
  for (const auto& prof : g_profiles) {
    auto it = prof.app_ids.find(uid);
    if (it != prof.app_ids.end() && !it->second.empty()) return it->second;
  }
  return {};
}

// AOSP keystore_attestation_id.cpp: Package Manager failure uses this placeholder.
std::vector<uint8_t> BuildUnknownPackageApplicationId() {
  static const char kUnknown[] = "UnknownPackage";
  bssl::ScopedCBB cbb;
  CBB seq, pkg_set, pkg_seq, name, version, sig_set;
  CBB_init(cbb.get(), 64);
  CBB_add_asn1(cbb.get(), &seq, CBS_ASN1_SEQUENCE);
  CBB_add_asn1(&seq, &pkg_set, CBS_ASN1_SET);
  CBB_add_asn1(&pkg_set, &pkg_seq, CBS_ASN1_SEQUENCE);
  CBB_add_asn1(&pkg_seq, &name, CBS_ASN1_OCTETSTRING);
  CBB_add_bytes(&name, reinterpret_cast<const uint8_t*>(kUnknown), sizeof(kUnknown) - 1);
  CBB_add_asn1(&pkg_seq, &version, CBS_ASN1_INTEGER);
  CBB_add_u8(&version, 1);
  CBB_add_asn1(&seq, &sig_set, CBS_ASN1_SET);
  uint8_t* out = nullptr;
  size_t len = 0;
  std::vector<uint8_t> v;
  if (CBB_finish(cbb.get(), &out, &len)) {
    v.assign(out, out + len);
    OPENSSL_free(out);
  }
  return v;
}

// Keystore prefixes each stored entry (USRPKEY_/USRCERT_/CACERT_/...); strip it so
// every operation on a key maps to the same identity.
std::string ExtractAlias(const String16& alias16) {
  std::string a = String8(alias16).c_str();
  for (const char* pfx : {"USRPKEY_", "USRCERT_", "CACERT_", "USRSKEY_"}) {
    size_t n = strlen(pfx);
    if (a.compare(0, n, pfx) == 0) return a.substr(n);
  }
  return a;
}

std::string KeyId(int uid, const String16& alias) {
  return std::to_string(uid) + ":" + ExtractAlias(alias);
}

// The strict-mode/work-source header written before the interface descriptor
// varies; enforceInterface consumes it. We read our own copy so the forwarded
// parcel keeps its position.
struct Reader {
  Parcel p;
  explicit Reader(const Parcel& src) {
    p.appendFrom(&src, 0, src.dataSize());
    p.setDataPosition(0);
  }
};

std::vector<uint8_t> ReadByteArray(Parcel& p) {
  int32_t len = p.readInt32();
  std::vector<uint8_t> v;
  if (len > 0) {
    v.resize(len);
    p.read(v.data(), len);
  }
  return v;
}

// Read a KeymasterArguments blob into KmParam values. Layout: int32 count, then
// per entry int32 tag followed by a value whose width is set by the tag's type.
std::vector<KmParam> ReadKeymasterArguments(Parcel& p,
                                            std::vector<std::vector<uint8_t>>& blob_store) {
  std::vector<KmParam> out;
  int32_t count = p.readInt32();
  // `count` is attacker-controlled and independent of the parcel size; clamp it so a bogus value can
  // neither drive a huge loop nor (below) a huge reservation. Real keymaster arg lists are tiny.
  if (count < 0 || count > 4096) count = 0;
  for (int32_t i = 0; i < count; ++i) {
    if (p.readInt32() == 0) continue;  // typed-list element presence marker
    KmParam kp{};
    kp.tag = static_cast<uint32_t>(p.readInt32());
    switch (teesim_km_tag_value_kind(kp.tag)) {
      case KM_VALUE_INT32:   // ENUM/ENUM_REP
      case KM_VALUE_UINT32:  // UINT/UINT_REP, USER_AUTH_TYPE
        kp.int_value = p.readInt32();
        break;
      case KM_VALUE_INT64:   // DATE
      case KM_VALUE_UINT64:  // ULONG/ULONG_REP
        kp.int_value = p.readInt64();
        break;
      case KM_VALUE_BOOL:
        kp.int_value = 1;
        break;
      case KM_VALUE_BYTES:  // BIGNUM/BYTES
        blob_store.push_back(ReadByteArray(p));
        kp.blob = blob_store.back().data();
        kp.blob_len = blob_store.back().size();
        break;
      default:
        break;
    }
    out.push_back(kp);
  }
  return out;
}

int64_t ParamInt(const std::vector<KmParam>& params, uint32_t tag, int64_t dflt) {
  for (const auto& p : params)
    if (p.tag == tag) return p.int_value;
  return dflt;
}

// writeTypedObject(obj != null): a leading 1 then the object's body.
void BeginTypedObject(Parcel& p) { p.writeInt32(1); }

// KeystoreResponse: (int errorCode, String errorMessage).
void WriteKeystoreResponse(Parcel& p, int32_t code) {
  BeginTypedObject(p);
  p.writeInt32(code);
  p.writeString16(nullptr, 0);  // null errorMessage
}

// KeymasterArguments carrying the given parameters (reverse of the reader).
void WriteKeymasterArguments(Parcel& p, const std::vector<KmParam>& params) {
  p.writeInt32(static_cast<int32_t>(params.size()));
  for (const auto& kp : params) {
    p.writeInt32(1);  // typed-list element presence marker
    p.writeInt32(static_cast<int32_t>(kp.tag));
    switch (teesim_km_tag_value_kind(kp.tag)) {
      case KM_VALUE_INT32:
      case KM_VALUE_UINT32:
        p.writeInt32(static_cast<int32_t>(kp.int_value));
        break;
      case KM_VALUE_INT64:
      case KM_VALUE_UINT64:
        p.writeInt64(kp.int_value);
        break;
      case KM_VALUE_BOOL:
        break;  // bool: presence only
      case KM_VALUE_BYTES:
        p.writeByteArray(kp.blob_len, kp.blob);
        break;
      default:
        break;
    }
  }
}

// Send a result back on the callback binder. onFinished is transaction code 1.
void InvokeCallback(const sp<IBinder>& cb, const String16& cb_descriptor,
                    const std::function<void(Parcel&)>& write_body) {
  if (!cb) return;
  Parcel data, reply;
  data.writeInterfaceToken(cb_descriptor);
  write_body(data);
  cb->transact(1 /*onFinished*/, data, &reply);
}

void ReplyStatus(Parcel* reply, int32_t status) {
  if (!reply) return;
  reply->writeNoException();
  reply->writeInt32(status);
}

bool HasTag(const std::vector<KmParam>& params, uint32_t tag) {
  for (const auto& p : params)
    if (p.tag == tag) return true;
  return false;
}

// Tags Keystore1 would have bound, plus the ApplicationId the daemon gathered.
// X.509 notBefore/notAfter are KeyMint-only tags; teesim-km fills them from
// IKeymasterDevice.hal attestKey validity rules.
void AddRequiredTags(std::vector<KmParam>& params, int uid,
                     std::vector<uint8_t>& app_id_store, bool with_attestation) {
  int64_t now_ms = static_cast<int64_t>(time(nullptr)) * 1000;
  if (!HasTag(params, TAG_CREATION_DATETIME))
    params.push_back({TAG_CREATION_DATETIME, now_ms, nullptr, 0});
  if (ParamInt(params, TAG_ALGORITHM, ALGORITHM_EC) == ALGORITHM_EC &&
      !HasTag(params, TAG_EC_CURVE)) {
    int64_t sz = ParamInt(params, TAG_KEY_SIZE, 256);
    params.push_back({TAG_EC_CURVE, sz == 384 ? 2 : sz == 521 ? 3 : sz == 224 ? 0 : 1, nullptr, 0});
  }
  if (with_attestation && !HasTag(params, TAG_ATTESTATION_APPLICATION_ID)) {
    app_id_store = AppIdForUid(uid);
    if (app_id_store.empty()) app_id_store = BuildUnknownPackageApplicationId();
    params.push_back({TAG_ATTESTATION_APPLICATION_ID, 0, app_id_store.data(), app_id_store.size()});
  }
}

// Mint the key in the TA (teesim_km_generate_key). `extra` carries attestation
// tags the caller supplies (the challenge). Returns a result the caller must free, or null.
TsCreationResult* ImportKey(const PendingKey& k, int uid, const std::vector<KmParam>& extra,
                            bool with_attestation) {
  TaPtr ta = ProfileForUid(uid);
  if (!ta) ta = DefaultTa();
  if (!ta) return nullptr;
  std::vector<KmParam> params = k.params;
  params.insert(params.end(), extra.begin(), extra.end());
  std::vector<uint8_t> app_id;
  AddRequiredTags(params, uid, app_id, with_attestation);
  // TAG_ORIGIN is reported in KeyCharacteristics; the TA rejects it as an input (-40).
  params.erase(std::remove_if(params.begin(), params.end(),
                              [](const KmParam& p) { return p.tag == TAG_ORIGIN; }),
               params.end());
  TsCreationResult* res = nullptr;
  int32_t rc = teesim_km_generate_key(ta.get(), params.data(), params.size(), nullptr, 0, nullptr, 0,
                                      nullptr, 0, &res);
  if (rc != 0 || !res) {
    LOGE("ImportKey: TA generate_key failed rc=%d(%s)", rc, teesim_km_err_name(rc));
    return nullptr;
  }
  return res;
}

bool ExtractSpkiFromCert(const uint8_t* der, size_t len, std::vector<uint8_t>& out) {
  const uint8_t* p = der;
  bssl::UniquePtr<X509> cert(d2i_X509(nullptr, &p, static_cast<long>(len)));
  if (!cert) return false;
  uint8_t* spki = nullptr;
  int n = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert.get()), &spki);
  if (n <= 0 || !spki) return false;
  out.assign(spki, spki + n);
  OPENSSL_free(spki);
  return true;
}

void StoreCharsFromResult(PendingKey& k, TsCreationResult* res) {
  k.sw_chars.clear();
  k.hw_chars.clear();
  k.char_blobs.clear();
  size_t n = teesim_km_result_num_chars(res);
  for (size_t ci = 0; ci < n; ++ci) {
    int32_t level = 0;
    size_t np = teesim_km_result_char(res, ci, &level);
    // A11 KeyCharacteristics only has software/tee. Keystore-enforced tags (creation
    // datetime, etc.) are what the Java API shows in softwareEnforced.
    auto& dest = (level == KM_SEC_SOFTWARE || level == KM_SEC_KEYSTORE) ? k.sw_chars : k.hw_chars;
    for (size_t pi = 0; pi < np; ++pi) {
      KmParam km{};
      teesim_km_result_char_param(res, ci, pi, &km);
      if (teesim_km_tag_value_kind(km.tag) == KM_VALUE_BYTES && km.blob && km.blob_len) {
        k.char_blobs.emplace_back(km.blob, km.blob + km.blob_len);
        km.blob = k.char_blobs.back().data();
        km.blob_len = k.char_blobs.back().size();
      }
      dest.push_back(km);
    }
  }
}

void WriteKeyCharacteristics(Parcel& p, const std::vector<KmParam>& sw,
                             const std::vector<KmParam>& hw) {
  BeginTypedObject(p);
  WriteKeymasterArguments(p, sw);
  WriteKeymasterArguments(p, hw);
}

// Take the certificate chain the TA returned. The leaf carries the public key the caller
// fetches with exportKey, so a leaf that does not parse leaves nothing to serve.
bool StoreChain(PendingKey& k, TsCreationResult* res) {
  k.certs.clear();
  size_t n = teesim_km_result_num_certs(res);
  for (size_t i = 0; i < n; ++i) {
    const uint8_t* c = nullptr;
    size_t cl = 0;
    teesim_km_result_cert(res, i, &c, &cl);
    k.certs.emplace_back(c, c + cl);
  }
  if (k.certs.empty()) {
    LOGE("StoreChain: FAILED, the TA returned no certificate for the key");
    return false;
  }
  if (!ExtractSpkiFromCert(k.certs[0].data(), k.certs[0].size(), k.spki)) {
    LOGE("StoreChain: FAILED, the leaf certificate does not parse; there is no public key to "
         "export");
    k.certs.clear();
    return false;
  }
  return true;
}

bool StoreCreation(PendingKey& k, TsCreationResult* res) {
  const uint8_t* ptr = nullptr;
  size_t len = 0;
  teesim_km_result_key_blob(res, &ptr, &len);
  k.ta_blob.assign(ptr, ptr + len);
  StoreCharsFromResult(k, res);
  return StoreChain(k, res);
}

// One TA generate_key per alias. A second generate_key would change the public
// key and break KeyPair vs leaf. Export may mint without attestation; attestKey
// then re-issues the chain on the same blob.
bool MintOnce(PendingKey& k, int uid, const std::vector<KmParam>& extra, bool with_attestation) {
  if (!k.ta_blob.empty()) return true;
  TsCreationResult* res = ImportKey(k, uid, extra, with_attestation);
  if (!res) return false;
  bool stored = StoreCreation(k, res);
  teesim_km_free_result(res);
  if (!stored) k.ta_blob.clear();  // nothing was served; a later call mints again
  return stored;
}

// Keystore1 attestKey: same key, new attestation record (challenge / ApplicationId).
bool AttestExisting(PendingKey& k, int uid, const std::vector<KmParam>& extra) {
  TaPtr ta = ProfileForUid(uid);
  if (!ta) ta = DefaultTa();
  if (!ta || k.ta_blob.empty()) return false;
  std::vector<KmParam> params = k.params;
  params.insert(params.end(), extra.begin(), extra.end());
  std::vector<uint8_t> app_id;
  AddRequiredTags(params, uid, app_id, true);
  params.erase(std::remove_if(params.begin(), params.end(),
                              [](const KmParam& p) { return p.tag == TAG_ORIGIN; }),
               params.end());
  TsCreationResult* res = nullptr;
  int32_t rc = teesim_km_attest_key(ta.get(), k.ta_blob.data(), k.ta_blob.size(), params.data(),
                                    params.size(), nullptr, 0, nullptr, 0, nullptr, 0, &res);
  if (rc != 0 || !res) {
    LOGE("AttestExisting: TA attest_key failed rc=%d(%s)", rc, teesim_km_err_name(rc));
    return false;
  }
  bool ok = StoreChain(k, res);
  teesim_km_free_result(res);
  return ok;
}

// Make sure the key exists in the TA so export / begin can run. Do not invent a
// challenge here — that would freeze a dummy value into the leaf.
bool EnsureTaKey(PendingKey& k, int uid) {
  if (!k.ta_blob.empty()) return true;
  return MintOnce(k, uid, {}, HasTag(k.params, TAG_ATTESTATION_CHALLENGE));
}

// OperationResult { int resultCode, IBinder token, long operationHandle, int
// inputConsumed, byte[] output, KeymasterArguments outParams }, as the non-null
// callback argument. Note the output array precedes outParams in this version.
// AES/GCM encrypt begin returns KM_TAG_NONCE in outParams; AndroidKeyStore
// Cipher.getIV() is that nonce. Empty outParams leaves getIV() null.
void WriteOperationResult(Parcel& p, int32_t code, const sp<IBinder>& token, int64_t op_handle,
                          int32_t input_consumed, const std::vector<uint8_t>& output,
                          const std::vector<KmParam>& out_params) {
  BeginTypedObject(p);
  p.writeInt32(code);
  p.writeStrongBinder(token);
  p.writeInt64(op_handle);
  p.writeInt32(input_consumed);
  p.writeByteArray(output.size(), output.data());
  WriteKeymasterArguments(p, out_params);
}

// --- Per-method handlers ----------------------------------------------------

bool HandleGenerateKey(int uid, Parcel& in, Parcel* reply) {
  sp<IBinder> cb = in.readStrongBinder();
  String16 alias = in.readString16();
  std::vector<std::vector<uint8_t>> blobs;
  std::vector<KmParam> params;
  if (in.readInt32() == 1) params = ReadKeymasterArguments(in, blobs);
  LOGI("generateKey: alias=%s params=%s", String8(alias).c_str(),
       KmDescribeParams(params.data(), params.size()).c_str());

  // Only asymmetric keys are worth simulating: they carry the attestation, and they are the only
  // kind this path can produce. A symmetric key (AES/3DES/HMAC) is never attested and lives entirely
  // in the real keymaster; claiming one here would report success while recording no key the real
  // keystore can see, so the app's first Cipher.init fails with KEY_NOT_FOUND (#291).
  const int64_t algorithm = ParamInt(params, TAG_ALGORITHM, 0);
  if (algorithm != ALGORITHM_RSA && algorithm != ALGORITHM_EC) {
    LOGI("generateKey: alias=%s is a %s key, not asymmetric; forwarding to the real keystore",
         String8(alias).c_str(), AlgorithmName(algorithm));
    return false;
  }

  PendingKey key;
  key.params = std::move(params);
  key.param_blobs = std::move(blobs);  // take ownership so the params' blob pointers stay valid
  key.RebindParamBlobs();              // and repoint them into our own storage, not the read buffer
  std::vector<KmParam> sw, hw;
  {
    std::lock_guard<std::mutex> lk(g_keys_mutex);
    auto& stored = g_keys[KeyId(uid, alias)] = std::move(key);
    if (!MintOnce(stored, uid, {}, HasTag(stored.params, TAG_ATTESTATION_CHALLENGE))) {
      LOGE("generateKey: FAILED, the TA declined to mint alias=%s", String8(alias).c_str());
      g_keys.erase(KeyId(uid, alias));
      return false;
    }
    if (!stored.hw_chars.empty() || !stored.sw_chars.empty()) {
      sw = stored.sw_chars;
      hw = stored.hw_chars;
    } else {
      hw = stored.params;
    }
  }
  LOGI("generateKey: simulated alias=%s sw=%zu hw=%zu", String8(alias).c_str(), sw.size(),
       hw.size());

  static const String16 kCb("android.security.keystore.IKeystoreKeyCharacteristicsCallback");
  InvokeCallback(cb, kCb, [&](Parcel& p) {
    WriteKeystoreResponse(p, KS_NO_ERROR);
    WriteKeyCharacteristics(p, sw, hw);
  });
  ReplyStatus(reply, KS_NO_ERROR);
  return true;
}

bool HandleGetKeyCharacteristics(int uid, Parcel& in, Parcel* reply) {
  sp<IBinder> cb = in.readStrongBinder();
  String16 alias = in.readString16();
  std::vector<KmParam> sw, hw;
  {
    std::lock_guard<std::mutex> lk(g_keys_mutex);
    auto it = g_keys.find(KeyId(uid, alias));
    if (it == g_keys.end()) {
      LOGD("getKeyCharacteristics: alias not one of ours; forwarding to the real keystore");
      return false;
    }
    if (!it->second.hw_chars.empty() || !it->second.sw_chars.empty()) {
      sw = it->second.sw_chars;
      hw = it->second.hw_chars;
    } else {
      hw = it->second.params;
    }
  }
  static const String16 kCb("android.security.keystore.IKeystoreKeyCharacteristicsCallback");
  InvokeCallback(cb, kCb, [&](Parcel& p) {
    WriteKeystoreResponse(p, KS_NO_ERROR);
    WriteKeyCharacteristics(p, sw, hw);
  });
  ReplyStatus(reply, KS_NO_ERROR);
  return true;
}

bool HandleExportKey(int uid, Parcel& in, Parcel* reply) {
  sp<IBinder> cb = in.readStrongBinder();
  String16 alias = in.readString16();

  std::vector<uint8_t> spki;
  {
    std::lock_guard<std::mutex> lk(g_keys_mutex);
    auto it = g_keys.find(KeyId(uid, alias));
    if (it == g_keys.end()) {
      LOGD("exportKey: alias not one of ours; forwarding to the real keystore");
      return false;
    }
    if (!EnsureTaKey(it->second, uid)) {
      LOGE("exportKey: FAILED, could not materialise the key in the TA");
      return false;
    }
    spki = it->second.spki;
  }

  static const String16 kCb("android.security.keystore.IKeystoreExportKeyCallback");
  InvokeCallback(cb, kCb, [&](Parcel& p) {
    BeginTypedObject(p);  // ExportResult
    p.writeInt32(KS_NO_ERROR);
    p.writeByteArray(spki.size(), spki.data());
  });
  ReplyStatus(reply, KS_NO_ERROR);
  return true;
}

bool HandleAttestKey(int uid, Parcel& in, Parcel* reply) {
  sp<IBinder> cb = in.readStrongBinder();
  String16 alias = in.readString16();
  std::vector<std::vector<uint8_t>> blobs;
  std::vector<KmParam> attest_params;
  if (in.readInt32() == 1) attest_params = ReadKeymasterArguments(in, blobs);

  std::vector<KmParam> extra;
  for (const auto& p : attest_params) {
    if (p.tag == TAG_ATTESTATION_CHALLENGE || p.tag == TAG_ATTESTATION_APPLICATION_ID)
      extra.push_back(p);
  }
  LOGI("attestKey: params=%s", KmDescribeParams(attest_params.data(), attest_params.size()).c_str());

  std::vector<std::vector<uint8_t>> chain;
  {
    std::lock_guard<std::mutex> lk(g_keys_mutex);
    auto it = g_keys.find(KeyId(uid, alias));
    if (it == g_keys.end()) {
      LOGD("attestKey: alias not one of ours; forwarding to the real keystore");
      return false;
    }
    if (it->second.ta_blob.empty()) {
      if (!MintOnce(it->second, uid, extra, true)) {
        LOGE("attestKey: FAILED, the TA declined to mint and attest the key");
        return false;
      }
    } else if (!AttestExisting(it->second, uid, extra)) {
      LOGE("attestKey: FAILED, the TA declined to re-attest the key");
      return false;
    }
    chain = it->second.certs;
  }
  LOGI("attestKey: simulated alias=%s certs=%zu", String8(alias).c_str(), chain.size());

  static const String16 kCb("android.security.keystore.IKeystoreCertificateChainCallback");
  InvokeCallback(cb, kCb, [&](Parcel& p) {
    WriteKeystoreResponse(p, KS_NO_ERROR);
    BeginTypedObject(p);  // KeymasterCertificateChain
    p.writeInt32(static_cast<int32_t>(chain.size()));
    for (const auto& c : chain) p.writeByteArray(c.size(), c.data());
  });
  ReplyStatus(reply, KS_NO_ERROR);
  return true;
}

bool HandleBegin(int uid, Parcel& in, Parcel* reply) {
  sp<IBinder> cb = in.readStrongBinder();
  in.readStrongBinder();  // appToken (unused)
  String16 alias = in.readString16();
  int32_t purpose = in.readInt32();
  in.readInt32();  // pruneable (unused)
  std::vector<std::vector<uint8_t>> blobs;
  std::vector<KmParam> op_params;
  if (in.readInt32() == 1) {
    for (const auto& p : ReadKeymasterArguments(in, blobs)) {
      // Pass only operation parameters; key characteristics come from the blob.
      if (p.tag == TAG_ALGORITHM || p.tag == TAG_KEY_SIZE || p.tag == TAG_EC_CURVE) continue;
      op_params.push_back(p);
    }
  }

  std::vector<uint8_t> blob;
  {
    std::lock_guard<std::mutex> lk(g_keys_mutex);
    auto it = g_keys.find(KeyId(uid, alias));
    if (it == g_keys.end()) {
      LOGD("begin: alias not one of ours; forwarding to the real keystore");
      return false;
    }
    if (!EnsureTaKey(it->second, uid)) {
      LOGE("begin: FAILED, could not materialise the key in the TA");
      return false;
    }
    blob = it->second.ta_blob;
  }

  TaPtr ta = ProfileForUid(uid);
  if (!ta) ta = DefaultTa();
  if (!ta) {
    LOGE("begin: FAILED, no TA configured for uid %d and no default; forwarding is not possible "
         "here because the key is ours",
         uid);
    return false;
  }
  TsBeginResult* res = nullptr;
  // The legacy keystore1 HAL carries auth tokens through its own mechanism, not the flat token structs
  // the keystore2 path uses, so no auth token is forwarded here yet (unchanged behavior). Auth-bound
  // keys on Android 10/11 are a separate follow-up; pass nullptr to mean "no token".
  int32_t rc = teesim_km_begin(ta.get(), purpose, blob.data(), blob.size(), op_params.data(),
                               op_params.size(), /*auth_token=*/nullptr, &res);
  if (rc != 0 || !res) {
    LOGE("begin: TA begin failed rc=%d(%s)", rc, teesim_km_err_name(rc));
    return false;
  }
  std::vector<std::vector<uint8_t>> out_blobs;
  std::vector<KmParam> out_params;
  const size_t nparams = teesim_km_begin_num_params(res);
  out_params.reserve(nparams);
  out_blobs.reserve(nparams);
  for (size_t i = 0; i < nparams; ++i) {
    KmParam kp{};
    teesim_km_begin_param(res, i, &kp);
    if (kp.blob != nullptr && kp.blob_len > 0) {
      out_blobs.emplace_back(kp.blob, kp.blob + kp.blob_len);
      kp.blob = out_blobs.back().data();
      kp.blob_len = out_blobs.back().size();
    } else {
      kp.blob = nullptr;
      kp.blob_len = 0;
    }
    out_params.push_back(kp);
  }
  int64_t op_handle = teesim_km_begin_op_handle(res);
  teesim_km_free_begin(res);

  sp<IBinder> token = sp<OpToken>::make();
  {
    std::lock_guard<std::mutex> lk(g_ops_mutex);
    g_ops[token.get()] = {token, op_handle, ta};
  }
  LOGD("begin: purpose=%s alias=%s params=%s out_params=%zu", PurposeName(purpose),
       String8(alias).c_str(), KmDescribeParams(op_params.data(), op_params.size()).c_str(),
       out_params.size());

  static const String16 kCb("android.security.keystore.IKeystoreOperationResultCallback");
  InvokeCallback(cb, kCb, [&](Parcel& p) {
    WriteOperationResult(p, KS_NO_ERROR, token, op_handle, 0, {}, out_params);
  });
  ReplyStatus(reply, KS_NO_ERROR);
  return true;
}

// Look up the TA operation handle and its TA for a token the caller passes back.
bool OpFor(const sp<IBinder>& token, int64_t* op_handle, TaPtr* ta, bool erase) {
  std::lock_guard<std::mutex> lk(g_ops_mutex);
  auto it = g_ops.find(token.get());
  if (it == g_ops.end()) return false;
  *op_handle = it->second.op_handle;
  *ta = it->second.ta;
  if (erase) g_ops.erase(it);
  return true;
}

void DeliverOperationResult(const sp<IBinder>& cb, int32_t rc, const sp<IBinder>& token,
                            int32_t input_consumed, const std::vector<uint8_t>& output) {
  static const String16 kCb("android.security.keystore.IKeystoreOperationResultCallback");
  InvokeCallback(cb, kCb, [&](Parcel& p) {
    WriteOperationResult(p, rc == 0 ? KS_NO_ERROR : KS_SYSTEM_ERROR, token, 0, input_consumed,
                         output, {});
  });
}

bool HandleUpdate(int /*uid*/, Parcel& in, Parcel* reply) {
  sp<IBinder> cb = in.readStrongBinder();
  sp<IBinder> token = in.readStrongBinder();
  std::vector<std::vector<uint8_t>> blobs;
  if (in.readInt32() == 1) ReadKeymasterArguments(in, blobs);  // op params (unused)
  std::vector<uint8_t> input = ReadByteArray(in);

  int64_t op_handle = 0;
  TaPtr ta;
  if (!OpFor(token, &op_handle, &ta, /*erase=*/false)) {
    LOGD("update: operation token not one of ours; forwarding to the real keystore");
    return false;
  }

  uint8_t* out = nullptr;
  size_t out_len = 0;
  int32_t rc = teesim_km_update(ta.get(), op_handle, input.data(), input.size(),
                                /*auth_token=*/nullptr, /*timestamp_token=*/nullptr, &out, &out_len);
  std::vector<uint8_t> output;
  if (rc == 0 && out) {
    output.assign(out, out + out_len);
    teesim_km_free_buf(out, out_len);
  } else if (rc != 0) {
    LOGE("update: TA update failed rc=%d(%s)", rc, teesim_km_err_name(rc));
  }

  DeliverOperationResult(cb, rc, token, static_cast<int32_t>(input.size()), output);
  ReplyStatus(reply, KS_NO_ERROR);
  return true;
}

bool HandleFinish(int /*uid*/, Parcel& in, Parcel* reply) {
  sp<IBinder> cb = in.readStrongBinder();
  sp<IBinder> token = in.readStrongBinder();
  std::vector<std::vector<uint8_t>> blobs;
  if (in.readInt32() == 1) ReadKeymasterArguments(in, blobs);  // op params (unused)
  // R added a leading `byte[] input` (single-shot finish) ahead of the signature; Q
  // has only the signature. Read input first on R so `signature` lands on the right field.
  std::vector<uint8_t> input;
  if (IsAndroidR()) input = ReadByteArray(in);
  std::vector<uint8_t> signature = ReadByteArray(in);  // supplied for verify

  int64_t op_handle = 0;
  TaPtr ta;
  if (!OpFor(token, &op_handle, &ta, /*erase=*/true)) {
    LOGD("finish: operation token not one of ours; forwarding to the real keystore");
    return false;
  }

  uint8_t* out = nullptr;
  size_t out_len = 0;
  int32_t rc = teesim_km_finish(ta.get(), op_handle, input.data(), input.size(), signature.data(),
                                signature.size(),
                                /*auth_token=*/nullptr, /*timestamp_token=*/nullptr,
                                /*confirmation_token=*/nullptr, 0, &out, &out_len);
  std::vector<uint8_t> output;
  if (rc == 0 && out) {
    output.assign(out, out + out_len);
    teesim_km_free_buf(out, out_len);
  } else if (rc != 0) {
    LOGE("finish: TA finish failed rc=%d(%s)", rc, teesim_km_err_name(rc));
  }
  LOGD("finish: output=%zu", output.size());

  DeliverOperationResult(cb, rc, token, static_cast<int32_t>(input.size()), output);
  ReplyStatus(reply, KS_NO_ERROR);
  return true;
}

// IKeystoreService.del / exist: int in the transaction reply, no callback binder.
// The request uid is UID_SELF (-1) or the key's owner; both map onto g_keys.
int ResolveKeyUid(int calling_uid, int32_t req_uid) {
  return req_uid == KS_UID_SELF ? calling_uid : req_uid;
}

bool HandleDel(int calling_uid, Parcel& in, Parcel* reply) {
  String16 alias = in.readString16();
  int uid = ResolveKeyUid(calling_uid, in.readInt32());
  {
    std::lock_guard<std::mutex> lk(g_keys_mutex);
    auto it = g_keys.find(KeyId(uid, alias));
    if (it == g_keys.end()) {
      LOGD("del: alias not one of ours; forwarding to the real keystore");
      return false;
    }
    g_keys.erase(it);
  }
  LOGI("del: simulated alias=%s uid=%d", String8(alias).c_str(), uid);
  ReplyStatus(reply, KS_NO_ERROR);
  return true;
}

bool HandleExist(int calling_uid, Parcel& in, Parcel* reply) {
  String16 alias = in.readString16();
  int uid = ResolveKeyUid(calling_uid, in.readInt32());
  {
    std::lock_guard<std::mutex> lk(g_keys_mutex);
    if (g_keys.find(KeyId(uid, alias)) == g_keys.end()) {
      LOGD("exist: alias not one of ours; forwarding to the real keystore");
      return false;
    }
  }
  LOGD("exist: answered from the simulated keys alias=%s uid=%d", String8(alias).c_str(), uid);
  ReplyStatus(reply, KS_NO_ERROR);
  return true;
}

bool HandleAbort(int /*uid*/, Parcel& in, Parcel* reply) {
  sp<IBinder> cb = in.readStrongBinder();
  sp<IBinder> token = in.readStrongBinder();
  int64_t op_handle = 0;
  TaPtr ta;
  if (!OpFor(token, &op_handle, &ta, /*erase=*/true)) {
    LOGD("abort: operation token not one of ours; forwarding to the real keystore");
    return false;
  }
  teesim_km_abort(ta.get(), op_handle);

  static const String16 kCb("android.security.keystore.IKeystoreResponseCallback");
  InvokeCallback(cb, kCb, [](Parcel& p) { WriteKeystoreResponse(p, KS_NO_ERROR); });
  ReplyStatus(reply, KS_NO_ERROR);
  return true;
}

}  // namespace

extern "C" const char* teesim_hook_name(void) { return "keystore1"; }

// Usage stats are a keystore2/KeyMint-only feature; Android 10/11 is out of scope
// for the scope picker, so this router reports an empty array (see control.h).
extern "C" char* teesim_usage_json_alloc(void) { return strdup("[]"); }

// RKP is a keystore2/Android-12+ construct; the keystore1 path never resolves a remotely-provisioned
// key, so there is nothing to track here (see control.h). Accept the pushed set as a no-op and never
// report a reassertion.
extern "C" void teesim_cfg_set_rkp_deleted(const char* const* /*names*/, size_t /*n*/) {}
extern "C" char* teesim_rkp_reassert_json_alloc(void) { return strdup("[]"); }

// Config-staging API (see common/control.h). teesim_cfg_begin/add_profile run on
// the control thread; only teesim_cfg_commit touches the live routing tables.
extern "C" void teesim_cfg_begin(const TsBootInfo* boot) {
  g_staging.clear();
  g_stage_vb_key.assign(boot->verified_boot_key,
                        boot->verified_boot_key + boot->verified_boot_key_len);
  g_stage_vb_hash.assign(boot->verified_boot_hash,
                         boot->verified_boot_hash + boot->verified_boot_hash_len);
  g_stage_locked = boot->device_locked;
  g_stage_vb_state = boot->verified_boot_state;
  g_stage_attest_version_tee = boot->attest_version_tee;
  g_stage_attest_version_strongbox = boot->attest_version_strongbox;
}

extern "C" bool teesim_cfg_add_profile(const TsProfile* p) {
  Ta* ta = teesim_km_init_ex(p->keybox, p->keybox_len, p->security_level, p->os_version,
                             p->os_patchlevel, p->vendor_patchlevel, p->boot_patchlevel,
                             g_stage_vb_key.data(), g_stage_vb_key.size(), g_stage_vb_hash.data(),
                             g_stage_vb_hash.size(), g_stage_locked, g_stage_vb_state,
                             g_stage_attest_version_tee, g_stage_attest_version_strongbox, p->ids);
  if (!ta) {
    LOGE("teesim_cfg_add_profile: profile %s failed to build (bad keybox?)", p->id ? p->id : "?");
    return false;
  }
  Profile prof;
  prof.id = p->id ? p->id : "";
  prof.ta = WrapTa(ta);
  // uid_packages[] is aligned 1:1 with uids[] and names the package behind each one, or "" for a raw
  // uid:N or an auto-included app that no entry names. It is carried on the wire rather than read off
  // packages[] by index: the two arrays have not lined up since a profile could name an app it does
  // not (yet) have installed, and pairing them by position hands a uid the wrong package name — which
  // this hook would then attest under.
  for (int i = 0; i < p->n_uids && p->uids; ++i) {
    if (p->uids[i] < 0) continue;
    const char* pkg = (p->uid_packages && p->uid_packages[i]) ? p->uid_packages[i] : "";
    prof.uids[p->uids[i]] = pkg;
    if (p->uid_app_ids && p->uid_app_id_lens && p->uid_app_ids[i] && p->uid_app_id_lens[i] > 0) {
      prof.app_ids[p->uids[i]].assign(p->uid_app_ids[i], p->uid_app_ids[i] + p->uid_app_id_lens[i]);
    }
    LOGI("teesim_cfg_add_profile:   uid %d -> package '%s' appId=%zuB", p->uids[i], pkg,
         prof.app_ids.count(p->uids[i]) ? prof.app_ids[p->uids[i]].size() : 0);
  }
  g_staging.push_back(std::move(prof));
  return true;
}

extern "C" int teesim_cfg_commit(uint64_t /*epoch*/, char* /*err*/, size_t /*err_len*/) {
  std::lock_guard<std::mutex> lk(g_cfg_mutex);
  g_profiles = std::move(g_staging);
  g_staging.clear();
  g_default_ta = g_profiles.empty() ? nullptr : g_profiles.front().ta;
  return static_cast<int>(g_profiles.size());
}

// The legacy keystore interceptor has no patch mode, so it re-signs nothing.
extern "C" bool teesim_cfg_resign(const char* /*profile_id*/, const uint8_t* /*leaf*/,
                                  size_t /*leaf_len*/, TsCertSink /*sink*/, void* /*ctx*/) {
  return false;
}

// The interception handler installed for the keystore service binder.
extern "C" bool teesim_ks_handle(uint32_t code, const Parcel& data, Parcel* reply,
                                  status_t& result) {
  // The ordinals are release-specific, so this dispatch runs against the resolved table
  // rather than a compile-time switch (see TxCodes).
  const TxCodes& tx = Codes();
  if (code != tx.del && code != tx.exist && code != tx.generateKey &&
      code != tx.getKeyCharacteristics && code != tx.exportKey && code != tx.attestKey &&
      code != tx.begin && code != tx.update && code != tx.finish && code != tx.abort)
    return false;
  int uid = IPCThreadState::self()->getCallingUid();
  // The target test comes first, and deliberately: stamping a context costs a package lookup and
  // two string allocations, and on a busy Android 10 device most transactions are not ours. The
  // forward line below names its own uid, so it needs no context to be attributable.
  if (!IsTarget(uid)) {
    LOGD("teesim_ks_handle: %s(code=%u) from uid %d is not a target; forwarding to the real keystore",
         TxName(code), code, uid);
    return false;
  }
  // Every line logged for this transaction — here, in the handlers, and inside the TA — names the
  // app it belongs to and the request it belongs to. Only a target reaches this point, so the
  // package is always known.
  const std::string pkg = PackageForUid(uid);
  char rid[16];
  snprintf(rid, sizeof(rid), "r%04x", teesim_log_new_rid());
  LogContext lc_("[" + std::to_string(uid) + (pkg.empty() ? "" : " " + pkg) + " " + rid + "] ");
  Reader r(data);
  if (!r.p.enforceInterface(kServiceDescriptor)) {
    LOGW("teesim_ks_handle: %s(code=%u) from uid %d has the wrong interface descriptor; forwarding untouched",
         TxName(code), code,
         uid);
    return false;
  }

  bool done = false;
  if (code == tx.del)                        done = HandleDel(uid, r.p, reply);
  else if (code == tx.exist)                 done = HandleExist(uid, r.p, reply);
  else if (code == tx.generateKey)           done = HandleGenerateKey(uid, r.p, reply);
  else if (code == tx.getKeyCharacteristics) done = HandleGetKeyCharacteristics(uid, r.p, reply);
  else if (code == tx.exportKey)             done = HandleExportKey(uid, r.p, reply);
  else if (code == tx.attestKey)             done = HandleAttestKey(uid, r.p, reply);
  else if (code == tx.begin)                 done = HandleBegin(uid, r.p, reply);
  else if (code == tx.update)                done = HandleUpdate(uid, r.p, reply);
  else if (code == tx.finish)                done = HandleFinish(uid, r.p, reply);
  else if (code == tx.abort)                 done = HandleAbort(uid, r.p, reply);
  if (done) result = OK;
  return done;
}
