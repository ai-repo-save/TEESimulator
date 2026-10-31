// KeyMint names for the log. The tables are generated from the AIDL (km_names_gen.inc, by
// scripts/gen-km-names.py), so a code or tag the HAL defines is never shown as a bare number.

#include "km_names.h"

#include <string.h>

#include <stdio.h>
#include <time.h>

#include <vector>

#include "redact.h"

namespace {

struct KmName {
  int32_t value;
  const char *name;
};

struct KmEnumTable {
  const KmName *names;
  size_t n;
};

struct KmTagEntry {
  uint32_t tag;
  const char *name;
  int8_t enum_id;  // index into kEnumTables, or kEnumNone
};

#include "km_names_gen.inc"

constexpr uint32_t kTypeMask = 0xf0000000u;
constexpr uint32_t kTypeDate = 6u << 28;
constexpr uint32_t kUserAuthType = 0x100001f8u;  // TagType.ENUM | 504

const KmTagEntry *FindTag(uint32_t tag) {
  for (const auto &t : kTags) {
    if (t.tag == tag) return &t;
  }
  return nullptr;
}

const char *FindName(const KmName *names, size_t n, int32_t value) {
  for (size_t i = 0; i < n; ++i) {
    if (names[i].value == value) return names[i].name;
  }
  return nullptr;
}

void AppendHex(std::string &out, const uint8_t *p, size_t n) {
  static const char kHex[] = "0123456789abcdef";
  for (size_t i = 0; i < n; ++i) {
    out += kHex[p[i] >> 4];
    out += kHex[p[i] & 15];
  }
}

void AppendBytes(std::string &out, const uint8_t *p, size_t n) {
  if (p == nullptr || n == 0) {
    out += "\"\"";
    return;
  }
  bool printable = true;
  for (size_t i = 0; i < n && printable; ++i) printable = p[i] >= 0x20 && p[i] < 0x7f;
  if (printable) {
    constexpr size_t kMaxText = 96;
    out += '"';
    out.append(reinterpret_cast<const char *>(p), n < kMaxText ? n : kMaxText);
    if (n > kMaxText) out += "...";
    out += '"';
    return;
  }
  constexpr size_t kMaxHex = 32;
  if (n <= kMaxHex) {
    AppendHex(out, p, n);
    return;
  }
  char head[24];
  snprintf(head, sizeof(head), "<%zuB ", n);
  out += head;
  AppendHex(out, p, 8);
  out += "~>";
}

void AppendDate(std::string &out, int64_t ms) {
  const time_t secs = static_cast<time_t>(ms / 1000);
  struct tm tm {};
  char buf[32];
  if (ms >= 0 && gmtime_r(&secs, &tm) != nullptr &&
      strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm) > 0) {
    out += buf;
  } else {
    out += std::to_string(ms);
  }
}

void AppendAuthType(std::string &out, uint32_t v) {
  const KmEnumTable &t = kEnumTables[kEnumHardwareAuthenticatorType];
  if (const char *exact = FindName(t.names, t.n, static_cast<int32_t>(v))) {
    out += exact;  // NONE and ANY
    return;
  }
  bool first = true;
  for (size_t i = 0; i < t.n; ++i) {
    const uint32_t bit = static_cast<uint32_t>(t.names[i].value);
    if (bit == 0 || bit == 0xffffffffu || (v & bit) != bit) continue;
    if (!first) out += '|';
    out += t.names[i].name;
    v &= ~bit;
    first = false;
  }
  if (v != 0) {
    if (!first) out += '|';
    char buf[16];
    snprintf(buf, sizeof(buf), "0x%x", v);
    out += buf;
  }
}

// The attestation ID tags that identify this particular device rather than its model. They are
// logged as Redact tokens, which still compare equal across lines and against the daemon's own.
bool IsDeviceIdentifier(const KmTagEntry *known) {
  static const char *const kNames[] = {
      "attestation_id_serial",
      "attestation_id_imei",
      "attestation_id_second_imei",
      "attestation_id_meid",
  };
  if (known == nullptr) return false;
  for (const char *n : kNames) {
    if (strcmp(known->name, n) == 0) return true;
  }
  return false;
}

void AppendValue(std::string &out, const KmParam &p, const KmTagEntry *known) {
  if (IsDeviceIdentifier(known) && teesim_km_tag_value_kind(p.tag) == KM_VALUE_BYTES) {
    out += RedactToken(p.blob, p.blob_len);
    return;
  }
  switch (teesim_km_tag_value_kind(p.tag)) {
    case KM_VALUE_BYTES:
      AppendBytes(out, p.blob, p.blob_len);
      return;
    case KM_VALUE_INT32: {
      const int32_t v = static_cast<int32_t>(p.int_value);
      if (known != nullptr && known->enum_id != kEnumNone) {
        const KmEnumTable &t = kEnumTables[known->enum_id];
        if (const char *name = FindName(t.names, t.n, v)) {
          out += name;
          return;
        }
      }
      out += std::to_string(v);
      return;
    }
    case KM_VALUE_UINT32: {
      const uint32_t v = static_cast<uint32_t>(p.int_value);
      if (p.tag == kUserAuthType) {
        AppendAuthType(out, v);
      } else {
        out += std::to_string(v);
      }
      return;
    }
    case KM_VALUE_INT64:
      if ((p.tag & kTypeMask) == kTypeDate) {
        AppendDate(out, p.int_value);
      } else {
        out += std::to_string(p.int_value);
      }
      return;
    case KM_VALUE_UINT64:
      out += std::to_string(static_cast<uint64_t>(p.int_value));
      return;
    case KM_VALUE_BOOL:
    case KM_VALUE_INVALID:
    default:
      if (p.blob != nullptr) {
        AppendBytes(out, p.blob, p.blob_len);
      } else {
        out += std::to_string(p.int_value);
      }
      return;
  }
}

}  // namespace

extern "C" const char *teesim_km_err_name(int32_t code) {
  const char *name = FindName(kErrors, sizeof(kErrors) / sizeof(kErrors[0]), code);
  return name != nullptr ? name : "?";
}

const char *KmTagName(uint32_t tag) {
  const KmTagEntry *t = FindTag(tag);
  return t != nullptr ? t->name : nullptr;
}

std::string KmDescribeParams(const KmParam *params, size_t n) {
  std::string out = "{";
  if (params == nullptr) return out + "}";
  // Group a repeated tag's values under its first appearance, so PURPOSE=SIGN, PURPOSE=VERIFY reads
  // as purpose=SIGN|VERIFY.
  std::vector<bool> done(n, false);
  for (size_t i = 0; i < n; ++i) {
    if (done[i]) continue;
    const uint32_t tag = params[i].tag;
    const KmTagEntry *known = FindTag(tag);
    if (out.size() > 1) out += ' ';
    if (known != nullptr) {
      out += known->name;
    } else {
      char buf[24];
      snprintf(buf, sizeof(buf), "tag_0x%08x", tag);
      out += buf;
    }
    if (teesim_km_tag_value_kind(tag) == KM_VALUE_BOOL) {
      done[i] = true;
      continue;
    }
    out += '=';
    bool first = true;
    for (size_t j = i; j < n; ++j) {
      if (params[j].tag != tag) continue;
      if (!first) out += '|';
      AppendValue(out, params[j], known);
      done[j] = true;
      first = false;
    }
  }
  return out + "}";
}
