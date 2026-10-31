// Host conformance tests for the attestation record this TA emits.
//
// The TA is the binary that produces the record; these tests build it for the host, feed fixed
// inputs (a fixed test keybox, a fixed challenge and application id, a pinned attestation version)
// and assert the result against the platform contract:
//
//   - attestationVersion -> keymasterVersion mapping: AOSP attestation doc version table.
//   - ORIGIN must be added by the implementation, hardware-enforced: keymaster/4.0/types.hal.
//   - CREATION_DATETIME must be in softwareEnforced: keymaster/4.0/types.hal.
//   - MODULE_HASH (724) exists only from KeyMint 4 (attestationVersion 400): keymint Tag.aidl.
//   - leaf validity for a pre-KeyMint TA: IKeymasterDevice.hal attestKey (ACTIVE_DATETIME or
//     CREATION_DATETIME; USAGE_EXPIRE_DATETIME or the batch certificate's notAfter).
//
// Run with rust/test-host.sh, which builds the host BoringSSL the backend links against.

use teesim_km::{Ta, TaConfig};
use kmr_wire::keymint::{
    Algorithm, DateTime, Digest, EcCurve, KeyParam, KeyPurpose, SecurityLevel,
};
use x509_cert::der::Decode;
use x509_cert::Certificate as X509Certificate;

const KEYBOX: &str = include_str!("data/test-keybox.xml");
const CHALLENGE: &[u8] = b"teesim-conformance";
const APP_ID: &[u8] = b"\x30\x03\x31\x01\x00"; // not decoded by the TA, only echoed

const ATTESTATION_OID: &str = "1.3.6.1.4.1.11129.2.1.17";

// KeyMint refuses generateKey without CERTIFICATE_NOT_BEFORE/AFTER (ErrorCode -80/-81); a Keymaster
// TA has no such tags and derives them from the request, so only the KeyMint cases supply them.
const NOT_BEFORE_MS: i64 = 1_700_000_000_000; // 2023-11-14T22:13:20Z
const NOT_AFTER_MS: i64 = 1_900_000_000_000; // 2030-03-17T17:46:40Z

fn ta(attestation_version: i32) -> Ta {
    Ta::new_ex(TaConfig {
        keybox_xml: KEYBOX,
        security_level: SecurityLevel::TrustedEnvironment as i32,
        os_version: 110000,
        os_patchlevel: 202109,
        vendor_patchlevel: 20210905,
        boot_patchlevel: 20210905,
        verified_boot_key: vec![0x11; 32],
        verified_boot_hash: vec![0x22; 32],
        device_boot_locked: true,
        verified_boot_state: 0,
        attest_version_tee: attestation_version,
        attest_version_strongbox: attestation_version,
        attestation_ids: None,
    })
    .expect("test keybox must load")
}

fn ec_params() -> Vec<KeyParam> {
    vec![
        KeyParam::Algorithm(Algorithm::Ec),
        KeyParam::Purpose(KeyPurpose::Sign),
        KeyParam::Digest(Digest::Sha256),
        KeyParam::EcCurve(EcCurve::P256),
        KeyParam::KeySize(kmr_wire::KeySizeInBits(256)),
        KeyParam::AttestationChallenge(CHALLENGE.to_vec()),
        KeyParam::AttestationApplicationId(APP_ID.to_vec()),
    ]
}

fn generate(ta: &mut Ta, attestation_version: i32) -> Vec<Vec<u8>> {
    let mut params = ec_params();
    if attestation_version >= 100 {
        params.push(KeyParam::CertificateNotBefore(DateTime { ms_since_epoch: NOT_BEFORE_MS }));
        params.push(KeyParam::CertificateNotAfter(DateTime { ms_since_epoch: NOT_AFTER_MS }));
    }
    let result = ta.generate_key(params, None).expect("generate_key must succeed");
    result
        .certificate_chain
        .iter()
        .map(|c| c.encoded_certificate.clone())
        .collect()
}

/// One DER element: tag (class, constructed, number), value offset/length and full extent.
#[derive(Clone, Copy)]
struct El {
    tag: u32,
    value: usize,
    end: usize,
}

fn element(buf: &[u8], at: usize) -> El {
    let mut i = at;
    let first = buf[i];
    i += 1;
    let mut tag = (first & 0x1f) as u32;
    if tag == 0x1f {
        tag = 0;
        loop {
            let b = buf[i];
            i += 1;
            tag = (tag << 7) | (b & 0x7f) as u32;
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    let mut len = buf[i] as usize;
    i += 1;
    if len & 0x80 != 0 {
        let n = len & 0x7f;
        len = 0;
        for _ in 0..n {
            len = (len << 8) | buf[i] as usize;
            i += 1;
        }
    }
    El { tag, value: i, end: i + len }
}

fn children(buf: &[u8], el: El) -> Vec<El> {
    let mut out = Vec::new();
    let mut at = el.value;
    while at < el.end {
        let child = element(buf, at);
        at = child.end;
        out.push(child);
    }
    out
}

fn int_value(buf: &[u8], el: El) -> i64 {
    let bytes = &buf[el.value..el.end];
    let negative = bytes[0] & 0x80 != 0;
    let mut v: i64 = if negative { -1 } else { 0 };
    for b in bytes {
        v = (v << 8) | *b as i64;
    }
    v
}

/// The decoded attestation extension of one leaf.
struct Record {
    attestation_version: i64,
    keymaster_version: i64,
    attestation_security_level: i64,
    keymaster_security_level: i64,
    challenge: Vec<u8>,
    software: Vec<(u32, Option<El>)>,
    hardware: Vec<(u32, Option<El>)>,
    raw: Vec<u8>,
}

impl Record {
    fn software_tag(&self, tag: u32) -> Option<El> {
        self.software.iter().find(|(t, _)| *t == tag).and_then(|(_, e)| *e)
    }
    fn hardware_tag(&self, tag: u32) -> Option<El> {
        self.hardware.iter().find(|(t, _)| *t == tag).and_then(|(_, e)| *e)
    }
    fn has(&self, tag: u32) -> bool {
        self.software_tag(tag).is_some() || self.hardware_tag(tag).is_some()
    }
}

fn record(leaf: &[u8]) -> Record {
    let cert = X509Certificate::from_der(leaf).expect("leaf must parse");
    let extension = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .expect("leaf has extensions")
        .iter()
        .find(|e| e.extn_id.to_string() == ATTESTATION_OID)
        .expect("leaf carries the attestation extension");
    let der = extension.extn_value.as_bytes();
    let top = element(der, 0);
    let fields = children(der, top);
    let list = |el: El| -> Vec<(u32, Option<El>)> {
        children(der, el)
            .into_iter()
            .map(|entry| {
                let inner = children(der, entry);
                (entry.tag, inner.first().copied())
            })
            .collect()
    };
    Record {
        attestation_version: int_value(der, fields[0]),
        attestation_security_level: int_value(der, fields[1]),
        keymaster_version: int_value(der, fields[2]),
        keymaster_security_level: int_value(der, fields[3]),
        challenge: der[fields[4].value..fields[4].end].to_vec(),
        software: list(fields[6]),
        hardware: list(fields[7]),
        raw: der.to_vec(),
    }
}

/// notBefore/notAfter of a DER certificate, in milliseconds since the epoch.
fn validity(der: &[u8]) -> (i64, i64) {
    let cert = X509Certificate::from_der(der).expect("certificate must parse");
    let ms = |t: x509_cert::time::Time| -> i64 {
        i64::try_from(t.to_unix_duration().as_millis()).expect("time fits")
    };
    (ms(cert.tbs_certificate.validity.not_before), ms(cert.tbs_certificate.validity.not_after))
}

#[test]
fn version_pair_follows_the_attestation_table() {
    // AOSP attestation doc: 2 = Keymaster 3.0, 3 = Keymaster 4.0, 4 = Keymaster 4.1, 100+ = KeyMint.
    for (attestation, expected_keymaster) in [(2, 3), (3, 4), (4, 41), (100, 100), (400, 400)] {
        let mut ta = ta(attestation);
        let chain = generate(&mut ta, attestation);
        let rec = record(&chain[0]);
        assert_eq!(rec.attestation_version, i64::from(attestation));
        assert_eq!(
            rec.keymaster_version, expected_keymaster,
            "attestationVersion {attestation} must pair with keymasterVersion {expected_keymaster}"
        );
        assert_eq!(rec.attestation_security_level, rec.keymaster_security_level);
    }
}

#[test]
fn origin_is_generated_and_hardware_enforced() {
    let mut ta = ta(400);
    let chain = generate(&mut ta, 400);
    let rec = record(&chain[0]);
    assert!(rec.software_tag(702).is_none(), "ORIGIN must not be software-enforced");
    let origin = rec.hardware_tag(702).expect("ORIGIN must be present");
    assert_eq!(int_value(&rec.raw, origin), 0, "ORIGIN must be GENERATED");
}

#[test]
fn creation_datetime_is_software_enforced() {
    for attestation in [3, 400] {
        let mut ta = ta(attestation);
        let chain = generate(&mut ta, attestation);
        let rec = record(&chain[0]);
        assert!(
            rec.software_tag(701).is_some(),
            "CREATION_DATETIME must be software-enforced at attestationVersion {attestation}"
        );
    }
}

#[test]
fn module_hash_appears_only_from_keymint_4() {
    let module_hash = vec![0xAB; 32];

    let mut keymaster = ta(3);
    keymaster
        .set_additional_attestation_info(vec![KeyParam::ModuleHash(module_hash.clone())])
        .expect("module hash must be accepted");
    let rec = record(&generate(&mut keymaster, 3)[0]);
    assert!(!rec.has(724), "MODULE_HASH must not appear in a Keymaster 4.0 record");

    let mut keymint = ta(400);
    keymint
        .set_additional_attestation_info(vec![KeyParam::ModuleHash(module_hash)])
        .expect("module hash must be accepted");
    let rec = record(&generate(&mut keymint, 400)[0]);
    assert!(rec.has(724), "MODULE_HASH must appear in a KeyMint 4 record");
}

#[test]
fn keymaster_leaf_validity_follows_attestkey() {
    // IKeymasterDevice.hal attestKey: notBefore = ACTIVE_DATETIME or CREATION_DATETIME,
    // notAfter = USAGE_EXPIRE_DATETIME or the batch attestation certificate's notAfter.
    // An X.509 time has one-second resolution (RFC 5280 section 4.1.2.5), so milliseconds truncate.
    let mut ta = ta(3);
    let chain = generate(&mut ta, 3);
    let rec = record(&chain[0]);
    let creation = int_value(&rec.raw, rec.software_tag(701).expect("creation datetime"));
    let (not_before, not_after) = validity(&chain[0]);
    let (_, batch_not_after) = validity(&chain[1]);
    assert_eq!(
        not_before,
        creation - creation % 1000,
        "leaf notBefore must be the creation datetime"
    );
    assert_eq!(not_after, batch_not_after, "leaf notAfter must be the batch certificate's");
}

#[test]
fn keymint_leaf_validity_uses_certificate_tags() {
    let mut ta = ta(400);
    let chain = generate(&mut ta, 400);
    let (not_before, not_after) = validity(&chain[0]);
    assert_eq!(not_before, NOT_BEFORE_MS, "leaf notBefore must be CERTIFICATE_NOT_BEFORE");
    assert_eq!(not_after, NOT_AFTER_MS, "leaf notAfter must be CERTIFICATE_NOT_AFTER");
}

#[test]
fn challenge_and_application_id_are_echoed() {
    let mut ta = ta(400);
    let chain = generate(&mut ta, 400);
    let rec = record(&chain[0]);
    assert_eq!(rec.challenge, CHALLENGE);
    let app_id = rec.software_tag(709).expect("ATTESTATION_APPLICATION_ID must be present");
    assert_eq!(&rec.raw[app_id.value..app_id.end], APP_ID);
}
