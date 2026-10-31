// Shared fixtures and DER helpers for the host conformance tests.
//
// The TA is driven directly: a fixed test keybox, a fixed challenge and application id, and a
// pinned attestation version. No device and no interceptor — the TA is the binary that produces
// the record.

use teesim_km::{Ta, TaConfig};
use kmr_wire::keymint::{Algorithm, Digest, EcCurve, KeyParam, KeyPurpose, SecurityLevel};
use x509_cert::der::Decode;
use x509_cert::Certificate as X509Certificate;

pub const KEYBOX: &str = include_str!("../data/test-keybox.xml");
pub const KEYBOX_PKCS8: &str = include_str!("../data/test-keybox-pkcs8.xml");
pub const CHALLENGE: &[u8] = b"teesim-conformance";
pub const APP_ID: &[u8] = b"\x30\x03\x31\x01\x00";
pub const ATTESTATION_OID: &str = "1.3.6.1.4.1.11129.2.1.17";

pub const NOT_BEFORE_MS: i64 = 1_700_000_000_000;
pub const NOT_AFTER_MS: i64 = 1_900_000_000_000;

/// Route the TA's log lines to stderr so a failing operation explains itself.
struct StderrLogger;

impl log::Log for StderrLogger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }
    fn log(&self, record: &log::Record) {
        eprintln!("[{}] {}", record.level(), record.args());
    }
    fn flush(&self) {}
}

pub fn init_logging() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = log::set_logger(&StderrLogger);
        log::set_max_level(log::LevelFilter::Trace);
    });
}

pub fn ta(attestation_version: i32) -> Ta {
    init_logging();
    ta_at(attestation_version, SecurityLevel::TrustedEnvironment)
}

pub fn ta_at(attestation_version: i32, level: SecurityLevel) -> Ta {
    ta_with_keybox(attestation_version, level, KEYBOX)
}

pub fn ta_with_keybox(attestation_version: i32, level: SecurityLevel, keybox: &'static str) -> Ta {
    Ta::new_ex(TaConfig {
        keybox_xml: keybox,
        security_level: level as i32,
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

pub fn ec_params() -> Vec<KeyParam> {
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

/// Parameters a KeyMint HAL requires the caller to supply; a Keymaster TA derives them instead.
pub fn certificate_validity(attestation_version: i32) -> Vec<KeyParam> {
    if attestation_version < 100 {
        return Vec::new();
    }
    vec![
        KeyParam::CertificateNotBefore(kmr_wire::keymint::DateTime { ms_since_epoch: NOT_BEFORE_MS }),
        KeyParam::CertificateNotAfter(kmr_wire::keymint::DateTime { ms_since_epoch: NOT_AFTER_MS }),
    ]
}

pub fn generate(ta: &mut Ta, attestation_version: i32) -> Vec<Vec<u8>> {
    let mut params = ec_params();
    params.extend(certificate_validity(attestation_version));
    let result = ta.generate_key(params, None).expect("generate_key must succeed");
    result.certificate_chain.iter().map(|c| c.encoded_certificate.clone()).collect()
}

/// One DER element: tag number, value offset/length, full extent.
#[derive(Clone, Copy)]
pub struct El {
    pub tag: u32,
    pub value: usize,
    pub end: usize,
}

pub fn element(buf: &[u8], at: usize) -> El {
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

pub fn children(buf: &[u8], el: El) -> Vec<El> {
    let mut out = Vec::new();
    let mut at = el.value;
    while at < el.end {
        let child = element(buf, at);
        at = child.end;
        out.push(child);
    }
    out
}

pub fn int_value(buf: &[u8], el: El) -> i64 {
    let bytes = &buf[el.value..el.end];
    let negative = bytes[0] & 0x80 != 0;
    let mut v: i64 = if negative { -1 } else { 0 };
    for b in bytes {
        v = (v << 8) | *b as i64;
    }
    v
}

/// The decoded attestation extension of one leaf.
pub struct Record {
    pub attestation_version: i64,
    pub keymaster_version: i64,
    pub attestation_security_level: i64,
    pub keymaster_security_level: i64,
    pub challenge: Vec<u8>,
    pub unique_id: Vec<u8>,
    pub software: Vec<(u32, Option<El>)>,
    pub hardware: Vec<(u32, Option<El>)>,
    pub raw: Vec<u8>,
}

impl Record {
    pub fn software_tag(&self, tag: u32) -> Option<El> {
        self.software.iter().find(|(t, _)| *t == tag).and_then(|(_, e)| *e)
    }
    pub fn hardware_tag(&self, tag: u32) -> Option<El> {
        self.hardware.iter().find(|(t, _)| *t == tag).and_then(|(_, e)| *e)
    }
    pub fn has(&self, tag: u32) -> bool {
        self.software_tag(tag).is_some() || self.hardware_tag(tag).is_some()
    }
    pub fn value_of(&self, tag: u32) -> Option<i64> {
        self.software_tag(tag)
            .or_else(|| self.hardware_tag(tag))
            .map(|el| int_value(&self.raw, el))
    }
}

/// True when the certificate carries the key-attestation extension. A key generated without an
/// attestation challenge has none: the TA still returns a self-signed certificate.
pub fn has_attestation_extension(leaf: &[u8]) -> bool {
    let cert = X509Certificate::from_der(leaf).expect("certificate must parse");
    cert.tbs_certificate
        .extensions
        .as_ref()
        .map(|list| list.iter().any(|e| e.extn_id.to_string() == ATTESTATION_OID))
        .unwrap_or(false)
}

pub fn record(leaf: &[u8]) -> Record {
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
        unique_id: der[fields[5].value..fields[5].end].to_vec(),
        software: list(fields[6]),
        hardware: list(fields[7]),
        raw: der.to_vec(),
    }
}

/// notBefore/notAfter of a DER certificate, in milliseconds since the epoch.
pub fn validity(der: &[u8]) -> (i64, i64) {
    let cert = X509Certificate::from_der(der).expect("certificate must parse");
    let ms = |t: x509_cert::time::Time| -> i64 {
        i64::try_from(t.to_unix_duration().as_millis()).expect("time fits")
    };
    (ms(cert.tbs_certificate.validity.not_before), ms(cert.tbs_certificate.validity.not_after))
}

pub fn certificate(der: &[u8]) -> X509Certificate {
    X509Certificate::from_der(der).expect("certificate must parse")
}

pub fn key_usage_bits(der: &[u8]) -> Option<Vec<bool>> {
    let cert = X509Certificate::from_der(der).ok()?;
    let extension = cert
        .tbs_certificate
        .extensions
        .as_ref()?
        .iter()
        .find(|e| e.extn_id.to_string() == "2.5.29.15")?;
    let raw = extension.extn_value.as_bytes();
    let bitstring = element(raw, 0);
    let bytes = &raw[bitstring.value + 1..bitstring.end]; // skip the unused-bits octet
    let mut bits = Vec::new();
    for byte in bytes {
        for shift in (0..8).rev() {
            bits.push(byte & (1 << shift) != 0);
        }
    }
    Some(bits)
}

pub fn spki_der(der: &[u8]) -> Vec<u8> {
    let cert = X509Certificate::from_der(der).expect("certificate must parse");
    let spki = &cert.tbs_certificate.subject_public_key_info;
    x509_cert::der::Encode::to_der(spki).expect("spki encodes")
}
