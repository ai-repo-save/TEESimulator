// Known-rule regression tests: each one pins a behaviour this fork had to fix.
//
// The exploratory checks (things nobody has asserted yet) live in sweep.rs; these exist so a
// regression is caught with the rule it violates.

mod common;

use common::*;

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
    use kmr_wire::keymint::KeyParam;
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
    assert_eq!(not_before, creation - creation % 1000, "leaf notBefore must be the creation datetime");
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

/// Keyboxes in the field carry the private key either as PKCS#8 (`BEGIN PRIVATE KEY`) or in the
/// algorithm's own encoding (`BEGIN RSA PRIVATE KEY`, `BEGIN EC PRIVATE KEY`). Both must load and
/// attest.
#[test]
fn keybox_accepts_pkcs8_private_keys() {
    use kmr_wire::keymint::{Algorithm, KeyParam, KeyPurpose, PaddingMode, SecurityLevel};

    let mut ta = common::ta_with_keybox(400, SecurityLevel::TrustedEnvironment, KEYBOX_PKCS8);
    let mut ec = ec_params();
    ec.extend(certificate_validity(400));
    ta.generate_key(ec, None).expect("EC attestation from a PKCS#8 keybox");

    let rsa = vec![
        KeyParam::Algorithm(Algorithm::Rsa),
        KeyParam::Purpose(KeyPurpose::Sign),
        KeyParam::Digest(kmr_wire::keymint::Digest::Sha256),
        KeyParam::Padding(PaddingMode::RsaPkcs115Sign),
        KeyParam::KeySize(kmr_wire::KeySizeInBits(2048)),
        KeyParam::RsaPublicExponent(kmr_wire::RsaExponent(65537)),
        KeyParam::AttestationChallenge(CHALLENGE.to_vec()),
        KeyParam::AttestationApplicationId(APP_ID.to_vec()),
        KeyParam::CertificateNotBefore(kmr_wire::keymint::DateTime { ms_since_epoch: NOT_BEFORE_MS }),
        KeyParam::CertificateNotAfter(kmr_wire::keymint::DateTime { ms_since_epoch: NOT_AFTER_MS }),
    ];
    ta.generate_key(rsa, None).expect("RSA attestation from a PKCS#8 keybox");
}
