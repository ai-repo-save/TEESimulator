// Exploratory conformance sweep: probes of the platform contract that no fix of ours has asserted
// yet. These are meant to find unknown deviations, not to re-state known ones — when one fails it
// is either a bug in this TA or a rule the platform does not actually impose, and both are worth
// knowing before the next merge.
//
// Sources: IKeymasterDevice.hal (certificate layout, key usage, validity, error codes),
// keymaster/4.0/types.hal (tag placement), KeyMint AIDL (limits, unique id), RFC 5280.

mod common;

use common::*;
use kmr_wire::keymint::{
    Algorithm, DateTime, Digest, KeyParam, KeyPurpose, PaddingMode, SecurityLevel,
};

fn creation_datetime(ms: i64) -> KeyParam {
    KeyParam::CreationDatetime(DateTime { ms_since_epoch: ms })
}

/// The attestation certificate must look like one a Keymaster TA issues:
/// v3, serial 1, CN="Android Keystore Key", issued by the next certificate in the chain, with the
/// key-usage bits matching the key's purpose and a signature algorithm matching the key type.
#[test]
fn certificate_structure_follows_attestkey() {
    let mut ta = ta(400);
    let chain = generate(&mut ta, 400);
    let leaf = certificate(&chain[0]);
    assert_eq!(format!("{:?}", leaf.tbs_certificate.version), "V3");
    // x509-cert renders SerialNumber as hex ("01"), so read the INTEGER from the DER instead.
    let leaf_der = &chain[0];
    let top = element(leaf_der, 0);
    let tbs = children(leaf_der, top)[0];
    let tbs_fields = children(leaf_der, tbs);
    let serial = if tbs_fields[0].tag == 0 { tbs_fields[1] } else { tbs_fields[0] };
    assert_eq!(int_value(leaf_der, serial), 1, "serialNumber must be 1");
    assert!(
        leaf.tbs_certificate.subject.to_string().contains("CN=Android Keystore Key"),
        "subject was {}",
        leaf.tbs_certificate.subject
    );
    assert_eq!(
        leaf.tbs_certificate.issuer.to_string(),
        certificate(&chain[1]).tbs_certificate.subject.to_string(),
        "leaf issuer must be the batch certificate's subject"
    );

    let usage = key_usage_bits(&chain[0]).expect("leaf must carry a key usage extension");
    assert!(usage[0], "digitalSignature must be set for a SIGN key");
    assert!(!usage[1], "contentCommitment must be clear");
    assert!(!usage[2], "keyEncipherment must be clear for a SIGN key");
    assert!(!usage[3], "dataEncipherment must be clear for a SIGN key");

    let signature_oid = leaf.signature_algorithm.oid.to_string();
    assert_eq!(signature_oid, "1.2.840.10045.4.3.2", "EC keys are signed with ecdsa-with-SHA256");
}

/// Every request parameter must appear where the platform puts it: the TA's own list for a
/// TEE-level key, softwareEnforced for the informational CREATION_DATETIME, and never twice.
#[test]
fn authorization_list_placement() {
    let mut ta = ta(400);
    let chain = generate(&mut ta, 400);
    let rec = record(&chain[0]);

    // purpose(1), algorithm(2), keySize(3), digest(5), ecCurve(10)
    for tag in [1u32, 2, 3, 5, 10] {
        assert!(
            rec.hardware_tag(tag).is_some(),
            "tag {tag} must be hardware-enforced for a TEE-level key"
        );
    }
    assert!(rec.software_tag(701).is_some(), "creation datetime must be software-enforced");
    assert!(
        rec.hardware_tag(701).is_none(),
        "creation datetime must not also appear hardware-enforced"
    );
    assert!(rec.software_tag(709).is_some(), "application id must be software-enforced");
}

/// A signature produced through begin/update/finish must verify under the public key the
/// certificate carries.
#[test]
fn ec_signature_verifies_with_the_attested_key() {
    let mut ta = ta(400);
    let mut params = ec_params();
    params.extend(certificate_validity(400));
    let result = ta.generate_key(params, None).expect("generate_key");
    let chain: Vec<Vec<u8>> =
        result.certificate_chain.iter().map(|c| c.encoded_certificate.clone()).collect();

    let begin = ta
        .begin(KeyPurpose::Sign, &result.key_blob, vec![KeyParam::Digest(Digest::Sha256)], None)
        .expect("begin");
    let message = b"teesim sweep";
    let signature = ta
        .finish(begin.op_handle, Some(message.to_vec()), None, None, None, None)
        .expect("finish");
    assert!(!signature.is_empty(), "finish must return the signature");

    let pkey = openssl::pkey::PKey::public_key_from_der(&spki_der(&chain[0]))
        .expect("attested SPKI must parse");
    let mut verifier =
        openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &pkey).expect("verifier");
    verifier.update(message).expect("update");
    assert!(verifier.verify(&signature).expect("verify"), "signature must verify");
}

/// Using the key for a purpose it was not created with must be refused with UNSUPPORTED_PURPOSE.
#[test]
fn wrong_purpose_is_rejected() {
    let mut ta = ta(400);
    let mut params = ec_params();
    params.extend(certificate_validity(400));
    let result = ta.generate_key(params, None).expect("generate_key");
    let error = ta
        .begin(KeyPurpose::Verify, &result.key_blob, vec![KeyParam::Digest(Digest::Sha256)], None)
        .expect_err("VERIFY on a SIGN key must fail");
    assert_eq!(error.code, -2, "expected UNSUPPORTED_PURPOSE, got {} ({})", error.code, error.msg);
}

/// An aborted operation must not be finishable afterwards.
#[test]
fn aborted_operation_cannot_finish() {
    let mut ta = ta(400);
    let mut params = ec_params();
    params.extend(certificate_validity(400));
    let result = ta.generate_key(params, None).expect("generate_key");
    let begin = ta
        .begin(KeyPurpose::Sign, &result.key_blob, vec![KeyParam::Digest(Digest::Sha256)], None)
        .expect("begin");
    ta.abort(begin.op_handle).expect("abort");
    let error = ta
        .finish(begin.op_handle, Some(b"x".to_vec()), None, None, None, None)
        .expect_err("finish after abort must fail");
    assert!(
        error.code == -28 || error.code == -76,
        "aborted operation must be refused (INVALID_OPERATION_HANDLE -28 or INVALID_OPERATION -76), got {} ({})",
        error.code,
        error.msg
    );
}

/// A blob made by one TA instance must be usable by a fresh instance with the same configuration.
/// This is the "keys survive a reboot" property: it only holds if the key-encryption key and the
/// root of trust are frozen, not random per process.
#[test]
fn key_blob_survives_a_new_ta_instance() {
    let mut first = ta(400);
    let mut params = ec_params();
    params.extend(certificate_validity(400));
    let result = first.generate_key(params, None).expect("generate_key");

    let mut second = ta(400);
    let begin = second
        .begin(KeyPurpose::Sign, &result.key_blob, vec![KeyParam::Digest(Digest::Sha256)], None)
        .expect("a fresh TA instance must open a blob made by another instance");
    second
        .finish(begin.op_handle, Some(b"across instances".to_vec()), None, None, None, None)
        .expect("finish across instances");
}

/// attestKey re-issues the chain over the same key: the public key in the new leaf must equal the
/// one the caller already holds.
#[test]
fn attest_key_keeps_the_public_key() {
    let mut ta = ta(400);
    let mut params = ec_params();
    params.extend(certificate_validity(400));
    let result = ta.generate_key(params, None).expect("generate_key");
    let before = spki_der(&result.certificate_chain[0].encoded_certificate);

    let mut attest_params = vec![
        KeyParam::AttestationChallenge(b"re-attest".to_vec()),
        KeyParam::AttestationApplicationId(APP_ID.to_vec()),
        creation_datetime(1_700_000_000_000),
    ];
    attest_params.extend(certificate_validity(400));
    let reattested = ta.attest_key(&result.key_blob, attest_params, None).expect("attest_key");
    let after = spki_der(&reattested.certificate_chain[0].encoded_certificate);
    assert_eq!(before, after, "attestKey must not change the attested public key");
}

/// INCLUDE_UNIQUE_ID must produce a unique id in the record (and creation datetime, which it
/// depends on).
#[test]
fn unique_id_is_present_when_requested() {
    let mut ta = ta(400);
    let mut params = ec_params();
    params.push(KeyParam::IncludeUniqueId);
    params.extend(certificate_validity(400));
    let result = ta.generate_key(params, None).expect("generate_key with unique id");
    let rec = record(&result.certificate_chain[0].encoded_certificate);
    assert_eq!(rec.unique_id.len(), 16, "uniqueId is a 128-bit hash (types.hal Tag::UNIQUE_ID)");
    assert!(rec.unique_id.iter().any(|b| *b != 0), "uniqueId must not be all zeroes");
}

/// An attestation challenge longer than the AIDL limit must be refused with INVALID_INPUT_LENGTH.
#[test]
fn oversized_challenge_is_rejected() {
    let mut ta = ta(400);
    let mut params = ec_params();
    params.retain(|p| !matches!(p, KeyParam::AttestationChallenge(_)));
    params.push(KeyParam::AttestationChallenge(vec![0x41; 129]));
    params.extend(certificate_validity(400));
    let error = ta.generate_key(params, None).expect_err("129-byte challenge must be refused");
    assert_eq!(error.code, -21, "expected INVALID_INPUT_LENGTH, got {} ({})", error.code, error.msg);
}

/// A key size outside the HAL's supported set must be refused with UNSUPPORTED_KEY_SIZE.
#[test]
fn unsupported_key_size_is_rejected() {
    let mut ta = ta(400);
    let params = vec![
        KeyParam::Algorithm(Algorithm::Rsa),
        KeyParam::Purpose(KeyPurpose::Sign),
        KeyParam::Digest(Digest::Sha256),
        KeyParam::Padding(PaddingMode::RsaPkcs115Sign),
        KeyParam::KeySize(kmr_wire::KeySizeInBits(512)),
        KeyParam::AttestationChallenge(CHALLENGE.to_vec()),
        KeyParam::AttestationApplicationId(APP_ID.to_vec()),
        KeyParam::CertificateNotBefore(DateTime { ms_since_epoch: NOT_BEFORE_MS }),
        KeyParam::CertificateNotAfter(DateTime { ms_since_epoch: NOT_AFTER_MS }),
    ];
    let error = ta.generate_key(params, None).expect_err("RSA-512 must be refused");
    assert!(
        error.code == -6 || error.code == -38,
        "unsupported size must be refused (UNSUPPORTED_KEY_SIZE -6 or INVALID_ARGUMENT -38), got {} ({})",
        error.code,
        error.msg
    );
}

/// Key usage bits are mandated per purpose: dataEncipherment iff DECRYPT, keyEncipherment iff
/// KEY_WRAP, digitalSignature iff SIGN.
#[test]
fn key_usage_bits_follow_the_purpose() {
    for (purpose, bit, name) in [
        (KeyPurpose::Decrypt, 3usize, "dataEncipherment"),
        (KeyPurpose::WrapKey, 2usize, "keyEncipherment"),
    ] {
        let mut ta = ta(400);
        let params = vec![
            KeyParam::Algorithm(Algorithm::Rsa),
            KeyParam::Purpose(purpose),
            KeyParam::Digest(Digest::Sha256),
            KeyParam::Padding(PaddingMode::RsaPkcs115Encrypt),
            KeyParam::KeySize(kmr_wire::KeySizeInBits(2048)),
            KeyParam::RsaPublicExponent(kmr_wire::RsaExponent(65537)),
            KeyParam::AttestationChallenge(CHALLENGE.to_vec()),
            KeyParam::AttestationApplicationId(APP_ID.to_vec()),
            KeyParam::CertificateNotBefore(DateTime { ms_since_epoch: NOT_BEFORE_MS }),
            KeyParam::CertificateNotAfter(DateTime { ms_since_epoch: NOT_AFTER_MS }),
        ];
        let result = ta.generate_key(params, None).expect("generate_key");
        let leaf = &result.certificate_chain[0].encoded_certificate;
        let usage = key_usage_bits(leaf).expect("key usage extension");
        assert!(usage[bit], "{name} must be set for purpose {purpose:?}");
        assert!(!usage[0], "digitalSignature must be clear for purpose {purpose:?}");
    }
}

/// An RSA key's leaf is signed with sha256WithRSAEncryption.
#[test]
fn rsa_leaf_uses_the_rsa_signature_algorithm() {
    let mut ta = ta(400);
    let params = vec![
        KeyParam::Algorithm(Algorithm::Rsa),
        KeyParam::Purpose(KeyPurpose::Sign),
        KeyParam::Digest(Digest::Sha256),
        KeyParam::Padding(PaddingMode::RsaPkcs115Sign),
        KeyParam::KeySize(kmr_wire::KeySizeInBits(2048)),
        KeyParam::RsaPublicExponent(kmr_wire::RsaExponent(65537)),
        KeyParam::AttestationChallenge(CHALLENGE.to_vec()),
        KeyParam::AttestationApplicationId(APP_ID.to_vec()),
        KeyParam::CertificateNotBefore(DateTime { ms_since_epoch: NOT_BEFORE_MS }),
        KeyParam::CertificateNotAfter(DateTime { ms_since_epoch: NOT_AFTER_MS }),
    ];
    let result = ta.generate_key(params, None).expect("generate_key");
    let leaf = certificate(&result.certificate_chain[0].encoded_certificate);
    assert_eq!(
        leaf.signature_algorithm.oid.to_string(),
        "1.2.840.113549.1.1.11",
        "RSA keys are signed with sha256WithRSAEncryption"
    );
}

/// A StrongBox-level TA reports StrongBox as both security levels.
#[test]
fn strongbox_instance_reports_strongbox() {
    let mut ta = ta_at(400, SecurityLevel::Strongbox);
    let chain = generate(&mut ta, 400);
    let rec = record(&chain[0]);
    assert_eq!(rec.attestation_security_level, 2, "attestationSecurityLevel must be StrongBox");
    assert_eq!(rec.keymaster_security_level, 2, "keymasterSecurityLevel must be StrongBox");
}

/// A blob written by a Keymaster-version TA must still open in a KeyMint-version TA: the KEK and
/// the root of trust are frozen, so a profile whose harvested version changed keeps its keys.
#[test]
fn blob_opens_across_attestation_versions() {
    let mut keymaster = ta(3);
    let mut params = ec_params();
    let result = keymaster.generate_key(params.clone(), None).expect("generate at v3");

    let mut keymint = ta(400);
    params.extend(certificate_validity(400));
    keymint
        .begin(KeyPurpose::Sign, &result.key_blob, vec![KeyParam::Digest(Digest::Sha256)], None)
        .expect("a KeyMint-version TA must open a Keymaster-version blob");
}

/// A blob that did not come from this TA must be refused, not misinterpreted.
#[test]
fn foreign_blob_is_refused() {
    let mut ta = ta(400);
    let error = ta
        .begin(KeyPurpose::Sign, b"not-a-teesim-blob", vec![KeyParam::Digest(Digest::Sha256)], None)
        .expect_err("a foreign blob must be refused");
    assert_eq!(error.code, -33, "expected INVALID_KEY_BLOB, got {} ({})", error.code, error.msg);
}

/// getKeyCharacteristics must describe the key the record describes: ORIGIN and ALGORITHM in the
/// TA's list.
#[test]
fn characteristics_match_the_record() {
    let mut ta = ta(400);
    let mut params = ec_params();
    params.extend(certificate_validity(400));
    let result = ta.generate_key(params, None).expect("generate_key");
    let chars = ta
        .get_key_characteristics(&result.key_blob, Vec::new(), Vec::new())
        .expect("get_key_characteristics");
    let mut found_origin = None;
    let mut found_algorithm = None;
    for characteristic in &chars {
        for param in &characteristic.authorizations {
            match param {
                KeyParam::Origin(o) => found_origin = Some(*o as i32),
                KeyParam::Algorithm(a) => found_algorithm = Some(*a as i32),
                _ => {}
            }
        }
    }
    assert_eq!(found_origin, Some(0), "characteristics must report ORIGIN=GENERATED");
    assert_eq!(found_algorithm, Some(3), "characteristics must report ALGORITHM=EC");
}

/// The keystore1 flow: generateKey carries no challenge, then attestKey supplies it. The second
/// call must produce a record for the same key that carries the challenge.
#[test]
fn attest_key_adds_a_challenge_to_a_key_generated_without_one() {
    let mut ta = ta(400);
    let mut params = ec_params();
    params.retain(|p| !matches!(p, KeyParam::AttestationChallenge(_)));
    params.extend(certificate_validity(400));
    let result = ta.generate_key(params, None).expect("generate_key without a challenge");
    assert!(
        !has_attestation_extension(&result.certificate_chain[0].encoded_certificate),
        "a key generated without a challenge carries no attestation record"
    );

    let mut attest_params = vec![
        KeyParam::AttestationChallenge(CHALLENGE.to_vec()),
        KeyParam::AttestationApplicationId(APP_ID.to_vec()),
        creation_datetime(1_700_000_000_000),
    ];
    attest_params.extend(certificate_validity(400));
    let reattested = ta.attest_key(&result.key_blob, attest_params, None).expect("attest_key");
    let rec = record(&reattested.certificate_chain[0].encoded_certificate);
    assert_eq!(rec.challenge, CHALLENGE, "the re-attested record must carry the challenge");
    assert_eq!(rec.value_of(702), Some(0), "the re-attested key is still GENERATED");
}
