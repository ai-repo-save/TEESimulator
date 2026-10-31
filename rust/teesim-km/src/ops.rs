// Per-method shims over the TA.
//
// Each method mirrors one IKeyMintDevice / IKeyMintOperation call: it builds the
// kmr_wire request, runs it through the TA, and returns the typed response. Blob
// arguments coming from keystore2 have our marker stripped before they reach the
// TA; blobs we hand back get the marker applied so later operations route here.

use crate::{as_array, device, mark_blob, strip_marker, OpError, Ta};
use kmr_wire::keymint::{
    AttestationKey, DateTime, HardwareAuthToken, KeyCharacteristics, KeyCreationResult, KeyFormat,
    KeyParam, KeyPurpose, Tag,
};
use kmr_wire::secureclock::TimeStampToken;
use kmr_wire::{
    cbor, read_to_value, AbortRequest, AbortResponse, AsCborValue, BeginRequest, BeginResponse,
    Code, DeleteKeyRequest, DeleteKeyResponse, EarlyBootEndedRequest, EarlyBootEndedResponse,
    FinishRequest, FinishResponse, GenerateKeyRequest, GenerateKeyResponse,
    GetKeyCharacteristicsRequest, GetKeyCharacteristicsResponse, ImportKeyRequest, ImportKeyResponse,
    InternalBeginResult, KeyMintOperation, SetAdditionalAttestationInfoRequest,
    SetAdditionalAttestationInfoResponse, UpdateAadRequest, UpdateAadResponse, UpdateRequest,
    UpdateResponse, UpgradeKeyRequest, UpgradeKeyResponse,
};

/// KeyMint `ErrorCode::UnknownError`, used for local (non-TA) failures.
const ERR_UNKNOWN: i32 = -1000;

impl Ta {
    /// Encode `req`, run it through the TA, and decode the typed response.
    ///
    /// Mirrors kmr-hal's channel framing: the request is `[opcode, req]` and the
    /// reply is `[error_code, [[op_type, rsp]]]`.
    fn perform<Req, Rsp>(&mut self, req: Req) -> Result<Rsp, OpError>
    where
        Req: AsCborValue + Code<KeyMintOperation>,
        Rsp: AsCborValue + Code<KeyMintOperation>,
    {
        let local = |m: String| OpError { code: ERR_UNKNOWN, msg: m };

        let req_arr = cbor::value::Value::Array(vec![
            <Req>::CODE.to_cbor_value().map_err(|e| local(format!("{e:?}")))?,
            req.to_cbor_value().map_err(|e| local(format!("{e:?}")))?,
        ]);
        let mut req_data = Vec::new();
        cbor::ser::into_writer(&req_arr, &mut req_data).map_err(|e| local(format!("encode: {e:?}")))?;

        let rsp = self.inner.process(&req_data);

        let mut top = as_array(read_to_value(&rsp).map_err(|e| local(format!("{e:?}")))?, 2)
            .map_err(&local)?;
        let opt_response = top.remove(1);
        let error_code = i32::from_cbor_value(top.remove(0)).map_err(|e| local(format!("{e:?}")))?;
        if error_code != 0 {
            return Err(OpError { code: error_code, msg: format!("TA error {error_code}") });
        }
        let mut one = as_array(opt_response, 1).map_err(&local)?;
        let mut inner = as_array(one.remove(0), 2).map_err(&local)?;
        let resp_value = inner.remove(1);
        let op_type =
            KeyMintOperation::from_cbor_value(inner.remove(0)).map_err(|e| local(format!("{e:?}")))?;
        if op_type != <Rsp>::CODE {
            return Err(local(format!("unexpected op_type {op_type:?}")));
        }
        Rsp::from_cbor_value(resp_value).map_err(|e| local(format!("{e:?}")))
    }

    /// generateKey. The returned key blob carries our marker. This TA instance is fixed at one
    /// security level, so the record's `attestationSecurityLevel` and version come from the instance
    /// the request was routed to — no per-request override.
    pub fn generate_key(
        &mut self,
        mut key_params: Vec<KeyParam>,
        attestation_key: Option<AttestationKey>,
    ) -> Result<KeyCreationResult, OpError> {
        log::debug!(
            "generate_key: security_level={:?}, attest_key={}",
            self.inner.security_level(),
            attestation_key.is_some()
        );
        ensure_creation_datetime(&mut key_params);
        self.ensure_keymaster_leaf_validity(&mut key_params);
        let resp: Result<GenerateKeyResponse, OpError> =
            self.perform(GenerateKeyRequest { key_params, attestation_key });
        let ret = resp?.ret;
        crate::resign::log_chain("generate_key result", &ret.certificate_chain);
        Ok(marked_result(ret))
    }

    /// attestKey on an existing TA blob: same public key, new attestation record.
    pub fn attest_key(
        &mut self,
        key_blob: &[u8],
        mut key_params: Vec<KeyParam>,
        attestation_key: Option<AttestationKey>,
    ) -> Result<KeyCreationResult, OpError> {
        log::info!(
            "teesim_km: attest_key: {} param(s), blob_len={}",
            key_params.len(),
            key_blob.len()
        );
        ensure_creation_datetime(&mut key_params);
        self.ensure_keymaster_leaf_validity(&mut key_params);
        let ret = self
            .inner
            .attest_existing_key(strip_marker(key_blob), &key_params, attestation_key)
            .map_err(|e| {
                let code = match e.kind() {
                    kmr_common::ErrorKind::Hal(c, _) => *c as i32,
                    _ => ERR_UNKNOWN,
                };
                log::error!("teesim_km: attest_key failed: {e:?}");
                OpError { code, msg: format!("{e:?}") }
            })?;
        crate::resign::log_chain("teesim_km: attest_key result", &ret.certificate_chain);
        Ok(marked_result(ret))
    }

    /// importKey. The returned key blob carries our marker. As with `generate_key`, the attestation
    /// level and version follow this fixed-level TA instance.
    pub fn import_key(
        &mut self,
        mut key_params: Vec<KeyParam>,
        key_format: KeyFormat,
        key_data: Vec<u8>,
        attestation_key: Option<AttestationKey>,
    ) -> Result<KeyCreationResult, OpError> {
        log::debug!(
            "import_key: format={:?}, {} key bytes, security_level={:?}, attest_key={}",
            key_format,
            key_data.len(),
            self.inner.security_level(),
            attestation_key.is_some()
        );
        ensure_creation_datetime(&mut key_params);
        self.ensure_keymaster_leaf_validity(&mut key_params);
        let resp: Result<ImportKeyResponse, OpError> =
            self.perform(ImportKeyRequest { key_params, key_format, key_data, attestation_key });
        let ret = resp?.ret;
        crate::resign::log_chain("import_key result", &ret.certificate_chain);
        Ok(marked_result(ret))
    }

    /// begin. `key_blob` is a marked blob; the marker is stripped before use.
    pub fn begin(
        &mut self,
        purpose: KeyPurpose,
        key_blob: &[u8],
        params: Vec<KeyParam>,
        auth_token: Option<HardwareAuthToken>,
    ) -> Result<InternalBeginResult, OpError> {
        let resp: BeginResponse = self.perform(BeginRequest {
            purpose,
            key_blob: strip_marker(key_blob).to_vec(),
            params,
            auth_token,
        })?;
        Ok(resp.ret)
    }

    /// update on an in-progress operation.
    pub fn update(
        &mut self,
        op_handle: i64,
        input: Vec<u8>,
        auth_token: Option<HardwareAuthToken>,
        timestamp_token: Option<TimeStampToken>,
    ) -> Result<Vec<u8>, OpError> {
        let resp: UpdateResponse =
            self.perform(UpdateRequest { op_handle, input, auth_token, timestamp_token })?;
        Ok(resp.ret)
    }

    /// updateAad on an in-progress operation.
    pub fn update_aad(
        &mut self,
        op_handle: i64,
        input: Vec<u8>,
        auth_token: Option<HardwareAuthToken>,
        timestamp_token: Option<TimeStampToken>,
    ) -> Result<(), OpError> {
        let _: UpdateAadResponse =
            self.perform(UpdateAadRequest { op_handle, input, auth_token, timestamp_token })?;
        Ok(())
    }

    /// finish an operation.
    pub fn finish(
        &mut self,
        op_handle: i64,
        input: Option<Vec<u8>>,
        signature: Option<Vec<u8>>,
        auth_token: Option<HardwareAuthToken>,
        timestamp_token: Option<TimeStampToken>,
        confirmation_token: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, OpError> {
        let resp: FinishResponse = self.perform(FinishRequest {
            op_handle,
            input,
            signature,
            auth_token,
            timestamp_token,
            confirmation_token,
        })?;
        Ok(resp.ret)
    }

    /// abort an operation.
    pub fn abort(&mut self, op_handle: i64) -> Result<(), OpError> {
        let _: AbortResponse = self.perform(AbortRequest { op_handle })?;
        Ok(())
    }

    /// earlyBootEnded: latch the end of early boot so our EARLY_BOOT_ONLY keys stop working, matching
    /// the transition keystore2 signals to the real HAL.
    pub fn early_boot_ended(&mut self) -> Result<(), OpError> {
        log::info!("early_boot_ended");
        let _: EarlyBootEndedResponse = self.perform(EarlyBootEndedRequest {})?;
        Ok(())
    }

    /// setAdditionalAttestationInfo: record info (e.g. MODULE_HASH) that keys attested by this TA must
    /// carry, so our attestations match what keystore2 pushes to the real HAL.
    pub fn set_additional_attestation_info(
        &mut self,
        info: Vec<KeyParam>,
    ) -> Result<(), OpError> {
        log::debug!("set_additional_attestation_info");
        let _: SetAdditionalAttestationInfoResponse =
            self.perform(SetAdditionalAttestationInfoRequest { info })?;
        Ok(())
    }

    /// deleteKey. `key_blob` is a marked blob.
    pub fn delete_key(&mut self, key_blob: &[u8]) -> Result<(), OpError> {
        log::debug!("delete_key: blob_len={}", key_blob.len());
        let _: DeleteKeyResponse =
            self.perform(DeleteKeyRequest { key_blob: strip_marker(key_blob).to_vec() })?;
        Ok(())
    }

    /// upgradeKey. Consumes a marked blob and returns a freshly marked one.
    pub fn upgrade_key(
        &mut self,
        key_blob: &[u8],
        upgrade_params: Vec<KeyParam>,
    ) -> Result<Vec<u8>, OpError> {
        log::debug!(
            "upgrade_key: blob_len={}",
            key_blob.len()
        );
        let resp: UpgradeKeyResponse = self.perform(UpgradeKeyRequest {
            key_blob_to_upgrade: strip_marker(key_blob).to_vec(),
            upgrade_params,
        })?;
        Ok(mark_blob(&resp.ret))
    }

    /// getKeyCharacteristics. `key_blob` is a marked blob.
    pub fn get_key_characteristics(
        &mut self,
        key_blob: &[u8],
        app_id: Vec<u8>,
        app_data: Vec<u8>,
    ) -> Result<Vec<KeyCharacteristics>, OpError> {
        log::debug!("get_key_characteristics: blob_len={}", key_blob.len());
        let resp: GetKeyCharacteristicsResponse = self.perform(GetKeyCharacteristicsRequest {
            key_blob: strip_marker(key_blob).to_vec(),
            app_id,
            app_data,
        })?;
        Ok(resp.ret)
    }
}

impl Ta {
    /// KeyMint `generateKey` requires `CERTIFICATE_NOT_*`. Keystore1 never sends those tags.
    /// `IKeymasterDevice.hal` attestKey sets X.509 validity from `ACTIVE_DATETIME` or
    /// `CREATION_DATETIME`, and `USAGE_EXPIRE_DATETIME` or the batch attestation certificate
    /// expiry. Applied only when the TA reports a pre-KeyMint attestation version.
    fn ensure_keymaster_leaf_validity(&self, params: &mut Vec<KeyParam>) {
        if self.inner.attestation_version() >= 100 {
            return;
        }
        let has_not_before = params.iter().any(|p| matches!(p, KeyParam::CertificateNotBefore(_)));
        let has_not_after = params.iter().any(|p| matches!(p, KeyParam::CertificateNotAfter(_)));
        if has_not_before && has_not_after {
            return;
        }
        let active = params.iter().find_map(|p| match p {
            KeyParam::ActiveDatetime(d) => Some(d.ms_since_epoch),
            _ => None,
        });
        let creation = params.iter().find_map(|p| match p {
            KeyParam::CreationDatetime(d) => Some(d.ms_since_epoch),
            _ => None,
        });
        let usage_expire = params.iter().find_map(|p| match p {
            KeyParam::UsageExpireDatetime(d) => Some(d.ms_since_epoch),
            _ => None,
        });
        let prefer_ec = params.iter().any(|p| matches!(p, KeyParam::Algorithm(kmr_wire::keymint::Algorithm::Ec)));
        let batch_expire = self.sign_info.batch_not_after_ms(prefer_ec);
        if !has_not_before {
            // ensure_creation_datetime() has already stamped CREATION_DATETIME, so this resolves;
            // IKeymasterDevice.hal prefers ACTIVE_DATETIME when the request carries one.
            let ms = active.or(creation).unwrap_or(0);
            params.push(KeyParam::CertificateNotBefore(DateTime { ms_since_epoch: ms }));
        }
        if !has_not_after {
            let not_after = usage_expire.or(batch_expire);
            if not_after.is_none() {
                log::warn!(
                    "ensure_keymaster_leaf_validity: neither USAGE_EXPIRE_DATETIME nor a readable \
                     keybox batch notAfter is present; CERTIFICATE_NOT_AFTER falls back to the epoch"
                );
            }
            params.push(KeyParam::CertificateNotAfter(DateTime {
                ms_since_epoch: not_after.unwrap_or(0),
            }));
        }
    }
}

/// Stamp `Tag::CREATION_DATETIME` into the parameters when keystore2 has not already done so.
///
/// On a genuine KeyMint device keystore2 always adds this tag before generateKey/importKey
/// (`add_required_parameters`, gated on `hw_info.versionNumber >= 100`), and the reference TA both
/// records it in the software-enforced attestation list and requires it whenever `INCLUDE_UNIQUE_ID`
/// is set (unique-id derivation folds in the creation time). This device's KeyMaster 4.0 HAL is
/// exposed to keystore2 through an emulation wrapper that reports version 40, so keystore2 skips the
/// tag entirely: unique-id requests (Google Wallet / device-ID attestation) then fail with
/// `INVALID_ARGUMENT`, and even ordinary attestations omit `creationDateTime` that a real device
/// would carry. Adding it here reproduces the value keystore2 would have supplied.
///
/// Left untouched if the tag is already present, so a genuine KeyMint backend's value always wins.
fn ensure_creation_datetime(params: &mut Vec<KeyParam>) {
    if params.iter().any(|p| p.tag() == Tag::CreationDatetime) {
        return;
    }
    let ms_since_epoch = device::realtime_ms_since_epoch();
    log::debug!(
        "ensure_creation_datetime: adding creation_datetime={ms_since_epoch} (keystore2 omitted it)"
    );
    params.push(KeyParam::CreationDatetime(DateTime { ms_since_epoch }));
}

/// Apply our marker to the key blob inside a creation result.
fn marked_result(mut r: KeyCreationResult) -> KeyCreationResult {
    r.key_blob = mark_blob(&r.key_blob);
    r
}
