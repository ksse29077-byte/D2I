use crate::windows_binding::{WindowsHostBinding, WindowsWfpBrowserEgressPolicy};
use crate::{
    hash_value, hex_decode_array, hex_encode, json_bytes, validate_hash, validate_text,
    validate_token, DesktopError, SignedWindowsWfpFunctionalAttestationV2,
    WindowsWfpBrowserEgressObservation,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const WINDOWS_WFP_PROVIDER_GUID: &str = "effa5c68-709d-4311-9a4c-1ff4f3c20bf0";
pub const WINDOWS_WFP_SUBLAYER_GUID: &str = "f328c32f-dba5-4527-bcc0-c3763b734590";
pub const WINDOWS_WFP_FILTER_GUIDS: [&str; 4] = [
    "769fcfb8-8dc3-4685-8e70-49deff9012d9",
    "faab358b-8445-488e-8836-ce1173cd6000",
    "5433444c-fc9f-4845-9139-f83e316cbac2",
    "17ddc305-ac3a-4799-886e-0990bed1f105",
];
pub const WINDOWS_WFP_VERIFIER_NETWORK_FILTER_GUIDS: [&str; 4] = [
    "19fe4430-e15a-4724-9f69-fa4094f91f68",
    "2a442793-137e-4e30-8dfd-36e6ec51f73e",
    "32525113-1bb9-4d36-b334-28049fe0e137",
    "4ab70e6d-4d44-43dc-98c2-c7872094039d",
];

const MAX_REQUEST_LIFETIME_SECONDS: u64 = 30;
const MAX_RECEIPT_LIFETIME_SECONDS: u64 = 30;
const MAX_CLOCK_SKEW_SECONDS: u64 = 5;
const EXPECTED_OBJECT_COUNT: usize = 10;

/// The only operation accepted by the dedicated verifier endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WfpVerifierOperation {
    VerifyD2iBrowserEgressV1,
}

/// Installation-time identity pinned into the WFP policy and runtime binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsWfpVerifierBrokerBinding {
    pub schema_version: u32,
    pub service_name: String,
    pub service_sid: String,
    pub pipe_name: String,
    pub verifier_build_id: String,
    pub verifier_executable: String,
    pub verifier_executable_hash: String,
    pub signer_key_id: String,
    pub signer_public_key: String,
}

/// Machine-DPAPI envelope for the verifier's dedicated Ed25519 key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsProtectedWfpVerifierKey {
    pub schema_version: u32,
    pub key_id: String,
    pub signer_public_key: String,
    pub protected_private_key_hex: String,
}

impl WindowsProtectedWfpVerifierKey {
    fn validate(&self) -> Result<(), DesktopError> {
        if self.schema_version != 1 {
            return Err(DesktopError::Invalid(
                "protected WFP verifier key schema_version must be 1".to_owned(),
            ));
        }
        validate_token(&self.key_id, "protected WFP verifier key ID")?;
        validate_public_key(&self.signer_public_key)?;
        let protected = decode_hex(&self.protected_private_key_hex)?;
        if protected.is_empty() || protected.len() > 4096 {
            return Err(DesktopError::Invalid(
                "protected WFP verifier key envelope is outside bounds".to_owned(),
            ));
        }
        Ok(())
    }
}

impl WindowsWfpVerifierBrokerBinding {
    pub(crate) fn validate(&self) -> Result<(), DesktopError> {
        if self.schema_version != 1 {
            return Err(DesktopError::Invalid(
                "WFP verifier broker binding schema_version must be 1".to_owned(),
            ));
        }
        validate_token(&self.service_name, "WFP verifier service_name")?;
        if self.service_name.len() > 80 {
            return Err(DesktopError::Invalid(
                "WFP verifier service_name exceeds 80 bytes".to_owned(),
            ));
        }
        validate_service_sid(&self.service_sid)?;
        validate_token(&self.pipe_name, "WFP verifier pipe_name")?;
        if self.pipe_name.len() > 80 {
            return Err(DesktopError::Invalid(
                "WFP verifier pipe_name exceeds 80 bytes".to_owned(),
            ));
        }
        validate_token(&self.verifier_build_id, "WFP verifier build_id")?;
        validate_absolute_windows_path(&self.verifier_executable, "WFP verifier executable")?;
        validate_hash(
            &self.verifier_executable_hash,
            "WFP verifier executable hash",
        )?;
        validate_token(&self.signer_key_id, "WFP verifier signer key ID")?;
        validate_public_key(&self.signer_public_key)?;
        Ok(())
    }
}

/// Exact object identifiers a verifier request is allowed to name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WfpExpectedObjectGuids {
    pub provider: String,
    pub sublayer: String,
    pub filters: [String; 4],
    pub verifier_network_filters: [String; 4],
}

impl WfpExpectedObjectGuids {
    /// Returns the immutable D2I browser-egress object set.
    pub fn d2i_browser_egress() -> Self {
        Self {
            provider: WINDOWS_WFP_PROVIDER_GUID.to_owned(),
            sublayer: WINDOWS_WFP_SUBLAYER_GUID.to_owned(),
            filters: WINDOWS_WFP_FILTER_GUIDS.map(str::to_owned),
            verifier_network_filters: WINDOWS_WFP_VERIFIER_NETWORK_FILTER_GUIDS.map(str::to_owned),
        }
    }

    fn validate(&self) -> Result<(), DesktopError> {
        if self != &Self::d2i_browser_egress() {
            return Err(DesktopError::AccessDenied(
                "WFP verifier request contains a non-fixed object GUID".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Bounded, secret-free request sent by the approved AppContainer runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WfpVerificationRequest {
    pub schema_version: u32,
    pub operation: WfpVerifierOperation,
    pub request_id: String,
    pub one_time_challenge: String,
    pub relay_process_id: u32,
    pub appcontainer_process_id: u32,
    pub expected_runtime_binding_digest: String,
    pub expected_machine_session_binding: WindowsHostBinding,
    pub expected_wfp_policy_digest: String,
    pub expected_object_guids: WfpExpectedObjectGuids,
    pub expected_edge_hash: String,
    pub expected_edge_driver_hash: String,
    pub expected_functional_report_hash: String,
    pub expected_attestation_hash: String,
    pub issued_at_unix_seconds: u64,
    pub deadline_unix_seconds: u64,
}

impl WfpVerificationRequest {
    /// Validates request bounds without trusting any requested value.
    pub fn validate(&self, now_unix_seconds: u64) -> Result<(), DesktopError> {
        if self.schema_version != 1 {
            return Err(DesktopError::Invalid(
                "WFP verification request schema_version must be 1".to_owned(),
            ));
        }
        validate_token(&self.request_id, "WFP verifier request ID")?;
        validate_challenge(&self.one_time_challenge)?;
        if self.relay_process_id == 0
            || self.appcontainer_process_id == 0
            || self.relay_process_id == self.appcontainer_process_id
        {
            return Err(DesktopError::Invalid(
                "WFP verifier relay and AppContainer process IDs are invalid".to_owned(),
            ));
        }
        for (value, field) in [
            (
                &self.expected_runtime_binding_digest,
                "expected runtime binding digest",
            ),
            (
                &self.expected_wfp_policy_digest,
                "expected WFP policy digest",
            ),
            (&self.expected_edge_hash, "expected Edge hash"),
            (&self.expected_edge_driver_hash, "expected EdgeDriver hash"),
            (
                &self.expected_functional_report_hash,
                "expected functional report hash",
            ),
            (&self.expected_attestation_hash, "expected attestation hash"),
        ] {
            validate_hash(value, field)?;
        }
        self.expected_machine_session_binding.validate()?;
        self.expected_object_guids.validate()?;
        validate_short_lifetime(
            self.issued_at_unix_seconds,
            self.deadline_unix_seconds,
            MAX_REQUEST_LIFETIME_SECONDS,
            "WFP verification request",
        )?;
        if now_unix_seconds.saturating_add(MAX_CLOCK_SKEW_SECONDS) < self.issued_at_unix_seconds
            || now_unix_seconds > self.deadline_unix_seconds
        {
            return Err(DesktopError::Replay(
                "WFP verification request is stale or not yet valid".to_owned(),
            ));
        }
        Ok(())
    }
}

/// One fixed WFP object comparison included in the signed receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WfpObjectVerificationResult {
    pub object_kind: String,
    pub object_guid: String,
    pub exact_fields_verified: bool,
    pub acl_verified: bool,
}

/// Result classification signed by the verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WfpVerificationStatus {
    Verified,
    Rejected,
}

/// Signed, canonical verifier result returned to the AppContainer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedWfpVerificationReceipt {
    pub schema_version: u32,
    pub request_id: String,
    pub one_time_challenge: String,
    pub relay_process_id: u32,
    pub appcontainer_process_id: u32,
    pub verifier_identity: String,
    pub verifier_build_id: String,
    pub verifier_executable_hash: String,
    pub runtime_binding_digest: String,
    pub machine_session_binding: WindowsHostBinding,
    pub verified_policy_canonical_digest: String,
    pub object_guids: WfpExpectedObjectGuids,
    pub object_results: Vec<WfpObjectVerificationResult>,
    pub object_acl_verification_passed: bool,
    pub verifier_network_egress_denied: bool,
    pub edge_hash: String,
    pub edge_driver_hash: String,
    pub source_functional_report_hash: String,
    pub attestation_hash: String,
    pub verification_started_at_unix_ms: u64,
    pub verification_completed_at_unix_ms: u64,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub monotonic_sequence: u64,
    pub result_status: WfpVerificationStatus,
    pub failure_code: String,
    pub signer_key_id: String,
    pub signer_public_key: String,
    pub signature_hex: String,
}

impl SignedWfpVerificationReceipt {
    /// Returns the canonical SHA-256 identity of the complete signed receipt.
    pub fn receipt_hash(&self) -> Result<String, DesktopError> {
        validate_receipt_shape(self)?;
        hash_value(self)
    }
}

/// Verifies the receipt's canonical Ed25519 signature without trusting its
/// signer as an installation authority.
pub fn verify_wfp_verification_receipt_signature(
    receipt: &SignedWfpVerificationReceipt,
) -> Result<(), DesktopError> {
    validate_receipt_shape(receipt)?;
    let public_key = VerifyingKey::from_bytes(&hex_decode_array::<32>(&receipt.signer_public_key)?)
        .map_err(|error| DesktopError::Integrity(error.to_string()))?;
    let signature = Signature::from_bytes(&hex_decode_array::<64>(&receipt.signature_hex)?);
    public_key
        .verify(&json_bytes(&receipt_payload(receipt))?, &signature)
        .map_err(|_| DesktopError::Integrity("WFP receipt signature is invalid".to_owned()))
}

#[derive(Serialize)]
struct SignedReceiptPayload<'a> {
    schema_version: u32,
    request_id: &'a str,
    one_time_challenge: &'a str,
    relay_process_id: u32,
    appcontainer_process_id: u32,
    verifier_identity: &'a str,
    verifier_build_id: &'a str,
    verifier_executable_hash: &'a str,
    runtime_binding_digest: &'a str,
    machine_session_binding: &'a WindowsHostBinding,
    verified_policy_canonical_digest: &'a str,
    object_guids: &'a WfpExpectedObjectGuids,
    object_results: &'a [WfpObjectVerificationResult],
    object_acl_verification_passed: bool,
    verifier_network_egress_denied: bool,
    edge_hash: &'a str,
    edge_driver_hash: &'a str,
    source_functional_report_hash: &'a str,
    attestation_hash: &'a str,
    verification_started_at_unix_ms: u64,
    verification_completed_at_unix_ms: u64,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    monotonic_sequence: u64,
    result_status: WfpVerificationStatus,
    failure_code: &'a str,
    signer_key_id: &'a str,
    signer_public_key: &'a str,
}

/// Fixed installation configuration read by the dedicated broker service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsWfpVerifierBrokerServiceConfiguration {
    pub schema_version: u32,
    pub broker: WindowsWfpVerifierBrokerBinding,
    pub approved_appcontainer_sid: String,
    pub approved_runtime_executable_hash: String,
    pub expected_runtime_binding_digest: String,
    pub expected_machine_session_binding: WindowsHostBinding,
    pub policy: WindowsWfpBrowserEgressPolicy,
    pub edge_driver_hash: String,
    pub functional_report_hash: String,
    pub attestation_hash: String,
    pub protected_signing_key_path: String,
}

impl WindowsWfpVerifierBrokerServiceConfiguration {
    /// Validates the immutable allowlist consumed by the broker.
    pub fn validate(&self) -> Result<(), DesktopError> {
        if self.schema_version != 1 {
            return Err(DesktopError::Invalid(
                "WFP verifier broker service configuration schema_version must be 1".to_owned(),
            ));
        }
        self.broker.validate()?;
        validate_appcontainer_sid(&self.approved_appcontainer_sid)?;
        for (value, field) in [
            (
                &self.approved_runtime_executable_hash,
                "approved runtime executable hash",
            ),
            (
                &self.expected_runtime_binding_digest,
                "expected runtime binding digest",
            ),
            (&self.edge_driver_hash, "broker EdgeDriver hash"),
            (
                &self.functional_report_hash,
                "broker functional report hash",
            ),
            (&self.attestation_hash, "broker attestation hash"),
        ] {
            validate_hash(value, field)?;
        }
        self.expected_machine_session_binding.validate()?;
        self.policy.validate()?;
        if self.policy.verifier_profile_sid != self.approved_appcontainer_sid {
            return Err(DesktopError::Integrity(
                "broker AppContainer SID differs from WFP policy".to_owned(),
            ));
        }
        if self.policy.browser_executable_hash.is_empty() {
            return Err(DesktopError::Invalid(
                "broker policy has no Edge hash".to_owned(),
            ));
        }
        validate_absolute_windows_path(
            &self.protected_signing_key_path,
            "broker protected signing key path",
        )?;
        Ok(())
    }

    /// Compares a request only with installation-pinned values.
    pub fn authorize_request(
        &self,
        request: &WfpVerificationRequest,
        now_unix_seconds: u64,
    ) -> Result<(), DesktopError> {
        self.validate()?;
        request.validate(now_unix_seconds)?;
        let attestation_policy_hash = self.policy.policy_hash()?;
        if request.expected_runtime_binding_digest != self.expected_runtime_binding_digest
            || request.expected_machine_session_binding != self.expected_machine_session_binding
            || request.expected_wfp_policy_digest != attestation_policy_hash
            || request.expected_edge_hash != self.policy.browser_executable_hash
            || request.expected_edge_driver_hash != self.edge_driver_hash
            || request.expected_functional_report_hash != self.functional_report_hash
            || request.expected_attestation_hash != self.attestation_hash
        {
            return Err(DesktopError::AccessDenied(
                "WFP verification request differs from the installed allowlist".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Protects a verifier signing key with machine DPAPI. The output file must
/// additionally be ACL-bound to the verifier Service SID.
pub fn protect_wfp_verifier_signing_key(
    key_id: String,
    signing_key: &SigningKey,
) -> Result<WindowsProtectedWfpVerifierKey, DesktopError> {
    validate_token(&key_id, "WFP verifier key ID")?;
    let signer_public_key = hex_encode(&signing_key.verifying_key().to_bytes());
    let purpose = verifier_key_purpose(&key_id, &signer_public_key)?;
    let protected = d2i_windows_host::protect_local_machine(signing_key.as_bytes(), &purpose)
        .map_err(|error| {
            DesktopError::AccessDenied(format!(
                "machine protection of WFP verifier key failed: {error}"
            ))
        })?;
    let envelope = WindowsProtectedWfpVerifierKey {
        schema_version: 1,
        key_id,
        signer_public_key,
        protected_private_key_hex: hex_encode(&protected),
    };
    envelope.validate()?;
    Ok(envelope)
}

/// Opens a machine-bound verifier key only after checking its purpose and
/// expected public identity.
pub fn unprotect_wfp_verifier_signing_key(
    envelope: &WindowsProtectedWfpVerifierKey,
    expected_key_id: &str,
    expected_public_key: &str,
) -> Result<SigningKey, DesktopError> {
    envelope.validate()?;
    if envelope.key_id != expected_key_id || envelope.signer_public_key != expected_public_key {
        return Err(DesktopError::Integrity(
            "protected WFP verifier key identity differs from broker binding".to_owned(),
        ));
    }
    let purpose = verifier_key_purpose(&envelope.key_id, &envelope.signer_public_key)?;
    let mut plaintext = d2i_windows_host::unprotect_local_machine(
        &decode_hex(&envelope.protected_private_key_hex)?,
        &purpose,
    )
    .map_err(|error| {
        DesktopError::AccessDenied(format!(
            "machine unprotect of WFP verifier key failed: {error}"
        ))
    })?;
    if plaintext.len() != 32 {
        plaintext.fill(0);
        return Err(DesktopError::Integrity(
            "unprotected WFP verifier key has an invalid length".to_owned(),
        ));
    }
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&plaintext);
    plaintext.fill(0);
    let key = SigningKey::from_bytes(&bytes);
    bytes.fill(0);
    if hex_encode(&key.verifying_key().to_bytes()) != envelope.signer_public_key {
        return Err(DesktopError::Integrity(
            "unprotected WFP verifier key has a different public identity".to_owned(),
        ));
    }
    Ok(key)
}

/// Creates a success receipt after the broker has exactly verified WFP state.
#[allow(clippy::too_many_arguments)]
pub fn create_signed_wfp_verification_receipt(
    configuration: &WindowsWfpVerifierBrokerServiceConfiguration,
    request: &WfpVerificationRequest,
    observation: &WindowsWfpBrowserEgressObservation,
    signing_key: &SigningKey,
    verifier_executable_hash: &str,
    verification_started_at_unix_ms: u64,
    verification_completed_at_unix_ms: u64,
    monotonic_sequence: u64,
    now_unix_seconds: u64,
) -> Result<SignedWfpVerificationReceipt, DesktopError> {
    configuration.authorize_request(request, now_unix_seconds)?;
    validate_hash(
        verifier_executable_hash,
        "observed verifier executable hash",
    )?;
    if verifier_executable_hash != configuration.broker.verifier_executable_hash
        || observation.policy_hash != request.expected_wfp_policy_digest
        || observation.browser_executable_hash != request.expected_edge_hash
        || observation.provider_key != request.expected_object_guids.provider
        || observation.sublayer_key != request.expected_object_guids.sublayer
        || observation.filter_keys != request.expected_object_guids.filters
        || observation.verifier_sid != configuration.broker.service_sid
    {
        return Err(DesktopError::Integrity(
            "live WFP observation differs from the broker request or identity".to_owned(),
        ));
    }
    if verification_started_at_unix_ms == 0
        || verification_completed_at_unix_ms < verification_started_at_unix_ms
        || monotonic_sequence == 0
    {
        return Err(DesktopError::Invalid(
            "WFP receipt timing or monotonic sequence is invalid".to_owned(),
        ));
    }
    let object_results = successful_object_results(&request.expected_object_guids);
    let signer_public_key = hex_encode(&signing_key.verifying_key().to_bytes());
    if signer_public_key != configuration.broker.signer_public_key {
        return Err(DesktopError::Integrity(
            "broker signing key differs from installation binding".to_owned(),
        ));
    }
    let expires_at_unix_seconds = now_unix_seconds
        .checked_add(MAX_RECEIPT_LIFETIME_SECONDS)
        .ok_or_else(|| DesktopError::Invalid("WFP receipt expiry overflow".to_owned()))?
        .min(request.deadline_unix_seconds);
    if expires_at_unix_seconds <= now_unix_seconds {
        return Err(DesktopError::Replay(
            "WFP request deadline elapsed before receipt creation".to_owned(),
        ));
    }
    let mut receipt = SignedWfpVerificationReceipt {
        schema_version: 1,
        request_id: request.request_id.clone(),
        one_time_challenge: request.one_time_challenge.clone(),
        relay_process_id: request.relay_process_id,
        appcontainer_process_id: request.appcontainer_process_id,
        verifier_identity: configuration.broker.service_sid.clone(),
        verifier_build_id: configuration.broker.verifier_build_id.clone(),
        verifier_executable_hash: verifier_executable_hash.to_owned(),
        runtime_binding_digest: request.expected_runtime_binding_digest.clone(),
        machine_session_binding: request.expected_machine_session_binding.clone(),
        verified_policy_canonical_digest: observation.policy_hash.clone(),
        object_guids: request.expected_object_guids.clone(),
        object_results,
        object_acl_verification_passed: true,
        verifier_network_egress_denied: true,
        edge_hash: request.expected_edge_hash.clone(),
        edge_driver_hash: request.expected_edge_driver_hash.clone(),
        source_functional_report_hash: request.expected_functional_report_hash.clone(),
        attestation_hash: request.expected_attestation_hash.clone(),
        verification_started_at_unix_ms,
        verification_completed_at_unix_ms,
        issued_at_unix_seconds: now_unix_seconds,
        expires_at_unix_seconds,
        monotonic_sequence,
        result_status: WfpVerificationStatus::Verified,
        failure_code: "none".to_owned(),
        signer_key_id: configuration.broker.signer_key_id.clone(),
        signer_public_key,
        signature_hex: String::new(),
    };
    receipt.signature_hex = hex_encode(
        &signing_key
            .sign(&json_bytes(&receipt_payload(&receipt))?)
            .to_bytes(),
    );
    validate_receipt_shape(&receipt)?;
    Ok(receipt)
}

/// One-call replay state owned by the runtime binding probe.
#[derive(Debug, Default)]
pub struct WfpReceiptReplayLedger {
    consumed_challenges: BTreeSet<String>,
    consumed_receipts: BTreeSet<String>,
    last_monotonic_sequence: Option<u64>,
}

impl WfpReceiptReplayLedger {
    /// Independently validates and consumes a receipt.
    pub fn validate_and_consume(
        &mut self,
        receipt: &SignedWfpVerificationReceipt,
        request: &WfpVerificationRequest,
        broker: &WindowsWfpVerifierBrokerBinding,
        functional_attestation: &SignedWindowsWfpFunctionalAttestationV2,
        now_unix_seconds: u64,
    ) -> Result<String, DesktopError> {
        validate_receipt_shape(receipt)?;
        broker.validate()?;
        request.validate(now_unix_seconds)?;
        if receipt.signer_key_id != broker.signer_key_id
            || receipt.signer_public_key != broker.signer_public_key
            || receipt.verifier_identity != broker.service_sid
            || receipt.verifier_build_id != broker.verifier_build_id
            || receipt.verifier_executable_hash != broker.verifier_executable_hash
        {
            return Err(DesktopError::Integrity(
                "WFP receipt signer or verifier binding differs".to_owned(),
            ));
        }
        verify_wfp_verification_receipt_signature(receipt)?;
        if receipt.request_id != request.request_id
            || receipt.one_time_challenge != request.one_time_challenge
            || receipt.relay_process_id != request.relay_process_id
            || receipt.appcontainer_process_id != request.appcontainer_process_id
            || receipt.runtime_binding_digest != request.expected_runtime_binding_digest
            || receipt.machine_session_binding != request.expected_machine_session_binding
            || receipt.verified_policy_canonical_digest != request.expected_wfp_policy_digest
            || receipt.object_guids != request.expected_object_guids
            || receipt.edge_hash != request.expected_edge_hash
            || receipt.edge_driver_hash != request.expected_edge_driver_hash
            || receipt.source_functional_report_hash != request.expected_functional_report_hash
            || receipt.attestation_hash != request.expected_attestation_hash
        {
            return Err(DesktopError::Integrity(
                "WFP receipt differs from its one-time request".to_owned(),
            ));
        }
        if functional_attestation.runtime_binding_digest != receipt.runtime_binding_digest
            || functional_attestation.machine_binding != receipt.machine_session_binding
            || functional_attestation.policy_hash != receipt.verified_policy_canonical_digest
            || functional_attestation.browser_executable_hash != receipt.edge_hash
            || functional_attestation.driver_executable_hash != receipt.edge_driver_hash
            || functional_attestation.self_test_report_hash != receipt.source_functional_report_hash
            || functional_attestation.attestation_hash()? != receipt.attestation_hash
            || functional_attestation.provider_key != receipt.object_guids.provider
            || functional_attestation.sublayer_key != receipt.object_guids.sublayer
            || functional_attestation.filter_keys != receipt.object_guids.filters
        {
            return Err(DesktopError::Integrity(
                "WFP receipt differs from the functional attestation".to_owned(),
            ));
        }
        if receipt.result_status != WfpVerificationStatus::Verified
            || receipt.failure_code != "none"
            || !receipt.object_acl_verification_passed
            || !receipt.verifier_network_egress_denied
            || receipt.object_results.len() != EXPECTED_OBJECT_COUNT
            || receipt
                .object_results
                .iter()
                .any(|result| !result.exact_fields_verified || !result.acl_verified)
        {
            return Err(DesktopError::AccessDenied(
                "WFP receipt does not prove complete exact verification".to_owned(),
            ));
        }
        if now_unix_seconds.saturating_add(MAX_CLOCK_SKEW_SECONDS) < receipt.issued_at_unix_seconds
            || now_unix_seconds > receipt.expires_at_unix_seconds
        {
            return Err(DesktopError::Replay(
                "WFP receipt is stale or not yet valid".to_owned(),
            ));
        }
        let receipt_hash = receipt.receipt_hash()?;
        if self
            .consumed_challenges
            .contains(&receipt.one_time_challenge)
            || self.consumed_receipts.contains(&receipt_hash)
            || self
                .last_monotonic_sequence
                .is_some_and(|sequence| receipt.monotonic_sequence <= sequence)
        {
            return Err(DesktopError::Replay(
                "WFP receipt, challenge, or monotonic sequence was reused".to_owned(),
            ));
        }
        self.consumed_challenges
            .insert(receipt.one_time_challenge.clone());
        self.consumed_receipts.insert(receipt_hash.clone());
        self.last_monotonic_sequence = Some(receipt.monotonic_sequence);
        Ok(receipt_hash)
    }
}

fn successful_object_results(guids: &WfpExpectedObjectGuids) -> Vec<WfpObjectVerificationResult> {
    let mut results = vec![
        WfpObjectVerificationResult {
            object_kind: "provider".to_owned(),
            object_guid: guids.provider.clone(),
            exact_fields_verified: true,
            acl_verified: true,
        },
        WfpObjectVerificationResult {
            object_kind: "sublayer".to_owned(),
            object_guid: guids.sublayer.clone(),
            exact_fields_verified: true,
            acl_verified: true,
        },
    ];
    for (index, guid) in guids.filters.iter().enumerate() {
        results.push(WfpObjectVerificationResult {
            object_kind: format!("filter_{index}"),
            object_guid: guid.clone(),
            exact_fields_verified: true,
            acl_verified: true,
        });
    }
    for (index, guid) in guids.verifier_network_filters.iter().enumerate() {
        results.push(WfpObjectVerificationResult {
            object_kind: format!("verifier_network_filter_{index}"),
            object_guid: guid.clone(),
            exact_fields_verified: true,
            acl_verified: true,
        });
    }
    results
}

fn validate_receipt_shape(receipt: &SignedWfpVerificationReceipt) -> Result<(), DesktopError> {
    if receipt.schema_version != 1 {
        return Err(DesktopError::Invalid(
            "WFP verification receipt schema_version must be 1".to_owned(),
        ));
    }
    validate_token(&receipt.request_id, "WFP receipt request ID")?;
    validate_challenge(&receipt.one_time_challenge)?;
    if receipt.relay_process_id == 0
        || receipt.appcontainer_process_id == 0
        || receipt.relay_process_id == receipt.appcontainer_process_id
    {
        return Err(DesktopError::Invalid(
            "WFP receipt relay and AppContainer process IDs are invalid".to_owned(),
        ));
    }
    validate_service_sid(&receipt.verifier_identity)?;
    validate_token(&receipt.verifier_build_id, "WFP receipt verifier build ID")?;
    for (value, field) in [
        (
            &receipt.verifier_executable_hash,
            "receipt verifier executable hash",
        ),
        (
            &receipt.runtime_binding_digest,
            "receipt runtime binding digest",
        ),
        (
            &receipt.verified_policy_canonical_digest,
            "receipt policy digest",
        ),
        (&receipt.edge_hash, "receipt Edge hash"),
        (&receipt.edge_driver_hash, "receipt EdgeDriver hash"),
        (
            &receipt.source_functional_report_hash,
            "receipt functional report hash",
        ),
        (&receipt.attestation_hash, "receipt attestation hash"),
    ] {
        validate_hash(value, field)?;
    }
    receipt.machine_session_binding.validate()?;
    receipt.object_guids.validate()?;
    if receipt.object_results.len() != EXPECTED_OBJECT_COUNT {
        return Err(DesktopError::Invalid(
            "WFP receipt must contain exactly ten object results".to_owned(),
        ));
    }
    let expected = successful_object_results(&receipt.object_guids);
    for (observed, expected) in receipt.object_results.iter().zip(expected.iter()) {
        validate_token(&observed.object_kind, "WFP receipt object kind")?;
        if observed.object_kind != expected.object_kind
            || observed.object_guid != expected.object_guid
        {
            return Err(DesktopError::Integrity(
                "WFP receipt object result order or GUID differs".to_owned(),
            ));
        }
    }
    if receipt.verification_started_at_unix_ms == 0
        || receipt.verification_completed_at_unix_ms < receipt.verification_started_at_unix_ms
        || receipt.monotonic_sequence == 0
    {
        return Err(DesktopError::Invalid(
            "WFP receipt timing or sequence is invalid".to_owned(),
        ));
    }
    validate_short_lifetime(
        receipt.issued_at_unix_seconds,
        receipt.expires_at_unix_seconds,
        MAX_RECEIPT_LIFETIME_SECONDS,
        "WFP verification receipt",
    )?;
    validate_token(&receipt.failure_code, "WFP receipt failure code")?;
    validate_token(&receipt.signer_key_id, "WFP receipt signer key ID")?;
    validate_public_key(&receipt.signer_public_key)?;
    let _ = hex_decode_array::<64>(&receipt.signature_hex)?;
    Ok(())
}

fn receipt_payload(receipt: &SignedWfpVerificationReceipt) -> SignedReceiptPayload<'_> {
    SignedReceiptPayload {
        schema_version: receipt.schema_version,
        request_id: &receipt.request_id,
        one_time_challenge: &receipt.one_time_challenge,
        relay_process_id: receipt.relay_process_id,
        appcontainer_process_id: receipt.appcontainer_process_id,
        verifier_identity: &receipt.verifier_identity,
        verifier_build_id: &receipt.verifier_build_id,
        verifier_executable_hash: &receipt.verifier_executable_hash,
        runtime_binding_digest: &receipt.runtime_binding_digest,
        machine_session_binding: &receipt.machine_session_binding,
        verified_policy_canonical_digest: &receipt.verified_policy_canonical_digest,
        object_guids: &receipt.object_guids,
        object_results: &receipt.object_results,
        object_acl_verification_passed: receipt.object_acl_verification_passed,
        verifier_network_egress_denied: receipt.verifier_network_egress_denied,
        edge_hash: &receipt.edge_hash,
        edge_driver_hash: &receipt.edge_driver_hash,
        source_functional_report_hash: &receipt.source_functional_report_hash,
        attestation_hash: &receipt.attestation_hash,
        verification_started_at_unix_ms: receipt.verification_started_at_unix_ms,
        verification_completed_at_unix_ms: receipt.verification_completed_at_unix_ms,
        issued_at_unix_seconds: receipt.issued_at_unix_seconds,
        expires_at_unix_seconds: receipt.expires_at_unix_seconds,
        monotonic_sequence: receipt.monotonic_sequence,
        result_status: receipt.result_status,
        failure_code: &receipt.failure_code,
        signer_key_id: &receipt.signer_key_id,
        signer_public_key: &receipt.signer_public_key,
    }
}

fn validate_short_lifetime(
    issued: u64,
    expires: u64,
    maximum: u64,
    field: &str,
) -> Result<(), DesktopError> {
    if issued == 0 || expires <= issued || expires.saturating_sub(issued) > maximum {
        return Err(DesktopError::Invalid(format!(
            "{field} lifetime must be within 1..={maximum} seconds"
        )));
    }
    Ok(())
}

fn validate_challenge(value: &str) -> Result<(), DesktopError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DesktopError::Invalid(
            "WFP one-time challenge must be 32 random bytes encoded as hex".to_owned(),
        ));
    }
    Ok(())
}

fn validate_public_key(value: &str) -> Result<(), DesktopError> {
    let _ = hex_decode_array::<32>(value)?;
    Ok(())
}

fn validate_service_sid(value: &str) -> Result<(), DesktopError> {
    validate_text(value, "WFP verifier Service SID")?;
    if !value.starts_with("S-1-5-80-")
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && byte != b'-' && byte != b'S')
    {
        return Err(DesktopError::Invalid(
            "WFP verifier identity must be a dedicated Service SID".to_owned(),
        ));
    }
    Ok(())
}

fn validate_appcontainer_sid(value: &str) -> Result<(), DesktopError> {
    validate_text(value, "WFP verifier AppContainer SID")?;
    if !value.starts_with("S-1-15-2-")
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && byte != b'-' && byte != b'S')
    {
        return Err(DesktopError::Invalid(
            "WFP verifier caller must be an exact AppContainer SID".to_owned(),
        ));
    }
    Ok(())
}

fn validate_absolute_windows_path(value: &str, field: &str) -> Result<(), DesktopError> {
    validate_text(value, field)?;
    let path = std::path::Path::new(value);
    if !path.is_absolute() || value.contains('"') {
        return Err(DesktopError::Invalid(format!(
            "{field} must be an absolute quote-free path"
        )));
    }
    Ok(())
}

fn verifier_key_purpose(key_id: &str, public_key: &str) -> Result<Vec<u8>, DesktopError> {
    json_bytes(&serde_json::json!({
        "schema_version": 1,
        "purpose": "d2i.windows.wfp.verifier.receipt",
        "key_id": key_id,
        "signer_public_key": public_key,
    }))
}

fn decode_hex(value: &str) -> Result<Vec<u8>, DesktopError> {
    if value.is_empty()
        || value.len() % 2 != 0
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(DesktopError::Invalid(
            "protected WFP verifier key is not valid hex".to_owned(),
        ));
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    for offset in (0..value.len()).step_by(2) {
        output.push(
            u8::from_str_radix(&value[offset..offset + 2], 16)
                .map_err(|error| DesktopError::Invalid(error.to_string()))?,
        );
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SignedWindowsWfpFunctionalAttestationV2, WindowsWfpIpv6EgressResult};
    use jsonschema::{Draft, JSONSchema};

    const NOW: u64 = 1_000;

    struct Fixture {
        key: SigningKey,
        broker: WindowsWfpVerifierBrokerBinding,
        service: WindowsWfpVerifierBrokerServiceConfiguration,
        request: WfpVerificationRequest,
        attestation: SignedWindowsWfpFunctionalAttestationV2,
        observation: WindowsWfpBrowserEgressObservation,
    }

    impl Fixture {
        fn new() -> Self {
            let key = SigningKey::from_bytes(&[7_u8; 32]);
            let fixture_root = std::env::current_dir()
                .unwrap_or_else(|error| panic!("fixture current directory failed: {error}"));
            let verifier_executable = fixture_root
                .join("d2i-desktop-fixture.exe")
                .to_string_lossy()
                .into_owned();
            let browser_executable = fixture_root
                .join("msedge-fixture.exe")
                .to_string_lossy()
                .into_owned();
            let protected_signing_key_path = fixture_root
                .join("wfp-receipt-key.json")
                .to_string_lossy()
                .into_owned();
            let broker = WindowsWfpVerifierBrokerBinding {
                schema_version: 1,
                service_name: "D2IWfpVerifier".to_owned(),
                service_sid: "S-1-5-80-1-2-3-4-5".to_owned(),
                pipe_name: "D2IWfpVerifier".to_owned(),
                verifier_build_id: "d2i-desktop-0.9.0".to_owned(),
                verifier_executable,
                verifier_executable_hash: fixed_hash(1),
                signer_key_id: "wfp-receipt-key-1".to_owned(),
                signer_public_key: hex_encode(&key.verifying_key().to_bytes()),
            };
            let host = WindowsHostBinding {
                major_version: 10,
                minor_version: 0,
                build_number: 26_100,
                architecture: "x86_64".to_owned(),
                session_id: 3,
                user_sid: "S-1-5-21-1-2-3-1001".to_owned(),
                integrity_level_rid: 8_192,
                elevation_type: "limited".to_owned(),
                is_appcontainer: false,
            };
            let policy = WindowsWfpBrowserEgressPolicy {
                schema_version: 3,
                enforcement_id: "edge-loopback".to_owned(),
                provider_id: crate::windows_binding::WINDOWS_WFP_LOOPBACK_PROVIDER_ID.to_owned(),
                browser_executable,
                browser_executable_hash: fixed_hash(2),
                verifier_profile_name: "d2i-wfp-runtime".to_owned(),
                verifier_profile_sid: "S-1-15-2-1-2-3".to_owned(),
                policy_owner_sid: host.user_sid.clone(),
                verifier_broker: Some(broker.clone()),
            };
            let runtime_binding_digest = fixed_hash(3);
            let driver_hash = fixed_hash(4);
            let report_hash = fixed_hash(5);
            let mut attestation = SignedWindowsWfpFunctionalAttestationV2 {
                schema_version: 2,
                runtime_binding_digest: runtime_binding_digest.clone(),
                machine_binding: host.clone(),
                enforcement_id: policy.enforcement_id.clone(),
                provider_id: policy.provider_id.clone(),
                policy_hash: policy.policy_hash().unwrap_or_default(),
                provider_key: WINDOWS_WFP_PROVIDER_GUID.to_owned(),
                sublayer_key: WINDOWS_WFP_SUBLAYER_GUID.to_owned(),
                filter_keys: WINDOWS_WFP_FILTER_GUIDS.map(str::to_owned),
                browser_version: "130.0.1.2".to_owned(),
                browser_executable_hash: policy.browser_executable_hash.clone(),
                driver_version: "130.0.1.2".to_owned(),
                driver_executable_hash: driver_hash.clone(),
                edge_driver_pin_hash: fixed_hash(6),
                self_test_report_hash: report_hash.clone(),
                activation_challenge: "functional-challenge-0001".to_owned(),
                self_test_started_at_unix_ms: 990_000,
                self_test_completed_at_unix_ms: 991_000,
                issued_at_unix_seconds: 990,
                expires_at_unix_seconds: 1_200,
                ipv4_loopback_passed: true,
                ipv4_direct_ip_blocked: true,
                ipv4_dns_blocked: true,
                ipv4_redirect_blocked: true,
                ipv6_loopback_passed: true,
                ipv6_non_loopback_result: WindowsWfpIpv6EgressResult::ExplicitlyBlocked,
                browser_session_ids: BTreeSet::from(["session-1".to_owned()]),
                allowed_origins: BTreeSet::from(["http://127.0.0.1:8080".to_owned()]),
                deny_by_default: true,
                signer_key_id: "functional-key".to_owned(),
                signer_public_key: "11".repeat(32),
                signature_hex: "22".repeat(64),
            };
            let attestation_hash = attestation.attestation_hash().unwrap_or_default();
            let request = WfpVerificationRequest {
                schema_version: 1,
                operation: WfpVerifierOperation::VerifyD2iBrowserEgressV1,
                request_id: "request-1".to_owned(),
                one_time_challenge: "33".repeat(32),
                relay_process_id: 41,
                appcontainer_process_id: 42,
                expected_runtime_binding_digest: runtime_binding_digest.clone(),
                expected_machine_session_binding: host.clone(),
                expected_wfp_policy_digest: policy.policy_hash().unwrap_or_default(),
                expected_object_guids: WfpExpectedObjectGuids::d2i_browser_egress(),
                expected_edge_hash: policy.browser_executable_hash.clone(),
                expected_edge_driver_hash: driver_hash.clone(),
                expected_functional_report_hash: report_hash.clone(),
                expected_attestation_hash: attestation_hash.clone(),
                issued_at_unix_seconds: NOW,
                deadline_unix_seconds: NOW + 20,
            };
            let service = WindowsWfpVerifierBrokerServiceConfiguration {
                schema_version: 1,
                broker: broker.clone(),
                approved_appcontainer_sid: policy.verifier_profile_sid.clone(),
                approved_runtime_executable_hash: fixed_hash(7),
                expected_runtime_binding_digest: runtime_binding_digest,
                expected_machine_session_binding: host,
                policy: policy.clone(),
                edge_driver_hash: driver_hash,
                functional_report_hash: report_hash,
                attestation_hash,
                protected_signing_key_path,
            };
            let observation = WindowsWfpBrowserEgressObservation {
                schema_version: 3,
                enforcement_id: policy.enforcement_id.clone(),
                provider_id: policy.provider_id.clone(),
                policy_hash: policy.policy_hash().unwrap_or_default(),
                browser_executable: policy.browser_executable.clone(),
                browser_executable_hash: policy.browser_executable_hash.clone(),
                provider_key: WINDOWS_WFP_PROVIDER_GUID.to_owned(),
                sublayer_key: WINDOWS_WFP_SUBLAYER_GUID.to_owned(),
                filter_keys: WINDOWS_WFP_FILTER_GUIDS.map(str::to_owned),
                verifier_sid: broker.service_sid.clone(),
                policy_owner_sid: policy.policy_owner_sid.clone(),
                engine_security_descriptor_hash: fixed_hash(8),
                object_security_descriptor_hash: fixed_hash(9),
            };
            attestation.policy_hash = observation.policy_hash.clone();
            Self {
                key,
                broker,
                service,
                request,
                attestation,
                observation,
            }
        }

        fn receipt(&self) -> SignedWfpVerificationReceipt {
            create_signed_wfp_verification_receipt(
                &self.service,
                &self.request,
                &self.observation,
                &self.key,
                &self.broker.verifier_executable_hash,
                NOW * 1_000,
                NOW * 1_000 + 1,
                42,
                NOW,
            )
            .unwrap_or_else(|error| panic!("receipt fixture failed: {error}"))
        }
    }

    #[test]
    fn receipt_is_canonical_signed_and_one_shot() {
        let fixture = Fixture::new();
        let receipt = fixture.receipt();
        verify_wfp_verification_receipt_signature(&receipt)
            .unwrap_or_else(|error| panic!("receipt signature failed: {error}"));
        let first_hash = receipt
            .receipt_hash()
            .unwrap_or_else(|error| panic!("receipt hash failed: {error}"));
        assert_eq!(
            first_hash,
            receipt
                .receipt_hash()
                .unwrap_or_else(|error| panic!("receipt hash failed: {error}"))
        );
        let mut replay = WfpReceiptReplayLedger::default();
        replay
            .validate_and_consume(
                &receipt,
                &fixture.request,
                &fixture.broker,
                &fixture.attestation,
                NOW,
            )
            .unwrap_or_else(|error| panic!("valid receipt failed: {error}"));
        assert!(matches!(
            replay.validate_and_consume(
                &receipt,
                &fixture.request,
                &fixture.broker,
                &fixture.attestation,
                NOW
            ),
            Err(DesktopError::Replay(_))
        ));
    }

    #[test]
    fn request_allowlist_rejects_stale_binding_hash_and_guid_changes() {
        let fixture = Fixture::new();
        let mut cases = Vec::new();

        let mut expired = fixture.request.clone();
        expired.issued_at_unix_seconds = NOW - 40;
        expired.deadline_unix_seconds = NOW - 10;
        cases.push(expired);

        let mut relay = fixture.request.clone();
        relay.relay_process_id = 0;
        cases.push(relay);

        let mut appcontainer = fixture.request.clone();
        appcontainer.appcontainer_process_id = appcontainer.relay_process_id;
        cases.push(appcontainer);

        let mut binding = fixture.request.clone();
        binding.expected_runtime_binding_digest = fixed_hash(20);
        cases.push(binding);

        let mut machine = fixture.request.clone();
        machine.expected_machine_session_binding.session_id += 1;
        cases.push(machine);

        let mut policy = fixture.request.clone();
        policy.expected_wfp_policy_digest = fixed_hash(21);
        cases.push(policy);

        let mut edge = fixture.request.clone();
        edge.expected_edge_hash = fixed_hash(22);
        cases.push(edge);

        let mut driver = fixture.request.clone();
        driver.expected_edge_driver_hash = fixed_hash(23);
        cases.push(driver);

        let mut report = fixture.request.clone();
        report.expected_functional_report_hash = fixed_hash(24);
        cases.push(report);

        let mut attestation = fixture.request.clone();
        attestation.expected_attestation_hash = fixed_hash(25);
        cases.push(attestation);

        let mut guid = fixture.request.clone();
        guid.expected_object_guids.filters[0] = "00000000-0000-0000-0000-000000000000".to_owned();
        cases.push(guid);

        for request in cases {
            assert!(fixture.service.authorize_request(&request, NOW).is_err());
        }
    }

    #[test]
    fn receipt_tamper_stale_signer_and_context_changes_fail_closed() {
        let fixture = Fixture::new();
        let receipt = fixture.receipt();
        let mut cases = Vec::new();

        let mut challenge = receipt.clone();
        challenge.one_time_challenge = "44".repeat(32);
        cases.push(challenge);

        let mut relay = receipt.clone();
        relay.relay_process_id += 1;
        cases.push(relay);

        let mut appcontainer = receipt.clone();
        appcontainer.appcontainer_process_id += 1;
        cases.push(appcontainer);

        let mut binding = receipt.clone();
        binding.runtime_binding_digest = fixed_hash(30);
        cases.push(binding);

        let mut machine = receipt.clone();
        machine.machine_session_binding.session_id += 1;
        cases.push(machine);

        let mut policy = receipt.clone();
        policy.verified_policy_canonical_digest = fixed_hash(31);
        cases.push(policy);

        let mut edge = receipt.clone();
        edge.edge_hash = fixed_hash(32);
        cases.push(edge);

        let mut driver = receipt.clone();
        driver.edge_driver_hash = fixed_hash(33);
        cases.push(driver);

        let mut report = receipt.clone();
        report.source_functional_report_hash = fixed_hash(34);
        cases.push(report);

        let mut attestation = receipt.clone();
        attestation.attestation_hash = fixed_hash(35);
        cases.push(attestation);

        let mut guid = receipt.clone();
        guid.object_guids.provider = "00000000-0000-0000-0000-000000000000".to_owned();
        cases.push(guid);

        let mut executable = receipt.clone();
        executable.verifier_executable_hash = fixed_hash(36);
        cases.push(executable);

        let mut signer = receipt.clone();
        signer.signer_public_key = hex_encode(
            &SigningKey::from_bytes(&[9_u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        cases.push(signer);

        let mut payload = receipt.clone();
        payload.object_results[0].exact_fields_verified = false;
        cases.push(payload);

        for mutated in cases {
            let mut replay = WfpReceiptReplayLedger::default();
            assert!(replay
                .validate_and_consume(
                    &mutated,
                    &fixture.request,
                    &fixture.broker,
                    &fixture.attestation,
                    NOW,
                )
                .is_err());
        }

        let mut replay = WfpReceiptReplayLedger::default();
        assert!(replay
            .validate_and_consume(
                &receipt,
                &fixture.request,
                &fixture.broker,
                &fixture.attestation,
                receipt.expires_at_unix_seconds + 1,
            )
            .is_err());
    }

    #[test]
    fn unknown_request_fields_and_truncated_receipts_are_rejected() {
        let fixture = Fixture::new();
        let mut request = serde_json::to_value(&fixture.request)
            .unwrap_or_else(|error| panic!("request JSON failed: {error}"));
        request
            .as_object_mut()
            .unwrap_or_else(|| panic!("request is not an object"))
            .insert("arbitrary_guid".to_owned(), serde_json::json!("value"));
        assert!(serde_json::from_value::<WfpVerificationRequest>(request).is_err());

        let bytes = json_bytes(&fixture.receipt())
            .unwrap_or_else(|error| panic!("receipt JSON failed: {error}"));
        assert!(
            serde_json::from_slice::<SignedWfpVerificationReceipt>(&bytes[..bytes.len() / 2])
                .is_err()
        );
    }

    #[test]
    fn broker_artifacts_match_their_published_schemas() {
        let fixture = Fixture::new();
        validate_schema(
            "desktop/windows-wfp-browser-egress-policy.schema.json",
            &fixture.service.policy,
        );
        validate_schema(
            "desktop/windows-wfp-verifier-broker-service-configuration.schema.json",
            &fixture.service,
        );
        validate_schema(
            "desktop/windows-wfp-verification-request.schema.json",
            &fixture.request,
        );
        validate_schema(
            "desktop/windows-wfp-verification-receipt.schema.json",
            &fixture.receipt(),
        );
        validate_schema(
            "desktop/windows-wfp-verifier-broker-key.schema.json",
            &WindowsProtectedWfpVerifierKey {
                schema_version: 1,
                key_id: fixture.broker.signer_key_id.clone(),
                signer_public_key: fixture.broker.signer_public_key.clone(),
                protected_private_key_hex: "aa".to_owned(),
            },
        );
    }

    fn validate_schema(relative: &str, instance: &impl Serialize) {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas")
            .join(relative);
        let schema: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&path)
                .unwrap_or_else(|error| panic!("schema {} read failed: {error}", path.display())),
        )
        .unwrap_or_else(|error| panic!("schema {} parse failed: {error}", path.display()));
        let validator = JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema)
            .unwrap_or_else(|error| panic!("schema {} compile failed: {error}", path.display()));
        let instance = serde_json::to_value(instance)
            .unwrap_or_else(|error| panic!("schema instance serialization failed: {error}"));
        if let Err(errors) = validator.validate(&instance) {
            let errors = errors.map(|error| error.to_string()).collect::<Vec<_>>();
            panic!("schema {relative} rejected its Rust contract: {errors:?}");
        };
    }

    fn fixed_hash(marker: u8) -> String {
        format!("sha256:{marker:02x}{}", "00".repeat(31))
    }
}
