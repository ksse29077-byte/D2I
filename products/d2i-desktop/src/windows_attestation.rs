use crate::windows_binding::{
    validate_browser_scope, WindowsHostBinding, WindowsWfpBrowserEgressPolicy,
    WINDOWS_WFP_LOOPBACK_PROVIDER_ID,
};
use crate::{
    hash_value, hex_decode_array, hex_encode, json_bytes, validate_hash, validate_token,
    verify_windows_wfp_browser_egress, DesktopError, WindowsEdgeDriverPin,
    WindowsWfpBrowserEgressObservation, WindowsWfpBrowserEgressSelfTestReport,
    WindowsWfpProbeDisposition,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Maximum age of a successful report when it is signed into an attestation.
pub const WINDOWS_WFP_REPORT_MAX_AGE_SECONDS: u64 = 300;
const WINDOWS_WFP_ATTESTATION_MAX_LIFETIME_SECONDS: u64 = 300;

/// IPv6 non-loopback result bound into a functional attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsWfpIpv6EgressResult {
    Blocked,
    ExplicitlyBlocked,
}

/// Deployment-provided scope for a one-time WFP functional attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsWfpFunctionalAttestationInputV2 {
    pub schema_version: u32,
    pub runtime_binding_digest: String,
    pub machine_binding: WindowsHostBinding,
    pub browser_session_ids: BTreeSet<String>,
    pub allowed_origins: BTreeSet<String>,
    pub activation_challenge: String,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub signer_key_id: String,
}

/// Provider-signed proof that one exact WFP policy passed the v2 functional test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedWindowsWfpFunctionalAttestationV2 {
    pub schema_version: u32,
    pub runtime_binding_digest: String,
    pub machine_binding: WindowsHostBinding,
    pub enforcement_id: String,
    pub provider_id: String,
    pub policy_hash: String,
    pub provider_key: String,
    pub sublayer_key: String,
    pub filter_keys: [String; 4],
    pub browser_version: String,
    pub browser_executable_hash: String,
    pub driver_version: String,
    pub driver_executable_hash: String,
    pub edge_driver_pin_hash: String,
    pub self_test_report_hash: String,
    pub activation_challenge: String,
    pub self_test_started_at_unix_ms: u64,
    pub self_test_completed_at_unix_ms: u64,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub ipv4_loopback_passed: bool,
    pub ipv4_direct_ip_blocked: bool,
    pub ipv4_dns_blocked: bool,
    pub ipv4_redirect_blocked: bool,
    pub ipv6_loopback_passed: bool,
    pub ipv6_non_loopback_result: WindowsWfpIpv6EgressResult,
    pub browser_session_ids: BTreeSet<String>,
    pub allowed_origins: BTreeSet<String>,
    pub deny_by_default: bool,
    pub signer_key_id: String,
    pub signer_public_key: String,
    pub signature_hex: String,
}

impl SignedWindowsWfpFunctionalAttestationV2 {
    /// Computes the canonical identity of the complete signed attestation.
    pub fn attestation_hash(&self) -> Result<String, DesktopError> {
        validate_windows_wfp_functional_attestation_v2(self)?;
        hash_value(self)
    }
}

#[derive(Serialize)]
struct SignedPayload<'a> {
    schema_version: u32,
    runtime_binding_digest: &'a str,
    machine_binding: &'a WindowsHostBinding,
    enforcement_id: &'a str,
    provider_id: &'a str,
    policy_hash: &'a str,
    provider_key: &'a str,
    sublayer_key: &'a str,
    filter_keys: &'a [String; 4],
    browser_version: &'a str,
    browser_executable_hash: &'a str,
    driver_version: &'a str,
    driver_executable_hash: &'a str,
    edge_driver_pin_hash: &'a str,
    self_test_report_hash: &'a str,
    activation_challenge: &'a str,
    self_test_started_at_unix_ms: u64,
    self_test_completed_at_unix_ms: u64,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    ipv4_loopback_passed: bool,
    ipv4_direct_ip_blocked: bool,
    ipv4_dns_blocked: bool,
    ipv4_redirect_blocked: bool,
    ipv6_loopback_passed: bool,
    ipv6_non_loopback_result: WindowsWfpIpv6EgressResult,
    browser_session_ids: &'a BTreeSet<String>,
    allowed_origins: &'a BTreeSet<String>,
    deny_by_default: bool,
    signer_key_id: &'a str,
    signer_public_key: &'a str,
}

/// Verifies a fresh successful report against live WFP state and signs v2.
pub fn create_windows_wfp_functional_attestation_v2(
    policy: &WindowsWfpBrowserEgressPolicy,
    pin: &WindowsEdgeDriverPin,
    report: &WindowsWfpBrowserEgressSelfTestReport,
    input: WindowsWfpFunctionalAttestationInputV2,
    signing_key: &SigningKey,
) -> Result<SignedWindowsWfpFunctionalAttestationV2, DesktopError> {
    report.validate()?;
    pin.verify()?;
    validate_input(&input)?;
    if input.activation_challenge != report.activation_challenge {
        return Err(DesktopError::Replay(
            "functional report activation challenge differs from the requested challenge"
                .to_owned(),
        ));
    }
    require_fresh_report(report, input.issued_at_unix_seconds)?;
    let before = verify_windows_wfp_browser_egress(policy)?;
    require_report_matches(policy, pin, report, &before)?;
    let signer_public_key = hex_encode(&signing_key.verifying_key().to_bytes());
    let ipv6_non_loopback_result = match report.ipv6_non_loopback.disposition {
        WindowsWfpProbeDisposition::Blocked => WindowsWfpIpv6EgressResult::Blocked,
        WindowsWfpProbeDisposition::ExplicitlyBlocked => {
            WindowsWfpIpv6EgressResult::ExplicitlyBlocked
        }
        WindowsWfpProbeDisposition::Passed => {
            return Err(DesktopError::Integrity(
                "functional report does not prove IPv6 non-loopback denial".to_owned(),
            ));
        }
    };
    let mut attestation = SignedWindowsWfpFunctionalAttestationV2 {
        schema_version: 2,
        runtime_binding_digest: input.runtime_binding_digest,
        machine_binding: input.machine_binding,
        enforcement_id: policy.enforcement_id.clone(),
        provider_id: WINDOWS_WFP_LOOPBACK_PROVIDER_ID.to_owned(),
        policy_hash: policy.policy_hash()?,
        provider_key: before.provider_key.clone(),
        sublayer_key: before.sublayer_key.clone(),
        filter_keys: before.filter_keys.clone(),
        browser_version: pin.browser_version.clone(),
        browser_executable_hash: pin.browser_executable_hash.clone(),
        driver_version: pin.driver_version.clone(),
        driver_executable_hash: pin.driver_executable_hash.clone(),
        edge_driver_pin_hash: hash_value(pin)?,
        self_test_report_hash: report.report_hash()?,
        activation_challenge: input.activation_challenge,
        self_test_started_at_unix_ms: report.started_at_unix_ms,
        self_test_completed_at_unix_ms: report.completed_at_unix_ms,
        issued_at_unix_seconds: input.issued_at_unix_seconds,
        expires_at_unix_seconds: input.expires_at_unix_seconds,
        ipv4_loopback_passed: true,
        ipv4_direct_ip_blocked: true,
        ipv4_dns_blocked: true,
        ipv4_redirect_blocked: true,
        ipv6_loopback_passed: true,
        ipv6_non_loopback_result,
        browser_session_ids: input.browser_session_ids,
        allowed_origins: input.allowed_origins,
        deny_by_default: true,
        signer_key_id: input.signer_key_id,
        signer_public_key,
        signature_hex: String::new(),
    };
    attestation.signature_hex = hex_encode(
        &signing_key
            .sign(&json_bytes(&payload(&attestation))?)
            .to_bytes(),
    );
    let after = verify_windows_wfp_browser_egress(policy)?;
    if after != before {
        return Err(DesktopError::Integrity(
            "WFP state changed while functional attestation was being signed".to_owned(),
        ));
    }
    validate_windows_wfp_functional_attestation_v2(&attestation)?;
    Ok(attestation)
}

/// Verifies v2 structure, signature, validity window, and expected public key.
pub fn verify_windows_wfp_functional_attestation_v2(
    attestation: &SignedWindowsWfpFunctionalAttestationV2,
    expected_signer_public_key: &str,
    now_unix_seconds: u64,
) -> Result<(), DesktopError> {
    validate_windows_wfp_functional_attestation_v2(attestation)?;
    if attestation.signer_public_key != expected_signer_public_key {
        return Err(DesktopError::Integrity(
            "functional attestation signer differs from the pinned provider key".to_owned(),
        ));
    }
    if now_unix_seconds < attestation.issued_at_unix_seconds
        || now_unix_seconds >= attestation.expires_at_unix_seconds
    {
        return Err(DesktopError::Replay(
            "functional attestation is not currently valid".to_owned(),
        ));
    }
    let key = VerifyingKey::from_bytes(&hex_decode_array::<32>(&attestation.signer_public_key)?)
        .map_err(|error| DesktopError::Integrity(error.to_string()))?;
    let signature = Signature::from_bytes(&hex_decode_array::<64>(&attestation.signature_hex)?);
    if key
        .verify(&json_bytes(&payload(attestation))?, &signature)
        .is_err()
    {
        return Err(DesktopError::Integrity(
            "functional attestation signature is invalid".to_owned(),
        ));
    }
    Ok(())
}

/// Verifies the signed artifact against the exact report, policy, pin, runtime, and host.
#[allow(clippy::too_many_arguments)]
pub fn verify_windows_wfp_functional_attestation_context_v2(
    attestation: &SignedWindowsWfpFunctionalAttestationV2,
    expected_signer_public_key: &str,
    policy: &WindowsWfpBrowserEgressPolicy,
    pin: &WindowsEdgeDriverPin,
    report: &WindowsWfpBrowserEgressSelfTestReport,
    runtime_binding_digest: &str,
    machine_binding: &WindowsHostBinding,
    activation_challenge: &str,
    now_unix_seconds: u64,
) -> Result<(), DesktopError> {
    verify_windows_wfp_functional_attestation_v2(
        attestation,
        expected_signer_public_key,
        now_unix_seconds,
    )?;
    let live = verify_windows_wfp_browser_egress(policy)?;
    require_report_matches(policy, pin, report, &live)?;
    if attestation.runtime_binding_digest != runtime_binding_digest
        || &attestation.machine_binding != machine_binding
        || attestation.activation_challenge != activation_challenge
        || attestation.policy_hash != policy.policy_hash()?
        || attestation.edge_driver_pin_hash != hash_value(pin)?
        || attestation.self_test_report_hash != report.report_hash()?
        || attestation.provider_key != live.provider_key
        || attestation.sublayer_key != live.sublayer_key
        || attestation.filter_keys != live.filter_keys
    {
        return Err(DesktopError::Integrity(
            "functional attestation differs from its runtime, report, pin, host, or live policy"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_windows_wfp_functional_attestation_v2(
    attestation: &SignedWindowsWfpFunctionalAttestationV2,
) -> Result<(), DesktopError> {
    if attestation.schema_version != 2
        || attestation.provider_id != WINDOWS_WFP_LOOPBACK_PROVIDER_ID
        || !attestation.deny_by_default
        || !attestation.ipv4_loopback_passed
        || !attestation.ipv4_direct_ip_blocked
        || !attestation.ipv4_dns_blocked
        || !attestation.ipv4_redirect_blocked
        || !attestation.ipv6_loopback_passed
    {
        return Err(DesktopError::Invalid(
            "functional WFP attestation must be a complete deny-by-default v2 proof".to_owned(),
        ));
    }
    validate_hash(
        &attestation.runtime_binding_digest,
        "functional attestation runtime binding digest",
    )?;
    attestation.machine_binding.validate()?;
    for (value, field) in [
        (&attestation.enforcement_id, "functional enforcement ID"),
        (&attestation.provider_id, "functional provider ID"),
        (&attestation.provider_key, "functional provider key"),
        (&attestation.sublayer_key, "functional sublayer key"),
        (
            &attestation.activation_challenge,
            "functional activation challenge",
        ),
        (&attestation.signer_key_id, "functional signer key ID"),
    ] {
        validate_token(value, field)?;
    }
    for key in &attestation.filter_keys {
        validate_token(key, "functional filter key")?;
    }
    for (value, field) in [
        (&attestation.policy_hash, "functional policy hash"),
        (&attestation.browser_executable_hash, "functional Edge hash"),
        (
            &attestation.driver_executable_hash,
            "functional EdgeDriver hash",
        ),
        (&attestation.edge_driver_pin_hash, "functional pin hash"),
        (&attestation.self_test_report_hash, "functional report hash"),
    ] {
        validate_hash(value, field)?;
    }
    validate_version(&attestation.browser_version, "functional Edge version")?;
    validate_version(&attestation.driver_version, "functional EdgeDriver version")?;
    validate_browser_scope(
        &attestation.browser_session_ids,
        &attestation.allowed_origins,
    )?;
    if attestation.self_test_started_at_unix_ms == 0
        || attestation.self_test_completed_at_unix_ms < attestation.self_test_started_at_unix_ms
        || attestation.issued_at_unix_seconds >= attestation.expires_at_unix_seconds
        || attestation.expires_at_unix_seconds - attestation.issued_at_unix_seconds
            > WINDOWS_WFP_ATTESTATION_MAX_LIFETIME_SECONDS
    {
        return Err(DesktopError::Invalid(
            "functional attestation time bounds are invalid".to_owned(),
        ));
    }
    if attestation.signer_public_key.len() != 64
        || !attestation
            .signer_public_key
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(DesktopError::Invalid(
            "functional attestation signer public key is invalid".to_owned(),
        ));
    }
    let _ = hex_decode_array::<64>(&attestation.signature_hex)?;
    Ok(())
}

fn validate_input(input: &WindowsWfpFunctionalAttestationInputV2) -> Result<(), DesktopError> {
    if input.schema_version != 2
        || input.issued_at_unix_seconds == 0
        || input.issued_at_unix_seconds >= input.expires_at_unix_seconds
        || input.expires_at_unix_seconds - input.issued_at_unix_seconds
            > WINDOWS_WFP_ATTESTATION_MAX_LIFETIME_SECONDS
    {
        return Err(DesktopError::Invalid(
            "functional attestation input version or lifetime is invalid".to_owned(),
        ));
    }
    validate_hash(
        &input.runtime_binding_digest,
        "functional runtime binding digest",
    )?;
    input.machine_binding.validate()?;
    validate_browser_scope(&input.browser_session_ids, &input.allowed_origins)?;
    validate_token(
        &input.activation_challenge,
        "functional activation challenge",
    )?;
    if input.activation_challenge.len() < 16 || input.activation_challenge.len() > 256 {
        return Err(DesktopError::Invalid(
            "functional activation challenge must contain 16..=256 characters".to_owned(),
        ));
    }
    validate_token(&input.signer_key_id, "functional signer key ID")
}

fn require_fresh_report(
    report: &WindowsWfpBrowserEgressSelfTestReport,
    issued_at_unix_seconds: u64,
) -> Result<(), DesktopError> {
    require_fresh_completion(report.completed_at_unix_ms, issued_at_unix_seconds)
}

fn require_fresh_completion(
    completed_at_unix_ms: u64,
    issued_at_unix_seconds: u64,
) -> Result<(), DesktopError> {
    let issued_ms = issued_at_unix_seconds.saturating_mul(1_000);
    if completed_at_unix_ms > issued_ms
        || issued_ms.saturating_sub(completed_at_unix_ms)
            > WINDOWS_WFP_REPORT_MAX_AGE_SECONDS.saturating_mul(1_000)
    {
        return Err(DesktopError::Replay(
            "functional report is from the future or exceeds the maximum age".to_owned(),
        ));
    }
    Ok(())
}

fn require_report_matches(
    policy: &WindowsWfpBrowserEgressPolicy,
    pin: &WindowsEdgeDriverPin,
    report: &WindowsWfpBrowserEgressSelfTestReport,
    live: &WindowsWfpBrowserEgressObservation,
) -> Result<(), DesktopError> {
    if report.wfp_observation != *live
        || report.wfp_observation.policy_hash != policy.policy_hash()?
        || report.edge_driver_pin_hash != hash_value(pin)?
        || report.browser_version != pin.browser_version
        || report.browser_executable_hash != pin.browser_executable_hash
        || report.driver_version != pin.driver_version
        || report.driver_executable_hash != pin.driver_executable_hash
    {
        return Err(DesktopError::Integrity(
            "functional report differs from the live policy or Edge pin".to_owned(),
        ));
    }
    Ok(())
}

fn payload(attestation: &SignedWindowsWfpFunctionalAttestationV2) -> SignedPayload<'_> {
    SignedPayload {
        schema_version: attestation.schema_version,
        runtime_binding_digest: &attestation.runtime_binding_digest,
        machine_binding: &attestation.machine_binding,
        enforcement_id: &attestation.enforcement_id,
        provider_id: &attestation.provider_id,
        policy_hash: &attestation.policy_hash,
        provider_key: &attestation.provider_key,
        sublayer_key: &attestation.sublayer_key,
        filter_keys: &attestation.filter_keys,
        browser_version: &attestation.browser_version,
        browser_executable_hash: &attestation.browser_executable_hash,
        driver_version: &attestation.driver_version,
        driver_executable_hash: &attestation.driver_executable_hash,
        edge_driver_pin_hash: &attestation.edge_driver_pin_hash,
        self_test_report_hash: &attestation.self_test_report_hash,
        activation_challenge: &attestation.activation_challenge,
        self_test_started_at_unix_ms: attestation.self_test_started_at_unix_ms,
        self_test_completed_at_unix_ms: attestation.self_test_completed_at_unix_ms,
        issued_at_unix_seconds: attestation.issued_at_unix_seconds,
        expires_at_unix_seconds: attestation.expires_at_unix_seconds,
        ipv4_loopback_passed: attestation.ipv4_loopback_passed,
        ipv4_direct_ip_blocked: attestation.ipv4_direct_ip_blocked,
        ipv4_dns_blocked: attestation.ipv4_dns_blocked,
        ipv4_redirect_blocked: attestation.ipv4_redirect_blocked,
        ipv6_loopback_passed: attestation.ipv6_loopback_passed,
        ipv6_non_loopback_result: attestation.ipv6_non_loopback_result,
        browser_session_ids: &attestation.browser_session_ids,
        allowed_origins: &attestation.allowed_origins,
        deny_by_default: attestation.deny_by_default,
        signer_key_id: &attestation.signer_key_id,
        signer_public_key: &attestation.signer_public_key,
    }
}

fn validate_version(value: &str, field: &str) -> Result<(), DesktopError> {
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() != 4
        || parts
            .iter()
            .any(|part| part.is_empty() || part.parse::<u32>().is_err())
    {
        return Err(DesktopError::Invalid(format!(
            "{field} must contain four numeric components"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_hash(marker: u8) -> String {
        format!("sha256:{marker:02x}{}", "00".repeat(31))
    }

    fn signed_fixture() -> (SignedWindowsWfpFunctionalAttestationV2, SigningKey) {
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        let mut attestation = SignedWindowsWfpFunctionalAttestationV2 {
            schema_version: 2,
            runtime_binding_digest: fixed_hash(1),
            machine_binding: WindowsHostBinding {
                major_version: 10,
                minor_version: 0,
                build_number: 26_100,
                architecture: "x86_64".to_owned(),
                session_id: 1,
                user_sid: "S-1-5-21-1".to_owned(),
                integrity_level_rid: 8_192,
                elevation_type: "limited".to_owned(),
                is_appcontainer: false,
            },
            enforcement_id: "wfp-test".to_owned(),
            provider_id: WINDOWS_WFP_LOOPBACK_PROVIDER_ID.to_owned(),
            policy_hash: fixed_hash(2),
            provider_key: "effa5c68-709d-4311-9a4c-1ff4f3c20bf0".to_owned(),
            sublayer_key: "f328c32f-dba5-4527-bcc0-c3763b734590".to_owned(),
            filter_keys: [
                "769fcfb8-8dc3-4685-8e70-49deff9012d9".to_owned(),
                "faab358b-8445-488e-8836-ce1173cd6000".to_owned(),
                "5433444c-fc9f-4845-9139-f83e316cbac2".to_owned(),
                "17ddc305-ac3a-4799-886e-0990bed1f105".to_owned(),
            ],
            browser_version: "150.0.4078.99".to_owned(),
            browser_executable_hash: fixed_hash(3),
            driver_version: "150.0.4078.99".to_owned(),
            driver_executable_hash: fixed_hash(4),
            edge_driver_pin_hash: fixed_hash(5),
            self_test_report_hash: fixed_hash(6),
            activation_challenge: "activation-challenge-0001".to_owned(),
            self_test_started_at_unix_ms: 99_000,
            self_test_completed_at_unix_ms: 100_000,
            issued_at_unix_seconds: 101,
            expires_at_unix_seconds: 201,
            ipv4_loopback_passed: true,
            ipv4_direct_ip_blocked: true,
            ipv4_dns_blocked: true,
            ipv4_redirect_blocked: true,
            ipv6_loopback_passed: true,
            ipv6_non_loopback_result: WindowsWfpIpv6EgressResult::ExplicitlyBlocked,
            browser_session_ids: BTreeSet::from(["edge-session".to_owned()]),
            allowed_origins: BTreeSet::from(["http://127.0.0.1:8080".to_owned()]),
            deny_by_default: true,
            signer_key_id: "egress-key-v2".to_owned(),
            signer_public_key: hex_encode(&key.verifying_key().to_bytes()),
            signature_hex: String::new(),
        };
        attestation.signature_hex = hex_encode(
            &key.sign(&json_bytes(&payload(&attestation)).unwrap_or_default())
                .to_bytes(),
        );
        (attestation, key)
    }

    #[test]
    fn v2_signature_and_expiry_are_fail_closed() {
        let (attestation, key) = signed_fixture();
        let public_key = hex_encode(&key.verifying_key().to_bytes());
        assert!(
            verify_windows_wfp_functional_attestation_v2(&attestation, &public_key, 150).is_ok()
        );
        assert!(
            verify_windows_wfp_functional_attestation_v2(&attestation, &public_key, 201).is_err()
        );
        assert!(verify_windows_wfp_functional_attestation_v2(
            &attestation,
            &hex_encode(
                &SigningKey::from_bytes(&[8_u8; 32])
                    .verifying_key()
                    .to_bytes()
            ),
            150,
        )
        .is_err());
    }

    #[test]
    fn v2_signed_context_rejects_every_bound_hash_and_challenge_mutation() {
        let (attestation, key) = signed_fixture();
        let public_key = hex_encode(&key.verifying_key().to_bytes());
        let mut mutations = Vec::new();
        let mut changed = attestation.clone();
        changed.runtime_binding_digest = fixed_hash(21);
        mutations.push(changed);
        let mut changed = attestation.clone();
        changed.policy_hash = fixed_hash(22);
        mutations.push(changed);
        let mut changed = attestation.clone();
        changed.driver_executable_hash = fixed_hash(23);
        mutations.push(changed);
        let mut changed = attestation.clone();
        changed.self_test_report_hash = fixed_hash(24);
        mutations.push(changed);
        let mut changed = attestation;
        changed.activation_challenge = "activation-challenge-other".to_owned();
        mutations.push(changed);
        for mutation in mutations {
            assert!(
                verify_windows_wfp_functional_attestation_v2(&mutation, &public_key, 150).is_err()
            );
        }
    }

    #[test]
    fn report_max_age_rejects_stale_and_future_completions() {
        assert!(require_fresh_completion(100_000, 101).is_ok());
        assert!(require_fresh_completion(100_000, 401).is_err());
        assert!(require_fresh_completion(102_000, 101).is_err());
    }
}
