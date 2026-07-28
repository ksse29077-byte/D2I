use crate::{
    hash_value, hex_decode_array, hex_encode, json_bytes, read_bounded, sha256_bytes,
    validate_hash, validate_text, validate_token, DesktopAdapterDescriptor, DesktopCapability,
    DesktopError, SignedWindowsWfpFunctionalAttestationV2,
};
use d2i_windows_host::host_identity;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

const MAX_BINDING_LIFETIME_SECONDS: u64 = 15 * 60;
const MAX_WORKER_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const WINDOWS_WFP_LOOPBACK_PROVIDER_ID: &str = "d2i.windows.wfp.loopback.v1";

/// One independently certified Windows adapter capability group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAdapterKind {
    UiAutomation,
    WebDriver,
    FileWrite,
    Process,
}

/// Exact zero-capability AppContainer identity used for process children.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsProcessIsolation {
    pub profile_name: String,
    pub profile_sid: String,
}

impl WindowsProcessIsolation {
    fn validate(&self) -> Result<(), DesktopError> {
        validate_appcontainer_profile_name(&self.profile_name)?;
        validate_windows_sid(&self.profile_sid, "AppContainer profile_sid")?;
        if !self.profile_sid.starts_with("S-1-15-2-") {
            return Err(DesktopError::Invalid(
                "AppContainer profile_sid must belong to the S-1-15-2 authority".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Hash-pinned browser image governed by the concrete loopback-only WFP policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsWfpBrowserEgressPolicy {
    pub schema_version: u32,
    pub enforcement_id: String,
    pub provider_id: String,
    pub browser_executable: String,
    pub browser_executable_hash: String,
    pub verifier_profile_name: String,
    pub verifier_profile_sid: String,
    pub policy_owner_sid: String,
}

impl WindowsWfpBrowserEgressPolicy {
    /// Validates the concrete provider identity and browser image declaration.
    pub fn validate(&self) -> Result<(), DesktopError> {
        if self.schema_version != 2 {
            return Err(DesktopError::Invalid(
                "Windows WFP browser-egress policy schema_version must be 2".to_owned(),
            ));
        }
        validate_token(&self.enforcement_id, "browser egress enforcement_id")?;
        if self.provider_id != WINDOWS_WFP_LOOPBACK_PROVIDER_ID {
            return Err(DesktopError::Invalid(format!(
                "Windows WFP browser-egress provider_id must be {WINDOWS_WFP_LOOPBACK_PROVIDER_ID}"
            )));
        }
        validate_absolute_path(&self.browser_executable, "browser_executable")?;
        validate_hash(&self.browser_executable_hash, "browser_executable_hash")?;
        validate_appcontainer_profile_name(&self.verifier_profile_name)?;
        validate_windows_sid(&self.verifier_profile_sid, "WFP verifier profile SID")?;
        if !self.verifier_profile_sid.starts_with("S-1-15-2-") {
            return Err(DesktopError::Invalid(
                "WFP verifier must use an AppContainer profile SID".to_owned(),
            ));
        }
        validate_windows_sid(&self.policy_owner_sid, "WFP policy owner SID")?;
        Ok(())
    }

    /// Returns the deterministic policy identity signed by the egress provider.
    pub fn policy_hash(&self) -> Result<String, DesktopError> {
        self.validate()?;
        hash_value(self)
    }
}

/// Reviewed browser-egress enforcement identity and exact allowed scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsBrowserEgressRequirement {
    pub enforcement_id: String,
    pub policy_hash: String,
    pub provider_id: String,
    pub provider_public_key: String,
    pub browser_session_ids: BTreeSet<String>,
    pub allowed_origins: BTreeSet<String>,
    pub functional_attestation_hash: Option<String>,
    pub edge_driver_executable_hash: Option<String>,
    pub self_test_report_hash: Option<String>,
    pub activation_challenge: Option<String>,
}

impl WindowsBrowserEgressRequirement {
    fn validate(&self) -> Result<(), DesktopError> {
        validate_token(&self.enforcement_id, "browser egress enforcement_id")?;
        validate_hash(&self.policy_hash, "browser egress policy_hash")?;
        validate_token(&self.provider_id, "browser egress provider_id")?;
        validate_public_key(
            &self.provider_public_key,
            "browser egress provider_public_key",
        )?;
        validate_browser_scope(&self.browser_session_ids, &self.allowed_origins)?;
        let concrete = self.provider_id == WINDOWS_WFP_LOOPBACK_PROVIDER_ID;
        let fields_present = self.functional_attestation_hash.is_some()
            && self.edge_driver_executable_hash.is_some()
            && self.self_test_report_hash.is_some()
            && self.activation_challenge.is_some();
        if concrete != fields_present {
            return Err(DesktopError::Invalid(
                "concrete WFP manifest requirements must pin the complete v2 proof".to_owned(),
            ));
        }
        if !concrete
            && (self.functional_attestation_hash.is_some()
                || self.edge_driver_executable_hash.is_some()
                || self.self_test_report_hash.is_some()
                || self.activation_challenge.is_some())
        {
            return Err(DesktopError::Invalid(
                "external egress requirements cannot claim WFP v2 fields".to_owned(),
            ));
        }
        for (value, field) in [
            (
                &self.functional_attestation_hash,
                "functional attestation hash",
            ),
            (
                &self.edge_driver_executable_hash,
                "manifest EdgeDriver hash",
            ),
            (
                &self.self_test_report_hash,
                "manifest self-test report hash",
            ),
        ] {
            if let Some(value) = value {
                validate_hash(value, field)?;
            }
        }
        if let Some(challenge) = &self.activation_challenge {
            validate_token(challenge, "manifest activation challenge")?;
        }
        Ok(())
    }
}

/// Unsigned observation emitted by an external browser-egress enforcer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsBrowserEgressInput {
    pub schema_version: u32,
    pub enforcement_id: String,
    pub policy_hash: String,
    pub provider_id: String,
    pub observed_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub browser_session_ids: BTreeSet<String>,
    pub allowed_origins: BTreeSet<String>,
    pub deny_by_default: bool,
}

/// Provider-signed proof of external browser-egress enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedWindowsBrowserEgressEvidence {
    pub schema_version: u32,
    pub enforcement_id: String,
    pub policy_hash: String,
    pub provider_id: String,
    pub observed_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub browser_session_ids: BTreeSet<String>,
    pub allowed_origins: BTreeSet<String>,
    pub deny_by_default: bool,
    pub signer_public_key: String,
    pub signature_hex: String,
}

/// Exact worker and capability configuration covered by runtime certification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsAdapterConfiguration {
    pub schema_version: u32,
    pub adapter_kind: WindowsAdapterKind,
    pub worker_executable: String,
    pub worker_executable_hash: String,
    pub request_timeout_ms: u64,
    pub active_process_limit: u32,
    pub per_process_memory_bytes: u64,
    pub write_roots: Vec<String>,
    pub webdriver_endpoint: Option<String>,
    pub browser_session_ids: BTreeSet<String>,
    pub browser_allowed_origins: BTreeSet<String>,
    pub browser_egress_policy: Option<WindowsWfpBrowserEgressPolicy>,
    pub ui_allowed_executable_hashes: BTreeSet<String>,
    pub process_isolation: Option<WindowsProcessIsolation>,
}

impl WindowsAdapterConfiguration {
    /// Validates kind-specific settings and worker resource bounds.
    pub fn validate(&self) -> Result<(), DesktopError> {
        if self.schema_version != 1 {
            return Err(DesktopError::Invalid(
                "Windows adapter configuration schema_version must be 1".to_owned(),
            ));
        }
        validate_absolute_path(&self.worker_executable, "worker_executable")?;
        validate_hash(&self.worker_executable_hash, "worker_executable_hash")?;
        if self.request_timeout_ms < 100 || self.request_timeout_ms > 60_000 {
            return Err(DesktopError::Invalid(
                "worker request timeout must be within 100..=60000 ms".to_owned(),
            ));
        }
        d2i_windows_host::WindowsJobLimits {
            active_process_limit: self.active_process_limit,
            per_process_memory_bytes: self.per_process_memory_bytes,
        }
        .validate()
        .map_err(|error| DesktopError::Invalid(error.to_string()))?;
        if self.adapter_kind == WindowsAdapterKind::Process {
            if self.active_process_limit < 2 {
                return Err(DesktopError::Invalid(
                    "process adapter requires room for its worker and one child".to_owned(),
                ));
            }
        } else if self.active_process_limit != 1 {
            return Err(DesktopError::Invalid(
                "non-process workers must set active_process_limit to 1".to_owned(),
            ));
        }
        if self.write_roots.len() > 256 {
            return Err(DesktopError::Invalid(
                "Windows write roots exceed 256 entries".to_owned(),
            ));
        }
        for root in &self.write_roots {
            validate_absolute_path(root, "Windows write root")?;
        }
        for session_id in &self.browser_session_ids {
            validate_token(session_id, "browser_session_id")?;
        }
        for origin in &self.browser_allowed_origins {
            validate_origin(origin)?;
        }
        for hash in &self.ui_allowed_executable_hashes {
            validate_hash(hash, "UI allowed executable hash")?;
        }
        match self.adapter_kind {
            WindowsAdapterKind::UiAutomation => {
                if self.ui_allowed_executable_hashes.is_empty()
                    || !self.write_roots.is_empty()
                    || self.webdriver_endpoint.is_some()
                    || !self.browser_session_ids.is_empty()
                    || !self.browser_allowed_origins.is_empty()
                    || self.browser_egress_policy.is_some()
                    || self.process_isolation.is_some()
                {
                    return Err(DesktopError::Invalid(
                        "UI Automation configuration contains missing or unrelated settings"
                            .to_owned(),
                    ));
                }
            }
            WindowsAdapterKind::WebDriver => {
                let endpoint = self.webdriver_endpoint.as_deref().ok_or_else(|| {
                    DesktopError::Invalid("WebDriver endpoint is required".to_owned())
                })?;
                validate_loopback_endpoint(endpoint)?;
                if self.browser_session_ids.is_empty()
                    || self.browser_allowed_origins.is_empty()
                    || !self.write_roots.is_empty()
                    || !self.ui_allowed_executable_hashes.is_empty()
                    || self.process_isolation.is_some()
                {
                    return Err(DesktopError::Invalid(
                        "WebDriver configuration contains missing or unrelated settings".to_owned(),
                    ));
                }
                if let Some(policy) = &self.browser_egress_policy {
                    policy.validate()?;
                    for origin in &self.browser_allowed_origins {
                        validate_loopback_origin(origin)?;
                    }
                }
            }
            WindowsAdapterKind::FileWrite => {
                if self.write_roots.is_empty()
                    || self.webdriver_endpoint.is_some()
                    || !self.browser_session_ids.is_empty()
                    || !self.browser_allowed_origins.is_empty()
                    || self.browser_egress_policy.is_some()
                    || !self.ui_allowed_executable_hashes.is_empty()
                    || self.process_isolation.is_some()
                {
                    return Err(DesktopError::Invalid(
                        "file-write configuration contains missing or unrelated settings"
                            .to_owned(),
                    ));
                }
            }
            WindowsAdapterKind::Process => {
                if !self.write_roots.is_empty()
                    || self.webdriver_endpoint.is_some()
                    || !self.browser_session_ids.is_empty()
                    || !self.browser_allowed_origins.is_empty()
                    || self.browser_egress_policy.is_some()
                    || !self.ui_allowed_executable_hashes.is_empty()
                {
                    return Err(DesktopError::Invalid(
                        "process configuration contains unrelated settings".to_owned(),
                    ));
                }
                self.process_isolation
                    .as_ref()
                    .ok_or_else(|| {
                        DesktopError::Invalid(
                            "process configuration requires zero-capability AppContainer isolation"
                                .to_owned(),
                        )
                    })?
                    .validate()?;
            }
        }
        Ok(())
    }

    /// Computes the exact worker configuration identity.
    pub fn configuration_hash(&self) -> Result<String, DesktopError> {
        self.validate()?;
        hash_value(self)
    }

    /// Returns the capability-minimal descriptor pinned by policy and certification.
    pub fn descriptor(&self) -> Result<DesktopAdapterDescriptor, DesktopError> {
        self.validate()?;
        descriptor_for_kind(self.adapter_kind)
    }
}

/// Exact Windows host state that a reviewed manifest expects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsHostBinding {
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    pub architecture: String,
    pub session_id: u32,
    pub user_sid: String,
    pub integrity_level_rid: u32,
    pub elevation_type: String,
    pub is_appcontainer: bool,
}

/// Captures the current exact Windows machine, user, integrity, and session binding.
pub fn current_windows_host_binding() -> Result<WindowsHostBinding, DesktopError> {
    let host = host_identity().map_err(|error| {
        DesktopError::AdapterUnavailable(format!("Windows host probe failed: {error}"))
    })?;
    let binding = WindowsHostBinding {
        major_version: host.major_version,
        minor_version: host.minor_version,
        build_number: host.build_number,
        architecture: host.architecture,
        session_id: host.session_id,
        user_sid: host.user_sid,
        integrity_level_rid: host.integrity_level_rid,
        elevation_type: host.elevation_type,
        is_appcontainer: host.is_appcontainer,
    };
    binding.validate()?;
    Ok(binding)
}

impl WindowsHostBinding {
    pub(crate) fn validate(&self) -> Result<(), DesktopError> {
        if self.major_version == 0 || self.build_number == 0 {
            return Err(DesktopError::Invalid(
                "Windows version must be an exact nonzero observation".to_owned(),
            ));
        }
        validate_token(&self.architecture, "Windows architecture")?;
        validate_windows_sid(&self.user_sid, "Windows user_sid")?;
        validate_token(&self.elevation_type, "Windows elevation_type")?;
        if self.integrity_level_rid == 0 || self.is_appcontainer {
            return Err(DesktopError::Invalid(
                "Windows probe must run as a non-AppContainer user token with an integrity level"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Reviewed trust roots and exact runtime contract for one adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsRuntimeManifest {
    pub schema_version: u32,
    pub integration_id: String,
    pub adapter_kind: WindowsAdapterKind,
    pub adapter_descriptor: DesktopAdapterDescriptor,
    pub configuration_hash: String,
    pub worker_executable_hash: String,
    pub process_isolation: Option<WindowsProcessIsolation>,
    pub browser_egress_requirement: Option<WindowsBrowserEgressRequirement>,
    pub host: WindowsHostBinding,
    pub interactive_session_required: bool,
    pub binding_attestor_id: String,
    pub binding_attestor_public_key: String,
    pub certifier_id: String,
    pub certifier_public_key: String,
}

impl WindowsRuntimeManifest {
    /// Validates exact binding expectations and pinned Ed25519 trust roots.
    pub fn validate(&self) -> Result<(), DesktopError> {
        if self.schema_version != 1 {
            return Err(DesktopError::Invalid(
                "Windows runtime manifest schema_version must be 1".to_owned(),
            ));
        }
        validate_token(&self.integration_id, "Windows integration_id")?;
        self.adapter_descriptor.validate()?;
        validate_hash(&self.configuration_hash, "configuration_hash")?;
        validate_hash(&self.worker_executable_hash, "worker_executable_hash")?;
        match self.adapter_kind {
            WindowsAdapterKind::Process => self
                .process_isolation
                .as_ref()
                .ok_or_else(|| {
                    DesktopError::Invalid(
                        "process manifest requires AppContainer isolation identity".to_owned(),
                    )
                })?
                .validate()?,
            _ if self.process_isolation.is_some() => {
                return Err(DesktopError::Invalid(
                    "non-process manifest contains AppContainer isolation identity".to_owned(),
                ));
            }
            _ => {}
        }
        match self.adapter_kind {
            WindowsAdapterKind::WebDriver => self
                .browser_egress_requirement
                .as_ref()
                .ok_or_else(|| {
                    DesktopError::Invalid(
                        "WebDriver manifest requires signed browser-egress enforcement".to_owned(),
                    )
                })?
                .validate()?,
            _ if self.browser_egress_requirement.is_some() => {
                return Err(DesktopError::Invalid(
                    "non-WebDriver manifest contains browser-egress requirements".to_owned(),
                ));
            }
            _ => {}
        }
        self.host.validate()?;
        validate_token(&self.binding_attestor_id, "binding_attestor_id")?;
        validate_public_key(
            &self.binding_attestor_public_key,
            "binding_attestor_public_key",
        )?;
        validate_token(&self.certifier_id, "certifier_id")?;
        validate_public_key(&self.certifier_public_key, "certifier_public_key")?;
        let expected = descriptor_for_kind(self.adapter_kind)?;
        if self.adapter_descriptor != expected {
            return Err(DesktopError::Invalid(
                "manifest adapter descriptor does not match adapter_kind".to_owned(),
            ));
        }
        Ok(())
    }

    /// Computes the immutable reviewed-manifest identity.
    pub fn manifest_hash(&self) -> Result<String, DesktopError> {
        self.validate()?;
        hash_value(self)
    }
}

/// Bounded worker capability observation with no user payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsCapabilityObservation {
    pub adapter_kind: WindowsAdapterKind,
    pub ready: bool,
    pub process_isolated: bool,
    pub job_kill_on_close: bool,
    pub active_process_limit: u32,
    pub per_process_memory_bytes: u64,
    pub process_appcontainer_sid: Option<String>,
    pub network_isolation_enforced: bool,
    pub details_hash: String,
}

impl WindowsCapabilityObservation {
    fn validate(&self) -> Result<(), DesktopError> {
        validate_hash(&self.details_hash, "capability details_hash")?;
        if self.active_process_limit == 0 || self.per_process_memory_bytes == 0 {
            return Err(DesktopError::Invalid(
                "capability observation has invalid resource bounds".to_owned(),
            ));
        }
        match self.adapter_kind {
            WindowsAdapterKind::Process => {
                let sid = self.process_appcontainer_sid.as_deref().ok_or_else(|| {
                    DesktopError::Invalid(
                        "process capability observation lacks AppContainer SID".to_owned(),
                    )
                })?;
                validate_windows_sid(sid, "process AppContainer SID")?;
                if !self.network_isolation_enforced {
                    return Err(DesktopError::Invalid(
                        "process capability observation lacks network isolation".to_owned(),
                    ));
                }
            }
            _ => {
                if self.process_appcontainer_sid.is_some() || self.network_isolation_enforced {
                    return Err(DesktopError::Invalid(
                        "non-process capability claims process AppContainer isolation".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Unsigned input collected from a concrete Windows worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsBindingInput {
    pub schema_version: u32,
    pub binding_id: String,
    pub integration_id: String,
    pub observed_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub attestor_id: String,
    pub host: WindowsHostBinding,
    pub adapter_kind: WindowsAdapterKind,
    pub adapter_descriptor_hash: String,
    pub configuration_hash: String,
    pub worker_executable: String,
    pub worker_executable_hash: String,
    pub capability: WindowsCapabilityObservation,
    pub browser_egress_evidence: Option<SignedWindowsBrowserEgressEvidence>,
    pub wfp_functional_attestation: Option<SignedWindowsWfpFunctionalAttestationV2>,
}

/// Probe-signed Windows runtime observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsBindingEvidence {
    pub schema_version: u32,
    pub binding_id: String,
    pub integration_id: String,
    pub observed_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub attestor_id: String,
    pub host: WindowsHostBinding,
    pub adapter_kind: WindowsAdapterKind,
    pub adapter_descriptor_hash: String,
    pub configuration_hash: String,
    pub worker_executable: String,
    pub worker_executable_hash: String,
    pub capability: WindowsCapabilityObservation,
    pub browser_egress_evidence: Option<SignedWindowsBrowserEgressEvidence>,
    pub wfp_functional_attestation: Option<SignedWindowsWfpFunctionalAttestationV2>,
    pub signer_public_key: String,
    pub signature_hex: String,
}

/// One deterministic, actionable certification mismatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsCertificationIssue {
    pub code: String,
    pub message: String,
    pub remediation: String,
}

/// Unsigned comparison report. Only a clean report can produce a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsCertificationReport {
    pub schema_version: u32,
    pub certification_id: String,
    pub integration_id: String,
    pub binding_id: String,
    pub certified: bool,
    pub manifest_hash: String,
    pub evidence_hash: String,
    pub issues: Vec<WindowsCertificationIssue>,
}

/// Certifier-signed proof that one fresh runtime observation matched a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedWindowsCertification {
    pub schema_version: u32,
    pub certification_id: String,
    pub integration_id: String,
    pub binding_id: String,
    pub manifest_hash: String,
    pub evidence_hash: String,
    pub configuration_hash: String,
    pub adapter_descriptor_hash: String,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub certifier_id: String,
    pub certifier_public_key: String,
    pub signature_hex: String,
}

/// Report plus a signed certificate only when every comparison passed.
#[derive(Debug, Clone)]
pub struct WindowsBindingCertification {
    pub report: WindowsCertificationReport,
    pub signed_certification: Option<SignedWindowsCertification>,
}

/// Opaque input to the persistent one-shot activation ledger.
#[derive(Debug)]
pub struct CertifiedWindowsBinding {
    pub(crate) integration_id: String,
    pub(crate) binding_id: String,
    pub(crate) certification_id: String,
    pub(crate) manifest_hash: String,
    pub(crate) evidence_hash: String,
    pub(crate) certification_hash: String,
    pub(crate) configuration_hash: String,
    pub(crate) adapter_kind: WindowsAdapterKind,
    pub(crate) adapter_descriptor: DesktopAdapterDescriptor,
    pub(crate) observed_at_unix_seconds: u64,
    pub(crate) expires_at_unix_seconds: u64,
    pub(crate) activation_challenge: Option<String>,
    pub(crate) self_test_report_hash: Option<String>,
}

/// Side-effect-free boundary implemented by a concrete Windows host probe.
pub trait WindowsRuntimeBindingProbe {
    /// Collects and signs a fresh observation without creating an adapter.
    fn collect_binding_evidence(&self) -> Result<WindowsBindingEvidence, DesktopError>;
}

/// Concrete probe that starts the hash-pinned worker inside a bounded Job Object.
pub struct ConcreteWindowsRuntimeBindingProbe {
    pub configuration: WindowsAdapterConfiguration,
    pub binding_id: String,
    pub integration_id: String,
    pub observed_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub attestor_id: String,
    browser_egress_evidence: Option<SignedWindowsBrowserEgressEvidence>,
    wfp_functional_attestation: Option<SignedWindowsWfpFunctionalAttestationV2>,
    signing_key: SigningKey,
}

impl ConcreteWindowsRuntimeBindingProbe {
    /// Creates a probe. The signing key remains caller-owned deployment material.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        configuration: WindowsAdapterConfiguration,
        binding_id: String,
        integration_id: String,
        observed_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
        attestor_id: String,
        signing_key: SigningKey,
    ) -> Result<Self, DesktopError> {
        configuration.validate()?;
        let input = Self {
            configuration,
            binding_id,
            integration_id,
            observed_at_unix_seconds,
            expires_at_unix_seconds,
            attestor_id,
            browser_egress_evidence: None,
            wfp_functional_attestation: None,
            signing_key,
        };
        validate_token(&input.binding_id, "binding_id")?;
        validate_token(&input.integration_id, "integration_id")?;
        validate_token(&input.attestor_id, "attestor_id")?;
        validate_lifetime(
            input.observed_at_unix_seconds,
            input.expires_at_unix_seconds,
        )?;
        Ok(input)
    }

    /// Attaches provider-signed external browser-egress evidence.
    pub fn with_browser_egress_evidence(
        mut self,
        evidence: SignedWindowsBrowserEgressEvidence,
    ) -> Result<Self, DesktopError> {
        validate_browser_egress_evidence(&evidence)?;
        if !verify_browser_egress_signature(&evidence)? {
            return Err(DesktopError::Integrity(
                "browser-egress evidence signature is invalid".to_owned(),
            ));
        }
        self.browser_egress_evidence = Some(evidence);
        Ok(self)
    }

    /// Attaches a concrete WFP v2 proof. Legacy v1 WFP evidence is rejected.
    pub fn with_wfp_functional_attestation(
        mut self,
        attestation: SignedWindowsWfpFunctionalAttestationV2,
    ) -> Result<Self, DesktopError> {
        crate::windows_attestation::validate_windows_wfp_functional_attestation_v2(&attestation)?;
        self.wfp_functional_attestation = Some(attestation);
        Ok(self)
    }
}

impl WindowsRuntimeBindingProbe for ConcreteWindowsRuntimeBindingProbe {
    fn collect_binding_evidence(&self) -> Result<WindowsBindingEvidence, DesktopError> {
        crate::windows_egress::verify_configured_windows_browser_egress(&self.configuration)?;
        let host = current_windows_host_binding()?;
        let worker = canonical_regular_path(
            Path::new(&self.configuration.worker_executable),
            "worker executable",
        )?;
        let worker_hash = sha256_bytes(&read_bounded(&worker, MAX_WORKER_BYTES)?);
        if worker_hash != self.configuration.worker_executable_hash {
            return Err(DesktopError::Integrity(
                "worker executable hash differs from configuration".to_owned(),
            ));
        }
        let capability = crate::windows_worker::probe_worker(&self.configuration)?;
        crate::windows_egress::verify_configured_windows_browser_egress(&self.configuration)?;
        validate_probe_browser_egress(
            &self.configuration,
            &host,
            self.observed_at_unix_seconds,
            self.browser_egress_evidence.as_ref(),
            self.wfp_functional_attestation.as_ref(),
        )?;
        create_windows_binding_evidence(
            WindowsBindingInput {
                schema_version: 1,
                binding_id: self.binding_id.clone(),
                integration_id: self.integration_id.clone(),
                observed_at_unix_seconds: self.observed_at_unix_seconds,
                expires_at_unix_seconds: self.expires_at_unix_seconds,
                attestor_id: self.attestor_id.clone(),
                host,
                adapter_kind: self.configuration.adapter_kind,
                adapter_descriptor_hash: self.configuration.descriptor()?.descriptor_hash()?,
                configuration_hash: self.configuration.configuration_hash()?,
                worker_executable: worker.display().to_string(),
                worker_executable_hash: worker_hash,
                capability,
                browser_egress_evidence: self.browser_egress_evidence.clone(),
                wfp_functional_attestation: self.wfp_functional_attestation.clone(),
            },
            &self.signing_key,
        )
    }
}

#[derive(Serialize)]
struct SignedEvidencePayload<'a> {
    schema_version: u32,
    binding_id: &'a str,
    integration_id: &'a str,
    observed_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    attestor_id: &'a str,
    host: &'a WindowsHostBinding,
    adapter_kind: WindowsAdapterKind,
    adapter_descriptor_hash: &'a str,
    configuration_hash: &'a str,
    worker_executable: &'a str,
    worker_executable_hash: &'a str,
    capability: &'a WindowsCapabilityObservation,
    browser_egress_evidence: &'a Option<SignedWindowsBrowserEgressEvidence>,
    wfp_functional_attestation: &'a Option<SignedWindowsWfpFunctionalAttestationV2>,
    signer_public_key: &'a str,
}

#[derive(Serialize)]
struct SignedBrowserEgressPayload<'a> {
    schema_version: u32,
    enforcement_id: &'a str,
    policy_hash: &'a str,
    provider_id: &'a str,
    observed_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    browser_session_ids: &'a BTreeSet<String>,
    allowed_origins: &'a BTreeSet<String>,
    deny_by_default: bool,
    signer_public_key: &'a str,
}

#[derive(Serialize)]
struct SignedCertificationPayload<'a> {
    schema_version: u32,
    certification_id: &'a str,
    integration_id: &'a str,
    binding_id: &'a str,
    manifest_hash: &'a str,
    evidence_hash: &'a str,
    configuration_hash: &'a str,
    adapter_descriptor_hash: &'a str,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    certifier_id: &'a str,
    certifier_public_key: &'a str,
}

/// Signs one short-lived external browser-egress enforcement observation.
pub fn create_windows_browser_egress_evidence(
    input: WindowsBrowserEgressInput,
    signing_key: &SigningKey,
) -> Result<SignedWindowsBrowserEgressEvidence, DesktopError> {
    if input.provider_id == WINDOWS_WFP_LOOPBACK_PROVIDER_ID {
        return Err(DesktopError::AccessDenied(
            "the concrete WFP provider can sign only after live WFP verification".to_owned(),
        ));
    }
    sign_windows_browser_egress_evidence(input, signing_key)
}

pub(crate) fn sign_windows_browser_egress_evidence(
    input: WindowsBrowserEgressInput,
    signing_key: &SigningKey,
) -> Result<SignedWindowsBrowserEgressEvidence, DesktopError> {
    validate_browser_egress_input(&input)?;
    let signer_public_key = hex_encode(&signing_key.verifying_key().to_bytes());
    let payload = SignedBrowserEgressPayload {
        schema_version: input.schema_version,
        enforcement_id: &input.enforcement_id,
        policy_hash: &input.policy_hash,
        provider_id: &input.provider_id,
        observed_at_unix_seconds: input.observed_at_unix_seconds,
        expires_at_unix_seconds: input.expires_at_unix_seconds,
        browser_session_ids: &input.browser_session_ids,
        allowed_origins: &input.allowed_origins,
        deny_by_default: input.deny_by_default,
        signer_public_key: &signer_public_key,
    };
    let signature_hex = hex_encode(&signing_key.sign(&json_bytes(&payload)?).to_bytes());
    Ok(SignedWindowsBrowserEgressEvidence {
        schema_version: input.schema_version,
        enforcement_id: input.enforcement_id,
        policy_hash: input.policy_hash,
        provider_id: input.provider_id,
        observed_at_unix_seconds: input.observed_at_unix_seconds,
        expires_at_unix_seconds: input.expires_at_unix_seconds,
        browser_session_ids: input.browser_session_ids,
        allowed_origins: input.allowed_origins,
        deny_by_default: input.deny_by_default,
        signer_public_key,
        signature_hex,
    })
}

/// Signs a bounded runtime observation with the deployment probe key.
pub fn create_windows_binding_evidence(
    input: WindowsBindingInput,
    signing_key: &SigningKey,
) -> Result<WindowsBindingEvidence, DesktopError> {
    validate_binding_input(&input)?;
    let signer_public_key = hex_encode(&signing_key.verifying_key().to_bytes());
    let payload = evidence_payload_from_input(&input, &signer_public_key);
    let signature_hex = hex_encode(&signing_key.sign(&json_bytes(&payload)?).to_bytes());
    Ok(WindowsBindingEvidence {
        schema_version: input.schema_version,
        binding_id: input.binding_id,
        integration_id: input.integration_id,
        observed_at_unix_seconds: input.observed_at_unix_seconds,
        expires_at_unix_seconds: input.expires_at_unix_seconds,
        attestor_id: input.attestor_id,
        host: input.host,
        adapter_kind: input.adapter_kind,
        adapter_descriptor_hash: input.adapter_descriptor_hash,
        configuration_hash: input.configuration_hash,
        worker_executable: input.worker_executable,
        worker_executable_hash: input.worker_executable_hash,
        capability: input.capability,
        browser_egress_evidence: input.browser_egress_evidence,
        wfp_functional_attestation: input.wfp_functional_attestation,
        signer_public_key,
        signature_hex,
    })
}

/// Compares signed evidence with a manifest and signs a successful certification.
#[allow(clippy::too_many_arguments)]
pub fn certify_windows_binding(
    manifest: &WindowsRuntimeManifest,
    evidence: &WindowsBindingEvidence,
    certification_id: String,
    certifier_id: String,
    certifier_key: &SigningKey,
    now_unix_seconds: u64,
) -> Result<WindowsBindingCertification, DesktopError> {
    manifest.validate()?;
    validate_evidence(evidence)?;
    validate_token(&certification_id, "certification_id")?;
    validate_token(&certifier_id, "certifier_id")?;
    let manifest_hash = manifest.manifest_hash()?;
    let evidence_hash = hash_value(evidence)?;
    let mut issues = Vec::new();

    compare(
        evidence.integration_id == manifest.integration_id,
        &mut issues,
        "D2IWC100",
        "integration identity differs",
        "probe the exact reviewed Windows integration",
    );
    compare(
        evidence.attestor_id == manifest.binding_attestor_id
            && evidence.signer_public_key == manifest.binding_attestor_public_key,
        &mut issues,
        "D2IWC101",
        "binding evidence is not signed by the manifest attestor",
        "use the pinned runtime-probe signing key",
    );
    compare(
        verify_evidence_signature(evidence)?,
        &mut issues,
        "D2IWC102",
        "binding evidence signature is invalid",
        "discard the evidence and collect a fresh observation",
    );
    compare(
        now_unix_seconds >= evidence.observed_at_unix_seconds
            && now_unix_seconds < evidence.expires_at_unix_seconds,
        &mut issues,
        "D2IWC103",
        "binding evidence is not currently valid",
        "collect fresh evidence with a trusted deployment clock",
    );
    compare(
        evidence.host == manifest.host,
        &mut issues,
        "D2IWC104",
        "Windows build, architecture, or session differs",
        "review and pin the exact target Windows host binding",
    );
    compare(
        evidence.adapter_kind == manifest.adapter_kind,
        &mut issues,
        "D2IWC105",
        "adapter kind differs",
        "probe the capability named by the manifest",
    );
    compare(
        evidence.adapter_descriptor_hash == manifest.adapter_descriptor.descriptor_hash()?,
        &mut issues,
        "D2IWC106",
        "adapter descriptor differs",
        "rebuild and review the expected adapter descriptor",
    );
    compare(
        evidence.configuration_hash == manifest.configuration_hash,
        &mut issues,
        "D2IWC107",
        "adapter configuration differs",
        "probe the exact reviewed worker configuration",
    );
    compare(
        evidence.worker_executable_hash == manifest.worker_executable_hash,
        &mut issues,
        "D2IWC108",
        "worker executable hash differs",
        "deploy the reviewed worker binary",
    );
    compare(
        evidence.capability.ready
            && evidence.capability.process_isolated
            && evidence.capability.job_kill_on_close
            && evidence.capability.adapter_kind == manifest.adapter_kind,
        &mut issues,
        "D2IWC109",
        "capability probe or required worker isolation failed",
        "repair the Job Object worker and repeat the capability probe",
    );
    compare(
        manifest.adapter_kind != WindowsAdapterKind::Process
            || (manifest
                .process_isolation
                .as_ref()
                .is_some_and(|isolation| {
                    evidence.capability.process_appcontainer_sid.as_deref()
                        == Some(isolation.profile_sid.as_str())
                })
                && evidence.capability.network_isolation_enforced),
        &mut issues,
        "D2IWC112",
        "zero-capability AppContainer network isolation was not observed",
        "provision the reviewed AppContainer profile and repeat the capability probe",
    );
    compare(
        browser_egress_matches(manifest, evidence, now_unix_seconds)?,
        &mut issues,
        "D2IWC113",
        "signed browser-egress enforcement does not match the reviewed requirement",
        "apply the reviewed deny-by-default egress policy and collect fresh provider evidence",
    );
    compare(
        !manifest.interactive_session_required || evidence.host.session_id != 0,
        &mut issues,
        "D2IWC110",
        "interactive adapter was observed outside a user session",
        "run the probe in the reviewed interactive desktop session",
    );
    compare(
        certifier_id == manifest.certifier_id
            && hex_encode(&certifier_key.verifying_key().to_bytes())
                == manifest.certifier_public_key,
        &mut issues,
        "D2IWC111",
        "certifier identity or key differs from the manifest",
        "use the independently pinned certification key",
    );
    issues.sort_by(|left, right| (&left.code, &left.message).cmp(&(&right.code, &right.message)));
    let certified = issues.is_empty();
    let report = WindowsCertificationReport {
        schema_version: 1,
        certification_id: certification_id.clone(),
        integration_id: manifest.integration_id.clone(),
        binding_id: evidence.binding_id.clone(),
        certified,
        manifest_hash: manifest_hash.clone(),
        evidence_hash: evidence_hash.clone(),
        issues,
    };
    let signed_certification = if certified {
        let certifier_public_key = hex_encode(&certifier_key.verifying_key().to_bytes());
        let expires_at_unix_seconds = browser_egress_expiry(evidence);
        let payload = SignedCertificationPayload {
            schema_version: 1,
            certification_id: &certification_id,
            integration_id: &manifest.integration_id,
            binding_id: &evidence.binding_id,
            manifest_hash: &manifest_hash,
            evidence_hash: &evidence_hash,
            configuration_hash: &evidence.configuration_hash,
            adapter_descriptor_hash: &evidence.adapter_descriptor_hash,
            issued_at_unix_seconds: now_unix_seconds,
            expires_at_unix_seconds,
            certifier_id: &certifier_id,
            certifier_public_key: &certifier_public_key,
        };
        let signature_hex = hex_encode(&certifier_key.sign(&json_bytes(&payload)?).to_bytes());
        Some(SignedWindowsCertification {
            schema_version: 1,
            certification_id: certification_id.clone(),
            integration_id: manifest.integration_id.clone(),
            binding_id: evidence.binding_id.clone(),
            manifest_hash: manifest_hash.clone(),
            evidence_hash: evidence_hash.clone(),
            configuration_hash: evidence.configuration_hash.clone(),
            adapter_descriptor_hash: evidence.adapter_descriptor_hash.clone(),
            issued_at_unix_seconds: now_unix_seconds,
            expires_at_unix_seconds,
            certifier_id: certifier_id.clone(),
            certifier_public_key: certifier_public_key.clone(),
            signature_hex,
        })
    } else {
        None
    };
    Ok(WindowsBindingCertification {
        report,
        signed_certification,
    })
}

/// Verifies both signatures and reconstructs the opaque one-shot ledger input.
pub fn verify_signed_windows_certification(
    manifest: &WindowsRuntimeManifest,
    evidence: &WindowsBindingEvidence,
    certification: &SignedWindowsCertification,
    now_unix_seconds: u64,
) -> Result<CertifiedWindowsBinding, DesktopError> {
    manifest.validate()?;
    validate_evidence(evidence)?;
    validate_signed_certification(certification)?;
    if !verify_evidence_signature(evidence)? {
        return Err(DesktopError::Integrity(
            "Windows evidence signature is invalid".to_owned(),
        ));
    }
    let manifest_hash = manifest.manifest_hash()?;
    let evidence_hash = hash_value(evidence)?;
    if evidence.integration_id != manifest.integration_id
        || evidence.attestor_id != manifest.binding_attestor_id
        || evidence.signer_public_key != manifest.binding_attestor_public_key
        || evidence.host != manifest.host
        || evidence.adapter_kind != manifest.adapter_kind
        || evidence.adapter_descriptor_hash != manifest.adapter_descriptor.descriptor_hash()?
        || evidence.configuration_hash != manifest.configuration_hash
        || evidence.worker_executable_hash != manifest.worker_executable_hash
        || !evidence.capability.ready
        || !evidence.capability.process_isolated
        || !evidence.capability.job_kill_on_close
        || (manifest.adapter_kind == WindowsAdapterKind::Process
            && (!evidence.capability.network_isolation_enforced
                || evidence.capability.process_appcontainer_sid.as_deref()
                    != manifest
                        .process_isolation
                        .as_ref()
                        .map(|isolation| isolation.profile_sid.as_str())))
        || !browser_egress_matches(manifest, evidence, now_unix_seconds)?
        || certification.integration_id != manifest.integration_id
        || certification.binding_id != evidence.binding_id
        || certification.manifest_hash != manifest_hash
        || certification.evidence_hash != evidence_hash
        || certification.configuration_hash != manifest.configuration_hash
        || certification.adapter_descriptor_hash != evidence.adapter_descriptor_hash
        || certification.certifier_id != manifest.certifier_id
        || certification.certifier_public_key != manifest.certifier_public_key
        || certification.expires_at_unix_seconds != browser_egress_expiry(evidence)
        || now_unix_seconds < certification.issued_at_unix_seconds
        || now_unix_seconds >= certification.expires_at_unix_seconds
        || now_unix_seconds < evidence.observed_at_unix_seconds
        || now_unix_seconds >= evidence.expires_at_unix_seconds
        || !verify_certification_signature(certification)?
    {
        return Err(DesktopError::Integrity(
            "signed Windows certification does not match fresh reviewed evidence".to_owned(),
        ));
    }
    Ok(CertifiedWindowsBinding {
        integration_id: manifest.integration_id.clone(),
        binding_id: evidence.binding_id.clone(),
        certification_id: certification.certification_id.clone(),
        manifest_hash,
        evidence_hash,
        certification_hash: hash_value(certification)?,
        configuration_hash: manifest.configuration_hash.clone(),
        adapter_kind: manifest.adapter_kind,
        adapter_descriptor: manifest.adapter_descriptor.clone(),
        observed_at_unix_seconds: evidence.observed_at_unix_seconds,
        expires_at_unix_seconds: evidence
            .expires_at_unix_seconds
            .min(certification.expires_at_unix_seconds),
        activation_challenge: evidence
            .wfp_functional_attestation
            .as_ref()
            .map(|attestation| attestation.activation_challenge.clone()),
        self_test_report_hash: evidence
            .wfp_functional_attestation
            .as_ref()
            .map(|attestation| attestation.self_test_report_hash.clone()),
    })
}

fn validate_binding_input(input: &WindowsBindingInput) -> Result<(), DesktopError> {
    if input.schema_version != 1 {
        return Err(DesktopError::Invalid(
            "Windows binding schema_version must be 1".to_owned(),
        ));
    }
    validate_token(&input.binding_id, "binding_id")?;
    validate_token(&input.integration_id, "integration_id")?;
    validate_token(&input.attestor_id, "attestor_id")?;
    validate_lifetime(
        input.observed_at_unix_seconds,
        input.expires_at_unix_seconds,
    )?;
    input.host.validate()?;
    validate_hash(&input.adapter_descriptor_hash, "adapter_descriptor_hash")?;
    validate_hash(&input.configuration_hash, "configuration_hash")?;
    validate_absolute_path(&input.worker_executable, "worker_executable")?;
    validate_hash(&input.worker_executable_hash, "worker_executable_hash")?;
    input.capability.validate()?;
    if input.capability.adapter_kind != input.adapter_kind {
        return Err(DesktopError::Invalid(
            "capability observation adapter kind differs from binding".to_owned(),
        ));
    }
    match input.adapter_kind {
        WindowsAdapterKind::WebDriver => {
            match (
                input.browser_egress_evidence.as_ref(),
                input.wfp_functional_attestation.as_ref(),
            ) {
                (Some(evidence), None) => validate_browser_egress_evidence(evidence)?,
                (None, Some(attestation)) => {
                    crate::windows_attestation::validate_windows_wfp_functional_attestation_v2(
                        attestation,
                    )?;
                }
                _ => {
                    return Err(DesktopError::Invalid(
                        "WebDriver binding requires exactly one browser-egress proof".to_owned(),
                    ));
                }
            }
        }
        _ if input.browser_egress_evidence.is_some()
            || input.wfp_functional_attestation.is_some() =>
        {
            return Err(DesktopError::Invalid(
                "non-WebDriver binding contains browser-egress evidence".to_owned(),
            ));
        }
        _ => {}
    }
    Ok(())
}

fn validate_browser_egress_input(input: &WindowsBrowserEgressInput) -> Result<(), DesktopError> {
    if input.schema_version != 1 {
        return Err(DesktopError::Invalid(
            "browser-egress evidence schema_version must be 1".to_owned(),
        ));
    }
    validate_token(&input.enforcement_id, "browser egress enforcement_id")?;
    validate_hash(&input.policy_hash, "browser egress policy_hash")?;
    validate_token(&input.provider_id, "browser egress provider_id")?;
    validate_lifetime(
        input.observed_at_unix_seconds,
        input.expires_at_unix_seconds,
    )?;
    validate_browser_scope(&input.browser_session_ids, &input.allowed_origins)?;
    if !input.deny_by_default {
        return Err(DesktopError::Invalid(
            "browser egress must be deny-by-default".to_owned(),
        ));
    }
    Ok(())
}

fn validate_browser_egress_evidence(
    evidence: &SignedWindowsBrowserEgressEvidence,
) -> Result<(), DesktopError> {
    validate_browser_egress_input(&WindowsBrowserEgressInput {
        schema_version: evidence.schema_version,
        enforcement_id: evidence.enforcement_id.clone(),
        policy_hash: evidence.policy_hash.clone(),
        provider_id: evidence.provider_id.clone(),
        observed_at_unix_seconds: evidence.observed_at_unix_seconds,
        expires_at_unix_seconds: evidence.expires_at_unix_seconds,
        browser_session_ids: evidence.browser_session_ids.clone(),
        allowed_origins: evidence.allowed_origins.clone(),
        deny_by_default: evidence.deny_by_default,
    })?;
    validate_public_key(
        &evidence.signer_public_key,
        "browser egress signer_public_key",
    )?;
    let _ = hex_decode_array::<64>(&evidence.signature_hex)?;
    Ok(())
}

pub(crate) fn validate_browser_scope(
    session_ids: &BTreeSet<String>,
    origins: &BTreeSet<String>,
) -> Result<(), DesktopError> {
    if session_ids.is_empty()
        || session_ids.len() > 256
        || origins.is_empty()
        || origins.len() > 256
    {
        return Err(DesktopError::Invalid(
            "browser egress scope requires 1..=256 sessions and origins".to_owned(),
        ));
    }
    for session_id in session_ids {
        validate_token(session_id, "browser egress session_id")?;
    }
    for origin in origins {
        validate_origin(origin)?;
    }
    Ok(())
}

fn validate_probe_browser_egress(
    configuration: &WindowsAdapterConfiguration,
    host: &WindowsHostBinding,
    observed_at_unix_seconds: u64,
    evidence: Option<&SignedWindowsBrowserEgressEvidence>,
    functional: Option<&SignedWindowsWfpFunctionalAttestationV2>,
) -> Result<(), DesktopError> {
    match configuration.adapter_kind {
        WindowsAdapterKind::WebDriver => {
            if let Some(policy) = &configuration.browser_egress_policy {
                if evidence.is_some() {
                    return Err(DesktopError::AccessDenied(
                        "legacy v1 evidence is not accepted for the concrete WFP provider"
                            .to_owned(),
                    ));
                }
                let functional = functional.ok_or_else(|| {
                    DesktopError::AdapterUnavailable(
                        "concrete WFP WebDriver probe requires functional attestation v2"
                            .to_owned(),
                    )
                })?;
                crate::verify_windows_wfp_functional_attestation_v2(
                    functional,
                    &functional.signer_public_key,
                    observed_at_unix_seconds,
                )?;
                if functional.runtime_binding_digest != configuration.configuration_hash()?
                    || functional.machine_binding != *host
                    || functional.enforcement_id != policy.enforcement_id
                    || functional.provider_id != policy.provider_id
                    || functional.policy_hash != policy.policy_hash()?
                    || functional.browser_session_ids != configuration.browser_session_ids
                    || functional.allowed_origins != configuration.browser_allowed_origins
                {
                    return Err(DesktopError::Integrity(
                        "functional attestation differs from the runtime, host, scope, or WFP policy"
                            .to_owned(),
                    ));
                }
            } else {
                if functional.is_some() {
                    return Err(DesktopError::Invalid(
                        "external-provider WebDriver binding cannot contain WFP attestation"
                            .to_owned(),
                    ));
                }
                let evidence = evidence.ok_or_else(|| {
                    DesktopError::AdapterUnavailable(
                        "WebDriver probe requires signed external egress evidence".to_owned(),
                    )
                })?;
                validate_browser_egress_evidence(evidence)?;
                if !verify_browser_egress_signature(evidence)?
                    || evidence.provider_id == WINDOWS_WFP_LOOPBACK_PROVIDER_ID
                    || !evidence.deny_by_default
                    || evidence.browser_session_ids != configuration.browser_session_ids
                    || evidence.allowed_origins != configuration.browser_allowed_origins
                    || observed_at_unix_seconds < evidence.observed_at_unix_seconds
                    || observed_at_unix_seconds >= evidence.expires_at_unix_seconds
                {
                    return Err(DesktopError::Integrity(
                        "browser-egress evidence is invalid, stale, or has a different scope"
                            .to_owned(),
                    ));
                }
            }
        }
        _ if evidence.is_some() || functional.is_some() => {
            return Err(DesktopError::Invalid(
                "browser-egress evidence can only be attached to WebDriver probes".to_owned(),
            ));
        }
        _ => {}
    }
    Ok(())
}

fn browser_egress_matches(
    manifest: &WindowsRuntimeManifest,
    evidence: &WindowsBindingEvidence,
    now_unix_seconds: u64,
) -> Result<bool, DesktopError> {
    match manifest.adapter_kind {
        WindowsAdapterKind::WebDriver => {
            let Some(requirement) = manifest.browser_egress_requirement.as_ref() else {
                return Ok(false);
            };
            if requirement.provider_id == WINDOWS_WFP_LOOPBACK_PROVIDER_ID {
                if evidence.browser_egress_evidence.is_some() {
                    return Ok(false);
                }
                let Some(observed) = evidence.wfp_functional_attestation.as_ref() else {
                    return Ok(false);
                };
                Ok(crate::verify_windows_wfp_functional_attestation_v2(
                    observed,
                    &requirement.provider_public_key,
                    now_unix_seconds,
                )
                .is_ok()
                    && observed.runtime_binding_digest == evidence.configuration_hash
                    && observed.machine_binding == evidence.host
                    && observed.enforcement_id == requirement.enforcement_id
                    && observed.policy_hash == requirement.policy_hash
                    && observed.provider_id == requirement.provider_id
                    && observed.browser_session_ids == requirement.browser_session_ids
                    && observed.allowed_origins == requirement.allowed_origins
                    && requirement.functional_attestation_hash.as_deref()
                        == Some(hash_value(observed)?.as_str())
                    && requirement.edge_driver_executable_hash.as_deref()
                        == Some(observed.driver_executable_hash.as_str())
                    && requirement.self_test_report_hash.as_deref()
                        == Some(observed.self_test_report_hash.as_str())
                    && requirement.activation_challenge.as_deref()
                        == Some(observed.activation_challenge.as_str()))
            } else {
                if evidence.wfp_functional_attestation.is_some() {
                    return Ok(false);
                }
                let Some(observed) = evidence.browser_egress_evidence.as_ref() else {
                    return Ok(false);
                };
                Ok(verify_browser_egress_signature(observed)?
                    && observed.enforcement_id == requirement.enforcement_id
                    && observed.policy_hash == requirement.policy_hash
                    && observed.provider_id == requirement.provider_id
                    && observed.signer_public_key == requirement.provider_public_key
                    && observed.browser_session_ids == requirement.browser_session_ids
                    && observed.allowed_origins == requirement.allowed_origins
                    && observed.deny_by_default
                    && now_unix_seconds >= observed.observed_at_unix_seconds
                    && now_unix_seconds < observed.expires_at_unix_seconds)
            }
        }
        _ => Ok(manifest.browser_egress_requirement.is_none()
            && evidence.browser_egress_evidence.is_none()
            && evidence.wfp_functional_attestation.is_none()),
    }
}

fn browser_egress_expiry(evidence: &WindowsBindingEvidence) -> u64 {
    let external_expiry = evidence
        .browser_egress_evidence
        .as_ref()
        .map(|egress| egress.expires_at_unix_seconds);
    let functional_expiry = evidence
        .wfp_functional_attestation
        .as_ref()
        .map(|attestation| attestation.expires_at_unix_seconds);
    [external_expiry, functional_expiry]
        .into_iter()
        .flatten()
        .fold(evidence.expires_at_unix_seconds, u64::min)
}

fn validate_evidence(evidence: &WindowsBindingEvidence) -> Result<(), DesktopError> {
    validate_binding_input(&WindowsBindingInput {
        schema_version: evidence.schema_version,
        binding_id: evidence.binding_id.clone(),
        integration_id: evidence.integration_id.clone(),
        observed_at_unix_seconds: evidence.observed_at_unix_seconds,
        expires_at_unix_seconds: evidence.expires_at_unix_seconds,
        attestor_id: evidence.attestor_id.clone(),
        host: evidence.host.clone(),
        adapter_kind: evidence.adapter_kind,
        adapter_descriptor_hash: evidence.adapter_descriptor_hash.clone(),
        configuration_hash: evidence.configuration_hash.clone(),
        worker_executable: evidence.worker_executable.clone(),
        worker_executable_hash: evidence.worker_executable_hash.clone(),
        capability: evidence.capability.clone(),
        browser_egress_evidence: evidence.browser_egress_evidence.clone(),
        wfp_functional_attestation: evidence.wfp_functional_attestation.clone(),
    })?;
    validate_public_key(&evidence.signer_public_key, "evidence signer_public_key")?;
    let _ = hex_decode_array::<64>(&evidence.signature_hex)?;
    Ok(())
}

fn validate_signed_certification(
    certification: &SignedWindowsCertification,
) -> Result<(), DesktopError> {
    if certification.schema_version != 1 {
        return Err(DesktopError::Invalid(
            "Windows certification schema_version must be 1".to_owned(),
        ));
    }
    for (value, field) in [
        (&certification.certification_id, "certification_id"),
        (&certification.integration_id, "integration_id"),
        (&certification.binding_id, "binding_id"),
        (&certification.certifier_id, "certifier_id"),
    ] {
        validate_token(value, field)?;
    }
    for (value, field) in [
        (&certification.manifest_hash, "certification manifest_hash"),
        (&certification.evidence_hash, "certification evidence_hash"),
        (
            &certification.configuration_hash,
            "certification configuration_hash",
        ),
        (
            &certification.adapter_descriptor_hash,
            "certification adapter_descriptor_hash",
        ),
    ] {
        validate_hash(value, field)?;
    }
    validate_public_key(&certification.certifier_public_key, "certifier_public_key")?;
    let _ = hex_decode_array::<64>(&certification.signature_hex)?;
    if certification.issued_at_unix_seconds >= certification.expires_at_unix_seconds
        || certification.expires_at_unix_seconds - certification.issued_at_unix_seconds
            > MAX_BINDING_LIFETIME_SECONDS
    {
        return Err(DesktopError::Invalid(
            "Windows certification lifetime is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn verify_evidence_signature(evidence: &WindowsBindingEvidence) -> Result<bool, DesktopError> {
    let key = VerifyingKey::from_bytes(&hex_decode_array::<32>(&evidence.signer_public_key)?)
        .map_err(|error| DesktopError::Integrity(error.to_string()))?;
    let signature = Signature::from_bytes(&hex_decode_array::<64>(&evidence.signature_hex)?);
    Ok(key
        .verify(&json_bytes(&evidence_payload(evidence))?, &signature)
        .is_ok())
}

fn verify_browser_egress_signature(
    evidence: &SignedWindowsBrowserEgressEvidence,
) -> Result<bool, DesktopError> {
    let key = VerifyingKey::from_bytes(&hex_decode_array::<32>(&evidence.signer_public_key)?)
        .map_err(|error| DesktopError::Integrity(error.to_string()))?;
    let signature = Signature::from_bytes(&hex_decode_array::<64>(&evidence.signature_hex)?);
    let payload = SignedBrowserEgressPayload {
        schema_version: evidence.schema_version,
        enforcement_id: &evidence.enforcement_id,
        policy_hash: &evidence.policy_hash,
        provider_id: &evidence.provider_id,
        observed_at_unix_seconds: evidence.observed_at_unix_seconds,
        expires_at_unix_seconds: evidence.expires_at_unix_seconds,
        browser_session_ids: &evidence.browser_session_ids,
        allowed_origins: &evidence.allowed_origins,
        deny_by_default: evidence.deny_by_default,
        signer_public_key: &evidence.signer_public_key,
    };
    Ok(key.verify(&json_bytes(&payload)?, &signature).is_ok())
}

fn verify_certification_signature(
    certification: &SignedWindowsCertification,
) -> Result<bool, DesktopError> {
    let key = VerifyingKey::from_bytes(&hex_decode_array::<32>(
        &certification.certifier_public_key,
    )?)
    .map_err(|error| DesktopError::Integrity(error.to_string()))?;
    let signature = Signature::from_bytes(&hex_decode_array::<64>(&certification.signature_hex)?);
    Ok(key
        .verify(
            &json_bytes(&certification_payload(certification))?,
            &signature,
        )
        .is_ok())
}

fn evidence_payload_from_input<'a>(
    input: &'a WindowsBindingInput,
    signer_public_key: &'a str,
) -> SignedEvidencePayload<'a> {
    SignedEvidencePayload {
        schema_version: input.schema_version,
        binding_id: &input.binding_id,
        integration_id: &input.integration_id,
        observed_at_unix_seconds: input.observed_at_unix_seconds,
        expires_at_unix_seconds: input.expires_at_unix_seconds,
        attestor_id: &input.attestor_id,
        host: &input.host,
        adapter_kind: input.adapter_kind,
        adapter_descriptor_hash: &input.adapter_descriptor_hash,
        configuration_hash: &input.configuration_hash,
        worker_executable: &input.worker_executable,
        worker_executable_hash: &input.worker_executable_hash,
        capability: &input.capability,
        browser_egress_evidence: &input.browser_egress_evidence,
        wfp_functional_attestation: &input.wfp_functional_attestation,
        signer_public_key,
    }
}

fn evidence_payload(evidence: &WindowsBindingEvidence) -> SignedEvidencePayload<'_> {
    SignedEvidencePayload {
        schema_version: evidence.schema_version,
        binding_id: &evidence.binding_id,
        integration_id: &evidence.integration_id,
        observed_at_unix_seconds: evidence.observed_at_unix_seconds,
        expires_at_unix_seconds: evidence.expires_at_unix_seconds,
        attestor_id: &evidence.attestor_id,
        host: &evidence.host,
        adapter_kind: evidence.adapter_kind,
        adapter_descriptor_hash: &evidence.adapter_descriptor_hash,
        configuration_hash: &evidence.configuration_hash,
        worker_executable: &evidence.worker_executable,
        worker_executable_hash: &evidence.worker_executable_hash,
        capability: &evidence.capability,
        browser_egress_evidence: &evidence.browser_egress_evidence,
        wfp_functional_attestation: &evidence.wfp_functional_attestation,
        signer_public_key: &evidence.signer_public_key,
    }
}

fn certification_payload(
    certification: &SignedWindowsCertification,
) -> SignedCertificationPayload<'_> {
    SignedCertificationPayload {
        schema_version: certification.schema_version,
        certification_id: &certification.certification_id,
        integration_id: &certification.integration_id,
        binding_id: &certification.binding_id,
        manifest_hash: &certification.manifest_hash,
        evidence_hash: &certification.evidence_hash,
        configuration_hash: &certification.configuration_hash,
        adapter_descriptor_hash: &certification.adapter_descriptor_hash,
        issued_at_unix_seconds: certification.issued_at_unix_seconds,
        expires_at_unix_seconds: certification.expires_at_unix_seconds,
        certifier_id: &certification.certifier_id,
        certifier_public_key: &certification.certifier_public_key,
    }
}

fn descriptor_for_kind(kind: WindowsAdapterKind) -> Result<DesktopAdapterDescriptor, DesktopError> {
    let (adapter_id, capabilities, network_capable) = match kind {
        WindowsAdapterKind::UiAutomation => (
            "windows-uia.desktop",
            BTreeSet::from([
                DesktopCapability::ListWindows,
                DesktopCapability::UiInteract,
            ]),
            false,
        ),
        WindowsAdapterKind::WebDriver => (
            "windows-webdriver.desktop",
            BTreeSet::from([
                DesktopCapability::BrowserNavigate,
                DesktopCapability::BrowserInteract,
            ]),
            true,
        ),
        WindowsAdapterKind::FileWrite => (
            "windows-file-write.desktop",
            BTreeSet::from([DesktopCapability::WriteFile]),
            false,
        ),
        WindowsAdapterKind::Process => (
            "windows-process.desktop",
            BTreeSet::from([
                DesktopCapability::LaunchProcess,
                DesktopCapability::TerminateProcess,
            ]),
            false,
        ),
    };
    let descriptor = DesktopAdapterDescriptor {
        schema_version: 1,
        adapter_id: adapter_id.to_owned(),
        adapter_version: "1.0.0".to_owned(),
        platform: "windows".to_owned(),
        capabilities,
        concrete_host_adapter: true,
        process_isolated: true,
        network_capable,
    };
    descriptor.validate()?;
    Ok(descriptor)
}

fn validate_lifetime(observed: u64, expires: u64) -> Result<(), DesktopError> {
    if observed == 0 || expires <= observed || expires - observed > MAX_BINDING_LIFETIME_SECONDS {
        return Err(DesktopError::Invalid(
            "Windows binding lifetime must be positive and no longer than 15 minutes".to_owned(),
        ));
    }
    Ok(())
}

fn validate_public_key(value: &str, field: &str) -> Result<(), DesktopError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DesktopError::Invalid(format!(
            "{field} must be a 32-byte hexadecimal Ed25519 key"
        )));
    }
    Ok(())
}

fn validate_absolute_path(value: &str, field: &str) -> Result<(), DesktopError> {
    validate_text(value, field)?;
    let path = Path::new(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(DesktopError::Invalid(format!(
            "{field} must be absolute without parent traversal"
        )));
    }
    Ok(())
}

fn validate_origin(value: &str) -> Result<(), DesktopError> {
    validate_text(value, "browser allowed origin")?;
    let rest = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .ok_or_else(|| DesktopError::Invalid("browser origin must use HTTP or HTTPS".to_owned()))?;
    if rest.is_empty()
        || rest.contains('/')
        || rest.contains('?')
        || rest.contains('#')
        || rest.contains('@')
    {
        return Err(DesktopError::Invalid(
            "browser origin must contain scheme and authority only".to_owned(),
        ));
    }
    Ok(())
}

fn validate_loopback_origin(value: &str) -> Result<(), DesktopError> {
    validate_origin(value)?;
    let authority = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .ok_or_else(|| DesktopError::Invalid("browser origin has no HTTP scheme".to_owned()))?;
    let valid = authority == "localhost"
        || authority.starts_with("localhost:")
        || authority == "127.0.0.1"
        || authority.starts_with("127.0.0.1:")
        || authority == "[::1]"
        || authority.starts_with("[::1]:");
    if !valid {
        return Err(DesktopError::Invalid(
            "Windows WFP loopback-only policy accepts only localhost, 127.0.0.1, or [::1] origins"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_loopback_endpoint(value: &str) -> Result<(), DesktopError> {
    validate_text(value, "WebDriver endpoint")?;
    let authority = value.strip_prefix("http://").ok_or_else(|| {
        DesktopError::Invalid("WebDriver endpoint must use loopback HTTP".to_owned())
    })?;
    let valid_host = authority.starts_with("127.0.0.1:")
        || authority.starts_with("localhost:")
        || authority.starts_with("[::1]:");
    if !valid_host
        || authority.contains('/')
        || authority.contains('?')
        || authority.contains('#')
        || authority.contains('@')
    {
        return Err(DesktopError::Invalid(
            "WebDriver endpoint must be an HTTP loopback authority without a path".to_owned(),
        ));
    }
    let port = authority
        .rsplit_once(':')
        .map(|(_, port)| port.trim_end_matches(']'))
        .ok_or_else(|| DesktopError::Invalid("WebDriver endpoint has no port".to_owned()))?
        .parse::<u16>()
        .map_err(|_| DesktopError::Invalid("WebDriver endpoint port is invalid".to_owned()))?;
    if port == 0 {
        return Err(DesktopError::Invalid(
            "WebDriver endpoint port must be nonzero".to_owned(),
        ));
    }
    Ok(())
}

fn validate_appcontainer_profile_name(value: &str) -> Result<(), DesktopError> {
    validate_text(value, "AppContainer profile_name")?;
    if value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(DesktopError::Invalid(
            "AppContainer profile_name must be 1..=64 ASCII letters, digits, '.', '-', or '_'"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_windows_sid(value: &str, field: &str) -> Result<(), DesktopError> {
    validate_text(value, field)?;
    if !value.starts_with("S-1-")
        || value.len() > 184
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'S' | b'-'))
    {
        return Err(DesktopError::Invalid(format!(
            "{field} is not a canonical Windows SID string"
        )));
    }
    Ok(())
}

fn canonical_regular_path(path: &Path, label: &str) -> Result<PathBuf, DesktopError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || d2i_windows_host::is_reparse_point(path)
            .map_err(|error| DesktopError::Integrity(error.to_string()))?
    {
        return Err(DesktopError::Integrity(format!(
            "{label} must be a non-reparse regular file"
        )));
    }
    std::fs::canonicalize(path).map_err(|error| DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })
}

fn compare(
    condition: bool,
    issues: &mut Vec<WindowsCertificationIssue>,
    code: &str,
    message: &str,
    remediation: &str,
) {
    if !condition {
        issues.push(WindowsCertificationIssue {
            code: code.to_owned(),
            message: message.to_owned(),
            remediation: remediation.to_owned(),
        });
    }
}
