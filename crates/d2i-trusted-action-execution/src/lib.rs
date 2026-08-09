//! Audit-safe contracts for binding one admitted Cognitive action to execution.
//!
//! This crate is side-effect free. It validates and seals hashes, identities,
//! and lifetimes; platform target material, payload bytes, adapter handles, and
//! execution permits remain in the product integration.

use d2i_action_candidates::{CandidateActionArguments, CandidateActionInput};
use d2i_action_selection::GroundedActionArgumentsV1;
pub use d2i_action_selection::PolicyReadyActionV1;
use d2i_cognitive_ir::{ObservationSnapshot, Reversibility};
pub use d2i_policy_admission::AdapterKindV1;
use d2i_policy_admission::{ActivationEligibilityContextV1, CognitiveActivationAdmissionV1};
use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Trusted Action Execution Binding schema version.
pub const TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION: u32 = 1;
/// Embedded Core-owned JSON Schema.
pub const TRUSTED_ACTION_EXECUTION_BINDING_V1_SCHEMA: &str =
    include_str!("../../../schemas/cognitive/trusted-action-execution-binding-v1.schema.json");

const MAX_ID_LEN: usize = 128;
const MAX_EVIDENCE_IDS: usize = 128;
const MAX_WARNINGS: usize = 64;
const MAX_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_JSON_DEPTH: usize = 64;
const MAX_JSON_NODES: usize = 100_000;
const MAX_SESSION_TTL_MS: u64 = 15 * 60 * 1_000;
const MAX_RESOLUTION_TTL_MS: u64 = 60_000;
const MAX_INPUT_BYTES: u64 = 8 * 1024 * 1024;

/// Fail-closed trusted execution contract error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustedExecutionError {
    /// A bounded field or interval is malformed.
    Invalid(String),
    /// A sealed hash or exact lifecycle binding differs.
    Integrity(String),
    /// The action is well formed but outside the six-action v1 surface.
    Unsupported(String),
    /// A one-shot identity or terminal artifact was reused.
    Replay(String),
    /// Strict JSON parsing or canonical serialization failed.
    Json(String),
}

impl Display for TrustedExecutionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid trusted execution: {message}"),
            Self::Integrity(message) => {
                write!(formatter, "trusted execution integrity failure: {message}")
            }
            Self::Unsupported(message) => {
                write!(formatter, "unsupported trusted execution: {message}")
            }
            Self::Replay(message) => write!(formatter, "trusted execution replay: {message}"),
            Self::Json(message) => write!(formatter, "trusted execution JSON failure: {message}"),
        }
    }
}

impl Error for TrustedExecutionError {}

/// Closed target source accepted by trusted execution v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedTargetSourceKindV1 {
    Uia,
    WebDriver,
}

/// Closed desktop capability family exposed in audit-safe artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedDesktopCapabilityV1 {
    UiInteract,
    BrowserInteract,
}

/// Closed operation family accepted by trusted execution v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedDesktopOperationKindV1 {
    UiaInvoke,
    UiaSetValue,
    UiaToggle,
    WebDriverClick,
    WebDriverType,
    WebDriverSelect,
}

impl TrustedDesktopOperationKindV1 {
    /// Returns the exact Cognitive capability token.
    #[must_use]
    pub const fn capability_id(self) -> &'static str {
        match self {
            Self::UiaInvoke => "uia.invoke",
            Self::UiaSetValue => "uia.set_value",
            Self::UiaToggle => "uia.toggle",
            Self::WebDriverClick => "webdriver.click",
            Self::WebDriverType => "webdriver.type",
            Self::WebDriverSelect => "webdriver.select",
        }
    }

    /// Returns the required source kind.
    #[must_use]
    pub const fn source_kind(self) -> TrustedTargetSourceKindV1 {
        match self {
            Self::UiaInvoke | Self::UiaSetValue | Self::UiaToggle => TrustedTargetSourceKindV1::Uia,
            Self::WebDriverClick | Self::WebDriverType | Self::WebDriverSelect => {
                TrustedTargetSourceKindV1::WebDriver
            }
        }
    }

    /// Returns the required activation adapter kind.
    #[must_use]
    pub const fn adapter_kind(self) -> AdapterKindV1 {
        match self.source_kind() {
            TrustedTargetSourceKindV1::Uia => AdapterKindV1::Uia,
            TrustedTargetSourceKindV1::WebDriver => AdapterKindV1::WebDriver,
        }
    }

    /// Returns the audit-safe Desktop capability family.
    #[must_use]
    pub const fn desktop_capability(self) -> TrustedDesktopCapabilityV1 {
        match self.source_kind() {
            TrustedTargetSourceKindV1::Uia => TrustedDesktopCapabilityV1::UiInteract,
            TrustedTargetSourceKindV1::WebDriver => TrustedDesktopCapabilityV1::BrowserInteract,
        }
    }

    /// Returns whether the operation requires non-secret input bytes.
    #[must_use]
    pub const fn requires_input(self) -> bool {
        matches!(
            self,
            Self::UiaSetValue | Self::WebDriverType | Self::WebDriverSelect
        )
    }
}

/// Closed input material kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputMaterialKindV1 {
    SetText,
    TypeText,
    Select,
}

/// v1 accepts non-secret material only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretClassificationV1 {
    NonSecret,
}

/// Terminal adapter-attempt status. It is not a verification verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedExecutionStatusV1 {
    Succeeded,
    Failed,
    Cancelled,
    DeniedBeforeCommit,
    Aborted,
}

/// Optional adapter status carried by a receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedAdapterOutcomeStatusV1 {
    Succeeded,
    Failed,
}

/// Immutable projection of one consumed platform activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedPlatformActivationV1 {
    pub activation_ledger_id: String,
    pub activation_ledger_chain_head: String,
    pub integration_id: String,
    pub binding_id: String,
    pub activation_record_hash: String,
    pub runtime_binding_sha256: String,
    pub adapter_kind: AdapterKindV1,
    pub adapter_descriptor_sha256: String,
    pub observed_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
}

impl TrustedPlatformActivationV1 {
    /// Validates all immutable activation identities and its bounded lifetime.
    pub fn validate(&self) -> Result<(), TrustedExecutionError> {
        for (value, label) in [
            (&self.activation_ledger_id, "activation_ledger_id"),
            (&self.integration_id, "activation integration_id"),
            (&self.binding_id, "activation binding_id"),
        ] {
            validate_id(value, label)?;
        }
        for (value, label) in [
            (
                &self.activation_ledger_chain_head,
                "activation_ledger_chain_head",
            ),
            (&self.activation_record_hash, "activation_record_hash"),
            (&self.runtime_binding_sha256, "runtime_binding_sha256"),
            (&self.adapter_descriptor_sha256, "adapter_descriptor_sha256"),
        ] {
            validate_hash(value, label)?;
        }
        validate_interval_seconds(
            self.observed_at_unix_seconds,
            self.expires_at_unix_seconds,
            "platform activation",
        )
    }
}

/// Caller-sealed execution session and runtime package identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedExecutionSessionV1 {
    pub schema_version: u32,
    pub execution_session_id: String,
    pub action_sequence: u64,
    pub runtime_build_id: String,
    pub runtime_package_sha256: String,
    pub generated_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub expected_organization_id: String,
    pub expected_integration_id: String,
    pub expected_adapter_kind: AdapterKindV1,
    pub expected_activation_ledger_id: String,
    pub expected_activation_ledger_chain_head: String,
    pub evidence_ids: Vec<String>,
    pub session_sha256: String,
}

impl TrustedExecutionSessionV1 {
    /// Sorts set-like evidence and seals the session.
    pub fn seal(mut self) -> Result<Self, TrustedExecutionError> {
        self.evidence_ids.sort();
        self.session_sha256 = self.compute_session_sha256()?;
        self.validate()?;
        Ok(self)
    }

    /// Computes the canonical session digest without its self-hash.
    pub fn compute_session_sha256(&self) -> Result<String, TrustedExecutionError> {
        hash_without_field(self, "session_sha256")
    }

    /// Validates bounds, exact identifiers, lifetime, and self-hash.
    pub fn validate(&self) -> Result<(), TrustedExecutionError> {
        validate_version(self.schema_version, "trusted execution session")?;
        for (value, label) in [
            (&self.execution_session_id, "execution_session_id"),
            (&self.runtime_build_id, "runtime_build_id"),
            (&self.expected_organization_id, "expected_organization_id"),
            (&self.expected_integration_id, "expected_integration_id"),
            (
                &self.expected_activation_ledger_id,
                "expected_activation_ledger_id",
            ),
        ] {
            validate_id(value, label)?;
        }
        if self.action_sequence == 0 {
            return invalid("action_sequence must be nonzero");
        }
        validate_hash(&self.runtime_package_sha256, "runtime_package_sha256")?;
        validate_hash(
            &self.expected_activation_ledger_chain_head,
            "expected_activation_ledger_chain_head",
        )?;
        validate_short_interval_ms(
            self.generated_at_unix_ms,
            self.expires_at_unix_ms,
            MAX_SESSION_TTL_MS,
            "trusted execution session",
        )?;
        validate_sorted_ids(
            &self.evidence_ids,
            "session evidence_ids",
            MAX_EVIDENCE_IDS,
            false,
        )?;
        validate_hash(&self.session_sha256, "session_sha256")?;
        if self.compute_session_sha256()? != self.session_sha256 {
            return integrity("session_sha256 differs from canonical session");
        }
        reject_forbidden_json(self, "trusted execution session")
    }

    /// Rejects an otherwise valid session outside its active interval.
    pub fn validate_at(&self, now_unix_ms: u64) -> Result<(), TrustedExecutionError> {
        self.validate()?;
        if now_unix_ms < self.generated_at_unix_ms || now_unix_ms >= self.expires_at_unix_ms {
            return invalid("trusted execution session is not active");
        }
        Ok(())
    }
}

/// Exact Cognitive, observation, session, eligibility, and activation binding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedExecutionBindingRequestV1 {
    pub schema_version: u32,
    pub policy_ready_action: PolicyReadyActionV1,
    pub cognitive_activation_admission: CognitiveActivationAdmissionV1,
    pub activation_eligibility: ActivationEligibilityContextV1,
    pub execution_session: TrustedExecutionSessionV1,
    pub platform_activation: TrustedPlatformActivationV1,
    pub source_observation_id: String,
    pub source_observation_hash: String,
    pub source_observation_sequence: u64,
    pub source_target_binding_sha256: String,
    pub expected_grounded_target_binding_sha256: String,
    pub expected_capability_binding_sha256: String,
    pub expected_policy_decision_sha256: String,
    pub expected_activation_admission_sha256: String,
    pub request_sha256: String,
}

impl TrustedExecutionBindingRequestV1 {
    /// Builds and seals a request from exact trusted artifacts.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy_ready_action: PolicyReadyActionV1,
        cognitive_activation_admission: CognitiveActivationAdmissionV1,
        activation_eligibility: ActivationEligibilityContextV1,
        execution_session: TrustedExecutionSessionV1,
        platform_activation: TrustedPlatformActivationV1,
        source_observation: &ObservationSnapshot,
        expected_grounded_target_binding_sha256: String,
    ) -> Result<Self, TrustedExecutionError> {
        source_observation
            .validate()
            .map_err(|error| TrustedExecutionError::Integrity(error.to_string()))?;
        let source_target_binding_sha256 = canonical_sha256(&source_observation.target_binding)?;
        let expected_capability_binding_sha256 =
            policy_ready_action.capability_binding_sha256.clone();
        let expected_policy_decision_sha256 = cognitive_activation_admission
            .policy_decision_sha256
            .clone();
        let expected_activation_admission_sha256 =
            cognitive_activation_admission.admission_sha256.clone();
        let mut request = Self {
            schema_version: TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION,
            policy_ready_action,
            cognitive_activation_admission,
            activation_eligibility,
            execution_session,
            platform_activation,
            source_observation_id: source_observation.observation_id.clone(),
            source_observation_hash: source_observation.state_hash.clone(),
            source_observation_sequence: source_observation.sequence,
            source_target_binding_sha256,
            expected_grounded_target_binding_sha256,
            expected_capability_binding_sha256,
            expected_policy_decision_sha256,
            expected_activation_admission_sha256,
            request_sha256: empty_hash(),
        };
        request.request_sha256 = request.compute_request_sha256()?;
        request.validate()?;
        Ok(request)
    }

    /// Computes the canonical request digest without its self-hash.
    pub fn compute_request_sha256(&self) -> Result<String, TrustedExecutionError> {
        hash_without_field(self, "request_sha256")
    }

    /// Validates every exact lifecycle and authority binding.
    pub fn validate(&self) -> Result<(), TrustedExecutionError> {
        validate_version(self.schema_version, "trusted execution request")?;
        self.cognitive_activation_admission
            .validate()
            .map_err(|error| TrustedExecutionError::Integrity(error.to_string()))?;
        self.activation_eligibility
            .validate()
            .map_err(|error| TrustedExecutionError::Integrity(error.to_string()))?;
        self.execution_session.validate()?;
        self.platform_activation.validate()?;
        validate_policy_ready(&self.policy_ready_action)?;
        validate_id(&self.source_observation_id, "source_observation_id")?;
        for (value, label) in [
            (&self.source_observation_hash, "source_observation_hash"),
            (
                &self.source_target_binding_sha256,
                "source_target_binding_sha256",
            ),
            (
                &self.expected_grounded_target_binding_sha256,
                "expected_grounded_target_binding_sha256",
            ),
            (
                &self.expected_capability_binding_sha256,
                "expected_capability_binding_sha256",
            ),
            (
                &self.expected_policy_decision_sha256,
                "expected_policy_decision_sha256",
            ),
            (
                &self.expected_activation_admission_sha256,
                "expected_activation_admission_sha256",
            ),
        ] {
            validate_hash(value, label)?;
        }
        let ready = &self.policy_ready_action;
        let admission = &self.cognitive_activation_admission;
        let eligibility = &self.activation_eligibility;
        let session = &self.execution_session;
        let platform = &self.platform_activation;
        let proposal_sha256 = canonical_sha256(&ready.proposal)?;
        if admission.policy_ready_sha256 != ready.policy_ready_sha256
            || admission.selection_sha256 != ready.selection_sha256
            || admission.proposal_id != ready.proposal.proposal_id
            || admission.proposal_sha256 != proposal_sha256
            || admission.goal_id != ready.goal_id
            || admission.plan_generation_id != ready.plan_generation_id
            || admission.source_observation_hash != ready.source_observation_hash
            || admission.source_observation_sequence != ready.source_observation_sequence
            || admission.capability_id != ready.capability_id
            || admission.semantic_target_id != ready.semantic_target_id
            || admission.application_pack_sha256 != ready.application_pack_sha256
            || admission.capability_binding_sha256 != ready.capability_binding_sha256
            || self.source_observation_id != ready.observation_id
            || self.source_observation_hash != ready.source_observation_hash
            || self.source_observation_sequence != ready.source_observation_sequence
            || self.expected_capability_binding_sha256 != ready.capability_binding_sha256
            || self.expected_policy_decision_sha256 != admission.policy_decision_sha256
            || self.expected_activation_admission_sha256 != admission.admission_sha256
        {
            return integrity("Cognitive action, admission, or observation binding differs");
        }
        if eligibility.organization_id != session.expected_organization_id
            || eligibility.integration_id != session.expected_integration_id
            || eligibility.integration_id != admission.integration_id
            || eligibility.integration_id != platform.integration_id
            || eligibility.activation_ledger_id != session.expected_activation_ledger_id
            || eligibility.activation_ledger_chain_head
                != session.expected_activation_ledger_chain_head
            || eligibility.activation_ledger_id != platform.activation_ledger_id
            || eligibility.activation_ledger_chain_head != platform.activation_ledger_chain_head
            || eligibility.application_pack_sha256 != ready.application_pack_sha256
            || eligibility.runtime_binding_sha256 != admission.runtime_binding_sha256
            || eligibility.runtime_binding_sha256 != platform.runtime_binding_sha256
            || eligibility.adapter_kind != admission.adapter_kind
            || eligibility.adapter_kind != session.expected_adapter_kind
            || eligibility.adapter_kind != platform.adapter_kind
            || eligibility.capability_binding_sha256 != ready.capability_binding_sha256
            || eligibility.source_observation_hash != ready.source_observation_hash
            || eligibility.source_observation_sequence != ready.source_observation_sequence
            || !eligibility
                .eligible_capability_ids
                .contains(&ready.capability_id)
        {
            return integrity("eligibility, session, admission, or platform activation differs");
        }
        let operation = operation_kind(ready)?;
        if self.expected_grounded_target_binding_sha256 != grounded_target_binding_sha256(ready)? {
            return integrity("expected grounded target differs from proposal arguments");
        }
        if operation.adapter_kind() != platform.adapter_kind
            || operation.adapter_kind() != admission.adapter_kind
        {
            return integrity("closed operation and activated adapter kind differ");
        }
        let intersection_start_ms = session
            .generated_at_unix_ms
            .max(admission.admitted_at_unix_seconds.saturating_mul(1_000))
            .max(eligibility.observed_at_unix_seconds.saturating_mul(1_000))
            .max(platform.observed_at_unix_seconds.saturating_mul(1_000));
        let intersection_end_ms = session
            .expires_at_unix_ms
            .min(admission.expires_at_unix_seconds.saturating_mul(1_000))
            .min(eligibility.expires_at_unix_seconds.saturating_mul(1_000))
            .min(platform.expires_at_unix_seconds.saturating_mul(1_000));
        if intersection_start_ms >= intersection_end_ms {
            return invalid("trusted execution validity intersection is empty");
        }
        validate_hash(&self.request_sha256, "request_sha256")?;
        if self.compute_request_sha256()? != self.request_sha256 {
            return integrity("request_sha256 differs from canonical request");
        }
        reject_forbidden_json(self, "trusted execution request")
    }

    /// Validates the source snapshot supplied at the product boundary.
    pub fn validate_source_observation(
        &self,
        observation: &ObservationSnapshot,
    ) -> Result<(), TrustedExecutionError> {
        observation
            .validate()
            .map_err(|error| TrustedExecutionError::Integrity(error.to_string()))?;
        if observation.observation_id != self.source_observation_id
            || observation.state_hash != self.source_observation_hash
            || observation.sequence != self.source_observation_sequence
            || canonical_sha256(&observation.target_binding)? != self.source_target_binding_sha256
        {
            return integrity("source observation was substituted");
        }
        Ok(())
    }
}

/// Audit-safe proof that exactly one runtime target was resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetResolutionProofV1 {
    pub schema_version: u32,
    pub resolution_id: String,
    pub request_sha256: String,
    pub proposal_sha256: String,
    pub grounded_target_binding_sha256: String,
    pub selected_element_id: String,
    pub selected_element_kind: String,
    pub source_kind: TrustedTargetSourceKindV1,
    pub source_observation_id: String,
    pub source_observation_hash: String,
    pub source_observation_sequence: u64,
    pub fresh_resolution_observation_hash: String,
    pub runtime_binding_sha256: String,
    pub integration_id: String,
    pub binding_id: String,
    pub activation_record_hash: String,
    pub adapter_descriptor_sha256: String,
    pub target_material_sha256: String,
    pub unique_match_count: u32,
    pub resolved_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub resolution_sha256: String,
}

impl TargetResolutionProofV1 {
    /// Sorts evidence and seals the proof.
    pub fn seal(mut self) -> Result<Self, TrustedExecutionError> {
        self.evidence_ids.sort();
        self.resolution_sha256 = self.compute_resolution_sha256()?;
        self.validate()?;
        Ok(self)
    }

    /// Computes the canonical proof digest without its self-hash.
    pub fn compute_resolution_sha256(&self) -> Result<String, TrustedExecutionError> {
        hash_without_field(self, "resolution_sha256")
    }

    /// Validates proof bounds, one-match semantics, and self-hash.
    pub fn validate(&self) -> Result<(), TrustedExecutionError> {
        validate_version(self.schema_version, "target resolution proof")?;
        for (value, label) in [
            (&self.resolution_id, "resolution_id"),
            (&self.selected_element_id, "resolved selected_element_id"),
            (
                &self.selected_element_kind,
                "resolved selected_element_kind",
            ),
            (
                &self.source_observation_id,
                "resolved source_observation_id",
            ),
            (&self.integration_id, "resolved integration_id"),
            (&self.binding_id, "resolved binding_id"),
        ] {
            validate_id(value, label)?;
        }
        for (value, label) in [
            (&self.request_sha256, "resolution request_sha256"),
            (&self.proposal_sha256, "resolution proposal_sha256"),
            (
                &self.grounded_target_binding_sha256,
                "grounded_target_binding_sha256",
            ),
            (
                &self.source_observation_hash,
                "resolution source_observation_hash",
            ),
            (
                &self.fresh_resolution_observation_hash,
                "fresh_resolution_observation_hash",
            ),
            (
                &self.runtime_binding_sha256,
                "resolution runtime_binding_sha256",
            ),
            (
                &self.activation_record_hash,
                "resolution activation_record_hash",
            ),
            (
                &self.adapter_descriptor_sha256,
                "resolution adapter_descriptor_sha256",
            ),
            (&self.target_material_sha256, "target_material_sha256"),
        ] {
            validate_hash(value, label)?;
        }
        if self.unique_match_count != 1 {
            return invalid("target resolution unique_match_count must be 1");
        }
        validate_short_interval_ms(
            self.resolved_at_unix_ms,
            self.expires_at_unix_ms,
            MAX_RESOLUTION_TTL_MS,
            "target resolution proof",
        )?;
        validate_sorted_ids(
            &self.evidence_ids,
            "resolution evidence_ids",
            MAX_EVIDENCE_IDS,
            false,
        )?;
        validate_hash(&self.resolution_sha256, "resolution_sha256")?;
        if self.compute_resolution_sha256()? != self.resolution_sha256 {
            return integrity("resolution_sha256 differs from canonical proof");
        }
        reject_forbidden_json(self, "target resolution proof")
    }

    /// Verifies exact request, selected element, source, and activation bindings.
    pub fn validate_against(
        &self,
        request: &TrustedExecutionBindingRequestV1,
    ) -> Result<(), TrustedExecutionError> {
        self.validate()?;
        request.validate()?;
        let ready = &request.policy_ready_action;
        let platform = &request.platform_activation;
        if self.request_sha256 != request.request_sha256
            || self.proposal_sha256 != canonical_sha256(&ready.proposal)?
            || self.grounded_target_binding_sha256
                != request.expected_grounded_target_binding_sha256
            || self.selected_element_id != ready.selected_element_id
            || self.selected_element_kind != ready.selected_element_kind
            || self.source_kind != operation_kind(ready)?.source_kind()
            || self.source_observation_id != request.source_observation_id
            || self.source_observation_hash != request.source_observation_hash
            || self.source_observation_sequence != request.source_observation_sequence
            || self.runtime_binding_sha256 != platform.runtime_binding_sha256
            || self.integration_id != platform.integration_id
            || self.binding_id != platform.binding_id
            || self.activation_record_hash != platform.activation_record_hash
            || self.adapter_descriptor_sha256 != platform.adapter_descriptor_sha256
        {
            return integrity("target resolution proof differs from execution request");
        }
        Ok(())
    }
}

/// Audit-safe proof of exact non-secret input bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputMaterialProofV1 {
    pub schema_version: u32,
    pub material_id: String,
    pub request_sha256: String,
    pub proposal_sha256: String,
    pub input_kind: InputMaterialKindV1,
    pub expected_content_sha256: String,
    pub supplied_content_sha256: String,
    pub byte_length: u64,
    pub secret_classification: SecretClassificationV1,
    pub material_source_id: String,
    pub resolved_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub material_proof_sha256: String,
}

impl InputMaterialProofV1 {
    /// Sorts evidence and seals the proof.
    pub fn seal(mut self) -> Result<Self, TrustedExecutionError> {
        self.evidence_ids.sort();
        self.material_proof_sha256 = self.compute_material_proof_sha256()?;
        self.validate()?;
        Ok(self)
    }

    /// Computes the canonical proof digest without its self-hash.
    pub fn compute_material_proof_sha256(&self) -> Result<String, TrustedExecutionError> {
        hash_without_field(self, "material_proof_sha256")
    }

    /// Validates non-secret classification, exact content hash, and bounds.
    pub fn validate(&self) -> Result<(), TrustedExecutionError> {
        validate_version(self.schema_version, "input material proof")?;
        validate_id(&self.material_id, "material_id")?;
        validate_id(&self.material_source_id, "material_source_id")?;
        for (value, label) in [
            (&self.request_sha256, "material request_sha256"),
            (&self.proposal_sha256, "material proposal_sha256"),
            (&self.expected_content_sha256, "expected_content_sha256"),
            (&self.supplied_content_sha256, "supplied_content_sha256"),
        ] {
            validate_hash(value, label)?;
        }
        if self.expected_content_sha256 != self.supplied_content_sha256
            || self.byte_length == 0
            || self.byte_length > MAX_INPUT_BYTES
        {
            return integrity("input material hash or byte bound differs");
        }
        validate_short_interval_ms(
            self.resolved_at_unix_ms,
            self.expires_at_unix_ms,
            MAX_RESOLUTION_TTL_MS,
            "input material proof",
        )?;
        validate_sorted_ids(
            &self.evidence_ids,
            "material evidence_ids",
            MAX_EVIDENCE_IDS,
            false,
        )?;
        validate_hash(&self.material_proof_sha256, "material_proof_sha256")?;
        if self.compute_material_proof_sha256()? != self.material_proof_sha256 {
            return integrity("material_proof_sha256 differs from canonical proof");
        }
        reject_forbidden_json(self, "input material proof")
    }

    /// Verifies exact proposal, operation, request, and input-hash bindings.
    pub fn validate_against(
        &self,
        request: &TrustedExecutionBindingRequestV1,
    ) -> Result<(), TrustedExecutionError> {
        self.validate()?;
        request.validate()?;
        let (kind, expected) = expected_input(&request.policy_ready_action)?;
        if self.request_sha256 != request.request_sha256
            || self.proposal_sha256 != canonical_sha256(&request.policy_ready_action.proposal)?
            || Some(self.input_kind) != kind
            || Some(self.expected_content_sha256.as_str()) != expected.as_deref()
        {
            return integrity("input material proof differs from proposal");
        }
        Ok(())
    }
}

/// Audit-safe binding between the Cognitive action and exact Desktop intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundDesktopActionV1 {
    pub schema_version: u32,
    pub bound_action_id: String,
    pub trusted_execution_request_sha256: String,
    pub policy_ready_sha256: String,
    pub selection_sha256: String,
    pub proposal_id: String,
    pub proposal_sha256: String,
    pub goal_id: String,
    pub plan_generation_id: String,
    pub source_observation_id: String,
    pub source_observation_hash: String,
    pub source_observation_sequence: u64,
    pub semantic_target_id: String,
    pub selected_element_id: String,
    pub capability_id: String,
    pub capability_binding_sha256: String,
    pub policy_decision_sha256: String,
    pub cognitive_activation_admission_sha256: String,
    pub execution_session_sha256: String,
    pub target_resolution_sha256: String,
    pub input_material_proof_sha256: Option<String>,
    pub integration_id: String,
    pub binding_id: String,
    pub activation_record_hash: String,
    pub adapter_kind: AdapterKindV1,
    pub adapter_descriptor_sha256: String,
    pub desktop_capability: TrustedDesktopCapabilityV1,
    pub desktop_operation_kind: TrustedDesktopOperationKindV1,
    pub desktop_operation_sha256: String,
    pub desktop_action_intent_sha256: String,
    pub generated_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub bound_action_sha256: String,
}

impl BoundDesktopActionV1 {
    /// Sorts evidence and seals the action binding.
    pub fn seal(mut self) -> Result<Self, TrustedExecutionError> {
        self.evidence_ids.sort();
        self.bound_action_sha256 = self.compute_bound_action_sha256()?;
        self.validate()?;
        Ok(self)
    }

    /// Computes the canonical action binding digest without its self-hash.
    pub fn compute_bound_action_sha256(&self) -> Result<String, TrustedExecutionError> {
        hash_without_field(self, "bound_action_sha256")
    }

    /// Validates hash-only operation metadata, bounds, and self-hash.
    pub fn validate(&self) -> Result<(), TrustedExecutionError> {
        validate_version(self.schema_version, "bound desktop action")?;
        for (value, label) in [
            (&self.bound_action_id, "bound_action_id"),
            (&self.proposal_id, "bound proposal_id"),
            (&self.goal_id, "bound goal_id"),
            (&self.plan_generation_id, "bound plan_generation_id"),
            (&self.source_observation_id, "bound source_observation_id"),
            (&self.semantic_target_id, "bound semantic_target_id"),
            (&self.selected_element_id, "bound selected_element_id"),
            (&self.capability_id, "bound capability_id"),
            (&self.integration_id, "bound integration_id"),
            (&self.binding_id, "bound binding_id"),
        ] {
            validate_id(value, label)?;
        }
        for (value, label) in [
            (
                &self.trusted_execution_request_sha256,
                "trusted_execution_request_sha256",
            ),
            (&self.policy_ready_sha256, "bound policy_ready_sha256"),
            (&self.selection_sha256, "bound selection_sha256"),
            (&self.proposal_sha256, "bound proposal_sha256"),
            (
                &self.source_observation_hash,
                "bound source_observation_hash",
            ),
            (
                &self.capability_binding_sha256,
                "bound capability_binding_sha256",
            ),
            (&self.policy_decision_sha256, "bound policy_decision_sha256"),
            (
                &self.cognitive_activation_admission_sha256,
                "cognitive_activation_admission_sha256",
            ),
            (&self.execution_session_sha256, "execution_session_sha256"),
            (&self.target_resolution_sha256, "target_resolution_sha256"),
            (&self.activation_record_hash, "bound activation_record_hash"),
            (
                &self.adapter_descriptor_sha256,
                "bound adapter_descriptor_sha256",
            ),
            (&self.desktop_operation_sha256, "desktop_operation_sha256"),
            (
                &self.desktop_action_intent_sha256,
                "desktop_action_intent_sha256",
            ),
        ] {
            validate_hash(value, label)?;
        }
        validate_optional_hash(
            &self.input_material_proof_sha256,
            "input_material_proof_sha256",
        )?;
        if self.capability_id != self.desktop_operation_kind.capability_id()
            || self.adapter_kind != self.desktop_operation_kind.adapter_kind()
            || self.desktop_capability != self.desktop_operation_kind.desktop_capability()
            || self.desktop_operation_kind.requires_input()
                != self.input_material_proof_sha256.is_some()
        {
            return integrity("bound action closed operation metadata differs");
        }
        validate_short_interval_ms(
            self.generated_at_unix_ms,
            self.expires_at_unix_ms,
            MAX_SESSION_TTL_MS,
            "bound desktop action",
        )?;
        validate_sorted_ids(
            &self.evidence_ids,
            "bound action evidence_ids",
            MAX_EVIDENCE_IDS,
            false,
        )?;
        validate_hash(&self.bound_action_sha256, "bound_action_sha256")?;
        if self.compute_bound_action_sha256()? != self.bound_action_sha256 {
            return integrity("bound_action_sha256 differs from canonical binding");
        }
        reject_forbidden_json(self, "bound desktop action")
    }

    /// Verifies exact request and proof bindings.
    pub fn validate_against(
        &self,
        request: &TrustedExecutionBindingRequestV1,
        resolution: &TargetResolutionProofV1,
        input: Option<&InputMaterialProofV1>,
    ) -> Result<(), TrustedExecutionError> {
        self.validate()?;
        request.validate()?;
        resolution.validate_against(request)?;
        if let Some(proof) = input {
            proof.validate_against(request)?;
        }
        let ready = &request.policy_ready_action;
        let admission = &request.cognitive_activation_admission;
        let platform = &request.platform_activation;
        if self.trusted_execution_request_sha256 != request.request_sha256
            || self.policy_ready_sha256 != ready.policy_ready_sha256
            || self.selection_sha256 != ready.selection_sha256
            || self.proposal_id != ready.proposal.proposal_id
            || self.proposal_sha256 != canonical_sha256(&ready.proposal)?
            || self.goal_id != ready.goal_id
            || self.plan_generation_id != ready.plan_generation_id
            || self.source_observation_id != request.source_observation_id
            || self.source_observation_hash != request.source_observation_hash
            || self.source_observation_sequence != request.source_observation_sequence
            || self.semantic_target_id != ready.semantic_target_id
            || self.selected_element_id != ready.selected_element_id
            || self.capability_id != ready.capability_id
            || self.capability_binding_sha256 != ready.capability_binding_sha256
            || self.policy_decision_sha256 != admission.policy_decision_sha256
            || self.cognitive_activation_admission_sha256 != admission.admission_sha256
            || self.execution_session_sha256 != request.execution_session.session_sha256
            || self.target_resolution_sha256 != resolution.resolution_sha256
            || self.input_material_proof_sha256.as_deref()
                != input.map(|proof| proof.material_proof_sha256.as_str())
            || self.integration_id != platform.integration_id
            || self.binding_id != platform.binding_id
            || self.activation_record_hash != platform.activation_record_hash
            || self.adapter_kind != platform.adapter_kind
            || self.adapter_descriptor_sha256 != platform.adapter_descriptor_sha256
            || self.desktop_operation_kind != operation_kind(ready)?
        {
            return integrity("bound desktop action differs from trusted inputs");
        }
        Ok(())
    }
}

/// Audit-safe binding of an adapter preparation to one bound action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedBoundActionV1 {
    pub schema_version: u32,
    pub bound_action_sha256: String,
    pub desktop_action_intent_sha256: String,
    pub desktop_operation_sha256: String,
    pub adapter_descriptor_sha256: String,
    pub target_resolution_sha256: String,
    pub input_material_proof_sha256: Option<String>,
    pub prepared_action_hash: String,
    pub precondition_hash: String,
    pub prepared_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub reversible: bool,
    pub evidence_ids: Vec<String>,
    pub prepared_binding_sha256: String,
}

impl PreparedBoundActionV1 {
    /// Sorts evidence and seals the prepared binding.
    pub fn seal(mut self) -> Result<Self, TrustedExecutionError> {
        self.evidence_ids.sort();
        self.prepared_binding_sha256 = self.compute_prepared_binding_sha256()?;
        self.validate()?;
        Ok(self)
    }

    /// Computes the canonical prepared binding digest without its self-hash.
    pub fn compute_prepared_binding_sha256(&self) -> Result<String, TrustedExecutionError> {
        hash_without_field(self, "prepared_binding_sha256")
    }

    /// Validates all preparation identities, lifetime, and self-hash.
    pub fn validate(&self) -> Result<(), TrustedExecutionError> {
        validate_version(self.schema_version, "prepared bound action")?;
        for (value, label) in [
            (&self.bound_action_sha256, "prepared bound_action_sha256"),
            (
                &self.desktop_action_intent_sha256,
                "prepared desktop_action_intent_sha256",
            ),
            (
                &self.desktop_operation_sha256,
                "prepared desktop_operation_sha256",
            ),
            (
                &self.adapter_descriptor_sha256,
                "prepared adapter_descriptor_sha256",
            ),
            (
                &self.target_resolution_sha256,
                "prepared target_resolution_sha256",
            ),
            (&self.prepared_action_hash, "prepared_action_hash"),
            (&self.precondition_hash, "prepared precondition_hash"),
        ] {
            validate_hash(value, label)?;
        }
        validate_optional_hash(
            &self.input_material_proof_sha256,
            "prepared input_material_proof_sha256",
        )?;
        validate_short_interval_ms(
            self.prepared_at_unix_ms,
            self.expires_at_unix_ms,
            MAX_SESSION_TTL_MS,
            "prepared bound action",
        )?;
        validate_sorted_ids(
            &self.evidence_ids,
            "prepared evidence_ids",
            MAX_EVIDENCE_IDS,
            false,
        )?;
        validate_hash(&self.prepared_binding_sha256, "prepared_binding_sha256")?;
        if self.compute_prepared_binding_sha256()? != self.prepared_binding_sha256 {
            return integrity("prepared_binding_sha256 differs from canonical binding");
        }
        reject_forbidden_json(self, "prepared bound action")
    }

    /// Verifies that the preparation belongs to one unchanged bound action.
    pub fn validate_against(
        &self,
        bound: &BoundDesktopActionV1,
    ) -> Result<(), TrustedExecutionError> {
        self.validate()?;
        bound.validate()?;
        if self.bound_action_sha256 != bound.bound_action_sha256
            || self.desktop_action_intent_sha256 != bound.desktop_action_intent_sha256
            || self.desktop_operation_sha256 != bound.desktop_operation_sha256
            || self.adapter_descriptor_sha256 != bound.adapter_descriptor_sha256
            || self.target_resolution_sha256 != bound.target_resolution_sha256
            || self.input_material_proof_sha256 != bound.input_material_proof_sha256
            || self.expires_at_unix_ms > bound.expires_at_unix_ms
        {
            return integrity("prepared binding differs from bound action");
        }
        Ok(())
    }
}

/// Audit-safe terminal adapter-attempt receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedActionExecutionReceiptV1 {
    pub schema_version: u32,
    pub execution_id: String,
    pub status: TrustedExecutionStatusV1,
    pub bound_action_sha256: String,
    pub prepared_binding_sha256: Option<String>,
    pub policy_ready_sha256: String,
    pub proposal_id: String,
    pub proposal_sha256: String,
    pub goal_id: String,
    pub plan_generation_id: String,
    pub source_observation_id: String,
    pub source_observation_hash: String,
    pub source_observation_sequence: u64,
    pub capability_id: String,
    pub semantic_target_id: String,
    pub cognitive_activation_admission_sha256: String,
    pub policy_decision_sha256: String,
    pub confirmation_grant_sha256: Option<String>,
    pub activation_record_hash: String,
    pub runtime_binding_sha256: String,
    pub adapter_descriptor_sha256: String,
    pub desktop_action_intent_sha256: String,
    pub desktop_operation_sha256: String,
    pub target_resolution_sha256: String,
    pub input_material_proof_sha256: Option<String>,
    pub preparation_hash: Option<String>,
    pub precondition_hash: Option<String>,
    pub execution_permit_sha256: Option<String>,
    pub adapter_outcome_status: Option<TrustedAdapterOutcomeStatusV1>,
    pub adapter_output_sha256: Option<String>,
    pub adapter_output_bytes: u64,
    pub started_at_unix_ms: Option<u64>,
    pub completed_at_unix_ms: u64,
    pub warnings: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub receipt_sha256: String,
}

impl TrustedActionExecutionReceiptV1 {
    /// Sorts set-like evidence and seals the receipt.
    pub fn seal(mut self) -> Result<Self, TrustedExecutionError> {
        self.evidence_ids.sort();
        self.receipt_sha256 = self.compute_receipt_sha256()?;
        self.validate()?;
        Ok(self)
    }

    /// Computes the canonical receipt digest without its self-hash.
    pub fn compute_receipt_sha256(&self) -> Result<String, TrustedExecutionError> {
        hash_without_field(self, "receipt_sha256")
    }

    /// Validates terminal status shape, bounded evidence, and self-hash.
    pub fn validate(&self) -> Result<(), TrustedExecutionError> {
        validate_version(self.schema_version, "trusted execution receipt")?;
        for (value, label) in [
            (&self.execution_id, "execution_id"),
            (&self.proposal_id, "receipt proposal_id"),
            (&self.goal_id, "receipt goal_id"),
            (&self.plan_generation_id, "receipt plan_generation_id"),
            (&self.source_observation_id, "receipt source_observation_id"),
            (&self.capability_id, "receipt capability_id"),
            (&self.semantic_target_id, "receipt semantic_target_id"),
        ] {
            validate_id(value, label)?;
        }
        for (value, label) in [
            (&self.bound_action_sha256, "receipt bound_action_sha256"),
            (&self.policy_ready_sha256, "receipt policy_ready_sha256"),
            (&self.proposal_sha256, "receipt proposal_sha256"),
            (
                &self.source_observation_hash,
                "receipt source_observation_hash",
            ),
            (
                &self.cognitive_activation_admission_sha256,
                "receipt cognitive_activation_admission_sha256",
            ),
            (
                &self.policy_decision_sha256,
                "receipt policy_decision_sha256",
            ),
            (
                &self.activation_record_hash,
                "receipt activation_record_hash",
            ),
            (
                &self.runtime_binding_sha256,
                "receipt runtime_binding_sha256",
            ),
            (
                &self.adapter_descriptor_sha256,
                "receipt adapter_descriptor_sha256",
            ),
            (
                &self.desktop_action_intent_sha256,
                "receipt desktop_action_intent_sha256",
            ),
            (
                &self.desktop_operation_sha256,
                "receipt desktop_operation_sha256",
            ),
            (
                &self.target_resolution_sha256,
                "receipt target_resolution_sha256",
            ),
        ] {
            validate_hash(value, label)?;
        }
        for (value, label) in [
            (
                &self.prepared_binding_sha256,
                "receipt prepared_binding_sha256",
            ),
            (
                &self.confirmation_grant_sha256,
                "receipt confirmation_grant_sha256",
            ),
            (
                &self.input_material_proof_sha256,
                "receipt input_material_proof_sha256",
            ),
            (&self.preparation_hash, "receipt preparation_hash"),
            (&self.precondition_hash, "receipt precondition_hash"),
            (
                &self.execution_permit_sha256,
                "receipt execution_permit_sha256",
            ),
            (&self.adapter_output_sha256, "receipt adapter_output_sha256"),
        ] {
            validate_optional_hash(value, label)?;
        }
        match self.status {
            TrustedExecutionStatusV1::Succeeded | TrustedExecutionStatusV1::Failed => {
                if self.prepared_binding_sha256.is_none()
                    || self.preparation_hash.is_none()
                    || self.precondition_hash.is_none()
                    || self.execution_permit_sha256.is_none()
                    || self.adapter_outcome_status.is_none()
                    || self.adapter_output_sha256.is_none()
                    || self.started_at_unix_ms.is_none()
                {
                    return invalid("executed receipt is missing adapter-attempt hashes");
                }
            }
            TrustedExecutionStatusV1::Cancelled
            | TrustedExecutionStatusV1::DeniedBeforeCommit
            | TrustedExecutionStatusV1::Aborted => {
                if self.adapter_outcome_status.is_some()
                    || self.adapter_output_sha256.is_some()
                    || self.adapter_output_bytes != 0
                {
                    return invalid("non-executed receipt cannot claim adapter output");
                }
            }
        }
        if self
            .started_at_unix_ms
            .is_some_and(|start| start > self.completed_at_unix_ms)
        {
            return invalid("receipt completion precedes start");
        }
        validate_texts(&self.warnings, "receipt warnings", MAX_WARNINGS)?;
        validate_sorted_ids(
            &self.evidence_ids,
            "receipt evidence_ids",
            MAX_EVIDENCE_IDS,
            false,
        )?;
        validate_hash(&self.receipt_sha256, "receipt_sha256")?;
        if self.compute_receipt_sha256()? != self.receipt_sha256 {
            return integrity("receipt_sha256 differs from canonical receipt");
        }
        reject_forbidden_json(self, "trusted execution receipt")
    }
}

/// Returns the exact closed v1 operation represented by a policy-ready action.
pub fn operation_kind(
    ready: &PolicyReadyActionV1,
) -> Result<TrustedDesktopOperationKindV1, TrustedExecutionError> {
    let arguments = action_arguments(ready)?;
    let kind = match (
        arguments.input(),
        ready.capability_id.as_str(),
        arguments.operation(),
    ) {
        (CandidateActionInput::Invoke, "uia.invoke", "uia.invoke") => {
            TrustedDesktopOperationKindV1::UiaInvoke
        }
        (CandidateActionInput::SetText { .. }, "uia.set_value", "uia.set_value") => {
            TrustedDesktopOperationKindV1::UiaSetValue
        }
        (CandidateActionInput::Toggle { .. }, "uia.toggle", "uia.toggle") => {
            TrustedDesktopOperationKindV1::UiaToggle
        }
        (CandidateActionInput::Click, "webdriver.click", "webdriver.click") => {
            TrustedDesktopOperationKindV1::WebDriverClick
        }
        (CandidateActionInput::TypeText { .. }, "webdriver.type", "webdriver.type") => {
            TrustedDesktopOperationKindV1::WebDriverType
        }
        (CandidateActionInput::Select { .. }, "webdriver.select", "webdriver.select") => {
            TrustedDesktopOperationKindV1::WebDriverSelect
        }
        _ => {
            return Err(TrustedExecutionError::Unsupported(
                "capability, operation, and typed input are not an exact v1 mapping".to_owned(),
            ));
        }
    };
    Ok(kind)
}

/// Returns the input kind and expected content hash for the exact operation.
pub fn expected_input(
    ready: &PolicyReadyActionV1,
) -> Result<(Option<InputMaterialKindV1>, Option<String>), TrustedExecutionError> {
    let value = match action_input(ready)? {
        CandidateActionInput::SetText { text_hash } => {
            (Some(InputMaterialKindV1::SetText), Some(text_hash))
        }
        CandidateActionInput::TypeText { text_hash } => {
            (Some(InputMaterialKindV1::TypeText), Some(text_hash))
        }
        CandidateActionInput::Select { value_hash } => {
            (Some(InputMaterialKindV1::Select), Some(value_hash))
        }
        CandidateActionInput::Invoke
        | CandidateActionInput::Toggle { .. }
        | CandidateActionInput::Click => (None, None),
    };
    Ok(value)
}

/// Returns the exact typed input carried by either supported v1 proposal bridge.
pub fn action_input(
    ready: &PolicyReadyActionV1,
) -> Result<CandidateActionInput, TrustedExecutionError> {
    Ok(action_arguments(ready)?.input().clone())
}

/// Returns the proposal's exact grounded-target digest.
///
/// Native Action Selection proposals carry a self-hashed grounded target. The
/// earlier fixture bridge is retained for compatibility and uses the canonical
/// digest of its closed target object.
pub fn grounded_target_binding_sha256(
    ready: &PolicyReadyActionV1,
) -> Result<String, TrustedExecutionError> {
    action_arguments(ready)?.grounded_target_binding_sha256()
}

/// Strictly parses JSON with duplicate-key, size, depth, and node limits.
pub fn parse_json_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, TrustedExecutionError> {
    if bytes.len() > MAX_JSON_BYTES {
        return invalid("JSON exceeds 8 MiB");
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue::deserialize(&mut deserializer)
        .map_err(|error| json_error("parse strict JSON", error))?
        .0;
    deserializer
        .end()
        .map_err(|error| json_error("parse trailing JSON", error))?;
    validate_json_limits(&value)?;
    serde_json::from_value(value).map_err(|error| json_error("decode strict JSON", error))
}

/// Computes recursive-key-sorted JSON SHA-256 using `sha256:<lowercase hex>`.
pub fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, TrustedExecutionError> {
    let value = serde_json::to_value(value)
        .map_err(|error| json_error("serialize canonical JSON", error))?;
    hash_value(&value)
}

/// Computes canonical SHA-256 over raw bytes.
#[must_use]
pub fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

enum ActionArgumentsV1 {
    Fixture(Box<CandidateActionArguments>),
    Grounded(Box<GroundedActionArgumentsV1>),
}

impl ActionArgumentsV1 {
    fn operation(&self) -> &str {
        match self {
            Self::Fixture(arguments) => &arguments.operation,
            Self::Grounded(arguments) => &arguments.operation,
        }
    }

    fn input(&self) -> &CandidateActionInput {
        match self {
            Self::Fixture(arguments) => &arguments.input,
            Self::Grounded(arguments) => &arguments.input,
        }
    }

    fn grounded_target_binding_sha256(&self) -> Result<String, TrustedExecutionError> {
        match self {
            Self::Fixture(arguments) => canonical_sha256(&arguments.target),
            Self::Grounded(arguments) => Ok(arguments.target.binding_sha256.clone()),
        }
    }
}

fn action_arguments(
    ready: &PolicyReadyActionV1,
) -> Result<ActionArgumentsV1, TrustedExecutionError> {
    if let Ok(arguments) =
        serde_json::from_value::<GroundedActionArgumentsV1>(ready.proposal.arguments.clone())
    {
        if arguments.schema_version != TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION {
            return invalid("grounded action arguments schema_version must be 1");
        }
        arguments
            .target
            .validate()
            .map_err(|error| TrustedExecutionError::Integrity(error.to_string()))?;
        validate_operation_and_input(&arguments.operation, &arguments.input)?;
        if arguments.target.application_pack_sha256 != ready.application_pack_sha256
            || arguments.target.observation_id != ready.observation_id
            || arguments.target.source_observation_hash != ready.source_observation_hash
            || arguments.target.source_observation_sequence != ready.source_observation_sequence
            || arguments.target.grounding_result_sha256 != ready.grounding_result_sha256
            || arguments.target.goal_id != ready.goal_id
            || arguments.target.plan_generation_id != ready.plan_generation_id
            || arguments.target.semantic_target_id != ready.semantic_target_id
            || arguments.target.selected_element_id != ready.selected_element_id
            || arguments.target.selected_element_kind != ready.selected_element_kind
        {
            return integrity("grounded arguments differ from policy-ready bindings");
        }
        return Ok(ActionArgumentsV1::Grounded(Box::new(arguments)));
    }

    let arguments: CandidateActionArguments =
        serde_json::from_value(ready.proposal.arguments.clone())
            .map_err(|error| json_error("decode action arguments", error))?;
    arguments
        .validate()
        .map_err(|error| TrustedExecutionError::Integrity(error.to_string()))?;
    if arguments.target.application_pack_sha256 != ready.application_pack_sha256
        || arguments.target.observation_id != ready.observation_id
        || arguments.target.source_observation_hash != ready.source_observation_hash
        || arguments.target.source_observation_sequence != ready.source_observation_sequence
        || arguments.target.semantic_target_id != ready.semantic_target_id
        || arguments.target.element_id != ready.selected_element_id
        || arguments.target.element_kind != ready.selected_element_kind
        || arguments.target.capability_binding_sha256 != ready.capability_binding_sha256
    {
        return integrity("fixture arguments differ from policy-ready bindings");
    }
    Ok(ActionArgumentsV1::Fixture(Box::new(arguments)))
}

fn validate_operation_and_input(
    operation: &str,
    input: &CandidateActionInput,
) -> Result<(), TrustedExecutionError> {
    validate_id(operation, "action arguments operation")?;
    match input {
        CandidateActionInput::SetText { text_hash }
        | CandidateActionInput::TypeText { text_hash } => {
            validate_hash(text_hash, "action arguments text_hash")
        }
        CandidateActionInput::Select { value_hash } => {
            validate_hash(value_hash, "action arguments value_hash")
        }
        CandidateActionInput::Invoke
        | CandidateActionInput::Toggle { .. }
        | CandidateActionInput::Click => Ok(()),
    }
}

fn validate_policy_ready(ready: &PolicyReadyActionV1) -> Result<(), TrustedExecutionError> {
    if ready.schema_version != 1 {
        return invalid("PolicyReadyActionV1 schema_version must be 1");
    }
    ready
        .proposal
        .validate()
        .map_err(|error| TrustedExecutionError::Integrity(error.to_string()))?;
    for (value, label) in [
        (&ready.selection_id, "policy-ready selection_id"),
        (&ready.goal_id, "policy-ready goal_id"),
        (&ready.world_state_id, "policy-ready world_state_id"),
        (&ready.plan_generation_id, "policy-ready plan_generation_id"),
        (&ready.observation_id, "policy-ready observation_id"),
        (&ready.semantic_target_id, "policy-ready semantic_target_id"),
        (
            &ready.selected_element_id,
            "policy-ready selected_element_id",
        ),
        (
            &ready.selected_element_kind,
            "policy-ready selected_element_kind",
        ),
        (&ready.capability_id, "policy-ready capability_id"),
    ] {
        validate_id(value, label)?;
    }
    for (value, label) in [
        (&ready.selection_sha256, "policy-ready selection_sha256"),
        (
            &ready.candidate_set_sha256,
            "policy-ready candidate_set_sha256",
        ),
        (
            &ready.source_observation_hash,
            "policy-ready source_observation_hash",
        ),
        (
            &ready.application_pack_sha256,
            "policy-ready application_pack_sha256",
        ),
        (
            &ready.grounding_result_sha256,
            "policy-ready grounding_result_sha256",
        ),
        (
            &ready.capability_binding_sha256,
            "policy-ready capability_binding_sha256",
        ),
        (
            &ready.policy_input_sha256,
            "policy-ready policy_input_sha256",
        ),
    ] {
        validate_hash(value, label)?;
    }
    if ready.goal_id != ready.proposal.goal_id
        || ready.plan_generation_id != ready.proposal.plan_generation_id
        || ready.source_observation_hash != ready.proposal.source_observation_hash
        || ready.source_observation_sequence != ready.proposal.valid_until_sequence
        || ready.semantic_target_id != ready.proposal.semantic_target
        || ready.capability_id != ready.proposal.capability_id
        || ready.risk != ready.proposal.risk
        || ready.reversibility != ready.proposal.reversibility
        || ready.confirmation_requirement != ready.proposal.confirmation_requirement
        || ready.expected_postconditions != ready.proposal.expected_postconditions
    {
        return integrity("PolicyReadyActionV1 differs from its selected proposal");
    }
    if ready
        .compute_policy_ready_sha256()
        .map_err(|error| TrustedExecutionError::Integrity(error.to_string()))?
        != ready.policy_ready_sha256
    {
        return integrity("policy_ready_sha256 differs from canonical action");
    }
    if ready.reversibility != Reversibility::Reversible
        || ready.proposal.reversibility != Reversibility::Reversible
    {
        return Err(TrustedExecutionError::Unsupported(
            "trusted execution v1 supports reversible actions only".to_owned(),
        ));
    }
    let _ = operation_kind(ready)?;
    Ok(())
}

fn validate_version(version: u32, label: &str) -> Result<(), TrustedExecutionError> {
    if version != TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION {
        return invalid(format!("{label} schema_version must be 1"));
    }
    Ok(())
}

fn validate_id(value: &str, label: &str) -> Result<(), TrustedExecutionError> {
    if value.is_empty()
        || value.len() > MAX_ID_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return invalid(format!("{label} must be a bounded identifier"));
    }
    Ok(())
}

fn validate_hash(value: &str, label: &str) -> Result<(), TrustedExecutionError> {
    let valid = value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid {
        return invalid(format!("{label} must be lowercase canonical sha256"));
    }
    Ok(())
}

fn validate_optional_hash(
    value: &Option<String>,
    label: &str,
) -> Result<(), TrustedExecutionError> {
    if let Some(value) = value {
        validate_hash(value, label)?;
    }
    Ok(())
}

fn validate_sorted_ids(
    values: &[String],
    label: &str,
    maximum: usize,
    allow_empty: bool,
) -> Result<(), TrustedExecutionError> {
    if (!allow_empty && values.is_empty()) || values.len() > maximum {
        return invalid(format!("{label} has invalid collection bounds"));
    }
    for value in values {
        validate_id(value, label)?;
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return invalid(format!("{label} must be sorted and duplicate-free"));
    }
    Ok(())
}

fn validate_texts(
    values: &[String],
    label: &str,
    maximum: usize,
) -> Result<(), TrustedExecutionError> {
    if values.len() > maximum {
        return invalid(format!("{label} exceeds {maximum} entries"));
    }
    for value in values {
        if value.is_empty() || value.len() > 4096 || value.contains('\0') {
            return invalid(format!("{label} contains invalid bounded text"));
        }
    }
    Ok(())
}

fn validate_interval_seconds(
    start: u64,
    expires: u64,
    label: &str,
) -> Result<(), TrustedExecutionError> {
    if start >= expires {
        return invalid(format!("{label} validity interval is empty"));
    }
    Ok(())
}

fn validate_short_interval_ms(
    start: u64,
    expires: u64,
    maximum_ttl: u64,
    label: &str,
) -> Result<(), TrustedExecutionError> {
    if start >= expires || expires.saturating_sub(start) > maximum_ttl {
        return invalid(format!("{label} lifetime is empty or exceeds its TTL"));
    }
    Ok(())
}

fn empty_hash() -> String {
    "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned()
}

fn hash_without_field<T: Serialize>(
    value: &T,
    field: &str,
) -> Result<String, TrustedExecutionError> {
    let mut value =
        serde_json::to_value(value).map_err(|error| json_error("serialize self-hash", error))?;
    let object = value.as_object_mut().ok_or_else(|| {
        TrustedExecutionError::Json("self-hashed artifact is not an object".to_owned())
    })?;
    object.remove(field);
    hash_value(&value)
}

fn hash_value(value: &Value) -> Result<String, TrustedExecutionError> {
    let canonical = canonicalize(value);
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| json_error("serialize canonical value", error))?;
    Ok(sha256_bytes(&bytes))
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort();
            let mut canonical = Map::new();
            for key in keys {
                if let Some(value) = object.get(key) {
                    canonical.insert(key.clone(), canonicalize(value));
                }
            }
            Value::Object(canonical)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        _ => value.clone(),
    }
}

fn reject_forbidden_json<T: Serialize>(
    value: &T,
    label: &str,
) -> Result<(), TrustedExecutionError> {
    let value =
        serde_json::to_value(value).map_err(|error| json_error("inspect forbidden JSON", error))?;
    fn walk(value: &Value) -> bool {
        match value {
            Value::Object(object) => object.iter().any(|(key, value)| {
                let key = key.to_ascii_lowercase();
                let forbidden_key = [
                    "password",
                    "credential",
                    "raw_input",
                    "selector",
                    "locator",
                    "coordinate",
                    "adapter_handle",
                    "activation_token",
                    "automation_id",
                    "payload",
                ]
                .iter()
                .any(|needle| key.contains(needle));
                forbidden_key || walk(value)
            }),
            Value::Array(values) => values.iter().any(walk),
            Value::String(text) => {
                let lower = text.to_ascii_lowercase();
                let raw_secret = ["password=", "token=", "secret=", "bearer ", "api_key="]
                    .iter()
                    .any(|needle| lower.contains(needle));
                let absolute_path = text.starts_with('/')
                    || text.starts_with("\\\\")
                    || (text.len() > 2
                        && text.as_bytes()[1] == b':'
                        && matches!(text.as_bytes()[2], b'\\' | b'/'));
                raw_secret || absolute_path
            }
            _ => false,
        }
    }
    if walk(&value) {
        return invalid(format!("{label} contains forbidden raw execution material"));
    }
    Ok(())
}

fn validate_json_limits(value: &Value) -> Result<(), TrustedExecutionError> {
    fn walk(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), TrustedExecutionError> {
        if depth > MAX_JSON_DEPTH {
            return invalid("JSON nesting exceeds 64");
        }
        *nodes = nodes.saturating_add(1);
        if *nodes > MAX_JSON_NODES {
            return invalid("JSON node count exceeds 100000");
        }
        match value {
            Value::Object(object) => {
                for value in object.values() {
                    walk(value, depth.saturating_add(1), nodes)?;
                }
            }
            Value::Array(values) => {
                for value in values {
                    walk(value, depth.saturating_add(1), nodes)?;
                }
            }
            Value::Number(number) if number.as_f64().is_some_and(|value| !value.is_finite()) => {
                return invalid("JSON contains non-finite number");
            }
            _ => {}
        }
        Ok(())
    }
    let mut nodes = 0;
    walk(value, 0, &mut nodes)
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value without duplicate object keys")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(value.into())))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(value.into())))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if !value.is_finite() {
                    return Err(E::custom("non-finite JSON number"));
                }
                serde_json::Number::from_f64(value)
                    .map(Value::Number)
                    .map(StrictValue)
                    .ok_or_else(|| E::custom("invalid JSON number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(StrictValue(Value::String(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value)))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                StrictValue::deserialize(deserializer)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<StrictValue>()? {
                    values.push(value.0);
                }
                Ok(StrictValue(Value::Array(values)))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut object = Map::new();
                while let Some((key, value)) = map.next_entry::<String, StrictValue>()? {
                    if object.insert(key.clone(), value.0).is_some() {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate JSON key: {key}"
                        )));
                    }
                }
                Ok(StrictValue(Value::Object(object)))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

fn invalid<T>(message: impl Into<String>) -> Result<T, TrustedExecutionError> {
    Err(TrustedExecutionError::Invalid(message.into()))
}

fn integrity<T>(message: impl Into<String>) -> Result<T, TrustedExecutionError> {
    Err(TrustedExecutionError::Integrity(message.into()))
}

fn json_error(context: &str, error: impl Display) -> TrustedExecutionError {
    TrustedExecutionError::Json(format!("{context}: {error}"))
}
