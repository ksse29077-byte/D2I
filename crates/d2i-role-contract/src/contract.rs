use crate::strict::{canonical_sha256, hash_without};
use crate::{
    canonicalize_ids, invalid, validate_evidence, validate_hash, validate_id, validate_ids,
    validate_text, RoleContractError, MAX_ITEMS, MAX_ROLE_TTL_SECONDS,
    ROLE_CONTRACT_COMPILER_BUILD_ID, ROLE_CONTRACT_SCHEMA_VERSION, ZERO_HASH,
};
use d2i_cognitive_ir::CognitiveRiskClass;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Supported human-authored source format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleCompileFormatV1 {
    Json,
    Yaml,
}

/// Explicit organization scope. Empty subsidiary sets mean no additional
/// restriction within the named organization, never a cross-organization wildcard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationScopeV1 {
    pub organization_id: String,
    pub business_unit_ids: Vec<String>,
    pub site_ids: Vec<String>,
    pub domain_ids: Vec<String>,
    pub environment_ids: Vec<String>,
    pub jurisdiction_ids: Vec<String>,
}

impl OrganizationScopeV1 {
    fn normalize(&mut self) -> Result<(), RoleContractError> {
        for (values, label) in [
            (&mut self.business_unit_ids, "business_unit_ids"),
            (&mut self.site_ids, "site_ids"),
            (&mut self.domain_ids, "domain_ids"),
            (&mut self.environment_ids, "environment_ids"),
            (&mut self.jurisdiction_ids, "jurisdiction_ids"),
        ] {
            canonicalize_ids(values, label, true)?;
        }
        self.validate()
    }

    /// Validates explicit scope IDs and bounded canonical sets.
    pub fn validate(&self) -> Result<(), RoleContractError> {
        validate_id(&self.organization_id, "organization_id")?;
        for (values, label) in [
            (&self.business_unit_ids, "business_unit_ids"),
            (&self.site_ids, "site_ids"),
            (&self.domain_ids, "domain_ids"),
            (&self.environment_ids, "environment_ids"),
            (&self.jurisdiction_ids, "jurisdiction_ids"),
        ] {
            validate_ids(values, label, true)?;
        }
        Ok(())
    }

    /// Returns true when this scope is no broader than `maximum`.
    pub fn is_subset_of(&self, maximum: &Self) -> bool {
        self.organization_id == maximum.organization_id
            && subset_or_unrestricted(&self.business_unit_ids, &maximum.business_unit_ids)
            && subset_or_unrestricted(&self.site_ids, &maximum.site_ids)
            && subset_or_unrestricted(&self.domain_ids, &maximum.domain_ids)
            && subset_or_unrestricted(&self.environment_ids, &maximum.environment_ids)
            && subset_or_unrestricted(&self.jurisdiction_ids, &maximum.jurisdiction_ids)
    }
}

/// Human-readable responsibility with typed references carrying semantics.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleResponsibilityDescriptorV1 {
    pub responsibility_id: String,
    pub outcome_class_ids: Vec<String>,
    pub accepted_work_class_ids: Vec<String>,
    pub evidence_class_ids: Vec<String>,
    pub reporting_obligation_ids: Vec<String>,
    pub description: String,
}

/// A bounded reference to a future Work Item class, not a Work Item instance.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedWorkClassRefV1 {
    pub work_class_id: String,
    pub contract_version: String,
    pub responsibility_id: String,
    pub allowed_priority_classes: Vec<String>,
    pub sla_profile_id: String,
    pub maximum_risk: CognitiveRiskClass,
    pub required_application_pack_ids: Vec<String>,
    pub required_integration_ids: Vec<String>,
    pub required_capability_ids: Vec<String>,
    pub permitted_observation_source_ids: Vec<String>,
    pub clarification_allowed: bool,
    pub automatic_recovery_allowed: bool,
    pub mandatory_escalation_reason_codes: Vec<String>,
}

/// Closed capability maximum for a Role Contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleCapabilityPolicyV1 {
    pub allowed_capability_ids: Vec<String>,
    pub prohibited_capability_ids: Vec<String>,
    pub autonomous_capability_ids: Vec<String>,
    pub confirmation_capability_ids: Vec<String>,
    pub escalation_only_capability_ids: Vec<String>,
    pub capability_group_ids: Vec<String>,
    pub semantic_target_ids: Vec<String>,
    pub maximum_attempts_per_capability: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownPolicyBehaviorV1 {
    Deny,
    Escalate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsafeVerificationBehaviorV1 {
    Escalate,
    Stop,
}

/// Maximum risk behavior. Irreversible and automatic high-criticality actions
/// are structurally disabled in v1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleRiskPolicyV1 {
    pub maximum_autonomous_risk: CognitiveRiskClass,
    pub maximum_confirmable_risk: CognitiveRiskClass,
    pub mandatory_escalation_risk: CognitiveRiskClass,
    pub irreversible_actions_allowed: bool,
    pub high_criticality_automatic_allowed: bool,
    pub unknown_policy_behavior: UnknownPolicyBehaviorV1,
    pub unsafe_verification_behavior: UnsafeVerificationBehaviorV1,
}

/// Exact Application Pack authorization maximum without runtime locators.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleApplicationBindingV1 {
    pub application_pack_id: String,
    pub application_pack_sha256: String,
    pub integration_ids: Vec<String>,
    pub allowed_semantic_target_ids: Vec<String>,
    pub allowed_capability_ids: Vec<String>,
    pub observation_source_ids: Vec<String>,
    pub environment_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationSourceKindV1 {
    DesktopUia,
    WebDriver,
    EnterpriseApi,
    Schedule,
    EventStream,
    SensorSummary,
    ManualAuthenticatedInstruction,
}

/// Bounded future intake source allowlist entry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleObservationSourceV1 {
    pub observation_source_id: String,
    pub source_kind: ObservationSourceKindV1,
    pub integration_id: String,
    pub trust_floor: String,
    pub read_only: bool,
    pub event_class_ids: Vec<String>,
    pub application_pack_id: Option<String>,
    pub maximum_staleness_seconds: u64,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyOverridePolicyV1 {
    Forbidden,
    SignedReferenceOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutsideWindowBehaviorV1 {
    DenyNewWork,
    EscalationOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeeklyWindowV1 {
    pub weekday: u8,
    pub start_minute_local: u16,
    pub end_minute_local: u16,
}

/// Calendar declaration. DST interpretation belongs to a trusted caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleWorkingCalendarV1 {
    pub calendar_id: String,
    pub timezone_id: String,
    pub weekly_windows: Vec<WeeklyWindowV1>,
    pub blackout_date_ids: Vec<String>,
    pub emergency_override_policy: EmergencyOverridePolicyV1,
    pub outside_window_behavior: OutsideWindowBehaviorV1,
    pub calendar_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KpiDirectionV1 {
    Maximize,
    Minimize,
    AtLeast,
    AtMost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KpiBreachBehaviorV1 {
    Report,
    Escalate,
}

/// Machine-readable KPI declaration. WORK-100 does not calculate it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleKpiDefinitionV1 {
    pub kpi_id: String,
    pub metric_id: String,
    pub direction: KpiDirectionV1,
    pub target_millionths: Option<i64>,
    pub target_integer: Option<i64>,
    pub measurement_window_id: String,
    pub evidence_class_ids: Vec<String>,
    pub warning_threshold: Option<i64>,
    pub breach_behavior: KpiBreachBehaviorV1,
    pub enabled: bool,
}

/// SLA declaration for a future Case; no timer is started in WORK-100.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleSlaProfileV1 {
    pub sla_profile_id: String,
    pub priority_class: String,
    pub acknowledge_within_seconds: u64,
    pub begin_within_seconds: u64,
    pub resolve_within_seconds: u64,
    pub escalation_after_seconds: u64,
    pub pause_conditions: Vec<String>,
    pub evidence_class_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleReportingTriggerV1 {
    OnTaskComplete,
    OnTaskFailed,
    OnEscalation,
    OnRoleSuspend,
    Periodic,
    SlaBreach,
}

/// Reporting obligation declaration with routing classes, not recipients.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleReportingObligationV1 {
    pub obligation_id: String,
    pub trigger: RoleReportingTriggerV1,
    pub report_class_id: String,
    pub routing_class_id: String,
    pub required_evidence_class_ids: Vec<String>,
    pub frequency_profile_id: Option<String>,
    pub retention_class_id: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossCaseReusePolicyV1 {
    Forbidden,
    HashReferenceOnly,
    ApprovedSummaryOnly,
}

/// Maximum future memory retention envelope; it stores no episodic memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleMemoryBoundaryV1 {
    pub allowed_memory_namespace_ids: Vec<String>,
    pub prohibited_data_class_ids: Vec<String>,
    pub retention_class_id: String,
    pub maximum_retention_days: u32,
    pub raw_credentials_allowed: bool,
    pub raw_ui_payload_allowed: bool,
    pub cross_case_reuse_policy: CrossCaseReusePolicyV1,
    pub learning_candidate_allowed: bool,
    pub memory_boundary_sha256: String,
}

/// Escalation routing-class declaration. Actual delivery is a later track.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleEscalationPolicyV1 {
    pub escalation_policy_id: String,
    pub routing_class_by_severity: BTreeMap<String, String>,
    pub mandatory_reason_codes: Vec<String>,
    pub authority_exceeded_route_class: String,
    pub unsafe_route_class: String,
    pub legal_review_route_class: String,
    pub policy_conflict_route_class: String,
    pub maximum_pending_seconds: u64,
    pub evidence_class_ids: Vec<String>,
}

/// Typed Human-by-Exception boundary. Prose cannot override these sets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleHumanExceptionPolicyV1 {
    pub autonomous_reason_codes: Vec<String>,
    pub confirmation_reason_codes: Vec<String>,
    pub mandatory_escalation_reason_codes: Vec<String>,
    pub prohibited_automatic_reason_codes: Vec<String>,
    pub human_touch_budget: Option<u32>,
    pub policy_sha256: String,
}

/// Human-authored source pack. Display prose is retained but never projected
/// into authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleSourcePackV1 {
    pub schema_version: u32,
    pub role_contract_id: String,
    pub role_version: String,
    pub display_name: String,
    pub purpose: String,
    pub organization_scope: OrganizationScopeV1,
    pub responsibilities: Vec<RoleResponsibilityDescriptorV1>,
    pub accepted_work_classes: Vec<AcceptedWorkClassRefV1>,
    pub prohibited_work_class_ids: Vec<String>,
    pub authority_ceiling: String,
    pub application_bindings: Vec<RoleApplicationBindingV1>,
    pub observation_sources: Vec<RoleObservationSourceV1>,
    pub capability_policy: RoleCapabilityPolicyV1,
    pub risk_policy: RoleRiskPolicyV1,
    pub working_calendar: RoleWorkingCalendarV1,
    pub kpi_definitions: Vec<RoleKpiDefinitionV1>,
    pub sla_profiles: Vec<RoleSlaProfileV1>,
    pub reporting_obligations: Vec<RoleReportingObligationV1>,
    pub memory_boundary: RoleMemoryBoundaryV1,
    pub escalation_policy: RoleEscalationPolicyV1,
    pub human_exception_policy: RoleHumanExceptionPolicyV1,
    pub policy_set_id: String,
    pub policy_set_version: String,
    pub policy_set_sha256: String,
    pub evidence_ids: Vec<String>,
}

/// Immutable compiled Role Contract maximum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleContractV1 {
    pub schema_version: u32,
    pub role_contract_id: String,
    pub role_version: String,
    pub role_contract_generation: u64,
    pub display_name: String,
    pub purpose: String,
    pub authority_ceiling: String,
    pub organization_scope: OrganizationScopeV1,
    pub responsibilities: Vec<RoleResponsibilityDescriptorV1>,
    pub accepted_work_classes: Vec<AcceptedWorkClassRefV1>,
    pub prohibited_work_class_ids: Vec<String>,
    pub capability_policy: RoleCapabilityPolicyV1,
    pub risk_policy: RoleRiskPolicyV1,
    pub application_bindings: Vec<RoleApplicationBindingV1>,
    pub observation_sources: Vec<RoleObservationSourceV1>,
    pub working_calendar: RoleWorkingCalendarV1,
    pub kpi_definitions: Vec<RoleKpiDefinitionV1>,
    pub sla_profiles: Vec<RoleSlaProfileV1>,
    pub reporting_obligations: Vec<RoleReportingObligationV1>,
    pub memory_boundary: RoleMemoryBoundaryV1,
    pub escalation_policy: RoleEscalationPolicyV1,
    pub human_exception_policy: RoleHumanExceptionPolicyV1,
    pub policy_set_id: String,
    pub policy_set_version: String,
    pub policy_set_sha256: String,
    pub source_inventory_sha256: String,
    pub compiler_build_id: String,
    pub evidence_ids: Vec<String>,
    pub contract_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleContractManifestV1 {
    pub schema_version: u32,
    pub role_contract_id: String,
    pub role_version: String,
    pub contract_sha256: String,
    pub source_inventory_sha256: String,
    pub schema_sha256: String,
    pub compiler_build_id: String,
    pub policy_set_sha256: String,
    pub application_pack_hashes: Vec<String>,
    pub required_capability_ids: Vec<String>,
    pub license_declaration: String,
    pub sbom_reference: String,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleSourceLockV1 {
    pub schema_version: u32,
    pub role_contract_id: String,
    pub role_version: String,
    pub source_inventory_sha256: String,
    pub source_entry_count: u32,
    pub source_lock_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleConformanceV1 {
    pub schema_version: u32,
    pub role_contract_id: String,
    pub contract_sha256: String,
    pub strict_schema_validated: bool,
    pub references_validated: bool,
    pub deterministic_normalization: bool,
    pub no_execution_authority: bool,
    pub conformance_sha256: String,
}

/// Additive WORK-100 bundle, separate from the existing D2I package format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleContractBundleV1 {
    pub schema_version: u32,
    pub contract: RoleContractV1,
    pub manifest: RoleContractManifestV1,
    pub source_lock: RoleSourceLockV1,
    pub conformance: RoleConformanceV1,
    pub bundle_sha256: String,
}

/// Parses and deterministically compiles one YAML or JSON Role source.
pub fn compile_role_source(
    bytes: &[u8],
    format: RoleCompileFormatV1,
) -> Result<RoleContractBundleV1, RoleContractError> {
    if bytes.is_empty() || bytes.len() > crate::MAX_SOURCE_BYTES {
        return invalid("role source is empty or exceeds its bound");
    }
    let source: RoleSourcePackV1 = match format {
        RoleCompileFormatV1::Json => crate::parse_json_strict(bytes)?,
        RoleCompileFormatV1::Yaml => serde_yaml::from_slice(bytes)
            .map_err(|error| RoleContractError::Json(error.to_string()))?,
    };
    source.compile()
}

impl RoleSourcePackV1 {
    fn compile(mut self) -> Result<RoleContractBundleV1, RoleContractError> {
        self.normalize()?;
        let source_inventory_sha256 = canonical_sha256(&self)?;
        let mut contract = RoleContractV1 {
            schema_version: ROLE_CONTRACT_SCHEMA_VERSION,
            role_contract_id: self.role_contract_id,
            role_version: self.role_version,
            role_contract_generation: 1,
            display_name: self.display_name,
            purpose: self.purpose,
            authority_ceiling: self.authority_ceiling,
            organization_scope: self.organization_scope,
            responsibilities: self.responsibilities,
            accepted_work_classes: self.accepted_work_classes,
            prohibited_work_class_ids: self.prohibited_work_class_ids,
            capability_policy: self.capability_policy,
            risk_policy: self.risk_policy,
            application_bindings: self.application_bindings,
            observation_sources: self.observation_sources,
            working_calendar: self.working_calendar,
            kpi_definitions: self.kpi_definitions,
            sla_profiles: self.sla_profiles,
            reporting_obligations: self.reporting_obligations,
            memory_boundary: self.memory_boundary,
            escalation_policy: self.escalation_policy,
            human_exception_policy: self.human_exception_policy,
            policy_set_id: self.policy_set_id,
            policy_set_version: self.policy_set_version,
            policy_set_sha256: self.policy_set_sha256,
            source_inventory_sha256,
            compiler_build_id: ROLE_CONTRACT_COMPILER_BUILD_ID.to_owned(),
            evidence_ids: self.evidence_ids,
            contract_sha256: ZERO_HASH.to_owned(),
        };
        contract.contract_sha256 = hash_without(&contract, &["contract_sha256"])?;
        contract.validate()?;

        let schema_sha256 = format!(
            "sha256:{:x}",
            Sha256::digest(crate::ROLE_CONTRACT_V1_SCHEMA)
        );
        let mut manifest = RoleContractManifestV1 {
            schema_version: ROLE_CONTRACT_SCHEMA_VERSION,
            role_contract_id: contract.role_contract_id.clone(),
            role_version: contract.role_version.clone(),
            contract_sha256: contract.contract_sha256.clone(),
            source_inventory_sha256: contract.source_inventory_sha256.clone(),
            schema_sha256,
            compiler_build_id: contract.compiler_build_id.clone(),
            policy_set_sha256: contract.policy_set_sha256.clone(),
            application_pack_hashes: contract
                .application_bindings
                .iter()
                .map(|binding| binding.application_pack_sha256.clone())
                .collect(),
            required_capability_ids: contract.capability_policy.allowed_capability_ids.clone(),
            license_declaration: "Apache-2.0".to_owned(),
            sbom_reference: "workspace-cargo-lock".to_owned(),
            manifest_sha256: ZERO_HASH.to_owned(),
        };
        manifest.application_pack_hashes.sort();
        manifest.manifest_sha256 = hash_without(&manifest, &["manifest_sha256"])?;

        let mut source_lock = RoleSourceLockV1 {
            schema_version: ROLE_CONTRACT_SCHEMA_VERSION,
            role_contract_id: contract.role_contract_id.clone(),
            role_version: contract.role_version.clone(),
            source_inventory_sha256: contract.source_inventory_sha256.clone(),
            source_entry_count: 1,
            source_lock_sha256: ZERO_HASH.to_owned(),
        };
        source_lock.source_lock_sha256 = hash_without(&source_lock, &["source_lock_sha256"])?;
        let mut conformance = RoleConformanceV1 {
            schema_version: ROLE_CONTRACT_SCHEMA_VERSION,
            role_contract_id: contract.role_contract_id.clone(),
            contract_sha256: contract.contract_sha256.clone(),
            strict_schema_validated: true,
            references_validated: true,
            deterministic_normalization: true,
            no_execution_authority: true,
            conformance_sha256: ZERO_HASH.to_owned(),
        };
        conformance.conformance_sha256 = hash_without(&conformance, &["conformance_sha256"])?;
        let mut bundle = RoleContractBundleV1 {
            schema_version: ROLE_CONTRACT_SCHEMA_VERSION,
            contract,
            manifest,
            source_lock,
            conformance,
            bundle_sha256: ZERO_HASH.to_owned(),
        };
        bundle.bundle_sha256 = hash_without(&bundle, &["bundle_sha256"])?;
        bundle.validate()?;
        Ok(bundle)
    }

    fn normalize(&mut self) -> Result<(), RoleContractError> {
        self.organization_scope.normalize()?;
        normalize_responsibilities(&mut self.responsibilities)?;
        normalize_work_classes(&mut self.accepted_work_classes)?;
        canonicalize_ids(
            &mut self.prohibited_work_class_ids,
            "prohibited_work_class_ids",
            true,
        )?;
        normalize_capability_policy(&mut self.capability_policy)?;
        normalize_applications(&mut self.application_bindings)?;
        normalize_observation_sources(&mut self.observation_sources)?;
        normalize_calendar(&mut self.working_calendar)?;
        normalize_kpis(&mut self.kpi_definitions)?;
        normalize_slas(&mut self.sla_profiles)?;
        normalize_reporting(&mut self.reporting_obligations)?;
        normalize_memory(&mut self.memory_boundary)?;
        normalize_escalation(&mut self.escalation_policy)?;
        normalize_human_exception(&mut self.human_exception_policy)?;
        canonicalize_ids(&mut self.evidence_ids, "role evidence_ids", false)?;
        self.validate()
    }

    fn validate(&self) -> Result<(), RoleContractError> {
        if self.schema_version != ROLE_CONTRACT_SCHEMA_VERSION {
            return invalid("Role source schema version is unsupported");
        }
        validate_id(&self.role_contract_id, "role_contract_id")?;
        validate_id(&self.role_version, "role_version")?;
        validate_text(&self.display_name, "display_name")?;
        validate_text(&self.purpose, "purpose")?;
        validate_id(&self.authority_ceiling, "authority_ceiling")?;
        validate_id(&self.policy_set_id, "policy_set_id")?;
        validate_id(&self.policy_set_version, "policy_set_version")?;
        validate_hash(&self.policy_set_sha256, "policy_set_sha256")?;
        validate_evidence(&self.evidence_ids, "role evidence_ids")?;
        validate_contract_parts(self)
    }
}

impl RoleContractV1 {
    /// Validates immutable hashes, all references, and authority maxima.
    pub fn validate(&self) -> Result<(), RoleContractError> {
        if self.schema_version != ROLE_CONTRACT_SCHEMA_VERSION || self.role_contract_generation == 0
        {
            return invalid("Role Contract schema or generation is invalid");
        }
        validate_id(&self.role_contract_id, "role_contract_id")?;
        validate_id(&self.role_version, "role_version")?;
        validate_text(&self.display_name, "display_name")?;
        validate_text(&self.purpose, "purpose")?;
        validate_id(&self.authority_ceiling, "authority_ceiling")?;
        validate_id(&self.policy_set_id, "policy_set_id")?;
        validate_id(&self.policy_set_version, "policy_set_version")?;
        validate_hash(&self.policy_set_sha256, "policy_set_sha256")?;
        validate_hash(&self.source_inventory_sha256, "source_inventory_sha256")?;
        validate_id(&self.compiler_build_id, "compiler_build_id")?;
        validate_evidence(&self.evidence_ids, "contract evidence_ids")?;
        validate_contract_parts(self)?;
        validate_hash(&self.contract_sha256, "contract_sha256")?;
        if hash_without(self, &["contract_sha256"])? != self.contract_sha256 {
            return crate::integrity("contract_sha256 differs from canonical Role Contract");
        }
        Ok(())
    }

    /// Finds an accepted work class by exact ID.
    #[must_use]
    pub fn work_class(&self, work_class_id: &str) -> Option<&AcceptedWorkClassRefV1> {
        self.accepted_work_classes
            .iter()
            .find(|work| work.work_class_id == work_class_id)
    }

    /// Finds an exact Application Pack binding.
    #[must_use]
    pub fn application(&self, application_pack_id: &str) -> Option<&RoleApplicationBindingV1> {
        self.application_bindings
            .iter()
            .find(|binding| binding.application_pack_id == application_pack_id)
    }
}

impl RoleContractBundleV1 {
    /// Verifies every bundle artifact and exact cross-binding.
    pub fn validate(&self) -> Result<(), RoleContractError> {
        if self.schema_version != ROLE_CONTRACT_SCHEMA_VERSION {
            return invalid("Role bundle schema version is unsupported");
        }
        self.contract.validate()?;
        for hash in [
            &self.manifest.contract_sha256,
            &self.manifest.source_inventory_sha256,
            &self.manifest.schema_sha256,
            &self.manifest.policy_set_sha256,
            &self.manifest.manifest_sha256,
            &self.source_lock.source_inventory_sha256,
            &self.source_lock.source_lock_sha256,
            &self.conformance.contract_sha256,
            &self.conformance.conformance_sha256,
            &self.bundle_sha256,
        ] {
            validate_hash(hash, "Role bundle hash")?;
        }
        if self.manifest.role_contract_id != self.contract.role_contract_id
            || self.manifest.role_version != self.contract.role_version
            || self.manifest.contract_sha256 != self.contract.contract_sha256
            || self.manifest.source_inventory_sha256 != self.contract.source_inventory_sha256
            || self.manifest.policy_set_sha256 != self.contract.policy_set_sha256
            || self.source_lock.role_contract_id != self.contract.role_contract_id
            || self.source_lock.role_version != self.contract.role_version
            || self.source_lock.source_inventory_sha256 != self.contract.source_inventory_sha256
            || self.conformance.role_contract_id != self.contract.role_contract_id
            || self.conformance.contract_sha256 != self.contract.contract_sha256
            || !self.conformance.strict_schema_validated
            || !self.conformance.references_validated
            || !self.conformance.deterministic_normalization
            || !self.conformance.no_execution_authority
        {
            return crate::integrity("Role bundle cross-binding differs");
        }
        if hash_without(&self.manifest, &["manifest_sha256"])? != self.manifest.manifest_sha256
            || hash_without(&self.source_lock, &["source_lock_sha256"])?
                != self.source_lock.source_lock_sha256
            || hash_without(&self.conformance, &["conformance_sha256"])?
                != self.conformance.conformance_sha256
            || hash_without(self, &["bundle_sha256"])? != self.bundle_sha256
        {
            return crate::integrity("Role bundle artifact self-hash differs");
        }
        Ok(())
    }
}

trait ContractParts {
    fn organization_scope(&self) -> &OrganizationScopeV1;
    fn responsibilities(&self) -> &[RoleResponsibilityDescriptorV1];
    fn work_classes(&self) -> &[AcceptedWorkClassRefV1];
    fn prohibited_work_classes(&self) -> &[String];
    fn capability_policy(&self) -> &RoleCapabilityPolicyV1;
    fn risk_policy(&self) -> &RoleRiskPolicyV1;
    fn applications(&self) -> &[RoleApplicationBindingV1];
    fn observation_sources(&self) -> &[RoleObservationSourceV1];
    fn calendar(&self) -> &RoleWorkingCalendarV1;
    fn kpis(&self) -> &[RoleKpiDefinitionV1];
    fn slas(&self) -> &[RoleSlaProfileV1];
    fn reporting(&self) -> &[RoleReportingObligationV1];
    fn memory(&self) -> &RoleMemoryBoundaryV1;
    fn escalation(&self) -> &RoleEscalationPolicyV1;
    fn human_exception(&self) -> &RoleHumanExceptionPolicyV1;
}

macro_rules! impl_parts {
    ($type:ty) => {
        impl ContractParts for $type {
            fn organization_scope(&self) -> &OrganizationScopeV1 {
                &self.organization_scope
            }
            fn responsibilities(&self) -> &[RoleResponsibilityDescriptorV1] {
                &self.responsibilities
            }
            fn work_classes(&self) -> &[AcceptedWorkClassRefV1] {
                &self.accepted_work_classes
            }
            fn prohibited_work_classes(&self) -> &[String] {
                &self.prohibited_work_class_ids
            }
            fn capability_policy(&self) -> &RoleCapabilityPolicyV1 {
                &self.capability_policy
            }
            fn risk_policy(&self) -> &RoleRiskPolicyV1 {
                &self.risk_policy
            }
            fn applications(&self) -> &[RoleApplicationBindingV1] {
                &self.application_bindings
            }
            fn observation_sources(&self) -> &[RoleObservationSourceV1] {
                &self.observation_sources
            }
            fn calendar(&self) -> &RoleWorkingCalendarV1 {
                &self.working_calendar
            }
            fn kpis(&self) -> &[RoleKpiDefinitionV1] {
                &self.kpi_definitions
            }
            fn slas(&self) -> &[RoleSlaProfileV1] {
                &self.sla_profiles
            }
            fn reporting(&self) -> &[RoleReportingObligationV1] {
                &self.reporting_obligations
            }
            fn memory(&self) -> &RoleMemoryBoundaryV1 {
                &self.memory_boundary
            }
            fn escalation(&self) -> &RoleEscalationPolicyV1 {
                &self.escalation_policy
            }
            fn human_exception(&self) -> &RoleHumanExceptionPolicyV1 {
                &self.human_exception_policy
            }
        }
    };
}

impl_parts!(RoleSourcePackV1);
impl_parts!(RoleContractV1);

fn validate_contract_parts(parts: &impl ContractParts) -> Result<(), RoleContractError> {
    parts.organization_scope().validate()?;
    validate_responsibilities(parts.responsibilities())?;
    validate_capability_policy(parts.capability_policy())?;
    validate_risk_policy(parts.risk_policy())?;
    validate_applications(parts.applications(), parts.capability_policy())?;
    validate_observation_sources(parts.observation_sources(), parts.applications())?;
    validate_calendar(parts.calendar())?;
    validate_kpis(parts.kpis())?;
    validate_slas(parts.slas())?;
    validate_reporting(parts.reporting())?;
    validate_memory(parts.memory())?;
    validate_escalation(parts.escalation())?;
    validate_human_exception(parts.human_exception())?;
    validate_ids(
        parts.prohibited_work_classes(),
        "prohibited work classes",
        true,
    )?;

    let responsibility_ids = ids(parts
        .responsibilities()
        .iter()
        .map(|item| &item.responsibility_id));
    let sla_ids = ids(parts.slas().iter().map(|item| &item.sla_profile_id));
    let app_ids = ids(parts
        .applications()
        .iter()
        .map(|item| &item.application_pack_id));
    let observation_ids = ids(parts
        .observation_sources()
        .iter()
        .map(|item| &item.observation_source_id));
    let accepted_ids = ids(parts.work_classes().iter().map(|item| &item.work_class_id));
    let prohibited_ids = parts
        .prohibited_work_classes()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if !accepted_ids.is_disjoint(&prohibited_ids) {
        return invalid("accepted and prohibited work classes overlap");
    }
    let allowed_caps = parts
        .capability_policy()
        .allowed_capability_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    for work in parts.work_classes() {
        validate_work_class(work)?;
        if !responsibility_ids.contains(&work.responsibility_id)
            || !sla_ids.contains(&work.sla_profile_id)
            || !work
                .required_application_pack_ids
                .iter()
                .all(|id| app_ids.contains(id))
            || !work
                .permitted_observation_source_ids
                .iter()
                .all(|id| observation_ids.contains(id))
            || !work
                .required_capability_ids
                .iter()
                .all(|id| allowed_caps.contains(id))
            || work.maximum_risk > parts.risk_policy().mandatory_escalation_risk
        {
            return invalid("work class contains a dangling or expanded reference");
        }
    }
    for work_id in &accepted_ids {
        let memberships = parts
            .responsibilities()
            .iter()
            .filter(|responsibility| responsibility.accepted_work_class_ids.contains(work_id))
            .count();
        if memberships == 0 {
            return invalid("accepted work class belongs to no responsibility");
        }
    }
    let obligation_ids = ids(parts.reporting().iter().map(|item| &item.obligation_id));
    for responsibility in parts.responsibilities() {
        if !responsibility
            .reporting_obligation_ids
            .iter()
            .all(|id| obligation_ids.contains(id))
        {
            return invalid("responsibility references an unknown reporting obligation");
        }
    }
    Ok(())
}

fn normalize_responsibilities(
    values: &mut [RoleResponsibilityDescriptorV1],
) -> Result<(), RoleContractError> {
    for value in values.iter_mut() {
        for (ids, label) in [
            (&mut value.outcome_class_ids, "outcome class IDs"),
            (
                &mut value.accepted_work_class_ids,
                "responsibility work classes",
            ),
            (
                &mut value.evidence_class_ids,
                "responsibility evidence classes",
            ),
            (
                &mut value.reporting_obligation_ids,
                "responsibility reporting obligations",
            ),
        ] {
            canonicalize_ids(ids, label, false)?;
        }
    }
    values.sort_by(|left, right| left.responsibility_id.cmp(&right.responsibility_id));
    validate_responsibilities(values)
}

fn validate_responsibilities(
    values: &[RoleResponsibilityDescriptorV1],
) -> Result<(), RoleContractError> {
    if values.is_empty()
        || values.len() > MAX_ITEMS
        || !values
            .windows(2)
            .all(|pair| pair[0].responsibility_id < pair[1].responsibility_id)
    {
        return invalid("responsibilities are empty, duplicated, unsorted, or oversized");
    }
    for value in values {
        validate_id(&value.responsibility_id, "responsibility_id")?;
        validate_text(&value.description, "responsibility description")?;
        validate_ids(&value.outcome_class_ids, "outcome class IDs", false)?;
        validate_ids(
            &value.accepted_work_class_ids,
            "responsibility work classes",
            false,
        )?;
        validate_ids(
            &value.evidence_class_ids,
            "responsibility evidence classes",
            false,
        )?;
        validate_ids(
            &value.reporting_obligation_ids,
            "responsibility reporting obligations",
            false,
        )?;
    }
    Ok(())
}

fn normalize_work_classes(values: &mut [AcceptedWorkClassRefV1]) -> Result<(), RoleContractError> {
    for value in values.iter_mut() {
        for (ids, label, empty) in [
            (
                &mut value.allowed_priority_classes,
                "priority classes",
                false,
            ),
            (
                &mut value.required_application_pack_ids,
                "required application packs",
                false,
            ),
            (
                &mut value.required_integration_ids,
                "required integrations",
                false,
            ),
            (
                &mut value.required_capability_ids,
                "required capabilities",
                false,
            ),
            (
                &mut value.permitted_observation_source_ids,
                "permitted observation sources",
                false,
            ),
            (
                &mut value.mandatory_escalation_reason_codes,
                "mandatory escalation reasons",
                true,
            ),
        ] {
            canonicalize_ids(ids, label, empty)?;
        }
    }
    values.sort_by(|left, right| left.work_class_id.cmp(&right.work_class_id));
    if values.is_empty()
        || values.len() > MAX_ITEMS
        || !values
            .windows(2)
            .all(|pair| pair[0].work_class_id < pair[1].work_class_id)
    {
        return invalid("accepted work classes are empty, duplicated, or oversized");
    }
    Ok(())
}

fn validate_work_class(value: &AcceptedWorkClassRefV1) -> Result<(), RoleContractError> {
    validate_id(&value.work_class_id, "work_class_id")?;
    validate_id(&value.contract_version, "work class contract_version")?;
    validate_id(&value.responsibility_id, "work class responsibility_id")?;
    validate_id(&value.sla_profile_id, "work class sla_profile_id")?;
    validate_ids(&value.allowed_priority_classes, "priority classes", false)?;
    validate_ids(
        &value.required_application_pack_ids,
        "required application packs",
        false,
    )?;
    validate_ids(
        &value.required_integration_ids,
        "required integrations",
        false,
    )?;
    validate_ids(
        &value.required_capability_ids,
        "required capabilities",
        false,
    )?;
    validate_ids(
        &value.permitted_observation_source_ids,
        "permitted observation sources",
        false,
    )?;
    validate_ids(
        &value.mandatory_escalation_reason_codes,
        "mandatory escalation reasons",
        true,
    )
}

fn normalize_capability_policy(
    value: &mut RoleCapabilityPolicyV1,
) -> Result<(), RoleContractError> {
    for (ids, label, empty) in [
        (
            &mut value.allowed_capability_ids,
            "allowed capabilities",
            false,
        ),
        (
            &mut value.prohibited_capability_ids,
            "prohibited capabilities",
            true,
        ),
        (
            &mut value.autonomous_capability_ids,
            "autonomous capabilities",
            true,
        ),
        (
            &mut value.confirmation_capability_ids,
            "confirmation capabilities",
            true,
        ),
        (
            &mut value.escalation_only_capability_ids,
            "escalation-only capabilities",
            true,
        ),
        (&mut value.capability_group_ids, "capability groups", true),
        (&mut value.semantic_target_ids, "semantic targets", false),
    ] {
        canonicalize_ids(ids, label, empty)?;
    }
    validate_capability_policy(value)
}

fn validate_capability_policy(value: &RoleCapabilityPolicyV1) -> Result<(), RoleContractError> {
    for (ids, label, empty) in [
        (&value.allowed_capability_ids, "allowed capabilities", false),
        (
            &value.prohibited_capability_ids,
            "prohibited capabilities",
            true,
        ),
        (
            &value.autonomous_capability_ids,
            "autonomous capabilities",
            true,
        ),
        (
            &value.confirmation_capability_ids,
            "confirmation capabilities",
            true,
        ),
        (
            &value.escalation_only_capability_ids,
            "escalation-only capabilities",
            true,
        ),
        (&value.capability_group_ids, "capability groups", true),
        (&value.semantic_target_ids, "semantic targets", false),
    ] {
        validate_ids(ids, label, empty)?;
    }
    if value.maximum_attempts_per_capability == 0 || value.maximum_attempts_per_capability > 16 {
        return invalid("maximum_attempts_per_capability is outside 1..=16");
    }
    let allowed = set(&value.allowed_capability_ids);
    let prohibited = set(&value.prohibited_capability_ids);
    let autonomous = set(&value.autonomous_capability_ids);
    let confirmation = set(&value.confirmation_capability_ids);
    let escalation = set(&value.escalation_only_capability_ids);
    if !allowed.is_disjoint(&prohibited)
        || !autonomous.is_subset(&allowed)
        || !confirmation.is_subset(&allowed)
        || !escalation.is_subset(&allowed)
        || !autonomous.is_disjoint(&confirmation)
        || !autonomous.is_disjoint(&escalation)
        || !confirmation.is_disjoint(&escalation)
    {
        return invalid("capability policy subsets overlap or exceed allowed capabilities");
    }
    Ok(())
}

fn validate_risk_policy(value: &RoleRiskPolicyV1) -> Result<(), RoleContractError> {
    if value.maximum_autonomous_risk > value.maximum_confirmable_risk
        || value.maximum_confirmable_risk > value.mandatory_escalation_risk
        || value.irreversible_actions_allowed
        || value.high_criticality_automatic_allowed
    {
        return invalid("Role risk ordering or v1 irreversible/high-criticality invariant failed");
    }
    Ok(())
}

fn normalize_applications(
    values: &mut [RoleApplicationBindingV1],
) -> Result<(), RoleContractError> {
    for value in values.iter_mut() {
        for (ids, label, empty) in [
            (
                &mut value.integration_ids,
                "application integrations",
                false,
            ),
            (
                &mut value.allowed_semantic_target_ids,
                "application semantic targets",
                false,
            ),
            (
                &mut value.allowed_capability_ids,
                "application capabilities",
                false,
            ),
            (
                &mut value.observation_source_ids,
                "application observation sources",
                false,
            ),
            (
                &mut value.environment_ids,
                "application environments",
                false,
            ),
        ] {
            canonicalize_ids(ids, label, empty)?;
        }
    }
    values.sort_by(|left, right| left.application_pack_id.cmp(&right.application_pack_id));
    Ok(())
}

fn validate_applications(
    values: &[RoleApplicationBindingV1],
    policy: &RoleCapabilityPolicyV1,
) -> Result<(), RoleContractError> {
    if values.is_empty()
        || values.len() > MAX_ITEMS
        || !values
            .windows(2)
            .all(|pair| pair[0].application_pack_id < pair[1].application_pack_id)
    {
        return invalid("application bindings are empty, duplicated, or oversized");
    }
    let allowed = set(&policy.allowed_capability_ids);
    for value in values {
        validate_id(&value.application_pack_id, "application_pack_id")?;
        validate_hash(&value.application_pack_sha256, "application_pack_sha256")?;
        validate_ids(&value.integration_ids, "application integrations", false)?;
        validate_ids(
            &value.allowed_semantic_target_ids,
            "application semantic targets",
            false,
        )?;
        validate_ids(
            &value.allowed_capability_ids,
            "application capabilities",
            false,
        )?;
        validate_ids(
            &value.observation_source_ids,
            "application observation sources",
            false,
        )?;
        validate_ids(&value.environment_ids, "application environments", false)?;
        if !set(&value.allowed_capability_ids).is_subset(&allowed)
            || !set(&value.allowed_semantic_target_ids).is_subset(&set(&policy.semantic_target_ids))
        {
            return invalid("application binding exceeds Role capability policy");
        }
    }
    Ok(())
}

fn normalize_observation_sources(
    values: &mut [RoleObservationSourceV1],
) -> Result<(), RoleContractError> {
    for value in values.iter_mut() {
        canonicalize_ids(
            &mut value.event_class_ids,
            "observation event classes",
            true,
        )?;
    }
    values.sort_by(|left, right| left.observation_source_id.cmp(&right.observation_source_id));
    Ok(())
}

fn validate_observation_sources(
    values: &[RoleObservationSourceV1],
    applications: &[RoleApplicationBindingV1],
) -> Result<(), RoleContractError> {
    if values.is_empty()
        || values.len() > MAX_ITEMS
        || !values
            .windows(2)
            .all(|pair| pair[0].observation_source_id < pair[1].observation_source_id)
    {
        return invalid("observation sources are empty, duplicated, or oversized");
    }
    let app_ids = ids(applications.iter().map(|item| &item.application_pack_id));
    for value in values {
        validate_id(&value.observation_source_id, "observation_source_id")?;
        validate_id(&value.integration_id, "observation integration_id")?;
        validate_id(&value.trust_floor, "observation trust_floor")?;
        validate_ids(&value.event_class_ids, "observation event classes", true)?;
        if value.maximum_staleness_seconds == 0 || value.maximum_staleness_seconds > 86_400 {
            return invalid("observation maximum staleness is outside its bound");
        }
        if let Some(app) = &value.application_pack_id {
            validate_id(app, "observation application_pack_id")?;
            if !app_ids.contains(app) {
                return invalid("observation source references unknown Application Pack");
            }
        }
    }
    Ok(())
}

fn normalize_calendar(value: &mut RoleWorkingCalendarV1) -> Result<(), RoleContractError> {
    value.weekly_windows.sort();
    canonicalize_ids(&mut value.blackout_date_ids, "blackout date IDs", true)?;
    value.calendar_sha256 = ZERO_HASH.to_owned();
    value.calendar_sha256 = hash_without(value, &["calendar_sha256"])?;
    validate_calendar(value)
}

fn validate_calendar(value: &RoleWorkingCalendarV1) -> Result<(), RoleContractError> {
    validate_id(&value.calendar_id, "calendar_id")?;
    validate_id(&value.timezone_id, "timezone_id")?;
    if value.weekly_windows.is_empty()
        || value.weekly_windows.len() > MAX_ITEMS
        || !value
            .weekly_windows
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    {
        return invalid("weekly windows are empty, duplicated, unsorted, or oversized");
    }
    for window in &value.weekly_windows {
        if window.weekday > 6
            || window.start_minute_local >= window.end_minute_local
            || window.end_minute_local > 1_440
        {
            return invalid("weekly window is outside its closed bounds");
        }
    }
    for pair in value.weekly_windows.windows(2) {
        if pair[0].weekday == pair[1].weekday
            && pair[0].end_minute_local > pair[1].start_minute_local
        {
            return invalid("overlapping weekly windows are rejected in v1");
        }
    }
    validate_ids(&value.blackout_date_ids, "blackout date IDs", true)?;
    validate_hash(&value.calendar_sha256, "calendar_sha256")?;
    if hash_without(value, &["calendar_sha256"])? != value.calendar_sha256 {
        return crate::integrity("calendar_sha256 differs");
    }
    Ok(())
}

fn normalize_kpis(values: &mut [RoleKpiDefinitionV1]) -> Result<(), RoleContractError> {
    for value in values.iter_mut() {
        canonicalize_ids(&mut value.evidence_class_ids, "KPI evidence classes", false)?;
    }
    values.sort_by(|left, right| left.kpi_id.cmp(&right.kpi_id));
    validate_kpis(values)
}

fn validate_kpis(values: &[RoleKpiDefinitionV1]) -> Result<(), RoleContractError> {
    if values.is_empty()
        || values.len() > MAX_ITEMS
        || !values
            .windows(2)
            .all(|pair| pair[0].kpi_id < pair[1].kpi_id)
    {
        return invalid("KPI definitions are empty, duplicated, or oversized");
    }
    for value in values {
        validate_id(&value.kpi_id, "kpi_id")?;
        validate_id(&value.metric_id, "metric_id")?;
        validate_id(&value.measurement_window_id, "measurement_window_id")?;
        validate_ids(&value.evidence_class_ids, "KPI evidence classes", false)?;
        if value.target_millionths.is_some() == value.target_integer.is_some() {
            return invalid("KPI requires exactly one typed target");
        }
    }
    Ok(())
}

fn normalize_slas(values: &mut [RoleSlaProfileV1]) -> Result<(), RoleContractError> {
    for value in values.iter_mut() {
        canonicalize_ids(&mut value.pause_conditions, "SLA pause conditions", true)?;
        canonicalize_ids(&mut value.evidence_class_ids, "SLA evidence classes", false)?;
    }
    values.sort_by(|left, right| left.sla_profile_id.cmp(&right.sla_profile_id));
    validate_slas(values)
}

fn validate_slas(values: &[RoleSlaProfileV1]) -> Result<(), RoleContractError> {
    if values.is_empty()
        || values.len() > MAX_ITEMS
        || !values
            .windows(2)
            .all(|pair| pair[0].sla_profile_id < pair[1].sla_profile_id)
    {
        return invalid("SLA profiles are empty, duplicated, or oversized");
    }
    for value in values {
        validate_id(&value.sla_profile_id, "sla_profile_id")?;
        validate_id(&value.priority_class, "priority_class")?;
        validate_ids(&value.pause_conditions, "SLA pause conditions", true)?;
        validate_ids(&value.evidence_class_ids, "SLA evidence classes", false)?;
        if value.acknowledge_within_seconds == 0
            || value.acknowledge_within_seconds > value.begin_within_seconds
            || value.begin_within_seconds > value.escalation_after_seconds
            || value.escalation_after_seconds > value.resolve_within_seconds
            || value.resolve_within_seconds > MAX_ROLE_TTL_SECONDS
        {
            return invalid("SLA timing order or bound is invalid");
        }
    }
    Ok(())
}

fn normalize_reporting(values: &mut [RoleReportingObligationV1]) -> Result<(), RoleContractError> {
    for value in values.iter_mut() {
        canonicalize_ids(
            &mut value.required_evidence_class_ids,
            "report evidence classes",
            false,
        )?;
    }
    values.sort_by(|left, right| left.obligation_id.cmp(&right.obligation_id));
    validate_reporting(values)
}

fn validate_reporting(values: &[RoleReportingObligationV1]) -> Result<(), RoleContractError> {
    if values.is_empty()
        || values.len() > MAX_ITEMS
        || !values
            .windows(2)
            .all(|pair| pair[0].obligation_id < pair[1].obligation_id)
    {
        return invalid("reporting obligations are empty, duplicated, or oversized");
    }
    for value in values {
        validate_id(&value.obligation_id, "obligation_id")?;
        validate_id(&value.report_class_id, "report_class_id")?;
        validate_id(&value.routing_class_id, "routing_class_id")?;
        validate_id(&value.retention_class_id, "retention_class_id")?;
        validate_ids(
            &value.required_evidence_class_ids,
            "report evidence classes",
            false,
        )?;
        if let Some(frequency) = &value.frequency_profile_id {
            validate_id(frequency, "frequency_profile_id")?;
        }
        if value.trigger == RoleReportingTriggerV1::Periodic && value.frequency_profile_id.is_none()
        {
            return invalid("periodic reporting requires frequency_profile_id");
        }
    }
    Ok(())
}

fn normalize_memory(value: &mut RoleMemoryBoundaryV1) -> Result<(), RoleContractError> {
    canonicalize_ids(
        &mut value.allowed_memory_namespace_ids,
        "memory namespaces",
        true,
    )?;
    canonicalize_ids(
        &mut value.prohibited_data_class_ids,
        "prohibited data classes",
        false,
    )?;
    value.memory_boundary_sha256 = ZERO_HASH.to_owned();
    value.memory_boundary_sha256 = hash_without(value, &["memory_boundary_sha256"])?;
    validate_memory(value)
}

fn validate_memory(value: &RoleMemoryBoundaryV1) -> Result<(), RoleContractError> {
    validate_ids(
        &value.allowed_memory_namespace_ids,
        "memory namespaces",
        true,
    )?;
    validate_ids(
        &value.prohibited_data_class_ids,
        "prohibited data classes",
        false,
    )?;
    validate_id(&value.retention_class_id, "memory retention_class_id")?;
    if value.maximum_retention_days > 3_650
        || value.raw_credentials_allowed
        || value.raw_ui_payload_allowed
    {
        return invalid("Role memory boundary permits forbidden raw or excessive retention");
    }
    validate_hash(&value.memory_boundary_sha256, "memory_boundary_sha256")?;
    if hash_without(value, &["memory_boundary_sha256"])? != value.memory_boundary_sha256 {
        return crate::integrity("memory_boundary_sha256 differs");
    }
    Ok(())
}

fn normalize_escalation(value: &mut RoleEscalationPolicyV1) -> Result<(), RoleContractError> {
    canonicalize_ids(
        &mut value.mandatory_reason_codes,
        "mandatory escalation reasons",
        false,
    )?;
    canonicalize_ids(
        &mut value.evidence_class_ids,
        "escalation evidence classes",
        false,
    )?;
    validate_escalation(value)
}

fn validate_escalation(value: &RoleEscalationPolicyV1) -> Result<(), RoleContractError> {
    validate_id(&value.escalation_policy_id, "escalation_policy_id")?;
    if value.routing_class_by_severity.is_empty() || value.routing_class_by_severity.len() > 16 {
        return invalid("severity routing map is empty or oversized");
    }
    for (severity, route) in &value.routing_class_by_severity {
        validate_id(severity, "escalation severity")?;
        validate_id(route, "escalation route class")?;
    }
    for route in [
        &value.authority_exceeded_route_class,
        &value.unsafe_route_class,
        &value.legal_review_route_class,
        &value.policy_conflict_route_class,
    ] {
        validate_id(route, "required escalation route")?;
    }
    validate_ids(
        &value.mandatory_reason_codes,
        "mandatory escalation reasons",
        false,
    )?;
    validate_ids(
        &value.evidence_class_ids,
        "escalation evidence classes",
        false,
    )?;
    if value.maximum_pending_seconds == 0 || value.maximum_pending_seconds > MAX_ROLE_TTL_SECONDS {
        return invalid("maximum_pending_seconds is outside its bound");
    }
    Ok(())
}

fn normalize_human_exception(
    value: &mut RoleHumanExceptionPolicyV1,
) -> Result<(), RoleContractError> {
    for (ids, label, empty) in [
        (
            &mut value.autonomous_reason_codes,
            "autonomous reasons",
            true,
        ),
        (
            &mut value.confirmation_reason_codes,
            "confirmation reasons",
            true,
        ),
        (
            &mut value.mandatory_escalation_reason_codes,
            "mandatory escalation reasons",
            false,
        ),
        (
            &mut value.prohibited_automatic_reason_codes,
            "prohibited automatic reasons",
            false,
        ),
    ] {
        canonicalize_ids(ids, label, empty)?;
    }
    value.policy_sha256 = ZERO_HASH.to_owned();
    value.policy_sha256 = hash_without(value, &["policy_sha256"])?;
    validate_human_exception(value)
}

fn validate_human_exception(value: &RoleHumanExceptionPolicyV1) -> Result<(), RoleContractError> {
    for (ids, label, empty) in [
        (&value.autonomous_reason_codes, "autonomous reasons", true),
        (
            &value.confirmation_reason_codes,
            "confirmation reasons",
            true,
        ),
        (
            &value.mandatory_escalation_reason_codes,
            "mandatory escalation reasons",
            false,
        ),
        (
            &value.prohibited_automatic_reason_codes,
            "prohibited automatic reasons",
            false,
        ),
    ] {
        validate_ids(ids, label, empty)?;
    }
    let required = [
        "legal_approval",
        "irreversible_change",
        "high_criticality",
        "authority_exceeded",
        "policy_unknown",
        "unsafe_verification",
        "material_ambiguity",
        "sensitive_input",
    ];
    if !required.iter().all(|reason| {
        value
            .mandatory_escalation_reason_codes
            .binary_search(&(*reason).to_owned())
            .is_ok()
            || value
                .prohibited_automatic_reason_codes
                .binary_search(&(*reason).to_owned())
                .is_ok()
    }) {
        return invalid("Human-by-Exception policy omits a mandatory v1 boundary");
    }
    if value.human_touch_budget == Some(0)
        || value.human_touch_budget.is_some_and(|budget| budget > 100)
    {
        return invalid("human_touch_budget is outside its bound");
    }
    validate_hash(&value.policy_sha256, "human exception policy_sha256")?;
    if hash_without(value, &["policy_sha256"])? != value.policy_sha256 {
        return crate::integrity("human exception policy_sha256 differs");
    }
    Ok(())
}

fn set(values: &[String]) -> BTreeSet<String> {
    values.iter().cloned().collect()
}

fn ids<'a>(values: impl Iterator<Item = &'a String>) -> BTreeSet<String> {
    values.cloned().collect()
}

fn subset_or_unrestricted(actual: &[String], maximum: &[String]) -> bool {
    maximum.is_empty() || set(actual).is_subset(&set(maximum))
}
