use crate::strict::hash_without;
use crate::{
    integrity, invalid, normalize_ids, reject_sensitive, validate_hash, validate_hashes,
    validate_id, validate_ids, WorkApplicationPackRefV1, WorkCaseError,
    WorkItemAdmissionDecisionV1, WorkItemAdmissionOutcomeV1, WorkItemV1, WorkPriorityClassV1,
    WORK_CASE_BUILD_ID, WORK_CASE_SCHEMA_VERSION, ZERO_HASH,
};
use d2i_cognitive_ir::{CognitiveRiskClass, ComparisonOp};
use d2i_cognitive_recovery::{EscalationRequestV1, EscalationSeverityV1};
use d2i_role_contract::{
    RoleContractV1, RoleDelegationGrantV1, RoleInstanceStatusV1, RoleInstanceV1,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Initial accountable Role binding. It is neither a lease nor execution authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseOwnershipBindingV1 {
    pub schema_version: u32,
    pub ownership_id: String,
    pub case_id: String,
    pub role_instance_id: String,
    pub role_contract_id: String,
    pub role_version: String,
    pub role_contract_sha256: String,
    pub delegation_sha256: String,
    pub organization_id: String,
    pub responsibility_id: String,
    pub work_class_id: String,
    pub ownership_generation: u64,
    pub bound_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub evidence_ids: Vec<String>,
    pub ownership_sha256: String,
}

impl CaseOwnershipBindingV1 {
    /// Creates one generation-1 owner from an admitted Work Item and active Role.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        case_id: String,
        work_item: &WorkItemV1,
        admission: &WorkItemAdmissionDecisionV1,
        contract: &RoleContractV1,
        delegation: &RoleDelegationGrantV1,
        instance: &RoleInstanceV1,
        bound_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
        mut evidence_ids: Vec<String>,
    ) -> Result<Self, WorkCaseError> {
        if admission.outcome != WorkItemAdmissionOutcomeV1::Admitted {
            return Err(WorkCaseError::NotAdmissible(
                "only admitted Work Items can bind Case ownership".to_owned(),
            ));
        }
        let responsibility_id = admission
            .selected_responsibility_id
            .clone()
            .ok_or_else(|| WorkCaseError::Integrity("admission lacks responsibility".to_owned()))?;
        normalize_ids(&mut evidence_ids, "ownership evidence", false)?;
        let mut binding = Self {
            schema_version: WORK_CASE_SCHEMA_VERSION,
            ownership_id: format!("ownership:{case_id}:1"),
            case_id,
            role_instance_id: instance.role_instance_id.clone(),
            role_contract_id: contract.role_contract_id.clone(),
            role_version: contract.role_version.clone(),
            role_contract_sha256: contract.contract_sha256.clone(),
            delegation_sha256: delegation.delegation_sha256.clone(),
            organization_id: work_item.organization_id.clone(),
            responsibility_id,
            work_class_id: work_item.work_class_id.clone(),
            ownership_generation: 1,
            bound_at_unix_seconds,
            expires_at_unix_seconds,
            evidence_ids,
            ownership_sha256: ZERO_HASH.to_owned(),
        };
        binding.ownership_sha256 = hash_without(&binding, &["ownership_sha256"])?;
        binding.validate_against(work_item, admission, contract, delegation, instance)?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<(), WorkCaseError> {
        if self.schema_version != WORK_CASE_SCHEMA_VERSION
            || self.ownership_generation != 1
            || self.bound_at_unix_seconds == 0
            || self.expires_at_unix_seconds <= self.bound_at_unix_seconds
        {
            return invalid("Case ownership schema, generation, or lifetime is invalid");
        }
        for (value, label) in [
            (&self.ownership_id, "ownership_id"),
            (&self.case_id, "ownership case_id"),
            (&self.role_instance_id, "ownership Role Instance"),
            (&self.role_contract_id, "ownership Role Contract ID"),
            (&self.role_version, "ownership Role version"),
            (&self.organization_id, "ownership organization"),
            (&self.responsibility_id, "ownership responsibility"),
            (&self.work_class_id, "ownership work class"),
        ] {
            validate_id(value, label)?;
        }
        for (hash, label) in [
            (&self.role_contract_sha256, "ownership Role Contract hash"),
            (&self.delegation_sha256, "ownership delegation hash"),
            (&self.ownership_sha256, "ownership hash"),
        ] {
            validate_hash(hash, label)?;
        }
        validate_ids(&self.evidence_ids, "ownership evidence", false)?;
        if hash_without(self, &["ownership_sha256"])? != self.ownership_sha256 {
            return integrity("Case ownership self-hash differs");
        }
        reject_sensitive(self, "Case ownership")
    }

    pub fn validate_against(
        &self,
        work_item: &WorkItemV1,
        admission: &WorkItemAdmissionDecisionV1,
        contract: &RoleContractV1,
        delegation: &RoleDelegationGrantV1,
        instance: &RoleInstanceV1,
    ) -> Result<(), WorkCaseError> {
        self.validate()?;
        work_item.validate()?;
        admission.validate()?;
        if admission.outcome != WorkItemAdmissionOutcomeV1::Admitted
            || self.role_instance_id != instance.role_instance_id
            || self.role_contract_id != contract.role_contract_id
            || self.role_version != contract.role_version
            || self.role_contract_sha256 != contract.contract_sha256
            || self.delegation_sha256 != delegation.delegation_sha256
            || self.organization_id != work_item.organization_id
            || self.work_class_id != work_item.work_class_id
            || admission.selected_responsibility_id.as_ref() != Some(&self.responsibility_id)
            || instance
                .activated_at_unix_seconds
                .is_none_or(|activated| self.bound_at_unix_seconds < activated)
            || self.bound_at_unix_seconds >= instance.expires_at_unix_seconds
            || self.expires_at_unix_seconds > instance.expires_at_unix_seconds
            || self.expires_at_unix_seconds > delegation.expires_at_unix_seconds
            || instance.current_status != RoleInstanceStatusV1::Active
        {
            return integrity("Case ownership differs from admitted active Role scope");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseVerificationKindV1 {
    KernelGoalComplete,
    KernelActionPassed,
    TrustedStateCriterion,
    TrustedEvidencePresent,
    AggregateAll,
    AggregateAny,
}

/// Typed Case success requirement evaluated only from verified artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseSuccessRequirementV1 {
    pub requirement_id: String,
    pub outcome_class_id: String,
    pub verification_kind: CaseVerificationKindV1,
    pub required: bool,
    pub minimum_satisfied_count: u32,
    pub referenced_requirement_ids: Vec<String>,
    pub target_state_ref: Option<String>,
    pub comparison_op: Option<ComparisonOp>,
    pub expected_value_hash: Option<String>,
    pub trusted_evidence_class_ids: Vec<String>,
    pub authoritative_source_class_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub requirement_sha256: String,
}

impl CaseSuccessRequirementV1 {
    pub fn seal(mut self) -> Result<Self, WorkCaseError> {
        normalize_ids(
            &mut self.referenced_requirement_ids,
            "referenced requirements",
            true,
        )?;
        normalize_ids(
            &mut self.trusted_evidence_class_ids,
            "trusted evidence classes",
            true,
        )?;
        normalize_ids(
            &mut self.authoritative_source_class_ids,
            "authoritative source classes",
            true,
        )?;
        normalize_ids(&mut self.evidence_ids, "success requirement evidence", true)?;
        self.requirement_sha256 = hash_without(&self, &["requirement_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), WorkCaseError> {
        validate_id(&self.requirement_id, "success requirement_id")?;
        validate_id(&self.outcome_class_id, "outcome class")?;
        validate_ids(
            &self.referenced_requirement_ids,
            "referenced requirements",
            true,
        )?;
        validate_ids(
            &self.trusted_evidence_class_ids,
            "trusted evidence classes",
            true,
        )?;
        validate_ids(
            &self.authoritative_source_class_ids,
            "authoritative source classes",
            true,
        )?;
        validate_ids(&self.evidence_ids, "success requirement evidence", true)?;
        if let Some(target) = &self.target_state_ref {
            validate_id(target, "target state ref")?;
        }
        if let Some(hash) = &self.expected_value_hash {
            validate_hash(hash, "expected value hash")?;
        }
        let aggregate = matches!(
            self.verification_kind,
            CaseVerificationKindV1::AggregateAll | CaseVerificationKindV1::AggregateAny
        );
        if aggregate
            != (!self.referenced_requirement_ids.is_empty()
                && self.minimum_satisfied_count > 0
                && self.target_state_ref.is_none()
                && self.comparison_op.is_none()
                && self.expected_value_hash.is_none())
        {
            return invalid("aggregate Case requirement shape is invalid");
        }
        if !aggregate
            && (self.minimum_satisfied_count != 1 || !self.referenced_requirement_ids.is_empty())
        {
            return invalid("non-aggregate Case requirement count/reference shape is invalid");
        }
        if self.verification_kind == CaseVerificationKindV1::TrustedStateCriterion
            && (self.target_state_ref.is_none()
                || self.comparison_op.is_none()
                || self.expected_value_hash.is_none())
        {
            return invalid("trusted state criterion lacks a typed expected state");
        }
        validate_hash(&self.requirement_sha256, "success requirement hash")?;
        if hash_without(self, &["requirement_sha256"])? != self.requirement_sha256 {
            return integrity("success requirement self-hash differs");
        }
        reject_sensitive(self, "Case success requirement")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseEvidenceProducerKindV1 {
    KernelTaskRun,
    VerifiedAction,
    FinalGoalVerification,
    TrustedObservation,
    SignedExternalEvidence,
    AuthenticatedHumanDecision,
    EscalationRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseEvidenceTrustFloorV1 {
    UntrustedReference,
    Authenticated,
    Trusted,
    Protected,
    Signed,
}

impl CaseEvidenceTrustFloorV1 {
    const fn satisfied_by(self, actual: Self) -> bool {
        actual as u8 >= self as u8
    }
}

/// Required evidence count, producer, trust, staleness, and retention policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseEvidenceRequirementV1 {
    pub evidence_requirement_id: String,
    pub evidence_class_id: String,
    pub minimum_count: u32,
    pub accepted_producer_kinds: Vec<CaseEvidenceProducerKindV1>,
    pub required_trust_floor: CaseEvidenceTrustFloorV1,
    pub required_artifact_type_ids: Vec<String>,
    pub maximum_staleness_seconds: Option<u64>,
    pub retention_class_id: String,
    pub redaction_required: bool,
    pub required: bool,
    pub requirement_sha256: String,
}

impl CaseEvidenceRequirementV1 {
    pub fn seal(mut self) -> Result<Self, WorkCaseError> {
        self.accepted_producer_kinds.sort();
        normalize_ids(
            &mut self.required_artifact_type_ids,
            "required artifact types",
            false,
        )?;
        self.requirement_sha256 = hash_without(&self, &["requirement_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), WorkCaseError> {
        validate_id(&self.evidence_requirement_id, "evidence requirement_id")?;
        validate_id(&self.evidence_class_id, "evidence class")?;
        validate_id(&self.retention_class_id, "evidence retention class")?;
        if self.minimum_count == 0
            || self.accepted_producer_kinds.is_empty()
            || !self
                .accepted_producer_kinds
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            || self.maximum_staleness_seconds == Some(0)
        {
            return invalid("evidence requirement count, producer, or staleness is invalid");
        }
        validate_ids(
            &self.required_artifact_type_ids,
            "required artifact types",
            false,
        )?;
        validate_hash(&self.requirement_sha256, "evidence requirement hash")?;
        if hash_without(self, &["requirement_sha256"])? != self.requirement_sha256 {
            return integrity("evidence requirement self-hash differs");
        }
        Ok(())
    }
}

/// Immutable absolute deadlines calculated by a trusted caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseSlaBindingV1 {
    pub schema_version: u32,
    pub sla_binding_id: String,
    pub case_id: String,
    pub role_sla_profile_id: String,
    pub priority_class: WorkPriorityClassV1,
    pub received_at_unix_seconds: u64,
    pub acknowledge_due_at_unix_seconds: u64,
    pub begin_due_at_unix_seconds: u64,
    pub resolve_due_at_unix_seconds: u64,
    pub escalation_due_at_unix_seconds: u64,
    pub pause_condition_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub binding_sha256: String,
}

impl CaseSlaBindingV1 {
    pub fn create(
        case_id: String,
        priority_class: WorkPriorityClassV1,
        received_at_unix_seconds: u64,
        role_profile: &d2i_role_contract::RoleSlaProfileV1,
        mut evidence_ids: Vec<String>,
    ) -> Result<Self, WorkCaseError> {
        normalize_ids(&mut evidence_ids, "SLA evidence", false)?;
        let mut binding = Self {
            schema_version: WORK_CASE_SCHEMA_VERSION,
            sla_binding_id: format!("sla-binding:{case_id}"),
            case_id,
            role_sla_profile_id: role_profile.sla_profile_id.clone(),
            priority_class,
            received_at_unix_seconds,
            acknowledge_due_at_unix_seconds: received_at_unix_seconds
                .saturating_add(role_profile.acknowledge_within_seconds),
            begin_due_at_unix_seconds: received_at_unix_seconds
                .saturating_add(role_profile.begin_within_seconds),
            resolve_due_at_unix_seconds: received_at_unix_seconds
                .saturating_add(role_profile.resolve_within_seconds),
            escalation_due_at_unix_seconds: received_at_unix_seconds
                .saturating_add(role_profile.escalation_after_seconds),
            pause_condition_ids: role_profile.pause_conditions.clone(),
            evidence_ids,
            binding_sha256: ZERO_HASH.to_owned(),
        };
        binding.pause_condition_ids.sort();
        binding.binding_sha256 = hash_without(&binding, &["binding_sha256"])?;
        binding.validate_against(role_profile)?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<(), WorkCaseError> {
        if self.schema_version != WORK_CASE_SCHEMA_VERSION
            || self.received_at_unix_seconds == 0
            || self.acknowledge_due_at_unix_seconds < self.received_at_unix_seconds
            || self.begin_due_at_unix_seconds < self.received_at_unix_seconds
            || self.resolve_due_at_unix_seconds < self.begin_due_at_unix_seconds
            || self.escalation_due_at_unix_seconds < self.begin_due_at_unix_seconds
        {
            return invalid("Case SLA absolute deadline order is invalid");
        }
        validate_id(&self.sla_binding_id, "SLA binding_id")?;
        validate_id(&self.case_id, "SLA case_id")?;
        validate_id(&self.role_sla_profile_id, "Role SLA profile")?;
        validate_ids(&self.pause_condition_ids, "SLA pause conditions", true)?;
        validate_ids(&self.evidence_ids, "SLA evidence", false)?;
        validate_hash(&self.binding_sha256, "SLA binding hash")?;
        if hash_without(self, &["binding_sha256"])? != self.binding_sha256 {
            return integrity("SLA binding self-hash differs");
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        profile: &d2i_role_contract::RoleSlaProfileV1,
    ) -> Result<(), WorkCaseError> {
        self.validate()?;
        if self.role_sla_profile_id != profile.sla_profile_id
            || self.acknowledge_due_at_unix_seconds
                != self
                    .received_at_unix_seconds
                    .saturating_add(profile.acknowledge_within_seconds)
            || self.begin_due_at_unix_seconds
                != self
                    .received_at_unix_seconds
                    .saturating_add(profile.begin_within_seconds)
            || self.resolve_due_at_unix_seconds
                != self
                    .received_at_unix_seconds
                    .saturating_add(profile.resolve_within_seconds)
            || self.escalation_due_at_unix_seconds
                != self
                    .received_at_unix_seconds
                    .saturating_add(profile.escalation_after_seconds)
            || self.pause_condition_ids != profile.pause_conditions
        {
            return integrity("Case SLA differs from the selected Role profile");
        }
        Ok(())
    }
}

/// Immutable one-Work-Item/one-Role Case definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseContractV1 {
    pub schema_version: u32,
    pub case_id: String,
    pub case_generation: u64,
    pub organization_id: String,
    pub source_work_item_id: String,
    pub source_work_item_sha256: String,
    pub work_item_admission_sha256: String,
    pub role_instance_id: String,
    pub role_contract_sha256: String,
    pub delegation_sha256: String,
    pub ownership_binding: CaseOwnershipBindingV1,
    pub work_class_id: String,
    pub responsibility_id: String,
    pub priority_class: WorkPriorityClassV1,
    pub risk_class: CognitiveRiskClass,
    pub subject_refs: Vec<String>,
    pub outcome_requirements: Vec<CaseSuccessRequirementV1>,
    pub evidence_requirements: Vec<CaseEvidenceRequirementV1>,
    pub sla_binding: CaseSlaBindingV1,
    pub allowed_application_pack_refs: Vec<WorkApplicationPackRefV1>,
    pub allowed_integration_ids: Vec<String>,
    pub allowed_capability_ids: Vec<String>,
    pub prohibited_capability_ids: Vec<String>,
    pub allowed_semantic_target_ids: Vec<String>,
    pub maximum_task_attempts: u32,
    pub maximum_recovery_cycles_per_task: u32,
    pub clarification_allowed: bool,
    pub automatic_recovery_allowed: bool,
    pub mandatory_escalation_reason_codes: Vec<String>,
    pub reporting_obligation_ids: Vec<String>,
    pub retention_class_id: String,
    pub opened_at_unix_seconds: u64,
    pub evidence_ids: Vec<String>,
    pub contract_sha256: String,
}

impl CaseContractV1 {
    /// Canonically seals a caller-assembled Case after exact Role/Work validation.
    #[allow(clippy::too_many_arguments)]
    pub fn seal_against(
        mut self,
        work_item: &WorkItemV1,
        admission: &WorkItemAdmissionDecisionV1,
        role_contract: &RoleContractV1,
        delegation: &RoleDelegationGrantV1,
        instance: &RoleInstanceV1,
    ) -> Result<Self, WorkCaseError> {
        self.subject_refs.sort();
        self.outcome_requirements
            .sort_by(|left, right| left.requirement_id.cmp(&right.requirement_id));
        self.evidence_requirements.sort_by(|left, right| {
            left.evidence_requirement_id
                .cmp(&right.evidence_requirement_id)
        });
        self.allowed_application_pack_refs.sort();
        for values in [
            &mut self.allowed_integration_ids,
            &mut self.allowed_capability_ids,
            &mut self.prohibited_capability_ids,
            &mut self.allowed_semantic_target_ids,
            &mut self.mandatory_escalation_reason_codes,
            &mut self.reporting_obligation_ids,
            &mut self.evidence_ids,
        ] {
            values.sort();
        }
        self.contract_sha256 = hash_without(&self, &["contract_sha256"])?;
        self.validate_against(work_item, admission, role_contract, delegation, instance)?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), WorkCaseError> {
        if self.schema_version != WORK_CASE_SCHEMA_VERSION
            || self.case_generation != 1
            || self.opened_at_unix_seconds == 0
            || self.maximum_task_attempts == 0
            || self.maximum_task_attempts > 1_024
            || self.maximum_recovery_cycles_per_task > 128
        {
            return invalid("Case Contract schema, generation, or limits are invalid");
        }
        for (value, label) in [
            (&self.case_id, "Case Contract case_id"),
            (&self.organization_id, "Case Contract organization"),
            (&self.source_work_item_id, "Case source Work Item"),
            (&self.role_instance_id, "Case Role Instance"),
            (&self.work_class_id, "Case work class"),
            (&self.responsibility_id, "Case responsibility"),
            (&self.retention_class_id, "Case retention class"),
        ] {
            validate_id(value, label)?;
        }
        for (hash, label) in [
            (&self.source_work_item_sha256, "Case source Work Item hash"),
            (&self.work_item_admission_sha256, "Case Work Item admission"),
            (&self.role_contract_sha256, "Case Role Contract hash"),
            (&self.delegation_sha256, "Case delegation hash"),
            (&self.contract_sha256, "Case Contract hash"),
        ] {
            validate_hash(hash, label)?;
        }
        self.ownership_binding.validate()?;
        self.sla_binding.validate()?;
        for (values, label, allow_empty) in [
            (&self.subject_refs, "Case subject refs", false),
            (&self.allowed_integration_ids, "Case integrations", false),
            (&self.allowed_capability_ids, "Case capabilities", false),
            (
                &self.prohibited_capability_ids,
                "Case prohibited capabilities",
                true,
            ),
            (
                &self.allowed_semantic_target_ids,
                "Case semantic targets",
                false,
            ),
            (
                &self.mandatory_escalation_reason_codes,
                "Case escalation reasons",
                true,
            ),
            (
                &self.reporting_obligation_ids,
                "Case reporting obligations",
                true,
            ),
            (&self.evidence_ids, "Case Contract evidence", false),
        ] {
            validate_ids(values, label, allow_empty)?;
        }
        if self.allowed_application_pack_refs.is_empty()
            || !self
                .allowed_application_pack_refs
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        {
            return invalid("Case Application Pack refs are empty, duplicate, or unsorted");
        }
        for reference in &self.allowed_application_pack_refs {
            reference.validate()?;
        }
        if self.outcome_requirements.is_empty()
            || !self
                .outcome_requirements
                .windows(2)
                .all(|pair| pair[0].requirement_id < pair[1].requirement_id)
            || self.evidence_requirements.is_empty()
            || !self
                .evidence_requirements
                .windows(2)
                .all(|pair| pair[0].evidence_requirement_id < pair[1].evidence_requirement_id)
        {
            return invalid("Case requirements are empty, duplicate, or unsorted");
        }
        for requirement in &self.outcome_requirements {
            requirement.validate()?;
        }
        validate_requirement_graph(&self.outcome_requirements)?;
        for requirement in &self.evidence_requirements {
            requirement.validate()?;
        }
        if !disjoint(
            &self.allowed_capability_ids,
            &self.prohibited_capability_ids,
        ) {
            return invalid("Case allowed and prohibited capabilities overlap");
        }
        if hash_without(self, &["contract_sha256"])? != self.contract_sha256 {
            return integrity("Case Contract self-hash differs");
        }
        reject_sensitive(self, "Case Contract")
    }

    pub fn validate_against(
        &self,
        work_item: &WorkItemV1,
        admission: &WorkItemAdmissionDecisionV1,
        role_contract: &RoleContractV1,
        delegation: &RoleDelegationGrantV1,
        instance: &RoleInstanceV1,
    ) -> Result<(), WorkCaseError> {
        self.validate()?;
        self.ownership_binding.validate_against(
            work_item,
            admission,
            role_contract,
            delegation,
            instance,
        )?;
        if admission.outcome != WorkItemAdmissionOutcomeV1::Admitted
            || self.case_id != self.ownership_binding.case_id
            || self.organization_id != work_item.organization_id
            || self.source_work_item_id != work_item.work_item_id
            || self.source_work_item_sha256 != work_item.work_item_sha256
            || self.work_item_admission_sha256 != admission.decision_sha256
            || self.role_instance_id != instance.role_instance_id
            || self.role_contract_sha256 != role_contract.contract_sha256
            || self.delegation_sha256 != delegation.delegation_sha256
            || self.work_class_id != work_item.work_class_id
            || self.responsibility_id != self.ownership_binding.responsibility_id
            || self.priority_class != work_item.priority_class
            || self.risk_class != work_item.risk_class
            || self.subject_refs != work_item.subject_refs
        {
            return integrity("Case Contract differs from its one-to-one admitted source");
        }
        let work = role_contract
            .accepted_work_classes
            .iter()
            .find(|candidate| candidate.work_class_id == self.work_class_id)
            .ok_or_else(|| WorkCaseError::Integrity("Case work class is absent".to_owned()))?;
        let role_sla = role_contract
            .sla_profiles
            .iter()
            .find(|profile| profile.sla_profile_id == self.sla_binding.role_sla_profile_id)
            .ok_or_else(|| WorkCaseError::Integrity("Case SLA profile is absent".to_owned()))?;
        self.sla_binding.validate_against(role_sla)?;
        if !is_subset(
            &self.allowed_integration_ids,
            &delegation.delegated_integration_ids,
        ) || !is_subset(
            &self.allowed_capability_ids,
            &delegation.delegated_capability_ids,
        ) || !is_subset(
            &self.allowed_capability_ids,
            &work_item.capability_requirement_ids,
        ) || !is_subset(
            &self.allowed_semantic_target_ids,
            &work_item.semantic_target_ids,
        ) || !is_subset(
            &self.reporting_obligation_ids,
            &admission.selected_reporting_obligation_ids,
        ) || self.clarification_allowed != work.clarification_allowed
            || self.automatic_recovery_allowed != work.automatic_recovery_allowed
        {
            return Err(WorkCaseError::NotAdmissible(
                "Case Contract expands Work Item or delegated Role scope".to_owned(),
            ));
        }
        if !self.allowed_application_pack_refs.iter().all(|reference| {
            work_item.application_pack_refs.contains(reference)
                && delegation
                    .delegated_application_pack_ids
                    .contains(&reference.application_pack_id)
        }) {
            return Err(WorkCaseError::NotAdmissible(
                "Case Contract expands Application Pack scope".to_owned(),
            ));
        }
        Ok(())
    }
}

fn validate_requirement_graph(
    requirements: &[CaseSuccessRequirementV1],
) -> Result<(), WorkCaseError> {
    let ids = requirements
        .iter()
        .map(|item| item.requirement_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut indegree = BTreeMap::<&str, usize>::new();
    let mut dependents = BTreeMap::<&str, Vec<&str>>::new();
    for requirement in requirements {
        indegree.insert(
            &requirement.requirement_id,
            requirement.referenced_requirement_ids.len(),
        );
        for referenced in &requirement.referenced_requirement_ids {
            if !ids.contains(referenced.as_str()) || referenced == &requirement.requirement_id {
                return invalid("Case requirement reference is absent or self-referential");
            }
            dependents
                .entry(referenced)
                .or_default()
                .push(&requirement.requirement_id);
        }
    }
    let mut queue = indegree
        .iter()
        .filter_map(|(id, count)| (*count == 0).then_some(*id))
        .collect::<VecDeque<_>>();
    let mut visited = 0;
    while let Some(id) = queue.pop_front() {
        visited += 1;
        for dependent in dependents.get(id).into_iter().flatten() {
            let count = indegree
                .get_mut(dependent)
                .ok_or_else(|| WorkCaseError::Integrity("requirement graph changed".to_owned()))?;
            *count = count.saturating_sub(1);
            if *count == 0 {
                queue.push_back(dependent);
            }
        }
    }
    if visited != requirements.len() {
        return invalid("Case aggregate requirement graph contains a cycle");
    }
    Ok(())
}

fn is_subset(values: &[String], maximum: &[String]) -> bool {
    values
        .iter()
        .all(|value| maximum.binary_search(value).is_ok())
}

fn disjoint(left: &[String], right: &[String]) -> bool {
    left.iter().all(|value| right.binary_search(value).is_err())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseLifecycleStatusV1 {
    Opened,
    Active,
    AwaitingClarification,
    Blocked,
    AwaitingVerification,
    EscalationPending,
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseTerminalOutcomeV1 {
    VerifiedComplete,
    ExplicitRefusal,
    Escalated,
}

/// Durable Case state. Task failure, timeout, and blocked are never terminal outcomes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseInstanceV1 {
    pub schema_version: u32,
    pub case_id: String,
    pub case_generation: u64,
    pub case_contract_sha256: String,
    pub work_item_sha256: String,
    pub role_instance_id: String,
    pub ownership_sha256: String,
    pub organization_id: String,
    pub current_status: CaseLifecycleStatusV1,
    pub terminal_outcome: Option<CaseTerminalOutcomeV1>,
    pub lifecycle_generation: u64,
    pub opened_at_unix_seconds: u64,
    pub activated_at_unix_seconds: Option<u64>,
    pub last_transition_at_unix_seconds: u64,
    pub terminal_at_unix_seconds: Option<u64>,
    pub latest_task_sequence: u64,
    pub task_attempt_count: u32,
    pub successful_task_count: u32,
    pub clarification_count: u32,
    pub escalation_count: u32,
    pub recovery_cycle_count: u32,
    pub unresolved_requirement_ids: Vec<String>,
    pub satisfied_requirement_ids: Vec<String>,
    pub evidence_index_sha256: String,
    pub active_block_sha256: Option<String>,
    pub latest_task_attempt_sha256: Option<String>,
    pub latest_kernel_run_record_sha256: Option<String>,
    pub latest_work_report_sha256: Option<String>,
    pub latest_verified_result_sha256: Option<String>,
    pub latest_escalation_sha256: Option<String>,
    pub ledger_id: String,
    pub ledger_chain_head: String,
    pub evidence_ids: Vec<String>,
    pub instance_sha256: String,
}

impl CaseInstanceV1 {
    pub fn open(
        contract: &CaseContractV1,
        evidence_index_sha256: String,
        ledger_id: String,
        ledger_chain_head: String,
        mut evidence_ids: Vec<String>,
    ) -> Result<Self, WorkCaseError> {
        contract.validate()?;
        normalize_ids(&mut evidence_ids, "Case Instance evidence", false)?;
        let mut unresolved = contract
            .outcome_requirements
            .iter()
            .filter(|item| item.required)
            .map(|item| item.requirement_id.clone())
            .collect::<Vec<_>>();
        unresolved.sort();
        let mut instance = Self {
            schema_version: WORK_CASE_SCHEMA_VERSION,
            case_id: contract.case_id.clone(),
            case_generation: contract.case_generation,
            case_contract_sha256: contract.contract_sha256.clone(),
            work_item_sha256: contract.source_work_item_sha256.clone(),
            role_instance_id: contract.role_instance_id.clone(),
            ownership_sha256: contract.ownership_binding.ownership_sha256.clone(),
            organization_id: contract.organization_id.clone(),
            current_status: CaseLifecycleStatusV1::Opened,
            terminal_outcome: None,
            lifecycle_generation: 1,
            opened_at_unix_seconds: contract.opened_at_unix_seconds,
            activated_at_unix_seconds: None,
            last_transition_at_unix_seconds: contract.opened_at_unix_seconds,
            terminal_at_unix_seconds: None,
            latest_task_sequence: 0,
            task_attempt_count: 0,
            successful_task_count: 0,
            clarification_count: 0,
            escalation_count: 0,
            recovery_cycle_count: 0,
            unresolved_requirement_ids: unresolved,
            satisfied_requirement_ids: Vec::new(),
            evidence_index_sha256,
            active_block_sha256: None,
            latest_task_attempt_sha256: None,
            latest_kernel_run_record_sha256: None,
            latest_work_report_sha256: None,
            latest_verified_result_sha256: None,
            latest_escalation_sha256: None,
            ledger_id,
            ledger_chain_head,
            evidence_ids,
            instance_sha256: ZERO_HASH.to_owned(),
        };
        instance.instance_sha256 = hash_without(&instance, &["instance_sha256"])?;
        instance.validate_against(contract)?;
        Ok(instance)
    }

    pub fn validate(&self) -> Result<(), WorkCaseError> {
        if self.schema_version != WORK_CASE_SCHEMA_VERSION
            || self.case_generation != 1
            || self.lifecycle_generation == 0
            || self.opened_at_unix_seconds == 0
            || self.last_transition_at_unix_seconds < self.opened_at_unix_seconds
            || self.task_attempt_count < self.successful_task_count
        {
            return invalid("Case Instance schema, generation, time, or counters are invalid");
        }
        for (value, label) in [
            (&self.case_id, "Case Instance case_id"),
            (&self.role_instance_id, "Case Instance Role"),
            (&self.organization_id, "Case Instance organization"),
            (&self.ledger_id, "Case ledger_id"),
        ] {
            validate_id(value, label)?;
        }
        for (hash, label) in [
            (&self.case_contract_sha256, "Case Instance contract"),
            (&self.work_item_sha256, "Case Instance Work Item"),
            (&self.ownership_sha256, "Case Instance ownership"),
            (&self.evidence_index_sha256, "Case Instance evidence index"),
            (&self.ledger_chain_head, "Case Instance ledger head"),
            (&self.instance_sha256, "Case Instance hash"),
        ] {
            validate_hash(hash, label)?;
        }
        for (value, label) in [
            (&self.active_block_sha256, "active block hash"),
            (&self.latest_task_attempt_sha256, "latest task attempt hash"),
            (
                &self.latest_kernel_run_record_sha256,
                "latest Kernel run hash",
            ),
            (&self.latest_work_report_sha256, "latest WorkReport hash"),
            (
                &self.latest_verified_result_sha256,
                "latest verified result hash",
            ),
            (&self.latest_escalation_sha256, "latest escalation hash"),
        ] {
            if let Some(hash) = value {
                validate_hash(hash, label)?;
            }
        }
        validate_ids(
            &self.unresolved_requirement_ids,
            "unresolved requirements",
            true,
        )?;
        validate_ids(
            &self.satisfied_requirement_ids,
            "satisfied requirements",
            true,
        )?;
        validate_ids(&self.evidence_ids, "Case Instance evidence", false)?;
        if !disjoint(
            &self.unresolved_requirement_ids,
            &self.satisfied_requirement_ids,
        ) {
            return integrity("satisfied and unresolved Case requirements overlap");
        }
        let terminal = self.current_status == CaseLifecycleStatusV1::Terminal;
        if terminal != (self.terminal_outcome.is_some() && self.terminal_at_unix_seconds.is_some())
        {
            return integrity("Case terminal status, outcome, and timestamp differ");
        }
        if (self.current_status == CaseLifecycleStatusV1::Blocked)
            != self.active_block_sha256.is_some()
        {
            return integrity("only blocked Case state may carry an active block");
        }
        if hash_without(self, &["instance_sha256"])? != self.instance_sha256 {
            return integrity("Case Instance self-hash differs");
        }
        reject_sensitive(self, "Case Instance")
    }

    pub fn validate_against(&self, contract: &CaseContractV1) -> Result<(), WorkCaseError> {
        self.validate()?;
        contract.validate()?;
        if self.case_id != contract.case_id
            || self.case_generation != contract.case_generation
            || self.case_contract_sha256 != contract.contract_sha256
            || self.work_item_sha256 != contract.source_work_item_sha256
            || self.role_instance_id != contract.role_instance_id
            || self.ownership_sha256 != contract.ownership_binding.ownership_sha256
            || self.organization_id != contract.organization_id
            || self.opened_at_unix_seconds != contract.opened_at_unix_seconds
            || self.task_attempt_count > contract.maximum_task_attempts
        {
            return integrity("Case Instance differs from immutable Case Contract");
        }
        let known = contract
            .outcome_requirements
            .iter()
            .map(|item| item.requirement_id.as_str())
            .collect::<BTreeSet<_>>();
        if self
            .unresolved_requirement_ids
            .iter()
            .chain(&self.satisfied_requirement_ids)
            .any(|id| !known.contains(id.as_str()))
        {
            return integrity("Case Instance references an unknown requirement");
        }
        Ok(())
    }

    /// Applies only a legal non-terminal lifecycle transition.
    pub fn transition_non_terminal(
        &self,
        next: CaseLifecycleStatusV1,
        at_unix_seconds: u64,
        active_block_sha256: Option<String>,
    ) -> Result<Self, WorkCaseError> {
        self.validate()?;
        if self.current_status == CaseLifecycleStatusV1::Terminal {
            return Err(WorkCaseError::Terminal(
                "Case reopen is not supported".to_owned(),
            ));
        }
        if next == CaseLifecycleStatusV1::Terminal
            || at_unix_seconds < self.last_transition_at_unix_seconds
        {
            return invalid("non-terminal transition target or time is invalid");
        }
        let legal = matches!(
            (self.current_status, next),
            (CaseLifecycleStatusV1::Opened, CaseLifecycleStatusV1::Active)
                | (
                    CaseLifecycleStatusV1::Opened,
                    CaseLifecycleStatusV1::AwaitingClarification
                )
                | (
                    CaseLifecycleStatusV1::Opened,
                    CaseLifecycleStatusV1::EscalationPending
                )
                | (
                    CaseLifecycleStatusV1::Active,
                    CaseLifecycleStatusV1::AwaitingClarification
                )
                | (
                    CaseLifecycleStatusV1::Active,
                    CaseLifecycleStatusV1::Blocked
                )
                | (
                    CaseLifecycleStatusV1::Active,
                    CaseLifecycleStatusV1::AwaitingVerification
                )
                | (
                    CaseLifecycleStatusV1::Active,
                    CaseLifecycleStatusV1::EscalationPending
                )
                | (
                    CaseLifecycleStatusV1::AwaitingClarification,
                    CaseLifecycleStatusV1::Active
                )
                | (
                    CaseLifecycleStatusV1::AwaitingClarification,
                    CaseLifecycleStatusV1::EscalationPending
                )
                | (
                    CaseLifecycleStatusV1::Blocked,
                    CaseLifecycleStatusV1::Active
                )
                | (
                    CaseLifecycleStatusV1::Blocked,
                    CaseLifecycleStatusV1::AwaitingClarification
                )
                | (
                    CaseLifecycleStatusV1::Blocked,
                    CaseLifecycleStatusV1::EscalationPending
                )
                | (
                    CaseLifecycleStatusV1::AwaitingVerification,
                    CaseLifecycleStatusV1::Active
                )
                | (
                    CaseLifecycleStatusV1::AwaitingVerification,
                    CaseLifecycleStatusV1::Blocked
                )
                | (
                    CaseLifecycleStatusV1::AwaitingVerification,
                    CaseLifecycleStatusV1::EscalationPending
                )
        );
        if !legal {
            return invalid("Case lifecycle transition is not allowed");
        }
        if (next == CaseLifecycleStatusV1::Blocked) != active_block_sha256.is_some() {
            return invalid("blocked transition requires exactly one block hash");
        }
        if let Some(hash) = &active_block_sha256 {
            validate_hash(hash, "transition block hash")?;
        }
        let mut result = self.clone();
        result.current_status = next;
        result.lifecycle_generation = result.lifecycle_generation.saturating_add(1);
        result.last_transition_at_unix_seconds = at_unix_seconds;
        result.active_block_sha256 = active_block_sha256;
        if next == CaseLifecycleStatusV1::Active && result.activated_at_unix_seconds.is_none() {
            result.activated_at_unix_seconds = Some(at_unix_seconds);
        }
        if next == CaseLifecycleStatusV1::AwaitingClarification {
            result.clarification_count = result.clarification_count.saturating_add(1);
        }
        if next == CaseLifecycleStatusV1::EscalationPending {
            result.escalation_count = result.escalation_count.saturating_add(1);
        }
        result.instance_sha256 = hash_without(&result, &["instance_sha256"])?;
        result.validate()?;
        Ok(result)
    }

    /// Applies one verified Task attempt without inferring Case terminal status.
    pub fn attach_attempt(
        &self,
        contract: &CaseContractV1,
        attempt: &CaseTaskAttemptV1,
        evidence_index_sha256: String,
    ) -> Result<Self, WorkCaseError> {
        self.validate_against(contract)?;
        attempt.validate()?;
        validate_hash(&evidence_index_sha256, "updated evidence index")?;
        if self.current_status == CaseLifecycleStatusV1::Terminal {
            return Err(WorkCaseError::Terminal(
                "terminal Case cannot accept a Task attempt".to_owned(),
            ));
        }
        if attempt.case_id != self.case_id
            || attempt.task_sequence != self.latest_task_sequence.saturating_add(1)
            || self.task_attempt_count >= contract.maximum_task_attempts
        {
            return Err(WorkCaseError::Replay(
                "Case Task attempt sequence or limit differs".to_owned(),
            ));
        }
        let mut next = self.clone();
        next.lifecycle_generation = next.lifecycle_generation.saturating_add(1);
        next.latest_task_sequence = attempt.task_sequence;
        next.task_attempt_count = next.task_attempt_count.saturating_add(1);
        if matches!(
            attempt.outcome,
            CaseTaskAttemptOutcomeV1::VerifiedGoalComplete
                | CaseTaskAttemptOutcomeV1::VerifiedPartial
        ) {
            next.successful_task_count = next.successful_task_count.saturating_add(1);
        }
        next.recovery_cycle_count = next
            .recovery_cycle_count
            .saturating_add(attempt.recovery_result_hashes.len() as u32);
        next.latest_task_attempt_sha256 = Some(attempt.attempt_sha256.clone());
        next.latest_kernel_run_record_sha256 = Some(attempt.kernel_task_run_record_sha256.clone());
        next.latest_work_report_sha256 = Some(attempt.work_report_sha256.clone());
        next.latest_verified_result_sha256 = attempt
            .final_goal_verification_sha256
            .clone()
            .or_else(|| attempt.verified_action_result_hashes.last().cloned());
        next.evidence_index_sha256 = evidence_index_sha256;
        next.last_transition_at_unix_seconds = attempt.completed_at_unix_seconds;
        next.instance_sha256 = hash_without(&next, &["instance_sha256"])?;
        next.validate_against(contract)?;
        Ok(next)
    }

    /// Binds the evaluator's exact required-result sets without closing the Case.
    pub fn apply_evaluation(
        &self,
        evaluation: &CaseClosureEvaluationV1,
    ) -> Result<Self, WorkCaseError> {
        self.validate()?;
        evaluation.validate()?;
        if self.current_status == CaseLifecycleStatusV1::Terminal
            || evaluation.case_id != self.case_id
            || evaluation.instance_sha256 != self.instance_sha256
        {
            return integrity("closure evaluation targets a stale or terminal Case");
        }
        let mut next = self.clone();
        next.satisfied_requirement_ids = evaluation
            .evaluated_requirement_results
            .iter()
            .filter(|result| result.satisfied)
            .map(|result| result.requirement_id.clone())
            .collect();
        next.satisfied_requirement_ids.sort();
        next.unresolved_requirement_ids = evaluation.missing_requirement_ids.clone();
        next.unresolved_requirement_ids.sort();
        next.lifecycle_generation = next.lifecycle_generation.saturating_add(1);
        next.last_transition_at_unix_seconds = evaluation.evaluated_at_unix_seconds;
        next.instance_sha256 = hash_without(&next, &["instance_sha256"])?;
        next.validate()?;
        Ok(next)
    }

    /// Closes only against an exact valid terminal candidate.
    pub fn close(
        &self,
        evaluation: &CaseClosureEvaluationV1,
        outcome: CaseTerminalOutcomeV1,
        terminal_at_unix_seconds: u64,
        latest_escalation_sha256: Option<String>,
    ) -> Result<Self, WorkCaseError> {
        self.validate()?;
        evaluation.validate()?;
        if self.current_status == CaseLifecycleStatusV1::Terminal
            || evaluation.instance_sha256 != self.instance_sha256
            || evaluation.terminal_candidate != Some(outcome)
            || terminal_at_unix_seconds < evaluation.evaluated_at_unix_seconds
        {
            return Err(WorkCaseError::Terminal(
                "Case closure lacks an exact current terminal candidate".to_owned(),
            ));
        }
        let legal = matches!(
            (self.current_status, outcome),
            (
                CaseLifecycleStatusV1::AwaitingVerification,
                CaseTerminalOutcomeV1::VerifiedComplete
            ) | (
                CaseLifecycleStatusV1::EscalationPending,
                CaseTerminalOutcomeV1::Escalated
            ) | (
                CaseLifecycleStatusV1::Opened
                    | CaseLifecycleStatusV1::Active
                    | CaseLifecycleStatusV1::Blocked
                    | CaseLifecycleStatusV1::AwaitingClarification,
                CaseTerminalOutcomeV1::ExplicitRefusal
            )
        );
        if !legal {
            return invalid("Case terminal lifecycle transition is not allowed");
        }
        if let Some(hash) = &latest_escalation_sha256 {
            validate_hash(hash, "Case terminal escalation hash")?;
        }
        if (outcome == CaseTerminalOutcomeV1::Escalated) != latest_escalation_sha256.is_some() {
            return integrity("only escalated terminal Case carries escalation evidence");
        }
        let mut next = self.clone();
        next.current_status = CaseLifecycleStatusV1::Terminal;
        next.terminal_outcome = Some(outcome);
        next.terminal_at_unix_seconds = Some(terminal_at_unix_seconds);
        next.last_transition_at_unix_seconds = terminal_at_unix_seconds;
        next.lifecycle_generation = next.lifecycle_generation.saturating_add(1);
        next.active_block_sha256 = None;
        next.latest_escalation_sha256 = latest_escalation_sha256;
        next.instance_sha256 = hash_without(&next, &["instance_sha256"])?;
        next.validate()?;
        Ok(next)
    }

    /// Rebinds the durable append-only ledger head after persistence.
    pub fn bind_ledger_head(&self, chain_head: String) -> Result<Self, WorkCaseError> {
        validate_hash(&chain_head, "Case ledger head")?;
        let mut next = self.clone();
        next.ledger_chain_head = chain_head;
        next.instance_sha256 = hash_without(&next, &["instance_sha256"])?;
        next.validate()?;
        Ok(next)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseBlockKindV1 {
    MissingInformation,
    ExternalDependency,
    RoleInactive,
    PolicyUnavailable,
    InfrastructureUnavailable,
    EvidenceMissing,
    VerificationInconclusive,
    BudgetExhausted,
}

/// Non-terminal bounded Case block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseBlockV1 {
    pub block_id: String,
    pub case_id: String,
    pub block_kind: CaseBlockKindV1,
    pub reason_codes: Vec<String>,
    pub originating_task_attempt_sha256: Option<String>,
    pub clarification_request_sha256: Option<String>,
    pub missing_requirement_ids: Vec<String>,
    pub blocking_dependency_refs: Vec<String>,
    pub blocked_at_unix_seconds: u64,
    pub review_after_unix_seconds: Option<u64>,
    pub evidence_ids: Vec<String>,
    pub block_sha256: String,
}

impl CaseBlockV1 {
    pub fn seal(mut self) -> Result<Self, WorkCaseError> {
        for values in [
            &mut self.reason_codes,
            &mut self.missing_requirement_ids,
            &mut self.blocking_dependency_refs,
            &mut self.evidence_ids,
        ] {
            values.sort();
        }
        self.block_sha256 = hash_without(&self, &["block_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), WorkCaseError> {
        if self.blocked_at_unix_seconds == 0
            || self
                .review_after_unix_seconds
                .is_some_and(|review| review <= self.blocked_at_unix_seconds)
        {
            return invalid("Case block time is invalid");
        }
        validate_id(&self.block_id, "Case block_id")?;
        validate_id(&self.case_id, "Case block case_id")?;
        validate_ids(&self.reason_codes, "Case block reasons", false)?;
        validate_ids(
            &self.missing_requirement_ids,
            "Case block missing requirements",
            true,
        )?;
        validate_ids(
            &self.blocking_dependency_refs,
            "Case blocking dependencies",
            true,
        )?;
        validate_ids(&self.evidence_ids, "Case block evidence", false)?;
        for (hash, label) in [
            (&self.originating_task_attempt_sha256, "block attempt hash"),
            (
                &self.clarification_request_sha256,
                "block clarification hash",
            ),
        ] {
            if let Some(hash) = hash {
                validate_hash(hash, label)?;
            }
        }
        validate_hash(&self.block_sha256, "Case block hash")?;
        if hash_without(self, &["block_sha256"])? != self.block_sha256 {
            return integrity("Case block self-hash differs");
        }
        reject_sensitive(self, "Case block")
    }
}

/// Hash-only reference to an independently validated evidence artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseEvidenceRefV1 {
    pub evidence_id: String,
    pub evidence_class_id: String,
    pub artifact_type_id: String,
    pub artifact_sha256: String,
    pub producer_kind: CaseEvidenceProducerKindV1,
    pub producer_id: String,
    pub trust_floor: CaseEvidenceTrustFloorV1,
    pub trust_labels: Vec<String>,
    pub observed_at_unix_seconds: u64,
    pub created_at_unix_seconds: u64,
    pub retention_class_id: String,
    pub redacted: bool,
    pub source_case_id: Option<String>,
    pub supersedes_evidence_id: Option<String>,
    pub evidence_ref_sha256: String,
}

impl CaseEvidenceRefV1 {
    pub fn seal(mut self) -> Result<Self, WorkCaseError> {
        normalize_ids(&mut self.trust_labels, "evidence trust labels", false)?;
        self.evidence_ref_sha256 = hash_without(&self, &["evidence_ref_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), WorkCaseError> {
        if self.observed_at_unix_seconds == 0
            || self.created_at_unix_seconds < self.observed_at_unix_seconds
        {
            return invalid("Case evidence timestamps are invalid");
        }
        for (value, label) in [
            (&self.evidence_id, "Case evidence_id"),
            (&self.evidence_class_id, "Case evidence class"),
            (&self.artifact_type_id, "Case artifact type"),
            (&self.producer_id, "Case evidence producer"),
            (&self.retention_class_id, "Case evidence retention class"),
        ] {
            validate_id(value, label)?;
        }
        validate_hash(&self.artifact_sha256, "Case evidence artifact hash")?;
        validate_ids(&self.trust_labels, "Case evidence trust labels", false)?;
        if let Some(case_id) = &self.source_case_id {
            validate_id(case_id, "evidence source Case")?;
        }
        if let Some(evidence_id) = &self.supersedes_evidence_id {
            validate_id(evidence_id, "superseded evidence ID")?;
            if evidence_id == &self.evidence_id {
                return invalid("evidence cannot supersede itself");
            }
        }
        validate_hash(&self.evidence_ref_sha256, "Case evidence ref hash")?;
        if hash_without(self, &["evidence_ref_sha256"])? != self.evidence_ref_sha256 {
            return integrity("Case evidence ref self-hash differs");
        }
        reject_sensitive(self, "Case evidence ref")
    }
}

/// Immutable-by-generation Case evidence index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceIndexV1 {
    pub case_id: String,
    pub evidence_refs: Vec<CaseEvidenceRefV1>,
    pub evidence_class_counts: BTreeMap<String, u32>,
    pub index_generation: u64,
    pub terminal: bool,
    pub index_sha256: String,
}

impl EvidenceIndexV1 {
    pub fn empty(case_id: String) -> Result<Self, WorkCaseError> {
        let mut index = Self {
            case_id,
            evidence_refs: Vec::new(),
            evidence_class_counts: BTreeMap::new(),
            index_generation: 1,
            terminal: false,
            index_sha256: ZERO_HASH.to_owned(),
        };
        index.index_sha256 = hash_without(&index, &["index_sha256"])?;
        index.validate()?;
        Ok(index)
    }

    pub fn append(&self, evidence: CaseEvidenceRefV1) -> Result<Self, WorkCaseError> {
        self.validate()?;
        evidence.validate()?;
        if self.terminal {
            return Err(WorkCaseError::Terminal(
                "terminal evidence index is immutable".to_owned(),
            ));
        }
        if evidence
            .source_case_id
            .as_ref()
            .is_some_and(|case_id| case_id != &self.case_id)
        {
            return integrity("evidence source Case differs from the index");
        }
        if self.evidence_refs.iter().any(|existing| {
            existing.evidence_id == evidence.evidence_id
                || existing.artifact_sha256 == evidence.artifact_sha256
                || existing.evidence_ref_sha256 == evidence.evidence_ref_sha256
        }) {
            return Err(WorkCaseError::Replay(
                "duplicate Case evidence ID, artifact, or reference".to_owned(),
            ));
        }
        if evidence.supersedes_evidence_id.as_ref().is_some_and(|id| {
            !self
                .evidence_refs
                .iter()
                .any(|existing| &existing.evidence_id == id)
        }) {
            return integrity("superseded Case evidence is absent");
        }
        let mut next = self.clone();
        next.evidence_refs.push(evidence);
        next.evidence_refs
            .sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
        next.index_generation = next.index_generation.saturating_add(1);
        next.recount();
        next.index_sha256 = hash_without(&next, &["index_sha256"])?;
        next.validate()?;
        Ok(next)
    }

    pub fn finalize(&self) -> Result<Self, WorkCaseError> {
        self.validate()?;
        let mut next = self.clone();
        next.terminal = true;
        next.index_generation = next.index_generation.saturating_add(1);
        next.index_sha256 = hash_without(&next, &["index_sha256"])?;
        next.validate()?;
        Ok(next)
    }

    pub fn validate(&self) -> Result<(), WorkCaseError> {
        validate_id(&self.case_id, "evidence index Case")?;
        if self.index_generation == 0
            || self.evidence_refs.len() > crate::MAX_EVIDENCE
            || !self
                .evidence_refs
                .windows(2)
                .all(|pair| pair[0].evidence_id < pair[1].evidence_id)
        {
            return invalid("evidence index generation, bounds, or order is invalid");
        }
        let mut ids = BTreeSet::new();
        let mut artifacts = BTreeSet::new();
        let mut refs = BTreeSet::new();
        let mut counts = BTreeMap::new();
        for evidence in &self.evidence_refs {
            evidence.validate()?;
            if !ids.insert(&evidence.evidence_id)
                || !artifacts.insert(&evidence.artifact_sha256)
                || !refs.insert(&evidence.evidence_ref_sha256)
            {
                return integrity("evidence index contains a duplicate binding");
            }
            *counts
                .entry(evidence.evidence_class_id.clone())
                .or_insert(0_u32) += 1;
        }
        if counts != self.evidence_class_counts {
            return integrity("evidence index class counts differ");
        }
        validate_hash(&self.index_sha256, "evidence index hash")?;
        if hash_without(self, &["index_sha256"])? != self.index_sha256 {
            return integrity("evidence index self-hash differs");
        }
        reject_sensitive(self, "Case evidence index")
    }

    fn recount(&mut self) {
        self.evidence_class_counts.clear();
        for evidence in &self.evidence_refs {
            *self
                .evidence_class_counts
                .entry(evidence.evidence_class_id.clone())
                .or_insert(0) += 1;
        }
    }
}

/// Bounded Case request for exactly one existing role-bound Kernel Task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseTaskRequestV1 {
    pub schema_version: u32,
    pub case_task_id: String,
    pub case_id: String,
    pub case_contract_sha256: String,
    pub case_instance_sha256: String,
    pub task_sequence: u64,
    pub role_instance_id: String,
    pub ownership_sha256: String,
    pub work_class_id: String,
    pub responsibility_id: String,
    pub authenticated_instruction_sha256: String,
    pub goal_spec_sha256: String,
    pub role_task_admission_sha256: String,
    pub role_bound_kernel_context_sha256: String,
    pub application_pack_sha256: String,
    pub integration_id: String,
    pub required_capability_ids: Vec<String>,
    pub addressed_requirement_ids: Vec<String>,
    pub evidence_requirement_ids: Vec<String>,
    pub requested_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub evidence_ids: Vec<String>,
    pub request_sha256: String,
}

impl CaseTaskRequestV1 {
    pub fn seal_against(
        mut self,
        contract: &CaseContractV1,
        instance: &CaseInstanceV1,
    ) -> Result<Self, WorkCaseError> {
        for values in [
            &mut self.required_capability_ids,
            &mut self.addressed_requirement_ids,
            &mut self.evidence_requirement_ids,
            &mut self.evidence_ids,
        ] {
            values.sort();
        }
        self.request_sha256 = hash_without(&self, &["request_sha256"])?;
        self.validate_against(contract, instance)?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), WorkCaseError> {
        if self.schema_version != WORK_CASE_SCHEMA_VERSION
            || self.task_sequence == 0
            || self.requested_at_unix_seconds == 0
            || self.expires_at_unix_seconds <= self.requested_at_unix_seconds
            || self.expires_at_unix_seconds - self.requested_at_unix_seconds > 300
        {
            return invalid("Case Task request schema, sequence, or TTL is invalid");
        }
        for (value, label) in [
            (&self.case_task_id, "Case Task ID"),
            (&self.case_id, "Case Task case_id"),
            (&self.role_instance_id, "Case Task Role"),
            (&self.work_class_id, "Case Task work class"),
            (&self.responsibility_id, "Case Task responsibility"),
            (&self.integration_id, "Case Task integration"),
        ] {
            validate_id(value, label)?;
        }
        for (hash, label) in [
            (&self.case_contract_sha256, "Case Task contract"),
            (&self.case_instance_sha256, "Case Task instance"),
            (&self.ownership_sha256, "Case Task ownership"),
            (
                &self.authenticated_instruction_sha256,
                "Case Task instruction",
            ),
            (&self.goal_spec_sha256, "Case Task GoalSpec"),
            (&self.role_task_admission_sha256, "Case Task Role admission"),
            (
                &self.role_bound_kernel_context_sha256,
                "Case Task Role context",
            ),
            (&self.application_pack_sha256, "Case Task Application Pack"),
            (&self.request_sha256, "Case Task request hash"),
        ] {
            validate_hash(hash, label)?;
        }
        for (values, label, allow_empty) in [
            (
                &self.required_capability_ids,
                "Case Task capabilities",
                false,
            ),
            (
                &self.addressed_requirement_ids,
                "Case Task addressed requirements",
                false,
            ),
            (
                &self.evidence_requirement_ids,
                "Case Task evidence requirements",
                false,
            ),
            (&self.evidence_ids, "Case Task evidence", false),
        ] {
            validate_ids(values, label, allow_empty)?;
        }
        if hash_without(self, &["request_sha256"])? != self.request_sha256 {
            return integrity("Case Task request self-hash differs");
        }
        reject_sensitive(self, "Case Task request")
    }

    pub fn validate_against(
        &self,
        contract: &CaseContractV1,
        instance: &CaseInstanceV1,
    ) -> Result<(), WorkCaseError> {
        self.validate()?;
        instance.validate_against(contract)?;
        if instance.current_status != CaseLifecycleStatusV1::Active
            || self.case_id != contract.case_id
            || self.case_contract_sha256 != contract.contract_sha256
            || self.case_instance_sha256 != instance.instance_sha256
            || self.task_sequence != instance.latest_task_sequence.saturating_add(1)
            || instance.task_attempt_count >= contract.maximum_task_attempts
            || self.role_instance_id != contract.role_instance_id
            || self.ownership_sha256 != contract.ownership_binding.ownership_sha256
            || self.work_class_id != contract.work_class_id
            || self.responsibility_id != contract.responsibility_id
            || self.requested_at_unix_seconds < instance.last_transition_at_unix_seconds
            || self.expires_at_unix_seconds > contract.ownership_binding.expires_at_unix_seconds
            || !contract
                .allowed_application_pack_refs
                .iter()
                .any(|pack| pack.application_pack_sha256 == self.application_pack_sha256)
            || contract
                .allowed_integration_ids
                .binary_search(&self.integration_id)
                .is_err()
            || !is_subset(
                &self.required_capability_ids,
                &contract.allowed_capability_ids,
            )
            || !is_subset(
                &self.addressed_requirement_ids,
                &instance.unresolved_requirement_ids,
            )
        {
            return Err(WorkCaseError::NotAdmissible(
                "Case Task request is stale or outside the active Case".to_owned(),
            ));
        }
        let evidence_ids = contract
            .evidence_requirements
            .iter()
            .map(|item| item.evidence_requirement_id.clone())
            .collect::<Vec<_>>();
        if !is_subset(&self.evidence_requirement_ids, &evidence_ids) {
            return integrity("Case Task references an unknown evidence requirement");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseTaskAttemptOutcomeV1 {
    VerifiedGoalComplete,
    VerifiedPartial,
    Failed,
    Inconclusive,
    Unsafe,
    ClarificationRequired,
    Escalated,
    InfrastructureError,
}

/// One immutable Kernel Task result binding. It cannot close a Case by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseTaskAttemptV1 {
    pub schema_version: u32,
    pub attempt_id: String,
    pub case_id: String,
    pub case_task_request_sha256: String,
    pub task_sequence: u64,
    pub role_task_admission_sha256: String,
    pub role_bound_kernel_context_sha256: String,
    pub kernel_task_run_record_sha256: String,
    pub work_report_sha256: String,
    pub final_goal_verification_sha256: Option<String>,
    pub verified_action_result_hashes: Vec<String>,
    pub recovery_result_hashes: Vec<String>,
    pub execution_receipt_hashes: Vec<String>,
    pub outcome: CaseTaskAttemptOutcomeV1,
    pub addressed_requirement_ids: Vec<String>,
    pub satisfied_requirement_ids: Vec<String>,
    pub produced_evidence_ref_ids: Vec<String>,
    pub started_at_unix_seconds: u64,
    pub completed_at_unix_seconds: u64,
    pub evidence_ids: Vec<String>,
    pub attempt_sha256: String,
}

impl CaseTaskAttemptV1 {
    pub fn seal_against(mut self, request: &CaseTaskRequestV1) -> Result<Self, WorkCaseError> {
        for values in [
            &mut self.verified_action_result_hashes,
            &mut self.recovery_result_hashes,
            &mut self.execution_receipt_hashes,
        ] {
            values.sort();
        }
        for values in [
            &mut self.addressed_requirement_ids,
            &mut self.satisfied_requirement_ids,
            &mut self.produced_evidence_ref_ids,
            &mut self.evidence_ids,
        ] {
            values.sort();
        }
        self.attempt_sha256 = hash_without(&self, &["attempt_sha256"])?;
        self.validate_against(request)?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), WorkCaseError> {
        if self.schema_version != WORK_CASE_SCHEMA_VERSION
            || self.task_sequence == 0
            || self.started_at_unix_seconds == 0
            || self.completed_at_unix_seconds < self.started_at_unix_seconds
        {
            return invalid("Case Task attempt schema, sequence, or time is invalid");
        }
        validate_id(&self.attempt_id, "Case attempt_id")?;
        validate_id(&self.case_id, "Case attempt case_id")?;
        for (hash, label) in [
            (&self.case_task_request_sha256, "attempt request"),
            (&self.role_task_admission_sha256, "attempt Role admission"),
            (
                &self.role_bound_kernel_context_sha256,
                "attempt Role context",
            ),
            (&self.kernel_task_run_record_sha256, "attempt Kernel run"),
            (&self.work_report_sha256, "attempt WorkReport"),
            (&self.attempt_sha256, "attempt hash"),
        ] {
            validate_hash(hash, label)?;
        }
        if let Some(hash) = &self.final_goal_verification_sha256 {
            validate_hash(hash, "attempt final verification")?;
        }
        for (values, label, allow_empty) in [
            (
                &self.verified_action_result_hashes,
                "attempt verified actions",
                true,
            ),
            (
                &self.recovery_result_hashes,
                "attempt recovery results",
                true,
            ),
            (
                &self.execution_receipt_hashes,
                "attempt execution receipts",
                true,
            ),
        ] {
            validate_hashes(values, label, allow_empty)?;
        }
        for (values, label, allow_empty) in [
            (
                &self.addressed_requirement_ids,
                "attempt addressed requirements",
                false,
            ),
            (
                &self.satisfied_requirement_ids,
                "attempt satisfied requirements",
                true,
            ),
            (
                &self.produced_evidence_ref_ids,
                "attempt evidence refs",
                true,
            ),
            (&self.evidence_ids, "attempt evidence", false),
        ] {
            validate_ids(values, label, allow_empty)?;
        }
        if !is_subset(
            &self.satisfied_requirement_ids,
            &self.addressed_requirement_ids,
        ) {
            return integrity("attempt satisfies a requirement it did not address");
        }
        if self.outcome == CaseTaskAttemptOutcomeV1::VerifiedGoalComplete
            && (self.final_goal_verification_sha256.is_none()
                || self.satisfied_requirement_ids.is_empty())
        {
            return integrity("verified goal-complete attempt lacks final proof");
        }
        if matches!(
            self.outcome,
            CaseTaskAttemptOutcomeV1::Failed
                | CaseTaskAttemptOutcomeV1::Inconclusive
                | CaseTaskAttemptOutcomeV1::InfrastructureError
                | CaseTaskAttemptOutcomeV1::ClarificationRequired
                | CaseTaskAttemptOutcomeV1::Unsafe
                | CaseTaskAttemptOutcomeV1::Escalated
        ) && !self.satisfied_requirement_ids.is_empty()
        {
            return integrity("non-verified attempt claims satisfied requirements");
        }
        if hash_without(self, &["attempt_sha256"])? != self.attempt_sha256 {
            return integrity("Case Task attempt self-hash differs");
        }
        reject_sensitive(self, "Case Task attempt")
    }

    pub fn validate_against(&self, request: &CaseTaskRequestV1) -> Result<(), WorkCaseError> {
        self.validate()?;
        request.validate()?;
        if self.case_id != request.case_id
            || self.case_task_request_sha256 != request.request_sha256
            || self.task_sequence != request.task_sequence
            || self.role_task_admission_sha256 != request.role_task_admission_sha256
            || self.role_bound_kernel_context_sha256 != request.role_bound_kernel_context_sha256
            || self.addressed_requirement_ids != request.addressed_requirement_ids
        {
            return integrity("Case Task attempt differs from its exact request");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseRequirementEvaluationV1 {
    pub requirement_id: String,
    pub satisfied: bool,
    pub satisfied_count: u32,
    pub evidence_ref_ids: Vec<String>,
    pub reason_codes: Vec<String>,
    pub result_sha256: String,
}

impl CaseRequirementEvaluationV1 {
    fn seal(mut self) -> Result<Self, WorkCaseError> {
        self.evidence_ref_ids.sort();
        self.reason_codes.sort();
        self.result_sha256 = hash_without(&self, &["result_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    fn validate(&self) -> Result<(), WorkCaseError> {
        validate_id(&self.requirement_id, "evaluated requirement")?;
        validate_ids(
            &self.evidence_ref_ids,
            "requirement evaluation evidence",
            true,
        )?;
        validate_ids(&self.reason_codes, "requirement evaluation reasons", false)?;
        validate_hash(&self.result_sha256, "requirement evaluation hash")?;
        if hash_without(self, &["result_sha256"])? != self.result_sha256 {
            return integrity("requirement evaluation self-hash differs");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseClosureEvaluationOutcomeV1 {
    VerifiedComplete,
    NotReady,
    Blocked,
    Unsafe,
    EscalationRequired,
    ExplicitRefusalValid,
    EscalatedValid,
}

/// Side-effect-free closure decision over exact Case, evidence, and attempt hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseClosureEvaluationV1 {
    pub evaluation_id: String,
    pub case_id: String,
    pub contract_sha256: String,
    pub instance_sha256: String,
    pub evidence_index_sha256: String,
    pub evaluated_requirement_results: Vec<CaseRequirementEvaluationV1>,
    pub missing_requirement_ids: Vec<String>,
    pub failed_requirement_ids: Vec<String>,
    pub unresolved_block_ids: Vec<String>,
    pub unsafe_evidence_ids: Vec<String>,
    pub outcome: CaseClosureEvaluationOutcomeV1,
    pub terminal_candidate: Option<CaseTerminalOutcomeV1>,
    pub reason_codes: Vec<String>,
    pub evaluated_at_unix_seconds: u64,
    pub evaluation_sha256: String,
}

impl CaseClosureEvaluationV1 {
    pub fn validate(&self) -> Result<(), WorkCaseError> {
        if self.evaluated_at_unix_seconds == 0
            || self.evaluated_requirement_results.is_empty()
            || !self
                .evaluated_requirement_results
                .windows(2)
                .all(|pair| pair[0].requirement_id < pair[1].requirement_id)
        {
            return invalid("closure evaluation time or requirement order is invalid");
        }
        validate_id(&self.evaluation_id, "closure evaluation_id")?;
        validate_id(&self.case_id, "closure Case")?;
        for (hash, label) in [
            (&self.contract_sha256, "closure contract"),
            (&self.instance_sha256, "closure instance"),
            (&self.evidence_index_sha256, "closure evidence index"),
            (&self.evaluation_sha256, "closure evaluation hash"),
        ] {
            validate_hash(hash, label)?;
        }
        for result in &self.evaluated_requirement_results {
            result.validate()?;
        }
        for (values, label, allow_empty) in [
            (
                &self.missing_requirement_ids,
                "closure missing requirements",
                true,
            ),
            (
                &self.failed_requirement_ids,
                "closure failed requirements",
                true,
            ),
            (
                &self.unresolved_block_ids,
                "closure unresolved blocks",
                true,
            ),
            (&self.unsafe_evidence_ids, "closure unsafe evidence", true),
            (&self.reason_codes, "closure reason codes", false),
        ] {
            validate_ids(values, label, allow_empty)?;
        }
        let expected_candidate = match self.outcome {
            CaseClosureEvaluationOutcomeV1::VerifiedComplete => {
                Some(CaseTerminalOutcomeV1::VerifiedComplete)
            }
            CaseClosureEvaluationOutcomeV1::ExplicitRefusalValid => {
                Some(CaseTerminalOutcomeV1::ExplicitRefusal)
            }
            CaseClosureEvaluationOutcomeV1::EscalatedValid => {
                Some(CaseTerminalOutcomeV1::Escalated)
            }
            _ => None,
        };
        if self.terminal_candidate != expected_candidate {
            return integrity("closure outcome and terminal candidate differ");
        }
        if self.outcome == CaseClosureEvaluationOutcomeV1::VerifiedComplete
            && (!self.missing_requirement_ids.is_empty()
                || !self.failed_requirement_ids.is_empty()
                || !self.unresolved_block_ids.is_empty()
                || !self.unsafe_evidence_ids.is_empty())
        {
            return integrity("verified Case closure contains an unresolved condition");
        }
        if hash_without(self, &["evaluation_sha256"])? != self.evaluation_sha256 {
            return integrity("closure evaluation self-hash differs");
        }
        reject_sensitive(self, "Case closure evaluation")
    }
}

/// Optional terminal artifacts and integrity facts supplied to the pure evaluator.
pub struct CaseClosureContextV1<'a> {
    pub contract: &'a CaseContractV1,
    pub instance: &'a CaseInstanceV1,
    pub evidence_index: &'a EvidenceIndexV1,
    pub attempts: &'a [CaseTaskAttemptV1],
    pub unresolved_blocks: &'a [CaseBlockV1],
    pub unsafe_evidence_ids: &'a [String],
    pub refusal: Option<&'a CaseRefusalV1>,
    pub escalation: Option<&'a CaseEscalationBindingV1>,
    pub ownership_role_valid: bool,
    pub audit_integrity_valid: bool,
    pub ledger_integrity_valid: bool,
    pub evaluated_at_unix_seconds: u64,
}

/// Evaluates Case requirements without I/O or side effects.
pub fn evaluate_case_closure(
    context: CaseClosureContextV1<'_>,
) -> Result<CaseClosureEvaluationV1, WorkCaseError> {
    context.contract.validate()?;
    context.instance.validate_against(context.contract)?;
    context.evidence_index.validate()?;
    if context.evidence_index.case_id != context.contract.case_id
        || context.evidence_index.index_sha256 != context.instance.evidence_index_sha256
        || context.evaluated_at_unix_seconds < context.instance.last_transition_at_unix_seconds
    {
        return integrity("closure context contains stale Case or evidence state");
    }
    let mut seen_attempts = BTreeSet::new();
    let mut seen_kernel_runs = BTreeSet::new();
    for attempt in context.attempts {
        attempt.validate()?;
        if attempt.case_id != context.contract.case_id
            || !seen_attempts.insert(&attempt.attempt_sha256)
            || !seen_kernel_runs.insert(&attempt.kernel_task_run_record_sha256)
        {
            return Err(WorkCaseError::Replay(
                "closure context reuses an attempt or Kernel run".to_owned(),
            ));
        }
    }
    for block in context.unresolved_blocks {
        block.validate()?;
        if block.case_id != context.contract.case_id {
            return integrity("closure block belongs to another Case");
        }
    }
    let unsafe_set = context
        .unsafe_evidence_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if unsafe_set.len() != context.unsafe_evidence_ids.len() {
        return invalid("unsafe evidence IDs contain duplicates");
    }
    for id in context.unsafe_evidence_ids {
        validate_id(id, "unsafe evidence ID")?;
    }

    let mut results = BTreeMap::<String, CaseRequirementEvaluationV1>::new();
    let mut pending = context
        .contract
        .outcome_requirements
        .iter()
        .collect::<VecDeque<_>>();
    let maximum_passes = pending.len().saturating_mul(2).saturating_add(1);
    let mut passes = 0;
    while !pending.is_empty() && passes < maximum_passes {
        passes += 1;
        let requirement = pending
            .pop_front()
            .ok_or_else(|| WorkCaseError::Integrity("requirement queue changed".to_owned()))?;
        let aggregate = matches!(
            requirement.verification_kind,
            CaseVerificationKindV1::AggregateAll | CaseVerificationKindV1::AggregateAny
        );
        if aggregate
            && requirement
                .referenced_requirement_ids
                .iter()
                .any(|id| !results.contains_key(id))
        {
            pending.push_back(requirement);
            continue;
        }
        let (satisfied_count, evidence_ref_ids) = evaluate_success_requirement(
            requirement,
            context.attempts,
            context.evidence_index,
            &results,
        );
        let satisfied = satisfied_count >= requirement.minimum_satisfied_count;
        let reason = if satisfied {
            "case-requirement-satisfied"
        } else {
            "case-requirement-missing"
        };
        let result = CaseRequirementEvaluationV1 {
            requirement_id: requirement.requirement_id.clone(),
            satisfied,
            satisfied_count,
            evidence_ref_ids,
            reason_codes: vec![reason.to_owned()],
            result_sha256: ZERO_HASH.to_owned(),
        }
        .seal()?;
        results.insert(requirement.requirement_id.clone(), result);
    }
    if !pending.is_empty() || results.len() != context.contract.outcome_requirements.len() {
        return integrity("closure requirement graph could not be fully evaluated");
    }

    let evidence_requirements_satisfied = context
        .contract
        .evidence_requirements
        .iter()
        .filter(|requirement| requirement.required)
        .all(|requirement| {
            evidence_requirement_satisfied(
                requirement,
                context.evidence_index,
                context.evaluated_at_unix_seconds,
            )
        });
    let mut missing = context
        .contract
        .outcome_requirements
        .iter()
        .filter(|requirement| {
            requirement.required
                && results
                    .get(&requirement.requirement_id)
                    .is_none_or(|result| !result.satisfied)
        })
        .map(|requirement| requirement.requirement_id.clone())
        .collect::<Vec<_>>();
    if !evidence_requirements_satisfied {
        missing.extend(
            context
                .contract
                .evidence_requirements
                .iter()
                .filter(|requirement| {
                    requirement.required
                        && !evidence_requirement_satisfied(
                            requirement,
                            context.evidence_index,
                            context.evaluated_at_unix_seconds,
                        )
                })
                .map(|requirement| requirement.evidence_requirement_id.clone()),
        );
    }
    missing.sort();
    missing.dedup();
    let unresolved_block_ids = context
        .unresolved_blocks
        .iter()
        .map(|block| block.block_id.clone())
        .collect::<Vec<_>>();
    let trusted_completion_source = context.evidence_index.evidence_refs.iter().any(|evidence| {
        matches!(
            evidence.producer_kind,
            CaseEvidenceProducerKindV1::KernelTaskRun
                | CaseEvidenceProducerKindV1::FinalGoalVerification
                | CaseEvidenceProducerKindV1::SignedExternalEvidence
        ) && CaseEvidenceTrustFloorV1::Trusted.satisfied_by(evidence.trust_floor)
    });

    let (outcome, candidate, reason) = if let Some(refusal) = context.refusal {
        refusal.validate()?;
        if refusal.case_id != context.contract.case_id
            || refusal.role_instance_id != context.contract.role_instance_id
        {
            return integrity("refusal belongs to another Case or Role");
        }
        (
            CaseClosureEvaluationOutcomeV1::ExplicitRefusalValid,
            Some(CaseTerminalOutcomeV1::ExplicitRefusal),
            "authorized-explicit-refusal",
        )
    } else if let Some(escalation) = context.escalation {
        escalation.validate()?;
        if escalation.case_id != context.contract.case_id
            || escalation.role_instance_id != context.contract.role_instance_id
            || escalation.case_contract_sha256 != context.contract.contract_sha256
            || escalation.case_instance_sha256 != context.instance.instance_sha256
            || escalation
                .originating_task_attempt_sha256
                .as_ref()
                .is_some_and(|hash| {
                    context
                        .attempts
                        .iter()
                        .all(|attempt| &attempt.attempt_sha256 != hash)
                })
        {
            return integrity("escalation differs from the exact Case, Role, or Task attempt");
        }
        (
            CaseClosureEvaluationOutcomeV1::EscalatedValid,
            Some(CaseTerminalOutcomeV1::Escalated),
            "case-escalation-bound",
        )
    } else if !context.unsafe_evidence_ids.is_empty() {
        (
            CaseClosureEvaluationOutcomeV1::Unsafe,
            None,
            "unsafe-evidence-requires-escalation",
        )
    } else if context.instance.current_status == CaseLifecycleStatusV1::EscalationPending
        || !context.ownership_role_valid
    {
        (
            CaseClosureEvaluationOutcomeV1::EscalationRequired,
            None,
            "Case-requires-escalation",
        )
    } else if !unresolved_block_ids.is_empty() || context.instance.active_block_sha256.is_some() {
        (
            CaseClosureEvaluationOutcomeV1::Blocked,
            None,
            "Case-has-active-block",
        )
    } else if missing.is_empty()
        && trusted_completion_source
        && context.audit_integrity_valid
        && context.ledger_integrity_valid
        && context.ownership_role_valid
    {
        (
            CaseClosureEvaluationOutcomeV1::VerifiedComplete,
            Some(CaseTerminalOutcomeV1::VerifiedComplete),
            "all-required-outcomes-and-evidence-verified",
        )
    } else {
        (
            CaseClosureEvaluationOutcomeV1::NotReady,
            None,
            "Case-requirements-not-ready",
        )
    };
    let mut evaluated = results.into_values().collect::<Vec<_>>();
    evaluated.sort_by(|left, right| left.requirement_id.cmp(&right.requirement_id));
    let mut evaluation = CaseClosureEvaluationV1 {
        evaluation_id: format!(
            "closure:{}:{}",
            context.contract.case_id, context.instance.lifecycle_generation
        ),
        case_id: context.contract.case_id.clone(),
        contract_sha256: context.contract.contract_sha256.clone(),
        instance_sha256: context.instance.instance_sha256.clone(),
        evidence_index_sha256: context.evidence_index.index_sha256.clone(),
        evaluated_requirement_results: evaluated,
        missing_requirement_ids: missing,
        failed_requirement_ids: Vec::new(),
        unresolved_block_ids,
        unsafe_evidence_ids: context.unsafe_evidence_ids.to_vec(),
        outcome,
        terminal_candidate: candidate,
        reason_codes: vec![reason.to_owned()],
        evaluated_at_unix_seconds: context.evaluated_at_unix_seconds,
        evaluation_sha256: ZERO_HASH.to_owned(),
    };
    evaluation.unsafe_evidence_ids.sort();
    evaluation.evaluation_sha256 = hash_without(&evaluation, &["evaluation_sha256"])?;
    evaluation.validate()?;
    Ok(evaluation)
}

fn evaluate_success_requirement(
    requirement: &CaseSuccessRequirementV1,
    attempts: &[CaseTaskAttemptV1],
    index: &EvidenceIndexV1,
    prior: &BTreeMap<String, CaseRequirementEvaluationV1>,
) -> (u32, Vec<String>) {
    match requirement.verification_kind {
        CaseVerificationKindV1::KernelGoalComplete => {
            let matching = attempts
                .iter()
                .filter(|attempt| {
                    attempt.outcome == CaseTaskAttemptOutcomeV1::VerifiedGoalComplete
                        && attempt
                            .satisfied_requirement_ids
                            .contains(&requirement.requirement_id)
                        && attempt.final_goal_verification_sha256.is_some()
                })
                .count() as u32;
            (matching, Vec::new())
        }
        CaseVerificationKindV1::KernelActionPassed => {
            let matching = attempts
                .iter()
                .filter(|attempt| {
                    matches!(
                        attempt.outcome,
                        CaseTaskAttemptOutcomeV1::VerifiedGoalComplete
                            | CaseTaskAttemptOutcomeV1::VerifiedPartial
                    ) && attempt
                        .satisfied_requirement_ids
                        .contains(&requirement.requirement_id)
                        && !attempt.verified_action_result_hashes.is_empty()
                })
                .count() as u32;
            (matching, Vec::new())
        }
        CaseVerificationKindV1::TrustedStateCriterion
        | CaseVerificationKindV1::TrustedEvidencePresent => {
            let evidence = index
                .evidence_refs
                .iter()
                .filter(|item| {
                    requirement
                        .trusted_evidence_class_ids
                        .contains(&item.evidence_class_id)
                        && CaseEvidenceTrustFloorV1::Trusted.satisfied_by(item.trust_floor)
                })
                .map(|item| item.evidence_id.clone())
                .collect::<Vec<_>>();
            (evidence.len() as u32, evidence)
        }
        CaseVerificationKindV1::AggregateAll | CaseVerificationKindV1::AggregateAny => {
            let count = requirement
                .referenced_requirement_ids
                .iter()
                .filter(|id| prior.get(*id).is_some_and(|result| result.satisfied))
                .count() as u32;
            (count, Vec::new())
        }
    }
}

fn evidence_requirement_satisfied(
    requirement: &CaseEvidenceRequirementV1,
    index: &EvidenceIndexV1,
    now: u64,
) -> bool {
    index
        .evidence_refs
        .iter()
        .filter(|evidence| {
            evidence.evidence_class_id == requirement.evidence_class_id
                && requirement
                    .accepted_producer_kinds
                    .contains(&evidence.producer_kind)
                && requirement
                    .required_artifact_type_ids
                    .contains(&evidence.artifact_type_id)
                && requirement
                    .required_trust_floor
                    .satisfied_by(evidence.trust_floor)
                && (!requirement.redaction_required || evidence.redacted)
                && requirement.maximum_staleness_seconds.is_none_or(|maximum| {
                    now <= evidence.observed_at_unix_seconds.saturating_add(maximum)
                })
        })
        .count()
        >= requirement.minimum_count as usize
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseRefusalCategoryV1 {
    UnsupportedWork,
    InvalidRequest,
    ProhibitedWork,
    DuplicateResolvedElsewhere,
    ExternallyCancelled,
}

/// Authorized explicit refusal. Runtime failure and budget exhaustion are not refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseRefusalV1 {
    pub refusal_id: String,
    pub case_id: String,
    pub role_instance_id: String,
    pub authority_class: String,
    pub refusal_reason_codes: Vec<String>,
    pub refusal_category: CaseRefusalCategoryV1,
    pub authorized_actor_id: String,
    pub authorization_artifact_sha256: String,
    pub raised_at_unix_seconds: u64,
    pub evidence_ids: Vec<String>,
    pub refusal_sha256: String,
}

impl CaseRefusalV1 {
    pub fn seal(mut self) -> Result<Self, WorkCaseError> {
        self.refusal_reason_codes.sort();
        self.evidence_ids.sort();
        self.refusal_sha256 = hash_without(&self, &["refusal_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), WorkCaseError> {
        if self.raised_at_unix_seconds == 0 {
            return invalid("Case refusal time is invalid");
        }
        for (value, label) in [
            (&self.refusal_id, "refusal_id"),
            (&self.case_id, "refusal Case"),
            (&self.role_instance_id, "refusal Role"),
            (&self.authority_class, "refusal authority class"),
            (&self.authorized_actor_id, "refusal actor"),
        ] {
            validate_id(value, label)?;
        }
        validate_ids(&self.refusal_reason_codes, "refusal reason codes", false)?;
        if self.refusal_reason_codes.iter().any(|reason| {
            matches!(
                reason.as_str(),
                "budget_exhausted" | "unsafe" | "authority_exceeded"
            )
        }) {
            return invalid("budget or unsafe escalation cannot be hidden as refusal");
        }
        validate_hash(
            &self.authorization_artifact_sha256,
            "refusal authorization artifact",
        )?;
        validate_ids(&self.evidence_ids, "refusal evidence", false)?;
        validate_hash(&self.refusal_sha256, "refusal hash")?;
        if hash_without(self, &["refusal_sha256"])? != self.refusal_sha256 {
            return integrity("Case refusal self-hash differs");
        }
        reject_sensitive(self, "Case refusal")
    }
}

/// Case binding to an existing verified Recovery escalation request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseEscalationBindingV1 {
    pub binding_id: String,
    pub case_id: String,
    pub role_instance_id: String,
    pub case_contract_sha256: String,
    pub case_instance_sha256: String,
    pub originating_task_attempt_sha256: Option<String>,
    pub escalation_request_sha256: String,
    pub escalation_severity: EscalationSeverityV1,
    pub reason_codes: Vec<String>,
    pub routing_class_id: String,
    pub required_evidence_ids: Vec<String>,
    pub bound_at_unix_seconds: u64,
    pub evidence_ids: Vec<String>,
    pub binding_sha256: String,
}

impl CaseEscalationBindingV1 {
    pub fn seal_against(mut self, request: &EscalationRequestV1) -> Result<Self, WorkCaseError> {
        request
            .validate()
            .map_err(|error| WorkCaseError::Integrity(error.to_string()))?;
        for values in [
            &mut self.reason_codes,
            &mut self.required_evidence_ids,
            &mut self.evidence_ids,
        ] {
            values.sort();
        }
        if self.escalation_request_sha256 != request.escalation_sha256
            || self.escalation_severity != request.severity
        {
            return integrity("Case escalation differs from Recovery escalation");
        }
        self.binding_sha256 = hash_without(&self, &["binding_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), WorkCaseError> {
        if self.bound_at_unix_seconds == 0 {
            return invalid("Case escalation time is invalid");
        }
        for (value, label) in [
            (&self.binding_id, "escalation binding_id"),
            (&self.case_id, "escalation Case"),
            (&self.role_instance_id, "escalation Role"),
            (&self.routing_class_id, "escalation routing class"),
        ] {
            validate_id(value, label)?;
        }
        for (hash, label) in [
            (&self.case_contract_sha256, "escalation Case Contract"),
            (&self.case_instance_sha256, "escalation Case Instance"),
            (
                &self.escalation_request_sha256,
                "Recovery escalation request",
            ),
            (&self.binding_sha256, "Case escalation binding"),
        ] {
            validate_hash(hash, label)?;
        }
        if let Some(hash) = &self.originating_task_attempt_sha256 {
            validate_hash(hash, "escalation originating attempt")?;
        }
        validate_ids(&self.reason_codes, "escalation reasons", false)?;
        validate_ids(
            &self.required_evidence_ids,
            "escalation required evidence",
            false,
        )?;
        validate_ids(&self.evidence_ids, "escalation evidence", false)?;
        if hash_without(self, &["binding_sha256"])? != self.binding_sha256 {
            return integrity("Case escalation binding self-hash differs");
        }
        reject_sensitive(self, "Case escalation binding")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseSlaStatusSnapshotV1 {
    NotEvaluated,
    WithinDeadline,
    Breached,
    Paused,
}

/// Immutable terminal Case record. It cannot authorize another Task or reopen a Case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseTerminalRecordV1 {
    pub schema_version: u32,
    pub terminal_record_id: String,
    pub case_id: String,
    pub case_contract_sha256: String,
    pub final_case_instance_sha256: String,
    pub ownership_sha256: String,
    pub terminal_outcome: CaseTerminalOutcomeV1,
    pub closure_evaluation_sha256: String,
    pub refusal_sha256: Option<String>,
    pub escalation_binding_sha256: Option<String>,
    pub evidence_index_sha256: String,
    pub task_attempt_hashes: Vec<String>,
    pub kernel_task_run_record_hashes: Vec<String>,
    pub work_report_hashes: Vec<String>,
    pub verified_result_hashes: Vec<String>,
    pub recovery_result_hashes: Vec<String>,
    pub opened_at_unix_seconds: u64,
    pub terminal_at_unix_seconds: u64,
    pub duration_seconds: u64,
    pub sla_binding_sha256: String,
    pub sla_status_snapshot: CaseSlaStatusSnapshotV1,
    pub reporting_obligation_ids: Vec<String>,
    pub audit_chain_head: String,
    pub case_ledger_chain_head: String,
    pub evidence_ids: Vec<String>,
    pub terminal_record_sha256: String,
}

impl CaseTerminalRecordV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn seal_against(
        mut self,
        contract: &CaseContractV1,
        instance: &CaseInstanceV1,
        evaluation: &CaseClosureEvaluationV1,
        evidence_index: &EvidenceIndexV1,
        attempts: &[CaseTaskAttemptV1],
        refusal: Option<&CaseRefusalV1>,
        escalation: Option<&CaseEscalationBindingV1>,
    ) -> Result<Self, WorkCaseError> {
        for values in [
            &mut self.task_attempt_hashes,
            &mut self.kernel_task_run_record_hashes,
            &mut self.work_report_hashes,
            &mut self.verified_result_hashes,
            &mut self.recovery_result_hashes,
        ] {
            values.sort();
        }
        for values in [&mut self.reporting_obligation_ids, &mut self.evidence_ids] {
            values.sort();
        }
        self.terminal_record_sha256 = hash_without(&self, &["terminal_record_sha256"])?;
        self.validate_against(
            contract,
            instance,
            evaluation,
            evidence_index,
            attempts,
            refusal,
            escalation,
        )?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), WorkCaseError> {
        if self.schema_version != WORK_CASE_SCHEMA_VERSION
            || self.opened_at_unix_seconds == 0
            || self.terminal_at_unix_seconds < self.opened_at_unix_seconds
            || self.duration_seconds
                != self
                    .terminal_at_unix_seconds
                    .saturating_sub(self.opened_at_unix_seconds)
        {
            return invalid("Case terminal record time or duration is invalid");
        }
        validate_id(&self.terminal_record_id, "terminal record_id")?;
        validate_id(&self.case_id, "terminal Case")?;
        for (hash, label) in [
            (&self.case_contract_sha256, "terminal Case Contract"),
            (&self.final_case_instance_sha256, "terminal Case Instance"),
            (&self.ownership_sha256, "terminal ownership"),
            (
                &self.closure_evaluation_sha256,
                "terminal closure evaluation",
            ),
            (&self.evidence_index_sha256, "terminal evidence index"),
            (&self.sla_binding_sha256, "terminal SLA binding"),
            (&self.audit_chain_head, "terminal audit head"),
            (&self.case_ledger_chain_head, "terminal Case ledger head"),
            (&self.terminal_record_sha256, "terminal record hash"),
        ] {
            validate_hash(hash, label)?;
        }
        if let Some(hash) = &self.refusal_sha256 {
            validate_hash(hash, "terminal refusal")?;
        }
        if let Some(hash) = &self.escalation_binding_sha256 {
            validate_hash(hash, "terminal escalation")?;
        }
        for (values, label, allow_empty) in [
            (&self.task_attempt_hashes, "terminal attempts", true),
            (
                &self.kernel_task_run_record_hashes,
                "terminal Kernel runs",
                true,
            ),
            (&self.work_report_hashes, "terminal WorkReports", true),
            (
                &self.verified_result_hashes,
                "terminal verified results",
                true,
            ),
            (
                &self.recovery_result_hashes,
                "terminal recovery results",
                true,
            ),
        ] {
            validate_hashes(values, label, allow_empty)?;
        }
        validate_ids(
            &self.reporting_obligation_ids,
            "terminal reporting obligations",
            true,
        )?;
        validate_ids(&self.evidence_ids, "terminal evidence", false)?;
        let proof_shape = match self.terminal_outcome {
            CaseTerminalOutcomeV1::VerifiedComplete => {
                self.refusal_sha256.is_none() && self.escalation_binding_sha256.is_none()
            }
            CaseTerminalOutcomeV1::ExplicitRefusal => {
                self.refusal_sha256.is_some() && self.escalation_binding_sha256.is_none()
            }
            CaseTerminalOutcomeV1::Escalated => {
                self.refusal_sha256.is_none() && self.escalation_binding_sha256.is_some()
            }
        };
        if !proof_shape {
            return integrity("terminal outcome evidence shapes are mixed");
        }
        if hash_without(self, &["terminal_record_sha256"])? != self.terminal_record_sha256 {
            return integrity("Case terminal record self-hash differs");
        }
        reject_sensitive(self, "Case terminal record")
    }

    #[allow(clippy::too_many_arguments)]
    pub fn validate_against(
        &self,
        contract: &CaseContractV1,
        instance: &CaseInstanceV1,
        evaluation: &CaseClosureEvaluationV1,
        evidence_index: &EvidenceIndexV1,
        attempts: &[CaseTaskAttemptV1],
        refusal: Option<&CaseRefusalV1>,
        escalation: Option<&CaseEscalationBindingV1>,
    ) -> Result<(), WorkCaseError> {
        self.validate()?;
        contract.validate()?;
        instance.validate_against(contract)?;
        evaluation.validate()?;
        evidence_index.validate()?;
        if instance.current_status != CaseLifecycleStatusV1::Terminal
            || instance.terminal_outcome != Some(self.terminal_outcome)
            || self.case_id != contract.case_id
            || self.case_contract_sha256 != contract.contract_sha256
            || self.final_case_instance_sha256 != instance.instance_sha256
            || self.ownership_sha256 != contract.ownership_binding.ownership_sha256
            || self.closure_evaluation_sha256 != evaluation.evaluation_sha256
            || evaluation.terminal_candidate != Some(self.terminal_outcome)
            || self.evidence_index_sha256 != evidence_index.index_sha256
            || !evidence_index.terminal
            || self.sla_binding_sha256 != contract.sla_binding.binding_sha256
            || self.reporting_obligation_ids != contract.reporting_obligation_ids
        {
            return integrity("terminal record differs from final Case artifacts");
        }
        let attempt_hashes = attempts
            .iter()
            .map(|attempt| attempt.attempt_sha256.clone())
            .collect::<BTreeSet<_>>();
        let kernel_hashes = attempts
            .iter()
            .map(|attempt| attempt.kernel_task_run_record_sha256.clone())
            .collect::<BTreeSet<_>>();
        if self
            .task_attempt_hashes
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            != attempt_hashes
            || self
                .kernel_task_run_record_hashes
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                != kernel_hashes
        {
            return integrity("terminal Task or Kernel run inventory differs");
        }
        match self.terminal_outcome {
            CaseTerminalOutcomeV1::VerifiedComplete => {
                if evaluation.outcome != CaseClosureEvaluationOutcomeV1::VerifiedComplete {
                    return integrity("verified terminal record lacks verified closure");
                }
            }
            CaseTerminalOutcomeV1::ExplicitRefusal => {
                let refusal = refusal.ok_or_else(|| {
                    WorkCaseError::Integrity("terminal refusal artifact is absent".to_owned())
                })?;
                refusal.validate()?;
                if self.refusal_sha256.as_ref() != Some(&refusal.refusal_sha256) {
                    return integrity("terminal refusal hash differs");
                }
            }
            CaseTerminalOutcomeV1::Escalated => {
                let escalation = escalation.ok_or_else(|| {
                    WorkCaseError::Integrity("terminal escalation artifact is absent".to_owned())
                })?;
                escalation.validate()?;
                if self.escalation_binding_sha256.as_ref() != Some(&escalation.binding_sha256) {
                    return integrity("terminal escalation hash differs");
                }
            }
        }
        Ok(())
    }
}

/// Transport-independent deterministic replay summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedCaseReplayReportV1 {
    pub schema_version: u32,
    pub build_id: String,
    pub work_item_sha256: String,
    pub case_contract_sha256: String,
    pub role_instance_id: String,
    pub ownership_sha256: String,
    pub task_outcomes: Vec<CaseTaskAttemptOutcomeV1>,
    pub satisfied_requirement_ids: Vec<String>,
    pub evidence_class_ids: Vec<String>,
    pub terminal_outcome: Option<CaseTerminalOutcomeV1>,
    pub work_report_semantic_hashes: Vec<String>,
    pub report_sha256: String,
}

impl NormalizedCaseReplayReportV1 {
    pub fn build(
        contract: &CaseContractV1,
        instance: &CaseInstanceV1,
        evidence: &EvidenceIndexV1,
        attempts: &[CaseTaskAttemptV1],
    ) -> Result<Self, WorkCaseError> {
        contract.validate()?;
        instance.validate_against(contract)?;
        evidence.validate()?;
        let mut evidence_classes = evidence
            .evidence_class_counts
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        evidence_classes.sort();
        let mut reports = attempts
            .iter()
            .map(|attempt| attempt.work_report_sha256.clone())
            .collect::<Vec<_>>();
        reports.sort();
        let mut report = Self {
            schema_version: WORK_CASE_SCHEMA_VERSION,
            build_id: WORK_CASE_BUILD_ID.to_owned(),
            work_item_sha256: contract.source_work_item_sha256.clone(),
            case_contract_sha256: contract.contract_sha256.clone(),
            role_instance_id: contract.role_instance_id.clone(),
            ownership_sha256: contract.ownership_binding.ownership_sha256.clone(),
            task_outcomes: attempts.iter().map(|attempt| attempt.outcome).collect(),
            satisfied_requirement_ids: instance.satisfied_requirement_ids.clone(),
            evidence_class_ids: evidence_classes,
            terminal_outcome: instance.terminal_outcome,
            work_report_semantic_hashes: reports,
            report_sha256: ZERO_HASH.to_owned(),
        };
        report.report_sha256 = hash_without(&report, &["report_sha256"])?;
        Ok(report)
    }
}
