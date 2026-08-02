use crate::contract::{
    AcceptedWorkClassRefV1, EmergencyOverridePolicyV1, OutsideWindowBehaviorV1, RoleContractV1,
    WeeklyWindowV1,
};
use crate::governance::{
    verify_role_contract_approval, verify_role_delegation, RoleContractApprovalV1,
    RoleDelegationGrantV1,
};
use crate::strict::hash_without;
use crate::{
    canonicalize_ids, integrity, invalid, min_risk, validate_evidence, validate_hash, validate_id,
    validate_ids, RoleContractError, ROLE_CONTRACT_SCHEMA_VERSION, ZERO_HASH,
};
use d2i_cognitive_ir::CognitiveRiskClass;
use d2i_cognitive_recovery::{
    AlternateCapabilityGroupV1, RecoveryFailureClassV1, RecoveryPolicyProfileV1,
    RECOVERY_SCHEMA_VERSION,
};
use d2i_policy_admission::{
    AuthorityScopeConstraintsV1, DelegatedAuthorityContextV1, TrustedPolicySnapshotV1,
    POLICY_ADMISSION_SCHEMA_VERSION,
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Persistent Role Instance lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleInstanceStatusV1 {
    Provisioned,
    Active,
    Suspended,
    Revoked,
    Expired,
}

/// Persistent runtime identity for one approved and delegated role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleInstanceV1 {
    pub schema_version: u32,
    pub role_instance_id: String,
    pub role_contract_id: String,
    pub role_version: String,
    pub contract_sha256: String,
    pub approval_sha256: String,
    pub delegation_sha256: String,
    pub organization_id: String,
    pub current_status: RoleInstanceStatusV1,
    pub instance_generation: u64,
    pub activated_at_unix_seconds: Option<u64>,
    pub suspended_at_unix_seconds: Option<u64>,
    pub expires_at_unix_seconds: u64,
    pub policy_set_sha256: String,
    pub authority_projection_template_sha256: String,
    pub recovery_profile_template_sha256: String,
    pub application_pack_ids: Vec<String>,
    pub integration_ids: Vec<String>,
    pub capability_ids: Vec<String>,
    pub ledger_id: String,
    pub ledger_chain_head: String,
    pub evidence_ids: Vec<String>,
    pub instance_sha256: String,
}

impl RoleInstanceV1 {
    /// Provisions an inactive Role Instance from one exact signed delegation.
    #[allow(clippy::too_many_arguments)]
    pub fn provision(
        role_instance_id: String,
        contract: &RoleContractV1,
        approval: &RoleContractApprovalV1,
        delegation: &RoleDelegationGrantV1,
        ledger_id: String,
        authority_projection_template_sha256: String,
        recovery_profile_template_sha256: String,
        evidence_ids: Vec<String>,
    ) -> Result<Self, RoleContractError> {
        let mut instance = Self {
            schema_version: ROLE_CONTRACT_SCHEMA_VERSION,
            role_instance_id,
            role_contract_id: contract.role_contract_id.clone(),
            role_version: contract.role_version.clone(),
            contract_sha256: contract.contract_sha256.clone(),
            approval_sha256: approval.approval_sha256.clone(),
            delegation_sha256: delegation.delegation_sha256.clone(),
            organization_id: contract.organization_scope.organization_id.clone(),
            current_status: RoleInstanceStatusV1::Provisioned,
            instance_generation: 1,
            activated_at_unix_seconds: None,
            suspended_at_unix_seconds: None,
            expires_at_unix_seconds: delegation.expires_at_unix_seconds,
            policy_set_sha256: contract.policy_set_sha256.clone(),
            authority_projection_template_sha256,
            recovery_profile_template_sha256,
            application_pack_ids: delegation.delegated_application_pack_ids.clone(),
            integration_ids: delegation.delegated_integration_ids.clone(),
            capability_ids: delegation.delegated_capability_ids.clone(),
            ledger_id,
            ledger_chain_head: ZERO_HASH.to_owned(),
            evidence_ids,
            instance_sha256: ZERO_HASH.to_owned(),
        };
        instance.normalize_and_seal()?;
        instance.validate_against(contract, approval, delegation)?;
        Ok(instance)
    }

    /// Applies one legal lifecycle transition without performing I/O.
    pub fn transition(
        &self,
        next: RoleInstanceStatusV1,
        at_unix_seconds: u64,
    ) -> Result<Self, RoleContractError> {
        self.validate_shape()?;
        if (at_unix_seconds == 0 || at_unix_seconds >= self.expires_at_unix_seconds)
            && next != RoleInstanceStatusV1::Expired
        {
            return invalid("Role transition time is expired or invalid");
        }
        let legal = matches!(
            (self.current_status, next),
            (
                RoleInstanceStatusV1::Provisioned,
                RoleInstanceStatusV1::Active
            ) | (
                RoleInstanceStatusV1::Active,
                RoleInstanceStatusV1::Suspended
            ) | (
                RoleInstanceStatusV1::Suspended,
                RoleInstanceStatusV1::Active
            ) | (
                RoleInstanceStatusV1::Provisioned,
                RoleInstanceStatusV1::Revoked
            ) | (RoleInstanceStatusV1::Active, RoleInstanceStatusV1::Revoked)
                | (
                    RoleInstanceStatusV1::Suspended,
                    RoleInstanceStatusV1::Revoked
                )
                | (
                    RoleInstanceStatusV1::Provisioned,
                    RoleInstanceStatusV1::Expired
                )
                | (RoleInstanceStatusV1::Active, RoleInstanceStatusV1::Expired)
                | (
                    RoleInstanceStatusV1::Suspended,
                    RoleInstanceStatusV1::Expired
                )
        );
        if !legal {
            return invalid("Role Instance lifecycle transition is not allowed");
        }
        let mut next_instance = self.clone();
        next_instance.current_status = next;
        match next {
            RoleInstanceStatusV1::Active => {
                next_instance.activated_at_unix_seconds = Some(at_unix_seconds);
                next_instance.suspended_at_unix_seconds = None;
            }
            RoleInstanceStatusV1::Suspended => {
                next_instance.suspended_at_unix_seconds = Some(at_unix_seconds);
            }
            RoleInstanceStatusV1::Revoked | RoleInstanceStatusV1::Expired => {
                next_instance.suspended_at_unix_seconds = None;
            }
            RoleInstanceStatusV1::Provisioned => {}
        }
        next_instance.instance_sha256 = hash_without(&next_instance, &["instance_sha256"])?;
        next_instance.validate_shape()?;
        Ok(next_instance)
    }

    /// Returns a copy rebound to the verified ledger head.
    pub fn bind_ledger_head(&self, chain_head: String) -> Result<Self, RoleContractError> {
        validate_hash(&chain_head, "Role ledger chain head")?;
        let mut rebound = self.clone();
        rebound.ledger_chain_head = chain_head;
        rebound.instance_sha256 = hash_without(&rebound, &["instance_sha256"])?;
        rebound.validate_shape()?;
        Ok(rebound)
    }

    /// Provisions the next immutable contract generation without reviving a terminal instance.
    #[allow(clippy::too_many_arguments)]
    pub fn upgrade(
        &self,
        contract: &RoleContractV1,
        approval: &RoleContractApprovalV1,
        delegation: &RoleDelegationGrantV1,
        authority_projection_template_sha256: String,
        recovery_profile_template_sha256: String,
        evidence_ids: Vec<String>,
    ) -> Result<Self, RoleContractError> {
        self.validate_shape()?;
        if matches!(
            self.current_status,
            RoleInstanceStatusV1::Revoked | RoleInstanceStatusV1::Expired
        ) || contract.role_contract_id != self.role_contract_id
            || contract.role_version == self.role_version
            || contract.contract_sha256 == self.contract_sha256
            || delegation.role_instance_id != self.role_instance_id
        {
            return invalid("Role upgrade is terminal, same-version, or changes identity");
        }
        let mut upgraded = Self::provision(
            self.role_instance_id.clone(),
            contract,
            approval,
            delegation,
            self.ledger_id.clone(),
            authority_projection_template_sha256,
            recovery_profile_template_sha256,
            evidence_ids,
        )?;
        upgraded.instance_generation = self.instance_generation.saturating_add(1);
        upgraded.ledger_chain_head = self.ledger_chain_head.clone();
        upgraded.normalize_and_seal()?;
        upgraded.validate_against(contract, approval, delegation)?;
        Ok(upgraded)
    }

    /// Validates immutable contract, approval, delegation, and projected set bindings.
    pub fn validate_against(
        &self,
        contract: &RoleContractV1,
        approval: &RoleContractApprovalV1,
        delegation: &RoleDelegationGrantV1,
    ) -> Result<(), RoleContractError> {
        self.validate_shape()?;
        if self.role_instance_id != delegation.role_instance_id
            || self.role_contract_id != contract.role_contract_id
            || self.role_version != contract.role_version
            || self.contract_sha256 != contract.contract_sha256
            || self.approval_sha256 != approval.approval_sha256
            || self.delegation_sha256 != delegation.delegation_sha256
            || self.organization_id != contract.organization_scope.organization_id
            || self.expires_at_unix_seconds != delegation.expires_at_unix_seconds
            || self.policy_set_sha256 != contract.policy_set_sha256
            || self.application_pack_ids != delegation.delegated_application_pack_ids
            || self.integration_ids != delegation.delegated_integration_ids
            || self.capability_ids != delegation.delegated_capability_ids
        {
            return integrity("Role Instance differs from its approved delegation");
        }
        Ok(())
    }

    /// Validates the standalone Role Instance contract and self-hash.
    pub fn validate_shape(&self) -> Result<(), RoleContractError> {
        if self.schema_version != ROLE_CONTRACT_SCHEMA_VERSION
            || self.instance_generation == 0
            || self.expires_at_unix_seconds == 0
        {
            return invalid("Role Instance schema, generation, or expiry is invalid");
        }
        for (value, label) in [
            (&self.role_instance_id, "role_instance_id"),
            (&self.role_contract_id, "instance role_contract_id"),
            (&self.role_version, "instance role_version"),
            (&self.organization_id, "instance organization_id"),
            (&self.ledger_id, "instance ledger_id"),
        ] {
            validate_id(value, label)?;
        }
        for (hash, label) in [
            (&self.contract_sha256, "instance contract_sha256"),
            (&self.approval_sha256, "instance approval_sha256"),
            (&self.delegation_sha256, "instance delegation_sha256"),
            (&self.policy_set_sha256, "instance policy_set_sha256"),
            (
                &self.authority_projection_template_sha256,
                "authority projection template hash",
            ),
            (
                &self.recovery_profile_template_sha256,
                "recovery profile template hash",
            ),
            (&self.ledger_chain_head, "instance ledger_chain_head"),
            (&self.instance_sha256, "instance_sha256"),
        ] {
            validate_hash(hash, label)?;
        }
        validate_ids(
            &self.application_pack_ids,
            "instance application packs",
            false,
        )?;
        validate_ids(&self.integration_ids, "instance integrations", false)?;
        validate_ids(&self.capability_ids, "instance capabilities", false)?;
        validate_evidence(&self.evidence_ids, "instance evidence IDs")?;
        match self.current_status {
            RoleInstanceStatusV1::Provisioned => {
                if self.activated_at_unix_seconds.is_some()
                    || self.suspended_at_unix_seconds.is_some()
                {
                    return invalid("provisioned Role contains activation timestamps");
                }
            }
            RoleInstanceStatusV1::Active => {
                if self.activated_at_unix_seconds.is_none()
                    || self.suspended_at_unix_seconds.is_some()
                {
                    return invalid("active Role timestamp shape is invalid");
                }
            }
            RoleInstanceStatusV1::Suspended => {
                if self.activated_at_unix_seconds.is_none()
                    || self.suspended_at_unix_seconds.is_none()
                {
                    return invalid("suspended Role timestamp shape is invalid");
                }
            }
            RoleInstanceStatusV1::Revoked | RoleInstanceStatusV1::Expired => {}
        }
        if hash_without(self, &["instance_sha256"])? != self.instance_sha256 {
            return integrity("instance_sha256 differs from canonical Role Instance");
        }
        Ok(())
    }

    fn normalize_and_seal(&mut self) -> Result<(), RoleContractError> {
        canonicalize_ids(
            &mut self.application_pack_ids,
            "instance application packs",
            false,
        )?;
        canonicalize_ids(&mut self.integration_ids, "instance integrations", false)?;
        canonicalize_ids(&mut self.capability_ids, "instance capabilities", false)?;
        canonicalize_ids(&mut self.evidence_ids, "instance evidence IDs", true)?;
        self.instance_sha256 = hash_without(self, &["instance_sha256"])?;
        self.validate_shape()
    }
}

/// Trusted caller-supplied local time projection; this is not a Scheduler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleOperationalTimeContextV1 {
    pub schema_version: u32,
    pub calendar_sha256: String,
    pub timezone_id: String,
    pub local_date: String,
    pub weekday: u8,
    pub local_minute_of_day: u16,
    pub utc_offset_minutes: i16,
    pub blackout_date_ids: Vec<String>,
    pub emergency_override_sha256: Option<String>,
    pub observed_at_unix_seconds: u64,
    pub evidence_ids: Vec<String>,
    pub context_sha256: String,
}

impl RoleOperationalTimeContextV1 {
    /// Canonically seals a trusted time projection.
    pub fn seal(mut self) -> Result<Self, RoleContractError> {
        canonicalize_ids(&mut self.blackout_date_ids, "time blackout date IDs", true)?;
        canonicalize_ids(&mut self.evidence_ids, "time evidence IDs", false)?;
        self.context_sha256 = hash_without(&self, &["context_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    /// Validates bounded local-time facts and the self-hash.
    pub fn validate(&self) -> Result<(), RoleContractError> {
        if self.schema_version != ROLE_CONTRACT_SCHEMA_VERSION
            || self.weekday > 6
            || self.local_minute_of_day >= 1_440
            || !(-840..=840).contains(&self.utc_offset_minutes)
            || self.observed_at_unix_seconds == 0
        {
            return invalid("operational time bounds are invalid");
        }
        validate_hash(&self.calendar_sha256, "time calendar_sha256")?;
        validate_id(&self.timezone_id, "time timezone_id")?;
        validate_local_date(&self.local_date)?;
        validate_ids(&self.blackout_date_ids, "time blackout date IDs", true)?;
        validate_evidence(&self.evidence_ids, "time evidence IDs")?;
        if let Some(override_hash) = &self.emergency_override_sha256 {
            validate_hash(override_hash, "emergency override hash")?;
        }
        validate_hash(&self.context_sha256, "time context_sha256")?;
        if hash_without(self, &["context_sha256"])? != self.context_sha256 {
            return integrity("operational time context hash differs");
        }
        Ok(())
    }
}

/// Core-owned, hash-only projection of an authenticated Kernel task request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleTaskAdmissionRequestV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub role_instance_sha256: String,
    pub contract_sha256: String,
    pub delegation_sha256: String,
    pub organization_id: String,
    pub authenticated_actor_id: String,
    pub authenticated_role_id: String,
    pub authenticated_instruction_sha256: String,
    pub goal_spec_sha256: String,
    pub work_class_id: String,
    pub requested_application_pack_id: String,
    pub requested_application_pack_sha256: String,
    pub requested_integration_id: String,
    pub required_capability_ids: Vec<String>,
    pub semantic_target_ids: Vec<String>,
    pub task_risk: CognitiveRiskClass,
    pub trusted_policy_snapshot_sha256: String,
    pub policy_set_sha256: String,
    pub operational_time_context: RoleOperationalTimeContextV1,
    pub requested_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub evidence_ids: Vec<String>,
    pub request_sha256: String,
}

impl RoleTaskAdmissionRequestV1 {
    /// Canonically seals set-like fields and the request identity.
    pub fn seal(mut self) -> Result<Self, RoleContractError> {
        canonicalize_ids(
            &mut self.required_capability_ids,
            "task required capabilities",
            false,
        )?;
        canonicalize_ids(
            &mut self.semantic_target_ids,
            "task semantic targets",
            false,
        )?;
        canonicalize_ids(&mut self.evidence_ids, "task request evidence IDs", false)?;
        self.request_sha256 = hash_without(&self, &["request_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    /// Validates bounds, exact hashes, TTL, and canonical self-hash.
    pub fn validate(&self) -> Result<(), RoleContractError> {
        if self.schema_version != ROLE_CONTRACT_SCHEMA_VERSION
            || self.requested_at_unix_seconds == 0
            || self.expires_at_unix_seconds <= self.requested_at_unix_seconds
            || self.expires_at_unix_seconds - self.requested_at_unix_seconds > 300
        {
            return invalid("Role Task request schema or TTL is invalid");
        }
        for (value, label) in [
            (&self.request_id, "Role Task request_id"),
            (&self.organization_id, "Role Task organization_id"),
            (
                &self.authenticated_actor_id,
                "Role Task authenticated_actor_id",
            ),
            (
                &self.authenticated_role_id,
                "Role Task authenticated_role_id",
            ),
            (&self.work_class_id, "Role Task work_class_id"),
            (
                &self.requested_application_pack_id,
                "Role Task Application Pack ID",
            ),
            (&self.requested_integration_id, "Role Task integration ID"),
        ] {
            validate_id(value, label)?;
        }
        for (hash, label) in [
            (&self.role_instance_sha256, "Role Task instance hash"),
            (&self.contract_sha256, "Role Task contract hash"),
            (&self.delegation_sha256, "Role Task delegation hash"),
            (
                &self.authenticated_instruction_sha256,
                "Role Task instruction hash",
            ),
            (&self.goal_spec_sha256, "Role Task GoalSpec hash"),
            (
                &self.requested_application_pack_sha256,
                "Role Task pack hash",
            ),
            (
                &self.trusted_policy_snapshot_sha256,
                "Role Task policy snapshot hash",
            ),
            (&self.policy_set_sha256, "Role Task policy set hash"),
            (&self.request_sha256, "Role Task request hash"),
        ] {
            validate_hash(hash, label)?;
        }
        validate_ids(
            &self.required_capability_ids,
            "task required capabilities",
            false,
        )?;
        validate_ids(&self.semantic_target_ids, "task semantic targets", false)?;
        validate_evidence(&self.evidence_ids, "task request evidence IDs")?;
        self.operational_time_context.validate()?;
        if hash_without(self, &["request_sha256"])? != self.request_sha256 {
            return integrity("Role Task request_sha256 differs");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleTaskAdmissionOutcomeV1 {
    Admitted,
    Denied,
    EscalationRequired,
    InactiveRole,
    OutsideOperatingWindow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleTaskAdmissionReasonCodeV1 {
    WithinRoleScope,
    InactiveRole,
    OrganizationMismatch,
    ActorMismatch,
    RoleMismatch,
    WorkClassNotAccepted,
    WorkClassProhibited,
    ApplicationPackDenied,
    IntegrationDenied,
    CapabilityDenied,
    ProhibitedCapability,
    RiskExceeded,
    PolicyMismatch,
    OutsideOperatingWindow,
    BlackoutDate,
    StaleRequest,
    IntegrityMismatch,
}

/// Deterministic task admission result. Its base digest deliberately excludes
/// optional projection hashes to avoid a digest cycle with the role context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleTaskAdmissionDecisionV1 {
    pub schema_version: u32,
    pub admission_id: String,
    pub request_sha256: String,
    pub role_instance_id: String,
    pub contract_sha256: String,
    pub delegation_sha256: String,
    pub work_class_id: String,
    pub outcome: RoleTaskAdmissionOutcomeV1,
    pub reason_codes: Vec<RoleTaskAdmissionReasonCodeV1>,
    pub selected_responsibility_id: Option<String>,
    pub selected_sla_profile_id: Option<String>,
    pub reporting_obligation_ids: Vec<String>,
    pub authority_projection_sha256: Option<String>,
    pub recovery_profile_projection_sha256: Option<String>,
    pub role_task_context_sha256: Option<String>,
    pub evidence_ids: Vec<String>,
    pub decided_at_unix_seconds: u64,
    pub admission_sha256: String,
}

/// Exact role and task binding supplied to KRN-500. It is not execution authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleBoundKernelTaskContextV1 {
    pub schema_version: u32,
    pub role_instance_id: String,
    pub role_contract_id: String,
    pub role_version: String,
    pub contract_sha256: String,
    pub delegation_sha256: String,
    pub role_task_admission_sha256: String,
    pub work_class_id: String,
    pub responsibility_id: String,
    pub sla_profile_id: String,
    pub reporting_obligation_ids: Vec<String>,
    pub authority_projection_sha256: String,
    pub recovery_profile_projection_sha256: String,
    pub authenticated_instruction_sha256: String,
    pub goal_spec_sha256: String,
    pub application_pack_sha256: String,
    pub integration_id: String,
    pub required_capability_ids: Vec<String>,
    pub valid_from_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub evidence_ids: Vec<String>,
    pub context_sha256: String,
}

impl RoleBoundKernelTaskContextV1 {
    /// Validates all identifiers, hashes, bounds, and the context self-hash.
    pub fn validate(&self, now_unix_seconds: u64) -> Result<(), RoleContractError> {
        if self.schema_version != ROLE_CONTRACT_SCHEMA_VERSION
            || self.valid_from_unix_seconds == 0
            || self.expires_at_unix_seconds <= self.valid_from_unix_seconds
            || now_unix_seconds < self.valid_from_unix_seconds
            || now_unix_seconds >= self.expires_at_unix_seconds
        {
            return invalid("role-bound Kernel context is stale or malformed");
        }
        for (value, label) in [
            (&self.role_instance_id, "context role_instance_id"),
            (&self.role_contract_id, "context role_contract_id"),
            (&self.role_version, "context role_version"),
            (&self.work_class_id, "context work_class_id"),
            (&self.responsibility_id, "context responsibility_id"),
            (&self.sla_profile_id, "context sla_profile_id"),
            (&self.integration_id, "context integration_id"),
        ] {
            validate_id(value, label)?;
        }
        for (hash, label) in [
            (&self.contract_sha256, "context contract hash"),
            (&self.delegation_sha256, "context delegation hash"),
            (&self.role_task_admission_sha256, "context admission hash"),
            (&self.authority_projection_sha256, "context authority hash"),
            (
                &self.recovery_profile_projection_sha256,
                "context recovery hash",
            ),
            (
                &self.authenticated_instruction_sha256,
                "context instruction hash",
            ),
            (&self.goal_spec_sha256, "context GoalSpec hash"),
            (&self.application_pack_sha256, "context pack hash"),
            (&self.context_sha256, "context self-hash"),
        ] {
            validate_hash(hash, label)?;
        }
        validate_ids(
            &self.reporting_obligation_ids,
            "context reporting obligations",
            true,
        )?;
        validate_ids(&self.required_capability_ids, "context capabilities", false)?;
        validate_evidence(&self.evidence_ids, "context evidence IDs")?;
        if hash_without(self, &["context_sha256"])? != self.context_sha256 {
            return integrity("RoleBoundKernelTaskContext hash differs");
        }
        Ok(())
    }
}

/// Decision plus projections. Only an admitted result contains projection artifacts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleTaskAdmissionArtifactsV1 {
    pub decision: RoleTaskAdmissionDecisionV1,
    pub authority_projection: Option<DelegatedAuthorityContextV1>,
    pub recovery_profile_projection: Option<RecoveryPolicyProfileV1>,
    pub role_task_context: Option<RoleBoundKernelTaskContextV1>,
}

/// Verifies signed governance and deterministically admits or rejects one task.
#[allow(clippy::too_many_arguments)]
pub fn admit_role_task(
    request: &RoleTaskAdmissionRequestV1,
    contract: &RoleContractV1,
    approval: &RoleContractApprovalV1,
    delegation: &RoleDelegationGrantV1,
    instance: &RoleInstanceV1,
    trusted_policy: &TrustedPolicySnapshotV1,
    approval_signer_key_id: &str,
    approval_key: &VerifyingKey,
    delegation_signer_key_id: &str,
    delegation_key: &VerifyingKey,
    now_unix_seconds: u64,
) -> Result<RoleTaskAdmissionArtifactsV1, RoleContractError> {
    request.validate()?;
    verify_role_contract_approval(
        approval,
        contract,
        approval_signer_key_id,
        approval_key,
        now_unix_seconds,
    )?;
    verify_role_delegation(
        delegation,
        contract,
        approval,
        delegation_signer_key_id,
        delegation_key,
        now_unix_seconds,
    )?;
    instance.validate_against(contract, approval, delegation)?;
    trusted_policy
        .validate()
        .map_err(|error| RoleContractError::Integrity(error.to_string()))?;

    let evaluation = evaluate_request(
        request,
        contract,
        delegation,
        instance,
        trusted_policy,
        now_unix_seconds,
    )?;
    if evaluation.outcome != RoleTaskAdmissionOutcomeV1::Admitted {
        return Ok(RoleTaskAdmissionArtifactsV1 {
            decision: build_decision(request, instance, evaluation, None, None, None)?,
            authority_projection: None,
            recovery_profile_projection: None,
            role_task_context: None,
        });
    }
    let work = contract.work_class(&request.work_class_id).ok_or_else(|| {
        RoleContractError::Integrity("admitted work class disappeared".to_owned())
    })?;
    project_role_task(
        request,
        contract,
        delegation,
        instance,
        trusted_policy,
        work,
        evaluation,
    )
}

/// Projects an already validated admitted task into existing KRN authority and recovery contracts.
#[allow(clippy::too_many_arguments)]
fn project_role_task(
    request: &RoleTaskAdmissionRequestV1,
    contract: &RoleContractV1,
    delegation: &RoleDelegationGrantV1,
    instance: &RoleInstanceV1,
    trusted_policy: &TrustedPolicySnapshotV1,
    work: &AcceptedWorkClassRefV1,
    evaluation: AdmissionEvaluation,
) -> Result<RoleTaskAdmissionArtifactsV1, RoleContractError> {
    let required = set(&request.required_capability_ids);
    let delegated = set(&delegation.delegated_capability_ids);
    let prohibited = set(&delegation.prohibited_capability_ids)
        .union(&set(&contract.capability_policy.prohibited_capability_ids))
        .cloned()
        .collect::<BTreeSet<_>>();
    let allowed = required
        .intersection(&delegated)
        .filter(|capability| !prohibited.contains(*capability))
        .cloned()
        .collect::<Vec<_>>();
    let autonomous = allowed
        .iter()
        .filter(|capability| {
            delegation.autonomous_capability_ids.contains(*capability)
                && contract
                    .capability_policy
                    .autonomous_capability_ids
                    .contains(*capability)
        })
        .cloned()
        .collect::<Vec<_>>();
    let confirmation = allowed
        .iter()
        .filter(|capability| {
            delegation.confirmation_capability_ids.contains(*capability)
                && contract
                    .capability_policy
                    .confirmation_capability_ids
                    .contains(*capability)
        })
        .cloned()
        .collect::<Vec<_>>();
    let authority = DelegatedAuthorityContextV1 {
        schema_version: POLICY_ADMISSION_SCHEMA_VERSION,
        authority_id: derived_id("role-authority", &request.request_sha256),
        organization_id: instance.organization_id.clone(),
        actor_id: instance.role_instance_id.clone(),
        role_id: contract.role_contract_id.clone(),
        policy_set_id: contract.policy_set_id.clone(),
        policy_set_version: contract.policy_set_version.clone(),
        policy_set_sha256: contract.policy_set_sha256.clone(),
        allowed_capability_ids: allowed.clone(),
        forbidden_capability_ids: Vec::new(),
        autonomous_capability_ids: autonomous,
        confirmation_capability_ids: confirmation,
        maximum_autonomous_risk: min_risk(
            delegation.maximum_autonomous_risk,
            min_risk(
                contract.risk_policy.maximum_autonomous_risk,
                work.maximum_risk,
            ),
        ),
        maximum_confirmable_risk: min_risk(
            delegation.maximum_confirmable_risk,
            min_risk(
                contract.risk_policy.maximum_confirmable_risk,
                work.maximum_risk,
            ),
        ),
        allowed_application_pack_sha256: request.requested_application_pack_sha256.clone(),
        allowed_integration_ids: vec![request.requested_integration_id.clone()],
        scope_constraints: AuthorityScopeConstraintsV1 {
            application_pack_sha256: request.requested_application_pack_sha256.clone(),
            integration_ids: vec![request.requested_integration_id.clone()],
            semantic_target_ids: request.semantic_target_ids.clone(),
        },
        valid_from_unix_seconds: request.requested_at_unix_seconds,
        expires_at_unix_seconds: request
            .expires_at_unix_seconds
            .min(delegation.expires_at_unix_seconds),
        evidence_ids: sorted(vec![
            contract.contract_sha256.clone(),
            delegation.delegation_sha256.clone(),
            request.request_sha256.clone(),
        ]),
        authority_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| RoleContractError::Integrity(error.to_string()))?;

    let automatic = work.automatic_recovery_allowed;
    let retryable_failure_classes = if automatic {
        vec![
            RecoveryFailureClassV1::TransientObservationFailure,
            RecoveryFailureClassV1::StaleBinding,
            RecoveryFailureClassV1::ActivationUnavailable,
            RecoveryFailureClassV1::TargetResolutionFailed,
            RecoveryFailureClassV1::ExecutionFailed,
            RecoveryFailureClassV1::PostconditionFailed,
            RecoveryFailureClassV1::ExpectedChangeMissing,
        ]
    } else {
        Vec::new()
    };
    let recovery = RecoveryPolicyProfileV1 {
        schema_version: RECOVERY_SCHEMA_VERSION,
        profile_id: derived_id("role-recovery", &request.request_sha256),
        policy_set_sha256: trusted_policy.policy_set_sha256.clone(),
        authority_sha256: authority.authority_sha256.clone(),
        retryable_failure_classes,
        reobservable_failure_classes: if automatic {
            vec![
                RecoveryFailureClassV1::TransientObservationFailure,
                RecoveryFailureClassV1::StaleBinding,
            ]
        } else {
            Vec::new()
        },
        alternate_capability_failure_classes: Vec::new(),
        replannable_failure_classes: Vec::new(),
        clarifiable_failure_classes: if work.clarification_allowed {
            vec![
                RecoveryFailureClassV1::AmbiguousTarget,
                RecoveryFailureClassV1::ClarificationRequired,
            ]
        } else {
            Vec::new()
        },
        mandatory_escalation_failure_classes: vec![
            RecoveryFailureClassV1::UnsafeSideEffect,
            RecoveryFailureClassV1::ProtectedInvariantViolation,
            RecoveryFailureClassV1::PolicyUnknown,
            RecoveryFailureClassV1::AuthorityExceeded,
        ],
        forbidden_automatic_failure_classes: vec![
            RecoveryFailureClassV1::PolicyDenied,
            RecoveryFailureClassV1::PolicyUnknown,
            RecoveryFailureClassV1::AuthorityExceeded,
            RecoveryFailureClassV1::UnsafeSideEffect,
            RecoveryFailureClassV1::ProtectedInvariantViolation,
        ],
        retryable_capability_ids: if automatic {
            allowed.clone()
        } else {
            Vec::new()
        },
        alternate_capability_groups: Vec::<AlternateCapabilityGroupV1>::new(),
        maximum_same_capability_attempts: contract
            .capability_policy
            .maximum_attempts_per_capability
            .min(2),
        allow_replan: false,
        allow_clarification: work.clarification_allowed,
        escalation_risk_threshold: min_risk(
            contract.risk_policy.mandatory_escalation_risk,
            work.maximum_risk,
        ),
        evidence_ids: sorted(vec![
            request.request_sha256.clone(),
            authority.authority_sha256.clone(),
        ]),
        profile_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| RoleContractError::Integrity(error.to_string()))?;
    recovery
        .validate_against(
            &trusted_policy.policy_set_sha256,
            &authority.authority_sha256,
            &allowed.iter().cloned().collect(),
        )
        .map_err(|error| RoleContractError::Integrity(error.to_string()))?;

    let mut preliminary = build_decision(request, instance, evaluation.clone(), None, None, None)?;
    let admission_binding = preliminary.admission_sha256.clone();
    let mut context = RoleBoundKernelTaskContextV1 {
        schema_version: ROLE_CONTRACT_SCHEMA_VERSION,
        role_instance_id: instance.role_instance_id.clone(),
        role_contract_id: contract.role_contract_id.clone(),
        role_version: contract.role_version.clone(),
        contract_sha256: contract.contract_sha256.clone(),
        delegation_sha256: delegation.delegation_sha256.clone(),
        role_task_admission_sha256: admission_binding,
        work_class_id: request.work_class_id.clone(),
        responsibility_id: work.responsibility_id.clone(),
        sla_profile_id: work.sla_profile_id.clone(),
        reporting_obligation_ids: evaluation.reporting_obligation_ids.clone(),
        authority_projection_sha256: authority.authority_sha256.clone(),
        recovery_profile_projection_sha256: recovery.profile_sha256.clone(),
        authenticated_instruction_sha256: request.authenticated_instruction_sha256.clone(),
        goal_spec_sha256: request.goal_spec_sha256.clone(),
        application_pack_sha256: request.requested_application_pack_sha256.clone(),
        integration_id: request.requested_integration_id.clone(),
        required_capability_ids: request.required_capability_ids.clone(),
        valid_from_unix_seconds: request.requested_at_unix_seconds,
        expires_at_unix_seconds: request
            .expires_at_unix_seconds
            .min(delegation.expires_at_unix_seconds),
        evidence_ids: sorted(vec![
            request.request_sha256.clone(),
            authority.authority_sha256.clone(),
            recovery.profile_sha256.clone(),
        ]),
        context_sha256: ZERO_HASH.to_owned(),
    };
    context.context_sha256 = hash_without(&context, &["context_sha256"])?;
    context.validate(request.requested_at_unix_seconds)?;
    preliminary.authority_projection_sha256 = Some(authority.authority_sha256.clone());
    preliminary.recovery_profile_projection_sha256 = Some(recovery.profile_sha256.clone());
    preliminary.role_task_context_sha256 = Some(context.context_sha256.clone());
    preliminary.validate()?;
    Ok(RoleTaskAdmissionArtifactsV1 {
        decision: preliminary,
        authority_projection: Some(authority),
        recovery_profile_projection: Some(recovery),
        role_task_context: Some(context),
    })
}

#[derive(Debug, Clone)]
struct AdmissionEvaluation {
    outcome: RoleTaskAdmissionOutcomeV1,
    reason_codes: Vec<RoleTaskAdmissionReasonCodeV1>,
    responsibility_id: Option<String>,
    sla_profile_id: Option<String>,
    reporting_obligation_ids: Vec<String>,
}

fn evaluate_request(
    request: &RoleTaskAdmissionRequestV1,
    contract: &RoleContractV1,
    delegation: &RoleDelegationGrantV1,
    instance: &RoleInstanceV1,
    policy: &TrustedPolicySnapshotV1,
    now: u64,
) -> Result<AdmissionEvaluation, RoleContractError> {
    let mut reasons = Vec::new();
    if instance.current_status != RoleInstanceStatusV1::Active
        || now >= instance.expires_at_unix_seconds
    {
        reasons.push(RoleTaskAdmissionReasonCodeV1::InactiveRole);
        return Ok(evaluation(
            contract,
            RoleTaskAdmissionOutcomeV1::InactiveRole,
            reasons,
            None,
        ));
    }
    if now < request.requested_at_unix_seconds || now >= request.expires_at_unix_seconds {
        reasons.push(RoleTaskAdmissionReasonCodeV1::StaleRequest);
    }
    if request.role_instance_sha256 != instance.instance_sha256
        || request.contract_sha256 != contract.contract_sha256
        || request.delegation_sha256 != delegation.delegation_sha256
    {
        reasons.push(RoleTaskAdmissionReasonCodeV1::IntegrityMismatch);
    }
    if request.organization_id != instance.organization_id {
        reasons.push(RoleTaskAdmissionReasonCodeV1::OrganizationMismatch);
    }
    if request.authenticated_actor_id != instance.role_instance_id {
        reasons.push(RoleTaskAdmissionReasonCodeV1::ActorMismatch);
    }
    if request.authenticated_role_id != contract.role_contract_id {
        reasons.push(RoleTaskAdmissionReasonCodeV1::RoleMismatch);
    }
    if contract
        .prohibited_work_class_ids
        .contains(&request.work_class_id)
    {
        reasons.push(RoleTaskAdmissionReasonCodeV1::WorkClassProhibited);
    }
    let work = contract.work_class(&request.work_class_id);
    if work.is_none()
        || !delegation
            .delegated_work_class_ids
            .contains(&request.work_class_id)
    {
        reasons.push(RoleTaskAdmissionReasonCodeV1::WorkClassNotAccepted);
    }
    let app = contract.application(&request.requested_application_pack_id);
    if app.is_none()
        || !delegation
            .delegated_application_pack_ids
            .contains(&request.requested_application_pack_id)
        || app.is_some_and(|value| {
            value.application_pack_sha256 != request.requested_application_pack_sha256
        })
    {
        reasons.push(RoleTaskAdmissionReasonCodeV1::ApplicationPackDenied);
    }
    if app.is_none_or(|value| {
        !value
            .integration_ids
            .contains(&request.requested_integration_id)
    }) || !delegation
        .delegated_integration_ids
        .contains(&request.requested_integration_id)
    {
        reasons.push(RoleTaskAdmissionReasonCodeV1::IntegrationDenied);
    }
    let required = set(&request.required_capability_ids);
    let allowed = set(&contract.capability_policy.allowed_capability_ids);
    let delegated = set(&delegation.delegated_capability_ids);
    if !required.is_subset(&allowed) || !required.is_subset(&delegated) {
        reasons.push(RoleTaskAdmissionReasonCodeV1::CapabilityDenied);
    }
    if !required.is_disjoint(&set(&contract.capability_policy.prohibited_capability_ids))
        || !required.is_disjoint(&set(&delegation.prohibited_capability_ids))
    {
        reasons.push(RoleTaskAdmissionReasonCodeV1::ProhibitedCapability);
    }
    if request.task_risk > delegation.maximum_confirmable_risk
        || request.task_risk > contract.risk_policy.maximum_confirmable_risk
        || work.is_some_and(|value| request.task_risk > value.maximum_risk)
    {
        reasons.push(RoleTaskAdmissionReasonCodeV1::RiskExceeded);
    }
    if request.policy_set_sha256 != contract.policy_set_sha256
        || request.policy_set_sha256 != delegation.policy_set_sha256
        || request.policy_set_sha256 != policy.policy_set_sha256
        || request.trusted_policy_snapshot_sha256 != policy.snapshot_sha256
        || request.organization_id != policy.organization_id
    {
        reasons.push(RoleTaskAdmissionReasonCodeV1::PolicyMismatch);
    }
    let in_window =
        evaluate_calendar(&contract.working_calendar.weekly_windows, request, contract)?;
    if !in_window {
        reasons.push(RoleTaskAdmissionReasonCodeV1::OutsideOperatingWindow);
        let outcome = match contract.working_calendar.outside_window_behavior {
            OutsideWindowBehaviorV1::DenyNewWork => {
                RoleTaskAdmissionOutcomeV1::OutsideOperatingWindow
            }
            OutsideWindowBehaviorV1::EscalationOnly => {
                RoleTaskAdmissionOutcomeV1::EscalationRequired
            }
        };
        return Ok(evaluation(contract, outcome, reasons, work));
    }
    reasons.sort();
    reasons.dedup();
    if reasons.is_empty() {
        reasons.push(RoleTaskAdmissionReasonCodeV1::WithinRoleScope);
        Ok(evaluation(
            contract,
            RoleTaskAdmissionOutcomeV1::Admitted,
            reasons,
            work,
        ))
    } else {
        let escalation = reasons.iter().any(|reason| {
            matches!(
                reason,
                RoleTaskAdmissionReasonCodeV1::RiskExceeded
                    | RoleTaskAdmissionReasonCodeV1::PolicyMismatch
            )
        });
        Ok(evaluation(
            contract,
            if escalation {
                RoleTaskAdmissionOutcomeV1::EscalationRequired
            } else {
                RoleTaskAdmissionOutcomeV1::Denied
            },
            reasons,
            work,
        ))
    }
}

fn evaluate_calendar(
    windows: &[WeeklyWindowV1],
    request: &RoleTaskAdmissionRequestV1,
    contract: &RoleContractV1,
) -> Result<bool, RoleContractError> {
    let time = &request.operational_time_context;
    if time.calendar_sha256 != contract.working_calendar.calendar_sha256
        || time.timezone_id != contract.working_calendar.timezone_id
        || time.observed_at_unix_seconds > request.requested_at_unix_seconds
        || request.requested_at_unix_seconds - time.observed_at_unix_seconds > 60
    {
        return integrity("operational time context is stale or calendar-unbound");
    }
    if contract
        .working_calendar
        .blackout_date_ids
        .contains(&time.local_date)
        || time.blackout_date_ids.contains(&time.local_date)
    {
        return Ok(time.emergency_override_sha256.is_some()
            && contract.working_calendar.emergency_override_policy
                == EmergencyOverridePolicyV1::SignedReferenceOnly);
    }
    Ok(windows.iter().any(|window| {
        window.weekday == time.weekday
            && window.start_minute_local <= time.local_minute_of_day
            && time.local_minute_of_day < window.end_minute_local
    }))
}

fn evaluation(
    contract: &RoleContractV1,
    outcome: RoleTaskAdmissionOutcomeV1,
    reason_codes: Vec<RoleTaskAdmissionReasonCodeV1>,
    work: Option<&AcceptedWorkClassRefV1>,
) -> AdmissionEvaluation {
    AdmissionEvaluation {
        outcome,
        reason_codes,
        responsibility_id: work.map(|value| value.responsibility_id.clone()),
        sla_profile_id: work.map(|value| value.sla_profile_id.clone()),
        reporting_obligation_ids: work
            .and_then(|selected| {
                contract.responsibilities.iter().find(|responsibility| {
                    responsibility.responsibility_id == selected.responsibility_id
                })
            })
            .map_or_else(Vec::new, |responsibility| {
                responsibility.reporting_obligation_ids.clone()
            }),
    }
}

fn build_decision(
    request: &RoleTaskAdmissionRequestV1,
    instance: &RoleInstanceV1,
    mut evaluation: AdmissionEvaluation,
    authority: Option<String>,
    recovery: Option<String>,
    context: Option<String>,
) -> Result<RoleTaskAdmissionDecisionV1, RoleContractError> {
    evaluation.reason_codes.sort();
    evaluation.reason_codes.dedup();
    evaluation.reporting_obligation_ids.sort();
    let mut decision = RoleTaskAdmissionDecisionV1 {
        schema_version: ROLE_CONTRACT_SCHEMA_VERSION,
        admission_id: derived_id("role-admission", &request.request_sha256),
        request_sha256: request.request_sha256.clone(),
        role_instance_id: instance.role_instance_id.clone(),
        contract_sha256: request.contract_sha256.clone(),
        delegation_sha256: request.delegation_sha256.clone(),
        work_class_id: request.work_class_id.clone(),
        outcome: evaluation.outcome,
        reason_codes: evaluation.reason_codes,
        selected_responsibility_id: evaluation.responsibility_id,
        selected_sla_profile_id: evaluation.sla_profile_id,
        reporting_obligation_ids: evaluation.reporting_obligation_ids,
        authority_projection_sha256: authority,
        recovery_profile_projection_sha256: recovery,
        role_task_context_sha256: context,
        evidence_ids: sorted(vec![
            request.request_sha256.clone(),
            instance.instance_sha256.clone(),
        ]),
        decided_at_unix_seconds: request.requested_at_unix_seconds,
        admission_sha256: ZERO_HASH.to_owned(),
    };
    decision.admission_sha256 = decision.binding_sha256()?;
    if decision.outcome != RoleTaskAdmissionOutcomeV1::Admitted
        || decision.authority_projection_sha256.is_some()
    {
        decision.validate()?;
    }
    Ok(decision)
}

impl RoleTaskAdmissionDecisionV1 {
    fn binding_sha256(&self) -> Result<String, RoleContractError> {
        hash_without(
            self,
            &[
                "authority_projection_sha256",
                "recovery_profile_projection_sha256",
                "role_task_context_sha256",
                "admission_sha256",
            ],
        )
    }

    /// Validates outcome-specific projection presence and immutable binding.
    pub fn validate(&self) -> Result<(), RoleContractError> {
        if self.schema_version != ROLE_CONTRACT_SCHEMA_VERSION || self.decided_at_unix_seconds == 0
        {
            return invalid("Role Task decision schema or timestamp is invalid");
        }
        validate_id(&self.admission_id, "admission_id")?;
        validate_id(&self.role_instance_id, "decision role_instance_id")?;
        validate_id(&self.work_class_id, "decision work_class_id")?;
        for hash in [
            &self.request_sha256,
            &self.contract_sha256,
            &self.delegation_sha256,
            &self.admission_sha256,
        ] {
            validate_hash(hash, "Role Task decision hash")?;
        }
        if self.reason_codes.is_empty()
            || !self.reason_codes.windows(2).all(|pair| pair[0] < pair[1])
        {
            return invalid("Role Task decision reasons are empty, duplicated, or unsorted");
        }
        validate_ids(
            &self.reporting_obligation_ids,
            "decision reporting obligations",
            true,
        )?;
        validate_evidence(&self.evidence_ids, "decision evidence IDs")?;
        let projections = [
            &self.authority_projection_sha256,
            &self.recovery_profile_projection_sha256,
            &self.role_task_context_sha256,
        ];
        if self.outcome == RoleTaskAdmissionOutcomeV1::Admitted {
            if self.selected_responsibility_id.is_none()
                || self.selected_sla_profile_id.is_none()
                || projections.iter().any(|value| value.is_none())
            {
                return invalid("admitted Role Task lacks required projections");
            }
        } else if (self.selected_responsibility_id.is_some()
            && self.outcome == RoleTaskAdmissionOutcomeV1::InactiveRole)
            || projections.iter().any(|value| value.is_some())
        {
            return invalid("non-admitted Role Task contains authority projections");
        }
        for hash in projections.into_iter().flatten() {
            validate_hash(hash, "Role Task projection hash")?;
        }
        if self.binding_sha256()? != self.admission_sha256 {
            return integrity("Role Task admission binding hash differs");
        }
        Ok(())
    }
}

fn validate_local_date(value: &str) -> Result<(), RoleContractError> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
    {
        return invalid("local_date must use YYYY-MM-DD");
    }
    Ok(())
}

fn derived_id(prefix: &str, digest: &str) -> String {
    let suffix = digest.strip_prefix("sha256:").unwrap_or(digest);
    let end = suffix.len().min(24);
    format!("{prefix}-{}", &suffix[..end])
}

fn sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn set(values: &[String]) -> BTreeSet<String> {
    values.iter().cloned().collect()
}
