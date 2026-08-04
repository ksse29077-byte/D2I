use crate::strict::{canonical_json_bytes, hash_without};
use crate::{
    authorization, integrity, invalid, replay, WorkQueueError, MAX_EVIDENCE_IDS, MAX_IDS,
    MAX_LEASE_SECONDS, MAX_OWNERSHIP_GENERATIONS, MAX_POOL_MEMBERS, MAX_QUEUE_ENTRIES,
    WORK_QUEUE_SCHEMA_VERSION, ZERO_HASH,
};
use d2i_cognitive_ir::CognitiveRiskClass;
use d2i_role_contract::{RoleInstanceStatusV1, RoleInstanceV1, RoleOperationalTimeContextV1};
use d2i_work_case::{CaseContractV1, CaseInstanceV1, CaseLifecycleStatusV1, WorkPriorityClassV1};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueStateTreatmentV1 {
    Exclude,
    Eligible,
    Attention,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseExpiryBehaviorV1 {
    ReturnToReady,
    Attention,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueLaneV1 {
    Ready,
    WaitingClarification,
    Blocked,
    AwaitingVerification,
    OwnerUnavailable,
    Leased,
    EscalationAttention,
    TerminalRemoved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomaticReassignmentReasonV1 {
    CoordinatorRecovery,
    LeaseRecovery,
    OwnerCapacityExhausted,
    OwnerExpired,
    OwnerRevoked,
    OwnerSuspended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipAssignmentReasonV1 {
    OriginBinding,
    ApprovedTransfer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerOutcomeV1 {
    CaseSelected,
    NoEligibleCase,
    OwnerReassignmentRequired,
    EscalationAttentionRequired,
    OutsideOperatingWindow,
    QueueEmpty,
    ResourceLimit,
    IntegrityFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerReasonCodeV1 {
    ActiveLease,
    AwaitingClarification,
    AwaitingVerificationNotEligible,
    Blocked,
    CaseSelected,
    EscalationAttention,
    InactiveOwner,
    IntegrityMismatch,
    NoEligibleCase,
    OutsideOperatingWindow,
    OwnerExpired,
    QueueEmpty,
    ResourceLimit,
    StaleCase,
    StaleOwnership,
    TerminalCase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatusV1 {
    Active,
    Renewed,
    Released,
    Expired,
    Revoked,
    Consumed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueOperationKindV1 {
    Enqueued,
    Reconciled,
    SchedulerEvaluated,
    LeaseClaimed,
    LeaseRenewed,
    LeaseReleased,
    LeaseExpired,
    OwnershipTransferred,
    WorkGrantCreated,
    RecoveryRepaired,
}

/// Finite, authority-narrowing Queue and Scheduler policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkQueuePolicyV1 {
    pub schema_version: u32,
    pub policy_id: String,
    pub policy_version: String,
    pub queue_id: String,
    pub organization_id: String,
    pub role_contract_id: String,
    pub role_version: String,
    pub role_contract_sha256: String,
    pub allowed_work_class_ids: Vec<String>,
    pub allowed_role_instance_ids: Vec<String>,
    pub maximum_queue_entries: u32,
    pub maximum_entries_examined_per_tick: u32,
    pub claim_lease_duration_seconds: u64,
    pub minimum_lease_duration_seconds: u64,
    pub maximum_lease_duration_seconds: u64,
    pub maximum_lease_renewals: u32,
    pub maximum_concurrent_leases_per_role: u32,
    pub maximum_open_cases_per_role: u32,
    pub aging_interval_seconds: u64,
    pub maximum_aging_buckets: u32,
    pub require_inside_operating_calendar: bool,
    pub blocked_treatment: QueueStateTreatmentV1,
    pub awaiting_clarification_treatment: QueueStateTreatmentV1,
    pub awaiting_verification_treatment: QueueStateTreatmentV1,
    pub escalation_pending_treatment: QueueStateTreatmentV1,
    pub owner_unavailable_treatment: QueueStateTreatmentV1,
    pub lease_expiry_behavior: LeaseExpiryBehaviorV1,
    pub reassignment_allowed: bool,
    pub automatic_reassignment_reasons: Vec<AutomaticReassignmentReasonV1>,
    pub maximum_ownership_generations: u64,
    pub maximum_queue_operations: u64,
    pub maximum_snapshot_bytes: u64,
    pub maximum_decision_bytes: u64,
    pub maximum_ledger_bytes: u64,
    pub logical_operation_budget: u64,
    pub maximum_scheduler_ticks_per_invocation: u32,
    pub maximum_concurrent_coordinators: u32,
    pub maximum_replay_records: u64,
    pub evidence_ids: Vec<String>,
    pub policy_sha256: String,
}

impl WorkQueuePolicyV1 {
    pub fn seal(mut self) -> Result<Self, WorkQueueError> {
        normalize_ids(
            &mut self.allowed_work_class_ids,
            "allowed work classes",
            false,
        )?;
        normalize_ids(
            &mut self.allowed_role_instance_ids,
            "allowed Role Instances",
            false,
        )?;
        self.automatic_reassignment_reasons.sort();
        reject_duplicates(
            &self.automatic_reassignment_reasons,
            "automatic reassignment reasons",
        )?;
        normalize_ids(&mut self.evidence_ids, "Queue policy evidence", false)?;
        self.policy_sha256 = hash_without(&self, &["policy_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), WorkQueueError> {
        if self.schema_version != WORK_QUEUE_SCHEMA_VERSION
            || self.maximum_queue_entries == 0
            || self.maximum_queue_entries as usize > MAX_QUEUE_ENTRIES
            || self.maximum_entries_examined_per_tick == 0
            || self.maximum_entries_examined_per_tick > self.maximum_queue_entries
            || self.minimum_lease_duration_seconds == 0
            || self.claim_lease_duration_seconds < self.minimum_lease_duration_seconds
            || self.claim_lease_duration_seconds > self.maximum_lease_duration_seconds
            || self.maximum_lease_duration_seconds > MAX_LEASE_SECONDS
            || self.maximum_lease_renewals > 64
            || self.maximum_concurrent_leases_per_role == 0
            || self.maximum_concurrent_leases_per_role > 128
            || self.maximum_open_cases_per_role == 0
            || self.maximum_open_cases_per_role > MAX_QUEUE_ENTRIES as u32
            || self.aging_interval_seconds == 0
            || self.maximum_aging_buckets > 1_024
            || self.maximum_ownership_generations == 0
            || self.maximum_ownership_generations > MAX_OWNERSHIP_GENERATIONS
            || self.maximum_queue_operations == 0
            || self.maximum_snapshot_bytes == 0
            || self.maximum_snapshot_bytes > crate::MAX_JSON_BYTES as u64
            || self.maximum_decision_bytes == 0
            || self.maximum_decision_bytes > crate::MAX_JSON_BYTES as u64
            || self.maximum_ledger_bytes == 0
            || self.logical_operation_budget == 0
            || self.maximum_scheduler_ticks_per_invocation != 1
            || self.maximum_concurrent_coordinators != 1
            || self.maximum_replay_records == 0
            || self.maximum_replay_records > crate::MAX_REPLAY_RECORDS as u64
        {
            return invalid("Queue policy contains invalid or unbounded limits");
        }
        for (value, label) in [
            (&self.policy_id, "Queue policy ID"),
            (&self.policy_version, "Queue policy version"),
            (&self.queue_id, "Queue ID"),
            (&self.organization_id, "Queue organization"),
            (&self.role_contract_id, "Queue Role Contract ID"),
            (&self.role_version, "Queue Role version"),
        ] {
            validate_id(value, label)?;
        }
        validate_hash(&self.role_contract_sha256, "Queue Role Contract hash")?;
        validate_ids(&self.allowed_work_class_ids, "allowed work classes", false)?;
        validate_ids(
            &self.allowed_role_instance_ids,
            "allowed Role Instances",
            false,
        )?;
        reject_duplicates(
            &self.automatic_reassignment_reasons,
            "automatic reassignment reasons",
        )?;
        if self.reassignment_allowed == self.automatic_reassignment_reasons.is_empty() {
            return invalid("reassignment flag and closed reason set differ");
        }
        if self.blocked_treatment == QueueStateTreatmentV1::Eligible
            || self.awaiting_clarification_treatment == QueueStateTreatmentV1::Eligible
            || self.escalation_pending_treatment == QueueStateTreatmentV1::Eligible
            || self.owner_unavailable_treatment == QueueStateTreatmentV1::Eligible
        {
            return authorization("v1 policy may not make blocked or attention states eligible");
        }
        validate_ids(&self.evidence_ids, "Queue policy evidence", false)?;
        validate_hash(&self.policy_sha256, "Queue policy hash")?;
        if hash_without(self, &["policy_sha256"])? != self.policy_sha256 {
            return integrity("Queue policy self-hash differs");
        }
        reject_sensitive(self, "Queue policy")
    }
}

/// Exact member of a signed ownership pool.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseOwnershipPoolMemberV1 {
    pub role_instance_id: String,
    pub role_instance_sha256: String,
    pub delegation_sha256: String,
    pub allowed_work_class_ids: Vec<String>,
    pub allowed_responsibility_ids: Vec<String>,
    pub allowed_application_pack_ids: Vec<String>,
    pub allowed_integration_ids: Vec<String>,
    pub allowed_capability_ids: Vec<String>,
    pub active: bool,
    pub expires_at_unix_seconds: u64,
    pub ownership_expires_at_unix_seconds: u64,
    pub active_lease_count: u32,
    pub non_terminal_case_count: u32,
}

impl CaseOwnershipPoolMemberV1 {
    fn normalize(&mut self) -> Result<(), WorkQueueError> {
        for (values, label) in [
            (&mut self.allowed_work_class_ids, "pool member work classes"),
            (
                &mut self.allowed_responsibility_ids,
                "pool member responsibilities",
            ),
            (
                &mut self.allowed_application_pack_ids,
                "pool member Application Packs",
            ),
            (
                &mut self.allowed_integration_ids,
                "pool member integrations",
            ),
            (&mut self.allowed_capability_ids, "pool member capabilities"),
        ] {
            normalize_ids(values, label, false)?;
        }
        self.validate()
    }

    fn validate(&self) -> Result<(), WorkQueueError> {
        validate_id(&self.role_instance_id, "pool Role Instance ID")?;
        validate_hash(&self.role_instance_sha256, "pool Role Instance hash")?;
        validate_hash(&self.delegation_sha256, "pool delegation hash")?;
        for (values, label) in [
            (&self.allowed_work_class_ids, "pool member work classes"),
            (
                &self.allowed_responsibility_ids,
                "pool member responsibilities",
            ),
            (
                &self.allowed_application_pack_ids,
                "pool member Application Packs",
            ),
            (&self.allowed_integration_ids, "pool member integrations"),
            (&self.allowed_capability_ids, "pool member capabilities"),
        ] {
            validate_ids(values, label, false)?;
        }
        if self.expires_at_unix_seconds == 0
            || self.ownership_expires_at_unix_seconds == 0
            || self.ownership_expires_at_unix_seconds > self.expires_at_unix_seconds
        {
            return invalid("pool member lifetime is invalid");
        }
        Ok(())
    }
}

/// Organization-signed exact set of Role Instances eligible for reassignment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseOwnershipPoolV1 {
    pub schema_version: u32,
    pub pool_id: String,
    pub pool_version: String,
    pub organization_id: String,
    pub role_contract_id: String,
    pub role_version: String,
    pub role_contract_sha256: String,
    pub members: Vec<CaseOwnershipPoolMemberV1>,
    pub allowed_work_class_ids: Vec<String>,
    pub allowed_responsibility_ids: Vec<String>,
    pub allowed_application_pack_ids: Vec<String>,
    pub allowed_integration_ids: Vec<String>,
    pub allowed_capability_ids: Vec<String>,
    pub maximum_risk: CognitiveRiskClass,
    pub automatic_reassignment_reasons: Vec<AutomaticReassignmentReasonV1>,
    pub maximum_concurrent_leases_per_role: u32,
    pub valid_from_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub signer_id: String,
    pub signer_key_id: String,
    pub evidence_ids: Vec<String>,
    pub approval_signature: String,
    pub pool_sha256: String,
}

pub fn create_case_ownership_pool(
    mut pool: CaseOwnershipPoolV1,
    signing_key: &SigningKey,
) -> Result<CaseOwnershipPoolV1, WorkQueueError> {
    pool.normalize()?;
    pool.approval_signature = "00".repeat(64);
    pool.pool_sha256 = hash_without(&pool, &["pool_sha256"])?;
    pool.validate()?;
    pool.approval_signature = hex_encode(&signing_key.sign(&pool.signing_bytes()?).to_bytes());
    pool.pool_sha256 = hash_without(&pool, &["pool_sha256"])?;
    pool.validate()?;
    Ok(pool)
}

pub fn verify_case_ownership_pool(
    pool: &CaseOwnershipPoolV1,
    expected_signer_key_id: &str,
    verifying_key: &VerifyingKey,
    role_instances: &[RoleInstanceV1],
    now_unix_seconds: u64,
) -> Result<(), WorkQueueError> {
    pool.validate()?;
    validate_id(
        expected_signer_key_id,
        "expected ownership pool signer key ID",
    )?;
    if pool.signer_key_id != expected_signer_key_id
        || now_unix_seconds < pool.valid_from_unix_seconds
        || now_unix_seconds >= pool.expires_at_unix_seconds
    {
        return authorization("ownership pool signer or lifetime differs");
    }
    let signature = Signature::from_bytes(&hex_decode_array::<64>(&pool.approval_signature)?);
    verifying_key
        .verify(&pool.signing_bytes()?, &signature)
        .map_err(|error| {
            WorkQueueError::Authorization(format!("ownership pool signature rejected: {error}"))
        })?;
    if role_instances.len() != pool.members.len() {
        return integrity("ownership pool Role Instance set is incomplete");
    }
    for member in &pool.members {
        let instance = role_instances
            .iter()
            .find(|candidate| candidate.role_instance_id == member.role_instance_id)
            .ok_or_else(|| {
                WorkQueueError::Integrity("ownership pool member is absent".to_owned())
            })?;
        instance.validate_shape()?;
        if instance.instance_sha256 != member.role_instance_sha256
            || instance.delegation_sha256 != member.delegation_sha256
            || instance.organization_id != pool.organization_id
            || instance.role_contract_id != pool.role_contract_id
            || instance.role_version != pool.role_version
            || instance.contract_sha256 != pool.role_contract_sha256
            || instance.application_pack_ids != member.allowed_application_pack_ids
            || instance.integration_ids != member.allowed_integration_ids
            || !is_subset(&member.allowed_capability_ids, &instance.capability_ids)
            || instance.current_status != RoleInstanceStatusV1::Active
            || instance.expires_at_unix_seconds != member.expires_at_unix_seconds
            || now_unix_seconds >= instance.expires_at_unix_seconds
        {
            return authorization("ownership pool member differs from active exact Role Instance");
        }
    }
    Ok(())
}

impl CaseOwnershipPoolV1 {
    fn normalize(&mut self) -> Result<(), WorkQueueError> {
        for member in &mut self.members {
            member.normalize()?;
        }
        self.members
            .sort_by(|left, right| left.role_instance_id.cmp(&right.role_instance_id));
        if self
            .members
            .windows(2)
            .any(|pair| pair[0].role_instance_id == pair[1].role_instance_id)
        {
            return invalid("ownership pool contains duplicate Role Instances");
        }
        for (values, label) in [
            (&mut self.allowed_work_class_ids, "pool work classes"),
            (
                &mut self.allowed_responsibility_ids,
                "pool responsibilities",
            ),
            (
                &mut self.allowed_application_pack_ids,
                "pool Application Packs",
            ),
            (&mut self.allowed_integration_ids, "pool integrations"),
            (&mut self.allowed_capability_ids, "pool capabilities"),
        ] {
            normalize_ids(values, label, false)?;
        }
        self.automatic_reassignment_reasons.sort();
        reject_duplicates(
            &self.automatic_reassignment_reasons,
            "pool transfer reasons",
        )?;
        normalize_ids(&mut self.evidence_ids, "pool evidence", false)
    }

    pub fn validate(&self) -> Result<(), WorkQueueError> {
        if self.schema_version != WORK_QUEUE_SCHEMA_VERSION
            || self.members.is_empty()
            || self.members.len() > MAX_POOL_MEMBERS
            || self.maximum_concurrent_leases_per_role == 0
            || self.valid_from_unix_seconds == 0
            || self.expires_at_unix_seconds <= self.valid_from_unix_seconds
        {
            return invalid("ownership pool schema, members, limits, or lifetime is invalid");
        }
        for (value, label) in [
            (&self.pool_id, "ownership pool ID"),
            (&self.pool_version, "ownership pool version"),
            (&self.organization_id, "ownership pool organization"),
            (&self.role_contract_id, "ownership pool Role Contract ID"),
            (&self.role_version, "ownership pool Role version"),
            (&self.signer_id, "ownership pool signer"),
            (&self.signer_key_id, "ownership pool signer key"),
        ] {
            validate_id(value, label)?;
        }
        validate_hash(
            &self.role_contract_sha256,
            "ownership pool Role Contract hash",
        )?;
        for member in &self.members {
            member.validate()?;
            if !is_subset(&member.allowed_work_class_ids, &self.allowed_work_class_ids)
                || !is_subset(
                    &member.allowed_responsibility_ids,
                    &self.allowed_responsibility_ids,
                )
                || !is_subset(
                    &member.allowed_application_pack_ids,
                    &self.allowed_application_pack_ids,
                )
                || !is_subset(
                    &member.allowed_integration_ids,
                    &self.allowed_integration_ids,
                )
                || !is_subset(&member.allowed_capability_ids, &self.allowed_capability_ids)
            {
                return authorization("ownership pool member expands approved pool scope");
            }
        }
        for (values, label) in [
            (&self.allowed_work_class_ids, "pool work classes"),
            (&self.allowed_responsibility_ids, "pool responsibilities"),
            (&self.allowed_application_pack_ids, "pool Application Packs"),
            (&self.allowed_integration_ids, "pool integrations"),
            (&self.allowed_capability_ids, "pool capabilities"),
        ] {
            validate_ids(values, label, false)?;
        }
        reject_duplicates(
            &self.automatic_reassignment_reasons,
            "pool transfer reasons",
        )?;
        validate_ids(&self.evidence_ids, "pool evidence", false)?;
        if self.approval_signature.len() != 128
            || !self.approval_signature.bytes().all(is_lower_hex)
        {
            return invalid("ownership pool signature encoding is invalid");
        }
        validate_hash(&self.pool_sha256, "ownership pool hash")?;
        if hash_without(self, &["pool_sha256"])? != self.pool_sha256 {
            return integrity("ownership pool self-hash differs");
        }
        reject_sensitive(self, "ownership pool")
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, WorkQueueError> {
        let mut value =
            serde_json::to_value(self).map_err(|error| WorkQueueError::Json(error.to_string()))?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| WorkQueueError::Json("ownership pool is not an object".to_owned()))?;
        object.remove("approval_signature");
        object.remove("pool_sha256");
        canonical_json_bytes(&value)
    }
}

/// Additive current owner overlay; the immutable generation-1 binding remains unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentCaseOwnershipStateV1 {
    pub schema_version: u32,
    pub ownership_state_id: String,
    pub case_id: String,
    pub case_contract_sha256: String,
    pub origin_ownership_sha256: String,
    pub ownership_generation: u64,
    pub current_role_instance_id: String,
    pub current_role_instance_sha256: String,
    pub current_role_contract_id: String,
    pub current_role_version: String,
    pub current_role_contract_sha256: String,
    pub current_delegation_sha256: String,
    pub organization_id: String,
    pub responsibility_id: String,
    pub work_class_id: String,
    pub previous_ownership_state_sha256: Option<String>,
    pub ownership_pool_sha256: String,
    pub queue_policy_sha256: String,
    pub assignment_reason: OwnershipAssignmentReasonV1,
    pub assigned_at_unix_seconds: u64,
    pub ownership_expires_at_unix_seconds: u64,
    pub active_lease_sha256: Option<String>,
    pub transfer_sha256: Option<String>,
    pub role_ledger_chain_head: String,
    pub case_ledger_chain_head: String,
    pub evidence_ids: Vec<String>,
    pub state_sha256: String,
}

impl CurrentCaseOwnershipStateV1 {
    pub fn validate(&self) -> Result<(), WorkQueueError> {
        if self.schema_version != WORK_QUEUE_SCHEMA_VERSION
            || self.ownership_generation == 0
            || self.ownership_generation > MAX_OWNERSHIP_GENERATIONS
            || self.assigned_at_unix_seconds == 0
            || self.ownership_expires_at_unix_seconds <= self.assigned_at_unix_seconds
            || (self.ownership_generation == 1)
                != (self.previous_ownership_state_sha256.is_none()
                    && self.transfer_sha256.is_none()
                    && self.assignment_reason == OwnershipAssignmentReasonV1::OriginBinding)
        {
            return invalid("current ownership generation, lifetime, or origin shape is invalid");
        }
        for (value, label) in [
            (&self.ownership_state_id, "ownership state ID"),
            (&self.case_id, "ownership Case ID"),
            (
                &self.current_role_instance_id,
                "current owner Role Instance",
            ),
            (
                &self.current_role_contract_id,
                "current owner Role Contract ID",
            ),
            (&self.current_role_version, "current owner Role version"),
            (&self.organization_id, "ownership organization"),
            (&self.responsibility_id, "ownership responsibility"),
            (&self.work_class_id, "ownership work class"),
        ] {
            validate_id(value, label)?;
        }
        for (value, label) in [
            (&self.case_contract_sha256, "ownership Case Contract hash"),
            (&self.origin_ownership_sha256, "origin ownership hash"),
            (
                &self.current_role_instance_sha256,
                "current Role Instance hash",
            ),
            (
                &self.current_role_contract_sha256,
                "current Role Contract hash",
            ),
            (&self.current_delegation_sha256, "current delegation hash"),
            (&self.ownership_pool_sha256, "ownership pool hash"),
            (&self.queue_policy_sha256, "Queue policy hash"),
            (&self.role_ledger_chain_head, "ownership Role ledger head"),
            (&self.case_ledger_chain_head, "ownership Case ledger head"),
            (&self.state_sha256, "ownership state hash"),
        ] {
            validate_hash(value, label)?;
        }
        for (value, label) in [
            (
                &self.previous_ownership_state_sha256,
                "previous ownership state hash",
            ),
            (&self.active_lease_sha256, "active lease hash"),
            (&self.transfer_sha256, "ownership transfer hash"),
        ] {
            if let Some(hash) = value {
                validate_hash(hash, label)?;
            }
        }
        validate_ids(&self.evidence_ids, "ownership state evidence", false)?;
        if hash_without(self, &["state_sha256"])? != self.state_sha256 {
            return integrity("current ownership state self-hash differs");
        }
        reject_sensitive(self, "current ownership state")
    }

    pub fn with_active_lease(&self, lease_sha256: Option<String>) -> Result<Self, WorkQueueError> {
        if let Some(hash) = &lease_sha256 {
            validate_hash(hash, "active lease hash")?;
        }
        let mut next = self.clone();
        next.active_lease_sha256 = lease_sha256;
        next.state_sha256 = hash_without(&next, &["state_sha256"])?;
        next.validate()?;
        Ok(next)
    }

    /// Refreshes only the current Role lifecycle hash and verified Role ledger head.
    pub fn refresh_role_binding(
        &self,
        role_instance: &RoleInstanceV1,
        role_ledger_chain_head: String,
    ) -> Result<Self, WorkQueueError> {
        self.validate()?;
        role_instance.validate_shape()?;
        validate_hash(&role_ledger_chain_head, "refreshed Role ledger head")?;
        if self.current_role_instance_id != role_instance.role_instance_id
            || self.current_role_contract_id != role_instance.role_contract_id
            || self.current_role_version != role_instance.role_version
            || self.current_role_contract_sha256 != role_instance.contract_sha256
            || self.current_delegation_sha256 != role_instance.delegation_sha256
            || self.organization_id != role_instance.organization_id
        {
            return authorization("Role lifecycle refresh changes current owner authority");
        }
        let mut next = self.clone();
        next.current_role_instance_sha256 = role_instance.instance_sha256.clone();
        next.role_ledger_chain_head = role_ledger_chain_head;
        next.state_sha256 = hash_without(&next, &["state_sha256"])?;
        next.validate()?;
        Ok(next)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn derive_initial_ownership(
    contract: &CaseContractV1,
    case_instance: &CaseInstanceV1,
    role_instance: &RoleInstanceV1,
    policy: &WorkQueuePolicyV1,
    pool: &CaseOwnershipPoolV1,
    assigned_at_unix_seconds: u64,
    role_ledger_chain_head: String,
    case_ledger_chain_head: String,
    mut evidence_ids: Vec<String>,
) -> Result<CurrentCaseOwnershipStateV1, WorkQueueError> {
    contract.validate()?;
    case_instance.validate_against(contract)?;
    role_instance.validate_shape()?;
    policy.validate()?;
    pool.validate()?;
    if contract.ownership_binding.ownership_generation != 1
        || role_instance.role_instance_id != contract.ownership_binding.role_instance_id
        || role_instance.instance_sha256.is_empty()
        || role_instance.current_status != RoleInstanceStatusV1::Active
        || assigned_at_unix_seconds >= role_instance.expires_at_unix_seconds
        || policy.organization_id != contract.organization_id
        || policy.role_contract_sha256 != contract.role_contract_sha256
        || !contains(&policy.allowed_work_class_ids, &contract.work_class_id)
        || !contains(
            &policy.allowed_role_instance_ids,
            &role_instance.role_instance_id,
        )
        || pool.organization_id != contract.organization_id
        || pool.role_contract_sha256 != contract.role_contract_sha256
        || !pool.members.iter().any(|member| {
            member.role_instance_id == role_instance.role_instance_id
                && member.role_instance_sha256 == role_instance.instance_sha256
        })
    {
        return authorization("origin ownership differs from Case, Role, policy, or pool");
    }
    normalize_ids(&mut evidence_ids, "origin ownership evidence", false)?;
    let mut state = CurrentCaseOwnershipStateV1 {
        schema_version: WORK_QUEUE_SCHEMA_VERSION,
        ownership_state_id: format!("ownership-state:{}:1", contract.case_id),
        case_id: contract.case_id.clone(),
        case_contract_sha256: contract.contract_sha256.clone(),
        origin_ownership_sha256: contract.ownership_binding.ownership_sha256.clone(),
        ownership_generation: 1,
        current_role_instance_id: role_instance.role_instance_id.clone(),
        current_role_instance_sha256: role_instance.instance_sha256.clone(),
        current_role_contract_id: role_instance.role_contract_id.clone(),
        current_role_version: role_instance.role_version.clone(),
        current_role_contract_sha256: role_instance.contract_sha256.clone(),
        current_delegation_sha256: role_instance.delegation_sha256.clone(),
        organization_id: contract.organization_id.clone(),
        responsibility_id: contract.responsibility_id.clone(),
        work_class_id: contract.work_class_id.clone(),
        previous_ownership_state_sha256: None,
        ownership_pool_sha256: pool.pool_sha256.clone(),
        queue_policy_sha256: policy.policy_sha256.clone(),
        assignment_reason: OwnershipAssignmentReasonV1::OriginBinding,
        assigned_at_unix_seconds,
        ownership_expires_at_unix_seconds: contract
            .ownership_binding
            .expires_at_unix_seconds
            .min(role_instance.expires_at_unix_seconds),
        active_lease_sha256: None,
        transfer_sha256: None,
        role_ledger_chain_head,
        case_ledger_chain_head,
        evidence_ids,
        state_sha256: ZERO_HASH.to_owned(),
    };
    state.state_sha256 = hash_without(&state, &["state_sha256"])?;
    state.validate()?;
    Ok(state)
}

/// Verifiable projection of one Case ledger state into one Queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkQueueEntryV1 {
    pub schema_version: u32,
    pub queue_entry_id: String,
    pub queue_id: String,
    pub enqueue_sequence: u64,
    pub case_id: String,
    pub case_contract_sha256: String,
    pub current_case_instance_sha256: String,
    pub case_lifecycle_generation: u64,
    pub current_lifecycle_status: CaseLifecycleStatusV1,
    pub current_ownership_state_sha256: String,
    pub current_role_instance_id: String,
    pub work_item_sha256: String,
    pub organization_id: String,
    pub work_class_id: String,
    pub responsibility_id: String,
    pub priority_class: WorkPriorityClassV1,
    pub received_at_unix_seconds: u64,
    pub opened_at_unix_seconds: u64,
    pub acknowledge_due_at_unix_seconds: u64,
    pub begin_due_at_unix_seconds: u64,
    pub resolve_due_at_unix_seconds: u64,
    pub escalation_due_at_unix_seconds: u64,
    pub active_block_sha256: Option<String>,
    pub active_lease_sha256: Option<String>,
    pub queue_lane: QueueLaneV1,
    pub last_reconciled_case_ledger_head: String,
    pub last_reconciled_role_ledger_head: String,
    pub intake_receipt_sha256: String,
    pub evidence_ids: Vec<String>,
    pub entry_sha256: String,
}

impl WorkQueueEntryV1 {
    pub fn validate(&self) -> Result<(), WorkQueueError> {
        if self.schema_version != WORK_QUEUE_SCHEMA_VERSION
            || self.enqueue_sequence == 0
            || self.case_lifecycle_generation == 0
            || self.received_at_unix_seconds == 0
            || self.opened_at_unix_seconds == 0
            || self.resolve_due_at_unix_seconds < self.begin_due_at_unix_seconds
        {
            return invalid("Queue entry schema, sequence, generation, or deadlines are invalid");
        }
        for (value, label) in [
            (&self.queue_entry_id, "Queue entry ID"),
            (&self.queue_id, "Queue ID"),
            (&self.case_id, "Queue Case ID"),
            (&self.current_role_instance_id, "Queue owner Role"),
            (&self.organization_id, "Queue organization"),
            (&self.work_class_id, "Queue work class"),
            (&self.responsibility_id, "Queue responsibility"),
        ] {
            validate_id(value, label)?;
        }
        for (value, label) in [
            (&self.case_contract_sha256, "Queue Case Contract hash"),
            (
                &self.current_case_instance_sha256,
                "Queue Case Instance hash",
            ),
            (
                &self.current_ownership_state_sha256,
                "Queue ownership state hash",
            ),
            (&self.work_item_sha256, "Queue Work Item hash"),
            (
                &self.last_reconciled_case_ledger_head,
                "Queue Case ledger head",
            ),
            (
                &self.last_reconciled_role_ledger_head,
                "Queue Role ledger head",
            ),
            (&self.intake_receipt_sha256, "Queue Intake receipt hash"),
            (&self.entry_sha256, "Queue entry hash"),
        ] {
            validate_hash(value, label)?;
        }
        for (value, label) in [
            (&self.active_block_sha256, "Queue active block hash"),
            (&self.active_lease_sha256, "Queue active lease hash"),
        ] {
            if let Some(hash) = value {
                validate_hash(hash, label)?;
            }
        }
        if (self.queue_lane == QueueLaneV1::Leased) != self.active_lease_sha256.is_some()
            || (self.queue_lane == QueueLaneV1::Blocked) != self.active_block_sha256.is_some()
            || (self.current_lifecycle_status == CaseLifecycleStatusV1::Terminal)
                != (self.queue_lane == QueueLaneV1::TerminalRemoved)
        {
            return integrity("Queue lane differs from Case, block, or lease state");
        }
        validate_ids(&self.evidence_ids, "Queue entry evidence", false)?;
        if hash_without(self, &["entry_sha256"])? != self.entry_sha256 {
            return integrity("Queue entry self-hash differs");
        }
        reject_sensitive(self, "Queue entry")
    }
}

#[allow(clippy::too_many_arguments)]
pub fn project_case_to_queue(
    policy: &WorkQueuePolicyV1,
    contract: &CaseContractV1,
    instance: &CaseInstanceV1,
    ownership: &CurrentCaseOwnershipStateV1,
    owner: &RoleInstanceV1,
    trusted_now_unix_seconds: u64,
    enqueue_sequence: u64,
    intake_receipt_sha256: String,
    role_ledger_chain_head: String,
    case_ledger_chain_head: String,
    mut evidence_ids: Vec<String>,
) -> Result<WorkQueueEntryV1, WorkQueueError> {
    policy.validate()?;
    contract.validate()?;
    instance.validate_against(contract)?;
    ownership.validate()?;
    owner.validate_shape()?;
    if enqueue_sequence == 0
        || policy.queue_id.is_empty()
        || policy.organization_id != contract.organization_id
        || ownership.case_id != contract.case_id
        || ownership.case_contract_sha256 != contract.contract_sha256
        || ownership.organization_id != contract.organization_id
        || ownership.work_class_id != contract.work_class_id
        || ownership.responsibility_id != contract.responsibility_id
        || ownership.case_ledger_chain_head != case_ledger_chain_head
        || ownership.role_ledger_chain_head != role_ledger_chain_head
        || ownership.current_role_instance_id != owner.role_instance_id
        || ownership.current_role_instance_sha256 != owner.instance_sha256
        || ownership.current_role_contract_sha256 != owner.contract_sha256
        || ownership.current_delegation_sha256 != owner.delegation_sha256
        || trusted_now_unix_seconds == 0
    {
        return integrity("Queue projection differs from current Case or ownership state");
    }
    validate_hash(&intake_receipt_sha256, "Intake receipt hash")?;
    normalize_ids(&mut evidence_ids, "Queue projection evidence", false)?;
    let queue_lane = classify_lane(instance, ownership, owner, trusted_now_unix_seconds);
    let mut entry = WorkQueueEntryV1 {
        schema_version: WORK_QUEUE_SCHEMA_VERSION,
        queue_entry_id: format!("queue-entry:{}", contract.case_id),
        queue_id: policy.queue_id.clone(),
        enqueue_sequence,
        case_id: contract.case_id.clone(),
        case_contract_sha256: contract.contract_sha256.clone(),
        current_case_instance_sha256: instance.instance_sha256.clone(),
        case_lifecycle_generation: instance.lifecycle_generation,
        current_lifecycle_status: instance.current_status,
        current_ownership_state_sha256: ownership.state_sha256.clone(),
        current_role_instance_id: ownership.current_role_instance_id.clone(),
        work_item_sha256: contract.source_work_item_sha256.clone(),
        organization_id: contract.organization_id.clone(),
        work_class_id: contract.work_class_id.clone(),
        responsibility_id: contract.responsibility_id.clone(),
        priority_class: contract.priority_class,
        received_at_unix_seconds: contract.sla_binding.received_at_unix_seconds,
        opened_at_unix_seconds: contract.opened_at_unix_seconds,
        acknowledge_due_at_unix_seconds: contract.sla_binding.acknowledge_due_at_unix_seconds,
        begin_due_at_unix_seconds: contract.sla_binding.begin_due_at_unix_seconds,
        resolve_due_at_unix_seconds: contract.sla_binding.resolve_due_at_unix_seconds,
        escalation_due_at_unix_seconds: contract.sla_binding.escalation_due_at_unix_seconds,
        active_block_sha256: instance.active_block_sha256.clone(),
        active_lease_sha256: ownership.active_lease_sha256.clone(),
        queue_lane,
        last_reconciled_case_ledger_head: case_ledger_chain_head,
        last_reconciled_role_ledger_head: role_ledger_chain_head,
        intake_receipt_sha256,
        evidence_ids,
        entry_sha256: ZERO_HASH.to_owned(),
    };
    entry.entry_sha256 = hash_without(&entry, &["entry_sha256"])?;
    entry.validate()?;
    Ok(entry)
}

fn classify_lane(
    instance: &CaseInstanceV1,
    ownership: &CurrentCaseOwnershipStateV1,
    owner: &RoleInstanceV1,
    trusted_now_unix_seconds: u64,
) -> QueueLaneV1 {
    if instance.current_status == CaseLifecycleStatusV1::Terminal {
        QueueLaneV1::TerminalRemoved
    } else if ownership.active_lease_sha256.is_some() {
        QueueLaneV1::Leased
    } else if owner.current_status != RoleInstanceStatusV1::Active
        || trusted_now_unix_seconds >= owner.expires_at_unix_seconds
        || trusted_now_unix_seconds >= ownership.ownership_expires_at_unix_seconds
    {
        QueueLaneV1::OwnerUnavailable
    } else {
        match instance.current_status {
            CaseLifecycleStatusV1::Opened | CaseLifecycleStatusV1::Active => QueueLaneV1::Ready,
            CaseLifecycleStatusV1::AwaitingClarification => QueueLaneV1::WaitingClarification,
            CaseLifecycleStatusV1::Blocked => QueueLaneV1::Blocked,
            CaseLifecycleStatusV1::AwaitingVerification => QueueLaneV1::AwaitingVerification,
            CaseLifecycleStatusV1::EscalationPending => QueueLaneV1::EscalationAttention,
            CaseLifecycleStatusV1::Terminal => QueueLaneV1::TerminalRemoved,
        }
    }
}

/// Deterministic, input-order-independent Queue projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkQueueSnapshotV1 {
    pub schema_version: u32,
    pub snapshot_id: String,
    pub queue_id: String,
    pub queue_policy_sha256: String,
    pub snapshot_sequence: u64,
    pub entries: Vec<WorkQueueEntryV1>,
    pub terminal_removed_count: u32,
    pub case_ledger_chain_head: String,
    pub role_ledger_chain_head: String,
    pub queue_ledger_chain_head: String,
    pub evidence_ids: Vec<String>,
    pub snapshot_sha256: String,
}

impl WorkQueueSnapshotV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        snapshot_id: String,
        policy: &WorkQueuePolicyV1,
        snapshot_sequence: u64,
        mut entries: Vec<WorkQueueEntryV1>,
        case_ledger_chain_head: String,
        role_ledger_chain_head: String,
        queue_ledger_chain_head: String,
        mut evidence_ids: Vec<String>,
    ) -> Result<Self, WorkQueueError> {
        policy.validate()?;
        if entries.len() > policy.maximum_queue_entries as usize {
            return crate::resource("Queue snapshot exceeds the policy maximum");
        }
        entries.sort_by(|left, right| left.case_id.cmp(&right.case_id));
        if entries
            .windows(2)
            .any(|pair| pair[0].case_id == pair[1].case_id)
        {
            return integrity("Queue snapshot contains duplicate Case entries");
        }
        let terminal_removed_count = entries
            .iter()
            .filter(|entry| entry.queue_lane == QueueLaneV1::TerminalRemoved)
            .count() as u32;
        entries.retain(|entry| entry.queue_lane != QueueLaneV1::TerminalRemoved);
        normalize_ids(&mut evidence_ids, "Queue snapshot evidence", false)?;
        let mut snapshot = Self {
            schema_version: WORK_QUEUE_SCHEMA_VERSION,
            snapshot_id,
            queue_id: policy.queue_id.clone(),
            queue_policy_sha256: policy.policy_sha256.clone(),
            snapshot_sequence,
            entries,
            terminal_removed_count,
            case_ledger_chain_head,
            role_ledger_chain_head,
            queue_ledger_chain_head,
            evidence_ids,
            snapshot_sha256: ZERO_HASH.to_owned(),
        };
        snapshot.snapshot_sha256 = hash_without(&snapshot, &["snapshot_sha256"])?;
        snapshot.validate()?;
        if canonical_json_bytes(&snapshot)?.len() as u64 > policy.maximum_snapshot_bytes {
            return crate::resource("Queue snapshot exceeds the serialized byte bound");
        }
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<(), WorkQueueError> {
        if self.schema_version != WORK_QUEUE_SCHEMA_VERSION
            || self.snapshot_sequence == 0
            || self.entries.len() > MAX_QUEUE_ENTRIES
            || self
                .entries
                .windows(2)
                .any(|pair| pair[0].case_id >= pair[1].case_id)
            || self
                .entries
                .iter()
                .any(|entry| entry.queue_lane == QueueLaneV1::TerminalRemoved)
        {
            return invalid("Queue snapshot schema, sequence, ordering, or size is invalid");
        }
        validate_id(&self.snapshot_id, "Queue snapshot ID")?;
        validate_id(&self.queue_id, "Queue snapshot queue ID")?;
        for (value, label) in [
            (&self.queue_policy_sha256, "Queue snapshot policy hash"),
            (
                &self.case_ledger_chain_head,
                "Queue snapshot Case ledger head",
            ),
            (
                &self.role_ledger_chain_head,
                "Queue snapshot Role ledger head",
            ),
            (
                &self.queue_ledger_chain_head,
                "Queue snapshot Queue ledger head",
            ),
            (&self.snapshot_sha256, "Queue snapshot hash"),
        ] {
            validate_hash(value, label)?;
        }
        for entry in &self.entries {
            entry.validate()?;
            if entry.queue_id != self.queue_id
                || entry.last_reconciled_case_ledger_head != self.case_ledger_chain_head
                || entry.last_reconciled_role_ledger_head != self.role_ledger_chain_head
            {
                return integrity("Queue entry ledger heads differ from snapshot");
            }
        }
        validate_ids(&self.evidence_ids, "Queue snapshot evidence", false)?;
        if hash_without(self, &["snapshot_sha256"])? != self.snapshot_sha256 {
            return integrity("Queue snapshot self-hash differs");
        }
        reject_sensitive(self, "Queue snapshot")
    }
}

/// Caller-supplied bounded one-shot Scheduler tick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkSchedulerTickV1 {
    pub schema_version: u32,
    pub tick_id: String,
    pub queue_id: String,
    pub queue_policy_sha256: String,
    pub queue_snapshot_sha256: String,
    pub trusted_now_unix_seconds: u64,
    pub operational_time_context: RoleOperationalTimeContextV1,
    pub current_role_ledger_head: String,
    pub current_case_ledger_head: String,
    pub current_queue_ledger_head: String,
    pub maximum_entries: u32,
    pub logical_operation_budget: u64,
    pub evidence_ids: Vec<String>,
    pub tick_sha256: String,
}

impl WorkSchedulerTickV1 {
    pub fn seal(mut self) -> Result<Self, WorkQueueError> {
        normalize_ids(&mut self.evidence_ids, "Scheduler tick evidence", false)?;
        self.tick_sha256 = hash_without(&self, &["tick_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), WorkQueueError> {
        if self.schema_version != WORK_QUEUE_SCHEMA_VERSION
            || self.trusted_now_unix_seconds == 0
            || self.maximum_entries == 0
            || self.maximum_entries as usize > MAX_QUEUE_ENTRIES
            || self.logical_operation_budget == 0
            || self.operational_time_context.observed_at_unix_seconds
                != self.trusted_now_unix_seconds
        {
            return invalid("Scheduler tick schema, time, or bounds are invalid");
        }
        validate_id(&self.tick_id, "Scheduler tick ID")?;
        validate_id(&self.queue_id, "Scheduler Queue ID")?;
        self.operational_time_context.validate()?;
        for (value, label) in [
            (&self.queue_policy_sha256, "Scheduler policy hash"),
            (&self.queue_snapshot_sha256, "Scheduler snapshot hash"),
            (&self.current_role_ledger_head, "Scheduler Role ledger head"),
            (&self.current_case_ledger_head, "Scheduler Case ledger head"),
            (
                &self.current_queue_ledger_head,
                "Scheduler Queue ledger head",
            ),
            (&self.tick_sha256, "Scheduler tick hash"),
        ] {
            validate_hash(value, label)?;
        }
        validate_ids(&self.evidence_ids, "Scheduler tick evidence", false)?;
        if hash_without(self, &["tick_sha256"])? != self.tick_sha256 {
            return integrity("Scheduler tick self-hash differs");
        }
        reject_sensitive(self, "Scheduler tick")
    }
}

/// Result of a bounded deterministic Scheduler tick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkSchedulerDecisionV1 {
    pub schema_version: u32,
    pub decision_id: String,
    pub tick_sha256: String,
    pub queue_snapshot_sha256: String,
    pub outcome: SchedulerOutcomeV1,
    pub selected_case_id: Option<String>,
    pub selected_queue_entry_sha256: Option<String>,
    pub selected_ownership_state_sha256: Option<String>,
    pub selected_role_instance_id: Option<String>,
    pub selected_lease_duration_seconds: Option<u64>,
    pub ordered_reason_codes: Vec<SchedulerReasonCodeV1>,
    pub examined_entry_count: u32,
    pub eligible_entry_count: u32,
    pub waiting_entry_count: u32,
    pub attention_entry_count: u32,
    pub terminal_removed_count: u32,
    pub logical_operations: u64,
    pub evidence_ids: Vec<String>,
    pub decision_sha256: String,
}

impl WorkSchedulerDecisionV1 {
    pub(crate) fn seal(mut self) -> Result<Self, WorkQueueError> {
        normalize_ids(&mut self.evidence_ids, "Scheduler decision evidence", false)?;
        self.decision_sha256 = hash_without(&self, &["decision_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), WorkQueueError> {
        if self.schema_version != WORK_QUEUE_SCHEMA_VERSION || self.logical_operations == 0 {
            return invalid("Scheduler decision schema or operation count is invalid");
        }
        validate_id(&self.decision_id, "Scheduler decision ID")?;
        validate_hash(&self.tick_sha256, "Scheduler decision tick hash")?;
        validate_hash(
            &self.queue_snapshot_sha256,
            "Scheduler decision snapshot hash",
        )?;
        let selected = self.outcome == SchedulerOutcomeV1::CaseSelected;
        if selected
            != (self.selected_case_id.is_some()
                && self.selected_queue_entry_sha256.is_some()
                && self.selected_ownership_state_sha256.is_some()
                && self.selected_role_instance_id.is_some()
                && self.selected_lease_duration_seconds.is_some())
        {
            return integrity("Scheduler selected fields differ from outcome");
        }
        if let Some(value) = &self.selected_case_id {
            validate_id(value, "selected Case ID")?;
        }
        if let Some(value) = &self.selected_role_instance_id {
            validate_id(value, "selected Role Instance ID")?;
        }
        for (value, label) in [
            (
                &self.selected_queue_entry_sha256,
                "selected Queue entry hash",
            ),
            (
                &self.selected_ownership_state_sha256,
                "selected ownership hash",
            ),
        ] {
            if let Some(hash) = value {
                validate_hash(hash, label)?;
            }
        }
        if self
            .selected_lease_duration_seconds
            .is_some_and(|value| value == 0 || value > MAX_LEASE_SECONDS)
        {
            return invalid("selected lease duration is invalid");
        }
        if self.ordered_reason_codes.is_empty()
            || self.ordered_reason_codes.len() > MAX_IDS
            || self.decision_sha256 == ZERO_HASH
        {
            return invalid("Scheduler reason or hash shape is invalid");
        }
        validate_ids(&self.evidence_ids, "Scheduler decision evidence", false)?;
        validate_hash(&self.decision_sha256, "Scheduler decision hash")?;
        if hash_without(self, &["decision_sha256"])? != self.decision_sha256 {
            return integrity("Scheduler decision self-hash differs");
        }
        reject_sensitive(self, "Scheduler decision")
    }
}

/// Exclusive bounded claim lease. It grants no adapter authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseLeaseV1 {
    pub schema_version: u32,
    pub claim_id: String,
    pub lease_id: String,
    pub case_id: String,
    pub queue_entry_sha256: String,
    pub scheduler_decision_sha256: String,
    pub current_ownership_state_sha256: String,
    pub role_instance_id: String,
    pub role_instance_sha256: String,
    pub role_contract_sha256: String,
    pub delegation_sha256: String,
    pub claim_sequence: u64,
    pub lease_epoch: u64,
    pub claimed_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub renewal_count: u32,
    pub lease_status: LeaseStatusV1,
    pub previous_lease_sha256: Option<String>,
    pub queue_ledger_chain_head: String,
    pub case_ledger_chain_head: String,
    pub role_ledger_chain_head: String,
    pub evidence_ids: Vec<String>,
    pub lease_sha256: String,
}

impl CaseLeaseV1 {
    pub fn validate(&self) -> Result<(), WorkQueueError> {
        if self.schema_version != WORK_QUEUE_SCHEMA_VERSION
            || self.claim_sequence == 0
            || self.lease_epoch == 0
            || self.claimed_at_unix_seconds == 0
            || self.expires_at_unix_seconds <= self.claimed_at_unix_seconds
            || self.expires_at_unix_seconds - self.claimed_at_unix_seconds > MAX_LEASE_SECONDS
        {
            return invalid("Case lease schema, sequence, epoch, or lifetime is invalid");
        }
        for (value, label) in [
            (&self.claim_id, "claim ID"),
            (&self.lease_id, "lease ID"),
            (&self.case_id, "lease Case ID"),
            (&self.role_instance_id, "lease Role Instance ID"),
        ] {
            validate_id(value, label)?;
        }
        for (value, label) in [
            (&self.queue_entry_sha256, "lease Queue entry hash"),
            (
                &self.scheduler_decision_sha256,
                "lease Scheduler decision hash",
            ),
            (&self.current_ownership_state_sha256, "lease ownership hash"),
            (&self.role_instance_sha256, "lease Role Instance hash"),
            (&self.role_contract_sha256, "lease Role Contract hash"),
            (&self.delegation_sha256, "lease delegation hash"),
            (&self.queue_ledger_chain_head, "lease Queue ledger head"),
            (&self.case_ledger_chain_head, "lease Case ledger head"),
            (&self.role_ledger_chain_head, "lease Role ledger head"),
            (&self.lease_sha256, "lease hash"),
        ] {
            validate_hash(value, label)?;
        }
        if let Some(hash) = &self.previous_lease_sha256 {
            validate_hash(hash, "previous lease hash")?;
        }
        validate_ids(&self.evidence_ids, "lease evidence", false)?;
        if hash_without(self, &["lease_sha256"])? != self.lease_sha256 {
            return integrity("Case lease self-hash differs");
        }
        reject_sensitive(self, "Case lease")
    }

    #[must_use]
    pub const fn is_active_at(&self, now_unix_seconds: u64) -> bool {
        matches!(
            self.lease_status,
            LeaseStatusV1::Active | LeaseStatusV1::Renewed
        ) && now_unix_seconds < self.expires_at_unix_seconds
    }
}

/// Audited exact ownership transfer request/result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseOwnershipTransferV1 {
    pub schema_version: u32,
    pub transfer_id: String,
    pub case_id: String,
    pub case_contract_sha256: String,
    pub current_case_instance_sha256: String,
    pub current_queue_entry_sha256: String,
    pub previous_ownership_state_sha256: String,
    pub source_role_instance_id: String,
    pub source_role_instance_sha256: String,
    pub target_role_instance_id: String,
    pub target_role_instance_sha256: String,
    pub organization_id: String,
    pub role_contract_id: String,
    pub role_version: String,
    pub role_contract_sha256: String,
    pub responsibility_id: String,
    pub work_class_id: String,
    pub ownership_pool_sha256: String,
    pub transfer_reason: AutomaticReassignmentReasonV1,
    pub transfer_at_unix_seconds: u64,
    pub current_case_ledger_head: String,
    pub current_queue_ledger_head: String,
    pub current_role_ledger_head: String,
    pub next_ownership_generation: u64,
    pub evidence_ids: Vec<String>,
    pub transfer_sha256: String,
}

impl CaseOwnershipTransferV1 {
    pub fn seal(mut self) -> Result<Self, WorkQueueError> {
        normalize_ids(&mut self.evidence_ids, "ownership transfer evidence", false)?;
        self.transfer_sha256 = hash_without(&self, &["transfer_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), WorkQueueError> {
        if self.schema_version != WORK_QUEUE_SCHEMA_VERSION
            || self.transfer_at_unix_seconds == 0
            || self.next_ownership_generation < 2
            || self.next_ownership_generation > MAX_OWNERSHIP_GENERATIONS
            || self.source_role_instance_id == self.target_role_instance_id
        {
            return invalid(
                "ownership transfer schema, time, generation, or identities are invalid",
            );
        }
        for (value, label) in [
            (&self.transfer_id, "transfer ID"),
            (&self.case_id, "transfer Case ID"),
            (&self.source_role_instance_id, "source Role Instance"),
            (&self.target_role_instance_id, "target Role Instance"),
            (&self.organization_id, "transfer organization"),
            (&self.role_contract_id, "transfer Role Contract ID"),
            (&self.role_version, "transfer Role version"),
            (&self.responsibility_id, "transfer responsibility"),
            (&self.work_class_id, "transfer work class"),
        ] {
            validate_id(value, label)?;
        }
        for (value, label) in [
            (&self.case_contract_sha256, "transfer Case Contract hash"),
            (
                &self.current_case_instance_sha256,
                "transfer Case Instance hash",
            ),
            (
                &self.current_queue_entry_sha256,
                "transfer Queue entry hash",
            ),
            (
                &self.previous_ownership_state_sha256,
                "transfer previous ownership hash",
            ),
            (
                &self.source_role_instance_sha256,
                "transfer source Role hash",
            ),
            (
                &self.target_role_instance_sha256,
                "transfer target Role hash",
            ),
            (&self.role_contract_sha256, "transfer Role Contract hash"),
            (&self.ownership_pool_sha256, "transfer pool hash"),
            (&self.current_case_ledger_head, "transfer Case ledger head"),
            (
                &self.current_queue_ledger_head,
                "transfer Queue ledger head",
            ),
            (&self.current_role_ledger_head, "transfer Role ledger head"),
            (&self.transfer_sha256, "transfer hash"),
        ] {
            validate_hash(value, label)?;
        }
        validate_ids(&self.evidence_ids, "ownership transfer evidence", false)?;
        if hash_without(self, &["transfer_sha256"])? != self.transfer_sha256 {
            return integrity("ownership transfer self-hash differs");
        }
        reject_sensitive(self, "ownership transfer")
    }
}

/// Non-executable planner handoff bound to one active lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseWorkGrantV1 {
    pub schema_version: u32,
    pub grant_id: String,
    pub case_id: String,
    pub current_case_instance_sha256: String,
    pub case_contract_sha256: String,
    pub ownership_state_sha256: String,
    pub lease_sha256: String,
    pub selected_role_instance_id: String,
    pub unresolved_requirement_ids: Vec<String>,
    pub allowed_application_pack_ids: Vec<String>,
    pub allowed_integration_ids: Vec<String>,
    pub allowed_capability_ids: Vec<String>,
    pub semantic_target_ids: Vec<String>,
    pub valid_from_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub one_time_grant_sequence: u64,
    pub evidence_ids: Vec<String>,
    pub grant_sha256: String,
}

impl CaseWorkGrantV1 {
    pub fn validate(&self) -> Result<(), WorkQueueError> {
        if self.schema_version != WORK_QUEUE_SCHEMA_VERSION
            || self.valid_from_unix_seconds == 0
            || self.expires_at_unix_seconds <= self.valid_from_unix_seconds
            || self.one_time_grant_sequence == 0
        {
            return invalid("Case Work Grant schema, lifetime, or sequence is invalid");
        }
        for (value, label) in [
            (&self.grant_id, "Work Grant ID"),
            (&self.case_id, "Work Grant Case ID"),
            (&self.selected_role_instance_id, "Work Grant Role Instance"),
        ] {
            validate_id(value, label)?;
        }
        for (value, label) in [
            (
                &self.current_case_instance_sha256,
                "Work Grant Case Instance hash",
            ),
            (&self.case_contract_sha256, "Work Grant Case Contract hash"),
            (&self.ownership_state_sha256, "Work Grant ownership hash"),
            (&self.lease_sha256, "Work Grant lease hash"),
            (&self.grant_sha256, "Work Grant hash"),
        ] {
            validate_hash(value, label)?;
        }
        for (values, label, empty) in [
            (
                &self.unresolved_requirement_ids,
                "Work Grant requirements",
                true,
            ),
            (
                &self.allowed_application_pack_ids,
                "Work Grant Application Packs",
                false,
            ),
            (
                &self.allowed_integration_ids,
                "Work Grant integrations",
                false,
            ),
            (
                &self.allowed_capability_ids,
                "Work Grant capabilities",
                false,
            ),
            (
                &self.semantic_target_ids,
                "Work Grant semantic targets",
                true,
            ),
            (&self.evidence_ids, "Work Grant evidence", false),
        ] {
            validate_ids(values, label, empty)?;
        }
        if hash_without(self, &["grant_sha256"])? != self.grant_sha256 {
            return integrity("Case Work Grant self-hash differs");
        }
        reject_sensitive(self, "Case Work Grant")
    }
}

/// Hash-only operation receipt used by protected persistence and recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkQueueOperationReceiptV1 {
    pub schema_version: u32,
    pub receipt_id: String,
    pub operation_kind: QueueOperationKindV1,
    pub queue_id: String,
    pub case_id: String,
    pub source_intake_receipt_sha256: String,
    pub queue_entry_sha256: Option<String>,
    pub scheduler_decision_sha256: Option<String>,
    pub lease_sha256: Option<String>,
    pub ownership_state_sha256: Option<String>,
    pub ownership_transfer_sha256: Option<String>,
    pub work_grant_sha256: Option<String>,
    pub role_ledger_chain_head: String,
    pub case_ledger_chain_head: String,
    pub queue_ledger_chain_head: String,
    pub recorded_at_unix_seconds: u64,
    pub evidence_ids: Vec<String>,
    pub receipt_sha256: String,
}

impl WorkQueueOperationReceiptV1 {
    pub fn seal(mut self) -> Result<Self, WorkQueueError> {
        normalize_ids(&mut self.evidence_ids, "Queue receipt evidence", false)?;
        self.receipt_sha256 = hash_without(&self, &["receipt_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), WorkQueueError> {
        if self.schema_version != WORK_QUEUE_SCHEMA_VERSION || self.recorded_at_unix_seconds == 0 {
            return invalid("Queue operation receipt schema or time is invalid");
        }
        for (value, label) in [
            (&self.receipt_id, "Queue receipt ID"),
            (&self.queue_id, "Queue receipt queue ID"),
            (&self.case_id, "Queue receipt Case ID"),
        ] {
            validate_id(value, label)?;
        }
        for (value, label) in [
            (
                &self.source_intake_receipt_sha256,
                "source Intake receipt hash",
            ),
            (
                &self.role_ledger_chain_head,
                "Queue receipt Role ledger head",
            ),
            (
                &self.case_ledger_chain_head,
                "Queue receipt Case ledger head",
            ),
            (
                &self.queue_ledger_chain_head,
                "Queue receipt Queue ledger head",
            ),
            (&self.receipt_sha256, "Queue receipt hash"),
        ] {
            validate_hash(value, label)?;
        }
        for (value, label) in [
            (&self.queue_entry_sha256, "Queue receipt entry hash"),
            (
                &self.scheduler_decision_sha256,
                "Queue receipt decision hash",
            ),
            (&self.lease_sha256, "Queue receipt lease hash"),
            (&self.ownership_state_sha256, "Queue receipt ownership hash"),
            (
                &self.ownership_transfer_sha256,
                "Queue receipt transfer hash",
            ),
            (&self.work_grant_sha256, "Queue receipt grant hash"),
        ] {
            if let Some(hash) = value {
                validate_hash(hash, label)?;
            }
        }
        validate_ids(&self.evidence_ids, "Queue receipt evidence", false)?;
        if hash_without(self, &["receipt_sha256"])? != self.receipt_sha256 {
            return integrity("Queue operation receipt self-hash differs");
        }
        reject_sensitive(self, "Queue operation receipt")
    }
}

pub(crate) fn validate_id(value: &str, label: &str) -> Result<(), WorkQueueError> {
    if value.is_empty()
        || value.len() > 128
        || value == "*"
        || value.eq_ignore_ascii_case("all")
        || value.eq_ignore_ascii_case("any")
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
    {
        return invalid(format!("{label} is not a bounded explicit identifier"));
    }
    Ok(())
}

pub(crate) fn validate_hash(value: &str, label: &str) -> Result<(), WorkQueueError> {
    if value.len() != 71 || !value.starts_with("sha256:") || !value[7..].bytes().all(is_lower_hex) {
        return invalid(format!("{label} is not a lowercase sha256 digest"));
    }
    Ok(())
}

pub(crate) fn normalize_ids(
    values: &mut [String],
    label: &str,
    allow_empty: bool,
) -> Result<(), WorkQueueError> {
    values.sort();
    validate_ids(values, label, allow_empty)
}

pub(crate) fn validate_ids(
    values: &[String],
    label: &str,
    allow_empty: bool,
) -> Result<(), WorkQueueError> {
    if values.len() > MAX_EVIDENCE_IDS
        || (!allow_empty && values.is_empty())
        || !values.windows(2).all(|pair| pair[0] < pair[1])
    {
        return invalid(format!(
            "{label} is empty, duplicated, unsorted, or oversized"
        ));
    }
    for value in values {
        validate_id(value, label)?;
    }
    Ok(())
}

pub(crate) fn reject_sensitive<T: Serialize>(value: &T, label: &str) -> Result<(), WorkQueueError> {
    let serialized = String::from_utf8(canonical_json_bytes(value)?)
        .map_err(|error| WorkQueueError::Json(error.to_string()))?
        .to_ascii_lowercase();
    for marker in [
        "raw_payload",
        "raw_instruction",
        "natural_language_instruction",
        "goal_spec",
        "action_proposal",
        "locator",
        "selector",
        "credential",
        "password",
        "private_key",
        "activation_token",
        "adapter_input",
        "executable_command",
        "authorization: bearer",
        "c:\\\\",
    ] {
        if serialized.contains(marker) {
            return integrity(format!(
                "{label} contains forbidden authority or sensitive material"
            ));
        }
    }
    Ok(())
}

pub(crate) fn is_subset(subset: &[String], superset: &[String]) -> bool {
    subset
        .iter()
        .all(|value| superset.binary_search(value).is_ok())
}

pub(crate) fn contains(values: &[String], value: &str) -> bool {
    values
        .binary_search_by(|candidate| candidate.as_str().cmp(value))
        .is_ok()
}

fn reject_duplicates<T: Ord>(values: &[T], label: &str) -> Result<(), WorkQueueError> {
    if values.len() > MAX_IDS || values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return invalid(format!("{label} is duplicated, unsorted, or oversized"));
    }
    Ok(())
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn hex_decode_array<const N: usize>(value: &str) -> Result<[u8; N], WorkQueueError> {
    if value.len() != N * 2 || !value.bytes().all(is_lower_hex) {
        return invalid("signature has invalid lowercase hexadecimal encoding");
    }
    let mut bytes = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Result<u8, WorkQueueError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => invalid("signature contains a non-hexadecimal byte"),
    }
}

pub(crate) fn ensure_unique_ids<'a>(
    values: impl Iterator<Item = &'a str>,
    label: &str,
) -> Result<(), WorkQueueError> {
    let mut set = BTreeSet::new();
    for value in values {
        if !set.insert(value) {
            return integrity(format!("{label} contains duplicate identifiers"));
        }
    }
    Ok(())
}

pub(crate) fn stale<T>(message: impl Into<String>) -> Result<T, WorkQueueError> {
    replay(message)
}
