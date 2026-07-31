use crate::{
    pretty_json_bytes, read_bounded, sha256_bytes, validate_hash, validate_token, write_new,
    DesktopError, WindowsDeploymentAuditEvent, WindowsDeploymentAuditEventKind,
    WindowsDeploymentAuditLedger, WindowsDeploymentAuditStatus,
};
use d2i_cognitive_recovery::{
    canonical_sha256, classify_recovery_trigger, decide_recovery, ClarificationRequestV1,
    ClarificationResponseV1, EscalationRequestV1, FreshRecoveryCycleEvidenceV1,
    FreshRecoveryCycleRequestV1, RecoveryBudgetV1, RecoveryClassificationV1,
    RecoveryCycleOutcomeV1, RecoveryCycleResultV1, RecoveryDecisionContextV1,
    RecoveryDecisionKindV1, RecoveryDecisionV1, RecoveryHistoryEntryV1, RecoveryHistoryOutcomeV1,
    RecoveryHistoryV1, RecoveryPolicyProfileV1, RecoveryTriggerV1, RecoveryVerificationVerdictV1,
    ReplanRequestV1, ReplanResultV1, RECOVERY_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

const MANIFEST_FILE: &str = "cognitive-recovery-ledger-manifest.json";
const STATE_FILE: &str = "cognitive-recovery-ledger-state.json";
const LOCK_FILE: &str = ".cognitive-recovery-ledger.lock";
const MAX_LEDGER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_LEDGER_RECORDS: u64 = 4_096;
const ZERO_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Closed logical event retained by the durable recovery ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryLedgerEventKindV1 {
    TriggerAccepted,
    Classified,
    Decided,
    FreshCycleRequested,
    FreshCycleCompleted,
    ReobservationCompleted,
    ReplanAccepted,
    ClarificationPending,
    ClarificationConsumed,
    Escalated,
    Terminal,
    Aborted,
}

/// One immutable, hash-chained recovery record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryLedgerRecordV1 {
    pub schema_version: u32,
    pub sequence: u64,
    pub ledger_id: String,
    pub session_id: String,
    pub goal_id: String,
    pub event_kind: RecoveryLedgerEventKindV1,
    pub trigger_sha256: Option<String>,
    pub classification_sha256: Option<String>,
    pub decision_sha256: Option<String>,
    pub clarification_response_sha256: Option<String>,
    pub result_sha256: Option<String>,
    pub budget_after: Option<RecoveryBudgetV1>,
    pub history_after: Option<RecoveryHistoryV1>,
    pub artifact_hashes: BTreeMap<String, String>,
    pub audit_record_hash: String,
    pub terminal: bool,
    pub poisoned: bool,
    pub recorded_at_unix_ms: u64,
    pub previous_record_hash: String,
    pub record_hash: String,
}

#[derive(Serialize)]
struct RecoveryLedgerRecordPayload<'a> {
    schema_version: u32,
    sequence: u64,
    ledger_id: &'a str,
    session_id: &'a str,
    goal_id: &'a str,
    event_kind: RecoveryLedgerEventKindV1,
    trigger_sha256: &'a Option<String>,
    classification_sha256: &'a Option<String>,
    decision_sha256: &'a Option<String>,
    clarification_response_sha256: &'a Option<String>,
    result_sha256: &'a Option<String>,
    budget_after: &'a Option<RecoveryBudgetV1>,
    history_after: &'a Option<RecoveryHistoryV1>,
    artifact_hashes: &'a BTreeMap<String, String>,
    audit_record_hash: &'a str,
    terminal: bool,
    poisoned: bool,
    recorded_at_unix_ms: u64,
    previous_record_hash: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryLedgerManifestV1 {
    schema_version: u32,
    ledger_id: String,
    session_id: String,
    goal_id: String,
    maximum_records: u64,
    created_at_unix_ms: u64,
    root_security_descriptor_hash: String,
    manifest_security_descriptor_hash: String,
    state_security_descriptor_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryLedgerSnapshotV1 {
    schema_version: u32,
    ledger_id: String,
    session_id: String,
    goal_id: String,
    records: Vec<RecoveryLedgerRecordV1>,
}

/// Fully replayed durable recovery state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryLedgerVerificationV1 {
    pub ledger_id: String,
    pub session_id: String,
    pub goal_id: String,
    pub record_count: u64,
    pub terminal_record_hash: String,
    pub latest_budget: Option<RecoveryBudgetV1>,
    pub latest_history: Option<RecoveryHistoryV1>,
    pub consumed_trigger_hashes: Vec<String>,
    pub consumed_decision_hashes: Vec<String>,
    pub consumed_clarification_response_hashes: Vec<String>,
    pub latest_recorded_at_unix_ms: u64,
    pub terminal: bool,
    pub poisoned: bool,
}

/// Protected durable append handle for one recovery goal/session.
#[derive(Debug)]
pub struct RecoveryLedgerV1 {
    root: PathBuf,
    manifest: RecoveryLedgerManifestV1,
    verification: RecoveryLedgerVerificationV1,
}

impl RecoveryLedgerV1 {
    /// Opens and fully verifies ACLs, records, replay sets, budgets, and history.
    pub fn open(root: &Path) -> Result<Self, DesktopError> {
        let manifest = load_manifest(root)?;
        let verification = verify_recovery_ledger(root)?;
        Ok(Self {
            root: root.to_path_buf(),
            manifest,
            verification,
        })
    }

    /// Returns the current verified state restored from disk.
    #[must_use]
    pub const fn verification(&self) -> &RecoveryLedgerVerificationV1 {
        &self.verification
    }

    /// Appends one logical record through a crash-safe atomic snapshot replace.
    pub fn append(&mut self, mut record: RecoveryLedgerRecordV1) -> Result<String, DesktopError> {
        let lock = RecoveryLedgerLock::acquire(&self.root)?;
        let latest = verify_recovery_ledger(&self.root)?;
        if latest != self.verification {
            return Err(DesktopError::Replay(
                "recovery ledger changed after it was opened".to_owned(),
            ));
        }
        if latest.record_count >= self.manifest.maximum_records || latest.terminal {
            return Err(DesktopError::AccessDenied(
                "recovery ledger is terminal or exhausted".to_owned(),
            ));
        }
        record.schema_version = RECOVERY_SCHEMA_VERSION;
        record.sequence = latest.record_count.saturating_add(1);
        record.ledger_id = self.manifest.ledger_id.clone();
        record.session_id = self.manifest.session_id.clone();
        record.goal_id = self.manifest.goal_id.clone();
        record.previous_record_hash = latest.terminal_record_hash.clone();
        record.record_hash = ZERO_HASH.to_owned();
        validate_record_transition(&record, &latest)?;
        record.record_hash = record_hash(&record)?;
        validate_record(&record)?;

        let mut snapshot = load_snapshot(&self.root)?;
        snapshot.records.push(record);
        atomic_replace_state(&self.root, &snapshot)?;
        let verified = verify_recovery_ledger(&self.root)?;
        if verified.record_count != latest.record_count.saturating_add(1) {
            return Err(DesktopError::Integrity(
                "recovery ledger atomic append did not advance exactly once".to_owned(),
            ));
        }
        self.verification = verified;
        drop(lock);
        Ok(self.verification.terminal_record_hash.clone())
    }
}

/// Initializes one protected recovery ledger.
pub fn initialize_recovery_ledger(
    root: &Path,
    ledger_id: &str,
    session_id: &str,
    goal_id: &str,
    maximum_records: u64,
    created_at_unix_ms: u64,
) -> Result<RecoveryLedgerV1, DesktopError> {
    for (value, label) in [
        (ledger_id, "recovery ledger_id"),
        (session_id, "recovery session_id"),
        (goal_id, "recovery goal_id"),
    ] {
        validate_token(value, label)?;
    }
    if maximum_records == 0 || maximum_records > MAX_LEDGER_RECORDS || created_at_unix_ms == 0 {
        return Err(DesktopError::Invalid(
            "recovery ledger initialization bounds are invalid".to_owned(),
        ));
    }
    std::fs::create_dir(root).map_err(|error| DesktopError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    let initialized = (|| {
        let root_security_descriptor_hash = harden_and_hash(root, "recovery ledger root")?;
        let manifest_path = root.join(MANIFEST_FILE);
        let state_path = root.join(STATE_FILE);
        write_new(&manifest_path, b"")?;
        write_new(&state_path, b"")?;
        let manifest_security_descriptor_hash =
            harden_and_hash(&manifest_path, "recovery ledger manifest")?;
        let state_security_descriptor_hash = harden_and_hash(&state_path, "recovery ledger state")?;
        let snapshot = RecoveryLedgerSnapshotV1 {
            schema_version: RECOVERY_SCHEMA_VERSION,
            ledger_id: ledger_id.to_owned(),
            session_id: session_id.to_owned(),
            goal_id: goal_id.to_owned(),
            records: Vec::new(),
        };
        overwrite_existing(&state_path, &pretty_json_bytes(&snapshot)?)?;
        let manifest = RecoveryLedgerManifestV1 {
            schema_version: RECOVERY_SCHEMA_VERSION,
            ledger_id: ledger_id.to_owned(),
            session_id: session_id.to_owned(),
            goal_id: goal_id.to_owned(),
            maximum_records,
            created_at_unix_ms,
            root_security_descriptor_hash,
            manifest_security_descriptor_hash,
            state_security_descriptor_hash,
        };
        overwrite_existing(&manifest_path, &pretty_json_bytes(&manifest)?)?;
        RecoveryLedgerV1::open(root)
    })();
    if initialized.is_err() {
        let _ = std::fs::remove_dir_all(root);
    }
    initialized
}

/// Fully verifies protected storage and reconstructs recovery state.
pub fn verify_recovery_ledger(root: &Path) -> Result<RecoveryLedgerVerificationV1, DesktopError> {
    let manifest = load_manifest(root)?;
    verify_storage_security(root, &manifest)?;
    let snapshot = load_snapshot(root)?;
    if snapshot.schema_version != RECOVERY_SCHEMA_VERSION
        || snapshot.ledger_id != manifest.ledger_id
        || snapshot.session_id != manifest.session_id
        || snapshot.goal_id != manifest.goal_id
        || snapshot.records.len() as u64 > manifest.maximum_records
    {
        return Err(DesktopError::Integrity(
            "recovery ledger snapshot identity or bounds differ".to_owned(),
        ));
    }

    let created_at_unix_ms = manifest.created_at_unix_ms;
    let mut verification = RecoveryLedgerVerificationV1 {
        ledger_id: manifest.ledger_id,
        session_id: manifest.session_id,
        goal_id: manifest.goal_id,
        record_count: 0,
        terminal_record_hash: ZERO_HASH.to_owned(),
        latest_budget: None,
        latest_history: None,
        consumed_trigger_hashes: Vec::new(),
        consumed_decision_hashes: Vec::new(),
        consumed_clarification_response_hashes: Vec::new(),
        latest_recorded_at_unix_ms: created_at_unix_ms,
        terminal: false,
        poisoned: false,
    };
    for record in &snapshot.records {
        validate_record_transition(record, &verification)?;
        if record.sequence != verification.record_count.saturating_add(1)
            || record.previous_record_hash != verification.terminal_record_hash
            || record.record_hash != record_hash(record)?
        {
            return Err(DesktopError::Integrity(
                "recovery ledger sequence or hash chain differs".to_owned(),
            ));
        }
        consume_once(
            &mut verification.consumed_trigger_hashes,
            &record.trigger_sha256,
            "trigger",
        )?;
        consume_once(
            &mut verification.consumed_decision_hashes,
            &record.decision_sha256,
            "decision",
        )?;
        consume_once(
            &mut verification.consumed_clarification_response_hashes,
            &record.clarification_response_sha256,
            "clarification response",
        )?;
        if let Some(value) = &record.budget_after {
            verification.latest_budget = Some(value.clone());
        }
        if let Some(value) = &record.history_after {
            verification.latest_history = Some(value.clone());
        }
        verification.record_count = record.sequence;
        verification.terminal_record_hash = record.record_hash.clone();
        verification.latest_recorded_at_unix_ms = record.recorded_at_unix_ms;
        verification.terminal = record.terminal;
        verification.poisoned |= record.poisoned;
    }
    Ok(verification)
}

/// Public coordinator state; transitions are monotonic and fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CognitiveRecoveryCoordinatorStateV1 {
    Ready,
    Begun,
    Classified,
    Decided,
    HandoffPending,
    Executing,
    NextCycle,
    Terminal,
    Poisoned,
}

/// Desktop-owned recovery state machine with durable replay protection.
#[derive(Debug)]
pub struct CognitiveRecoveryCoordinatorV1 {
    goal_id: String,
    current_plan_generation_id: String,
    budget: RecoveryBudgetV1,
    history: RecoveryHistoryV1,
    profile: RecoveryPolicyProfileV1,
    ledger: RecoveryLedgerV1,
    audit: WindowsDeploymentAuditLedger,
    state: CognitiveRecoveryCoordinatorStateV1,
    trigger: Option<RecoveryTriggerV1>,
    classification: Option<RecoveryClassificationV1>,
    decision: Option<RecoveryDecisionV1>,
    pending_clarification: Option<ClarificationRequestV1>,
    last_recorded_at_unix_ms: u64,
}

impl CognitiveRecoveryCoordinatorV1 {
    /// Restores one coordinator only when durable budget/history match exactly.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        goal_id: String,
        current_plan_generation_id: String,
        budget: RecoveryBudgetV1,
        history: RecoveryHistoryV1,
        profile: RecoveryPolicyProfileV1,
        ledger: RecoveryLedgerV1,
        audit: WindowsDeploymentAuditLedger,
    ) -> Result<Self, DesktopError> {
        validate_token(&goal_id, "recovery coordinator goal_id")?;
        validate_token(
            &current_plan_generation_id,
            "recovery coordinator plan generation",
        )?;
        budget.validate()?;
        history.validate()?;
        profile.validate()?;
        let durable = ledger.verification();
        if durable.goal_id != goal_id
            || budget.goal_id != goal_id
            || history.goal_id != goal_id
            || durable
                .latest_budget
                .as_ref()
                .is_some_and(|value| value != &budget)
            || durable
                .latest_history
                .as_ref()
                .is_some_and(|value| value != &history)
            || durable.terminal
            || durable.poisoned
        {
            return Err(DesktopError::Integrity(
                "recovery coordinator state differs from durable ledger".to_owned(),
            ));
        }
        let last_recorded_at_unix_ms = durable.latest_recorded_at_unix_ms;
        Ok(Self {
            goal_id,
            current_plan_generation_id,
            budget,
            history,
            profile,
            ledger,
            audit,
            state: CognitiveRecoveryCoordinatorStateV1::Ready,
            trigger: None,
            classification: None,
            decision: None,
            pending_clarification: None,
            last_recorded_at_unix_ms,
        })
    }

    /// Returns the current state-machine state.
    #[must_use]
    pub const fn state(&self) -> CognitiveRecoveryCoordinatorStateV1 {
        self.state
    }

    /// Returns the current immutable budget snapshot.
    #[must_use]
    pub const fn budget(&self) -> &RecoveryBudgetV1 {
        &self.budget
    }

    /// Returns the current immutable recovery history.
    #[must_use]
    pub const fn history(&self) -> &RecoveryHistoryV1 {
        &self.history
    }

    /// Begins recovery after duplicate-trigger and exact lifecycle checks.
    pub fn begin(
        &mut self,
        trigger: RecoveryTriggerV1,
        recorded_at_unix_ms: u64,
    ) -> Result<(), DesktopError> {
        self.require_state(CognitiveRecoveryCoordinatorStateV1::Ready)?;
        trigger.validate()?;
        if trigger.goal_id != self.goal_id
            || trigger
                .plan_generation_id
                .as_ref()
                .is_some_and(|value| value != &self.current_plan_generation_id)
            || self
                .ledger
                .verification()
                .consumed_trigger_hashes
                .contains(&trigger.trigger_sha256)
        {
            return Err(DesktopError::Replay(
                "recovery trigger is duplicated or bound to another goal/plan".to_owned(),
            ));
        }
        let artifacts = BTreeMap::from([("trigger".to_owned(), trigger.trigger_sha256.clone())]);
        let audit_hash = self.append_audit(
            WindowsDeploymentAuditEventKind::RecoveryTriggerAccepted,
            WindowsDeploymentAuditStatus::Succeeded,
            "trigger-accepted",
            artifacts.clone(),
            recorded_at_unix_ms,
        )?;
        self.append_ledger(
            RecoveryLedgerEventKindV1::TriggerAccepted,
            Some(trigger.trigger_sha256.clone()),
            None,
            None,
            None,
            None,
            None,
            None,
            artifacts,
            audit_hash,
            false,
            false,
            recorded_at_unix_ms,
        )?;
        self.trigger = Some(trigger);
        self.state = CognitiveRecoveryCoordinatorStateV1::Begun;
        Ok(())
    }

    /// Applies the pure deterministic classifier with unsafe priority.
    pub fn classify(
        &mut self,
        recorded_at_unix_ms: u64,
    ) -> Result<&RecoveryClassificationV1, DesktopError> {
        self.require_state(CognitiveRecoveryCoordinatorStateV1::Begun)?;
        let trigger = self
            .trigger
            .as_ref()
            .ok_or_else(|| DesktopError::Integrity("recovery trigger is absent".to_owned()))?;
        let classification = classify_recovery_trigger(trigger)?;
        let artifacts = BTreeMap::from([
            ("trigger".to_owned(), trigger.trigger_sha256.clone()),
            (
                "classification".to_owned(),
                classification.classification_sha256.clone(),
            ),
        ]);
        let audit_hash = self.append_audit(
            WindowsDeploymentAuditEventKind::RecoveryClassified,
            WindowsDeploymentAuditStatus::Succeeded,
            "classified",
            artifacts.clone(),
            recorded_at_unix_ms,
        )?;
        self.append_ledger(
            RecoveryLedgerEventKindV1::Classified,
            None,
            Some(classification.classification_sha256.clone()),
            None,
            None,
            None,
            None,
            None,
            artifacts,
            audit_hash,
            false,
            false,
            recorded_at_unix_ms,
        )?;
        self.classification = Some(classification);
        self.state = CognitiveRecoveryCoordinatorStateV1::Classified;
        self.classification
            .as_ref()
            .ok_or_else(|| DesktopError::Integrity("classification was not retained".to_owned()))
    }

    /// Selects one deterministic, budget-consuming recovery strategy.
    pub fn decide(
        &mut self,
        context: &RecoveryDecisionContextV1,
        decided_at_unix_ms: u64,
    ) -> Result<&RecoveryDecisionV1, DesktopError> {
        self.require_state(CognitiveRecoveryCoordinatorStateV1::Classified)?;
        let trigger = self
            .trigger
            .as_ref()
            .ok_or_else(|| DesktopError::Integrity("recovery trigger is absent".to_owned()))?;
        let classification = self.classification.as_ref().ok_or_else(|| {
            DesktopError::Integrity("recovery classification is absent".to_owned())
        })?;
        let recovery_id = deterministic_id(
            "recovery",
            &[
                &trigger.trigger_sha256,
                &classification.classification_sha256,
                &self.budget.budget_sha256,
            ],
        )?;
        let decision = decide_recovery(
            recovery_id,
            trigger,
            classification,
            &self.budget,
            &self.history,
            &self.profile,
            context,
            decided_at_unix_ms,
            vec!["desktop-recovery-coordinator".to_owned()],
        )?;
        let artifacts = BTreeMap::from([
            ("decision".to_owned(), decision.decision_sha256.clone()),
            (
                "budget_before".to_owned(),
                self.budget.budget_sha256.clone(),
            ),
            (
                "budget_after".to_owned(),
                decision.budget_after.budget_sha256.clone(),
            ),
        ]);
        let audit_hash = self.append_audit(
            WindowsDeploymentAuditEventKind::RecoveryDecisionCreated,
            WindowsDeploymentAuditStatus::Succeeded,
            "decision-created",
            artifacts.clone(),
            decided_at_unix_ms,
        )?;
        self.append_ledger(
            RecoveryLedgerEventKindV1::Decided,
            None,
            None,
            Some(decision.decision_sha256.clone()),
            None,
            None,
            Some(decision.budget_after.clone()),
            None,
            artifacts,
            audit_hash,
            false,
            false,
            decided_at_unix_ms,
        )?;
        self.budget = decision.budget_after.clone();
        self.decision = Some(decision);
        self.state = CognitiveRecoveryCoordinatorStateV1::Decided;
        self.decision
            .as_ref()
            .ok_or_else(|| DesktopError::Integrity("decision was not retained".to_owned()))
    }

    /// Runs one externally supplied read-only observation and records its fresh identity.
    ///
    /// The desktop observation plane owns the worker and activation. This method
    /// proves audit availability first and rejects reused observation identities.
    pub fn execute_reobservation<F>(
        &mut self,
        recorded_at_unix_ms: u64,
        observe: F,
    ) -> Result<RecoveryTriggerV1, DesktopError>
    where
        F: FnOnce() -> Result<RecoveryTriggerV1, DesktopError>,
    {
        self.require_decision(RecoveryDecisionKindV1::Reobserve)?;
        let decision = self.required_decision()?.clone();
        let prior_trigger = self
            .trigger
            .as_ref()
            .cloned()
            .ok_or_else(|| DesktopError::Integrity("recovery trigger is absent".to_owned()))?;
        let prior_latest_id = prior_trigger
            .fresh_observation_id
            .as_ref()
            .unwrap_or(&prior_trigger.source_observation_id);
        let prior_latest_hash = prior_trigger
            .fresh_observation_hash
            .as_ref()
            .unwrap_or(&prior_trigger.source_observation_hash);
        let prior_latest_sequence = prior_trigger
            .fresh_observation_sequence
            .unwrap_or(prior_trigger.source_observation_sequence);
        let artifacts = BTreeMap::from([("decision".to_owned(), decision.decision_sha256.clone())]);
        let _ = self.append_audit(
            WindowsDeploymentAuditEventKind::RecoveryFreshCycleStarted,
            WindowsDeploymentAuditStatus::Succeeded,
            "reobservation-started",
            artifacts,
            recorded_at_unix_ms,
        )?;
        let latest = verify_recovery_ledger(&self.ledger.root)?;
        if latest != *self.ledger.verification() {
            return Err(DesktopError::Replay(
                "recovery ledger changed before reobservation".to_owned(),
            ));
        }
        self.state = CognitiveRecoveryCoordinatorStateV1::Executing;
        let fresh_trigger = match observe() {
            Ok(value) => value,
            Err(error) => {
                self.poison(recorded_at_unix_ms, "reobservation-failed")?;
                return Err(error);
            }
        };
        fresh_trigger.validate()?;
        if fresh_trigger.goal_id != self.goal_id
            || fresh_trigger.source_observation_id == *prior_latest_id
            || fresh_trigger.source_observation_hash == *prior_latest_hash
            || fresh_trigger.source_observation_sequence <= prior_latest_sequence
        {
            self.poison(recorded_at_unix_ms, "reobservation-reused-stale-state")?;
            return Err(DesktopError::Replay(
                "reobservation did not produce a newer exact observation".to_owned(),
            ));
        }
        let entry = RecoveryHistoryEntryV1 {
            schema_version: RECOVERY_SCHEMA_VERSION,
            cycle_index: self.history.entries.len().saturating_add(1) as u32,
            trigger_sha256: prior_trigger.trigger_sha256,
            classification_sha256: decision.classification_sha256.clone(),
            decision_sha256: decision.decision_sha256,
            plan_generation_id: Some(self.current_plan_generation_id.clone()),
            proposal_id: None,
            proposal_sha256: None,
            capability_id: None,
            input_sha256: None,
            source_observation_hash: prior_latest_hash.clone(),
            source_observation_sequence: prior_latest_sequence,
            fresh_observation_hash: Some(fresh_trigger.source_observation_hash.clone()),
            fresh_observation_sequence: Some(fresh_trigger.source_observation_sequence),
            policy_decision_sha256: None,
            cognitive_admission_sha256: None,
            activation_record_hash: None,
            execution_receipt_sha256: None,
            verified_action_result_sha256: None,
            terminal_outcome: RecoveryHistoryOutcomeV1::Inconclusive,
            evidence_ids: vec!["read-only-reobservation".to_owned()],
            entry_sha256: ZERO_HASH.to_owned(),
        }
        .seal()?;
        let history_after = self.history.append(entry)?;
        let artifacts = BTreeMap::from([
            (
                "fresh_observation".to_owned(),
                fresh_trigger.source_observation_hash.clone(),
            ),
            ("history".to_owned(), history_after.history_sha256.clone()),
        ]);
        let audit_hash = self.append_audit(
            WindowsDeploymentAuditEventKind::RecoveryFreshObservationCollected,
            WindowsDeploymentAuditStatus::Succeeded,
            "reobservation-completed",
            artifacts.clone(),
            recorded_at_unix_ms.saturating_add(1),
        )?;
        self.append_ledger(
            RecoveryLedgerEventKindV1::ReobservationCompleted,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(history_after.clone()),
            artifacts,
            audit_hash,
            false,
            false,
            recorded_at_unix_ms.saturating_add(1),
        )?;
        self.history = history_after;
        self.state = CognitiveRecoveryCoordinatorStateV1::NextCycle;
        Ok(fresh_trigger)
    }

    /// Records complete, continue, stop, or budget-exhausted decisions without mutation.
    pub fn finish_without_mutation(
        &mut self,
        terminal_verified_result_sha256: Option<String>,
        recorded_at_unix_ms: u64,
    ) -> Result<RecoveryCycleResultV1, DesktopError> {
        self.require_state(CognitiveRecoveryCoordinatorStateV1::Decided)?;
        let decision = self.required_decision()?.clone();
        let classification = self.classification.as_ref().ok_or_else(|| {
            DesktopError::Integrity("recovery classification is absent".to_owned())
        })?;
        let outcome = match decision.decision_kind {
            RecoveryDecisionKindV1::NoRecoveryComplete => RecoveryCycleOutcomeV1::Completed,
            RecoveryDecisionKindV1::ContinueExecution => RecoveryCycleOutcomeV1::ContinuePlan,
            RecoveryDecisionKindV1::Stop
                if classification.primary_class
                    == d2i_cognitive_recovery::RecoveryFailureClassV1::BudgetExhausted =>
            {
                RecoveryCycleOutcomeV1::BudgetExhausted
            }
            RecoveryDecisionKindV1::Stop => RecoveryCycleOutcomeV1::Stopped,
            _ => {
                return Err(DesktopError::AccessDenied(
                    "recovery decision requires another typed operation".to_owned(),
                ));
            }
        };
        if let Some(value) = &terminal_verified_result_sha256 {
            validate_hash(value, "terminal verified recovery result")?;
        }
        let result =
            self.non_mutating_result(outcome, None, None, terminal_verified_result_sha256)?;
        let is_terminal = outcome != RecoveryCycleOutcomeV1::ContinuePlan;
        let artifacts = BTreeMap::from([("result".to_owned(), result.result_sha256.clone())]);
        let audit_hash = self.append_audit(
            if matches!(
                outcome,
                RecoveryCycleOutcomeV1::Completed | RecoveryCycleOutcomeV1::ContinuePlan
            ) {
                WindowsDeploymentAuditEventKind::RecoveryCompleted
            } else {
                WindowsDeploymentAuditEventKind::RecoveryStopped
            },
            if outcome == RecoveryCycleOutcomeV1::Completed {
                WindowsDeploymentAuditStatus::Succeeded
            } else {
                WindowsDeploymentAuditStatus::Blocked
            },
            if is_terminal {
                "terminal"
            } else {
                "continue-plan"
            },
            artifacts.clone(),
            recorded_at_unix_ms,
        )?;
        self.append_ledger(
            RecoveryLedgerEventKindV1::Terminal,
            None,
            None,
            None,
            None,
            Some(result.result_sha256.clone()),
            None,
            None,
            artifacts,
            audit_hash,
            is_terminal,
            false,
            recorded_at_unix_ms,
        )?;
        self.state = if is_terminal {
            CognitiveRecoveryCoordinatorStateV1::Terminal
        } else {
            CognitiveRecoveryCoordinatorStateV1::NextCycle
        };
        Ok(result)
    }

    /// Records a strict replacement plan and permits the next fresh cycle.
    pub fn accept_replan(
        &mut self,
        request: &ReplanRequestV1,
        result: &ReplanResultV1,
        authorized_capability_ids: &BTreeSet<String>,
        recorded_at_unix_ms: u64,
    ) -> Result<(), DesktopError> {
        self.require_decision(RecoveryDecisionKindV1::Replan)?;
        let decision = self.required_decision()?;
        if request.recovery_decision_sha256 != decision.decision_sha256
            || request.goal_id != self.goal_id
        {
            return Err(DesktopError::Integrity(
                "replan request differs from the recovery decision".to_owned(),
            ));
        }
        result.validate_against(request, authorized_capability_ids)?;
        let artifacts = BTreeMap::from([
            ("replan_request".to_owned(), request.request_sha256.clone()),
            ("replan_result".to_owned(), result.result_sha256.clone()),
            ("new_plan".to_owned(), result.new_plan_sha256.clone()),
        ]);
        let audit_hash = self.append_audit(
            WindowsDeploymentAuditEventKind::RecoveryFreshCycleRequested,
            WindowsDeploymentAuditStatus::Succeeded,
            "replan-accepted",
            artifacts.clone(),
            recorded_at_unix_ms,
        )?;
        self.append_ledger(
            RecoveryLedgerEventKindV1::ReplanAccepted,
            None,
            None,
            None,
            None,
            Some(result.result_sha256.clone()),
            None,
            None,
            artifacts,
            audit_hash,
            false,
            false,
            recorded_at_unix_ms,
        )?;
        self.current_plan_generation_id = result.new_plan_generation_id.clone();
        self.state = CognitiveRecoveryCoordinatorStateV1::NextCycle;
        Ok(())
    }

    /// Materializes a typed clarification with no desktop mutation.
    pub fn request_clarification(
        &mut self,
        request: ClarificationRequestV1,
        recorded_at_unix_ms: u64,
    ) -> Result<(), DesktopError> {
        self.require_decision(RecoveryDecisionKindV1::RequestClarification)?;
        request.validate()?;
        let decision = self.required_decision()?;
        if request.recovery_decision_sha256 != decision.decision_sha256
            || request.goal_id != self.goal_id
        {
            return Err(DesktopError::Integrity(
                "clarification request differs from the recovery decision".to_owned(),
            ));
        }
        let artifacts =
            BTreeMap::from([("clarification".to_owned(), request.request_sha256.clone())]);
        let audit_hash = self.append_audit(
            WindowsDeploymentAuditEventKind::RecoveryClarificationCreated,
            WindowsDeploymentAuditStatus::Blocked,
            "clarification-pending",
            artifacts.clone(),
            recorded_at_unix_ms,
        )?;
        self.append_ledger(
            RecoveryLedgerEventKindV1::ClarificationPending,
            None,
            None,
            None,
            None,
            Some(request.request_sha256.clone()),
            None,
            None,
            artifacts,
            audit_hash,
            false,
            false,
            recorded_at_unix_ms,
        )?;
        self.pending_clarification = Some(request);
        self.state = CognitiveRecoveryCoordinatorStateV1::HandoffPending;
        Ok(())
    }

    /// Consumes one exact authenticated clarification response once.
    pub fn consume_clarification(
        &mut self,
        response: &ClarificationResponseV1,
        now_unix_ms: u64,
    ) -> Result<(), DesktopError> {
        self.require_state(CognitiveRecoveryCoordinatorStateV1::HandoffPending)?;
        let request = self.pending_clarification.as_ref().ok_or_else(|| {
            DesktopError::Precondition("no clarification request is pending".to_owned())
        })?;
        response.validate_against(request, now_unix_ms)?;
        if self
            .ledger
            .verification()
            .consumed_clarification_response_hashes
            .contains(&response.response_sha256)
        {
            return Err(DesktopError::Replay(
                "clarification response was already consumed".to_owned(),
            ));
        }
        let artifacts = BTreeMap::from([
            ("clarification".to_owned(), request.request_sha256.clone()),
            (
                "clarification_response".to_owned(),
                response.response_sha256.clone(),
            ),
        ]);
        let audit_hash = self.append_audit(
            WindowsDeploymentAuditEventKind::RecoveryClarificationResponseAccepted,
            WindowsDeploymentAuditStatus::Succeeded,
            "clarification-consumed",
            artifacts.clone(),
            now_unix_ms,
        )?;
        self.append_ledger(
            RecoveryLedgerEventKindV1::ClarificationConsumed,
            None,
            None,
            None,
            Some(response.response_sha256.clone()),
            None,
            None,
            None,
            artifacts,
            audit_hash,
            false,
            false,
            now_unix_ms,
        )?;
        self.pending_clarification = None;
        self.state = CognitiveRecoveryCoordinatorStateV1::NextCycle;
        Ok(())
    }

    /// Records a non-executable escalation and makes the coordinator terminal.
    pub fn escalate(
        &mut self,
        escalation: &EscalationRequestV1,
        recorded_at_unix_ms: u64,
    ) -> Result<RecoveryCycleResultV1, DesktopError> {
        self.require_decision(RecoveryDecisionKindV1::Escalate)?;
        escalation.validate()?;
        let decision = self.required_decision()?;
        if escalation.recovery_decision_sha256 != decision.decision_sha256
            || escalation.goal_id != self.goal_id
        {
            return Err(DesktopError::Integrity(
                "escalation differs from the recovery decision".to_owned(),
            ));
        }
        let result = self.non_mutating_result(
            RecoveryCycleOutcomeV1::Escalated,
            None,
            Some(escalation.escalation_sha256.clone()),
            None,
        )?;
        let artifacts = BTreeMap::from([
            (
                "escalation".to_owned(),
                escalation.escalation_sha256.clone(),
            ),
            ("result".to_owned(), result.result_sha256.clone()),
        ]);
        let audit_hash = self.append_audit(
            WindowsDeploymentAuditEventKind::RecoveryEscalationCreated,
            WindowsDeploymentAuditStatus::Blocked,
            "escalated",
            artifacts.clone(),
            recorded_at_unix_ms,
        )?;
        self.append_ledger(
            RecoveryLedgerEventKindV1::Escalated,
            None,
            None,
            None,
            None,
            Some(result.result_sha256.clone()),
            None,
            None,
            artifacts,
            audit_hash,
            true,
            false,
            recorded_at_unix_ms,
        )?;
        self.state = CognitiveRecoveryCoordinatorStateV1::Terminal;
        Ok(result)
    }

    /// Executes one caller-supplied, already bounded fresh KRN-100..300 cycle.
    ///
    /// Audit and ledger writeability are proven before `execute` is invoked.
    pub fn execute_fresh_cycle<F>(
        &mut self,
        request: &FreshRecoveryCycleRequestV1,
        recorded_at_unix_ms: u64,
        execute: F,
    ) -> Result<RecoveryCycleResultV1, DesktopError>
    where
        F: FnOnce() -> Result<FreshRecoveryCycleEvidenceV1, DesktopError>,
    {
        let decision = self.required_decision()?.clone();
        if !matches!(
            decision.decision_kind,
            RecoveryDecisionKindV1::RetryFreshCycle
                | RecoveryDecisionKindV1::SelectAlternateCapability
                | RecoveryDecisionKindV1::Replan
        ) {
            return Err(DesktopError::Precondition(
                "decision does not authorize a fresh cycle".to_owned(),
            ));
        }
        self.require_state(CognitiveRecoveryCoordinatorStateV1::Decided)?;
        request.validate_against(&decision, &self.history, recorded_at_unix_ms)?;

        let requested_artifacts = BTreeMap::from([(
            "fresh_cycle_request".to_owned(),
            request.cycle_request_sha256.clone(),
        )]);
        let audit_hash = self.append_audit(
            WindowsDeploymentAuditEventKind::RecoveryFreshCycleStarted,
            WindowsDeploymentAuditStatus::Succeeded,
            "fresh-cycle-started",
            requested_artifacts.clone(),
            recorded_at_unix_ms,
        )?;
        self.append_ledger(
            RecoveryLedgerEventKindV1::FreshCycleRequested,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            requested_artifacts,
            audit_hash,
            false,
            false,
            recorded_at_unix_ms,
        )?;
        self.state = CognitiveRecoveryCoordinatorStateV1::Executing;

        let evidence = match execute() {
            Ok(value) => value,
            Err(error) => {
                self.poison(recorded_at_unix_ms, "fresh-cycle-execution-failed")?;
                return Err(error);
            }
        };
        if let Err(error) = evidence.validate_against(request, &self.history) {
            self.poison(recorded_at_unix_ms, "fresh-cycle-evidence-rejected")?;
            return Err(error.into());
        }
        let history_before_sha256 = self.history.history_sha256.clone();
        let history_entry = RecoveryHistoryEntryV1 {
            schema_version: RECOVERY_SCHEMA_VERSION,
            cycle_index: self.history.entries.len().saturating_add(1) as u32,
            trigger_sha256: decision.trigger_sha256.clone(),
            classification_sha256: decision.classification_sha256.clone(),
            decision_sha256: decision.decision_sha256.clone(),
            plan_generation_id: Some(evidence.plan_generation_id.clone()),
            proposal_id: Some(evidence.proposal_id.clone()),
            proposal_sha256: Some(evidence.proposal_sha256.clone()),
            capability_id: Some(evidence.capability_id.clone()),
            input_sha256: Some(evidence.input_sha256.clone()),
            source_observation_hash: request.latest_observation_hash.clone(),
            source_observation_sequence: request.latest_observation_sequence,
            fresh_observation_hash: Some(evidence.observation_hash.clone()),
            fresh_observation_sequence: Some(evidence.observation_sequence),
            policy_decision_sha256: Some(evidence.policy_decision_sha256.clone()),
            cognitive_admission_sha256: Some(evidence.cognitive_admission_sha256.clone()),
            activation_record_hash: Some(evidence.activation_record_hash.clone()),
            execution_receipt_sha256: Some(evidence.execution_receipt_sha256.clone()),
            verified_action_result_sha256: Some(evidence.verified_action_result_sha256.clone()),
            terminal_outcome: history_outcome(evidence.verification_verdict),
            evidence_ids: vec!["fresh-cycle-complete".to_owned()],
            entry_sha256: ZERO_HASH.to_owned(),
        }
        .seal()?;
        let history_after = self.history.append(history_entry)?;
        let outcome = match evidence.verification_verdict {
            RecoveryVerificationVerdictV1::Passed => RecoveryCycleOutcomeV1::Recovered,
            RecoveryVerificationVerdictV1::Unsafe => RecoveryCycleOutcomeV1::Failed,
            _ => RecoveryCycleOutcomeV1::Failed,
        };
        let result = RecoveryCycleResultV1 {
            schema_version: RECOVERY_SCHEMA_VERSION,
            recovery_id: decision.recovery_id.clone(),
            outcome,
            trigger_sha256: decision.trigger_sha256.clone(),
            classification_sha256: decision.classification_sha256.clone(),
            decision_sha256: decision.decision_sha256.clone(),
            budget_before_sha256: decision.budget_before_sha256.clone(),
            budget_after_sha256: self.budget.budget_sha256.clone(),
            history_before_sha256,
            history_after_sha256: history_after.history_sha256.clone(),
            fresh_cycle_request_sha256: Some(request.cycle_request_sha256.clone()),
            replan_result_sha256: None,
            clarification_sha256: None,
            escalation_sha256: None,
            new_proposal_sha256: Some(evidence.proposal_sha256.clone()),
            new_admission_sha256: Some(evidence.cognitive_admission_sha256.clone()),
            new_activation_record_hash: Some(evidence.activation_record_hash.clone()),
            new_execution_receipt_sha256: Some(evidence.execution_receipt_sha256.clone()),
            new_verification_result_sha256: Some(evidence.verified_action_result_sha256.clone()),
            terminal_verified_result_sha256: Some(evidence.verified_action_result_sha256.clone()),
            evidence_ids: vec!["desktop-fresh-recovery".to_owned()],
            result_sha256: ZERO_HASH.to_owned(),
        }
        .seal()?;
        let artifacts = BTreeMap::from([
            ("result".to_owned(), result.result_sha256.clone()),
            (
                "fresh_observation".to_owned(),
                evidence.observation_hash.clone(),
            ),
            ("proposal".to_owned(), evidence.proposal_sha256.clone()),
            (
                "admission".to_owned(),
                evidence.cognitive_admission_sha256.clone(),
            ),
            (
                "activation".to_owned(),
                evidence.activation_record_hash.clone(),
            ),
            (
                "execution_receipt".to_owned(),
                evidence.execution_receipt_sha256.clone(),
            ),
            (
                "verification".to_owned(),
                evidence.verified_action_result_sha256.clone(),
            ),
            ("history".to_owned(), history_after.history_sha256.clone()),
        ]);
        let audit_hash = self.append_audit(
            WindowsDeploymentAuditEventKind::RecoveryFreshVerificationCompleted,
            match evidence.verification_verdict {
                RecoveryVerificationVerdictV1::Passed => WindowsDeploymentAuditStatus::Succeeded,
                RecoveryVerificationVerdictV1::Unsafe => WindowsDeploymentAuditStatus::Blocked,
                _ => WindowsDeploymentAuditStatus::Failed,
            },
            "fresh-cycle-completed",
            artifacts.clone(),
            recorded_at_unix_ms.saturating_add(1),
        )?;
        self.append_ledger(
            RecoveryLedgerEventKindV1::FreshCycleCompleted,
            None,
            None,
            None,
            None,
            Some(result.result_sha256.clone()),
            None,
            Some(history_after.clone()),
            artifacts,
            audit_hash,
            false,
            false,
            recorded_at_unix_ms.saturating_add(1),
        )?;
        self.history = history_after;
        self.state = CognitiveRecoveryCoordinatorStateV1::NextCycle;
        Ok(result)
    }

    fn non_mutating_result(
        &self,
        outcome: RecoveryCycleOutcomeV1,
        clarification_sha256: Option<String>,
        escalation_sha256: Option<String>,
        terminal_verified_result_sha256: Option<String>,
    ) -> Result<RecoveryCycleResultV1, DesktopError> {
        let decision = self.required_decision()?;
        Ok(RecoveryCycleResultV1 {
            schema_version: RECOVERY_SCHEMA_VERSION,
            recovery_id: decision.recovery_id.clone(),
            outcome,
            trigger_sha256: decision.trigger_sha256.clone(),
            classification_sha256: decision.classification_sha256.clone(),
            decision_sha256: decision.decision_sha256.clone(),
            budget_before_sha256: decision.budget_before_sha256.clone(),
            budget_after_sha256: self.budget.budget_sha256.clone(),
            history_before_sha256: self.history.history_sha256.clone(),
            history_after_sha256: self.history.history_sha256.clone(),
            fresh_cycle_request_sha256: None,
            replan_result_sha256: None,
            clarification_sha256,
            escalation_sha256,
            new_proposal_sha256: None,
            new_admission_sha256: None,
            new_activation_record_hash: None,
            new_execution_receipt_sha256: None,
            new_verification_result_sha256: None,
            terminal_verified_result_sha256,
            evidence_ids: vec!["non-mutating-recovery-handoff".to_owned()],
            result_sha256: ZERO_HASH.to_owned(),
        }
        .seal()?)
    }

    fn required_decision(&self) -> Result<&RecoveryDecisionV1, DesktopError> {
        self.decision
            .as_ref()
            .ok_or_else(|| DesktopError::Precondition("recovery decision is absent".to_owned()))
    }

    fn require_decision(&self, expected: RecoveryDecisionKindV1) -> Result<(), DesktopError> {
        self.require_state(CognitiveRecoveryCoordinatorStateV1::Decided)?;
        if self.required_decision()?.decision_kind != expected {
            return Err(DesktopError::AccessDenied(format!(
                "recovery decision does not authorize {expected:?}"
            )));
        }
        Ok(())
    }

    fn require_state(
        &self,
        expected: CognitiveRecoveryCoordinatorStateV1,
    ) -> Result<(), DesktopError> {
        if self.state != expected {
            return Err(DesktopError::Precondition(format!(
                "recovery coordinator state {:?} is not {expected:?}",
                self.state
            )));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn append_ledger(
        &mut self,
        event_kind: RecoveryLedgerEventKindV1,
        trigger_sha256: Option<String>,
        classification_sha256: Option<String>,
        decision_sha256: Option<String>,
        clarification_response_sha256: Option<String>,
        result_sha256: Option<String>,
        budget_after: Option<RecoveryBudgetV1>,
        history_after: Option<RecoveryHistoryV1>,
        artifact_hashes: BTreeMap<String, String>,
        audit_record_hash: String,
        terminal: bool,
        poisoned: bool,
        recorded_at_unix_ms: u64,
    ) -> Result<(), DesktopError> {
        self.ledger.append(RecoveryLedgerRecordV1 {
            schema_version: RECOVERY_SCHEMA_VERSION,
            sequence: 0,
            ledger_id: self.ledger.verification().ledger_id.clone(),
            session_id: self.ledger.verification().session_id.clone(),
            goal_id: self.goal_id.clone(),
            event_kind,
            trigger_sha256,
            classification_sha256,
            decision_sha256,
            clarification_response_sha256,
            result_sha256,
            budget_after,
            history_after,
            artifact_hashes,
            audit_record_hash,
            terminal,
            poisoned,
            recorded_at_unix_ms,
            previous_record_hash: ZERO_HASH.to_owned(),
            record_hash: ZERO_HASH.to_owned(),
        })?;
        self.last_recorded_at_unix_ms = recorded_at_unix_ms;
        Ok(())
    }

    fn append_audit(
        &mut self,
        kind: WindowsDeploymentAuditEventKind,
        status: WindowsDeploymentAuditStatus,
        suffix: &str,
        artifact_hashes: BTreeMap<String, String>,
        recorded_at_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        validate_token(suffix, "recovery audit suffix")?;
        let detail_hash =
            canonical_sha256(&(self.goal_id.as_str(), suffix, status, &artifact_hashes))?;
        self.audit.append(WindowsDeploymentAuditEvent {
            schema_version: 1,
            event_id: format!(
                "recovery-{suffix}-{}",
                self.audit.record_count().saturating_add(1)
            ),
            kind,
            status,
            artifact_hashes,
            detail_hash,
            recorded_at_unix_ms: recorded_at_unix_ms.max(1),
        })
    }

    fn poison(&mut self, recorded_at_unix_ms: u64, reason: &str) -> Result<(), DesktopError> {
        let detail_hash = canonical_sha256(&reason)?;
        let artifacts = BTreeMap::from([("failure".to_owned(), detail_hash)]);
        let audit_hash = self.append_audit(
            WindowsDeploymentAuditEventKind::RecoveryAborted,
            WindowsDeploymentAuditStatus::Failed,
            "aborted",
            artifacts.clone(),
            recorded_at_unix_ms,
        )?;
        self.append_ledger(
            RecoveryLedgerEventKindV1::Aborted,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            artifacts,
            audit_hash,
            true,
            true,
            recorded_at_unix_ms,
        )?;
        self.state = CognitiveRecoveryCoordinatorStateV1::Poisoned;
        Ok(())
    }
}

impl Drop for CognitiveRecoveryCoordinatorV1 {
    fn drop(&mut self) {
        if matches!(
            self.state,
            CognitiveRecoveryCoordinatorStateV1::Begun
                | CognitiveRecoveryCoordinatorStateV1::Classified
                | CognitiveRecoveryCoordinatorStateV1::Decided
                | CognitiveRecoveryCoordinatorStateV1::Executing
        ) {
            let now = self.last_recorded_at_unix_ms.saturating_add(1).max(1);
            let _ = self.poison(now, "coordinator-dropped-before-result");
        }
    }
}

fn history_outcome(verdict: RecoveryVerificationVerdictV1) -> RecoveryHistoryOutcomeV1 {
    match verdict {
        RecoveryVerificationVerdictV1::Passed => RecoveryHistoryOutcomeV1::Passed,
        RecoveryVerificationVerdictV1::Failed => RecoveryHistoryOutcomeV1::Failed,
        RecoveryVerificationVerdictV1::Inconclusive => RecoveryHistoryOutcomeV1::Inconclusive,
        RecoveryVerificationVerdictV1::Unsupported => RecoveryHistoryOutcomeV1::Unsupported,
        RecoveryVerificationVerdictV1::Unsafe => RecoveryHistoryOutcomeV1::Unsafe,
    }
}

fn validate_record_transition(
    record: &RecoveryLedgerRecordV1,
    latest: &RecoveryLedgerVerificationV1,
) -> Result<(), DesktopError> {
    validate_record(record)?;
    if record.ledger_id != latest.ledger_id
        || record.session_id != latest.session_id
        || record.goal_id != latest.goal_id
        || latest.terminal
        || latest.poisoned
    {
        return Err(DesktopError::Integrity(
            "recovery record differs from durable identity or terminal state".to_owned(),
        ));
    }
    if let (Some(before), Some(after)) = (&latest.latest_budget, &record.budget_after) {
        validate_budget_non_increase(before, after)?;
    }
    if let (Some(before), Some(after)) = (&latest.latest_history, &record.history_after) {
        if after.entries.len() != before.entries.len().saturating_add(1)
            || !after.entries.starts_with(&before.entries)
        {
            return Err(DesktopError::Integrity(
                "recovery history did not append exactly one entry".to_owned(),
            ));
        }
    }
    for (values, candidate, label) in [
        (
            &latest.consumed_trigger_hashes,
            &record.trigger_sha256,
            "trigger",
        ),
        (
            &latest.consumed_decision_hashes,
            &record.decision_sha256,
            "decision",
        ),
        (
            &latest.consumed_clarification_response_hashes,
            &record.clarification_response_sha256,
            "clarification response",
        ),
    ] {
        if candidate
            .as_ref()
            .is_some_and(|value| values.binary_search(value).is_ok())
        {
            return Err(DesktopError::Replay(format!(
                "recovery ledger reused {label}"
            )));
        }
    }
    Ok(())
}

fn validate_record(record: &RecoveryLedgerRecordV1) -> Result<(), DesktopError> {
    if record.schema_version != RECOVERY_SCHEMA_VERSION
        || record.sequence == 0
        || record.recorded_at_unix_ms == 0
        || record.artifact_hashes.len() > 32
        || record.poisoned && !record.terminal
    {
        return Err(DesktopError::Invalid(
            "recovery ledger record bounds are invalid".to_owned(),
        ));
    }
    for (value, label) in [
        (&record.ledger_id, "record ledger_id"),
        (&record.session_id, "record session_id"),
        (&record.goal_id, "record goal_id"),
    ] {
        validate_token(value, label)?;
    }
    for (value, label) in [
        (&record.trigger_sha256, "record trigger hash"),
        (&record.classification_sha256, "record classification hash"),
        (&record.decision_sha256, "record decision hash"),
        (
            &record.clarification_response_sha256,
            "record clarification response hash",
        ),
        (&record.result_sha256, "record result hash"),
    ] {
        if let Some(value) = value {
            validate_hash(value, label)?;
        }
    }
    for (name, value) in &record.artifact_hashes {
        validate_token(name, "recovery artifact name")?;
        validate_hash(value, "recovery artifact hash")?;
    }
    validate_hash(&record.audit_record_hash, "recovery audit cross-reference")?;
    validate_hash(
        &record.previous_record_hash,
        "previous recovery record hash",
    )?;
    validate_hash(&record.record_hash, "recovery record hash")?;
    if let Some(value) = &record.budget_after {
        value.validate()?;
        if value.goal_id != record.goal_id {
            return Err(DesktopError::Integrity(
                "recovery budget goal differs from ledger goal".to_owned(),
            ));
        }
    }
    if let Some(value) = &record.history_after {
        value.validate()?;
        if value.goal_id != record.goal_id {
            return Err(DesktopError::Integrity(
                "recovery history goal differs from ledger goal".to_owned(),
            ));
        }
    }
    reject_forbidden_record_content(record)
}

fn validate_budget_non_increase(
    before: &RecoveryBudgetV1,
    after: &RecoveryBudgetV1,
) -> Result<(), DesktopError> {
    if before.budget_id != after.budget_id
        || before.goal_id != after.goal_id
        || before.maximum_total_cycles != after.maximum_total_cycles
        || before.maximum_reobservations != after.maximum_reobservations
        || before.maximum_fresh_retries != after.maximum_fresh_retries
        || before.maximum_alternate_capability_attempts
            != after.maximum_alternate_capability_attempts
        || before.maximum_replans != after.maximum_replans
        || before.maximum_clarifications != after.maximum_clarifications
        || after.remaining_total_cycles > before.remaining_total_cycles
        || after.remaining_reobservations > before.remaining_reobservations
        || after.remaining_fresh_retries > before.remaining_fresh_retries
        || after.remaining_alternate_capability_attempts
            > before.remaining_alternate_capability_attempts
        || after.remaining_replans > before.remaining_replans
        || after.remaining_clarifications > before.remaining_clarifications
    {
        return Err(DesktopError::Integrity(
            "durable recovery budget identity changed or increased".to_owned(),
        ));
    }
    Ok(())
}

fn consume_once(
    values: &mut Vec<String>,
    value: &Option<String>,
    label: &str,
) -> Result<(), DesktopError> {
    if let Some(value) = value {
        if values.binary_search(value).is_ok() {
            return Err(DesktopError::Replay(format!(
                "recovery ledger replayed {label}"
            )));
        }
        values.push(value.clone());
        values.sort();
    }
    Ok(())
}

fn record_hash(record: &RecoveryLedgerRecordV1) -> Result<String, DesktopError> {
    Ok(canonical_sha256(&RecoveryLedgerRecordPayload {
        schema_version: record.schema_version,
        sequence: record.sequence,
        ledger_id: &record.ledger_id,
        session_id: &record.session_id,
        goal_id: &record.goal_id,
        event_kind: record.event_kind,
        trigger_sha256: &record.trigger_sha256,
        classification_sha256: &record.classification_sha256,
        decision_sha256: &record.decision_sha256,
        clarification_response_sha256: &record.clarification_response_sha256,
        result_sha256: &record.result_sha256,
        budget_after: &record.budget_after,
        history_after: &record.history_after,
        artifact_hashes: &record.artifact_hashes,
        audit_record_hash: &record.audit_record_hash,
        terminal: record.terminal,
        poisoned: record.poisoned,
        recorded_at_unix_ms: record.recorded_at_unix_ms,
        previous_record_hash: &record.previous_record_hash,
    })?)
}

fn reject_forbidden_record_content(record: &RecoveryLedgerRecordV1) -> Result<(), DesktopError> {
    fn forbidden(value: &Value) -> bool {
        match value {
            Value::String(value) => {
                let lower = value.to_ascii_lowercase();
                value.contains(":\\")
                    || value.starts_with('/')
                    || [
                        "password",
                        "credential",
                        "bearer ",
                        "api_key",
                        "access_token",
                    ]
                    .iter()
                    .any(|marker| lower.contains(marker))
            }
            Value::Array(values) => values.iter().any(forbidden),
            Value::Object(values) => values.iter().any(|(key, value)| {
                matches!(
                    key.to_ascii_lowercase().as_str(),
                    "raw_locator" | "raw_payload" | "credential" | "secret" | "token"
                ) || forbidden(value)
            }),
            Value::Null | Value::Bool(_) | Value::Number(_) => false,
        }
    }
    let value =
        serde_json::to_value(record).map_err(|error| DesktopError::Json(error.to_string()))?;
    if forbidden(&value) {
        return Err(DesktopError::AccessDenied(
            "recovery ledger record contains forbidden raw or secret material".to_owned(),
        ));
    }
    Ok(())
}

fn load_manifest(root: &Path) -> Result<RecoveryLedgerManifestV1, DesktopError> {
    validate_root(root)?;
    let bytes = read_bounded(&root.join(MANIFEST_FILE), 1024 * 1024)?;
    let manifest: RecoveryLedgerManifestV1 = d2i_cognitive_recovery::parse_json_strict(&bytes)?;
    if manifest.schema_version != RECOVERY_SCHEMA_VERSION
        || manifest.maximum_records == 0
        || manifest.maximum_records > MAX_LEDGER_RECORDS
        || manifest.created_at_unix_ms == 0
    {
        return Err(DesktopError::Invalid(
            "recovery ledger manifest bounds are invalid".to_owned(),
        ));
    }
    for (value, label) in [
        (&manifest.ledger_id, "manifest ledger_id"),
        (&manifest.session_id, "manifest session_id"),
        (&manifest.goal_id, "manifest goal_id"),
    ] {
        validate_token(value, label)?;
    }
    for value in [
        &manifest.root_security_descriptor_hash,
        &manifest.manifest_security_descriptor_hash,
        &manifest.state_security_descriptor_hash,
    ] {
        validate_hash(value, "recovery ledger security descriptor hash")?;
    }
    Ok(manifest)
}

fn load_snapshot(root: &Path) -> Result<RecoveryLedgerSnapshotV1, DesktopError> {
    let bytes = read_bounded(&root.join(STATE_FILE), MAX_LEDGER_BYTES)?;
    d2i_cognitive_recovery::parse_json_strict(&bytes).map_err(Into::into)
}

fn validate_root(root: &Path) -> Result<(), DesktopError> {
    let metadata = std::fs::symlink_metadata(root).map_err(|error| DesktopError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(DesktopError::Integrity(
            "recovery ledger root must be a non-symlink directory".to_owned(),
        ));
    }
    for name in [MANIFEST_FILE, STATE_FILE] {
        let path = root.join(name);
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| DesktopError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(DesktopError::Integrity(
                "recovery ledger artifacts must be regular files".to_owned(),
            ));
        }
    }
    Ok(())
}

fn verify_storage_security(
    root: &Path,
    manifest: &RecoveryLedgerManifestV1,
) -> Result<(), DesktopError> {
    for (path, expected, label) in [
        (
            root.to_path_buf(),
            &manifest.root_security_descriptor_hash,
            "root",
        ),
        (
            root.join(MANIFEST_FILE),
            &manifest.manifest_security_descriptor_hash,
            "manifest",
        ),
        (
            root.join(STATE_FILE),
            &manifest.state_security_descriptor_hash,
            "state",
        ),
    ] {
        let descriptor = d2i_windows_host::path_security_descriptor(&path).map_err(|error| {
            DesktopError::Integrity(format!("recovery ledger {label} ACL read failed: {error}"))
        })?;
        if sha256_bytes(&descriptor) != *expected {
            return Err(DesktopError::Integrity(format!(
                "recovery ledger {label} ACL changed"
            )));
        }
    }
    Ok(())
}

fn harden_and_hash(path: &Path, label: &str) -> Result<String, DesktopError> {
    let descriptor = d2i_windows_host::harden_path_for_current_user(path).map_err(|error| {
        DesktopError::Integrity(format!("{label} ACL hardening failed: {error}"))
    })?;
    Ok(sha256_bytes(&descriptor))
}

fn overwrite_existing(path: &Path, bytes: &[u8]) -> Result<(), DesktopError> {
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|error| DesktopError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| DesktopError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })
}

fn atomic_replace_state(
    root: &Path,
    snapshot: &RecoveryLedgerSnapshotV1,
) -> Result<(), DesktopError> {
    let temporary = root.join(format!(
        ".recovery-state-{}-{}.tmp",
        std::process::id(),
        snapshot.records.len()
    ));
    let result = (|| {
        write_new(&temporary, &pretty_json_bytes(snapshot)?)?;
        let _ = d2i_windows_host::harden_path_for_current_user(&temporary).map_err(|error| {
            DesktopError::Integrity(format!("temporary recovery state ACL failed: {error}"))
        })?;
        d2i_windows_host::atomic_move(&temporary, &root.join(STATE_FILE), true).map_err(|error| {
            DesktopError::Io {
                path: root.join(STATE_FILE).display().to_string(),
                message: format!("atomic recovery state replace failed: {error}"),
            }
        })
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

struct RecoveryLedgerLock(PathBuf);

impl RecoveryLedgerLock {
    fn acquire(root: &Path) -> Result<Self, DesktopError> {
        let path = root.join(LOCK_FILE);
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| DesktopError::Io {
                path: path.display().to_string(),
                message: format!("recovery ledger lock unavailable: {error}"),
            })?;
        if let Err(error) = d2i_windows_host::harden_path_for_current_user(&path) {
            let _ = std::fs::remove_file(&path);
            return Err(DesktopError::Integrity(format!(
                "recovery ledger lock ACL failed: {error}"
            )));
        }
        Ok(Self(path))
    }
}

impl Drop for RecoveryLedgerLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn deterministic_id(prefix: &str, values: &[&str]) -> Result<String, DesktopError> {
    validate_token(prefix, "recovery deterministic prefix")?;
    let digest = canonical_sha256(&values)?;
    Ok(format!("{prefix}-{}", &digest[7..31]))
}
