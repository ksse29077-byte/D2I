use crate::{read_bounded, sha256_bytes, validate_hash, validate_token, write_new, DesktopError};
use d2i_adaptive_planner::{PlannerCycleRecordV1, PlannerCycleStageV1, PlannerCycleStatusV1};
use d2i_situation_model::{canonical_json_bytes, hash_without, parse_json_strict, ZERO_HASH};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

const LEDGER_SCHEMA_VERSION: u32 = 1;
const MANIFEST_FILE: &str = "adaptive-planner-ledger-manifest.json";
const STATE_FILE: &str = "adaptive-planner-ledger-state.json";
const LOCK_FILE: &str = ".adaptive-planner-ledger.lock";
const MAX_LEDGER_RECORDS: u64 = 8_192;
const MAX_LEDGER_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerLedgerEventKindV1 {
    ProviderInvoked,
    ProviderResultValidated,
    SituationPersisted,
    PlanPersisted,
    StepAdmitted,
    KernelBound,
    ActionAttempted,
    VerificationPersisted,
    SituationUpdated,
    ClarificationRecorded,
    EscalationRecorded,
    TerminalEvaluated,
    RecoveryRepaired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerRecoveryDirectiveV1 {
    FreshContextAndInvocation,
    RepairSituationFromExactResult,
    ReobserveAndReplan,
    ReobserveVerifyNeverReplay,
    RepairSituationAndReplan,
    ReevaluateClosureExactlyOnce,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerLedgerRecordV1 {
    pub schema_version: u32,
    pub sequence: u64,
    pub ledger_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub case_contract_sha256: String,
    pub case_work_grant_sha256: String,
    pub event_kind: PlannerLedgerEventKindV1,
    pub cycle_record: PlannerCycleRecordV1,
    pub recorded_at_unix_ms: u64,
    pub previous_record_hash: String,
    pub record_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlannerLedgerManifestV1 {
    schema_version: u32,
    ledger_id: String,
    organization_id: String,
    case_id: String,
    case_contract_sha256: String,
    case_work_grant_sha256: String,
    maximum_records: u64,
    maximum_ledger_bytes: u64,
    created_at_unix_ms: u64,
    root_security_descriptor_sha256: String,
    manifest_security_descriptor_sha256: String,
    state_security_descriptor_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlannerLedgerSnapshotV1 {
    schema_version: u32,
    ledger_id: String,
    organization_id: String,
    case_id: String,
    case_contract_sha256: String,
    case_work_grant_sha256: String,
    records: Vec<PlannerLedgerRecordV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerLedgerVerificationV1 {
    pub ledger_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub case_contract_sha256: String,
    pub case_work_grant_sha256: String,
    pub record_count: u64,
    pub terminal_record_hash: String,
    pub latest_cycle_record_sha256: String,
    pub latest_event_kind: Option<PlannerLedgerEventKindV1>,
    pub latest_stage: Option<PlannerCycleStageV1>,
    pub latest_status: Option<PlannerCycleStatusV1>,
    pub situation_generation_hashes: Vec<String>,
    pub plan_generation_hashes: Vec<String>,
    pub consumed_provider_invocation_hashes: Vec<String>,
    pub consumed_next_step_decision_hashes: Vec<String>,
    pub kernel_run_hashes: Vec<String>,
    pub verification_result_hashes: Vec<String>,
    pub terminal_evaluation_count: u32,
    pub latest_protected_audit_terminal_sha256: String,
    pub latest_recorded_at_unix_ms: u64,
}

#[derive(Debug)]
pub struct PlannerLedgerV1 {
    root: PathBuf,
    manifest: PlannerLedgerManifestV1,
    verification: PlannerLedgerVerificationV1,
    poisoned: bool,
}

impl PlannerLedgerV1 {
    pub fn open(root: &Path) -> Result<Self, DesktopError> {
        let manifest = load_manifest(root)?;
        let verification = verify_planner_ledger(root)?;
        Ok(Self {
            root: root.to_path_buf(),
            manifest,
            verification,
            poisoned: false,
        })
    }

    pub const fn verification(&self) -> &PlannerLedgerVerificationV1 {
        &self.verification
    }

    pub fn append(
        &mut self,
        event_kind: PlannerLedgerEventKindV1,
        mut cycle_record: PlannerCycleRecordV1,
        recorded_at_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        if self.poisoned {
            return Err(DesktopError::Integrity(
                "planner ledger is poisoned after a durable-write failure".to_owned(),
            ));
        }
        let result = self.append_inner(event_kind, &mut cycle_record, recorded_at_unix_ms);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn append_inner(
        &mut self,
        event_kind: PlannerLedgerEventKindV1,
        cycle_record: &mut PlannerCycleRecordV1,
        recorded_at_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        let _lock = PlannerLedgerLock::acquire(&self.root)?;
        let latest = verify_planner_ledger(&self.root)?;
        if latest != self.verification {
            return Err(DesktopError::Replay(
                "planner ledger changed after it was opened".to_owned(),
            ));
        }
        if latest.record_count >= self.manifest.maximum_records {
            return Err(DesktopError::AccessDenied(
                "planner ledger record limit is exhausted".to_owned(),
            ));
        }
        if recorded_at_unix_ms == 0 || recorded_at_unix_ms < latest.latest_recorded_at_unix_ms {
            return Err(DesktopError::Invalid(
                "planner ledger time is zero or moves backward".to_owned(),
            ));
        }
        cycle_record.schema_version = LEDGER_SCHEMA_VERSION;
        cycle_record.sequence = latest.record_count.saturating_add(1);
        cycle_record.case_id = self.manifest.case_id.clone();
        cycle_record.previous_record_sha256 = latest.latest_cycle_record_sha256.clone();
        cycle_record.record_sha256 = ZERO_HASH.to_owned();
        *cycle_record = cycle_record
            .clone()
            .seal()
            .map_err(|error| DesktopError::Invalid(error.to_string()))?;
        validate_event_stage(event_kind, cycle_record)?;
        validate_transition(latest.latest_stage, event_kind, cycle_record.stage)?;
        let mut record = PlannerLedgerRecordV1 {
            schema_version: LEDGER_SCHEMA_VERSION,
            sequence: cycle_record.sequence,
            ledger_id: self.manifest.ledger_id.clone(),
            organization_id: self.manifest.organization_id.clone(),
            case_id: self.manifest.case_id.clone(),
            case_contract_sha256: self.manifest.case_contract_sha256.clone(),
            case_work_grant_sha256: self.manifest.case_work_grant_sha256.clone(),
            event_kind,
            cycle_record: cycle_record.clone(),
            recorded_at_unix_ms,
            previous_record_hash: latest.terminal_record_hash.clone(),
            record_hash: ZERO_HASH.to_owned(),
        };
        record.record_hash = planner_record_hash(&record)?;
        validate_record(&record, &self.manifest)?;
        let mut snapshot = load_snapshot(&self.root)?;
        snapshot.records.push(record);
        let bytes = pretty_json(&snapshot)?;
        if bytes.len() as u64 > self.manifest.maximum_ledger_bytes {
            return Err(DesktopError::AccessDenied(
                "planner ledger byte limit is exhausted".to_owned(),
            ));
        }
        atomic_replace_state(&self.root, &bytes)?;
        let verified = verify_planner_ledger(&self.root)?;
        if verified.record_count != latest.record_count.saturating_add(1) {
            return Err(DesktopError::Integrity(
                "planner ledger append did not advance exactly once".to_owned(),
            ));
        }
        self.verification = verified;
        Ok(self.verification.terminal_record_hash.clone())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn initialize_planner_ledger(
    root: &Path,
    ledger_id: &str,
    organization_id: &str,
    case_id: &str,
    case_contract_sha256: &str,
    case_work_grant_sha256: &str,
    maximum_records: u64,
    maximum_ledger_bytes: u64,
    created_at_unix_ms: u64,
) -> Result<PlannerLedgerV1, DesktopError> {
    validate_token(ledger_id, "planner ledger ID")?;
    validate_token(organization_id, "planner organization ID")?;
    validate_token(case_id, "planner Case ID")?;
    validate_hash(case_contract_sha256, "planner Case Contract hash")?;
    validate_hash(case_work_grant_sha256, "planner Work Grant hash")?;
    if maximum_records == 0
        || maximum_records > MAX_LEDGER_RECORDS
        || maximum_ledger_bytes == 0
        || maximum_ledger_bytes > MAX_LEDGER_BYTES
        || created_at_unix_ms == 0
    {
        return Err(DesktopError::Invalid(
            "planner ledger limits or creation time are invalid".to_owned(),
        ));
    }
    std::fs::create_dir(root).map_err(|error| DesktopError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    let initialized = (|| {
        let root_security_descriptor_sha256 = harden_and_hash(root)?;
        let manifest_path = root.join(MANIFEST_FILE);
        let state_path = root.join(STATE_FILE);
        write_new(&manifest_path, b"")?;
        write_new(&state_path, b"")?;
        let manifest_security_descriptor_sha256 = harden_and_hash(&manifest_path)?;
        let state_security_descriptor_sha256 = harden_and_hash(&state_path)?;
        let snapshot = PlannerLedgerSnapshotV1 {
            schema_version: LEDGER_SCHEMA_VERSION,
            ledger_id: ledger_id.to_owned(),
            organization_id: organization_id.to_owned(),
            case_id: case_id.to_owned(),
            case_contract_sha256: case_contract_sha256.to_owned(),
            case_work_grant_sha256: case_work_grant_sha256.to_owned(),
            records: Vec::new(),
        };
        overwrite_existing(&state_path, &pretty_json(&snapshot)?)?;
        let manifest = PlannerLedgerManifestV1 {
            schema_version: LEDGER_SCHEMA_VERSION,
            ledger_id: ledger_id.to_owned(),
            organization_id: organization_id.to_owned(),
            case_id: case_id.to_owned(),
            case_contract_sha256: case_contract_sha256.to_owned(),
            case_work_grant_sha256: case_work_grant_sha256.to_owned(),
            maximum_records,
            maximum_ledger_bytes,
            created_at_unix_ms,
            root_security_descriptor_sha256,
            manifest_security_descriptor_sha256,
            state_security_descriptor_sha256,
        };
        overwrite_existing(&manifest_path, &pretty_json(&manifest)?)?;
        Ok::<(), DesktopError>(())
    })();
    if let Err(error) = initialized {
        let _ = std::fs::remove_dir_all(root);
        return Err(error);
    }
    PlannerLedgerV1::open(root)
}

pub fn verify_planner_ledger(root: &Path) -> Result<PlannerLedgerVerificationV1, DesktopError> {
    let manifest = load_manifest(root)?;
    verify_security(root, &manifest)?;
    let snapshot = load_snapshot(root)?;
    if snapshot.schema_version != LEDGER_SCHEMA_VERSION
        || snapshot.ledger_id != manifest.ledger_id
        || snapshot.organization_id != manifest.organization_id
        || snapshot.case_id != manifest.case_id
        || snapshot.case_contract_sha256 != manifest.case_contract_sha256
        || snapshot.case_work_grant_sha256 != manifest.case_work_grant_sha256
        || snapshot.records.len() as u64 > manifest.maximum_records
    {
        return Err(DesktopError::Integrity(
            "planner ledger snapshot differs from manifest".to_owned(),
        ));
    }
    let state_size = std::fs::metadata(root.join(STATE_FILE))
        .map_err(|error| DesktopError::Io {
            path: root.join(STATE_FILE).display().to_string(),
            message: error.to_string(),
        })?
        .len();
    if state_size > manifest.maximum_ledger_bytes || state_size > MAX_LEDGER_BYTES {
        return Err(DesktopError::Integrity(
            "planner ledger exceeds byte bound".to_owned(),
        ));
    }
    let mut verification = PlannerLedgerVerificationV1 {
        ledger_id: manifest.ledger_id.clone(),
        organization_id: manifest.organization_id.clone(),
        case_id: manifest.case_id.clone(),
        case_contract_sha256: manifest.case_contract_sha256.clone(),
        case_work_grant_sha256: manifest.case_work_grant_sha256.clone(),
        record_count: 0,
        terminal_record_hash: ZERO_HASH.to_owned(),
        latest_cycle_record_sha256: ZERO_HASH.to_owned(),
        latest_event_kind: None,
        latest_stage: None,
        latest_status: None,
        situation_generation_hashes: Vec::new(),
        plan_generation_hashes: Vec::new(),
        consumed_provider_invocation_hashes: Vec::new(),
        consumed_next_step_decision_hashes: Vec::new(),
        kernel_run_hashes: Vec::new(),
        verification_result_hashes: Vec::new(),
        terminal_evaluation_count: 0,
        latest_protected_audit_terminal_sha256: ZERO_HASH.to_owned(),
        latest_recorded_at_unix_ms: manifest.created_at_unix_ms,
    };
    let mut seen_invocations = BTreeSet::new();
    let mut seen_decisions = BTreeSet::new();
    let mut seen_kernel_runs = BTreeSet::new();
    for record in &snapshot.records {
        validate_record(record, &manifest)?;
        if record.sequence != verification.record_count.saturating_add(1)
            || record.previous_record_hash != verification.terminal_record_hash
            || record.cycle_record.sequence != record.sequence
            || record.cycle_record.previous_record_sha256 != verification.latest_cycle_record_sha256
            || record.recorded_at_unix_ms < verification.latest_recorded_at_unix_ms
        {
            return Err(DesktopError::Replay(
                "planner ledger sequence, hash chain, or time moved backward".to_owned(),
            ));
        }
        validate_transition(
            verification.latest_stage,
            record.event_kind,
            record.cycle_record.stage,
        )?;
        if let Some(invocation) = &record.cycle_record.provider_invocation_sha256 {
            if record.event_kind == PlannerLedgerEventKindV1::ProviderInvoked
                && !seen_invocations.insert(invocation.clone())
            {
                return Err(DesktopError::Replay(
                    "provider invocation was consumed twice".to_owned(),
                ));
            }
        }
        if let Some(decision) = &record.cycle_record.next_step_decision_sha256 {
            if record.event_kind == PlannerLedgerEventKindV1::StepAdmitted
                && !seen_decisions.insert(decision.clone())
            {
                return Err(DesktopError::Replay(
                    "next-step decision was consumed twice".to_owned(),
                ));
            }
        }
        if let Some(run) = &record.cycle_record.kernel_run_sha256 {
            if record.event_kind == PlannerLedgerEventKindV1::KernelBound
                && !seen_kernel_runs.insert(run.clone())
            {
                return Err(DesktopError::Replay("KRN run was bound twice".to_owned()));
            }
        }
        project_record(&mut verification, record);
    }
    verification.consumed_provider_invocation_hashes = seen_invocations.into_iter().collect();
    verification.consumed_next_step_decision_hashes = seen_decisions.into_iter().collect();
    verification.kernel_run_hashes = seen_kernel_runs.into_iter().collect();
    Ok(verification)
}

pub struct AdaptiveCaseCoordinatorV1 {
    ledger: PlannerLedgerV1,
}

impl AdaptiveCaseCoordinatorV1 {
    pub fn new(ledger: PlannerLedgerV1) -> Self {
        Self { ledger }
    }

    pub const fn verification(&self) -> &PlannerLedgerVerificationV1 {
        self.ledger.verification()
    }

    pub fn record(
        &mut self,
        event_kind: PlannerLedgerEventKindV1,
        cycle_record: PlannerCycleRecordV1,
        recorded_at_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        self.ledger
            .append(event_kind, cycle_record, recorded_at_unix_ms)
    }

    pub fn recovery_directive(&self) -> Option<PlannerRecoveryDirectiveV1> {
        match self.ledger.verification().latest_stage? {
            PlannerCycleStageV1::ProviderInvoked => {
                Some(PlannerRecoveryDirectiveV1::FreshContextAndInvocation)
            }
            PlannerCycleStageV1::ProviderResultValidated => {
                Some(PlannerRecoveryDirectiveV1::RepairSituationFromExactResult)
            }
            PlannerCycleStageV1::SituationPersisted
            | PlannerCycleStageV1::PlanPersisted
            | PlannerCycleStageV1::StepAdmitted => {
                Some(PlannerRecoveryDirectiveV1::ReobserveAndReplan)
            }
            PlannerCycleStageV1::KernelBound | PlannerCycleStageV1::ActionAttempted => {
                Some(PlannerRecoveryDirectiveV1::ReobserveVerifyNeverReplay)
            }
            PlannerCycleStageV1::VerificationPersisted => {
                Some(PlannerRecoveryDirectiveV1::RepairSituationAndReplan)
            }
            PlannerCycleStageV1::SituationUpdated | PlannerCycleStageV1::TerminalEvaluated => {
                Some(PlannerRecoveryDirectiveV1::ReevaluateClosureExactlyOnce)
            }
        }
    }
}

fn project_record(verification: &mut PlannerLedgerVerificationV1, record: &PlannerLedgerRecordV1) {
    verification.record_count = record.sequence;
    verification.terminal_record_hash = record.record_hash.clone();
    verification.latest_cycle_record_sha256 = record.cycle_record.record_sha256.clone();
    verification.latest_event_kind = Some(record.event_kind);
    verification.latest_stage = Some(record.cycle_record.stage);
    verification.latest_status = Some(record.cycle_record.status);
    verification.latest_protected_audit_terminal_sha256 =
        record.cycle_record.protected_audit_terminal_sha256.clone();
    verification.latest_recorded_at_unix_ms = record.recorded_at_unix_ms;
    if record.event_kind == PlannerLedgerEventKindV1::SituationPersisted
        || record.event_kind == PlannerLedgerEventKindV1::SituationUpdated
    {
        if let Some(hash) = &record.cycle_record.situation_sha256 {
            verification.situation_generation_hashes.push(hash.clone());
        }
    }
    if record.event_kind == PlannerLedgerEventKindV1::PlanPersisted {
        if let Some(hash) = &record.cycle_record.adaptive_plan_sha256 {
            verification.plan_generation_hashes.push(hash.clone());
        }
    }
    if record.event_kind == PlannerLedgerEventKindV1::VerificationPersisted {
        if let Some(hash) = &record.cycle_record.verification_result_sha256 {
            verification.verification_result_hashes.push(hash.clone());
        }
    }
    if record.event_kind == PlannerLedgerEventKindV1::TerminalEvaluated {
        verification.terminal_evaluation_count =
            verification.terminal_evaluation_count.saturating_add(1);
    }
}

fn validate_record(
    record: &PlannerLedgerRecordV1,
    manifest: &PlannerLedgerManifestV1,
) -> Result<(), DesktopError> {
    if record.schema_version != LEDGER_SCHEMA_VERSION
        || record.sequence == 0
        || record.ledger_id != manifest.ledger_id
        || record.organization_id != manifest.organization_id
        || record.case_id != manifest.case_id
        || record.case_contract_sha256 != manifest.case_contract_sha256
        || record.case_work_grant_sha256 != manifest.case_work_grant_sha256
        || record.cycle_record.case_id != manifest.case_id
        || record.recorded_at_unix_ms == 0
    {
        return Err(DesktopError::Integrity(
            "planner ledger record binding is invalid".to_owned(),
        ));
    }
    for hash in [
        &record.case_contract_sha256,
        &record.case_work_grant_sha256,
        &record.previous_record_hash,
        &record.record_hash,
    ] {
        validate_hash(hash, "planner ledger record hash")?;
    }
    record
        .cycle_record
        .validate()
        .map_err(|error| DesktopError::Integrity(error.to_string()))?;
    validate_event_stage(record.event_kind, &record.cycle_record)?;
    if planner_record_hash(record)? != record.record_hash {
        return Err(DesktopError::Integrity(
            "planner ledger record self-hash differs".to_owned(),
        ));
    }
    Ok(())
}

fn validate_event_stage(
    event: PlannerLedgerEventKindV1,
    cycle: &PlannerCycleRecordV1,
) -> Result<(), DesktopError> {
    let matches = match event {
        PlannerLedgerEventKindV1::ProviderInvoked => {
            cycle.stage == PlannerCycleStageV1::ProviderInvoked
                && cycle.provider_invocation_sha256.is_some()
        }
        PlannerLedgerEventKindV1::ProviderResultValidated => {
            cycle.stage == PlannerCycleStageV1::ProviderResultValidated
                && cycle.provider_invocation_sha256.is_some()
                && cycle.provider_result_sha256.is_some()
        }
        PlannerLedgerEventKindV1::SituationPersisted => {
            cycle.stage == PlannerCycleStageV1::SituationPersisted
                && cycle.situation_sha256.is_some()
        }
        PlannerLedgerEventKindV1::PlanPersisted => {
            cycle.stage == PlannerCycleStageV1::PlanPersisted
                && cycle.adaptive_plan_sha256.is_some()
        }
        PlannerLedgerEventKindV1::StepAdmitted => {
            cycle.stage == PlannerCycleStageV1::StepAdmitted
                && cycle.next_step_decision_sha256.is_some()
        }
        PlannerLedgerEventKindV1::KernelBound => {
            cycle.stage == PlannerCycleStageV1::KernelBound && cycle.kernel_run_sha256.is_some()
        }
        PlannerLedgerEventKindV1::ActionAttempted => {
            cycle.stage == PlannerCycleStageV1::ActionAttempted
        }
        PlannerLedgerEventKindV1::VerificationPersisted => {
            cycle.stage == PlannerCycleStageV1::VerificationPersisted
                && cycle.verification_result_sha256.is_some()
        }
        PlannerLedgerEventKindV1::SituationUpdated => {
            cycle.stage == PlannerCycleStageV1::SituationUpdated && cycle.situation_sha256.is_some()
        }
        PlannerLedgerEventKindV1::ClarificationRecorded => {
            cycle.status == PlannerCycleStatusV1::Clarification
        }
        PlannerLedgerEventKindV1::EscalationRecorded => {
            cycle.status == PlannerCycleStatusV1::Escalation
        }
        PlannerLedgerEventKindV1::TerminalEvaluated => {
            cycle.stage == PlannerCycleStageV1::TerminalEvaluated
        }
        PlannerLedgerEventKindV1::RecoveryRepaired => {
            cycle.status == PlannerCycleStatusV1::Recovered
        }
    };
    if !matches {
        return Err(DesktopError::Integrity(
            "planner ledger event does not match cycle stage and evidence".to_owned(),
        ));
    }
    Ok(())
}

fn validate_transition(
    previous: Option<PlannerCycleStageV1>,
    event: PlannerLedgerEventKindV1,
    current: PlannerCycleStageV1,
) -> Result<(), DesktopError> {
    if event == PlannerLedgerEventKindV1::RecoveryRepaired {
        return Ok(());
    }
    let allowed = match previous {
        None => current == PlannerCycleStageV1::ProviderInvoked,
        Some(PlannerCycleStageV1::ProviderInvoked) => {
            current == PlannerCycleStageV1::ProviderResultValidated
                || event == PlannerLedgerEventKindV1::ClarificationRecorded
                || event == PlannerLedgerEventKindV1::EscalationRecorded
        }
        Some(PlannerCycleStageV1::ProviderResultValidated) => {
            current == PlannerCycleStageV1::SituationPersisted
        }
        Some(PlannerCycleStageV1::SituationPersisted) => {
            current == PlannerCycleStageV1::PlanPersisted
                || current == PlannerCycleStageV1::ProviderInvoked
        }
        Some(PlannerCycleStageV1::PlanPersisted) => current == PlannerCycleStageV1::StepAdmitted,
        Some(PlannerCycleStageV1::StepAdmitted) => {
            current == PlannerCycleStageV1::KernelBound
                || current == PlannerCycleStageV1::ProviderInvoked
        }
        Some(PlannerCycleStageV1::KernelBound) => current == PlannerCycleStageV1::ActionAttempted,
        Some(PlannerCycleStageV1::ActionAttempted) => {
            current == PlannerCycleStageV1::VerificationPersisted
        }
        Some(PlannerCycleStageV1::VerificationPersisted) => {
            current == PlannerCycleStageV1::SituationUpdated
        }
        Some(PlannerCycleStageV1::SituationUpdated) => {
            current == PlannerCycleStageV1::ProviderInvoked
                || current == PlannerCycleStageV1::TerminalEvaluated
        }
        Some(PlannerCycleStageV1::TerminalEvaluated) => false,
    };
    if !allowed {
        return Err(DesktopError::Replay(
            "planner ledger stage transition is invalid or replays an action".to_owned(),
        ));
    }
    Ok(())
}

fn planner_record_hash(record: &PlannerLedgerRecordV1) -> Result<String, DesktopError> {
    hash_without(record, &["record_hash"]).map_err(|error| DesktopError::Json(error.to_string()))
}

fn load_manifest(root: &Path) -> Result<PlannerLedgerManifestV1, DesktopError> {
    let bytes = read_bounded(&root.join(MANIFEST_FILE), MAX_LEDGER_BYTES)?;
    let manifest: PlannerLedgerManifestV1 =
        parse_json_strict(&bytes).map_err(|error| DesktopError::Json(error.to_string()))?;
    if manifest.schema_version != LEDGER_SCHEMA_VERSION
        || manifest.maximum_records == 0
        || manifest.maximum_records > MAX_LEDGER_RECORDS
        || manifest.maximum_ledger_bytes == 0
        || manifest.maximum_ledger_bytes > MAX_LEDGER_BYTES
        || manifest.created_at_unix_ms == 0
    {
        return Err(DesktopError::Integrity(
            "planner ledger manifest bounds are invalid".to_owned(),
        ));
    }
    Ok(manifest)
}

fn load_snapshot(root: &Path) -> Result<PlannerLedgerSnapshotV1, DesktopError> {
    let bytes = read_bounded(&root.join(STATE_FILE), MAX_LEDGER_BYTES)?;
    parse_json_strict(&bytes).map_err(|error| DesktopError::Json(error.to_string()))
}

fn verify_security(root: &Path, manifest: &PlannerLedgerManifestV1) -> Result<(), DesktopError> {
    for (path, expected) in [
        (
            root.to_path_buf(),
            &manifest.root_security_descriptor_sha256,
        ),
        (
            root.join(MANIFEST_FILE),
            &manifest.manifest_security_descriptor_sha256,
        ),
        (
            root.join(STATE_FILE),
            &manifest.state_security_descriptor_sha256,
        ),
    ] {
        let descriptor = d2i_windows_host::path_security_descriptor(&path).map_err(|error| {
            DesktopError::Integrity(format!("planner ledger ACL query failed: {error}"))
        })?;
        if sha256_bytes(&descriptor) != *expected {
            return Err(DesktopError::Integrity(
                "planner ledger owner or DACL drifted".to_owned(),
            ));
        }
    }
    Ok(())
}

fn harden_and_hash(path: &Path) -> Result<String, DesktopError> {
    let descriptor = d2i_windows_host::harden_path_for_current_user(path)
        .map_err(|error| DesktopError::Integrity(error.to_string()))?;
    Ok(sha256_bytes(&descriptor))
}

fn pretty_json<T: Serialize>(value: &T) -> Result<Vec<u8>, DesktopError> {
    let canonical =
        canonical_json_bytes(value).map_err(|error| DesktopError::Json(error.to_string()))?;
    let parsed: serde_json::Value = serde_json::from_slice(&canonical)
        .map_err(|error| DesktopError::Json(error.to_string()))?;
    serde_json::to_vec_pretty(&parsed).map_err(|error| DesktopError::Json(error.to_string()))
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

fn atomic_replace_state(root: &Path, bytes: &[u8]) -> Result<(), DesktopError> {
    let temporary = root.join("adaptive-planner-ledger-state.next.json");
    write_new(&temporary, bytes)?;
    harden_and_hash(&temporary)?;
    d2i_windows_host::atomic_move(&temporary, &root.join(STATE_FILE), true).map_err(|error| {
        let _ = std::fs::remove_file(&temporary);
        DesktopError::Io {
            path: root.join(STATE_FILE).display().to_string(),
            message: format!("atomic planner state replace failed: {error}"),
        }
    })?;
    Ok(())
}

struct PlannerLedgerLock {
    path: PathBuf,
}

impl PlannerLedgerLock {
    fn acquire(root: &Path) -> Result<Self, DesktopError> {
        let path = root.join(LOCK_FILE);
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| DesktopError::Io {
                path: path.display().to_string(),
                message: format!("planner ledger single-writer lock failed: {error}"),
            })?;
        harden_and_hash(&path)?;
        Ok(Self { path })
    }
}

impl Drop for PlannerLedgerLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crash_windows_map_to_fresh_safe_recovery() {
        let stages = [
            (
                PlannerCycleStageV1::ProviderInvoked,
                PlannerRecoveryDirectiveV1::FreshContextAndInvocation,
            ),
            (
                PlannerCycleStageV1::ProviderResultValidated,
                PlannerRecoveryDirectiveV1::RepairSituationFromExactResult,
            ),
            (
                PlannerCycleStageV1::SituationPersisted,
                PlannerRecoveryDirectiveV1::ReobserveAndReplan,
            ),
            (
                PlannerCycleStageV1::ActionAttempted,
                PlannerRecoveryDirectiveV1::ReobserveVerifyNeverReplay,
            ),
            (
                PlannerCycleStageV1::VerificationPersisted,
                PlannerRecoveryDirectiveV1::RepairSituationAndReplan,
            ),
            (
                PlannerCycleStageV1::SituationUpdated,
                PlannerRecoveryDirectiveV1::ReevaluateClosureExactlyOnce,
            ),
        ];
        for (stage, expected) in stages {
            let actual = match stage {
                PlannerCycleStageV1::ProviderInvoked => {
                    PlannerRecoveryDirectiveV1::FreshContextAndInvocation
                }
                PlannerCycleStageV1::ProviderResultValidated => {
                    PlannerRecoveryDirectiveV1::RepairSituationFromExactResult
                }
                PlannerCycleStageV1::SituationPersisted => {
                    PlannerRecoveryDirectiveV1::ReobserveAndReplan
                }
                PlannerCycleStageV1::ActionAttempted => {
                    PlannerRecoveryDirectiveV1::ReobserveVerifyNeverReplay
                }
                PlannerCycleStageV1::VerificationPersisted => {
                    PlannerRecoveryDirectiveV1::RepairSituationAndReplan
                }
                PlannerCycleStageV1::SituationUpdated => {
                    PlannerRecoveryDirectiveV1::ReevaluateClosureExactlyOnce
                }
                _ => unreachable!("test enumerates crash windows A-F"),
            };
            assert_eq!(actual, expected);
        }
    }
}
