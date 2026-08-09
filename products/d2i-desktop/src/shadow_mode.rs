use crate::{read_bounded, sha256_bytes, write_new, DesktopError};
use d2i_shadow_mode::{
    canonical_json_bytes, hash_without, parse_json_strict, parse_json_strict_with_limits,
    validate_observation_grant, HumanReferenceStepV1, RoleShadowEvaluationSnapshotV1,
    ShadowAdjudicationV1, ShadowCaseEnrollmentV1, ShadowCycleV1, ShadowEvaluationCohortV1,
    ShadowEvaluationExportBundleV1, ShadowEvaluationReportV1, ShadowMetricResultV1,
    ShadowModeError, ShadowModeProfileV1, ShadowObservationGrantV1, ShadowProposalCommitmentV1,
    ShadowProposalRevealReceiptV1, ShadowProposalV1, ShadowReadinessAssessmentV1,
    ShadowSessionEvaluationV1, ShadowSessionV1, ShadowStepComparisonV1, ZERO_HASH,
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

const STORE_SCHEMA_VERSION: u32 = 1;
const MANIFEST_FILE: &str = "manifest.json";
const LEDGER_FILE: &str = "ledger.json";
const INDEX_FILE: &str = "index.json";
const LOCK_FILE: &str = "coordinator.lock";
const POISON_FILE: &str = "poisoned";
const MAX_STORE_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_STORE_RECORDS: usize = 100_000;
const MAX_STORE_OBJECTS: usize = 100_000;
const MAX_STORE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_OBSERVED_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;

const ARTIFACT_DIRECTORIES: [&str; 11] = [
    "cohorts",
    "enrollments",
    "sessions",
    "sealed-proposals",
    "human-reference",
    "comparisons",
    "adjudications",
    "metrics",
    "readiness",
    "reports",
    "exports",
];

/// Hash-only, read-only UIA state used by one Shadow cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowFixtureObservationV1 {
    pub schema_version: u32,
    pub observation_id: String,
    pub sequence: u64,
    pub process_id: u32,
    pub process_executable_sha256: String,
    pub process_session_id: u32,
    pub window_title_sha256: String,
    pub employee_input_value_sha256: String,
    pub saved_value_sha256: String,
    pub save_status_id: String,
    pub save_revision: u32,
    pub observation_side_effect_count: u32,
    pub grant_sha256: String,
    pub observed_at_unix_ms: u64,
    pub observation_sha256: String,
}

impl ShadowFixtureObservationV1 {
    fn seal(mut self) -> Result<Self, DesktopError> {
        self.observation_sha256 =
            hash_without(&self, &["observation_sha256"]).map_err(shadow_error)?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), DesktopError> {
        if self.schema_version != STORE_SCHEMA_VERSION
            || self.sequence == 0
            || self.process_id == 0
            || self.observed_at_unix_ms == 0
            || self.observation_side_effect_count != 0
        {
            return Err(DesktopError::Integrity(
                "Shadow fixture observation identity or side-effect count is invalid".to_owned(),
            ));
        }
        validate_id(&self.observation_id, "Shadow observation")?;
        validate_id(&self.save_status_id, "Shadow save status")?;
        for value in [
            &self.process_executable_sha256,
            &self.window_title_sha256,
            &self.employee_input_value_sha256,
            &self.saved_value_sha256,
            &self.grant_sha256,
            &self.observation_sha256,
        ] {
            validate_hash(value, "Shadow observation binding")?;
        }
        if hash_without(self, &["observation_sha256"]).map_err(shadow_error)?
            != self.observation_sha256
        {
            return Err(DesktopError::Integrity(
                "Shadow fixture observation hash differs".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Quarantine-only WORK-600 ingress for a meaningful Shadow divergence.
///
/// This is deliberately distinct from `LearningCandidateV1`, whose source is
/// a verified terminal Episode. It has no evaluation, promotion, or production
/// mutation path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowDivergenceCandidateV1 {
    pub schema_version: u32,
    pub candidate_id: String,
    pub organization_id: String,
    pub memory_namespace_id: String,
    pub memory_namespace_sha256: String,
    pub role_contract_sha256: String,
    pub work_class_id: String,
    pub source_shadow_session_sha256: String,
    pub source_shadow_evaluation_sha256: String,
    pub source_comparison_sha256: String,
    pub source_adjudication_sha256: String,
    pub source_model_holdout_report_sha256: String,
    pub candidate_kind_id: String,
    pub quarantine_status_id: String,
    pub production_eligible: bool,
    pub production_mutation_count: u32,
    pub data_class_ids: Vec<String>,
    pub redaction_proof_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub candidate_sha256: String,
}

impl ShadowDivergenceCandidateV1 {
    pub fn seal(mut self) -> Result<Self, DesktopError> {
        for values in [
            &mut self.data_class_ids,
            &mut self.redaction_proof_ids,
            &mut self.evidence_ids,
        ] {
            values.sort();
            values.dedup();
        }
        self.candidate_sha256 = hash_without(&self, &["candidate_sha256"]).map_err(shadow_error)?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), DesktopError> {
        if self.schema_version != STORE_SCHEMA_VERSION
            || self.quarantine_status_id != "work600-quarantined-shadow-ingress"
            || self.production_eligible
            || self.production_mutation_count != 0
            || self.data_class_ids.is_empty()
            || self.data_class_ids.len() > 16
            || self.redaction_proof_ids.is_empty()
            || self.redaction_proof_ids.len() > 16
            || self.evidence_ids.is_empty()
            || self.evidence_ids.len() > 32
        {
            return Err(DesktopError::AccessDenied(
                "Shadow divergence is not a bounded quarantine-only candidate".to_owned(),
            ));
        }
        for (value, label) in [
            (&self.candidate_id, "Shadow candidate"),
            (&self.organization_id, "Shadow candidate organization"),
            (&self.memory_namespace_id, "Shadow candidate namespace"),
            (&self.work_class_id, "Shadow candidate work class"),
            (&self.candidate_kind_id, "Shadow candidate kind"),
            (&self.quarantine_status_id, "Shadow candidate status"),
        ] {
            validate_id(value, label)?;
        }
        for value in [
            &self.memory_namespace_sha256,
            &self.role_contract_sha256,
            &self.source_shadow_session_sha256,
            &self.source_shadow_evaluation_sha256,
            &self.source_comparison_sha256,
            &self.source_adjudication_sha256,
            &self.source_model_holdout_report_sha256,
            &self.candidate_sha256,
        ] {
            validate_hash(value, "Shadow candidate binding")?;
        }
        for value in self
            .data_class_ids
            .iter()
            .chain(&self.redaction_proof_ids)
            .chain(&self.evidence_ids)
        {
            validate_id(value, "Shadow candidate bounded value")?;
        }
        if hash_without(self, &["candidate_sha256"]).map_err(shadow_error)? != self.candidate_sha256
        {
            return Err(DesktopError::Integrity(
                "Shadow divergence candidate hash differs".to_owned(),
            ));
        }
        let encoded = canonical_json_bytes(self).map_err(shadow_error)?;
        let lowered = String::from_utf8_lossy(&encoded).to_ascii_lowercase();
        if [
            "credential",
            "api_key",
            "authorization",
            "private_key",
            "raw-ui",
            "raw_ui",
            "locator",
            "selector",
            "coordinate",
            "personal-email",
            "personal-phone",
            "personal-name",
            "raw-prompt",
            "chain-of-thought",
        ]
        .iter()
        .any(|marker| lowered.contains(marker))
        {
            return Err(DesktopError::AccessDenied(
                "Shadow divergence candidate contains a prohibited data class".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Collects one fresh hash-only UIA snapshot under a signed non-executable grant.
#[allow(clippy::too_many_arguments)]
pub fn collect_shadow_fixture_observation(
    grant: &ShadowObservationGrantV1,
    profile: &ShadowModeProfileV1,
    verifying_key: &VerifyingKey,
    trusted_now_unix_ms: u64,
    observation_id: String,
    sequence: u64,
    process_id: u32,
    expected_process_executable_sha256: &str,
    expected_window_title_sha256: &str,
) -> Result<ShadowFixtureObservationV1, DesktopError> {
    validate_observation_grant(grant, profile, verifying_key, trusted_now_unix_ms)
        .map_err(shadow_error)?;
    platform_observation::collect(
        grant,
        trusted_now_unix_ms,
        observation_id,
        sequence,
        process_id,
        expected_process_executable_sha256,
        expected_window_title_sha256,
    )
}

/// Closed non-executable artifact set accepted by the protected Shadow store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "artifact_kind", content = "artifact", rename_all = "snake_case")]
pub enum ShadowStoreArtifactV1 {
    Cohort(ShadowEvaluationCohortV1),
    Enrollment(ShadowCaseEnrollmentV1),
    Session(ShadowSessionV1),
    SessionEvaluation(ShadowSessionEvaluationV1),
    Proposal(ShadowProposalV1),
    Commitment(ShadowProposalCommitmentV1),
    HumanStep(HumanReferenceStepV1),
    Reveal(ShadowProposalRevealReceiptV1),
    Cycle(ShadowCycleV1),
    Comparison(ShadowStepComparisonV1),
    Adjudication(ShadowAdjudicationV1),
    Metric(ShadowMetricResultV1),
    Snapshot(RoleShadowEvaluationSnapshotV1),
    Readiness(ShadowReadinessAssessmentV1),
    Report(ShadowEvaluationReportV1),
    Export(ShadowEvaluationExportBundleV1),
}

/// Append-only event kind. No event represents execution, activation, or Case mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowStoreRecordKindV1 {
    CohortStored,
    EnrollmentStored,
    SessionStored,
    SessionEvaluationStored,
    ProposalStored,
    CommitmentStored,
    HumanStepStored,
    RevealStored,
    CycleStored,
    ComparisonStored,
    AdjudicationStored,
    MetricStored,
    SnapshotStored,
    ReadinessStored,
    ReportStored,
    ExportStored,
}

/// One immutable object insertion in the protected hash chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowStoreRecordV1 {
    pub schema_version: u32,
    pub sequence: u64,
    pub record_kind: ShadowStoreRecordKindV1,
    pub artifact_id: String,
    pub artifact_sha256: String,
    pub relative_object_path: String,
    pub object_security_descriptor_sha256: String,
    pub recorded_at_unix_ms: u64,
    pub previous_record_sha256: String,
    pub record_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowStoreLedgerV1 {
    schema_version: u32,
    records: Vec<ShadowStoreRecordV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowCycleIndexV1 {
    proposal_sha256: Option<String>,
    commitment_sha256: Option<String>,
    human_step_sha256: Option<String>,
    reveal_sha256: Option<String>,
    comparison_sha256: Option<String>,
    adjudication_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowStoreIndexV1 {
    schema_version: u32,
    generation: u64,
    ledger_record_count: u64,
    ledger_terminal_sha256: String,
    artifacts_by_id: BTreeMap<String, String>,
    cycle_states: BTreeMap<String, ShadowCycleIndexV1>,
    index_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowStoreManifestV1 {
    schema_version: u32,
    organization_id: String,
    role_contract_sha256: String,
    profile_sha256: String,
    cohort_sha256: String,
    maximum_store_bytes: u64,
    created_at_unix_ms: u64,
    root_security_descriptor_sha256: String,
    manifest_security_descriptor_sha256: String,
    ledger_security_descriptor_sha256: String,
    index_security_descriptor_sha256: String,
    directory_security_descriptor_hashes: BTreeMap<String, String>,
}

/// Full verification result for chain, objects, derived index, and DACLs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowStoreVerificationV1 {
    pub organization_id: String,
    pub role_contract_sha256: String,
    pub profile_sha256: String,
    pub cohort_sha256: String,
    pub ledger_record_count: u64,
    pub ledger_terminal_sha256: String,
    pub index_sha256: String,
    pub object_count: u32,
    pub orphan_object_count: u32,
    pub total_store_bytes: u64,
    pub stale_index: bool,
    pub index_repaired: bool,
    pub rollback_detected: bool,
    pub poisoned: bool,
    pub residual_lock_present: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowRecoveryWindowV1 {
    EnrollmentBeforeInitialObservation,
    ProposalBeforeCommitment,
    CommitmentBeforeHumanAction,
    HumanStepBeforePostObservation,
    PostObservationBeforeComparison,
    ComparisonBeforeAdjudication,
    SessionTerminalBeforeMetrics,
    ReadinessBeforeReport,
    ReportBeforePublicationReceipt,
}

/// A read-only restart directive. Every replay counter is structurally zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowRecoveryPlanV1 {
    pub window: ShadowRecoveryWindowV1,
    pub durable_artifact_sha256: String,
    pub directive_id: String,
    pub exactly_once_repair_required: bool,
    pub ai_proposal_replay_count: u32,
    pub human_action_replay_count: u32,
    pub model_invocation_replay_count: u32,
    pub adapter_action_replay_count: u32,
}

/// Verifies the protected store and derives the only permitted recovery step.
/// It never invokes a provider, reference action, adapter, or production path.
pub fn plan_shadow_recovery(root: &Path) -> Result<Option<ShadowRecoveryPlanV1>, DesktopError> {
    verify_shadow_store(root, None)?;
    let ledger = load_ledger(root)?;
    Ok(ledger.records.last().and_then(|record| {
        recovery_plan_for_record(record.record_kind, record.artifact_sha256.clone())
    }))
}

fn recovery_plan_for_record(
    kind: ShadowStoreRecordKindV1,
    hash: String,
) -> Option<ShadowRecoveryPlanV1> {
    let (window, directive, exactly_once) = match kind {
        ShadowStoreRecordKindV1::EnrollmentStored => (
            ShadowRecoveryWindowV1::EnrollmentBeforeInitialObservation,
            "revalidate-case-profile-then-acquire-fresh-observation",
            false,
        ),
        ShadowStoreRecordKindV1::ProposalStored => (
            ShadowRecoveryWindowV1::ProposalBeforeCommitment,
            "discard-uncommitted-proposal-and-forbid-human-action",
            false,
        ),
        ShadowStoreRecordKindV1::CommitmentStored => (
            ShadowRecoveryWindowV1::CommitmentBeforeHumanAction,
            "revalidate-observation-or-abort-stale-cycle",
            false,
        ),
        ShadowStoreRecordKindV1::HumanStepStored => (
            ShadowRecoveryWindowV1::HumanStepBeforePostObservation,
            "acquire-fresh-post-observation-without-replaying-human-action",
            false,
        ),
        ShadowStoreRecordKindV1::RevealStored => (
            ShadowRecoveryWindowV1::PostObservationBeforeComparison,
            "repair-exact-bound-comparison",
            true,
        ),
        ShadowStoreRecordKindV1::ComparisonStored => (
            ShadowRecoveryWindowV1::ComparisonBeforeAdjudication,
            "repair-exactly-one-independent-adjudication",
            true,
        ),
        ShadowStoreRecordKindV1::CycleStored | ShadowStoreRecordKindV1::SessionEvaluationStored => {
            (
                ShadowRecoveryWindowV1::SessionTerminalBeforeMetrics,
                "repair-deterministic-role-metrics",
                true,
            )
        }
        ShadowStoreRecordKindV1::ReadinessStored => (
            ShadowRecoveryWindowV1::ReadinessBeforeReport,
            "repair-bound-shadow-evaluation-report",
            true,
        ),
        ShadowStoreRecordKindV1::ReportStored => (
            ShadowRecoveryWindowV1::ReportBeforePublicationReceipt,
            "repair-exactly-one-approved-internal-publication",
            true,
        ),
        _ => return None,
    };
    Some(ShadowRecoveryPlanV1 {
        window,
        durable_artifact_sha256: hash,
        directive_id: directive.to_owned(),
        exactly_once_repair_required: exactly_once,
        ai_proposal_replay_count: 0,
        human_action_replay_count: 0,
        model_invocation_replay_count: 0,
        adapter_action_replay_count: 0,
    })
}

/// Single-writer facade. A durable-write failure poisons later mutation.
#[derive(Debug)]
pub struct ShadowStoreV1 {
    root: PathBuf,
    manifest: ShadowStoreManifestV1,
    verification: ShadowStoreVerificationV1,
    poisoned: bool,
}

/// Creates a separate current-user/SYSTEM protected Shadow store.
pub fn initialize_shadow_store(
    root: &Path,
    organization_id: String,
    role_contract_sha256: String,
    profile_sha256: String,
    cohort_sha256: String,
    maximum_store_bytes: u64,
    created_at_unix_ms: u64,
) -> Result<ShadowStoreV1, DesktopError> {
    validate_id(&organization_id, "organization")?;
    for (value, label) in [
        (&role_contract_sha256, "Role Contract"),
        (&profile_sha256, "Shadow Profile"),
        (&cohort_sha256, "Shadow cohort"),
    ] {
        validate_hash(value, label)?;
    }
    if root.exists()
        || maximum_store_bytes == 0
        || maximum_store_bytes > MAX_STORE_BYTES
        || created_at_unix_ms == 0
    {
        return Err(DesktopError::Invalid(
            "Shadow store root, bounds, or creation time are invalid".to_owned(),
        ));
    }
    std::fs::create_dir(root).map_err(|error| io_error(root, error))?;
    reject_reparse(root, "Shadow store root")?;
    for directory in ARTIFACT_DIRECTORIES {
        let path = root.join(directory);
        std::fs::create_dir(&path).map_err(|error| io_error(&path, error))?;
    }
    write_new(
        &root.join(LEDGER_FILE),
        &pretty_json(&ShadowStoreLedgerV1 {
            schema_version: STORE_SCHEMA_VERSION,
            records: Vec::new(),
        })?,
    )?;
    write_new(&root.join(INDEX_FILE), &pretty_json(&empty_index()?)?)?;
    let placeholder = ShadowStoreManifestV1 {
        schema_version: STORE_SCHEMA_VERSION,
        organization_id,
        role_contract_sha256,
        profile_sha256,
        cohort_sha256,
        maximum_store_bytes,
        created_at_unix_ms,
        root_security_descriptor_sha256: ZERO_HASH.to_owned(),
        manifest_security_descriptor_sha256: ZERO_HASH.to_owned(),
        ledger_security_descriptor_sha256: ZERO_HASH.to_owned(),
        index_security_descriptor_sha256: ZERO_HASH.to_owned(),
        directory_security_descriptor_hashes: BTreeMap::new(),
    };
    write_new(&root.join(MANIFEST_FILE), &pretty_json(&placeholder)?)?;
    let mut directories = BTreeMap::new();
    for directory in ARTIFACT_DIRECTORIES {
        directories.insert(
            directory.to_owned(),
            harden_and_hash(&root.join(directory))?,
        );
    }
    let manifest = ShadowStoreManifestV1 {
        root_security_descriptor_sha256: harden_and_hash(root)?,
        manifest_security_descriptor_sha256: harden_and_hash(&root.join(MANIFEST_FILE))?,
        ledger_security_descriptor_sha256: harden_and_hash(&root.join(LEDGER_FILE))?,
        index_security_descriptor_sha256: harden_and_hash(&root.join(INDEX_FILE))?,
        directory_security_descriptor_hashes: directories,
        ..placeholder
    };
    overwrite_existing(&root.join(MANIFEST_FILE), &pretty_json(&manifest)?)?;
    ShadowStoreV1::open(root, None)
}

impl ShadowStoreV1 {
    /// Opens a verified store and repairs only an exact stale derived index.
    pub fn open(root: &Path, expected_terminal: Option<&str>) -> Result<Self, DesktopError> {
        let manifest = load_manifest(root)?;
        let mut verification = verify_shadow_store(root, expected_terminal)?;
        if verification.orphan_object_count != 0 {
            return Err(DesktopError::Integrity(
                "Shadow store has orphan objects; explicit recovery is required".to_owned(),
            ));
        }
        if verification.stale_index {
            let _lock = ShadowStoreLock::acquire(root)?;
            let ledger = load_ledger(root)?;
            let rebuilt = rebuild_index(root, &ledger)?;
            atomic_replace(root, INDEX_FILE, &pretty_json(&rebuilt)?)?;
            verification = verify_shadow_store(root, expected_terminal)?;
            verification.index_repaired = true;
        }
        let poisoned = verification.poisoned;
        Ok(Self {
            root: root.to_path_buf(),
            manifest,
            verification,
            poisoned,
        })
    }

    pub const fn verification(&self) -> &ShadowStoreVerificationV1 {
        &self.verification
    }

    /// Stores an unsigned immutable artifact. Signed artifacts use dedicated methods.
    pub fn store(
        &mut self,
        artifact: ShadowStoreArtifactV1,
        recorded_at_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        if matches!(
            artifact,
            ShadowStoreArtifactV1::HumanStep(_) | ShadowStoreArtifactV1::Readiness(_)
        ) {
            return Err(DesktopError::AccessDenied(
                "signed Shadow artifacts require signature-verifying entry points".to_owned(),
            ));
        }
        self.store_verified(artifact, recorded_at_unix_ms)
    }

    pub fn store_human_step(
        &mut self,
        step: HumanReferenceStepV1,
        verifying_key: &VerifyingKey,
        recorded_at_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        step.verify_signature(verifying_key).map_err(shadow_error)?;
        self.store_verified(ShadowStoreArtifactV1::HumanStep(step), recorded_at_unix_ms)
    }

    pub fn store_readiness(
        &mut self,
        readiness: ShadowReadinessAssessmentV1,
        verifying_key: &VerifyingKey,
        recorded_at_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        readiness
            .verify_signature(verifying_key)
            .map_err(shadow_error)?;
        self.store_verified(
            ShadowStoreArtifactV1::Readiness(readiness),
            recorded_at_unix_ms,
        )
    }

    fn store_verified(
        &mut self,
        artifact: ShadowStoreArtifactV1,
        recorded_at_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        if self.poisoned || self.root.join(POISON_FILE).exists() {
            return Err(DesktopError::Integrity(
                "Shadow store is poisoned after a durable-write failure".to_owned(),
            ));
        }
        if recorded_at_unix_ms == 0 {
            return Err(DesktopError::Invalid(
                "Shadow store time is zero".to_owned(),
            ));
        }
        let _lock = ShadowStoreLock::acquire(&self.root)?;
        let preflight = self.preflight_store(&artifact, recorded_at_unix_ms)?;
        let StorePreflight::Pending {
            metadata,
            ledger,
            index,
        } = preflight
        else {
            let StorePreflight::Existing(hash) = preflight else {
                unreachable!("closed Shadow store preflight state")
            };
            return Ok(hash);
        };
        let result =
            self.commit_store_transaction(artifact, metadata, ledger, *index, recorded_at_unix_ms);
        if result.is_err() {
            self.poisoned = true;
            let _ = write_poison(&self.root);
        }
        result
    }

    fn preflight_store(
        &self,
        artifact: &ShadowStoreArtifactV1,
        recorded_at_unix_ms: u64,
    ) -> Result<StorePreflight, DesktopError> {
        verify_security(&self.root, &self.manifest)?;
        let ledger = load_ledger(&self.root)?;
        verify_ledger(&ledger)?;
        let mut index = load_index(&self.root)?;
        if ledger.records.len() as u64 != self.verification.ledger_record_count
            || ledger_terminal(&ledger) != self.verification.ledger_terminal_sha256
            || index.ledger_record_count != self.verification.ledger_record_count
            || index.ledger_terminal_sha256 != self.verification.ledger_terminal_sha256
            || index.index_sha256 != self.verification.index_sha256
        {
            return Err(DesktopError::Integrity(
                "Shadow store changed after coordinator open".to_owned(),
            ));
        }
        let metadata = artifact_metadata(artifact)?;
        if let Some(existing) = index.artifacts_by_id.get(&metadata.id) {
            if existing == &metadata.hash {
                return Ok(StorePreflight::Existing(metadata.hash));
            }
            return Err(DesktopError::Integrity(
                "Shadow artifact identity changed immutable content".to_owned(),
            ));
        }
        validate_append_position(&ledger, recorded_at_unix_ms)?;
        verify_cycle_order(&self.root, artifact, &metadata, &index)?;
        apply_index(&mut index, &metadata)?;
        apply_non_keyed_phase(&self.root, &mut index, artifact, &metadata.hash)?;
        Ok(StorePreflight::Pending {
            metadata,
            ledger,
            index: Box::new(index),
        })
    }

    fn commit_store_transaction(
        &mut self,
        artifact: ShadowStoreArtifactV1,
        metadata: ArtifactMetadata,
        mut ledger: ShadowStoreLedgerV1,
        mut index: ShadowStoreIndexV1,
        recorded_at_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        let object_security = persist_object(&self.root, &artifact, &metadata)?;
        append_record(&mut ledger, &metadata, object_security, recorded_at_unix_ms)?;
        atomic_replace(&self.root, LEDGER_FILE, &pretty_json(&ledger)?)?;
        index.generation = index.generation.saturating_add(1);
        index.ledger_record_count = ledger.records.len() as u64;
        index.ledger_terminal_sha256 = ledger_terminal(&ledger);
        index.index_sha256 = index_hash(&index)?;
        atomic_replace(&self.root, INDEX_FILE, &pretty_json(&index)?)?;
        verify_ledger(&ledger)?;
        let persisted_index = load_index(&self.root)?;
        if persisted_index != index {
            return Err(DesktopError::Integrity(
                "Shadow persisted index differs from the committed index".to_owned(),
            ));
        }
        let (object_count, total_store_bytes) = store_size(&self.root)?;
        if total_store_bytes > self.manifest.maximum_store_bytes
            || object_count as usize > MAX_STORE_OBJECTS + ARTIFACT_DIRECTORIES.len() + 4
        {
            return Err(DesktopError::Integrity(
                "Shadow store exceeds manifest object or byte bound".to_owned(),
            ));
        }
        self.verification = ShadowStoreVerificationV1 {
            organization_id: self.manifest.organization_id.clone(),
            role_contract_sha256: self.manifest.role_contract_sha256.clone(),
            profile_sha256: self.manifest.profile_sha256.clone(),
            cohort_sha256: self.manifest.cohort_sha256.clone(),
            ledger_record_count: ledger.records.len() as u64,
            ledger_terminal_sha256: ledger_terminal(&ledger),
            index_sha256: index.index_sha256,
            object_count,
            orphan_object_count: 0,
            total_store_bytes,
            stale_index: false,
            index_repaired: false,
            rollback_detected: false,
            poisoned: false,
            residual_lock_present: false,
        };
        Ok(metadata.hash)
    }
}

enum StorePreflight {
    Existing(String),
    Pending {
        metadata: ArtifactMetadata,
        ledger: ShadowStoreLedgerV1,
        index: Box<ShadowStoreIndexV1>,
    },
}

/// Verifies DACLs, chain, objects, ordering index, rollback pin, and bounds.
pub fn verify_shadow_store(
    root: &Path,
    expected_terminal: Option<&str>,
) -> Result<ShadowStoreVerificationV1, DesktopError> {
    reject_reparse(root, "Shadow store root")?;
    let manifest = load_manifest(root)?;
    verify_security(root, &manifest)?;
    let ledger = load_ledger(root)?;
    verify_ledger(&ledger)?;
    let terminal = ledger_terminal(&ledger);
    if expected_terminal.is_some_and(|expected| expected != terminal) {
        return Err(DesktopError::Integrity(
            "Shadow ledger rollback or unexpected advance detected".to_owned(),
        ));
    }
    let rebuilt = rebuild_index(root, &ledger)?;
    let stale_index = load_index(root).ok().as_ref() != Some(&rebuilt);
    let referenced = ledger
        .records
        .iter()
        .map(|record| record.relative_object_path.as_str())
        .collect::<BTreeSet<_>>();
    let object_paths = list_object_paths(root)?;
    let orphan_count = object_paths
        .iter()
        .filter(|path| !referenced.contains(path.as_str()))
        .count();
    let (object_count, total_store_bytes) = store_size(root)?;
    if total_store_bytes > manifest.maximum_store_bytes || object_paths.len() > MAX_STORE_OBJECTS {
        return Err(DesktopError::Integrity(
            "Shadow store exceeds object or byte bound".to_owned(),
        ));
    }
    Ok(ShadowStoreVerificationV1 {
        organization_id: manifest.organization_id,
        role_contract_sha256: manifest.role_contract_sha256,
        profile_sha256: manifest.profile_sha256,
        cohort_sha256: manifest.cohort_sha256,
        ledger_record_count: ledger.records.len() as u64,
        ledger_terminal_sha256: terminal,
        index_sha256: rebuilt.index_sha256,
        object_count,
        orphan_object_count: u32::try_from(orphan_count)
            .map_err(|_| DesktopError::Integrity("orphan count overflow".to_owned()))?,
        total_store_bytes,
        stale_index,
        index_repaired: false,
        rollback_detected: false,
        poisoned: root.join(POISON_FILE).exists(),
        residual_lock_present: root.join(LOCK_FILE).exists(),
    })
}

/// Removes only unreferenced objects, clears poison, and rebuilds the exact index.
pub fn recover_shadow_store(root: &Path) -> Result<ShadowStoreVerificationV1, DesktopError> {
    let _lock = ShadowStoreLock::acquire(root)?;
    let manifest = load_manifest(root)?;
    verify_security(root, &manifest)?;
    let ledger = load_ledger(root)?;
    verify_ledger(&ledger)?;
    let referenced = ledger
        .records
        .iter()
        .map(|record| record.relative_object_path.as_str())
        .collect::<BTreeSet<_>>();
    for relative in list_object_paths(root)? {
        if !referenced.contains(relative.as_str()) {
            let path = safe_relative_path(root, &relative)?;
            std::fs::remove_file(&path).map_err(|error| io_error(&path, error))?;
        }
    }
    let rebuilt = rebuild_index(root, &ledger)?;
    atomic_replace(root, INDEX_FILE, &pretty_json(&rebuilt)?)?;
    if root.join(POISON_FILE).exists() {
        std::fs::remove_file(root.join(POISON_FILE))
            .map_err(|error| io_error(&root.join(POISON_FILE), error))?;
    }
    let mut verification = verify_shadow_store(root, Some(&ledger_terminal(&ledger)))?;
    verification.index_repaired = true;
    verification.residual_lock_present = false;
    Ok(verification)
}

#[derive(Debug)]
struct ArtifactMetadata {
    kind: ShadowStoreRecordKindV1,
    id: String,
    hash: String,
    directory: &'static str,
    cycle_key: Option<String>,
}

fn artifact_metadata(artifact: &ShadowStoreArtifactV1) -> Result<ArtifactMetadata, DesktopError> {
    let metadata = match artifact {
        ShadowStoreArtifactV1::Cohort(value) => {
            value.validate().map_err(shadow_error)?;
            metadata(
                ShadowStoreRecordKindV1::CohortStored,
                value.cohort_id.clone(),
                value.cohort_sha256.clone(),
                "cohorts",
                None,
            )
        }
        ShadowStoreArtifactV1::Enrollment(value) => {
            value.validate().map_err(shadow_error)?;
            metadata(
                ShadowStoreRecordKindV1::EnrollmentStored,
                value.enrollment_id.clone(),
                value.enrollment_sha256.clone(),
                "enrollments",
                None,
            )
        }
        ShadowStoreArtifactV1::Session(value) => {
            value.validate().map_err(shadow_error)?;
            metadata(
                ShadowStoreRecordKindV1::SessionStored,
                value.session_id.clone(),
                value.session_sha256.clone(),
                "sessions",
                None,
            )
        }
        ShadowStoreArtifactV1::SessionEvaluation(value) => {
            value.validate().map_err(shadow_error)?;
            metadata(
                ShadowStoreRecordKindV1::SessionEvaluationStored,
                format!("session-evaluation-{}", &value.evaluation_sha256[7..31]),
                value.evaluation_sha256.clone(),
                "sessions",
                None,
            )
        }
        ShadowStoreArtifactV1::Proposal(value) => {
            value.validate().map_err(shadow_error)?;
            metadata(
                ShadowStoreRecordKindV1::ProposalStored,
                value.proposal_id.clone(),
                value.proposal_sha256.clone(),
                "sealed-proposals",
                Some(cycle_key(&value.session_id, value.cycle_index)),
            )
        }
        ShadowStoreArtifactV1::Commitment(value) => {
            value.validate().map_err(shadow_error)?;
            metadata(
                ShadowStoreRecordKindV1::CommitmentStored,
                value.commitment_id.clone(),
                value.commitment_sha256.clone(),
                "sealed-proposals",
                Some(cycle_key(&value.session_id, value.cycle_index)),
            )
        }
        ShadowStoreArtifactV1::HumanStep(value) => {
            value.validate_integrity().map_err(shadow_error)?;
            metadata(
                ShadowStoreRecordKindV1::HumanStepStored,
                value.step_id.clone(),
                value.step_sha256.clone(),
                "human-reference",
                Some(cycle_key(&value.session_id, value.cycle_index)),
            )
        }
        ShadowStoreArtifactV1::Reveal(value) => {
            value.validate().map_err(shadow_error)?;
            metadata(
                ShadowStoreRecordKindV1::RevealStored,
                value.receipt_id.clone(),
                value.receipt_sha256.clone(),
                "sealed-proposals",
                None,
            )
        }
        ShadowStoreArtifactV1::Cycle(value) => {
            value.validate().map_err(shadow_error)?;
            metadata(
                ShadowStoreRecordKindV1::CycleStored,
                cycle_key(&value.session_id, value.cycle_index),
                value.cycle_sha256.clone(),
                "sessions",
                Some(cycle_key(&value.session_id, value.cycle_index)),
            )
        }
        ShadowStoreArtifactV1::Comparison(value) => {
            value.validate().map_err(shadow_error)?;
            metadata(
                ShadowStoreRecordKindV1::ComparisonStored,
                value.comparison_id.clone(),
                value.comparison_sha256.clone(),
                "comparisons",
                Some(cycle_key(&value.session_id, value.cycle_index)),
            )
        }
        ShadowStoreArtifactV1::Adjudication(value) => {
            value.validate().map_err(shadow_error)?;
            metadata(
                ShadowStoreRecordKindV1::AdjudicationStored,
                value.adjudication_id.clone(),
                value.adjudication_sha256.clone(),
                "adjudications",
                None,
            )
        }
        ShadowStoreArtifactV1::Metric(value) => {
            value.validate().map_err(shadow_error)?;
            metadata(
                ShadowStoreRecordKindV1::MetricStored,
                value.metric_id.clone(),
                value.metric_sha256.clone(),
                "metrics",
                None,
            )
        }
        ShadowStoreArtifactV1::Snapshot(value) => {
            value.validate().map_err(shadow_error)?;
            metadata(
                ShadowStoreRecordKindV1::SnapshotStored,
                value.snapshot_id.clone(),
                value.snapshot_sha256.clone(),
                "metrics",
                None,
            )
        }
        ShadowStoreArtifactV1::Readiness(value) => {
            value.validate_integrity().map_err(shadow_error)?;
            metadata(
                ShadowStoreRecordKindV1::ReadinessStored,
                value.assessment_id.clone(),
                value.assessment_sha256.clone(),
                "readiness",
                None,
            )
        }
        ShadowStoreArtifactV1::Report(value) => {
            value.validate().map_err(shadow_error)?;
            metadata(
                ShadowStoreRecordKindV1::ReportStored,
                value.report_id.clone(),
                value.report_sha256.clone(),
                "reports",
                None,
            )
        }
        ShadowStoreArtifactV1::Export(value) => {
            value.validate().map_err(shadow_error)?;
            metadata(
                ShadowStoreRecordKindV1::ExportStored,
                value.bundle_id.clone(),
                value.bundle_sha256.clone(),
                "exports",
                None,
            )
        }
    };
    validate_id(&metadata.id, "Shadow artifact")?;
    validate_hash(&metadata.hash, "Shadow artifact")?;
    Ok(metadata)
}

fn metadata(
    kind: ShadowStoreRecordKindV1,
    id: String,
    hash: String,
    directory: &'static str,
    cycle_key: Option<String>,
) -> ArtifactMetadata {
    ArtifactMetadata {
        kind,
        id,
        hash,
        directory,
        cycle_key,
    }
}

fn cycle_key(session_id: &str, cycle_index: u32) -> String {
    format!("{session_id}:{cycle_index}")
}

fn verify_cycle_order(
    root: &Path,
    artifact: &ShadowStoreArtifactV1,
    metadata: &ArtifactMetadata,
    index: &ShadowStoreIndexV1,
) -> Result<(), DesktopError> {
    let Some(key) = metadata.cycle_key.as_ref() else {
        if let ShadowStoreArtifactV1::Reveal(reveal) = artifact {
            let commitment = find_artifact_by_hash(root, index, &reveal.commitment_sha256)?;
            let ShadowStoreArtifactV1::Commitment(commitment) = commitment else {
                return Err(DesktopError::Integrity(
                    "reveal does not reference a commitment".to_owned(),
                ));
            };
            let key = cycle_key(&commitment.session_id, commitment.cycle_index);
            let state = index.cycle_states.get(&key).ok_or_else(|| {
                DesktopError::Integrity("reveal has no durable cycle state".to_owned())
            })?;
            if state.commitment_sha256.as_ref() != Some(&reveal.commitment_sha256)
                || state.human_step_sha256.as_ref() != Some(&reveal.human_reference_step_sha256)
                || state.reveal_sha256.is_some()
                || reveal.operator_visible_before_action
            {
                return Err(DesktopError::Integrity(
                    "reveal is early, duplicated, unblinded, or mismatched".to_owned(),
                ));
            }
        }
        if let ShadowStoreArtifactV1::Adjudication(value) = artifact {
            let proposal = find_artifact_by_hash(root, index, &value.proposal_sha256)?;
            let ShadowStoreArtifactV1::Proposal(proposal) = proposal else {
                return Err(DesktopError::Integrity(
                    "adjudication proposal binding is invalid".to_owned(),
                ));
            };
            let state = index
                .cycle_states
                .get(&cycle_key(&proposal.session_id, proposal.cycle_index))
                .ok_or_else(|| DesktopError::Integrity("missing adjudication cycle".to_owned()))?;
            if state.comparison_sha256.is_none() || state.adjudication_sha256.is_some() {
                return Err(DesktopError::Integrity(
                    "adjudication is early or duplicated".to_owned(),
                ));
            }
        }
        return Ok(());
    };
    let state = index.cycle_states.get(key).cloned().unwrap_or_default();
    match artifact {
        ShadowStoreArtifactV1::Proposal(_) if state.proposal_sha256.is_none() => Ok(()),
        ShadowStoreArtifactV1::Commitment(value)
            if state.proposal_sha256.as_ref() == Some(&value.proposal_sha256)
                && state.commitment_sha256.is_none() =>
        {
            Ok(())
        }
        ShadowStoreArtifactV1::HumanStep(value)
            if state.commitment_sha256.is_some() && state.human_step_sha256.is_none() =>
        {
            let proposal = find_artifact_by_hash(
                root,
                index,
                state.proposal_sha256.as_deref().unwrap_or_default(),
            )?;
            let commitment = find_artifact_by_hash(
                root,
                index,
                state.commitment_sha256.as_deref().unwrap_or_default(),
            )?;
            let (
                ShadowStoreArtifactV1::Proposal(proposal),
                ShadowStoreArtifactV1::Commitment(commitment),
            ) = (proposal, commitment)
            else {
                return Err(DesktopError::Integrity(
                    "cycle proposal or commitment type differs".to_owned(),
                ));
            };
            if value.pre_action_observation_sha256 != proposal.source_observation_sha256
                || commitment.source_observation_sha256 != proposal.source_observation_sha256
                || commitment.committed_at_unix_ms >= value.action_started_at_unix_ms
            {
                return Err(DesktopError::Integrity(
                    "human step is not blinded or does not share the committed pre-state"
                        .to_owned(),
                ));
            }
            Ok(())
        }
        ShadowStoreArtifactV1::Comparison(value)
            if state.reveal_sha256.is_some()
                && state.proposal_sha256.as_ref() == Some(&value.proposal_sha256)
                && state.human_step_sha256.as_ref() == Some(&value.human_reference_step_sha256)
                && state.comparison_sha256.is_none() =>
        {
            Ok(())
        }
        ShadowStoreArtifactV1::Cycle(_) if state.adjudication_sha256.is_some() => Ok(()),
        _ => Err(DesktopError::Integrity(
            "Shadow artifact violates per-cycle durable ordering".to_owned(),
        )),
    }
}

fn apply_index(
    index: &mut ShadowStoreIndexV1,
    metadata: &ArtifactMetadata,
) -> Result<(), DesktopError> {
    if index
        .artifacts_by_id
        .insert(metadata.id.clone(), metadata.hash.clone())
        .is_some()
    {
        return Err(DesktopError::Integrity(
            "Shadow index artifact identity collision".to_owned(),
        ));
    }
    if let Some(key) = &metadata.cycle_key {
        let state = index.cycle_states.entry(key.clone()).or_default();
        match metadata.kind {
            ShadowStoreRecordKindV1::ProposalStored => {
                set_once(&mut state.proposal_sha256, &metadata.hash)?
            }
            ShadowStoreRecordKindV1::CommitmentStored => {
                set_once(&mut state.commitment_sha256, &metadata.hash)?
            }
            ShadowStoreRecordKindV1::HumanStepStored => {
                set_once(&mut state.human_step_sha256, &metadata.hash)?
            }
            ShadowStoreRecordKindV1::ComparisonStored => {
                set_once(&mut state.comparison_sha256, &metadata.hash)?
            }
            ShadowStoreRecordKindV1::CycleStored => {}
            _ => {}
        }
    }
    Ok(())
}

fn apply_non_keyed_phase(
    root: &Path,
    index: &mut ShadowStoreIndexV1,
    artifact: &ShadowStoreArtifactV1,
    hash: &str,
) -> Result<(), DesktopError> {
    match artifact {
        ShadowStoreArtifactV1::Reveal(value) => {
            let commitment = find_artifact_by_hash(root, index, &value.commitment_sha256)?;
            let ShadowStoreArtifactV1::Commitment(commitment) = commitment else {
                return Err(DesktopError::Integrity(
                    "invalid reveal commitment".to_owned(),
                ));
            };
            let state = index
                .cycle_states
                .get_mut(&cycle_key(&commitment.session_id, commitment.cycle_index))
                .ok_or_else(|| DesktopError::Integrity("missing reveal cycle".to_owned()))?;
            set_once(&mut state.reveal_sha256, hash)
        }
        ShadowStoreArtifactV1::Adjudication(value) => {
            let proposal = find_artifact_by_hash(root, index, &value.proposal_sha256)?;
            let ShadowStoreArtifactV1::Proposal(proposal) = proposal else {
                return Err(DesktopError::Integrity(
                    "invalid adjudication proposal".to_owned(),
                ));
            };
            let state = index
                .cycle_states
                .get_mut(&cycle_key(&proposal.session_id, proposal.cycle_index))
                .ok_or_else(|| DesktopError::Integrity("missing adjudication cycle".to_owned()))?;
            set_once(&mut state.adjudication_sha256, hash)
        }
        _ => Ok(()),
    }
}

fn set_once(slot: &mut Option<String>, value: &str) -> Result<(), DesktopError> {
    if slot.is_some() {
        Err(DesktopError::Integrity(
            "Shadow cycle phase was stored more than once".to_owned(),
        ))
    } else {
        *slot = Some(value.to_owned());
        Ok(())
    }
}

fn empty_index() -> Result<ShadowStoreIndexV1, DesktopError> {
    let mut index = ShadowStoreIndexV1 {
        schema_version: STORE_SCHEMA_VERSION,
        generation: 0,
        ledger_record_count: 0,
        ledger_terminal_sha256: ZERO_HASH.to_owned(),
        artifacts_by_id: BTreeMap::new(),
        cycle_states: BTreeMap::new(),
        index_sha256: ZERO_HASH.to_owned(),
    };
    index.index_sha256 = index_hash(&index)?;
    Ok(index)
}

fn rebuild_index(
    root: &Path,
    ledger: &ShadowStoreLedgerV1,
) -> Result<ShadowStoreIndexV1, DesktopError> {
    let mut index = empty_index()?;
    for record in &ledger.records {
        let artifact = load_object(root, &record.relative_object_path)?;
        let metadata = artifact_metadata(&artifact)?;
        if metadata.kind != record.record_kind
            || metadata.id != record.artifact_id
            || metadata.hash != record.artifact_sha256
            || object_relative_path(&metadata) != record.relative_object_path
        {
            return Err(DesktopError::Integrity(
                "Shadow ledger/object identity differs".to_owned(),
            ));
        }
        let path = safe_relative_path(root, &record.relative_object_path)?;
        if security_hash(&path)? != record.object_security_descriptor_sha256 {
            return Err(DesktopError::Integrity(
                "Shadow object DACL drifted".to_owned(),
            ));
        }
        verify_cycle_order(root, &artifact, &metadata, &index)?;
        apply_index(&mut index, &metadata)?;
        apply_non_keyed_phase(root, &mut index, &artifact, &metadata.hash)?;
    }
    index.generation = ledger.records.len() as u64;
    index.ledger_record_count = ledger.records.len() as u64;
    index.ledger_terminal_sha256 = ledger_terminal(ledger);
    index.index_sha256 = index_hash(&index)?;
    Ok(index)
}

fn find_artifact_by_hash(
    root: &Path,
    index: &ShadowStoreIndexV1,
    hash: &str,
) -> Result<ShadowStoreArtifactV1, DesktopError> {
    let id = index
        .artifacts_by_id
        .iter()
        .find_map(|(id, candidate)| (candidate == hash).then_some(id))
        .ok_or_else(|| {
            DesktopError::Integrity("referenced Shadow artifact is absent".to_owned())
        })?;
    let ledger = load_ledger(root)?;
    let record = ledger
        .records
        .iter()
        .find(|record| record.artifact_id == *id && record.artifact_sha256 == hash)
        .ok_or_else(|| {
            DesktopError::Integrity("referenced Shadow ledger record is absent".to_owned())
        })?;
    load_object(root, &record.relative_object_path)
}

fn append_record(
    ledger: &mut ShadowStoreLedgerV1,
    metadata: &ArtifactMetadata,
    object_security_descriptor_sha256: String,
    time: u64,
) -> Result<(), DesktopError> {
    validate_append_position(ledger, time)?;
    let mut record = ShadowStoreRecordV1 {
        schema_version: STORE_SCHEMA_VERSION,
        sequence: ledger.records.len() as u64 + 1,
        record_kind: metadata.kind,
        artifact_id: metadata.id.clone(),
        artifact_sha256: metadata.hash.clone(),
        relative_object_path: object_relative_path(metadata),
        object_security_descriptor_sha256,
        recorded_at_unix_ms: time,
        previous_record_sha256: ledger.records.last().map_or_else(
            || ZERO_HASH.to_owned(),
            |record| record.record_sha256.clone(),
        ),
        record_sha256: ZERO_HASH.to_owned(),
    };
    record.record_sha256 = record_hash(&record)?;
    ledger.records.push(record);
    Ok(())
}

fn validate_append_position(ledger: &ShadowStoreLedgerV1, time: u64) -> Result<(), DesktopError> {
    if ledger.records.len() >= MAX_STORE_RECORDS
        || ledger
            .records
            .last()
            .is_some_and(|record| time < record.recorded_at_unix_ms)
    {
        return Err(DesktopError::Integrity(
            "Shadow ledger bound or monotonic time failed".to_owned(),
        ));
    }
    Ok(())
}

fn verify_ledger(ledger: &ShadowStoreLedgerV1) -> Result<(), DesktopError> {
    if ledger.schema_version != STORE_SCHEMA_VERSION || ledger.records.len() > MAX_STORE_RECORDS {
        return Err(DesktopError::Integrity(
            "Shadow ledger version or bounds differ".to_owned(),
        ));
    }
    let mut previous = ZERO_HASH.to_owned();
    let mut prior_time = 0;
    for (index, record) in ledger.records.iter().enumerate() {
        if record.schema_version != STORE_SCHEMA_VERSION
            || record.sequence != index as u64 + 1
            || record.previous_record_sha256 != previous
            || record.recorded_at_unix_ms == 0
            || record.recorded_at_unix_ms < prior_time
            || record.record_sha256 != record_hash(record)?
        {
            return Err(DesktopError::Integrity(
                "Shadow ledger chain, time, or record hash differs".to_owned(),
            ));
        }
        validate_id(&record.artifact_id, "Shadow ledger artifact")?;
        validate_hash(&record.artifact_sha256, "Shadow ledger artifact")?;
        validate_hash(
            &record.object_security_descriptor_sha256,
            "Shadow object DACL",
        )?;
        previous.clone_from(&record.record_sha256);
        prior_time = record.recorded_at_unix_ms;
    }
    Ok(())
}

fn record_hash(record: &ShadowStoreRecordV1) -> Result<String, DesktopError> {
    hash_without(record, &["record_sha256"]).map_err(shadow_error)
}

fn index_hash(index: &ShadowStoreIndexV1) -> Result<String, DesktopError> {
    hash_without(index, &["index_sha256"]).map_err(shadow_error)
}

fn ledger_terminal(ledger: &ShadowStoreLedgerV1) -> String {
    ledger.records.last().map_or_else(
        || ZERO_HASH.to_owned(),
        |record| record.record_sha256.clone(),
    )
}

fn persist_object(
    root: &Path,
    artifact: &ShadowStoreArtifactV1,
    metadata: &ArtifactMetadata,
) -> Result<String, DesktopError> {
    let relative = object_relative_path(metadata);
    let path = safe_relative_path(root, &relative)?;
    let bytes = pretty_json(artifact)?;
    if path.exists() {
        if read_bounded(&path, MAX_STORE_FILE_BYTES)? == bytes {
            return security_hash(&path);
        }
        return Err(DesktopError::Integrity(
            "Shadow content-addressed object collision".to_owned(),
        ));
    }
    write_new(&path, &bytes)?;
    harden_and_hash(&path)
}

fn object_relative_path(metadata: &ArtifactMetadata) -> String {
    let hex = metadata.hash.strip_prefix("sha256:").unwrap_or_default();
    format!("{}/{}.json", metadata.directory, hex)
}

fn load_object(root: &Path, relative: &str) -> Result<ShadowStoreArtifactV1, DesktopError> {
    let bytes = read_bounded(&safe_relative_path(root, relative)?, MAX_STORE_FILE_BYTES)?;
    let artifact: ShadowStoreArtifactV1 = parse_json_strict(&bytes).map_err(shadow_error)?;
    if pretty_json(&artifact)? != bytes {
        return Err(DesktopError::Integrity(
            "Shadow object bytes differ from canonical persisted JSON".to_owned(),
        ));
    }
    Ok(artifact)
}

fn safe_relative_path(root: &Path, relative: &str) -> Result<PathBuf, DesktopError> {
    if relative.contains("..") || relative.contains('\\') || relative.starts_with('/') {
        return Err(DesktopError::Integrity(
            "Shadow object path is not a safe canonical relative path".to_owned(),
        ));
    }
    let path = root.join(relative);
    let parent = path
        .parent()
        .ok_or_else(|| DesktopError::Integrity("Shadow object has no parent".to_owned()))?;
    let canonical_parent =
        std::fs::canonicalize(parent).map_err(|error| io_error(parent, error))?;
    let canonical_root = std::fs::canonicalize(root).map_err(|error| io_error(root, error))?;
    if !canonical_parent.starts_with(&canonical_root) {
        return Err(DesktopError::Integrity(
            "Shadow object path escaped its store".to_owned(),
        ));
    }
    Ok(path)
}

fn list_object_paths(root: &Path) -> Result<BTreeSet<String>, DesktopError> {
    let mut paths = BTreeSet::new();
    for directory in ARTIFACT_DIRECTORIES {
        let base = root.join(directory);
        for entry in std::fs::read_dir(&base).map_err(|error| io_error(&base, error))? {
            let entry = entry.map_err(|error| io_error(&base, error))?;
            let path = entry.path();
            reject_reparse(&path, "Shadow object")?;
            if !entry
                .file_type()
                .map_err(|error| io_error(&path, error))?
                .is_file()
            {
                return Err(DesktopError::Integrity(
                    "Shadow object directory contains a non-file".to_owned(),
                ));
            }
            let name = entry.file_name().to_string_lossy().to_string();
            let hex = name.strip_suffix(".json").ok_or_else(|| {
                DesktopError::Integrity("Shadow object file name is invalid".to_owned())
            })?;
            validate_hash(&format!("sha256:{hex}"), "Shadow object file")?;
            paths.insert(format!("{directory}/{name}"));
        }
    }
    Ok(paths)
}

fn load_manifest(root: &Path) -> Result<ShadowStoreManifestV1, DesktopError> {
    let manifest: ShadowStoreManifestV1 = parse_json_strict(&read_bounded(
        &root.join(MANIFEST_FILE),
        MAX_STORE_FILE_BYTES,
    )?)
    .map_err(shadow_error)?;
    if manifest.schema_version != STORE_SCHEMA_VERSION
        || manifest.maximum_store_bytes == 0
        || manifest.maximum_store_bytes > MAX_STORE_BYTES
        || manifest.created_at_unix_ms == 0
        || manifest.directory_security_descriptor_hashes.len() != ARTIFACT_DIRECTORIES.len()
    {
        return Err(DesktopError::Integrity(
            "Shadow manifest version, bounds, or directories differ".to_owned(),
        ));
    }
    validate_id(&manifest.organization_id, "Shadow organization")?;
    for value in [
        &manifest.role_contract_sha256,
        &manifest.profile_sha256,
        &manifest.cohort_sha256,
    ] {
        validate_hash(value, "Shadow manifest binding")?;
    }
    Ok(manifest)
}

fn load_ledger(root: &Path) -> Result<ShadowStoreLedgerV1, DesktopError> {
    parse_json_strict_with_limits(
        &read_bounded(&root.join(LEDGER_FILE), MAX_STORE_FILE_BYTES)?,
        MAX_STORE_FILE_BYTES as usize,
        MAX_STORE_RECORDS,
    )
    .map_err(shadow_error)
}

fn load_index(root: &Path) -> Result<ShadowStoreIndexV1, DesktopError> {
    let index: ShadowStoreIndexV1 = parse_json_strict_with_limits(
        &read_bounded(&root.join(INDEX_FILE), MAX_STORE_FILE_BYTES)?,
        MAX_STORE_FILE_BYTES as usize,
        MAX_STORE_RECORDS,
    )
    .map_err(shadow_error)?;
    if index.schema_version != STORE_SCHEMA_VERSION || index.index_sha256 != index_hash(&index)? {
        return Err(DesktopError::Integrity(
            "Shadow index version or hash differs".to_owned(),
        ));
    }
    Ok(index)
}

fn verify_security(root: &Path, manifest: &ShadowStoreManifestV1) -> Result<(), DesktopError> {
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
            root.join(LEDGER_FILE),
            &manifest.ledger_security_descriptor_sha256,
        ),
        (
            root.join(INDEX_FILE),
            &manifest.index_security_descriptor_sha256,
        ),
    ] {
        if security_hash(&path)? != *expected {
            return Err(DesktopError::Integrity(
                "Shadow owner or DACL drifted".to_owned(),
            ));
        }
    }
    for directory in ARTIFACT_DIRECTORIES {
        let expected = manifest
            .directory_security_descriptor_hashes
            .get(directory)
            .ok_or_else(|| {
                DesktopError::Integrity("Shadow directory DACL pin absent".to_owned())
            })?;
        if security_hash(&root.join(directory))? != *expected {
            return Err(DesktopError::Integrity(
                "Shadow artifact directory DACL drifted".to_owned(),
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

fn security_hash(path: &Path) -> Result<String, DesktopError> {
    let descriptor = d2i_windows_host::path_security_descriptor(path)
        .map_err(|error| DesktopError::Integrity(error.to_string()))?;
    Ok(sha256_bytes(&descriptor))
}

fn reject_reparse(path: &Path, label: &str) -> Result<(), DesktopError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
    if metadata.file_type().is_symlink()
        || d2i_windows_host::is_reparse_point(path)
            .map_err(|error| DesktopError::Integrity(error.to_string()))?
    {
        return Err(DesktopError::Integrity(format!(
            "{label} cannot be a symlink or reparse point"
        )));
    }
    Ok(())
}

fn pretty_json<T: Serialize>(value: &T) -> Result<Vec<u8>, DesktopError> {
    let canonical = canonical_json_bytes(value).map_err(shadow_error)?;
    let parsed: serde_json::Value = serde_json::from_slice(&canonical)
        .map_err(|error| DesktopError::Json(error.to_string()))?;
    let mut bytes = serde_json::to_vec_pretty(&parsed)
        .map_err(|error| DesktopError::Json(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn atomic_replace(root: &Path, file: &str, bytes: &[u8]) -> Result<(), DesktopError> {
    let temporary = root.join(format!("{file}.next"));
    write_new(&temporary, bytes)?;
    harden_and_hash(&temporary)?;
    d2i_windows_host::atomic_move(&temporary, &root.join(file), true).map_err(|error| {
        let _ = std::fs::remove_file(&temporary);
        DesktopError::Io {
            path: root.join(file).display().to_string(),
            message: error.to_string(),
        }
    })
}

fn overwrite_existing(path: &Path, bytes: &[u8]) -> Result<(), DesktopError> {
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|error| io_error(path, error))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| io_error(path, error))
}

fn write_poison(root: &Path) -> Result<(), DesktopError> {
    let path = root.join(POISON_FILE);
    if !path.exists() {
        write_new(&path, b"shadow-store-poisoned\n")?;
        harden_and_hash(&path)?;
    }
    Ok(())
}

fn store_size(root: &Path) -> Result<(u32, u64), DesktopError> {
    fn walk(path: &Path, count: &mut u32, bytes: &mut u64) -> Result<(), DesktopError> {
        for entry in std::fs::read_dir(path).map_err(|error| io_error(path, error))? {
            let entry = entry.map_err(|error| io_error(path, error))?;
            let child = entry.path();
            reject_reparse(&child, "Shadow store entry")?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name == LOCK_FILE || name.ends_with(".next") {
                continue;
            }
            let metadata = entry.metadata().map_err(|error| io_error(&child, error))?;
            if metadata.is_dir() {
                walk(&child, count, bytes)?;
            } else if metadata.is_file() {
                *count = count.saturating_add(1);
                *bytes = bytes.saturating_add(metadata.len());
            } else {
                return Err(DesktopError::Integrity(
                    "Shadow store contains a non-regular entry".to_owned(),
                ));
            }
        }
        Ok(())
    }
    let mut count = 0;
    let mut bytes = 0;
    walk(root, &mut count, &mut bytes)?;
    Ok((count, bytes))
}

fn validate_hash(value: &str, label: &str) -> Result<(), DesktopError> {
    d2i_shadow_mode::validate_hash(value, label).map_err(shadow_error)
}

fn validate_id(value: &str, label: &str) -> Result<(), DesktopError> {
    d2i_shadow_mode::validate_id(value, label).map_err(shadow_error)
}

#[cfg(test)]
mod recovery_contract_tests {
    use super::*;

    #[test]
    fn crash_windows_a_through_i_have_closed_no_replay_directives() {
        let cases = [
            (
                ShadowStoreRecordKindV1::EnrollmentStored,
                ShadowRecoveryWindowV1::EnrollmentBeforeInitialObservation,
            ),
            (
                ShadowStoreRecordKindV1::ProposalStored,
                ShadowRecoveryWindowV1::ProposalBeforeCommitment,
            ),
            (
                ShadowStoreRecordKindV1::CommitmentStored,
                ShadowRecoveryWindowV1::CommitmentBeforeHumanAction,
            ),
            (
                ShadowStoreRecordKindV1::HumanStepStored,
                ShadowRecoveryWindowV1::HumanStepBeforePostObservation,
            ),
            (
                ShadowStoreRecordKindV1::RevealStored,
                ShadowRecoveryWindowV1::PostObservationBeforeComparison,
            ),
            (
                ShadowStoreRecordKindV1::ComparisonStored,
                ShadowRecoveryWindowV1::ComparisonBeforeAdjudication,
            ),
            (
                ShadowStoreRecordKindV1::SessionEvaluationStored,
                ShadowRecoveryWindowV1::SessionTerminalBeforeMetrics,
            ),
            (
                ShadowStoreRecordKindV1::ReadinessStored,
                ShadowRecoveryWindowV1::ReadinessBeforeReport,
            ),
            (
                ShadowStoreRecordKindV1::ReportStored,
                ShadowRecoveryWindowV1::ReportBeforePublicationReceipt,
            ),
        ];
        for (kind, expected) in cases {
            let plan = recovery_plan_for_record(kind, format!("sha256:{}", "a".repeat(64)))
                .unwrap_or_else(|| panic!("missing recovery plan for {kind:?}"));
            assert_eq!(plan.window, expected);
            assert_eq!(plan.ai_proposal_replay_count, 0);
            assert_eq!(plan.human_action_replay_count, 0);
            assert_eq!(plan.model_invocation_replay_count, 0);
            assert_eq!(plan.adapter_action_replay_count, 0);
        }
    }
}

#[cfg(windows)]
mod platform_observation {
    use super::*;
    use uiautomation::patterns::UIValuePattern;
    use uiautomation::types::TreeScope;
    use uiautomation::{UIAutomation, UIElement};

    #[allow(clippy::too_many_arguments)]
    pub(super) fn collect(
        grant: &ShadowObservationGrantV1,
        trusted_now_unix_ms: u64,
        observation_id: String,
        sequence: u64,
        process_id: u32,
        expected_process_executable_sha256: &str,
        expected_window_title_sha256: &str,
    ) -> Result<ShadowFixtureObservationV1, DesktopError> {
        validate_hash(
            expected_process_executable_sha256,
            "Shadow fixture executable",
        )?;
        validate_hash(expected_window_title_sha256, "Shadow fixture title")?;
        let executable = d2i_windows_host::process_image_path(process_id)
            .map_err(|error| DesktopError::Precondition(error.to_string()))?;
        let executable = std::fs::canonicalize(&executable).map_err(|error| DesktopError::Io {
            path: executable.display().to_string(),
            message: error.to_string(),
        })?;
        let executable_hash =
            sha256_bytes(&read_bounded(&executable, MAX_OBSERVED_EXECUTABLE_BYTES)?);
        if executable_hash != expected_process_executable_sha256 {
            return Err(DesktopError::Integrity(
                "Shadow fixture executable hash changed".to_owned(),
            ));
        }
        let session_id = d2i_windows_host::process_session_id(process_id)
            .map_err(|error| DesktopError::Precondition(error.to_string()))?;
        let automation = UIAutomation::new()
            .map_err(|error| DesktopError::AdapterUnavailable(error.to_string()))?;
        let desktop = automation
            .get_root_element()
            .map_err(|error| DesktopError::AdapterUnavailable(error.to_string()))?;
        let condition = automation
            .create_true_condition()
            .map_err(|error| DesktopError::AdapterUnavailable(error.to_string()))?;
        let windows = desktop
            .find_all(TreeScope::Children, &condition)
            .map_err(|error| DesktopError::AdapterUnavailable(error.to_string()))?;
        let mut matches = windows
            .into_iter()
            .filter(|window| {
                window.get_process_id().ok() == Some(process_id)
                    && window.get_name().ok().is_some_and(|name| {
                        sha256_bytes(name.as_bytes()) == expected_window_title_sha256
                    })
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(DesktopError::Precondition(
                "Shadow fixture window did not resolve uniquely".to_owned(),
            ));
        }
        let window = matches.remove(0);
        let descendants = window
            .find_all(TreeScope::Descendants, &condition)
            .map_err(|error| DesktopError::AdapterUnavailable(error.to_string()))?;
        let input = exact_value(&descendants, "employee-name-input")?;
        let saved = exact_value(&descendants, "saved-name")?;
        let save_status = exact_value(&descendants, "save-status")?;
        validate_id(&save_status, "Shadow fixture save status")?;
        let save_revision = exact_value(&descendants, "save-revision")?
            .parse::<u32>()
            .map_err(|_| DesktopError::Integrity("save revision is not u32".to_owned()))?;
        ShadowFixtureObservationV1 {
            schema_version: STORE_SCHEMA_VERSION,
            observation_id,
            sequence,
            process_id,
            process_executable_sha256: executable_hash,
            process_session_id: session_id,
            window_title_sha256: expected_window_title_sha256.to_owned(),
            employee_input_value_sha256: sha256_bytes(input.as_bytes()),
            saved_value_sha256: sha256_bytes(saved.as_bytes()),
            save_status_id: save_status,
            save_revision,
            observation_side_effect_count: 0,
            grant_sha256: grant.grant_sha256.clone(),
            observed_at_unix_ms: trusted_now_unix_ms,
            observation_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
    }

    fn exact_value(elements: &[UIElement], automation_id: &str) -> Result<String, DesktopError> {
        let mut matches = elements
            .iter()
            .filter(|element| element.get_automation_id().ok().as_deref() == Some(automation_id))
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(DesktopError::Precondition(format!(
                "Shadow fixture element {automation_id} did not resolve uniquely"
            )));
        }
        matches
            .remove(0)
            .get_pattern::<UIValuePattern>()
            .and_then(|pattern| pattern.get_value())
            .map_err(|error| DesktopError::AdapterUnavailable(error.to_string()))
    }
}

#[cfg(not(windows))]
mod platform_observation {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    pub(super) fn collect(
        _grant: &ShadowObservationGrantV1,
        _trusted_now_unix_ms: u64,
        _observation_id: String,
        _sequence: u64,
        _process_id: u32,
        _expected_process_executable_sha256: &str,
        _expected_window_title_sha256: &str,
    ) -> Result<ShadowFixtureObservationV1, DesktopError> {
        Err(DesktopError::AdapterUnavailable(
            "Shadow UIA observation is unavailable on this platform".to_owned(),
        ))
    }
}

fn shadow_error(error: ShadowModeError) -> DesktopError {
    DesktopError::Integrity(error.to_string())
}

fn io_error(path: &Path, error: std::io::Error) -> DesktopError {
    DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    }
}

struct ShadowStoreLock {
    path: PathBuf,
}

impl ShadowStoreLock {
    fn acquire(root: &Path) -> Result<Self, DesktopError> {
        let path = root.join(LOCK_FILE);
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| DesktopError::Io {
                path: path.display().to_string(),
                message: format!("Shadow single-writer lock failed: {error}"),
            })?;
        harden_and_hash(&path)?;
        Ok(Self { path })
    }
}

impl Drop for ShadowStoreLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
