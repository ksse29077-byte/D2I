use crate::{
    json_bytes, load_candidate_package, read_bounded, sha256_bytes, LearningError,
    OfflineEvaluationReport,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

const LEDGER_FILE: &str = "promotions.jsonl";
const LEDGER_LOCK: &str = ".promotion.lock";
const MAX_LEDGER_BYTES: u64 = 64 * 1024 * 1024;
const ZERO_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Explicit human approval attached to a promotion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub approver_id: String,
    pub approved_at_unix_seconds: u64,
    pub rationale: String,
}

/// Shadow/canary rollout metadata for a future build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryPlan {
    pub shadow_required: bool,
    pub canary_percent: u8,
    pub observation_seconds: u64,
    pub stop_on_critical_error: bool,
}

/// Rollback target and trigger retained before any deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackPlan {
    pub rollback_build_id: String,
    pub rollback_package_content_hash: String,
    pub maximum_critical_errors: u64,
    pub minimum_task_success_rate_milli: u16,
}

/// Signed append-only approval for use as a future build input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionRecord {
    pub schema_version: u32,
    pub sequence: u64,
    pub previous_record_hash: String,
    pub state: String,
    pub candidate_id: String,
    pub candidate_content_hash: String,
    pub base_build_id: String,
    pub base_package_content_hash: String,
    pub dataset_hash: String,
    pub gold_dataset_hash: String,
    pub evaluation_hash: String,
    pub evaluator_id: String,
    pub approval: Approval,
    pub canary: CanaryPlan,
    pub rollback: RollbackPlan,
    pub signer_public_key: String,
    pub signature: String,
    pub record_hash: String,
}

#[derive(Serialize)]
struct SignedPayload<'a> {
    schema_version: u32,
    sequence: u64,
    previous_record_hash: &'a str,
    state: &'a str,
    candidate_id: &'a str,
    candidate_content_hash: &'a str,
    base_build_id: &'a str,
    base_package_content_hash: &'a str,
    dataset_hash: &'a str,
    gold_dataset_hash: &'a str,
    evaluation_hash: &'a str,
    evaluator_id: &'a str,
    approval: &'a Approval,
    canary: &'a CanaryPlan,
    rollback: &'a RollbackPlan,
    signer_public_key: &'a str,
}

#[derive(Serialize)]
struct RecordHashPayload<'a> {
    signed: SignedPayload<'a>,
    signature: &'a str,
}

/// Verifies, signs, and appends one promotion without touching the base package.
pub fn append_promotion(
    ledger_root: &Path,
    candidate_root: &Path,
    evaluation: &OfflineEvaluationReport,
    approval: Approval,
    canary: CanaryPlan,
    rollback: RollbackPlan,
    secret_key: [u8; 32],
) -> Result<PromotionRecord, LearningError> {
    validate_plans(&approval, &canary, &rollback)?;
    let candidate = load_candidate_package(candidate_root)?;
    crate::evaluation::verify_evaluation_report(&candidate, evaluation)?;
    if !evaluation.gate.passed {
        return Err(LearningError::GateRejected(evaluation.gate.reasons.clone()));
    }
    if evaluation.candidate_id != candidate.manifest.candidate_id
        || evaluation.candidate_content_hash != candidate.candidate_content_hash
        || evaluation.base_build_id != candidate.manifest.base_build_id
        || evaluation.base_package_content_hash != candidate.manifest.base_package_content_hash
    {
        return Err(LearningError::Integrity(
            "evaluation does not match the candidate and base identity".to_owned(),
        ));
    }
    if rollback.rollback_build_id != candidate.manifest.base_build_id
        || rollback.rollback_package_content_hash != candidate.manifest.base_package_content_hash
    {
        return Err(LearningError::Invalid(
            "rollback target must be the verified base package".to_owned(),
        ));
    }
    if approval.approved_at_unix_seconds < evaluation.evaluated_at_unix_seconds {
        return Err(LearningError::Invalid(
            "approval timestamp precedes offline evaluation".to_owned(),
        ));
    }
    initialize_ledger_if_missing(ledger_root)?;
    let lock = LedgerLock::acquire(ledger_root)?;
    let records = load_and_verify_ledger(ledger_root)?;
    let sequence = u64::try_from(records.len()).unwrap_or(u64::MAX);
    let previous_record_hash = records
        .last()
        .map_or(ZERO_HASH, |record| record.record_hash.as_str())
        .to_owned();
    let evaluation_hash = sha256_bytes(&json_bytes(evaluation)?);
    let signing_key = SigningKey::from_bytes(&secret_key);
    let signer_public_key = hex_encode(&signing_key.verifying_key().to_bytes());
    let state = "approved_for_next_build".to_owned();
    let payload = SignedPayload {
        schema_version: 1,
        sequence,
        previous_record_hash: &previous_record_hash,
        state: &state,
        candidate_id: &candidate.manifest.candidate_id,
        candidate_content_hash: &candidate.candidate_content_hash,
        base_build_id: &candidate.manifest.base_build_id,
        base_package_content_hash: &candidate.manifest.base_package_content_hash,
        dataset_hash: &candidate.manifest.dataset_hash,
        gold_dataset_hash: &evaluation.gold_dataset_hash,
        evaluation_hash: &evaluation_hash,
        evaluator_id: &evaluation.evaluator_id,
        approval: &approval,
        canary: &canary,
        rollback: &rollback,
        signer_public_key: &signer_public_key,
    };
    let signature = hex_encode(&signing_key.sign(&json_bytes(&payload)?).to_bytes());
    let record_hash = sha256_bytes(&json_bytes(&RecordHashPayload {
        signed: payload,
        signature: &signature,
    })?);
    let record = PromotionRecord {
        schema_version: 1,
        sequence,
        previous_record_hash,
        state,
        candidate_id: candidate.manifest.candidate_id,
        candidate_content_hash: candidate.candidate_content_hash,
        base_build_id: candidate.manifest.base_build_id,
        base_package_content_hash: candidate.manifest.base_package_content_hash,
        dataset_hash: candidate.manifest.dataset_hash,
        gold_dataset_hash: evaluation.gold_dataset_hash.clone(),
        evaluation_hash,
        evaluator_id: evaluation.evaluator_id.clone(),
        approval,
        canary,
        rollback,
        signer_public_key,
        signature,
        record_hash,
    };
    let path = ledger_root.join(LEDGER_FILE);
    let mut bytes = json_bytes(&record)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .append(true)
        .open(&path)
        .map_err(|error| LearningError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_data())
        .map_err(|error| LearningError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
    drop(lock);
    Ok(record)
}

/// Verifies hash-chain continuity and every Ed25519 signature.
pub fn verify_promotion_ledger(ledger_root: &Path) -> Result<Vec<PromotionRecord>, LearningError> {
    load_and_verify_ledger(ledger_root)
}

fn load_and_verify_ledger(root: &Path) -> Result<Vec<PromotionRecord>, LearningError> {
    let metadata = std::fs::symlink_metadata(root).map_err(|error| LearningError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LearningError::Integrity(
            "promotion ledger must be a regular directory".to_owned(),
        ));
    }
    let bytes = read_bounded(&root.join(LEDGER_FILE), MAX_LEDGER_BYTES)?;
    let mut records = Vec::new();
    let mut previous = ZERO_HASH.to_owned();
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        let record: PromotionRecord =
            serde_json::from_slice(line).map_err(|error| LearningError::Json(error.to_string()))?;
        if record.schema_version != 1
            || record.sequence != u64::try_from(records.len()).unwrap_or(u64::MAX)
            || record.previous_record_hash != previous
            || record.state != "approved_for_next_build"
        {
            return Err(LearningError::Integrity(format!(
                "promotion chain metadata is invalid at line {}",
                index + 1
            )));
        }
        let payload = signed_payload(&record);
        let payload_bytes = json_bytes(&payload)?;
        let public_bytes = hex_decode_array::<32>(&record.signer_public_key)?;
        let signature_bytes = hex_decode_array::<64>(&record.signature)?;
        let verifying_key = VerifyingKey::from_bytes(&public_bytes)
            .map_err(|error| LearningError::Signature(error.to_string()))?;
        let signature = Signature::from_bytes(&signature_bytes);
        verifying_key
            .verify_strict(&payload_bytes, &signature)
            .map_err(|error| LearningError::Signature(error.to_string()))?;
        let expected_hash = sha256_bytes(&json_bytes(&RecordHashPayload {
            signed: payload,
            signature: &record.signature,
        })?);
        if record.record_hash != expected_hash {
            return Err(LearningError::Integrity(format!(
                "promotion record hash mismatch at line {}",
                index + 1
            )));
        }
        previous = record.record_hash.clone();
        records.push(record);
    }
    Ok(records)
}

fn signed_payload(record: &PromotionRecord) -> SignedPayload<'_> {
    SignedPayload {
        schema_version: record.schema_version,
        sequence: record.sequence,
        previous_record_hash: &record.previous_record_hash,
        state: &record.state,
        candidate_id: &record.candidate_id,
        candidate_content_hash: &record.candidate_content_hash,
        base_build_id: &record.base_build_id,
        base_package_content_hash: &record.base_package_content_hash,
        dataset_hash: &record.dataset_hash,
        gold_dataset_hash: &record.gold_dataset_hash,
        evaluation_hash: &record.evaluation_hash,
        evaluator_id: &record.evaluator_id,
        approval: &record.approval,
        canary: &record.canary,
        rollback: &record.rollback,
        signer_public_key: &record.signer_public_key,
    }
}

fn initialize_ledger_if_missing(root: &Path) -> Result<(), LearningError> {
    if root.exists() {
        let metadata = std::fs::symlink_metadata(root).map_err(|error| LearningError::Io {
            path: root.display().to_string(),
            message: error.to_string(),
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(LearningError::Integrity(
                "promotion ledger must be a regular directory".to_owned(),
            ));
        }
        return Ok(());
    }
    std::fs::create_dir(root).map_err(|error| LearningError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    crate::write_new(&root.join(LEDGER_FILE), b"")
}

fn validate_plans(
    approval: &Approval,
    canary: &CanaryPlan,
    rollback: &RollbackPlan,
) -> Result<(), LearningError> {
    if approval.approver_id.is_empty()
        || approval.approved_at_unix_seconds == 0
        || approval.rationale.is_empty()
        || canary.canary_percent > 100
        || canary.observation_seconds == 0
        || rollback.rollback_build_id.is_empty()
        || rollback.maximum_critical_errors > 1000
        || rollback.minimum_task_success_rate_milli > 1000
    {
        return Err(LearningError::Invalid(
            "approval, canary, or rollback metadata is outside bounds".to_owned(),
        ));
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode_array<const N: usize>(value: &str) -> Result<[u8; N], LearningError> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(LearningError::Signature(
            "hex signature or key length is invalid".to_owned(),
        ));
    }
    let mut output = [0_u8; N];
    for (index, slot) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *slot = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|error| LearningError::Signature(error.to_string()))?;
    }
    Ok(output)
}

struct LedgerLock {
    path: PathBuf,
}

impl LedgerLock {
    fn acquire(root: &Path) -> Result<Self, LearningError> {
        let path = root.join(LEDGER_LOCK);
        let _file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| LearningError::Io {
                path: path.display().to_string(),
                message: format!("cannot acquire promotion lock: {error}"),
            })?;
        Ok(Self { path })
    }
}

impl Drop for LedgerLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
