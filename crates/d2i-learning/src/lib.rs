//! Controlled, offline experience compilation and signed promotion auditing.

mod candidate;
mod dataset;
mod episode;
mod evaluation;
mod promotion;
mod store;

pub use candidate::{
    build_candidate_package, load_candidate_package, AdaptationProposals, CandidateBuildOptions,
    CandidateDatasetReport, CandidatePackage, CandidatePackageManifest, ExecutorRefitProposal,
    QuarantineRecord, RetrievalWeightProposal, RoutingThresholdProposal, RuleCandidateProposal,
};
pub use dataset::{
    check_dataset_registry, load_dataset_registry, verify_dataset_artifacts, DatasetAdmissionIssue,
    DatasetAdmissionStatus, DatasetArtifact, DatasetArtifactVerification, DatasetLicense,
    DatasetPurpose, DatasetRegistry, DatasetRegistryEntry, DatasetRegistryReport, DatasetReviews,
    DatasetRiskProfile, DatasetUse, LicenseScope, ReviewAttestation, ReviewDecision,
};
pub use episode::{
    ActionRecord, CorrectionRecord, Episode, EpisodeOutcome, EpisodePolicy, EpisodeProvenance,
    OutcomeStatus, SelectedRoute, Situation, TrustLevel,
};
pub use evaluation::{
    evaluate_candidate_package, EvaluationGate, OfflineEvaluationReport, PromotionPolicy,
};
pub use promotion::{
    append_promotion, verify_promotion_ledger, Approval, CanaryPlan, PromotionRecord, RollbackPlan,
};
pub use store::{
    append_episode, export_store, initialize_store, read_verified_episodes, verify_store, Actor,
    ExperienceStorePolicy, RolePolicy, StoreVerification,
};

use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::Path;

const MAX_JSON_BYTES: usize = 2 * 1024 * 1024;

/// Structured controlled-learning failure.
#[derive(Debug)]
pub enum LearningError {
    Invalid(String),
    AccessDenied(String),
    Integrity(String),
    GateRejected(Vec<String>),
    Io { path: String, message: String },
    Json(String),
    Package(String),
    Signature(String),
}

impl Display for LearningError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid learning artifact: {message}"),
            Self::AccessDenied(message) => write!(formatter, "access denied: {message}"),
            Self::Integrity(message) => write!(formatter, "integrity failure: {message}"),
            Self::GateRejected(reasons) => {
                write!(formatter, "promotion gate rejected: {}", reasons.join("; "))
            }
            Self::Io { path, message } => write!(formatter, "I/O error at {path}: {message}"),
            Self::Json(message) => write!(formatter, "JSON error: {message}"),
            Self::Package(message) => write!(formatter, "package error: {message}"),
            Self::Signature(message) => write!(formatter, "signature error: {message}"),
        }
    }
}

impl Error for LearningError {}

fn json_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, LearningError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| LearningError::Json(error.to_string()))?;
    if bytes.len() > MAX_JSON_BYTES {
        return Err(LearningError::Invalid(format!(
            "serialized record exceeds {MAX_JSON_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

fn pretty_json_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, LearningError> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|error| LearningError::Json(error.to_string()))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_JSON_BYTES {
        return Err(LearningError::Invalid(format!(
            "serialized artifact exceeds {MAX_JSON_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, LearningError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| LearningError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return Err(LearningError::Integrity(
            "artifact must be a bounded regular file".to_owned(),
        ));
    }
    std::fs::read(path).map_err(|error| LearningError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), LearningError> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| LearningError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
    file.write_all(bytes).map_err(|error| LearningError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    file.sync_all().map_err(|error| LearningError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })
}
