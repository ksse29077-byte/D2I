//! Safety-separated contracts for D2I embodied intelligence integrations.

mod activation;
mod certification;
mod contract;
mod fleet;
mod hardware;
mod integration;
mod memory;
mod replay;
mod ros2;
mod safety;

pub use contract::{
    ActionIntent, ActionKind, DeadlineClass, SafetyConstraint, SensorEvent, SensorKind,
};
pub use fleet::{
    create_fleet_promotion, verify_fleet_promotion, FleetApproval, FleetCohort,
    FleetPromotionInput, FleetPromotionRecord, PackageSignatureAttestation,
    SimulationQualification,
};
pub use hardware::{dispatch_authorized, HardwarePort, HardwareProfile, UnavailableHardwarePort};
pub use integration::{
    check_integration_readiness, load_integration_manifest, CallbackGroupContract,
    CallbackGroupKind, DurabilityPolicy, EndpointQos, ExecutorContract, ExecutorKind,
    HardwareIntegrationContract, HistoryPolicy, IntegrationManifest, IntegrationReadinessReport,
    LivelinessPolicy, NetworkPolicy, QosCompatibility, ReadinessIssue, ReliabilityPolicy,
    Ros2IntegrationContract, SafetyIntegrationContract, TopicContract, TopicDirection,
};
pub use memory::{
    append_robot_episode, initialize_robot_memory, read_robot_episodes, verify_robot_memory,
    MemoryActor, RobotEpisode, RobotMemoryPolicy, RobotMemoryVerification, RobotOutcome,
};
pub use replay::{
    replay_simulation, EmbodiedPlanner, SimulationFrame, SimulationReplayReport, SimulationTrace,
};
pub use ros2::{
    OfflineConformanceRos2Transport, Ros2Adapter, Ros2TopicMap, Ros2Transport,
    UnavailableRos2Transport,
};
pub use safety::{
    validate_permit, FailClosedSafetyController, SafetyAssessment, SafetyController,
    SafetyDecisionStatus,
};

use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::Path;

const MAX_JSON_BYTES: usize = 2 * 1024 * 1024;

/// Structured embodied-product failure.
#[derive(Debug)]
pub enum EmbodiedError {
    Invalid(String),
    Integrity(String),
    Deadline(String),
    SafetyDenied(String),
    AccessDenied(String),
    AdapterUnavailable(String),
    Replay(Vec<String>),
    Signature(String),
    Package(String),
    Json(String),
    Io { path: String, message: String },
}

impl Display for EmbodiedError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid embodied artifact: {message}"),
            Self::Integrity(message) => write!(formatter, "integrity failure: {message}"),
            Self::Deadline(message) => write!(formatter, "deadline failure: {message}"),
            Self::SafetyDenied(message) => write!(formatter, "safety controller denied: {message}"),
            Self::AccessDenied(message) => write!(formatter, "access denied: {message}"),
            Self::AdapterUnavailable(message) => {
                write!(formatter, "adapter unavailable: {message}")
            }
            Self::Replay(reasons) => write!(
                formatter,
                "simulation replay failed: {}",
                reasons.join("; ")
            ),
            Self::Signature(message) => write!(formatter, "signature failure: {message}"),
            Self::Package(message) => write!(formatter, "package failure: {message}"),
            Self::Json(message) => write!(formatter, "JSON failure: {message}"),
            Self::Io { path, message } => write!(formatter, "I/O failure at {path}: {message}"),
        }
    }
}

impl Error for EmbodiedError {}

fn json_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, EmbodiedError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| EmbodiedError::Json(error.to_string()))?;
    if bytes.len() > MAX_JSON_BYTES {
        return Err(EmbodiedError::Invalid(format!(
            "serialized artifact exceeds {MAX_JSON_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

fn pretty_json_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, EmbodiedError> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|error| EmbodiedError::Json(error.to_string()))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_JSON_BYTES {
        return Err(EmbodiedError::Invalid(format!(
            "serialized artifact exceeds {MAX_JSON_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, EmbodiedError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| EmbodiedError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return Err(EmbodiedError::Integrity(
            "artifact must be a bounded regular file".to_owned(),
        ));
    }
    std::fs::read(path).map_err(|error| EmbodiedError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), EmbodiedError> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| EmbodiedError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| EmbodiedError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })
}

fn validate_text(value: &str, field: &str) -> Result<(), EmbodiedError> {
    if value.is_empty() || value.len() > 4096 || value.contains('\0') {
        return Err(EmbodiedError::Invalid(format!(
            "{field} is empty or exceeds bounds"
        )));
    }
    Ok(())
}

fn validate_token(value: &str, field: &str) -> Result<(), EmbodiedError> {
    validate_text(value, field)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
    }) {
        return Err(EmbodiedError::Invalid(format!(
            "{field} contains unsupported characters"
        )));
    }
    Ok(())
}

fn validate_hash(value: &str, field: &str) -> Result<(), EmbodiedError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(EmbodiedError::Invalid(format!(
            "{field} must use sha256:<hex>"
        )));
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(EmbodiedError::Invalid(format!(
            "{field} has invalid SHA-256 syntax"
        )));
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode_array<const N: usize>(value: &str) -> Result<[u8; N], EmbodiedError> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(EmbodiedError::Signature(
            "hex signature or key length is invalid".to_owned(),
        ));
    }
    let mut output = [0_u8; N];
    for (index, slot) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *slot = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|error| EmbodiedError::Signature(error.to_string()))?;
    }
    Ok(output)
}
pub use activation::{
    activate_certified_integration, initialize_activation_ledger, verify_activation_ledger,
    ActivatedIntegration, ActivationAdmission, ActivationLedgerPolicy,
    ActivationLedgerVerification, ActivationRecord,
};
pub use certification::{
    certify_probed_runtime, certify_runtime_binding, create_runtime_binding_evidence,
    load_runtime_binding_evidence, BindingCertification, BindingCertificationReport,
    CertificationIssue, CertifiedIntegration, RuntimeBindingEvidence, RuntimeBindingInput,
    RuntimeBindingProbe, RuntimeHardwareBinding, RuntimeRos2Binding, RuntimeSafetyBinding,
    RuntimeTopicBinding,
};
