//! Deterministic, authority-free Work Radar and Work Intake contracts.
//!
//! This crate turns bounded signals from explicitly approved sources into the
//! existing immutable Work Item admission flow. It owns no filesystem,
//! network, background scheduling, process, credential, or adapter authority.

mod contract;
mod intake;
mod strict;

pub use contract::*;
pub use intake::*;
pub use strict::{canonical_json_bytes, canonical_sha256, parse_json_strict};

use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Schema version shared by all WORK-300 contracts.
pub const WORK_INTAKE_SCHEMA_VERSION: u32 = 1;
/// Stable verifier identity for WORK-300 deterministic artifacts.
pub const WORK_INTAKE_BUILD_ID: &str = "d2i-work-intake-v1";
/// Published approved source registration schema.
pub const RADAR_SOURCE_REGISTRATION_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/work-radar-source-registration-v1.schema.json");
/// Published signed Work Source approval schema.
pub const WORK_SOURCE_APPROVAL_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/work-source-approval-v1.schema.json");
/// Published typed Work Signal schema.
pub const WORK_SIGNAL_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/work-signal-v1.schema.json");
/// Published exact intake mapping schema.
pub const WORK_INTAKE_MAPPING_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/work-intake-mapping-v1.schema.json");
/// Published durable checkpoint schema.
pub const RADAR_CHECKPOINT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/work-radar-checkpoint-v1.schema.json");
/// Published intake receipt schema.
pub const WORK_INTAKE_RECEIPT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/work-intake-receipt-v1.schema.json");
/// Published Radar cycle report schema.
pub const RADAR_CYCLE_REPORT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/work-radar-cycle-report-v1.schema.json");

pub const MAX_ID_LENGTH: usize = 128;
pub const MAX_EVENTS_PER_CYCLE: usize = 128;
pub const MAX_REFERENCES: usize = 128;
pub const MAX_EVIDENCE: usize = 256;
pub const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_CYCLE_LOGICAL_OPERATIONS: u64 = 16_384;
pub const ZERO_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Fail-closed Radar or Intake failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkIntakeError {
    Invalid(String),
    Integrity(String),
    NotAdmissible(String),
    Replay(String),
    ResourceLimit(String),
    Adapter(String),
    Json(String),
    Io(String),
}

impl Display for WorkIntakeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid Work Intake artifact: {message}"),
            Self::Integrity(message) => {
                write!(formatter, "Work Intake integrity failure: {message}")
            }
            Self::NotAdmissible(message) => write!(formatter, "Work Intake denied: {message}"),
            Self::Replay(message) => write!(formatter, "Work Intake replay rejected: {message}"),
            Self::ResourceLimit(message) => {
                write!(formatter, "Work Intake resource limit: {message}")
            }
            Self::Adapter(message) => write!(formatter, "Radar adapter failure: {message}"),
            Self::Json(message) => write!(formatter, "Work Intake JSON failure: {message}"),
            Self::Io(message) => write!(formatter, "Work Intake I/O failure: {message}"),
        }
    }
}

impl Error for WorkIntakeError {}

impl From<d2i_work_case::WorkCaseError> for WorkIntakeError {
    fn from(error: d2i_work_case::WorkCaseError) -> Self {
        match error {
            d2i_work_case::WorkCaseError::Invalid(message) => Self::Invalid(message),
            d2i_work_case::WorkCaseError::Integrity(message) => Self::Integrity(message),
            d2i_work_case::WorkCaseError::NotAdmissible(message) => Self::NotAdmissible(message),
            d2i_work_case::WorkCaseError::Replay(message)
            | d2i_work_case::WorkCaseError::Terminal(message) => Self::Replay(message),
            d2i_work_case::WorkCaseError::Json(message) => Self::Json(message),
            d2i_work_case::WorkCaseError::Io(message) => Self::Io(message),
        }
    }
}

impl From<d2i_role_contract::RoleContractError> for WorkIntakeError {
    fn from(error: d2i_role_contract::RoleContractError) -> Self {
        let message = error.to_string();
        match error {
            d2i_role_contract::RoleContractError::Invalid(_) => Self::Invalid(message),
            d2i_role_contract::RoleContractError::Integrity(_) => Self::Integrity(message),
            d2i_role_contract::RoleContractError::NotAdmissible(_) => Self::NotAdmissible(message),
            d2i_role_contract::RoleContractError::Replay(_) => Self::Replay(message),
            d2i_role_contract::RoleContractError::Json(_) => Self::Json(message),
            d2i_role_contract::RoleContractError::Io(_) => Self::Io(message),
        }
    }
}
