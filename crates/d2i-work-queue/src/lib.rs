//! Deterministic work queues, exclusive Case leases, and current ownership.
//!
//! This crate is platform-neutral and side-effect free. Queue, lease, ownership,
//! and work-grant artifacts are coordination evidence, never execution authority.

mod contract;
mod scheduler;
mod strict;

pub use contract::*;
pub use scheduler::*;
pub use strict::{canonical_json_bytes, canonical_sha256, parse_json_strict};

use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Exact schema version implemented by WORK-400 v1.
pub const WORK_QUEUE_SCHEMA_VERSION: u32 = 1;
/// Stable verifier identity for deterministic receipts and reports.
pub const WORK_QUEUE_BUILD_ID: &str = "d2i-work-queue-v1";
/// Maximum number of Cases in one v1 queue.
pub const MAX_QUEUE_ENTRIES: usize = 128;
/// Maximum pool members in one approved ownership pool.
pub const MAX_POOL_MEMBERS: usize = 128;
/// Maximum IDs in a bounded set.
pub const MAX_IDS: usize = 128;
/// Maximum evidence and reason references.
pub const MAX_EVIDENCE_IDS: usize = 256;
/// Maximum strict JSON input size.
pub const MAX_JSON_BYTES: usize = 8 * 1024 * 1024;
/// Maximum lease lifetime accepted by the contract.
pub const MAX_LEASE_SECONDS: u64 = 86_400;
/// Maximum ownership generations retained by v1.
pub const MAX_OWNERSHIP_GENERATIONS: u64 = 1_024;
/// Maximum deterministic replay records.
pub const MAX_REPLAY_RECORDS: usize = 65_536;
/// Canonical empty chain head.
pub const ZERO_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

pub const WORK_QUEUE_POLICY_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/work-queue-policy-v1.schema.json");
pub const CASE_OWNERSHIP_POOL_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/case-ownership-pool-v1.schema.json");
pub const CURRENT_CASE_OWNERSHIP_STATE_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/current-case-ownership-state-v1.schema.json");
pub const WORK_QUEUE_ENTRY_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/work-queue-entry-v1.schema.json");
pub const WORK_QUEUE_SNAPSHOT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/work-queue-snapshot-v1.schema.json");
pub const WORK_SCHEDULER_TICK_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/work-scheduler-tick-v1.schema.json");
pub const WORK_SCHEDULER_DECISION_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/work-scheduler-decision-v1.schema.json");
pub const CASE_LEASE_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/case-lease-v1.schema.json");
pub const CASE_OWNERSHIP_TRANSFER_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/case-ownership-transfer-v1.schema.json");
pub const CASE_WORK_GRANT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/case-work-grant-v1.schema.json");
pub const WORK_QUEUE_OPERATION_RECEIPT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/work-queue-operation-receipt-v1.schema.json");
pub const NORMALIZED_QUEUE_REPLAY_REPORT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/normalized-queue-replay-report-v1.schema.json");

/// Fail-closed Queue, Scheduler, lease, or ownership error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkQueueError {
    Invalid(String),
    Integrity(String),
    Authorization(String),
    Replay(String),
    ResourceLimit(String),
    Json(String),
    Io(String),
}

impl Display for WorkQueueError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid work queue contract: {message}"),
            Self::Integrity(message) => {
                write!(formatter, "work queue integrity failure: {message}")
            }
            Self::Authorization(message) => {
                write!(formatter, "work queue authorization denied: {message}")
            }
            Self::Replay(message) => write!(formatter, "work queue replay rejected: {message}"),
            Self::ResourceLimit(message) => {
                write!(formatter, "work queue resource limit: {message}")
            }
            Self::Json(message) => write!(formatter, "work queue JSON failure: {message}"),
            Self::Io(message) => write!(formatter, "work queue I/O failure: {message}"),
        }
    }
}

impl Error for WorkQueueError {}

impl From<d2i_work_case::WorkCaseError> for WorkQueueError {
    fn from(error: d2i_work_case::WorkCaseError) -> Self {
        Self::Integrity(error.to_string())
    }
}

impl From<d2i_role_contract::RoleContractError> for WorkQueueError {
    fn from(error: d2i_role_contract::RoleContractError) -> Self {
        Self::Integrity(error.to_string())
    }
}

pub(crate) fn invalid<T>(message: impl Into<String>) -> Result<T, WorkQueueError> {
    Err(WorkQueueError::Invalid(message.into()))
}

pub(crate) fn integrity<T>(message: impl Into<String>) -> Result<T, WorkQueueError> {
    Err(WorkQueueError::Integrity(message.into()))
}

pub(crate) fn authorization<T>(message: impl Into<String>) -> Result<T, WorkQueueError> {
    Err(WorkQueueError::Authorization(message.into()))
}

pub(crate) fn replay<T>(message: impl Into<String>) -> Result<T, WorkQueueError> {
    Err(WorkQueueError::Replay(message.into()))
}

pub(crate) fn resource<T>(message: impl Into<String>) -> Result<T, WorkQueueError> {
    Err(WorkQueueError::ResourceLimit(message.into()))
}
