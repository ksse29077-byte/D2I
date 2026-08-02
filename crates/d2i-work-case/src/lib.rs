//! Immutable Work Item and verified-closure Case contracts.
//!
//! Work Items describe admitted work. Case contracts retain responsibility and
//! evidence across one or more task attempts. Neither artifact grants runtime
//! execution authority.

mod case;
mod strict;
mod work_item;

pub use case::*;
pub use strict::{canonical_json_bytes, canonical_sha256, parse_json_strict};
pub use work_item::*;

use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Work Item and Case schema version.
pub const WORK_CASE_SCHEMA_VERSION: u32 = 1;
/// Stable build identity for the v1 contract implementation.
pub const WORK_CASE_BUILD_ID: &str = "d2i-work-case-v1";
/// Published Work Item schema.
pub const WORK_ITEM_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/work-item-v1.schema.json");
/// Published Case Contract schema.
pub const CASE_CONTRACT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/case-contract-v1.schema.json");
/// Published Case Instance schema.
pub const CASE_INSTANCE_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/case-instance-v1.schema.json");

pub(crate) const MAX_ID_LEN: usize = 128;
pub(crate) const MAX_ITEMS: usize = 128;
pub(crate) const MAX_EVIDENCE: usize = 256;
pub(crate) const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const ZERO_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Fail-closed Work Item or Case contract error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkCaseError {
    Invalid(String),
    Integrity(String),
    NotAdmissible(String),
    Replay(String),
    Terminal(String),
    Json(String),
    Io(String),
}

impl Display for WorkCaseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid Work/Case contract: {message}"),
            Self::Integrity(message) => write!(formatter, "Work/Case integrity failure: {message}"),
            Self::NotAdmissible(message) => write!(formatter, "Work Item denied: {message}"),
            Self::Replay(message) => write!(formatter, "Work/Case replay rejected: {message}"),
            Self::Terminal(message) => {
                write!(formatter, "terminal Case mutation rejected: {message}")
            }
            Self::Json(message) => write!(formatter, "Work/Case JSON failure: {message}"),
            Self::Io(message) => write!(formatter, "Work/Case I/O failure: {message}"),
        }
    }
}

impl Error for WorkCaseError {}

pub(crate) fn invalid<T>(message: impl Into<String>) -> Result<T, WorkCaseError> {
    Err(WorkCaseError::Invalid(message.into()))
}

pub(crate) fn integrity<T>(message: impl Into<String>) -> Result<T, WorkCaseError> {
    Err(WorkCaseError::Integrity(message.into()))
}

pub(crate) fn validate_id(value: &str, label: &str) -> Result<(), WorkCaseError> {
    if value.is_empty()
        || value.len() > MAX_ID_LEN
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

pub(crate) fn validate_hash(value: &str, label: &str) -> Result<(), WorkCaseError> {
    if value.len() != 71
        || !value.starts_with("sha256:")
        || !value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return invalid(format!("{label} is not a lowercase sha256 digest"));
    }
    Ok(())
}

pub(crate) fn normalize_ids(
    values: &mut [String],
    label: &str,
    allow_empty: bool,
) -> Result<(), WorkCaseError> {
    values.sort();
    validate_ids(values, label, allow_empty)
}

pub(crate) fn validate_ids(
    values: &[String],
    label: &str,
    allow_empty: bool,
) -> Result<(), WorkCaseError> {
    if values.len() > MAX_ITEMS
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

pub(crate) fn validate_hashes(
    values: &[String],
    label: &str,
    allow_empty: bool,
) -> Result<(), WorkCaseError> {
    if values.len() > MAX_EVIDENCE
        || (!allow_empty && values.is_empty())
        || !values.windows(2).all(|pair| pair[0] < pair[1])
    {
        return invalid(format!("{label} is duplicated, unsorted, or oversized"));
    }
    for value in values {
        validate_hash(value, label)?;
    }
    Ok(())
}

pub(crate) fn normalize_hashes(
    values: &mut [String],
    label: &str,
    allow_empty: bool,
) -> Result<(), WorkCaseError> {
    values.sort();
    validate_hashes(values, label, allow_empty)
}

pub(crate) fn reject_sensitive<T: serde::Serialize>(
    value: &T,
    label: &str,
) -> Result<(), WorkCaseError> {
    let serialized = String::from_utf8(canonical_json_bytes(value)?)
        .map_err(|error| WorkCaseError::Json(error.to_string()))?
        .to_ascii_lowercase();
    for marker in [
        "raw_payload",
        "raw_instruction",
        "email_body",
        "document_body",
        "locator",
        "selector",
        "credential",
        "password",
        "private_key",
        "authorization: bearer",
        "c:\\\\",
    ] {
        if serialized.contains(marker) {
            return integrity(format!("{label} contains forbidden sensitive material"));
        }
    }
    Ok(())
}
