//! Deterministic Role Contract v1 compiler and bounded workforce admission.
//!
//! A role contract declares a maximum organizational envelope. It is not a
//! policy decision, activation token, execution permit, Work Item, or Case.

mod admission;
mod contract;
mod governance;
mod strict;

pub use admission::{
    admit_role_task, RoleBoundKernelTaskContextV1, RoleInstanceStatusV1, RoleInstanceV1,
    RoleOperationalTimeContextV1, RoleTaskAdmissionArtifactsV1, RoleTaskAdmissionDecisionV1,
    RoleTaskAdmissionOutcomeV1, RoleTaskAdmissionReasonCodeV1, RoleTaskAdmissionRequestV1,
};
pub use contract::{
    compile_role_source, AcceptedWorkClassRefV1, CrossCaseReusePolicyV1, EmergencyOverridePolicyV1,
    KpiBreachBehaviorV1, KpiDirectionV1, ObservationSourceKindV1, OrganizationScopeV1,
    OutsideWindowBehaviorV1, RoleApplicationBindingV1, RoleCapabilityPolicyV1, RoleCompileFormatV1,
    RoleConformanceV1, RoleContractBundleV1, RoleContractManifestV1, RoleContractV1,
    RoleEscalationPolicyV1, RoleHumanExceptionPolicyV1, RoleKpiDefinitionV1, RoleMemoryBoundaryV1,
    RoleObservationSourceV1, RoleReportingObligationV1, RoleReportingTriggerV1,
    RoleResponsibilityDescriptorV1, RoleRiskPolicyV1, RoleSlaProfileV1, RoleSourceLockV1,
    RoleSourcePackV1, RoleWorkingCalendarV1, UnknownPolicyBehaviorV1, UnsafeVerificationBehaviorV1,
    WeeklyWindowV1,
};
pub use governance::{
    create_role_contract_approval, create_role_delegation, verify_role_contract_approval,
    verify_role_delegation, RoleContractApprovalV1, RoleDelegationGrantV1,
};
pub use strict::{canonical_json_bytes, canonical_sha256, parse_json_strict};

use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Role Contract v1 schema version.
pub const ROLE_CONTRACT_SCHEMA_VERSION: u32 = 1;
/// Stable build identity for the first Role Contract compiler.
pub const ROLE_CONTRACT_COMPILER_BUILD_ID: &str = "d2i-role-contract-compiler-v1";
/// Published Role Contract schema.
pub const ROLE_CONTRACT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/role-contract-v1.schema.json");
/// Published Role Instance schema.
pub const ROLE_INSTANCE_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/role-instance-v1.schema.json");

pub(crate) const MAX_ID_LEN: usize = 128;
pub(crate) const MAX_TEXT_LEN: usize = 2_048;
pub(crate) const MAX_ITEMS: usize = 128;
pub(crate) const MAX_EVIDENCE: usize = 64;
pub(crate) const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_ROLE_TTL_SECONDS: u64 = 31_536_000;
pub(crate) const ZERO_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Fail-closed Role Contract error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleContractError {
    /// A bounded field, reference, or state transition is invalid.
    Invalid(String),
    /// A digest, signature, or immutable binding was substituted.
    Integrity(String),
    /// A role or task is outside delegated authority.
    NotAdmissible(String),
    /// A one-time admission or lifecycle transition was replayed.
    Replay(String),
    /// Strict serialization or source parsing failed.
    Json(String),
    /// File-backed CLI operation failed.
    Io(String),
}

impl Display for RoleContractError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid role contract: {message}"),
            Self::Integrity(message) => {
                write!(formatter, "role contract integrity failure: {message}")
            }
            Self::NotAdmissible(message) => write!(formatter, "role task denied: {message}"),
            Self::Replay(message) => write!(formatter, "role replay rejected: {message}"),
            Self::Json(message) => write!(formatter, "role JSON failure: {message}"),
            Self::Io(message) => write!(formatter, "role I/O failure: {message}"),
        }
    }
}

impl Error for RoleContractError {}

pub(crate) fn invalid<T>(message: impl Into<String>) -> Result<T, RoleContractError> {
    Err(RoleContractError::Invalid(message.into()))
}

pub(crate) fn integrity<T>(message: impl Into<String>) -> Result<T, RoleContractError> {
    Err(RoleContractError::Integrity(message.into()))
}

pub(crate) fn validate_id(value: &str, label: &str) -> Result<(), RoleContractError> {
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

pub(crate) fn validate_text(value: &str, label: &str) -> Result<(), RoleContractError> {
    if value.trim().is_empty() || value.len() > MAX_TEXT_LEN || value.contains('\0') {
        return invalid(format!("{label} is empty or exceeds its bound"));
    }
    let lower = value.to_ascii_lowercase();
    for marker in [
        "password=",
        "token=",
        "private key",
        "authorization: bearer",
    ] {
        if lower.contains(marker) {
            return invalid(format!("{label} contains secret-like material"));
        }
    }
    Ok(())
}

pub(crate) fn validate_hash(value: &str, label: &str) -> Result<(), RoleContractError> {
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

pub(crate) fn canonicalize_ids(
    values: &mut [String],
    label: &str,
    allow_empty: bool,
) -> Result<(), RoleContractError> {
    values.sort();
    validate_ids(values, label, allow_empty)
}

pub(crate) fn validate_ids(
    values: &[String],
    label: &str,
    allow_empty: bool,
) -> Result<(), RoleContractError> {
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

pub(crate) fn validate_evidence(values: &[String], label: &str) -> Result<(), RoleContractError> {
    if values.len() > MAX_EVIDENCE {
        return invalid(format!("{label} exceeds the evidence bound"));
    }
    validate_ids(values, label, true)
}

pub(crate) fn min_risk(
    left: d2i_cognitive_ir::CognitiveRiskClass,
    right: d2i_cognitive_ir::CognitiveRiskClass,
) -> d2i_cognitive_ir::CognitiveRiskClass {
    if left <= right {
        left
    } else {
        right
    }
}
