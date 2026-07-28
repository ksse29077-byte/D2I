use crate::{
    hash_value, validate_hash, validate_text, validate_token, DesktopActionIntent,
    DesktopAdapterDescriptor, DesktopCapability, DesktopError, DesktopOperation, RiskClass,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Authenticated actor requesting a desktop action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopActor {
    pub actor_id: String,
    pub roles: BTreeSet<String>,
}

impl DesktopActor {
    /// Validates the actor identity and bounded role set.
    pub fn validate(&self) -> Result<(), DesktopError> {
        validate_token(&self.actor_id, "actor_id")?;
        if self.roles.is_empty() || self.roles.len() > 64 {
            return Err(DesktopError::Invalid(
                "actor must have 1..=64 roles".to_owned(),
            ));
        }
        for role in &self.roles {
            validate_token(role, "actor role")?;
        }
        Ok(())
    }
}

/// Exact executable identity allowed by policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedExecutable {
    pub path: String,
    pub content_hash: String,
    pub arguments_prefix: Vec<String>,
    pub may_request_network: bool,
}

/// Immutable deny-by-default desktop policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopPolicy {
    pub schema_version: u32,
    pub policy_id: String,
    pub policy_version: String,
    pub allowed_actor_roles: BTreeSet<String>,
    pub allowed_capabilities: BTreeSet<DesktopCapability>,
    pub approval_required_for: BTreeSet<RiskClass>,
    pub allowed_read_roots: Vec<String>,
    pub allowed_write_roots: Vec<String>,
    pub allowed_executables: Vec<AllowedExecutable>,
    pub network_allowed: bool,
    pub allowed_network_origins: BTreeSet<String>,
    pub allowed_adapters: BTreeMap<String, String>,
    pub approver_public_keys: BTreeMap<String, String>,
    pub maximum_actions_per_session: u32,
    pub maximum_action_lifetime_ms: u64,
}

impl DesktopPolicy {
    /// Validates all policy bounds and exact allowlist identities.
    pub fn validate(&self) -> Result<(), DesktopError> {
        if self.schema_version != 1 {
            return Err(DesktopError::Invalid(
                "desktop policy schema_version must be 1".to_owned(),
            ));
        }
        validate_token(&self.policy_id, "policy_id")?;
        validate_token(&self.policy_version, "policy_version")?;
        if self.allowed_actor_roles.is_empty() || self.allowed_actor_roles.len() > 64 {
            return Err(DesktopError::Invalid(
                "allowed_actor_roles must contain 1..=64 values".to_owned(),
            ));
        }
        for role in &self.allowed_actor_roles {
            validate_token(role, "allowed actor role")?;
        }
        if self.allowed_capabilities.is_empty() {
            return Err(DesktopError::Invalid(
                "policy must explicitly allow at least one capability".to_owned(),
            ));
        }
        for mandatory in [
            RiskClass::ExternalCommunication,
            RiskClass::CredentialSensitive,
            RiskClass::Destructive,
            RiskClass::Privileged,
        ] {
            if !self.approval_required_for.contains(&mandatory) {
                return Err(DesktopError::Invalid(format!(
                    "{mandatory:?} actions must require human approval"
                )));
            }
        }
        if self.maximum_actions_per_session == 0 || self.maximum_actions_per_session > 100_000 {
            return Err(DesktopError::Invalid(
                "maximum_actions_per_session is outside 1..=100000".to_owned(),
            ));
        }
        if self.maximum_action_lifetime_ms == 0 || self.maximum_action_lifetime_ms > 15 * 60 * 1000
        {
            return Err(DesktopError::Invalid(
                "maximum_action_lifetime_ms is outside 1..=900000".to_owned(),
            ));
        }
        validate_roots(&self.allowed_read_roots, "allowed_read_roots")?;
        validate_roots(&self.allowed_write_roots, "allowed_write_roots")?;
        for executable in &self.allowed_executables {
            validate_absolute_path(&executable.path, "allowed executable path")?;
            validate_hash(&executable.content_hash, "allowed executable hash")?;
            if executable.arguments_prefix.len() > 128 {
                return Err(DesktopError::Invalid(
                    "allowed executable argument prefix exceeds 128".to_owned(),
                ));
            }
            for argument in &executable.arguments_prefix {
                validate_text(argument, "allowed argument prefix")?;
            }
        }
        if !self.network_allowed && !self.allowed_network_origins.is_empty() {
            return Err(DesktopError::Invalid(
                "network origins must be empty when network is denied".to_owned(),
            ));
        }
        for origin in &self.allowed_network_origins {
            validate_origin(origin)?;
        }
        if self.allowed_adapters.is_empty() {
            return Err(DesktopError::Invalid(
                "policy must pin at least one adapter descriptor".to_owned(),
            ));
        }
        for (adapter_id, descriptor_hash) in &self.allowed_adapters {
            validate_token(adapter_id, "adapter_id")?;
            validate_hash(descriptor_hash, "adapter descriptor hash")?;
        }
        for (approver_id, key) in &self.approver_public_keys {
            validate_token(approver_id, "approver_id")?;
            if key.len() != 64 || !key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(DesktopError::Invalid(
                    "approver public key must be 32-byte hex".to_owned(),
                ));
            }
        }
        if !self.approval_required_for.is_empty() && self.approver_public_keys.is_empty() {
            return Err(DesktopError::Invalid(
                "approval policy has no pinned approver keys".to_owned(),
            ));
        }
        Ok(())
    }

    /// Computes the exact policy identity bound into approvals and audit.
    pub fn policy_hash(&self) -> Result<String, DesktopError> {
        self.validate()?;
        hash_value(self)
    }
}

/// Terminal policy state for one proposed action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecisionStatus {
    Allowed,
    ApprovalRequired,
    Denied,
}

/// Fully bound policy result; reasons contain no action payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecision {
    pub status: PolicyDecisionStatus,
    pub policy_hash: String,
    pub action_hash: String,
    pub adapter_descriptor_hash: String,
    pub capability: DesktopCapability,
    pub risk_class: RiskClass,
    pub reasons: Vec<String>,
}

impl PolicyDecision {
    /// Computes the decision digest used by execution permits and audit records.
    pub fn decision_hash(&self) -> Result<String, DesktopError> {
        hash_value(self)
    }
}

/// Evaluates immutable action metadata against a deny-by-default policy.
pub fn evaluate_policy(
    policy: &DesktopPolicy,
    actor: &DesktopActor,
    adapter: &DesktopAdapterDescriptor,
    intent: &DesktopActionIntent,
) -> Result<PolicyDecision, DesktopError> {
    policy.validate()?;
    actor.validate()?;
    adapter.validate()?;
    intent.validate()?;

    let policy_hash = policy.policy_hash()?;
    let action_hash = intent.action_hash()?;
    let adapter_hash = adapter.descriptor_hash()?;
    let capability = intent.operation.capability();
    let risk_class = intent.operation.risk_class();
    let mut reasons = Vec::new();

    if actor.roles.is_disjoint(&policy.allowed_actor_roles) {
        reasons.push("actor has no policy-allowed role".to_owned());
    }
    if !policy.allowed_capabilities.contains(&capability) {
        reasons.push("capability is not allowed by policy".to_owned());
    }
    if !adapter.capabilities.contains(&capability) {
        reasons.push("adapter does not declare the required capability".to_owned());
    }
    match policy.allowed_adapters.get(&adapter.adapter_id) {
        Some(expected) if expected == &adapter_hash => {}
        _ => reasons.push("adapter identity is not pinned by policy".to_owned()),
    }
    if intent.expires_at_unix_ms - intent.generated_at_unix_ms > policy.maximum_action_lifetime_ms {
        reasons.push("action lifetime exceeds policy".to_owned());
    }

    evaluate_paths(policy, &intent.operation, &mut reasons);
    evaluate_process(policy, &intent.operation, &mut reasons);
    evaluate_network(policy, adapter, &intent.operation, &mut reasons);

    let status = if reasons.is_empty() {
        if policy.approval_required_for.contains(&risk_class) {
            PolicyDecisionStatus::ApprovalRequired
        } else {
            PolicyDecisionStatus::Allowed
        }
    } else {
        PolicyDecisionStatus::Denied
    };

    Ok(PolicyDecision {
        status,
        policy_hash,
        action_hash,
        adapter_descriptor_hash: adapter_hash,
        capability,
        risk_class,
        reasons,
    })
}

fn evaluate_paths(policy: &DesktopPolicy, operation: &DesktopOperation, reasons: &mut Vec<String>) {
    for (path, write) in operation.path_targets() {
        let roots = if write {
            &policy.allowed_write_roots
        } else {
            &policy.allowed_read_roots
        };
        if !roots
            .iter()
            .any(|root| Path::new(path).starts_with(Path::new(root)))
        {
            reasons.push(format!(
                "{} path is outside the configured roots",
                if write { "write" } else { "read" }
            ));
        }
    }
}

fn evaluate_process(
    policy: &DesktopPolicy,
    operation: &DesktopOperation,
    reasons: &mut Vec<String>,
) {
    let allowed = match operation {
        DesktopOperation::LaunchProcess {
            executable,
            executable_hash,
            arguments,
            network_requested,
            ..
        } => policy.allowed_executables.iter().any(|candidate| {
            candidate.path == *executable
                && candidate.content_hash == *executable_hash
                && arguments.starts_with(&candidate.arguments_prefix)
                && (!network_requested || candidate.may_request_network)
        }),
        DesktopOperation::TerminateProcess {
            expected_executable_hash,
            ..
        } => policy
            .allowed_executables
            .iter()
            .any(|candidate| candidate.content_hash == *expected_executable_hash),
        DesktopOperation::UiInteract { window, .. } => policy
            .allowed_executables
            .iter()
            .any(|candidate| candidate.content_hash == window.executable_hash),
        _ => return,
    };
    if !allowed {
        reasons.push("executable identity or argument prefix is not allowed".to_owned());
    }
}

fn evaluate_network(
    policy: &DesktopPolicy,
    adapter: &DesktopAdapterDescriptor,
    operation: &DesktopOperation,
    reasons: &mut Vec<String>,
) {
    let requested = operation.origin();
    let process_network_requested = matches!(
        operation,
        DesktopOperation::LaunchProcess {
            network_requested: true,
            ..
        }
    );
    if process_network_requested && !adapter.network_capable {
        reasons.push("adapter cannot satisfy requested process network access".to_owned());
    }
    if requested.is_some() || process_network_requested {
        if !policy.network_allowed {
            reasons.push("network is denied by policy".to_owned());
        } else if let Some(origin) = requested {
            if !policy.allowed_network_origins.contains(origin) {
                reasons.push("network origin is not allowlisted".to_owned());
            }
        }
    }
}

fn validate_roots(roots: &[String], field: &str) -> Result<(), DesktopError> {
    if roots.len() > 256 {
        return Err(DesktopError::Invalid(format!(
            "{field} exceeds 256 entries"
        )));
    }
    for root in roots {
        validate_absolute_path(root, field)?;
    }
    Ok(())
}

fn validate_absolute_path(value: &str, field: &str) -> Result<(), DesktopError> {
    validate_text(value, field)?;
    let path = Path::new(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(DesktopError::Invalid(format!(
            "{field} must be absolute without parent traversal"
        )));
    }
    Ok(())
}

fn validate_origin(origin: &str) -> Result<(), DesktopError> {
    validate_text(origin, "network origin")?;
    let rest = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .ok_or_else(|| DesktopError::Invalid("network origin has invalid scheme".to_owned()))?;
    if rest.is_empty() || rest.contains('/') || rest.contains('@') {
        return Err(DesktopError::Invalid(
            "network origin must contain scheme and authority only".to_owned(),
        ));
    }
    Ok(())
}
