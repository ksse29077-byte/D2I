use crate::{DesktopError, GoalProgress, Provenance, RoleInstanceLedgerVerificationV1, WorkReport};
use d2i_cognitive_recovery::RecoveryPolicyProfileV1;
use d2i_module_sdk::{
    canonical_json_bytes, canonical_sha256, load_module_manifest, parse_json_strict,
    validate_result_binding, LoadedModuleManifest, ModuleInvocationEnvelope, ModuleResultEnvelope,
    NetworkRequirement,
};
use d2i_policy_admission::DelegatedAuthorityContextV1;
use d2i_role_contract::{RoleBoundKernelTaskContextV1, RoleInstanceStatusV1};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Schema version for the additive KRN-500 task artifacts.
pub const KERNEL_TASK_SCHEMA_VERSION: u32 = 1;
/// Product runtime build identity recorded in KRN-500 reports.
pub const KERNEL_TASK_RUNTIME_BUILD_ID: &str = "d2i-kernel-task-runtime-v1";

const MAX_INSTRUCTION_BYTES: usize = 16 * 1024;
const MAX_EVIDENCE_IDS: usize = 128;
const MAX_HASHES: usize = 256;
const MAX_STAGE_RECORDS: usize = 128;
const MAX_ACTION_CYCLES: usize = 16;
const MAX_MODULE_RECORDS: usize = 32;
const MAX_MODULE_INPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_MODULE_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_MODULE_STDERR_BYTES: usize = 64 * 1024;
const MAX_HOST_EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;

/// Strict authenticated task input accepted by the first complete Kernel E2E.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedTaskInstructionV1 {
    pub schema_version: u32,
    pub instruction_id: String,
    pub locale: String,
    pub source_id: String,
    pub authenticated_actor_id: String,
    pub authenticated_role_id: String,
    pub organization_id: String,
    pub instruction_text: String,
    pub structured_success_criteria: Vec<d2i_cognitive_ir::Postcondition>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub provenance: Provenance,
    pub evidence_ids: Vec<String>,
    pub instruction_sha256: String,
}

impl AuthenticatedTaskInstructionV1 {
    /// Seals the instruction after normalizing evidence identifiers.
    pub fn seal(mut self) -> Result<Self, DesktopError> {
        self.evidence_ids.sort();
        self.instruction_sha256 = self.compute_instruction_sha256()?;
        Ok(self)
    }

    /// Computes the canonical hash with the self-hash omitted.
    pub fn compute_instruction_sha256(&self) -> Result<String, DesktopError> {
        hash_without_field(self, "instruction_sha256")
    }

    /// Validates authentication metadata, bounds, lifetime, and self-hash.
    pub fn validate(&self, now_unix_ms: u64) -> Result<(), DesktopError> {
        if self.schema_version != KERNEL_TASK_SCHEMA_VERSION || self.locale != "ko-KR" {
            return invalid("authenticated instruction schema or locale is unsupported");
        }
        for (value, field) in [
            (&self.instruction_id, "instruction_id"),
            (&self.source_id, "source_id"),
            (&self.authenticated_actor_id, "authenticated_actor_id"),
            (&self.authenticated_role_id, "authenticated_role_id"),
            (&self.organization_id, "organization_id"),
        ] {
            validate_id(value, field)?;
        }
        validate_text(
            &self.instruction_text,
            "instruction_text",
            MAX_INSTRUCTION_BYTES,
        )?;
        if self.structured_success_criteria.is_empty()
            || self.structured_success_criteria.len() > 16
        {
            return invalid("structured_success_criteria must contain 1..=16 entries");
        }
        for criterion in &self.structured_success_criteria {
            validate_id(&criterion.target_state, "success criterion target_state")?;
            if criterion.timeout_ms == 0 || criterion.timeout_ms > 60_000 {
                return invalid("success criterion timeout must be within 1..=60000 ms");
            }
            reject_sensitive_value(&criterion.expected_value, "success criterion")?;
        }
        if self.issued_at_unix_ms == 0
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
            || now_unix_ms < self.issued_at_unix_ms
            || now_unix_ms >= self.expires_at_unix_ms
            || self
                .expires_at_unix_ms
                .saturating_sub(self.issued_at_unix_ms)
                > 300_000
        {
            return invalid("authenticated instruction lifetime is invalid or expired");
        }
        validate_text(
            &self.provenance.source,
            "instruction provenance source",
            4_096,
        )?;
        validate_hash(
            &self.provenance.source_hash,
            "instruction provenance source_hash",
        )?;
        validate_id(
            &self.provenance.module_id,
            "instruction provenance module_id",
        )?;
        if self.provenance.module_id != "authenticated-user-instruction" {
            return invalid("instruction provenance is not authenticated_user_instruction");
        }
        validate_sorted_ids(
            &self.evidence_ids,
            "instruction evidence_ids",
            MAX_EVIDENCE_IDS,
        )?;
        reject_sensitive_text(&self.instruction_text, "instruction_text")?;
        validate_hash(&self.instruction_sha256, "instruction_sha256")?;
        if self.compute_instruction_sha256()? != self.instruction_sha256 {
            return integrity("instruction_sha256 differs from canonical instruction");
        }
        Ok(())
    }
}

/// Parses an authenticated instruction with duplicate-key and unknown-field rejection.
pub fn parse_authenticated_task_instruction_v1(
    bytes: &[u8],
    now_unix_ms: u64,
) -> Result<AuthenticatedTaskInstructionV1, DesktopError> {
    if bytes.len() > MAX_INSTRUCTION_BYTES * 2 {
        return invalid("authenticated instruction JSON exceeds its byte bound");
    }
    let instruction: AuthenticatedTaskInstructionV1 =
        parse_json_strict(bytes).map_err(module_error)?;
    instruction.validate(now_unix_ms)?;
    Ok(instruction)
}

/// Runtime-only pin for one supported standalone module host.
#[derive(Debug, Clone)]
pub struct ModuleHostBindingV1 {
    pub module_root: PathBuf,
    pub host_executable: PathBuf,
    pub expected_host_sha256: String,
    pub expected_module_id: String,
    pub expected_module_version: String,
    pub expected_capability_id: String,
    pub expected_capability_version: String,
    pub expected_input_schema_id: String,
    pub expected_output_schema_id: String,
}

impl ModuleHostBindingV1 {
    /// Loads and validates all immutable host and module identities.
    pub fn validate(&self) -> Result<LoadedModuleManifest, DesktopError> {
        let supported = expected_module_contract(&self.expected_module_id).ok_or_else(|| {
            DesktopError::AccessDenied("module ID is not allowed by KRN-500".to_owned())
        })?;
        if (
            self.expected_module_version.as_str(),
            self.expected_capability_id.as_str(),
            self.expected_capability_version.as_str(),
            self.expected_input_schema_id.as_str(),
            self.expected_output_schema_id.as_str(),
        ) != supported
        {
            return integrity("module host binding differs from the closed KRN-500 allowlist");
        }
        let root = canonical_directory(&self.module_root, "module root")?;
        let executable = canonical_file(&self.host_executable, "module host executable")?;
        if sha256_regular_file(&executable, MAX_HOST_EXECUTABLE_BYTES)? != self.expected_host_sha256
        {
            return integrity("module host executable hash mismatch");
        }
        let loaded = load_module_manifest(&root).map_err(module_error)?;
        if loaded.identifier.module_id != self.expected_module_id
            || loaded.identifier.module_version != self.expected_module_version
        {
            return integrity("loaded module identity differs from host binding");
        }
        let capability = loaded
            .manifest
            .capabilities
            .iter()
            .find(|item| item.capability.capability_id == self.expected_capability_id)
            .ok_or_else(|| {
                DesktopError::Integrity("expected module capability is absent".to_owned())
            })?;
        if capability.capability.capability_version != self.expected_capability_version
            || !capability
                .input_schemas
                .contains(&self.expected_input_schema_id)
            || !capability
                .output_schemas
                .contains(&self.expected_output_schema_id)
            || capability.capability.network_requirement != NetworkRequirement::Denied
            || capability.capability.side_effect
            || loaded.manifest.execution.network_requirement != NetworkRequirement::Denied
            || loaded.manifest.execution.side_effect
            || loaded.manifest.execution.filesystem_required
            || loaded.manifest.execution.environment_variables_allowed
            || loaded.manifest.security.secrets_required
            || loaded.manifest.security.raw_secret_input
            || loaded.manifest.security.privileged_operation
        {
            return integrity("module manifest violates the bounded no-authority host contract");
        }
        Ok(loaded)
    }
}

/// Terminal status of one out-of-process module host invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleInvocationTerminalStatusV1 {
    Succeeded,
    ModuleUnsupported,
    ModuleFailed,
    HostFailed,
    TimedOut,
}

/// Audit-safe machine record for one exact module process invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleInvocationRecordV1 {
    pub schema_version: u32,
    pub invocation_id: String,
    pub invocation_sha256: String,
    pub module_id: String,
    pub module_version: String,
    pub build_id: String,
    pub manifest_sha256: String,
    pub artifact_sha256: String,
    pub host_executable_sha256: String,
    pub input_schema_sha256: String,
    pub output_schema_sha256: String,
    pub result_output_sha256: Option<String>,
    pub process_id: u32,
    pub exit_code: Option<i32>,
    pub stderr_present: bool,
    pub logical_tick: u64,
    pub status: ModuleInvocationTerminalStatusV1,
    pub record_sha256: String,
}

impl ModuleInvocationRecordV1 {
    fn seal(mut self) -> Result<Self, DesktopError> {
        self.record_sha256 = hash_without_field(&self, "record_sha256")?;
        Ok(self)
    }

    /// Validates the record self-hash and bounded identities.
    pub fn validate(&self) -> Result<(), DesktopError> {
        if self.schema_version != KERNEL_TASK_SCHEMA_VERSION || self.process_id == 0 {
            return invalid("module invocation record schema or process ID is invalid");
        }
        validate_id(&self.invocation_id, "module record invocation_id")?;
        validate_id(&self.module_id, "module record module_id")?;
        validate_id(&self.module_version, "module record module_version")?;
        validate_id(&self.build_id, "module record build_id")?;
        for (value, field) in [
            (&self.invocation_sha256, "invocation_sha256"),
            (&self.manifest_sha256, "manifest_sha256"),
            (&self.artifact_sha256, "artifact_sha256"),
            (&self.host_executable_sha256, "host_executable_sha256"),
            (&self.input_schema_sha256, "input_schema_sha256"),
            (&self.output_schema_sha256, "output_schema_sha256"),
            (&self.record_sha256, "record_sha256"),
        ] {
            validate_hash(value, field)?;
        }
        if let Some(hash) = &self.result_output_sha256 {
            validate_hash(hash, "result_output_sha256")?;
        }
        if hash_without_field(self, "record_sha256")? != self.record_sha256 {
            return integrity("module invocation record hash mismatch");
        }
        Ok(())
    }
}

/// Closed subprocess coordinator for the three standalone KRN-500 modules.
pub struct ModuleInvocationCoordinatorV1 {
    bindings: BTreeMap<String, ModuleHostBindingV1>,
    timeout: Duration,
    records: Vec<ModuleInvocationRecordV1>,
    consumed_invocation_ids: BTreeSet<String>,
}

impl ModuleInvocationCoordinatorV1 {
    /// Creates a coordinator containing exactly one pin for each supported module.
    pub fn new(
        bindings: Vec<ModuleHostBindingV1>,
        timeout: Duration,
    ) -> Result<Self, DesktopError> {
        if timeout.is_zero() || timeout > Duration::from_secs(30) || bindings.len() != 3 {
            return invalid("module coordinator requires three bindings and a 1..=30s timeout");
        }
        let mut by_id = BTreeMap::new();
        for binding in bindings {
            let _ = binding.validate()?;
            let id = binding.expected_module_id.clone();
            if by_id.insert(id, binding).is_some() {
                return invalid("duplicate module host binding");
            }
        }
        if by_id.keys().map(String::as_str).collect::<BTreeSet<_>>()
            != BTreeSet::from(["element-grounder", "goal-compiler", "plan-ranker"])
        {
            return invalid("module coordinator bindings do not match the closed allowlist");
        }
        Ok(Self {
            bindings: by_id,
            timeout,
            records: Vec::new(),
            consumed_invocation_ids: BTreeSet::new(),
        })
    }

    /// Invokes one pinned host once and validates the exact Module Contract result.
    pub fn invoke(
        &mut self,
        invocation: &ModuleInvocationEnvelope,
    ) -> Result<ModuleResultEnvelope, DesktopError> {
        invocation.validate().map_err(module_error)?;
        if !self
            .consumed_invocation_ids
            .insert(invocation.invocation_id.clone())
        {
            return Err(DesktopError::Replay(
                "module invocation_id has already been consumed".to_owned(),
            ));
        }
        let binding = self
            .bindings
            .get(&invocation.module.module_id)
            .ok_or_else(|| DesktopError::AccessDenied("unknown module invocation".to_owned()))?
            .clone();
        let loaded = binding.validate()?;
        if invocation.module != loaded.identifier
            || invocation.requested_capability != binding.expected_capability_id
            || invocation.input_schema_id != binding.expected_input_schema_id
            || invocation.deadline_logical_tick <= invocation.logical_sequence
            || invocation.resource_budget.max_input_bytes
                > loaded.manifest.execution.maximum_input_bytes
            || invocation.resource_budget.max_output_bytes
                > loaded.manifest.execution.maximum_output_bytes
            || !invocation.trust_labels.iter().all(|label| {
                loaded
                    .manifest
                    .security
                    .accepted_trust_labels
                    .contains(label)
            })
        {
            return integrity("module invocation differs from its pinned manifest or lifecycle");
        }
        let input_schema_sha256 = schema_hash(&loaded, &binding.expected_input_schema_id)?;
        let output_schema_sha256 = schema_hash(&loaded, &binding.expected_output_schema_id)?;
        let invocation_sha256 = canonical_sha256(invocation).map_err(module_error)?;
        let input = canonical_json_bytes(invocation).map_err(module_error)?;
        if input.len() > MAX_MODULE_INPUT_BYTES {
            return invalid("module invocation exceeds host input bound");
        }

        let executable = canonical_file(&binding.host_executable, "module host executable")?;
        let root = canonical_directory(&binding.module_root, "module root")?;
        let mut child = Command::new(&executable)
            .current_dir(&root)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| DesktopError::Io {
                path: "module-host".to_owned(),
                message: error.to_string(),
            })?;
        let process_id = child.id();
        let stdout = child.stdout.take().ok_or_else(|| {
            DesktopError::Integrity("module host stdout pipe is absent".to_owned())
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            DesktopError::Integrity("module host stderr pipe is absent".to_owned())
        })?;
        let stdout_reader =
            thread::spawn(move || read_pipe_bounded(stdout, MAX_MODULE_OUTPUT_BYTES));
        let stderr_reader =
            thread::spawn(move || read_pipe_bounded(stderr, MAX_MODULE_STDERR_BYTES));
        let mut stdin = child.stdin.take().ok_or_else(|| {
            DesktopError::Integrity("module host stdin pipe is absent".to_owned())
        })?;
        stdin.write_all(&input).map_err(|error| DesktopError::Io {
            path: "module-host-stdin".to_owned(),
            message: error.to_string(),
        })?;
        drop(stdin);

        let started = Instant::now();
        let exit_status = loop {
            if let Some(status) = child.try_wait().map_err(|error| DesktopError::Io {
                path: "module-host".to_owned(),
                message: error.to_string(),
            })? {
                break Some(status);
            }
            if started.elapsed() >= self.timeout {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            thread::sleep(Duration::from_millis(10));
        };
        let stdout = join_reader(stdout_reader)?;
        let stderr = join_reader(stderr_reader)?;
        let status = if exit_status.is_none() {
            ModuleInvocationTerminalStatusV1::TimedOut
        } else if !exit_status
            .as_ref()
            .is_some_and(std::process::ExitStatus::success)
        {
            ModuleInvocationTerminalStatusV1::HostFailed
        } else {
            ModuleInvocationTerminalStatusV1::Succeeded
        };
        let mut record = ModuleInvocationRecordV1 {
            schema_version: KERNEL_TASK_SCHEMA_VERSION,
            invocation_id: invocation.invocation_id.clone(),
            invocation_sha256,
            module_id: loaded.identifier.module_id.clone(),
            module_version: loaded.identifier.module_version.clone(),
            build_id: loaded.identifier.build_id.clone(),
            manifest_sha256: loaded.identifier.manifest_sha256.clone(),
            artifact_sha256: loaded.identifier.artifact_sha256.clone(),
            host_executable_sha256: binding.expected_host_sha256.clone(),
            input_schema_sha256,
            output_schema_sha256,
            result_output_sha256: None,
            process_id,
            exit_code: exit_status
                .as_ref()
                .and_then(std::process::ExitStatus::code),
            stderr_present: !stderr.is_empty(),
            logical_tick: invocation.logical_sequence,
            status,
            record_sha256: empty_hash(),
        };
        let Some(exit_status) = exit_status else {
            self.records.push(record.seal()?);
            return Err(DesktopError::AdapterUnavailable(
                "module host timed out and was terminated".to_owned(),
            ));
        };
        if !exit_status.success() {
            self.records.push(record.seal()?);
            return Err(DesktopError::AdapterUnavailable(
                "module host exited without a valid result".to_owned(),
            ));
        }
        let result: ModuleResultEnvelope = match parse_json_strict(&stdout) {
            Ok(result) => result,
            Err(error) => {
                record.status = ModuleInvocationTerminalStatusV1::HostFailed;
                record.result_output_sha256 = Some(format!("sha256:{:x}", Sha256::digest(&stdout)));
                self.records.push(record.seal()?);
                return Err(module_error(error));
            }
        };
        if let Err(error) = validate_result_binding(invocation, &result) {
            record.status = ModuleInvocationTerminalStatusV1::HostFailed;
            record.result_output_sha256 = Some(result.output_hash.clone());
            self.records.push(record.seal()?);
            return Err(module_error(error));
        }
        if result.output_schema_id != binding.expected_output_schema_id {
            record.status = ModuleInvocationTerminalStatusV1::HostFailed;
            record.result_output_sha256 = Some(result.output_hash.clone());
            self.records.push(record.seal()?);
            return integrity("module result output schema differs from the pinned contract");
        }
        record.result_output_sha256 = Some(result.output_hash.clone());
        record.status = match result.status {
            d2i_module_sdk::ModuleResultStatus::Succeeded => {
                ModuleInvocationTerminalStatusV1::Succeeded
            }
            d2i_module_sdk::ModuleResultStatus::Unsupported => {
                ModuleInvocationTerminalStatusV1::ModuleUnsupported
            }
            d2i_module_sdk::ModuleResultStatus::Failed => {
                ModuleInvocationTerminalStatusV1::ModuleFailed
            }
        };
        self.records.push(record.seal()?);
        Ok(result)
    }

    /// Immutable invocation records accumulated by this coordinator.
    #[must_use]
    pub fn records(&self) -> &[ModuleInvocationRecordV1] {
        &self.records
    }
}

/// Ordered task runtime state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelTaskRuntimeStateV1 {
    Created,
    GoalCompiled,
    InitiallyObserved,
    PlanningReady,
    ActionCycleActive,
    ActionVerified,
    Advancing,
    Recovering,
    FinalVerification,
    Reported,
    Terminal,
}

/// Status of one stage in the task hash chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelTaskStageStatusV1 {
    Succeeded,
    Failed,
    Aborted,
}

/// One immutable transition in a Kernel task run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelTaskStageRecordV1 {
    pub schema_version: u32,
    pub stage_id: String,
    pub from_state: KernelTaskRuntimeStateV1,
    pub to_state: KernelTaskRuntimeStateV1,
    pub previous_stage_sha256: String,
    pub input_hashes: Vec<String>,
    pub output_hashes: Vec<String>,
    pub runtime_ids: Vec<String>,
    pub logical_tick: u64,
    pub status: KernelTaskStageStatusV1,
    pub evidence_ids: Vec<String>,
    pub stage_sha256: String,
}

impl KernelTaskStageRecordV1 {
    fn seal(mut self) -> Result<Self, DesktopError> {
        self.input_hashes.sort();
        self.output_hashes.sort();
        self.runtime_ids.sort();
        self.evidence_ids.sort();
        self.stage_sha256 = hash_without_field(&self, "stage_sha256")?;
        Ok(self)
    }

    /// Validates bounds and the stage self-hash.
    pub fn validate(&self) -> Result<(), DesktopError> {
        if self.schema_version != KERNEL_TASK_SCHEMA_VERSION || self.logical_tick == 0 {
            return invalid("kernel stage schema or logical tick is invalid");
        }
        validate_id(&self.stage_id, "stage_id")?;
        validate_hash(&self.previous_stage_sha256, "previous_stage_sha256")?;
        validate_sorted_hashes(&self.input_hashes, "stage input_hashes")?;
        validate_sorted_hashes(&self.output_hashes, "stage output_hashes")?;
        validate_sorted_ids(&self.runtime_ids, "stage runtime_ids", 32)?;
        validate_sorted_ids(&self.evidence_ids, "stage evidence_ids", MAX_EVIDENCE_IDS)?;
        validate_hash(&self.stage_sha256, "stage_sha256")?;
        if hash_without_field(self, "stage_sha256")? != self.stage_sha256 {
            return integrity("kernel stage record hash mismatch");
        }
        Ok(())
    }
}

/// Product-level state machine for one bounded KRN-500 task.
pub struct CognitiveKernelTaskRuntimeV1 {
    task_run_id: String,
    instruction_sha256: String,
    role_context_sha256: Option<String>,
    state: KernelTaskRuntimeStateV1,
    stages: Vec<KernelTaskStageRecordV1>,
    used_stage_ids: BTreeSet<String>,
    last_tick: u64,
}

impl CognitiveKernelTaskRuntimeV1 {
    /// Begins one task and records the authenticated input as the chain root.
    pub fn begin(
        task_run_id: String,
        instruction_sha256: String,
        logical_tick: u64,
    ) -> Result<Self, DesktopError> {
        Self::begin_internal(task_run_id, instruction_sha256, None, logical_tick)
    }

    /// Begins one task only after exact Role admission and projection verification.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_role_bound(
        task_run_id: String,
        instruction_sha256: String,
        goal_spec_sha256: &str,
        application_pack_sha256: &str,
        integration_id: &str,
        context: &RoleBoundKernelTaskContextV1,
        authority: &DelegatedAuthorityContextV1,
        recovery: &RecoveryPolicyProfileV1,
        role_ledger: &RoleInstanceLedgerVerificationV1,
        now_unix_seconds: u64,
        logical_tick: u64,
    ) -> Result<Self, DesktopError> {
        context.validate(now_unix_seconds).map_err(role_error)?;
        authority.validate().map_err(policy_error)?;
        recovery.validate().map_err(recovery_error)?;
        let instance = role_ledger.current_instance.as_ref().ok_or_else(|| {
            DesktopError::AccessDenied("Role ledger has no provisioned instance".to_owned())
        })?;
        if instance.current_status != RoleInstanceStatusV1::Active
            || now_unix_seconds >= instance.expires_at_unix_seconds
            || instance.role_instance_id != context.role_instance_id
            || instance.role_contract_id != context.role_contract_id
            || instance.role_version != context.role_version
            || instance.contract_sha256 != context.contract_sha256
            || instance.delegation_sha256 != context.delegation_sha256
            || context.authenticated_instruction_sha256 != instruction_sha256
            || context.goal_spec_sha256 != goal_spec_sha256
            || context.application_pack_sha256 != application_pack_sha256
            || context.integration_id != integration_id
            || context.authority_projection_sha256 != authority.authority_sha256
            || context.recovery_profile_projection_sha256 != recovery.profile_sha256
            || context.required_capability_ids != authority.allowed_capability_ids
            || authority.actor_id != context.role_instance_id
            || authority.role_id != context.role_contract_id
            || authority.allowed_application_pack_sha256 != context.application_pack_sha256
            || authority.allowed_integration_ids != vec![context.integration_id.clone()]
            || recovery.authority_sha256 != context.authority_projection_sha256
            || role_ledger
                .consumed_task_admission_hashes
                .binary_search(&context.role_task_admission_sha256)
                .is_err()
            || role_ledger
                .started_role_context_hashes
                .binary_search(&context.context_sha256)
                .is_err()
            || role_ledger
                .terminal_role_context_hashes
                .binary_search(&context.context_sha256)
                .is_ok()
        {
            return Err(DesktopError::AccessDenied(
                "Role-bound Kernel context differs from active ledger or projections".to_owned(),
            ));
        }
        Self::begin_internal(
            task_run_id,
            instruction_sha256,
            Some(context.context_sha256.clone()),
            logical_tick,
        )
    }

    fn begin_internal(
        task_run_id: String,
        instruction_sha256: String,
        role_context_sha256: Option<String>,
        logical_tick: u64,
    ) -> Result<Self, DesktopError> {
        validate_id(&task_run_id, "task_run_id")?;
        validate_hash(&instruction_sha256, "instruction_sha256")?;
        if let Some(hash) = &role_context_sha256 {
            validate_hash(hash, "role_context_sha256")?;
        }
        let mut input_hashes = vec![instruction_sha256.clone()];
        let mut evidence_ids = vec!["authenticated-instruction".to_owned()];
        if let Some(hash) = &role_context_sha256 {
            input_hashes.push(hash.clone());
            evidence_ids.push("role-task-admission".to_owned());
        }
        let mut runtime = Self {
            task_run_id,
            instruction_sha256: instruction_sha256.clone(),
            role_context_sha256,
            state: KernelTaskRuntimeStateV1::Created,
            stages: Vec::new(),
            used_stage_ids: BTreeSet::new(),
            last_tick: 0,
        };
        runtime.record(
            "created",
            KernelTaskRuntimeStateV1::Created,
            input_hashes,
            Vec::new(),
            vec![KERNEL_TASK_RUNTIME_BUILD_ID.to_owned()],
            logical_tick,
            KernelTaskStageStatusV1::Succeeded,
            evidence_ids,
        )?;
        Ok(runtime)
    }

    /// Records successful Goal Compiler completion.
    pub fn compile_goal(
        &mut self,
        invocation_sha256: String,
        goal_sha256: String,
        logical_tick: u64,
    ) -> Result<(), DesktopError> {
        self.transition(
            "goal-compiled",
            KernelTaskRuntimeStateV1::Created,
            KernelTaskRuntimeStateV1::GoalCompiled,
            vec![self.instruction_sha256.clone(), invocation_sha256],
            vec![goal_sha256],
            vec!["goal-compiler".to_owned()],
            logical_tick,
            vec!["module-contract-v1".to_owned()],
        )
    }

    /// Records the actual initial read-only observation.
    pub fn observe_initial(
        &mut self,
        goal_sha256: String,
        observation_sha256: String,
        logical_tick: u64,
    ) -> Result<(), DesktopError> {
        self.transition(
            "initially-observed",
            KernelTaskRuntimeStateV1::GoalCompiled,
            KernelTaskRuntimeStateV1::InitiallyObserved,
            vec![goal_sha256],
            vec![observation_sha256],
            vec!["windows-uia-observation-v1".to_owned()],
            logical_tick,
            vec!["read-only-worker-clean-exit".to_owned()],
        )
    }

    /// Records a validated deterministic DAG and its bound world state.
    pub fn prepare_plan(
        &mut self,
        observation_sha256: String,
        world_sha256: String,
        plan_sha256: String,
        logical_tick: u64,
    ) -> Result<(), DesktopError> {
        self.transition(
            "planning-ready",
            KernelTaskRuntimeStateV1::InitiallyObserved,
            KernelTaskRuntimeStateV1::PlanningReady,
            vec![observation_sha256],
            vec![world_sha256, plan_sha256],
            vec!["deterministic-plan-v1".to_owned()],
            logical_tick,
            vec!["validated-dag".to_owned()],
        )
    }

    /// Begins one fresh action cycle from planning, advancement, or recovery.
    pub fn execute_next_step(
        &mut self,
        stage_id: String,
        input_hashes: Vec<String>,
        logical_tick: u64,
    ) -> Result<(), DesktopError> {
        if !matches!(
            self.state,
            KernelTaskRuntimeStateV1::PlanningReady
                | KernelTaskRuntimeStateV1::Advancing
                | KernelTaskRuntimeStateV1::Recovering
        ) {
            return invalid("action cycle cannot begin from the current task state");
        }
        let from = self.state;
        self.record(
            &stage_id,
            KernelTaskRuntimeStateV1::ActionCycleActive,
            input_hashes,
            Vec::new(),
            vec!["safe-execution-kernel".to_owned()],
            logical_tick,
            KernelTaskStageStatusV1::Succeeded,
            vec!["fresh-action-cycle".to_owned()],
        )?;
        let last = self
            .stages
            .last_mut()
            .ok_or_else(|| DesktopError::Integrity("action stage record disappeared".to_owned()))?;
        last.from_state = from;
        last.stage_sha256 = hash_without_field(last, "stage_sha256")?;
        self.state = KernelTaskRuntimeStateV1::ActionCycleActive;
        Ok(())
    }

    /// Records one terminal independently verified action result.
    pub fn record_action_verified(
        &mut self,
        stage_id: String,
        input_hashes: Vec<String>,
        verified_result_sha256: String,
        logical_tick: u64,
    ) -> Result<(), DesktopError> {
        self.transition(
            &stage_id,
            KernelTaskRuntimeStateV1::ActionCycleActive,
            KernelTaskRuntimeStateV1::ActionVerified,
            input_hashes,
            vec![verified_result_sha256],
            vec!["cognitive-verifier-v2".to_owned()],
            logical_tick,
            vec!["fresh-read-only-verification".to_owned()],
        )
    }

    /// Advances after a passed action or a terminal non-mutating decision.
    pub fn advance(
        &mut self,
        stage_id: String,
        input_hashes: Vec<String>,
        logical_tick: u64,
    ) -> Result<(), DesktopError> {
        self.transition(
            &stage_id,
            KernelTaskRuntimeStateV1::ActionVerified,
            KernelTaskRuntimeStateV1::Advancing,
            input_hashes,
            Vec::new(),
            vec![KERNEL_TASK_RUNTIME_BUILD_ID.to_owned()],
            logical_tick,
            vec!["verified-action-consumed".to_owned()],
        )
    }

    /// Enters bounded KRN-400 recovery from a verified non-passing action.
    pub fn recover(
        &mut self,
        trigger_sha256: String,
        decision_sha256: String,
        logical_tick: u64,
    ) -> Result<(), DesktopError> {
        self.transition(
            "recovering",
            KernelTaskRuntimeStateV1::ActionVerified,
            KernelTaskRuntimeStateV1::Recovering,
            vec![trigger_sha256],
            vec![decision_sha256],
            vec!["cognitive-recovery-control-v1".to_owned()],
            logical_tick,
            vec!["bounded-recovery".to_owned()],
        )
    }

    /// Records a terminal recovery result that performs no further mutation.
    pub fn complete_recovery(
        &mut self,
        recovery_result_sha256: String,
        logical_tick: u64,
    ) -> Result<(), DesktopError> {
        self.transition(
            "recovery-complete",
            KernelTaskRuntimeStateV1::Recovering,
            KernelTaskRuntimeStateV1::Advancing,
            vec![recovery_result_sha256],
            Vec::new(),
            vec!["cognitive-recovery-control-v1".to_owned()],
            logical_tick,
            vec!["non-mutating-recovery-terminal".to_owned()],
        )
    }

    /// Records the separate final stability observation and goal verdict.
    pub fn verify_final_goal(
        &mut self,
        input_hashes: Vec<String>,
        final_verification_sha256: String,
        logical_tick: u64,
    ) -> Result<(), DesktopError> {
        if !matches!(
            self.state,
            KernelTaskRuntimeStateV1::Advancing | KernelTaskRuntimeStateV1::PlanningReady
        ) {
            return invalid("final verification cannot begin from the current task state");
        }
        let from = self.state;
        self.record(
            "final-verification",
            KernelTaskRuntimeStateV1::FinalVerification,
            input_hashes,
            vec![final_verification_sha256],
            vec!["final-goal-verifier-v1".to_owned()],
            logical_tick,
            KernelTaskStageStatusV1::Succeeded,
            vec!["terminal-stability-observation".to_owned()],
        )?;
        let last = self.stages.last_mut().ok_or_else(|| {
            DesktopError::Integrity("final verification stage disappeared".to_owned())
        })?;
        last.from_state = from;
        last.stage_sha256 = hash_without_field(last, "stage_sha256")?;
        self.state = KernelTaskRuntimeStateV1::FinalVerification;
        Ok(())
    }

    /// Binds a WorkReport to the final verification.
    pub fn build_work_report(
        &mut self,
        final_verification_sha256: String,
        work_report_sha256: String,
        logical_tick: u64,
    ) -> Result<(), DesktopError> {
        self.transition(
            "reported",
            KernelTaskRuntimeStateV1::FinalVerification,
            KernelTaskRuntimeStateV1::Reported,
            vec![final_verification_sha256],
            vec![work_report_sha256],
            vec!["cognitive-ir-v1-work-report".to_owned()],
            logical_tick,
            vec!["verified-report-binding".to_owned()],
        )
    }

    /// Terminates a reported task and returns its stage chain.
    pub fn finalize(
        &mut self,
        work_report_sha256: String,
        logical_tick: u64,
    ) -> Result<Vec<KernelTaskStageRecordV1>, DesktopError> {
        self.transition(
            "terminal",
            KernelTaskRuntimeStateV1::Reported,
            KernelTaskRuntimeStateV1::Terminal,
            vec![work_report_sha256],
            Vec::new(),
            vec![KERNEL_TASK_RUNTIME_BUILD_ID.to_owned()],
            logical_tick,
            vec!["task-terminal".to_owned()],
        )?;
        Ok(self.stages.clone())
    }

    /// Fails closed from any nonterminal state without producing completion evidence.
    pub fn abort(
        &mut self,
        failure_sha256: String,
        logical_tick: u64,
    ) -> Result<Vec<KernelTaskStageRecordV1>, DesktopError> {
        if self.state == KernelTaskRuntimeStateV1::Terminal {
            return invalid("terminal task cannot be aborted twice");
        }
        validate_hash(&failure_sha256, "abort failure_sha256")?;
        let from = self.state;
        self.record(
            "aborted",
            KernelTaskRuntimeStateV1::Terminal,
            vec![failure_sha256],
            Vec::new(),
            vec![KERNEL_TASK_RUNTIME_BUILD_ID.to_owned()],
            logical_tick,
            KernelTaskStageStatusV1::Aborted,
            vec!["fail-closed".to_owned()],
        )?;
        let last = self
            .stages
            .last_mut()
            .ok_or_else(|| DesktopError::Integrity("abort stage disappeared".to_owned()))?;
        last.from_state = from;
        last.stage_sha256 = hash_without_field(last, "stage_sha256")?;
        self.state = KernelTaskRuntimeStateV1::Terminal;
        Ok(self.stages.clone())
    }

    /// Current runtime state.
    #[must_use]
    pub const fn state(&self) -> KernelTaskRuntimeStateV1 {
        self.state
    }

    /// Task run identifier.
    #[must_use]
    pub fn task_run_id(&self) -> &str {
        &self.task_run_id
    }

    /// Role task context bound to this run, when Role governance was required.
    #[must_use]
    pub fn role_context_sha256(&self) -> Option<&str> {
        self.role_context_sha256.as_deref()
    }

    /// Current immutable stage records.
    #[must_use]
    pub fn stages(&self) -> &[KernelTaskStageRecordV1] {
        &self.stages
    }

    #[allow(clippy::too_many_arguments)]
    fn transition(
        &mut self,
        stage_id: &str,
        expected: KernelTaskRuntimeStateV1,
        next: KernelTaskRuntimeStateV1,
        input_hashes: Vec<String>,
        output_hashes: Vec<String>,
        runtime_ids: Vec<String>,
        logical_tick: u64,
        evidence_ids: Vec<String>,
    ) -> Result<(), DesktopError> {
        if self.state != expected {
            return invalid("kernel task stage order violation");
        }
        self.record(
            stage_id,
            next,
            input_hashes,
            output_hashes,
            runtime_ids,
            logical_tick,
            KernelTaskStageStatusV1::Succeeded,
            evidence_ids,
        )?;
        self.state = next;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn record(
        &mut self,
        stage_id: &str,
        to_state: KernelTaskRuntimeStateV1,
        input_hashes: Vec<String>,
        output_hashes: Vec<String>,
        runtime_ids: Vec<String>,
        logical_tick: u64,
        status: KernelTaskStageStatusV1,
        evidence_ids: Vec<String>,
    ) -> Result<(), DesktopError> {
        if self.stages.len() >= MAX_STAGE_RECORDS
            || logical_tick <= self.last_tick
            || !self.used_stage_ids.insert(stage_id.to_owned())
        {
            return invalid("kernel stage is duplicate, out of order, or over the record bound");
        }
        let previous_stage_sha256 = self
            .stages
            .last()
            .map_or_else(empty_hash, |record| record.stage_sha256.clone());
        let record = KernelTaskStageRecordV1 {
            schema_version: KERNEL_TASK_SCHEMA_VERSION,
            stage_id: stage_id.to_owned(),
            from_state: self.state,
            to_state,
            previous_stage_sha256,
            input_hashes,
            output_hashes,
            runtime_ids,
            logical_tick,
            status,
            evidence_ids,
            stage_sha256: empty_hash(),
        }
        .seal()?;
        record.validate()?;
        self.last_tick = logical_tick;
        self.stages.push(record);
        Ok(())
    }
}

/// One complete attempt from grounding through independent verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionCycleRecordV1 {
    pub schema_version: u32,
    pub cycle_id: String,
    pub step_id: String,
    pub source_observation_sha256: String,
    pub grounder_result_sha256: String,
    pub candidate_set_sha256: String,
    pub ranker_result_sha256: String,
    pub selected_action_sha256: String,
    pub policy_decision_sha256: String,
    pub cognitive_admission_sha256: String,
    pub windows_activation_record_sha256: String,
    pub execution_receipt_sha256: String,
    pub verified_action_result_sha256: String,
    pub verification_verdict: FinalVerificationVerdictV1,
    pub completed: bool,
    pub evidence_ids: Vec<String>,
    pub cycle_sha256: String,
}

impl ActionCycleRecordV1 {
    /// Seals and validates one action cycle.
    pub fn seal(mut self) -> Result<Self, DesktopError> {
        self.evidence_ids.sort();
        self.cycle_sha256 = hash_without_field(&self, "cycle_sha256")?;
        self.validate()?;
        Ok(self)
    }

    /// Validates all artifact bindings and the cycle self-hash.
    pub fn validate(&self) -> Result<(), DesktopError> {
        if self.schema_version != KERNEL_TASK_SCHEMA_VERSION {
            return invalid("action cycle schema_version must be 1");
        }
        validate_id(&self.cycle_id, "cycle_id")?;
        validate_id(&self.step_id, "step_id")?;
        for hash in [
            &self.source_observation_sha256,
            &self.grounder_result_sha256,
            &self.candidate_set_sha256,
            &self.ranker_result_sha256,
            &self.selected_action_sha256,
            &self.policy_decision_sha256,
            &self.cognitive_admission_sha256,
            &self.windows_activation_record_sha256,
            &self.execution_receipt_sha256,
            &self.verified_action_result_sha256,
            &self.cycle_sha256,
        ] {
            validate_hash(hash, "action cycle hash")?;
        }
        validate_sorted_ids(&self.evidence_ids, "cycle evidence_ids", MAX_EVIDENCE_IDS)?;
        if self.completed != (self.verification_verdict == FinalVerificationVerdictV1::Passed) {
            return integrity("action cycle completion differs from verification verdict");
        }
        if hash_without_field(self, "cycle_sha256")? != self.cycle_sha256 {
            return integrity("action cycle hash mismatch");
        }
        Ok(())
    }
}

/// Closed final criterion or protected-invariant result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalCriterionResultV1 {
    pub criterion_id: String,
    pub passed: bool,
    pub observed_value_sha256: String,
    pub reason_code: String,
    pub evidence_ids: Vec<String>,
}

impl FinalCriterionResultV1 {
    fn validate(&self) -> Result<(), DesktopError> {
        validate_id(&self.criterion_id, "final criterion_id")?;
        validate_hash(&self.observed_value_sha256, "final observed_value_sha256")?;
        validate_id(&self.reason_code, "final reason_code")?;
        validate_sorted_ids(
            &self.evidence_ids,
            "final criterion evidence",
            MAX_EVIDENCE_IDS,
        )
    }
}

/// Closed terminal verdict used by action and final task records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalVerificationVerdictV1 {
    Passed,
    Failed,
    Unsafe,
    ClarificationRequired,
}

/// Independent terminal stability proof for one GoalSpec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalGoalVerificationV1 {
    pub schema_version: u32,
    pub goal_id: String,
    pub final_plan_generation_id: String,
    pub final_observation_id: String,
    pub final_observation_sha256: String,
    pub final_observation_sequence: u64,
    pub required_goal_criteria: Vec<FinalCriterionResultV1>,
    pub protected_invariant_results: Vec<FinalCriterionResultV1>,
    pub completed_action_result_hashes: Vec<String>,
    pub recovery_result_hashes: Vec<String>,
    pub verdict: FinalVerificationVerdictV1,
    pub goal_progress: GoalProgress,
    pub evidence_ids: Vec<String>,
    pub final_verification_sha256: String,
}

impl FinalGoalVerificationV1 {
    /// Seals a bounded final verification after normalizing unordered sets.
    pub fn seal(mut self) -> Result<Self, DesktopError> {
        self.completed_action_result_hashes.sort();
        self.recovery_result_hashes.sort();
        self.evidence_ids.sort();
        for result in &mut self.required_goal_criteria {
            result.evidence_ids.sort();
        }
        for result in &mut self.protected_invariant_results {
            result.evidence_ids.sort();
        }
        self.final_verification_sha256 = hash_without_field(&self, "final_verification_sha256")?;
        self.validate()?;
        Ok(self)
    }

    /// Validates final completion semantics and the self-hash.
    pub fn validate(&self) -> Result<(), DesktopError> {
        if self.schema_version != KERNEL_TASK_SCHEMA_VERSION || self.final_observation_sequence == 0
        {
            return invalid("final goal verification schema or sequence is invalid");
        }
        validate_id(&self.goal_id, "final goal_id")?;
        validate_id(&self.final_plan_generation_id, "final plan_generation_id")?;
        validate_id(&self.final_observation_id, "final observation_id")?;
        validate_hash(&self.final_observation_sha256, "final observation_sha256")?;
        if self.required_goal_criteria.is_empty() || self.protected_invariant_results.is_empty() {
            return invalid("final verification requires goal and protected results");
        }
        for result in self
            .required_goal_criteria
            .iter()
            .chain(&self.protected_invariant_results)
        {
            result.validate()?;
        }
        validate_sorted_hashes(
            &self.completed_action_result_hashes,
            "completed action result hashes",
        )?;
        validate_sorted_hashes(&self.recovery_result_hashes, "recovery result hashes")?;
        validate_sorted_ids(&self.evidence_ids, "final evidence_ids", MAX_EVIDENCE_IDS)?;
        let all_passed = self
            .required_goal_criteria
            .iter()
            .chain(&self.protected_invariant_results)
            .all(|result| result.passed);
        if (self.verdict == FinalVerificationVerdictV1::Passed)
            != (all_passed && self.goal_progress == GoalProgress::Complete)
        {
            return integrity("final Passed verdict does not match all criteria and Goal Complete");
        }
        validate_hash(&self.final_verification_sha256, "final_verification_sha256")?;
        if hash_without_field(self, "final_verification_sha256")? != self.final_verification_sha256
        {
            return integrity("final goal verification hash mismatch");
        }
        Ok(())
    }
}

/// Task-level terminal outcome. It is not a Case or Role status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelFinalOutcomeV1 {
    Completed,
    ClarificationRequired,
    Escalated,
    Stopped,
    Failed,
    InfrastructureError,
}

/// Immutable audit-safe record for one complete Kernel task run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelTaskRunRecordV1 {
    pub schema_version: u32,
    pub task_run_id: String,
    pub authenticated_instruction_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_context_sha256: Option<String>,
    pub goal_compiler_invocation_sha256: String,
    pub goal_spec_sha256: String,
    pub application_pack_sha256: String,
    pub initial_observation_sha256: String,
    pub plan_sha256: String,
    pub stage_records: Vec<KernelTaskStageRecordV1>,
    pub action_cycle_records: Vec<ActionCycleRecordV1>,
    pub module_invocation_records: Vec<ModuleInvocationRecordV1>,
    pub policy_decision_hashes: Vec<String>,
    pub activation_admission_hashes: Vec<String>,
    pub windows_activation_record_hashes: Vec<String>,
    pub execution_receipt_hashes: Vec<String>,
    pub verified_action_result_hashes: Vec<String>,
    pub recovery_trigger_hashes: Vec<String>,
    pub recovery_decision_hashes: Vec<String>,
    pub recovery_result_hashes: Vec<String>,
    pub final_goal_verification_sha256: String,
    pub final_outcome: KernelFinalOutcomeV1,
    pub work_report_sha256: String,
    pub audit_chain_head: String,
    pub started_at_unix_ms: u64,
    pub completed_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub run_record_sha256: String,
}

impl KernelTaskRunRecordV1 {
    /// Normalizes hash sets, seals the record, and validates every nested artifact.
    pub fn seal(mut self, report: &WorkReport) -> Result<Self, DesktopError> {
        for values in [
            &mut self.policy_decision_hashes,
            &mut self.activation_admission_hashes,
            &mut self.windows_activation_record_hashes,
            &mut self.execution_receipt_hashes,
            &mut self.verified_action_result_hashes,
            &mut self.recovery_trigger_hashes,
            &mut self.recovery_decision_hashes,
            &mut self.recovery_result_hashes,
        ] {
            values.sort();
        }
        self.evidence_ids.sort();
        self.run_record_sha256 = hash_without_field(&self, "run_record_sha256")?;
        self.validate(report)?;
        Ok(self)
    }

    /// Validates chain continuity, report binding, outcome semantics, and self-hash.
    pub fn validate(&self, report: &WorkReport) -> Result<(), DesktopError> {
        if self.schema_version != KERNEL_TASK_SCHEMA_VERSION
            || self.stage_records.is_empty()
            || self.stage_records.len() > MAX_STAGE_RECORDS
            || self.action_cycle_records.len() > MAX_ACTION_CYCLES
            || self.module_invocation_records.len() > MAX_MODULE_RECORDS
            || self.started_at_unix_ms == 0
            || self.completed_at_unix_ms < self.started_at_unix_ms
        {
            return invalid("kernel task run record bounds or lifetime are invalid");
        }
        validate_id(&self.task_run_id, "task_run_id")?;
        for hash in [
            &self.authenticated_instruction_sha256,
            &self.goal_compiler_invocation_sha256,
            &self.goal_spec_sha256,
            &self.application_pack_sha256,
            &self.initial_observation_sha256,
            &self.plan_sha256,
            &self.final_goal_verification_sha256,
            &self.work_report_sha256,
            &self.audit_chain_head,
            &self.run_record_sha256,
        ] {
            validate_hash(hash, "kernel run hash")?;
        }
        if let Some(hash) = &self.role_context_sha256 {
            validate_hash(hash, "kernel run role_context_sha256")?;
            if self
                .stage_records
                .first()
                .is_none_or(|stage| !stage.input_hashes.contains(hash))
            {
                return integrity("role-bound Kernel run root omits its Role context");
            }
        }
        let mut previous = empty_hash();
        let mut tick = 0;
        for stage in &self.stage_records {
            stage.validate()?;
            if stage.previous_stage_sha256 != previous || stage.logical_tick <= tick {
                return integrity("kernel stage chain continuity is invalid");
            }
            previous = stage.stage_sha256.clone();
            tick = stage.logical_tick;
        }
        for cycle in &self.action_cycle_records {
            cycle.validate()?;
        }
        for record in &self.module_invocation_records {
            record.validate()?;
        }
        for values in [
            &self.policy_decision_hashes,
            &self.activation_admission_hashes,
            &self.windows_activation_record_hashes,
            &self.execution_receipt_hashes,
            &self.verified_action_result_hashes,
            &self.recovery_trigger_hashes,
            &self.recovery_decision_hashes,
            &self.recovery_result_hashes,
        ] {
            validate_sorted_hashes(values, "kernel run hash set")?;
        }
        validate_sorted_ids(
            &self.evidence_ids,
            "kernel run evidence_ids",
            MAX_EVIDENCE_IDS,
        )?;
        report.validate()?;
        if canonical_sha256(report).map_err(module_error)? != self.work_report_sha256 {
            return integrity("WorkReport hash differs from KernelTaskRunRecord");
        }
        if self.final_outcome == KernelFinalOutcomeV1::Completed
            && (report.user_decision_required || !report.incomplete_items.is_empty())
        {
            return integrity("completed task record contains unverified or incomplete work");
        }
        let serialized = String::from_utf8(canonical_json_bytes(self).map_err(module_error)?)
            .map_err(|error| DesktopError::Json(error.to_string()))?;
        for forbidden in [
            "automation_id",
            "locator",
            "selector",
            "raw_payload",
            "credential",
            "password",
            "private_key",
        ] {
            if serialized.to_ascii_lowercase().contains(forbidden) {
                return integrity("KernelTaskRunRecord contains forbidden sensitive material");
            }
        }
        if hash_without_field(self, "run_record_sha256")? != self.run_record_sha256 {
            return integrity("KernelTaskRunRecord self-hash mismatch");
        }
        Ok(())
    }
}

fn expected_module_contract(
    module_id: &str,
) -> Option<(
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
)> {
    match module_id {
        "goal-compiler" => Some((
            "1.0.0",
            "cognitive.goal-compile",
            "1.0.0",
            "goal-compilation-input-v1",
            "goal-compilation-result-v1",
        )),
        "element-grounder" => Some((
            "1.0.0",
            "cognitive.element-ground",
            "1.0.0",
            "element-grounding-input-v1",
            "element-grounding-result-v1",
        )),
        "plan-ranker" => Some((
            "1.0.0",
            "cognitive.plan-rank",
            "1.0.0",
            "cognitive-plan-ranking-input-v1",
            "cognitive-plan-ranking-output-v1",
        )),
        _ => None,
    }
}

fn role_error(error: d2i_role_contract::RoleContractError) -> DesktopError {
    DesktopError::Integrity(error.to_string())
}

fn policy_error(error: d2i_policy_admission::PolicyAdmissionError) -> DesktopError {
    DesktopError::Integrity(error.to_string())
}

fn recovery_error(error: d2i_cognitive_recovery::RecoveryError) -> DesktopError {
    DesktopError::Integrity(error.to_string())
}

fn schema_hash(loaded: &LoadedModuleManifest, schema_id: &str) -> Result<String, DesktopError> {
    loaded
        .manifest
        .schemas
        .iter()
        .find(|schema| schema.schema_id == schema_id)
        .map(|schema| schema.sha256.clone())
        .ok_or_else(|| DesktopError::Integrity("pinned schema is absent".to_owned()))
}

fn read_pipe_bounded<R: Read>(reader: R, maximum: usize) -> Result<Vec<u8>, String> {
    let limit = u64::try_from(maximum.saturating_add(1)).map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    reader
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > maximum {
        return Err("module host pipe exceeded its byte bound".to_owned());
    }
    Ok(bytes)
}

fn join_reader(
    handle: thread::JoinHandle<Result<Vec<u8>, String>>,
) -> Result<Vec<u8>, DesktopError> {
    handle
        .join()
        .map_err(|_| DesktopError::AdapterUnavailable("module pipe reader panicked".to_owned()))?
        .map_err(DesktopError::AdapterUnavailable)
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, DesktopError> {
    let canonical = fs::canonicalize(path).map_err(|error| DesktopError::Io {
        path: label.to_owned(),
        message: error.to_string(),
    })?;
    if !canonical.is_dir() {
        return invalid(format!("{label} is not a directory"));
    }
    Ok(canonical)
}

fn canonical_file(path: &Path, label: &str) -> Result<PathBuf, DesktopError> {
    let canonical = fs::canonicalize(path).map_err(|error| DesktopError::Io {
        path: label.to_owned(),
        message: error.to_string(),
    })?;
    let metadata = fs::symlink_metadata(&canonical).map_err(|error| DesktopError::Io {
        path: label.to_owned(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return invalid(format!("{label} is not a regular file"));
    }
    Ok(canonical)
}

fn sha256_regular_file(path: &Path, maximum: u64) -> Result<String, DesktopError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| DesktopError::Io {
        path: "module-host".to_owned(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return invalid("module host must be a bounded regular file");
    }
    let bytes = fs::read(path).map_err(|error| DesktopError::Io {
        path: "module-host".to_owned(),
        message: error.to_string(),
    })?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn hash_without_field<T: Serialize>(value: &T, field: &str) -> Result<String, DesktopError> {
    let mut value =
        serde_json::to_value(value).map_err(|error| DesktopError::Json(error.to_string()))?;
    value
        .as_object_mut()
        .ok_or_else(|| DesktopError::Json("hash target is not an object".to_owned()))?
        .remove(field);
    canonical_sha256(&value).map_err(module_error)
}

fn validate_id(value: &str, field: &str) -> Result<(), DesktopError> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return invalid(format!("{field} is not a bounded identifier"));
    }
    Ok(())
}

fn validate_text(value: &str, field: &str, maximum: usize) -> Result<(), DesktopError> {
    if value.is_empty() || value.len() > maximum || value.contains('\0') {
        return invalid(format!("{field} is empty, contains NUL, or exceeds bounds"));
    }
    Ok(())
}

fn validate_hash(value: &str, field: &str) -> Result<(), DesktopError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return invalid(format!("{field} must use sha256:<lowercase-hex>"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return invalid(format!("{field} has invalid SHA-256 syntax"));
    }
    Ok(())
}

fn validate_sorted_ids(values: &[String], field: &str, maximum: usize) -> Result<(), DesktopError> {
    if values.is_empty() || values.len() > maximum {
        return invalid(format!("{field} must contain 1..={maximum} values"));
    }
    let mut previous: Option<&str> = None;
    for value in values {
        validate_id(value, field)?;
        if previous.is_some_and(|item| item >= value.as_str()) {
            return invalid(format!("{field} must be sorted and unique"));
        }
        previous = Some(value);
    }
    Ok(())
}

fn validate_sorted_hashes(values: &[String], field: &str) -> Result<(), DesktopError> {
    if values.len() > MAX_HASHES {
        return invalid(format!("{field} exceeds its collection bound"));
    }
    let mut previous: Option<&str> = None;
    for value in values {
        validate_hash(value, field)?;
        if previous.is_some_and(|item| item >= value.as_str()) {
            return invalid(format!("{field} must be sorted and unique"));
        }
        previous = Some(value);
    }
    Ok(())
}

fn reject_sensitive_text(value: &str, field: &str) -> Result<(), DesktopError> {
    let lower = value.to_ascii_lowercase();
    if [
        "password=",
        "password:",
        "token=",
        "token:",
        "secret=",
        "api_key=",
        "authorization:",
        "bearer ",
        "cookie:",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
    {
        return integrity(format!("{field} contains secret-like material"));
    }
    Ok(())
}

fn reject_sensitive_value(value: &Value, field: &str) -> Result<(), DesktopError> {
    let text =
        serde_json::to_string(value).map_err(|error| DesktopError::Json(error.to_string()))?;
    reject_sensitive_text(&text, field)
}

fn module_error(error: d2i_module_sdk::ModuleError) -> DesktopError {
    DesktopError::Integrity(error.to_string())
}

fn empty_hash() -> String {
    format!("sha256:{:x}", Sha256::digest([]))
}

fn invalid<T>(message: impl Into<String>) -> Result<T, DesktopError> {
    Err(DesktopError::Invalid(message.into()))
}

fn integrity<T>(message: impl Into<String>) -> Result<T, DesktopError> {
    Err(DesktopError::Integrity(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2i_cognitive_ir::{ComparisonOp, Postcondition};
    use d2i_module_sdk::{ModuleProvenance, ReplayContext, ResourceBudget, CONTRACT_VERSION_V1};
    use serde_json::json;

    fn digest(value: &str) -> String {
        canonical_sha256(&value).unwrap_or_else(|error| panic!("hash failed: {error}"))
    }

    fn instruction(now: u64) -> AuthenticatedTaskInstructionV1 {
        AuthenticatedTaskInstructionV1 {
            schema_version: 1,
            instruction_id: "instruction-1".to_owned(),
            locale: "ko-KR".to_owned(),
            source_id: "authenticated-cli".to_owned(),
            authenticated_actor_id: "actor-1".to_owned(),
            authenticated_role_id: "task-operator".to_owned(),
            organization_id: "organization-1".to_owned(),
            instruction_text: "목표: 로컬 테스트 값을 저장".to_owned(),
            structured_success_criteria: vec![Postcondition {
                target_state: "saved.name".to_owned(),
                op: ComparisonOp::Equals,
                expected_value: json!("D2I-E2E-VERIFIED-NAME"),
                required: true,
                timeout_ms: 5_000,
            }],
            issued_at_unix_ms: now,
            expires_at_unix_ms: now + 60_000,
            provenance: Provenance {
                source: "authenticated local test instruction".to_owned(),
                source_hash: digest("instruction-source"),
                module_id: "authenticated-user-instruction".to_owned(),
            },
            evidence_ids: vec!["authenticated-session".to_owned()],
            instruction_sha256: empty_hash(),
        }
        .seal()
        .unwrap_or_else(|error| panic!("instruction seal failed: {error}"))
    }

    #[cfg(windows)]
    fn test_module_binding(module_id: &str, host: &Path) -> ModuleHostBindingV1 {
        let (capability, input_schema, output_schema) = match module_id {
            "goal-compiler" => (
                "cognitive.goal-compile",
                "goal-compilation-input-v1",
                "goal-compilation-result-v1",
            ),
            "element-grounder" => (
                "cognitive.element-ground",
                "element-grounding-input-v1",
                "element-grounding-result-v1",
            ),
            "plan-ranker" => (
                "cognitive.plan-rank",
                "cognitive-plan-ranking-input-v1",
                "cognitive-plan-ranking-output-v1",
            ),
            _ => panic!("unsupported test module"),
        };
        let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        ModuleHostBindingV1 {
            module_root: repository.join("modules").join(module_id),
            host_executable: host.to_owned(),
            expected_host_sha256: sha256_regular_file(host, MAX_HOST_EXECUTABLE_BYTES)
                .unwrap_or_else(|error| panic!("host hash failed: {error}")),
            expected_module_id: module_id.to_owned(),
            expected_module_version: "1.0.0".to_owned(),
            expected_capability_id: capability.to_owned(),
            expected_capability_version: "1.0.0".to_owned(),
            expected_input_schema_id: input_schema.to_owned(),
            expected_output_schema_id: output_schema.to_owned(),
        }
    }

    #[cfg(windows)]
    fn test_goal_invocation(module_root: &Path) -> ModuleInvocationEnvelope {
        let loaded = load_module_manifest(module_root)
            .unwrap_or_else(|error| panic!("load test manifest failed: {error}"));
        let fixture_hash = digest("malformed-host-fixture");
        let invocation = ModuleInvocationEnvelope {
            contract_version: CONTRACT_VERSION_V1,
            invocation_id: "malformed-host-invocation".to_owned(),
            module: loaded.identifier,
            requested_capability: "cognitive.goal-compile".to_owned(),
            input_schema_id: "goal-compilation-input-v1".to_owned(),
            input_schema_version: 1,
            payload: json!({"fixture": "malformed-host-output"}),
            goal_id: "goal-malformed-host".to_owned(),
            source_observation_hash: None,
            plan_generation_id: None,
            logical_sequence: 1,
            deadline_logical_tick: 2,
            resource_budget: ResourceBudget {
                max_input_bytes: loaded.manifest.execution.maximum_input_bytes,
                max_output_bytes: loaded.manifest.execution.maximum_output_bytes,
                memory_bytes: loaded.manifest.execution.memory_limit_bytes,
                logical_operation_budget: loaded.manifest.execution.logical_operation_budget,
            },
            trust_labels: BTreeSet::from(["fixture".to_owned()]),
            redactions: Vec::new(),
            provenance: ModuleProvenance {
                source_id: "kernel-coordinator-test".to_owned(),
                source_sha256: fixture_hash.clone(),
                producer: KERNEL_TASK_RUNTIME_BUILD_ID.to_owned(),
            },
            replay: ReplayContext {
                replay_id: "replay-malformed-host".to_owned(),
                seed: 500,
                fixture_hash,
            },
            correlation_id: "correlation-malformed-host".to_owned(),
            trace_id: "trace-malformed-host".to_owned(),
        };
        invocation
            .validate()
            .unwrap_or_else(|error| panic!("test invocation invalid: {error}"));
        invocation
    }

    #[test]
    fn authenticated_instruction_is_strict_ttl_bound_and_tamper_evident() {
        let value = instruction(1_000);
        assert!(value.validate(1_001).is_ok());
        assert!(value.validate(61_000).is_err());
        let bytes = serde_json::to_vec(&value)
            .unwrap_or_else(|error| panic!("serialize instruction failed: {error}"));
        assert_eq!(
            parse_authenticated_task_instruction_v1(&bytes, 1_001)
                .unwrap_or_else(|error| panic!("parse instruction failed: {error}")),
            value
        );
        assert!(parse_authenticated_task_instruction_v1(
            br#"{"schema_version":1,"schema_version":1}"#,
            1_001
        )
        .is_err());
        let mut tampered = value;
        tampered.organization_id = "organization-2".to_owned();
        assert!(tampered.validate(1_001).is_err());
    }

    #[test]
    fn task_runtime_rejects_skip_duplicate_and_nonmonotonic_stages() {
        let mut runtime =
            CognitiveKernelTaskRuntimeV1::begin("task-run-1".to_owned(), digest("instruction"), 1)
                .unwrap_or_else(|error| panic!("begin failed: {error}"));
        assert!(runtime
            .observe_initial(digest("goal"), digest("observation"), 2)
            .is_err());
        runtime
            .compile_goal(digest("invocation"), digest("goal"), 2)
            .unwrap_or_else(|error| panic!("compile stage failed: {error}"));
        assert!(runtime
            .compile_goal(digest("invocation"), digest("goal"), 3)
            .is_err());
        assert!(runtime
            .observe_initial(digest("goal"), digest("observation"), 2)
            .is_err());
    }

    #[test]
    fn final_verification_cannot_claim_false_completion() {
        let result = FinalCriterionResultV1 {
            criterion_id: "saved-name".to_owned(),
            passed: false,
            observed_value_sha256: digest("wrong"),
            reason_code: "value-mismatch".to_owned(),
            evidence_ids: vec!["final-observation".to_owned()],
        };
        let value = FinalGoalVerificationV1 {
            schema_version: 1,
            goal_id: "goal-1".to_owned(),
            final_plan_generation_id: "plan-1".to_owned(),
            final_observation_id: "observation-final".to_owned(),
            final_observation_sha256: digest("observation"),
            final_observation_sequence: 5,
            required_goal_criteria: vec![result.clone()],
            protected_invariant_results: vec![result],
            completed_action_result_hashes: vec![digest("action")],
            recovery_result_hashes: Vec::new(),
            verdict: FinalVerificationVerdictV1::Passed,
            goal_progress: GoalProgress::Complete,
            evidence_ids: vec!["terminal-stability".to_owned()],
            final_verification_sha256: empty_hash(),
        };
        assert!(value.seal().is_err());
    }

    #[test]
    fn strict_parser_helper_rejects_duplicate_keys() {
        let parsed: Result<Value, _> = parse_json_strict(br#"{"a":1,"a":2}"#);
        assert!(parsed.is_err());
    }

    #[cfg(windows)]
    #[test]
    fn module_coordinator_rejects_wrong_hash_and_records_malformed_stdout() {
        let system_root = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        let sort = system_root.join("System32/sort.exe");
        let mut wrong_hash = test_module_binding("goal-compiler", &sort);
        wrong_hash.expected_host_sha256 = digest("wrong-host");
        assert!(wrong_hash.validate().is_err());

        let bindings = ["goal-compiler", "element-grounder", "plan-ranker"]
            .iter()
            .map(|module_id| test_module_binding(module_id, &sort))
            .collect::<Vec<_>>();
        let goal_root = bindings[0].module_root.clone();
        let mut coordinator = ModuleInvocationCoordinatorV1::new(bindings, Duration::from_secs(2))
            .unwrap_or_else(|error| panic!("coordinator setup failed: {error}"));
        assert!(coordinator
            .invoke(&test_goal_invocation(&goal_root))
            .is_err());
        assert_eq!(coordinator.records().len(), 1);
        assert_eq!(
            coordinator.records()[0].status,
            ModuleInvocationTerminalStatusV1::HostFailed
        );
        assert!(coordinator.records()[0].result_output_sha256.is_some());
    }
}
