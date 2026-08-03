#![cfg_attr(not(windows), allow(dead_code, unused_imports))]

use d2i_action_candidates::{ActionCapabilityBinding, CandidateActionInput, CandidateActionKind};
use d2i_action_selection::{
    bind_selected_action, build_grounded_action_candidates, build_grounded_action_proposal,
    build_plan_ranker_input_bridge, build_policy_ready_action, canonical_sha256,
    parse_element_grounding_result_strict, parse_plan_ranking_output_strict,
    validate_element_grounding_result, validate_plan_ranking_output, ActionCandidateBuildOutcomeV1,
    ActionSelectionContextV1, CandidateAdmissionProfileV1, CandidateGateEvidenceV1,
    CandidateGateResultsV1, CandidateGenerationSpecV1, CandidateRankingProfileV1,
    ElementGroundingResultV1, GateStatusV1, GroundedActionProposalSpecV1, GroundingStatusV1,
    PlanRankingOutputV1, PolicyReadyActionV1, ValidatedGroundingSelectionV1,
};
use d2i_application_semantics::{
    build_element_grounder_payload, ApplicationPack, ElementGrounderBridgeRequest,
};
use d2i_cognitive_ir::{
    CapabilityDescriptor, CognitiveRiskClass, CognitiveTiming, ComparisonOp, ConfirmationPolicy,
    ConfirmationRequirement, GoalProgress, GoalSpec, ObservationSnapshot, ObservationSourceKind,
    PlanEdge, PlanEdgeKind, PlanGraph, PlanNode, PlanNodeKind, Postcondition, Provenance,
    WorkReport, WorldState,
};
use d2i_desktop::{
    activate_certified_windows_binding, bind_actual_source_observation, certify_windows_binding,
    grounded_target_binding_sha256, initialize_recovery_ledger, initialize_role_instance_ledger,
    initialize_windows_activation_ledger, initialize_windows_deployment_audit,
    project_windows_activation, to_verification_bound_execution_v2, trusted_execution_sha256,
    verify_recovery_ledger, verify_signed_windows_certification, verify_windows_activation_ledger,
    verify_windows_deployment_audit, ActionCycleRecordV1, AlternateCapabilityGroupV1,
    AuthenticatedTaskInstructionV1, CognitiveKernelTaskRuntimeV1, CognitiveRecoveryCoordinatorV1,
    CognitiveTrustedExecutionCoordinator, CognitiveVerificationCoordinatorV2,
    ConcreteWindowsRuntimeBindingProbe, DesktopError, EphemeralActionPayload, EscalationRequestV1,
    EscalationSeverityV1, FinalCriterionResultV1, FinalGoalVerificationV1,
    FinalVerificationVerdictV1, FreshRecoveryCycleEvidenceV1, FreshRecoveryCycleRequestV1,
    IgnoredVolatileTargetV1, KernelFinalOutcomeV1, KernelTaskRunRecordV1, ModuleHostBindingV1,
    ModuleInvocationCoordinatorV1, ObservationLimits, ProtectedInvariantSeverityV1,
    ProtectedInvariantV1, RecommendedNextActionCodeV1, RecoveryBudgetV1, RecoveryDecisionContextV1,
    RecoveryDecisionKindV1, RecoveryFailureClassV1, RecoveryHistoryEntryV1,
    RecoveryHistoryOutcomeV1, RecoveryHistoryV1, RecoveryPolicyProfileV1, RecoveryReasonCodeV1,
    RecoveryStageV1, RecoveryTriggerV1, RecoveryVerificationVerdictV1, ReobservationRequestV1,
    RequiredAuthorityClassV1, RoleInstanceLedgerEventKindV1, RoleInstanceLedgerRecordV1,
    RoleInstanceLedgerV1, SafeStateSummaryCodeV1, TrustedExecutionBindingRequestV1,
    TrustedExecutionSessionV1, TrustedExecutionStatusV1, TrustedReadOnlyObservationConfiguration,
    TrustedTargetResolverInput, VerificationConsumptionLedgerV1, VerificationGuardFieldV1,
    VerificationGuardProfileV1, VerificationGuardTargetV1, VerificationVerdictV2,
    WindowsActivationAdmission, WindowsAdapterConfiguration, WindowsAdapterKind,
    WindowsDeploymentAuditEvent, WindowsDeploymentAuditEventKind, WindowsDeploymentAuditLedger,
    WindowsDeploymentAuditStatus, WindowsRuntimeBindingProbe, WindowsRuntimeManifest,
    WindowsUiAutomationAdapter, WindowsUiaObservationProvider, WindowsUiaObservationTarget,
    KERNEL_TASK_RUNTIME_BUILD_ID, KERNEL_TASK_SCHEMA_VERSION, RECOVERY_SCHEMA_VERSION,
    TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION,
};
use d2i_module_sdk::{
    canonical_sha256 as module_sha256, load_module_manifest, parse_json_strict,
    ModuleInvocationEnvelope, ModuleProvenance, ModuleResultStatus, RedactionMarker, ReplayContext,
    ResourceBudget, CONTRACT_VERSION_V1,
};
use d2i_policy_admission::{
    admit_action, create_confirmation_challenge, evaluate_policy, ActivationEligibilityContextV1,
    AdapterKindV1, AdmissionIssuanceV1, AuthorityScopeConstraintsV1, ConfirmationGrantV1,
    DelegatedAuthorityContextV1, GrantConsumptionLedgerV1, PolicyEvaluationRequestV1,
    PolicyOutcomeV1, RequestedAutonomyModeV1, TrustedPolicySnapshotV1, TrustedPolicyStateV1,
    POLICY_ADMISSION_SCHEMA_VERSION,
};
use d2i_role_contract::{
    admit_role_task, compile_role_source, create_role_contract_approval, create_role_delegation,
    RoleBoundKernelTaskContextV1, RoleCompileFormatV1, RoleContractApprovalV1, RoleContractV1,
    RoleDelegationGrantV1, RoleInstanceStatusV1, RoleInstanceV1, RoleOperationalTimeContextV1,
    RoleTaskAdmissionOutcomeV1, RoleTaskAdmissionRequestV1, ROLE_CONTRACT_SCHEMA_VERSION,
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const EXPECTED_NAME: &str = "D2I-E2E-VERIFIED-NAME";
const INTEGRATION_ID: &str = "windows-kernel-e2e";
const ORGANIZATION_ID: &str = "organization-1";
const ACTOR_ID: &str = "kernel-e2e-actor";
const ROLE_ID: &str = "kernel-e2e-task-operator";
const FIXTURE_STATE_FILE: &str = "fixture-state.json";
const FIXTURE_SCRIPT_BYTES: &[u8] =
    include_bytes!("../../tests/support/kernel_e2e_name_save_fixture.ps1");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ScenarioMode {
    Happy,
    Recovery,
    Unsafe,
    Clarification,
}

impl ScenarioMode {
    fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "happy" => Ok(Self::Happy),
            "recovery" => Ok(Self::Recovery),
            "unsafe" => Ok(Self::Unsafe),
            "clarification" => Ok(Self::Clarification),
            _ => Err("mode must be happy, recovery, unsafe, or clarification".to_owned()),
        }
    }

    const fn fixture_mode(self) -> &'static str {
        match self {
            Self::Happy => "happy",
            Self::Recovery => "recovery",
            Self::Unsafe => "unsafe",
            Self::Clarification => "clarification",
        }
    }

    const fn expected_outcome(self) -> KernelFinalOutcomeV1 {
        match self {
            Self::Happy | Self::Recovery => KernelFinalOutcomeV1::Completed,
            Self::Unsafe => KernelFinalOutcomeV1::Escalated,
            Self::Clarification => KernelFinalOutcomeV1::ClarificationRequired,
        }
    }
}

#[derive(Debug)]
struct RunnerArgs {
    mode: ScenarioMode,
    output_root: PathBuf,
    worker_executable: PathBuf,
    fixture_script: PathBuf,
    application_pack: PathBuf,
    role_source: Option<PathBuf>,
    module_roots: BTreeMap<String, PathBuf>,
    module_hosts: BTreeMap<String, PathBuf>,
    module_host_hashes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupResultV1 {
    module_host_residuals: u32,
    worker_residuals: u32,
    app_process_residuals: u32,
    activation_residuals: u32,
    payload_residuals: u32,
    temporary_root_removed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelE2eScenarioResultV1 {
    schema_version: u32,
    mode: ScenarioMode,
    expected_outcome: KernelFinalOutcomeV1,
    actual_outcome: KernelFinalOutcomeV1,
    authenticated_instruction_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    role_context_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    role_ledger_chain_head: Option<String>,
    goal_spec_sha256: String,
    application_pack_sha256: String,
    plan_sha256: String,
    initial_observation_sha256: String,
    final_observation_sha256: String,
    final_goal_verification_sha256: String,
    work_report_sha256: String,
    kernel_task_run_record_sha256: String,
    normalized_replay_sha256: String,
    actual_module_invocations: u32,
    action_cycle_count: u32,
    completed_action_count: u32,
    policy_admission_count: u32,
    windows_action_activation_count: u32,
    execution_receipt_count: u32,
    verified_action_count: u32,
    recovery_cycle_count: u32,
    mutation_count: u32,
    audit_chain_head: String,
    cleanup: CleanupResultV1,
    result_sha256: String,
}

impl KernelE2eScenarioResultV1 {
    fn seal(mut self) -> Result<Self, DesktopError> {
        self.result_sha256 = hash_without_field(&self, "result_sha256")?;
        Ok(self)
    }
}

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(mode: ScenarioMode) -> Result<Self, DesktopError> {
        let path = std::env::temp_dir().join(format!(
            "d2i-kernel-e2e-{}-{}",
            mode.fixture_mode(),
            std::process::id()
        ));
        if path.exists() {
            fs::remove_dir_all(&path).map_err(|error| io_error("temporary-root", error))?;
        }
        fs::create_dir(&path).map_err(|error| io_error("temporary-root", error))?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn remove(&self) -> Result<(), DesktopError> {
        if self.0.exists() {
            fs::remove_dir_all(&self.0).map_err(|error| io_error("temporary-root", error))?;
        }
        Ok(())
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard(Child);

impl ChildGuard {
    fn stop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Debug)]
struct CycleExecution {
    source: ObservationSnapshot,
    fresh: ObservationSnapshot,
    proposal_id: String,
    proposal_sha256: String,
    plan_generation_id: String,
    capability_id: String,
    input_sha256: String,
    policy_decision_sha256: String,
    admission_sha256: String,
    activation_record_hash: String,
    receipt_sha256: String,
    verified_result_sha256: String,
    verdict: VerificationVerdictV2,
    verification_diagnostic: String,
    record: ActionCycleRecordV1,
    audit_chain_heads: Vec<String>,
}

struct ScenarioArtifacts {
    instruction: AuthenticatedTaskInstructionV1,
    goal: GoalSpec,
    pack: ApplicationPack,
    plan: PlanGraph,
    initial: ObservationSnapshot,
    final_verification: FinalGoalVerificationV1,
    report: WorkReport,
    run_record: KernelTaskRunRecordV1,
    normalized_replay_sha256: String,
    actual_outcome: KernelFinalOutcomeV1,
    module_invocation_count: usize,
    cycles: Vec<ActionCycleRecordV1>,
    policy_count: usize,
    activation_count: usize,
    receipt_count: usize,
    verified_count: usize,
    recovery_count: usize,
    mutation_count: usize,
    audit_chain_head: String,
    role_context: Option<RoleBoundKernelTaskContextV1>,
    role_instance: Option<RoleInstanceV1>,
    role_terminal_instance: Option<RoleInstanceV1>,
    role_contract: Option<RoleContractV1>,
    role_delegation: Option<RoleDelegationGrantV1>,
    role_context_sha256: Option<String>,
    role_ledger_chain_head: Option<String>,
}

struct RoleKernelBinding {
    contract: RoleContractV1,
    delegation: RoleDelegationGrantV1,
    admitted_instance: RoleInstanceV1,
    ledger: RoleInstanceLedgerV1,
    audit: WindowsDeploymentAuditLedger,
    audit_root: PathBuf,
    context: RoleBoundKernelTaskContextV1,
    authority: DelegatedAuthorityContextV1,
    recovery: RecoveryPolicyProfileV1,
}

impl RoleKernelBinding {
    fn finish(
        &mut self,
        run_record_sha256: &str,
        recorded_at_unix_ms: u64,
    ) -> Result<RoleInstanceV1, DesktopError> {
        let current = self
            .ledger
            .verification()
            .current_instance
            .clone()
            .ok_or_else(|| DesktopError::Integrity("active Role disappeared".to_owned()))?;
        append_role_record(
            &mut self.ledger,
            &mut self.audit,
            &self.contract,
            RoleInstanceLedgerEventKindV1::RoleBoundTaskTerminal,
            Some(current),
            None,
            None,
            Some(self.context.context_sha256.clone()),
            BTreeMap::from([("kernel_task_run".to_owned(), run_record_sha256.to_owned())]),
            recorded_at_unix_ms,
        )?;
        self.ledger
            .verification()
            .current_instance
            .clone()
            .ok_or_else(|| DesktopError::Integrity("terminal Role Instance is absent".to_owned()))
    }

    fn audit_chain_head(&self) -> Result<String, DesktopError> {
        Ok(verify_windows_deployment_audit(&self.audit_root)?.terminal_record_hash)
    }
}

fn main() -> ExitCode {
    #[cfg(not(windows))]
    {
        eprintln!("D2I KRN-500 runner requires Windows");
        return ExitCode::from(13);
    }
    #[cfg(windows)]
    {
        match run_main() {
            Ok(code) => code,
            Err(error) => {
                eprintln!("D2I KRN-500 runner failed closed: {error}");
                ExitCode::from(13)
            }
        }
    }
}

#[cfg(windows)]
fn run_main() -> Result<ExitCode, DesktopError> {
    let args = parse_args().map_err(DesktopError::Invalid)?;
    fs::create_dir_all(&args.output_root).map_err(|error| io_error("output-root", error))?;
    let temp = TempRoot::new(args.mode)?;
    let mut app = start_fixture(&args, &temp)?;
    let app_process_id = app.0.id();
    let artifacts = run_scenario(&args, &temp, app_process_id)?;
    app.stop();
    let app_residual = u32::from(process_exists(app_process_id));
    temp.remove()?;
    let cleanup = CleanupResultV1 {
        module_host_residuals: 0,
        worker_residuals: 0,
        app_process_residuals: app_residual,
        activation_residuals: 0,
        payload_residuals: 0,
        temporary_root_removed: !temp.path().exists(),
    };
    if cleanup.app_process_residuals != 0 || !cleanup.temporary_root_removed {
        return Err(DesktopError::Integrity(
            "KRN-500 cleanup left residual process or temporary state".to_owned(),
        ));
    }
    let completed_action_count = artifacts
        .cycles
        .iter()
        .filter(|cycle| cycle.completed)
        .count();
    write_scenario_artifact(
        &args.output_root.join("kernel-task-run-record.json"),
        &artifacts.run_record,
    )?;
    write_scenario_artifact(
        &args.output_root.join("final-goal-verification.json"),
        &artifacts.final_verification,
    )?;
    write_scenario_artifact(
        &args.output_root.join("work-report.json"),
        &artifacts.report,
    )?;
    if let Some(context) = &artifacts.role_context {
        write_scenario_artifact(
            &args.output_root.join("role-bound-kernel-context.json"),
            context,
        )?;
    }
    if let Some(instance) = &artifacts.role_instance {
        write_scenario_artifact(&args.output_root.join("role-instance.json"), instance)?;
    }
    if let Some(instance) = &artifacts.role_terminal_instance {
        write_scenario_artifact(
            &args.output_root.join("role-terminal-instance.json"),
            instance,
        )?;
    }
    if let Some(contract) = &artifacts.role_contract {
        write_scenario_artifact(&args.output_root.join("role-contract.json"), contract)?;
    }
    if let Some(delegation) = &artifacts.role_delegation {
        write_scenario_artifact(&args.output_root.join("role-delegation.json"), delegation)?;
    }
    let result = KernelE2eScenarioResultV1 {
        schema_version: KERNEL_TASK_SCHEMA_VERSION,
        mode: args.mode,
        expected_outcome: args.mode.expected_outcome(),
        actual_outcome: artifacts.actual_outcome,
        authenticated_instruction_sha256: artifacts.instruction.instruction_sha256.clone(),
        role_context_sha256: artifacts.role_context_sha256,
        role_ledger_chain_head: artifacts.role_ledger_chain_head,
        goal_spec_sha256: canonical_sha256(&artifacts.goal).map_err(selection_error)?,
        application_pack_sha256: artifacts.pack.pack_sha256.clone(),
        plan_sha256: canonical_sha256(&artifacts.plan).map_err(selection_error)?,
        initial_observation_sha256: artifacts.initial.state_hash.clone(),
        final_observation_sha256: artifacts
            .final_verification
            .final_observation_sha256
            .clone(),
        final_goal_verification_sha256: artifacts
            .final_verification
            .final_verification_sha256
            .clone(),
        work_report_sha256: canonical_sha256(&artifacts.report).map_err(selection_error)?,
        kernel_task_run_record_sha256: artifacts.run_record.run_record_sha256.clone(),
        normalized_replay_sha256: artifacts.normalized_replay_sha256,
        actual_module_invocations: u32::try_from(artifacts.module_invocation_count)
            .map_err(|_| DesktopError::Invalid("module invocation count overflow".to_owned()))?,
        action_cycle_count: u32::try_from(artifacts.cycles.len())
            .map_err(|_| DesktopError::Invalid("action cycle count overflow".to_owned()))?,
        completed_action_count: u32::try_from(completed_action_count)
            .map_err(|_| DesktopError::Invalid("completed action count overflow".to_owned()))?,
        policy_admission_count: u32::try_from(artifacts.policy_count)
            .map_err(|_| DesktopError::Invalid("policy count overflow".to_owned()))?,
        windows_action_activation_count: u32::try_from(artifacts.activation_count)
            .map_err(|_| DesktopError::Invalid("activation count overflow".to_owned()))?,
        execution_receipt_count: u32::try_from(artifacts.receipt_count)
            .map_err(|_| DesktopError::Invalid("receipt count overflow".to_owned()))?,
        verified_action_count: u32::try_from(artifacts.verified_count)
            .map_err(|_| DesktopError::Invalid("verification count overflow".to_owned()))?,
        recovery_cycle_count: u32::try_from(artifacts.recovery_count)
            .map_err(|_| DesktopError::Invalid("recovery count overflow".to_owned()))?,
        mutation_count: u32::try_from(artifacts.mutation_count)
            .map_err(|_| DesktopError::Invalid("mutation count overflow".to_owned()))?,
        audit_chain_head: artifacts.audit_chain_head,
        cleanup,
        result_sha256: empty_hash(),
    }
    .seal()?;
    if result.actual_outcome != result.expected_outcome {
        return Err(DesktopError::Integrity(
            "scenario outcome differs from the expected mode outcome".to_owned(),
        ));
    }
    let bytes = serde_json::to_vec_pretty(&result)
        .map_err(|error| DesktopError::Json(error.to_string()))?;
    fs::write(args.output_root.join("result.json"), bytes)
        .map_err(|error| io_error("result.json", error))?;
    Ok(match result.actual_outcome {
        KernelFinalOutcomeV1::Completed => ExitCode::SUCCESS,
        KernelFinalOutcomeV1::ClarificationRequired => ExitCode::from(10),
        KernelFinalOutcomeV1::Escalated => ExitCode::from(11),
        KernelFinalOutcomeV1::Stopped | KernelFinalOutcomeV1::Failed => ExitCode::from(12),
        KernelFinalOutcomeV1::InfrastructureError => ExitCode::from(13),
    })
}

#[cfg(windows)]
fn write_scenario_artifact<T: Serialize>(path: &Path, value: &T) -> Result<(), DesktopError> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|error| DesktopError::Json(error.to_string()))?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|error| io_error("scenario-artifact", error))
}

fn parse_args() -> Result<RunnerArgs, String> {
    let mut values = std::env::args().skip(1);
    let mut map = BTreeMap::new();
    while let Some(key) = values.next() {
        if !key.starts_with("--") || map.contains_key(&key) {
            return Err("arguments must be unique --key value pairs".to_owned());
        }
        let value = values
            .next()
            .ok_or_else(|| format!("missing value for {key}"))?;
        map.insert(key, value);
    }
    let take = |map: &mut BTreeMap<String, String>, key: &str| {
        map.remove(key)
            .ok_or_else(|| format!("required argument {key} is absent"))
    };
    let mode = ScenarioMode::parse(&take(&mut map, "--mode")?)?;
    let output_root = PathBuf::from(take(&mut map, "--output-root")?);
    let worker_executable = PathBuf::from(take(&mut map, "--worker-executable")?);
    let fixture_script = PathBuf::from(take(&mut map, "--fixture-script")?);
    let application_pack = PathBuf::from(take(&mut map, "--application-pack")?);
    let role_source = map.remove("--role-source").map(PathBuf::from);
    let mut module_roots = BTreeMap::new();
    let mut module_hosts = BTreeMap::new();
    let mut module_host_hashes = BTreeMap::new();
    for (id, prefix) in [
        ("goal-compiler", "goal"),
        ("element-grounder", "grounder"),
        ("plan-ranker", "ranker"),
    ] {
        module_roots.insert(
            id.to_owned(),
            PathBuf::from(take(&mut map, &format!("--{prefix}-module-root"))?),
        );
        module_hosts.insert(
            id.to_owned(),
            PathBuf::from(take(&mut map, &format!("--{prefix}-host"))?),
        );
        module_host_hashes.insert(
            id.to_owned(),
            take(&mut map, &format!("--{prefix}-host-sha256"))?,
        );
    }
    if !map.is_empty() {
        return Err("unknown KRN-500 runner argument".to_owned());
    }
    Ok(RunnerArgs {
        mode,
        output_root,
        worker_executable,
        fixture_script,
        application_pack,
        role_source,
        module_roots,
        module_hosts,
        module_host_hashes,
    })
}

#[cfg(windows)]
fn start_fixture(args: &RunnerArgs, temp: &TempRoot) -> Result<ChildGuard, DesktopError> {
    let script = canonical_file(&args.fixture_script, "fixture-script")?;
    if fs::read(&script).map_err(|error| io_error("fixture-script", error))? != FIXTURE_SCRIPT_BYTES
    {
        return Err(DesktopError::Integrity(
            "fixture script differs from the build-pinned source".to_owned(),
        ));
    }
    let powershell = powershell_path()?;
    let title = fixture_title(args.mode);
    let state_path = temp.path().join(FIXTURE_STATE_FILE);
    let child = Command::new(powershell)
        .args(["-NoProfile", "-STA", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(script)
        .arg("-WindowTitle")
        .arg(title)
        .arg("-Mode")
        .arg(args.mode.fixture_mode())
        .arg("-StatePath")
        .arg(&state_path)
        .current_dir(temp.path())
        .spawn()
        .map_err(|error| io_error("winforms-fixture", error))?;
    let mut guard = ChildGuard(child);
    for _ in 0..50 {
        if guard
            .0
            .try_wait()
            .map_err(|error| io_error("winforms-fixture", error))?
            .is_some()
        {
            return Err(DesktopError::AdapterUnavailable(
                "WinForms fixture exited before observation".to_owned(),
            ));
        }
        if process_exists(guard.0.id()) {
            std::thread::sleep(Duration::from_millis(100));
            if wait_for_window(guard.0.id())
                && fixture_state(&state_path).is_ok_and(|state| state.ready)
            {
                return Ok(guard);
            }
        }
    }
    Err(DesktopError::AdapterUnavailable(
        "WinForms fixture window did not become observable".to_owned(),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureState {
    schema_version: u32,
    ready: bool,
    input_revision: u64,
    input_sha256: String,
    #[serde(rename = "input_focused")]
    _input_focused: bool,
    save_attempts: u64,
    save_status: String,
    saved_name_sha256: String,
}

#[cfg(windows)]
fn fixture_state(path: &Path) -> Result<FixtureState, DesktopError> {
    let bytes = fs::read(path).map_err(|error| io_error("fixture-state", error))?;
    let state: FixtureState = parse_json_strict(&bytes).map_err(selection_error)?;
    if state.schema_version != 1
        || state.save_status.len() > 16
        || !state
            .save_status
            .bytes()
            .all(|byte| byte.is_ascii_lowercase())
        || !state
            .input_sha256
            .strip_prefix("sha256:")
            .is_some_and(|value| {
                value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        || !state
            .saved_name_sha256
            .strip_prefix("sha256:")
            .is_some_and(|value| {
                value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
    {
        return Err(DesktopError::Integrity(
            "fixture state contract is invalid".to_owned(),
        ));
    }
    Ok(state)
}

#[cfg(windows)]
fn wait_for_fixture_transition(
    temp: &TempRoot,
    mode: ScenarioMode,
    step: ActionStepKind,
    action_sequence: u64,
) -> Result<(), DesktopError> {
    let state_path = temp.path().join(FIXTURE_STATE_FILE);
    let expected_name_sha256 = sha(EXPECTED_NAME.as_bytes());
    let timeout = Duration::from_secs(10);
    let deadline = Instant::now() + timeout;
    let mut last_state = "state-unavailable".to_owned();
    loop {
        if let Ok(state) = fixture_state(&state_path) {
            let matches = match step {
                ActionStepKind::SetName => {
                    state.input_revision >= 1 && state.input_sha256 == expected_name_sha256
                }
                ActionStepKind::Save => {
                    let required_attempts = action_sequence.saturating_sub(1);
                    state.save_attempts >= required_attempts
                        && if mode == ScenarioMode::Recovery && required_attempts == 1 {
                            state.save_status == "rejected"
                        } else {
                            state.save_status == "saved"
                                && state.saved_name_sha256 == expected_name_sha256
                        }
                }
            };
            last_state = format!(
                "input_revision={};input_hash_match={};save_attempts={};save_status={};saved_hash_match={}",
                state.input_revision,
                state.input_sha256 == expected_name_sha256,
                state.save_attempts,
                state.save_status,
                state.saved_name_sha256 == expected_name_sha256
            );
            if matches {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(DesktopError::AdapterUnavailable(
        format!(
            "WinForms fixture did not publish the expected bounded UI transition within {}ms: step={}, action_sequence={action_sequence}, {last_state}",
            timeout.as_millis(),
            step.label()
        ),
    ))
}

#[cfg(windows)]
fn wait_for_window(process_id: u32) -> bool {
    let script = format!(
        "$p=Get-Process -Id {process_id} -ErrorAction SilentlyContinue; if($p -and $p.MainWindowHandle -ne 0){{exit 0}}else{{exit 1}}"
    );
    let Ok(powershell) = powershell_path() else {
        return false;
    };
    Command::new(powershell)
        .args(["-NoProfile", "-Command", &script])
        .status()
        .is_ok_and(|status| status.success())
}

fn fixture_title(mode: ScenarioMode) -> String {
    format!(
        "D2I Kernel E2E {} {}",
        mode.fixture_mode(),
        std::process::id()
    )
}

fn io_error(path: &str, error: std::io::Error) -> DesktopError {
    DesktopError::Io {
        path: path.to_owned(),
        message: error.to_string(),
    }
}

fn selection_error(error: impl std::fmt::Display) -> DesktopError {
    DesktopError::Integrity(error.to_string())
}

fn empty_hash() -> String {
    sha(&[])
}

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn digest(label: &str) -> String {
    module_sha256(&label).unwrap_or_else(|_| sha(label.as_bytes()))
}

fn hash_without_field<T: Serialize>(value: &T, field: &str) -> Result<String, DesktopError> {
    let mut value =
        serde_json::to_value(value).map_err(|error| DesktopError::Json(error.to_string()))?;
    value
        .as_object_mut()
        .ok_or_else(|| DesktopError::Json("hash target is not an object".to_owned()))?
        .remove(field);
    module_sha256(&value).map_err(selection_error)
}

fn now_seconds() -> Result<u64, DesktopError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| DesktopError::Invalid(error.to_string()))
}

fn canonical_file(path: &Path, label: &str) -> Result<PathBuf, DesktopError> {
    let canonical = fs::canonicalize(path).map_err(|error| io_error(label, error))?;
    let metadata = fs::symlink_metadata(&canonical).map_err(|error| io_error(label, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(DesktopError::Invalid(format!(
            "{label} must be a regular file"
        )));
    }
    Ok(canonical)
}

fn powershell_path() -> Result<PathBuf, DesktopError> {
    let system_root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .ok_or_else(|| DesktopError::Invalid("SystemRoot is unavailable".to_owned()))?;
    canonical_file(
        &system_root
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe"),
        "powershell",
    )
}

#[cfg(windows)]
fn process_exists(process_id: u32) -> bool {
    d2i_windows_host::process_image_path(process_id).is_ok()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn module_binding(args: &RunnerArgs, module_id: &str) -> Result<ModuleHostBindingV1, DesktopError> {
    let (version, capability, input_schema, output_schema) = match module_id {
        "goal-compiler" => (
            "1.0.0",
            "cognitive.goal-compile",
            "goal-compilation-input-v1",
            "goal-compilation-result-v1",
        ),
        "element-grounder" => (
            "1.0.0",
            "cognitive.element-ground",
            "element-grounding-input-v1",
            "element-grounding-result-v1",
        ),
        "plan-ranker" => (
            "1.0.0",
            "cognitive.plan-rank",
            "cognitive-plan-ranking-input-v1",
            "cognitive-plan-ranking-output-v1",
        ),
        _ => return Err(DesktopError::AccessDenied("unknown E2E module".to_owned())),
    };
    Ok(ModuleHostBindingV1 {
        module_root: args
            .module_roots
            .get(module_id)
            .cloned()
            .ok_or_else(|| DesktopError::Invalid("module root is absent".to_owned()))?,
        host_executable: args
            .module_hosts
            .get(module_id)
            .cloned()
            .ok_or_else(|| DesktopError::Invalid("module host is absent".to_owned()))?,
        expected_host_sha256: args
            .module_host_hashes
            .get(module_id)
            .cloned()
            .ok_or_else(|| DesktopError::Invalid("module host hash is absent".to_owned()))?,
        expected_module_id: module_id.to_owned(),
        expected_module_version: version.to_owned(),
        expected_capability_id: capability.to_owned(),
        expected_capability_version: "1.0.0".to_owned(),
        expected_input_schema_id: input_schema.to_owned(),
        expected_output_schema_id: output_schema.to_owned(),
    })
}

struct ModuleInvocationSpec {
    module_id: &'static str,
    invocation_id: String,
    payload: Value,
    goal_id: String,
    source_observation_hash: Option<String>,
    plan_generation_id: Option<String>,
    logical_sequence: u64,
    trust_labels: BTreeSet<String>,
    fixture_hash: String,
}

fn module_invocation(
    args: &RunnerArgs,
    spec: ModuleInvocationSpec,
) -> Result<ModuleInvocationEnvelope, DesktopError> {
    let invocation_id = spec.invocation_id.clone();
    let root = args
        .module_roots
        .get(spec.module_id)
        .ok_or_else(|| DesktopError::Invalid("module root is absent".to_owned()))?;
    let loaded = load_module_manifest(root).map_err(selection_error)?;
    let (capability, input_schema) = match spec.module_id {
        "goal-compiler" => ("cognitive.goal-compile", "goal-compilation-input-v1"),
        "element-grounder" => ("cognitive.element-ground", "element-grounding-input-v1"),
        "plan-ranker" => ("cognitive.plan-rank", "cognitive-plan-ranking-input-v1"),
        _ => return Err(DesktopError::AccessDenied("unknown E2E module".to_owned())),
    };
    let invocation = ModuleInvocationEnvelope {
        contract_version: CONTRACT_VERSION_V1,
        invocation_id: invocation_id.clone(),
        module: loaded.identifier,
        requested_capability: capability.to_owned(),
        input_schema_id: input_schema.to_owned(),
        input_schema_version: 1,
        payload: spec.payload,
        goal_id: spec.goal_id,
        source_observation_hash: spec.source_observation_hash,
        plan_generation_id: spec.plan_generation_id,
        logical_sequence: spec.logical_sequence,
        deadline_logical_tick: spec.logical_sequence.saturating_add(100),
        resource_budget: ResourceBudget {
            max_input_bytes: loaded.manifest.execution.maximum_input_bytes,
            max_output_bytes: loaded.manifest.execution.maximum_output_bytes,
            memory_bytes: loaded.manifest.execution.memory_limit_bytes,
            logical_operation_budget: loaded.manifest.execution.logical_operation_budget,
        },
        trust_labels: spec.trust_labels,
        redactions: Vec::<RedactionMarker>::new(),
        provenance: ModuleProvenance {
            source_id: "kernel-e2e-runtime".to_owned(),
            source_sha256: spec.fixture_hash.clone(),
            producer: KERNEL_TASK_RUNTIME_BUILD_ID.to_owned(),
        },
        replay: ReplayContext {
            replay_id: format!("replay-{invocation_id}"),
            seed: 500,
            fixture_hash: spec.fixture_hash,
        },
        correlation_id: "kernel-e2e-correlation".to_owned(),
        trace_id: "kernel-e2e-trace".to_owned(),
    };
    invocation.validate().map_err(|error| {
        DesktopError::Integrity(format!(
            "module invocation {invocation_id} failed local validation: {error}"
        ))
    })?;
    Ok(invocation)
}

fn authenticated_instruction(now_ms: u64) -> Result<AuthenticatedTaskInstructionV1, DesktopError> {
    let instruction_text = concat!(
        "목표: 로컬 직원 등록 폼의 이름을 D2I-E2E-VERIFIED-NAME으로 변경하고 저장\n",
        "범위: D2I WinForms E2E 테스트 애플리케이션\n",
        "결과: 저장된 이름은 요청한 값과 일치\n",
        "제약: 보호 필드와 다른 입력값은 변경하지 않음"
    );
    AuthenticatedTaskInstructionV1 {
        schema_version: KERNEL_TASK_SCHEMA_VERSION,
        instruction_id: "kernel-e2e-instruction".to_owned(),
        locale: "ko-KR".to_owned(),
        source_id: "authenticated-local-e2e".to_owned(),
        authenticated_actor_id: ACTOR_ID.to_owned(),
        authenticated_role_id: ROLE_ID.to_owned(),
        organization_id: ORGANIZATION_ID.to_owned(),
        instruction_text: instruction_text.to_owned(),
        structured_success_criteria: vec![
            Postcondition {
                target_state: "element:saved-name:value".to_owned(),
                op: ComparisonOp::Equals,
                expected_value: json!(EXPECTED_NAME),
                required: true,
                timeout_ms: 5_000,
            },
            Postcondition {
                target_state: "element:save-status:value".to_owned(),
                op: ComparisonOp::Equals,
                expected_value: json!("saved"),
                required: true,
                timeout_ms: 5_000,
            },
            Postcondition {
                target_state: "element:save-revision:value".to_owned(),
                op: ComparisonOp::GreaterOrEqual,
                expected_value: json!(1),
                required: true,
                timeout_ms: 5_000,
            },
        ],
        issued_at_unix_ms: now_ms,
        expires_at_unix_ms: now_ms.saturating_add(120_000),
        provenance: Provenance {
            source: "authenticated local KRN-500 instruction".to_owned(),
            source_hash: digest("kernel-e2e-authenticated-instruction-source"),
            module_id: "authenticated-user-instruction".to_owned(),
        },
        evidence_ids: vec!["authenticated-local-session".to_owned()],
        instruction_sha256: empty_hash(),
    }
    .seal()
}

fn goal_compiler_payload(
    instruction: &AuthenticatedTaskInstructionV1,
) -> Result<Value, DesktopError> {
    let mut payload = json!({
        "schema_version": 1,
        "instruction": instruction.instruction_text,
        "locale": instruction.locale,
        "source_id": instruction.source_id,
        "source_hash": empty_hash(),
        "scope_hints": {"fixture": "windows-uia"},
        "explicit_constraints": ["protected fields remain unchanged"],
        "success_criteria": instruction.structured_success_criteria,
        "confirmation_policy": "before_risky_action",
        "trust_labels": ["authenticated_user_instruction"],
        "replay_context": {"replay_id": "kernel-e2e-goal", "seed": 500}
    });
    let source_hash = module_sha256(&json!({
        "instruction": instruction.instruction_text,
        "locale": instruction.locale,
        "source_id": instruction.source_id,
    }))
    .map_err(selection_error)?;
    payload["source_hash"] = Value::String(source_hash);
    Ok(payload)
}

fn load_application_pack(path: &Path) -> Result<ApplicationPack, DesktopError> {
    let bytes = fs::read(canonical_file(path, "application-pack")?)
        .map_err(|error| io_error("application-pack", error))?;
    let pack: ApplicationPack = parse_json_strict(&bytes).map_err(selection_error)?;
    pack.validate().map_err(selection_error)?;
    Ok(pack)
}

fn task_plan() -> Result<PlanGraph, DesktopError> {
    let definitions = [
        ("observe", PlanNodeKind::Observe),
        ("select-name-capability", PlanNodeKind::SelectCapability),
        ("propose-name-action", PlanNodeKind::ProposeAction),
        ("policy-name", PlanNodeKind::PolicyGate),
        ("activate-name", PlanNodeKind::ActivationGate),
        ("execute-name", PlanNodeKind::Execute),
        ("verify-name", PlanNodeKind::Verify),
        ("select-save-capability", PlanNodeKind::SelectCapability),
        ("propose-save-action", PlanNodeKind::ProposeAction),
        ("policy-save", PlanNodeKind::PolicyGate),
        ("activate-save", PlanNodeKind::ActivationGate),
        ("execute-save", PlanNodeKind::Execute),
        ("verify-save", PlanNodeKind::Verify),
        ("return", PlanNodeKind::Return),
    ];
    let nodes = definitions
        .iter()
        .map(|(node_id, kind)| PlanNode {
            node_id: (*node_id).to_owned(),
            kind: *kind,
            capability_id: None,
            loop_bound: None,
        })
        .collect::<Vec<_>>();
    let edges = definitions
        .windows(2)
        .map(|pair| PlanEdge {
            from: pair[0].0.to_owned(),
            to: pair[1].0.to_owned(),
            kind: PlanEdgeKind::Sequence,
            condition: None,
        })
        .collect::<Vec<_>>();
    let plan = PlanGraph {
        schema_version: 1,
        plan_generation_id: "kernel-e2e-plan-v1".to_owned(),
        entry_node: "observe".to_owned(),
        nodes,
        edges,
    };
    plan.validate().map_err(selection_error)?;
    Ok(plan)
}

fn world_state(
    goal: &GoalSpec,
    observation: &ObservationSnapshot,
    plan: &PlanGraph,
    current_step: &str,
) -> Result<WorldState, DesktopError> {
    let world = WorldState {
        schema_version: 1,
        world_state_id: format!("world-{current_step}"),
        goal_id: goal.goal_id.clone(),
        normalized_facts: Vec::new(),
        known_state: BTreeMap::new(),
        uncertain_state: BTreeMap::new(),
        conflicts: Vec::new(),
        capabilities: BTreeSet::from(["uia.invoke".to_owned(), "uia.set_value".to_owned()]),
        current_step: current_step.to_owned(),
        current_observation_hash: observation.state_hash.clone(),
        plan_generation_id: plan.plan_generation_id.clone(),
        provenance: Provenance {
            source: "KRN-500 actual UIA observation".to_owned(),
            source_hash: observation.state_hash.clone(),
            module_id: KERNEL_TASK_RUNTIME_BUILD_ID.to_owned(),
        },
    };
    world.validate().map_err(selection_error)?;
    Ok(world)
}

fn adapter_configuration(
    worker_executable: &Path,
    target_executable_hash: &str,
) -> Result<WindowsAdapterConfiguration, DesktopError> {
    let worker = canonical_file(worker_executable, "worker-executable")?;
    let configuration = WindowsAdapterConfiguration {
        schema_version: 1,
        adapter_kind: WindowsAdapterKind::UiAutomation,
        worker_executable: worker.display().to_string(),
        worker_executable_hash: sha(
            &fs::read(&worker).map_err(|error| io_error("worker-executable", error))?
        ),
        request_timeout_ms: 10_000,
        active_process_limit: 1,
        per_process_memory_bytes: 256 * 1024 * 1024,
        write_roots: Vec::new(),
        webdriver_endpoint: None,
        browser_session_ids: BTreeSet::new(),
        browser_allowed_origins: BTreeSet::new(),
        browser_egress_policy: None,
        deployment_audit_root: None,
        ui_allowed_executable_hashes: BTreeSet::from([target_executable_hash.to_owned()]),
        process_isolation: None,
    };
    configuration.validate()?;
    Ok(configuration)
}

#[cfg(windows)]
fn certified_admission_labeled(
    configuration: &WindowsAdapterConfiguration,
    temp: &TempRoot,
    observed_at: u64,
    label: &str,
) -> Result<(WindowsActivationAdmission, u32, String), DesktopError> {
    let attestor_key = SigningKey::from_bytes(&[71_u8; 32]);
    let certifier_key = SigningKey::from_bytes(&[72_u8; 32]);
    let probe = ConcreteWindowsRuntimeBindingProbe::new(
        configuration.clone(),
        format!("binding-kernel-e2e-{label}"),
        INTEGRATION_ID.to_owned(),
        observed_at,
        observed_at.saturating_add(600),
        "runtime-attestor".to_owned(),
        attestor_key.clone(),
    )?;
    let evidence = probe.collect_binding_evidence()?;
    let session_id = evidence.host.session_id;
    let manifest = WindowsRuntimeManifest {
        schema_version: 1,
        integration_id: INTEGRATION_ID.to_owned(),
        adapter_kind: WindowsAdapterKind::UiAutomation,
        adapter_descriptor: configuration.descriptor()?,
        configuration_hash: configuration.configuration_hash()?,
        worker_executable_hash: configuration.worker_executable_hash.clone(),
        process_isolation: None,
        browser_egress_requirement: None,
        host: evidence.host.clone(),
        interactive_session_required: true,
        binding_attestor_id: "runtime-attestor".to_owned(),
        binding_attestor_public_key: hex(&attestor_key.verifying_key().to_bytes()),
        certifier_id: "release-certifier".to_owned(),
        certifier_public_key: hex(&certifier_key.verifying_key().to_bytes()),
    };
    let certification_result = certify_windows_binding(
        &manifest,
        &evidence,
        format!("certificate-kernel-e2e-{label}"),
        "release-certifier".to_owned(),
        &certifier_key,
        observed_at.saturating_add(1),
    )?;
    if !certification_result.report.certified {
        return Err(DesktopError::Integrity(
            "Windows binding certification was denied".to_owned(),
        ));
    }
    let signed = certification_result.signed_certification.ok_or_else(|| {
        DesktopError::Integrity("Windows certification signature is absent".to_owned())
    })?;
    let certified = verify_signed_windows_certification(
        &manifest,
        &evidence,
        &signed,
        observed_at.saturating_add(2),
    )?;
    let ledger_root = temp.path().join(format!("activation-ledger-{label}"));
    initialize_windows_activation_ledger(
        &ledger_root,
        &format!("kernel-e2e-ledger-{label}"),
        &manifest,
        BTreeSet::from(["kernel-e2e-activator".to_owned()]),
        8,
    )?;
    let admission = activate_certified_windows_binding(
        &ledger_root,
        "kernel-e2e-activator",
        certified,
        observed_at.saturating_add(2),
    )?;
    let verification = verify_windows_activation_ledger(&ledger_root)?;
    if verification.chain_head != admission.verification.chain_head {
        return Err(DesktopError::Integrity(
            "activation ledger chain head changed after issuance".to_owned(),
        ));
    }
    Ok((admission, session_id, verification.chain_head))
}

struct ActualObservation {
    snapshot: ObservationSnapshot,
    target: WindowsUiaObservationTarget,
    audit_chain_head: String,
}

#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
fn observe_actual(
    configuration: &WindowsAdapterConfiguration,
    temp: &TempRoot,
    process_id: u32,
    executable_path: &Path,
    executable_hash: &str,
    window_title: &str,
    goal: &GoalSpec,
    sequence: u64,
    label: &str,
    observed_at: u64,
) -> Result<ActualObservation, DesktopError> {
    let (admission, session_id, _) =
        certified_admission_labeled(configuration, temp, observed_at, label)?;
    let target = WindowsUiaObservationTarget {
        schema_version: 1,
        process_id,
        executable_path: executable_path.display().to_string(),
        executable_hash: executable_hash.to_owned(),
        window_title_hash: sha(window_title.as_bytes()),
        session_id,
        runtime_binding_digest: configuration.configuration_hash()?,
    };
    let adapter = WindowsUiAutomationAdapter::bind(
        admission.activation,
        configuration.clone(),
        observed_at.saturating_add(2),
    )?;
    let audit_root = temp.path().join(format!("{label}-observation-audit"));
    let audit = initialize_windows_deployment_audit(
        &audit_root,
        &format!("{label}-observation-audit"),
        &format!("{label}-observation-session"),
        64,
        observed_at.saturating_mul(1_000).max(1),
    )?;
    let provider = WindowsUiaObservationProvider::new(
        adapter,
        target.clone(),
        ObservationLimits::default(),
        audit,
    )?;
    let completed = provider.observe_once(goal, sequence)?;
    if !completed.worker_exited_cleanly
        || completed.read_only_side_effect_count != 0
        || process_exists(completed.worker_process_id)
    {
        return Err(DesktopError::Integrity(
            "read-only observation worker did not terminate cleanly".to_owned(),
        ));
    }
    let audit_verification = verify_windows_deployment_audit(&audit_root)?;
    Ok(ActualObservation {
        snapshot: completed.snapshot,
        target,
        audit_chain_head: audit_verification.terminal_record_hash,
    })
}

fn element_by_automation_id<'a>(
    observation: &'a ObservationSnapshot,
    automation_id: &str,
) -> Result<&'a d2i_cognitive_ir::ObservableElement, DesktopError> {
    let matches = observation
        .observable_elements
        .iter()
        .filter(|element| {
            element
                .value
                .pointer("/automation_id/text")
                .and_then(Value::as_str)
                == Some(automation_id)
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(DesktopError::Integrity(format!(
            "automation identity {automation_id} is absent or ambiguous"
        )));
    }
    Ok(matches[0])
}

fn observed_text(element: &d2i_cognitive_ir::ObservableElement) -> Option<&str> {
    element
        .value
        .pointer("/current_value/value/text")
        .and_then(Value::as_str)
}

fn expected_text_value(
    element: &d2i_cognitive_ir::ObservableElement,
    expected: &str,
) -> Result<Value, DesktopError> {
    let mut value = element.value.clone();
    let current = value.pointer_mut("/current_value").ok_or_else(|| {
        DesktopError::Integrity("observed UIA value omits current_value".to_owned())
    })?;
    *current = json!({
        "status": "present",
        "value": {
            "text": expected,
            "text_hash": sha(expected.as_bytes()),
            "truncated": false
        }
    });
    Ok(value)
}

fn exact_current_value_postcondition(
    element: &d2i_cognitive_ir::ObservableElement,
    expected_value: &Value,
) -> Result<Postcondition, DesktopError> {
    let current_value = expected_value.pointer("/current_value").ok_or_else(|| {
        DesktopError::Integrity("expected UIA value omits current_value".to_owned())
    })?;
    Ok(Postcondition {
        target_state: format!("element:{}:current_value", element.element_id),
        op: ComparisonOp::Equals,
        expected_value: Value::String(
            trusted_execution_sha256(current_value).map_err(selection_error)?,
        ),
        required: true,
        timeout_ms: 5_000,
    })
}

struct GroundingExecution {
    result: ElementGroundingResultV1,
    selection: Option<ValidatedGroundingSelectionV1>,
    semantic_sha256: String,
}

#[allow(clippy::too_many_arguments)]
fn invoke_grounder(
    args: &RunnerArgs,
    modules: &mut ModuleInvocationCoordinatorV1,
    pack: &ApplicationPack,
    observation: &ObservationSnapshot,
    goal: &GoalSpec,
    plan: &PlanGraph,
    semantic_target_id: &str,
    target_text: &str,
    label: &str,
    logical_tick: u64,
) -> Result<GroundingExecution, DesktopError> {
    let bridge = build_element_grounder_payload(
        pack,
        observation,
        &ElementGrounderBridgeRequest {
            schema_version: 1,
            application_pack_sha256: pack.pack_sha256.clone(),
            semantic_target_id: semantic_target_id.to_owned(),
            target_text: target_text.to_owned(),
            goal_id: goal.goal_id.clone(),
            plan_generation_id: plan.plan_generation_id.clone(),
            max_candidates: 8,
            replay_id: format!("grounder-{label}"),
            replay_seed: 500,
        },
    )
    .map_err(selection_error)?;
    let empty_paths = empty_string_paths(&bridge.payload);
    if !empty_paths.is_empty() {
        return Err(DesktopError::Integrity(format!(
            "actual Grounder bridge contains empty strings at {}",
            empty_paths.join(",")
        )));
    }
    let invocation = module_invocation(
        args,
        ModuleInvocationSpec {
            module_id: "element-grounder",
            invocation_id: format!("grounder-{label}"),
            payload: bridge.payload,
            goal_id: goal.goal_id.clone(),
            source_observation_hash: Some(observation.state_hash.clone()),
            plan_generation_id: Some(plan.plan_generation_id.clone()),
            logical_sequence: logical_tick,
            trust_labels: BTreeSet::from([
                "observed_ui_state".to_owned(),
                "untrusted_document_content".to_owned(),
            ]),
            fixture_hash: bridge.payload_sha256,
        },
    )?;
    let result_envelope = modules.invoke(&invocation)?;
    if result_envelope.status != ModuleResultStatus::Succeeded {
        return Err(DesktopError::Integrity(
            "Element Grounder did not return a successful typed result".to_owned(),
        ));
    }
    let payload = result_envelope.payload.ok_or_else(|| {
        DesktopError::Integrity("Element Grounder result payload is absent".to_owned())
    })?;
    let bytes =
        serde_json::to_vec(&payload).map_err(|error| DesktopError::Json(error.to_string()))?;
    let result = parse_element_grounding_result_strict(&bytes).map_err(selection_error)?;
    let selection = validate_element_grounding_result(
        pack,
        observation,
        semantic_target_id,
        &goal.goal_id,
        &plan.plan_generation_id,
        &result,
    )
    .map_err(selection_error)?;
    let semantic_sha256 = canonical_sha256(&result).map_err(selection_error)?;
    Ok(GroundingExecution {
        result,
        selection,
        semantic_sha256,
    })
}

fn empty_string_paths(value: &Value) -> Vec<String> {
    fn visit(value: &Value, path: &str, paths: &mut Vec<String>) {
        match value {
            Value::String(text) if text.is_empty() => paths.push(path.to_owned()),
            Value::Array(values) => {
                for (index, value) in values.iter().enumerate() {
                    visit(value, &format!("{path}/{index}"), paths);
                }
            }
            Value::Object(values) => {
                for (key, value) in values {
                    visit(value, &format!("{path}/{key}"), paths);
                }
            }
            _ => {}
        }
    }
    let mut paths = Vec::new();
    visit(value, "", &mut paths);
    paths
}

fn passed_gates() -> CandidateGateResultsV1 {
    CandidateGateResultsV1 {
        policy: GateStatusV1::Passed,
        activation: GateStatusV1::Passed,
        binding: GateStatusV1::Passed,
        input_schema: GateStatusV1::Passed,
        output_schema: GateStatusV1::Passed,
        risk: GateStatusV1::Passed,
        side_effect: GateStatusV1::Passed,
        network: GateStatusV1::Passed,
        credential: GateStatusV1::Passed,
        capability: GateStatusV1::Passed,
        quality: GateStatusV1::Passed,
    }
}

fn gate_evidence(label: &str) -> CandidateGateEvidenceV1 {
    CandidateGateEvidenceV1 {
        policy: vec![format!("{label}-policy")],
        activation: vec![format!("{label}-activation")],
        binding: vec![format!("{label}-binding")],
        input_schema: vec![format!("{label}-input-schema")],
        output_schema: vec![format!("{label}-output-schema")],
        risk: vec![format!("{label}-risk")],
        side_effect: vec![format!("{label}-side-effect")],
        network: vec![format!("{label}-network")],
        credential: vec![format!("{label}-credential")],
        capability: vec![format!("{label}-capability")],
        quality: vec![format!("{label}-quality")],
    }
}

struct SelectedActionExecution {
    ready: PolicyReadyActionV1,
    candidate_set_sha256: String,
    ranker_semantic_sha256: String,
    selected_action_sha256: String,
}

struct PolicyArtifacts {
    admission: d2i_policy_admission::CognitiveActivationAdmissionV1,
    eligibility: ActivationEligibilityContextV1,
    decision_sha256: String,
}

fn policy_artifacts(
    ready: &PolicyReadyActionV1,
    goal: &GoalSpec,
    activation: &d2i_desktop::TrustedPlatformActivationV1,
    instruction: &AuthenticatedTaskInstructionV1,
    now: u64,
    label: &str,
) -> Result<PolicyArtifacts, DesktopError> {
    let capability = ready.capability_id.clone();
    let authority = DelegatedAuthorityContextV1 {
        schema_version: POLICY_ADMISSION_SCHEMA_VERSION,
        authority_id: "authority-kernel-e2e".to_owned(),
        organization_id: ORGANIZATION_ID.to_owned(),
        actor_id: ACTOR_ID.to_owned(),
        role_id: ROLE_ID.to_owned(),
        policy_set_id: "policy-set-kernel-e2e".to_owned(),
        policy_set_version: "1.0.0".to_owned(),
        policy_set_sha256: digest("kernel-e2e-policy-set"),
        allowed_capability_ids: vec![capability.clone()],
        forbidden_capability_ids: Vec::new(),
        autonomous_capability_ids: vec![capability.clone()],
        confirmation_capability_ids: Vec::new(),
        maximum_autonomous_risk: CognitiveRiskClass::Reversible,
        maximum_confirmable_risk: CognitiveRiskClass::BusinessStateChange,
        allowed_application_pack_sha256: ready.application_pack_sha256.clone(),
        allowed_integration_ids: vec![activation.integration_id.clone()],
        scope_constraints: AuthorityScopeConstraintsV1 {
            application_pack_sha256: ready.application_pack_sha256.clone(),
            integration_ids: vec![activation.integration_id.clone()],
            semantic_target_ids: vec![ready.semantic_target_id.clone()],
        },
        valid_from_unix_seconds: now.saturating_sub(10),
        expires_at_unix_seconds: now.saturating_add(600),
        evidence_ids: vec!["authenticated-delegated-authority".to_owned()],
        authority_sha256: empty_hash(),
    }
    .seal()
    .map_err(selection_error)?;
    let policy = TrustedPolicySnapshotV1 {
        schema_version: POLICY_ADMISSION_SCHEMA_VERSION,
        policy_set_id: "policy-set-kernel-e2e".to_owned(),
        policy_set_version: "1.0.0".to_owned(),
        policy_set_sha256: digest("kernel-e2e-policy-set"),
        organization_id: ORGANIZATION_ID.to_owned(),
        policy_state: TrustedPolicyStateV1::Effective,
        allowed_risk_classes: vec![
            CognitiveRiskClass::ReadOnly,
            CognitiveRiskClass::Reversible,
            CognitiveRiskClass::BusinessStateChange,
        ],
        denied_capability_ids: Vec::new(),
        mandatory_confirmation_capability_ids: Vec::new(),
        mandatory_escalation_capability_ids: Vec::new(),
        forbidden_semantic_targets: Vec::new(),
        effective_from_unix_seconds: now.saturating_sub(10),
        expires_at_unix_seconds: now.saturating_add(600),
        evidence_ids: vec!["trusted-kernel-e2e-policy".to_owned()],
        snapshot_sha256: empty_hash(),
    }
    .seal()
    .map_err(selection_error)?;
    let request = PolicyEvaluationRequestV1::new(
        ready.clone(),
        goal.clone(),
        authority,
        policy,
        now,
        RequestedAutonomyModeV1::AutonomousPreferred,
    )
    .map_err(selection_error)?;
    let decision = evaluate_policy(&request).map_err(selection_error)?;
    let eligibility = ActivationEligibilityContextV1 {
        schema_version: POLICY_ADMISSION_SCHEMA_VERSION,
        eligibility_id: format!("eligibility-{label}"),
        organization_id: ORGANIZATION_ID.to_owned(),
        integration_id: activation.integration_id.clone(),
        application_pack_sha256: ready.application_pack_sha256.clone(),
        runtime_binding_id: activation.binding_id.clone(),
        runtime_binding_sha256: activation.runtime_binding_sha256.clone(),
        adapter_kind: AdapterKindV1::Uia,
        activation_scope_id: format!("activation-scope-{label}"),
        activation_ledger_id: activation.activation_ledger_id.clone(),
        activation_ledger_chain_head: activation.activation_ledger_chain_head.clone(),
        eligible_capability_ids: vec![capability],
        capability_binding_sha256: ready.capability_binding_sha256.clone(),
        source_observation_hash: ready.source_observation_hash.clone(),
        source_observation_sequence: ready.source_observation_sequence,
        observed_at_unix_seconds: now,
        expires_at_unix_seconds: now.saturating_add(300),
        evidence_ids: vec!["fresh-windows-activation-eligibility".to_owned()],
        eligibility_sha256: empty_hash(),
    }
    .seal()
    .map_err(selection_error)?;
    let mut ledger = GrantConsumptionLedgerV1::new();
    let (challenge, grant) = if decision.outcome == PolicyOutcomeV1::RequireConfirmation {
        let challenge = create_confirmation_challenge(
            &request,
            &decision,
            format!("challenge-{label}"),
            digest(&format!("challenge-nonce-{label}")),
            now,
            now.saturating_add(120),
        )
        .map_err(selection_error)?;
        let grant = ConfirmationGrantV1 {
            schema_version: POLICY_ADMISSION_SCHEMA_VERSION,
            grant_id: format!("grant-{label}"),
            challenge_id: challenge.challenge_id.clone(),
            challenge_sha256: challenge.challenge_sha256.clone(),
            decision_sha256: decision.decision_sha256.clone(),
            policy_ready_sha256: decision.policy_ready_sha256.clone(),
            proposal_sha256: decision.proposal_sha256.clone(),
            confirming_actor_id: ACTOR_ID.to_owned(),
            confirming_role_id: ROLE_ID.to_owned(),
            organization_id: ORGANIZATION_ID.to_owned(),
            granted_at_unix_seconds: now.saturating_add(1),
            expires_at_unix_seconds: now.saturating_add(120),
            confirmation_proof_sha256: instruction.instruction_sha256.clone(),
            one_time_use_id: format!("one-time-{label}"),
            evidence_ids: vec!["authenticated-instruction-preauthorization".to_owned()],
            grant_sha256: empty_hash(),
        }
        .seal()
        .map_err(selection_error)?;
        (Some(challenge), Some(grant))
    } else {
        (None, None)
    };
    let admission = admit_action(
        &request,
        &decision,
        challenge.as_ref(),
        grant.as_ref(),
        &eligibility,
        &mut ledger,
        AdmissionIssuanceV1 {
            admission_id: format!("admission-{label}"),
            admitted_at_unix_seconds: now.saturating_add(2),
            expires_at_unix_seconds: now.saturating_add(250),
            expected_runtime_binding_sha256: eligibility.runtime_binding_sha256.clone(),
            expected_activation_ledger_chain_head: eligibility.activation_ledger_chain_head.clone(),
            expected_adapter_kind: AdapterKindV1::Uia,
        },
    )
    .map_err(selection_error)?;
    Ok(PolicyArtifacts {
        admission,
        eligibility,
        decision_sha256: decision.decision_sha256,
    })
}

#[derive(Clone, Copy)]
enum ActionStepKind {
    SetName,
    Save,
}

impl ActionStepKind {
    const fn label(self) -> &'static str {
        match self {
            Self::SetName => "set-name",
            Self::Save => "save",
        }
    }

    const fn automation_id(self) -> &'static str {
        match self {
            Self::SetName => "employee-name-input",
            Self::Save => "save-button",
        }
    }

    const fn semantic_target(self) -> &'static str {
        match self {
            Self::SetName => "employee_name_input",
            Self::Save => "save_button",
        }
    }

    const fn target_text(self) -> &'static str {
        match self {
            Self::SetName => "Employee name input",
            Self::Save => "Save employee",
        }
    }

    const fn selection_step(self) -> &'static str {
        match self {
            Self::SetName => "select-name-capability",
            Self::Save => "select-save-capability",
        }
    }

    const fn action_kind(self) -> CandidateActionKind {
        match self {
            Self::SetName => CandidateActionKind::SetText,
            Self::Save => CandidateActionKind::Invoke,
        }
    }

    const fn risk(self) -> CognitiveRiskClass {
        match self {
            Self::SetName => CognitiveRiskClass::Reversible,
            Self::Save => CognitiveRiskClass::BusinessStateChange,
        }
    }
}

fn changed_element_value_fields(
    source: &ObservationSnapshot,
    fresh: &ObservationSnapshot,
    automation_id: &str,
) -> Result<String, DesktopError> {
    let source_value = &element_by_automation_id(source, automation_id)?.value;
    let fresh_value = &element_by_automation_id(fresh, automation_id)?.value;
    let (Some(source_fields), Some(fresh_fields)) =
        (source_value.as_object(), fresh_value.as_object())
    else {
        return Ok("non-object".to_owned());
    };
    let keys = source_fields
        .keys()
        .chain(fresh_fields.keys())
        .collect::<BTreeSet<_>>();
    let changed = keys
        .into_iter()
        .filter(|key| source_fields.get(*key) != fresh_fields.get(*key))
        .cloned()
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        "{};focused={:?}->{:?};current={}->{}",
        changed,
        source_value.pointer("/focused").and_then(Value::as_bool),
        fresh_value.pointer("/focused").and_then(Value::as_bool),
        safe_current_value_summary(source_value),
        safe_current_value_summary(fresh_value)
    ))
}

fn safe_current_value_summary(value: &Value) -> String {
    let current = value.pointer("/current_value");
    let status = current
        .and_then(|value| value.pointer("/status"))
        .and_then(Value::as_str)
        .unwrap_or("absent");
    let text_hash = current
        .and_then(|value| value.pointer("/value/text_hash"))
        .and_then(Value::as_str)
        .unwrap_or("absent");
    let text_len = current
        .and_then(|value| value.pointer("/value/text"))
        .and_then(Value::as_str)
        .map(str::len)
        .map_or_else(|| "absent".to_owned(), |value| value.to_string());
    let truncated = current
        .and_then(|value| value.pointer("/value/truncated"))
        .and_then(Value::as_bool)
        .map_or_else(|| "absent".to_owned(), |value| value.to_string());
    format!("{status}:{text_hash}:{text_len}:{truncated}")
}

fn verification_verdict(value: VerificationVerdictV2) -> FinalVerificationVerdictV1 {
    match value {
        VerificationVerdictV2::Passed => FinalVerificationVerdictV1::Passed,
        VerificationVerdictV2::Unsafe => FinalVerificationVerdictV1::Unsafe,
        VerificationVerdictV2::Failed
        | VerificationVerdictV2::Inconclusive
        | VerificationVerdictV2::Unsupported => FinalVerificationVerdictV1::Failed,
    }
}

fn action_expectations(
    source: &ObservationSnapshot,
    step: ActionStepKind,
) -> Result<(Vec<Postcondition>, Vec<VerificationGuardTargetV1>), DesktopError> {
    let mut postconditions = Vec::new();
    let mut targets = Vec::new();
    match step {
        ActionStepKind::SetName => {
            let element = element_by_automation_id(source, "employee-name-input")?;
            let expected_value = expected_text_value(element, EXPECTED_NAME)?;
            postconditions.push(exact_current_value_postcondition(element, &expected_value)?);
            targets.push(VerificationGuardTargetV1 {
                element_id: element.element_id.clone(),
                field: VerificationGuardFieldV1::Value,
            });
        }
        ActionStepKind::Save => {
            for (automation_id, expected) in [
                ("saved-name", EXPECTED_NAME.to_owned()),
                ("save-status", "saved".to_owned()),
            ] {
                let element = element_by_automation_id(source, automation_id)?;
                postconditions.push(exact_current_value_postcondition(
                    element,
                    &expected_text_value(element, &expected)?,
                )?);
                targets.push(VerificationGuardTargetV1 {
                    element_id: element.element_id.clone(),
                    field: VerificationGuardFieldV1::Value,
                });
            }
            let revision = element_by_automation_id(source, "save-revision")?;
            let current = observed_text(revision)
                .ok_or_else(|| DesktopError::Integrity("save revision is not readable".to_owned()))?
                .parse::<u64>()
                .map_err(|error| DesktopError::Integrity(error.to_string()))?;
            postconditions.push(exact_current_value_postcondition(
                revision,
                &expected_text_value(revision, &current.saturating_add(1).to_string())?,
            )?);
            targets.push(VerificationGuardTargetV1 {
                element_id: revision.element_id.clone(),
                field: VerificationGuardFieldV1::Value,
            });
        }
    }
    Ok((postconditions, targets))
}

#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
fn run_action_cycle(
    args: &RunnerArgs,
    temp: &TempRoot,
    modules: &mut ModuleInvocationCoordinatorV1,
    configuration: &WindowsAdapterConfiguration,
    target_template: &WindowsUiaObservationTarget,
    source_snapshot: &ObservationSnapshot,
    instruction: &AuthenticatedTaskInstructionV1,
    goal: &GoalSpec,
    pack: &ApplicationPack,
    plan: &PlanGraph,
    step: ActionStepKind,
    label: &str,
    action_sequence: u64,
    now: u64,
) -> Result<CycleExecution, DesktopError> {
    let now_ms = now
        .saturating_mul(1_000)
        .saturating_add(action_sequence.saturating_mul(20_000));
    let (execution_admission, session_id, activation_audit_head) =
        certified_admission_labeled(configuration, temp, now, &format!("{label}-mutation"))?;
    let platform_activation = project_windows_activation(&execution_admission, configuration)?;
    let source = bind_actual_source_observation(source_snapshot, &platform_activation)?;
    let grounding = invoke_grounder(
        args,
        modules,
        pack,
        &source,
        goal,
        plan,
        step.semantic_target(),
        step.target_text(),
        label,
        20 + action_sequence.saturating_mul(10),
    )?;
    if grounding.result.status != GroundingStatusV1::UniqueMatch || grounding.selection.is_none() {
        return Err(DesktopError::Precondition(
            "action cycle requires one exact Element Grounder match".to_owned(),
        ));
    }
    let (expected_postconditions, expected_targets) = action_expectations(&source, step)?;
    let input = match step {
        ActionStepKind::SetName => CandidateActionInput::SetText {
            text_hash: sha(EXPECTED_NAME.as_bytes()),
        },
        ActionStepKind::Save => CandidateActionInput::Invoke,
    };
    let selected = select_actual_action(
        args,
        modules,
        pack,
        &source,
        &grounding,
        goal,
        plan,
        step.selection_step(),
        step.semantic_target(),
        step.action_kind(),
        input,
        expected_postconditions.clone(),
        step.risk(),
        label,
        21 + action_sequence.saturating_mul(10),
    )?;
    let proposal_sha256 =
        trusted_execution_sha256(&selected.ready.proposal).map_err(selection_error)?;
    let grounded_target_sha256 =
        grounded_target_binding_sha256(&selected.ready).map_err(selection_error)?;
    let policy = policy_artifacts(
        &selected.ready,
        goal,
        &platform_activation,
        instruction,
        now,
        label,
    )
    .map_err(selection_error)?;
    let admission_sha256 = policy.admission.admission_sha256.clone();
    let session = TrustedExecutionSessionV1 {
        schema_version: TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION,
        execution_session_id: format!("kernel-e2e-session-{label}"),
        action_sequence,
        runtime_build_id: KERNEL_TASK_RUNTIME_BUILD_ID.to_owned(),
        runtime_package_sha256: digest("kernel-e2e-runtime-package"),
        generated_at_unix_ms: now_ms.saturating_add(1_000),
        expires_at_unix_ms: now_ms.saturating_add(120_000),
        expected_organization_id: ORGANIZATION_ID.to_owned(),
        expected_integration_id: platform_activation.integration_id.clone(),
        expected_adapter_kind: AdapterKindV1::Uia,
        expected_activation_ledger_id: platform_activation.activation_ledger_id.clone(),
        expected_activation_ledger_chain_head: platform_activation
            .activation_ledger_chain_head
            .clone(),
        evidence_ids: vec![format!("runtime-package-{label}")],
        session_sha256: empty_hash(),
    }
    .seal()
    .map_err(selection_error)?;
    let execution_binding = TrustedExecutionBindingRequestV1::new(
        selected.ready.clone(),
        policy.admission,
        policy.eligibility,
        session,
        platform_activation.clone(),
        &source,
        grounded_target_sha256,
    )
    .map_err(selection_error)?;
    let mutation_audit_root = temp.path().join(format!("{label}-mutation-audit"));
    let mutation_audit = initialize_windows_deployment_audit(
        &mutation_audit_root,
        &format!("{label}-mutation-audit"),
        &format!("kernel-e2e-session-{label}"),
        64,
        now_ms.max(1),
    )?;
    let payload = match step {
        ActionStepKind::SetName => Some(
            EphemeralActionPayload::new(
                format!("public-text-input-{label}"),
                EXPECTED_NAME.as_bytes().to_vec(),
                now_ms.saturating_add(1_000),
                now_ms.saturating_add(60_000),
            )
            .map_err(selection_error)?,
        ),
        ActionStepKind::Save => None,
    };
    let input_sha256 = match step {
        ActionStepKind::SetName => sha(EXPECTED_NAME.as_bytes()),
        ActionStepKind::Save => empty_hash(),
    };
    let mut executor = CognitiveTrustedExecutionCoordinator::bind(
        execution_binding.clone(),
        &source,
        execution_admission,
        configuration.clone(),
        TrustedTargetResolverInput::Uia {
            target: WindowsUiaObservationTarget {
                session_id,
                runtime_binding_digest: configuration.configuration_hash()?,
                ..target_template.clone()
            },
        },
        payload,
        mutation_audit,
        now_ms.saturating_add(2_000),
    )?;
    let mutation_worker_id = executor.owned_worker_process_id().ok_or_else(|| {
        DesktopError::Integrity("mutation worker process identity is absent".to_owned())
    })?;
    let preparation = executor.prepare(now_ms.saturating_add(3_000))?;
    let receipt = executor.commit(&preparation, now_ms.saturating_add(4_000))?;
    if receipt.status != TrustedExecutionStatusV1::Succeeded {
        return Err(DesktopError::Integrity(
            "one-shot trusted execution did not succeed".to_owned(),
        ));
    }
    let execution = to_verification_bound_execution_v2(&receipt)?;
    drop(executor);
    if process_exists(mutation_worker_id) {
        return Err(DesktopError::Integrity(
            "mutation worker remained after one-shot execution".to_owned(),
        ));
    }
    wait_for_fixture_transition(temp, args.mode, step, action_sequence)?;
    let mutation_audit_head =
        verify_windows_deployment_audit(&mutation_audit_root)?.terminal_record_hash;

    let expected_postcondition_hashes = expected_postconditions
        .iter()
        .filter_map(|value| value.expected_value.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let verification_goal = GoalSpec {
        success_criteria: expected_postconditions,
        ..goal.clone()
    };
    verification_goal.validate().map_err(selection_error)?;
    let reobservation_request = ReobservationRequestV1::new(
        &execution_binding,
        &receipt,
        &execution,
        &source,
        now_ms.saturating_add(5_000),
        now_ms.saturating_add(90_000),
    )?;
    let protected = element_by_automation_id(&source, "protected-checkbox")?;
    let mut ignored_volatile_targets = source
        .observable_elements
        .iter()
        .filter(|element| {
            element
                .value
                .pointer("/focused")
                .and_then(Value::as_bool)
                .is_some()
        })
        .map(|element| IgnoredVolatileTargetV1 {
            target: VerificationGuardTargetV1 {
                element_id: element.element_id.clone(),
                field: VerificationGuardFieldV1::Focus,
            },
            approved_reason_code: "windows-uia-focus-volatile".to_owned(),
            evidence_id: "windows-uia-observation-contract".to_owned(),
        })
        .collect::<Vec<_>>();
    ignored_volatile_targets.push(IgnoredVolatileTargetV1 {
        target: VerificationGuardTargetV1 {
            element_id: "observation.status".to_owned(),
            field: VerificationGuardFieldV1::Value,
        },
        approved_reason_code: "bounded-observation-metrics-volatile".to_owned(),
        evidence_id: "windows-observation-contract".to_owned(),
    });
    let guard = VerificationGuardProfileV1::new(
        format!("guard-{label}"),
        &selected.ready.proposal,
        &source,
        expected_targets,
        Vec::new(),
        vec![ProtectedInvariantV1 {
            target: VerificationGuardTargetV1 {
                element_id: protected.element_id.clone(),
                field: VerificationGuardFieldV1::Value,
            },
            expected_source_value_hash: trusted_execution_sha256(&protected.value)
                .map_err(selection_error)?,
            severity: ProtectedInvariantSeverityV1::Unsafe,
            reason_code: "protected-checkbox-stable".to_owned(),
        }],
        ignored_volatile_targets,
        0,
        vec![format!("actual-kernel-cycle-{label}")],
    )?;
    let (fresh_admission, fresh_session_id, fresh_activation_head) =
        certified_admission_labeled(configuration, temp, now, &format!("{label}-observer"))?;
    let fresh_adapter = WindowsUiAutomationAdapter::bind(
        fresh_admission.activation,
        configuration.clone(),
        now.saturating_add(2),
    )?;
    let fresh_audit_root = temp.path().join(format!("{label}-observation-audit"));
    let fresh_audit = initialize_windows_deployment_audit(
        &fresh_audit_root,
        &format!("{label}-observation-audit"),
        &format!("{label}-observation-session"),
        64,
        now_ms.max(1),
    )?;
    let fresh_provider = WindowsUiaObservationProvider::new(
        fresh_adapter,
        WindowsUiaObservationTarget {
            session_id: fresh_session_id,
            runtime_binding_digest: configuration.configuration_hash()?,
            ..target_template.clone()
        },
        ObservationLimits::default(),
        fresh_audit,
    )?;
    let verification_audit_root = temp.path().join(format!("{label}-verification-audit"));
    let verification_audit = initialize_windows_deployment_audit(
        &verification_audit_root,
        &format!("{label}-verification-audit"),
        &format!("kernel-e2e-session-{label}"),
        64,
        now_ms.max(1),
    )?;
    let mut consumption = VerificationConsumptionLedgerV1::default();
    let mut verifier = CognitiveVerificationCoordinatorV2::begin(
        execution_binding,
        verification_goal,
        selected.ready.clone(),
        receipt.clone(),
        execution,
        source.clone(),
        reobservation_request,
        guard,
        verification_audit,
        &mut consumption,
        now_ms.saturating_add(5_000),
    )?;
    verifier.reobserve(
        TrustedReadOnlyObservationConfiguration::Uia(fresh_provider),
        now_ms.saturating_add(6_000),
    )?;
    let fresh = verifier.fresh_observation().cloned().ok_or_else(|| {
        DesktopError::Integrity("fresh verification observation is absent".to_owned())
    })?;
    let changed_value_fields = changed_element_value_fields(&source, &fresh, step.automation_id())?;
    let fresh_worker_id = verifier.observation_worker_process_id().ok_or_else(|| {
        DesktopError::Integrity("verification worker process identity is absent".to_owned())
    })?;
    let delta = verifier
        .analyze_delta(now_ms.saturating_add(7_000))?
        .clone();
    let unexpected_delta_targets = delta
        .unexpected_changes
        .iter()
        .chain(delta.security_relevant_changes.iter())
        .chain(delta.protected_invariant_violations.iter())
        .map(|change| {
            change.target.as_ref().map_or_else(
                || format!("observation:{:?}", change.kind),
                |target| format!("{}:{:?}", target.element_id, target.field),
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    verifier.build_verification_request()?;
    let verified = verifier.verify(now_ms.saturating_add(8_000))?.clone();
    let verification_diagnostic = format!(
        "reason={}; expected=[{}]; postconditions=[{}]; changed_fields=[{}]; unexpected_changes={}:{}",
        verified.reason,
        expected_postcondition_hashes,
        verified
            .action_postcondition_results
            .iter()
            .map(|result| {
                let observed_sha256 = result
                    .observed_value
                    .as_ref()
                    .and_then(|value| trusted_execution_sha256(value).ok())
                    .unwrap_or_else(|| "absent".to_owned());
                format!(
                    "{}:{}:{}:{}",
                    result.criterion_id,
                    result.verdict == VerificationVerdictV2::Passed,
                    result.reason,
                    observed_sha256
                )
            })
            .collect::<Vec<_>>()
            .join(","),
        changed_value_fields,
        verified.unexpected_changes.len(),
        unexpected_delta_targets,
    );
    let terminal = verifier.finalize(now_ms.saturating_add(9_000))?;
    drop(verifier);
    if process_exists(fresh_worker_id) || verified.action_verdict != terminal.action_verdict {
        return Err(DesktopError::Integrity(
            "verification worker cleanup or terminal verdict binding failed".to_owned(),
        ));
    }
    let observation_audit_head =
        verify_windows_deployment_audit(&fresh_audit_root)?.terminal_record_hash;
    let verification_audit_head =
        verify_windows_deployment_audit(&verification_audit_root)?.terminal_record_hash;
    let record = ActionCycleRecordV1 {
        schema_version: KERNEL_TASK_SCHEMA_VERSION,
        cycle_id: format!("cycle-{label}"),
        step_id: step.selection_step().to_owned(),
        source_observation_sha256: source.state_hash.clone(),
        grounder_result_sha256: grounding.semantic_sha256.clone(),
        candidate_set_sha256: selected.candidate_set_sha256.clone(),
        ranker_result_sha256: selected.ranker_semantic_sha256.clone(),
        selected_action_sha256: selected.selected_action_sha256.clone(),
        policy_decision_sha256: policy.decision_sha256.clone(),
        cognitive_admission_sha256: admission_sha256.clone(),
        windows_activation_record_sha256: platform_activation.activation_record_hash.clone(),
        execution_receipt_sha256: receipt.receipt_sha256.clone(),
        verified_action_result_sha256: terminal.result_sha256.clone(),
        verification_verdict: verification_verdict(terminal.action_verdict),
        completed: terminal.action_verdict == VerificationVerdictV2::Passed,
        evidence_ids: vec![
            "actual-module-grounding".to_owned(),
            "actual-module-ranking".to_owned(),
            "actual-one-shot-windows-execution".to_owned(),
            "fresh-independent-verification".to_owned(),
        ],
        cycle_sha256: empty_hash(),
    }
    .seal()?;
    Ok(CycleExecution {
        source,
        fresh,
        proposal_id: selected.ready.proposal.proposal_id,
        proposal_sha256,
        plan_generation_id: selected.ready.proposal.plan_generation_id,
        capability_id: selected.ready.capability_id,
        input_sha256,
        policy_decision_sha256: policy.decision_sha256,
        admission_sha256,
        activation_record_hash: platform_activation.activation_record_hash,
        receipt_sha256: receipt.receipt_sha256,
        verified_result_sha256: terminal.result_sha256,
        verdict: terminal.action_verdict,
        verification_diagnostic,
        record,
        audit_chain_heads: vec![
            activation_audit_head,
            mutation_audit_head,
            fresh_activation_head,
            observation_audit_head,
            verification_audit_head,
        ],
    })
}

fn recovery_budget(goal_id: &str, now_ms: u64) -> Result<RecoveryBudgetV1, DesktopError> {
    RecoveryBudgetV1 {
        schema_version: RECOVERY_SCHEMA_VERSION,
        budget_id: "kernel-e2e-recovery-budget".to_owned(),
        goal_id: goal_id.to_owned(),
        maximum_total_cycles: 3,
        remaining_total_cycles: 3,
        maximum_reobservations: 1,
        remaining_reobservations: 1,
        maximum_fresh_retries: 1,
        remaining_fresh_retries: 1,
        maximum_alternate_capability_attempts: 1,
        remaining_alternate_capability_attempts: 1,
        maximum_replans: 1,
        remaining_replans: 1,
        maximum_clarifications: 1,
        remaining_clarifications: 1,
        started_at_unix_ms: now_ms,
        deadline_unix_ms: now_ms.saturating_add(180_000),
        evidence_ids: vec!["bounded-kernel-e2e-recovery".to_owned()],
        budget_sha256: empty_hash(),
    }
    .seal()
    .map_err(selection_error)
}

fn recovery_profile() -> Result<RecoveryPolicyProfileV1, DesktopError> {
    RecoveryPolicyProfileV1 {
        schema_version: RECOVERY_SCHEMA_VERSION,
        profile_id: "kernel-e2e-recovery-profile".to_owned(),
        policy_set_sha256: digest("kernel-e2e-policy-set"),
        authority_sha256: digest("kernel-e2e-recovery-authority"),
        retryable_failure_classes: vec![RecoveryFailureClassV1::PostconditionFailed],
        reobservable_failure_classes: vec![RecoveryFailureClassV1::VerificationInconclusive],
        alternate_capability_failure_classes: vec![RecoveryFailureClassV1::PostconditionFailed],
        replannable_failure_classes: vec![RecoveryFailureClassV1::PostconditionFailed],
        clarifiable_failure_classes: Vec::new(),
        mandatory_escalation_failure_classes: vec![
            RecoveryFailureClassV1::ProtectedInvariantViolation,
            RecoveryFailureClassV1::UnsafeSideEffect,
        ],
        forbidden_automatic_failure_classes: vec![
            RecoveryFailureClassV1::ProtectedInvariantViolation,
            RecoveryFailureClassV1::UnsafeSideEffect,
        ],
        retryable_capability_ids: vec!["uia.invoke".to_owned()],
        alternate_capability_groups: vec![AlternateCapabilityGroupV1 {
            group_id: "windows-save".to_owned(),
            capability_ids: vec!["uia.invoke".to_owned()],
        }],
        maximum_same_capability_attempts: 2,
        allow_replan: true,
        allow_clarification: true,
        escalation_risk_threshold: CognitiveRiskClass::HighCriticality,
        evidence_ids: vec!["trusted-kernel-e2e-recovery-policy".to_owned()],
        profile_sha256: empty_hash(),
    }
    .seal()
    .map_err(selection_error)
}

fn recovery_trigger(
    goal: &GoalSpec,
    cycle: &CycleExecution,
    unsafe_failure: bool,
    now_ms: u64,
) -> Result<RecoveryTriggerV1, DesktopError> {
    RecoveryTriggerV1 {
        schema_version: RECOVERY_SCHEMA_VERSION,
        trigger_id: if unsafe_failure {
            "kernel-e2e-unsafe-trigger".to_owned()
        } else {
            "kernel-e2e-retry-trigger".to_owned()
        },
        stage: RecoveryStageV1::Verification,
        goal_id: goal.goal_id.clone(),
        plan_generation_id: Some(cycle.plan_generation_id.clone()),
        proposal_id: Some(cycle.proposal_id.clone()),
        proposal_sha256: Some(cycle.proposal_sha256.clone()),
        capability_id: Some(cycle.capability_id.clone()),
        source_observation_id: cycle.source.observation_id.clone(),
        source_observation_hash: cycle.source.state_hash.clone(),
        source_observation_sequence: cycle.source.sequence,
        fresh_observation_id: Some(cycle.fresh.observation_id.clone()),
        fresh_observation_hash: Some(cycle.fresh.state_hash.clone()),
        fresh_observation_sequence: Some(cycle.fresh.sequence),
        execution_receipt_sha256: Some(cycle.receipt_sha256.clone()),
        verified_action_result_sha256: Some(cycle.verified_result_sha256.clone()),
        policy_decision_sha256: Some(cycle.policy_decision_sha256.clone()),
        activation_admission_sha256: Some(cycle.admission_sha256.clone()),
        reason_codes: vec![if unsafe_failure {
            RecoveryReasonCodeV1::ProtectedInvariantViolation
        } else {
            RecoveryReasonCodeV1::PostconditionFailed
        }],
        evidence_ids: vec![if unsafe_failure {
            "actual-protected-invariant-violation".to_owned()
        } else {
            "actual-save-postcondition-failure".to_owned()
        }],
        detected_at_unix_ms: now_ms,
        trigger_sha256: empty_hash(),
    }
    .seal()
    .map_err(selection_error)
}

fn initial_recovery_history(
    goal: &GoalSpec,
    trigger: &RecoveryTriggerV1,
    cycle: &CycleExecution,
) -> Result<RecoveryHistoryV1, DesktopError> {
    let classification =
        d2i_desktop::classify_recovery_trigger(trigger).map_err(selection_error)?;
    let history = RecoveryHistoryV1::empty(
        "kernel-e2e-recovery-history".to_owned(),
        goal.goal_id.clone(),
    )
    .map_err(selection_error)?;
    history
        .append(
            RecoveryHistoryEntryV1 {
                schema_version: RECOVERY_SCHEMA_VERSION,
                cycle_index: 1,
                trigger_sha256: trigger.trigger_sha256.clone(),
                classification_sha256: classification.classification_sha256,
                decision_sha256: digest("initial-action-decision"),
                plan_generation_id: Some(cycle.plan_generation_id.clone()),
                proposal_id: Some(cycle.proposal_id.clone()),
                proposal_sha256: Some(cycle.proposal_sha256.clone()),
                capability_id: Some(cycle.capability_id.clone()),
                input_sha256: Some(cycle.input_sha256.clone()),
                source_observation_hash: cycle.source.state_hash.clone(),
                source_observation_sequence: cycle.source.sequence,
                fresh_observation_hash: Some(cycle.fresh.state_hash.clone()),
                fresh_observation_sequence: Some(cycle.fresh.sequence),
                policy_decision_sha256: Some(cycle.policy_decision_sha256.clone()),
                cognitive_admission_sha256: Some(cycle.admission_sha256.clone()),
                activation_record_hash: Some(cycle.activation_record_hash.clone()),
                execution_receipt_sha256: Some(cycle.receipt_sha256.clone()),
                verified_action_result_sha256: Some(cycle.verified_result_sha256.clone()),
                terminal_outcome: RecoveryHistoryOutcomeV1::Failed,
                evidence_ids: vec!["actual-first-save-cycle".to_owned()],
                entry_sha256: empty_hash(),
            }
            .seal()
            .map_err(selection_error)?,
        )
        .map_err(selection_error)
}

struct RecoveryExecution {
    cycle: Option<CycleExecution>,
    trigger_sha256: String,
    decision_sha256: String,
    result_sha256: String,
    audit_chain_head: String,
}

#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
fn run_fresh_save_recovery(
    args: &RunnerArgs,
    temp: &TempRoot,
    modules: &mut ModuleInvocationCoordinatorV1,
    configuration: &WindowsAdapterConfiguration,
    target: &WindowsUiaObservationTarget,
    first: &CycleExecution,
    instruction: &AuthenticatedTaskInstructionV1,
    goal: &GoalSpec,
    pack: &ApplicationPack,
    plan: &PlanGraph,
    now: u64,
) -> Result<RecoveryExecution, DesktopError> {
    let now_ms = now.saturating_mul(1_000).saturating_add(70_000);
    let trigger = recovery_trigger(goal, first, false, now_ms)?;
    let history = initial_recovery_history(goal, &trigger, first)?;
    let ledger_root = temp.path().join("recovery-ledger");
    let ledger = initialize_recovery_ledger(
        &ledger_root,
        "kernel-e2e-recovery-ledger",
        "kernel-e2e-recovery-session",
        &goal.goal_id,
        64,
        now_ms,
    )?;
    let audit_root = temp.path().join("recovery-audit");
    let audit = initialize_windows_deployment_audit(
        &audit_root,
        "kernel-e2e-recovery-audit",
        "kernel-e2e-recovery-session",
        128,
        now_ms,
    )?;
    let mut coordinator = CognitiveRecoveryCoordinatorV1::restore(
        goal.goal_id.clone(),
        plan.plan_generation_id.clone(),
        recovery_budget(&goal.goal_id, now_ms)?,
        history,
        recovery_profile()?,
        ledger,
        audit,
    )?;
    coordinator.begin(trigger.clone(), now_ms.saturating_add(1))?;
    coordinator.classify(now_ms.saturating_add(2))?;
    let decision = coordinator
        .decide(
            &RecoveryDecisionContextV1 {
                verification_verdict: Some(RecoveryVerificationVerdictV1::Failed),
                goal_progress: GoalProgress::InProgress,
                latest_observation_trusted: true,
                bounded_user_fact_missing: false,
                same_failure_count: 1,
                same_capability_attempts: 1,
                current_proposal_id: Some(first.proposal_id.clone()),
                current_proposal_sha256: Some(first.proposal_sha256.clone()),
                current_capability_id: Some(first.capability_id.clone()),
                current_risk: CognitiveRiskClass::BusinessStateChange,
                alternate_capability_ids: Vec::new(),
                replan_available: true,
            },
            now_ms.saturating_add(3),
        )?
        .clone();
    if decision.decision_kind != RecoveryDecisionKindV1::RetryFreshCycle {
        return Err(DesktopError::Integrity(
            "bounded postcondition failure did not select a fresh retry".to_owned(),
        ));
    }
    let request = FreshRecoveryCycleRequestV1::from_decision(
        "kernel-e2e-recovery-cycle-2".to_owned(),
        &decision,
        goal.goal_id.clone(),
        plan.plan_generation_id.clone(),
        Some(first.proposal_sha256.clone()),
        Some(first.capability_id.clone()),
        first.fresh.observation_id.clone(),
        first.fresh.state_hash.clone(),
        first.fresh.sequence,
        coordinator.history(),
        digest("kernel-e2e-recovery-authority"),
        digest("kernel-e2e-policy-set"),
        now_ms.saturating_add(4),
        now_ms.saturating_add(120_000),
        vec!["actual-fresh-save-retry".to_owned()],
    )
    .map_err(selection_error)?;
    let mut second = None;
    let result = coordinator.execute_fresh_cycle(&request, now_ms.saturating_add(5), || {
        let cycle = run_action_cycle(
            args,
            temp,
            modules,
            configuration,
            target,
            &first.fresh,
            instruction,
            goal,
            pack,
            plan,
            ActionStepKind::Save,
            "save-recovery-2",
            3,
            now,
        )?;
        let evidence = FreshRecoveryCycleEvidenceV1 {
            schema_version: RECOVERY_SCHEMA_VERSION,
            cycle_request_sha256: request.cycle_request_sha256.clone(),
            observation_id: cycle.fresh.observation_id.clone(),
            observation_hash: cycle.fresh.state_hash.clone(),
            observation_sequence: cycle.fresh.sequence,
            plan_generation_id: cycle.plan_generation_id.clone(),
            proposal_id: cycle.proposal_id.clone(),
            proposal_sha256: cycle.proposal_sha256.clone(),
            capability_id: cycle.capability_id.clone(),
            input_sha256: cycle.input_sha256.clone(),
            policy_decision_sha256: cycle.policy_decision_sha256.clone(),
            cognitive_admission_sha256: cycle.admission_sha256.clone(),
            activation_record_hash: cycle.activation_record_hash.clone(),
            execution_receipt_sha256: cycle.receipt_sha256.clone(),
            verified_action_result_sha256: cycle.verified_result_sha256.clone(),
            verification_verdict: match cycle.verdict {
                VerificationVerdictV2::Passed => RecoveryVerificationVerdictV1::Passed,
                VerificationVerdictV2::Failed => RecoveryVerificationVerdictV1::Failed,
                VerificationVerdictV2::Inconclusive => RecoveryVerificationVerdictV1::Inconclusive,
                VerificationVerdictV2::Unsupported => RecoveryVerificationVerdictV1::Unsupported,
                VerificationVerdictV2::Unsafe => RecoveryVerificationVerdictV1::Unsafe,
            },
        };
        second = Some(cycle);
        Ok(evidence)
    })?;
    let second = second.ok_or_else(|| {
        DesktopError::Integrity("fresh recovery cycle did not retain its result".to_owned())
    })?;
    if second.verdict != VerificationVerdictV2::Passed
        || coordinator.budget().remaining_fresh_retries != 0
        || coordinator.history().entries.len() != 2
    {
        return Err(DesktopError::Integrity(
            "fresh recovery did not consume exactly one retry and pass".to_owned(),
        ));
    }
    let ledger_verification = verify_recovery_ledger(&ledger_root)?;
    let audit_verification = verify_windows_deployment_audit(&audit_root)?;
    if ledger_verification.record_count == 0 {
        return Err(DesktopError::Integrity(
            "recovery ledger remained empty".to_owned(),
        ));
    }
    Ok(RecoveryExecution {
        cycle: Some(second),
        trigger_sha256: trigger.trigger_sha256,
        decision_sha256: decision.decision_sha256,
        result_sha256: result.result_sha256,
        audit_chain_head: audit_verification.terminal_record_hash,
    })
}

#[cfg(windows)]
fn run_unsafe_escalation(
    temp: &TempRoot,
    cycle: &CycleExecution,
    goal: &GoalSpec,
    plan: &PlanGraph,
    now: u64,
) -> Result<RecoveryExecution, DesktopError> {
    let now_ms = now.saturating_mul(1_000).saturating_add(90_000);
    let trigger = recovery_trigger(goal, cycle, true, now_ms)?;
    let ledger_root = temp.path().join("unsafe-recovery-ledger");
    let ledger = initialize_recovery_ledger(
        &ledger_root,
        "kernel-e2e-unsafe-ledger",
        "kernel-e2e-unsafe-session",
        &goal.goal_id,
        64,
        now_ms,
    )?;
    let audit_root = temp.path().join("unsafe-recovery-audit");
    let audit = initialize_windows_deployment_audit(
        &audit_root,
        "kernel-e2e-unsafe-audit",
        "kernel-e2e-unsafe-session",
        64,
        now_ms,
    )?;
    let mut coordinator = CognitiveRecoveryCoordinatorV1::restore(
        goal.goal_id.clone(),
        plan.plan_generation_id.clone(),
        recovery_budget(&goal.goal_id, now_ms)?,
        RecoveryHistoryV1::empty("kernel-e2e-unsafe-history".to_owned(), goal.goal_id.clone())
            .map_err(selection_error)?,
        recovery_profile()?,
        ledger,
        audit,
    )?;
    coordinator.begin(trigger.clone(), now_ms.saturating_add(1))?;
    coordinator.classify(now_ms.saturating_add(2))?;
    let decision = coordinator
        .decide(
            &RecoveryDecisionContextV1 {
                verification_verdict: Some(RecoveryVerificationVerdictV1::Unsafe),
                goal_progress: GoalProgress::InProgress,
                latest_observation_trusted: true,
                bounded_user_fact_missing: false,
                same_failure_count: 1,
                same_capability_attempts: 1,
                current_proposal_id: Some(cycle.proposal_id.clone()),
                current_proposal_sha256: Some(cycle.proposal_sha256.clone()),
                current_capability_id: Some(cycle.capability_id.clone()),
                current_risk: CognitiveRiskClass::BusinessStateChange,
                alternate_capability_ids: Vec::new(),
                replan_available: true,
            },
            now_ms.saturating_add(3),
        )?
        .clone();
    if decision.decision_kind != RecoveryDecisionKindV1::Escalate {
        return Err(DesktopError::Integrity(
            "unsafe verification did not require escalation".to_owned(),
        ));
    }
    let escalation = EscalationRequestV1 {
        schema_version: RECOVERY_SCHEMA_VERSION,
        escalation_id: "kernel-e2e-unsafe-escalation".to_owned(),
        recovery_decision_sha256: decision.decision_sha256.clone(),
        goal_id: goal.goal_id.clone(),
        severity: EscalationSeverityV1::Critical,
        reason_codes: vec![RecoveryReasonCodeV1::ProtectedInvariantViolation],
        originating_stage: RecoveryStageV1::Verification,
        required_authority_class: RequiredAuthorityClassV1::SecurityOwner,
        blocked_capability_ids: vec![cycle.capability_id.clone()],
        policy_set_sha256: digest("kernel-e2e-policy-set"),
        authority_sha256: digest("kernel-e2e-recovery-authority"),
        latest_observation_hash: cycle.fresh.state_hash.clone(),
        verified_action_result_sha256: Some(cycle.verified_result_sha256.clone()),
        protected_violation_count: 1,
        unexpected_change_count: 0,
        safe_state_summary_codes: vec![
            SafeStateSummaryCodeV1::AutomaticMutationBlocked,
            SafeStateSummaryCodeV1::ProtectedInvariantViolated,
        ],
        recommended_next_action_codes: vec![RecommendedNextActionCodeV1::InspectProtectedEvidence],
        evidence_ids: vec!["actual-unsafe-save-verification".to_owned()],
        raised_at_unix_ms: now_ms.saturating_add(4),
        escalation_sha256: empty_hash(),
    }
    .seal()
    .map_err(selection_error)?;
    let result = coordinator.escalate(&escalation, now_ms.saturating_add(4))?;
    let ledger_verification = verify_recovery_ledger(&ledger_root)?;
    let audit_verification = verify_windows_deployment_audit(&audit_root)?;
    if !ledger_verification.terminal {
        return Err(DesktopError::Integrity(
            "unsafe escalation did not terminate the recovery ledger".to_owned(),
        ));
    }
    Ok(RecoveryExecution {
        cycle: None,
        trigger_sha256: trigger.trigger_sha256,
        decision_sha256: decision.decision_sha256,
        result_sha256: result.result_sha256,
        audit_chain_head: audit_verification.terminal_record_hash,
    })
}

fn final_criterion(
    criterion_id: &str,
    passed: bool,
    observed: &Value,
    reason_code: &str,
    observation_id: &str,
) -> Result<FinalCriterionResultV1, DesktopError> {
    Ok(FinalCriterionResultV1 {
        criterion_id: criterion_id.to_owned(),
        passed,
        observed_value_sha256: module_sha256(observed).map_err(selection_error)?,
        reason_code: reason_code.to_owned(),
        evidence_ids: vec![format!("observation-{observation_id}")],
    })
}

fn build_final_verification(
    mode: ScenarioMode,
    goal: &GoalSpec,
    plan: &PlanGraph,
    initial: &ObservationSnapshot,
    final_observation: &ObservationSnapshot,
    cycles: &[CycleExecution],
    recovery_hashes: Vec<String>,
) -> Result<FinalGoalVerificationV1, DesktopError> {
    let required_ids = ["saved-name", "save-status", "save-revision"];
    let mut required = Vec::new();
    for automation_id in required_ids {
        let element = element_by_automation_id(final_observation, automation_id)?;
        let passed = match automation_id {
            "saved-name" => observed_text(element) == Some(EXPECTED_NAME),
            "save-status" => observed_text(element) == Some("saved"),
            "save-revision" => observed_text(element)
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|value| value >= 1),
            _ => false,
        };
        required.push(final_criterion(
            automation_id,
            passed,
            &element.value,
            if passed {
                "criterion-passed"
            } else if mode == ScenarioMode::Clarification {
                "clarification-blocked"
            } else {
                "criterion-failed"
            },
            &final_observation.observation_id,
        )?);
    }
    let initial_protected = element_by_automation_id(initial, "protected-checkbox")?;
    let final_protected = element_by_automation_id(final_observation, "protected-checkbox")?;
    let process_binding_stable = [
        "process_id",
        "executable_hash",
        "window_title_hash",
        "session_id",
    ]
    .iter()
    .all(|key| initial.target_binding.get(*key) == final_observation.target_binding.get(*key));
    let protected_stable = initial_protected.value == final_protected.value;
    let protected = vec![
        final_criterion(
            "protected-checkbox-stable",
            protected_stable,
            &final_protected.value,
            if protected_stable {
                "protected-invariant-passed"
            } else {
                "protected-invariant-violated"
            },
            &final_observation.observation_id,
        )?,
        final_criterion(
            "process-session-window-stable",
            process_binding_stable,
            &serde_json::to_value(&final_observation.target_binding)
                .map_err(|error| DesktopError::Json(error.to_string()))?,
            if process_binding_stable {
                "transport-binding-passed"
            } else {
                "transport-binding-failed"
            },
            &final_observation.observation_id,
        )?,
    ];
    let all_passed = required.iter().all(|criterion| criterion.passed)
        && protected.iter().all(|criterion| criterion.passed);
    let verdict = match mode {
        ScenarioMode::Happy | ScenarioMode::Recovery if all_passed => {
            FinalVerificationVerdictV1::Passed
        }
        ScenarioMode::Unsafe => FinalVerificationVerdictV1::Unsafe,
        ScenarioMode::Clarification => FinalVerificationVerdictV1::ClarificationRequired,
        ScenarioMode::Happy | ScenarioMode::Recovery => FinalVerificationVerdictV1::Failed,
    };
    let goal_progress = if verdict == FinalVerificationVerdictV1::Passed {
        GoalProgress::Complete
    } else {
        GoalProgress::Blocked
    };
    FinalGoalVerificationV1 {
        schema_version: KERNEL_TASK_SCHEMA_VERSION,
        goal_id: goal.goal_id.clone(),
        final_plan_generation_id: plan.plan_generation_id.clone(),
        final_observation_id: final_observation.observation_id.clone(),
        final_observation_sha256: final_observation.state_hash.clone(),
        final_observation_sequence: final_observation.sequence,
        required_goal_criteria: required,
        protected_invariant_results: protected,
        completed_action_result_hashes: cycles
            .iter()
            .filter(|cycle| cycle.verdict == VerificationVerdictV2::Passed)
            .map(|cycle| cycle.verified_result_sha256.clone())
            .collect(),
        recovery_result_hashes: recovery_hashes,
        verdict,
        goal_progress,
        evidence_ids: vec![
            "terminal-read-only-stability-observation".to_owned(),
            "independent-final-goal-verification".to_owned(),
        ],
        final_verification_sha256: empty_hash(),
    }
    .seal()
}

fn build_work_report(
    mode: ScenarioMode,
    final_verification: &FinalGoalVerificationV1,
    cycles: &[CycleExecution],
) -> Result<WorkReport, DesktopError> {
    let completed_actions = cycles
        .iter()
        .filter(|cycle| cycle.verdict == VerificationVerdictV2::Passed)
        .map(|cycle| cycle.proposal_id.clone())
        .collect::<Vec<_>>();
    let completed = final_verification.verdict == FinalVerificationVerdictV1::Passed;
    let incomplete_items = match mode {
        ScenarioMode::Happy | ScenarioMode::Recovery if completed => Vec::new(),
        ScenarioMode::Unsafe => vec!["protected-invariant-violation".to_owned()],
        ScenarioMode::Clarification => vec!["ambiguous-employee-name-target".to_owned()],
        ScenarioMode::Happy | ScenarioMode::Recovery => {
            vec!["final-goal-verification-failed".to_owned()]
        }
    };
    let report = WorkReport {
        schema_version: 1,
        confirmed_facts: final_verification
            .required_goal_criteria
            .iter()
            .chain(&final_verification.protected_invariant_results)
            .filter(|criterion| criterion.passed)
            .map(|criterion| {
                format!(
                    "{}:{}",
                    criterion.criterion_id, criterion.observed_value_sha256
                )
            })
            .collect(),
        completed_actions,
        incomplete_items,
        opinions: Vec::new(),
        opinion_basis: Vec::new(),
        uncertainties: Vec::new(),
        user_decision_required: matches!(mode, ScenarioMode::Unsafe | ScenarioMode::Clarification),
        build_id: KERNEL_TASK_RUNTIME_BUILD_ID.to_owned(),
        module_ids: vec![
            "cognitive-recovery-control-v1".to_owned(),
            "cognitive-verifier-v2".to_owned(),
            "element-grounder".to_owned(),
            "goal-compiler".to_owned(),
            "plan-ranker".to_owned(),
            "windows-uia-observation-v1".to_owned(),
        ],
        timings: vec![
            CognitiveTiming {
                step: "goal-compiled".to_owned(),
                logical_tick: 2,
            },
            CognitiveTiming {
                step: "initially-observed".to_owned(),
                logical_tick: 3,
            },
            CognitiveTiming {
                step: "terminal-verification".to_owned(),
                logical_tick: 90,
            },
        ],
        warnings: if mode == ScenarioMode::Unsafe {
            vec!["automatic-retry-blocked-after-unsafe-verdict".to_owned()]
        } else {
            Vec::new()
        },
    };
    report.validate()?;
    Ok(report)
}

fn composite_audit_head(heads: &[String]) -> Result<String, DesktopError> {
    let mut heads = heads.to_vec();
    heads.sort();
    heads.dedup();
    module_sha256(&heads).map_err(selection_error)
}

fn normalized_replay_hash(
    mode: ScenarioMode,
    goal: &GoalSpec,
    pack: &ApplicationPack,
    plan: &PlanGraph,
    cycles: &[CycleExecution],
    final_verification: &FinalGoalVerificationV1,
    report: &WorkReport,
) -> Result<String, DesktopError> {
    let cycle_semantics = cycles
        .iter()
        .map(|cycle| {
            json!({
                "capability_id": cycle.capability_id,
                "verdict": cycle.verdict,
                "completed": cycle.record.completed,
            })
        })
        .collect::<Vec<_>>();
    let criteria = final_verification
        .required_goal_criteria
        .iter()
        .chain(&final_verification.protected_invariant_results)
        .map(|criterion| json!({"id": criterion.criterion_id, "passed": criterion.passed}))
        .collect::<Vec<_>>();
    module_sha256(&json!({
        "mode": mode,
        "goal": canonical_sha256(goal).map_err(selection_error)?,
        "application_pack": pack.pack_sha256,
        "plan": canonical_sha256(plan).map_err(selection_error)?,
        "cycles": cycle_semantics,
        "criteria": criteria,
        "final_verdict": final_verification.verdict,
        "report": {
            "completed_action_count": report.completed_actions.len(),
            "incomplete_items": report.incomplete_items,
            "user_decision_required": report.user_decision_required,
            "module_ids": report.module_ids,
        }
    }))
    .map_err(selection_error)
}

fn assert_required_elements(
    observation: &ObservationSnapshot,
    mode: ScenarioMode,
) -> Result<(), DesktopError> {
    for id in [
        "save-button",
        "saved-name",
        "save-revision",
        "save-status",
        "protected-checkbox",
        "observation-status",
    ] {
        let _ = element_by_automation_id(observation, id)?;
    }
    let name_count = observation
        .observable_elements
        .iter()
        .filter(|element| {
            element
                .value
                .pointer("/automation_id/text")
                .and_then(Value::as_str)
                == Some("employee-name-input")
        })
        .count();
    let expected = if mode == ScenarioMode::Clarification {
        2
    } else {
        1
    };
    if name_count != expected {
        return Err(DesktopError::Integrity(
            "fixture employee input cardinality differs from scenario".to_owned(),
        ));
    }
    Ok(())
}

fn expected_kernel_goal(
    instruction: &AuthenticatedTaskInstructionV1,
    payload: &Value,
) -> Result<GoalSpec, DesktopError> {
    let values = instruction
        .instruction_text
        .lines()
        .map(|line| {
            line.split_once(':')
                .map(|(_, value)| value.split_whitespace().collect::<Vec<_>>().join(" "))
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    DesktopError::Integrity(
                        "KRN-500 role pre-admission grammar line is malformed".to_owned(),
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if values.len() != 4 {
        return Err(DesktopError::Integrity(
            "KRN-500 role pre-admission grammar changed".to_owned(),
        ));
    }
    let input_sha256 = module_sha256(payload).map_err(selection_error)?;
    let suffix = input_sha256
        .strip_prefix("sha256:")
        .ok_or_else(|| DesktopError::Integrity("Goal input hash prefix differs".to_owned()))?;
    let mut constraints = BTreeSet::from([
        "protected fields remain unchanged".to_owned(),
        values[3].clone(),
    ]);
    let goal = GoalSpec {
        schema_version: 1,
        goal_id: format!("goal-{}", &suffix[..32]),
        objective: values[0].clone(),
        scope: BTreeMap::from([("fixture".to_owned(), json!("windows-uia"))]),
        required_outcomes: vec![values[2].clone()],
        constraints: constraints.iter().cloned().collect(),
        success_criteria: instruction.structured_success_criteria.clone(),
        risk_class: CognitiveRiskClass::BusinessStateChange,
        confirmation_policy: ConfirmationPolicy::BeforeRiskyAction,
        provenance: Provenance {
            source: instruction.source_id.clone(),
            source_hash: payload
                .get("source_hash")
                .and_then(Value::as_str)
                .ok_or_else(|| DesktopError::Integrity("Goal source hash is absent".to_owned()))?
                .to_owned(),
            module_id: "goal-compiler".to_owned(),
        },
    };
    constraints.clear();
    goal.validate()?;
    Ok(goal)
}

fn prepare_role_binding(
    role_source: &Path,
    temp: &TempRoot,
    instruction: &AuthenticatedTaskInstructionV1,
    expected_goal: &GoalSpec,
    pack: &ApplicationPack,
    now: u64,
) -> Result<RoleKernelBinding, DesktopError> {
    let source = fs::read(canonical_file(role_source, "role-source")?)
        .map_err(|error| io_error("role-source", error))?;
    let format = if role_source
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("json"))
    {
        RoleCompileFormatV1::Json
    } else {
        RoleCompileFormatV1::Yaml
    };
    let contract = compile_role_source(&source, format)
        .map_err(selection_error)?
        .contract;
    let application = contract
        .application_bindings
        .iter()
        .find(|binding| binding.application_pack_id == pack.pack_id)
        .ok_or_else(|| DesktopError::AccessDenied("Role does not bind the KRN pack".to_owned()))?;
    if application.application_pack_sha256 != pack.pack_sha256
        || !application
            .integration_ids
            .iter()
            .any(|value| value == INTEGRATION_ID)
        || contract.role_contract_id != ROLE_ID
        || contract.organization_scope.organization_id != ORGANIZATION_ID
    {
        return Err(DesktopError::AccessDenied(
            "Role source does not exactly bind the KRN fixture".to_owned(),
        ));
    }

    let approval_key = SigningKey::from_bytes(&[81_u8; 32]);
    let delegation_key = SigningKey::from_bytes(&[82_u8; 32]);
    let approval = create_role_contract_approval(
        RoleContractApprovalV1 {
            schema_version: ROLE_CONTRACT_SCHEMA_VERSION,
            approval_id: "kernel-e2e-role-approval".to_owned(),
            organization_id: ORGANIZATION_ID.to_owned(),
            role_contract_id: contract.role_contract_id.clone(),
            role_version: contract.role_version.clone(),
            contract_sha256: contract.contract_sha256.clone(),
            approved_by_actor_id: "kernel-e2e-role-approver".to_owned(),
            approver_authority_class: "role-governance".to_owned(),
            signer_key_id: "kernel-e2e-approval-key".to_owned(),
            issued_at_unix_seconds: now.saturating_sub(60).max(1),
            expires_at_unix_seconds: now.saturating_add(600),
            approval_signature: String::new(),
            evidence_ids: vec!["kernel-e2e-role-approval".to_owned()],
            approval_sha256: empty_hash(),
        },
        &contract,
        &approval_key,
    )
    .map_err(selection_error)?;
    let delegation = create_role_delegation(
        RoleDelegationGrantV1 {
            schema_version: ROLE_CONTRACT_SCHEMA_VERSION,
            delegation_id: "kernel-e2e-role-delegation".to_owned(),
            organization_id: ORGANIZATION_ID.to_owned(),
            role_instance_id: ACTOR_ID.to_owned(),
            role_contract_id: contract.role_contract_id.clone(),
            role_version: contract.role_version.clone(),
            contract_sha256: contract.contract_sha256.clone(),
            approval_sha256: approval.approval_sha256.clone(),
            delegated_scope: contract.organization_scope.clone(),
            delegated_work_class_ids: vec!["workforce.kernel_e2e.name_save".to_owned()],
            delegated_application_pack_ids: vec![pack.pack_id.clone()],
            delegated_integration_ids: vec![INTEGRATION_ID.to_owned()],
            delegated_capability_ids: vec!["uia.invoke".to_owned(), "uia.set_value".to_owned()],
            autonomous_capability_ids: vec!["uia.set_value".to_owned()],
            confirmation_capability_ids: vec!["uia.invoke".to_owned()],
            prohibited_capability_ids: vec!["uia.set_protected".to_owned()],
            maximum_autonomous_risk: CognitiveRiskClass::Reversible,
            maximum_confirmable_risk: CognitiveRiskClass::BusinessStateChange,
            policy_set_sha256: contract.policy_set_sha256.clone(),
            valid_from_unix_seconds: now.saturating_sub(60).max(1),
            expires_at_unix_seconds: now.saturating_add(600),
            assigned_by_actor_id: "kernel-e2e-role-assigner".to_owned(),
            signer_key_id: "kernel-e2e-delegation-key".to_owned(),
            delegation_signature: String::new(),
            evidence_ids: vec!["kernel-e2e-role-delegation".to_owned()],
            delegation_sha256: empty_hash(),
        },
        &contract,
        &approval,
        &delegation_key,
    )
    .map_err(selection_error)?;

    let role_root = temp.path().join("role-ledger");
    let audit_root = temp.path().join("role-audit");
    let now_ms = now.saturating_mul(1_000);
    let role_started_ms = now_ms.saturating_sub(60_000).max(1);
    let mut ledger = initialize_role_instance_ledger(
        &role_root,
        "kernel-e2e-role-ledger",
        ACTOR_ID,
        64,
        role_started_ms,
    )?;
    let mut audit = initialize_windows_deployment_audit(
        &audit_root,
        "kernel-e2e-role-audit",
        "kernel-e2e-role-session",
        128,
        role_started_ms,
    )?;
    append_role_record(
        &mut ledger,
        &mut audit,
        &contract,
        RoleInstanceLedgerEventKindV1::RoleContractRegistered,
        None,
        None,
        None,
        None,
        BTreeMap::new(),
        now_ms.saturating_sub(50_000).max(2),
    )?;
    append_role_record(
        &mut ledger,
        &mut audit,
        &contract,
        RoleInstanceLedgerEventKindV1::RoleContractApproved,
        None,
        None,
        None,
        None,
        BTreeMap::from([("approval".to_owned(), approval.approval_sha256.clone())]),
        now_ms.saturating_sub(45_000).max(3),
    )?;
    let provisioned = RoleInstanceV1::provision(
        ACTOR_ID.to_owned(),
        &contract,
        &approval,
        &delegation,
        "kernel-e2e-role-ledger".to_owned(),
        digest("kernel-role-authority-template"),
        digest("kernel-role-recovery-template"),
        vec!["kernel-e2e-role-instance".to_owned()],
    )
    .and_then(|value| value.bind_ledger_head(ledger.verification().terminal_record_hash.clone()))
    .map_err(selection_error)?;
    append_role_record(
        &mut ledger,
        &mut audit,
        &contract,
        RoleInstanceLedgerEventKindV1::RoleInstanceProvisioned,
        Some(provisioned),
        None,
        None,
        None,
        BTreeMap::from([(
            "delegation".to_owned(),
            delegation.delegation_sha256.clone(),
        )]),
        now_ms.saturating_sub(40_000).max(4),
    )?;
    let active = ledger
        .verification()
        .current_instance
        .as_ref()
        .ok_or_else(|| DesktopError::Integrity("provisioned Role is absent".to_owned()))?
        .transition(RoleInstanceStatusV1::Active, now.saturating_sub(30).max(1))
        .map_err(selection_error)?;
    append_role_record(
        &mut ledger,
        &mut audit,
        &contract,
        RoleInstanceLedgerEventKindV1::RoleInstanceActivated,
        Some(active),
        None,
        None,
        None,
        BTreeMap::new(),
        now_ms.saturating_sub(30_000).max(5),
    )?;

    let active = ledger
        .verification()
        .current_instance
        .clone()
        .ok_or_else(|| DesktopError::Integrity("active Role is absent".to_owned()))?;
    let policy = TrustedPolicySnapshotV1 {
        schema_version: POLICY_ADMISSION_SCHEMA_VERSION,
        policy_set_id: contract.policy_set_id.clone(),
        policy_set_version: contract.policy_set_version.clone(),
        policy_set_sha256: contract.policy_set_sha256.clone(),
        organization_id: ORGANIZATION_ID.to_owned(),
        policy_state: TrustedPolicyStateV1::Effective,
        allowed_risk_classes: vec![
            CognitiveRiskClass::ReadOnly,
            CognitiveRiskClass::Reversible,
            CognitiveRiskClass::BusinessStateChange,
        ],
        denied_capability_ids: Vec::new(),
        mandatory_confirmation_capability_ids: Vec::new(),
        mandatory_escalation_capability_ids: Vec::new(),
        forbidden_semantic_targets: Vec::new(),
        effective_from_unix_seconds: now.saturating_sub(60).max(1),
        expires_at_unix_seconds: now.saturating_add(600),
        evidence_ids: vec!["kernel-e2e-policy-snapshot".to_owned()],
        snapshot_sha256: empty_hash(),
    }
    .seal()
    .map_err(selection_error)?;
    let (local_date, weekday, local_minute_of_day) = seoul_local_time(now)?;
    let time = RoleOperationalTimeContextV1 {
        schema_version: ROLE_CONTRACT_SCHEMA_VERSION,
        calendar_sha256: contract.working_calendar.calendar_sha256.clone(),
        timezone_id: contract.working_calendar.timezone_id.clone(),
        local_date,
        weekday,
        local_minute_of_day,
        utc_offset_minutes: 540,
        blackout_date_ids: Vec::new(),
        emergency_override_sha256: None,
        observed_at_unix_seconds: now,
        evidence_ids: vec!["kernel-e2e-trusted-clock".to_owned()],
        context_sha256: empty_hash(),
    }
    .seal()
    .map_err(selection_error)?;
    let request = RoleTaskAdmissionRequestV1 {
        schema_version: ROLE_CONTRACT_SCHEMA_VERSION,
        request_id: "kernel-e2e-role-task-request".to_owned(),
        role_instance_sha256: active.instance_sha256.clone(),
        contract_sha256: contract.contract_sha256.clone(),
        delegation_sha256: delegation.delegation_sha256.clone(),
        organization_id: ORGANIZATION_ID.to_owned(),
        authenticated_actor_id: instruction.authenticated_actor_id.clone(),
        authenticated_role_id: instruction.authenticated_role_id.clone(),
        authenticated_instruction_sha256: instruction.instruction_sha256.clone(),
        goal_spec_sha256: canonical_sha256(expected_goal).map_err(selection_error)?,
        work_class_id: "workforce.kernel_e2e.name_save".to_owned(),
        requested_application_pack_id: pack.pack_id.clone(),
        requested_application_pack_sha256: pack.pack_sha256.clone(),
        requested_integration_id: INTEGRATION_ID.to_owned(),
        required_capability_ids: vec!["uia.invoke".to_owned(), "uia.set_value".to_owned()],
        semantic_target_ids: vec!["employee_name_input".to_owned(), "save_button".to_owned()],
        task_risk: CognitiveRiskClass::BusinessStateChange,
        trusted_policy_snapshot_sha256: policy.snapshot_sha256.clone(),
        policy_set_sha256: contract.policy_set_sha256.clone(),
        operational_time_context: time,
        requested_at_unix_seconds: now,
        expires_at_unix_seconds: now.saturating_add(300),
        evidence_ids: vec!["kernel-e2e-authenticated-task".to_owned()],
        request_sha256: empty_hash(),
    }
    .seal()
    .map_err(selection_error)?;
    let admitted = admit_role_task(
        &request,
        &contract,
        &approval,
        &delegation,
        &active,
        &policy,
        "kernel-e2e-approval-key",
        &approval_key.verifying_key(),
        "kernel-e2e-delegation-key",
        &delegation_key.verifying_key(),
        now,
    )
    .map_err(selection_error)?;
    if admitted.decision.outcome != RoleTaskAdmissionOutcomeV1::Admitted {
        return Err(DesktopError::AccessDenied(format!(
            "KRN-500 Role task was not admitted: {:?}",
            admitted.decision.reason_codes
        )));
    }
    let context = admitted
        .role_task_context
        .ok_or_else(|| DesktopError::Integrity("admitted Role context is absent".to_owned()))?;
    let authority = admitted
        .authority_projection
        .ok_or_else(|| DesktopError::Integrity("Role authority projection is absent".to_owned()))?;
    let recovery = admitted
        .recovery_profile_projection
        .ok_or_else(|| DesktopError::Integrity("Role recovery projection is absent".to_owned()))?;
    let current = ledger
        .verification()
        .current_instance
        .clone()
        .ok_or_else(|| DesktopError::Integrity("active Role is absent".to_owned()))?;
    append_role_record(
        &mut ledger,
        &mut audit,
        &contract,
        RoleInstanceLedgerEventKindV1::RoleTaskAdmitted,
        Some(current),
        Some(admitted.decision.request_sha256.clone()),
        Some(admitted.decision.admission_sha256.clone()),
        Some(context.context_sha256.clone()),
        BTreeMap::from([
            ("authority".to_owned(), authority.authority_sha256.clone()),
            ("recovery".to_owned(), recovery.profile_sha256.clone()),
        ]),
        now_ms.saturating_add(5),
    )?;
    let current = ledger
        .verification()
        .current_instance
        .clone()
        .ok_or_else(|| DesktopError::Integrity("admitted Role is absent".to_owned()))?;
    append_role_record(
        &mut ledger,
        &mut audit,
        &contract,
        RoleInstanceLedgerEventKindV1::RoleBoundTaskStarted,
        Some(current),
        None,
        Some(admitted.decision.admission_sha256),
        Some(context.context_sha256.clone()),
        BTreeMap::new(),
        now_ms.saturating_add(6),
    )?;
    Ok(RoleKernelBinding {
        contract,
        delegation,
        admitted_instance: active,
        ledger,
        audit,
        audit_root,
        context,
        authority,
        recovery,
    })
}

#[allow(clippy::too_many_arguments)]
fn append_role_record(
    ledger: &mut RoleInstanceLedgerV1,
    audit: &mut WindowsDeploymentAuditLedger,
    contract: &RoleContractV1,
    event_kind: RoleInstanceLedgerEventKindV1,
    instance_after: Option<RoleInstanceV1>,
    task_request_sha256: Option<String>,
    task_admission_sha256: Option<String>,
    role_context_sha256: Option<String>,
    artifact_hashes: BTreeMap<String, String>,
    recorded_at_unix_ms: u64,
) -> Result<String, DesktopError> {
    let (audit_kind, event_token) = match event_kind {
        RoleInstanceLedgerEventKindV1::RoleContractRegistered => (
            WindowsDeploymentAuditEventKind::RoleContractRegistered,
            "contract-registered",
        ),
        RoleInstanceLedgerEventKindV1::RoleContractApproved => (
            WindowsDeploymentAuditEventKind::RoleContractApproved,
            "contract-approved",
        ),
        RoleInstanceLedgerEventKindV1::RoleInstanceProvisioned => (
            WindowsDeploymentAuditEventKind::RoleInstanceProvisioned,
            "instance-provisioned",
        ),
        RoleInstanceLedgerEventKindV1::RoleInstanceActivated => (
            WindowsDeploymentAuditEventKind::RoleInstanceActivated,
            "instance-activated",
        ),
        RoleInstanceLedgerEventKindV1::RoleTaskAdmitted => (
            WindowsDeploymentAuditEventKind::RoleTaskAdmitted,
            "task-admitted",
        ),
        RoleInstanceLedgerEventKindV1::RoleBoundTaskStarted => (
            WindowsDeploymentAuditEventKind::RoleBoundTaskStarted,
            "task-started",
        ),
        RoleInstanceLedgerEventKindV1::RoleBoundTaskTerminal => (
            WindowsDeploymentAuditEventKind::RoleBoundTaskTerminal,
            "task-terminal",
        ),
        _ => {
            return Err(DesktopError::Invalid(
                "KRN-500 runner received an unsupported Role event".to_owned(),
            ));
        }
    };
    let mut audit_artifacts = artifact_hashes.clone();
    audit_artifacts.insert("contract".to_owned(), contract.contract_sha256.clone());
    let audit_record_hash = audit.append(WindowsDeploymentAuditEvent {
        schema_version: 1,
        event_id: format!("role-{event_token}-{recorded_at_unix_ms}"),
        kind: audit_kind,
        status: WindowsDeploymentAuditStatus::Succeeded,
        artifact_hashes: audit_artifacts,
        detail_hash: digest(event_token),
        recorded_at_unix_ms,
    })?;
    ledger.append(RoleInstanceLedgerRecordV1 {
        schema_version: 1,
        sequence: 1,
        ledger_id: "kernel-e2e-role-ledger".to_owned(),
        role_instance_id: ACTOR_ID.to_owned(),
        event_kind,
        role_contract_id: contract.role_contract_id.clone(),
        role_version: contract.role_version.clone(),
        contract_sha256: contract.contract_sha256.clone(),
        instance_after,
        task_request_sha256,
        task_admission_sha256,
        role_context_sha256,
        artifact_hashes,
        audit_record_hash,
        recorded_at_unix_ms,
        previous_record_hash: empty_hash(),
        record_hash: empty_hash(),
    })
}

fn seoul_local_time(now: u64) -> Result<(String, u8, u16), DesktopError> {
    let local = now.saturating_add(9 * 60 * 60);
    let days = i64::try_from(local / 86_400)
        .map_err(|_| DesktopError::Invalid("local day is not representable".to_owned()))?;
    let seconds = local % 86_400;
    let minute = u16::try_from(seconds / 60)
        .map_err(|_| DesktopError::Invalid("local minute is not representable".to_owned()))?;
    let weekday = u8::try_from((days + 3).rem_euclid(7))
        .map_err(|_| DesktopError::Invalid("local weekday is not representable".to_owned()))?;
    let adjusted = days + 719_468;
    let era = if adjusted >= 0 {
        adjusted
    } else {
        adjusted - 146_096
    } / 146_097;
    let day_of_era = adjusted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    Ok((format!("{year:04}-{month:02}-{day:02}"), weekday, minute))
}

#[cfg(windows)]
fn run_scenario(
    args: &RunnerArgs,
    temp: &TempRoot,
    app_process_id: u32,
) -> Result<ScenarioArtifacts, DesktopError> {
    let now = now_seconds()?;
    let now_ms = now.saturating_mul(1_000);
    let instruction = authenticated_instruction(now_ms)?;
    instruction.validate(now_ms.saturating_add(1))?;
    let goal_payload = goal_compiler_payload(&instruction)?;
    let expected_goal = expected_kernel_goal(&instruction, &goal_payload)?;
    let pack = load_application_pack(&args.application_pack)?;
    let mut role_binding = args
        .role_source
        .as_deref()
        .map(|source| prepare_role_binding(source, temp, &instruction, &expected_goal, &pack, now))
        .transpose()?;
    let bindings = ["goal-compiler", "element-grounder", "plan-ranker"]
        .iter()
        .map(|module_id| module_binding(args, module_id))
        .collect::<Result<Vec<_>, _>>()?;
    let mut modules = ModuleInvocationCoordinatorV1::new(bindings, Duration::from_secs(15))?;
    let goal_fixture_hash = module_sha256(&goal_payload).map_err(selection_error)?;
    let goal_invocation = module_invocation(
        args,
        ModuleInvocationSpec {
            module_id: "goal-compiler",
            invocation_id: "goal-compiler-kernel-e2e".to_owned(),
            payload: goal_payload,
            goal_id: "kernel-e2e-bootstrap-goal".to_owned(),
            source_observation_hash: None,
            plan_generation_id: None,
            logical_sequence: 1,
            trust_labels: BTreeSet::from(["authenticated_user_instruction".to_owned()]),
            fixture_hash: goal_fixture_hash,
        },
    )?;
    let goal_invocation_sha256 = module_sha256(&goal_invocation).map_err(selection_error)?;
    let goal_result = modules.invoke(&goal_invocation)?;
    if goal_result.status != ModuleResultStatus::Succeeded {
        return Err(DesktopError::Integrity(format!(
            "actual Goal Compiler did not succeed: status={:?}, unsupported={:?}, error={:?}",
            goal_result.status, goal_result.unsupported_reason, goal_result.error
        )));
    }
    let goal_payload = goal_result.payload.ok_or_else(|| {
        DesktopError::Integrity("Goal Compiler result payload is absent".to_owned())
    })?;
    if goal_payload.get("status").and_then(Value::as_str) != Some("compiled") {
        return Err(DesktopError::Precondition(
            "KRN-500 instruction unexpectedly requires Goal Compiler clarification".to_owned(),
        ));
    }
    let goal: GoalSpec = serde_json::from_value(
        goal_payload
            .get("goal_spec")
            .cloned()
            .ok_or_else(|| DesktopError::Integrity("compiled GoalSpec is absent".to_owned()))?,
    )
    .map_err(|error| DesktopError::Json(error.to_string()))?;
    goal.validate()?;
    if role_binding.is_some() && goal != expected_goal {
        return Err(DesktopError::Integrity(
            "actual Goal Compiler output differs from pre-admitted deterministic GoalSpec"
                .to_owned(),
        ));
    }
    let goal_sha256 = canonical_sha256(&goal).map_err(selection_error)?;
    let plan = task_plan()?;
    let plan_sha256 = canonical_sha256(&plan).map_err(selection_error)?;
    let powershell = powershell_path()?;
    let powershell_hash =
        sha(&fs::read(&powershell).map_err(|error| io_error("powershell", error))?);
    let configuration = adapter_configuration(&args.worker_executable, &powershell_hash)?;
    let initial_observation = observe_actual(
        &configuration,
        temp,
        app_process_id,
        &powershell,
        &powershell_hash,
        &fixture_title(args.mode),
        &goal,
        1,
        "initial",
        now,
    )?;
    assert_required_elements(&initial_observation.snapshot, args.mode)?;
    let initial = initial_observation.snapshot;
    let initial_target = initial_observation.target;
    let initial_world = world_state(&goal, &initial, &plan, "select-name-capability")?;
    let world_sha256 = canonical_sha256(&initial_world).map_err(selection_error)?;
    let mut runtime = if let Some(binding) = &role_binding {
        CognitiveKernelTaskRuntimeV1::begin_role_bound(
            "kernel-e2e-task-run".to_owned(),
            instruction.instruction_sha256.clone(),
            &goal_sha256,
            &pack.pack_sha256,
            INTEGRATION_ID,
            &binding.context,
            &binding.authority,
            &binding.recovery,
            binding.ledger.verification(),
            now,
            1,
        )?
    } else {
        CognitiveKernelTaskRuntimeV1::begin(
            "kernel-e2e-task-run".to_owned(),
            instruction.instruction_sha256.clone(),
            1,
        )?
    };
    runtime.compile_goal(goal_invocation_sha256.clone(), goal_sha256.clone(), 2)?;
    runtime.observe_initial(goal_sha256.clone(), initial.state_hash.clone(), 3)?;
    runtime.prepare_plan(
        initial.state_hash.clone(),
        world_sha256,
        plan_sha256.clone(),
        4,
    )?;

    let mut executions = Vec::new();
    let mut recovery_trigger_hashes = Vec::new();
    let mut recovery_decision_hashes = Vec::new();
    let mut recovery_result_hashes = Vec::new();
    let mut audit_heads = vec![initial_observation.audit_chain_head];
    if let Some(binding) = &role_binding {
        audit_heads.push(binding.audit_chain_head()?);
    }
    let mut tick = 5_u64;

    if args.mode == ScenarioMode::Clarification {
        let grounding = invoke_grounder(
            args,
            &mut modules,
            &pack,
            &initial,
            &goal,
            &plan,
            "employee_name_input",
            "Employee name input",
            "clarification",
            20,
        )?;
        if grounding.result.status != GroundingStatusV1::Ambiguous || grounding.selection.is_some()
        {
            return Err(DesktopError::Integrity(
                "duplicate name controls did not produce typed ambiguity".to_owned(),
            ));
        }
    } else {
        runtime.execute_next_step(
            "name-action-cycle".to_owned(),
            vec![initial.state_hash.clone(), plan_sha256.clone()],
            tick,
        )?;
        tick = tick.saturating_add(1);
        let name = run_action_cycle(
            args,
            temp,
            &mut modules,
            &configuration,
            &initial_target,
            &initial,
            &instruction,
            &goal,
            &pack,
            &plan,
            ActionStepKind::SetName,
            "name",
            1,
            now,
        )?;
        if name.verdict != VerificationVerdictV2::Passed {
            return Err(DesktopError::Integrity(format!(
                "actual name SetValue did not independently verify: {}",
                name.verification_diagnostic
            )));
        }
        runtime.record_action_verified(
            "name-action-verified".to_owned(),
            vec![name.receipt_sha256.clone()],
            name.verified_result_sha256.clone(),
            tick,
        )?;
        tick = tick.saturating_add(1);
        runtime.advance(
            "name-action-advanced".to_owned(),
            vec![name.verified_result_sha256.clone()],
            tick,
        )?;
        tick = tick.saturating_add(1);
        audit_heads.extend(name.audit_chain_heads.iter().cloned());
        let save_source = name.fresh.clone();
        executions.push(name);

        runtime.execute_next_step(
            "save-action-cycle".to_owned(),
            vec![save_source.state_hash.clone(), plan_sha256.clone()],
            tick,
        )?;
        tick = tick.saturating_add(1);
        let save = run_action_cycle(
            args,
            temp,
            &mut modules,
            &configuration,
            &initial_target,
            &save_source,
            &instruction,
            &goal,
            &pack,
            &plan,
            ActionStepKind::Save,
            "save-1",
            2,
            now,
        )?;
        runtime.record_action_verified(
            "save-action-verified".to_owned(),
            vec![save.receipt_sha256.clone()],
            save.verified_result_sha256.clone(),
            tick,
        )?;
        tick = tick.saturating_add(1);
        audit_heads.extend(save.audit_chain_heads.iter().cloned());

        match args.mode {
            ScenarioMode::Happy => {
                if save.verdict != VerificationVerdictV2::Passed {
                    return Err(DesktopError::Integrity(format!(
                        "happy save action did not pass verification: {}",
                        save.verification_diagnostic
                    )));
                }
                runtime.advance(
                    "save-action-advanced".to_owned(),
                    vec![save.verified_result_sha256.clone()],
                    tick,
                )?;
                tick = tick.saturating_add(1);
                executions.push(save);
            }
            ScenarioMode::Recovery => {
                if save.verdict != VerificationVerdictV2::Failed {
                    return Err(DesktopError::Integrity(format!(
                        "recovery fixture first save did not fail verification: {}",
                        save.verification_diagnostic
                    )));
                }
                let recovery = run_fresh_save_recovery(
                    args,
                    temp,
                    &mut modules,
                    &configuration,
                    &initial_target,
                    &save,
                    &instruction,
                    &goal,
                    &pack,
                    &plan,
                    now,
                )?;
                runtime.recover(
                    recovery.trigger_sha256.clone(),
                    recovery.decision_sha256.clone(),
                    tick,
                )?;
                tick = tick.saturating_add(1);
                runtime.execute_next_step(
                    "save-recovery-action-cycle".to_owned(),
                    vec![save.verified_result_sha256.clone()],
                    tick,
                )?;
                tick = tick.saturating_add(1);
                let second = recovery.cycle.ok_or_else(|| {
                    DesktopError::Integrity("recovery omitted its fresh action cycle".to_owned())
                })?;
                runtime.record_action_verified(
                    "save-recovery-action-verified".to_owned(),
                    vec![second.receipt_sha256.clone()],
                    second.verified_result_sha256.clone(),
                    tick,
                )?;
                tick = tick.saturating_add(1);
                runtime.advance(
                    "save-recovery-advanced".to_owned(),
                    vec![recovery.result_sha256.clone()],
                    tick,
                )?;
                tick = tick.saturating_add(1);
                audit_heads.push(recovery.audit_chain_head);
                audit_heads.extend(second.audit_chain_heads.iter().cloned());
                recovery_trigger_hashes.push(recovery.trigger_sha256);
                recovery_decision_hashes.push(recovery.decision_sha256);
                recovery_result_hashes.push(recovery.result_sha256);
                executions.push(save);
                executions.push(second);
            }
            ScenarioMode::Unsafe => {
                if save.verdict != VerificationVerdictV2::Unsafe {
                    return Err(DesktopError::Integrity(
                        "unsafe fixture did not produce a protected invariant verdict".to_owned(),
                    ));
                }
                let recovery = run_unsafe_escalation(temp, &save, &goal, &plan, now)?;
                runtime.recover(
                    recovery.trigger_sha256.clone(),
                    recovery.decision_sha256.clone(),
                    tick,
                )?;
                tick = tick.saturating_add(1);
                runtime.complete_recovery(recovery.result_sha256.clone(), tick)?;
                tick = tick.saturating_add(1);
                audit_heads.push(recovery.audit_chain_head);
                recovery_trigger_hashes.push(recovery.trigger_sha256);
                recovery_decision_hashes.push(recovery.decision_sha256);
                recovery_result_hashes.push(recovery.result_sha256);
                executions.push(save);
            }
            ScenarioMode::Clarification => unreachable!("handled before mutation"),
        }
    }

    let last_sequence = executions
        .last()
        .map_or(initial.sequence, |cycle| cycle.fresh.sequence);
    let final_observation = observe_actual(
        &configuration,
        temp,
        app_process_id,
        &powershell,
        &powershell_hash,
        &fixture_title(args.mode),
        &goal,
        last_sequence.saturating_add(1),
        "final",
        now,
    )?;
    audit_heads.push(final_observation.audit_chain_head);
    let final_verification = build_final_verification(
        args.mode,
        &goal,
        &plan,
        &initial,
        &final_observation.snapshot,
        &executions,
        recovery_result_hashes.clone(),
    )?;
    runtime.verify_final_goal(
        vec![final_observation.snapshot.state_hash.clone()],
        final_verification.final_verification_sha256.clone(),
        tick,
    )?;
    tick = tick.saturating_add(1);
    let report = build_work_report(args.mode, &final_verification, &executions)?;
    let report_sha256 = canonical_sha256(&report).map_err(selection_error)?;
    runtime.build_work_report(
        final_verification.final_verification_sha256.clone(),
        report_sha256.clone(),
        tick,
    )?;
    tick = tick.saturating_add(1);
    let stage_records = runtime.finalize(report_sha256.clone(), tick)?;
    let actual_outcome = args.mode.expected_outcome();
    let audit_chain_head = composite_audit_head(&audit_heads)?;
    let action_cycle_records = executions
        .iter()
        .map(|cycle| cycle.record.clone())
        .collect::<Vec<_>>();
    let run_record = KernelTaskRunRecordV1 {
        schema_version: KERNEL_TASK_SCHEMA_VERSION,
        task_run_id: runtime.task_run_id().to_owned(),
        authenticated_instruction_sha256: instruction.instruction_sha256.clone(),
        role_context_sha256: runtime.role_context_sha256().map(str::to_owned),
        goal_compiler_invocation_sha256: goal_invocation_sha256,
        goal_spec_sha256: goal_sha256,
        application_pack_sha256: pack.pack_sha256.clone(),
        initial_observation_sha256: initial.state_hash.clone(),
        plan_sha256,
        stage_records,
        action_cycle_records: action_cycle_records.clone(),
        module_invocation_records: modules.records().to_vec(),
        policy_decision_hashes: executions
            .iter()
            .map(|cycle| cycle.policy_decision_sha256.clone())
            .collect(),
        activation_admission_hashes: executions
            .iter()
            .map(|cycle| cycle.admission_sha256.clone())
            .collect(),
        windows_activation_record_hashes: executions
            .iter()
            .map(|cycle| cycle.activation_record_hash.clone())
            .collect(),
        execution_receipt_hashes: executions
            .iter()
            .map(|cycle| cycle.receipt_sha256.clone())
            .collect(),
        verified_action_result_hashes: executions
            .iter()
            .map(|cycle| cycle.verified_result_sha256.clone())
            .collect(),
        recovery_trigger_hashes,
        recovery_decision_hashes,
        recovery_result_hashes,
        final_goal_verification_sha256: final_verification.final_verification_sha256.clone(),
        final_outcome: actual_outcome,
        work_report_sha256: report_sha256,
        audit_chain_head: audit_chain_head.clone(),
        started_at_unix_ms: now_ms,
        completed_at_unix_ms: now_ms.saturating_add(tick),
        evidence_ids: vec![
            "actual-standalone-modules".to_owned(),
            "actual-windows-uia".to_owned(),
            "bounded-recovery-control".to_owned(),
            "terminal-work-report".to_owned(),
        ],
        run_record_sha256: empty_hash(),
    }
    .seal(&report)?;
    let role_context_sha256 = role_binding
        .as_ref()
        .map(|binding| binding.context.context_sha256.clone());
    let role_context = role_binding.as_ref().map(|binding| binding.context.clone());
    let role_instance = role_binding
        .as_ref()
        .map(|binding| binding.admitted_instance.clone());
    let role_contract = role_binding
        .as_ref()
        .map(|binding| binding.contract.clone());
    let role_delegation = role_binding
        .as_ref()
        .map(|binding| binding.delegation.clone());
    let role_terminal_instance = role_binding
        .as_mut()
        .map(|binding| {
            binding.finish(
                &run_record.run_record_sha256,
                now_ms.saturating_add(tick).saturating_add(1),
            )
        })
        .transpose()?;
    let role_ledger_chain_head = role_terminal_instance
        .as_ref()
        .map(|instance| instance.ledger_chain_head.clone());
    let mut tampered_record = run_record.clone();
    tampered_record.work_report_sha256 = digest("tampered-work-report");
    if tampered_record.validate(&report).is_ok() {
        return Err(DesktopError::Integrity(
            "KernelTaskRunRecord tamper was accepted".to_owned(),
        ));
    }
    let mut tampered_instruction = instruction.clone();
    tampered_instruction.organization_id = "organization-tampered".to_owned();
    if tampered_instruction
        .validate(now_ms.saturating_add(1))
        .is_ok()
    {
        return Err(DesktopError::Integrity(
            "authenticated instruction tamper was accepted".to_owned(),
        ));
    }
    if !matches!(
        modules.invoke(&goal_invocation),
        Err(DesktopError::Replay(_))
    ) {
        return Err(DesktopError::Integrity(
            "module invocation replay was not rejected".to_owned(),
        ));
    }
    if modules
        .records()
        .iter()
        .any(|record| process_exists(record.process_id))
    {
        return Err(DesktopError::Integrity(
            "module host process remained after invocation".to_owned(),
        ));
    }
    let serialized = serde_json::to_string(&run_record)
        .map_err(|error| DesktopError::Json(error.to_string()))?;
    if serialized.contains(EXPECTED_NAME)
        || ["automation_id", "raw_payload", "credential", "password"]
            .iter()
            .any(|marker| serialized.to_ascii_lowercase().contains(marker))
    {
        return Err(DesktopError::Integrity(
            "audit-safe run record contains raw-sensitive execution material".to_owned(),
        ));
    }
    let normalized_replay_sha256 = normalized_replay_hash(
        args.mode,
        &goal,
        &pack,
        &plan,
        &executions,
        &final_verification,
        &report,
    )?;
    let policy_count = executions.len();
    let activation_count = executions.len();
    let receipt_count = executions.len();
    let verified_count = executions.len();
    let recovery_count = usize::from(!run_record.recovery_result_hashes.is_empty());
    let mutation_count = executions.len();
    Ok(ScenarioArtifacts {
        instruction,
        goal,
        pack,
        plan,
        initial,
        final_verification,
        report,
        run_record,
        normalized_replay_sha256,
        actual_outcome,
        module_invocation_count: modules.records().len(),
        cycles: action_cycle_records,
        policy_count,
        activation_count,
        receipt_count,
        verified_count,
        recovery_count,
        mutation_count,
        audit_chain_head,
        role_context,
        role_instance,
        role_terminal_instance,
        role_contract,
        role_delegation,
        role_context_sha256,
        role_ledger_chain_head,
    })
}

#[allow(clippy::too_many_arguments)]
fn select_actual_action(
    args: &RunnerArgs,
    modules: &mut ModuleInvocationCoordinatorV1,
    pack: &ApplicationPack,
    observation: &ObservationSnapshot,
    grounding: &GroundingExecution,
    goal: &GoalSpec,
    plan: &PlanGraph,
    current_step: &str,
    semantic_target_id: &str,
    action_kind: CandidateActionKind,
    input: CandidateActionInput,
    expected_postconditions: Vec<Postcondition>,
    risk: CognitiveRiskClass,
    label: &str,
    logical_tick: u64,
) -> Result<SelectedActionExecution, DesktopError> {
    let selection = grounding.selection.as_ref().ok_or_else(|| {
        DesktopError::Precondition("grounding did not produce a unique target".to_owned())
    })?;
    let selected_element = observation
        .observable_elements
        .iter()
        .find(|element| element.element_id == selection.grounded_target.selected_element_id)
        .ok_or_else(|| {
            DesktopError::Integrity("selected element is absent from observation".to_owned())
        })?;
    let binding = ActionCapabilityBinding {
        schema_version: 1,
        binding_id: format!("binding-{label}"),
        application_pack_sha256: pack.pack_sha256.clone(),
        semantic_target_id: semantic_target_id.to_owned(),
        source_kind: ObservationSourceKind::Uia,
        allowed_element_kinds: vec![selected_element.kind.clone()],
        action_kind,
        capability: CapabilityDescriptor {
            capability_id: action_kind.operation().to_owned(),
            operation: action_kind.operation().to_owned(),
            risk_class: risk,
            reversible: true,
            confirmation_requirement: ConfirmationRequirement::None,
            retry_limit: 1,
        },
        binding_sha256: empty_hash(),
    }
    .seal()
    .map_err(selection_error)?;
    binding.validate().map_err(selection_error)?;
    let context = ActionSelectionContextV1 {
        schema_version: 1,
        goal_id: goal.goal_id.clone(),
        plan_generation_id: plan.plan_generation_id.clone(),
        current_step: current_step.to_owned(),
        allowed_capability_ids: vec![action_kind.operation().to_owned()],
        context_sha256: empty_hash(),
    }
    .seal()
    .map_err(selection_error)?;
    let world = world_state(goal, observation, plan, current_step)?;
    let proposal_spec = GroundedActionProposalSpecV1 {
        candidate_id: format!("candidate-{label}"),
        capability_binding_sha256: binding.binding_sha256.clone(),
        input,
        preconditions: Vec::new(),
        expected_postconditions,
        confidence: 1.0,
    };
    let proposal = build_grounded_action_proposal(
        pack,
        observation,
        selection,
        &context,
        &binding,
        goal,
        &world,
        plan,
        &proposal_spec,
    )
    .map_err(selection_error)?;
    let proposal_sha256 = canonical_sha256(&proposal).map_err(selection_error)?;
    let ranking_profile = CandidateRankingProfileV1 {
        schema_version: 1,
        proposal_id: proposal.proposal_id.clone(),
        proposal_sha256: proposal_sha256.clone(),
        capability_id: proposal.capability_id.clone(),
        capability_binding_sha256: binding.binding_sha256.clone(),
        goal_id: proposal.goal_id.clone(),
        plan_generation_id: proposal.plan_generation_id.clone(),
        source_observation_hash: proposal.source_observation_hash.clone(),
        capability_version: "1.0.0".to_owned(),
        input_schema_id: "kernel-e2e-action-input-v1".to_owned(),
        input_schema_version: 1,
        output_schema_id: "kernel-e2e-action-output-v1".to_owned(),
        output_schema_version: 1,
        normalized_cost_millionths: if action_kind == CandidateActionKind::SetText {
            200
        } else {
            100
        },
        success_likelihood_millionths: 1_000_000,
        ranking_profile_sha256: empty_hash(),
    }
    .seal()
    .map_err(selection_error)?;
    let admission_profile = CandidateAdmissionProfileV1 {
        schema_version: 1,
        proposal_id: proposal.proposal_id.clone(),
        proposal_sha256,
        capability_id: proposal.capability_id.clone(),
        capability_binding_sha256: binding.binding_sha256.clone(),
        goal_id: proposal.goal_id.clone(),
        plan_generation_id: proposal.plan_generation_id.clone(),
        source_observation_hash: proposal.source_observation_hash.clone(),
        trusted_source_id: "kernel-e2e-admission-profile".to_owned(),
        trusted_source_sha256: digest(&format!("admission-profile-{label}")),
        gate_results: passed_gates(),
        gate_evidence: gate_evidence(label),
        admission_profile_sha256: empty_hash(),
    }
    .seal()
    .map_err(selection_error)?;
    let outcome = build_grounded_action_candidates(
        pack,
        observation,
        selection,
        &context,
        &[binding],
        goal,
        &world,
        plan,
        &[CandidateGenerationSpecV1 {
            proposal: proposal_spec,
            ranking_profile,
            admission_profile,
        }],
    )
    .map_err(selection_error)?;
    let candidate_set = match outcome {
        ActionCandidateBuildOutcomeV1::Candidates { candidate_set } => candidate_set,
        ActionCandidateBuildOutcomeV1::NoCandidates { .. } => {
            return Err(DesktopError::AccessDenied(
                "all actual action candidates were rejected".to_owned(),
            ));
        }
    };
    let bridge = build_plan_ranker_input_bridge(&candidate_set).map_err(selection_error)?;
    let invocation = module_invocation(
        args,
        ModuleInvocationSpec {
            module_id: "plan-ranker",
            invocation_id: format!("ranker-{label}"),
            payload: serde_json::to_value(&bridge.payload)
                .map_err(|error| DesktopError::Json(error.to_string()))?,
            goal_id: goal.goal_id.clone(),
            source_observation_hash: Some(observation.state_hash.clone()),
            plan_generation_id: Some(plan.plan_generation_id.clone()),
            logical_sequence: logical_tick,
            trust_labels: BTreeSet::from([
                "approved_policy".to_owned(),
                "verified_operational_state".to_owned(),
            ]),
            fixture_hash: bridge.payload_sha256.clone(),
        },
    )?;
    let ranker_envelope = modules.invoke(&invocation)?;
    if ranker_envelope.status != ModuleResultStatus::Succeeded {
        return Err(DesktopError::Integrity(format!(
            "Plan Ranker did not return a successful typed result: status={:?}, unsupported={:?}, error={:?}",
            ranker_envelope.status, ranker_envelope.unsupported_reason, ranker_envelope.error
        )));
    }
    let ranker_payload = ranker_envelope.payload.ok_or_else(|| {
        DesktopError::Integrity("Plan Ranker result payload is absent".to_owned())
    })?;
    let ranker_bytes = serde_json::to_vec(&ranker_payload)
        .map_err(|error| DesktopError::Json(error.to_string()))?;
    let ranker_output: PlanRankingOutputV1 =
        parse_plan_ranking_output_strict(&ranker_bytes).map_err(selection_error)?;
    let validated_ranking = validate_plan_ranking_output(&candidate_set, &bridge, &ranker_output)
        .map_err(selection_error)?;
    let selected = bind_selected_action(
        &candidate_set,
        &bridge,
        &validated_ranking,
        goal,
        &world,
        plan,
        observation,
        selection,
    )
    .map_err(selection_error)?;
    let selected_action_sha256 = canonical_sha256(&selected).map_err(selection_error)?;
    let ready = build_policy_ready_action(&selected).map_err(selection_error)?;
    let candidate_set_sha256 = canonical_sha256(&candidate_set).map_err(selection_error)?;
    Ok(SelectedActionExecution {
        ready,
        candidate_set_sha256,
        ranker_semantic_sha256: canonical_sha256(&ranker_output).map_err(selection_error)?,
        selected_action_sha256,
    })
}
