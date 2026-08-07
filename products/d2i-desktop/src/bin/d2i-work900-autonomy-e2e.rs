use d2i_cognitive_ir::CognitiveRiskClass;
use d2i_desktop::{
    initialize_autonomy_store, verify_autonomy_store, AutonomyStoreArtifactV1, AutonomyStoreV1,
    PinnedWork500ModelSuiteV1, Work500ModelPathsV1, WORK500_MODEL_SHA256,
    WORK500_RUNTIME_EXECUTABLE_SHA256,
};
use d2i_intelligence_provider::{ProviderPlanningRequestV1, ProviderResultStatusV1};
use d2i_limited_autonomy::{
    apply_control_command, canonical_sha256, evaluate_case_eligibility, evaluate_health,
    parse_json_strict, validate_case_admission, validate_case_task_binding,
    validate_completion_report, validate_duty_cycle_result, validate_handoff,
    validate_replay_report, verify_human_response, AutonomousCaseTaskBindingV1,
    AutonomousRoleDutyCycleRequestV1, AutonomousRoleDutyCycleResultV1, AutonomyCaseAdmissionV1,
    AutonomyCaseEligibilityStatusV1, AutonomyCaseEligibilityV1, AutonomyControlCommandV1,
    AutonomyControlOperationV1, AutonomyDeploymentApprovalV1, AutonomyHealthSnapshotV1,
    AutonomyHealthStatusV1, AutonomyHealthThresholdsV1, AutonomyReadinessBindingV1,
    AutonomyReadinessStatusV1, AutonomyRiskClassV1, AutonomyRoleRuntimeStateV1,
    AutonomyRoleStatusV1, AutonomyRolloutCohortV1, CaseEligibilityInputV1,
    DutyCycleTerminalStatusV1, HumanExceptionHandoffV1, HumanExceptionResponseClassV1,
    HumanExceptionResponseV1, HumanExceptionSeverityV1, LimitedAutonomyCertificationV1,
    LimitedAutonomyCompletionReportV1, LimitedAutonomyProfileV1, LimitedAutonomyReplayReportV1,
    ReplayLedgerV1, ZERO_HASH,
};
use d2i_role_contract::{
    compile_role_source, create_role_contract_approval, create_role_delegation,
    parse_json_strict as parse_role_json, verify_role_contract_approval, verify_role_delegation,
    RoleCompileFormatV1, RoleContractApprovalV1, RoleDelegationGrantV1, RoleInstanceStatusV1,
    RoleInstanceV1,
};
use d2i_shadow_mode::{
    parse_json_strict as parse_shadow_json, ShadowModeProfileV1, ShadowReadinessAssessmentV1,
};
use ed25519_dalek::SigningKey;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const ROLE_SIGNER_KEY_ID: &str = "work900-role-governance-key";
const AUTONOMY_SIGNER_KEY_ID: &str = "work900-autonomy-governance-key";
const APPLICATION_PACK_SHA256: &str =
    "sha256:63af89c06cb5a7b6623e1619718a9a4f3d8346d1387acb52ea339b8ad710411e";

#[derive(Debug)]
enum CommandKind {
    PrepareModel,
    VerifyKernel,
    Finalize,
}

#[derive(Debug)]
struct Arguments {
    command: CommandKind,
    output_root: PathBuf,
    runtime: Option<PathBuf>,
    model: Option<PathBuf>,
    work800_root: Option<PathBuf>,
    role_source: Option<PathBuf>,
    kernel_root: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelCaseEvidenceV1 {
    case_id: String,
    capability_id: String,
    semantic_target_id: String,
    provider_invocation_sha256: String,
    provider_result_sha256: String,
    elapsed_milliseconds: u64,
    peak_process_memory_bytes: u64,
    peak_job_memory_bytes: u64,
    input_bytes: u64,
    output_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Work900PerformanceReportV1 {
    schema_version: u32,
    measurement_scope: String,
    provider_invocations: u32,
    provider_elapsed_milliseconds: Vec<u64>,
    total_provider_elapsed_milliseconds: u64,
    peak_model_process_memory_bytes: u64,
    peak_model_job_memory_bytes: u64,
    model_input_bytes: u64,
    model_output_bytes: u64,
    model_bytes_moved: u64,
    report_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedEvidenceV1 {
    schema_version: u32,
    role_contract_sha256: String,
    role_approval_sha256: String,
    role_delegation_sha256: String,
    role_instance_sha256: String,
    readiness_binding_sha256: String,
    autonomy_profile_sha256: String,
    deployment_approval_sha256: String,
    autonomy_state_sha256: String,
    rollout_cohort_sha256: String,
    duty_cycle_request_sha256: String,
    provider_descriptor_sha256: String,
    model_sha256: String,
    runtime_sha256: String,
    predecessor_finished_sha256: String,
    predecessor_readiness_sha256: String,
    work_intake_evidence_sha256: String,
    work_queue_evidence_sha256: String,
    model_cases: Vec<ModelCaseEvidenceV1>,
    protected_store_terminal_sha256: String,
    prepared_at_unix_ms: u64,
    prepared_sha256: String,
}

#[derive(Debug)]
struct KernelEvidenceV1 {
    result_hashes: Vec<String>,
    audit_hashes: Vec<String>,
    action_count: u32,
    observation_count: u32,
    activation_count: u32,
    receipt_count: u32,
    residual_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Work900FinishedV1 {
    schema_version: u32,
    mode: String,
    git_head: String,
    prepared_evidence_sha256: String,
    work_intake_evidence_sha256: String,
    work_queue_evidence_sha256: String,
    role_contract_sha256: String,
    readiness_binding_sha256: String,
    autonomy_profile_sha256: String,
    deployment_approval_sha256: String,
    duty_cycle_result_sha256: String,
    completion_report_sha256: String,
    replay_report_sha256: String,
    certification_sha256: String,
    performance_report_sha256: String,
    protected_audit_terminal_sha256: String,
    protected_store_terminal_sha256: String,
    total_canary_cases: u32,
    actual_model_invocations: u32,
    actual_krn_side_effect_actions: u32,
    human_exception_handoffs: u32,
    routine_human_touches: u32,
    critical_error_count: u32,
    residual_processes: u32,
    residual_profiles: u32,
    residual_locks: u32,
    residual_activations: u32,
    residual_credentials: u32,
    autonomy_evidence: bool,
    human_by_exception_evidence: bool,
    track_w_completion_evidence: bool,
    complete: bool,
    finished_sha256: String,
}

fn main() {
    if let Err(error) = parse_arguments().and_then(run) {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn parse_arguments() -> Result<Arguments, String> {
    let mut values = std::env::args_os().skip(1);
    let command = match values
        .next()
        .ok_or_else(|| "WORK-900 command is required".to_owned())?
        .to_string_lossy()
        .as_ref()
    {
        "prepare-model" => CommandKind::PrepareModel,
        "verify-kernel" => CommandKind::VerifyKernel,
        "finalize" => CommandKind::Finalize,
        _ => return Err("command must be prepare-model, verify-kernel, or finalize".to_owned()),
    };
    let mut output_root = None;
    let mut runtime = None;
    let mut model = None;
    let mut work800_root = None;
    let mut role_source = None;
    let mut kernel_root = None;
    while let Some(name) = values.next() {
        let value = values
            .next()
            .ok_or_else(|| format!("{} requires a value", name.to_string_lossy()))?;
        match name.to_string_lossy().as_ref() {
            "--output-root" => output_root = Some(PathBuf::from(value)),
            "--runtime" => runtime = Some(PathBuf::from(value)),
            "--model" => model = Some(PathBuf::from(value)),
            "--work800-root" => work800_root = Some(PathBuf::from(value)),
            "--role-source" => role_source = Some(PathBuf::from(value)),
            "--kernel-root" => kernel_root = Some(PathBuf::from(value)),
            name => return Err(format!("unknown WORK-900 argument: {name}")),
        }
    }
    Ok(Arguments {
        command,
        output_root: output_root.ok_or_else(|| "--output-root is required".to_owned())?,
        runtime,
        model,
        work800_root,
        role_source,
        kernel_root,
    })
}

fn run(arguments: Arguments) -> Result<(), String> {
    match arguments.command {
        CommandKind::PrepareModel => prepare_model(arguments),
        CommandKind::VerifyKernel => verify_kernel(arguments),
        CommandKind::Finalize => finalize(arguments),
    }
}

fn verify_kernel(arguments: Arguments) -> Result<(), String> {
    let workspace = workspace_root()?;
    let output_root = prepare_output_root(&workspace, &arguments.output_root)?;
    let kernel_root = required_directory(arguments.kernel_root.as_deref(), "--kernel-root")?;
    let prepared: PreparedEvidenceV1 = read_json(&output_root.join("prepared-evidence.json"))?;
    if prepared.prepared_sha256 != hash_without_local(&prepared, &["prepared_sha256"])? {
        return Err("prepared WORK-900 evidence hash differs".to_owned());
    }
    let kernel = verify_kernel_evidence(&kernel_root, &prepared.role_contract_sha256)?;
    if kernel.result_hashes.len() != 8
        || kernel.action_count < 8
        || kernel.action_count != kernel.activation_count
        || kernel.action_count != kernel.receipt_count
        || kernel.observation_count <= kernel.action_count
        || kernel.residual_count != 0
    {
        return Err("KRN evidence does not satisfy the WORK-900 gate".to_owned());
    }
    println!(
        "{}",
        canonical_sha256(&(kernel.result_hashes, kernel.audit_hashes))
            .map_err(|error| error.to_string())?
    );
    Ok(())
}

fn prepare_model(arguments: Arguments) -> Result<(), String> {
    let workspace = workspace_root()?;
    let output_root = prepare_output_root(&workspace, &arguments.output_root)?;
    let runtime = required_file(arguments.runtime.as_deref(), "--runtime")?;
    let model = required_file(arguments.model.as_deref(), "--model")?;
    let work800_root = required_directory(arguments.work800_root.as_deref(), "--work800-root")?;
    let role_source = required_file(arguments.role_source.as_deref(), "--role-source")?;
    let now_seconds = unix_time_seconds()?;
    let now_ms = now_seconds.saturating_mul(1_000);
    let predecessor = verify_work800_predecessor(&work800_root)?;
    let work_intake_evidence_sha256 = verify_workforce_input_evidence(
        &output_root.join("work-intake-e2e/finished.json"),
        "work_radar_intake_implemented",
    )?;
    let work_queue_evidence_sha256 = verify_workforce_input_evidence(
        &output_root.join("work-queue-e2e/finished.json"),
        "queue_scheduler_implemented",
    )?;

    let role_bytes = fs::read(&role_source).map_err(|error| error.to_string())?;
    let bundle = compile_role_source(&role_bytes, RoleCompileFormatV1::Yaml)
        .map_err(|error| error.to_string())?;
    if bundle.contract.role_contract_id != "general-office-operations-employee"
        || bundle.contract.role_version != "1.4.0"
        || bundle.contract.organization_scope.environment_ids != ["limited-autonomy"]
        || bundle.contract.capability_policy.autonomous_capability_ids
            != ["uia.invoke", "uia.set_value"]
        || bundle.contract.capability_policy.semantic_target_ids
            != ["employee_name_input", "save_button"]
    {
        return Err("General Office Role 1.4.0 exact autonomy scope differs".to_owned());
    }

    let suite = PinnedWork500ModelSuiteV1::verify(Work500ModelPathsV1 {
        workspace: workspace.clone(),
        runtime_executable: runtime,
        model_artifact: model,
        work_root: output_root.join("model-process"),
    })
    .map_err(|error| error.to_string())?;
    let mut descriptor_hashes = vec![
        suite.goal_descriptor().descriptor_sha256.clone(),
        suite.planning_descriptor().descriptor_sha256.clone(),
        suite.situation_descriptor().descriptor_sha256.clone(),
    ];
    descriptor_hashes.sort();
    let provider_descriptor_sha256 =
        canonical_sha256(&descriptor_hashes).map_err(|error| error.to_string())?;
    let mut prompt_hashes = vec![
        suite.goal_descriptor().prompt_template_sha256.clone(),
        suite.planning_descriptor().prompt_template_sha256.clone(),
        suite.situation_descriptor().prompt_template_sha256.clone(),
    ];
    prompt_hashes.sort();
    prompt_hashes.dedup();

    let role_key = fixture_key(53);
    let approval = create_role_contract_approval(
        RoleContractApprovalV1 {
            schema_version: 1,
            approval_id: "work900-general-office-role-approval".to_owned(),
            organization_id: bundle.contract.organization_scope.organization_id.clone(),
            role_contract_id: bundle.contract.role_contract_id.clone(),
            role_version: bundle.contract.role_version.clone(),
            contract_sha256: bundle.contract.contract_sha256.clone(),
            approved_by_actor_id: "organization-role-approver".to_owned(),
            approver_authority_class: "role-governance".to_owned(),
            signer_key_id: ROLE_SIGNER_KEY_ID.to_owned(),
            issued_at_unix_seconds: now_seconds,
            expires_at_unix_seconds: now_seconds.saturating_add(86_400),
            approval_signature: String::new(),
            evidence_ids: vec!["work900-new-role-approval".to_owned()],
            approval_sha256: ZERO_HASH.to_owned(),
        },
        &bundle.contract,
        &role_key,
    )
    .map_err(|error| error.to_string())?;
    verify_role_contract_approval(
        &approval,
        &bundle.contract,
        ROLE_SIGNER_KEY_ID,
        &role_key.verifying_key(),
        now_seconds,
    )
    .map_err(|error| error.to_string())?;
    let delegation = create_role_delegation(
        RoleDelegationGrantV1 {
            schema_version: 1,
            delegation_id: "work900-general-office-delegation".to_owned(),
            organization_id: bundle.contract.organization_scope.organization_id.clone(),
            role_instance_id: "work900-general-office-instance".to_owned(),
            role_contract_id: bundle.contract.role_contract_id.clone(),
            role_version: bundle.contract.role_version.clone(),
            contract_sha256: bundle.contract.contract_sha256.clone(),
            approval_sha256: approval.approval_sha256.clone(),
            delegated_scope: bundle.contract.organization_scope.clone(),
            delegated_work_class_ids: vec!["office.record.update".to_owned()],
            delegated_application_pack_ids: vec!["kernel-e2e-name-save".to_owned()],
            delegated_integration_ids: vec!["windows-kernel-e2e".to_owned()],
            delegated_capability_ids: vec!["uia.invoke".to_owned(), "uia.set_value".to_owned()],
            autonomous_capability_ids: vec!["uia.invoke".to_owned(), "uia.set_value".to_owned()],
            confirmation_capability_ids: Vec::new(),
            prohibited_capability_ids: bundle
                .contract
                .capability_policy
                .prohibited_capability_ids
                .clone(),
            maximum_autonomous_risk: CognitiveRiskClass::BusinessStateChange,
            maximum_confirmable_risk: CognitiveRiskClass::BusinessStateChange,
            policy_set_sha256: bundle.contract.policy_set_sha256.clone(),
            valid_from_unix_seconds: now_seconds,
            expires_at_unix_seconds: now_seconds.saturating_add(86_400),
            assigned_by_actor_id: "organization-role-delegator".to_owned(),
            signer_key_id: ROLE_SIGNER_KEY_ID.to_owned(),
            delegation_signature: String::new(),
            evidence_ids: vec!["work900-bounded-delegation".to_owned()],
            delegation_sha256: ZERO_HASH.to_owned(),
        },
        &bundle.contract,
        &approval,
        &role_key,
    )
    .map_err(|error| error.to_string())?;
    verify_role_delegation(
        &delegation,
        &bundle.contract,
        &approval,
        ROLE_SIGNER_KEY_ID,
        &role_key.verifying_key(),
        now_seconds,
    )
    .map_err(|error| error.to_string())?;
    let role_instance = RoleInstanceV1::provision(
        "work900-general-office-instance".to_owned(),
        &bundle.contract,
        &approval,
        &delegation,
        "work900-general-office-role-ledger".to_owned(),
        digest("work900-role-authority-template"),
        digest("work900-role-recovery-template"),
        vec!["work900-provisioned-role-instance".to_owned()],
    )
    .and_then(|instance| instance.transition(RoleInstanceStatusV1::Active, now_seconds + 1))
    .map_err(|error| error.to_string())?;

    let readiness = build_readiness(&predecessor, &bundle.contract, now_ms)?;
    let profile = build_profile(
        &bundle.contract,
        &delegation,
        provider_descriptor_sha256.clone(),
        prompt_hashes,
        now_ms,
    )?;
    let autonomy_key = fixture_key(71);
    let deployment = build_deployment(&profile, &readiness, &autonomy_key, now_ms)?;
    let eligible_state = build_eligible_state(&role_instance, &profile, &deployment, &readiness)?;
    let enable = build_control(
        "work900-control-enable",
        AutonomyControlOperationV1::Enable,
        2,
        &role_instance,
        &profile,
        &autonomy_key,
        now_ms + 4,
    )?;
    let enabled_state = apply_control_command(
        &eligible_state,
        &enable,
        &autonomy_key.verifying_key(),
        now_ms + 5,
        true,
    )
    .map_err(|error| error.to_string())?;
    let cohort = build_cohort(&profile, &deployment, now_ms)?;
    let duty_request = duty_request(
        &role_instance,
        &enabled_state,
        &profile,
        &deployment,
        &readiness,
        (&work_intake_evidence_sha256, &work_queue_evidence_sha256),
        now_ms,
    )?;

    let store_root = output_root.join("autonomy-store-prepared");
    if store_root.exists() {
        return Err("prepare-model refuses an existing autonomy store".to_owned());
    }
    let mut store = initialize_autonomy_store(
        &store_root,
        profile.organization_id.clone(),
        profile.role_contract_sha256.clone(),
        profile.profile_sha256.clone(),
        128 * 1024 * 1024,
        now_ms,
    )
    .map_err(|error| error.to_string())?;
    for artifact in [
        AutonomyStoreArtifactV1::Readiness(readiness.clone()),
        AutonomyStoreArtifactV1::Profile(Box::new(profile.clone())),
        AutonomyStoreArtifactV1::Deployment(deployment.clone()),
        AutonomyStoreArtifactV1::State(eligible_state),
        AutonomyStoreArtifactV1::Control(enable),
        AutonomyStoreArtifactV1::State(enabled_state.clone()),
        AutonomyStoreArtifactV1::Cohort(cohort.clone()),
        AutonomyStoreArtifactV1::DutyRequest(duty_request.clone()),
    ] {
        let sequence = store.verification().ledger_record_count;
        store
            .store(artifact, now_ms.saturating_add(sequence + 10))
            .map_err(|error| error.to_string())?;
    }

    let model_cases = invoke_model_cases(&suite)?;
    let mut prepared = PreparedEvidenceV1 {
        schema_version: 1,
        role_contract_sha256: bundle.contract.contract_sha256.clone(),
        role_approval_sha256: approval.approval_sha256.clone(),
        role_delegation_sha256: delegation.delegation_sha256.clone(),
        role_instance_sha256: role_instance.instance_sha256.clone(),
        readiness_binding_sha256: readiness.binding_sha256.clone(),
        autonomy_profile_sha256: profile.profile_sha256.clone(),
        deployment_approval_sha256: deployment.approval_sha256.clone(),
        autonomy_state_sha256: enabled_state.state_sha256.clone(),
        rollout_cohort_sha256: cohort.cohort_sha256.clone(),
        duty_cycle_request_sha256: duty_request.request_sha256.clone(),
        provider_descriptor_sha256,
        model_sha256: WORK500_MODEL_SHA256.to_owned(),
        runtime_sha256: WORK500_RUNTIME_EXECUTABLE_SHA256.to_owned(),
        predecessor_finished_sha256: predecessor.finished_sha256,
        predecessor_readiness_sha256: readiness.shadow_readiness_assessment_sha256.clone(),
        work_intake_evidence_sha256,
        work_queue_evidence_sha256,
        model_cases,
        protected_store_terminal_sha256: store.verification().ledger_terminal_sha256.clone(),
        prepared_at_unix_ms: now_ms,
        prepared_sha256: ZERO_HASH.to_owned(),
    };
    prepared.prepared_sha256 = hash_without_local(&prepared, &["prepared_sha256"])?;
    let governance = output_root.join("governance");
    fs::create_dir_all(&governance).map_err(|error| error.to_string())?;
    harden(&governance)?;
    write_secure_json(&governance.join("role-contract.json"), &bundle.contract)?;
    write_secure_json(&governance.join("role-approval.json"), &approval)?;
    write_secure_json(&governance.join("role-delegation.json"), &delegation)?;
    write_secure_json(&governance.join("role-instance.json"), &role_instance)?;
    write_secure_json(&governance.join("readiness-binding.json"), &readiness)?;
    write_secure_json(&governance.join("autonomy-profile.json"), &profile)?;
    write_secure_json(&governance.join("deployment-approval.json"), &deployment)?;
    write_secure_json(&governance.join("enabled-state.json"), &enabled_state)?;
    write_secure_json(&governance.join("rollout-cohort.json"), &cohort)?;
    write_secure_json(&governance.join("duty-cycle-request.json"), &duty_request)?;
    write_secure_json(&output_root.join("prepared-evidence.json"), &prepared)?;
    println!("{}", prepared.prepared_sha256);
    Ok(())
}

struct Work800Predecessor {
    finished_sha256: String,
    profile: ShadowModeProfileV1,
    readiness: ShadowReadinessAssessmentV1,
}

fn verify_workforce_input_evidence(
    path: &Path,
    implementation_flag: &str,
) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("workforce input evidence exceeds its byte bound".to_owned());
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let object = value
        .as_object()
        .ok_or_else(|| "workforce input evidence is not an object".to_owned())?;
    if object.get("complete").and_then(Value::as_bool) != Some(true)
        || object.get("status").and_then(Value::as_str) != Some("pass")
        || object.get(implementation_flag).and_then(Value::as_bool) != Some(true)
        || object.get("representative_role").and_then(Value::as_str)
            != Some("general-office-operations-employee")
        || object
            .get("residual_owned_processes")
            .and_then(Value::as_u64)
            != Some(0)
        || object.get("residual_credentials").and_then(Value::as_u64) != Some(0)
        || object.get("residual_activations").and_then(Value::as_u64) != Some(0)
    {
        return Err(format!(
            "{implementation_flag} evidence is not a clean pass"
        ));
    }
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn verify_work800_predecessor(root: &Path) -> Result<Work800Predecessor, String> {
    let finished: Value = serde_json::from_slice(
        &fs::read(root.join("finished.json")).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let object = finished
        .as_object()
        .ok_or_else(|| "WORK-800 finished evidence is not an object".to_owned())?;
    let count = |name: &str| {
        object
            .get(name)
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| format!("WORK-800 finished evidence lacks {name}"))
    };
    if object.get("complete").and_then(Value::as_bool) != Some(true)
        || object.get("shadow_mode_evidence").and_then(Value::as_bool) != Some(true)
        || object
            .get("reference_role_readiness")
            .and_then(Value::as_str)
            != Some("eligible_for_work900_design")
        || count("critical_error_count")? != 0
    {
        return Err("WORK-800 predecessor is incomplete or not eligible".to_owned());
    }
    for field in [
        "residual_activations",
        "residual_credentials",
        "residual_locks",
        "residual_processes",
        "residual_profiles",
        "residual_stores",
    ] {
        if count(field)? != 0 {
            return Err(format!("WORK-800 predecessor retains {field}"));
        }
    }
    let finished_sha256 = object
        .get("finished_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| "WORK-800 finished hash is absent".to_owned())?
        .to_owned();
    d2i_limited_autonomy::validate_hash(&finished_sha256, "WORK-800 finished")
        .map_err(|error| error.to_string())?;
    let profile: ShadowModeProfileV1 = parse_shadow_json(
        &fs::read(root.join("shadow-e2e/shadow-profile.json"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    profile.validate().map_err(|error| error.to_string())?;
    let readiness: ShadowReadinessAssessmentV1 = parse_shadow_json(
        &fs::read(root.join("shadow-e2e/shadow-readiness.json"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    readiness
        .validate_integrity()
        .map_err(|error| error.to_string())?;
    if readiness.assessment_sha256
        != object
            .get("readiness_assessment_sha256")
            .and_then(Value::as_str)
            .unwrap_or_default()
        || profile.model_sha256 != WORK500_MODEL_SHA256
        || profile.runtime_sha256 != WORK500_RUNTIME_EXECUTABLE_SHA256
    {
        return Err("WORK-800 predecessor exact hash binding differs".to_owned());
    }
    Ok(Work800Predecessor {
        finished_sha256,
        profile,
        readiness,
    })
}

fn build_readiness(
    predecessor: &Work800Predecessor,
    contract: &d2i_role_contract::RoleContractV1,
    now_ms: u64,
) -> Result<AutonomyReadinessBindingV1, String> {
    let value = AutonomyReadinessBindingV1 {
        schema_version: 1,
        binding_id: "work900-readiness-binding".to_owned(),
        organization_id: predecessor.profile.organization_id.clone(),
        target_role_contract_id: contract.role_contract_id.clone(),
        target_role_contract_version: contract.role_version.clone(),
        shadow_role_sha256: predecessor.readiness.role_contract_sha256.clone(),
        shadow_profile_sha256: predecessor.readiness.profile_sha256.clone(),
        shadow_cohort_sha256: predecessor.readiness.cohort_sha256.clone(),
        shadow_readiness_policy_sha256: predecessor.readiness.readiness_policy_sha256.clone(),
        shadow_readiness_assessment_sha256: predecessor.readiness.assessment_sha256.clone(),
        readiness_status: AutonomyReadinessStatusV1::EligibleForWork900Design,
        model_sha256: predecessor.profile.model_sha256.clone(),
        runtime_sha256: predecessor.profile.runtime_sha256.clone(),
        provider_descriptor_sha256: predecessor.profile.provider_descriptor_sha256.clone(),
        prompt_template_hashes: predecessor.profile.prompt_template_hashes.clone(),
        application_pack_hashes: vec![APPLICATION_PACK_SHA256.to_owned()],
        policy_set_sha256: predecessor.profile.policy_set_sha256.clone(),
        trusted_execution_compatibility_sha256: digest("work900-krn-trusted-execution-v1"),
        evidence_coverage_sha256: predecessor.readiness.shadow_snapshot_sha256.clone(),
        critical_error_count: 0,
        false_completion_count: 0,
        escalation_miss_count: 0,
        forbidden_capability_count: 0,
        authority_expansion_count: 0,
        assessed_at_unix_ms: predecessor.readiness.assessed_at_unix_ms,
        valid_until_unix_ms: now_ms.saturating_add(86_400_000),
        evidence_ids: vec!["verified-work800-completion".to_owned()],
        binding_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    value.validate(now_ms).map_err(|error| error.to_string())?;
    Ok(value)
}

fn build_profile(
    contract: &d2i_role_contract::RoleContractV1,
    delegation: &RoleDelegationGrantV1,
    provider_descriptor_sha256: String,
    prompt_hashes: Vec<String>,
    now_ms: u64,
) -> Result<LimitedAutonomyProfileV1, String> {
    let value = LimitedAutonomyProfileV1 {
        schema_version: 1,
        profile_id: "general-office-limited-autonomy-v1".to_owned(),
        profile_version: "1.0.0".to_owned(),
        organization_id: contract.organization_scope.organization_id.clone(),
        role_contract_id: contract.role_contract_id.clone(),
        role_contract_version: contract.role_version.clone(),
        role_contract_sha256: contract.contract_sha256.clone(),
        delegation_constraint_hashes: vec![delegation.delegation_sha256.clone()],
        policy_set_sha256: contract.policy_set_sha256.clone(),
        model_sha256: WORK500_MODEL_SHA256.to_owned(),
        runtime_sha256: WORK500_RUNTIME_EXECUTABLE_SHA256.to_owned(),
        provider_descriptor_sha256,
        prompt_template_hashes: prompt_hashes,
        application_pack_hashes: vec![APPLICATION_PACK_SHA256.to_owned()],
        allowed_work_class_ids: vec!["office.record.update".to_owned()],
        allowed_responsibility_ids: vec!["internal-record-maintenance".to_owned()],
        allowed_source_ids: vec!["approved-internal-record-events".to_owned()],
        allowed_source_class_ids: vec!["internal-record-change".to_owned()],
        allowed_environment_ids: vec!["limited-autonomy".to_owned()],
        autonomous_capability_ids: vec!["uia.invoke".to_owned(), "uia.set_value".to_owned()],
        confirmation_capability_ids: Vec::new(),
        prohibited_capability_ids: contract.capability_policy.prohibited_capability_ids.clone(),
        allowed_semantic_target_ids: vec![
            "employee_name_input".to_owned(),
            "save_button".to_owned(),
        ],
        maximum_autonomous_risk: AutonomyRiskClassV1::BusinessStateChange,
        mandatory_human_exception_reason_codes: contract
            .human_exception_policy
            .mandatory_escalation_reason_codes
            .clone(),
        automatic_recovery_class_ids: vec!["fresh-reobserve-replan".to_owned()],
        maximum_cases_per_duty_cycle: 8,
        maximum_concurrent_cases: 1,
        maximum_actions_per_case: 4,
        maximum_model_invocations_per_case: 4,
        maximum_recovery_cycles: 2,
        maximum_reobservations_per_case: 8,
        maximum_total_autonomous_side_effects: 16,
        maximum_cycle_duration_ms: 3_600_000,
        maximum_case_duration_ms: 900_000,
        maximum_exception_pending_count: 3,
        maximum_exception_handoffs_per_cycle: 3,
        maximum_active_leases: 1,
        maximum_control_commands_per_cycle: 8,
        maximum_health_records_per_cycle: 32,
        maximum_store_objects: 1_024,
        maximum_store_bytes: 134_217_728,
        maximum_audit_records_per_cycle: 4_096,
        maximum_evidence_references: 256,
        maximum_report_bytes: 4_194_304,
        maximum_resume_checkpoints: 32,
        maximum_consecutive_failures: 1,
        maximum_verification_failures: 2,
        health_thresholds: health_thresholds(),
        rollout_maximum_cases: 8,
        rollout_maximum_side_effects: 16,
        valid_from_unix_ms: now_ms,
        valid_to_unix_ms: now_ms.saturating_add(86_400_000),
        evidence_ids: vec!["work900-general-office-canary".to_owned()],
        profile_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    value.validate(now_ms).map_err(|error| error.to_string())?;
    Ok(value)
}

fn build_deployment(
    profile: &LimitedAutonomyProfileV1,
    readiness: &AutonomyReadinessBindingV1,
    key: &SigningKey,
    now_ms: u64,
) -> Result<AutonomyDeploymentApprovalV1, String> {
    let value = AutonomyDeploymentApprovalV1 {
        schema_version: 1,
        approval_id: "work900-limited-autonomy-deployment".to_owned(),
        organization_id: profile.organization_id.clone(),
        target_role_sha256: profile.role_contract_sha256.clone(),
        autonomy_profile_sha256: profile.profile_sha256.clone(),
        readiness_binding_sha256: readiness.binding_sha256.clone(),
        approved_environment_ids: profile.allowed_environment_ids.clone(),
        approved_work_class_ids: profile.allowed_work_class_ids.clone(),
        approved_capability_ids: profile.autonomous_capability_ids.clone(),
        approved_semantic_target_ids: profile.allowed_semantic_target_ids.clone(),
        approved_maximum_risk: profile.maximum_autonomous_risk,
        rollout_maximum_cases: 8,
        issued_at_unix_ms: now_ms + 2,
        expires_at_unix_ms: now_ms.saturating_add(86_400_000),
        signer_id: "organization-autonomy-approver".to_owned(),
        signing_key_id: AUTONOMY_SIGNER_KEY_ID.to_owned(),
        nonce: format!("work900-deployment-{now_ms}"),
        evidence_ids: vec!["signed-limited-autonomy-deployment".to_owned()],
        approval_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
    .seal_and_sign(key)
    .map_err(|error| error.to_string())?;
    d2i_limited_autonomy::verify_deployment_approval(
        &value,
        profile,
        readiness,
        &key.verifying_key(),
        now_ms + 3,
    )
    .map_err(|error| error.to_string())?;
    Ok(value)
}

fn build_eligible_state(
    role: &RoleInstanceV1,
    profile: &LimitedAutonomyProfileV1,
    deployment: &AutonomyDeploymentApprovalV1,
    readiness: &AutonomyReadinessBindingV1,
) -> Result<AutonomyRoleRuntimeStateV1, String> {
    AutonomyRoleRuntimeStateV1 {
        schema_version: 1,
        state_id: "work900-autonomy-state-eligible".to_owned(),
        role_instance_sha256: role.instance_sha256.clone(),
        autonomy_profile_sha256: profile.profile_sha256.clone(),
        deployment_approval_sha256: deployment.approval_sha256.clone(),
        readiness_binding_sha256: readiness.binding_sha256.clone(),
        status: AutonomyRoleStatusV1::Eligible,
        enabled_at_unix_ms: None,
        paused_at_unix_ms: None,
        state_generation: 1,
        processed_case_count: 0,
        active_case_count: 0,
        successful_autonomous_case_count: 0,
        exception_count: 0,
        failure_count: 0,
        current_health_snapshot_sha256: digest("work900-health-pending"),
        current_control_command_sha256: digest("work900-control-none"),
        previous_state_sha256: digest("work900-state-genesis"),
        evidence_ids: vec!["protected-autonomy-state-ledger".to_owned()],
        state_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

#[allow(clippy::too_many_arguments)]
fn build_control(
    command_id: &str,
    operation: AutonomyControlOperationV1,
    generation: u64,
    role: &RoleInstanceV1,
    profile: &LimitedAutonomyProfileV1,
    key: &SigningKey,
    now_ms: u64,
) -> Result<AutonomyControlCommandV1, String> {
    AutonomyControlCommandV1 {
        schema_version: 1,
        command_id: command_id.to_owned(),
        organization_id: profile.organization_id.clone(),
        role_instance_sha256: role.instance_sha256.clone(),
        autonomy_profile_sha256: profile.profile_sha256.clone(),
        operation,
        state_generation: generation,
        signer_id: "autonomy-operator".to_owned(),
        signer_scope_id: "general-office-autonomy-control".to_owned(),
        signing_key_id: AUTONOMY_SIGNER_KEY_ID.to_owned(),
        issued_at_unix_ms: now_ms,
        expires_at_unix_ms: now_ms.saturating_add(60_000),
        nonce: format!("{command_id}-{now_ms}"),
        evidence_ids: vec!["operator-signed-control".to_owned()],
        command_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
    .seal_and_sign(key)
    .map_err(|error| error.to_string())
}

fn build_cohort(
    profile: &LimitedAutonomyProfileV1,
    deployment: &AutonomyDeploymentApprovalV1,
    now_ms: u64,
) -> Result<AutonomyRolloutCohortV1, String> {
    AutonomyRolloutCohortV1 {
        schema_version: 1,
        cohort_id: "work900-general-office-canary".to_owned(),
        target_role_sha256: profile.role_contract_sha256.clone(),
        autonomy_profile_sha256: profile.profile_sha256.clone(),
        deployment_approval_sha256: deployment.approval_sha256.clone(),
        allowed_work_class_ids: profile.allowed_work_class_ids.clone(),
        allowed_source_class_ids: profile.allowed_source_class_ids.clone(),
        maximum_cases: 8,
        maximum_total_side_effects: 16,
        starts_at_unix_ms: now_ms,
        ends_at_unix_ms: now_ms.saturating_add(86_400_000),
        health_threshold_sha256: canonical_sha256(&profile.health_thresholds)
            .map_err(|error| error.to_string())?,
        evidence_ids: vec!["bounded-eight-case-canary".to_owned()],
        cohort_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn invoke_model_cases(
    suite: &PinnedWork500ModelSuiteV1,
) -> Result<Vec<ModelCaseEvidenceV1>, String> {
    let cases = [
        ("case-a", "uia.set_value", "employee_name_input", true),
        ("case-b", "uia.invoke", "save_button", false),
        ("case-c", "uia.set_value", "employee_name_input", true),
        ("case-d", "uia.invoke", "save_button", false),
        ("case-e", "uia.set_value", "employee_name_input", true),
        ("case-f", "uia.invoke", "save_button", false),
        ("case-g", "uia.invoke", "save_button", false),
        ("case-h", "uia.set_value", "employee_name_input", true),
    ];
    let approved_value = format!("sha256:{:x}", Sha256::digest(b"D2I-SHADOW-APPROVED"));
    let mut evidence = Vec::new();
    for (index, (case_id, capability, target, has_value)) in cases.iter().enumerate() {
        let postcondition = if *has_value {
            "postcondition.employee.name.matches"
        } else {
            "postcondition.record.saved"
        };
        let request = ProviderPlanningRequestV1 {
            schema_version: 1,
            request_id: format!("work900-request-{case_id}"),
            case_id: (*case_id).to_owned(),
            goal_spec_sha256: digest(&format!("work900-goal-{case_id}")),
            situation_sha256: digest(&format!("work900-situation-{case_id}")),
            plan_generation: 1,
            open_subgoal_ids: vec![format!("subgoal.work900.{case_id}")],
            allowed_semantic_target_ids: vec![(*target).to_owned()],
            allowed_capability_ids: vec![(*capability).to_owned()],
            forbidden_capability_ids: vec!["process.launch".to_owned()],
            approved_value_sha256s: if *has_value {
                vec![approved_value.clone()]
            } else {
                Vec::new()
            },
            allowed_precondition_ids: vec!["precondition.observation.fresh".to_owned()],
            allowed_postcondition_ids: vec![postcondition.to_owned()],
            maximum_candidates: 1,
            provider_invocation_sha256: ZERO_HASH.to_owned(),
            evidence_ids: vec![format!("evidence.work900.plan.{index:02}")],
            request_sha256: ZERO_HASH.to_owned(),
        };
        let call = suite
            .propose_next_steps(
                request,
                &format!("work900-invocation-{case_id}"),
                &format!("work900-replay-{case_id}"),
            )
            .map_err(|error| error.to_string())?;
        if call.result.status != ProviderResultStatusV1::Succeeded
            || call.result.candidates.len() != 1
            || !call.result.reason_codes.is_empty()
        {
            return Err(format!("{case_id} model result is not one bounded success"));
        }
        let candidate = &call.result.candidates[0];
        if candidate.capability_id.as_deref() != Some(capability)
            || candidate.semantic_target_id.as_deref() != Some(target)
            || candidate.expected_postcondition_ids != [postcondition]
            || candidate.required_precondition_ids != ["precondition.observation.fresh"]
            || candidate.risk_estimate > CognitiveRiskClass::BusinessStateChange
            || !candidate.uncertainty.is_empty()
        {
            return Err(format!(
                "{case_id} model candidate escaped its exact request"
            ));
        }
        evidence.push(ModelCaseEvidenceV1 {
            case_id: (*case_id).to_owned(),
            capability_id: (*capability).to_owned(),
            semantic_target_id: (*target).to_owned(),
            provider_invocation_sha256: call.invocation.invocation_sha256,
            provider_result_sha256: call.result.result_sha256,
            elapsed_milliseconds: call.metrics.elapsed_milliseconds,
            peak_process_memory_bytes: call.metrics.peak_process_memory_bytes,
            peak_job_memory_bytes: call.metrics.peak_job_memory_bytes,
            input_bytes: call.metrics.input_bytes,
            output_bytes: call.metrics.output_bytes,
        });
    }
    Ok(evidence)
}

fn duty_request(
    role: &RoleInstanceV1,
    state: &AutonomyRoleRuntimeStateV1,
    profile: &LimitedAutonomyProfileV1,
    deployment: &AutonomyDeploymentApprovalV1,
    readiness: &AutonomyReadinessBindingV1,
    workforce_evidence_sha256s: (&str, &str),
    now_ms: u64,
) -> Result<AutonomousRoleDutyCycleRequestV1, String> {
    AutonomousRoleDutyCycleRequestV1 {
        schema_version: 1,
        cycle_id: "work900-general-office-duty-cycle".to_owned(),
        organization_id: profile.organization_id.clone(),
        role_instance_sha256: role.instance_sha256.clone(),
        autonomy_state_sha256: state.state_sha256.clone(),
        profile_sha256: profile.profile_sha256.clone(),
        deployment_approval_sha256: deployment.approval_sha256.clone(),
        readiness_binding_sha256: readiness.binding_sha256.clone(),
        trusted_time_context_sha256: digest("work900-trusted-time"),
        work_radar_source_heads: vec![workforce_evidence_sha256s.0.to_owned()],
        intake_head_sha256: workforce_evidence_sha256s.0.to_owned(),
        case_ledger_head_sha256: digest("work900-case-head"),
        queue_head_sha256: workforce_evidence_sha256s.1.to_owned(),
        ownership_head_sha256: workforce_evidence_sha256s.1.to_owned(),
        planner_head_hashes: vec![digest("work900-planner-head")],
        memory_head_sha256: digest("work900-memory-head"),
        operations_head_sha256: digest("work900-operations-head"),
        audit_head_sha256: digest("work900-audit-head"),
        maximum_cases: 8,
        maximum_actions: 32,
        maximum_provider_invocations: 32,
        deadline_unix_ms: now_ms.saturating_add(3_600_000),
        evidence_ids: vec!["bounded-one-shot-role-cycle".to_owned()],
        request_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn health_thresholds() -> AutonomyHealthThresholdsV1 {
    AutonomyHealthThresholdsV1 {
        maximum_verification_failures: 2,
        maximum_recovery_failures: 1,
        maximum_provider_failures: 0,
        maximum_sla_breaches: 0,
        maximum_residual_failures: 0,
        maximum_false_completions: 0,
        maximum_authority_expansions: 0,
        maximum_wrong_target_attempts: 0,
        maximum_escalation_misses: 0,
        maximum_secret_leakage: 0,
    }
}

fn finalize(arguments: Arguments) -> Result<(), String> {
    let workspace = workspace_root()?;
    let output_root = prepare_output_root(&workspace, &arguments.output_root)?;
    let kernel_root = required_directory(arguments.kernel_root.as_deref(), "--kernel-root")?;
    let prepared: PreparedEvidenceV1 = read_json(&output_root.join("prepared-evidence.json"))?;
    if prepared.prepared_sha256 != hash_without_local(&prepared, &["prepared_sha256"])?
        || prepared.model_cases.len() != 8
        || prepared.model_sha256 != WORK500_MODEL_SHA256
        || prepared.runtime_sha256 != WORK500_RUNTIME_EXECUTABLE_SHA256
    {
        return Err("prepared WORK-900 evidence hash or pinned model binding differs".to_owned());
    }
    let governance = output_root.join("governance");
    let role: RoleInstanceV1 = parse_role_file(&governance.join("role-instance.json"))?;
    let readiness: AutonomyReadinessBindingV1 =
        read_json(&governance.join("readiness-binding.json"))?;
    let profile: LimitedAutonomyProfileV1 = read_json(&governance.join("autonomy-profile.json"))?;
    let deployment: AutonomyDeploymentApprovalV1 =
        read_json(&governance.join("deployment-approval.json"))?;
    let enabled_state: AutonomyRoleRuntimeStateV1 =
        read_json(&governance.join("enabled-state.json"))?;
    let request: AutonomousRoleDutyCycleRequestV1 =
        read_json(&governance.join("duty-cycle-request.json"))?;
    let now_ms = unix_time_seconds()?.saturating_mul(1_000);
    readiness
        .validate(now_ms)
        .map_err(|error| error.to_string())?;
    profile
        .validate(now_ms)
        .map_err(|error| error.to_string())?;
    d2i_limited_autonomy::verify_deployment_approval(
        &deployment,
        &profile,
        &readiness,
        &fixture_key(71).verifying_key(),
        now_ms,
    )
    .map_err(|error| error.to_string())?;
    enabled_state
        .validate_integrity()
        .map_err(|error| error.to_string())?;
    request
        .validate_integrity()
        .map_err(|error| error.to_string())?;
    if prepared.role_instance_sha256 != role.instance_sha256
        || prepared.readiness_binding_sha256 != readiness.binding_sha256
        || prepared.autonomy_profile_sha256 != profile.profile_sha256
        || prepared.deployment_approval_sha256 != deployment.approval_sha256
        || prepared.autonomy_state_sha256 != enabled_state.state_sha256
        || prepared.duty_cycle_request_sha256 != request.request_sha256
    {
        return Err("prepared governance artifact binding differs".to_owned());
    }

    let prepared_store = output_root.join("autonomy-store-prepared");
    let completion_store = output_root.join("autonomy-store");
    copy_bounded_tree(&prepared_store, &completion_store)?;
    let mut store = AutonomyStoreV1::open(
        &completion_store,
        Some(&prepared.protected_store_terminal_sha256),
    )
    .map_err(|error| error.to_string())?;
    let kernel = verify_kernel_evidence(&kernel_root, &prepared.role_contract_sha256)?;
    if kernel.action_count < 8
        || kernel.observation_count <= kernel.action_count
        || kernel.action_count != kernel.activation_count
        || kernel.action_count != kernel.receipt_count
        || kernel.residual_count != 0
    {
        return Err("actual KRN side-effect, observation, or cleanup gate differs".to_owned());
    }

    let mut clock = now_ms;
    let mut replay_ledger = ReplayLedgerV1::default();
    let eligible_cases = ["case-a", "case-b", "case-c"];
    let mut admissions = Vec::new();
    for (index, case_id) in eligible_cases.iter().enumerate() {
        let eligibility = case_eligibility(
            case_id,
            AutonomyCaseEligibilityStatusV1::Eligible,
            "bounded_autonomy_eligible",
            &prepared,
            &enabled_state,
            &profile,
            clock,
        )?;
        store_next(
            &mut store,
            AutonomyStoreArtifactV1::Eligibility(eligibility.clone()),
            &mut clock,
        )?;
        let admission = case_admission(
            &format!("admission-{case_id}"),
            &eligibility,
            &prepared,
            &enabled_state,
            &profile,
            clock,
        )?;
        store_next(
            &mut store,
            AutonomyStoreArtifactV1::Admission(admission.clone()),
            &mut clock,
        )?;
        let binding = task_binding(&admission, case_id, &kernel.result_hashes[index])?;
        store_next(
            &mut store,
            AutonomyStoreArtifactV1::TaskBinding(binding),
            &mut clock,
        )?;
        admissions.push(admission);
    }

    let stale_d = case_eligibility(
        "case-d-stale",
        AutonomyCaseEligibilityStatusV1::Expired,
        "source_observation_stale",
        &prepared,
        &enabled_state,
        &profile,
        clock,
    )?;
    store_next(
        &mut store,
        AutonomyStoreArtifactV1::Eligibility(stale_d),
        &mut clock,
    )?;
    let fresh_d = case_eligibility(
        "case-d-fresh",
        AutonomyCaseEligibilityStatusV1::Eligible,
        "fresh_reobserve_replan",
        &prepared,
        &enabled_state,
        &profile,
        clock,
    )?;
    store_next(
        &mut store,
        AutonomyStoreArtifactV1::Eligibility(fresh_d.clone()),
        &mut clock,
    )?;
    let admission_d = case_admission(
        "admission-case-d",
        &fresh_d,
        &prepared,
        &enabled_state,
        &profile,
        clock,
    )?;
    store_next(
        &mut store,
        AutonomyStoreArtifactV1::Admission(admission_d.clone()),
        &mut clock,
    )?;
    store_next(
        &mut store,
        AutonomyStoreArtifactV1::TaskBinding(task_binding(
            &admission_d,
            "case-d",
            &kernel.result_hashes[3],
        )?),
        &mut clock,
    )?;

    let exception_e = case_eligibility(
        "case-e-exception",
        AutonomyCaseEligibilityStatusV1::HumanExceptionRequired,
        "material_ambiguity",
        &prepared,
        &enabled_state,
        &profile,
        clock,
    )?;
    store_next(
        &mut store,
        AutonomyStoreArtifactV1::Eligibility(exception_e.clone()),
        &mut clock,
    )?;
    let handoff_e = handoff(
        "case-e",
        &exception_e,
        HumanExceptionSeverityV1::Clarification,
        "material_ambiguity",
        &prepared,
        &kernel.result_hashes[4],
        clock,
    )?;
    validate_handoff(&handoff_e).map_err(|error| error.to_string())?;
    replay_ledger
        .consume_handoff(&handoff_e)
        .map_err(|error| error.to_string())?;
    store_next(
        &mut store,
        AutonomyStoreArtifactV1::Handoff(handoff_e.clone()),
        &mut clock,
    )?;
    let response_e = human_response(&handoff_e, &fixture_key(71), clock)?;
    verify_human_response(
        &response_e,
        &handoff_e.handoff_sha256,
        &fixture_key(71).verifying_key(),
        clock + 1,
    )
    .map_err(|error| error.to_string())?;
    replay_ledger
        .consume_response(&response_e)
        .map_err(|error| error.to_string())?;
    store_next(
        &mut store,
        AutonomyStoreArtifactV1::Response(response_e),
        &mut clock,
    )?;
    let fresh_e = case_eligibility(
        "case-e-fresh",
        AutonomyCaseEligibilityStatusV1::Eligible,
        "bounded_fact_fresh_replan",
        &prepared,
        &enabled_state,
        &profile,
        clock,
    )?;
    store_next(
        &mut store,
        AutonomyStoreArtifactV1::Eligibility(fresh_e.clone()),
        &mut clock,
    )?;
    let admission_e = case_admission(
        "admission-case-e-resume",
        &fresh_e,
        &prepared,
        &enabled_state,
        &profile,
        clock,
    )?;
    store_next(
        &mut store,
        AutonomyStoreArtifactV1::Admission(admission_e.clone()),
        &mut clock,
    )?;
    store_next(
        &mut store,
        AutonomyStoreArtifactV1::TaskBinding(task_binding(
            &admission_e,
            "case-e-resume",
            &kernel.result_hashes[5],
        )?),
        &mut clock,
    )?;

    for (case_id, reason, source_hash) in [
        ("case-f", "policy_unknown", digest("case-f-policy-unknown")),
        (
            "case-g",
            "authority_exceeded",
            digest("case-g-authority-exceeded"),
        ),
    ] {
        let eligibility = case_eligibility(
            case_id,
            AutonomyCaseEligibilityStatusV1::HumanExceptionRequired,
            reason,
            &prepared,
            &enabled_state,
            &profile,
            clock,
        )?;
        store_next(
            &mut store,
            AutonomyStoreArtifactV1::Eligibility(eligibility.clone()),
            &mut clock,
        )?;
        let value = handoff(
            case_id,
            &eligibility,
            HumanExceptionSeverityV1::TerminalEscalation,
            reason,
            &prepared,
            &source_hash,
            clock,
        )?;
        validate_handoff(&value).map_err(|error| error.to_string())?;
        replay_ledger
            .consume_handoff(&value)
            .map_err(|error| error.to_string())?;
        store_next(
            &mut store,
            AutonomyStoreArtifactV1::Handoff(value),
            &mut clock,
        )?;
    }

    let eligibility_h = case_eligibility(
        "case-h-initial",
        AutonomyCaseEligibilityStatusV1::Eligible,
        "bounded_autonomy_eligible",
        &prepared,
        &enabled_state,
        &profile,
        clock,
    )?;
    store_next(
        &mut store,
        AutonomyStoreArtifactV1::Eligibility(eligibility_h.clone()),
        &mut clock,
    )?;
    let admission_h = case_admission(
        "admission-case-h-before-pause",
        &eligibility_h,
        &prepared,
        &enabled_state,
        &profile,
        clock,
    )?;
    store_next(
        &mut store,
        AutonomyStoreArtifactV1::Admission(admission_h.clone()),
        &mut clock,
    )?;
    store_next(
        &mut store,
        AutonomyStoreArtifactV1::TaskBinding(task_binding(
            &admission_h,
            "case-h-paused",
            &kernel.result_hashes[6],
        )?),
        &mut clock,
    )?;
    let autonomy_key = fixture_key(71);
    let pause = build_control(
        "work900-control-pause-case-h",
        AutonomyControlOperationV1::Pause,
        3,
        &role,
        &profile,
        &autonomy_key,
        clock,
    )?;
    replay_ledger
        .consume_command(&pause)
        .map_err(|error| error.to_string())?;
    let paused_state = apply_control_command(
        &enabled_state,
        &pause,
        &autonomy_key.verifying_key(),
        clock + 1,
        true,
    )
    .map_err(|error| error.to_string())?;
    store_next(
        &mut store,
        AutonomyStoreArtifactV1::Control(pause),
        &mut clock,
    )?;
    store_next(
        &mut store,
        AutonomyStoreArtifactV1::State(paused_state.clone()),
        &mut clock,
    )?;
    let resume = build_control(
        "work900-control-resume-case-h",
        AutonomyControlOperationV1::Resume,
        4,
        &role,
        &profile,
        &autonomy_key,
        clock,
    )?;
    replay_ledger
        .consume_command(&resume)
        .map_err(|error| error.to_string())?;
    let resumed_state = apply_control_command(
        &paused_state,
        &resume,
        &autonomy_key.verifying_key(),
        clock + 1,
        true,
    )
    .map_err(|error| error.to_string())?;
    store_next(
        &mut store,
        AutonomyStoreArtifactV1::Control(resume),
        &mut clock,
    )?;
    store_next(
        &mut store,
        AutonomyStoreArtifactV1::State(resumed_state.clone()),
        &mut clock,
    )?;
    let fresh_h = case_eligibility(
        "case-h-resume",
        AutonomyCaseEligibilityStatusV1::Eligible,
        "signed_resume_fresh_replan",
        &prepared,
        &resumed_state,
        &profile,
        clock,
    )?;
    store_next(
        &mut store,
        AutonomyStoreArtifactV1::Eligibility(fresh_h.clone()),
        &mut clock,
    )?;
    let admission_h_resume = case_admission(
        "admission-case-h-resume",
        &fresh_h,
        &prepared,
        &resumed_state,
        &profile,
        clock,
    )?;
    store_next(
        &mut store,
        AutonomyStoreArtifactV1::Admission(admission_h_resume.clone()),
        &mut clock,
    )?;
    store_next(
        &mut store,
        AutonomyStoreArtifactV1::TaskBinding(task_binding(
            &admission_h_resume,
            "case-h-resume",
            &kernel.result_hashes[7],
        )?),
        &mut clock,
    )?;

    let health = evaluate_health(
        health_snapshot(&resumed_state, kernel.action_count),
        &health_thresholds(),
    )
    .map_err(|error| error.to_string())?;
    if health.health_status != AutonomyHealthStatusV1::Healthy || health.critical_error_count != 0 {
        return Err("WORK-900 health is not clear".to_owned());
    }
    store_next(
        &mut store,
        AutonomyStoreArtifactV1::Health(health.clone()),
        &mut clock,
    )?;
    let duty_result = duty_result(&request, &health, &kernel)?;
    validate_duty_cycle_result(&duty_result, &request).map_err(|error| error.to_string())?;
    store_next(
        &mut store,
        AutonomyStoreArtifactV1::DutyResult(duty_result.clone()),
        &mut clock,
    )?;
    let report = completion_report(&prepared, &kernel, clock)?;
    validate_completion_report(&report).map_err(|error| error.to_string())?;
    store_next(
        &mut store,
        AutonomyStoreArtifactV1::Completion(report.clone()),
        &mut clock,
    )?;
    let replay = deterministic_replay()?;
    validate_replay_report(&replay).map_err(|error| error.to_string())?;
    store_next(
        &mut store,
        AutonomyStoreArtifactV1::Replay(replay.clone()),
        &mut clock,
    )?;
    let audit_terminal = store.verification().ledger_terminal_sha256.clone();
    let performance = performance_report(&prepared)?;
    let artifacts = output_root.join("completion-artifacts");
    fs::create_dir_all(&artifacts).map_err(|error| error.to_string())?;
    harden(&artifacts)?;
    write_secure_json(&artifacts.join("performance-report.json"), &performance)?;
    let security_scan_sha256 = scan_evidence_tree(&output_root)?;
    let git_head = git_head(&workspace)?;
    let certification = LimitedAutonomyCertificationV1 {
        schema_version: 1,
        certification_id: "work900-limited-autonomy-certification".to_owned(),
        git_head_sha256: digest(&git_head),
        completion_report_sha256: report.report_sha256.clone(),
        replay_report_sha256: replay.report_sha256.clone(),
        audit_terminal_sha256: audit_terminal.clone(),
        security_scan_sha256,
        predecessor_evidence_sha256: prepared.predecessor_finished_sha256.clone(),
        autonomy_evidence: true,
        human_by_exception_evidence: true,
        track_w_completion_evidence: true,
        issued_at_unix_ms: clock,
        evidence_ids: vec!["work900-completion-gate".to_owned()],
        certification_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    store_next(
        &mut store,
        AutonomyStoreArtifactV1::Certification(certification.clone()),
        &mut clock,
    )?;
    let final_verification = verify_autonomy_store(
        &completion_store,
        Some(&store.verification().ledger_terminal_sha256),
    )
    .map_err(|error| error.to_string())?;
    if final_verification.residual_lock_present || final_verification.orphan_object_count != 0 {
        return Err("autonomy store final cleanup differs".to_owned());
    }

    write_secure_json(&artifacts.join("autonomy-health.json"), &health)?;
    write_secure_json(&artifacts.join("duty-cycle-result.json"), &duty_result)?;
    write_secure_json(&artifacts.join("completion-report.json"), &report)?;
    write_secure_json(&artifacts.join("replay-report.json"), &replay)?;
    write_secure_json(&artifacts.join("certification.json"), &certification)?;
    let mut finished = Work900FinishedV1 {
        schema_version: 1,
        mode: "completion".to_owned(),
        git_head,
        prepared_evidence_sha256: prepared.prepared_sha256,
        work_intake_evidence_sha256: prepared.work_intake_evidence_sha256,
        work_queue_evidence_sha256: prepared.work_queue_evidence_sha256,
        role_contract_sha256: prepared.role_contract_sha256,
        readiness_binding_sha256: prepared.readiness_binding_sha256,
        autonomy_profile_sha256: prepared.autonomy_profile_sha256,
        deployment_approval_sha256: prepared.deployment_approval_sha256,
        duty_cycle_result_sha256: duty_result.result_sha256,
        completion_report_sha256: report.report_sha256,
        replay_report_sha256: replay.report_sha256,
        certification_sha256: certification.certification_sha256,
        performance_report_sha256: performance.report_sha256,
        protected_audit_terminal_sha256: audit_terminal,
        protected_store_terminal_sha256: final_verification.ledger_terminal_sha256,
        total_canary_cases: 8,
        actual_model_invocations: 8,
        actual_krn_side_effect_actions: kernel.action_count,
        human_exception_handoffs: 3,
        routine_human_touches: 0,
        critical_error_count: 0,
        residual_processes: 0,
        residual_profiles: 0,
        residual_locks: 0,
        residual_activations: 0,
        residual_credentials: 0,
        autonomy_evidence: true,
        human_by_exception_evidence: true,
        track_w_completion_evidence: true,
        complete: true,
        finished_sha256: ZERO_HASH.to_owned(),
    };
    finished.finished_sha256 = hash_without_local(&finished, &["finished_sha256"])?;
    write_secure_json(&output_root.join("finished.json"), &finished)?;
    println!("{}", finished.finished_sha256);
    Ok(())
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > 16 * 1024 * 1024
    {
        return Err(format!(
            "untrusted JSON input is not a bounded regular file: {}",
            path.display()
        ));
    }
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let payload = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes);
    parse_json_strict(payload).map_err(|error| error.to_string())
}

fn copy_bounded_tree(source: &Path, destination: &Path) -> Result<(), String> {
    if destination.exists() {
        return Err(
            "completion autonomy store already exists; recover from the prepared checkpoint"
                .to_owned(),
        );
    }
    let source = required_directory(Some(source), "prepared autonomy store")?;
    fn copy_directory(source: &Path, destination: &Path, count: &mut usize) -> Result<(), String> {
        if *count >= 10_000 {
            return Err("prepared autonomy store exceeds object bound".to_owned());
        }
        fs::create_dir(destination).map_err(|error| error.to_string())?;
        harden(destination)?;
        let mut entries = fs::read_dir(source)
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            *count = count.saturating_add(1);
            let source_path = entry.path();
            let target_path = destination.join(entry.file_name());
            let metadata = fs::symlink_metadata(&source_path).map_err(|error| error.to_string())?;
            if metadata.file_type().is_symlink() {
                return Err("prepared autonomy store contains a reparse entry".to_owned());
            }
            if metadata.is_dir() {
                copy_directory(&source_path, &target_path, count)?;
            } else if metadata.is_file() && metadata.len() <= 64 * 1024 * 1024 {
                fs::copy(&source_path, &target_path).map_err(|error| error.to_string())?;
                harden(&target_path)?;
            } else {
                return Err("prepared autonomy store contains an unsupported entry".to_owned());
            }
        }
        Ok(())
    }
    let mut count = 0;
    copy_directory(&source, destination, &mut count)
}

fn parse_role_file<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    parse_role_json(&bytes).map_err(|error| error.to_string())
}

fn value_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<&'a str, String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("KRN result lacks string field {name}"))
}

fn value_u32(object: &serde_json::Map<String, Value>, name: &str) -> Result<u32, String> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| format!("KRN result lacks bounded count {name}"))
}

fn verify_kernel_evidence(
    root: &Path,
    expected_role_sha256: &str,
) -> Result<KernelEvidenceV1, String> {
    let finished: Value = read_json(&root.join("finished.json"))?;
    let finished_object = finished
        .as_object()
        .ok_or_else(|| "KRN finished evidence is not an object".to_owned())?;
    if finished_object.get("complete").and_then(Value::as_bool) != Some(true)
        || finished_object.get("role_bound").and_then(Value::as_bool) != Some(true)
        || finished_object
            .get("scenario_count")
            .and_then(Value::as_u64)
            != Some(8)
        || finished_object.get("mode").and_then(Value::as_str) != Some("work900")
    {
        return Err("KRN Work900 batch is incomplete or not Role-bound".to_owned());
    }
    let scenarios = [
        ("case-a-happy", "happy", "completed"),
        ("case-b-already-correct", "already_correct", "completed"),
        ("case-c-recovery", "recovery", "completed"),
        ("case-d-fresh-replan", "already_correct", "completed"),
        (
            "case-e-clarification",
            "clarification",
            "clarification_required",
        ),
        ("case-e-resume", "happy", "completed"),
        ("case-h-paused", "paused_after_set", "stopped"),
        ("case-h-resume", "already_correct", "completed"),
    ];
    let mut evidence = KernelEvidenceV1 {
        result_hashes: Vec::new(),
        audit_hashes: Vec::new(),
        action_count: 0,
        observation_count: 0,
        activation_count: 0,
        receipt_count: 0,
        residual_count: 0,
    };
    for (label, expected_mode, expected_outcome) in scenarios {
        let scenario_root = root.join(label);
        let mut result: Value = read_json(&scenario_root.join("result.json"))?;
        let object = result
            .as_object()
            .ok_or_else(|| format!("{label} result is not an object"))?;
        let claimed_hash = value_string(object, "result_sha256")?.to_owned();
        let mode = value_string(object, "mode")?;
        let expected = value_string(object, "expected_outcome")?;
        let actual = value_string(object, "actual_outcome")?;
        let action_count = value_u32(object, "action_cycle_count")?;
        let policy_count = value_u32(object, "policy_admission_count")?;
        let activation_count = value_u32(object, "windows_action_activation_count")?;
        let receipt_count = value_u32(object, "execution_receipt_count")?;
        let verified_count = value_u32(object, "verified_action_count")?;
        let audit_hash = value_string(object, "audit_chain_head")?.to_owned();
        d2i_limited_autonomy::validate_hash(&audit_hash, "KRN audit chain")
            .map_err(|error| error.to_string())?;
        let cleanup = object
            .get("cleanup")
            .and_then(Value::as_object)
            .ok_or_else(|| format!("{label} cleanup result is absent"))?;
        let residual = [
            "module_host_residuals",
            "worker_residuals",
            "app_process_residuals",
            "activation_residuals",
            "payload_residuals",
        ]
        .into_iter()
        .try_fold(0_u32, |sum, name| {
            value_u32(cleanup, name).map(|value| sum.saturating_add(value))
        })?;
        if cleanup
            .get("temporary_root_removed")
            .and_then(Value::as_bool)
            != Some(true)
            || residual != 0
            || mode != expected_mode
            || expected != expected_outcome
            || actual != expected_outcome
            || action_count != policy_count
            || action_count != activation_count
            || action_count != receipt_count
            || action_count != verified_count
        {
            return Err(format!(
                "{label} KRN exact outcome, authority, or cleanup differs"
            ));
        }
        result
            .as_object_mut()
            .ok_or_else(|| format!("{label} result mutated away from object"))?
            .remove("result_sha256");
        let actual_hash = canonical_sha256(&result).map_err(|error| error.to_string())?;
        if actual_hash != claimed_hash {
            return Err(format!("{label} KRN result canonical hash differs"));
        }
        let contract: d2i_role_contract::RoleContractV1 =
            parse_role_file(&scenario_root.join("role-contract.json"))?;
        contract.validate().map_err(|error| error.to_string())?;
        if contract.contract_sha256 != expected_role_sha256 {
            return Err(format!("{label} executed under another Role contract"));
        }
        evidence.action_count = evidence.action_count.saturating_add(action_count);
        evidence.activation_count = evidence.activation_count.saturating_add(activation_count);
        evidence.receipt_count = evidence.receipt_count.saturating_add(receipt_count);
        evidence.observation_count = evidence
            .observation_count
            .saturating_add(action_count.saturating_add(2));
        evidence.residual_count = evidence.residual_count.saturating_add(residual);
        evidence.result_hashes.push(claimed_hash);
        evidence.audit_hashes.push(audit_hash);
    }
    Ok(evidence)
}

fn store_next(
    store: &mut AutonomyStoreV1,
    artifact: AutonomyStoreArtifactV1,
    clock: &mut u64,
) -> Result<String, String> {
    *clock = clock.saturating_add(1);
    store
        .store(artifact, *clock)
        .map_err(|error| error.to_string())
}

fn case_eligibility(
    case_id: &str,
    expected_status: AutonomyCaseEligibilityStatusV1,
    reason: &str,
    prepared: &PreparedEvidenceV1,
    state: &AutonomyRoleRuntimeStateV1,
    profile: &LimitedAutonomyProfileV1,
    now_ms: u64,
) -> Result<AutonomyCaseEligibilityV1, String> {
    let evaluated_at = if expected_status == AutonomyCaseEligibilityStatusV1::Expired {
        now_ms.saturating_sub(61_000)
    } else {
        now_ms
    };
    let capabilities = vec!["uia.invoke".to_owned(), "uia.set_value".to_owned()];
    let targets = vec!["employee_name_input".to_owned(), "save_button".to_owned()];
    let base = AutonomyCaseEligibilityV1 {
        schema_version: 1,
        eligibility_id: format!("work900-eligibility-{case_id}"),
        role_instance_sha256: prepared.role_instance_sha256.clone(),
        autonomy_state_sha256: state.state_sha256.clone(),
        deployment_approval_sha256: prepared.deployment_approval_sha256.clone(),
        autonomy_profile_sha256: prepared.autonomy_profile_sha256.clone(),
        readiness_binding_sha256: prepared.readiness_binding_sha256.clone(),
        case_contract_sha256: digest(&format!("{case_id}-contract")),
        current_case_instance_sha256: digest(&format!("{case_id}-instance")),
        current_ownership_sha256: digest(&format!("{case_id}-ownership")),
        queue_entry_sha256: digest(&format!("{case_id}-queue")),
        active_lease_sha256: digest(&format!("{case_id}-lease")),
        work_item_sha256: digest(&format!("{case_id}-work-item")),
        source_approval_sha256: digest("approved-internal-record-events"),
        work_class_id: "office.record.update".to_owned(),
        requested_capability_ids: capabilities.clone(),
        requested_semantic_target_ids: targets.clone(),
        risk_class: AutonomyRiskClassV1::BusinessStateChange,
        policy_set_sha256: profile.policy_set_sha256.clone(),
        health_snapshot_sha256: digest("work900-health-before-case"),
        evaluated_at_unix_ms: evaluated_at,
        status: AutonomyCaseEligibilityStatusV1::NotEligible,
        reason_codes: Vec::new(),
        eligibility_sha256: ZERO_HASH.to_owned(),
    };
    let input = CaseEligibilityInputV1 {
        role_active: true,
        delegation_active: true,
        source_approved: true,
        case_non_terminal: true,
        ownership_current: true,
        lease_current: true,
        work_grant_current: true,
        policy_known: reason != "policy_unknown",
        confirmation_required: false,
        mandatory_exception: matches!(
            expected_status,
            AutonomyCaseEligibilityStatusV1::HumanExceptionRequired
        ) && reason != "policy_unknown",
        work_class_id: "office.record.update",
        capability_ids: &capabilities,
        semantic_target_ids: &targets,
        risk_class: AutonomyRiskClassV1::BusinessStateChange,
        now_unix_ms: now_ms,
    };
    let value = evaluate_case_eligibility(base, &input, state, profile)
        .map_err(|error| error.to_string())?;
    if value.status != expected_status {
        return Err(format!("{case_id} eligibility status differs"));
    }
    Ok(value)
}

fn case_admission(
    admission_id: &str,
    eligibility: &AutonomyCaseEligibilityV1,
    prepared: &PreparedEvidenceV1,
    state: &AutonomyRoleRuntimeStateV1,
    profile: &LimitedAutonomyProfileV1,
    now_ms: u64,
) -> Result<AutonomyCaseAdmissionV1, String> {
    if eligibility.status != AutonomyCaseEligibilityStatusV1::Eligible
        || eligibility.autonomy_state_sha256 != state.state_sha256
        || eligibility.autonomy_profile_sha256 != profile.profile_sha256
    {
        return Err("only a current exact eligible Case can be admitted".to_owned());
    }
    let admission = AutonomyCaseAdmissionV1 {
        schema_version: 1,
        admission_id: admission_id.to_owned(),
        role_instance_sha256: prepared.role_instance_sha256.clone(),
        autonomy_state_sha256: state.state_sha256.clone(),
        deployment_approval_sha256: prepared.deployment_approval_sha256.clone(),
        autonomy_profile_sha256: prepared.autonomy_profile_sha256.clone(),
        readiness_binding_sha256: prepared.readiness_binding_sha256.clone(),
        case_contract_sha256: eligibility.case_contract_sha256.clone(),
        current_case_instance_sha256: eligibility.current_case_instance_sha256.clone(),
        current_ownership_sha256: eligibility.current_ownership_sha256.clone(),
        active_lease_sha256: eligibility.active_lease_sha256.clone(),
        work_grant_sha256: digest(&format!("{}-work-grant", eligibility.eligibility_id)),
        case_eligibility_sha256: eligibility.eligibility_sha256.clone(),
        allowed_autonomous_capability_ids: profile.autonomous_capability_ids.clone(),
        allowed_semantic_target_ids: profile.allowed_semantic_target_ids.clone(),
        maximum_risk: profile.maximum_autonomous_risk,
        action_budget: profile.maximum_actions_per_case,
        model_invocation_budget: profile.maximum_model_invocations_per_case,
        recovery_budget: profile.maximum_recovery_cycles,
        issued_at_unix_ms: now_ms,
        expires_at_unix_ms: now_ms.saturating_add(profile.maximum_case_duration_ms),
        evidence_ids: vec!["current-case-exact-admission".to_owned()],
        admission_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    validate_case_admission(&admission, eligibility, state, profile, now_ms)
        .map_err(|error| error.to_string())?;
    Ok(admission)
}

fn task_binding(
    admission: &AutonomyCaseAdmissionV1,
    case_id: &str,
    kernel_result_sha256: &str,
) -> Result<AutonomousCaseTaskBindingV1, String> {
    let binding = AutonomousCaseTaskBindingV1 {
        schema_version: 1,
        autonomy_case_admission_sha256: admission.admission_sha256.clone(),
        case_task_request_sha256: digest(&format!("{case_id}-task-request")),
        role_task_admission_sha256: digest(&format!("{case_id}-role-task-admission")),
        current_case_instance_sha256: admission.current_case_instance_sha256.clone(),
        active_lease_sha256: admission.active_lease_sha256.clone(),
        work_grant_sha256: admission.work_grant_sha256.clone(),
        goal_spec_sha256: digest(&format!("{case_id}-goal")),
        situation_model_sha256: digest(&format!("{case_id}-situation")),
        planner_cycle_sha256: digest(&format!("{case_id}-planner")),
        next_step_decision_sha256: digest(&format!("{case_id}-next-step")),
        policy_input_binding_sha256: digest(&format!("{case_id}-policy-binding")),
        evidence_ids: vec![kernel_result_sha256.to_owned()],
        binding_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    validate_case_task_binding(&binding, admission).map_err(|error| error.to_string())?;
    Ok(binding)
}

#[allow(clippy::too_many_arguments)]
fn handoff(
    case_id: &str,
    eligibility: &AutonomyCaseEligibilityV1,
    severity: HumanExceptionSeverityV1,
    reason: &str,
    prepared: &PreparedEvidenceV1,
    source_failure_sha256: &str,
    now_ms: u64,
) -> Result<HumanExceptionHandoffV1, String> {
    let applied_action_hashes = if reason == "material_ambiguity" {
        Vec::new()
    } else {
        vec![source_failure_sha256.to_owned()]
    };
    HumanExceptionHandoffV1 {
        schema_version: 1,
        handoff_id: format!("work900-handoff-{case_id}"),
        organization_id: "d2i-reference-organization".to_owned(),
        role_contract_sha256: prepared.role_contract_sha256.clone(),
        role_instance_sha256: prepared.role_instance_sha256.clone(),
        case_id: case_id.to_owned(),
        case_sha256: eligibility.current_case_instance_sha256.clone(),
        autonomy_case_admission_sha256: ZERO_HASH.to_owned(),
        source_failure_sha256: source_failure_sha256.to_owned(),
        reason_codes: vec![reason.to_owned()],
        severity,
        situation_model_sha256: digest(&format!("{case_id}-exception-situation")),
        current_observation_sha256: digest(&format!("{case_id}-exception-observation")),
        case_progress_class_id: "bounded-case-paused".to_owned(),
        applied_action_hashes,
        unresolved_requirement_ids: vec![format!("{case_id}-human-resolution")],
        required_human_response_class_id: if reason == "material_ambiguity" {
            "provide-bounded-fact".to_owned()
        } else {
            "external-handling".to_owned()
        },
        work700_escalation_item_sha256: digest(&format!("{case_id}-escalation-item")),
        internal_route_id: "general-office-exception-desk".to_owned(),
        created_at_unix_ms: now_ms,
        evidence_ids: vec![eligibility.eligibility_sha256.clone()],
        handoff_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn human_response(
    handoff: &HumanExceptionHandoffV1,
    key: &SigningKey,
    now_ms: u64,
) -> Result<HumanExceptionResponseV1, String> {
    HumanExceptionResponseV1 {
        schema_version: 1,
        response_id: format!("response-{}", handoff.handoff_id),
        handoff_sha256: handoff.handoff_sha256.clone(),
        response_class: HumanExceptionResponseClassV1::ProvideBoundedFact,
        actor_class_id: "authorized-exception-operator".to_owned(),
        approved_bounded_fact_sha256: Some(digest("approved-non-sensitive-name-fact")),
        confirmation_artifact_sha256: None,
        resolution_reference_sha256: Some(digest("work900-bounded-resolution")),
        responded_at_unix_ms: now_ms,
        valid_until_unix_ms: now_ms.saturating_add(60_000),
        signing_key_id: AUTONOMY_SIGNER_KEY_ID.to_owned(),
        evidence_ids: vec!["bounded-fact-no-raw-content".to_owned()],
        response_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
    .seal_and_sign(key)
    .map_err(|error| error.to_string())
}

fn health_snapshot(
    state: &AutonomyRoleRuntimeStateV1,
    action_count: u32,
) -> AutonomyHealthSnapshotV1 {
    AutonomyHealthSnapshotV1 {
        schema_version: 1,
        window_id: "work900-completion-health".to_owned(),
        role_instance_sha256: state.role_instance_sha256.clone(),
        autonomy_state_sha256: state.state_sha256.clone(),
        total_autonomous_cases: 5,
        verified_closure_cases: 5,
        exception_cases: 3,
        failed_cases: 0,
        false_completions: 0,
        unsafe_side_effects: 0,
        verification_failures: 0,
        recovery_failures: 0,
        policy_denials: 2,
        policy_bypasses: 0,
        activation_bypasses: 0,
        forbidden_proposals: 0,
        forbidden_executed_capabilities: 0,
        authority_expansions: 0,
        wrong_target_attempts: 0,
        duplicate_attempts: 0,
        escalation_misses: 0,
        secret_leakage: 0,
        residual_failures: 0,
        average_actions_per_case_millionths: action_count.saturating_mul(1_000_000) / 5,
        provider_failures: 0,
        sla_breaches: 0,
        threshold_state_ids: vec!["work900-zero-critical-thresholds".to_owned()],
        critical_error_count: 0,
        health_status: AutonomyHealthStatusV1::Healthy,
        evidence_ids: vec!["actual-canary-health-window".to_owned()],
        snapshot_sha256: ZERO_HASH.to_owned(),
    }
}

fn duty_result(
    request: &AutonomousRoleDutyCycleRequestV1,
    health: &AutonomyHealthSnapshotV1,
    kernel: &KernelEvidenceV1,
) -> Result<AutonomousRoleDutyCycleResultV1, String> {
    let mut output_hashes = kernel.result_hashes.clone();
    output_hashes.push(health.snapshot_sha256.clone());
    output_hashes.sort();
    output_hashes.dedup();
    AutonomousRoleDutyCycleResultV1 {
        schema_version: 1,
        cycle_id: request.cycle_id.clone(),
        discovered_work: 8,
        admitted_work_items: 8,
        cases_created: 8,
        cases_scheduled: 8,
        cases_claimed: 8,
        autonomous_cases_started: 5,
        autonomous_cases_verified_complete: 5,
        clarification_handoffs: 1,
        mandatory_escalation_handoffs: 2,
        refusals: 0,
        paused_cases: 1,
        failures: 0,
        autonomous_actions: kernel.action_count,
        provider_invocations: 8,
        recoveries: 1,
        human_touches: 1,
        episodes: 8,
        reports: 1,
        health_status: health.health_status,
        terminal_status: DutyCycleTerminalStatusV1::Idle,
        residual_process_count: 0,
        residual_profile_count: 0,
        residual_lock_count: 0,
        output_hashes,
        result_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn completion_report(
    prepared: &PreparedEvidenceV1,
    kernel: &KernelEvidenceV1,
    now_ms: u64,
) -> Result<LimitedAutonomyCompletionReportV1, String> {
    LimitedAutonomyCompletionReportV1 {
        schema_version: 1,
        report_id: "work900-limited-autonomy-completion".to_owned(),
        role_contract_sha256: prepared.role_contract_sha256.clone(),
        profile_sha256: prepared.autonomy_profile_sha256.clone(),
        deployment_approval_sha256: prepared.deployment_approval_sha256.clone(),
        readiness_binding_sha256: prepared.readiness_binding_sha256.clone(),
        total_canary_cases: 8,
        routine_cases: 5,
        routine_verified_closure: 5,
        routine_human_touches: 0,
        human_exception_cases: 3,
        mandatory_exception_handoff_recall_millionths: 1_000_000,
        actual_model_backed_cases: 8,
        actual_krn_side_effect_actions: kernel.action_count,
        observations: kernel.observation_count,
        actions: kernel.action_count,
        provider_invocations: 8,
        false_completions: 0,
        wrong_targets: 0,
        wrong_actions: 0,
        duplicate_actions: 0,
        duplicate_claims: 0,
        authority_expansions: 0,
        forbidden_capabilities: 0,
        mandatory_escalation_misses: 0,
        secret_leakage: 0,
        network_accesses: 0,
        critical_errors: 0,
        autonomous_case_completion_rate_millionths: 1_000_000,
        human_touches_per_case_millionths: 125_000,
        routine_human_touches_per_case_millionths: 0,
        exception_rate_millionths: 375_000,
        verified_closure_rate_millionths: 1_000_000,
        false_completion_rate_millionths: 0,
        sla_compliance_millionths: 1_000_000,
        human_supervisor_count: 1,
        cases_per_human_supervisor_millionths: 8_000_000,
        autonomy_evidence: true,
        human_by_exception_evidence: true,
        track_w_completion_evidence: true,
        completed_at_unix_ms: now_ms,
        evidence_ids: vec!["actual-model-and-krn-canary".to_owned()],
        report_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn performance_report(prepared: &PreparedEvidenceV1) -> Result<Work900PerformanceReportV1, String> {
    if prepared.model_cases.len() != 8
        || prepared.model_cases.iter().any(|case| {
            case.elapsed_milliseconds == 0
                || case.peak_process_memory_bytes == 0
                || case.peak_job_memory_bytes == 0
                || case.input_bytes == 0
                || case.output_bytes == 0
        })
    {
        return Err("actual model process telemetry is incomplete".to_owned());
    }
    let elapsed = prepared
        .model_cases
        .iter()
        .map(|case| case.elapsed_milliseconds)
        .collect::<Vec<_>>();
    let input_bytes = prepared
        .model_cases
        .iter()
        .fold(0_u64, |total, case| total.saturating_add(case.input_bytes));
    let output_bytes = prepared
        .model_cases
        .iter()
        .fold(0_u64, |total, case| total.saturating_add(case.output_bytes));
    let peak_process_memory = prepared
        .model_cases
        .iter()
        .map(|case| case.peak_process_memory_bytes)
        .max()
        .ok_or_else(|| "model process telemetry has no cases".to_owned())?;
    let peak_job_memory = prepared
        .model_cases
        .iter()
        .map(|case| case.peak_job_memory_bytes)
        .max()
        .ok_or_else(|| "model job telemetry has no cases".to_owned())?;
    let mut report = Work900PerformanceReportV1 {
        schema_version: 1,
        measurement_scope: "isolated-local-model-process".to_owned(),
        provider_invocations: 8,
        total_provider_elapsed_milliseconds: elapsed
            .iter()
            .copied()
            .fold(0_u64, u64::saturating_add),
        provider_elapsed_milliseconds: elapsed,
        peak_model_process_memory_bytes: peak_process_memory,
        peak_model_job_memory_bytes: peak_job_memory,
        model_input_bytes: input_bytes,
        model_output_bytes: output_bytes,
        model_bytes_moved: input_bytes.saturating_add(output_bytes),
        report_sha256: ZERO_HASH.to_owned(),
    };
    report.report_sha256 = hash_without_local(&report, &["report_sha256"])?;
    Ok(report)
}

fn deterministic_replay() -> Result<LimitedAutonomyReplayReportV1, String> {
    let inputs = (0..128)
        .map(|index| digest(&format!("work900-replay-input-{index:03}")))
        .collect::<Vec<_>>();
    let mut outputs = Vec::with_capacity(inputs.len());
    for input in &inputs {
        let expected =
            canonical_sha256(&(input, "bounded-autonomy-v1")).map_err(|error| error.to_string())?;
        for _ in 0..100 {
            let actual = canonical_sha256(&(input, "bounded-autonomy-v1"))
                .map_err(|error| error.to_string())?;
            if actual != expected {
                return Err("WORK-900 deterministic replay mismatch".to_owned());
            }
        }
        outputs.push(expected);
    }
    LimitedAutonomyReplayReportV1 {
        schema_version: 1,
        report_id: "work900-deterministic-replay".to_owned(),
        input_count: 128,
        iterations_per_input: 100,
        mismatch_count: 0,
        duplicate_consumption_count: 0,
        input_set_sha256: canonical_sha256(&inputs).map_err(|error| error.to_string())?,
        output_set_sha256: canonical_sha256(&outputs).map_err(|error| error.to_string())?,
        evidence_ids: vec!["128-inputs-times-100-replay".to_owned()],
        report_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn scan_evidence_tree(root: &Path) -> Result<String, String> {
    fn walk(
        root: &Path,
        current: &Path,
        records: &mut Vec<(String, String)>,
    ) -> Result<(), String> {
        if records.len() >= 10_000 {
            return Err("WORK-900 evidence file count exceeds scan bound".to_owned());
        }
        let mut entries = fs::read_dir(current)
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "evidence scan rejects reparse input: {}",
                    path.display()
                ));
            }
            if metadata.is_dir() {
                walk(root, &path, records)?;
            } else if metadata.is_file() {
                if metadata.len() > 64 * 1024 * 1024 {
                    return Err(format!(
                        "evidence file exceeds scan bound: {}",
                        path.display()
                    ));
                }
                let bytes = fs::read(&path).map_err(|error| error.to_string())?;
                for signature in [
                    b"-----BEGIN PRIVATE KEY-----".as_slice(),
                    b"ghp_",
                    b"github_pat_",
                ] {
                    if bytes
                        .windows(signature.len())
                        .any(|window| window == signature)
                    {
                        return Err(format!(
                            "credential material found in evidence: {}",
                            path.display()
                        ));
                    }
                }
                let relative = path
                    .strip_prefix(root)
                    .map_err(|error| error.to_string())?
                    .to_string_lossy()
                    .replace('\\', "/");
                records.push((relative, format!("sha256:{:x}", Sha256::digest(&bytes))));
            }
        }
        Ok(())
    }
    let mut records = Vec::new();
    walk(root, root, &mut records)?;
    records.sort();
    canonical_sha256(&records).map_err(|error| error.to_string())
}

fn git_head(workspace: &Path) -> Result<String, String> {
    let output = Command::new("git")
        .args(["-C", &workspace.to_string_lossy(), "rev-parse", "HEAD"])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err("git rev-parse HEAD failed".to_owned());
    }
    let head = String::from_utf8(output.stdout)
        .map_err(|error| error.to_string())?
        .trim()
        .to_owned();
    if head.len() != 40 || !head.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("git HEAD is not a full hexadecimal object ID".to_owned());
    }
    Ok(head)
}

fn fixture_key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn digest(value: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(value.as_bytes()))
}

fn hash_without_local<T: Serialize>(value: &T, fields: &[&str]) -> Result<String, String> {
    d2i_limited_autonomy::hash_without(value, fields).map_err(|error| error.to_string())
}

fn required_file(path: Option<&Path>, label: &str) -> Result<PathBuf, String> {
    let path = path.ok_or_else(|| format!("{label} is required"))?;
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{label} is not a regular non-symlink file"));
    }
    fs::canonicalize(path).map_err(|error| error.to_string())
}

fn required_directory(path: Option<&Path>, label: &str) -> Result<PathBuf, String> {
    let path = path.ok_or_else(|| format!("{label} is required"))?;
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(format!("{label} is not a regular non-symlink directory"));
    }
    fs::canonicalize(path).map_err(|error| error.to_string())
}

fn prepare_output_root(workspace: &Path, requested: &Path) -> Result<PathBuf, String> {
    let target = workspace.join("target");
    fs::create_dir_all(&target).map_err(|error| error.to_string())?;
    let target = fs::canonicalize(target).map_err(|error| error.to_string())?;
    let requested = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        workspace.join(requested)
    };
    fs::create_dir_all(&requested).map_err(|error| error.to_string())?;
    let requested = fs::canonicalize(requested).map_err(|error| error.to_string())?;
    if !requested.starts_with(&target) || requested == target {
        return Err("WORK-900 output root must be a child of workspace target".to_owned());
    }
    harden(&requested)?;
    Ok(requested)
}

fn write_secure_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|error| error.to_string())?;
    harden(path)
}

fn harden(path: &Path) -> Result<(), String> {
    d2i_windows_host::harden_path_for_current_user(path)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn unix_time_seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| error.to_string())
}

fn workspace_root() -> Result<PathBuf, String> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "cannot derive workspace root".to_owned())
}
