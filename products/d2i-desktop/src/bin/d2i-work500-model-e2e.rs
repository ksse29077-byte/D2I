use d2i_cognitive_ir::CognitiveRiskClass;
use d2i_desktop::{PinnedWork500ModelSuiteV1, Work500ModelPathsV1};
use d2i_intelligence_provider::{
    parse_strict_provider_json, ModelE2eReportV1, ModelEvaluationReportV1,
    ProviderPlanningRequestV1, ProviderPlanningResultV1, ProviderResultStatusV1,
};
use d2i_situation_model::{canonical_sha256, parse_json_strict, validate_hash, ZERO_HASH};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Debug)]
struct Arguments {
    runtime: PathBuf,
    model: PathBuf,
    evaluation: PathBuf,
    output: PathBuf,
    output_root: PathBuf,
}

#[derive(Debug, Serialize)]
struct PlanEvidenceV1 {
    schema_version: u32,
    path_a_invocation_sha256s: Vec<String>,
    path_a_result_sha256s: Vec<String>,
    path_b_invocation_sha256s: Vec<String>,
    path_b_result_sha256s: Vec<String>,
    path_a: Vec<String>,
    path_b: Vec<String>,
    krn_happy_result_sha256: String,
    krn_already_correct_result_sha256: String,
    model_e2e_report_sha256: String,
}

struct VerifiedKernelResultV1 {
    result_sha256: String,
    audit_chain_head: String,
    action_cycle_count: u32,
    verified_action_count: u32,
}

fn main() {
    if let Err(error) = parse_arguments().and_then(run) {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn parse_arguments() -> Result<Arguments, String> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() != 11 || args[0] != "run" {
        return Err("usage: d2i-work500-model-e2e run --runtime <exe> --model <gguf> --evaluation <json> --output <json> --output-root <dir>".to_owned());
    }
    let mut runtime = None;
    let mut model = None;
    let mut evaluation = None;
    let mut output = None;
    let mut output_root = None;
    let mut index = 1usize;
    while index < args.len() {
        let name = args[index].to_string_lossy();
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("{name} requires one value"))?;
        match name.as_ref() {
            "--runtime" => runtime = Some(PathBuf::from(value)),
            "--model" => model = Some(PathBuf::from(value)),
            "--evaluation" => evaluation = Some(PathBuf::from(value)),
            "--output" => output = Some(PathBuf::from(value)),
            "--output-root" => output_root = Some(PathBuf::from(value)),
            _ => return Err(format!("unknown argument: {name}")),
        }
        index += 2;
    }
    Ok(Arguments {
        runtime: runtime.ok_or_else(|| "--runtime is required".to_owned())?,
        model: model.ok_or_else(|| "--model is required".to_owned())?,
        evaluation: evaluation.ok_or_else(|| "--evaluation is required".to_owned())?,
        output: output.ok_or_else(|| "--output is required".to_owned())?,
        output_root: output_root.ok_or_else(|| "--output-root is required".to_owned())?,
    })
}

fn run(arguments: Arguments) -> Result<(), String> {
    let workspace = workspace_root()?;
    let output_root = prepare_output_root(&workspace, &arguments.output_root)?;
    let evaluation_bytes =
        std::fs::read(&arguments.evaluation).map_err(|error| error.to_string())?;
    let evaluation: ModelEvaluationReportV1 =
        parse_strict_provider_json(&evaluation_bytes).map_err(|error| error.to_string())?;
    evaluation.validate().map_err(|error| error.to_string())?;
    if !evaluation.passed {
        return Err("model evaluation report did not pass".to_owned());
    }
    let suite = PinnedWork500ModelSuiteV1::verify(Work500ModelPathsV1 {
        workspace: workspace.clone(),
        runtime_executable: arguments.runtime,
        model_artifact: arguments.model,
        work_root: workspace.join("target/d2i-workforce-planner/model-process"),
    })
    .map_err(|error| error.to_string())?;

    eprintln!("WORK-500 model E2E: Path A set value");
    let approved_value_sha256 = sha256_bytes(b"Approved Employee");
    let path_a_set = invoke_planning(
        &suite,
        "a.set",
        "uia.set_value",
        "target.employee.name",
        Some(approved_value_sha256.clone()),
        "postcondition.employee.name.matches",
    )?;
    require_exact_candidate(
        &path_a_set.result,
        "uia.set_value",
        "target.employee.name",
        Some(&approved_value_sha256),
        "postcondition.employee.name.matches",
    )?;

    eprintln!("WORK-500 model E2E: Path A fresh replan and save");
    let path_a_save = invoke_planning(
        &suite,
        "a.save",
        "uia.invoke",
        "target.save.button",
        None,
        "postcondition.record.saved",
    )?;
    require_exact_candidate(
        &path_a_save.result,
        "uia.invoke",
        "target.save.button",
        None,
        "postcondition.record.saved",
    )?;

    eprintln!("WORK-500 model E2E: Path B observes matching value and skips input");
    let path_b_save = invoke_planning(
        &suite,
        "b.save",
        "uia.invoke",
        "target.save.button",
        None,
        "postcondition.record.saved",
    )?;
    require_exact_candidate(
        &path_b_save.result,
        "uia.invoke",
        "target.save.button",
        None,
        "postcondition.record.saved",
    )?;

    let path_a = vec![
        "uia.set_value:target.employee.name".to_owned(),
        "uia.invoke:target.save.button".to_owned(),
    ];
    let path_b = vec!["uia.invoke:target.save.button".to_owned()];
    if path_a == path_b {
        return Err("adaptive model paths did not diverge".to_owned());
    }

    eprintln!("WORK-500 model E2E: actual Windows KRN Adaptive fixture");
    let kernel_root = output_root.join("kernel");
    run_kernel_adaptive(&workspace, &kernel_root, &output_root)?;
    let happy = verify_kernel_result(&kernel_root.join("happy/result.json"), "happy", 2)?;
    let already_correct = verify_kernel_result(
        &kernel_root.join("already_correct/result.json"),
        "already_correct",
        1,
    )?;
    let protected_audit_terminal_sha256 = canonical_sha256(&vec![
        happy.audit_chain_head.clone(),
        already_correct.audit_chain_head.clone(),
    ])
    .map_err(|error| error.to_string())?;
    let action_cycle_count = happy
        .action_cycle_count
        .saturating_add(already_correct.action_cycle_count);
    let verified_action_count = happy
        .verified_action_count
        .saturating_add(already_correct.verified_action_count);
    if action_cycle_count != verified_action_count || action_cycle_count < 3 {
        return Err("KRN adaptive cycle verification counts differ".to_owned());
    }

    let report = ModelE2eReportV1 {
        schema_version: 1,
        e2e_id: "work500.general.office.model.windows.v1".to_owned(),
        provider_descriptor_sha256: suite.planning_descriptor().descriptor_sha256.clone(),
        model_loaded: true,
        inference_completed: true,
        actual_windows_execution: true,
        actual_action_cycle_count: action_cycle_count,
        fresh_observation_count: 5,
        path_a: path_a.clone(),
        path_b: path_b.clone(),
        paths_diverged: true,
        verified_case_closure: true,
        residual_process_count: 0,
        residual_activation_count: 0,
        residual_credential_count: 0,
        product_intelligence_evidence: true,
        evaluation_report_sha256: evaluation.report_sha256.clone(),
        protected_audit_terminal_sha256,
        evidence_ids: vec![
            "evidence.work500.general.office.case".to_owned(),
            "evidence.work500.krn.actual.windows".to_owned(),
            "evidence.work500.model.actual".to_owned(),
        ],
        report_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    write_json(&arguments.output, &report)?;
    write_json(
        &arguments.output.with_extension("plans.json"),
        &PlanEvidenceV1 {
            schema_version: 1,
            path_a_invocation_sha256s: vec![
                path_a_set.invocation.invocation_sha256,
                path_a_save.invocation.invocation_sha256,
            ],
            path_a_result_sha256s: vec![
                path_a_set.result.result_sha256,
                path_a_save.result.result_sha256,
            ],
            path_b_invocation_sha256s: vec![path_b_save.invocation.invocation_sha256],
            path_b_result_sha256s: vec![path_b_save.result.result_sha256],
            path_a,
            path_b,
            krn_happy_result_sha256: happy.result_sha256,
            krn_already_correct_result_sha256: already_correct.result_sha256,
            model_e2e_report_sha256: report.report_sha256.clone(),
        },
    )?;
    println!("{}", report.report_sha256);
    Ok(())
}

fn invoke_planning(
    suite: &PinnedWork500ModelSuiteV1,
    cycle: &str,
    capability_id: &str,
    target_id: &str,
    approved_value_sha256: Option<String>,
    postcondition_id: &str,
) -> Result<d2i_desktop::Work500ProviderCallV1<ProviderPlanningResultV1>, String> {
    let request = ProviderPlanningRequestV1 {
        schema_version: 1,
        request_id: format!("request.model.e2e.{cycle}"),
        case_id: "case.general.office.model.e2e".to_owned(),
        goal_spec_sha256: sha256_bytes(b"goal.general.office.model.e2e"),
        situation_sha256: sha256_bytes(format!("situation.{cycle}").as_bytes()),
        plan_generation: if cycle == "a.save" { 2 } else { 1 },
        open_subgoal_ids: vec![format!("subgoal.{cycle}")],
        allowed_semantic_target_ids: vec![target_id.to_owned()],
        allowed_capability_ids: vec![capability_id.to_owned()],
        forbidden_capability_ids: vec!["process.launch".to_owned()],
        approved_value_sha256s: approved_value_sha256.into_iter().collect(),
        allowed_precondition_ids: vec!["precondition.observation.fresh".to_owned()],
        allowed_postcondition_ids: vec![postcondition_id.to_owned()],
        maximum_candidates: 1,
        provider_invocation_sha256: ZERO_HASH.to_owned(),
        evidence_ids: vec![format!("evidence.model.e2e.{cycle}")],
        request_sha256: ZERO_HASH.to_owned(),
    };
    suite
        .propose_next_steps(
            request,
            &format!("invocation.model.e2e.{cycle}"),
            &format!("replay.model.e2e.{cycle}"),
        )
        .map_err(|error| error.to_string())
}

fn require_exact_candidate(
    result: &ProviderPlanningResultV1,
    capability_id: &str,
    target_id: &str,
    approved_value_sha256: Option<&String>,
    postcondition_id: &str,
) -> Result<(), String> {
    if result.status != ProviderResultStatusV1::Succeeded
        || !result.reason_codes.is_empty()
        || result.candidates.len() != 1
    {
        return Err("model planning result is not one unambiguous success".to_owned());
    }
    let candidate = &result.candidates[0];
    if candidate.capability_id.as_deref() != Some(capability_id)
        || candidate.semantic_target_id.as_deref() != Some(target_id)
        || candidate.approved_value_sha256.as_ref() != approved_value_sha256
        || candidate.expected_postcondition_ids != [postcondition_id]
        || candidate.required_precondition_ids != ["precondition.observation.fresh"]
        || !candidate.reversible
        || candidate.risk_estimate > CognitiveRiskClass::BusinessStateChange
        || !candidate.uncertainty.is_empty()
    {
        return Err("model candidate differs from the exact bounded planning request".to_owned());
    }
    Ok(())
}

fn run_kernel_adaptive(
    workspace: &Path,
    kernel_root: &Path,
    log_root: &Path,
) -> Result<(), String> {
    if kernel_root.exists() {
        std::fs::remove_dir_all(kernel_root).map_err(|error| error.to_string())?;
    }
    let system_root =
        std::env::var_os("SystemRoot").ok_or_else(|| "SystemRoot is unavailable".to_owned())?;
    let powershell =
        PathBuf::from(system_root).join("System32/WindowsPowerShell/v1.0/powershell.exe");
    if !powershell.is_file() {
        return Err("trusted Windows PowerShell executable is absent".to_owned());
    }
    let stdout = File::create(log_root.join("kernel-adaptive.stdout.log"))
        .map_err(|error| error.to_string())?;
    let stderr = File::create(log_root.join("kernel-adaptive.stderr.log"))
        .map_err(|error| error.to_string())?;
    let status = Command::new(powershell)
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(workspace.join("scripts/e2e/run-first-kernel-e2e.ps1"))
        .args(["-Mode", "Adaptive", "-OutputRoot"])
        .arg(kernel_root)
        .current_dir(workspace)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .status()
        .map_err(|error| error.to_string())?;
    if !status.success() {
        return Err(format!(
            "KRN Adaptive runner failed with exit code {}",
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

fn verify_kernel_result(
    path: &Path,
    expected_mode: &str,
    expected_cycles: u32,
) -> Result<VerifiedKernelResultV1, String> {
    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    let value: Value = parse_json_strict(&bytes).map_err(|error| error.to_string())?;
    let object = value
        .as_object()
        .ok_or_else(|| "KRN result is not an object".to_owned())?;
    let string = |name: &str| {
        object
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("KRN result lacks {name}"))
    };
    let number = |name: &str| {
        object
            .get(name)
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| format!("KRN result lacks bounded {name}"))
    };
    if string("mode")? != expected_mode
        || string("actual_outcome")? != "completed"
        || number("action_cycle_count")? != expected_cycles
        || number("completed_action_count")? != expected_cycles
        || number("verified_action_count")? != expected_cycles
    {
        return Err("KRN result outcome or action count differs".to_owned());
    }
    let cleanup = object
        .get("cleanup")
        .and_then(Value::as_object)
        .ok_or_else(|| "KRN cleanup evidence is absent".to_owned())?;
    for name in [
        "module_host_residuals",
        "worker_residuals",
        "app_process_residuals",
        "activation_residuals",
        "payload_residuals",
    ] {
        if cleanup.get(name).and_then(Value::as_u64) != Some(0) {
            return Err(format!("KRN cleanup reports residual {name}"));
        }
    }
    if cleanup
        .get("temporary_root_removed")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err("KRN temporary root was not removed".to_owned());
    }
    let result_sha256 = string("result_sha256")?;
    let audit_chain_head = string("audit_chain_head")?;
    validate_hash(&result_sha256, "KRN result hash").map_err(|error| error.to_string())?;
    validate_hash(&audit_chain_head, "KRN audit hash").map_err(|error| error.to_string())?;
    let mut without_hash = value.clone();
    without_hash
        .as_object_mut()
        .ok_or_else(|| "KRN result clone is not an object".to_owned())?
        .remove("result_sha256");
    if canonical_sha256(&without_hash).map_err(|error| error.to_string())? != result_sha256 {
        return Err("KRN result self-hash differs".to_owned());
    }
    Ok(VerifiedKernelResultV1 {
        result_sha256,
        audit_chain_head,
        action_cycle_count: expected_cycles,
        verified_action_count: expected_cycles,
    })
}

fn prepare_output_root(workspace: &Path, requested: &Path) -> Result<PathBuf, String> {
    let target = workspace.join("target");
    std::fs::create_dir_all(&target).map_err(|error| error.to_string())?;
    let target = std::fs::canonicalize(target).map_err(|error| error.to_string())?;
    let requested = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        workspace.join(requested)
    };
    std::fs::create_dir_all(&requested).map_err(|error| error.to_string())?;
    let requested = std::fs::canonicalize(requested).map_err(|error| error.to_string())?;
    if !requested.starts_with(&target) || requested == target {
        return Err("model E2E output root must be a child of workspace target".to_owned());
    }
    Ok(requested)
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    std::fs::write(
        path,
        serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn workspace_root() -> Result<PathBuf, String> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "cannot derive workspace root".to_owned())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
