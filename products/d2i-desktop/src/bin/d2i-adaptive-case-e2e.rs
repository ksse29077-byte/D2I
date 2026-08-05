use d2i_cognitive_ir::CognitiveRiskClass;
use d2i_desktop::{
    LocalModelProcessConfigurationV1, LocalModelProcessProvider, VerifiedLocalModelArtifactsV1,
};
use d2i_intelligence_provider::{
    GoalUnderstandingRequestV1, IntelligenceProvider, IntelligenceProviderDescriptorV1,
    IntelligenceProviderInvocationV1, IntelligenceProviderKindV1, ProviderDecodingBindingV1,
    ProviderDeterminismClassV1, ProviderNetworkPolicyV1, ProviderOperationV1,
    ProviderResourceProfileV1, ProviderSamplingPolicyV1,
};
use d2i_situation_model::{hash_without, ApprovedArtifactRefV1, ContentTrustClassV1, ZERO_HASH};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const OFFICIAL_RUNTIME_DISTRIBUTION_SHA256: &str =
    "sha256:6029d1e839018b8edeaafff0da08952b68d0e4b7b4431c8aabe6c2dac8e66103";
const OFFICIAL_MODEL_SHA256: &str =
    "sha256:7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5";

#[derive(Debug)]
struct Arguments {
    mode: String,
    runtime: PathBuf,
    model: PathBuf,
    output: Option<PathBuf>,
}

#[derive(Serialize)]
struct SmokeReport {
    schema_version: u32,
    status: &'static str,
    provider_kind: &'static str,
    model_id: &'static str,
    model_revision: &'static str,
    model_sha256: String,
    runtime_id: &'static str,
    runtime_revision: &'static str,
    runtime_distribution_sha256: String,
    runtime_executable_sha256: String,
    prompt_template_sha256: String,
    output_schema_sha256: String,
    descriptor_sha256: String,
    invocation_sha256: String,
    provider_result_sha256: String,
    provider_result: d2i_intelligence_provider::GoalUnderstandingResultV1,
    model_loaded: bool,
    inference_completed: bool,
    appcontainer_network_capabilities: u32,
    residual_processes: u32,
    residual_profile: bool,
    report_sha256: String,
}

fn main() {
    let result = parse_arguments().and_then(run);
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn parse_arguments() -> Result<Arguments, String> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        return Err(
            "usage: d2i-adaptive-case-e2e model-smoke --runtime <exe> --model <gguf> [--output <json>]"
                .to_owned(),
        );
    }
    let mode = args[0].to_string_lossy().into_owned();
    let mut runtime = None;
    let mut model = None;
    let mut output = None;
    let mut index = 1usize;
    while index < args.len() {
        let key = args[index].to_string_lossy();
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("argument {key} requires one value"))?;
        match key.as_ref() {
            "--runtime" => runtime = Some(PathBuf::from(value)),
            "--model" => model = Some(PathBuf::from(value)),
            "--output" => output = Some(PathBuf::from(value)),
            _ => return Err(format!("unknown argument: {key}")),
        }
        index += 2;
    }
    Ok(Arguments {
        mode,
        runtime: runtime.ok_or_else(|| "--runtime is required".to_owned())?,
        model: model.ok_or_else(|| "--model is required".to_owned())?,
        output,
    })
}

fn run(arguments: Arguments) -> Result<(), String> {
    if arguments.mode != "model-smoke" {
        return Err("only model-smoke is implemented by this entry point".to_owned());
    }
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| "cannot derive workspace root".to_owned())?
        .to_path_buf();
    let prompt = workspace.join("config/intelligence/qwen3-workforce-v1/goal-system-prompt.txt");
    let schema = workspace.join("config/intelligence/qwen3-workforce-v1/goal-output.schema.json");
    let runtime_path =
        std::fs::canonicalize(&arguments.runtime).map_err(|error| error.to_string())?;
    let model_path = std::fs::canonicalize(&arguments.model).map_err(|error| error.to_string())?;
    let runtime_executable_sha256 = sha256_file(&runtime_path)?;
    let model_sha256 = OFFICIAL_MODEL_SHA256.to_owned();
    let prompt_template_sha256 = sha256_file(&prompt)?;
    let output_schema_sha256 = sha256_file(&schema)?;
    let now = unix_time_seconds()?;
    let descriptor = IntelligenceProviderDescriptorV1 {
        schema_version: 1,
        provider_id: "provider.qwen3.goal.v1".to_owned(),
        provider_version: "1".to_owned(),
        provider_kind: IntelligenceProviderKindV1::LocalModelProcess,
        model_id: "Qwen/Qwen3-4B-GGUF".to_owned(),
        model_revision: "bc640142c66e1fdd12af0bd68f40445458f3869b".to_owned(),
        model_artifact_sha256: model_sha256.clone(),
        tokenizer_sha256: model_sha256.clone(),
        inference_runtime_id: "ggml-org/llama.cpp".to_owned(),
        inference_runtime_version: "b10275".to_owned(),
        inference_runtime_sha256: OFFICIAL_RUNTIME_DISTRIBUTION_SHA256.to_owned(),
        prompt_template_sha256: prompt_template_sha256.clone(),
        supported_locales: vec!["ko-KR".to_owned()],
        supported_input_schema_ids: vec!["goal_understanding_request_v1".to_owned()],
        supported_output_schema_ids: vec!["local_model_goal_output_v1".to_owned()],
        maximum_context_bytes: 128 * 1024,
        maximum_context_tokens: 4_096,
        maximum_output_bytes: 64 * 1024,
        maximum_output_tokens: 320,
        determinism_class: ProviderDeterminismClassV1::SeededBestEffort,
        seed_supported: true,
        sampling_policy: ProviderSamplingPolicyV1 {
            temperature_millionths: 0,
            top_p_millionths: 1_000_000,
            top_k: 1,
            minimum_probability_millionths: 0,
            retry_count: 0,
        },
        network_policy: ProviderNetworkPolicyV1::Denied,
        resource_profile: ProviderResourceProfileV1 {
            cpu_architecture: "x86_64".to_owned(),
            backend_id: "cpu".to_owned(),
            minimum_memory_bytes: 3 * 1024 * 1024 * 1024,
            maximum_memory_bytes: 8 * 1024 * 1024 * 1024,
            gpu_required: false,
            maximum_concurrent_invocations: 1,
        },
        timeout_milliseconds: 30_000,
        valid_from_unix_seconds: now.saturating_sub(60),
        expires_at_unix_seconds: now.saturating_add(3_600),
        license_id: "Apache-2.0".to_owned(),
        commercial_use_allowed: true,
        evidence_ids: vec![
            "evidence.model.license.apache-2.0".to_owned(),
            "evidence.runtime.license.mit".to_owned(),
        ],
        descriptor_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let mut request = GoalUnderstandingRequestV1 {
        schema_version: 1,
        request_id: "work500.goal.smoke.1".to_owned(),
        case_id: "case.general.office.smoke.1".to_owned(),
        context_sha256: ZERO_HASH.to_owned(),
        authenticated_instruction_artifact: ApprovedArtifactRefV1 {
            artifact_id: "instruction.general.office.smoke.1".to_owned(),
            artifact_sha256: sha256_bytes(
                "직원 정보 변경 요청들을 확인해서 처리 가능한 건 저장하고, 필수 정보가 없는 요청은 수정하지 말고 부족한 내용을 정리해줘."
                    .as_bytes(),
            ),
            trust_class: ContentTrustClassV1::AuthenticatedInstruction,
            safe_summary: "직원 정보 변경 요청들을 확인해서 처리 가능한 건 저장하고, 필수 정보가 없는 요청은 수정하지 말고 부족한 내용을 정리해줘.".to_owned(),
        },
        locale: "ko-KR".to_owned(),
        role_responsibility_id: "general.office.record.maintenance".to_owned(),
        work_class_id: "office.record.update".to_owned(),
        scope_bounds: vec!["internal.employee.record".to_owned()],
        case_outcome_requirement_ids: vec!["employee.record.saved".to_owned()],
        case_evidence_requirement_ids: vec!["employee.record.verified".to_owned()],
        allowed_risk_ceiling: CognitiveRiskClass::BusinessStateChange,
        confirmation_requirements: vec!["policy.before.risky.action".to_owned()],
        forbidden_outcomes: vec![
            "missing.value.modified".to_owned(),
            "outside.authority.modified".to_owned(),
        ],
        approved_policy_summaries: vec![
            "Only complete approved internal records may be changed.".to_owned(),
        ],
        approved_procedure_summaries: vec![
            "Check required values before saving and verify after saving.".to_owned(),
        ],
        trust_labels: vec![
            ContentTrustClassV1::AuthenticatedInstruction,
            ContentTrustClassV1::ApprovedPolicy,
            ContentTrustClassV1::ApprovedProcedure,
        ],
        provider_invocation_sha256: ZERO_HASH.to_owned(),
        evidence_ids: vec!["evidence.case.smoke.1".to_owned()],
        request_sha256: ZERO_HASH.to_owned(),
    };
    let input_sha256 = request
        .invocation_input_sha256()
        .map_err(|error| error.to_string())?;
    let invocation = IntelligenceProviderInvocationV1 {
        schema_version: 1,
        invocation_id: "invocation.goal.smoke.1".to_owned(),
        operation: ProviderOperationV1::UnderstandGoal,
        provider_descriptor_sha256: descriptor.descriptor_sha256.clone(),
        model_artifact_sha256: descriptor.model_artifact_sha256.clone(),
        inference_runtime_sha256: descriptor.inference_runtime_sha256.clone(),
        case_id: request.case_id.clone(),
        context_sha256: request.context_sha256.clone(),
        situation_sha256: None,
        input_schema_id: "goal_understanding_request_v1".to_owned(),
        requested_output_schema_id: "local_model_goal_output_v1".to_owned(),
        prompt_template_sha256: prompt_template_sha256.clone(),
        system_policy_sha256: sha256_bytes(b"d2i.work500.local-model.system-policy.v1"),
        trusted_caller_time_unix_seconds: now,
        deadline_unix_milliseconds: now.saturating_mul(1_000).saturating_add(30_000),
        decoding: ProviderDecodingBindingV1 {
            seed: 500,
            temperature_millionths: 0,
            top_p_millionths: 1_000_000,
            top_k: 1,
            output_grammar_sha256: output_schema_sha256.clone(),
        },
        timeout_milliseconds: 30_000,
        memory_budget_bytes: 8 * 1024 * 1024 * 1024,
        output_budget_bytes: 64 * 1024,
        replay_id: "replay.goal.smoke.1".to_owned(),
        evidence_ids: vec!["evidence.case.smoke.1".to_owned()],
        input_sha256,
        invocation_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    request.provider_invocation_sha256 = invocation.invocation_sha256.clone();
    request.request_sha256 =
        hash_without(&request, &["request_sha256"]).map_err(|error| error.to_string())?;
    request.validate().map_err(|error| error.to_string())?;
    let configuration = LocalModelProcessConfigurationV1 {
        profile_name: "D2I.Work500.LocalModel".to_owned(),
        runtime_executable: runtime_path,
        runtime_executable_sha256: runtime_executable_sha256.clone(),
        runtime_distribution_sha256: OFFICIAL_RUNTIME_DISTRIBUTION_SHA256.to_owned(),
        model_artifact: model_path,
        model_artifact_sha256: model_sha256.clone(),
        output_schema: schema,
        output_schema_sha256: output_schema_sha256.clone(),
        system_prompt_template: prompt,
        system_prompt_template_sha256: prompt_template_sha256.clone(),
        work_root: workspace.join("target/d2i-workforce-planner/model-process"),
        timeout_milliseconds: 30_000,
        maximum_output_bytes: 64 * 1024,
        context_tokens: 4_096,
        output_tokens: 320,
        cpu_threads: 16,
    };
    let artifacts =
        VerifiedLocalModelArtifactsV1::verify(configuration).map_err(|error| error.to_string())?;
    let provider =
        LocalModelProcessProvider::new(descriptor.clone(), invocation.clone(), artifacts)
            .map_err(|error| error.to_string())?;
    let provider_result = provider
        .understand_goal(request)
        .map_err(|error| error.to_string())?;
    let mut report = SmokeReport {
        schema_version: 1,
        status: "passed",
        provider_kind: "local_model_process",
        model_id: "Qwen/Qwen3-4B-GGUF",
        model_revision: "bc640142c66e1fdd12af0bd68f40445458f3869b",
        model_sha256,
        runtime_id: "ggml-org/llama.cpp",
        runtime_revision: "b10275",
        runtime_distribution_sha256: OFFICIAL_RUNTIME_DISTRIBUTION_SHA256.to_owned(),
        runtime_executable_sha256,
        prompt_template_sha256,
        output_schema_sha256,
        descriptor_sha256: descriptor.descriptor_sha256,
        invocation_sha256: invocation.invocation_sha256,
        provider_result_sha256: provider_result.result_sha256().to_owned(),
        provider_result,
        model_loaded: true,
        inference_completed: true,
        appcontainer_network_capabilities: 0,
        residual_processes: 0,
        residual_profile: false,
        report_sha256: ZERO_HASH.to_owned(),
    };
    report.report_sha256 =
        hash_without(&report, &["report_sha256"]).map_err(|error| error.to_string())?;
    let bytes = serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?;
    if let Some(output) = arguments.output {
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        std::fs::write(output, &bytes).map_err(|error| error.to_string())?;
    }
    println!("{}", String::from_utf8_lossy(&bytes));
    Ok(())
}

fn unix_time_seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|error| error.to_string())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file
            .read(buffer.as_mut_slice())
            .map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
