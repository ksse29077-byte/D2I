use crate::{
    LocalModelProcessConfigurationV1, LocalModelProcessProvider, VerifiedLocalModelArtifactsV1,
};
use d2i_intelligence_provider::{
    GoalUnderstandingRequestV1, GoalUnderstandingResultV1, IntelligenceProvider,
    IntelligenceProviderDescriptorV1, IntelligenceProviderError, IntelligenceProviderInvocationV1,
    IntelligenceProviderKindV1, ProviderDecodingBindingV1, ProviderDeterminismClassV1,
    ProviderNetworkPolicyV1, ProviderOperationV1, ProviderPlanningRequestV1,
    ProviderPlanningResultV1, ProviderResourceProfileV1, ProviderSamplingPolicyV1,
    SituationInterpretationRequestV1, SituationInterpretationResultV1,
};
use d2i_situation_model::{hash_without, ZERO_HASH};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const WORK500_MODEL_ID: &str = "Qwen/Qwen3-4B-GGUF";
pub const WORK500_MODEL_REVISION: &str = "bc640142c66e1fdd12af0bd68f40445458f3869b";
pub const WORK500_MODEL_SHA256: &str =
    "sha256:7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5";
pub const WORK500_RUNTIME_ID: &str = "ggml-org/llama.cpp";
pub const WORK500_RUNTIME_REVISION: &str = "b10275";
pub const WORK500_RUNTIME_DISTRIBUTION_SHA256: &str =
    "sha256:6029d1e839018b8edeaafff0da08952b68d0e4b7b4431c8aabe6c2dac8e66103";
pub const WORK500_RUNTIME_EXECUTABLE_SHA256: &str =
    "sha256:ea0809388e71270d1f238276ef123216a5a6d3663500185abe05d8cd72daceaf";

const WORK500_PROVIDER_TIMEOUT_MILLISECONDS: u64 = 45_000;
const WORK500_PROVIDER_MEMORY_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const WORK500_PROVIDER_OUTPUT_BYTES: u64 = 64 * 1024;
const WORK500_PROVIDER_CONTEXT_TOKENS: u32 = 4_096;
const WORK500_PROVIDER_OUTPUT_TOKENS: u32 = 768;
const WORK500_PROVIDER_CPU_THREADS: u32 = 16;

#[derive(Debug, Clone)]
pub struct Work500ModelPathsV1 {
    pub workspace: PathBuf,
    pub runtime_executable: PathBuf,
    pub model_artifact: PathBuf,
    pub work_root: PathBuf,
}

#[derive(Debug, Clone)]
struct Work500OperationBindingV1 {
    descriptor: IntelligenceProviderDescriptorV1,
    artifacts: VerifiedLocalModelArtifactsV1,
    input_schema_id: &'static str,
    output_schema_id: &'static str,
}

#[derive(Debug, Clone)]
pub struct Work500ProviderCallV1<T> {
    pub descriptor: IntelligenceProviderDescriptorV1,
    pub invocation: IntelligenceProviderInvocationV1,
    pub result: T,
}

#[derive(Debug, Clone)]
pub struct PinnedWork500ModelSuiteV1 {
    goal: Work500OperationBindingV1,
    situation: Work500OperationBindingV1,
    planning: Work500OperationBindingV1,
}

impl PinnedWork500ModelSuiteV1 {
    pub fn verify(paths: Work500ModelPathsV1) -> Result<Self, IntelligenceProviderError> {
        let workspace = canonical_directory(&paths.workspace, "workspace")?;
        let runtime_executable = canonical_file(&paths.runtime_executable, "runtime executable")?;
        let model_artifact = canonical_file(&paths.model_artifact, "model artifact")?;
        let work_root = absolute_work_root(&paths.work_root)?;

        let goal_configuration = operation_configuration(
            &workspace,
            &runtime_executable,
            &model_artifact,
            &work_root,
            "goal",
        )?;
        let goal_artifacts = VerifiedLocalModelArtifactsV1::verify(goal_configuration)
            .map_err(|error| contextual_error("goal artifact verification", error))?;
        let situation_artifacts = goal_artifacts
            .derive_operation_binding(operation_configuration(
                &workspace,
                &runtime_executable,
                &model_artifact,
                &work_root,
                "situation",
            )?)
            .map_err(|error| contextual_error("situation artifact verification", error))?;
        let planning_artifacts = goal_artifacts
            .derive_operation_binding(operation_configuration(
                &workspace,
                &runtime_executable,
                &model_artifact,
                &work_root,
                "planning",
            )?)
            .map_err(|error| contextual_error("planning artifact verification", error))?;
        let now = unix_time_seconds()?;

        Ok(Self {
            goal: operation_binding(
                "goal",
                "goal_understanding_request_v1",
                "local_model_goal_output_v1",
                goal_artifacts,
                now,
            )?,
            situation: operation_binding(
                "situation",
                "situation_interpretation_request_v1",
                "local_model_situation_output_v1",
                situation_artifacts,
                now,
            )?,
            planning: operation_binding(
                "planning",
                "provider_planning_request_v1",
                "local_model_planning_output_v1",
                planning_artifacts,
                now,
            )?,
        })
    }

    pub fn goal_descriptor(&self) -> &IntelligenceProviderDescriptorV1 {
        &self.goal.descriptor
    }

    pub fn situation_descriptor(&self) -> &IntelligenceProviderDescriptorV1 {
        &self.situation.descriptor
    }

    pub fn planning_descriptor(&self) -> &IntelligenceProviderDescriptorV1 {
        &self.planning.descriptor
    }

    /// Rebinds only the descriptor validity window for a bounded resumable
    /// evaluation. Model, runtime, prompt, schema, and resource bindings remain
    /// unchanged, and an expired or future-issued window is rejected.
    pub fn rebind_descriptor_validity_for_resume(
        &mut self,
        issued_at_unix_seconds: u64,
        current_time_unix_seconds: u64,
    ) -> Result<(), IntelligenceProviderError> {
        if issued_at_unix_seconds > current_time_unix_seconds.saturating_add(60)
            || current_time_unix_seconds > issued_at_unix_seconds.saturating_add(86_400)
        {
            return Err(IntelligenceProviderError::Unauthorized(
                "resumable provider descriptor validity window is stale or future-issued"
                    .to_owned(),
            ));
        }
        for binding in [&mut self.goal, &mut self.situation, &mut self.planning] {
            let mut descriptor = binding.descriptor.clone();
            descriptor.valid_from_unix_seconds = issued_at_unix_seconds.saturating_sub(60);
            descriptor.expires_at_unix_seconds = issued_at_unix_seconds.saturating_add(86_400);
            descriptor.descriptor_sha256 = ZERO_HASH.to_owned();
            binding.descriptor = descriptor.seal()?;
        }
        Ok(())
    }

    pub fn understand_goal(
        &self,
        mut request: GoalUnderstandingRequestV1,
        invocation_id: &str,
        replay_id: &str,
    ) -> Result<Work500ProviderCallV1<GoalUnderstandingResultV1>, IntelligenceProviderError> {
        let input_sha256 = request.invocation_input_sha256()?;
        let invocation = build_invocation(
            &self.goal,
            ProviderOperationV1::UnderstandGoal,
            invocation_id,
            replay_id,
            &request.case_id,
            &request.context_sha256,
            None,
            input_sha256,
            request.evidence_ids.clone(),
        )?;
        request.provider_invocation_sha256 = invocation.invocation_sha256.clone();
        request.request_sha256 = hash_without(&request, &["request_sha256"])?;
        request.validate()?;
        let provider = LocalModelProcessProvider::new(
            self.goal.descriptor.clone(),
            invocation.clone(),
            self.goal.artifacts.clone(),
        )?;
        let result = provider.understand_goal(request)?;
        Ok(Work500ProviderCallV1 {
            descriptor: self.goal.descriptor.clone(),
            invocation,
            result,
        })
    }

    pub fn interpret_situation(
        &self,
        mut request: SituationInterpretationRequestV1,
        invocation_id: &str,
        replay_id: &str,
    ) -> Result<Work500ProviderCallV1<SituationInterpretationResultV1>, IntelligenceProviderError>
    {
        let input_sha256 = request.invocation_input_sha256()?;
        let invocation = build_invocation(
            &self.situation,
            ProviderOperationV1::InterpretSituation,
            invocation_id,
            replay_id,
            &request.case_id,
            &request.context_sha256,
            request.previous_situation_sha256.as_deref(),
            input_sha256,
            request.evidence_ids.clone(),
        )?;
        request.provider_invocation_sha256 = invocation.invocation_sha256.clone();
        request.request_sha256 = hash_without(&request, &["request_sha256"])?;
        request.validate()?;
        let provider = LocalModelProcessProvider::new(
            self.situation.descriptor.clone(),
            invocation.clone(),
            self.situation.artifacts.clone(),
        )?;
        let result = provider.interpret_situation(request)?;
        Ok(Work500ProviderCallV1 {
            descriptor: self.situation.descriptor.clone(),
            invocation,
            result,
        })
    }

    pub fn propose_next_steps(
        &self,
        mut request: ProviderPlanningRequestV1,
        invocation_id: &str,
        replay_id: &str,
    ) -> Result<Work500ProviderCallV1<ProviderPlanningResultV1>, IntelligenceProviderError> {
        let input_sha256 = request.invocation_input_sha256()?;
        let invocation = build_invocation(
            &self.planning,
            ProviderOperationV1::ProposeNextSteps,
            invocation_id,
            replay_id,
            &request.case_id,
            &request.goal_spec_sha256,
            Some(&request.situation_sha256),
            input_sha256,
            request.evidence_ids.clone(),
        )?;
        request.provider_invocation_sha256 = invocation.invocation_sha256.clone();
        request.request_sha256 = hash_without(&request, &["request_sha256"])?;
        request.validate()?;
        let provider = LocalModelProcessProvider::new(
            self.planning.descriptor.clone(),
            invocation.clone(),
            self.planning.artifacts.clone(),
        )?;
        let result = provider.propose_next_steps(request)?;
        Ok(Work500ProviderCallV1 {
            descriptor: self.planning.descriptor.clone(),
            invocation,
            result,
        })
    }
}

fn operation_configuration(
    workspace: &Path,
    runtime_executable: &Path,
    model_artifact: &Path,
    work_root: &Path,
    operation: &str,
) -> Result<LocalModelProcessConfigurationV1, IntelligenceProviderError> {
    let schema = workspace.join(format!(
        "config/intelligence/qwen3-workforce-v1/{operation}-output.schema.json"
    ));
    let prompt = workspace.join(format!(
        "config/intelligence/qwen3-workforce-v1/{operation}-system-prompt.txt"
    ));
    Ok(LocalModelProcessConfigurationV1 {
        profile_name: format!("D2I.Work500.{operation}"),
        runtime_executable: runtime_executable.to_path_buf(),
        runtime_executable_sha256: WORK500_RUNTIME_EXECUTABLE_SHA256.to_owned(),
        runtime_distribution_sha256: WORK500_RUNTIME_DISTRIBUTION_SHA256.to_owned(),
        model_artifact: model_artifact.to_path_buf(),
        model_artifact_sha256: WORK500_MODEL_SHA256.to_owned(),
        output_schema_sha256: sha256_file(&schema)?,
        output_schema: schema,
        system_prompt_template_sha256: sha256_file(&prompt)?,
        system_prompt_template: prompt,
        work_root: work_root.join(operation),
        timeout_milliseconds: WORK500_PROVIDER_TIMEOUT_MILLISECONDS,
        maximum_output_bytes: WORK500_PROVIDER_OUTPUT_BYTES,
        context_tokens: WORK500_PROVIDER_CONTEXT_TOKENS,
        output_tokens: WORK500_PROVIDER_OUTPUT_TOKENS,
        cpu_threads: WORK500_PROVIDER_CPU_THREADS,
    })
}

fn operation_binding(
    operation: &str,
    input_schema_id: &'static str,
    output_schema_id: &'static str,
    artifacts: VerifiedLocalModelArtifactsV1,
    now: u64,
) -> Result<Work500OperationBindingV1, IntelligenceProviderError> {
    let configuration = artifacts.configuration();
    let descriptor = IntelligenceProviderDescriptorV1 {
        schema_version: 1,
        provider_id: format!("provider.qwen3.{operation}.v1"),
        provider_version: "1".to_owned(),
        provider_kind: IntelligenceProviderKindV1::LocalModelProcess,
        model_id: WORK500_MODEL_ID.to_owned(),
        model_revision: WORK500_MODEL_REVISION.to_owned(),
        model_artifact_sha256: WORK500_MODEL_SHA256.to_owned(),
        tokenizer_sha256: WORK500_MODEL_SHA256.to_owned(),
        inference_runtime_id: WORK500_RUNTIME_ID.to_owned(),
        inference_runtime_version: WORK500_RUNTIME_REVISION.to_owned(),
        inference_runtime_sha256: WORK500_RUNTIME_DISTRIBUTION_SHA256.to_owned(),
        prompt_template_sha256: configuration.system_prompt_template_sha256.clone(),
        supported_locales: vec!["ko-KR".to_owned(), "en-US".to_owned()],
        supported_input_schema_ids: vec![input_schema_id.to_owned()],
        supported_output_schema_ids: vec![output_schema_id.to_owned()],
        maximum_context_bytes: 128 * 1024,
        maximum_context_tokens: WORK500_PROVIDER_CONTEXT_TOKENS,
        maximum_output_bytes: WORK500_PROVIDER_OUTPUT_BYTES,
        maximum_output_tokens: WORK500_PROVIDER_OUTPUT_TOKENS,
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
            maximum_memory_bytes: WORK500_PROVIDER_MEMORY_BYTES,
            gpu_required: false,
            maximum_concurrent_invocations: 1,
        },
        timeout_milliseconds: WORK500_PROVIDER_TIMEOUT_MILLISECONDS,
        valid_from_unix_seconds: now.saturating_sub(60),
        expires_at_unix_seconds: now.saturating_add(86_400),
        license_id: "Apache-2.0".to_owned(),
        commercial_use_allowed: true,
        evidence_ids: vec![
            "evidence.model.license.apache-2.0".to_owned(),
            "evidence.runtime.license.mit".to_owned(),
        ],
        descriptor_sha256: ZERO_HASH.to_owned(),
    }
    .seal()?;
    Ok(Work500OperationBindingV1 {
        descriptor,
        artifacts,
        input_schema_id,
        output_schema_id,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_invocation(
    binding: &Work500OperationBindingV1,
    operation: ProviderOperationV1,
    invocation_id: &str,
    replay_id: &str,
    case_id: &str,
    context_sha256: &str,
    situation_sha256: Option<&str>,
    input_sha256: String,
    evidence_ids: Vec<String>,
) -> Result<IntelligenceProviderInvocationV1, IntelligenceProviderError> {
    let now = unix_time_seconds()?;
    IntelligenceProviderInvocationV1 {
        schema_version: 1,
        invocation_id: invocation_id.to_owned(),
        operation,
        provider_descriptor_sha256: binding.descriptor.descriptor_sha256.clone(),
        model_artifact_sha256: WORK500_MODEL_SHA256.to_owned(),
        inference_runtime_sha256: WORK500_RUNTIME_DISTRIBUTION_SHA256.to_owned(),
        case_id: case_id.to_owned(),
        context_sha256: context_sha256.to_owned(),
        situation_sha256: situation_sha256.map(str::to_owned),
        input_schema_id: binding.input_schema_id.to_owned(),
        requested_output_schema_id: binding.output_schema_id.to_owned(),
        prompt_template_sha256: binding.descriptor.prompt_template_sha256.clone(),
        system_policy_sha256: sha256_bytes(b"d2i.work500.local-model.system-policy.v1"),
        trusted_caller_time_unix_seconds: now,
        deadline_unix_milliseconds: now
            .saturating_mul(1_000)
            .saturating_add(WORK500_PROVIDER_TIMEOUT_MILLISECONDS),
        decoding: ProviderDecodingBindingV1 {
            seed: 500,
            temperature_millionths: 0,
            top_p_millionths: 1_000_000,
            top_k: 1,
            output_grammar_sha256: binding
                .artifacts
                .configuration()
                .output_schema_sha256
                .clone(),
        },
        timeout_milliseconds: WORK500_PROVIDER_TIMEOUT_MILLISECONDS,
        memory_budget_bytes: WORK500_PROVIDER_MEMORY_BYTES,
        output_budget_bytes: WORK500_PROVIDER_OUTPUT_BYTES,
        replay_id: replay_id.to_owned(),
        evidence_ids,
        input_sha256,
        invocation_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, IntelligenceProviderError> {
    let path = std::fs::canonicalize(path)
        .map_err(|error| IntelligenceProviderError::Unavailable(format!("{label}: {error}")))?;
    if !path.is_dir() {
        return Err(IntelligenceProviderError::Invalid(format!(
            "{label} is not a directory"
        )));
    }
    Ok(path)
}

fn canonical_file(path: &Path, label: &str) -> Result<PathBuf, IntelligenceProviderError> {
    let path = std::fs::canonicalize(path)
        .map_err(|error| IntelligenceProviderError::Unavailable(format!("{label}: {error}")))?;
    if !path.is_file() {
        return Err(IntelligenceProviderError::Invalid(format!(
            "{label} is not a file"
        )));
    }
    Ok(path)
}

fn absolute_work_root(path: &Path) -> Result<PathBuf, IntelligenceProviderError> {
    if !path.is_absolute() {
        return Err(IntelligenceProviderError::Invalid(
            "model work root must be absolute".to_owned(),
        ));
    }
    std::fs::create_dir_all(path)
        .map_err(|error| IntelligenceProviderError::Unavailable(error.to_string()))?;
    std::fs::canonicalize(path)
        .map_err(|error| IntelligenceProviderError::Unavailable(error.to_string()))
}

fn sha256_file(path: &Path) -> Result<String, IntelligenceProviderError> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)
        .map_err(|error| IntelligenceProviderError::Unavailable(error.to_string()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| IntelligenceProviderError::Unavailable(error.to_string()))?;
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

fn unix_time_seconds() -> Result<u64, IntelligenceProviderError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|error| IntelligenceProviderError::Unavailable(error.to_string()))
}

fn contextual_error(context: &str, error: IntelligenceProviderError) -> IntelligenceProviderError {
    IntelligenceProviderError::Integrity(format!("{context}: {error}"))
}
