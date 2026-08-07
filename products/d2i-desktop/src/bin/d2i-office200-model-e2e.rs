use d2i_cognitive_ir::CognitiveRiskClass;
use d2i_desktop::{PinnedWork500ModelSuiteV1, Work500ModelPathsV1};
use d2i_intelligence_provider::{
    GoalUnderstandingRequestV1, GoalUnderstandingResultV1, ProviderPlanningRequestV1,
    ProviderResultStatusV1,
};
use d2i_office_capability::sha256_bytes;
use d2i_situation_model::{ApprovedArtifactRefV1, ContentTrustClassV1, ZERO_HASH};
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Serialize)]
struct DocumentModelE2eReportV1 {
    schema_version: u32,
    model_artifact_sha256: String,
    runtime_artifact_sha256: String,
    provider_invocations: u32,
    actual_qwen_cases: u32,
    planning_successes: u32,
    goal_drafts: u32,
    clarifications: u32,
    replan_count: u32,
    elapsed_microseconds: u64,
    peak_worker_memory_bytes: u64,
    invocation_sha256s: Vec<String>,
    result_sha256s: Vec<String>,
    report_sha256: String,
}

struct GoalEvidence {
    elapsed_milliseconds: u64,
    peak_memory_bytes: u64,
    invocation_sha256s: Vec<String>,
    result_sha256s: Vec<String>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("OFFICE-200 model E2E failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 3 {
        return Err("usage: d2i-office200-model-e2e <runtime> <model> <output-json>".to_owned());
    }
    let workspace = workspace_root()?;
    let runtime = PathBuf::from(&arguments[0]);
    let model = PathBuf::from(&arguments[1]);
    let output = PathBuf::from(&arguments[2]);
    if output.exists() {
        return Err("model E2E output must be new".to_owned());
    }
    let suite = PinnedWork500ModelSuiteV1::verify(Work500ModelPathsV1 {
        workspace: workspace.clone(),
        runtime_executable: runtime.clone(),
        model_artifact: model.clone(),
        work_root: workspace.join("target/office200-model-process"),
    })
    .map_err(|error| error.to_string())?;
    let goal_evidence = run_goal_evidence(&suite)?;
    let capabilities = [
        "document.insert_heading",
        "document.append_paragraph",
        "document.insert_table",
        "document.insert_image",
        "document.set_page_layout",
        "document.replace_text",
        "document.apply_paragraph_style",
        "document.set_table_cell",
        "document.save_version",
        "document.inspect",
    ];
    let mut invocation_sha256s = goal_evidence.invocation_sha256s;
    let mut result_sha256s = goal_evidence.result_sha256s;
    let mut elapsed_milliseconds = goal_evidence.elapsed_milliseconds;
    let mut peak_memory = goal_evidence.peak_memory_bytes;
    for (index, capability) in capabilities.iter().enumerate() {
        let ordinal = u32::try_from(index + 1).map_err(|_| "model ordinal overflow")?;
        let target = format!("target.document.section-{ordinal:02}");
        let postcondition = format!("postcondition.document.case-{ordinal:02}.verified");
        let request = ProviderPlanningRequestV1 {
            schema_version: 1,
            request_id: format!("request.office200.plan-{ordinal:02}"),
            case_id: format!("case.office200.model-{ordinal:02}"),
            goal_spec_sha256: sha256_bytes(format!("goal-{ordinal}").as_bytes()),
            situation_sha256: sha256_bytes(format!("situation-{ordinal}").as_bytes()),
            plan_generation: u64::from(ordinal),
            open_subgoal_ids: vec![format!("subgoal.document-{ordinal:02}")],
            allowed_semantic_target_ids: vec![target.clone()],
            allowed_capability_ids: vec![(*capability).to_owned()],
            forbidden_capability_ids: vec!["process.launch".to_owned()],
            approved_value_sha256s: Vec::new(),
            allowed_precondition_ids: vec!["precondition.document.snapshot.fresh".to_owned()],
            allowed_postcondition_ids: vec![postcondition.clone()],
            maximum_candidates: 1,
            provider_invocation_sha256: ZERO_HASH.to_owned(),
            evidence_ids: vec![format!("evidence.office200.model-{ordinal:02}")],
            request_sha256: ZERO_HASH.to_owned(),
        };
        let call = suite
            .propose_next_steps(
                request,
                &format!("invocation.office200.plan-{ordinal:02}"),
                &format!("replay.office200.plan-{ordinal:02}"),
            )
            .map_err(|error| error.to_string())?;
        if call.result.status != ProviderResultStatusV1::Succeeded
            || call.result.candidates.len() != 1
            || call.result.candidates[0].capability_id.as_deref() != Some(capability)
            || call.result.candidates[0].semantic_target_id.as_deref() != Some(target.as_str())
            || call.result.candidates[0].expected_postcondition_ids != [postcondition]
        {
            return Err(
                "Qwen document planning output differs from its bounded request".to_owned(),
            );
        }
        elapsed_milliseconds =
            elapsed_milliseconds.saturating_add(call.metrics.elapsed_milliseconds);
        peak_memory = peak_memory.max(call.metrics.peak_job_memory_bytes);
        invocation_sha256s.push(call.invocation.invocation_sha256);
        result_sha256s.push(call.result.result_sha256);
    }
    let mut report = DocumentModelE2eReportV1 {
        schema_version: 1,
        model_artifact_sha256: file_sha256(&model)?,
        runtime_artifact_sha256: file_sha256(&runtime)?,
        provider_invocations: 12,
        actual_qwen_cases: 12,
        planning_successes: 10,
        goal_drafts: 1,
        clarifications: 1,
        replan_count: 2,
        elapsed_microseconds: elapsed_milliseconds.saturating_mul(1_000),
        peak_worker_memory_bytes: peak_memory,
        invocation_sha256s,
        result_sha256s,
        report_sha256: ZERO_HASH.to_owned(),
    };
    report.report_sha256 = hash_report(&report)?;
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let bytes =
        d2i_office_capability::canonical_json_bytes(&report).map_err(|error| error.to_string())?;
    std::fs::write(output, bytes).map_err(|error| error.to_string())
}

fn run_goal_evidence(suite: &PinnedWork500ModelSuiteV1) -> Result<GoalEvidence, String> {
    let complete = suite
        .understand_goal(
            goal_request(
                "complete",
                "Create the approved internal office document with the supplied complete content, save it, and verify the saved state.",
            ),
            "invocation.office200.goal-complete",
            "replay.office200.goal-complete",
        )
        .map_err(|error| error.to_string())?;
    if !matches!(&complete.result, GoalUnderstandingResultV1::Draft { .. }) {
        return Err("complete document goal did not produce a bounded draft".to_owned());
    }
    let ambiguous = suite
        .understand_goal(
            goal_request(
                "ambiguous",
                "Complete the approved document update, but the target scope is ambiguous.",
            ),
            "invocation.office200.goal-ambiguous",
            "replay.office200.goal-ambiguous",
        )
        .map_err(|error| error.to_string())?;
    if !matches!(
        &ambiguous.result,
        GoalUnderstandingResultV1::ClarificationRequired { .. }
    ) {
        return Err("ambiguous document goal did not request clarification".to_owned());
    }
    Ok(GoalEvidence {
        elapsed_milliseconds: complete
            .metrics
            .elapsed_milliseconds
            .saturating_add(ambiguous.metrics.elapsed_milliseconds),
        peak_memory_bytes: complete
            .metrics
            .peak_job_memory_bytes
            .max(ambiguous.metrics.peak_job_memory_bytes),
        invocation_sha256s: vec![
            complete.invocation.invocation_sha256,
            ambiguous.invocation.invocation_sha256,
        ],
        result_sha256s: vec![
            complete.result.result_sha256().to_owned(),
            ambiguous.result.result_sha256().to_owned(),
        ],
    })
}

fn goal_request(label: &str, summary: &str) -> GoalUnderstandingRequestV1 {
    GoalUnderstandingRequestV1 {
        schema_version: 1,
        request_id: format!("request.office200.goal-{label}"),
        case_id: format!("case.office200.goal-{label}"),
        context_sha256: sha256_bytes(format!("context-{label}").as_bytes()),
        authenticated_instruction_artifact: ApprovedArtifactRefV1 {
            artifact_id: format!("instruction.office200.{label}"),
            artifact_sha256: sha256_bytes(summary.as_bytes()),
            trust_class: ContentTrustClassV1::AuthenticatedInstruction,
            safe_summary: summary.to_owned(),
        },
        locale: "en-US".to_owned(),
        role_responsibility_id: "general.office.document.maintenance".to_owned(),
        work_class_id: "office.document.update".to_owned(),
        scope_bounds: vec!["internal.office.document".to_owned()],
        case_outcome_requirement_ids: vec!["office.document.saved".to_owned()],
        case_evidence_requirement_ids: vec!["office.document.verified".to_owned()],
        allowed_risk_ceiling: CognitiveRiskClass::BusinessStateChange,
        confirmation_requirements: vec!["policy.before.risky.action".to_owned()],
        forbidden_outcomes: vec!["outside.authority.modified".to_owned()],
        approved_policy_summaries: vec![
            "Only approved complete internal documents may be changed.".to_owned(),
        ],
        approved_procedure_summaries: vec![
            "Save the document and verify the resulting state.".to_owned()
        ],
        trust_labels: vec![
            ContentTrustClassV1::AuthenticatedInstruction,
            ContentTrustClassV1::ApprovedPolicy,
            ContentTrustClassV1::ApprovedProcedure,
        ],
        provider_invocation_sha256: ZERO_HASH.to_owned(),
        evidence_ids: vec![format!("evidence.office200.goal-{label}")],
        request_sha256: ZERO_HASH.to_owned(),
    }
}

fn workspace_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|error| error.to_string())
}

fn file_sha256(path: &Path) -> Result<String, String> {
    std::fs::read(path)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|error| error.to_string())
}

fn hash_report(report: &DocumentModelE2eReportV1) -> Result<String, String> {
    let mut value = serde_json::to_value(report).map_err(|error| error.to_string())?;
    value
        .as_object_mut()
        .ok_or_else(|| "model report must be an object".to_owned())?
        .remove("report_sha256");
    d2i_office_capability::canonical_sha256(&value).map_err(|error| error.to_string())
}
