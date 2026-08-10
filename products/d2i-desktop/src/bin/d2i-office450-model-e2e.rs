use d2i_desktop::{PinnedWork500ModelSuiteV1, Work500ModelPathsV1};
use d2i_intelligence_provider::SituationInterpretationRequestV1;
use d2i_office_capability::{canonical_json_bytes, canonical_sha256, sha256_bytes};
use d2i_situation_model::{
    ConfidenceV1, ContentTrustClassV1, FreshnessBoundV1, SituationFactKindV1, SituationFactV1,
    ZERO_HASH,
};
use serde::Serialize;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize)]
struct DesignModelReportV1 {
    schema_version: u32,
    model_artifact_sha256: String,
    runtime_artifact_sha256: String,
    provider_invocation_sha256: String,
    result_sha256: String,
    request_bytes: u32,
    elapsed_microseconds: u64,
    peak_worker_memory_bytes: u64,
    model_invocation_count: u32,
    language_or_bounded_semantic_count: u32,
    raw_corpus_count: u32,
    raw_xml_count: u32,
    raw_coordinate_count: u32,
    raw_color_count: u32,
    raw_font_count: u32,
    raw_font_size_count: u32,
    layout_execution_authority_count: u32,
    complete: bool,
    report_sha256: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("OFFICE-450 model E2E failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 3 {
        return Err("usage: d2i-office450-model-e2e <runtime> <model> <output-json>".to_owned());
    }
    let runtime = PathBuf::from(&arguments[0])
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let model = PathBuf::from(&arguments[1])
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let output = PathBuf::from(&arguments[2]);
    if output.exists() || !runtime.is_file() || !model.is_file() {
        return Err("pinned model input or fresh output binding differs".to_owned());
    }
    let workspace = workspace_root()?;
    let suite = PinnedWork500ModelSuiteV1::verify(Work500ModelPathsV1 {
        workspace: workspace.clone(),
        runtime_executable: runtime.clone(),
        model_artifact: model.clone(),
        work_root: workspace.join("target/office450-model-process"),
    })
    .map_err(|error| error.to_string())?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs();
    let fact = SituationFactV1 {
        fact_id: "fact.office450.training-total".to_owned(),
        fact_kind: SituationFactKindV1::Observed,
        subject: "training.2026-07".to_owned(),
        predicate: "participant.total".to_owned(),
        typed_object: json!({ "value": 193, "unit_id": "unit.people" }),
        confidence: ConfidenceV1::Millionths(1_000_000),
        evidence_refs: vec!["evidence.office300.typed-fact".to_owned()],
        source_trust_class: ContentTrustClassV1::VerifiedObservation,
        provider_id: None,
        freshness: FreshnessBoundV1 {
            observed_at_unix_seconds: now,
            valid_until_unix_seconds: now.saturating_add(120),
            maximum_age_seconds: 120,
        },
        contradiction_group_id: None,
        fact_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let request = SituationInterpretationRequestV1 {
        schema_version: 1,
        request_id: "request.office450.language-render".to_owned(),
        case_id: "case.office450.monthly-report".to_owned(),
        context_sha256: canonical_sha256(&("claim-preserving", &fact.fact_sha256))
            .map_err(|error| error.to_string())?,
        generation: 1,
        trusted_base_facts: vec![fact],
        unresolved_requirement_ids: vec!["requirement.title.40-to-55-chars".to_owned()],
        allowed_semantic_target_ids: vec!["language.title.monthly-report".to_owned()],
        allowed_capability_ids: vec!["language.render.claim-preserving".to_owned()],
        forbidden_capability_ids: vec![
            "design.raw-coordinate".to_owned(),
            "design.raw-color".to_owned(),
            "design.raw-font".to_owned(),
            "design.raw-font-size".to_owned(),
            "presentation.execute-layout".to_owned(),
            "network.fetch".to_owned(),
            "process.launch".to_owned(),
        ],
        source_observation_hashes: vec![sha256_bytes(b"office300-typed-fact-observation")],
        previous_situation_sha256: None,
        provider_invocation_sha256: ZERO_HASH.to_owned(),
        evidence_ids: vec!["evidence.office450.language-boundary".to_owned()],
        request_sha256: ZERO_HASH.to_owned(),
    };
    let request_bytes = u32::try_from(
        canonical_json_bytes(&request)
            .map_err(|error| error.to_string())?
            .len(),
    )
    .map_err(|error| error.to_string())?;
    if request_bytes > 16 * 1024 {
        return Err("OFFICE-450 model context exceeds 16 KiB".to_owned());
    }
    let call = suite
        .interpret_situation(
            request,
            "invocation.office450.language-render",
            "replay.office450.language-render",
        )
        .map_err(|error| error.to_string())?;
    call.result.validate().map_err(|error| error.to_string())?;
    let mut report = DesignModelReportV1 {
        schema_version: 1,
        model_artifact_sha256: file_sha256(&model)?,
        runtime_artifact_sha256: file_sha256(&runtime)?,
        provider_invocation_sha256: call.invocation.invocation_sha256,
        result_sha256: call.result.result_sha256,
        request_bytes,
        elapsed_microseconds: call.metrics.elapsed_milliseconds.saturating_mul(1_000),
        peak_worker_memory_bytes: call.metrics.peak_job_memory_bytes,
        model_invocation_count: 1,
        language_or_bounded_semantic_count: 1,
        raw_corpus_count: 0,
        raw_xml_count: 0,
        raw_coordinate_count: 0,
        raw_color_count: 0,
        raw_font_count: 0,
        raw_font_size_count: 0,
        layout_execution_authority_count: 0,
        complete: true,
        report_sha256: ZERO_HASH.to_owned(),
    };
    report.report_sha256 = report_hash(&report)?;
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    std::fs::write(
        output,
        canonical_json_bytes(&report).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
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

fn report_hash(report: &DesignModelReportV1) -> Result<String, String> {
    let mut value = serde_json::to_value(report).map_err(|error| error.to_string())?;
    value["report_sha256"] = serde_json::Value::String(ZERO_HASH.to_owned());
    canonical_sha256(&value).map_err(|error| error.to_string())
}
