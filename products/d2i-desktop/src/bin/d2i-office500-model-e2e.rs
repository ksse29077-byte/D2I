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
struct PdfModelReportV1 {
    schema_version: u32,
    model_artifact_sha256: String,
    runtime_artifact_sha256: String,
    provider_invocation_sha256: String,
    result_sha256: String,
    request_bytes: u32,
    elapsed_microseconds: u64,
    peak_worker_memory_bytes: u64,
    model_invocation_count: u32,
    profile_selection_only_count: u32,
    raw_pdf_count: u32,
    rendered_page_image_count: u32,
    extracted_pdf_fact_count: u32,
    export_execution_authority_count: u32,
    complete: bool,
    report_sha256: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("OFFICE-500 model E2E failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 3 {
        return Err("usage: d2i-office500-model-e2e <runtime> <model> <output-json>".to_owned());
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
        work_root: workspace.join("target/office500-model-process"),
    })
    .map_err(|error| error.to_string())?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs();
    let fact = SituationFactV1 {
        fact_id: "fact.office500.finalization-purpose".to_owned(),
        fact_kind: SituationFactKindV1::Observed,
        subject: "artifact.monthly-report".to_owned(),
        predicate: "submission.destination".to_owned(),
        typed_object: json!({ "class_id": "external_submission", "retention_id": "standard" }),
        confidence: ConfidenceV1::Millionths(1_000_000),
        evidence_refs: vec!["evidence.office500.trusted-intent".to_owned()],
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
        request_id: "request.office500.profile-choice".to_owned(),
        case_id: "case.office500.pdf-finalization".to_owned(),
        context_sha256: canonical_sha256(&("profile-choice", &fact.fact_sha256))
            .map_err(|error| error.to_string())?,
        generation: 1,
        trusted_base_facts: vec![fact],
        unresolved_requirement_ids: vec!["requirement.select-fixed-profile".to_owned()],
        allowed_semantic_target_ids: vec!["profile.submission_static".to_owned()],
        allowed_capability_ids: vec!["language.choose-pdf-profile".to_owned()],
        forbidden_capability_ids: vec![
            "pdf.read-raw".to_owned(),
            "pdf.read-rendered-image".to_owned(),
            "pdf.extract-authoritative-facts".to_owned(),
            "pdf.export".to_owned(),
            "network.fetch".to_owned(),
            "process.launch".to_owned(),
        ],
        source_observation_hashes: vec![sha256_bytes(b"office500-trusted-finalization-intent")],
        previous_situation_sha256: None,
        provider_invocation_sha256: ZERO_HASH.to_owned(),
        evidence_ids: vec!["evidence.office500.model-boundary".to_owned()],
        request_sha256: ZERO_HASH.to_owned(),
    };
    let request_bytes = u32::try_from(
        canonical_json_bytes(&request)
            .map_err(|error| error.to_string())?
            .len(),
    )
    .map_err(|error| error.to_string())?;
    if request_bytes > 16 * 1024 {
        return Err("OFFICE-500 model context exceeds 16 KiB".to_owned());
    }
    let call = suite
        .interpret_situation(
            request,
            "invocation.office500.profile-choice",
            "replay.office500.profile-choice",
        )
        .map_err(|error| error.to_string())?;
    call.result.validate().map_err(|error| error.to_string())?;
    let mut report = PdfModelReportV1 {
        schema_version: 1,
        model_artifact_sha256: file_sha256(&model)?,
        runtime_artifact_sha256: file_sha256(&runtime)?,
        provider_invocation_sha256: call.invocation.invocation_sha256,
        result_sha256: call.result.result_sha256,
        request_bytes,
        elapsed_microseconds: call.metrics.elapsed_milliseconds.saturating_mul(1_000),
        peak_worker_memory_bytes: call.metrics.peak_job_memory_bytes,
        model_invocation_count: 1,
        profile_selection_only_count: 1,
        raw_pdf_count: 0,
        rendered_page_image_count: 0,
        extracted_pdf_fact_count: 0,
        export_execution_authority_count: 0,
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

fn report_hash(report: &PdfModelReportV1) -> Result<String, String> {
    let mut value = serde_json::to_value(report).map_err(|error| error.to_string())?;
    value["report_sha256"] = serde_json::Value::String(ZERO_HASH.to_owned());
    canonical_sha256(&value).map_err(|error| error.to_string())
}
