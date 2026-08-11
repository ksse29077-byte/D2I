use d2i_browser_research::{
    sha256_bytes, EvidenceTrustClassV1, ResearchModelContextSliceV1,
    ZERO_HASH as RESEARCH_ZERO_HASH,
};
use d2i_desktop::{PinnedWork500ModelSuiteV1, Work500ModelPathsV1};
use d2i_intelligence_provider::SituationInterpretationRequestV1;
use d2i_office_capability::{canonical_json_bytes, canonical_sha256};
use d2i_situation_model::{
    ConfidenceV1, ContentTrustClassV1, FreshnessBoundV1, SituationFactKindV1, SituationFactV1,
    ZERO_HASH,
};
use d2i_windows_host::{ensure_appcontainer_profile_deleted, installed_process_ids_by_name};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResearchModelReportV1 {
    schema_version: u32,
    model_artifact_sha256: String,
    runtime_artifact_sha256: String,
    provider_invocation_sha256s: Vec<String>,
    result_sha256s: Vec<String>,
    context_sha256s: Vec<String>,
    request_bytes: u32,
    elapsed_microseconds: u64,
    peak_worker_memory_bytes: u64,
    model_invocation_count: u32,
    raw_html_count: u32,
    raw_url_count: u32,
    raw_download_count: u32,
    raw_pdf_count: u32,
    raw_image_count: u32,
    credential_count: u32,
    network_authority_count: u32,
    workspace_promotion_authority_count: u32,
    provider_network_policy_denied: bool,
    model_appcontainer_profile_removed: bool,
    residual_model_worker_count: u32,
    complete: bool,
    report_sha256: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("OFFICE-600 model E2E failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 3 {
        return Err("usage: d2i-office600-model-e2e <runtime> <model> <output-json>".to_owned());
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
    let baseline_model_processes = installed_process_ids_by_name(&["llama-cli.exe"])
        .map_err(|error| error.to_string())?
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let workspace = workspace_root()?;
    let suite = PinnedWork500ModelSuiteV1::verify(Work500ModelPathsV1 {
        workspace: workspace.clone(),
        runtime_executable: runtime.clone(),
        model_artifact: model.clone(),
        work_root: workspace.join("target/office600-model-process"),
    })
    .map_err(|error| error.to_string())?;
    let now = unix_seconds()?;
    let mut invocation_hashes = Vec::new();
    let mut result_hashes = Vec::new();
    let mut context_hashes = Vec::new();
    let mut request_bytes = 0_u32;
    let mut elapsed_microseconds = 0_u64;
    let mut peak_worker_memory_bytes = 0_u64;
    for index in 1..=2_u32 {
        let context = model_context(index)?;
        let fact = SituationFactV1 {
            fact_id: format!("fact.office600.evidence.{index}"),
            fact_kind: SituationFactKindV1::Observed,
            subject: format!("research.case.{index}"),
            predicate: "evidence.synthesis-context".to_owned(),
            typed_object: json!({
                "trust_class": "untrusted_external_research",
                "evidence_ids": context.evidence_ids.clone(),
                "bounded_excerpts": context.bounded_excerpts.clone(),
                "conflict_ids": context.conflict_ids.clone(),
                "unknowns": context.unknowns.clone(),
            }),
            confidence: ConfidenceV1::Millionths(900_000),
            evidence_refs: vec![format!("evidence.office600.context.{index}")],
            source_trust_class: ContentTrustClassV1::UntrustedContent,
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
            request_id: format!("request.office600.synthesis.{index}"),
            case_id: format!("case.office600.model.{index}"),
            context_sha256: context.context_sha256.clone(),
            generation: 1,
            trusted_base_facts: vec![fact],
            unresolved_requirement_ids: vec!["requirement.evidence-grounded-summary".to_owned()],
            allowed_semantic_target_ids: vec!["research.evidence-summary".to_owned()],
            allowed_capability_ids: vec!["language.synthesize-evidence".to_owned()],
            forbidden_capability_ids: vec![
                "network.fetch".to_owned(),
                "browser.navigate".to_owned(),
                "workspace.promote".to_owned(),
                "download.read-raw".to_owned(),
                "credential.read".to_owned(),
                "process.launch".to_owned(),
            ],
            source_observation_hashes: context.source_ids.clone(),
            previous_situation_sha256: None,
            provider_invocation_sha256: ZERO_HASH.to_owned(),
            evidence_ids: context.evidence_ids.clone(),
            request_sha256: ZERO_HASH.to_owned(),
        };
        let bytes = canonical_json_bytes(&request).map_err(|error| error.to_string())?;
        request_bytes = request_bytes.saturating_add(
            u32::try_from(bytes.len()).map_err(|_| "model request size overflow".to_owned())?,
        );
        if bytes.len() > 64 * 1024 {
            return Err("OFFICE-600 model context exceeds 64 KiB".to_owned());
        }
        let call = suite
            .interpret_situation(
                request,
                &format!("invocation.office600.synthesis.{index}"),
                &format!("replay.office600.synthesis.{index}"),
            )
            .map_err(|error| error.to_string())?;
        call.result.validate().map_err(|error| error.to_string())?;
        invocation_hashes.push(call.invocation.invocation_sha256);
        result_hashes.push(call.result.result_sha256);
        context_hashes.push(context.context_sha256);
        elapsed_microseconds = elapsed_microseconds
            .saturating_add(call.metrics.elapsed_milliseconds.saturating_mul(1_000));
        peak_worker_memory_bytes = peak_worker_memory_bytes.max(call.metrics.peak_job_memory_bytes);
    }
    let provider_network_policy_denied = matches!(
        suite.situation_descriptor().network_policy,
        d2i_intelligence_provider::ProviderNetworkPolicyV1::Denied
    );
    let model_appcontainer_profile_removed =
        ensure_appcontainer_profile_deleted("D2I.Work500.situation").is_ok();
    let residual_model_worker_count = wait_for_new_model_processes(&baseline_model_processes)?;
    if !provider_network_policy_denied
        || !model_appcontainer_profile_removed
        || residual_model_worker_count != 0
    {
        return Err(format!(
            "model network or residual isolation evidence differs: policy_denied={provider_network_policy_denied}, profile_removed={model_appcontainer_profile_removed}, residual_workers={residual_model_worker_count}"
        ));
    }
    let mut report = ResearchModelReportV1 {
        schema_version: 1,
        model_artifact_sha256: file_sha256(&model)?,
        runtime_artifact_sha256: file_sha256(&runtime)?,
        provider_invocation_sha256s: invocation_hashes,
        result_sha256s: result_hashes,
        context_sha256s: context_hashes,
        request_bytes,
        elapsed_microseconds,
        peak_worker_memory_bytes,
        model_invocation_count: 2,
        raw_html_count: 0,
        raw_url_count: 0,
        raw_download_count: 0,
        raw_pdf_count: 0,
        raw_image_count: 0,
        credential_count: 0,
        network_authority_count: 0,
        workspace_promotion_authority_count: 0,
        provider_network_policy_denied,
        model_appcontainer_profile_removed,
        residual_model_worker_count,
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

fn wait_for_new_model_processes(baseline: &std::collections::BTreeSet<u32>) -> Result<u32, String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let current =
            installed_process_ids_by_name(&["llama-cli.exe"]).map_err(|error| error.to_string())?;
        let residual = current
            .into_iter()
            .filter(|process_id| !baseline.contains(process_id))
            .count();
        if residual == 0 {
            return Ok(0);
        }
        if std::time::Instant::now() >= deadline {
            return u32::try_from(residual).map_err(|_| "model process count overflow".to_owned());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn model_context(index: u32) -> Result<ResearchModelContextSliceV1, String> {
    ResearchModelContextSliceV1 {
        schema_version: 1,
        organization_id: "example-office-organization".to_owned(),
        case_id: format!("case.office600.model.{index}"),
        brief_sha256: sha256_bytes(format!("brief-{index}").as_bytes()),
        trust_class: EvidenceTrustClassV1::UntrustedExternalResearch,
        source_ids: vec![sha256_bytes(format!("snapshot-{index}").as_bytes())],
        evidence_ids: vec![format!("evidence.office600.model.{index}")],
        bounded_excerpts: vec![format!(
            "Observed public source {index} supports a bounded research summary."
        )],
        conflict_ids: Vec::new(),
        unknowns: vec!["Publication policy details remain unknown.".to_owned()],
        raw_html_count: 0,
        raw_url_count: 0,
        download_byte_count: 0,
        network_authority_count: 0,
        workspace_promotion_authority_count: 0,
        context_sha256: RESEARCH_ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn workspace_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|error| error.to_string())
}

fn unix_seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| error.to_string())
}

fn file_sha256(path: &Path) -> Result<String, String> {
    std::fs::read(path)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|error| error.to_string())
}

fn report_hash(report: &ResearchModelReportV1) -> Result<String, String> {
    let mut value = serde_json::to_value(report).map_err(|error| error.to_string())?;
    value["report_sha256"] = serde_json::Value::String(ZERO_HASH.to_owned());
    canonical_sha256(&value).map_err(|error| error.to_string())
}
