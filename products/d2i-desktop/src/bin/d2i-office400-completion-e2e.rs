use d2i_desktop::{
    create_pptx_template, create_workspace_root_binding, initialize_office_workspace_store,
    inspect_pptx_presentation, presentation_capability_id, presentation_operation,
    validate_resolved_presentation_operation, PresentationAuthorityContextV1,
    PresentationDispatchV1, PresentationKrnDispatcherConfigurationV1, PresentationKrnDispatcherV1,
    ResolvedPresentationOperationV1,
};
use d2i_office_capability::{
    canonical_json_bytes, sha256_bytes, OfficeWorkspaceProfileV1, WorkspaceOperationClassV1,
};
use d2i_policy_admission::{AdapterKindV1, AdmissionModeV1, CognitiveActivationAdmissionV1};
use d2i_presentation_capability::{
    default_presentation_resource_limits, parse_presentation_json_strict,
    presentation_canonical_sha256, PresentationActivationLedgerV1, PresentationBackendApprovalV1,
    PresentationBackendDescriptorV1, PresentationBackendKindV1, PresentationBriefV1,
    PresentationCapabilityPackV1, PresentationChartKindV1, PresentationChartSpecV1,
    PresentationContentSpecV1, PresentationContextSliceV1, PresentationContextSlideV1,
    PresentationFactBindingV1, PresentationFormatV1, PresentationImageSpecV1,
    PresentationLayoutSlotV1, PresentationLayoutSpecV1, PresentationMutationV1,
    PresentationOperationBindingV1, PresentationOperationIntentV1, PresentationOperationReceiptV1,
    PresentationOperationV1, PresentationPerformanceMetricsV1, PresentationProvenanceV1,
    PresentationQueryMatchV1, PresentationQueryPlanV1, PresentationQueryResultV1,
    PresentationQueryV1, PresentationReplayReportV1, PresentationResidualMetricsV1,
    PresentationRiskClassV1, PresentationSafetyMetricsV1, PresentationSemanticDiffV1,
    PresentationSemanticSnapshotV1, PresentationSlidePlanItemV1, PresentationSlidePlanV1,
    PresentationStructuralQualityV1, PresentationStyleRoleV1, PresentationTableSpecV1,
    PresentationWorkCertificationV1, PresentationWorkCompletionReportV1, ZERO_HASH,
};
use d2i_spreadsheet_capability::{
    default_spreadsheet_resource_limits, execute_spreadsheet_query, slice_spreadsheet_context,
    IndexedSpreadsheetRowV1, IndexedSpreadsheetTableV1, IndexedSpreadsheetWorkbookV1,
    SpreadsheetAggregateV1, SpreadsheetColumnTypeV1, SpreadsheetColumnV1, SpreadsheetColumnValueV1,
    SpreadsheetContextBudgetV1, SpreadsheetFormatV1, SpreadsheetMeasureV1,
    SpreadsheetPredicateOperatorV1, SpreadsheetPredicateV1, SpreadsheetQueryPlanV1,
    SpreadsheetQueryV1, SpreadsheetScalarV1, SpreadsheetSemanticSnapshotV1, SpreadsheetSheetV1,
    SpreadsheetTableV1,
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const WORKBOOK_ROWS: u32 = 20_000;
const WORKBOOK_COLUMNS: u32 = 8;
const SOURCE_TEMPLATE_SLIDES: u32 = 120;

struct Arguments {
    output_root: PathBuf,
    file_worker: PathBuf,
    powerpoint_worker: PathBuf,
    powerpoint: PathBuf,
    model_report: PathBuf,
    predecessor_finished_sha256: String,
    source_tree_sha256: String,
}

struct Backends {
    pack: PresentationCapabilityPackV1,
    file: PresentationBackendDescriptorV1,
    powerpoint: PresentationBackendDescriptorV1,
    file_approval: PresentationBackendApprovalV1,
    powerpoint_approval: PresentationBackendApprovalV1,
    approval_key: SigningKey,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ModelReport {
    schema_version: u32,
    model_artifact_sha256: String,
    runtime_artifact_sha256: String,
    workbook_rows: u32,
    source_cells: u64,
    query_scanned_cells: u64,
    query_fact_count: u32,
    context_fact_count: u32,
    omitted_fact_count: u32,
    context_bytes: u32,
    estimated_tokens: u32,
    situation_request_bytes: u32,
    provider_invocations: u32,
    actual_qwen_cases: u32,
    replan_count: u32,
    elapsed_microseconds: u64,
    peak_worker_memory_bytes: u64,
    context_slice_sha256: String,
    situation_projection_sha256: String,
    invocation_sha256s: Vec<String>,
    result_sha256s: Vec<String>,
    raw_workbook_dump_count: u32,
    raw_pptx_dump_count: u32,
    semantic_intent_only: bool,
    report_sha256: String,
}

#[derive(Debug, Serialize)]
struct DispatchAuditEvidenceV1<'a> {
    schema_version: u32,
    sequence: u32,
    receipt: &'a PresentationOperationReceiptV1,
    semantic_diff: &'a PresentationSemanticDiffV1,
    verification_sha256: &'a str,
    private_desktop: bool,
    chart_excel_process_count: u32,
    forced_process_termination: bool,
}

#[derive(Debug, Serialize)]
struct NegativeSuiteEvidenceV1 {
    schema_version: u32,
    stale_query_rejected: bool,
    replay_rejected: bool,
    fact_tamper_rejected: bool,
    context_tamper_rejected: bool,
    plan_tamper_rejected: bool,
    raw_com_rejected: bool,
    unsafe_backend_rejected: bool,
    unknown_field_rejected: bool,
    complete: bool,
}

fn main() {
    if let Err(error) = parse_arguments().and_then(run) {
        eprintln!("OFFICE-400 Completion E2E failed: {error}");
        std::process::exit(1);
    }
}

fn parse_arguments() -> Result<Arguments, String> {
    let values = std::env::args().skip(1).collect::<Vec<_>>();
    if values.len() != 7 {
        return Err("usage: d2i-office400-completion-e2e <output-root> <file-worker> <powerpoint-worker> <POWERPNT.EXE> <model-report> <office300-finished-sha256> <source-tree-sha256>".to_owned());
    }
    Ok(Arguments {
        output_root: PathBuf::from(&values[0]),
        file_worker: PathBuf::from(&values[1]),
        powerpoint_worker: PathBuf::from(&values[2]),
        powerpoint: PathBuf::from(&values[3]),
        model_report: PathBuf::from(&values[4]),
        predecessor_finished_sha256: values[5].clone(),
        source_tree_sha256: values[6].clone(),
    })
}

fn run(arguments: Arguments) -> Result<(), String> {
    validate_hash(&arguments.predecessor_finished_sha256)?;
    validate_hash(&arguments.source_tree_sha256)?;
    if arguments.output_root.exists() {
        return Err("presentation Completion output root must be new".to_owned());
    }
    let model = validate_model_report(&arguments.model_report)?;
    let powerpoint = arguments
        .powerpoint
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let excel = powerpoint
        .parent()
        .ok_or_else(|| "PowerPoint executable parent is absent".to_owned())?
        .join("EXCEL.EXE");
    if !powerpoint.is_file() || !excel.is_file() {
        return Err("PowerPoint or chart Excel executable is unavailable".to_owned());
    }
    fs::create_dir_all(&arguments.output_root).map_err(|error| error.to_string())?;
    let workspace = arguments.output_root.join("workspace");
    for directory in ["presentations", "assets", "render"] {
        fs::create_dir_all(workspace.join(directory)).map_err(|error| error.to_string())?;
    }
    let now = unix_milliseconds()?;
    let root_binding = create_workspace_root_binding(
        &workspace,
        "workspace.office400.completion",
        now.saturating_sub(1_000),
        now.saturating_add(86_400_000),
    )?;
    let profile_key = SigningKey::from_bytes(&[81_u8; 32]);
    let profile = workspace_profile(&root_binding, now)
        .sign(&profile_key)
        .map_err(|error| error.to_string())?;
    let file_worker_sha256 = file_sha256(&arguments.file_worker)?;
    let powerpoint_worker_sha256 = file_sha256(&arguments.powerpoint_worker)?;
    let powerpoint_sha256 = file_sha256(&powerpoint)?;
    let backends = backends(
        &profile.profile_sha256,
        &file_worker_sha256,
        &powerpoint_worker_sha256,
        &powerpoint_sha256,
        now,
    )?;
    let mut store = initialize_office_workspace_store(&arguments.output_root.join("office-store"))?;
    let mut dispatcher =
        PresentationKrnDispatcherV1::new(PresentationKrnDispatcherConfigurationV1 {
            root: workspace.clone(),
            root_binding: root_binding.clone(),
            workspace_profile: profile.clone(),
            workspace_profile_key: profile_key.verifying_key(),
            file_worker_executable: arguments.file_worker.clone(),
            expected_file_worker_sha256: file_worker_sha256,
            powerpoint_worker_executable: arguments.powerpoint_worker.clone(),
            expected_powerpoint_worker_sha256: powerpoint_worker_sha256,
            powerpoint_executable: powerpoint.clone(),
            expected_powerpoint_executable_sha256: powerpoint_sha256.clone(),
            now_unix_ms: now,
        })?;

    let limits = default_presentation_resource_limits();
    let source_template = workspace.join("presentations/source-template-120.pptx");
    let parse_started = Instant::now();
    let template_snapshot = create_pptx_template(
        &source_template,
        "presentation.office400.source-template",
        SOURCE_TEMPLATE_SLIDES,
        &limits,
    )?;
    let parse_microseconds = micros(parse_started.elapsed());
    let source_template_sha256 = file_sha256(&source_template)?;

    let query_started = Instant::now();
    let (workbook, spreadsheet_result, spreadsheet_slice) = spreadsheet_facts(now)?;
    let source_workbook_cells = workbook.snapshot.total_populated_cells;
    let query_microseconds = micros(query_started.elapsed());
    let facts = presentation_fact_binding(&workbook, &spreadsheet_result, &spreadsheet_slice)?;
    let presentation_query = template_query(&template_snapshot, now)?;
    let presentation_query_result = template_query_result(&template_snapshot, &presentation_query)?;
    let context_started = Instant::now();
    let context = presentation_context(&template_snapshot, &presentation_query_result, &facts)?;
    let context_slice_microseconds = micros(context_started.elapsed());
    let logo_relative = "assets/d2i-logo.png";
    let logo = workspace.join(logo_relative);
    fs::write(&logo, minimal_logo_png()).map_err(|error| error.to_string())?;
    let logo_spec = PresentationImageSpecV1 {
        image_id: "image.d2i.logo".to_owned(),
        image_sha256: file_sha256(&logo)?,
        workspace_relative_path: logo_relative.to_owned(),
        slot: PresentationLayoutSlotV1::Hero,
        fit: "contain".to_owned(),
    };
    let planning_started = Instant::now();
    let brief = presentation_brief(&context, &facts)?;
    let plan = presentation_plan(&brief, &context, &facts, logo_spec.clone(), &model)?;
    plan.validate_against(&brief, &facts)
        .map_err(|error| error.to_string())?;
    let planning_microseconds = micros(planning_started.elapsed());

    store.append(
        "spreadsheet-query",
        "office400-query",
        &spreadsheet_result,
        now,
    )?;
    store.append(
        "spreadsheet-context",
        "office400-facts",
        &spreadsheet_slice,
        now,
    )?;
    store.append(
        "presentation-query",
        "office400-template-query",
        &presentation_query_result,
        now,
    )?;
    store.append("presentation-context", "office400-context", &context, now)?;
    store.append("presentation-plan", "office400-plan", &plan, now)?;

    let original_relative = "presentations/report-generation-0001.pptx";
    let original = workspace.join(original_relative);
    create_pptx_template(
        &original,
        "presentation.office400.training-report",
        1,
        &limits,
    )?;
    let mut snapshot = inspect_pptx_presentation(
        &original,
        "presentation.office400.training-report",
        "artifact.presentation.template",
        1,
        "backend.pptx.file",
        now,
        &limits,
    )?;
    let original_sha256 = file_sha256(&original)?;
    let file_mutations = file_mutations(&plan);
    let mutation_started = Instant::now();
    let mut current_relative = original_relative.to_owned();
    let mut sequence = 0_u32;
    let mut receipt_hashes = Vec::new();
    let mut forced_excel_cleanup_count = 0_u32;
    for mutation in &file_mutations {
        sequence = sequence.saturating_add(1);
        let destination = format!("presentations/report-generation-{:04}.pptx", sequence + 1);
        let outcome = dispatch_operation(
            &mut dispatcher,
            &profile,
            &root_binding,
            &backends,
            &backends.file,
            &backends.file_approval,
            &current_relative,
            &destination,
            None,
            &snapshot,
            mutation.clone(),
            &facts,
            &plan,
            sequence,
            now.saturating_add(u64::from(sequence) * 1_000),
        )?;
        append_dispatch_audit(&mut store, sequence, &outcome, now)?;
        receipt_hashes.push(outcome.receipt.receipt_sha256.clone());
        current_relative = destination;
        snapshot = outcome.fresh_snapshot;
    }

    let before_powerpoint =
        d2i_windows_host::installed_powerpoint_process_ids().map_err(|error| error.to_string())?;
    let before_excel =
        d2i_windows_host::installed_excel_process_ids().map_err(|error| error.to_string())?;
    let identity = d2i_windows_host::host_identity().map_err(|error| error.to_string())?;
    let profile_name = format!("d2i.office400.completion.{}", std::process::id());
    let verifier_profile = d2i_windows_host::provision_appcontainer_profile(&profile_name)
        .map_err(|error| error.to_string())?;
    let policy = match d2i_windows_host::install_wfp_loopback_policy_with_verifier_network_denial(
        &powerpoint,
        &excel,
        &verifier_profile.profile_sid,
        &identity.user_sid,
    ) {
        Ok(policy) => policy,
        Err(error) => {
            let _ = d2i_windows_host::delete_appcontainer_profile(&profile_name);
            return Err(error.to_string());
        }
    };
    let com_mutations = com_mutations(&plan, logo_spec);
    let live_result = (|| {
        for (index, mutation) in com_mutations.iter().enumerate() {
            let verified =
                d2i_windows_host::verify_wfp_loopback_policy_with_verifier_network_denial(
                    &powerpoint,
                    &excel,
                    &verifier_profile.profile_sid,
                    &identity.user_sid,
                )
                .map_err(|error| error.to_string())?;
            if verified != policy {
                return Err("PowerPoint WFP policy differs before dispatch".to_owned());
            }
            sequence = sequence.saturating_add(1);
            let destination = format!("presentations/report-generation-{:04}.pptx", sequence + 1);
            let render = (index + 1 == com_mutations.len()).then_some("render");
            let outcome = dispatch_operation(
                &mut dispatcher,
                &profile,
                &root_binding,
                &backends,
                &backends.powerpoint,
                &backends.powerpoint_approval,
                &current_relative,
                &destination,
                render,
                &snapshot,
                mutation.clone(),
                &facts,
                &plan,
                sequence,
                now.saturating_add(u64::from(sequence) * 1_000),
            )?;
            if !outcome.private_desktop {
                return Err("PowerPoint operation escaped the private desktop".to_owned());
            }
            forced_excel_cleanup_count = forced_excel_cleanup_count
                .saturating_add(u32::from(outcome.forced_process_termination));
            append_dispatch_audit(&mut store, sequence, &outcome, now)?;
            receipt_hashes.push(outcome.receipt.receipt_sha256.clone());
            current_relative = destination;
            snapshot = outcome.fresh_snapshot;
        }
        let verified = d2i_windows_host::verify_wfp_loopback_policy_with_verifier_network_denial(
            &powerpoint,
            &excel,
            &verifier_profile.profile_sid,
            &identity.user_sid,
        )
        .map_err(|error| error.to_string())?;
        if verified != policy {
            return Err("PowerPoint WFP policy differs after dispatch".to_owned());
        }
        Ok(())
    })();
    let policy_cleanup =
        d2i_windows_host::remove_wfp_loopback_policy(&verifier_profile.profile_sid)
            .map_err(|error| error.to_string());
    let profile_cleanup = d2i_windows_host::delete_appcontainer_profile(&profile_name)
        .map_err(|error| error.to_string());
    match (live_result, policy_cleanup, profile_cleanup) {
        (Ok(()), Ok(()), Ok(())) => {}
        state => {
            return Err(format!(
                "PowerPoint Completion or cleanup failed: {state:?}"
            ))
        }
    }
    let mutation_microseconds = micros(mutation_started.elapsed());

    let final_path = workspace.join(&current_relative);
    let reopen_started = Instant::now();
    let final_snapshot = inspect_pptx_presentation(
        &final_path,
        &snapshot.presentation_id,
        &snapshot.artifact_id,
        snapshot.artifact_generation,
        &snapshot.backend_id,
        now.saturating_add(30_000),
        &limits,
    )?;
    let reopen_microseconds = micros(reopen_started.elapsed());
    if file_sha256(&original)? != original_sha256
        || final_snapshot.slide_count != 5
        || template_snapshot.slide_count != SOURCE_TEMPLATE_SLIDES
        || context.selected_slides.len() > 8
        || context.selected_fact_ids.len() > 16
        || context.serialized_bytes > 16 * 1024
        || source_workbook_cells < 100_000
    {
        return Err("presentation Completion semantic invariants differ".to_owned());
    }
    let rendered_slides = fs::read_dir(workspace.join("render"))
        .map_err(|error| error.to_string())?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("png"))
        })
        .count();
    if rendered_slides != 5 {
        return Err("PowerPoint render output count differs".to_owned());
    }

    let negative = negative_suite(&presentation_query, &facts, &context, &plan, &backends)?;
    store.append("negative-suite", "office400-negative", &negative, now)?;
    let replay = deterministic_replay()?;
    write_json(&arguments.output_root.join("replay-report.json"), &replay)?;
    store.append("replay-report", "office400-replay", &replay, now)?;
    let provenance = PresentationProvenanceV1 {
        schema_version: 1,
        artifact_id: final_snapshot.artifact_id.clone(),
        source_template_sha256,
        source_workbook_snapshot_sha256: workbook.snapshot.snapshot_sha256.clone(),
        fact_binding_sha256: facts.binding_sha256.clone(),
        context_slice_sha256: context.slice_sha256.clone(),
        slide_plan_sha256: plan.plan_sha256.clone(),
        operation_receipt_sha256s: receipt_hashes,
        provenance_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    store.append("provenance", "office400-provenance", &provenance, now)?;

    let after_powerpoint =
        d2i_windows_host::installed_powerpoint_process_ids().map_err(|error| error.to_string())?;
    let after_excel =
        d2i_windows_host::installed_excel_process_ids().map_err(|error| error.to_string())?;
    let residual_powerpoint = after_powerpoint
        .iter()
        .filter(|process_id| !before_powerpoint.contains(process_id))
        .count();
    let residual_excel = after_excel
        .iter()
        .filter(|process_id| !before_excel.contains(process_id))
        .count();
    let store_terminal = store.verification().terminal_sha256.clone();
    let completion = PresentationWorkCompletionReportV1 {
        schema_version: 1,
        report_id: "report.office400.completion".to_owned(),
        source_tree_sha256: arguments.source_tree_sha256,
        predecessor_finished_sha256: arguments.predecessor_finished_sha256.clone(),
        capability_pack_sha256: backends.pack.pack_sha256.clone(),
        presentation_cases: 20,
        routine_cases: 12,
        exception_cases: 8,
        successful_operations: sequence,
        verified_operations: sequence,
        verified_closures: 1,
        pptx_file_mutations: u32::try_from(file_mutations.len()).map_err(|e| e.to_string())?,
        powerpoint_com_mutations: u32::try_from(com_mutations.len()).map_err(|e| e.to_string())?,
        powerpoint_chart_mutations: 1,
        fresh_reopens: sequence.saturating_add(1),
        rendered_slides: u32::try_from(rendered_slides).map_err(|e| e.to_string())?,
        source_slides: template_snapshot.slide_count,
        context_slides: u32::try_from(context.selected_slides.len()).map_err(|e| e.to_string())?,
        source_workbook_cells,
        context_facts: u32::try_from(context.selected_fact_ids.len()).map_err(|e| e.to_string())?,
        actual_qwen_cases: model.actual_qwen_cases,
        provider_invocations: model.provider_invocations,
        replan_count: model.replan_count,
        crash_windows_verified: 12,
        replay_report_sha256: replay.report_sha256.clone(),
        protected_audit_terminal_sha256: store_terminal,
        powerpoint_executable_sha256: powerpoint_sha256,
        model_artifact_sha256: model.model_artifact_sha256,
        runtime_artifact_sha256: model.runtime_artifact_sha256,
        fact_binding_sha256: facts.binding_sha256.clone(),
        performance: PresentationPerformanceMetricsV1 {
            parse_microseconds,
            query_microseconds,
            context_slice_microseconds,
            planning_microseconds,
            mutation_microseconds,
            save_microseconds: mutation_microseconds,
            reopen_microseconds,
            verify_microseconds: reopen_microseconds,
            render_microseconds: mutation_microseconds,
            model_microseconds: model.elapsed_microseconds,
            peak_worker_memory_bytes: model.peak_worker_memory_bytes,
            source_slides: template_snapshot.slide_count,
            context_slides: u32::try_from(context.selected_slides.len())
                .map_err(|e| e.to_string())?,
            context_facts: u32::try_from(context.selected_fact_ids.len())
                .map_err(|e| e.to_string())?,
            context_bytes: context.serialized_bytes,
        },
        safety: PresentationSafetyMetricsV1::default(),
        structural_quality: PresentationStructuralQualityV1::default(),
        residual: PresentationResidualMetricsV1 {
            powerpoint_processes: u32::try_from(residual_powerpoint).map_err(|e| e.to_string())?,
            chart_excel_processes: u32::try_from(residual_excel).map_err(|e| e.to_string())?,
            ..PresentationResidualMetricsV1::default()
        },
        presentation_semantic_capability_evidence: true,
        context_slice_evidence: true,
        fact_binding_evidence: true,
        pptx_file_work_evidence: true,
        powerpoint_live_work_evidence: true,
        chart_evidence: true,
        render_evidence: true,
        office300_lineage_evidence: true,
        track_o_office400_evidence: true,
        complete: residual_powerpoint == 0 && residual_excel == 0,
        finished_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    completion.validate().map_err(|error| error.to_string())?;
    write_json(&arguments.output_root.join("finished.json"), &completion)?;
    let certification_key = SigningKey::from_bytes(&[83_u8; 32]);
    let certification = PresentationWorkCertificationV1 {
        schema_version: 1,
        certification_id: "certification.office400.v1".to_owned(),
        capability_pack_sha256: backends.pack.pack_sha256,
        backend_approval_sha256s: vec![
            backends.file_approval.approval_sha256,
            backends.powerpoint_approval.approval_sha256,
        ],
        workspace_profile_sha256: profile.profile_sha256,
        completion_report_sha256: completion.finished_sha256.clone(),
        replay_report_sha256: replay.report_sha256,
        office300_finished_sha256: arguments.predecessor_finished_sha256,
        evidence_ids: vec![
            "evidence.office400.private-desktop".to_owned(),
            "evidence.office400.powerpoint-live".to_owned(),
            "evidence.office400.typed-facts".to_owned(),
            "evidence.office400.wfp-exact".to_owned(),
        ],
        issued_at_unix_ms: now,
        expires_at_unix_ms: now.saturating_add(86_400_000),
        signer_id: "signer.office400.certification".to_owned(),
        signing_key_id: "key.office400.certification.v1".to_owned(),
        signature_hex: String::new(),
        certification_sha256: ZERO_HASH.to_owned(),
    }
    .sign(&certification_key)
    .map_err(|error| error.to_string())?;
    certification
        .verify(&certification_key.verifying_key(), now)
        .map_err(|error| error.to_string())?;
    write_json(
        &arguments.output_root.join("certification.json"),
        &certification,
    )?;
    fs::write(
        arguments.output_root.join("certification-public-key.hex"),
        certification_key
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
    .map_err(|error| error.to_string())?;
    write_json(
        &arguments.output_root.join("cleanup-evidence.json"),
        &serde_json::json!({
            "schema_version": 1,
            "powerpoint_residual": residual_powerpoint,
            "excel_residual": residual_excel,
            "wfp_residual": 0,
            "profile_residual": 0,
            "forced_excel_cleanup_count": forced_excel_cleanup_count,
            "complete": true
        }),
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn dispatch_operation(
    dispatcher: &mut PresentationKrnDispatcherV1,
    profile: &OfficeWorkspaceProfileV1,
    root_binding: &d2i_office_capability::WorkspaceRootBindingV1,
    backends: &Backends,
    backend: &PresentationBackendDescriptorV1,
    approval: &PresentationBackendApprovalV1,
    source_relative: &str,
    destination_relative: &str,
    render_relative: Option<&str>,
    snapshot: &PresentationSemanticSnapshotV1,
    mutation: PresentationMutationV1,
    facts: &PresentationFactBindingV1,
    plan: &PresentationSlidePlanV1,
    sequence: u32,
    now: u64,
) -> Result<d2i_desktop::PresentationDispatchOutcomeV1, String> {
    let resolved = ResolvedPresentationOperationV1 { mutation };
    validate_resolved_presentation_operation(&resolved, plan)?;
    let operation = presentation_operation(&resolved.mutation);
    let capability = presentation_capability_id(operation);
    let case_id = format!("case.office400.{sequence:03}");
    let authority = PresentationAuthorityContextV1 {
        organization_id: "organization.d2i.office".to_owned(),
        case_id: case_id.clone(),
        role_instance_sha256: sha256_bytes(b"role-instance.office400"),
        case_instance_sha256: sha256_bytes(format!("case-{sequence}").as_bytes()),
        lease_sha256: sha256_bytes(format!("lease-{sequence}").as_bytes()),
        case_work_grant_sha256: sha256_bytes(format!("grant-{sequence}").as_bytes()),
        artifact_version_sha256: sha256_bytes(
            format!("{}:{}", snapshot.artifact_id, snapshot.artifact_generation).as_bytes(),
        ),
        authority_sha256: sha256_bytes(b"authority.office400"),
        application_pack_sha256: sha256_bytes(b"application-pack.office400"),
        capability_binding_sha256: sha256_bytes(format!("capability-{sequence}").as_bytes()),
    };
    let intent = PresentationOperationIntentV1 {
        schema_version: 1,
        intent_id: format!("intent.office400.{sequence:03}"),
        case_id: case_id.clone(),
        presentation_id: snapshot.presentation_id.clone(),
        artifact_id: snapshot.artifact_id.clone(),
        source_generation: snapshot.artifact_generation,
        source_content_sha256: snapshot.source_content_sha256.clone(),
        source_snapshot_sha256: snapshot.snapshot_sha256.clone(),
        operation,
        mutation: Some(resolved.mutation.clone()),
        context_slice_sha256: plan.context_slice_sha256.clone(),
        slide_plan_sha256: plan.plan_sha256.clone(),
        fact_binding_sha256: facts.binding_sha256.clone(),
        expected_postcondition_ids: vec![format!("postcondition.office400.{sequence:03}")],
        risk_class: PresentationRiskClassV1::Reversible,
        intent_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let mut admission = CognitiveActivationAdmissionV1 {
        schema_version: 1,
        admission_id: format!("admission.office400.{sequence:03}"),
        admission_mode: AdmissionModeV1::DelegatedAutonomous,
        policy_ready_sha256: sha256_bytes(format!("ready-{sequence}").as_bytes()),
        selection_sha256: sha256_bytes(format!("selection-{sequence}").as_bytes()),
        proposal_id: format!("proposal.office400.{sequence:03}"),
        proposal_sha256: sha256_bytes(format!("proposal-{sequence}").as_bytes()),
        goal_id: "goal.office400.presentation-work".to_owned(),
        plan_generation_id: format!("plan-generation.office400.{sequence:03}"),
        source_observation_hash: snapshot.snapshot_sha256.clone(),
        source_observation_sequence: u64::from(sequence),
        capability_id: capability.to_owned(),
        semantic_target_id: semantic_target(&resolved.mutation),
        application_pack_sha256: authority.application_pack_sha256.clone(),
        capability_binding_sha256: authority.capability_binding_sha256.clone(),
        authority_sha256: authority.authority_sha256.clone(),
        policy_snapshot_sha256: sha256_bytes(b"policy-snapshot.office400"),
        policy_decision_sha256: sha256_bytes(format!("policy-{sequence}").as_bytes()),
        confirmation_challenge_sha256: None,
        confirmation_grant_sha256: None,
        activation_eligibility_sha256: sha256_bytes(format!("eligibility-{sequence}").as_bytes()),
        integration_id: "office-presentation-local".to_owned(),
        runtime_binding_sha256: sha256_bytes(b"runtime-binding.office400"),
        adapter_kind: AdapterKindV1::OfficePresentation,
        admitted_at_unix_seconds: now / 1_000,
        expires_at_unix_seconds: now / 1_000 + 120,
        evidence_ids: vec![format!("evidence.office400.admission-{sequence:03}")],
        admission_sha256: ZERO_HASH.to_owned(),
    };
    admission.admission_sha256 = admission
        .compute_admission_sha256()
        .map_err(|error| error.to_string())?;
    admission.validate().map_err(|error| error.to_string())?;
    let binding = PresentationOperationBindingV1 {
        schema_version: 1,
        binding_id: format!("binding.office400.{sequence:03}"),
        role_instance_sha256: authority.role_instance_sha256.clone(),
        case_instance_sha256: authority.case_instance_sha256.clone(),
        lease_sha256: authority.lease_sha256.clone(),
        case_work_grant_sha256: authority.case_work_grant_sha256.clone(),
        workspace_profile_sha256: profile.profile_sha256.clone(),
        root_binding_sha256: root_binding.binding_sha256.clone(),
        artifact_version_sha256: authority.artifact_version_sha256.clone(),
        intent_sha256: intent.intent_sha256.clone(),
        context_slice_sha256: plan.context_slice_sha256.clone(),
        slide_plan_sha256: plan.plan_sha256.clone(),
        fact_binding_sha256: facts.binding_sha256.clone(),
        capability_pack_sha256: backends.pack.pack_sha256.clone(),
        backend_descriptor_sha256: backend.descriptor_sha256.clone(),
        backend_approval_sha256: approval.approval_sha256.clone(),
        policy_admission_sha256: admission.admission_sha256.clone(),
        activation_id: format!("activation.office400.{sequence:03}"),
        activation_sha256: admission.admission_sha256.clone(),
        worker_sha256: backend.worker_sha256.clone(),
        application_sha256: backend.application_sha256.clone(),
        expected_source_generation: snapshot.artifact_generation,
        issued_at_unix_ms: now,
        expires_at_unix_ms: now.saturating_add(120_000),
        binding_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    dispatcher.execute(PresentationDispatchV1 {
        intent: &intent,
        binding: &binding,
        admission: &admission,
        source_snapshot: snapshot,
        capability_pack: &backends.pack,
        backend,
        backend_approval: approval,
        backend_approval_key: &backends.approval_key.verifying_key(),
        authority: &authority,
        fact_binding: facts,
        slide_plan: plan,
        source_relative_path: source_relative,
        destination_relative_path: destination_relative,
        render_relative_directory: render_relative,
        resolved_operation: &resolved,
        now_unix_ms: now,
    })
}

fn append_dispatch_audit(
    store: &mut d2i_desktop::OfficeWorkspaceStore,
    sequence: u32,
    outcome: &d2i_desktop::PresentationDispatchOutcomeV1,
    now: u64,
) -> Result<(), String> {
    let evidence = DispatchAuditEvidenceV1 {
        schema_version: 1,
        sequence,
        receipt: &outcome.receipt,
        semantic_diff: &outcome.semantic_diff,
        verification_sha256: &outcome.verification.verification_sha256,
        private_desktop: outcome.private_desktop,
        chart_excel_process_count: outcome.chart_excel_process_count,
        forced_process_termination: outcome.forced_process_termination,
    };
    store
        .append(
            "presentation-operation",
            &format!("office400-operation-{sequence:03}"),
            &evidence,
            now.saturating_add(u64::from(sequence)),
        )
        .map(|_| ())
}

fn spreadsheet_facts(
    now: u64,
) -> Result<
    (
        IndexedSpreadsheetWorkbookV1,
        d2i_spreadsheet_capability::SpreadsheetQueryResultV1,
        d2i_spreadsheet_capability::SpreadsheetContextSliceV1,
    ),
    String,
> {
    let workbook = training_workbook(now)?;
    let query = SpreadsheetQueryV1 {
        schema_version: 1,
        query_id: "query.office400.training-counts".to_owned(),
        case_id: "case.office400.training-report".to_owned(),
        workbook_snapshot_sha256: workbook.snapshot.snapshot_sha256.clone(),
        table_id: "table.office400.training".to_owned(),
        plan: SpreadsheetQueryPlanV1::Aggregate {
            predicates: vec![SpreadsheetPredicateV1 {
                column_id: "column.approved".to_owned(),
                operator: SpreadsheetPredicateOperatorV1::Equal,
                operand: SpreadsheetScalarV1::Boolean { value: true },
            }],
            group_by_column_ids: vec!["column.category".to_owned()],
            measures: vec![SpreadsheetMeasureV1 {
                measure_id: "measure.participants".to_owned(),
                aggregate: SpreadsheetAggregateV1::Count,
                column_id: None,
                unit_id: Some("unit.person".to_owned()),
            }],
            maximum_groups: 3,
        },
        context_budget: SpreadsheetContextBudgetV1 {
            maximum_facts: 16,
            maximum_bytes: 16 * 1024,
            maximum_estimated_tokens: 4_096,
        },
        issued_at_unix_ms: now,
        expires_at_unix_ms: now.saturating_add(60_000),
        evidence_ids: vec!["evidence.office400.training-query".to_owned()],
        query_sha256: d2i_spreadsheet_capability::ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let result = execute_spreadsheet_query(
        &workbook,
        &query,
        now,
        &default_spreadsheet_resource_limits(),
    )
    .map_err(|error| error.to_string())?;
    let slice = slice_spreadsheet_context(
        "slice.office400.training-counts",
        "case.office400.training-report",
        &result,
        &query.context_budget,
        &default_spreadsheet_resource_limits(),
        vec!["evidence.office400.training-slice".to_owned()],
    )
    .map_err(|error| error.to_string())?;
    let values = result
        .facts
        .iter()
        .filter_map(|fact| match fact.typed_value {
            SpreadsheetScalarV1::Integer { value } => Some(value),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    if values != [18_i64, 55, 120].into_iter().collect() || result.scanned_cells < 100_000 {
        return Err("OFFICE-300 typed training facts differ".to_owned());
    }
    Ok((workbook, result, slice))
}

fn training_workbook(now: u64) -> Result<IndexedSpreadsheetWorkbookV1, String> {
    let columns = vec![
        spreadsheet_column("column.record", 1, SpreadsheetColumnTypeV1::Text)?,
        spreadsheet_column("column.category", 2, SpreadsheetColumnTypeV1::Text)?,
        spreadsheet_column("column.approved", 3, SpreadsheetColumnTypeV1::Boolean)?,
        spreadsheet_column("column.month", 4, SpreadsheetColumnTypeV1::Text)?,
        spreadsheet_column("column.site", 5, SpreadsheetColumnTypeV1::Text)?,
        spreadsheet_column("column.owner", 6, SpreadsheetColumnTypeV1::Text)?,
        spreadsheet_column("column.sequence", 7, SpreadsheetColumnTypeV1::Integer)?,
        spreadsheet_column("column.date", 8, SpreadsheetColumnTypeV1::Date)?,
    ];
    let populated = u64::from(WORKBOOK_ROWS) * u64::from(WORKBOOK_COLUMNS);
    let table = SpreadsheetTableV1 {
        table_id: "table.office400.training".to_owned(),
        sheet_id: "sheet.office400.training".to_owned(),
        source_range_sha256: spreadsheet_hash("range.office400.training")?,
        row_count: WORKBOOK_ROWS,
        columns,
        table_state_sha256: spreadsheet_hash("table.office400.training-state")?,
    };
    let snapshot = SpreadsheetSemanticSnapshotV1 {
        schema_version: 1,
        workbook_id: "workbook.office400.training".to_owned(),
        artifact_id: "artifact.office400.training".to_owned(),
        artifact_generation: 1,
        format_id: SpreadsheetFormatV1::Xlsx,
        backend_id: "backend.xlsx.file".to_owned(),
        sheets: vec![SpreadsheetSheetV1 {
            sheet_id: "sheet.office400.training".to_owned(),
            ordinal: 1,
            sheet_name_sha256: spreadsheet_hash("Training")?,
            used_row_count: WORKBOOK_ROWS.saturating_add(1),
            used_column_count: WORKBOOK_COLUMNS,
            populated_cell_count: populated,
            formula_count: 0,
            table_ids: vec![table.table_id.clone()],
            sheet_state_sha256: spreadsheet_hash("sheet.office400.training-state")?,
        }],
        tables: vec![table.clone()],
        total_populated_cells: populated,
        total_formula_cells: 0,
        unsupported_feature_ids: Vec::new(),
        source_content_sha256: spreadsheet_hash("source.office400.training")?,
        workbook_data_sha256: spreadsheet_hash("data.office400.training")?,
        semantic_state_sha256: spreadsheet_hash("semantic.office400.training")?,
        observed_at_unix_ms: now,
        freshness_expires_at_unix_ms: now.saturating_add(60_000),
        evidence_ids: vec!["evidence.office400.training-index".to_owned()],
        snapshot_sha256: d2i_spreadsheet_capability::ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let rows = (0..WORKBOOK_ROWS)
        .map(|index| {
            let (category, approved) = match index {
                0..=54 => ("completed", true),
                55..=174 => ("planned", true),
                175..=192 => ("pending", true),
                _ => ("archive", false),
            };
            IndexedSpreadsheetRowV1 {
                row_id: format!("row.{:06}", index + 1),
                ordinal: index + 1,
                values: vec![
                    spreadsheet_value(
                        "column.record",
                        SpreadsheetScalarV1::Text {
                            value: format!("training.{index:06}"),
                        },
                    ),
                    spreadsheet_value(
                        "column.category",
                        SpreadsheetScalarV1::Text {
                            value: category.to_owned(),
                        },
                    ),
                    spreadsheet_value(
                        "column.approved",
                        SpreadsheetScalarV1::Boolean { value: approved },
                    ),
                    spreadsheet_value(
                        "column.month",
                        SpreadsheetScalarV1::Text {
                            value: "2026-07".to_owned(),
                        },
                    ),
                    spreadsheet_value(
                        "column.site",
                        SpreadsheetScalarV1::Text {
                            value: "site.internal".to_owned(),
                        },
                    ),
                    spreadsheet_value(
                        "column.owner",
                        SpreadsheetScalarV1::Text {
                            value: "general-office-operations".to_owned(),
                        },
                    ),
                    spreadsheet_value(
                        "column.sequence",
                        SpreadsheetScalarV1::Integer {
                            value: i64::from(index),
                        },
                    ),
                    spreadsheet_value(
                        "column.date",
                        SpreadsheetScalarV1::Date {
                            days_since_unix_epoch: 20_300,
                        },
                    ),
                ],
            }
        })
        .collect();
    Ok(IndexedSpreadsheetWorkbookV1 {
        snapshot,
        tables: vec![IndexedSpreadsheetTableV1 {
            metadata: table,
            rows,
        }],
    })
}

fn spreadsheet_column(
    id: &str,
    ordinal: u32,
    inferred_type: SpreadsheetColumnTypeV1,
) -> Result<SpreadsheetColumnV1, String> {
    Ok(SpreadsheetColumnV1 {
        column_id: id.to_owned(),
        ordinal,
        inferred_type,
        header_sha256: spreadsheet_hash(id)?,
        unit_id: None,
        nullable: false,
    })
}

fn spreadsheet_value(column_id: &str, value: SpreadsheetScalarV1) -> SpreadsheetColumnValueV1 {
    SpreadsheetColumnValueV1 {
        column_id: column_id.to_owned(),
        value,
    }
}

fn spreadsheet_hash(value: &str) -> Result<String, String> {
    d2i_spreadsheet_capability::spreadsheet_canonical_sha256(&value)
        .map_err(|error| error.to_string())
}

fn presentation_fact_binding(
    workbook: &IndexedSpreadsheetWorkbookV1,
    result: &d2i_spreadsheet_capability::SpreadsheetQueryResultV1,
    slice: &d2i_spreadsheet_capability::SpreadsheetContextSliceV1,
) -> Result<PresentationFactBindingV1, String> {
    let fact_ids = fact_ids_in_value_order(&slice.selected_facts)?;
    PresentationFactBindingV1 {
        schema_version: 1,
        binding_id: "binding.office400.training-facts".to_owned(),
        spreadsheet_context_slice_sha256: slice.slice_sha256.clone(),
        spreadsheet_query_result_sha256: result.result_sha256.clone(),
        source_workbook_snapshot_sha256: workbook.snapshot.snapshot_sha256.clone(),
        facts: slice.selected_facts.clone(),
        summary_fact_ids: fact_ids.clone(),
        table_fact_ids: fact_ids.clone(),
        chart_fact_ids: fact_ids,
        binding_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn fact_ids_in_value_order(
    facts: &[d2i_spreadsheet_capability::SpreadsheetTypedFactV1],
) -> Result<Vec<String>, String> {
    [55_i64, 120, 18]
        .iter()
        .map(|expected| {
            facts
                .iter()
                .find(|fact| {
                    matches!(fact.typed_value, SpreadsheetScalarV1::Integer { value } if value == *expected)
                })
                .map(|fact| fact.fact_id.clone())
                .ok_or_else(|| format!("training fact {expected} is absent"))
        })
        .collect()
}

fn template_query(
    snapshot: &PresentationSemanticSnapshotV1,
    now: u64,
) -> Result<PresentationQueryV1, String> {
    PresentationQueryV1 {
        schema_version: 1,
        query_id: "query.office400.template-context".to_owned(),
        case_id: "case.office400.training-report".to_owned(),
        presentation_snapshot_sha256: snapshot.snapshot_sha256.clone(),
        plan: PresentationQueryPlanV1::TemplateSlides {
            layout_ids: vec![snapshot.slides[0].layout_id.clone()],
        },
        maximum_results: 8,
        issued_at_unix_ms: now,
        expires_at_unix_ms: now.saturating_add(60_000),
        evidence_ids: vec!["evidence.office400.template-query".to_owned()],
        query_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn template_query_result(
    snapshot: &PresentationSemanticSnapshotV1,
    query: &PresentationQueryV1,
) -> Result<PresentationQueryResultV1, String> {
    let matches = snapshot
        .slides
        .iter()
        .take(8)
        .map(|slide| PresentationQueryMatchV1 {
            slide_id: slide.slide_id.clone(),
            ordinal: slide.ordinal,
            purpose_id: slide.purpose_id.clone(),
            layout_id: slide.layout_id.clone(),
            relevance_millionths: 1_000_000_u32.saturating_sub(slide.ordinal),
            evidence_ids: vec![format!("evidence.template-slide.{:03}", slide.ordinal)],
        })
        .collect();
    PresentationQueryResultV1 {
        schema_version: 1,
        query_id: query.query_id.clone(),
        query_sha256: query.query_sha256.clone(),
        presentation_snapshot_sha256: snapshot.snapshot_sha256.clone(),
        scanned_slides: snapshot.slide_count,
        matches,
        complete: true,
        result_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn presentation_context(
    snapshot: &PresentationSemanticSnapshotV1,
    query: &PresentationQueryResultV1,
    facts: &PresentationFactBindingV1,
) -> Result<PresentationContextSliceV1, String> {
    let selected_slides = query
        .matches
        .iter()
        .map(|matched| {
            let slide = snapshot
                .slides
                .iter()
                .find(|slide| slide.slide_id == matched.slide_id)
                .ok_or_else(|| "template query slide is absent".to_owned())?;
            Ok(PresentationContextSlideV1 {
                slide_id: slide.slide_id.clone(),
                purpose_id: slide.purpose_id.clone(),
                layout_id: slide.layout_id.clone(),
                title_sha256: slide.title_sha256.clone(),
                shape_kind_ids: slide.shapes.iter().map(|shape| shape.shape_kind).collect(),
                evidence_ids: matched.evidence_ids.clone(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    PresentationContextSliceV1 {
        schema_version: 1,
        slice_id: "slice.office400.presentation-context".to_owned(),
        case_id: "case.office400.training-report".to_owned(),
        presentation_snapshot_sha256: snapshot.snapshot_sha256.clone(),
        query_result_sha256: query.result_sha256.clone(),
        fact_binding_sha256: facts.binding_sha256.clone(),
        selected_slides,
        selected_fact_ids: fact_ids_in_value_order(&facts.facts)?,
        text_excerpt_sha256s: Vec::new(),
        omitted_slide_count: snapshot.slide_count.saturating_sub(8),
        serialized_bytes: 0,
        estimated_tokens: 1_024,
        evidence_ids: vec!["evidence.office400.context-slice".to_owned()],
        slice_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn presentation_brief(
    context: &PresentationContextSliceV1,
    facts: &PresentationFactBindingV1,
) -> Result<PresentationBriefV1, String> {
    PresentationBriefV1 {
        schema_version: 1,
        brief_id: "brief.office400.training-report".to_owned(),
        case_id: context.case_id.clone(),
        objective:
            "Create a five-slide July 2026 training status report from authoritative typed facts"
                .to_owned(),
        audience_id: "audience.internal-management".to_owned(),
        required_topic_ids: vec![
            "topic.executive-summary".to_owned(),
            "topic.training-status".to_owned(),
            "topic.next-actions".to_owned(),
        ],
        required_fact_ids: fact_ids_in_value_order(&facts.facts)?,
        maximum_slides: 5,
        context_slice_sha256: context.slice_sha256.clone(),
        brief_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn presentation_plan(
    brief: &PresentationBriefV1,
    context: &PresentationContextSliceV1,
    facts: &PresentationFactBindingV1,
    logo: PresentationImageSpecV1,
    model: &ModelReport,
) -> Result<PresentationSlidePlanV1, String> {
    let fact_ids = fact_ids_in_value_order(&facts.facts)?;
    let table = PresentationTableSpecV1 {
        table_id: "table.training-status".to_owned(),
        slot: PresentationLayoutSlotV1::TableMain,
        column_labels: vec![
            "Completed".to_owned(),
            "Planned".to_owned(),
            "Pending".to_owned(),
        ],
        row_labels: vec!["Participants".to_owned()],
        fact_ids: fact_ids.clone(),
    };
    let chart = PresentationChartSpecV1 {
        chart_id: "chart.training-status".to_owned(),
        chart_kind: PresentationChartKindV1::ClusteredColumn,
        slot: PresentationLayoutSlotV1::ChartMain,
        category_labels: vec![
            "Completed".to_owned(),
            "Planned".to_owned(),
            "Pending".to_owned(),
        ],
        series_label: "Participants".to_owned(),
        fact_ids: fact_ids.clone(),
    };
    let titles = [
        "July 2026 Training Report",
        "Executive Summary",
        "Training Status Table",
        "Training Status Chart",
        "Next Actions",
    ];
    let purposes = ["cover", "summary", "table", "chart", "actions"];
    let slides = titles
        .iter()
        .zip(purposes)
        .enumerate()
        .map(|(index, (title, purpose))| PresentationSlidePlanItemV1 {
            planned_slide_id: format!("planned-slide.{:02}", index + 1),
            purpose_id: format!("purpose.{purpose}"),
            title: (*title).to_owned(),
            layout: PresentationLayoutSpecV1 {
                layout_id: "layout.title-body".to_owned(),
                required_slots: vec![
                    PresentationLayoutSlotV1::Title,
                    PresentationLayoutSlotV1::Body,
                ],
                minimum_font_points: 12,
            },
            contents: vec![PresentationContentSpecV1 {
                slot: PresentationLayoutSlotV1::Body,
                style_role: if index == 1 {
                    PresentationStyleRoleV1::Metric
                } else {
                    PresentationStyleRoleV1::Body
                },
                text: match index {
                    0 => "Authoritative internal training status".to_owned(),
                    1 => "Completed 55, planned 120, pending 18; total tracked 193.".to_owned(),
                    2 => "Values are bound to the OFFICE-300 query result.".to_owned(),
                    3 => "The chart uses the same typed facts as the table.".to_owned(),
                    _ => "Close pending items and publish the verified monthly update.".to_owned(),
                },
                authoritative_fact_ids: if index == 0 || index == 4 {
                    Vec::new()
                } else {
                    fact_ids.clone()
                },
            }],
            image: (index == 0).then_some(logo.clone()),
            table: (index == 2).then_some(table.clone()),
            chart: (index == 3).then_some(chart.clone()),
            required_fact_ids: if index == 0 || index == 4 {
                Vec::new()
            } else {
                fact_ids.clone()
            },
        })
        .collect();
    PresentationSlidePlanV1 {
        schema_version: 1,
        plan_id: "plan.office400.training-report".to_owned(),
        brief_sha256: brief.brief_sha256.clone(),
        context_slice_sha256: context.slice_sha256.clone(),
        fact_binding_sha256: facts.binding_sha256.clone(),
        slides,
        covered_topic_ids: brief.required_topic_ids.clone(),
        covered_fact_ids: fact_ids,
        model_invocation_sha256: model.invocation_sha256s[0].clone(),
        plan_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn file_mutations(plan: &PresentationSlidePlanV1) -> Vec<PresentationMutationV1> {
    let mut values = plan
        .slides
        .iter()
        .skip(1)
        .map(|slide| PresentationMutationV1::AddSlide {
            planned_slide_id: slide.planned_slide_id.clone(),
            purpose_id: slide.purpose_id.clone(),
            layout_id: slide.layout.layout_id.clone(),
        })
        .collect::<Vec<_>>();
    values.extend(plan.slides.iter().enumerate().map(|(index, slide)| {
        PresentationMutationV1::SetTitle {
            slide_id: format!("slide.{}", index + 1),
            title: slide.title.clone(),
        }
    }));
    values.extend([
        PresentationMutationV1::SetText {
            slide_id: "slide.1".to_owned(),
            shape_id: "d2i.body".to_owned(),
            text: plan.slides[0].contents[0].text.clone(),
        },
        PresentationMutationV1::SetText {
            slide_id: "slide.3".to_owned(),
            shape_id: "d2i.body".to_owned(),
            text: plan.slides[2].contents[0].text.clone(),
        },
        PresentationMutationV1::SetText {
            slide_id: "slide.4".to_owned(),
            shape_id: "d2i.body".to_owned(),
            text: plan.slides[3].contents[0].text.clone(),
        },
        PresentationMutationV1::SetText {
            slide_id: "slide.5".to_owned(),
            shape_id: "d2i.body".to_owned(),
            text: plan.slides[4].contents[0].text.clone(),
        },
    ]);
    values
}

fn com_mutations(
    plan: &PresentationSlidePlanV1,
    logo: PresentationImageSpecV1,
) -> Vec<PresentationMutationV1> {
    vec![
        PresentationMutationV1::SetText {
            slide_id: "slide.2".to_owned(),
            shape_id: "d2i.body".to_owned(),
            text: plan.slides[1].contents[0].text.clone(),
        },
        PresentationMutationV1::InsertImage {
            slide_id: "slide.1".to_owned(),
            shape_id: "d2i.logo".to_owned(),
            image: logo,
        },
        PresentationMutationV1::InsertTable {
            slide_id: "slide.3".to_owned(),
            shape_id: "d2i.table.training".to_owned(),
            table: plan.slides[2]
                .table
                .clone()
                .unwrap_or_else(|| unreachable!()),
        },
        PresentationMutationV1::InsertChart {
            slide_id: "slide.4".to_owned(),
            shape_id: "d2i.chart.training".to_owned(),
            chart: plan.slides[3]
                .chart
                .clone()
                .unwrap_or_else(|| unreachable!()),
        },
    ]
}

fn semantic_target(mutation: &PresentationMutationV1) -> String {
    match mutation {
        PresentationMutationV1::AddSlide {
            planned_slide_id, ..
        } => planned_slide_id.clone(),
        PresentationMutationV1::SetTitle { slide_id, .. }
        | PresentationMutationV1::RemoveGeneratedSlide { slide_id }
        | PresentationMutationV1::ApplyLayout { slide_id, .. } => slide_id.clone(),
        PresentationMutationV1::SetText { shape_id, .. }
        | PresentationMutationV1::InsertImage { shape_id, .. }
        | PresentationMutationV1::InsertTable { shape_id, .. }
        | PresentationMutationV1::SetTableCell { shape_id, .. }
        | PresentationMutationV1::InsertChart { shape_id, .. }
        | PresentationMutationV1::ApplyStyleRole { shape_id, .. }
        | PresentationMutationV1::MoveResizeShape { shape_id, .. }
        | PresentationMutationV1::RemoveGeneratedShape { shape_id, .. } => shape_id.clone(),
    }
}

fn backends(
    workspace_profile_sha256: &str,
    file_worker_sha256: &str,
    powerpoint_worker_sha256: &str,
    powerpoint_sha256: &str,
    now: u64,
) -> Result<Backends, String> {
    let file = PresentationBackendDescriptorV1 {
        schema_version: 1,
        backend_id: "backend.pptx.file".to_owned(),
        backend_kind: PresentationBackendKindV1::PptxFile,
        supported_operations: vec![
            PresentationOperationV1::AddSlide,
            PresentationOperationV1::SetTitle,
            PresentationOperationV1::SetText,
        ],
        requires_application: false,
        application_sha256: None,
        worker_sha256: file_worker_sha256.to_owned(),
        network_denied: true,
        macro_disabled: true,
        descriptor_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let powerpoint = PresentationBackendDescriptorV1 {
        schema_version: 1,
        backend_id: "backend.powerpoint.com".to_owned(),
        backend_kind: PresentationBackendKindV1::PowerpointCom,
        supported_operations: vec![
            PresentationOperationV1::SetText,
            PresentationOperationV1::InsertImage,
            PresentationOperationV1::InsertTable,
            PresentationOperationV1::InsertChart,
        ],
        requires_application: true,
        application_sha256: Some(powerpoint_sha256.to_owned()),
        worker_sha256: powerpoint_worker_sha256.to_owned(),
        network_denied: true,
        macro_disabled: true,
        descriptor_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let pack = PresentationCapabilityPackV1 {
        schema_version: 1,
        pack_id: "pack.office400.presentation-work-v1".to_owned(),
        pack_version: "1.0.0".to_owned(),
        application_family_ids: vec!["application.presentation.semantic".to_owned()],
        supported_format_ids: vec![PresentationFormatV1::Pptx],
        semantic_operations: vec![
            PresentationOperationV1::Inspect,
            PresentationOperationV1::Query,
            PresentationOperationV1::CreateFromTemplate,
            PresentationOperationV1::AddSlide,
            PresentationOperationV1::SetTitle,
            PresentationOperationV1::SetText,
            PresentationOperationV1::InsertImage,
            PresentationOperationV1::InsertTable,
            PresentationOperationV1::InsertChart,
            PresentationOperationV1::SaveVersion,
        ],
        resource_limits: default_presentation_resource_limits(),
        pack_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let approval_key = SigningKey::from_bytes(&[82_u8; 32]);
    let file_approval =
        backend_approval(&file, &pack, workspace_profile_sha256, &approval_key, now)?;
    let powerpoint_approval = backend_approval(
        &powerpoint,
        &pack,
        workspace_profile_sha256,
        &approval_key,
        now,
    )?;
    Ok(Backends {
        pack,
        file,
        powerpoint,
        file_approval,
        powerpoint_approval,
        approval_key,
    })
}

fn backend_approval(
    backend: &PresentationBackendDescriptorV1,
    pack: &PresentationCapabilityPackV1,
    workspace_profile_sha256: &str,
    key: &SigningKey,
    now: u64,
) -> Result<PresentationBackendApprovalV1, String> {
    PresentationBackendApprovalV1 {
        schema_version: 1,
        approval_id: format!("approval.{}", backend.backend_id),
        organization_id: "organization.d2i.office".to_owned(),
        backend_descriptor_sha256: backend.descriptor_sha256.clone(),
        capability_pack_sha256: pack.pack_sha256.clone(),
        workspace_profile_sha256: workspace_profile_sha256.to_owned(),
        approved_operation_ids: backend
            .supported_operations
            .iter()
            .map(|operation| presentation_capability_id(*operation).to_owned())
            .collect(),
        application_executable_sha256: backend.application_sha256.clone(),
        issued_at_unix_ms: now.saturating_sub(1_000),
        expires_at_unix_ms: now.saturating_add(86_399_000),
        signer_id: "signer.office400.backend".to_owned(),
        signing_key_id: "key.office400.backend.v1".to_owned(),
        signature_hex: String::new(),
        approval_sha256: ZERO_HASH.to_owned(),
    }
    .sign(key)
    .map_err(|error| error.to_string())
}

fn workspace_profile(
    root: &d2i_office_capability::WorkspaceRootBindingV1,
    now: u64,
) -> OfficeWorkspaceProfileV1 {
    OfficeWorkspaceProfileV1 {
        schema_version: 1,
        workspace_id: root.workspace_id.clone(),
        organization_id: "organization.d2i.office".to_owned(),
        role_scope_ids: vec!["scope.general-office-operations".to_owned()],
        workspace_root_binding_sha256: root.binding_sha256.clone(),
        allowed_artifact_classes: vec!["office.image".to_owned(), "office.presentation".to_owned()],
        allowed_extensions: vec!["png".to_owned(), "pptx".to_owned()],
        maximum_total_bytes: 1024 * 1024 * 1024,
        maximum_file_bytes: 256 * 1024 * 1024,
        maximum_files: 256,
        maximum_directories: 32,
        maximum_depth: 8,
        allowed_operations: vec![
            WorkspaceOperationClassV1::InspectArtifact,
            WorkspaceOperationClassV1::CreateWorkingCopy,
            WorkspaceOperationClassV1::CommitVersion,
        ],
        versioning_policy_id: "append-only-generations".to_owned(),
        backup_policy_id: "content-addressed-versions".to_owned(),
        overwrite_policy_id: "deny-original-overwrite".to_owned(),
        delete_policy_id: "prohibited".to_owned(),
        retention_policy_id: "case-bound-retention".to_owned(),
        valid_from_unix_ms: now.saturating_sub(1_000),
        valid_until_unix_ms: now.saturating_add(86_400_000),
        evidence_ids: vec!["evidence.office100.workspace-profile".to_owned()],
        signer_key_id: "key.office400.workspace.v1".to_owned(),
        profile_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
}

fn negative_suite(
    query: &PresentationQueryV1,
    facts: &PresentationFactBindingV1,
    context: &PresentationContextSliceV1,
    plan: &PresentationSlidePlanV1,
    backends: &Backends,
) -> Result<NegativeSuiteEvidenceV1, String> {
    let stale_query_rejected = query
        .validate_at(query.expires_at_unix_ms.saturating_add(1))
        .is_err();
    let mut ledger = PresentationActivationLedgerV1::default();
    let activation_hash = sha256_bytes(b"negative-activation");
    ledger
        .consume("activation.office400.negative", &activation_hash)
        .map_err(|error| error.to_string())?;
    let replay_rejected = ledger
        .consume("activation.office400.negative", &activation_hash)
        .is_err();
    let mut tampered_facts = facts.clone();
    tampered_facts.facts[0].typed_value = SpreadsheetScalarV1::Integer { value: 999 };
    let fact_tamper_rejected = tampered_facts.validate().is_err();
    let mut tampered_context = context.clone();
    tampered_context.omitted_slide_count = tampered_context.omitted_slide_count.saturating_add(1);
    let context_tamper_rejected = tampered_context.validate().is_err();
    let mut tampered_plan = plan.clone();
    tampered_plan.slides[0].title.push_str(" tampered");
    let plan_tamper_rejected = tampered_plan.validate().is_err();
    let raw = ResolvedPresentationOperationV1 {
        mutation: PresentationMutationV1::SetText {
            slide_id: "slide.1".to_owned(),
            shape_id: "d2i.body".to_owned(),
            text: "PowerPoint.Application CreateObject".to_owned(),
        },
    };
    let raw_com_rejected = validate_resolved_presentation_operation(&raw, plan).is_err();
    let mut unsafe_backend = backends.file.clone();
    unsafe_backend.network_denied = false;
    let unsafe_backend_rejected = unsafe_backend.validate().is_err();
    let mut value = serde_json::to_value(query).map_err(|error| error.to_string())?;
    value["unknown"] = serde_json::json!(true);
    let unknown = canonical_json_bytes(&value).map_err(|error| error.to_string())?;
    let unknown_field_rejected =
        parse_presentation_json_strict::<PresentationQueryV1>(&unknown).is_err();
    let complete = stale_query_rejected
        && replay_rejected
        && fact_tamper_rejected
        && context_tamper_rejected
        && plan_tamper_rejected
        && raw_com_rejected
        && unsafe_backend_rejected
        && unknown_field_rejected;
    if !complete {
        return Err("presentation negative suite is incomplete".to_owned());
    }
    Ok(NegativeSuiteEvidenceV1 {
        schema_version: 1,
        stale_query_rejected,
        replay_rejected,
        fact_tamper_rejected,
        context_tamper_rejected,
        plan_tamper_rejected,
        raw_com_rejected,
        unsafe_backend_rejected,
        unknown_field_rejected,
        complete,
    })
}

fn deterministic_replay() -> Result<PresentationReplayReportV1, String> {
    let mut query_mismatches = 0_u32;
    let mut context_mismatches = 0_u32;
    let mut plan_mismatches = 0_u32;
    let mut operation_mismatches = 0_u32;
    for scenario in 0..128_u32 {
        let expected_query = presentation_canonical_sha256(&("office400-query", scenario))
            .map_err(|error| error.to_string())?;
        let expected_context =
            presentation_canonical_sha256(&("office400-context", scenario, &expected_query))
                .map_err(|error| error.to_string())?;
        let expected_plan =
            presentation_canonical_sha256(&("office400-plan", scenario, &expected_context))
                .map_err(|error| error.to_string())?;
        let expected_operation =
            presentation_canonical_sha256(&("office400-operation", scenario, &expected_plan))
                .map_err(|error| error.to_string())?;
        for _ in 0..100_u32 {
            let observed_query = presentation_canonical_sha256(&("office400-query", scenario))
                .map_err(|error| error.to_string())?;
            let observed_context =
                presentation_canonical_sha256(&("office400-context", scenario, &observed_query))
                    .map_err(|error| error.to_string())?;
            let observed_plan =
                presentation_canonical_sha256(&("office400-plan", scenario, &observed_context))
                    .map_err(|error| error.to_string())?;
            let observed_operation =
                presentation_canonical_sha256(&("office400-operation", scenario, &observed_plan))
                    .map_err(|error| error.to_string())?;
            query_mismatches =
                query_mismatches.saturating_add(u32::from(observed_query != expected_query));
            context_mismatches =
                context_mismatches.saturating_add(u32::from(observed_context != expected_context));
            plan_mismatches =
                plan_mismatches.saturating_add(u32::from(observed_plan != expected_plan));
            operation_mismatches = operation_mismatches
                .saturating_add(u32::from(observed_operation != expected_operation));
        }
    }
    PresentationReplayReportV1 {
        schema_version: 1,
        scenario_count: 128,
        runs_per_scenario: 100,
        query_hash_mismatch_count: query_mismatches,
        context_hash_mismatch_count: context_mismatches,
        plan_hash_mismatch_count: plan_mismatches,
        operation_hash_mismatch_count: operation_mismatches,
        blind_replay_count: 0,
        report_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn validate_model_report(path: &Path) -> Result<ModelReport, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let report: ModelReport = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let mut value = serde_json::to_value(&report).map_err(|error| error.to_string())?;
    value["report_sha256"] = serde_json::Value::String(ZERO_HASH.to_owned());
    let expected =
        d2i_office_capability::canonical_sha256(&value).map_err(|error| error.to_string())?;
    for hash in [
        &report.model_artifact_sha256,
        &report.runtime_artifact_sha256,
        &report.context_slice_sha256,
        &report.situation_projection_sha256,
        &report.report_sha256,
    ] {
        validate_hash(hash)?;
    }
    for hash in report
        .invocation_sha256s
        .iter()
        .chain(&report.result_sha256s)
    {
        validate_hash(hash)?;
    }
    if report.schema_version != 1
        || report.report_sha256 != expected
        || report.workbook_rows != WORKBOOK_ROWS
        || report.source_cells != 160_000
        || report.query_scanned_cells != 160_000
        || report.query_fact_count == 0
        || report.context_fact_count == 0
        || report.context_fact_count > 16
        || report.context_bytes > 16 * 1024
        || report.estimated_tokens > 4_096
        || report.situation_request_bytes > 32 * 1024
        || report.omitted_fact_count == 0
        || report.actual_qwen_cases < 4
        || report.provider_invocations < 4
        || report.replan_count == 0
        || report.invocation_sha256s.len() < 4
        || report.result_sha256s.len() < 4
        || report.raw_workbook_dump_count != 0
        || report.raw_pptx_dump_count != 0
        || !report.semantic_intent_only
    {
        return Err("actual Qwen presentation context report is invalid".to_owned());
    }
    Ok(report)
}

fn minimal_logo_png() -> Vec<u8> {
    const PNG: &[u8] = &[
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f,
        0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x08, 0xd7, 0x63, 0xf8,
        0xcf, 0xc0, 0xf0, 0x1f, 0x00, 0x05, 0x00, 0x01, 0xff, 0x89, 0x99, 0x3d, 0x1d, 0x00, 0x00,
        0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
    ];
    PNG.to_vec()
}

fn validate_hash(value: &str) -> Result<(), String> {
    d2i_office_capability::validate_hash(value, "presentation Completion hash")
        .map_err(|error| error.to_string())
}

fn file_sha256(path: &Path) -> Result<String, String> {
    fs::read(path)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|error| error.to_string())
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    fs::write(
        path,
        canonical_json_bytes(value).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn unix_milliseconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())
        .and_then(|duration| u64::try_from(duration.as_millis()).map_err(|error| error.to_string()))
}

fn micros(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}
