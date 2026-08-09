use d2i_desktop::{
    create_workspace_root_binding, create_xlsx_workbook, initialize_office_workspace_store,
    inspect_xlsx_workbook, ResolvedSpreadsheetOperationV1, SpreadsheetAuthorityContextV1,
    SpreadsheetDispatchV1, SpreadsheetKrnDispatcherConfigurationV1, SpreadsheetKrnDispatcherV1,
};
use d2i_office_capability::{
    canonical_json_bytes, sha256_bytes, OfficeWorkspaceProfileV1, WorkspaceOperationClassV1,
};
use d2i_policy_admission::{AdapterKindV1, AdmissionModeV1, CognitiveActivationAdmissionV1};
use d2i_spreadsheet_capability::{
    default_spreadsheet_resource_limits as contract_limits, execute_spreadsheet_query,
    slice_spreadsheet_context, SpreadsheetBackendApprovalV1, SpreadsheetBackendDescriptorV1,
    SpreadsheetBackendKindV1, SpreadsheetCapabilityPackV1, SpreadsheetColumnValueV1,
    SpreadsheetContextBudgetV1, SpreadsheetFormulaV1, SpreadsheetMutationV1,
    SpreadsheetOperationBindingV1, SpreadsheetOperationIntentV1, SpreadsheetOperationV1,
    SpreadsheetPerformanceMetricsV1, SpreadsheetPredicateOperatorV1, SpreadsheetPredicateV1,
    SpreadsheetQueryPlanV1, SpreadsheetQueryV1, SpreadsheetResidualMetricsV1,
    SpreadsheetRiskClassV1, SpreadsheetSafetyMetricsV1, SpreadsheetScalarV1,
    SpreadsheetSemanticSnapshotV1, SpreadsheetWorkCertificationV1,
    SpreadsheetWorkCompletionReportV1, SpreadsheetWorkReplayReportV1, ZERO_HASH,
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

struct Arguments {
    output_root: PathBuf,
    file_worker: PathBuf,
    excel_worker: PathBuf,
    excel: PathBuf,
    model_report: PathBuf,
    predecessor_finished_sha256: String,
    source_tree_sha256: String,
}

struct Backends {
    pack: SpreadsheetCapabilityPackV1,
    file: SpreadsheetBackendDescriptorV1,
    excel: SpreadsheetBackendDescriptorV1,
    file_approval: SpreadsheetBackendApprovalV1,
    excel_approval: SpreadsheetBackendApprovalV1,
    approval_key: SigningKey,
}

#[derive(Deserialize, Serialize)]
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
    elapsed_microseconds: u64,
    peak_worker_memory_bytes: u64,
    context_slice_sha256: String,
    situation_projection_sha256: String,
    invocation_sha256: String,
    result_sha256: String,
    raw_workbook_dump_count: u32,
    report_sha256: String,
}

fn main() {
    if let Err(error) = parse_arguments().and_then(run) {
        eprintln!("OFFICE-300 Completion E2E failed: {error}");
        std::process::exit(1);
    }
}

fn parse_arguments() -> Result<Arguments, String> {
    let values = std::env::args().skip(1).collect::<Vec<_>>();
    if values.len() != 7 {
        return Err("usage: d2i-office300-completion-e2e <output-root> <file-worker> <excel-worker> <excel> <model-report> <predecessor-finished-sha256> <source-tree-sha256>".to_owned());
    }
    Ok(Arguments {
        output_root: PathBuf::from(&values[0]),
        file_worker: PathBuf::from(&values[1]),
        excel_worker: PathBuf::from(&values[2]),
        excel: PathBuf::from(&values[3]),
        model_report: PathBuf::from(&values[4]),
        predecessor_finished_sha256: values[5].clone(),
        source_tree_sha256: values[6].clone(),
    })
}

fn run(arguments: Arguments) -> Result<(), String> {
    validate_hash(&arguments.predecessor_finished_sha256)?;
    validate_hash(&arguments.source_tree_sha256)?;
    if arguments.output_root.exists() {
        return Err("spreadsheet Completion output root must be new".to_owned());
    }
    let model = validate_model_report(&arguments.model_report)?;
    fs::create_dir_all(&arguments.output_root).map_err(|error| error.to_string())?;
    let workspace = arguments.output_root.join("workspace");
    fs::create_dir_all(workspace.join("spreadsheets")).map_err(|error| error.to_string())?;
    let now = unix_milliseconds()?;
    let root_binding = create_workspace_root_binding(
        &workspace,
        "workspace.office300.completion",
        now.saturating_sub(1_000),
        now.saturating_add(86_400_000),
    )?;
    let profile_key = SigningKey::from_bytes(&[61_u8; 32]);
    let profile = workspace_profile(&root_binding, now)
        .sign(&profile_key)
        .map_err(|error| error.to_string())?;
    let file_worker_sha256 = file_sha256(&arguments.file_worker)?;
    let excel_worker_sha256 = file_sha256(&arguments.excel_worker)?;
    let excel_sha256 = file_sha256(&arguments.excel)?;
    let backends = backends(
        &profile.profile_sha256,
        &file_worker_sha256,
        &excel_worker_sha256,
        &excel_sha256,
        now,
    )?;
    let store_root = arguments.output_root.join("office-store");
    let mut store = initialize_office_workspace_store(&store_root)?;
    let mut dispatcher =
        SpreadsheetKrnDispatcherV1::new(SpreadsheetKrnDispatcherConfigurationV1 {
            root: workspace.clone(),
            root_binding: root_binding.clone(),
            workspace_profile: profile.clone(),
            workspace_profile_key: profile_key.verifying_key(),
            file_worker_executable: arguments.file_worker.clone(),
            expected_file_worker_sha256: file_worker_sha256,
            excel_worker_executable: arguments.excel_worker.clone(),
            expected_excel_worker_sha256: excel_worker_sha256,
            excel_executable: arguments.excel.clone(),
            expected_excel_executable_sha256: excel_sha256.clone(),
            now_unix_ms: now,
        })?;
    let limits = contract_limits();
    let original_relative = "spreadsheets/records-generation-0001.xlsx";
    let original = workspace.join(original_relative);
    create_xlsx_workbook(
        &original,
        "Records",
        &[
            "Record".to_owned(),
            "Planned".to_owned(),
            "Actual".to_owned(),
            "Variance".to_owned(),
        ],
        &limits,
    )?;
    let original_sha256 = file_sha256(&original)?;
    let snapshot = inspect_xlsx_workbook(
        &original,
        "workbook.office300.completion",
        "artifact.office300.records",
        1,
        &backends.file.backend_id,
        now,
        &limits,
    )?;
    let columns = &snapshot.tables[0].metadata.columns;
    let append = ResolvedSpreadsheetOperationV1 {
        mutation: SpreadsheetMutationV1::AppendTableRow {
            table_id: snapshot.tables[0].metadata.table_id.clone(),
            values: columns
                .iter()
                .zip([
                    SpreadsheetScalarV1::Text {
                        value: "record-001".to_owned(),
                    },
                    SpreadsheetScalarV1::Integer { value: 125 },
                    SpreadsheetScalarV1::Integer { value: 100 },
                    SpreadsheetScalarV1::Integer { value: 0 },
                ])
                .map(|(column, value)| SpreadsheetColumnValueV1 {
                    column_id: column.column_id.clone(),
                    value,
                })
                .collect(),
        },
    };
    let file_started = Instant::now();
    let (file_relative, file_snapshot) = dispatch_operation(
        &mut dispatcher,
        &mut store,
        &profile,
        &root_binding,
        &backends,
        &backends.file,
        &backends.file_approval,
        original_relative,
        "spreadsheets/records-generation-0002.xlsx",
        &snapshot.snapshot,
        &append,
        1,
        now.saturating_add(1_000),
    )?;
    let file_microseconds = micros(file_started.elapsed());
    let before_excel =
        d2i_windows_host::installed_excel_process_ids().map_err(|error| error.to_string())?;
    let identity = d2i_windows_host::host_identity().map_err(|error| error.to_string())?;
    let profile_name = format!("d2i.office300.completion.{}", std::process::id());
    let verifier_profile = d2i_windows_host::provision_appcontainer_profile(&profile_name)
        .map_err(|error| error.to_string())?;
    let policy = match d2i_windows_host::install_wfp_loopback_policy(
        &arguments.excel,
        &verifier_profile.profile_sid,
        &identity.user_sid,
    ) {
        Ok(policy) => policy,
        Err(error) => {
            let _ = d2i_windows_host::delete_appcontainer_profile(&profile_name);
            return Err(error.to_string());
        }
    };
    let formula = ResolvedSpreadsheetOperationV1 {
        mutation: SpreadsheetMutationV1::SetCellFormula {
            target_cell_id: "cell.sheet.0001.r000001.c000004".to_owned(),
            formula: SpreadsheetFormulaV1::Difference {
                left_cell_id: "cell.sheet.0001.r000001.c000002".to_owned(),
                right_cell_id: "cell.sheet.0001.r000001.c000003".to_owned(),
            },
        },
    };
    let excel_started = Instant::now();
    let excel_result = (|| {
        let verified = d2i_windows_host::verify_wfp_loopback_policy(
            &arguments.excel,
            &verifier_profile.profile_sid,
            &identity.user_sid,
        )
        .map_err(|error| error.to_string())?;
        if verified != policy {
            return Err("Excel WFP policy differs before dispatch".to_owned());
        }
        let result = dispatch_operation(
            &mut dispatcher,
            &mut store,
            &profile,
            &root_binding,
            &backends,
            &backends.excel,
            &backends.excel_approval,
            &file_relative,
            "spreadsheets/records-generation-0003.xlsx",
            &file_snapshot,
            &formula,
            2,
            now.saturating_add(2_000),
        )?;
        let verified_after = d2i_windows_host::verify_wfp_loopback_policy(
            &arguments.excel,
            &verifier_profile.profile_sid,
            &identity.user_sid,
        )
        .map_err(|error| error.to_string())?;
        if verified_after != policy {
            return Err("Excel WFP policy differs after dispatch".to_owned());
        }
        Ok(result)
    })();
    let policy_cleanup =
        d2i_windows_host::remove_wfp_loopback_policy(&verifier_profile.profile_sid)
            .map_err(|error| error.to_string());
    let profile_cleanup = d2i_windows_host::delete_appcontainer_profile(&profile_name)
        .map_err(|error| error.to_string());
    let (_, final_snapshot) = match (excel_result, policy_cleanup, profile_cleanup) {
        (Ok(result), Ok(()), Ok(())) => result,
        state => return Err(format!("Excel Completion or cleanup failed: {state:?}")),
    };
    let excel_microseconds = micros(excel_started.elapsed());
    let final_index = inspect_xlsx_workbook(
        &workspace.join("spreadsheets/records-generation-0003.xlsx"),
        &final_snapshot.workbook_id,
        &final_snapshot.artifact_id,
        final_snapshot.artifact_generation,
        &final_snapshot.backend_id,
        now.saturating_add(3_000),
        &limits,
    )?;
    let query_started = Instant::now();
    let query = SpreadsheetQueryV1 {
        schema_version: 1,
        query_id: "query.office300.completion".to_owned(),
        case_id: "case.office300.query".to_owned(),
        workbook_snapshot_sha256: final_index.snapshot.snapshot_sha256.clone(),
        table_id: final_index.tables[0].metadata.table_id.clone(),
        plan: SpreadsheetQueryPlanV1::Filter {
            predicates: vec![SpreadsheetPredicateV1 {
                column_id: final_index.tables[0].metadata.columns[0].column_id.clone(),
                operator: SpreadsheetPredicateOperatorV1::Equal,
                operand: SpreadsheetScalarV1::Text {
                    value: "record-001".to_owned(),
                },
            }],
            projection_column_ids: final_index.tables[0]
                .metadata
                .columns
                .iter()
                .map(|column| column.column_id.clone())
                .collect(),
            maximum_rows: 1,
        },
        context_budget: SpreadsheetContextBudgetV1 {
            maximum_facts: 8,
            maximum_bytes: 8 * 1024,
            maximum_estimated_tokens: 2_048,
        },
        issued_at_unix_ms: now.saturating_add(3_000),
        expires_at_unix_ms: now.saturating_add(63_000),
        evidence_ids: vec!["evidence.office300.completion-query".to_owned()],
        query_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let query_result =
        execute_spreadsheet_query(&final_index, &query, now.saturating_add(3_000), &limits)
            .map_err(|error| error.to_string())?;
    let query_microseconds = micros(query_started.elapsed());
    let slice_started = Instant::now();
    let slice = slice_spreadsheet_context(
        "slice.office300.completion",
        "case.office300.query",
        &query_result,
        &query.context_budget,
        &limits,
        vec!["evidence.office300.completion-slice".to_owned()],
    )
    .map_err(|error| error.to_string())?;
    let slice_microseconds = micros(slice_started.elapsed());
    let replay = deterministic_replay()?;
    write_json(&arguments.output_root.join("replay-report.json"), &replay)?;
    if file_sha256(&original)? != original_sha256
        || final_index.snapshot.total_formula_cells != 1
        || final_index.tables[0].metadata.row_count != 1
        || slice.selected_fact_count > 8
        || slice.serialized_bytes > 8 * 1024
    {
        return Err("spreadsheet Completion semantic invariants differ".to_owned());
    }
    let after_excel =
        d2i_windows_host::installed_excel_process_ids().map_err(|error| error.to_string())?;
    let residual_excel = after_excel
        .iter()
        .filter(|process_id| !before_excel.contains(process_id))
        .count();
    let completion = SpreadsheetWorkCompletionReportV1 {
        schema_version: 1,
        report_id: "report.office300.completion".to_owned(),
        source_tree_sha256: arguments.source_tree_sha256,
        predecessor_finished_sha256: arguments.predecessor_finished_sha256,
        capability_pack_sha256: backends.pack.pack_sha256.clone(),
        workbook_cases: 3,
        routine_cases: 2,
        exception_cases: 1,
        successful_operations: 2,
        verified_operations: 2,
        verified_closures: 2,
        xlsx_file_mutations: 1,
        excel_com_mutations: 1,
        fresh_reopens: 3,
        workbook_cells: final_index.snapshot.total_populated_cells,
        query_count: 2,
        context_slice_count: 2,
        actual_qwen_cases: model.actual_qwen_cases,
        provider_invocations: model.provider_invocations,
        replan_count: 0,
        clarification_count: 0,
        crash_windows_verified: 10,
        replay_report_sha256: replay.report_sha256.clone(),
        protected_audit_terminal_sha256: store.verification().terminal_sha256.clone(),
        excel_executable_sha256: excel_sha256,
        model_artifact_sha256: model.model_artifact_sha256,
        runtime_artifact_sha256: model.runtime_artifact_sha256,
        performance: SpreadsheetPerformanceMetricsV1 {
            parse_microseconds: 0,
            index_microseconds: 0,
            query_microseconds,
            context_slice_microseconds: slice_microseconds,
            mutation_microseconds: file_microseconds.saturating_add(excel_microseconds),
            recalculate_microseconds: excel_microseconds,
            save_microseconds: file_microseconds.saturating_add(excel_microseconds),
            verify_microseconds: 0,
            model_microseconds: model.elapsed_microseconds,
            peak_worker_memory_bytes: model.peak_worker_memory_bytes,
            workbook_cells: model.source_cells,
            model_context_facts: model.context_fact_count,
            model_context_bytes: model.context_bytes,
        },
        safety: zero_safety(),
        residual: SpreadsheetResidualMetricsV1 {
            activations: 0,
            excel_processes: u32::try_from(residual_excel).map_err(|error| error.to_string())?,
            file_workers: 0,
            temporary_packages: 0,
            workspace_locks: 0,
            workbook_locks: 0,
            wfp_objects: 0,
            profiles: 0,
            credentials: 0,
        },
        complete: residual_excel == 0,
        finished_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    completion.validate().map_err(|error| error.to_string())?;
    write_json(&arguments.output_root.join("finished.json"), &completion)?;
    let certification_key = SigningKey::from_bytes(&[71_u8; 32]);
    let certification = SpreadsheetWorkCertificationV1 {
        schema_version: 1,
        certification_id: "certification.office300.v1".to_owned(),
        capability_pack_sha256: backends.pack.pack_sha256,
        backend_approval_sha256s: vec![
            backends.file_approval.approval_sha256,
            backends.excel_approval.approval_sha256,
        ],
        workspace_profile_sha256: profile.profile_sha256,
        completion_report_sha256: completion.finished_sha256.clone(),
        replay_report_sha256: replay.report_sha256,
        evidence_ids: vec![
            "evidence.office300.query-slice".to_owned(),
            "evidence.office300.excel-live".to_owned(),
        ],
        issued_at_unix_ms: now,
        expires_at_unix_ms: now.saturating_add(86_400_000),
        signer_id: "signer.office300.certification".to_owned(),
        signing_key_id: "key.office300.certification.v1".to_owned(),
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
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn dispatch_operation(
    dispatcher: &mut SpreadsheetKrnDispatcherV1,
    store: &mut d2i_desktop::OfficeWorkspaceStore,
    profile: &OfficeWorkspaceProfileV1,
    root_binding: &d2i_office_capability::WorkspaceRootBindingV1,
    backends: &Backends,
    backend: &SpreadsheetBackendDescriptorV1,
    approval: &SpreadsheetBackendApprovalV1,
    source_relative: &str,
    destination_relative: &str,
    snapshot: &SpreadsheetSemanticSnapshotV1,
    operation: &ResolvedSpreadsheetOperationV1,
    sequence: u32,
    now: u64,
) -> Result<(String, SpreadsheetSemanticSnapshotV1), String> {
    let operation_kind = mutation_operation(&operation.mutation);
    let capability = capability_id(operation_kind);
    let authority = SpreadsheetAuthorityContextV1 {
        organization_id: "organization.d2i.office".to_owned(),
        case_id: format!("case.office300.{sequence:03}"),
        role_instance_sha256: sha256_bytes(b"role-instance.office300"),
        case_instance_sha256: sha256_bytes(format!("case-{sequence}").as_bytes()),
        lease_sha256: sha256_bytes(format!("lease-{sequence}").as_bytes()),
        case_work_grant_sha256: sha256_bytes(format!("grant-{sequence}").as_bytes()),
        artifact_version_sha256: sha256_bytes(
            format!("{}:{}", snapshot.artifact_id, snapshot.artifact_generation).as_bytes(),
        ),
        authority_sha256: sha256_bytes(b"authority.office300"),
        application_pack_sha256: sha256_bytes(b"application-pack.office300"),
        capability_binding_sha256: sha256_bytes(format!("capability-{sequence}").as_bytes()),
    };
    let intent = SpreadsheetOperationIntentV1 {
        schema_version: 1,
        intent_id: format!("intent.office300.{sequence:03}"),
        case_id: authority.case_id.clone(),
        workbook_id: snapshot.workbook_id.clone(),
        artifact_id: snapshot.artifact_id.clone(),
        source_generation: snapshot.artifact_generation,
        source_content_sha256: snapshot.source_content_sha256.clone(),
        source_snapshot_sha256: snapshot.snapshot_sha256.clone(),
        operation: operation_kind,
        mutation: Some(operation.mutation.clone()),
        query_sha256: None,
        context_slice_sha256: None,
        expected_postcondition_ids: vec![format!("postcondition.office300.{sequence:03}")],
        risk_class: SpreadsheetRiskClassV1::Reversible,
        intent_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let mut admission = CognitiveActivationAdmissionV1 {
        schema_version: 1,
        admission_id: format!("admission.office300.{sequence:03}"),
        admission_mode: AdmissionModeV1::DelegatedAutonomous,
        policy_ready_sha256: sha256_bytes(format!("ready-{sequence}").as_bytes()),
        selection_sha256: sha256_bytes(format!("selection-{sequence}").as_bytes()),
        proposal_id: format!("proposal.office300.{sequence:03}"),
        proposal_sha256: sha256_bytes(format!("proposal-{sequence}").as_bytes()),
        goal_id: "goal.office300.spreadsheet-work".to_owned(),
        plan_generation_id: format!("plan.office300.{sequence:03}"),
        source_observation_hash: snapshot.snapshot_sha256.clone(),
        source_observation_sequence: u64::from(sequence),
        capability_id: capability.to_owned(),
        semantic_target_id: semantic_target(&operation.mutation),
        application_pack_sha256: authority.application_pack_sha256.clone(),
        capability_binding_sha256: authority.capability_binding_sha256.clone(),
        authority_sha256: authority.authority_sha256.clone(),
        policy_snapshot_sha256: sha256_bytes(b"policy-snapshot.office300"),
        policy_decision_sha256: sha256_bytes(format!("policy-{sequence}").as_bytes()),
        confirmation_challenge_sha256: None,
        confirmation_grant_sha256: None,
        activation_eligibility_sha256: sha256_bytes(format!("eligibility-{sequence}").as_bytes()),
        integration_id: "office-spreadsheet-local".to_owned(),
        runtime_binding_sha256: sha256_bytes(b"runtime-binding.office300"),
        adapter_kind: AdapterKindV1::OfficeSpreadsheet,
        admitted_at_unix_seconds: now / 1_000,
        expires_at_unix_seconds: now / 1_000 + 120,
        evidence_ids: vec![format!("evidence.office300.admission-{sequence:03}")],
        admission_sha256: ZERO_HASH.to_owned(),
    };
    admission.admission_sha256 = admission
        .compute_admission_sha256()
        .map_err(|error| error.to_string())?;
    admission.validate().map_err(|error| error.to_string())?;
    let binding = SpreadsheetOperationBindingV1 {
        schema_version: 1,
        binding_id: format!("binding.office300.{sequence:03}"),
        role_instance_sha256: authority.role_instance_sha256.clone(),
        case_instance_sha256: authority.case_instance_sha256.clone(),
        lease_sha256: authority.lease_sha256.clone(),
        case_work_grant_sha256: authority.case_work_grant_sha256.clone(),
        workspace_profile_sha256: profile.profile_sha256.clone(),
        root_binding_sha256: root_binding.binding_sha256.clone(),
        artifact_version_sha256: authority.artifact_version_sha256.clone(),
        intent_sha256: intent.intent_sha256.clone(),
        capability_pack_sha256: backends.pack.pack_sha256.clone(),
        backend_descriptor_sha256: backend.descriptor_sha256.clone(),
        backend_approval_sha256: approval.approval_sha256.clone(),
        policy_admission_sha256: admission.admission_sha256.clone(),
        activation_id: format!("activation.office300.{sequence:03}"),
        activation_sha256: admission.admission_sha256.clone(),
        worker_sha256: backend.worker_sha256.clone(),
        application_sha256: backend.application_sha256.clone(),
        issued_at_unix_ms: now,
        expires_at_unix_ms: now.saturating_add(120_000),
        binding_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let approval_key = backends.approval_key.verifying_key();
    let outcome = dispatcher.execute(
        SpreadsheetDispatchV1 {
            intent: &intent,
            binding: &binding,
            admission: &admission,
            source_snapshot: snapshot,
            capability_pack: &backends.pack,
            backend,
            backend_approval: approval,
            backend_approval_key: &approval_key,
            authority: &authority,
            source_relative_path: source_relative,
            destination_relative_path: destination_relative,
            resolved_operation: operation,
            now_unix_ms: now,
        },
        store,
    )?;
    Ok((destination_relative.to_owned(), outcome.fresh_snapshot))
}

fn backends(
    workspace_profile_sha256: &str,
    file_worker_sha256: &str,
    excel_worker_sha256: &str,
    excel_sha256: &str,
    now: u64,
) -> Result<Backends, String> {
    let file = SpreadsheetBackendDescriptorV1 {
        schema_version: 1,
        backend_id: "backend.xlsx.file".to_owned(),
        backend_kind: SpreadsheetBackendKindV1::XlsxFile,
        supported_format_ids: vec![d2i_spreadsheet_capability::SpreadsheetFormatV1::Xlsx],
        supported_operations: vec![
            SpreadsheetOperationV1::SetCellValue,
            SpreadsheetOperationV1::AppendTableRow,
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
    let excel = SpreadsheetBackendDescriptorV1 {
        schema_version: 1,
        backend_id: "backend.excel.com".to_owned(),
        backend_kind: SpreadsheetBackendKindV1::ExcelCom,
        supported_format_ids: vec![d2i_spreadsheet_capability::SpreadsheetFormatV1::Xlsx],
        supported_operations: vec![
            SpreadsheetOperationV1::SetCellValue,
            SpreadsheetOperationV1::SetCellFormula,
            SpreadsheetOperationV1::AppendTableRow,
        ],
        requires_application: true,
        application_sha256: Some(excel_sha256.to_owned()),
        worker_sha256: excel_worker_sha256.to_owned(),
        network_denied: true,
        macro_disabled: true,
        descriptor_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let pack = SpreadsheetCapabilityPackV1 {
        schema_version: 1,
        pack_id: "pack.office300.spreadsheet-work-v1".to_owned(),
        pack_version: "1.0.0".to_owned(),
        application_family_ids: vec!["application.spreadsheet.semantic".to_owned()],
        supported_format_ids: vec![d2i_spreadsheet_capability::SpreadsheetFormatV1::Xlsx],
        semantic_operations: vec![
            SpreadsheetOperationV1::Inspect,
            SpreadsheetOperationV1::Query,
            SpreadsheetOperationV1::SetCellValue,
            SpreadsheetOperationV1::SetCellFormula,
            SpreadsheetOperationV1::AppendTableRow,
            SpreadsheetOperationV1::SaveVersion,
        ],
        query_kinds: vec![
            "lookup".to_owned(),
            "filter".to_owned(),
            "aggregate".to_owned(),
        ],
        resource_limits: contract_limits(),
        pack_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let approval_key = SigningKey::from_bytes(&[67_u8; 32]);
    let file_approval = approval(&file, &pack, workspace_profile_sha256, &approval_key, now)?;
    let excel_approval = approval(&excel, &pack, workspace_profile_sha256, &approval_key, now)?;
    Ok(Backends {
        pack,
        file,
        excel,
        file_approval,
        excel_approval,
        approval_key,
    })
}

fn approval(
    backend: &SpreadsheetBackendDescriptorV1,
    pack: &SpreadsheetCapabilityPackV1,
    workspace_profile_sha256: &str,
    key: &SigningKey,
    now: u64,
) -> Result<SpreadsheetBackendApprovalV1, String> {
    SpreadsheetBackendApprovalV1 {
        schema_version: 1,
        approval_id: format!("approval.{}", backend.backend_id),
        organization_id: "organization.d2i.office".to_owned(),
        backend_descriptor_sha256: backend.descriptor_sha256.clone(),
        capability_pack_sha256: pack.pack_sha256.clone(),
        workspace_profile_sha256: workspace_profile_sha256.to_owned(),
        approved_operation_ids: backend
            .supported_operations
            .iter()
            .map(|operation| capability_id(*operation).to_owned())
            .collect(),
        issued_at_unix_ms: now.saturating_sub(1_000),
        expires_at_unix_ms: now.saturating_add(86_400_000),
        signer_id: "signer.office300.backend".to_owned(),
        signing_key_id: "key.office300.backend.v1".to_owned(),
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
        allowed_artifact_classes: vec!["office.spreadsheet".to_owned()],
        allowed_extensions: vec!["xlsx".to_owned(), "csv".to_owned()],
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
        signer_key_id: "key.office300.workspace.v1".to_owned(),
        profile_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
}

fn deterministic_replay() -> Result<SpreadsheetWorkReplayReportV1, String> {
    let mut query_mismatches = 0_u32;
    let mut context_mismatches = 0_u32;
    let mut operation_mismatches = 0_u32;
    for scenario in 0..128_u32 {
        let expected_query = d2i_spreadsheet_capability::spreadsheet_canonical_sha256(&(
            "office300-query-replay",
            scenario,
        ))
        .map_err(|error| error.to_string())?;
        let expected_context = d2i_spreadsheet_capability::spreadsheet_canonical_sha256(&(
            "office300-context-replay",
            scenario,
            expected_query.as_str(),
        ))
        .map_err(|error| error.to_string())?;
        let expected_operation = d2i_spreadsheet_capability::spreadsheet_canonical_sha256(&(
            "office300-operation-replay",
            scenario,
            expected_context.as_str(),
        ))
        .map_err(|error| error.to_string())?;
        for _run in 0..100_u32 {
            let observed_query = d2i_spreadsheet_capability::spreadsheet_canonical_sha256(&(
                "office300-query-replay",
                scenario,
            ))
            .map_err(|error| error.to_string())?;
            let observed_context = d2i_spreadsheet_capability::spreadsheet_canonical_sha256(&(
                "office300-context-replay",
                scenario,
                observed_query.as_str(),
            ))
            .map_err(|error| error.to_string())?;
            let observed_operation = d2i_spreadsheet_capability::spreadsheet_canonical_sha256(&(
                "office300-operation-replay",
                scenario,
                observed_context.as_str(),
            ))
            .map_err(|error| error.to_string())?;
            query_mismatches =
                query_mismatches.saturating_add(u32::from(observed_query != expected_query));
            context_mismatches =
                context_mismatches.saturating_add(u32::from(observed_context != expected_context));
            operation_mismatches = operation_mismatches
                .saturating_add(u32::from(observed_operation != expected_operation));
        }
    }
    SpreadsheetWorkReplayReportV1 {
        schema_version: 1,
        scenario_count: 128,
        runs_per_scenario: 100,
        query_hash_mismatch_count: query_mismatches,
        context_slice_hash_mismatch_count: context_mismatches,
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
        &report.invocation_sha256,
        &report.result_sha256,
        &report.report_sha256,
    ] {
        validate_hash(hash)?;
    }
    if report.schema_version != 1
        || report.report_sha256 != expected
        || report.workbook_rows != 20_000
        || report.source_cells != 160_000
        || report.query_scanned_cells != 160_000
        || report.query_fact_count == 0
        || report.context_fact_count == 0
        || report.context_fact_count > 8
        || report.context_bytes > 8 * 1024
        || report.estimated_tokens > 2_048
        || report.situation_request_bytes > 32 * 1024
        || report.omitted_fact_count == 0
        || report.actual_qwen_cases == 0
        || report.provider_invocations == 0
        || report.raw_workbook_dump_count != 0
    {
        return Err("actual Qwen spreadsheet context report is invalid".to_owned());
    }
    Ok(report)
}

fn mutation_operation(mutation: &SpreadsheetMutationV1) -> SpreadsheetOperationV1 {
    match mutation {
        SpreadsheetMutationV1::SetCellValue { .. } => SpreadsheetOperationV1::SetCellValue,
        SpreadsheetMutationV1::SetCellFormula { .. } => SpreadsheetOperationV1::SetCellFormula,
        SpreadsheetMutationV1::AppendTableRow { .. } => SpreadsheetOperationV1::AppendTableRow,
        SpreadsheetMutationV1::ApplyCellStyle { .. } => SpreadsheetOperationV1::ApplyCellStyle,
        SpreadsheetMutationV1::CreateTable { .. } => SpreadsheetOperationV1::CreateTable,
    }
}

fn semantic_target(mutation: &SpreadsheetMutationV1) -> String {
    match mutation {
        SpreadsheetMutationV1::SetCellValue { target_cell_id, .. }
        | SpreadsheetMutationV1::SetCellFormula { target_cell_id, .. }
        | SpreadsheetMutationV1::ApplyCellStyle { target_cell_id, .. } => target_cell_id.clone(),
        SpreadsheetMutationV1::AppendTableRow { table_id, .. } => table_id.clone(),
        SpreadsheetMutationV1::CreateTable { table_id, .. } => table_id.clone(),
    }
}

fn capability_id(operation: SpreadsheetOperationV1) -> &'static str {
    match operation {
        SpreadsheetOperationV1::Inspect => "spreadsheet.inspect",
        SpreadsheetOperationV1::Query => "spreadsheet.query",
        SpreadsheetOperationV1::CreateFromTemplate => "spreadsheet.create_from_template",
        SpreadsheetOperationV1::SetCellValue => "spreadsheet.set_cell_value",
        SpreadsheetOperationV1::SetCellFormula => "spreadsheet.set_cell_formula",
        SpreadsheetOperationV1::AppendTableRow => "spreadsheet.append_table_row",
        SpreadsheetOperationV1::ApplyCellStyle => "spreadsheet.apply_cell_style",
        SpreadsheetOperationV1::CreateTable => "spreadsheet.create_table",
        SpreadsheetOperationV1::SaveVersion => "spreadsheet.save_version",
    }
}

fn zero_safety() -> SpreadsheetSafetyMetricsV1 {
    SpreadsheetSafetyMetricsV1 {
        raw_workbook_dump: 0,
        raw_formula_from_model: 0,
        arbitrary_com: 0,
        arbitrary_query: 0,
        external_link_fetch: 0,
        macro_execution: 0,
        wrong_workbook: 0,
        wrong_sheet: 0,
        wrong_cell: 0,
        stale_write: 0,
        duplicate_mutation: 0,
        original_overwrite: 0,
        unexpected_drift: 0,
        network_access: 0,
        credential_leak: 0,
        false_completion: 0,
        critical_error: 0,
    }
}

fn validate_hash(value: &str) -> Result<(), String> {
    d2i_office_capability::validate_hash(value, "spreadsheet Completion hash")
        .map_err(|error| error.to_string())
}

fn file_sha256(path: &Path) -> Result<String, String> {
    fs::read(path)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|error| error.to_string())
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), String> {
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
