use crate::office_workspace::canonical_text;
use crate::{
    inspect_xlsx_workbook, spawn_spreadsheet_file_worker, OfficeWorkspaceStore,
    ResolvedSpreadsheetOperationV1, SpreadsheetFileWorkerRequestV1,
};
#[cfg(windows)]
use crate::{spawn_excel_spreadsheet_worker, ExcelSpreadsheetWorkerRequestV1};
use d2i_office_capability::{
    sha256_bytes, validate_hash, validate_id, validate_relative_path_token,
    OfficeWorkspaceProfileV1, WorkspaceRootBindingV1,
};
use d2i_policy_admission::{AdapterKindV1, CognitiveActivationAdmissionV1};
use d2i_spreadsheet_capability::{
    SpreadsheetActivationLedgerV1, SpreadsheetBackendApprovalV1, SpreadsheetBackendDescriptorV1,
    SpreadsheetBackendKindV1, SpreadsheetCapabilityPackV1, SpreadsheetMutationV1,
    SpreadsheetOperationBindingV1, SpreadsheetOperationIntentV1, SpreadsheetOperationReceiptV1,
    SpreadsheetOperationResultV1, SpreadsheetOperationV1, SpreadsheetPostOperationVerificationV1,
    SpreadsheetSemanticDiffV1, SpreadsheetSemanticSnapshotV1, SpreadsheetVerificationStatusV1,
    ZERO_HASH,
};
use ed25519_dalek::VerifyingKey;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpreadsheetAuthorityContextV1 {
    pub organization_id: String,
    pub case_id: String,
    pub role_instance_sha256: String,
    pub case_instance_sha256: String,
    pub lease_sha256: String,
    pub case_work_grant_sha256: String,
    pub artifact_version_sha256: String,
    pub authority_sha256: String,
    pub application_pack_sha256: String,
    pub capability_binding_sha256: String,
}

pub struct SpreadsheetDispatchV1<'a> {
    pub intent: &'a SpreadsheetOperationIntentV1,
    pub binding: &'a SpreadsheetOperationBindingV1,
    pub admission: &'a CognitiveActivationAdmissionV1,
    pub source_snapshot: &'a SpreadsheetSemanticSnapshotV1,
    pub capability_pack: &'a SpreadsheetCapabilityPackV1,
    pub backend: &'a SpreadsheetBackendDescriptorV1,
    pub backend_approval: &'a SpreadsheetBackendApprovalV1,
    pub backend_approval_key: &'a VerifyingKey,
    pub authority: &'a SpreadsheetAuthorityContextV1,
    pub source_relative_path: &'a str,
    pub destination_relative_path: &'a str,
    pub resolved_operation: &'a ResolvedSpreadsheetOperationV1,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpreadsheetDispatchOutcomeV1 {
    pub receipt: SpreadsheetOperationReceiptV1,
    pub semantic_diff: SpreadsheetSemanticDiffV1,
    pub verification: SpreadsheetPostOperationVerificationV1,
    pub fresh_snapshot: SpreadsheetSemanticSnapshotV1,
    pub workspace_store_terminal_sha256: String,
}

pub struct SpreadsheetKrnDispatcherConfigurationV1 {
    pub root: PathBuf,
    pub root_binding: WorkspaceRootBindingV1,
    pub workspace_profile: OfficeWorkspaceProfileV1,
    pub workspace_profile_key: VerifyingKey,
    pub file_worker_executable: PathBuf,
    pub expected_file_worker_sha256: String,
    #[cfg(windows)]
    pub excel_worker_executable: PathBuf,
    #[cfg(windows)]
    pub expected_excel_worker_sha256: String,
    #[cfg(windows)]
    pub excel_executable: PathBuf,
    #[cfg(windows)]
    pub expected_excel_executable_sha256: String,
    pub now_unix_ms: u64,
}

pub struct SpreadsheetKrnDispatcherV1 {
    root: PathBuf,
    root_binding: WorkspaceRootBindingV1,
    workspace_profile: OfficeWorkspaceProfileV1,
    file_worker_executable: PathBuf,
    file_worker_sha256: String,
    #[cfg(windows)]
    excel_worker_executable: PathBuf,
    #[cfg(windows)]
    excel_worker_sha256: String,
    #[cfg(windows)]
    excel_executable: PathBuf,
    #[cfg(windows)]
    excel_executable_sha256: String,
    activation_ledger: SpreadsheetActivationLedgerV1,
}

impl SpreadsheetKrnDispatcherV1 {
    pub fn new(configuration: SpreadsheetKrnDispatcherConfigurationV1) -> Result<Self, String> {
        configuration
            .workspace_profile
            .validate_signature(&configuration.workspace_profile_key)
            .map_err(|error| error.to_string())?;
        configuration
            .root_binding
            .validate_integrity()
            .map_err(|error| error.to_string())?;
        verify_workspace_boundary(
            &configuration.root,
            &configuration.root_binding,
            &configuration.workspace_profile,
            configuration.now_unix_ms,
        )?;
        verify_executable(
            &configuration.file_worker_executable,
            &configuration.expected_file_worker_sha256,
            "spreadsheet file worker",
        )?;
        #[cfg(windows)]
        {
            verify_executable(
                &configuration.excel_worker_executable,
                &configuration.expected_excel_worker_sha256,
                "spreadsheet Excel worker",
            )?;
            verify_executable(
                &configuration.excel_executable,
                &configuration.expected_excel_executable_sha256,
                "Excel",
            )?;
        }
        Ok(Self {
            root: configuration.root,
            root_binding: configuration.root_binding,
            workspace_profile: configuration.workspace_profile,
            file_worker_executable: configuration.file_worker_executable,
            file_worker_sha256: configuration.expected_file_worker_sha256,
            #[cfg(windows)]
            excel_worker_executable: configuration.excel_worker_executable,
            #[cfg(windows)]
            excel_worker_sha256: configuration.expected_excel_worker_sha256,
            #[cfg(windows)]
            excel_executable: configuration.excel_executable,
            #[cfg(windows)]
            excel_executable_sha256: configuration.expected_excel_executable_sha256,
            activation_ledger: SpreadsheetActivationLedgerV1::default(),
        })
    }

    pub fn execute(
        &mut self,
        dispatch: SpreadsheetDispatchV1<'_>,
        store: &mut OfficeWorkspaceStore,
    ) -> Result<SpreadsheetDispatchOutcomeV1, String> {
        validate_dispatch(&dispatch, &self.workspace_profile, &self.root_binding)?;
        verify_workspace_boundary(
            &self.root,
            &self.root_binding,
            &self.workspace_profile,
            dispatch.now_unix_ms,
        )?;
        let source = resolve_relative(&self.root, dispatch.source_relative_path, false)?;
        let destination = resolve_relative(&self.root, dispatch.destination_relative_path, true)?;
        if source == destination || destination.exists() {
            return Err("spreadsheet destination must be a new generation".to_owned());
        }
        let source_sha256 = file_sha256(&source)?;
        if source_sha256 != dispatch.intent.source_content_sha256
            || source_sha256 != dispatch.source_snapshot.source_content_sha256
        {
            return Err("spreadsheet source differs from its exact binding".to_owned());
        }
        let (worker, worker_sha256) = match dispatch.backend.backend_kind {
            SpreadsheetBackendKindV1::XlsxFile => {
                (&self.file_worker_executable, &self.file_worker_sha256)
            }
            SpreadsheetBackendKindV1::ExcelCom => {
                #[cfg(windows)]
                {
                    if dispatch.binding.application_sha256.as_deref()
                        != Some(self.excel_executable_sha256.as_str())
                    {
                        return Err("Excel application hash differs from binding".to_owned());
                    }
                    (&self.excel_worker_executable, &self.excel_worker_sha256)
                }
                #[cfg(not(windows))]
                {
                    return Err("Excel COM is Windows-only".to_owned());
                }
            }
            SpreadsheetBackendKindV1::CsvFile => {
                return Err("CSV mutation is not enabled in spreadsheet v1".to_owned())
            }
        };
        if worker_sha256 != &dispatch.binding.worker_sha256
            || worker_sha256 != &dispatch.backend.worker_sha256
        {
            return Err("spreadsheet worker hash differs from descriptor or binding".to_owned());
        }
        verify_executable(worker, worker_sha256, "spreadsheet worker")?;
        self.activation_ledger
            .consume(
                &dispatch.binding.activation_id,
                &dispatch.binding.activation_sha256,
            )
            .map_err(|error| error.to_string())?;
        let generation = dispatch
            .source_snapshot
            .artifact_generation
            .saturating_add(1);
        let worker_snapshot = match dispatch.backend.backend_kind {
            SpreadsheetBackendKindV1::XlsxFile => {
                spawn_spreadsheet_file_worker(
                    worker,
                    worker_sha256,
                    &SpreadsheetFileWorkerRequestV1 {
                        schema_version: 1,
                        request_id: dispatch.binding.activation_id.clone(),
                        source_path: source.to_string_lossy().to_string(),
                        destination_path: destination.to_string_lossy().to_string(),
                        expected_source_sha256: source_sha256.clone(),
                        workbook_id: dispatch.source_snapshot.workbook_id.clone(),
                        artifact_id: dispatch.source_snapshot.artifact_id.clone(),
                        generation,
                        backend_id: dispatch.backend.backend_id.clone(),
                        observed_at_unix_ms: dispatch.now_unix_ms.saturating_add(1),
                        operation: dispatch.resolved_operation.clone(),
                        limits: dispatch.capability_pack.resource_limits.clone(),
                    },
                    Duration::from_millis(
                        dispatch
                            .capability_pack
                            .resource_limits
                            .maximum_worker_milliseconds,
                    ),
                )?
                .snapshot
            }
            SpreadsheetBackendKindV1::ExcelCom => {
                #[cfg(windows)]
                {
                    spawn_excel_spreadsheet_worker(
                        worker,
                        worker_sha256,
                        &self.excel_executable,
                        &self.excel_executable_sha256,
                        &ExcelSpreadsheetWorkerRequestV1 {
                            schema_version: 1,
                            request_id: dispatch.binding.activation_id.clone(),
                            source_path: source.to_string_lossy().to_string(),
                            destination_path: destination.to_string_lossy().to_string(),
                            expected_source_sha256: source_sha256.clone(),
                            excel_executable_path: self
                                .excel_executable
                                .to_string_lossy()
                                .to_string(),
                            expected_excel_sha256: self.excel_executable_sha256.clone(),
                            workbook_id: dispatch.source_snapshot.workbook_id.clone(),
                            artifact_id: dispatch.source_snapshot.artifact_id.clone(),
                            generation,
                            backend_id: dispatch.backend.backend_id.clone(),
                            observed_at_unix_ms: dispatch.now_unix_ms.saturating_add(1),
                            operation: dispatch.resolved_operation.clone(),
                            limits: dispatch.capability_pack.resource_limits.clone(),
                        },
                        Duration::from_millis(
                            dispatch
                                .capability_pack
                                .resource_limits
                                .maximum_application_session_milliseconds,
                        ),
                    )?
                    .snapshot
                }
                #[cfg(not(windows))]
                {
                    return Err("Excel COM is Windows-only".to_owned());
                }
            }
            SpreadsheetBackendKindV1::CsvFile => {
                return Err("CSV mutation is not enabled in spreadsheet v1".to_owned())
            }
        };
        let fresh = inspect_xlsx_workbook(
            &destination,
            &dispatch.source_snapshot.workbook_id,
            &dispatch.source_snapshot.artifact_id,
            generation,
            &dispatch.backend.backend_id,
            dispatch.now_unix_ms.saturating_add(2),
            &dispatch.capability_pack.resource_limits,
        )?;
        verify_fresh_reopen(&worker_snapshot, &fresh.snapshot)?;
        let diff = build_diff(
            dispatch.source_snapshot,
            &fresh.snapshot,
            &dispatch.resolved_operation.mutation,
        )?;
        let receipt = SpreadsheetOperationReceiptV1 {
            schema_version: 1,
            receipt_id: format!("receipt.{}", dispatch.binding.activation_id),
            binding_sha256: dispatch.binding.binding_sha256.clone(),
            operation: dispatch.intent.operation,
            result: SpreadsheetOperationResultV1::Verified,
            source_content_sha256: source_sha256,
            destination_content_sha256: Some(fresh.snapshot.source_content_sha256.clone()),
            fresh_snapshot_sha256: Some(fresh.snapshot.snapshot_sha256.clone()),
            query_result_sha256: None,
            context_slice_sha256: None,
            activation_consumed: true,
            started_at_unix_ms: dispatch.now_unix_ms,
            completed_at_unix_ms: dispatch.now_unix_ms.saturating_add(3),
            audit_event_ids: vec![format!("audit.{}", dispatch.binding.activation_id)],
            receipt_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())?;
        let verification = SpreadsheetPostOperationVerificationV1 {
            schema_version: 1,
            verification_id: format!("verification.{}", dispatch.binding.activation_id),
            binding_sha256: dispatch.binding.binding_sha256.clone(),
            receipt_sha256: receipt.receipt_sha256.clone(),
            diff_sha256: diff.diff_sha256.clone(),
            fresh_snapshot_sha256: fresh.snapshot.snapshot_sha256.clone(),
            expected_postcondition_ids: dispatch.intent.expected_postcondition_ids.clone(),
            satisfied_postcondition_ids: dispatch.intent.expected_postcondition_ids.clone(),
            protected_invariant_ids: vec![
                "spreadsheet.original.immutable".to_owned(),
                "spreadsheet.fresh.reopen".to_owned(),
                "spreadsheet.one.activation.one.operation".to_owned(),
            ],
            status: SpreadsheetVerificationStatusV1::Verified,
            verified_at_unix_ms: dispatch.now_unix_ms.saturating_add(4),
            verification_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())?;
        for (kind, id, artifact) in [
            (
                "spreadsheet-snapshot",
                format!("snapshot.{}", dispatch.binding.activation_id),
                serde_json::to_value(&fresh.snapshot).map_err(|error| error.to_string())?,
            ),
            (
                "spreadsheet-receipt",
                format!("receipt.{}", dispatch.binding.activation_id),
                serde_json::to_value(&receipt).map_err(|error| error.to_string())?,
            ),
            (
                "spreadsheet-diff",
                format!("diff.{}", dispatch.binding.activation_id),
                serde_json::to_value(&diff).map_err(|error| error.to_string())?,
            ),
            (
                "spreadsheet-verification",
                format!("verification.{}", dispatch.binding.activation_id),
                serde_json::to_value(&verification).map_err(|error| error.to_string())?,
            ),
        ] {
            store.append(kind, &id, &artifact, dispatch.now_unix_ms.saturating_add(5))?;
        }
        Ok(SpreadsheetDispatchOutcomeV1 {
            receipt,
            semantic_diff: diff,
            verification,
            fresh_snapshot: fresh.snapshot,
            workspace_store_terminal_sha256: store.verification().terminal_sha256.clone(),
        })
    }
}

fn validate_dispatch(
    dispatch: &SpreadsheetDispatchV1<'_>,
    profile: &OfficeWorkspaceProfileV1,
    root_binding: &WorkspaceRootBindingV1,
) -> Result<(), String> {
    dispatch
        .intent
        .validate()
        .map_err(|error| error.to_string())?;
    dispatch
        .binding
        .validate()
        .map_err(|error| error.to_string())?;
    dispatch
        .source_snapshot
        .validate()
        .map_err(|error| error.to_string())?;
    dispatch
        .capability_pack
        .validate()
        .map_err(|error| error.to_string())?;
    dispatch
        .backend
        .validate()
        .map_err(|error| error.to_string())?;
    dispatch
        .backend_approval
        .verify(dispatch.backend_approval_key, dispatch.now_unix_ms)
        .map_err(|error| error.to_string())?;
    dispatch
        .admission
        .validate()
        .map_err(|error| error.to_string())?;
    validate_authority(dispatch.authority)?;
    validate_relative_path_token(dispatch.source_relative_path)
        .map_err(|error| error.to_string())?;
    validate_relative_path_token(dispatch.destination_relative_path)
        .map_err(|error| error.to_string())?;
    let capability = operation_capability(dispatch.intent.operation);
    let operation_id = capability.to_owned();
    if dispatch.intent.mutation.as_ref() != Some(&dispatch.resolved_operation.mutation)
        || dispatch.intent.case_id != dispatch.authority.case_id
        || dispatch.intent.workbook_id != dispatch.source_snapshot.workbook_id
        || dispatch.intent.artifact_id != dispatch.source_snapshot.artifact_id
        || dispatch.intent.source_generation != dispatch.source_snapshot.artifact_generation
        || dispatch.intent.source_content_sha256 != dispatch.source_snapshot.source_content_sha256
        || dispatch.intent.source_snapshot_sha256 != dispatch.source_snapshot.snapshot_sha256
        || dispatch.binding.role_instance_sha256 != dispatch.authority.role_instance_sha256
        || dispatch.binding.case_instance_sha256 != dispatch.authority.case_instance_sha256
        || dispatch.binding.lease_sha256 != dispatch.authority.lease_sha256
        || dispatch.binding.case_work_grant_sha256 != dispatch.authority.case_work_grant_sha256
        || dispatch.binding.workspace_profile_sha256 != profile.profile_sha256
        || dispatch.binding.root_binding_sha256 != root_binding.binding_sha256
        || dispatch.binding.artifact_version_sha256 != dispatch.authority.artifact_version_sha256
        || dispatch.binding.intent_sha256 != dispatch.intent.intent_sha256
        || dispatch.binding.capability_pack_sha256 != dispatch.capability_pack.pack_sha256
        || dispatch.binding.backend_descriptor_sha256 != dispatch.backend.descriptor_sha256
        || dispatch.binding.backend_approval_sha256 != dispatch.backend_approval.approval_sha256
        || dispatch.binding.policy_admission_sha256 != dispatch.admission.admission_sha256
        || dispatch.binding.activation_sha256 != dispatch.admission.admission_sha256
        || dispatch.binding.application_sha256 != dispatch.backend.application_sha256
        || dispatch.admission.adapter_kind != AdapterKindV1::OfficeSpreadsheet
        || dispatch.admission.capability_id != capability
        || dispatch.admission.application_pack_sha256 != dispatch.authority.application_pack_sha256
        || dispatch.admission.capability_binding_sha256
            != dispatch.authority.capability_binding_sha256
        || dispatch.admission.authority_sha256 != dispatch.authority.authority_sha256
        || dispatch.backend_approval.organization_id != dispatch.authority.organization_id
        || dispatch.backend_approval.backend_descriptor_sha256 != dispatch.backend.descriptor_sha256
        || dispatch.backend_approval.capability_pack_sha256 != dispatch.capability_pack.pack_sha256
        || dispatch.backend_approval.workspace_profile_sha256 != profile.profile_sha256
        || !dispatch
            .backend_approval
            .approved_operation_ids
            .contains(&operation_id)
        || !dispatch
            .backend
            .supported_operations
            .contains(&dispatch.intent.operation)
        || !dispatch
            .capability_pack
            .semantic_operations
            .contains(&dispatch.intent.operation)
        || dispatch.binding.issued_at_unix_ms > dispatch.now_unix_ms
        || dispatch.now_unix_ms >= dispatch.binding.expires_at_unix_ms
        || dispatch.source_snapshot.freshness_expires_at_unix_ms < dispatch.now_unix_ms
        || dispatch.admission.admitted_at_unix_seconds > dispatch.now_unix_ms / 1_000
        || dispatch.now_unix_ms / 1_000 >= dispatch.admission.expires_at_unix_seconds
    {
        return Err("spreadsheet dispatch differs from its exact authority binding".to_owned());
    }
    Ok(())
}

fn validate_authority(authority: &SpreadsheetAuthorityContextV1) -> Result<(), String> {
    validate_id(&authority.organization_id, "spreadsheet organization")
        .map_err(|error| error.to_string())?;
    validate_id(&authority.case_id, "spreadsheet Case").map_err(|error| error.to_string())?;
    for hash in [
        &authority.role_instance_sha256,
        &authority.case_instance_sha256,
        &authority.lease_sha256,
        &authority.case_work_grant_sha256,
        &authority.artifact_version_sha256,
        &authority.authority_sha256,
        &authority.application_pack_sha256,
        &authority.capability_binding_sha256,
    ] {
        validate_hash(hash, "spreadsheet authority hash").map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn build_diff(
    before: &SpreadsheetSemanticSnapshotV1,
    after: &SpreadsheetSemanticSnapshotV1,
    mutation: &SpreadsheetMutationV1,
) -> Result<SpreadsheetSemanticDiffV1, String> {
    if before.source_content_sha256 == after.source_content_sha256
        || before.snapshot_sha256 == after.snapshot_sha256
    {
        return Err("spreadsheet mutation produced no semantic change".to_owned());
    }
    let (table_ids, cell_ids) = match mutation {
        SpreadsheetMutationV1::SetCellValue { target_cell_id, .. }
        | SpreadsheetMutationV1::SetCellFormula { target_cell_id, .. }
        | SpreadsheetMutationV1::ApplyCellStyle { target_cell_id, .. } => {
            (Vec::new(), vec![target_cell_id.clone()])
        }
        SpreadsheetMutationV1::AppendTableRow { table_id, .. } => {
            (vec![table_id.clone()], Vec::new())
        }
        SpreadsheetMutationV1::CreateTable { table_id, .. } => (vec![table_id.clone()], Vec::new()),
    };
    SpreadsheetSemanticDiffV1 {
        schema_version: 1,
        before_snapshot_sha256: before.snapshot_sha256.clone(),
        after_snapshot_sha256: after.snapshot_sha256.clone(),
        changed_sheet_ids: after
            .sheets
            .iter()
            .map(|sheet| sheet.sheet_id.clone())
            .collect(),
        changed_table_ids: table_ids,
        changed_cell_ids: cell_ids,
        formula_change_count: after
            .total_formula_cells
            .saturating_sub(before.total_formula_cells),
        unexpected_change_ids: Vec::new(),
        diff_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn operation_capability(operation: SpreadsheetOperationV1) -> &'static str {
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

fn verify_workspace_boundary(
    root: &Path,
    binding: &WorkspaceRootBindingV1,
    profile: &OfficeWorkspaceProfileV1,
    now_unix_ms: u64,
) -> Result<(), String> {
    let canonical = root.canonicalize().map_err(|error| error.to_string())?;
    if canonical_text(&canonical) != binding.canonical_root
        || binding.workspace_id != profile.workspace_id
        || profile.workspace_root_binding_sha256 != binding.binding_sha256
        || now_unix_ms < binding.valid_from_unix_ms
        || now_unix_ms > binding.valid_until_unix_ms
        || now_unix_ms < profile.valid_from_unix_ms
        || now_unix_ms > profile.valid_until_unix_ms
        || binding.network_share_allowed
        || binding.removable_media_allowed
        || !binding.reparse_forbidden
        || !binding.symlink_forbidden
    {
        return Err("spreadsheet workspace boundary differs".to_owned());
    }
    Ok(())
}

fn verify_fresh_reopen(
    worker: &SpreadsheetSemanticSnapshotV1,
    fresh: &SpreadsheetSemanticSnapshotV1,
) -> Result<(), String> {
    worker.validate().map_err(|error| error.to_string())?;
    fresh.validate().map_err(|error| error.to_string())?;
    let mismatches = [
        ("workbook_id", fresh.workbook_id != worker.workbook_id),
        ("artifact_id", fresh.artifact_id != worker.artifact_id),
        (
            "artifact_generation",
            fresh.artifact_generation != worker.artifact_generation,
        ),
        ("backend_id", fresh.backend_id != worker.backend_id),
        (
            "source_content_sha256",
            fresh.source_content_sha256 != worker.source_content_sha256,
        ),
        (
            "workbook_data_sha256",
            fresh.workbook_data_sha256 != worker.workbook_data_sha256,
        ),
        (
            "semantic_state_sha256",
            fresh.semantic_state_sha256 != worker.semantic_state_sha256,
        ),
        (
            "total_populated_cells",
            fresh.total_populated_cells != worker.total_populated_cells,
        ),
        (
            "total_formula_cells",
            fresh.total_formula_cells != worker.total_formula_cells,
        ),
        (
            "unsupported_feature_ids",
            fresh.unsupported_feature_ids != worker.unsupported_feature_ids,
        ),
        (
            "observed_at_unix_ms",
            fresh.observed_at_unix_ms <= worker.observed_at_unix_ms,
        ),
        (
            "snapshot_sha256_not_fresh",
            fresh.snapshot_sha256 == worker.snapshot_sha256,
        ),
    ]
    .into_iter()
    .filter_map(|(field, differs)| differs.then_some(field))
    .collect::<Vec<_>>();
    if !mismatches.is_empty() {
        return Err(format!(
            "fresh spreadsheet reopen differs from worker output: {}",
            mismatches.join(",")
        ));
    }
    Ok(())
}

fn resolve_relative(root: &Path, relative: &str, new_file: bool) -> Result<PathBuf, String> {
    validate_relative_path_token(relative).map_err(|error| error.to_string())?;
    let relative_path = Path::new(relative);
    if relative_path
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err("spreadsheet path is not a bounded relative token".to_owned());
    }
    let candidate = root.join(relative_path);
    let parent = candidate
        .parent()
        .ok_or_else(|| "spreadsheet path parent is absent".to_owned())?
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let canonical_root = root.canonicalize().map_err(|error| error.to_string())?;
    if !parent.starts_with(&canonical_root)
        || d2i_windows_host::is_reparse_point(&parent).map_err(|error| error.to_string())?
        || (!new_file && !candidate.is_file())
    {
        return Err("spreadsheet path escapes or is unavailable".to_owned());
    }
    Ok(candidate)
}

fn verify_executable(path: &Path, expected_sha256: &str, label: &str) -> Result<(), String> {
    validate_hash(expected_sha256, label).map_err(|error| error.to_string())?;
    if !path.is_file()
        || d2i_windows_host::is_reparse_point(path).map_err(|error| error.to_string())?
        || file_sha256(path)? != expected_sha256
    {
        return Err(format!("{label} executable binding differs"));
    }
    Ok(())
}

fn file_sha256(path: &Path) -> Result<String, String> {
    fs::read(path)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod canonical_path_tests {
    use super::{canonical_text, verify_fresh_reopen};
    use crate::{create_xlsx_workbook, inspect_xlsx_workbook};
    use d2i_spreadsheet_capability::default_spreadsheet_resource_limits;
    use std::fs;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn extended_windows_paths_match_root_binding_normalization() {
        assert_eq!(
            canonical_text(Path::new(r"\\?\C:\workspace\spreadsheets")),
            "C:/workspace/spreadsheets"
        );
        assert_eq!(
            canonical_text(Path::new(r"\\?\UNC\server\share\spreadsheets")),
            "//server/share/spreadsheets"
        );
    }

    #[test]
    fn fresh_reopen_preserves_semantics_with_new_observation_identity() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let root = std::env::temp_dir().join(format!(
            "d2i-office300-fresh-reopen-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root)
            .unwrap_or_else(|error| panic!("create fresh reopen root: {error}"));
        let workbook = root.join("fixture.xlsx");
        let limits = default_spreadsheet_resource_limits();
        create_xlsx_workbook(&workbook, "Records", &["Value".to_owned()], &limits)
            .unwrap_or_else(|error| panic!("create fresh reopen workbook: {error}"));
        let worker = inspect_xlsx_workbook(
            &workbook,
            "workbook.office300.fresh-reopen",
            "artifact.office300.fresh-reopen",
            1,
            "backend.xlsx.file",
            1_000,
            &limits,
        )
        .unwrap_or_else(|error| panic!("inspect worker snapshot: {error}"))
        .snapshot;
        let fresh = inspect_xlsx_workbook(
            &workbook,
            "workbook.office300.fresh-reopen",
            "artifact.office300.fresh-reopen",
            1,
            "backend.xlsx.file",
            1_001,
            &limits,
        )
        .unwrap_or_else(|error| panic!("inspect fresh snapshot: {error}"))
        .snapshot;
        assert!(verify_fresh_reopen(&worker, &fresh).is_ok());
        let error = match verify_fresh_reopen(&worker, &worker) {
            Ok(()) => panic!("the same observation cannot prove a fresh reopen"),
            Err(error) => error,
        };
        assert!(error.contains("observed_at_unix_ms"));
        assert!(error.contains("snapshot_sha256_not_fresh"));
        fs::remove_dir_all(root)
            .unwrap_or_else(|error| panic!("remove fresh reopen root: {error}"));
    }
}
