use crate::{
    inspect_docx_document, inspect_hwpx_document, spawn_document_file_worker,
    spawn_word_document_worker, DocumentFileWorkerRequestV1, OfficeWorkspaceStore,
    ResolvedDocumentOperationV1, WordDocumentWorkerRequestV1,
};
use d2i_document_capability::{
    DocumentActivationLedgerV1, DocumentBackendApprovalV1, DocumentBackendDescriptorV1,
    DocumentBackendKindV1, DocumentCapabilityPackV1, DocumentFormatV1, DocumentNodeKindV1,
    DocumentOperationBindingV1, DocumentOperationIntentV1, DocumentOperationReceiptV1,
    DocumentOperationResultV1, DocumentOperationV1, DocumentPostOperationVerificationV1,
    DocumentSemanticDiffV1, DocumentSemanticSnapshotV1, DocumentVerificationStatusV1, ZERO_HASH,
};
use d2i_office_capability::{
    sha256_bytes, validate_hash, validate_id, validate_relative_path_token,
    OfficeWorkspaceProfileV1, WorkspaceRootBindingV1,
};
use d2i_policy_admission::{AdapterKindV1, CognitiveActivationAdmissionV1};
use ed25519_dalek::VerifyingKey;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentAuthorityContextV1 {
    pub organization_id: String,
    pub environment_id: String,
    pub role_id: String,
    pub role_scope_id: String,
    pub role_contract_sha256: String,
    pub role_instance_sha256: String,
    pub case_id: String,
    pub case_sha256: String,
    pub lease_sha256: String,
    pub work_grant_sha256: String,
    pub authority_sha256: String,
    pub application_pack_sha256: String,
    pub capability_binding_sha256: String,
}

pub struct DocumentDispatchV1<'a> {
    pub intent: &'a DocumentOperationIntentV1,
    pub binding: &'a DocumentOperationBindingV1,
    pub admission: &'a CognitiveActivationAdmissionV1,
    pub source_snapshot: &'a DocumentSemanticSnapshotV1,
    pub capability_pack: &'a DocumentCapabilityPackV1,
    pub backend: &'a DocumentBackendDescriptorV1,
    pub backend_approval: &'a DocumentBackendApprovalV1,
    pub backend_approval_key: &'a VerifyingKey,
    pub authority: &'a DocumentAuthorityContextV1,
    pub source_relative_path: &'a str,
    pub destination_relative_path: &'a str,
    pub resolved_operation: &'a ResolvedDocumentOperationV1,
    pub application_binary_sha256: Option<&'a str>,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentDispatchOutcomeV1 {
    pub receipt: DocumentOperationReceiptV1,
    pub semantic_diff: DocumentSemanticDiffV1,
    pub verification: DocumentPostOperationVerificationV1,
    pub fresh_snapshot: DocumentSemanticSnapshotV1,
    pub workspace_store_terminal_sha256: String,
}

pub struct DocumentKrnDispatcherV1 {
    root: PathBuf,
    root_binding: WorkspaceRootBindingV1,
    workspace_profile: OfficeWorkspaceProfileV1,
    file_worker_executable: PathBuf,
    file_worker_sha256: String,
    word_worker_executable: PathBuf,
    word_worker_sha256: String,
    word_executable: PathBuf,
    word_executable_sha256: String,
    activation_ledger: DocumentActivationLedgerV1,
}

pub struct DocumentKrnDispatcherConfigurationV1 {
    pub root: PathBuf,
    pub root_binding: WorkspaceRootBindingV1,
    pub workspace_profile: OfficeWorkspaceProfileV1,
    pub workspace_profile_key: VerifyingKey,
    pub file_worker_executable: PathBuf,
    pub expected_file_worker_sha256: String,
    pub word_worker_executable: PathBuf,
    pub expected_word_worker_sha256: String,
    pub word_executable: PathBuf,
    pub expected_word_executable_sha256: String,
    pub now_unix_ms: u64,
}

impl DocumentKrnDispatcherV1 {
    pub fn new(configuration: DocumentKrnDispatcherConfigurationV1) -> Result<Self, String> {
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
            "document file worker",
        )?;
        verify_executable(
            &configuration.word_worker_executable,
            &configuration.expected_word_worker_sha256,
            "Word worker",
        )?;
        verify_executable(
            &configuration.word_executable,
            &configuration.expected_word_executable_sha256,
            "WINWORD",
        )?;
        Ok(Self {
            root: configuration.root,
            root_binding: configuration.root_binding,
            workspace_profile: configuration.workspace_profile,
            file_worker_executable: configuration.file_worker_executable,
            file_worker_sha256: configuration.expected_file_worker_sha256,
            word_worker_executable: configuration.word_worker_executable,
            word_worker_sha256: configuration.expected_word_worker_sha256,
            word_executable: configuration.word_executable,
            word_executable_sha256: configuration.expected_word_executable_sha256,
            activation_ledger: DocumentActivationLedgerV1::default(),
        })
    }

    pub fn execute(
        &mut self,
        dispatch: DocumentDispatchV1<'_>,
        store: &mut OfficeWorkspaceStore,
    ) -> Result<DocumentDispatchOutcomeV1, String> {
        validate_dispatch(&dispatch, &self.workspace_profile, &self.root_binding)?;
        verify_workspace_boundary(
            &self.root,
            &self.root_binding,
            &self.workspace_profile,
            dispatch.now_unix_ms,
        )?;
        let source = resolve_relative(&self.root, dispatch.source_relative_path, false)?;
        let destination = resolve_relative(&self.root, dispatch.destination_relative_path, true)?;
        if destination.exists() || source == destination {
            return Err("document mutation destination must be a new generation".to_owned());
        }
        let source_sha256 = sha256_bytes(&fs::read(&source).map_err(|error| error.to_string())?);
        if source_sha256 != dispatch.binding.artifact_content_sha256
            || source_sha256 != dispatch.source_snapshot.source_content_sha256
        {
            return Err("document source bytes differ from the bound snapshot".to_owned());
        }
        let (worker, worker_sha256) = match dispatch.backend.backend_kind {
            DocumentBackendKindV1::HwpxFile | DocumentBackendKindV1::DocxFile => {
                (&self.file_worker_executable, &self.file_worker_sha256)
            }
            DocumentBackendKindV1::WordCom => {
                if dispatch.application_binary_sha256 != Some(self.word_executable_sha256.as_str())
                {
                    return Err("Word binary hash differs from the dispatch".to_owned());
                }
                (&self.word_worker_executable, &self.word_worker_sha256)
            }
            DocumentBackendKindV1::HancomAutomation => {
                return Err(
                    "Hancom Automation is disabled without licensed backend evidence".to_owned(),
                )
            }
        };
        if dispatch.binding.worker_sha256 != *worker_sha256
            || dispatch.backend.worker_artifact_sha256 != *worker_sha256
        {
            return Err("document worker differs from descriptor or binding".to_owned());
        }
        verify_executable(worker, worker_sha256, "document worker")?;
        self.activation_ledger
            .consume(
                dispatch.binding,
                &dispatch.admission.policy_decision_sha256,
                &dispatch.admission.admission_sha256,
                dispatch.now_unix_ms,
            )
            .map_err(|error| error.to_string())?;
        let started_at = dispatch.now_unix_ms;
        let (worker_snapshot, bytes_written, application_receipt_ids) =
            match dispatch.backend.backend_kind {
                DocumentBackendKindV1::HwpxFile | DocumentBackendKindV1::DocxFile => {
                    let response = spawn_document_file_worker(
                        worker,
                        worker_sha256,
                        &DocumentFileWorkerRequestV1 {
                            schema_version: 1,
                            request_id: dispatch.binding.one_time_use_id.clone(),
                            source_path: source.to_string_lossy().to_string(),
                            destination_path: destination.to_string_lossy().to_string(),
                            expected_source_sha256: source_sha256.clone(),
                            format_id: dispatch.source_snapshot.format_id,
                            document_id: dispatch.source_snapshot.document_id.clone(),
                            artifact_id: dispatch.source_snapshot.artifact_id.clone(),
                            generation: dispatch.binding.expected_output_generation,
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
                    )?;
                    (response.snapshot, response.bytes_written, Vec::new())
                }
                DocumentBackendKindV1::WordCom => {
                    let response = spawn_word_document_worker(
                        worker,
                        worker_sha256,
                        &self.word_executable,
                        &WordDocumentWorkerRequestV1 {
                            schema_version: 1,
                            request_id: dispatch.binding.one_time_use_id.clone(),
                            source_path: source.to_string_lossy().to_string(),
                            destination_path: destination.to_string_lossy().to_string(),
                            expected_source_sha256: source_sha256.clone(),
                            document_id: dispatch.source_snapshot.document_id.clone(),
                            artifact_id: dispatch.source_snapshot.artifact_id.clone(),
                            generation: dispatch.binding.expected_output_generation,
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
                    )?;
                    let bytes_written = fs::metadata(&destination)
                        .map_err(|error| error.to_string())?
                        .len();
                    (
                        response.snapshot,
                        bytes_written,
                        vec![format!(
                            "word-process-{}",
                            response.mutation_receipt.word_process_id
                        )],
                    )
                }
                DocumentBackendKindV1::HancomAutomation => {
                    return Err("unreachable Hancom backend dispatch".to_owned())
                }
            };
        let fresh_snapshot = inspect_destination(
            &destination,
            dispatch.source_snapshot,
            dispatch.binding.expected_output_generation,
            &dispatch.backend.backend_id,
            dispatch.now_unix_ms.saturating_add(2),
            &dispatch.capability_pack.resource_limits,
        )?;
        if worker_snapshot.source_content_sha256 != fresh_snapshot.source_content_sha256
            || worker_snapshot.semantic_state_sha256 != fresh_snapshot.semantic_state_sha256
            || worker_snapshot.ordered_nodes != fresh_snapshot.ordered_nodes
            || worker_snapshot.table_refs != fresh_snapshot.table_refs
            || worker_snapshot.image_refs != fresh_snapshot.image_refs
            || worker_snapshot.page_layout_summary != fresh_snapshot.page_layout_summary
            || !operation_effect_verified(
                dispatch.source_snapshot,
                &fresh_snapshot,
                dispatch.resolved_operation,
            )
        {
            return Err("fresh document verification differs from the requested effect".to_owned());
        }
        let receipt = DocumentOperationReceiptV1 {
            schema_version: 1,
            receipt_id: format!("receipt.{}", dispatch.binding.one_time_use_id),
            binding_sha256: dispatch.binding.binding_sha256.clone(),
            backend_id: dispatch.backend.backend_id.clone(),
            worker_sha256: worker_sha256.clone(),
            operation: dispatch.intent.operation,
            pre_generation: dispatch.binding.artifact_generation,
            post_generation: dispatch.binding.expected_output_generation,
            pre_content_sha256: source_sha256,
            post_content_sha256: fresh_snapshot.source_content_sha256.clone(),
            pre_semantic_sha256: dispatch.source_snapshot.semantic_state_sha256.clone(),
            post_semantic_sha256: fresh_snapshot.semantic_state_sha256.clone(),
            bytes_written,
            application_receipt_ids,
            started_at_unix_ms: started_at,
            completed_at_unix_ms: dispatch.now_unix_ms.saturating_add(3),
            result_class: DocumentOperationResultV1::Verified,
            receipt_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())?;
        let semantic_diff = build_semantic_diff(
            &dispatch.binding.one_time_use_id,
            dispatch.source_snapshot,
            &fresh_snapshot,
        )?;
        let verification = DocumentPostOperationVerificationV1 {
            schema_version: 1,
            verification_id: format!("verification.{}", dispatch.binding.one_time_use_id),
            receipt_sha256: receipt.receipt_sha256.clone(),
            fresh_snapshot_sha256: fresh_snapshot.snapshot_sha256.clone(),
            required_postcondition_ids: dispatch.intent.required_postcondition_ids.clone(),
            passed_postcondition_ids: dispatch.intent.required_postcondition_ids.clone(),
            failed_postcondition_ids: Vec::new(),
            semantic_diff_sha256: semantic_diff.diff_sha256.clone(),
            status: DocumentVerificationStatusV1::Verified,
            verification_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())?;
        for (kind, id, artifact) in [
            (
                "semantic-snapshot",
                format!("snapshot.{}", dispatch.binding.one_time_use_id),
                serde_json::to_value(&fresh_snapshot).map_err(|error| error.to_string())?,
            ),
            (
                "operation-receipt",
                format!("receipt.{}", dispatch.binding.one_time_use_id),
                serde_json::to_value(&receipt).map_err(|error| error.to_string())?,
            ),
            (
                "semantic-diff",
                format!("diff.{}", dispatch.binding.one_time_use_id),
                serde_json::to_value(&semantic_diff).map_err(|error| error.to_string())?,
            ),
            (
                "document-verification",
                format!("verification.{}", dispatch.binding.one_time_use_id),
                serde_json::to_value(&verification).map_err(|error| error.to_string())?,
            ),
        ] {
            store.append(kind, &id, &artifact, dispatch.now_unix_ms.saturating_add(4))?;
        }
        Ok(DocumentDispatchOutcomeV1 {
            receipt,
            semantic_diff,
            verification,
            fresh_snapshot,
            workspace_store_terminal_sha256: store.verification().terminal_sha256.clone(),
        })
    }
}

fn validate_dispatch(
    dispatch: &DocumentDispatchV1<'_>,
    profile: &OfficeWorkspaceProfileV1,
    root_binding: &WorkspaceRootBindingV1,
) -> Result<(), String> {
    dispatch
        .intent
        .validate_integrity()
        .map_err(|error| error.to_string())?;
    dispatch
        .binding
        .validate_integrity()
        .map_err(|error| error.to_string())?;
    dispatch
        .source_snapshot
        .validate_integrity()
        .map_err(|error| error.to_string())?;
    dispatch
        .capability_pack
        .validate_integrity()
        .map_err(|error| error.to_string())?;
    dispatch
        .backend
        .validate_integrity()
        .map_err(|error| error.to_string())?;
    dispatch
        .backend_approval
        .validate_signature(dispatch.backend_approval_key)
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
    let capability = document_capability(dispatch.intent.operation);
    let operation = resolved_operation_kind(dispatch.resolved_operation);
    let application_hashes_match = match dispatch.application_binary_sha256 {
        Some(hash) => dispatch
            .backend_approval
            .application_binary_sha256s
            .contains(&hash.to_owned()),
        None => dispatch
            .backend_approval
            .application_binary_sha256s
            .is_empty(),
    };
    if dispatch.intent.operation != operation
        || dispatch.intent.case_id != dispatch.authority.case_id
        || dispatch.intent.document_artifact_id != dispatch.source_snapshot.artifact_id
        || dispatch.intent.document_generation != dispatch.source_snapshot.artifact_generation
        || dispatch.intent.semantic_state_sha256 != dispatch.source_snapshot.semantic_state_sha256
        || dispatch.binding.artifact_id != dispatch.source_snapshot.artifact_id
        || dispatch.binding.artifact_generation != dispatch.source_snapshot.artifact_generation
        || dispatch.binding.semantic_snapshot_sha256 != dispatch.source_snapshot.snapshot_sha256
        || dispatch.binding.operation_intent_sha256 != dispatch.intent.intent_sha256
        || dispatch.binding.capability_pack_sha256 != dispatch.capability_pack.pack_sha256
        || dispatch.binding.backend_descriptor_sha256 != dispatch.backend.backend_sha256
        || dispatch.binding.backend_approval_sha256 != dispatch.backend_approval.approval_sha256
        || dispatch.binding.policy_decision_sha256 != dispatch.admission.policy_decision_sha256
        || dispatch.binding.cognitive_activation_admission_sha256
            != dispatch.admission.admission_sha256
        || dispatch.binding.role_contract_sha256 != dispatch.authority.role_contract_sha256
        || dispatch.binding.role_instance_sha256 != dispatch.authority.role_instance_sha256
        || dispatch.binding.case_sha256 != dispatch.authority.case_sha256
        || dispatch.binding.lease_sha256 != dispatch.authority.lease_sha256
        || dispatch.binding.work_grant_sha256 != dispatch.authority.work_grant_sha256
        || dispatch.binding.workspace_profile_sha256 != profile.profile_sha256
        || dispatch.binding.workspace_root_binding_sha256 != root_binding.binding_sha256
        || dispatch.admission.adapter_kind != AdapterKindV1::OfficeDocument
        || dispatch.admission.capability_id != capability
        || dispatch.admission.authority_sha256 != dispatch.authority.authority_sha256
        || dispatch.admission.application_pack_sha256 != dispatch.authority.application_pack_sha256
        || dispatch.admission.capability_binding_sha256
            != dispatch.authority.capability_binding_sha256
        || dispatch.backend_approval.organization_id != dispatch.authority.organization_id
        || !dispatch
            .backend_approval
            .environment_ids
            .contains(&dispatch.authority.environment_id)
        || !dispatch
            .backend_approval
            .role_ids
            .contains(&dispatch.authority.role_id)
        || dispatch.backend_approval.backend_descriptor_sha256 != dispatch.backend.backend_sha256
        || dispatch.backend_approval.capability_pack_sha256 != dispatch.capability_pack.pack_sha256
        || !dispatch
            .backend_approval
            .allowed_formats
            .contains(&dispatch.source_snapshot.format_id)
        || !dispatch
            .backend_approval
            .allowed_operations
            .contains(&dispatch.intent.operation)
        || !application_hashes_match
        || !dispatch
            .capability_pack
            .supported_format_ids
            .contains(&dispatch.source_snapshot.format_id)
        || !dispatch
            .capability_pack
            .semantic_operations
            .contains(&dispatch.intent.operation)
        || !dispatch
            .capability_pack
            .backend_descriptor_sha256s
            .contains(&dispatch.backend.backend_sha256)
        || !dispatch
            .backend
            .supported_formats
            .contains(&dispatch.source_snapshot.format_id)
        || !dispatch
            .backend
            .supported_operations
            .contains(&dispatch.intent.operation)
        || profile.organization_id != dispatch.authority.organization_id
        || !profile
            .role_scope_ids
            .contains(&dispatch.authority.role_scope_id)
        || dispatch.source_snapshot.freshness_expires_at_unix_ms < dispatch.now_unix_ms
        || dispatch.admission.admitted_at_unix_seconds > dispatch.now_unix_ms / 1_000
        || dispatch.now_unix_ms / 1_000 >= dispatch.admission.expires_at_unix_seconds
        || dispatch.backend_approval.valid_from_unix_ms > dispatch.now_unix_ms
        || dispatch.now_unix_ms > dispatch.backend_approval.valid_until_unix_ms
    {
        return Err("document dispatch differs from an exact authority binding".to_owned());
    }
    Ok(())
}

fn validate_authority(authority: &DocumentAuthorityContextV1) -> Result<(), String> {
    for (value, label) in [
        (&authority.organization_id, "organization"),
        (&authority.environment_id, "environment"),
        (&authority.role_id, "role"),
        (&authority.role_scope_id, "role scope"),
        (&authority.case_id, "case"),
    ] {
        validate_id(value, label).map_err(|error| error.to_string())?;
    }
    for (value, label) in [
        (&authority.role_contract_sha256, "role contract"),
        (&authority.role_instance_sha256, "role instance"),
        (&authority.case_sha256, "case"),
        (&authority.lease_sha256, "lease"),
        (&authority.work_grant_sha256, "work grant"),
        (&authority.authority_sha256, "authority"),
        (&authority.application_pack_sha256, "application pack"),
        (&authority.capability_binding_sha256, "capability binding"),
    ] {
        validate_hash(value, label).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn verify_workspace_boundary(
    root: &Path,
    binding: &WorkspaceRootBindingV1,
    profile: &OfficeWorkspaceProfileV1,
    now_unix_ms: u64,
) -> Result<(), String> {
    if !root.is_dir()
        || d2i_windows_host::is_reparse_point(root).map_err(|error| error.to_string())?
        || binding.workspace_id != profile.workspace_id
        || profile.workspace_root_binding_sha256 != binding.binding_sha256
        || !(binding.valid_from_unix_ms <= now_unix_ms && now_unix_ms < binding.valid_until_unix_ms)
        || !(profile.valid_from_unix_ms <= now_unix_ms && now_unix_ms < profile.valid_until_unix_ms)
    {
        return Err("document workspace root binding is unavailable or stale".to_owned());
    }
    let canonical = root.canonicalize().map_err(|error| error.to_string())?;
    if normalized_path(&canonical) != normalized_text(&binding.canonical_root)
        || sha256_bytes(normalized_path(&canonical).to_ascii_lowercase().as_bytes())
            != binding.root_identity
        || sha256_bytes(
            &d2i_windows_host::path_security_descriptor(root).map_err(|error| error.to_string())?,
        ) != binding.security_descriptor_sha256
    {
        return Err("document workspace root identity differs".to_owned());
    }
    Ok(())
}

fn verify_executable(path: &Path, expected_sha256: &str, label: &str) -> Result<(), String> {
    validate_hash(expected_sha256, label).map_err(|error| error.to_string())?;
    if !path.is_file()
        || d2i_windows_host::is_reparse_point(path).map_err(|error| error.to_string())?
        || sha256_bytes(&fs::read(path).map_err(|error| error.to_string())?) != expected_sha256
    {
        return Err(format!("{label} executable identity differs"));
    }
    Ok(())
}

fn resolve_relative(root: &Path, relative: &str, allow_missing: bool) -> Result<PathBuf, String> {
    validate_relative_path_token(relative).map_err(|error| error.to_string())?;
    let relative_path = Path::new(relative);
    if relative_path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("document path token contains a non-normal component".to_owned());
    }
    let candidate = root.join(relative_path);
    let existing = if allow_missing {
        candidate
            .parent()
            .ok_or_else(|| "document destination parent missing".to_owned())?
            .canonicalize()
            .map_err(|error| error.to_string())?
    } else {
        candidate
            .canonicalize()
            .map_err(|error| error.to_string())?
    };
    let canonical_root = root.canonicalize().map_err(|error| error.to_string())?;
    if !existing.starts_with(&canonical_root)
        || d2i_windows_host::is_reparse_point(&existing).map_err(|error| error.to_string())?
    {
        return Err("document path escapes the workspace root".to_owned());
    }
    Ok(candidate)
}

fn inspect_destination(
    path: &Path,
    source: &DocumentSemanticSnapshotV1,
    generation: u64,
    backend_id: &str,
    observed_at_unix_ms: u64,
    limits: &d2i_document_capability::DocumentResourceLimitsV1,
) -> Result<DocumentSemanticSnapshotV1, String> {
    match source.format_id {
        DocumentFormatV1::Hwpx => inspect_hwpx_document(
            path,
            &source.document_id,
            &source.artifact_id,
            generation,
            backend_id,
            observed_at_unix_ms,
            limits,
        ),
        DocumentFormatV1::Docx => inspect_docx_document(
            path,
            &source.document_id,
            &source.artifact_id,
            generation,
            backend_id,
            observed_at_unix_ms,
            limits,
        ),
        DocumentFormatV1::Hwp | DocumentFormatV1::Doc => {
            Err("legacy binary document inspection requires conversion".to_owned())
        }
    }
}

fn operation_effect_verified(
    before: &DocumentSemanticSnapshotV1,
    after: &DocumentSemanticSnapshotV1,
    operation: &ResolvedDocumentOperationV1,
) -> bool {
    if before.artifact_generation.saturating_add(1) != after.artifact_generation
        || before.source_content_sha256 == after.source_content_sha256
        || before.semantic_state_sha256 == after.semantic_state_sha256
    {
        return false;
    }
    match operation {
        ResolvedDocumentOperationV1::AppendParagraph { text, .. } => contains_text(after, text),
        ResolvedDocumentOperationV1::InsertHeading { text, .. } => {
            contains_text(after, text)
                && after
                    .ordered_nodes
                    .iter()
                    .any(|node| node.node_kind == DocumentNodeKindV1::Heading)
        }
        ResolvedDocumentOperationV1::ReplaceText {
            target_node_id,
            expected_old_text_sha256,
            replacement_text,
            ..
        } => {
            before.ordered_nodes.iter().any(|node| {
                node.node_id == *target_node_id
                    && node.text_sha256.as_deref() == Some(expected_old_text_sha256)
            }) && after.ordered_nodes.iter().any(|node| {
                node.node_id == *target_node_id
                    && node.text_sha256.as_deref()
                        == Some(sha256_bytes(replacement_text.as_bytes()).as_str())
            })
        }
        ResolvedDocumentOperationV1::ApplyParagraphStyle { target_node_id, .. } => {
            node_map(before)
                .ok()
                .and_then(|nodes| nodes.get(target_node_id).cloned())
                != node_map(after)
                    .ok()
                    .and_then(|nodes| nodes.get(target_node_id).cloned())
        }
        ResolvedDocumentOperationV1::InsertTable { .. } => {
            after.table_refs.len() == before.table_refs.len().saturating_add(1)
        }
        ResolvedDocumentOperationV1::SetTableCell { .. } => {
            after.table_refs.len() == before.table_refs.len()
        }
        ResolvedDocumentOperationV1::InsertImage { .. } => {
            after.image_refs.len() == before.image_refs.len().saturating_add(1)
        }
        ResolvedDocumentOperationV1::SetPageLayout { .. } => {
            before.page_layout_summary != after.page_layout_summary
        }
    }
}

fn contains_text(snapshot: &DocumentSemanticSnapshotV1, text: &str) -> bool {
    let hash = sha256_bytes(text.as_bytes());
    snapshot
        .ordered_nodes
        .iter()
        .any(|node| node.text_sha256.as_deref() == Some(hash.as_str()))
}

fn build_semantic_diff(
    one_time_use_id: &str,
    before: &DocumentSemanticSnapshotV1,
    after: &DocumentSemanticSnapshotV1,
) -> Result<DocumentSemanticDiffV1, String> {
    let before_nodes = node_map(before)?;
    let after_nodes = node_map(after)?;
    let added = after_nodes
        .keys()
        .filter(|id| !before_nodes.contains_key(*id))
        .cloned()
        .collect::<Vec<_>>();
    let removed = before_nodes
        .keys()
        .filter(|id| !after_nodes.contains_key(*id))
        .cloned()
        .collect::<Vec<_>>();
    let changed = before_nodes
        .iter()
        .filter_map(|(id, hash)| {
            after_nodes
                .get(id)
                .filter(|after_hash| *after_hash != hash)
                .map(|_| id.clone())
        })
        .collect::<Vec<_>>();
    DocumentSemanticDiffV1 {
        schema_version: 1,
        diff_id: format!("diff.{one_time_use_id}"),
        added_node_ids: added,
        removed_node_ids: removed,
        changed_node_ids: changed.clone(),
        text_change_ids: changed,
        style_change_ids: Vec::new(),
        table_change_ids: symmetric_ids(&before.table_refs, &after.table_refs),
        image_change_ids: symmetric_ids(&before.image_refs, &after.image_refs),
        layout_change_ids: if before.page_layout_summary == after.page_layout_summary {
            Vec::new()
        } else {
            vec!["page-layout".to_owned()]
        },
        unexpected_change_ids: Vec::new(),
        diff_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn node_map(snapshot: &DocumentSemanticSnapshotV1) -> Result<BTreeMap<String, String>, String> {
    snapshot
        .ordered_nodes
        .iter()
        .map(|node| {
            Ok((
                node.node_id.clone(),
                d2i_document_capability::document_canonical_sha256(node)
                    .map_err(|error| error.to_string())?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()
}

fn symmetric_ids(left: &[String], right: &[String]) -> Vec<String> {
    let left = left.iter().cloned().collect::<BTreeSet<_>>();
    let right = right.iter().cloned().collect::<BTreeSet<_>>();
    left.symmetric_difference(&right).cloned().collect()
}

fn document_capability(operation: DocumentOperationV1) -> &'static str {
    match operation {
        DocumentOperationV1::Inspect => "document.inspect",
        DocumentOperationV1::CreateFromTemplate => "document.create_from_template",
        DocumentOperationV1::AppendParagraph => "document.append_paragraph",
        DocumentOperationV1::InsertHeading => "document.insert_heading",
        DocumentOperationV1::ReplaceText => "document.replace_text",
        DocumentOperationV1::ApplyParagraphStyle => "document.apply_paragraph_style",
        DocumentOperationV1::InsertTable => "document.insert_table",
        DocumentOperationV1::SetTableCell => "document.set_table_cell",
        DocumentOperationV1::InsertImage => "document.insert_image",
        DocumentOperationV1::SetPageLayout => "document.set_page_layout",
        DocumentOperationV1::SaveVersion => "document.save_version",
        DocumentOperationV1::RemoveGeneratedNode => "document.remove_generated_node",
    }
}

fn resolved_operation_kind(operation: &ResolvedDocumentOperationV1) -> DocumentOperationV1 {
    match operation {
        ResolvedDocumentOperationV1::AppendParagraph { .. } => DocumentOperationV1::AppendParagraph,
        ResolvedDocumentOperationV1::InsertHeading { .. } => DocumentOperationV1::InsertHeading,
        ResolvedDocumentOperationV1::ReplaceText { .. } => DocumentOperationV1::ReplaceText,
        ResolvedDocumentOperationV1::ApplyParagraphStyle { .. } => {
            DocumentOperationV1::ApplyParagraphStyle
        }
        ResolvedDocumentOperationV1::InsertTable { .. } => DocumentOperationV1::InsertTable,
        ResolvedDocumentOperationV1::SetTableCell { .. } => DocumentOperationV1::SetTableCell,
        ResolvedDocumentOperationV1::InsertImage { .. } => DocumentOperationV1::InsertImage,
        ResolvedDocumentOperationV1::SetPageLayout { .. } => DocumentOperationV1::SetPageLayout,
    }
}

fn normalized_path(path: &Path) -> String {
    normalized_text(&path.to_string_lossy())
}

fn normalized_text(value: &str) -> String {
    value
        .strip_prefix(r"\\?\")
        .unwrap_or(value)
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase()
}
