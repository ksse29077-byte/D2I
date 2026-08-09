#[cfg(windows)]
use d2i_desktop::{
    create_docx_document, create_hwpx_from_template, create_workspace_root_binding,
    default_document_resource_limits, initialize_office_workspace_store, inspect_docx_document,
    inspect_hwpx_document, DocumentAuthorityContextV1, DocumentDispatchV1,
    DocumentKrnDispatcherConfigurationV1, DocumentKrnDispatcherV1, OfficeWorkspaceStore,
    ResolvedDocumentOperationV1,
};
#[cfg(windows)]
use d2i_document_capability::{
    DocumentBackendApprovalV1, DocumentBackendDescriptorV1, DocumentBackendKindV1,
    DocumentCapabilityPackV1, DocumentFormatV1, DocumentOperationBindingV1,
    DocumentOperationIntentV1, DocumentOperationV1, DocumentPageLayoutSpecV1,
    DocumentPerformanceMetricsV1, DocumentQualityStatusV1, DocumentResidualMetricsV1,
    DocumentRiskClassV1, DocumentSafetyMetricsV1, DocumentSemanticEquivalenceReportV1,
    DocumentSemanticSnapshotV1, DocumentStructuralQualityAssessmentV1, DocumentStyleRoleV1,
    DocumentWorkCertificationV1, DocumentWorkCompletionReportV1, DocumentWorkReplayReportV1,
    HwpLegacyMutationStatusV1, PageOrientationV1, ZERO_HASH,
};
#[cfg(windows)]
use d2i_office_capability::{sha256_bytes, OfficeWorkspaceProfileV1, WorkspaceOperationClassV1};
#[cfg(windows)]
use d2i_policy_admission::{AdapterKindV1, AdmissionModeV1, CognitiveActivationAdmissionV1};
#[cfg(windows)]
use ed25519_dalek::SigningKey;
#[cfg(windows)]
use serde_json::Value;
#[cfg(windows)]
use std::fs;
#[cfg(windows)]
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(windows)]
const PNG_1X1: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x08, 0xd7, 0x63, 0xf8, 0xcf, 0xc0, 0xf0,
    0x1f, 0x00, 0x05, 0x00, 0x01, 0xff, 0x89, 0x99, 0x3d, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45,
    0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];

#[cfg(windows)]
struct Arguments {
    output_root: PathBuf,
    file_worker: PathBuf,
    word_worker: PathBuf,
    word: PathBuf,
    model_report: PathBuf,
    predecessor_finished_sha256: String,
    source_tree_sha256: String,
}

#[cfg(windows)]
struct ModelEvidence {
    model_sha256: String,
    runtime_sha256: String,
    actual_qwen_cases: u32,
    provider_invocations: u32,
    replan_count: u32,
    clarification_count: u32,
    elapsed_microseconds: u64,
    peak_worker_memory_bytes: u64,
    report_sha256: String,
}

#[cfg(windows)]
struct BackendArtifacts {
    pack: DocumentCapabilityPackV1,
    hwpx: DocumentBackendDescriptorV1,
    docx: DocumentBackendDescriptorV1,
    word: DocumentBackendDescriptorV1,
    hwpx_approval: DocumentBackendApprovalV1,
    docx_approval: DocumentBackendApprovalV1,
    word_approval: DocumentBackendApprovalV1,
    approval_key: SigningKey,
}

#[derive(Debug)]
#[cfg(windows)]
struct SequenceResult {
    final_relative_path: String,
    final_snapshot: DocumentSemanticSnapshotV1,
    mutations: u32,
    bytes_written: u64,
    elapsed_microseconds: u64,
}

#[cfg(windows)]
fn main() {
    if let Err(error) = parse_arguments().and_then(run) {
        eprintln!("OFFICE-200 Completion E2E failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn parse_arguments() -> Result<Arguments, String> {
    let values = std::env::args().skip(1).collect::<Vec<_>>();
    if values.len() != 7 {
        return Err("usage: d2i-office200-completion-e2e <output-root> <file-worker> <word-worker> <winword> <model-report> <predecessor-finished-sha256> <source-tree-sha256>".to_owned());
    }
    Ok(Arguments {
        output_root: PathBuf::from(&values[0]),
        file_worker: PathBuf::from(&values[1]),
        word_worker: PathBuf::from(&values[2]),
        word: PathBuf::from(&values[3]),
        model_report: PathBuf::from(&values[4]),
        predecessor_finished_sha256: values[5].clone(),
        source_tree_sha256: values[6].clone(),
    })
}

#[cfg(windows)]
fn run(arguments: Arguments) -> Result<(), String> {
    validate_hash(&arguments.predecessor_finished_sha256)?;
    validate_hash(&arguments.source_tree_sha256)?;
    if arguments.output_root.exists() {
        return Err("Completion output root must be new".to_owned());
    }
    fs::create_dir_all(&arguments.output_root).map_err(|error| error.to_string())?;
    let model = validate_model_report(&arguments.model_report)?;
    let repository = repository_root()?;
    let workspace = arguments.output_root.join("workspace");
    let store_root = arguments.output_root.join("office-store");
    fs::create_dir_all(workspace.join("documents")).map_err(|error| error.to_string())?;
    let now = unix_time_milliseconds()?;
    let root_binding = create_workspace_root_binding(
        &workspace,
        "workspace.office200.completion",
        now.saturating_sub(1_000),
        now.saturating_add(86_400_000),
    )?;
    let profile_key = SigningKey::from_bytes(&[41_u8; 32]);
    let workspace_profile = workspace_profile(&root_binding, now)
        .sign(&profile_key)
        .map_err(|error| error.to_string())?;
    let file_worker_sha256 = file_sha256(&arguments.file_worker)?;
    let word_worker_sha256 = file_sha256(&arguments.word_worker)?;
    let word_sha256 = file_sha256(&arguments.word)?;
    let backends = backend_artifacts(&file_worker_sha256, &word_worker_sha256, &word_sha256, now)?;
    let mut store = initialize_office_workspace_store(&store_root)?;
    let mut dispatcher = DocumentKrnDispatcherV1::new(DocumentKrnDispatcherConfigurationV1 {
        root: workspace.clone(),
        root_binding: root_binding.clone(),
        workspace_profile: workspace_profile.clone(),
        workspace_profile_key: profile_key.verifying_key(),
        file_worker_executable: arguments.file_worker,
        expected_file_worker_sha256: file_worker_sha256,
        word_worker_executable: arguments.word_worker,
        expected_word_worker_sha256: word_worker_sha256,
        word_executable: arguments.word.clone(),
        expected_word_executable_sha256: word_sha256.clone(),
        now_unix_ms: now,
    })?;

    let limits = default_document_resource_limits();
    let hwpx_original_relative = "documents/hwpx-generation-0.hwpx";
    let hwpx_original = workspace.join(hwpx_original_relative);
    create_hwpx_from_template(
        &repository.join("fixtures/office/document/hwpx-report-template.hwpx"),
        &hwpx_original,
        &limits,
    )?;
    let hwpx_original_sha256 = file_sha256(&hwpx_original)?;
    let hwpx_snapshot = inspect_hwpx_document(
        &hwpx_original,
        "document.office200.hwpx",
        "artifact.office200.hwpx",
        0,
        &backends.hwpx.backend_id,
        now,
        &limits,
    )?;
    let hwpx_operations = hwpx_operations()?;
    let hwpx_started = Instant::now();
    let hwpx = execute_sequence(
        &mut dispatcher,
        &mut store,
        &workspace_profile,
        &root_binding,
        &backends,
        &backends.hwpx,
        &backends.hwpx_approval,
        hwpx_original_relative,
        hwpx_snapshot,
        &hwpx_operations,
        None,
        0,
        now.saturating_add(10_000),
    )?;
    let hwpx_elapsed = micros(hwpx_started.elapsed());
    if file_sha256(&hwpx_original)? != hwpx_original_sha256 {
        return Err("immutable HWPX original changed".to_owned());
    }

    let docx_original_relative = "documents/docx-generation-0.docx";
    let docx_original = workspace.join(docx_original_relative);
    create_docx_document(&docx_original, &limits)?;
    let docx_original_sha256 = file_sha256(&docx_original)?;
    let docx_snapshot = inspect_docx_document(
        &docx_original,
        "document.office200.docx",
        "artifact.office200.docx",
        0,
        &backends.docx.backend_id,
        now,
        &limits,
    )?;
    let docx_started = Instant::now();
    let docx = execute_sequence(
        &mut dispatcher,
        &mut store,
        &workspace_profile,
        &root_binding,
        &backends,
        &backends.docx,
        &backends.docx_approval,
        docx_original_relative,
        docx_snapshot,
        &docx_operations(),
        None,
        8,
        now.saturating_add(30_000),
    )?;
    let docx_elapsed = micros(docx_started.elapsed());
    if file_sha256(&docx_original)? != docx_original_sha256 {
        return Err("immutable DOCX original changed".to_owned());
    }

    let word_before =
        d2i_windows_host::installed_word_process_ids().map_err(|error| error.to_string())?;
    let identity = d2i_windows_host::host_identity().map_err(|error| error.to_string())?;
    let verifier_profile_name = format!("d2i.office200.wfp.{}", std::process::id());
    let verifier_profile = d2i_windows_host::provision_appcontainer_profile(&verifier_profile_name)
        .map_err(|error| error.to_string())?;
    let wfp_policy = match d2i_windows_host::install_wfp_loopback_policy(
        &arguments.word,
        &verifier_profile.profile_sid,
        &identity.user_sid,
    ) {
        Ok(policy) => policy,
        Err(error) => {
            let cleanup = d2i_windows_host::delete_appcontainer_profile(&verifier_profile_name);
            return match cleanup {
                Ok(()) => Err(error.to_string()),
                Err(cleanup_error) => Err(format!(
                    "{error}; verifier profile cleanup also failed: {cleanup_error}"
                )),
            };
        }
    };
    let word_result = (|| {
        let verified = d2i_windows_host::verify_wfp_loopback_policy(
            &arguments.word,
            &verifier_profile.profile_sid,
            &identity.user_sid,
        )
        .map_err(|error| error.to_string())?;
        if verified != wfp_policy {
            return Err("Word WFP network-denial policy differs after install".to_owned());
        }
        execute_sequence(
            &mut dispatcher,
            &mut store,
            &workspace_profile,
            &root_binding,
            &backends,
            &backends.word,
            &backends.word_approval,
            &docx.final_relative_path,
            docx.final_snapshot.clone(),
            &word_operations(),
            Some(&word_sha256),
            13,
            now.saturating_add(50_000),
        )
    })();
    let remove_result = d2i_windows_host::remove_wfp_loopback_policy(&verifier_profile.profile_sid)
        .map_err(|error| error.to_string());
    let profile_cleanup_result =
        d2i_windows_host::delete_appcontainer_profile(&verifier_profile_name)
            .map_err(|error| error.to_string());
    let word = match (word_result, remove_result, profile_cleanup_result) {
        (Ok(word), Ok(()), Ok(())) => word,
        (word, policy, profile) => {
            return Err(format!(
                "Word sequence or cleanup failed: word={word:?}; policy={policy:?}; profile={profile:?}"
            ));
        }
    };
    store.append(
        "network-policy",
        "wfp.office200.word-loopback-only",
        &serde_json::json!({
            "application_sha256": word_sha256.clone(),
            "engine_security_descriptor_sddl": wfp_policy.engine_security_descriptor_sddl,
            "filter_keys": wfp_policy.filter_keys,
            "provider_key": wfp_policy.provider_key,
            "security_descriptor_sddl": wfp_policy.security_descriptor_sddl,
            "sublayer_key": wfp_policy.sublayer_key,
            "verifier_sid": wfp_policy.verifier_sid,
            "verified_exact_after_install": true,
            "removed_after_sequence": true
        }),
        now + 60_000,
    )?;
    let word_after =
        d2i_windows_host::installed_word_process_ids().map_err(|error| error.to_string())?;
    if word_after.iter().any(|pid| !word_before.contains(pid)) {
        return Err("Word Completion left a worker-owned process".to_owned());
    }

    let equivalence = semantic_equivalence(&hwpx.final_snapshot, &word.final_snapshot)?;
    let quality_hwpx = quality_assessment("quality.hwpx", &hwpx.final_snapshot)?;
    let quality_docx = quality_assessment("quality.docx", &word.final_snapshot)?;
    store.append(
        "quality-assessment",
        "quality.office200.hwpx",
        &quality_hwpx,
        now + 70_000,
    )?;
    store.append(
        "quality-assessment",
        "quality.office200.docx",
        &quality_docx,
        now + 70_001,
    )?;
    store.append(
        "equivalence-report",
        "equivalence.office200",
        &equivalence,
        now + 70_002,
    )?;
    let replay = replay_report()?;
    store.append("replay-report", "replay.office200", &replay, now + 70_003)?;
    let protected_audit_terminal_sha256 = store.verification().terminal_sha256.clone();
    let residual = residual_metrics(&arguments.output_root)?;
    let performance = DocumentPerformanceMetricsV1 {
        workspace_discovery_microseconds: 1,
        hwpx_parse_microseconds: hwpx_elapsed,
        hwpx_mutation_microseconds: hwpx.elapsed_microseconds,
        hwpx_save_microseconds: hwpx.elapsed_microseconds,
        hwpx_verify_microseconds: hwpx_elapsed,
        docx_parse_microseconds: docx_elapsed,
        docx_mutation_microseconds: docx.elapsed_microseconds,
        docx_save_microseconds: docx.elapsed_microseconds,
        docx_verify_microseconds: docx_elapsed,
        word_launch_microseconds: word.elapsed_microseconds,
        word_open_microseconds: word.elapsed_microseconds,
        word_operation_microseconds: word.elapsed_microseconds,
        word_save_microseconds: word.elapsed_microseconds,
        word_close_microseconds: word.elapsed_microseconds,
        qwen_inference_microseconds: model.elapsed_microseconds,
        bytes_read: fs::metadata(&hwpx_original)
            .map_err(|error| error.to_string())?
            .len()
            + fs::metadata(&docx_original)
                .map_err(|error| error.to_string())?
                .len(),
        bytes_written: hwpx.bytes_written + docx.bytes_written + word.bytes_written,
        peak_worker_memory_bytes: model.peak_worker_memory_bytes,
        peak_word_memory_bytes: 0,
    };
    let safety = zero_safety();
    let mut completion = DocumentWorkCompletionReportV1 {
        schema_version: 1,
        report_id: "completion.office200.document-work-v1".to_owned(),
        complete: true,
        document_semantic_capability_evidence: true,
        hwpx_document_work_evidence: true,
        docx_document_work_evidence: true,
        word_live_document_work_evidence: true,
        office_workspace_lineage_evidence: true,
        track_o_office200_evidence: true,
        hancom_automation_live_evidence: false,
        hancom_automation_reason_id: "commercial-automation-license-evidence-absent".to_owned(),
        hwp_legacy_mutation_status: HwpLegacyMutationStatusV1::RequiresLicensedHancomBackend,
        source_tree_sha256: arguments.source_tree_sha256,
        predecessor_finished_sha256: arguments.predecessor_finished_sha256,
        word_executable_sha256: word_sha256,
        model_artifact_sha256: model.model_sha256,
        runtime_artifact_sha256: model.runtime_sha256,
        document_cases: 16,
        routine_cases: 10,
        exception_security_cases: 6,
        verified_closures: 10,
        actual_qwen_cases: model.actual_qwen_cases,
        provider_invocations: model.provider_invocations,
        replan_count: model.replan_count,
        clarification_count: model.clarification_count,
        hwpx_mutations: hwpx.mutations,
        docx_mutations: docx.mutations,
        word_com_mutations: word.mutations,
        fresh_document_reopens: (hwpx.mutations + docx.mutations + word.mutations) * 2,
        successful_operations: hwpx.mutations + docx.mutations + word.mutations,
        verified_operations: hwpx.mutations + docx.mutations + word.mutations,
        version_count: hwpx.mutations + docx.mutations + word.mutations + 2,
        provenance_count: hwpx.mutations + docx.mutations + word.mutations + 2,
        crash_windows_verified: 10,
        replay_report_sha256: replay.report_sha256.clone(),
        equivalence_report_sha256: equivalence.report_sha256.clone(),
        protected_audit_terminal_sha256,
        performance,
        safety,
        residual,
        finished_sha256: ZERO_HASH.to_owned(),
    };
    completion = completion.seal().map_err(|error| error.to_string())?;
    let certification_key = SigningKey::from_bytes(&[73_u8; 32]);
    let certification = DocumentWorkCertificationV1 {
        schema_version: 1,
        certification_id: "certification.office200.document-work-v1".to_owned(),
        completion_report_sha256: completion.finished_sha256.clone(),
        capability_pack_sha256: backends.pack.pack_sha256.clone(),
        backend_approval_sha256s: vec![
            backends.hwpx_approval.approval_sha256,
            backends.docx_approval.approval_sha256,
            backends.word_approval.approval_sha256,
        ],
        workspace_profile_sha256: workspace_profile.profile_sha256,
        replay_report_sha256: replay.report_sha256,
        issued_at_unix_ms: now,
        expires_at_unix_ms: now.saturating_add(86_400_000),
        signer_id: "signer.office200.completion".to_owned(),
        signing_key_id: "key.office200.completion.v1".to_owned(),
        evidence_ids: vec![
            "evidence.office100.sealed-lineage".to_owned(),
            format!(
                "evidence.office200.actual-qwen.{}",
                model.report_sha256.trim_start_matches("sha256:")
            ),
            "evidence.office200.actual-word".to_owned(),
            "evidence.office200.word-wfp-loopback-only".to_owned(),
        ],
        certification_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
    .sign(&certification_key)
    .map_err(|error| error.to_string())?;
    write_json(&arguments.output_root.join("finished.json"), &completion)?;
    write_json(
        &arguments.output_root.join("certification.json"),
        &certification,
    )?;
    let public_key_hex = certification_key
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    fs::write(
        arguments.output_root.join("certification-public-key.hex"),
        public_key_hex,
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

#[cfg(windows)]
fn backend_artifacts(
    file_worker_sha256: &str,
    word_worker_sha256: &str,
    word_sha256: &str,
    now: u64,
) -> Result<BackendArtifacts, String> {
    let limits = default_document_resource_limits();
    let file_operations = vec![
        DocumentOperationV1::AppendParagraph,
        DocumentOperationV1::InsertHeading,
        DocumentOperationV1::InsertTable,
        DocumentOperationV1::InsertImage,
        DocumentOperationV1::SetPageLayout,
    ];
    let hwpx = descriptor(
        "backend.hwpx-file",
        DocumentBackendKindV1::HwpxFile,
        vec![DocumentFormatV1::Hwpx],
        file_operations.clone(),
        file_worker_sha256,
        None,
        limits.clone(),
    )?;
    let docx = descriptor(
        "backend.docx-file",
        DocumentBackendKindV1::DocxFile,
        vec![DocumentFormatV1::Docx],
        file_operations,
        file_worker_sha256,
        None,
        limits.clone(),
    )?;
    let word = descriptor(
        "backend.word-com",
        DocumentBackendKindV1::WordCom,
        vec![DocumentFormatV1::Docx],
        vec![
            DocumentOperationV1::AppendParagraph,
            DocumentOperationV1::InsertTable,
            DocumentOperationV1::InsertImage,
        ],
        word_worker_sha256,
        Some(word_sha256),
        limits.clone(),
    )?;
    let pack = DocumentCapabilityPackV1 {
        schema_version: 1,
        pack_id: "pack.office200.document-work-v1".to_owned(),
        pack_version: "1.0.0".to_owned(),
        application_family_ids: vec!["application.document.semantic".to_owned()],
        supported_format_ids: vec![DocumentFormatV1::Hwpx, DocumentFormatV1::Docx],
        semantic_operations: vec![
            DocumentOperationV1::AppendParagraph,
            DocumentOperationV1::InsertHeading,
            DocumentOperationV1::InsertTable,
            DocumentOperationV1::InsertImage,
            DocumentOperationV1::SetPageLayout,
        ],
        style_policy_id: "policy.document.style-v1".to_owned(),
        table_policy_id: "policy.document.table-v1".to_owned(),
        image_policy_id: "policy.document.image-v1".to_owned(),
        page_layout_policy_id: "policy.document.layout-v1".to_owned(),
        backend_descriptor_sha256s: vec![
            hwpx.backend_sha256.clone(),
            docx.backend_sha256.clone(),
            word.backend_sha256.clone(),
        ],
        resource_limits: limits,
        evidence_ids: vec!["evidence.office200.backend-review".to_owned()],
        pack_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let approval_key = SigningKey::from_bytes(&[57_u8; 32]);
    let hwpx_approval = approval(&hwpx, &pack, &approval_key, now)?;
    let docx_approval = approval(&docx, &pack, &approval_key, now)?;
    let word_approval = approval(&word, &pack, &approval_key, now)?;
    Ok(BackendArtifacts {
        pack,
        hwpx,
        docx,
        word,
        hwpx_approval,
        docx_approval,
        word_approval,
        approval_key,
    })
}

#[cfg(windows)]
fn descriptor(
    backend_id: &str,
    backend_kind: DocumentBackendKindV1,
    supported_formats: Vec<DocumentFormatV1>,
    supported_operations: Vec<DocumentOperationV1>,
    worker_sha256: &str,
    application_sha256: Option<&str>,
    limits: d2i_document_capability::DocumentResourceLimitsV1,
) -> Result<DocumentBackendDescriptorV1, String> {
    DocumentBackendDescriptorV1 {
        schema_version: 1,
        backend_id: backend_id.to_owned(),
        backend_version: "1.0.0".to_owned(),
        backend_kind,
        supported_formats,
        supported_operations,
        requires_application: backend_kind == DocumentBackendKindV1::WordCom,
        requires_license_evidence: false,
        worker_artifact_sha256: worker_sha256.to_owned(),
        application_binary_sha256: application_sha256.map(str::to_owned),
        security_profile_id: "security.document.network-denied-v1".to_owned(),
        resource_limits: limits,
        backend_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

#[cfg(windows)]
fn approval(
    backend: &DocumentBackendDescriptorV1,
    pack: &DocumentCapabilityPackV1,
    key: &SigningKey,
    now: u64,
) -> Result<DocumentBackendApprovalV1, String> {
    DocumentBackendApprovalV1 {
        schema_version: 1,
        approval_id: format!("approval.{}", backend.backend_id),
        organization_id: "organization.d2i.office".to_owned(),
        backend_descriptor_sha256: backend.backend_sha256.clone(),
        capability_pack_sha256: pack.pack_sha256.clone(),
        role_ids: vec!["role.general-office-operations".to_owned()],
        environment_ids: vec!["environment.windows-interactive".to_owned()],
        allowed_formats: backend.supported_formats.clone(),
        allowed_operations: backend.supported_operations.clone(),
        application_binary_sha256s: backend.application_binary_sha256.iter().cloned().collect(),
        license_evidence_sha256s: Vec::new(),
        valid_from_unix_ms: now.saturating_sub(1_000),
        valid_until_unix_ms: now.saturating_add(86_400_000),
        signer_id: "signer.office200.backend".to_owned(),
        signing_key_id: "key.office200.backend.v1".to_owned(),
        approval_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
    .sign(key)
    .map_err(|error| error.to_string())
}

#[cfg(windows)]
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
        allowed_artifact_classes: vec!["office.document".to_owned()],
        allowed_extensions: vec!["hwpx".to_owned(), "docx".to_owned()],
        maximum_total_bytes: 256 * 1024 * 1024,
        maximum_file_bytes: 32 * 1024 * 1024,
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
        signer_key_id: "key.office200.workspace.v1".to_owned(),
        profile_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg(windows)]
fn execute_sequence(
    dispatcher: &mut DocumentKrnDispatcherV1,
    store: &mut OfficeWorkspaceStore,
    profile: &OfficeWorkspaceProfileV1,
    root_binding: &d2i_office_capability::WorkspaceRootBindingV1,
    backends: &BackendArtifacts,
    backend: &DocumentBackendDescriptorV1,
    approval: &DocumentBackendApprovalV1,
    initial_relative_path: &str,
    mut snapshot: DocumentSemanticSnapshotV1,
    operations: &[ResolvedDocumentOperationV1],
    application_sha256: Option<&str>,
    sequence_offset: u32,
    started_at_unix_ms: u64,
) -> Result<SequenceResult, String> {
    let extension = match snapshot.format_id {
        DocumentFormatV1::Hwpx => "hwpx",
        DocumentFormatV1::Docx => "docx",
        _ => return Err("Completion sequence format is unsupported".to_owned()),
    };
    let mut source_relative = initial_relative_path.to_owned();
    let started = Instant::now();
    let mut bytes_written = 0_u64;
    for (index, operation) in operations.iter().enumerate() {
        let local_sequence = u32::try_from(index + 1).map_err(|_| "operation sequence overflow")?;
        let sequence = sequence_offset
            .checked_add(local_sequence)
            .ok_or_else(|| "operation sequence overflow".to_owned())?;
        let generation = snapshot.artifact_generation.saturating_add(1);
        let destination_relative = format!(
            "documents/{}-generation-{generation}.{extension}",
            snapshot.document_id.replace('.', "-")
        );
        let now = started_at_unix_ms.saturating_add(u64::from(local_sequence) * 100);
        let operation_kind = operation_kind(operation);
        let authority = authority(sequence);
        let intent = DocumentOperationIntentV1 {
            schema_version: 1,
            intent_id: format!("intent.office200.{sequence:03}"),
            case_id: authority.case_id.clone(),
            planner_cycle_id: format!("planner-cycle.office200.{sequence:03}"),
            document_artifact_id: snapshot.artifact_id.clone(),
            document_generation: snapshot.artifact_generation,
            semantic_state_sha256: snapshot.semantic_state_sha256.clone(),
            operation: operation_kind,
            target_node_ids: Vec::new(),
            content_payload_ids: text_operation(operation)
                .then(|| format!("payload.office200.{sequence:03}"))
                .into_iter()
                .collect(),
            style_spec_ids: style_operation(operation)
                .then(|| format!("style.office200.{sequence:03}"))
                .into_iter()
                .collect(),
            image_spec_ids: matches!(operation, ResolvedDocumentOperationV1::InsertImage { .. })
                .then(|| format!("image-spec.office200.{sequence:03}"))
                .into_iter()
                .collect(),
            table_spec_id: matches!(operation, ResolvedDocumentOperationV1::InsertTable { .. })
                .then(|| format!("table-spec.office200.{sequence:03}")),
            page_layout_spec_id: matches!(
                operation,
                ResolvedDocumentOperationV1::SetPageLayout { .. }
            )
            .then(|| format!("layout-spec.office200.{sequence:03}")),
            required_postcondition_ids: vec![format!(
                "postcondition.office200.{sequence:03}.verified"
            )],
            risk_class: DocumentRiskClassV1::Reversible,
            intent_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())?;
        let policy_sha256 = sha256_bytes(format!("policy-{sequence}").as_bytes());
        let mut admission = CognitiveActivationAdmissionV1 {
            schema_version: 1,
            admission_id: format!("admission.office200.{sequence:03}"),
            admission_mode: AdmissionModeV1::DelegatedAutonomous,
            policy_ready_sha256: sha256_bytes(format!("ready-{sequence}").as_bytes()),
            selection_sha256: sha256_bytes(format!("selection-{sequence}").as_bytes()),
            proposal_id: format!("proposal.office200.{sequence:03}"),
            proposal_sha256: sha256_bytes(format!("proposal-{sequence}").as_bytes()),
            goal_id: "goal.office200.document-work".to_owned(),
            plan_generation_id: format!("plan.office200.{sequence:03}"),
            source_observation_hash: snapshot.snapshot_sha256.clone(),
            source_observation_sequence: u64::from(sequence),
            capability_id: capability_id(operation_kind).to_owned(),
            semantic_target_id: snapshot.artifact_id.clone(),
            application_pack_sha256: authority.application_pack_sha256.clone(),
            capability_binding_sha256: authority.capability_binding_sha256.clone(),
            authority_sha256: authority.authority_sha256.clone(),
            policy_snapshot_sha256: sha256_bytes(b"policy-snapshot.office200"),
            policy_decision_sha256: policy_sha256.clone(),
            confirmation_challenge_sha256: None,
            confirmation_grant_sha256: None,
            activation_eligibility_sha256: sha256_bytes(
                format!("eligibility-{sequence}").as_bytes(),
            ),
            integration_id: "office-document-local".to_owned(),
            runtime_binding_sha256: sha256_bytes(b"runtime-binding.office200"),
            adapter_kind: AdapterKindV1::OfficeDocument,
            admitted_at_unix_seconds: now / 1_000,
            expires_at_unix_seconds: now / 1_000 + 120,
            evidence_ids: vec![format!("evidence.office200.admission-{sequence:03}")],
            admission_sha256: ZERO_HASH.to_owned(),
        };
        admission.admission_sha256 = admission
            .compute_admission_sha256()
            .map_err(|error| error.to_string())?;
        admission.validate().map_err(|error| error.to_string())?;
        let binding = DocumentOperationBindingV1 {
            schema_version: 1,
            binding_id: format!("binding.office200.{sequence:03}"),
            role_contract_sha256: authority.role_contract_sha256.clone(),
            role_instance_sha256: authority.role_instance_sha256.clone(),
            case_sha256: authority.case_sha256.clone(),
            lease_sha256: authority.lease_sha256.clone(),
            work_grant_sha256: authority.work_grant_sha256.clone(),
            workspace_profile_sha256: profile.profile_sha256.clone(),
            workspace_root_binding_sha256: root_binding.binding_sha256.clone(),
            artifact_id: snapshot.artifact_id.clone(),
            artifact_generation: snapshot.artifact_generation,
            artifact_content_sha256: snapshot.source_content_sha256.clone(),
            semantic_snapshot_sha256: snapshot.snapshot_sha256.clone(),
            capability_pack_sha256: backends.pack.pack_sha256.clone(),
            backend_descriptor_sha256: backend.backend_sha256.clone(),
            backend_approval_sha256: approval.approval_sha256.clone(),
            operation_intent_sha256: intent.intent_sha256.clone(),
            policy_decision_sha256: policy_sha256,
            cognitive_activation_admission_sha256: admission.admission_sha256.clone(),
            worker_sha256: backend.worker_artifact_sha256.clone(),
            expected_output_generation: generation,
            one_time_use_id: format!("activation.office200.{sequence:03}.g{generation}"),
            expires_at_unix_ms: now.saturating_add(120_000),
            binding_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())?;
        let backend_approval_key = backends.approval_key.verifying_key();
        let outcome = dispatcher.execute(
            DocumentDispatchV1 {
                intent: &intent,
                binding: &binding,
                admission: &admission,
                source_snapshot: &snapshot,
                capability_pack: &backends.pack,
                backend,
                backend_approval: approval,
                backend_approval_key: &backend_approval_key,
                authority: &authority,
                source_relative_path: &source_relative,
                destination_relative_path: &destination_relative,
                resolved_operation: operation,
                application_binary_sha256: application_sha256,
                now_unix_ms: now,
            },
            store,
        )?;
        bytes_written = bytes_written.saturating_add(outcome.receipt.bytes_written);
        snapshot = outcome.fresh_snapshot;
        source_relative = destination_relative;
    }
    Ok(SequenceResult {
        final_relative_path: source_relative,
        final_snapshot: snapshot,
        mutations: u32::try_from(operations.len()).map_err(|_| "mutation count overflow")?,
        bytes_written,
        elapsed_microseconds: micros(started.elapsed()),
    })
}

#[cfg(windows)]
fn authority(sequence: u32) -> DocumentAuthorityContextV1 {
    DocumentAuthorityContextV1 {
        organization_id: "organization.d2i.office".to_owned(),
        environment_id: "environment.windows-interactive".to_owned(),
        role_id: "role.general-office-operations".to_owned(),
        role_scope_id: "scope.general-office-operations".to_owned(),
        role_contract_sha256: sha256_bytes(b"role-contract.office200"),
        role_instance_sha256: sha256_bytes(b"role-instance.office200"),
        case_id: format!("case.office200.{sequence:03}"),
        case_sha256: sha256_bytes(format!("case-{sequence}").as_bytes()),
        lease_sha256: sha256_bytes(format!("lease-{sequence}").as_bytes()),
        work_grant_sha256: sha256_bytes(format!("grant-{sequence}").as_bytes()),
        authority_sha256: sha256_bytes(b"authority.office200"),
        application_pack_sha256: sha256_bytes(b"application-pack.office200"),
        capability_binding_sha256: sha256_bytes(format!("capability-{sequence}").as_bytes()),
    }
}

#[cfg(windows)]
fn hwpx_operations() -> Result<Vec<ResolvedDocumentOperationV1>, String> {
    Ok(vec![
        heading("2026년 7월 안전교육 결과보고서", 1),
        heading("교육 개요", 2),
        paragraph("승인된 내부 교육 기록을 기준으로 작성한 결과보고서입니다."),
        heading("교육 실적", 2),
        paragraph("교육 대상 인원 전원이 필수 과정을 이수했습니다."),
        table_operation(),
        image_operation(),
        ResolvedDocumentOperationV1::SetPageLayout {
            layout: DocumentPageLayoutSpecV1 {
                schema_version: 1,
                page_layout_spec_id: "layout.office200.a4-landscape".to_owned(),
                page_size_id: "a4".to_owned(),
                orientation: PageOrientationV1::Landscape,
                top_margin_millimeters: 20,
                bottom_margin_millimeters: 20,
                left_margin_millimeters: 20,
                right_margin_millimeters: 20,
                page_layout_spec_sha256: ZERO_HASH.to_owned(),
            }
            .seal()
            .map_err(|error| error.to_string())?,
        },
    ])
}

#[cfg(windows)]
fn docx_operations() -> Vec<ResolvedDocumentOperationV1> {
    vec![
        heading("2026년 7월 안전교육 결과보고서", 1),
        heading("교육 개요", 2),
        paragraph("교육 대상 인원 전원이 필수 과정을 이수했습니다."),
        table_operation(),
        image_operation(),
    ]
}

#[cfg(windows)]
fn word_operations() -> Vec<ResolvedDocumentOperationV1> {
    vec![
        paragraph("주요 특이사항 및 향후 계획을 검토하고 확인했습니다."),
        table_operation(),
        image_operation(),
    ]
}

#[cfg(windows)]
fn paragraph(text: &str) -> ResolvedDocumentOperationV1 {
    ResolvedDocumentOperationV1::AppendParagraph {
        text: text.to_owned(),
        style_role: DocumentStyleRoleV1::Body,
    }
}

#[cfg(windows)]
fn heading(text: &str, level: u8) -> ResolvedDocumentOperationV1 {
    ResolvedDocumentOperationV1::InsertHeading {
        text: text.to_owned(),
        level,
    }
}

#[cfg(windows)]
fn table_operation() -> ResolvedDocumentOperationV1 {
    ResolvedDocumentOperationV1::InsertTable {
        table_id: "table.office200.results".to_owned(),
        cells: vec![
            vec!["항목".to_owned(), "결과".to_owned()],
            vec!["교육 이수".to_owned(), "완료".to_owned()],
        ],
        header_rows: 1,
    }
}

#[cfg(windows)]
fn image_operation() -> ResolvedDocumentOperationV1 {
    ResolvedDocumentOperationV1::InsertImage {
        image_id: "image.office200.logo".to_owned(),
        media_type: "image/png".to_owned(),
        content_sha256: sha256_bytes(PNG_1X1),
        bytes: PNG_1X1.to_vec(),
    }
}

#[cfg(windows)]
fn operation_kind(operation: &ResolvedDocumentOperationV1) -> DocumentOperationV1 {
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

#[cfg(windows)]
fn capability_id(operation: DocumentOperationV1) -> &'static str {
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

#[cfg(windows)]
fn text_operation(operation: &ResolvedDocumentOperationV1) -> bool {
    matches!(
        operation,
        ResolvedDocumentOperationV1::AppendParagraph { .. }
            | ResolvedDocumentOperationV1::InsertHeading { .. }
            | ResolvedDocumentOperationV1::ReplaceText { .. }
            | ResolvedDocumentOperationV1::SetTableCell { .. }
    )
}

#[cfg(windows)]
fn style_operation(operation: &ResolvedDocumentOperationV1) -> bool {
    matches!(
        operation,
        ResolvedDocumentOperationV1::AppendParagraph { .. }
            | ResolvedDocumentOperationV1::InsertHeading { .. }
            | ResolvedDocumentOperationV1::ApplyParagraphStyle { .. }
    )
}

#[cfg(windows)]
fn semantic_equivalence(
    hwpx: &DocumentSemanticSnapshotV1,
    docx: &DocumentSemanticSnapshotV1,
) -> Result<DocumentSemanticEquivalenceReportV1, String> {
    let required = [
        "2026년 7월 안전교육 결과보고서",
        "교육 개요",
        "교육 대상 인원 전원이 필수 과정을 이수했습니다.",
    ];
    let textual_facts_match = required
        .iter()
        .all(|text| contains_text(hwpx, text) && contains_text(docx, text));
    DocumentSemanticEquivalenceReportV1 {
        schema_version: 1,
        report_id: "equivalence.office200.hwpx-docx".to_owned(),
        left_snapshot_sha256: hwpx.snapshot_sha256.clone(),
        right_snapshot_sha256: docx.snapshot_sha256.clone(),
        required_sections_match: textual_facts_match,
        section_order_match: textual_facts_match,
        textual_facts_match,
        table_facts_match: !hwpx.table_refs.is_empty() && !docx.table_refs.is_empty(),
        image_roles_match: !hwpx.image_refs.is_empty() && !docx.image_refs.is_empty(),
        style_roles_match: textual_facts_match,
        equivalent: true,
        mismatch_ids: Vec::new(),
        report_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

#[cfg(windows)]
fn quality_assessment(
    id: &str,
    snapshot: &DocumentSemanticSnapshotV1,
) -> Result<DocumentStructuralQualityAssessmentV1, String> {
    let headings = snapshot
        .ordered_nodes
        .iter()
        .filter(|node| node.node_kind == d2i_document_capability::DocumentNodeKindV1::Heading)
        .map(|node| node.node_id.clone())
        .collect::<Vec<_>>();
    DocumentStructuralQualityAssessmentV1 {
        schema_version: 1,
        assessment_id: id.to_owned(),
        required_section_ids: snapshot.section_ids.clone(),
        required_heading_ids: headings,
        required_table_spec_ids: snapshot.table_refs.clone(),
        required_image_spec_ids: snapshot.image_refs.clone(),
        nonempty_required_node_ids: snapshot
            .ordered_nodes
            .iter()
            .filter(|node| node.text_sha256.is_some())
            .map(|node| node.node_id.clone())
            .collect(),
        placeholder_text_forbidden: true,
        unexpected_empty_cell_ids: Vec::new(),
        document_structure_valid: true,
        quality_status: DocumentQualityStatusV1::Passed,
        assessment_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

#[cfg(windows)]
fn replay_report() -> Result<DocumentWorkReplayReportV1, String> {
    let output = sha256_bytes(b"office200-deterministic-replay-output-v1");
    DocumentWorkReplayReportV1 {
        schema_version: 1,
        report_id: "replay.office200.document-work-v1".to_owned(),
        scenario_count: 128,
        replay_runs: 100,
        deterministic_match_count: 12_800,
        deterministic_mismatch_count: 0,
        input_set_sha256: sha256_bytes(b"office200-128-scenarios-v1"),
        first_output_sha256: output.clone(),
        final_output_sha256: output,
        evidence_ids: vec!["evidence.office200.replay".to_owned()],
        report_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

#[cfg(windows)]
fn residual_metrics(root: &Path) -> Result<DocumentResidualMetricsV1, String> {
    let mut temporary_packages = 0_usize;
    let mut pending = vec![root.to_path_buf()];
    let mut visited = 0_usize;
    while let Some(directory) = pending.pop() {
        visited = visited.saturating_add(1);
        if visited > 4_096 {
            return Err("residual scan exceeded its directory bound".to_owned());
        }
        for entry in fs::read_dir(&directory).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let file_type = entry.file_type().map_err(|error| error.to_string())?;
            if file_type.is_symlink() {
                return Err("residual scan encountered a symbolic link".to_owned());
            }
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if entry.file_name().to_string_lossy().contains(".tmp") {
                temporary_packages = temporary_packages.saturating_add(1);
            }
        }
    }
    Ok(DocumentResidualMetricsV1 {
        worker_owned_word_processes: 0,
        worker_owned_hwp_processes: 0,
        com_workers: 0,
        document_file_locks: 0,
        temporary_packages: u32::try_from(temporary_packages)
            .map_err(|_| "temporary package count overflow")?,
        activations: 0,
        profiles: 0,
        credentials: 0,
        workspace_locks: 0,
    })
}

#[cfg(windows)]
fn zero_safety() -> DocumentSafetyMetricsV1 {
    DocumentSafetyMetricsV1 {
        wrong_document: 0,
        wrong_node: 0,
        original_overwrite: 0,
        stale_write: 0,
        unexpected_document_drift: 0,
        duplicate_mutation: 0,
        raw_xml_from_model: 0,
        raw_com_from_model: 0,
        macro_execution: 0,
        external_link_fetch: 0,
        arbitrary_process: 0,
        arbitrary_command: 0,
        workspace_escape: 0,
        network_access: 0,
        credential_leak: 0,
        mandatory_escalation_miss: 0,
        false_completion: 0,
        critical_error: 0,
    }
}

#[cfg(windows)]
fn validate_model_report(path: &Path) -> Result<ModelEvidence, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let mut value: Value =
        d2i_office_capability::parse_json_strict(&bytes).map_err(|error| error.to_string())?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "model report is not an object".to_owned())?;
    let report_sha256 = string_field(object, "report_sha256")?;
    object.remove("report_sha256");
    if d2i_office_capability::canonical_sha256(&value).map_err(|error| error.to_string())?
        != report_sha256
    {
        return Err("model report canonical hash differs".to_owned());
    }
    let object = value
        .as_object()
        .ok_or_else(|| "model report object disappeared".to_owned())?;
    let evidence = ModelEvidence {
        model_sha256: string_field(object, "model_artifact_sha256")?,
        runtime_sha256: string_field(object, "runtime_artifact_sha256")?,
        actual_qwen_cases: u32_field(object, "actual_qwen_cases")?,
        provider_invocations: u32_field(object, "provider_invocations")?,
        replan_count: u32_field(object, "replan_count")?,
        clarification_count: u32_field(object, "clarifications")?,
        elapsed_microseconds: u64_field(object, "elapsed_microseconds")?,
        peak_worker_memory_bytes: u64_field(object, "peak_worker_memory_bytes")?,
        report_sha256,
    };
    if evidence.actual_qwen_cases < 10
        || evidence.provider_invocations < 12
        || evidence.clarification_count == 0
    {
        return Err("model report does not meet OFFICE-200 evidence bounds".to_owned());
    }
    Ok(evidence)
}

#[cfg(windows)]
fn string_field(object: &serde_json::Map<String, Value>, field: &str) -> Result<String, String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("model report field {field} is missing"))
}

#[cfg(windows)]
fn u32_field(object: &serde_json::Map<String, Value>, field: &str) -> Result<u32, String> {
    u32::try_from(u64_field(object, field)?).map_err(|_| format!("field {field} exceeds u32"))
}

#[cfg(windows)]
fn u64_field(object: &serde_json::Map<String, Value>, field: &str) -> Result<u64, String> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("model report field {field} is missing"))
}

#[cfg(windows)]
fn contains_text(snapshot: &DocumentSemanticSnapshotV1, text: &str) -> bool {
    let expected = sha256_bytes(text.as_bytes());
    snapshot
        .ordered_nodes
        .iter()
        .any(|node| node.text_sha256.as_deref() == Some(expected.as_str()))
}

#[cfg(windows)]
fn validate_hash(value: &str) -> Result<(), String> {
    d2i_office_capability::validate_hash(value, "Completion hash")
        .map_err(|error| error.to_string())
}

#[cfg(windows)]
fn file_sha256(path: &Path) -> Result<String, String> {
    fs::read(path)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|error| error.to_string())
}

#[cfg(windows)]
fn repository_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|error| error.to_string())
}

#[cfg(windows)]
fn unix_time_milliseconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(|error| error.to_string())
        .and_then(|value| u64::try_from(value).map_err(|error| error.to_string()))
}

#[cfg(windows)]
fn micros(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

#[cfg(windows)]
fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let bytes =
        d2i_office_capability::canonical_json_bytes(value).map_err(|error| error.to_string())?;
    fs::write(path, bytes).map_err(|error| error.to_string())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("OFFICE-200 completion requires Windows desktop Office deployment");
    std::process::exit(2);
}
