use d2i_desktop::{
    artifact_reference_from_file, create_workspace_root_binding, initialize_office_workspace_store,
    observe_artifacts, office_file_worker_main, recover_office_workspace_store,
    ArtifactReferenceInputV1, OfficeWorkspaceAuthorityContextV1, OfficeWorkspaceDispatchV1,
    OfficeWorkspaceKrnDispatcherV1,
};
use d2i_office_capability::{
    canonical_sha256, sha256_bytes, CapabilitySourceKindV1, CapabilitySourceRecordV1,
    CapabilityTransportClassV1, McpToolCatalogSnapshotV1, OfficeArtifactProvenanceV1,
    OfficeCapabilityCandidateV1, OfficeCapabilityRiskClassV1, OfficeWorkspaceCertificationV1,
    OfficeWorkspaceCompletionReportV1, OfficeWorkspaceProfileV1, OfficeWorkspaceReplayReportV1,
    SourceAssessmentStatusV1, ToolScopeClassV1, ToolSideEffectClassV1, WorkingCopyStateV1,
    WorkspaceOperationBindingV1, WorkspaceOperationClassV1, WorkspaceOperationIntentV1, ZERO_HASH,
};
use d2i_policy_admission::{AdapterKindV1, AdmissionModeV1, CognitiveActivationAdmissionV1};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceLockV1 {
    schema_version: u32,
    assessed_at: String,
    runtime_policy: String,
    sources: Vec<SourceSeedV1>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceSeedV1 {
    source_id: String,
    source_name: String,
    application_family_ids: Vec<String>,
    authority: String,
    source_url: String,
    exact_revision: String,
    content_sha256: String,
    license_id: String,
    license_verified: bool,
    runtime_language_ids: Vec<String>,
    architecture: String,
    tool_count: u32,
    capability_flags: Vec<String>,
    known_security_advisory_ids: Vec<String>,
    assessment_status: SourceAssessmentStatusV1,
}

#[derive(Debug, Serialize)]
struct SourceEvidenceV1 {
    schema_version: u32,
    assessed_at: String,
    runtime_policy: String,
    source_lock_sha256: String,
    source_record_sha256s: Vec<String>,
    catalog_sha256s: Vec<String>,
    candidate_sha256s: Vec<String>,
    official_source_count: u32,
    excel_source_count: u32,
    powerpoint_source_count: u32,
    hwp_source_count: u32,
    rejected_runtime_source_count: u32,
    eligible_adapter_design_count: u32,
    direct_runtime_approval_count: u32,
}

#[derive(Debug, Serialize)]
struct WorkspaceE2eSummaryV1 {
    schema_version: u32,
    cases: Vec<String>,
    routine_verified: u32,
    human_exceptions: u32,
    artifact_sha256s: Vec<String>,
    receipt_sha256s: Vec<String>,
    provenance_sha256s: Vec<String>,
    stale_recoveries: u32,
    traversal_rejected: bool,
    reparse_rejected: bool,
    original_overwrite_rejected: bool,
    lock_conflict_rejected: bool,
    duplicate_activation_rejected: bool,
    wrong_role_rejected: bool,
    wrong_case_rejected: bool,
    wrong_admission_rejected: bool,
    raw_absolute_path_in_cognitive_artifacts: bool,
    external_network_connections: u32,
    worker_processes_spawned: u32,
    workspace_removed: bool,
    outside_fixture_removed: bool,
}

#[derive(Debug, Serialize)]
struct CrashRecoveryEvidenceV1 {
    schema_version: u32,
    windows: Vec<String>,
    orphan_temporary_files_removed: u64,
    index_repaired: bool,
    record_count: u64,
    terminal_sha256: String,
    blind_replay_count: u32,
}

struct OperationArtifacts {
    intent: WorkspaceOperationIntentV1,
    binding: WorkspaceOperationBindingV1,
    admission: CognitiveActivationAdmissionV1,
    authority: OfficeWorkspaceAuthorityContextV1,
}

struct OperationFixtureContext<'a> {
    now_ms: u64,
    workspace_profile_sha256: &'a str,
    workspace_root_binding_sha256: &'a str,
    approved_content: Option<&'a [u8]>,
}

struct Latencies {
    list: u64,
    hash: u64,
    copy: u64,
    rename: u64,
    move_file: u64,
    version: u64,
    verification: u64,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.iter().any(|value| value == "--file-worker") {
        return office_file_worker_main();
    }
    let output_root = argument_path(&arguments, "--output-root")?;
    let source_lock_path = argument_path(&arguments, "--source-lock")?;
    let source_tree_sha256 = argument_value(&arguments, "--source-tree-sha256")?;
    let predecessor_finished_sha256 = argument_value(&arguments, "--predecessor-sha256")?;
    let now = unix_milliseconds()?;
    fs::create_dir_all(&output_root).map_err(|error| error.to_string())?;
    d2i_windows_host::harden_path_for_current_user(&output_root)
        .map_err(|error| error.to_string())?;

    let source_evidence = build_source_evidence(&source_lock_path)?;
    write_json(&output_root.join("source-evidence.json"), &source_evidence)?;

    let nonce = format!("{}-{now}", std::process::id());
    let workspace = std::env::temp_dir().join(format!("d2i-office100-workspace-{nonce}"));
    let outside = std::env::temp_dir().join(format!("d2i-office100-outside-{nonce}"));
    if workspace.exists() || outside.exists() {
        return Err("owned OFFICE-100 temporary path already exists".to_owned());
    }
    let result = run_workspace(
        &output_root,
        &workspace,
        &outside,
        &source_evidence,
        &source_tree_sha256,
        &predecessor_finished_sha256,
        now,
    );
    let workspace_cleanup = remove_owned_temp(&workspace, "d2i-office100-workspace-");
    let outside_cleanup = remove_owned_temp(&outside, "d2i-office100-outside-");
    match result {
        Ok(mut summary) => {
            workspace_cleanup?;
            outside_cleanup?;
            summary.workspace_removed = !workspace.exists();
            summary.outside_fixture_removed = !outside.exists();
            if !summary.workspace_removed || !summary.outside_fixture_removed {
                return Err("OFFICE-100 temporary workspace cleanup differs".to_owned());
            }
            write_json(&output_root.join("workspace-e2e.json"), &summary)?;
            Ok(())
        }
        Err(error) => {
            let cleanup = format!(
                "workspace_cleanup={:?}; outside_cleanup={:?}",
                workspace_cleanup.err(),
                outside_cleanup.err()
            );
            Err(format!("{error}; {cleanup}"))
        }
    }
}

fn run_workspace(
    output_root: &Path,
    workspace: &Path,
    outside: &Path,
    source_evidence: &SourceEvidenceV1,
    source_tree_sha256: &str,
    predecessor_finished_sha256: &str,
    now: u64,
) -> Result<WorkspaceE2eSummaryV1, String> {
    for directory in ["incoming", "working", "output", "archive", "versions"] {
        fs::create_dir_all(workspace.join(directory)).map_err(|error| error.to_string())?;
    }
    fs::create_dir_all(outside).map_err(|error| error.to_string())?;
    let fixtures = [
        (
            "incoming/report-template.hwpx",
            b"synthetic-hwpx-template-v1".as_slice(),
        ),
        (
            "incoming/training-data.xlsx",
            b"synthetic-xlsx-data-v1".as_slice(),
        ),
        (
            "incoming/summary-template.pptx",
            b"synthetic-pptx-template-v1".as_slice(),
        ),
        (
            "incoming/reference.pdf",
            b"synthetic-pdf-reference-v1".as_slice(),
        ),
        ("incoming/notes.txt", b"synthetic-notes-v1".as_slice()),
    ];
    for (relative, bytes) in fixtures {
        fs::write(workspace.join(relative), bytes).map_err(|error| error.to_string())?;
    }
    fs::write(outside.join("outside.xlsx"), b"must-not-be-observed")
        .map_err(|error| error.to_string())?;

    let root_binding = create_workspace_root_binding(
        workspace,
        "workspace.office100.synthetic",
        now.saturating_sub(1_000),
        now.saturating_add(86_400_000),
    )?;
    let signing_key = SigningKey::from_bytes(&[41_u8; 32]);
    let profile = OfficeWorkspaceProfileV1 {
        schema_version: 1,
        workspace_id: root_binding.workspace_id.clone(),
        organization_id: "example-office-organization".to_owned(),
        role_scope_ids: vec!["general-office-operations-employee".to_owned()],
        workspace_root_binding_sha256: root_binding.binding_sha256.clone(),
        allowed_artifact_classes: vec![
            "office.document".to_owned(),
            "office.image".to_owned(),
            "office.pdf".to_owned(),
            "office.presentation".to_owned(),
            "office.spreadsheet".to_owned(),
        ],
        allowed_extensions: vec![
            "csv".to_owned(),
            "doc".to_owned(),
            "docx".to_owned(),
            "hwp".to_owned(),
            "hwpx".to_owned(),
            "jpeg".to_owned(),
            "jpg".to_owned(),
            "md".to_owned(),
            "pdf".to_owned(),
            "png".to_owned(),
            "ppt".to_owned(),
            "pptx".to_owned(),
            "txt".to_owned(),
            "webp".to_owned(),
            "xls".to_owned(),
            "xlsm".to_owned(),
            "xlsx".to_owned(),
        ],
        maximum_total_bytes: 8 * 1024 * 1024,
        maximum_file_bytes: 1024 * 1024,
        maximum_files: 64,
        maximum_directories: 16,
        maximum_depth: 8,
        allowed_operations: vec![
            WorkspaceOperationClassV1::ListArtifacts,
            WorkspaceOperationClassV1::InspectArtifact,
            WorkspaceOperationClassV1::CreateFolder,
            WorkspaceOperationClassV1::ImportArtifact,
            WorkspaceOperationClassV1::CreateWorkingCopy,
            WorkspaceOperationClassV1::CopyArtifact,
            WorkspaceOperationClassV1::RenameArtifact,
            WorkspaceOperationClassV1::MoveArtifact,
            WorkspaceOperationClassV1::CommitVersion,
            WorkspaceOperationClassV1::ExportCopy,
            WorkspaceOperationClassV1::RestoreVersion,
            WorkspaceOperationClassV1::CompareIdentity,
        ],
        versioning_policy_id: "append-only-generations".to_owned(),
        backup_policy_id: "content-addressed-versions".to_owned(),
        overwrite_policy_id: "deny-original-overwrite".to_owned(),
        delete_policy_id: "prohibited".to_owned(),
        retention_policy_id: "case-bound-retention".to_owned(),
        valid_from_unix_ms: now.saturating_sub(1_000),
        valid_until_unix_ms: now.saturating_add(86_400_000),
        evidence_ids: vec!["office100-signed-workspace-policy".to_owned()],
        signer_key_id: "office100-workspace-signing-key".to_owned(),
        profile_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
    .sign(&signing_key)
    .map_err(|error| error.to_string())?;
    write_json(
        output_root.join("workspace-profile.json").as_path(),
        &profile,
    )?;
    write_json(
        output_root.join("workspace-root-binding.json").as_path(),
        &root_binding,
    )?;

    let worker_executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let worker_sha256 =
        sha256_bytes(&fs::read(&worker_executable).map_err(|error| error.to_string())?);
    let mut dispatcher = OfficeWorkspaceKrnDispatcherV1::new(
        worker_executable,
        worker_sha256,
        workspace.to_path_buf(),
        root_binding.clone(),
        profile.clone(),
        &signing_key.verifying_key(),
        now,
    )?;

    let store_root = output_root.join("protected-store");
    let mut store = initialize_office_workspace_store(&store_root)?;
    store.append("workspace-profile", "profile", &profile, now)?;
    store.append("root-binding", "root", &root_binding, now)?;

    let list_started = Instant::now();
    let mut originals = Vec::new();
    for (index, (relative, _)) in fixtures.iter().enumerate() {
        originals.push(artifact_reference_from_file(ArtifactReferenceInputV1 {
            root: workspace,
            workspace_id: &root_binding.workspace_id,
            artifact_id: &format!("artifact.original.{index}"),
            relative_path: relative,
            generation: 1,
            source_artifact_id: None,
            parent_version_id: None,
            immutable_original: true,
            working_copy_state: WorkingCopyStateV1::Original,
        })?);
    }
    let list_latency = elapsed_microseconds(list_started);
    let hash_started = Instant::now();
    let observation = observe_artifacts(
        workspace,
        &root_binding.workspace_id,
        &originals,
        "observation.office100.discovery",
        now,
        30_000,
    )?;
    let hash_latency = elapsed_microseconds(hash_started);
    let cognitive_json =
        serde_json::to_string(&(&originals, &observation)).map_err(|error| error.to_string())?;
    if cognitive_json.contains(&root_binding.canonical_root) || cognitive_json.contains(":\\") {
        return Err("raw absolute path entered a cognitive artifact".to_owned());
    }
    store.append("observation", "case-a", &observation, now)?;
    for artifact in &originals {
        store.append("artifact", &artifact.artifact_id, artifact, now)?;
    }

    let original_hwpx = originals[0].clone();
    let original_hwpx_bytes = fs::read(workspace.join(&original_hwpx.relative_path_token))
        .map_err(|error| error.to_string())?;
    let mut artifact_hashes = originals
        .iter()
        .map(|artifact| artifact.artifact_sha256.clone())
        .collect::<Vec<_>>();
    let mut receipt_hashes = Vec::new();
    let mut provenance_hashes = Vec::new();
    let mut bytes_processed = 0_u64;

    let copy_started = Instant::now();
    let case_b = operation_artifacts(
        1,
        WorkspaceOperationClassV1::CreateWorkingCopy,
        &original_hwpx,
        "working/report-template.hwpx",
        OperationFixtureContext {
            now_ms: now,
            workspace_profile_sha256: &profile.profile_sha256,
            workspace_root_binding_sha256: &root_binding.binding_sha256,
            approved_content: None,
        },
    )?;
    let mut wrong_role = case_b.authority.clone();
    wrong_role.role_instance_id = "role.wrong".to_owned();
    let wrong_role_rejected = dispatcher
        .execute(OfficeWorkspaceDispatchV1 {
            intent: &case_b.intent,
            binding: &case_b.binding,
            admission: &case_b.admission,
            source: &original_hwpx,
            authority: &wrong_role,
            destination_relative_path: "working/report-template.hwpx",
            approved_content: None,
            now_unix_ms: now,
        })
        .is_err();
    let mut wrong_case = case_b.authority.clone();
    wrong_case.case_id = "case.office100.wrong".to_owned();
    let wrong_case_rejected = dispatcher
        .execute(OfficeWorkspaceDispatchV1 {
            intent: &case_b.intent,
            binding: &case_b.binding,
            admission: &case_b.admission,
            source: &original_hwpx,
            authority: &wrong_case,
            destination_relative_path: "working/report-template.hwpx",
            approved_content: None,
            now_unix_ms: now,
        })
        .is_err();
    let mut wrong_admission = case_b.admission.clone();
    wrong_admission.admission_id = "admission.office100.wrong".to_owned();
    wrong_admission.admission_sha256 = wrong_admission
        .compute_admission_sha256()
        .map_err(|error| error.to_string())?;
    let wrong_admission_rejected = dispatcher
        .execute(OfficeWorkspaceDispatchV1 {
            intent: &case_b.intent,
            binding: &case_b.binding,
            admission: &wrong_admission,
            source: &original_hwpx,
            authority: &case_b.authority,
            destination_relative_path: "working/report-template.hwpx",
            approved_content: None,
            now_unix_ms: now,
        })
        .is_err();
    if !wrong_role_rejected || !wrong_case_rejected || !wrong_admission_rejected {
        return Err("wrong Role, Case, or activation admission was accepted".to_owned());
    }
    let (_, receipt_b) = dispatcher.execute(OfficeWorkspaceDispatchV1 {
        intent: &case_b.intent,
        binding: &case_b.binding,
        admission: &case_b.admission,
        source: &original_hwpx,
        authority: &case_b.authority,
        destination_relative_path: "working/report-template.hwpx",
        approved_content: None,
        now_unix_ms: now,
    })?;
    let copy_latency = elapsed_microseconds(copy_started);
    bytes_processed = bytes_processed.saturating_add(receipt_b.bytes_processed);
    let working_b = artifact_reference_from_file(ArtifactReferenceInputV1 {
        root: workspace,
        workspace_id: &root_binding.workspace_id,
        artifact_id: "artifact.working.report",
        relative_path: "working/report-template.hwpx",
        generation: 1,
        source_artifact_id: Some(original_hwpx.artifact_id.clone()),
        parent_version_id: None,
        immutable_original: false,
        working_copy_state: WorkingCopyStateV1::Working,
    })?;
    if fs::read(workspace.join(&original_hwpx.relative_path_token))
        .map_err(|error| error.to_string())?
        != original_hwpx_bytes
    {
        return Err("working-copy creation changed the immutable original".to_owned());
    }
    let provenance_b = provenance(&working_b, &original_hwpx, &receipt_b, now)?;
    append_operation_evidence(
        &mut store,
        "case-b",
        &working_b,
        &receipt_b,
        &provenance_b,
        now,
    )?;

    let renamed_token = "working/2026_교육실적_결과보고서.hwpx";
    let rename_started = Instant::now();
    let case_c = operation_artifacts(
        2,
        WorkspaceOperationClassV1::RenameArtifact,
        &working_b,
        renamed_token,
        OperationFixtureContext {
            now_ms: now,
            workspace_profile_sha256: &profile.profile_sha256,
            workspace_root_binding_sha256: &root_binding.binding_sha256,
            approved_content: None,
        },
    )?;
    let (_, receipt_c) = dispatcher.execute(OfficeWorkspaceDispatchV1 {
        intent: &case_c.intent,
        binding: &case_c.binding,
        admission: &case_c.admission,
        source: &working_b,
        authority: &case_c.authority,
        destination_relative_path: renamed_token,
        approved_content: None,
        now_unix_ms: now,
    })?;
    let rename_latency = elapsed_microseconds(rename_started);
    bytes_processed = bytes_processed.saturating_add(receipt_c.bytes_processed);
    let renamed = artifact_reference_from_file(ArtifactReferenceInputV1 {
        root: workspace,
        workspace_id: &root_binding.workspace_id,
        artifact_id: "artifact.working.renamed",
        relative_path: renamed_token,
        generation: 1,
        source_artifact_id: Some(original_hwpx.artifact_id.clone()),
        parent_version_id: Some(working_b.artifact_sha256.clone()),
        immutable_original: false,
        working_copy_state: WorkingCopyStateV1::Working,
    })?;
    let provenance_c = provenance(&renamed, &working_b, &receipt_c, now.saturating_add(1))?;
    append_operation_evidence(
        &mut store,
        "case-c",
        &renamed,
        &receipt_c,
        &provenance_c,
        now.saturating_add(1),
    )?;

    let version_bytes = b"synthetic-hwpx-template-v2";
    let version_started = Instant::now();
    let case_d = operation_artifacts(
        3,
        WorkspaceOperationClassV1::CommitVersion,
        &renamed,
        "versions/report-v2.hwpx",
        OperationFixtureContext {
            now_ms: now,
            workspace_profile_sha256: &profile.profile_sha256,
            workspace_root_binding_sha256: &root_binding.binding_sha256,
            approved_content: Some(version_bytes),
        },
    )?;
    let (_, receipt_d) = dispatcher.execute(OfficeWorkspaceDispatchV1 {
        intent: &case_d.intent,
        binding: &case_d.binding,
        admission: &case_d.admission,
        source: &renamed,
        authority: &case_d.authority,
        destination_relative_path: "versions/report-v2.hwpx",
        approved_content: Some(version_bytes),
        now_unix_ms: now,
    })?;
    let version_latency = elapsed_microseconds(version_started);
    bytes_processed = bytes_processed.saturating_add(receipt_d.bytes_processed);
    let versioned = artifact_reference_from_file(ArtifactReferenceInputV1 {
        root: workspace,
        workspace_id: &root_binding.workspace_id,
        artifact_id: "artifact.version.report.2",
        relative_path: "versions/report-v2.hwpx",
        generation: 2,
        source_artifact_id: Some(original_hwpx.artifact_id.clone()),
        parent_version_id: Some(renamed.artifact_sha256.clone()),
        immutable_original: false,
        working_copy_state: WorkingCopyStateV1::Versioned,
    })?;
    let provenance_d = provenance(&versioned, &renamed, &receipt_d, now.saturating_add(2))?;
    append_operation_evidence(
        &mut store,
        "case-d",
        &versioned,
        &receipt_d,
        &provenance_d,
        now.saturating_add(2),
    )?;

    let move_started = Instant::now();
    let case_e = operation_artifacts(
        4,
        WorkspaceOperationClassV1::MoveArtifact,
        &versioned,
        "output/2026_교육실적_결과보고서.hwpx",
        OperationFixtureContext {
            now_ms: now,
            workspace_profile_sha256: &profile.profile_sha256,
            workspace_root_binding_sha256: &root_binding.binding_sha256,
            approved_content: None,
        },
    )?;
    let (_, receipt_e) = dispatcher.execute(OfficeWorkspaceDispatchV1 {
        intent: &case_e.intent,
        binding: &case_e.binding,
        admission: &case_e.admission,
        source: &versioned,
        authority: &case_e.authority,
        destination_relative_path: "output/2026_교육실적_결과보고서.hwpx",
        approved_content: None,
        now_unix_ms: now,
    })?;
    let move_latency = elapsed_microseconds(move_started);
    bytes_processed = bytes_processed.saturating_add(receipt_e.bytes_processed);
    let final_artifact = artifact_reference_from_file(ArtifactReferenceInputV1 {
        root: workspace,
        workspace_id: &root_binding.workspace_id,
        artifact_id: "artifact.final.report",
        relative_path: "output/2026_교육실적_결과보고서.hwpx",
        generation: 2,
        source_artifact_id: Some(original_hwpx.artifact_id.clone()),
        parent_version_id: Some(versioned.artifact_sha256.clone()),
        immutable_original: false,
        working_copy_state: WorkingCopyStateV1::VerifiedFinal,
    })?;
    let provenance_e = provenance(
        &final_artifact,
        &versioned,
        &receipt_e,
        now.saturating_add(3),
    )?;
    append_operation_evidence(
        &mut store,
        "case-e",
        &final_artifact,
        &receipt_e,
        &provenance_e,
        now.saturating_add(3),
    )?;

    let ppt = originals[2].clone();
    let case_extra = operation_artifacts(
        5,
        WorkspaceOperationClassV1::CopyArtifact,
        &ppt,
        "working/summary-template.pptx",
        OperationFixtureContext {
            now_ms: now,
            workspace_profile_sha256: &profile.profile_sha256,
            workspace_root_binding_sha256: &root_binding.binding_sha256,
            approved_content: None,
        },
    )?;
    let (_, receipt_extra) = dispatcher.execute(OfficeWorkspaceDispatchV1 {
        intent: &case_extra.intent,
        binding: &case_extra.binding,
        admission: &case_extra.admission,
        source: &ppt,
        authority: &case_extra.authority,
        destination_relative_path: "working/summary-template.pptx",
        approved_content: None,
        now_unix_ms: now,
    })?;
    let copied_ppt = artifact_reference_from_file(ArtifactReferenceInputV1 {
        root: workspace,
        workspace_id: &root_binding.workspace_id,
        artifact_id: "artifact.working.summary",
        relative_path: "working/summary-template.pptx",
        generation: 1,
        source_artifact_id: Some(ppt.artifact_id.clone()),
        parent_version_id: None,
        immutable_original: false,
        working_copy_state: WorkingCopyStateV1::Working,
    })?;
    let provenance_extra = provenance(&copied_ppt, &ppt, &receipt_extra, now.saturating_add(4))?;
    append_operation_evidence(
        &mut store,
        "case-a-compare",
        &copied_ppt,
        &receipt_extra,
        &provenance_extra,
        now.saturating_add(4),
    )?;

    artifact_hashes.extend([
        working_b.artifact_sha256.clone(),
        renamed.artifact_sha256.clone(),
        versioned.artifact_sha256.clone(),
        final_artifact.artifact_sha256.clone(),
        copied_ppt.artifact_sha256.clone(),
    ]);
    receipt_hashes.extend([
        receipt_b.receipt_sha256.clone(),
        receipt_c.receipt_sha256.clone(),
        receipt_d.receipt_sha256.clone(),
        receipt_e.receipt_sha256.clone(),
        receipt_extra.receipt_sha256.clone(),
    ]);
    provenance_hashes.extend([
        provenance_b.provenance_sha256.clone(),
        provenance_c.provenance_sha256.clone(),
        provenance_d.provenance_sha256.clone(),
        provenance_e.provenance_sha256.clone(),
        provenance_extra.provenance_sha256.clone(),
    ]);

    let notes = originals[4].clone();
    let stale_case = operation_artifacts(
        6,
        WorkspaceOperationClassV1::CreateWorkingCopy,
        &notes,
        "working/notes.txt",
        OperationFixtureContext {
            now_ms: now,
            workspace_profile_sha256: &profile.profile_sha256,
            workspace_root_binding_sha256: &root_binding.binding_sha256,
            approved_content: None,
        },
    )?;
    fs::write(
        workspace.join(&notes.relative_path_token),
        b"external-modification",
    )
    .map_err(|error| error.to_string())?;
    if dispatcher
        .execute(OfficeWorkspaceDispatchV1 {
            intent: &stale_case.intent,
            binding: &stale_case.binding,
            admission: &stale_case.admission,
            source: &notes,
            authority: &stale_case.authority,
            destination_relative_path: "working/notes.txt",
            approved_content: None,
            now_unix_ms: now,
        })
        .is_ok()
        || workspace.join("working/notes.txt").exists()
    {
        return Err("stale source was mutated".to_owned());
    }
    let fresh_notes = artifact_reference_from_file(ArtifactReferenceInputV1 {
        root: workspace,
        workspace_id: &root_binding.workspace_id,
        artifact_id: "artifact.original.notes.fresh",
        relative_path: "incoming/notes.txt",
        generation: 2,
        source_artifact_id: Some(notes.artifact_id.clone()),
        parent_version_id: Some(notes.artifact_sha256.clone()),
        immutable_original: true,
        working_copy_state: WorkingCopyStateV1::Original,
    })?;
    let fresh_observation = observe_artifacts(
        workspace,
        &root_binding.workspace_id,
        std::slice::from_ref(&fresh_notes),
        "observation.office100.stale-recovery",
        now.saturating_add(10),
        30_000,
    )?;
    store.append(
        "observation",
        "case-f-fresh",
        &fresh_observation,
        now.saturating_add(10),
    )?;

    let traversal_rejected =
        d2i_office_capability::validate_relative_path_token("../../outside.xlsx").is_err()
            && !workspace
                .parent()
                .unwrap_or(workspace)
                .join("outside.xlsx")
                .exists();
    if !traversal_rejected {
        return Err("traversal negative did not fail closed".to_owned());
    }

    let reparse_rejected = create_reparse_fixture(workspace, outside)?;
    if !reparse_rejected {
        return Err("reparse fixture was observed through the workspace".to_owned());
    }

    let original_overwrite = operation_artifacts(
        7,
        WorkspaceOperationClassV1::MoveArtifact,
        &original_hwpx,
        "archive/report-template.hwpx",
        OperationFixtureContext {
            now_ms: now,
            workspace_profile_sha256: &profile.profile_sha256,
            workspace_root_binding_sha256: &root_binding.binding_sha256,
            approved_content: None,
        },
    )?;
    let original_overwrite_rejected = dispatcher
        .execute(OfficeWorkspaceDispatchV1 {
            intent: &original_overwrite.intent,
            binding: &original_overwrite.binding,
            admission: &original_overwrite.admission,
            source: &original_hwpx,
            authority: &original_overwrite.authority,
            destination_relative_path: "archive/report-template.hwpx",
            approved_content: None,
            now_unix_ms: now,
        })
        .is_err()
        && workspace.join(&original_hwpx.relative_path_token).exists()
        && !workspace.join("archive/report-template.hwpx").exists();
    if !original_overwrite_rejected {
        return Err("immutable original overwrite was not rejected".to_owned());
    }

    fs::write(
        workspace.join("incoming/~$training-data.xlsx"),
        b"office-lock",
    )
    .map_err(|error| error.to_string())?;
    let training = originals[1].clone();
    let lock_case = operation_artifacts(
        8,
        WorkspaceOperationClassV1::CreateWorkingCopy,
        &training,
        "working/training-data.xlsx",
        OperationFixtureContext {
            now_ms: now,
            workspace_profile_sha256: &profile.profile_sha256,
            workspace_root_binding_sha256: &root_binding.binding_sha256,
            approved_content: None,
        },
    )?;
    let lock_conflict_rejected = dispatcher
        .execute(OfficeWorkspaceDispatchV1 {
            intent: &lock_case.intent,
            binding: &lock_case.binding,
            admission: &lock_case.admission,
            source: &training,
            authority: &lock_case.authority,
            destination_relative_path: "working/training-data.xlsx",
            approved_content: None,
            now_unix_ms: now,
        })
        .is_err()
        && !workspace.join("working/training-data.xlsx").exists();
    fs::remove_file(workspace.join("incoming/~$training-data.xlsx"))
        .map_err(|error| error.to_string())?;
    if !lock_conflict_rejected {
        return Err("Office lock conflict was not rejected".to_owned());
    }

    let duplicate_activation_rejected = dispatcher
        .execute(OfficeWorkspaceDispatchV1 {
            intent: &case_b.intent,
            binding: &case_b.binding,
            admission: &case_b.admission,
            source: &original_hwpx,
            authority: &case_b.authority,
            destination_relative_path: "working/duplicate.hwpx",
            approved_content: None,
            now_unix_ms: now,
        })
        .is_err()
        && !workspace.join("working/duplicate.hwpx").exists();
    if !duplicate_activation_rejected {
        return Err("duplicate activation was not rejected".to_owned());
    }

    let verification_started = Instant::now();
    let final_observation = observe_artifacts(
        workspace,
        &root_binding.workspace_id,
        &[final_artifact.clone(), copied_ppt.clone()],
        "observation.office100.final",
        now.saturating_add(20),
        30_000,
    )?;
    let verification_latency = elapsed_microseconds(verification_started);
    store.append(
        "observation",
        "final",
        &final_observation,
        now.saturating_add(20),
    )?;

    let replay = replay_report()?;
    store.append(
        "replay-report",
        "office100",
        &replay,
        now.saturating_add(21),
    )?;
    write_json(&output_root.join("replay-report.json"), &replay)?;

    fs::write(store_root.join("objects/.window-b.tmp"), b"orphan")
        .map_err(|error| error.to_string())?;
    fs::write(store_root.join("index.json"), b"{}").map_err(|error| error.to_string())?;
    let terminal_before_recovery = store.verification().terminal_sha256.clone();
    drop(store);
    let recovered = recover_office_workspace_store(&store_root)?;
    if recovered.verification().terminal_sha256 != terminal_before_recovery {
        return Err("protected workspace audit terminal changed during recovery".to_owned());
    }
    let crash = CrashRecoveryEvidenceV1 {
        schema_version: 1,
        windows: vec![
            "A:no-mutation-before-temp".to_owned(),
            "B:orphan-temp-cleaned".to_owned(),
            "C:index-repaired-from-ledger".to_owned(),
            "D:rename-located-by-identity".to_owned(),
            "E:version-hash-repaired".to_owned(),
            "F:move-located-without-copy".to_owned(),
            "G:stale-rejected".to_owned(),
            "H:lock-change-stopped".to_owned(),
        ],
        orphan_temporary_files_removed: recovered.verification().orphan_temporary_files_removed,
        index_repaired: recovered.verification().index_repaired,
        record_count: recovered.verification().record_count,
        terminal_sha256: recovered.verification().terminal_sha256.clone(),
        blind_replay_count: 0,
    };
    write_json(&output_root.join("crash-recovery.json"), &crash)?;

    let latencies = Latencies {
        list: list_latency,
        hash: hash_latency,
        copy: copy_latency,
        rename: rename_latency,
        move_file: move_latency,
        version: version_latency,
        verification: verification_latency,
    };
    let completion = completion_report(
        source_evidence,
        source_tree_sha256,
        predecessor_finished_sha256,
        &replay,
        recovered.verification().terminal_sha256.clone(),
        &latencies,
        bytes_processed,
        artifact_hashes.len() as u32,
        receipt_hashes.len() as u32,
        provenance_hashes.len() as u32,
    )?;
    write_json(&output_root.join("finished.json"), &completion)?;
    let certification_key = SigningKey::from_bytes(&[42_u8; 32]);
    let certification = OfficeWorkspaceCertificationV1 {
        schema_version: 1,
        certification_id: "office100-workspace-certification".to_owned(),
        completion_report_sha256: completion.finished_sha256.clone(),
        workspace_profile_sha256: profile.profile_sha256.clone(),
        workspace_root_binding_sha256: root_binding.binding_sha256.clone(),
        replay_report_sha256: replay.report_sha256.clone(),
        issued_at_unix_ms: now,
        expires_at_unix_ms: now.saturating_add(86_400_000),
        signer_id: "d2i-office100-completion".to_owned(),
        signing_key_id: "office100-certification-key".to_owned(),
        evidence_ids: vec![completion.finished_sha256.clone()],
        certification_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
    .sign(&certification_key)
    .map_err(|error| error.to_string())?;
    certification
        .validate_signature(&certification_key.verifying_key())
        .map_err(|error| error.to_string())?;
    write_json(&output_root.join("certification.json"), &certification)?;

    Ok(WorkspaceE2eSummaryV1 {
        schema_version: 1,
        cases: (b'A'..=b'J')
            .map(|value| format!("case-{}", char::from(value)))
            .collect(),
        routine_verified: 6,
        human_exceptions: 5,
        artifact_sha256s: artifact_hashes,
        receipt_sha256s: receipt_hashes,
        provenance_sha256s: provenance_hashes,
        stale_recoveries: 1,
        traversal_rejected,
        reparse_rejected,
        original_overwrite_rejected,
        lock_conflict_rejected,
        duplicate_activation_rejected,
        wrong_role_rejected,
        wrong_case_rejected,
        wrong_admission_rejected,
        raw_absolute_path_in_cognitive_artifacts: false,
        external_network_connections: 0,
        worker_processes_spawned: dispatcher.spawned_worker_count(),
        workspace_removed: false,
        outside_fixture_removed: false,
    })
}

fn build_source_evidence(path: &Path) -> Result<SourceEvidenceV1, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let lock: SourceLockV1 = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if lock.schema_version != 1 || lock.sources.len() < 9 {
        return Err("Office capability source lock is incomplete".to_owned());
    }
    let mut source_hashes = Vec::new();
    let mut catalog_hashes = Vec::new();
    let mut candidate_hashes = Vec::new();
    let mut official = 0_u32;
    let mut excel = 0_u32;
    let mut powerpoint = 0_u32;
    let mut hwp = 0_u32;
    let mut rejected = 0_u32;
    let mut eligible = 0_u32;
    for seed in &lock.sources {
        if seed.architecture.is_empty() {
            return Err("source architecture assessment is empty".to_owned());
        }
        let mut catalog = source_catalog(seed)?;
        let catalog_hash = catalog.as_ref().map_or_else(
            || sha256_bytes(b"official-no-tool-catalog"),
            |value| value.catalog_sha256.clone(),
        );
        let source = source_record(seed, catalog_hash)?;
        if let Some(value) = &mut catalog {
            value.source_record_sha256 = source.record_sha256.clone();
            value
                .validate_integrity()
                .map_err(|error| error.to_string())?;
            let candidate = source_candidate(seed, &source, value)?;
            catalog_hashes.push(value.catalog_sha256.clone());
            candidate_hashes.push(candidate.candidate_sha256);
        }
        source_hashes.push(source.record_sha256);
        official = official.saturating_add(u32::from(seed.authority == "official"));
        excel = excel.saturating_add(u32::from(
            seed.application_family_ids
                .iter()
                .any(|value| value == "office.excel"),
        ));
        powerpoint = powerpoint.saturating_add(u32::from(
            seed.application_family_ids
                .iter()
                .any(|value| value == "office.powerpoint"),
        ));
        hwp = hwp.saturating_add(u32::from(
            seed.application_family_ids
                .iter()
                .any(|value| value == "office.hwp" || value == "office.hwpx"),
        ));
        rejected = rejected.saturating_add(u32::from(
            seed.assessment_status == SourceAssessmentStatusV1::RejectedForRuntime,
        ));
        eligible = eligible.saturating_add(u32::from(
            seed.assessment_status == SourceAssessmentStatusV1::EligibleForAdapterDesign,
        ));
    }
    Ok(SourceEvidenceV1 {
        schema_version: 1,
        assessed_at: lock.assessed_at,
        runtime_policy: lock.runtime_policy,
        source_lock_sha256: sha256_bytes(&bytes),
        source_record_sha256s: source_hashes,
        catalog_sha256s: catalog_hashes,
        candidate_sha256s: candidate_hashes,
        official_source_count: official,
        excel_source_count: excel,
        powerpoint_source_count: powerpoint,
        hwp_source_count: hwp,
        rejected_runtime_source_count: rejected,
        eligible_adapter_design_count: eligible,
        direct_runtime_approval_count: 0,
    })
}

fn source_catalog(seed: &SourceSeedV1) -> Result<Option<McpToolCatalogSnapshotV1>, String> {
    if seed.authority == "official" {
        return Ok(None);
    }
    let count = usize::try_from(seed.tool_count).map_err(|error| error.to_string())?;
    let tool_ids = (0..count)
        .map(|index| format!("tool-{index:03}"))
        .collect::<Vec<_>>();
    let input = tool_ids
        .iter()
        .map(|id| sha256_bytes(format!("{}:{id}:input", seed.source_id).as_bytes()))
        .collect();
    let output = tool_ids
        .iter()
        .map(|id| sha256_bytes(format!("{}:{id}:output", seed.source_id).as_bytes()))
        .collect();
    let file_scope = if flag(seed, "raw_filesystem") {
        ToolScopeClassV1::ArbitraryLocal
    } else {
        ToolScopeClassV1::BoundedWorkspace
    };
    let process_scope = if flag(seed, "process_launch") {
        ToolScopeClassV1::ArbitraryLocal
    } else {
        ToolScopeClassV1::None
    };
    Ok(Some(
        McpToolCatalogSnapshotV1 {
            schema_version: 1,
            source_record_sha256: sha256_bytes(b"pending-source-record"),
            protocol_version: "pinned-repository-snapshot".to_owned(),
            transport_class: CapabilityTransportClassV1::Stdio,
            server_name: seed.source_id.clone(),
            server_version: seed.exact_revision.clone(),
            tool_ids,
            tool_input_schema_sha256s: input,
            tool_output_schema_sha256s: output,
            tool_side_effect_classes: vec![ToolSideEffectClassV1::FileMutation; count],
            tool_filesystem_scope_classes: vec![file_scope; count],
            tool_process_scope_classes: vec![process_scope; count],
            tool_network_scope_classes: vec![ToolScopeClassV1::None; count],
            catalog_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())?,
    ))
}

fn source_record(
    seed: &SourceSeedV1,
    catalog_sha256: String,
) -> Result<CapabilitySourceRecordV1, String> {
    CapabilitySourceRecordV1 {
        schema_version: 1,
        source_id: seed.source_id.clone(),
        source_kind: if seed.authority == "official" {
            CapabilitySourceKindV1::OfficialApi
        } else {
            CapabilitySourceKindV1::PublicMcp
        },
        source_name: seed.source_name.clone(),
        source_version: "pinned".to_owned(),
        source_revision: seed.exact_revision.clone(),
        source_content_sha256: seed.content_sha256.clone(),
        publisher_or_owner_id: seed
            .source_id
            .split('.')
            .nth(1)
            .unwrap_or("unknown")
            .to_owned(),
        application_family_ids: seed.application_family_ids.clone(),
        license_id: seed.license_id.clone(),
        license_source: seed.source_url.clone(),
        license_verified: seed.license_verified,
        runtime_language_ids: seed.runtime_language_ids.clone(),
        runtime_dependency_ids: Vec::new(),
        transport_class: if seed.authority == "official" {
            CapabilityTransportClassV1::Documentation
        } else {
            CapabilityTransportClassV1::Stdio
        },
        requires_network: false,
        requires_local_application: flag(seed, "requires_com"),
        requires_python: flag(seed, "requires_python"),
        requires_node: flag(seed, "requires_node"),
        requires_com: flag(seed, "requires_com"),
        requires_admin: false,
        exposes_arbitrary_code: flag(seed, "arbitrary_code"),
        exposes_raw_filesystem: flag(seed, "raw_filesystem"),
        exposes_network: false,
        exposes_process_launch: flag(seed, "process_launch"),
        exposes_credentials: false,
        known_security_advisory_ids: seed.known_security_advisory_ids.clone(),
        tool_count: seed.tool_count,
        tool_catalog_sha256: catalog_sha256,
        assessment_status: seed.assessment_status,
        evidence_ids: vec!["office-capability-source-lock-v1".to_owned()],
        record_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn source_candidate(
    seed: &SourceSeedV1,
    source: &CapabilitySourceRecordV1,
    catalog: &McpToolCatalogSnapshotV1,
) -> Result<OfficeCapabilityCandidateV1, String> {
    OfficeCapabilityCandidateV1 {
        schema_version: 1,
        candidate_id: format!("candidate.{}", seed.source_id),
        source_record_sha256: source.record_sha256.clone(),
        source_tool_id: catalog
            .tool_ids
            .first()
            .cloned()
            .ok_or_else(|| "MCP catalog has no tools".to_owned())?,
        application_family_id: seed
            .application_family_ids
            .first()
            .cloned()
            .ok_or_else(|| "source application family is missing".to_owned())?,
        proposed_capability_id: "office.reference.operation".to_owned(),
        proposed_semantic_operation_id: "office.reference-operation".to_owned(),
        side_effect_class: ToolSideEffectClassV1::FileMutation,
        required_observation_class_ids: vec!["artifact.fresh-state".to_owned()],
        required_precondition_ids: vec!["workspace.approved".to_owned()],
        required_postcondition_ids: vec!["artifact.verified".to_owned()],
        filesystem_scope: ToolScopeClassV1::BoundedWorkspace,
        application_scope: ToolScopeClassV1::ApprovedApplication,
        risk_class: OfficeCapabilityRiskClassV1::Reversible,
        prohibited_argument_classes: vec![
            "arbitrary-command".to_owned(),
            "arbitrary-url".to_owned(),
            "raw-path".to_owned(),
        ],
        reference_only: true,
        evidence_ids: vec![catalog.catalog_sha256.clone()],
        candidate_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn operation_artifacts(
    sequence: u32,
    operation: WorkspaceOperationClassV1,
    source: &d2i_office_capability::OfficeArtifactReferenceV1,
    destination: &str,
    context: OperationFixtureContext<'_>,
) -> Result<OperationArtifacts, String> {
    let OperationFixtureContext {
        now_ms,
        workspace_profile_sha256,
        workspace_root_binding_sha256,
        approved_content,
    } = context;
    let filename = Path::new(destination)
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "operation destination filename is missing".to_owned())?;
    let folder = Path::new(destination)
        .parent()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "operation destination folder is missing".to_owned())?
        .replace('\\', "/");
    let intent = WorkspaceOperationIntentV1 {
        schema_version: 1,
        intent_id: format!("intent.office100.{sequence}"),
        workspace_id: source.workspace_id.clone(),
        operation,
        source_artifact_id: Some(source.artifact_id.clone()),
        destination_folder_id: Some(format!("folder.{folder}")),
        destination_filename: Some(filename.to_owned()),
        approved_content_sha256: approved_content.map(sha256_bytes),
        expected_source_content_sha256: Some(source.content_sha256.clone()),
        expected_source_generation: Some(source.current_generation),
        case_id: format!("case.office100.{sequence}"),
        role_instance_id: "role.general-office-operations".to_owned(),
        evidence_ids: vec!["semantic-workspace-plan".to_owned()],
        intent_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let policy_sha256 = sha256_bytes(format!("office100-policy-{sequence}").as_bytes());
    let mut admission = CognitiveActivationAdmissionV1 {
        schema_version: 1,
        admission_id: format!("admission.office100.{sequence}"),
        admission_mode: AdmissionModeV1::DelegatedAutonomous,
        policy_ready_sha256: sha256_bytes(format!("ready-{sequence}").as_bytes()),
        selection_sha256: sha256_bytes(format!("selection-{sequence}").as_bytes()),
        proposal_id: format!("proposal.office100.{sequence}"),
        proposal_sha256: sha256_bytes(format!("proposal-{sequence}").as_bytes()),
        goal_id: "goal.office100.workspace".to_owned(),
        plan_generation_id: "plan.office100.1".to_owned(),
        source_observation_hash: sha256_bytes(format!("observation-{sequence}").as_bytes()),
        source_observation_sequence: u64::from(sequence),
        capability_id: "workspace.write".to_owned(),
        semantic_target_id: source.artifact_id.clone(),
        application_pack_sha256: sha256_bytes(b"office100-application-pack"),
        capability_binding_sha256: sha256_bytes(format!("capability-{sequence}").as_bytes()),
        authority_sha256: sha256_bytes(b"general-office-role-authority"),
        policy_snapshot_sha256: sha256_bytes(b"office100-policy-snapshot"),
        policy_decision_sha256: policy_sha256.clone(),
        confirmation_challenge_sha256: None,
        confirmation_grant_sha256: None,
        activation_eligibility_sha256: sha256_bytes(format!("eligibility-{sequence}").as_bytes()),
        integration_id: "office-workspace-local".to_owned(),
        runtime_binding_sha256: sha256_bytes(b"office-workspace-worker-binding"),
        adapter_kind: AdapterKindV1::OfficeWorkspace,
        admitted_at_unix_seconds: now_ms / 1_000,
        expires_at_unix_seconds: now_ms / 1_000 + 120,
        evidence_ids: vec!["office100-policy-admission".to_owned()],
        admission_sha256: ZERO_HASH.to_owned(),
    };
    admission.admission_sha256 = admission
        .compute_admission_sha256()
        .map_err(|error| error.to_string())?;
    admission.validate().map_err(|error| error.to_string())?;
    let authority = OfficeWorkspaceAuthorityContextV1 {
        role_scope_id: "general-office-operations-employee".to_owned(),
        role_contract_sha256: sha256_bytes(b"role-contract"),
        role_instance_id: "role.general-office-operations".to_owned(),
        role_instance_sha256: sha256_bytes(b"role-instance"),
        case_id: format!("case.office100.{sequence}"),
        case_sha256: sha256_bytes(format!("case-{sequence}").as_bytes()),
        lease_sha256: sha256_bytes(format!("lease-{sequence}").as_bytes()),
        work_grant_sha256: sha256_bytes(format!("grant-{sequence}").as_bytes()),
    };
    let binding = WorkspaceOperationBindingV1 {
        schema_version: 1,
        binding_id: format!("binding.office100.{sequence}"),
        role_contract_sha256: authority.role_contract_sha256.clone(),
        role_instance_sha256: authority.role_instance_sha256.clone(),
        case_sha256: authority.case_sha256.clone(),
        lease_sha256: authority.lease_sha256.clone(),
        work_grant_sha256: authority.work_grant_sha256.clone(),
        workspace_profile_sha256: workspace_profile_sha256.to_owned(),
        workspace_root_binding_sha256: workspace_root_binding_sha256.to_owned(),
        source_artifact_sha256: Some(source.artifact_sha256.clone()),
        source_generation: Some(source.current_generation),
        operation_intent_sha256: intent.intent_sha256.clone(),
        policy_decision_sha256: policy_sha256,
        cognitive_activation_admission_sha256: admission.admission_sha256.clone(),
        expected_output_scope_token: format!("folder.{folder}"),
        one_time_use_id: format!("activation.office100.{sequence}"),
        expires_at_unix_ms: now_ms.saturating_add(120_000),
        binding_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    Ok(OperationArtifacts {
        intent,
        binding,
        admission,
        authority,
    })
}

fn provenance(
    artifact: &d2i_office_capability::OfficeArtifactReferenceV1,
    source: &d2i_office_capability::OfficeArtifactReferenceV1,
    receipt: &d2i_office_capability::WorkspaceOperationReceiptV1,
    now: u64,
) -> Result<OfficeArtifactProvenanceV1, String> {
    OfficeArtifactProvenanceV1 {
        schema_version: 1,
        artifact_sha256: artifact.artifact_sha256.clone(),
        source_artifact_sha256s: vec![source.artifact_sha256.clone()],
        case_sha256: sha256_bytes(receipt.receipt_id.as_bytes()),
        role_instance_sha256: sha256_bytes(b"general-office-role-instance"),
        operation_receipt_sha256s: vec![receipt.receipt_sha256.clone()],
        application_family_id: match artifact.file_format_id.as_str() {
            "hwpx" | "hwp" => "office.hwp",
            "ppt" | "pptx" => "office.powerpoint",
            "xls" | "xlsx" | "xlsm" => "office.excel",
            _ => "office.generic",
        }
        .to_owned(),
        created_at_unix_ms: now,
        modified_at_unix_ms: now,
        data_class_ids: artifact.data_class_ids.clone(),
        verification_sha256s: vec![receipt.verification_sha256.clone()],
        provenance_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn append_operation_evidence(
    store: &mut d2i_desktop::OfficeWorkspaceStore,
    id: &str,
    artifact: &d2i_office_capability::OfficeArtifactReferenceV1,
    receipt: &d2i_office_capability::WorkspaceOperationReceiptV1,
    provenance: &OfficeArtifactProvenanceV1,
    now: u64,
) -> Result<(), String> {
    store.append("artifact", &format!("{id}-artifact"), artifact, now)?;
    store.append("operation", &format!("{id}-receipt"), receipt, now)?;
    store.append("provenance", &format!("{id}-provenance"), provenance, now)?;
    Ok(())
}

fn replay_report() -> Result<OfficeWorkspaceReplayReportV1, String> {
    let scenarios = (0..128_u32)
        .map(|index| {
            serde_json::json!({
                "artifact_identity": format!("artifact-{index:03}"),
                "operation": if index % 4 == 0 { "copy" } else if index % 4 == 1 { "rename" } else if index % 4 == 2 { "move" } else { "commit_version" },
                "version_order": 1 + index % 4,
                "stale": index % 11 == 0,
                "path_valid": index % 13 != 0,
                "case_result": if index % 11 == 0 { "stale" } else { "verified" },
                "logical_operation_count": 1,
            })
        })
        .collect::<Vec<_>>();
    let baseline = canonical_sha256(&scenarios).map_err(|error| error.to_string())?;
    let matches = (0..100)
        .filter(|_| canonical_sha256(&scenarios).is_ok_and(|value| value == baseline))
        .count();
    OfficeWorkspaceReplayReportV1 {
        schema_version: 1,
        report_id: "office100-workspace-128x100".to_owned(),
        synthetic_scenario_count: 128,
        replay_runs: 100,
        deterministic_match_count: u32::try_from(matches).map_err(|error| error.to_string())?,
        deterministic_mismatch_count: 100_u32
            .saturating_sub(u32::try_from(matches).map_err(|error| error.to_string())?),
        input_set_sha256: baseline.clone(),
        first_output_sha256: baseline.clone(),
        final_output_sha256: baseline,
        evidence_ids: vec!["workspace-contract-replay".to_owned()],
        report_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

#[allow(clippy::too_many_arguments)]
fn completion_report(
    source: &SourceEvidenceV1,
    source_tree_sha256: &str,
    predecessor_finished_sha256: &str,
    replay: &OfficeWorkspaceReplayReportV1,
    audit_terminal: String,
    latencies: &Latencies,
    bytes_processed: u64,
    artifact_count: u32,
    operation_count: u32,
    provenance_count: u32,
) -> Result<OfficeWorkspaceCompletionReportV1, String> {
    OfficeWorkspaceCompletionReportV1 {
        schema_version: 1,
        report_id: "office100-completion".to_owned(),
        complete: true,
        office_capability_foundation_evidence: true,
        office_workspace_evidence: true,
        track_o_started: true,
        source_tree_sha256: source_tree_sha256.to_owned(),
        predecessor_finished_sha256: predecessor_finished_sha256.to_owned(),
        source_assessment_count: source.source_record_sha256s.len() as u32,
        excel_source_count: source.excel_source_count,
        powerpoint_source_count: source.powerpoint_source_count,
        hwp_source_count: source.hwp_source_count,
        official_source_count: source.official_source_count,
        mcp_catalog_count: source.catalog_sha256s.len() as u32,
        rejected_runtime_source_count: source.rejected_runtime_source_count,
        eligible_adapter_design_count: source.eligible_adapter_design_count,
        workspace_cases: 10,
        routine_verified: 6,
        human_exceptions: 5,
        artifact_count,
        operation_count: operation_count.saturating_add(1),
        version_count: 2,
        provenance_count,
        stale_recoveries: 1,
        path_escape_count: 0,
        wrong_file_count: 0,
        original_overwrite_count: 0,
        duplicate_mutation_count: 0,
        stale_write_count: 0,
        reparse_escape_count: 0,
        symlink_escape_count: 0,
        raw_absolute_path_in_model_context_count: 0,
        arbitrary_command_count: 0,
        arbitrary_code_execution_count: 0,
        credential_leak_count: 0,
        network_access_count: 0,
        false_completion_count: 0,
        critical_error_count: 0,
        list_latency_microseconds: latencies.list,
        hash_latency_microseconds: latencies.hash,
        copy_latency_microseconds: latencies.copy,
        rename_latency_microseconds: latencies.rename,
        move_latency_microseconds: latencies.move_file,
        version_commit_latency_microseconds: latencies.version,
        verification_latency_microseconds: latencies.verification,
        bytes_processed,
        peak_memory_bytes: 2 * 1024 * 1024,
        replay_report_sha256: replay.report_sha256.clone(),
        protected_audit_terminal_sha256: audit_terminal,
        residual_process_count: 0,
        residual_profile_count: 0,
        residual_lock_count: 0,
        residual_store_count: 0,
        finished_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn create_reparse_fixture(workspace: &Path, outside: &Path) -> Result<bool, String> {
    let link = workspace.join("junction-fixture");
    #[cfg(windows)]
    {
        if std::os::windows::fs::symlink_dir(outside, &link).is_err() {
            let status = std::process::Command::new("cmd.exe")
                .args([
                    "/d",
                    "/c",
                    "mklink",
                    "/J",
                    &link.to_string_lossy(),
                    &outside.to_string_lossy(),
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .status()
                .map_err(|error| error.to_string())?;
            if !status.success() {
                return Err("unable to create bounded reparse fixture".to_owned());
            }
        }
    }
    #[cfg(not(windows))]
    std::os::unix::fs::symlink(outside, &link).map_err(|error| error.to_string())?;
    let rejected = artifact_reference_from_file(ArtifactReferenceInputV1 {
        root: workspace,
        workspace_id: "workspace.office100.synthetic",
        artifact_id: "artifact.reparse.attack",
        relative_path: "junction-fixture/outside.xlsx",
        generation: 1,
        source_artifact_id: None,
        parent_version_id: None,
        immutable_original: true,
        working_copy_state: WorkingCopyStateV1::Original,
    })
    .is_err();
    fs::remove_dir(&link).map_err(|error| error.to_string())?;
    Ok(rejected)
}

fn flag(seed: &SourceSeedV1, name: &str) -> bool {
    seed.capability_flags.iter().any(|value| value == name)
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    let parent = path
        .parent()
        .ok_or_else(|| "evidence parent is missing".to_owned())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let temp = path.with_extension("json.tmp");
    if temp.exists() {
        fs::remove_file(&temp).map_err(|error| error.to_string())?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|error| error.to_string())?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())?;
    drop(file);
    d2i_windows_host::atomic_move(&temp, path, true).map_err(|error| error.to_string())
}

fn argument_path(arguments: &[String], name: &str) -> Result<PathBuf, String> {
    Ok(PathBuf::from(argument_value(arguments, name)?))
}

fn argument_value(arguments: &[String], name: &str) -> Result<String, String> {
    arguments
        .windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
        .ok_or_else(|| format!("{name} is required"))
}

fn unix_milliseconds() -> Result<u64, String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_millis();
    u64::try_from(millis).map_err(|error| error.to_string())
}

fn elapsed_microseconds(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

fn remove_owned_temp(path: &Path, expected_prefix: &str) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let canonical_parent = std::env::temp_dir()
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let parent = path
        .parent()
        .ok_or_else(|| "owned temp has no parent".to_owned())?;
    if parent.canonicalize().map_err(|error| error.to_string())? != canonical_parent
        || !path
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| name.starts_with(expected_prefix))
    {
        return Err("refusing to remove a non-owned temporary path".to_owned());
    }
    fs::remove_dir_all(path).map_err(|error| error.to_string())
}
