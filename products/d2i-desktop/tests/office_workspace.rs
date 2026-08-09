use d2i_desktop::{
    artifact_reference_from_file, create_workspace_root_binding, execute_file_worker_request,
    observe_artifacts, ArtifactReferenceInputV1, OfficeFileWorkerOperationV1,
    OfficeFileWorkerRequestV1, OfficeWorkspaceKrnDispatcherV1,
};
use d2i_office_capability::{
    sha256_bytes, OfficeWorkspaceProfileV1, WorkingCopyStateV1, WorkspaceOperationClassV1,
    ZERO_HASH,
};
use ed25519_dalek::SigningKey;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn temporary_root(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_nanos());
    std::env::temp_dir().join(format!(
        "d2i-office100-integration-{label}-{}-{nonce}",
        std::process::id()
    ))
}

fn profile(workspace_id: &str, root_binding_sha256: String, now: u64) -> OfficeWorkspaceProfileV1 {
    OfficeWorkspaceProfileV1 {
        schema_version: 1,
        workspace_id: workspace_id.to_owned(),
        organization_id: "example-office-organization".to_owned(),
        role_scope_ids: vec!["general-office-operations-employee".to_owned()],
        workspace_root_binding_sha256: root_binding_sha256,
        allowed_artifact_classes: vec!["office.document".to_owned()],
        allowed_extensions: vec!["hwpx".to_owned()],
        maximum_total_bytes: 4096,
        maximum_file_bytes: 1024,
        maximum_files: 8,
        maximum_directories: 4,
        maximum_depth: 4,
        allowed_operations: vec![
            WorkspaceOperationClassV1::ListArtifacts,
            WorkspaceOperationClassV1::InspectArtifact,
            WorkspaceOperationClassV1::CreateWorkingCopy,
        ],
        versioning_policy_id: "append-only-generations".to_owned(),
        backup_policy_id: "content-addressed-versions".to_owned(),
        overwrite_policy_id: "deny-original-overwrite".to_owned(),
        delete_policy_id: "prohibited".to_owned(),
        retention_policy_id: "case-bound-retention".to_owned(),
        valid_from_unix_ms: now.saturating_sub(1),
        valid_until_unix_ms: now.saturating_add(86_400_000),
        evidence_ids: vec!["office100-integration-profile".to_owned()],
        signer_key_id: "office100-test-key".to_owned(),
        profile_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
}

#[cfg(windows)]
#[test]
fn unsigned_tampered_and_wrong_root_profiles_fail_closed() {
    let root = temporary_root("profile");
    fs::create_dir_all(&root).unwrap_or_else(|error| panic!("create root: {error}"));
    let now = 1_000_000_u64;
    let binding = create_workspace_root_binding(
        &root,
        "workspace.office100.integration",
        now.saturating_sub(1),
        now.saturating_add(86_400_000),
    )
    .unwrap_or_else(|error| panic!("root binding: {error}"));
    let executable = std::env::current_exe().unwrap_or_else(|error| panic!("current exe: {error}"));
    let executable_hash = sha256_bytes(
        &fs::read(&executable).unwrap_or_else(|error| panic!("read executable: {error}")),
    );
    let key = SigningKey::from_bytes(&[31_u8; 32]);
    let unsigned = profile(&binding.workspace_id, binding.binding_sha256.clone(), now);
    assert!(OfficeWorkspaceKrnDispatcherV1::new(
        executable.clone(),
        executable_hash.clone(),
        root.clone(),
        binding.clone(),
        unsigned,
        &key.verifying_key(),
        now,
    )
    .is_err());
    let mut tampered = profile(&binding.workspace_id, binding.binding_sha256.clone(), now)
        .sign(&key)
        .unwrap_or_else(|error| panic!("sign: {error}"));
    tampered.maximum_files += 1;
    assert!(OfficeWorkspaceKrnDispatcherV1::new(
        executable.clone(),
        executable_hash.clone(),
        root.clone(),
        binding.clone(),
        tampered,
        &key.verifying_key(),
        now,
    )
    .is_err());
    let signed = profile(&binding.workspace_id, binding.binding_sha256.clone(), now)
        .sign(&key)
        .unwrap_or_else(|error| panic!("sign valid: {error}"));
    let wrong_root = temporary_root("wrong-root");
    fs::create_dir_all(&wrong_root).unwrap_or_else(|error| panic!("wrong root: {error}"));
    assert!(OfficeWorkspaceKrnDispatcherV1::new(
        executable,
        executable_hash,
        wrong_root.clone(),
        binding,
        signed,
        &key.verifying_key(),
        now,
    )
    .is_err());
    fs::remove_dir_all(root).unwrap_or_else(|error| panic!("cleanup root: {error}"));
    fs::remove_dir_all(wrong_root).unwrap_or_else(|error| panic!("cleanup wrong root: {error}"));
}

#[test]
fn cross_workspace_wrong_artifact_and_external_change_are_rejected() {
    let root = temporary_root("artifact");
    fs::create_dir_all(root.join("incoming"))
        .unwrap_or_else(|error| panic!("create root: {error}"));
    fs::write(root.join("incoming/report.hwpx"), b"version-one")
        .unwrap_or_else(|error| panic!("write fixture: {error}"));
    let artifact = artifact_reference_from_file(ArtifactReferenceInputV1 {
        root: &root,
        workspace_id: "workspace.office100.integration",
        artifact_id: "artifact.report",
        relative_path: "incoming/report.hwpx",
        generation: 1,
        source_artifact_id: None,
        parent_version_id: None,
        immutable_original: true,
        working_copy_state: WorkingCopyStateV1::Original,
    })
    .unwrap_or_else(|error| panic!("artifact: {error}"));
    assert!(observe_artifacts(
        &root,
        "workspace.other",
        std::slice::from_ref(&artifact),
        "observation.cross-workspace",
        1_000,
        100,
    )
    .is_err());
    fs::write(root.join("incoming/report.hwpx"), b"external-change")
        .unwrap_or_else(|error| panic!("external change: {error}"));
    let observation = observe_artifacts(
        &root,
        "workspace.office100.integration",
        std::slice::from_ref(&artifact),
        "observation.stale",
        1_000,
        100,
    )
    .unwrap_or_else(|error| panic!("fresh observation: {error}"));
    assert_ne!(observation.content_sha256s[0], artifact.content_sha256);
    fs::remove_dir_all(root).unwrap_or_else(|error| panic!("cleanup: {error}"));
}

#[test]
fn worker_rejects_absolute_unc_ads_device_and_oversized_content() {
    let root = temporary_root("worker-negative");
    fs::create_dir_all(root.join("incoming"))
        .unwrap_or_else(|error| panic!("create incoming: {error}"));
    fs::create_dir_all(root.join("working"))
        .unwrap_or_else(|error| panic!("create working: {error}"));
    fs::write(root.join("incoming/report.hwpx"), b"version-one")
        .unwrap_or_else(|error| panic!("write source: {error}"));
    let canonical = root
        .canonicalize()
        .unwrap_or_else(|error| panic!("canonical root: {error}"));
    let root_text = canonical
        .to_string_lossy()
        .strip_prefix(r"\\?\")
        .unwrap_or(&canonical.to_string_lossy())
        .replace('\\', "/");
    let base = OfficeFileWorkerRequestV1 {
        schema_version: 1,
        request_id: "worker-negative-1".to_owned(),
        workspace_root: root_text,
        workspace_root_binding_sha256: sha256_bytes(b"binding"),
        operation: OfficeFileWorkerOperationV1::Copy,
        source_relative_path: "incoming/report.hwpx".to_owned(),
        destination_relative_path: "working/report.hwpx".to_owned(),
        expected_source_sha256: sha256_bytes(b"version-one"),
        expected_source_generation: 1,
        approved_content_hex: None,
        approved_content_sha256: None,
        maximum_bytes: 64,
    };
    for invalid in [
        "C:/outside.hwpx",
        "//server/share.hwpx",
        "working/file.hwpx:stream",
        "//?/C:/device.hwpx",
    ] {
        let mut request = base.clone();
        request.destination_relative_path = invalid.to_owned();
        assert!(
            execute_file_worker_request(&request).is_err(),
            "accepted {invalid}"
        );
    }
    let oversized = vec![b'a'; 65];
    let mut request = base;
    request.operation = OfficeFileWorkerOperationV1::CommitVersion;
    request.approved_content_hex =
        Some(oversized.iter().map(|byte| format!("{byte:02x}")).collect());
    request.approved_content_sha256 = Some(sha256_bytes(&oversized));
    assert!(execute_file_worker_request(&request).is_err());
    assert!(!root.join("working/report.hwpx").exists());
    fs::remove_dir_all(root).unwrap_or_else(|error| panic!("cleanup: {error}"));
}

#[test]
fn resource_limits_and_delete_or_overwrite_policy_cannot_be_weakened() {
    let key = SigningKey::from_bytes(&[32_u8; 32]);
    let mut unsafe_profile = profile(
        "workspace.office100.integration",
        sha256_bytes(b"root"),
        1_000_000,
    );
    unsafe_profile.delete_policy_id = "autonomous-delete".to_owned();
    assert!(unsafe_profile.sign(&key).is_err());
    let mut oversized = profile(
        "workspace.office100.integration",
        sha256_bytes(b"root"),
        1_000_000,
    );
    oversized.maximum_file_bytes = oversized.maximum_total_bytes + 1;
    assert!(oversized.sign(&key).is_err());
    let mut too_deep = profile(
        "workspace.office100.integration",
        sha256_bytes(b"root"),
        1_000_000,
    );
    too_deep.maximum_depth = 17;
    assert!(too_deep.sign(&key).is_err());
}
