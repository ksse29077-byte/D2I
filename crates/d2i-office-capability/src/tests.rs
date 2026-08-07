use super::*;
use ed25519_dalek::SigningKey;
use serde_json::json;

fn hash(label: &str) -> String {
    sha256_bytes(label.as_bytes())
}

fn source(status: SourceAssessmentStatusV1) -> CapabilitySourceRecordV1 {
    CapabilitySourceRecordV1 {
        schema_version: 1,
        source_id: "source.excel.reference".to_owned(),
        source_kind: CapabilitySourceKindV1::PublicMcp,
        source_name: "Reference Excel MCP".to_owned(),
        source_version: "pinned".to_owned(),
        source_revision: "f51340ecd5778952405044b203d3a2d4c8a46833".to_owned(),
        source_content_sha256: hash("source-content"),
        publisher_or_owner_id: "reference-owner".to_owned(),
        application_family_ids: vec!["office.excel".to_owned()],
        license_id: "MIT".to_owned(),
        license_source: "https://github.com/example/license".to_owned(),
        license_verified: true,
        runtime_language_ids: vec!["python".to_owned()],
        runtime_dependency_ids: vec!["openpyxl".to_owned()],
        transport_class: CapabilityTransportClassV1::Stdio,
        requires_network: false,
        requires_local_application: false,
        requires_python: true,
        requires_node: false,
        requires_com: false,
        requires_admin: false,
        exposes_arbitrary_code: false,
        exposes_raw_filesystem: false,
        exposes_network: false,
        exposes_process_launch: false,
        exposes_credentials: false,
        known_security_advisory_ids: Vec::new(),
        tool_count: 2,
        tool_catalog_sha256: hash("catalog"),
        assessment_status: status,
        evidence_ids: vec!["pinned-source-tree".to_owned()],
        record_sha256: ZERO_HASH.to_owned(),
    }
}

fn catalog(source_hash: String) -> McpToolCatalogSnapshotV1 {
    McpToolCatalogSnapshotV1 {
        schema_version: 1,
        source_record_sha256: source_hash,
        protocol_version: "2025-11-25".to_owned(),
        transport_class: CapabilityTransportClassV1::Stdio,
        server_name: "reference-excel-mcp".to_owned(),
        server_version: "pinned".to_owned(),
        tool_ids: vec!["read_range".to_owned(), "write_range".to_owned()],
        tool_input_schema_sha256s: vec![hash("read-input"), hash("write-input")],
        tool_output_schema_sha256s: vec![hash("read-output"), hash("write-output")],
        tool_side_effect_classes: vec![
            ToolSideEffectClassV1::ReadOnly,
            ToolSideEffectClassV1::FileMutation,
        ],
        tool_filesystem_scope_classes: vec![
            ToolScopeClassV1::BoundedWorkspace,
            ToolScopeClassV1::BoundedWorkspace,
        ],
        tool_process_scope_classes: vec![ToolScopeClassV1::None, ToolScopeClassV1::None],
        tool_network_scope_classes: vec![ToolScopeClassV1::None, ToolScopeClassV1::None],
        catalog_sha256: ZERO_HASH.to_owned(),
    }
}

fn root_binding() -> WorkspaceRootBindingV1 {
    WorkspaceRootBindingV1 {
        schema_version: 1,
        workspace_id: "workspace.office100".to_owned(),
        canonical_root: "C:/bounded/runtime-only/root".to_owned(),
        root_identity: "root.office100".to_owned(),
        volume_identity: "volume.fixed.local".to_owned(),
        security_descriptor_sha256: hash("dacl"),
        reparse_forbidden: true,
        symlink_forbidden: true,
        network_share_allowed: false,
        removable_media_allowed: false,
        valid_from_unix_ms: 1_000,
        valid_until_unix_ms: 2_000,
        binding_sha256: ZERO_HASH.to_owned(),
    }
}

fn profile(root_hash: String) -> OfficeWorkspaceProfileV1 {
    OfficeWorkspaceProfileV1 {
        schema_version: 1,
        workspace_id: "workspace.office100".to_owned(),
        organization_id: "example-office-organization".to_owned(),
        role_scope_ids: vec!["general-office-operations-employee".to_owned()],
        workspace_root_binding_sha256: root_hash,
        allowed_artifact_classes: vec!["office.document".to_owned()],
        allowed_extensions: vec!["hwpx".to_owned(), "xlsx".to_owned()],
        maximum_total_bytes: 1_048_576,
        maximum_file_bytes: 262_144,
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
        valid_from_unix_ms: 1_000,
        valid_until_unix_ms: 2_000,
        evidence_ids: vec!["office100-workspace-policy".to_owned()],
        signer_key_id: "office100-workspace-key".to_owned(),
        profile_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
}

fn artifact() -> OfficeArtifactReferenceV1 {
    OfficeArtifactReferenceV1 {
        schema_version: 1,
        artifact_id: "artifact.report-template".to_owned(),
        workspace_id: "workspace.office100".to_owned(),
        relative_path_token: "incoming/report-template.hwpx".to_owned(),
        artifact_class: "office.document".to_owned(),
        file_format_id: "hwpx".to_owned(),
        content_sha256: hash("synthetic-hwpx"),
        byte_length: 14,
        creation_generation: 1,
        current_generation: 1,
        source_artifact_id: None,
        parent_version_id: None,
        immutable_original: true,
        working_copy_state: WorkingCopyStateV1::Original,
        data_class_ids: vec!["internal".to_owned()],
        evidence_ids: vec!["fixture-import".to_owned()],
        artifact_sha256: ZERO_HASH.to_owned(),
    }
}

fn intent(source: &OfficeArtifactReferenceV1) -> WorkspaceOperationIntentV1 {
    WorkspaceOperationIntentV1 {
        schema_version: 1,
        intent_id: "intent.create-working-copy".to_owned(),
        workspace_id: source.workspace_id.clone(),
        operation: WorkspaceOperationClassV1::CreateWorkingCopy,
        source_artifact_id: Some(source.artifact_id.clone()),
        destination_folder_id: Some("folder.current-case-work".to_owned()),
        destination_filename: Some("2026_교육실적_결과보고서.hwpx".to_owned()),
        approved_content_sha256: None,
        expected_source_content_sha256: Some(source.content_sha256.clone()),
        expected_source_generation: Some(source.current_generation),
        case_id: "case.office100".to_owned(),
        role_instance_id: "role.general-office".to_owned(),
        evidence_ids: vec!["semantic-workspace-plan".to_owned()],
        intent_sha256: ZERO_HASH.to_owned(),
    }
}

fn binding(intent_hash: String, source_hash: String) -> WorkspaceOperationBindingV1 {
    WorkspaceOperationBindingV1 {
        schema_version: 1,
        binding_id: "binding.office100".to_owned(),
        role_contract_sha256: hash("role-contract"),
        role_instance_sha256: hash("role-instance"),
        case_sha256: hash("case"),
        lease_sha256: hash("lease"),
        work_grant_sha256: hash("grant"),
        workspace_profile_sha256: hash("profile"),
        workspace_root_binding_sha256: hash("root"),
        source_artifact_sha256: Some(source_hash),
        source_generation: Some(1),
        operation_intent_sha256: intent_hash,
        policy_decision_sha256: hash("policy"),
        cognitive_activation_admission_sha256: hash("admission"),
        expected_output_scope_token: "folder.current-case-work".to_owned(),
        one_time_use_id: "activation.office100.1".to_owned(),
        expires_at_unix_ms: 2_000,
        binding_sha256: ZERO_HASH.to_owned(),
    }
}

#[test]
fn signed_workspace_profile_rejects_tamper_wrong_key_and_unsafe_policy() {
    let root = root_binding()
        .seal()
        .unwrap_or_else(|error| panic!("root: {error}"));
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let signed = profile(root.binding_sha256)
        .sign(&key)
        .unwrap_or_else(|error| panic!("sign: {error}"));
    signed
        .validate_signature(&key.verifying_key())
        .unwrap_or_else(|error| panic!("verify: {error}"));
    assert!(signed
        .validate_signature(&SigningKey::from_bytes(&[8_u8; 32]).verifying_key())
        .is_err());
    let mut tampered = signed.clone();
    tampered.maximum_files += 1;
    assert!(tampered.validate_signature(&key.verifying_key()).is_err());
    let mut unsafe_profile = profile(hash("root"));
    unsafe_profile.delete_policy_id = "autonomous-delete".to_owned();
    assert!(unsafe_profile.sign(&key).is_err());
}

#[test]
fn public_sources_remain_reference_only_and_dangerous_tools_are_rejected() {
    let safe = source(SourceAssessmentStatusV1::EligibleForAdapterDesign)
        .seal()
        .unwrap_or_else(|error| panic!("source: {error}"));
    assert!(runtime_rejection_reason_ids(&safe).is_empty());
    let mut dangerous = source(SourceAssessmentStatusV1::RejectedForRuntime);
    dangerous.exposes_arbitrary_code = true;
    dangerous.exposes_process_launch = true;
    dangerous.exposes_raw_filesystem = true;
    dangerous.transport_class = CapabilityTransportClassV1::RemoteHttp;
    dangerous.exposes_network = true;
    dangerous.license_verified = false;
    let dangerous = dangerous
        .seal()
        .unwrap_or_else(|error| panic!("dangerous: {error}"));
    assert_eq!(runtime_rejection_reason_ids(&dangerous).len(), 5);
    let mut promoted = dangerous;
    promoted.assessment_status = SourceAssessmentStatusV1::ApprovedForOfflineConformance;
    promoted.record_sha256 = ZERO_HASH.to_owned();
    assert!(promoted.seal().is_err());
}

#[test]
fn catalog_candidate_and_artifact_contracts_are_exact() {
    let unlinked_catalog = catalog(hash("pending-source"))
        .seal()
        .unwrap_or_else(|error| panic!("unlinked catalog: {error}"));
    let mut source_input = source(SourceAssessmentStatusV1::ApprovedAsReference);
    source_input.tool_catalog_sha256 = unlinked_catalog.catalog_sha256.clone();
    let source = source_input
        .seal()
        .unwrap_or_else(|error| panic!("source: {error}"));
    let mut catalog = unlinked_catalog;
    catalog.source_record_sha256 = source.record_sha256.clone();
    catalog
        .validate_integrity()
        .unwrap_or_else(|error| panic!("linked catalog: {error}"));
    assert_eq!(catalog.tool_ids.len(), 2);
    let candidate = OfficeCapabilityCandidateV1 {
        schema_version: 1,
        candidate_id: "candidate.spreadsheet.read-range".to_owned(),
        source_record_sha256: source.record_sha256,
        source_tool_id: "read_range".to_owned(),
        application_family_id: "office.excel".to_owned(),
        proposed_capability_id: "spreadsheet.inspect".to_owned(),
        proposed_semantic_operation_id: "spreadsheet.read-range".to_owned(),
        side_effect_class: ToolSideEffectClassV1::ReadOnly,
        required_observation_class_ids: vec!["spreadsheet.range-state".to_owned()],
        required_precondition_ids: vec!["artifact.fresh".to_owned()],
        required_postcondition_ids: vec!["artifact.unchanged".to_owned()],
        filesystem_scope: ToolScopeClassV1::BoundedWorkspace,
        application_scope: ToolScopeClassV1::ApprovedApplication,
        risk_class: OfficeCapabilityRiskClassV1::ReadOnly,
        prohibited_argument_classes: vec!["raw-path".to_owned(), "arbitrary-command".to_owned()],
        reference_only: true,
        evidence_ids: vec![catalog.catalog_sha256],
        candidate_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("candidate: {error}"));
    candidate
        .validate_integrity()
        .unwrap_or_else(|error| panic!("candidate verify: {error}"));
    artifact()
        .seal()
        .unwrap_or_else(|error| panic!("artifact: {error}"));
}

#[test]
fn path_policy_rejects_traversal_absolute_unc_device_ads_and_aliases() {
    for invalid in [
        "../outside.xlsx",
        "..\\outside.xlsx",
        "%2e%2e/outside.xlsx",
        "safe/..\\outside.xlsx",
        "/absolute.xlsx",
        "C:/drive.xlsx",
        "C:drive-relative.xlsx",
        "\\\\server\\share.xlsx",
        "\\\\?\\C:\\device.xlsx",
        "\\\\.\\C:\\device.xlsx",
        "safe/file.xlsx:stream",
        "safe/CON.xlsx",
        "safe/report.xlsx. ",
        "safe/PROGRA~1.xlsx",
    ] {
        assert!(
            validate_relative_path_token(invalid).is_err(),
            "accepted {invalid}"
        );
    }
    validate_relative_path_token("working/2026_교육실적_결과보고서.hwpx")
        .unwrap_or_else(|error| panic!("valid Korean filename: {error}"));
}

#[test]
fn intent_binding_and_activation_are_hash_bound_and_one_shot() {
    let source = artifact()
        .seal()
        .unwrap_or_else(|error| panic!("artifact: {error}"));
    let intent = intent(&source)
        .seal()
        .unwrap_or_else(|error| panic!("intent: {error}"));
    let binding = binding(intent.intent_sha256, source.artifact_sha256)
        .seal()
        .unwrap_or_else(|error| panic!("binding: {error}"));
    let mut ledger = WorkspaceActivationLedgerV1::default();
    ledger
        .consume(&binding, &hash("policy"), &hash("admission"), 1_500)
        .unwrap_or_else(|error| panic!("consume: {error}"));
    assert!(ledger
        .consume(&binding, &hash("policy"), &hash("admission"), 1_500)
        .is_err());
    assert_eq!(ledger.consumed_count(), 1);
    let mut other = binding;
    other.one_time_use_id = "activation.office100.2".to_owned();
    other.binding_sha256 = ZERO_HASH.to_owned();
    let other = other
        .seal()
        .unwrap_or_else(|error| panic!("other binding: {error}"));
    assert!(ledger
        .consume(&other, &hash("policy"), &hash("admission"), 2_001)
        .is_err());
}

#[test]
fn strict_json_rejects_duplicate_unknown_float_secret_path_and_script_fields() {
    let sealed = artifact()
        .seal()
        .unwrap_or_else(|error| panic!("artifact: {error}"));
    let valid =
        serde_json::to_vec(&sealed).unwrap_or_else(|error| panic!("serialize artifact: {error}"));
    parse_json_strict::<OfficeArtifactReferenceV1>(&valid)
        .unwrap_or_else(|error| panic!("strict valid: {error}"));
    assert!(parse_json_strict::<Value>(br#"{"a":1,"a":2}"#).is_err());
    assert!(parse_json_strict::<Value>(br#"{"a":1.5}"#).is_err());
    assert!(parse_json_strict::<Value>(br#"{"raw_path":"C:/secret"}"#).is_err());
    assert!(parse_json_strict::<Value>(br#"{"script":"Remove-Item *"}"#).is_err());
    let mut unknown: Value =
        serde_json::from_slice(&valid).unwrap_or_else(|error| panic!("decode artifact: {error}"));
    unknown["unknown"] = json!(true);
    assert!(parse_json_strict::<OfficeArtifactReferenceV1>(
        &serde_json::to_vec(&unknown).unwrap_or_else(|error| panic!("unknown: {error}"))
    )
    .is_err());
}

#[test]
fn observation_receipt_and_provenance_reject_mismatched_state() {
    let source = artifact()
        .seal()
        .unwrap_or_else(|error| panic!("artifact: {error}"));
    let observation = WorkspaceObservationSnapshotV1 {
        schema_version: 1,
        observation_id: "observation.office100".to_owned(),
        workspace_id: source.workspace_id.clone(),
        artifact_ids: vec![source.artifact_id.clone()],
        artifact_generations: vec![source.current_generation],
        content_sha256s: vec![source.content_sha256.clone()],
        sizes: vec![source.byte_length],
        formats: vec![source.file_format_id.clone()],
        lock_states: vec![ArtifactLockStateV1::Unlocked],
        write_states: vec!["immutable-original".to_owned()],
        observed_at_unix_ms: 1_000,
        freshness_expires_at_unix_ms: 2_000,
        observation_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("observation: {error}"));
    let receipt = WorkspaceOperationReceiptV1 {
        schema_version: 1,
        receipt_id: "receipt.office100".to_owned(),
        operation_intent_sha256: hash("intent"),
        binding_sha256: hash("binding"),
        source_artifact_sha256: Some(source.artifact_sha256.clone()),
        source_generation: Some(1),
        destination_artifact_sha256: Some(hash("destination")),
        destination_generation: Some(1),
        operation_class: WorkspaceOperationClassV1::CreateWorkingCopy,
        status: WorkspaceOperationStatusV1::Verified,
        structured_result_code: "verified-working-copy".to_owned(),
        bytes_processed: source.byte_length,
        atomic_commit: true,
        old_identity_sha256: Some(hash("old")),
        new_identity_sha256: Some(hash("new")),
        started_at_unix_ms: 1_100,
        completed_at_unix_ms: 1_200,
        verification_sha256: observation.observation_sha256.clone(),
        receipt_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("receipt: {error}"));
    OfficeArtifactProvenanceV1 {
        schema_version: 1,
        artifact_sha256: hash("destination"),
        source_artifact_sha256s: vec![source.artifact_sha256],
        case_sha256: hash("case"),
        role_instance_sha256: hash("role"),
        operation_receipt_sha256s: vec![receipt.receipt_sha256],
        application_family_id: "office.hwp".to_owned(),
        created_at_unix_ms: 1_200,
        modified_at_unix_ms: 1_200,
        data_class_ids: vec!["internal".to_owned()],
        verification_sha256s: vec![hash("verification")],
        provenance_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("provenance: {error}"));
    let mut mismatch = observation;
    mismatch.sizes.clear();
    mismatch.observation_sha256 = ZERO_HASH.to_owned();
    assert!(mismatch.seal().is_err());
}

#[test]
fn replay_is_identical_for_128_scenarios_across_100_runs() {
    let inputs = (0..128_u32)
        .map(|index| {
            json!({
                "artifact_id": format!("artifact-{index:03}"),
                "generation": 1 + u64::from(index % 4),
                "operation": if index % 2 == 0 { "inspect_artifact" } else { "create_working_copy" },
                "stale": index % 11 == 0,
            })
        })
        .collect::<Vec<_>>();
    let baseline =
        canonical_sha256(&inputs).unwrap_or_else(|error| panic!("baseline replay: {error}"));
    let mut matches = 0_u32;
    for _ in 0..100 {
        if canonical_sha256(&inputs).unwrap_or_else(|error| panic!("replay: {error}")) == baseline {
            matches += 1;
        }
    }
    OfficeWorkspaceReplayReportV1 {
        schema_version: 1,
        report_id: "office100-128x100".to_owned(),
        synthetic_scenario_count: 128,
        replay_runs: 100,
        deterministic_match_count: matches,
        deterministic_mismatch_count: 100 - matches,
        input_set_sha256: baseline.clone(),
        first_output_sha256: baseline.clone(),
        final_output_sha256: baseline,
        evidence_ids: vec!["workspace-contract-replay".to_owned()],
        report_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("replay report: {error}"));
}

#[test]
fn completion_and_certification_require_all_zero_error_gates() {
    let replay = OfficeWorkspaceReplayReportV1 {
        schema_version: 1,
        report_id: "office100-128x100".to_owned(),
        synthetic_scenario_count: 128,
        replay_runs: 100,
        deterministic_match_count: 100,
        deterministic_mismatch_count: 0,
        input_set_sha256: hash("replay"),
        first_output_sha256: hash("replay"),
        final_output_sha256: hash("replay"),
        evidence_ids: vec!["workspace-contract-replay".to_owned()],
        report_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("replay: {error}"));
    let report = OfficeWorkspaceCompletionReportV1 {
        schema_version: 1,
        report_id: "office100-completion".to_owned(),
        complete: true,
        office_capability_foundation_evidence: true,
        office_workspace_evidence: true,
        track_o_started: true,
        source_tree_sha256: hash("source-tree"),
        predecessor_finished_sha256: hash("edge100"),
        source_assessment_count: 15,
        excel_source_count: 4,
        powerpoint_source_count: 4,
        hwp_source_count: 5,
        official_source_count: 3,
        mcp_catalog_count: 9,
        rejected_runtime_source_count: 5,
        eligible_adapter_design_count: 4,
        workspace_cases: 10,
        routine_verified: 6,
        human_exceptions: 4,
        artifact_count: 8,
        operation_count: 8,
        version_count: 2,
        provenance_count: 4,
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
        list_latency_microseconds: 10,
        hash_latency_microseconds: 20,
        copy_latency_microseconds: 30,
        rename_latency_microseconds: 40,
        move_latency_microseconds: 50,
        version_commit_latency_microseconds: 60,
        verification_latency_microseconds: 70,
        bytes_processed: 1_024,
        peak_memory_bytes: 4_096,
        replay_report_sha256: replay.report_sha256.clone(),
        protected_audit_terminal_sha256: hash("audit"),
        residual_process_count: 0,
        residual_profile_count: 0,
        residual_lock_count: 0,
        residual_store_count: 0,
        finished_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("completion: {error}"));
    let key = SigningKey::from_bytes(&[9_u8; 32]);
    let certification = OfficeWorkspaceCertificationV1 {
        schema_version: 1,
        certification_id: "office100-certification".to_owned(),
        completion_report_sha256: report.finished_sha256.clone(),
        workspace_profile_sha256: hash("profile"),
        workspace_root_binding_sha256: hash("root"),
        replay_report_sha256: replay.report_sha256,
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 2_000,
        signer_id: "office100-certifier".to_owned(),
        signing_key_id: "office100-certification-key".to_owned(),
        evidence_ids: vec![report.finished_sha256.clone()],
        certification_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
    .sign(&key)
    .unwrap_or_else(|error| panic!("certification: {error}"));
    certification
        .validate_signature(&key.verifying_key())
        .unwrap_or_else(|error| panic!("certification verify: {error}"));
    let mut failed = report;
    failed.path_escape_count = 1;
    failed.finished_sha256 = ZERO_HASH.to_owned();
    assert!(failed.seal().is_err());
}

#[test]
fn identical_input_has_identical_canonical_result_hash() {
    let first = artifact()
        .seal()
        .unwrap_or_else(|error| panic!("first: {error}"));
    let second = artifact()
        .seal()
        .unwrap_or_else(|error| panic!("second: {error}"));
    assert_eq!(first, second);
    assert_eq!(first.artifact_sha256, second.artifact_sha256);
}
