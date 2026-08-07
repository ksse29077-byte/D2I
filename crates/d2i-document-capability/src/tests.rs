use super::*;
use ed25519_dalek::SigningKey;

fn hash(label: &str) -> String {
    sha256_bytes(label.as_bytes())
}

fn limits() -> DocumentResourceLimitsV1 {
    DocumentResourceLimitsV1 {
        maximum_document_bytes: 16 * 1024 * 1024,
        maximum_package_entries: 256,
        maximum_uncompressed_bytes: 64 * 1024 * 1024,
        maximum_compression_ratio: 100,
        maximum_xml_bytes: 8 * 1024 * 1024,
        maximum_xml_depth: 64,
        maximum_xml_nodes: 100_000,
        maximum_xml_attributes: 250_000,
        maximum_sections: 32,
        maximum_nodes: 4_096,
        maximum_tables: 64,
        maximum_table_rows: 256,
        maximum_table_columns: 64,
        maximum_table_cells: 16_384,
        maximum_images: 64,
        maximum_image_bytes: 8 * 1024 * 1024,
        maximum_total_embedded_bytes: 32 * 1024 * 1024,
        maximum_text_characters_per_node: 8_192,
        maximum_total_observed_characters: 128_000,
        maximum_generated_characters_per_case: 128_000,
        maximum_operations_per_case: 64,
        maximum_model_invocations: 64,
        maximum_save_generations: 64,
        maximum_worker_milliseconds: 30_000,
        maximum_application_session_milliseconds: 120_000,
        maximum_worker_memory_bytes: 1024 * 1024 * 1024,
    }
}

fn descriptor(kind: DocumentBackendKindV1) -> DocumentBackendDescriptorV1 {
    let (id, formats, application, license) = match kind {
        DocumentBackendKindV1::HwpxFile => (
            "backend.hwpx-file",
            vec![DocumentFormatV1::Hwpx],
            false,
            false,
        ),
        DocumentBackendKindV1::DocxFile => (
            "backend.docx-file",
            vec![DocumentFormatV1::Docx],
            false,
            false,
        ),
        DocumentBackendKindV1::WordCom => (
            "backend.word-com",
            vec![DocumentFormatV1::Docx, DocumentFormatV1::Doc],
            true,
            false,
        ),
        DocumentBackendKindV1::HancomAutomation => (
            "backend.hancom-automation",
            vec![DocumentFormatV1::Hwpx, DocumentFormatV1::Hwp],
            true,
            true,
        ),
    };
    DocumentBackendDescriptorV1 {
        schema_version: 1,
        backend_id: id.to_owned(),
        backend_version: "1.0.0".to_owned(),
        backend_kind: kind,
        supported_formats: formats,
        supported_operations: vec![DocumentOperationV1::AppendParagraph],
        requires_application: application,
        requires_license_evidence: license,
        worker_artifact_sha256: hash("worker"),
        application_binary_sha256: application.then(|| hash("application")),
        security_profile_id: "security.document.offline".to_owned(),
        resource_limits: limits(),
        backend_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("descriptor: {error}"))
}

fn approval(descriptor: &DocumentBackendDescriptorV1) -> DocumentBackendApprovalV1 {
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    DocumentBackendApprovalV1 {
        schema_version: 1,
        approval_id: format!("approval.{}", descriptor.backend_id),
        organization_id: "organization.fixture".to_owned(),
        backend_descriptor_sha256: descriptor.backend_sha256.clone(),
        capability_pack_sha256: hash("capability-pack"),
        role_ids: vec!["role.general-office".to_owned()],
        environment_ids: vec!["environment.windows-interactive".to_owned()],
        allowed_formats: descriptor.supported_formats.clone(),
        allowed_operations: descriptor.supported_operations.clone(),
        application_binary_sha256s: descriptor
            .application_binary_sha256
            .iter()
            .cloned()
            .collect(),
        license_evidence_sha256s: descriptor
            .requires_license_evidence
            .then(|| hash("hancom-license"))
            .into_iter()
            .collect(),
        valid_from_unix_ms: 1_000,
        valid_until_unix_ms: 10_000,
        signer_id: "signer.office".to_owned(),
        signing_key_id: "key.office".to_owned(),
        approval_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
    .sign(&key)
    .unwrap_or_else(|error| panic!("approval: {error}"))
}

fn binding() -> DocumentOperationBindingV1 {
    DocumentOperationBindingV1 {
        schema_version: 1,
        binding_id: "binding.document.1".to_owned(),
        role_contract_sha256: hash("role-contract"),
        role_instance_sha256: hash("role-instance"),
        case_sha256: hash("case"),
        lease_sha256: hash("lease"),
        work_grant_sha256: hash("work-grant"),
        workspace_profile_sha256: hash("workspace-profile"),
        workspace_root_binding_sha256: hash("workspace-root"),
        artifact_id: "artifact.document.1".to_owned(),
        artifact_generation: 3,
        artifact_content_sha256: hash("document-generation-3"),
        semantic_snapshot_sha256: hash("semantic-generation-3"),
        capability_pack_sha256: hash("capability-pack"),
        backend_descriptor_sha256: hash("backend"),
        backend_approval_sha256: hash("approval"),
        operation_intent_sha256: hash("intent"),
        policy_decision_sha256: hash("policy"),
        cognitive_activation_admission_sha256: hash("activation"),
        worker_sha256: hash("worker"),
        expected_output_generation: 4,
        one_time_use_id: "activation.document.1".to_owned(),
        expires_at_unix_ms: 10_000,
        binding_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("binding: {error}"))
}

#[test]
fn korean_payload_hash_is_deterministic_and_tamper_evident() {
    let payload = DocumentContentPayloadV1 {
        schema_version: 1,
        payload_id: "payload.report-title".to_owned(),
        case_id: "case.office200".to_owned(),
        content_class_id: "document.heading".to_owned(),
        language_id: "ko-KR".to_owned(),
        text: "2026년 7월 안전교육 결과보고서".to_owned(),
        character_count: 19,
        data_class_ids: vec!["internal.synthetic".to_owned()],
        source_evidence_ids: vec!["evidence.fixture".to_owned()],
        payload_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("payload: {error}"));
    let repeated = payload
        .clone()
        .seal()
        .unwrap_or_else(|error| panic!("repeated payload: {error}"));
    assert_eq!(payload.payload_sha256, repeated.payload_sha256);
    let mut mutated = payload;
    mutated.text.push('!');
    assert!(mutated.validate_integrity().is_err());
}

#[test]
fn activation_is_one_shot_and_exactly_bound() {
    let binding = binding();
    let mut ledger = DocumentActivationLedgerV1::default();
    ledger
        .consume(&binding, &hash("policy"), &hash("activation"), 5_000)
        .unwrap_or_else(|error| panic!("consume: {error}"));
    assert!(matches!(
        ledger.consume(&binding, &hash("policy"), &hash("activation"), 5_001),
        Err(DocumentCapabilityError::Replay(_))
    ));
    let mut fresh = DocumentActivationLedgerV1::default();
    assert!(matches!(
        fresh.consume(&binding, &hash("wrong-policy"), &hash("activation"), 5_000),
        Err(DocumentCapabilityError::Unauthorized(_))
    ));
}

#[test]
fn stale_binding_is_rejected_before_consumption() {
    let binding = binding();
    let mut ledger = DocumentActivationLedgerV1::default();
    assert!(matches!(
        ledger.consume(&binding, &hash("policy"), &hash("activation"), 10_001),
        Err(DocumentCapabilityError::Stale(_))
    ));
}

#[test]
fn file_backend_precedes_word_and_hancom_requires_license() {
    let hwpx = descriptor(DocumentBackendKindV1::HwpxFile);
    let hancom = descriptor(DocumentBackendKindV1::HancomAutomation);
    let approvals = vec![approval(&hwpx), approval(&hancom)];
    let descriptors = vec![hancom.clone(), hwpx.clone()];
    let selected = select_document_backend(
        DocumentFormatV1::Hwpx,
        DocumentOperationV1::AppendParagraph,
        &descriptors,
        &approvals,
        DocumentBackendAvailabilityV1 {
            application_available: true,
            license_evidence_available: false,
        },
        5_000,
    )
    .unwrap_or_else(|error| panic!("selection: {error}"));
    assert_eq!(selected.backend_kind, DocumentBackendKindV1::HwpxFile);
    assert!(select_document_backend(
        DocumentFormatV1::Hwp,
        DocumentOperationV1::AppendParagraph,
        &[hancom],
        &approvals,
        DocumentBackendAvailabilityV1 {
            application_available: true,
            license_evidence_available: false,
        },
        5_000,
    )
    .is_err());
}

#[test]
fn strict_json_rejects_unknown_and_duplicate_fields() {
    let unknown = br#"{"schema_version":1,"unknown":true}"#;
    assert!(parse_document_json_strict::<DocumentContentPayloadV1>(unknown).is_err());
    let duplicate = br#"{"schema_version":1,"schema_version":1}"#;
    assert!(parse_document_json_strict::<serde_json::Value>(duplicate).is_err());
}

#[test]
fn table_and_image_bounds_reject_raw_or_remote_capability() {
    let oversized = DocumentTableSpecV1 {
        schema_version: 1,
        table_spec_id: "table.fixture".to_owned(),
        rows: 257,
        columns: 1,
        header_rows: 1,
        column_role_ids: vec!["column.value".to_owned()],
        style_spec_id: "style.table".to_owned(),
        maximum_width_policy_id: "width.page".to_owned(),
        table_spec_sha256: ZERO_HASH.to_owned(),
    };
    assert!(oversized.seal().is_err());
    let remote = DocumentImageSpecV1 {
        schema_version: 1,
        image_spec_id: "image.remote".to_owned(),
        artifact_id: "artifact.logo".to_owned(),
        content_sha256: hash("logo"),
        media_type: "image/svg+xml".to_owned(),
        placement_class_id: "inline".to_owned(),
        maximum_width_millimeters: 40,
        maximum_height_millimeters: 20,
        caption_payload_id: None,
        embedded: false,
        image_spec_sha256: ZERO_HASH.to_owned(),
    };
    assert!(remote.seal().is_err());
}
