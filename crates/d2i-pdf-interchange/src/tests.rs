use super::*;
use ed25519_dalek::SigningKey;

fn hash(label: &str) -> String {
    pdf_canonical_sha256(&label).unwrap_or_else(|error| panic!("hash failed: {error}"))
}

fn verification() -> PdfPostExportVerificationV1 {
    PdfPostExportVerificationV1 {
        schema_version: 1,
        verification_id: "verification.pdf.1".to_owned(),
        export_receipt_sha256: hash("receipt"),
        document_snapshot_sha256: hash("snapshot"),
        geometry_verification_sha256: hash("geometry"),
        visual_fidelity_report_sha256: Some(hash("visual")),
        source_lineage_verified: true,
        security_verified: true,
        independent_load_verified: true,
        independent_render_verified: true,
        verified: true,
        failure_code: PdfFailureCodeV1::None,
        verification_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("seal failed: {error}"))
}

fn pair() -> FinalArtifactPairV1 {
    let verification = verification();
    FinalArtifactPairV1 {
        schema_version: 1,
        pair_id: "pair.pdf.1".to_owned(),
        organization_id: "org.alpha".to_owned(),
        source_artifact_id: "artifact.source.1".to_owned(),
        source_generation: 7,
        source_artifact_sha256: hash("source"),
        source_snapshot_sha256: hash("source-snapshot"),
        pdf_artifact_id: "artifact.pdf.1".to_owned(),
        pdf_generation: 1,
        pdf_artifact_sha256: hash("pdf"),
        export_profile_sha256: hash("profile"),
        export_backend_sha256: hash("backend"),
        export_receipt_sha256: hash("receipt"),
        post_export_verification_sha256: verification.verification_sha256.clone(),
        design_quality_ref: Some("design.quality.1".to_owned()),
        fact_lineage_refs: vec!["fact.lineage.1".to_owned()],
        created_at_unix_ms: 1_000,
        state: FinalArtifactPairStateV1::Finalized,
        ready_for_submission: true,
        pair_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("seal failed: {error}"))
}

fn request(format: PdfSourceFormatV1) -> PdfExportRequestV1 {
    PdfExportRequestV1 {
        schema_version: 1,
        request_id: "request.pdf.1".to_owned(),
        organization_id: "org.alpha".to_owned(),
        case_id: "case.pdf.1".to_owned(),
        role_id: "role.office".to_owned(),
        workspace_id: "workspace.office".to_owned(),
        source_artifact_id: "artifact.source.1".to_owned(),
        source_format: format,
        source_generation: 1,
        expected_source_sha256: hash("source"),
        expected_source_snapshot_sha256: hash("snapshot"),
        expected_source_verification_sha256: hash("verification"),
        expected_source_quality_sha256: hash("quality"),
        expected_application_state_sha256: hash("application"),
        finalization_intent_sha256: hash("intent"),
        export_profile_sha256: hash("profile"),
        backend_approval_sha256: hash("approval"),
        page_selection_policy: PdfPageSelectionPolicyV1::AllApproved,
        approved_sheet_ids: Vec::new(),
        expected_design_quality_ref: Some("design.quality.1".to_owned()),
        output_artifact_id: "artifact.pdf.1".to_owned(),
        issued_at_unix_ms: 1_000,
        deadline_unix_ms: 2_000,
        request_sha256: ZERO_HASH.to_owned(),
    }
}

fn render_request(external_untrusted: bool) -> PdfRenderRequestV1 {
    PdfRenderRequestV1 {
        schema_version: 1,
        request_id: "render.pdf.1".to_owned(),
        expected_pdf_sha256: hash("pdf"),
        external_untrusted,
        maximum_pages: if external_untrusted {
            MAX_EXTERNAL_PDF_PAGES
        } else {
            MAX_PDF_PAGES
        },
        maximum_pdf_bytes: if external_untrusted {
            MAX_EXTERNAL_PDF_BYTES
        } else {
            MAX_PDF_BYTES
        },
        maximum_total_pixels: 10_000_000,
        maximum_page_width_millipoints: 2_000_000,
        maximum_page_height_millipoints: 2_000_000,
        maximum_output_png_bytes: 64 * 1024 * 1024,
        maximum_worker_memory_bytes: 768 * 1024 * 1024,
        maximum_page_render_milliseconds: 30_000,
        maximum_total_render_milliseconds: 120_000,
        destination_width_pixels: 1_800,
        issued_at_unix_ms: 1_000,
        deadline_unix_ms: 2_000,
        request_sha256: ZERO_HASH.to_owned(),
    }
}

fn profile(kind: PdfInterchangeProfileV1) -> PdfExportProfileV1 {
    PdfExportProfileV1 {
        schema_version: 1,
        profile: kind,
        quality_id: "print".to_owned(),
        optimization_id: "print".to_owned(),
        metadata_policy_id: "exclude_source_properties".to_owned(),
        structure_tag_policy_id: "include".to_owned(),
        bookmark_policy_id: "none".to_owned(),
        hidden_content_policy_id: "exclude".to_owned(),
        pdfa_requested: kind == PdfInterchangeProfileV1::ArchivePdfaRequested,
        page_selection_policy: PdfPageSelectionPolicyV1::AllApproved,
        external_link_policy_id: "reject".to_owned(),
        font_policy_id: "require_installed_no_bitmap_fallback".to_owned(),
        profile_sha256: ZERO_HASH.to_owned(),
    }
}

#[test]
fn identical_input_produces_identical_pair_hash() {
    assert_eq!(pair(), pair());
    assert!(pair().validate_finalization(&verification()).is_ok());
}

#[test]
fn source_change_supersedes_pair_and_removes_submission_readiness() {
    let superseded = pair()
        .supersede(&hash("changed-source"))
        .unwrap_or_else(|error| panic!("supersede failed: {error}"));
    assert_eq!(superseded.state, FinalArtifactPairStateV1::Superseded);
    assert!(!superseded.ready_for_submission);
}

#[test]
fn incomplete_verification_cannot_be_hidden_as_ready() {
    let mut evidence = verification();
    evidence.independent_render_verified = false;
    evidence.verified = false;
    evidence.failure_code = PdfFailureCodeV1::PdfLoadFailed;
    evidence.verification_sha256 = ZERO_HASH.to_owned();
    let evidence = evidence
        .seal()
        .unwrap_or_else(|error| panic!("seal failed: {error}"));
    assert!(pair().validate_finalization(&evidence).is_err());
}

#[test]
fn hwpx_requires_licensed_backend_and_external_pdf_is_render_only() {
    let hwpx = match request(PdfSourceFormatV1::Hwpx)
        .seal()
        .unwrap_or_else(|error| panic!("seal failed: {error}"))
        .validate_preflight(1_500)
    {
        Ok(()) => panic!("HWPX must not use an unlicensed exporter"),
        Err(error) => error,
    };
    assert!(hwpx.to_string().contains("requires_licensed_hancom"));
    assert!(request(PdfSourceFormatV1::ExternalPdf)
        .seal()
        .unwrap_or_else(|error| panic!("seal failed: {error}"))
        .validate_preflight(1_500)
        .is_err());
}

#[test]
fn external_pdf_has_stricter_render_bounds() {
    let request = PdfRenderRequestV1 {
        schema_version: 1,
        request_id: "render.pdf.1".to_owned(),
        expected_pdf_sha256: hash("pdf"),
        external_untrusted: true,
        maximum_pages: MAX_EXTERNAL_PDF_PAGES + 1,
        maximum_pdf_bytes: MAX_EXTERNAL_PDF_BYTES,
        maximum_total_pixels: 10_000_000,
        maximum_page_width_millipoints: 2_000_000,
        maximum_page_height_millipoints: 2_000_000,
        maximum_output_png_bytes: 64 * 1024 * 1024,
        maximum_worker_memory_bytes: 768 * 1024 * 1024,
        maximum_page_render_milliseconds: 30_000,
        maximum_total_render_milliseconds: 120_000,
        destination_width_pixels: 1_800,
        issued_at_unix_ms: 1_000,
        deadline_unix_ms: 2_000,
        request_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("seal failed: {error}"));
    assert!(request.validate_limits(1_024, 1_500).is_err());
}

#[test]
fn seal_rejects_mutation_expiry_and_wrong_signer() {
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let other = SigningKey::from_bytes(&[8_u8; 32]);
    let seal = PdfFinalizationSealV1 {
        schema_version: 1,
        seal_id: "seal.pdf.1".to_owned(),
        organization_id: "org.alpha".to_owned(),
        case_id: "case.pdf.1".to_owned(),
        final_artifact_pair_sha256: pair().pair_sha256,
        source_artifact_sha256: hash("source"),
        pdf_artifact_sha256: hash("pdf"),
        export_profile_sha256: hash("profile"),
        post_export_verification_sha256: verification().verification_sha256,
        pair_state: FinalArtifactPairStateV1::Finalized,
        source_tree_sha256: hash("tree"),
        protected_audit_terminal_sha256: hash("audit"),
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 2_000,
        signer_id: "signer.office500".to_owned(),
        signing_key_id: "key.office500".to_owned(),
        signature_hex: String::new(),
        seal_sha256: ZERO_HASH.to_owned(),
    }
    .sign(&key)
    .unwrap_or_else(|error| panic!("sign failed: {error}"));
    assert!(seal.verify(&key.verifying_key(), 1_500).is_ok());
    assert!(seal.verify(&other.verifying_key(), 1_500).is_err());
    assert!(seal.verify(&key.verifying_key(), 2_000).is_err());
    let mut mutated = seal;
    mutated.signer_id = "signer.changed".to_owned();
    assert!(mutated.verify(&key.verifying_key(), 1_500).is_err());
}

#[test]
fn backend_approval_is_signed_bounded_and_expires() {
    let key = SigningKey::from_bytes(&[9_u8; 32]);
    let approval = PdfExportBackendApprovalV1 {
        schema_version: 1,
        approval_id: "approval.word.1".to_owned(),
        organization_id: "org.alpha".to_owned(),
        environment_id: "environment.windows.office".to_owned(),
        backend_descriptor_sha256: hash("word-backend"),
        allowed_source_formats: vec![PdfSourceFormatV1::Docx],
        approved_profile_ids: vec![PdfInterchangeProfileV1::SubmissionStatic],
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 2_000,
        signer_id: "signer.backend".to_owned(),
        signing_key_id: "key.backend.1".to_owned(),
        signature_hex: String::new(),
        approval_sha256: ZERO_HASH.to_owned(),
    }
    .sign(&key)
    .unwrap_or_else(|error| panic!("approval sign failed: {error}"));
    assert!(approval.verify(&key.verifying_key(), 1_500).is_ok());
    assert!(approval.verify(&key.verifying_key(), 2_000).is_err());
}

#[test]
fn archived_certification_preserves_provenance_without_restoring_authority() {
    let key = SigningKey::from_bytes(&[10_u8; 32]);
    let other = SigningKey::from_bytes(&[11_u8; 32]);
    let certification = PdfWorkCertificationV1 {
        schema_version: 1,
        certification_id: "certification.office500.test".to_owned(),
        completion_report_sha256: hash("completion"),
        predecessor_finished_sha256: hash("predecessor"),
        model_artifact_sha256: hash("model"),
        runtime_artifact_sha256: hash("runtime"),
        word_executable_sha256: hash("word"),
        excel_executable_sha256: hash("excel"),
        powerpoint_executable_sha256: hash("powerpoint"),
        pdf_render_worker_sha256: hash("renderer"),
        evidence_ids: vec!["evidence.office500.test".to_owned()],
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 2_000,
        signer_id: "signer.office500.test".to_owned(),
        signing_key_id: "key.office500.test".to_owned(),
        signature_hex: String::new(),
        certification_sha256: ZERO_HASH.to_owned(),
    }
    .sign(&key)
    .unwrap_or_else(|error| panic!("certification sign failed: {error}"));

    assert!(certification.verify(&key.verifying_key(), 2_000).is_err());
    assert!(certification.verify_archived(&key.verifying_key()).is_ok());
    assert!(certification
        .verify_archived(&other.verifying_key())
        .is_err());

    let mut mutated = certification;
    mutated.completion_report_sha256 = hash("different-completion");
    assert!(mutated.verify_archived(&key.verifying_key()).is_err());
}

#[test]
fn unknown_fields_and_forbidden_runtime_tokens_fail_closed() {
    let mut value =
        serde_json::to_value(pair()).unwrap_or_else(|error| panic!("serialize failed: {error}"));
    value["unknown"] = serde_json::json!(true);
    assert!(parse_pdf_json_strict::<FinalArtifactPairV1>(
        &serde_json::to_vec(&value).unwrap_or_else(|error| panic!("serialize failed: {error}"))
    )
    .is_err());
    let mut value =
        serde_json::to_value(pair()).unwrap_or_else(|error| panic!("serialize failed: {error}"));
    value["pair_id"] = serde_json::json!("ShellExecute");
    assert!(parse_pdf_json_strict::<FinalArtifactPairV1>(
        &serde_json::to_vec(&value).unwrap_or_else(|error| panic!("serialize failed: {error}"))
    )
    .is_err());
}

#[test]
fn replay_requires_exact_128_by_100() {
    let report = PdfWorkReplayReportV1 {
        schema_version: 1,
        scenario_count: 128,
        runs_per_scenario: 100,
        export_selection_mismatch_count: 0,
        geometry_mismatch_count: 0,
        lineage_mismatch_count: 0,
        manifest_mismatch_count: 0,
        stale_acceptance_count: 0,
        blind_replay_count: 0,
        report_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("seal failed: {error}"));
    assert!(report.validate_gate().is_ok());
}

#[test]
fn recovery_matrix_verifies_all_thirteen_without_blind_export() {
    let verified = verify_pdf_recovery_matrix_v1()
        .unwrap_or_else(|error| panic!("recovery matrix verification failed: {error}"));
    assert_eq!(verified, 13);
    let partial = decide_pdf_recovery_v1(PdfRecoveryEvidenceV1 {
        stage: PdfRecoveryStageV1::PartialRenderDurable,
        exact_pdf_hash_available: true,
        render_checkpoint_verified: false,
        source_generation_matches: true,
    });
    assert!(partial.is_err());
    let missing_hash = decide_pdf_recovery_v1(PdfRecoveryEvidenceV1 {
        stage: PdfRecoveryStageV1::PdfObserved,
        exact_pdf_hash_available: false,
        render_checkpoint_verified: false,
        source_generation_matches: true,
    });
    assert!(missing_hash.is_err());
    let changed = decide_pdf_recovery_v1(PdfRecoveryEvidenceV1 {
        stage: PdfRecoveryStageV1::SourceGenerationChanged,
        exact_pdf_hash_available: true,
        render_checkpoint_verified: false,
        source_generation_matches: false,
    })
    .unwrap_or_else(|error| panic!("source-change decision failed: {error}"));
    assert_eq!(changed.action, PdfRecoveryActionV1::ProhibitSeal);
    assert!(!changed.seal_allowed);
    assert!(!changed.blind_export_replay_allowed);
}

#[test]
fn profile_ids_are_closed_and_stable() {
    assert_eq!(
        PdfInterchangeProfileV1::SubmissionStatic.profile_id(),
        "submission_static"
    );
    assert_eq!(
        PdfInterchangeProfileV1::InternalReview.profile_id(),
        "internal_review"
    );
    assert_eq!(
        PdfInterchangeProfileV1::ArchivePdfaRequested.profile_id(),
        "archive_pdfa_requested"
    );
}

#[test]
fn archive_profile_requires_pdfa_request() {
    let mut value = profile(PdfInterchangeProfileV1::ArchivePdfaRequested);
    value.pdfa_requested = false;
    let value = value
        .seal()
        .unwrap_or_else(|error| panic!("seal failed: {error}"));
    assert!(value.validate_profile().is_err());
}

#[test]
fn submission_profile_rejects_hidden_content() {
    let mut value = profile(PdfInterchangeProfileV1::SubmissionStatic);
    value.hidden_content_policy_id = "include".to_owned();
    let value = value
        .seal()
        .unwrap_or_else(|error| panic!("seal failed: {error}"));
    assert!(value.validate_profile().is_err());
}

#[test]
fn export_request_rejects_expiry() {
    let value = request(PdfSourceFormatV1::Docx)
        .seal()
        .unwrap_or_else(|error| panic!("seal failed: {error}"));
    assert!(value.validate_preflight(2_000).is_err());
}

#[test]
fn export_request_rejects_excessive_ttl() {
    let mut value = request(PdfSourceFormatV1::Docx);
    value.deadline_unix_ms = value.issued_at_unix_ms + 300_001;
    let value = value
        .seal()
        .unwrap_or_else(|error| panic!("seal failed: {error}"));
    assert!(value.validate_preflight(1_500).is_err());
}

#[test]
fn export_request_rejects_zero_generation() {
    let mut value = request(PdfSourceFormatV1::Xlsx);
    value.source_generation = 0;
    let value = value
        .seal()
        .unwrap_or_else(|error| panic!("seal failed: {error}"));
    assert!(value.validate_preflight(1_500).is_err());
}

#[test]
fn render_request_rejects_oversized_pdf_before_load() {
    let value = render_request(true)
        .seal()
        .unwrap_or_else(|error| panic!("seal failed: {error}"));
    assert!(value
        .validate_limits(MAX_EXTERNAL_PDF_BYTES + 1, 1_500)
        .is_err());
}

#[test]
fn render_request_rejects_extreme_page_limit() {
    let mut value = render_request(false);
    value.maximum_pages = MAX_PDF_PAGES + 1;
    let value = value
        .seal()
        .unwrap_or_else(|error| panic!("seal failed: {error}"));
    assert!(value.validate_limits(1_024, 1_500).is_err());
}

#[test]
fn render_request_rejects_unbounded_width() {
    let mut value = render_request(false);
    value.destination_width_pixels = 2_401;
    let value = value
        .seal()
        .unwrap_or_else(|error| panic!("seal failed: {error}"));
    assert!(value.validate_limits(1_024, 1_500).is_err());
}

#[test]
fn render_request_rejects_timeout_escape() {
    let mut value = render_request(false);
    value.maximum_total_render_milliseconds = 300_001;
    value.deadline_unix_ms = 302_000;
    let value = value
        .seal()
        .unwrap_or_else(|error| panic!("seal failed: {error}"));
    assert!(value.validate_limits(1_024, 1_500).is_err());
}

#[test]
fn unchanged_source_cannot_supersede_pair() {
    let value = pair();
    let source = value.source_artifact_sha256.clone();
    assert!(value.supersede(&source).is_err());
}

#[test]
fn revoked_pair_cannot_be_submission_ready() {
    let mut value = pair();
    value.state = FinalArtifactPairStateV1::Revoked;
    value.pair_sha256 = ZERO_HASH.to_owned();
    let value = value
        .seal()
        .unwrap_or_else(|error| panic!("seal failed: {error}"));
    assert!(value.validate_finalization(&verification()).is_err());
}

#[test]
fn pair_rejects_wrong_verification_binding() {
    let mut value = pair();
    value.post_export_verification_sha256 = hash("wrong-verification");
    value.pair_sha256 = ZERO_HASH.to_owned();
    let value = value
        .seal()
        .unwrap_or_else(|error| panic!("seal failed: {error}"));
    assert!(value.validate_finalization(&verification()).is_err());
}

#[test]
fn unknown_profile_enum_is_rejected() {
    let mut value = serde_json::to_value(profile(PdfInterchangeProfileV1::SubmissionStatic))
        .unwrap_or_else(|error| panic!("serialize failed: {error}"));
    value["profile"] = serde_json::json!("arbitrary_exporter");
    assert!(parse_pdf_json_strict::<PdfExportProfileV1>(
        &serde_json::to_vec(&value).unwrap_or_else(|error| panic!("serialize failed: {error}"))
    )
    .is_err());
}

#[test]
fn forbidden_raw_absolute_path_is_rejected() {
    let mut value = request(PdfSourceFormatV1::Pptx);
    value.output_artifact_id = "C:\\temp\\output.pdf".to_owned();
    assert!(value.seal().is_err());
}
