use super::*;
use std::error::Error;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn hash(label: &str) -> TestResult<String> {
    Ok(design_canonical_sha256(&label)?)
}

fn artifact(
    organization: &str,
    index: u32,
    quality_label: DesignQualityLabelV1,
    holdout: bool,
) -> TestResult<DesignArtifactRecordV1> {
    Ok(DesignArtifactRecordV1 {
        artifact_id: format!("artifact.{organization}.{index}"),
        artifact_sha256: hash(&format!("artifact-{organization}-{index}"))?,
        format: if index % 2 == 0 {
            DesignArtifactFormatV1::Pptx
        } else {
            DesignArtifactFormatV1::Hwpx
        },
        artifact_class: if index % 2 == 0 {
            "monthly_report".to_owned()
        } else {
            "result_report".to_owned()
        },
        template_family_hint: Some(format!("family.{}", index % 2)),
        quality_label,
        approval_state: DesignApprovalStateV1::Approved,
        approved_at_unix_ms: Some(1_000),
        unit_ratings: vec![DesignUnitRatingV1 {
            unit_id: format!("unit.{index}.1"),
            quality_label,
            evidence_ids: vec![format!("evidence.{index}.rating")],
        }],
        template_status_id: "template.approved".to_owned(),
        data_classification_id: "internal".to_owned(),
        provenance_ids: vec![format!("provenance.{index}")],
        holdout,
    })
}

fn corpus(organization: &str) -> TestResult<OrganizationDesignCorpusV1> {
    Ok(OrganizationDesignCorpusV1 {
        schema_version: 1,
        corpus_id: format!("corpus.{organization}.v1"),
        organization_id: organization.to_owned(),
        artifacts: vec![
            artifact(organization, 0, DesignQualityLabelV1::Gold, false)?,
            artifact(organization, 1, DesignQualityLabelV1::Approved, false)?,
            artifact(organization, 2, DesignQualityLabelV1::Gold, true)?,
        ],
        manifest_approval_sha256: hash(&format!("approval-{organization}"))?,
        corpus_sha256: ZERO_HASH.to_owned(),
    }
    .seal()?)
}

fn feature(
    organization: &str,
    artifact: &DesignArtifactRecordV1,
) -> TestResult<DesignArtifactFeatureV1> {
    let vector = DesignFeatureVectorV1 {
        layout_ratios: vec![60_000, 880_000],
        font_role_ratios: vec![1_000_000, 500_000],
        color_role_distribution: vec![700_000, 300_000],
        spacing_distribution: vec![60_000, 30_000],
        white_space_millionths: 420_000,
        shape_density_millionths: 220_000,
        text_density_millionths: 310_000,
        image_ratio_millionths: 180_000,
        table_density_millionths: 160_000,
        chart_density_millionths: 120_000,
        alignment_features: vec![1_000_000],
        vector_sha256: ZERO_HASH.to_owned(),
    }
    .seal()?;
    Ok(DesignArtifactFeatureV1 {
        schema_version: 1,
        feature_id: format!("feature.{}", artifact.artifact_id),
        organization_id: organization.to_owned(),
        artifact_id: artifact.artifact_id.clone(),
        artifact_sha256: artifact.artifact_sha256.clone(),
        artifact_class: artifact.artifact_class.clone(),
        format: artifact.format,
        template_family_id: artifact
            .template_family_hint
            .clone()
            .unwrap_or_else(|| "family.fixture".to_owned()),
        unit_role_id: "unit.summary".to_owned(),
        layout_id: format!("layout.{}", artifact.artifact_class),
        normalized_slots: Vec::new(),
        typography_role_ids: vec![CommonDesignRoleV1::ArtifactTitle, CommonDesignRoleV1::Body],
        color_role_ids: vec![
            "brand_primary".to_owned(),
            "brand_secondary".to_owned(),
            "accent_1".to_owned(),
            "background".to_owned(),
            "surface".to_owned(),
            "text_primary".to_owned(),
            "text_secondary".to_owned(),
            "positive".to_owned(),
            "warning".to_owned(),
            "critical".to_owned(),
        ],
        spacing_ids: vec!["design.spacing.outer_margin".to_owned()],
        table_feature_ids: vec!["table.approved".to_owned()],
        chart_feature_ids: vec!["chart.approved".to_owned()],
        image_feature_ids: vec!["image.approved".to_owned()],
        density_class: DesignDensityClassV1::Medium,
        source_exemplar_ref: format!("exemplar.{}", artifact.artifact_id),
        quality_weight_millionths: match artifact.quality_label {
            DesignQualityLabelV1::Gold => 1_000_000,
            DesignQualityLabelV1::Approved => 800_000,
            _ => 0,
        },
        vector,
        feature_sha256: ZERO_HASH.to_owned(),
    }
    .seal()?)
}

fn candidate(organization: &str) -> TestResult<DesignPackCandidateV1> {
    let corpus = corpus(organization)?;
    let features = corpus
        .artifacts
        .iter()
        .map(|artifact| feature(organization, artifact))
        .collect::<TestResult<Vec<_>>>()?;
    Ok(compile_design_pack(&corpus, &features, 10_000)?)
}

#[test]
fn same_corpus_compiles_to_same_pack_hash() -> TestResult {
    let first = candidate("org.alpha")?;
    let second = candidate("org.alpha")?;
    assert_eq!(first.candidate_sha256, second.candidate_sha256);
    assert_eq!(first.pack.pack_sha256, second.pack.pack_sha256);
    assert!(first.quarantined);
    Ok(())
}

#[test]
fn cross_organization_feature_is_rejected() -> TestResult {
    let corpus = corpus("org.alpha")?;
    let mut feature = feature("org.alpha", &corpus.artifacts[0])?;
    feature.organization_id = "org.beta".to_owned();
    feature = feature.seal()?;
    assert!(matches!(
        compile_design_pack(&corpus, &[feature], 10_000),
        Err(DesignIntelligenceError::AccessDenied(_))
    ));
    Ok(())
}

#[test]
fn pack_approval_is_signed_and_tamper_evident() -> TestResult {
    let candidate = candidate("org.alpha")?;
    let key = SigningKey::from_bytes(&[9_u8; 32]);
    let approval = approve_design_pack(
        &candidate,
        candidate.pack.profile.artifact_class_refs.clone(),
        "environment.production".to_owned(),
        1_000,
        10_000,
        &key,
    )?;
    approval.verify(&key.verifying_key(), 5_000)?;
    let mut changed = approval;
    changed.organization_id = "org.beta".to_owned();
    assert!(changed.verify(&key.verifying_key(), 5_000).is_err());
    Ok(())
}

#[test]
fn typography_uses_only_approved_installed_fallback() -> TestResult {
    let candidate = candidate("org.alpha")?;
    let request = TypographyRequestV1 {
        schema_version: 1,
        request_id: "request.typography.1".to_owned(),
        organization_id: "org.alpha".to_owned(),
        design_pack_sha256: candidate.pack.pack_sha256.clone(),
        semantic_role: CommonDesignRoleV1::Body,
        text_sha256: hash("body text")?,
        character_count: 40,
        language_script_id: "hangul".to_owned(),
        available_width_millionths: 800_000,
        available_height_millionths: 500_000,
        request_sha256: ZERO_HASH.to_owned(),
    }
    .seal()?;
    let fonts = BTreeSet::from(["Malgun Gothic".to_owned()]);
    let decision = solve_typography(&request, &candidate.pack, &fonts)?;
    assert_eq!(
        decision.selected_font_family.as_deref(),
        Some("Malgun Gothic")
    );
    assert!(decision.used_fallback);
    assert!(decision.font_size_millipoints >= 10_000);
    Ok(())
}

#[test]
fn compiled_pack_keeps_table_chart_image_and_logo_policy_closed() -> TestResult {
    let candidate = candidate("org.alpha")?;
    let pack = &candidate.pack;
    assert_eq!(pack.table_grammar.organization_id, "org.alpha");
    assert_eq!(pack.chart_grammar.organization_id, "org.alpha");
    assert_eq!(pack.image_grammar.organization_id, "org.alpha");
    assert_eq!(pack.logo_policy.organization_id, "org.alpha");
    assert!(!pack.table_grammar.border_policy_id.is_empty());
    assert!(!pack.chart_grammar.allowed_chart_type_ids.is_empty());
    assert!(!pack
        .image_grammar
        .preferred_aspect_ratio_millionths
        .is_empty());
    assert!(pack.logo_policy.distortion_forbidden);
    assert!(pack
        .rule_provenance
        .iter()
        .all(|rule| !rule.source_exemplar_ids.is_empty()));
    Ok(())
}

#[test]
fn exemplar_query_is_exact_deterministic_and_content_minimized() -> TestResult {
    let corpus = corpus("org.alpha")?;
    let features = corpus
        .artifacts
        .iter()
        .map(|artifact| feature("org.alpha", artifact))
        .collect::<TestResult<Vec<_>>>()?;
    let candidate = compile_design_pack(&corpus, &features, 10_000)?;
    let index = build_exemplar_index(&corpus, &candidate.pack, &features)?;
    assert!(index
        .exemplars
        .iter()
        .all(|exemplar| exemplar.text_length == 0 && exemplar.line_count == 0));
    let request = DesignExemplarQueryV1 {
        schema_version: 1,
        query_id: "query.exemplar.test".to_owned(),
        organization_id: "org.alpha".to_owned(),
        artifact_class: "monthly_report".to_owned(),
        unit_role_id: "unit.summary".to_owned(),
        required_content_role_ids: vec![CommonDesignRoleV1::Body],
        table_required: true,
        chart_required: true,
        image_required: true,
        density_class: DesignDensityClassV1::Medium,
        aspect_or_page_class_id: "wide.16x9".to_owned(),
        maximum_results: 4,
        query_sha256: ZERO_HASH.to_owned(),
    }
    .seal()?;
    let first = query_exemplars(&index, &request)?;
    let second = query_exemplars(&index, &request)?;
    assert_eq!(first.result_sha256, second.result_sha256);
    assert_eq!(first.matches.len(), 1);
    let mut wrong_organization = request;
    wrong_organization.organization_id = "org.beta".to_owned();
    wrong_organization = wrong_organization.seal()?;
    assert!(query_exemplars(&index, &wrong_organization).is_err());
    Ok(())
}

#[test]
fn layout_solver_is_deterministic_and_exactly_pack_bound() -> TestResult {
    let candidate = candidate("org.alpha")?;
    let request = ArtifactLayoutRequestV1 {
        schema_version: 1,
        request_id: "request.layout.test".to_owned(),
        organization_id: "org.alpha".to_owned(),
        design_pack_sha256: candidate.pack.pack_sha256.clone(),
        artifact_class: "monthly_report".to_owned(),
        content_role_ids: vec![CommonDesignRoleV1::ArtifactTitle, CommonDesignRoleV1::Body],
        required_fact_ids: vec!["fact.monthly.total".to_owned()],
        required_image_ids: Vec::new(),
        density_class: DesignDensityClassV1::Medium,
        aspect_or_page_class_id: "wide.16x9".to_owned(),
        request_sha256: ZERO_HASH.to_owned(),
    }
    .seal()?;
    let first = solve_layout(&request, &candidate.pack)?;
    let second = solve_layout(&request, &candidate.pack)?;
    assert_eq!(first.decision_sha256, second.decision_sha256);
    assert_eq!(first.fit_status, DesignFitStatusV1::Fit);
    let mut wrong_pack = request;
    wrong_pack.design_pack_sha256 = hash("wrong-pack")?;
    wrong_pack = wrong_pack.seal()?;
    assert!(solve_layout(&wrong_pack, &candidate.pack).is_err());
    Ok(())
}

#[test]
fn critic_detects_bad_design_and_emits_bounded_closed_repairs() -> TestResult {
    let hard = critique_hard(
        "critique.hard.1".to_owned(),
        "org.alpha".to_owned(),
        hash("artifact")?,
        hash("pack")?,
        HardDesignViolationMetricsV1 {
            text_overflow: 1,
            image_distortion: 1,
            wrong_organization_pack: 1,
            ..HardDesignViolationMetricsV1::default()
        },
    )?;
    let soft = critique_soft(
        "critique.soft.1".to_owned(),
        "org.alpha".to_owned(),
        hash("artifact")?,
        hash("pack")?,
        "family.monthly".to_owned(),
        [900_000; 5],
        300_000,
    )?;
    let plan = plan_refinement("plan.1".to_owned(), &hard, &soft)?;
    assert_eq!(hard.status, DesignCritiqueStatusV1::Failed);
    assert!(!plan.steps.is_empty());
    assert!(plan.steps.len() <= MAX_REFINEMENT_ROUNDS as usize);
    Ok(())
}

#[test]
fn visual_claims_require_authoritative_fact_binding() -> TestResult {
    let valid = verify_visual_claim_integrity(
        "report.visual.1".to_owned(),
        hash("artifact")?,
        vec!["fact.kpi.1".to_owned()],
        vec!["fact.kpi.1".to_owned()],
        Vec::new(),
        Vec::new(),
    )?;
    assert!(valid.verified);
    let invalid = verify_visual_claim_integrity(
        "report.visual.2".to_owned(),
        hash("artifact")?,
        vec!["fact.kpi.1".to_owned()],
        vec!["fact.kpi.2".to_owned()],
        Vec::new(),
        Vec::new(),
    )?;
    assert!(!invalid.verified);
    Ok(())
}

#[test]
fn replay_requires_128_by_100_and_is_hash_stable() -> TestResult {
    let baseline = (0..REQUIRED_REPLAY_SCENARIOS)
        .map(|index| hash(&format!("scenario-{index}")))
        .collect::<TestResult<Vec<_>>>()?;
    let runs = baseline
        .iter()
        .map(|value| vec![value.clone(); REQUIRED_REPLAY_RUNS as usize])
        .collect::<Vec<_>>();
    let first = verify_design_replay(&baseline, &runs)?;
    let second = verify_design_replay(&baseline, &runs)?;
    first.validate_gate()?;
    assert_eq!(first.report_sha256, second.report_sha256);
    Ok(())
}

#[test]
fn strict_json_rejects_unknown_fields_and_raw_format_tokens() -> TestResult {
    let corpus = corpus("org.alpha")?;
    let mut value = serde_json::to_value(&corpus)?;
    value["unexpected"] = serde_json::json!(true);
    assert!(
        parse_design_json_strict::<OrganizationDesignCorpusV1>(&serde_json::to_vec(&value)?)
            .is_err()
    );

    let mut forbidden = serde_json::to_value(&corpus)?;
    forbidden["corpus_id"] = serde_json::json!("PowerPoint.Application");
    assert!(
        parse_design_json_strict::<OrganizationDesignCorpusV1>(&serde_json::to_vec(&forbidden)?)
            .is_err()
    );
    Ok(())
}

#[test]
fn certification_rejects_expiry_signature_and_payload_tamper() -> TestResult {
    let key = SigningKey::from_bytes(&[11_u8; 32]);
    let certification = DesignWorkCertificationV1 {
        schema_version: 1,
        certification_id: "certification.office450.test".to_owned(),
        completion_report_sha256: hash("completion")?,
        predecessor_finished_sha256: hash("predecessor")?,
        model_artifact_sha256: hash("model")?,
        runtime_artifact_sha256: hash("runtime")?,
        powerpoint_executable_sha256: hash("powerpoint")?,
        design_pack_sha256s: vec![hash("pack")?],
        evidence_ids: vec!["evidence.office450.test".to_owned()],
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 10_000,
        signer_id: "signer.office450.test".to_owned(),
        signing_key_id: "key.office450.test".to_owned(),
        signature_hex: String::new(),
        certification_sha256: ZERO_HASH.to_owned(),
    }
    .sign(&key)?;
    certification.verify(&key.verifying_key(), 5_000)?;
    assert!(certification.verify(&key.verifying_key(), 10_000).is_err());
    assert!(certification
        .verify(&SigningKey::from_bytes(&[12_u8; 32]).verifying_key(), 5_000)
        .is_err());
    let mut changed = certification;
    changed.design_pack_sha256s[0] = hash("other-pack")?;
    assert!(changed.verify(&key.verifying_key(), 5_000).is_err());
    Ok(())
}

#[test]
fn direct_rust_construction_still_enforces_nested_bounds() -> TestResult {
    let mut value = corpus("org.alpha")?;
    value.corpus_id = "a".repeat(2_049);
    assert!(value.seal().is_err());
    Ok(())
}
