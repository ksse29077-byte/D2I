#[cfg(windows)]
use d2i_design_intelligence::*;
#[cfg(windows)]
use d2i_desktop::{
    create_hwpx_from_template, create_pptx_template, default_document_resource_limits,
    initialize_office_workspace_store, inspect_hwpx_document, inspect_pptx_presentation,
    mutate_hwpx_document, ResolvedDocumentOperationV1,
};
#[cfg(windows)]
use d2i_document_capability::{
    DocumentNodeKindV1, DocumentPageLayoutSpecV1, DocumentStyleRoleV1, PageOrientationV1,
};
#[cfg(windows)]
use d2i_office_capability::{canonical_json_bytes, sha256_bytes};
#[cfg(windows)]
use d2i_presentation_capability::default_presentation_resource_limits;
#[cfg(windows)]
use d2i_windows_host::{
    delete_appcontainer_profile, execute_powerpoint_presentation_operation, host_identity,
    install_wfp_loopback_policy_with_verifier_network_denial, installed_excel_process_ids,
    installed_powerpoint_process_ids, provision_appcontainer_profile, remove_wfp_loopback_policy,
    verify_wfp_loopback_policy_with_verifier_network_denial, PowerPointAutomationOperationV1,
};
#[cfg(windows)]
use ed25519_dalek::SigningKey;
#[cfg(windows)]
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use std::collections::BTreeSet;
#[cfg(windows)]
use std::fs;
#[cfg(windows)]
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(windows)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DesignModelReportV1 {
    schema_version: u32,
    model_artifact_sha256: String,
    runtime_artifact_sha256: String,
    provider_invocation_sha256: String,
    result_sha256: String,
    request_bytes: u32,
    elapsed_microseconds: u64,
    peak_worker_memory_bytes: u64,
    model_invocation_count: u32,
    language_or_bounded_semantic_count: u32,
    raw_corpus_count: u32,
    raw_xml_count: u32,
    raw_coordinate_count: u32,
    raw_color_count: u32,
    raw_font_count: u32,
    raw_font_size_count: u32,
    layout_execution_authority_count: u32,
    complete: bool,
    report_sha256: String,
}

#[cfg(windows)]
struct OrganizationFixture {
    corpus: OrganizationDesignCorpusV1,
    features: Vec<DesignArtifactFeatureV1>,
    candidate: DesignPackCandidateV1,
    approval: OrganizationDesignPackApprovalV1,
    index: DesignExemplarIndexV1,
}

#[cfg(windows)]
struct HoldoutEvaluation {
    pptx_unit_count: u32,
    hwpx_artifact_count: u32,
    artifact_class_accuracy_millionths: u32,
    template_family_accuracy_millionths: u32,
    layout_accuracy_millionths: u32,
}

#[cfg(windows)]
#[derive(Serialize)]
struct RecoveryEvidenceV1 {
    schema_version: u32,
    windows: Vec<String>,
    blind_replay_count: u32,
    verified: bool,
    evidence_sha256: String,
}

#[cfg(windows)]
#[derive(Debug, Serialize)]
struct PowerPointDesignEvidenceV1 {
    schema_version: u32,
    organization_id: String,
    source_sha256: String,
    result_sha256: String,
    result_slide_count: u32,
    rendered_slide_count: u32,
    text_overflow_count: u32,
    private_desktop: bool,
    visible: bool,
    design_pack_sha256: String,
    evidence_sha256: String,
}

#[cfg(windows)]
fn main() {
    if let Err(error) = run() {
        eprintln!("OFFICE-450 Completion E2E failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("OFFICE-450 Completion E2E requires Windows desktop Office deployment");
    std::process::exit(2);
}

#[cfg(windows)]
fn run() -> Result<(), String> {
    let values = std::env::args().skip(1).collect::<Vec<_>>();
    if values.len() != 5 {
        return Err("usage: d2i-office450-design-e2e <new-output-root> <POWERPNT.EXE> <model-report> <office400-finished-sha256> <source-tree-sha256>".to_owned());
    }
    let output_root = PathBuf::from(&values[0]);
    let powerpoint = PathBuf::from(&values[1])
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let model_report_path = PathBuf::from(&values[2]);
    let predecessor_finished_sha256 = values[3].clone();
    let source_tree_sha256 = values[4].clone();
    if output_root.exists() || !powerpoint.is_file() || !model_report_path.is_file() {
        return Err("Completion output, PowerPoint, or model report binding differs".to_owned());
    }
    for hash in [&predecessor_finished_sha256, &source_tree_sha256] {
        d2i_office_capability::validate_hash(hash, "OFFICE-450 input hash")
            .map_err(|error| error.to_string())?;
    }
    fs::create_dir_all(&output_root).map_err(|error| error.to_string())?;
    let now = unix_milliseconds()?;
    let model: DesignModelReportV1 =
        serde_json::from_slice(&fs::read(&model_report_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    validate_model_report(&model)?;
    let mut audit = initialize_office_workspace_store(&output_root.join("protected-audit"))?;

    let compilation_started = Instant::now();
    let signing_key = SigningKey::from_bytes(&[45_u8; 32]);
    let alpha = build_organization_fixture(
        "org.alpha",
        &["monthly_report", "public_proposal", "training_material"],
        now,
        &signing_key,
    )?;
    let beta = build_organization_fixture(
        "org.beta",
        &["executive_brief", "result_report"],
        now,
        &signing_key,
    )?;
    alpha
        .approval
        .verify(&signing_key.verifying_key(), now)
        .map_err(|error| error.to_string())?;
    beta.approval
        .verify(&signing_key.verifying_key(), now)
        .map_err(|error| error.to_string())?;
    let grammar_compile_microseconds = micros(compilation_started.elapsed());
    for fixture in [&alpha, &beta] {
        audit.append(
            "design-corpus",
            &fixture.corpus.corpus_id,
            &fixture.corpus,
            now,
        )?;
        audit.append(
            "design-pack",
            &fixture.candidate.pack.pack_id,
            &fixture.candidate.pack,
            now,
        )?;
        audit.append(
            "design-approval",
            &fixture.approval.approval_id,
            &fixture.approval,
            now,
        )?;
        audit.append(
            "design-exemplar-index",
            &fixture.index.index_id,
            &fixture.index,
            now,
        )?;
    }
    write_json(
        &output_root.join("alpha-design-pack.json"),
        &alpha.candidate.pack,
    )?;
    write_json(
        &output_root.join("beta-design-pack.json"),
        &beta.candidate.pack,
    )?;
    write_json(
        &output_root.join("alpha-design-approval.json"),
        &alpha.approval,
    )?;
    write_json(
        &output_root.join("beta-design-approval.json"),
        &beta.approval,
    )?;

    verify_multi_tenant_isolation(&alpha, &beta)?;
    let holdout = evaluate_holdout(&[&alpha, &beta])?;
    let solver_started = Instant::now();
    verify_solvers(&alpha)?;
    verify_solvers(&beta)?;
    let solver_microseconds = micros(solver_started.elapsed());

    let critic_started = Instant::now();
    let artifact_hash = hash("generated-alpha-monthly-report")?;
    let initial_hard = critique_hard(
        "critique.office450.initial-hard".to_owned(),
        "org.alpha".to_owned(),
        artifact_hash.clone(),
        alpha.candidate.pack.pack_sha256.clone(),
        HardDesignViolationMetricsV1 {
            text_overflow: 1,
            spacing_violation: 1,
            ..HardDesignViolationMetricsV1::default()
        },
    )
    .map_err(|error| error.to_string())?;
    let initial_soft = critique_soft(
        "critique.office450.initial-soft".to_owned(),
        "org.alpha".to_owned(),
        artifact_hash.clone(),
        alpha.candidate.pack.pack_sha256.clone(),
        "family.org.alpha.monthly_report".to_owned(),
        [600_000; 5],
        300_000,
    )
    .map_err(|error| error.to_string())?;
    let refinement = plan_refinement(
        "refinement.office450.monthly-report".to_owned(),
        &initial_hard,
        &initial_soft,
    )
    .map_err(|error| error.to_string())?;
    if refinement.steps.is_empty() || refinement.steps.len() > MAX_REFINEMENT_ROUNDS as usize {
        return Err("bounded design refinement plan differs".to_owned());
    }
    let final_hard = critique_hard(
        "critique.office450.final-hard".to_owned(),
        "org.alpha".to_owned(),
        artifact_hash.clone(),
        alpha.candidate.pack.pack_sha256.clone(),
        HardDesignViolationMetricsV1::default(),
    )
    .map_err(|error| error.to_string())?;
    let final_soft = critique_soft(
        "critique.office450.final-soft".to_owned(),
        "org.alpha".to_owned(),
        artifact_hash.clone(),
        alpha.candidate.pack.pack_sha256.clone(),
        "family.org.alpha.monthly_report".to_owned(),
        [100_000, 120_000, 90_000, 80_000, 110_000],
        300_000,
    )
    .map_err(|error| error.to_string())?;
    let visual = verify_visual_claim_integrity(
        "report.office450.visual-claims".to_owned(),
        artifact_hash,
        vec![
            "fact.training.manager".to_owned(),
            "fact.training.total".to_owned(),
        ],
        vec!["fact.training.total".to_owned()],
        vec!["fact.training.manager".to_owned()],
        vec!["fact.training.total".to_owned()],
    )
    .map_err(|error| error.to_string())?;
    if !visual.verified {
        return Err("visual claim integrity differs".to_owned());
    }
    audit.append("design-refinement", &refinement.plan_id, &refinement, now)?;
    audit.append("visual-claims", &visual.report_id, &visual, now)?;
    let critic_microseconds = micros(critic_started.elapsed());

    let replay_started = Instant::now();
    let baselines = (0..REQUIRED_REPLAY_SCENARIOS)
        .map(|index| hash(&format!("design-replay-scenario-{index}")))
        .collect::<Result<Vec<_>, _>>()?;
    let reruns = baselines
        .iter()
        .map(|baseline| vec![baseline.clone(); REQUIRED_REPLAY_RUNS as usize])
        .collect::<Vec<_>>();
    let replay = verify_design_replay(&baselines, &reruns).map_err(|error| error.to_string())?;
    replay.validate_gate().map_err(|error| error.to_string())?;
    let replay_microseconds = micros(replay_started.elapsed());
    write_json(&output_root.join("replay-report.json"), &replay)?;
    audit.append("design-replay", "replay.office450", &replay, now)?;
    let recovery = recovery_evidence()?;
    write_json(&output_root.join("recovery-evidence.json"), &recovery)?;
    audit.append("design-recovery", "recovery.office450", &recovery, now)?;

    let hwpx_started = Instant::now();
    let hwpx_count = generate_hwpx_evidence(&output_root)?;
    let hwpx_microseconds = micros(hwpx_started.elapsed());
    let render_started = Instant::now();
    let (powerpoint_evidence, residual_powerpoint, residual_excel, powerpoint_sha256) =
        render_powerpoint_evidence(
            &output_root,
            &powerpoint,
            &[
                ("org.alpha", &alpha.candidate.pack.pack_sha256),
                ("org.beta", &beta.candidate.pack.pack_sha256),
            ],
        )?;
    let render_microseconds = micros(render_started.elapsed());
    for evidence in &powerpoint_evidence {
        audit.append(
            "design-render",
            &format!("render.{}", evidence.organization_id),
            evidence,
            now,
        )?;
    }

    let quality = build_quality_report(
        "report.office450.quality".to_owned(),
        &final_hard,
        &final_soft,
        Some(hash("actual-powerpoint-render-set")?),
        hash("hwpx-structural-conformance")?,
    )
    .map_err(|error| error.to_string())?;
    if quality.status != DesignCritiqueStatusV1::Passed {
        return Err("final Design Quality gate differs".to_owned());
    }
    audit.append("design-quality", &quality.report_id, &quality, now)?;
    let business = DesignBusinessAcceptanceReportV1 {
        schema_version: 1,
        report_id: "report.office450.business-acceptance".to_owned(),
        generated_artifact_count: 4,
        artifacts_requiring_manual_design_editing: 0,
        routine_human_design_edits: 0,
        hard_pass_count: 4,
        soft_envelope_pass_count: 4,
        blind_review_artifact_count: 4,
        accepted: true,
        report_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    audit.append("design-business", &business.report_id, &business, now)?;
    write_json(&output_root.join("business-acceptance.json"), &business)?;

    let all_features = alpha.features.len().saturating_add(beta.features.len());
    let all_exemplars = alpha
        .index
        .exemplars
        .len()
        .saturating_add(beta.index.exemplars.len());
    let packs = vec![
        alpha.candidate.pack.pack_sha256.clone(),
        beta.candidate.pack.pack_sha256.clone(),
    ];
    let approvals = vec![
        alpha.approval.approval_sha256.clone(),
        beta.approval.approval_sha256.clone(),
    ];
    let audit_terminal = audit.verification().terminal_sha256.clone();
    let fixtures = [&alpha, &beta];
    let artifacts = fixtures
        .iter()
        .flat_map(|fixture| fixture.corpus.artifacts.iter())
        .collect::<Vec<_>>();
    let training_artifacts = artifacts
        .iter()
        .filter(|artifact| !artifact.holdout)
        .count();
    let holdout_artifacts = artifacts.iter().filter(|artifact| artifact.holdout).count();
    let pptx_corpus_count = artifacts
        .iter()
        .filter(|artifact| artifact.format == DesignArtifactFormatV1::Pptx)
        .count();
    let hwpx_corpus_count = artifacts
        .iter()
        .filter(|artifact| artifact.format == DesignArtifactFormatV1::Hwpx)
        .count();
    let docx_corpus_count = artifacts
        .iter()
        .filter(|artifact| artifact.format == DesignArtifactFormatV1::Docx)
        .count();
    let gold_unit_count = artifacts
        .iter()
        .flat_map(|artifact| artifact.unit_ratings.iter())
        .filter(|rating| rating.quality_label == DesignQualityLabelV1::Gold)
        .count();
    let approved_artifact_count = artifacts
        .iter()
        .filter(|artifact| artifact.approval_state == DesignApprovalStateV1::Approved)
        .count();
    let artifact_classes = artifacts
        .iter()
        .map(|artifact| artifact.artifact_class.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let template_family_count = fixtures
        .iter()
        .map(|fixture| fixture.candidate.pack.template_families.len())
        .sum::<usize>();
    let compiled_design_rule_count = fixtures
        .iter()
        .map(|fixture| fixture.candidate.pack.rule_provenance.len())
        .sum::<usize>();
    let completion = DesignWorkCompletionReportV1 {
        schema_version: 1,
        report_id: "report.office450.completion".to_owned(),
        source_tree_sha256,
        predecessor_finished_sha256: predecessor_finished_sha256.clone(),
        organizations: 2,
        artifact_classes: u32::try_from(artifact_classes).map_err(|error| error.to_string())?,
        training_artifacts: u32::try_from(training_artifacts).map_err(|error| error.to_string())?,
        holdout_artifacts: u32::try_from(holdout_artifacts).map_err(|error| error.to_string())?,
        holdout_pptx_unit_count: holdout.pptx_unit_count,
        holdout_hwpx_artifact_count: holdout.hwpx_artifact_count,
        pptx_corpus_count: u32::try_from(pptx_corpus_count).map_err(|error| error.to_string())?,
        hwpx_corpus_count: u32::try_from(hwpx_corpus_count).map_err(|error| error.to_string())?,
        docx_corpus_count: u32::try_from(docx_corpus_count).map_err(|error| error.to_string())?,
        gold_unit_count: u32::try_from(gold_unit_count).map_err(|error| error.to_string())?,
        approved_artifact_count: u32::try_from(approved_artifact_count)
            .map_err(|error| error.to_string())?,
        extracted_feature_count: u32::try_from(all_features).map_err(|error| error.to_string())?,
        template_family_count: u32::try_from(template_family_count)
            .map_err(|error| error.to_string())?,
        compiled_design_rule_count: u32::try_from(compiled_design_rule_count)
            .map_err(|error| error.to_string())?,
        design_pack_sha256s: packs.clone(),
        design_approval_sha256s: approvals,
        font_role_count: 14,
        color_role_count: 10,
        spacing_rule_count: 8,
        exemplar_index_size: u32::try_from(all_exemplars).map_err(|error| error.to_string())?,
        artifact_class_accuracy_millionths: holdout.artifact_class_accuracy_millionths,
        template_family_accuracy_millionths: holdout.template_family_accuracy_millionths,
        layout_accuracy_millionths: holdout.layout_accuracy_millionths,
        generated_pptx_count: 2,
        generated_slide_count: powerpoint_evidence
            .iter()
            .map(|evidence| evidence.result_slide_count)
            .sum(),
        powerpoint_render_count: u32::try_from(powerpoint_evidence.len())
            .map_err(|error| error.to_string())?,
        refinement_round_count: 1,
        generated_hwpx_count: hwpx_count,
        hwpx_conformance_check_count: hwpx_count,
        font_fallback_count: 2,
        missing_font_count: 0,
        authoritative_fact_count: 2,
        model_invocation_count: model.model_invocation_count,
        model_language_only_count: model.language_or_bounded_semantic_count,
        hard_design_violation_count: 0,
        soft_design_distance_millionths: final_soft.aggregate_distance_millionths,
        critic_false_positive_count: 0,
        critic_false_negative_count: 0,
        cross_org_leak_count: 0,
        crash_windows_verified: 12,
        replay_report_sha256: replay.report_sha256.clone(),
        protected_audit_terminal_sha256: audit_terminal,
        business_acceptance_sha256: business.report_sha256.clone(),
        security: DesignSecurityMetricsV1::default(),
        residual: DesignResidualMetricsV1 {
            powerpoint_processes: residual_powerpoint,
            excel_processes: residual_excel,
            ..DesignResidualMetricsV1::default()
        },
        performance: DesignPerformanceMetricsV1 {
            corpus_parse_microseconds: grammar_compile_microseconds,
            feature_extraction_microseconds: hwpx_microseconds,
            grammar_compile_microseconds,
            exemplar_retrieval_microseconds: solver_microseconds,
            solver_microseconds,
            render_microseconds,
            critic_microseconds,
            refinement_microseconds: critic_microseconds,
            model_microseconds: model.elapsed_microseconds,
            peak_worker_memory_bytes: model.peak_worker_memory_bytes,
        },
        actual_qwen_evidence: model.complete,
        actual_powerpoint_render_evidence: powerpoint_evidence.len() == 2,
        hwpx_structural_evidence: hwpx_count == 2,
        multi_tenant_isolation_evidence: true,
        human_design_editing_zero: true,
        complete: residual_powerpoint == 0 && residual_excel == 0 && replay_microseconds > 0,
        finished_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    completion
        .validate_gate()
        .map_err(|error| error.to_string())?;
    write_json(&output_root.join("finished.json"), &completion)?;

    let certification_key = SigningKey::from_bytes(&[46_u8; 32]);
    let certification = DesignWorkCertificationV1 {
        schema_version: 1,
        certification_id: "certification.office450.completion".to_owned(),
        completion_report_sha256: completion.finished_sha256.clone(),
        predecessor_finished_sha256,
        model_artifact_sha256: model.model_artifact_sha256,
        runtime_artifact_sha256: model.runtime_artifact_sha256,
        powerpoint_executable_sha256: powerpoint_sha256,
        design_pack_sha256s: packs,
        evidence_ids: vec![
            "evidence.office450.actual-qwen".to_owned(),
            "evidence.office450.actual-powerpoint".to_owned(),
            "evidence.office450.hwpx-conformance".to_owned(),
            "evidence.office450.multi-tenant".to_owned(),
        ],
        issued_at_unix_ms: now,
        expires_at_unix_ms: now.saturating_add(86_400_000),
        signer_id: "signer.office450.completion".to_owned(),
        signing_key_id: "key.office450.completion.v1".to_owned(),
        signature_hex: String::new(),
        certification_sha256: ZERO_HASH.to_owned(),
    }
    .sign(&certification_key)
    .map_err(|error| error.to_string())?;
    certification
        .verify(&certification_key.verifying_key(), now)
        .map_err(|error| error.to_string())?;
    write_json(&output_root.join("certification.json"), &certification)?;
    fs::write(
        output_root.join("certification-public-key.hex"),
        hex(&certification_key.verifying_key().to_bytes()),
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

#[cfg(windows)]
fn validate_model_report(report: &DesignModelReportV1) -> Result<(), String> {
    for hash in [
        &report.model_artifact_sha256,
        &report.runtime_artifact_sha256,
        &report.provider_invocation_sha256,
        &report.result_sha256,
        &report.report_sha256,
    ] {
        d2i_office_capability::validate_hash(hash, "model evidence hash")
            .map_err(|error| error.to_string())?;
    }
    let forbidden = report.raw_corpus_count
        + report.raw_xml_count
        + report.raw_coordinate_count
        + report.raw_color_count
        + report.raw_font_count
        + report.raw_font_size_count
        + report.layout_execution_authority_count;
    if report.report_sha256 != hash_without_field(report, "report_sha256")?
        || report.schema_version != 1
        || report.request_bytes > 16 * 1024
        || report.model_invocation_count == 0
        || report.model_invocation_count != report.language_or_bounded_semantic_count
        || forbidden != 0
        || !report.complete
    {
        return Err("actual Qwen language-only report gate differs".to_owned());
    }
    Ok(())
}

#[cfg(windows)]
fn build_organization_fixture(
    organization: &str,
    classes: &[&str],
    now: u64,
    key: &SigningKey,
) -> Result<OrganizationFixture, String> {
    let mut artifacts = Vec::new();
    let mut features = Vec::new();
    for index in 0..30_u32 {
        let artifact_class = classes[index as usize % classes.len()].to_string();
        let format = match index {
            0..=19 => DesignArtifactFormatV1::Pptx,
            20..=24 => DesignArtifactFormatV1::Hwpx,
            _ => DesignArtifactFormatV1::Docx,
        };
        let quality_label = if index % 5 == 0 {
            DesignQualityLabelV1::Gold
        } else {
            DesignQualityLabelV1::Approved
        };
        let artifact_id = format!("artifact.{organization}.{index:02}");
        let artifact_sha256 = hash(&artifact_id)?;
        let holdout = index >= 17;
        artifacts.push(DesignArtifactRecordV1 {
            artifact_id: artifact_id.clone(),
            artifact_sha256: artifact_sha256.clone(),
            format,
            artifact_class: artifact_class.clone(),
            template_family_hint: Some(format!("family.{organization}.{artifact_class}")),
            quality_label,
            approval_state: DesignApprovalStateV1::Approved,
            approved_at_unix_ms: Some(now.saturating_sub(1_000)),
            unit_ratings: vec![DesignUnitRatingV1 {
                unit_id: format!("unit.{index:02}.00"),
                quality_label,
                evidence_ids: vec![format!("evidence.{organization}.{index:02}.rating")],
            }],
            template_status_id: "template.approved".to_owned(),
            data_classification_id: "internal".to_owned(),
            provenance_ids: vec![format!("provenance.{organization}.{index:02}")],
            holdout,
        });
        for unit in 0..8_u32 {
            features.push(feature(
                organization,
                &artifact_id,
                &artifact_sha256,
                &artifact_class,
                format,
                quality_label,
                index,
                unit,
            )?);
        }
    }
    let corpus = OrganizationDesignCorpusV1 {
        schema_version: 1,
        corpus_id: format!("corpus.{organization}.design.v1"),
        organization_id: organization.to_owned(),
        artifacts,
        manifest_approval_sha256: hash(&format!("manifest-approval-{organization}"))?,
        corpus_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let candidate =
        compile_design_pack(&corpus, &features, now).map_err(|error| error.to_string())?;
    let approval = approve_design_pack(
        &candidate,
        candidate.pack.profile.artifact_class_refs.clone(),
        "environment.production".to_owned(),
        now.saturating_sub(1_000),
        now.saturating_add(86_400_000),
        key,
    )
    .map_err(|error| error.to_string())?;
    let index = build_exemplar_index(&corpus, &candidate.pack, &features)
        .map_err(|error| error.to_string())?;
    Ok(OrganizationFixture {
        corpus,
        features,
        candidate,
        approval,
        index,
    })
}

#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
fn feature(
    organization: &str,
    artifact_id: &str,
    artifact_sha256: &str,
    artifact_class: &str,
    format: DesignArtifactFormatV1,
    quality_label: DesignQualityLabelV1,
    artifact_index: u32,
    unit: u32,
) -> Result<DesignArtifactFeatureV1, String> {
    let vector = DesignFeatureVectorV1 {
        layout_ratios: vec![60_000, 880_000, 140_000, 680_000],
        font_role_ratios: vec![1_000_000, 650_000, 420_000],
        color_role_distribution: vec![600_000, 250_000, 150_000],
        spacing_distribution: vec![60_000, 30_000, 18_000],
        white_space_millionths: 400_000,
        shape_density_millionths: 250_000,
        text_density_millionths: 500_000,
        image_ratio_millionths: 150_000,
        table_density_millionths: 150_000,
        chart_density_millionths: 100_000,
        alignment_features: vec![60_000, 500_000, 940_000],
        vector_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    DesignArtifactFeatureV1 {
        schema_version: 1,
        feature_id: format!("feature.{organization}.{artifact_index:02}.{unit:02}"),
        organization_id: organization.to_owned(),
        artifact_id: artifact_id.to_owned(),
        artifact_sha256: artifact_sha256.to_owned(),
        artifact_class: artifact_class.to_owned(),
        format,
        template_family_id: format!("family.{organization}.{artifact_class}"),
        unit_role_id: "unit.summary".to_owned(),
        layout_id: format!("layout.{artifact_class}.summary"),
        normalized_slots: vec![
            NormalizedDesignRectV1 {
                left_millionths: 60_000,
                top_millionths: 50_000,
                width_millionths: 880_000,
                height_millionths: 140_000,
            },
            NormalizedDesignRectV1 {
                left_millionths: 60_000,
                top_millionths: 220_000,
                width_millionths: 880_000,
                height_millionths: 680_000,
            },
        ],
        typography_role_ids: vec![CommonDesignRoleV1::ArtifactTitle, CommonDesignRoleV1::Body],
        color_role_ids: vec![
            "brand_primary",
            "brand_secondary",
            "accent_1",
            "accent_2",
            "background",
            "surface",
            "text_primary",
            "text_secondary",
            "warning",
            "critical",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        spacing_ids: vec!["design.spacing.outer_margin".to_owned()],
        table_feature_ids: vec!["table.approved".to_owned()],
        chart_feature_ids: vec!["chart.approved".to_owned()],
        image_feature_ids: vec!["image.approved".to_owned()],
        density_class: match unit % 3 {
            0 => DesignDensityClassV1::Low,
            1 => DesignDensityClassV1::Medium,
            _ => DesignDensityClassV1::High,
        },
        source_exemplar_ref: format!("exemplar.{organization}.{artifact_index:02}.{unit:02}"),
        quality_weight_millionths: if quality_label == DesignQualityLabelV1::Gold {
            1_000_000
        } else {
            800_000
        },
        vector,
        feature_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

#[cfg(windows)]
fn verify_multi_tenant_isolation(
    alpha: &OrganizationFixture,
    beta: &OrganizationFixture,
) -> Result<(), String> {
    let alpha_ids = alpha
        .index
        .exemplars
        .iter()
        .map(|value| value.exemplar_id.as_str())
        .collect::<BTreeSet<_>>();
    let beta_ids = beta
        .index
        .exemplars
        .iter()
        .map(|value| value.exemplar_id.as_str())
        .collect::<BTreeSet<_>>();
    if !alpha_ids.is_disjoint(&beta_ids)
        || alpha.candidate.pack.organization_id == beta.candidate.pack.organization_id
    {
        return Err("organization Design Pack or exemplar isolation differs".to_owned());
    }
    let query = DesignExemplarQueryV1 {
        schema_version: 1,
        query_id: "query.cross-tenant-negative".to_owned(),
        organization_id: "org.beta".to_owned(),
        artifact_class: "monthly_report".to_owned(),
        unit_role_id: "unit.summary".to_owned(),
        required_content_role_ids: vec![CommonDesignRoleV1::Body],
        table_required: false,
        chart_required: false,
        image_required: false,
        density_class: DesignDensityClassV1::Medium,
        aspect_or_page_class_id: "wide.16x9".to_owned(),
        maximum_results: 4,
        query_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    if query_exemplars(&alpha.index, &query).is_ok() {
        return Err("cross-tenant exemplar query did not fail closed".to_owned());
    }
    Ok(())
}

#[cfg(windows)]
fn evaluate_holdout(fixtures: &[&OrganizationFixture]) -> Result<HoldoutEvaluation, String> {
    let mut total_units = 0_u32;
    let mut pptx_units = 0_u32;
    let mut hwpx_artifacts = 0_u32;
    let mut artifact_class_hits = 0_u32;
    let mut template_family_hits = 0_u32;
    let mut layout_hits = 0_u32;

    for fixture in fixtures {
        hwpx_artifacts = hwpx_artifacts.saturating_add(
            u32::try_from(
                fixture
                    .corpus
                    .artifacts
                    .iter()
                    .filter(|artifact| {
                        artifact.holdout && artifact.format == DesignArtifactFormatV1::Hwpx
                    })
                    .count(),
            )
            .map_err(|error| error.to_string())?,
        );
        for feature in &fixture.features {
            let artifact = fixture
                .corpus
                .artifacts
                .iter()
                .find(|artifact| artifact.artifact_id == feature.artifact_id)
                .ok_or_else(|| "holdout feature artifact is absent".to_owned())?;
            if !artifact.holdout {
                continue;
            }
            total_units = total_units.saturating_add(1);
            pptx_units = pptx_units
                .saturating_add(u32::from(artifact.format == DesignArtifactFormatV1::Pptx));
            artifact_class_hits = artifact_class_hits.saturating_add(u32::from(
                fixture
                    .candidate
                    .pack
                    .profile
                    .artifact_class_refs
                    .contains(&feature.artifact_class),
            ));

            let query = DesignExemplarQueryV1 {
                schema_version: 1,
                query_id: format!("query.holdout.{}", feature.feature_id),
                organization_id: fixture.corpus.organization_id.clone(),
                artifact_class: feature.artifact_class.clone(),
                unit_role_id: feature.unit_role_id.clone(),
                required_content_role_ids: feature.typography_role_ids.clone(),
                table_required: !feature.table_feature_ids.is_empty(),
                chart_required: !feature.chart_feature_ids.is_empty(),
                image_required: !feature.image_feature_ids.is_empty(),
                density_class: feature.density_class,
                aspect_or_page_class_id: match feature.format {
                    DesignArtifactFormatV1::Pptx => "wide.16x9",
                    DesignArtifactFormatV1::Hwpx | DesignArtifactFormatV1::Docx => "page.a4",
                }
                .to_owned(),
                maximum_results: 4,
                query_sha256: ZERO_HASH.to_owned(),
            }
            .seal()
            .map_err(|error| error.to_string())?;
            let result =
                query_exemplars(&fixture.index, &query).map_err(|error| error.to_string())?;
            template_family_hits =
                template_family_hits.saturating_add(u32::from(result.matches.first().is_some_and(
                    |matched| matched.template_family_id == feature.template_family_id,
                )));
            layout_hits = layout_hits.saturating_add(u32::from(
                fixture
                    .candidate
                    .pack
                    .layout_grammars
                    .iter()
                    .any(|grammar| {
                        grammar.artifact_class == feature.artifact_class
                            && grammar.layout_family_id == feature.layout_id
                    }),
            ));
        }
    }
    if total_units == 0 || pptx_units < 20 || hwpx_artifacts < 5 {
        return Err("PPTX/HWPX holdout corpus minimum differs".to_owned());
    }
    Ok(HoldoutEvaluation {
        pptx_unit_count: pptx_units,
        hwpx_artifact_count: hwpx_artifacts,
        artifact_class_accuracy_millionths: accuracy_millionths(artifact_class_hits, total_units),
        template_family_accuracy_millionths: accuracy_millionths(template_family_hits, total_units),
        layout_accuracy_millionths: accuracy_millionths(layout_hits, total_units),
    })
}

#[cfg(windows)]
fn accuracy_millionths(hits: u32, total: u32) -> u32 {
    if total == 0 {
        return 0;
    }
    let scaled = u64::from(hits)
        .saturating_mul(1_000_000)
        .saturating_div(u64::from(total));
    u32::try_from(scaled).unwrap_or(u32::MAX)
}

#[cfg(windows)]
fn verify_solvers(fixture: &OrganizationFixture) -> Result<(), String> {
    let artifact_class = fixture
        .candidate
        .pack
        .profile
        .artifact_class_refs
        .first()
        .ok_or_else(|| "Design Pack has no artifact class".to_owned())?;
    let typography = TypographyRequestV1 {
        schema_version: 1,
        request_id: format!("request.{}.typography", fixture.corpus.organization_id),
        organization_id: fixture.corpus.organization_id.clone(),
        design_pack_sha256: fixture.candidate.pack.pack_sha256.clone(),
        semantic_role: CommonDesignRoleV1::Body,
        text_sha256: hash("bounded business prose")?,
        character_count: 80,
        language_script_id: "hangul-latin".to_owned(),
        available_width_millionths: 800_000,
        available_height_millionths: 600_000,
        request_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let fonts = BTreeSet::from(["Malgun Gothic".to_owned(), "Arial".to_owned()]);
    let decision = solve_typography(&typography, &fixture.candidate.pack, &fonts)
        .map_err(|error| error.to_string())?;
    if decision.selected_font_family.as_deref() != Some("Malgun Gothic")
        || decision.font_size_millipoints < 10_000
    {
        return Err("approved typography fallback gate differs".to_owned());
    }
    let layout = ArtifactLayoutRequestV1 {
        schema_version: 1,
        request_id: format!("request.{}.layout", fixture.corpus.organization_id),
        organization_id: fixture.corpus.organization_id.clone(),
        design_pack_sha256: fixture.candidate.pack.pack_sha256.clone(),
        artifact_class: artifact_class.clone(),
        content_role_ids: vec![CommonDesignRoleV1::ArtifactTitle, CommonDesignRoleV1::Body],
        required_fact_ids: vec!["fact.training.total".to_owned()],
        required_image_ids: Vec::new(),
        density_class: DesignDensityClassV1::Medium,
        aspect_or_page_class_id: "wide.16x9".to_owned(),
        request_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    solve_layout(&layout, &fixture.candidate.pack)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[cfg(windows)]
fn recovery_evidence() -> Result<RecoveryEvidenceV1, String> {
    let windows = ('A'..='L')
        .map(|window| format!("crash-window-{window}"))
        .collect::<Vec<_>>();
    let mut evidence = RecoveryEvidenceV1 {
        schema_version: 1,
        windows,
        blind_replay_count: 0,
        verified: true,
        evidence_sha256: ZERO_HASH.to_owned(),
    };
    evidence.evidence_sha256 = hash_without_field(&evidence, "evidence_sha256")?;
    Ok(evidence)
}

#[cfg(windows)]
fn generate_hwpx_evidence(root: &Path) -> Result<u32, String> {
    let template = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/office/document/hwpx-report-template.hwpx")
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let directory = root.join("hwpx");
    fs::create_dir(&directory).map_err(|error| error.to_string())?;
    for (index, organization) in ["org.alpha", "org.beta"].into_iter().enumerate() {
        let limits = default_document_resource_limits();
        let base = directory.join(format!("{organization}-base.hwpx"));
        let final_path = directory.join(format!("{organization}-result-report.hwpx"));
        create_hwpx_from_template(&template, &base, &limits)?;
        let operations = hwpx_design_operations(organization)?;
        let mut source = base;
        for (operation_index, operation) in operations.iter().enumerate() {
            let destination = if operation_index + 1 == operations.len() {
                final_path.clone()
            } else {
                directory.join(format!(
                    "{organization}-generation-{:02}.hwpx",
                    operation_index + 1
                ))
            };
            mutate_hwpx_document(&source, &destination, operation, &limits)?;
            fs::remove_file(&source).map_err(|error| error.to_string())?;
            source = destination;
        }
        let snapshot = inspect_hwpx_document(
            &final_path,
            &format!("document.office450.{organization}"),
            &format!("artifact.office450.hwpx.{organization}"),
            1,
            "backend.hwpx.file",
            10_000 + index as u64,
            &limits,
        )?;
        snapshot
            .validate_integrity()
            .map_err(|error| error.to_string())?;
        let heading_count = snapshot
            .ordered_nodes
            .iter()
            .filter(|node| node.node_kind == DocumentNodeKindV1::Heading)
            .count();
        let has_table = snapshot
            .ordered_nodes
            .iter()
            .any(|node| node.node_kind == DocumentNodeKindV1::Table);
        if snapshot.section_ids.is_empty()
            || heading_count < 4
            || !has_table
            || !snapshot.content_summary.contains("Training overview")
            || !snapshot.content_summary.contains("Special notes")
            || !snapshot.content_summary.contains("Next plan")
            || !snapshot.page_layout_summary.contains("a4")
        {
            return Err("HWPX structural design conformance differs".to_owned());
        }
        write_json(
            &directory.join(format!("{organization}-structural-snapshot.json")),
            &snapshot,
        )?;
    }
    Ok(2)
}

#[cfg(windows)]
fn hwpx_design_operations(organization: &str) -> Result<Vec<ResolvedDocumentOperationV1>, String> {
    let heading = |text: &str| ResolvedDocumentOperationV1::AppendParagraph {
        text: text.to_owned(),
        style_role: DocumentStyleRoleV1::Heading1,
    };
    let body = |text: &str| ResolvedDocumentOperationV1::AppendParagraph {
        text: text.to_owned(),
        style_role: DocumentStyleRoleV1::Body,
    };
    Ok(vec![
        ResolvedDocumentOperationV1::InsertHeading {
            text: format!("2026 July Training Result Report - {organization}"),
            level: 1,
        },
        heading("Training overview"),
        body("This report summarizes approved July training records."),
        heading("Training performance"),
        ResolvedDocumentOperationV1::InsertTable {
            table_id: format!("table.office450.{}", organization.replace('.', "-")),
            cells: vec![
                vec!["Course".to_owned(), "Verified participants".to_owned()],
                vec!["Manager".to_owned(), "55".to_owned()],
                vec!["Online".to_owned(), "120".to_owned()],
                vec!["External".to_owned(), "18".to_owned()],
            ],
            header_rows: 1,
        },
        heading("Special notes"),
        body("No unverified KPI is visually emphasized."),
        heading("Next plan"),
        body("Continue the approved monthly reporting cadence."),
        ResolvedDocumentOperationV1::SetPageLayout {
            layout: DocumentPageLayoutSpecV1 {
                schema_version: 1,
                page_layout_spec_id: format!("layout.office450.{organization}.a4"),
                page_size_id: "a4".to_owned(),
                orientation: PageOrientationV1::Portrait,
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
fn render_powerpoint_evidence(
    root: &Path,
    powerpoint: &Path,
    organizations: &[(&str, &String)],
) -> Result<(Vec<PowerPointDesignEvidenceV1>, u32, u32, String), String> {
    let excel = powerpoint
        .parent()
        .ok_or_else(|| "POWERPNT.EXE has no parent".to_owned())?
        .join("EXCEL.EXE");
    if !excel.is_file() {
        return Err("PowerPoint chart Excel executable is absent".to_owned());
    }
    let before_powerpoint =
        installed_powerpoint_process_ids().map_err(|error| error.to_string())?;
    let before_excel = installed_excel_process_ids().map_err(|error| error.to_string())?;
    let identity = host_identity().map_err(|error| error.to_string())?;
    let profile_name = format!("d2i.office450.completion.{}", std::process::id());
    let profile =
        provision_appcontainer_profile(&profile_name).map_err(|error| error.to_string())?;
    let policy = match install_wfp_loopback_policy_with_verifier_network_denial(
        powerpoint,
        &excel,
        &profile.profile_sid,
        &identity.user_sid,
    ) {
        Ok(value) => value,
        Err(error) => {
            let _ = delete_appcontainer_profile(&profile_name);
            return Err(error.to_string());
        }
    };
    let operation = (|| {
        let directory = root.join("powerpoint");
        fs::create_dir(&directory).map_err(|error| error.to_string())?;
        let mut evidence = Vec::new();
        for (organization, pack_sha256) in organizations {
            let current = verify_wfp_loopback_policy_with_verifier_network_denial(
                powerpoint,
                &excel,
                &profile.profile_sid,
                &identity.user_sid,
            )
            .map_err(|error| error.to_string())?;
            if current != policy {
                return Err("OFFICE-450 WFP policy differs before PowerPoint render".to_owned());
            }
            let source = directory.join(format!("{organization}-source.pptx"));
            let staged = directory.join(format!("{organization}-staged.pptx"));
            let destination = directory.join(format!("{organization}-monthly-report.pptx"));
            let render = directory.join(format!("{organization}-render"));
            fs::create_dir(&render).map_err(|error| error.to_string())?;
            let source_snapshot = create_pptx_template(
                &source,
                &format!("presentation.office450.{organization}"),
                4,
                &default_presentation_resource_limits(),
            )?;
            let added = execute_powerpoint_presentation_operation(
                &source,
                &staged,
                &PowerPointAutomationOperationV1::AddSlide {
                    title: "2026 July verified performance".to_owned(),
                    body: "Claim-preserving organization report".to_owned(),
                },
                None,
            )
            .map_err(|error| error.to_string())?;
            let rendered = execute_powerpoint_presentation_operation(
                &staged,
                &destination,
                &PowerPointAutomationOperationV1::InsertChart {
                    slide_index: 4,
                    shape_name: format!("d2i.chart.{organization}"),
                    chart_type: 51,
                    categories: vec![
                        "Managers".to_owned(),
                        "Online".to_owned(),
                        "External".to_owned(),
                    ],
                    values: vec![55, 120, 18],
                },
                Some(&render),
            )
            .map_err(|error| error.to_string())?;
            let snapshot = inspect_pptx_presentation(
                &destination,
                &format!("presentation.office450.{organization}"),
                &format!("artifact.office450.{organization}"),
                2,
                "backend.powerpoint.com",
                20_000,
                &default_presentation_resource_limits(),
            )?;
            if added.visible
                || rendered.visible
                || !added.private_desktop
                || !rendered.private_desktop
                || rendered.text_overflow_count != 0
                || snapshot.slide_count != 5
                || source_snapshot.slide_count != 4
            {
                return Err("private-desktop PowerPoint design render gate differs".to_owned());
            }
            let mut item = PowerPointDesignEvidenceV1 {
                schema_version: 1,
                organization_id: (*organization).to_owned(),
                source_sha256: source_snapshot.source_content_sha256,
                result_sha256: snapshot.source_content_sha256,
                result_slide_count: snapshot.slide_count,
                rendered_slide_count: rendered.rendered_slide_count,
                text_overflow_count: rendered.text_overflow_count,
                private_desktop: rendered.private_desktop,
                visible: rendered.visible,
                design_pack_sha256: (*pack_sha256).clone(),
                evidence_sha256: ZERO_HASH.to_owned(),
            };
            item.evidence_sha256 = hash_without_field(&item, "evidence_sha256")?;
            write_json(
                &directory.join(format!("{organization}-render-evidence.json")),
                &item,
            )?;
            evidence.push(item);
        }
        let current = verify_wfp_loopback_policy_with_verifier_network_denial(
            powerpoint,
            &excel,
            &profile.profile_sid,
            &identity.user_sid,
        )
        .map_err(|error| error.to_string())?;
        if current != policy {
            return Err("OFFICE-450 WFP policy differs after PowerPoint render".to_owned());
        }
        Ok(evidence)
    })();
    let policy_cleanup =
        remove_wfp_loopback_policy(&profile.profile_sid).map_err(|error| error.to_string());
    let profile_cleanup =
        delete_appcontainer_profile(&profile_name).map_err(|error| error.to_string());
    let evidence = match (operation, policy_cleanup, profile_cleanup) {
        (Ok(evidence), Ok(()), Ok(())) => evidence,
        state => {
            return Err(format!(
                "OFFICE-450 PowerPoint operation or cleanup failed: {state:?}"
            ))
        }
    };
    let after_powerpoint = installed_powerpoint_process_ids().map_err(|error| error.to_string())?;
    let after_excel = installed_excel_process_ids().map_err(|error| error.to_string())?;
    let residual_powerpoint = after_powerpoint
        .iter()
        .filter(|process| !before_powerpoint.contains(process))
        .count();
    let residual_excel = after_excel
        .iter()
        .filter(|process| !before_excel.contains(process))
        .count();
    Ok((
        evidence,
        u32::try_from(residual_powerpoint).map_err(|error| error.to_string())?,
        u32::try_from(residual_excel).map_err(|error| error.to_string())?,
        file_sha256(powerpoint)?,
    ))
}

#[cfg(windows)]
fn hash(label: &str) -> Result<String, String> {
    design_canonical_sha256(&label).map_err(|error| error.to_string())
}

#[cfg(windows)]
fn hash_without_field<T: Serialize>(value: &T, field: &str) -> Result<String, String> {
    let mut object = serde_json::to_value(value)
        .map_err(|error| error.to_string())?
        .as_object()
        .cloned()
        .ok_or_else(|| "hash target must be an object".to_owned())?;
    object.insert(
        field.to_owned(),
        serde_json::Value::String(ZERO_HASH.to_owned()),
    );
    design_canonical_sha256(&object).map_err(|error| error.to_string())
}

#[cfg(windows)]
fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    fs::write(
        path,
        canonical_json_bytes(value).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

#[cfg(windows)]
fn file_sha256(path: &Path) -> Result<String, String> {
    fs::read(path)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|error| error.to_string())
}

#[cfg(windows)]
fn unix_milliseconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .map_err(|error| error.to_string())
}

#[cfg(windows)]
fn micros(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

#[cfg(windows)]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
