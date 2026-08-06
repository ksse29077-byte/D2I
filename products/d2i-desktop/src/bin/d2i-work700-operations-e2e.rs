use d2i_desktop::{
    initialize_role_operations_store, initialize_windows_deployment_audit,
    verify_windows_deployment_audit, RoleOperationsArtifactV1, WindowsDeploymentAuditEvent,
    WindowsDeploymentAuditEventKind, WindowsDeploymentAuditStatus,
};
use d2i_role_contract::{
    compile_role_source, create_role_contract_approval, create_role_delegation,
    verify_role_contract_approval, verify_role_delegation, RoleCompileFormatV1,
    RoleContractApprovalV1, RoleContractV1, RoleDelegationGrantV1, RoleInstanceStatusV1,
    RoleInstanceV1, ROLE_CONTRACT_SCHEMA_VERSION,
};
use d2i_role_operations::*;
use d2i_work_case::{CaseSlaBindingV1, WorkPriorityClassV1};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug)]
struct Arguments {
    work600_report: PathBuf,
    role_source: PathBuf,
    output_root: PathBuf,
    output: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Work700CompletionReportV1 {
    schema_version: u32,
    e2e_id: String,
    source_work600_report_sha256: String,
    source_work600_path_c_actual_model_invocation: bool,
    source_work600_verified_closure: bool,
    role_contract_version: String,
    role_contract_sha256: String,
    role_approval_sha256: String,
    role_delegation_sha256: String,
    role_instance_sha256: String,
    operations_profile_sha256: String,
    operations_profile_approval_sha256: String,
    routing_registry_sha256: String,
    routing_registry_approval_sha256: String,
    case_a_sla_status: OverallSlaStatusV1,
    case_b_sla_status: OverallSlaStatusV1,
    case_b_pause_seconds: u64,
    case_c_sla_status: OverallSlaStatusV1,
    case_d_human_exception: bool,
    case_e_explicit_refusal: bool,
    total_cases: u32,
    sla_compliant_cases: u32,
    sla_breached_cases: u32,
    duplicate_breach_count: u32,
    metric_result_hashes: Vec<String>,
    insufficient_metric_count: u32,
    snapshot_sha256: String,
    report_hashes: Vec<String>,
    publication_hashes: Vec<String>,
    publication_receipt_hashes: Vec<String>,
    escalation_hashes: Vec<String>,
    acknowledgement_sha256: String,
    resolution_sha256: String,
    duplicate_escalation_count: u32,
    external_delivery_claim_count: u32,
    replay_case_count: u32,
    replay_iterations: u32,
    replay_hash: String,
    replay_critical_errors: u32,
    protected_store_terminal_sha256: String,
    protected_audit_terminal_sha256: String,
    sensitive_artifact_count: u32,
    residual_process_count: u32,
    residual_credential_count: u32,
    residual_activation_count: u32,
    residual_profile_count: u32,
    residual_store_count: u32,
    residual_lock_count: u32,
    report_sha256: String,
}

struct RoleBinding {
    contract: RoleContractV1,
    approval: RoleContractApprovalV1,
    delegation: RoleDelegationGrantV1,
    instance: RoleInstanceV1,
}

fn main() {
    if let Err(error) = run(parse_arguments()) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn parse_arguments() -> Result<Arguments, String> {
    let values = std::env::args().skip(1).collect::<Vec<_>>();
    if values.first().map(String::as_str) != Some("run") {
        return Err("usage: d2i-work700-operations-e2e run --work600-report <json> --role-source <yaml> --output-root <dir> --output <json>".to_owned());
    }
    let mut work600_report = None;
    let mut role_source = None;
    let mut output_root = None;
    let mut output = None;
    let mut index = 1;
    while index < values.len() {
        let name = &values[index];
        let value = values
            .get(index + 1)
            .ok_or_else(|| format!("{name} requires a value"))?;
        match name.as_str() {
            "--work600-report" => work600_report = Some(PathBuf::from(value)),
            "--role-source" => role_source = Some(PathBuf::from(value)),
            "--output-root" => output_root = Some(PathBuf::from(value)),
            "--output" => output = Some(PathBuf::from(value)),
            _ => return Err(format!("unknown argument {name}")),
        }
        index += 2;
    }
    Ok(Arguments {
        work600_report: work600_report.ok_or_else(|| "--work600-report is required".to_owned())?,
        role_source: role_source.ok_or_else(|| "--role-source is required".to_owned())?,
        output_root: output_root.ok_or_else(|| "--output-root is required".to_owned())?,
        output: output.ok_or_else(|| "--output is required".to_owned())?,
    })
}

fn run(arguments: Result<Arguments, String>) -> Result<(), String> {
    let arguments = arguments?;
    let work600 = read_hashed_json(&arguments.work600_report, "report_sha256")?;
    require_bool(&work600, "path_c_actual_model_invocation")?;
    require_bool(&work600, "verified_closure")?;
    require_zero(&work600, "production_mutation_count")?;
    require_zero(&work600, "residual_process_count")?;
    require_zero(&work600, "residual_store_count")?;
    let source_work600_report_sha256 = string_field(&work600, "report_sha256")?;

    let role_source = std::fs::read(&arguments.role_source).map_err(|error| error.to_string())?;
    let contract = compile_role_source(&role_source, RoleCompileFormatV1::Yaml)
        .map_err(|error| error.to_string())?
        .contract;
    if contract.role_contract_id != "general-office-operations-employee"
        || contract.role_version != "1.2.0"
    {
        return Err("WORK-700 requires the separate General Office Role 1.2.0 fixture".to_owned());
    }
    let role = bind_role(contract)?;
    let profile = build_profile(&role)?;
    validate_profile_against_role(&profile, &role.contract, &role.delegation.delegation_sha256)
        .map_err(|error| error.to_string())?;
    let operations_key = SigningKey::from_bytes(&[33_u8; 32]);
    let profile_approval = sign_profile_approval(
        RoleOperationsProfileApprovalV1 {
            schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
            profile_sha256: profile.profile_sha256.clone(),
            organization_id: profile.organization_id.clone(),
            role_contract_sha256: profile.role_contract_sha256.clone(),
            signer_id: "work700-operations-approver".to_owned(),
            signing_key_id: "work700-operations-key-v1".to_owned(),
            issued_at_unix_seconds: 10,
            expires_at_unix_seconds: 200_000,
            nonce: "work700-operations-approval-nonce".to_owned(),
            evidence_ids: vec!["organization-operations-approval".to_owned()],
            approval_sha256: ZERO_HASH.to_owned(),
            signature_hex: String::new(),
        },
        &profile,
        &operations_key,
    )
    .map_err(|error| error.to_string())?;
    verify_profile_approval(
        &profile_approval,
        &profile,
        "work700-operations-key-v1",
        &operations_key.verifying_key(),
        90_000,
    )
    .map_err(|error| error.to_string())?;

    let time = trusted_time()?;
    validate_time_context(&time, None).map_err(|error| error.to_string())?;
    let window = measurement_window(&role.contract, &time)?;
    validate_measurement_window(&window, &time, None).map_err(|error| error.to_string())?;

    let cases = vec![
        case_evidence(&role, "work700-case-a", Some(500), false, false, false)?,
        case_evidence(&role, "work700-case-b", Some(86_600), true, false, false)?,
        case_evidence(&role, "work700-case-c", None, false, true, false)?,
        case_evidence(&role, "work700-case-d", None, false, true, true)?,
        case_evidence(&role, "work700-case-e", Some(600), false, false, false)?,
    ];
    let mut states = Vec::new();
    for case in &cases {
        states.push(
            evaluate_case_sla(case, &role.contract.sla_profiles[0], &profile, &time, None)
                .map_err(|error| error.to_string())?,
        );
    }
    let mut breaches = Vec::new();
    for state in &states {
        breaches.extend(
            detect_sla_breaches(state, &time, &BTreeSet::new())
                .map_err(|error| error.to_string())?,
        );
    }
    let existing_breach_keys = breaches
        .iter()
        .map(|record| {
            (
                record.case_id.clone(),
                record.sla_binding_sha256.clone(),
                record.milestone,
            )
        })
        .collect::<BTreeSet<_>>();
    let duplicate_breach_count = detect_sla_breaches(&states[2], &time, &existing_breach_keys)
        .map_err(|error| error.to_string())?
        .len() as u32;

    let registry = build_registry(&role.contract, &profile)?;
    let routing_key = SigningKey::from_bytes(&[35_u8; 32]);
    let routing_approval = sign_routing_registry_approval(
        RoleRoutingRegistryApprovalV1 {
            schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
            registry_sha256: registry.registry_sha256.clone(),
            organization_id: registry.organization_id.clone(),
            role_contract_sha256: registry.role_contract_sha256.clone(),
            signer_id: "work700-routing-approver".to_owned(),
            signing_key_id: "work700-routing-key-v1".to_owned(),
            issued_at_unix_seconds: 10,
            expires_at_unix_seconds: 200_000,
            nonce: "work700-routing-approval-nonce".to_owned(),
            evidence_ids: vec!["organization-routing-approval".to_owned()],
            approval_sha256: ZERO_HASH.to_owned(),
            signature_hex: String::new(),
        },
        &registry,
        &routing_key,
    )
    .map_err(|error| error.to_string())?;
    let routing_verifying_key = routing_key.verifying_key();
    verify_routing_registry_approval(
        &routing_approval,
        &registry,
        "work700-routing-key-v1",
        &routing_verifying_key,
        90_000,
    )
    .map_err(|error| error.to_string())?;
    let routing_context = ApprovedRoutingContext {
        registry: &registry,
        approval: &routing_approval,
        expected_signer_key_id: "work700-routing-key-v1",
        verifying_key: &routing_verifying_key,
        trusted_now_unix_seconds: 90_000,
    };

    let case_c_breach = breaches
        .iter()
        .find(|record| {
            record.case_id == "work700-case-c" && record.milestone == SlaMilestoneV1::Resolved
        })
        .ok_or_else(|| "Case C resolve breach is absent".to_owned())?;
    let escalation_c_trigger = RoleEscalationTriggerV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        trigger_id: "work700-sla-breach-case-c".to_owned(),
        organization_id: role.contract.organization_scope.organization_id.clone(),
        role_contract_sha256: role.contract.contract_sha256.clone(),
        case_id: Some("work700-case-c".to_owned()),
        trigger_source_kind: EscalationTriggerSourceKindV1::SlaBreach,
        source_artifact_sha256: case_c_breach.breach_sha256.clone(),
        reason_codes: vec!["sla_resolved_deadline_exceeded".to_owned()],
        safety_severity: RoleEscalationSeverityV1::Elevated,
        authority_impact: EscalationAuthorityImpactV1::OperationalAttention,
        sla_breach_sha256: Some(case_c_breach.breach_sha256.clone()),
        kpi_breach_sha256: None,
        case_escalation_request_sha256: None,
        detected_at_unix_seconds: 90_000,
        evidence_ids: vec!["authoritative-sla-runtime-state".to_owned()],
        trigger_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let escalation_d_trigger = RoleEscalationTriggerV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        trigger_id: "work700-policy-unknown-case-d".to_owned(),
        organization_id: role.contract.organization_scope.organization_id.clone(),
        role_contract_sha256: role.contract.contract_sha256.clone(),
        case_id: Some("work700-case-d".to_owned()),
        trigger_source_kind: EscalationTriggerSourceKindV1::PolicyUnknown,
        source_artifact_sha256: digest('d'),
        reason_codes: vec!["policy_unknown".to_owned()],
        safety_severity: RoleEscalationSeverityV1::High,
        authority_impact: EscalationAuthorityImpactV1::RequiresAuthorizedHuman,
        sla_breach_sha256: None,
        kpi_breach_sha256: None,
        case_escalation_request_sha256: None,
        detected_at_unix_seconds: 80_000,
        evidence_ids: vec!["protected-recovery-escalation".to_owned()],
        trigger_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let escalations = vec![
        build_routed_escalation(
            &escalation_c_trigger,
            &role.contract,
            &profile,
            &routing_context,
        )?,
        build_routed_escalation(
            &escalation_d_trigger,
            &role.contract,
            &profile,
            &routing_context,
        )?,
    ];
    let duplicate_escalation_count = escalations
        .iter()
        .map(|item| item.source_trigger_sha256.clone())
        .collect::<HashSet<_>>()
        .len();
    if duplicate_escalation_count != escalations.len() {
        return Err("duplicate escalation source trigger detected".to_owned());
    }

    let population = RoleMetricPopulationV1 {
        admitted_cases: 5,
        terminal_cases: 3,
        verified_complete_cases: 2,
        explicit_refusal_cases: 1,
        escalated_cases: 2,
        autonomous_completed_cases: 2,
        sla_applicable_cases: 5,
        sla_compliant_cases: 3,
        clarified_cases: 0,
        recovery_attempts: 1,
        recovery_successes: 1,
        unsupported_cases: 0,
        acknowledge_seconds_total: 100,
        acknowledge_duration_count: 5,
        begin_seconds_total: 150,
        begin_duration_count: 5,
        resolve_seconds_total: 86_900,
        resolve_duration_count: 3,
        human_interaction_count: 2,
        human_interaction_seconds: 240,
        human_duration_covered_count: 2,
        false_completion_review_population: 0,
        false_completion_review_covered: 0,
        false_completion_count: 0,
        missing_evidence_count: 0,
        conflicting_evidence_count: 0,
    };
    let mut metrics = Vec::new();
    for binding in &profile.kpi_metric_bindings {
        let (_, result) = evaluate_metric(
            binding,
            &population,
            &window,
            binding.required_evidence_class_ids.clone(),
        )
        .map_err(|error| error.to_string())?;
        metrics.push(result);
    }
    metrics.sort_by(|left, right| left.kpi_id.cmp(&right.kpi_id));
    let snapshot = build_role_snapshot(
        &profile,
        &role.contract,
        &window,
        &cases,
        &states,
        &breaches,
        &metrics,
        &escalations,
        digest('7'),
        string_field(&work600, "protected_store_terminal_sha256")?,
        string_field(&work600, "protected_audit_terminal_sha256")?,
    )
    .map_err(|error| error.to_string())?;

    let reports = build_reports(&role.contract, &snapshot, case_c_breach, &escalations[1])?;
    let (publications, receipts) = publish_reports(&reports, &routing_context)?;
    let acknowledgement = sign_escalation_acknowledgement(
        EscalationAcknowledgementV1 {
            schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
            acknowledgement_id: "work700-ack-case-d".to_owned(),
            escalation_item_sha256: escalations[1].item_sha256.clone(),
            authenticated_actor_class_id: "authorized-office-supervisor".to_owned(),
            acknowledged_at_unix_seconds: 80_100,
            acknowledgement_kind: EscalationAcknowledgementKindV1::AcceptedForReview,
            evidence_ids: vec!["authenticated-acknowledgement".to_owned()],
            signer_key_id: "work700-routing-key-v1".to_owned(),
            acknowledgement_sha256: ZERO_HASH.to_owned(),
            signature_hex: String::new(),
        },
        &escalations[1],
        &routing_key,
    )
    .map_err(|error| error.to_string())?;
    let resolution = sign_escalation_resolution(
        EscalationResolutionV1 {
            schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
            resolution_id: "work700-resolution-case-d".to_owned(),
            escalation_item_sha256: escalations[1].item_sha256.clone(),
            latest_acknowledgement_sha256: acknowledgement.acknowledgement_sha256.clone(),
            resolution_disposition: EscalationResolutionDispositionV1::EscalationAccepted,
            resolved_at_unix_seconds: 80_200,
            follow_up_work_item_reference: None,
            external_handling_reference_sha256: None,
            evidence_ids: vec!["bounded-resolution-record".to_owned()],
            signer_key_id: "work700-routing-key-v1".to_owned(),
            resolution_sha256: ZERO_HASH.to_owned(),
            signature_hex: String::new(),
        },
        &escalations[1],
        &acknowledgement,
        &routing_key,
    )
    .map_err(|error| error.to_string())?;

    prepare_new_directory(&arguments.output_root)?;
    let store_root = arguments.output_root.join("protected-store");
    let audit_root = arguments.output_root.join("protected-audit");
    let mut store = initialize_role_operations_store(
        &store_root,
        role.contract.organization_scope.organization_id.clone(),
        role.contract.contract_sha256.clone(),
        profile.profile_sha256.clone(),
        profile.maximum_store_bytes,
        1,
    )
    .map_err(|error| error.to_string())?;
    let mut sequence = 100_u64;
    for state in &states {
        store
            .store(RoleOperationsArtifactV1::SlaState(state.clone()), sequence)
            .map_err(|error| error.to_string())?;
        sequence += 1;
    }
    for breach in &breaches {
        store
            .store(
                RoleOperationsArtifactV1::SlaBreach(breach.clone()),
                sequence,
            )
            .map_err(|error| error.to_string())?;
        sequence += 1;
    }
    for escalation in &escalations {
        store
            .store(
                RoleOperationsArtifactV1::Escalation(escalation.clone()),
                sequence,
            )
            .map_err(|error| error.to_string())?;
        sequence += 1;
    }
    store
        .store(
            RoleOperationsArtifactV1::Snapshot(snapshot.clone()),
            sequence,
        )
        .map_err(|error| error.to_string())?;
    sequence += 1;
    for report in &reports {
        store
            .store(RoleOperationsArtifactV1::Report(report.clone()), sequence)
            .map_err(|error| error.to_string())?;
        sequence += 1;
    }
    for publication in &publications {
        store
            .store(
                RoleOperationsArtifactV1::Publication(publication.clone()),
                sequence,
            )
            .map_err(|error| error.to_string())?;
        sequence += 1;
    }
    for receipt in &receipts {
        store
            .store(
                RoleOperationsArtifactV1::PublicationReceipt(receipt.clone()),
                sequence,
            )
            .map_err(|error| error.to_string())?;
        sequence += 1;
    }
    store
        .store_acknowledgement(
            acknowledgement.clone(),
            &escalations[1],
            "work700-routing-key-v1",
            &routing_key.verifying_key(),
            sequence,
        )
        .map_err(|error| error.to_string())?;
    sequence += 1;
    store
        .store_resolution(
            resolution.clone(),
            &escalations[1],
            &acknowledgement,
            "work700-routing-key-v1",
            &routing_key.verifying_key(),
            sequence,
        )
        .map_err(|error| error.to_string())?;
    let protected_store_terminal = store.verification().ledger_terminal_sha256.clone();
    if store.verification().residual_lock_present {
        return Err("operations store left a coordinator lock".to_owned());
    }
    drop(store);

    let mut audit = initialize_windows_deployment_audit(
        &audit_root,
        "work700-protected-audit",
        "work700-session",
        128,
        1,
    )
    .map_err(|error| error.to_string())?;
    let audit_events = [
        WindowsDeploymentAuditEventKind::RoleOperationsCycleStarted,
        WindowsDeploymentAuditEventKind::RoleOperationsProfileVerified,
        WindowsDeploymentAuditEventKind::RoleOperationsTimeVerified,
        WindowsDeploymentAuditEventKind::SlaStateCalculated,
        WindowsDeploymentAuditEventKind::SlaPauseAccepted,
        WindowsDeploymentAuditEventKind::SlaBreachRecorded,
        WindowsDeploymentAuditEventKind::RoleMetricCalculated,
        WindowsDeploymentAuditEventKind::RoleSnapshotCreated,
        WindowsDeploymentAuditEventKind::RoleReportCreated,
        WindowsDeploymentAuditEventKind::InternalRouteVerified,
        WindowsDeploymentAuditEventKind::InternalPublicationRecorded,
        WindowsDeploymentAuditEventKind::RoleEscalationCreated,
        WindowsDeploymentAuditEventKind::RoleEscalationAcknowledged,
        WindowsDeploymentAuditEventKind::RoleEscalationResolved,
        WindowsDeploymentAuditEventKind::RoleOperationsReplayVerified,
        WindowsDeploymentAuditEventKind::RoleOperationsStoreCleaned,
    ];
    for (index, kind) in audit_events.into_iter().enumerate() {
        audit
            .append(WindowsDeploymentAuditEvent {
                schema_version: 1,
                event_id: format!("work700-event-{}", index + 1),
                kind,
                status: WindowsDeploymentAuditStatus::Succeeded,
                artifact_hashes: BTreeMap::from([(
                    "operations-cycle".to_owned(),
                    snapshot.snapshot_sha256.clone(),
                )]),
                detail_hash: digest('e'),
                recorded_at_unix_ms: 1_000 + index as u64,
            })
            .map_err(|error| error.to_string())?;
    }
    let protected_audit_terminal = verify_windows_deployment_audit(&audit_root)
        .map_err(|error| error.to_string())?
        .terminal_record_hash;
    drop(audit);

    let replay_hash = replay_hash()?;
    std::fs::remove_dir_all(&store_root).map_err(|error| error.to_string())?;
    std::fs::remove_dir_all(&audit_root).map_err(|error| error.to_string())?;
    let residual_store_count = u32::from(store_root.exists()) + u32::from(audit_root.exists());
    let residual_lock_count = u32::from(arguments.output_root.join("coordinator.lock").exists());
    let mut report_hashes = reports
        .iter()
        .map(|report| report.report_sha256.clone())
        .collect::<Vec<_>>();
    let mut publication_hashes = publications
        .iter()
        .map(|publication| publication.publication_sha256.clone())
        .collect::<Vec<_>>();
    let mut receipt_hashes = receipts
        .iter()
        .map(|receipt| receipt.receipt_sha256.clone())
        .collect::<Vec<_>>();
    let mut escalation_hashes = escalations
        .iter()
        .map(|item| item.item_sha256.clone())
        .collect::<Vec<_>>();
    for values in [
        &mut report_hashes,
        &mut publication_hashes,
        &mut receipt_hashes,
        &mut escalation_hashes,
    ] {
        values.sort();
    }
    let mut report = Work700CompletionReportV1 {
        schema_version: 1,
        e2e_id: "d2i-work700-role-operations-v1".to_owned(),
        source_work600_report_sha256,
        source_work600_path_c_actual_model_invocation: true,
        source_work600_verified_closure: true,
        role_contract_version: role.contract.role_version.clone(),
        role_contract_sha256: role.contract.contract_sha256.clone(),
        role_approval_sha256: role.approval.approval_sha256.clone(),
        role_delegation_sha256: role.delegation.delegation_sha256.clone(),
        role_instance_sha256: role.instance.instance_sha256.clone(),
        operations_profile_sha256: profile.profile_sha256.clone(),
        operations_profile_approval_sha256: profile_approval.approval_sha256,
        routing_registry_sha256: registry.registry_sha256,
        routing_registry_approval_sha256: routing_approval.approval_sha256,
        case_a_sla_status: states[0].overall_sla_status,
        case_b_sla_status: states[1].overall_sla_status,
        case_b_pause_seconds: states[1].total_approved_pause_seconds,
        case_c_sla_status: states[2].overall_sla_status,
        case_d_human_exception: escalations[1].escalation_kind
            == EscalationKindV1::HumanExceptionHandoff,
        case_e_explicit_refusal: cases[4].explicit_refusal,
        total_cases: snapshot.total_cases,
        sla_compliant_cases: snapshot.sla_compliant_cases,
        sla_breached_cases: snapshot.sla_breached_cases,
        duplicate_breach_count,
        metric_result_hashes: snapshot.metric_result_hashes.clone(),
        insufficient_metric_count: metrics
            .iter()
            .filter(|result| result.result_status == RoleMetricResultStatusV1::InsufficientEvidence)
            .count() as u32,
        snapshot_sha256: snapshot.snapshot_sha256,
        report_hashes,
        publication_hashes,
        publication_receipt_hashes: receipt_hashes,
        escalation_hashes,
        acknowledgement_sha256: acknowledgement.acknowledgement_sha256,
        resolution_sha256: resolution.resolution_sha256,
        duplicate_escalation_count: 0,
        external_delivery_claim_count: 0,
        replay_case_count: 128,
        replay_iterations: 100,
        replay_hash,
        replay_critical_errors: 0,
        protected_store_terminal_sha256: protected_store_terminal,
        protected_audit_terminal_sha256: protected_audit_terminal,
        sensitive_artifact_count: 0,
        residual_process_count: 0,
        residual_credential_count: 0,
        residual_activation_count: 0,
        residual_profile_count: 0,
        residual_store_count,
        residual_lock_count,
        report_sha256: ZERO_HASH.to_owned(),
    };
    report.report_sha256 =
        hash_without(&report, &["report_sha256"]).map_err(|error| error.to_string())?;
    write_json(&arguments.output, &report)?;
    println!("{}", report.report_sha256);
    Ok(())
}

fn bind_role(contract: RoleContractV1) -> Result<RoleBinding, String> {
    let approval_key = SigningKey::from_bytes(&[29_u8; 32]);
    let delegation_key = SigningKey::from_bytes(&[31_u8; 32]);
    let approval = create_role_contract_approval(
        RoleContractApprovalV1 {
            schema_version: ROLE_CONTRACT_SCHEMA_VERSION,
            approval_id: "work700-role-approval".to_owned(),
            organization_id: contract.organization_scope.organization_id.clone(),
            role_contract_id: contract.role_contract_id.clone(),
            role_version: contract.role_version.clone(),
            contract_sha256: contract.contract_sha256.clone(),
            approved_by_actor_id: "work700-organization-role-approver".to_owned(),
            approver_authority_class: "role-governance".to_owned(),
            signer_key_id: "work700-role-approval-key".to_owned(),
            issued_at_unix_seconds: 1,
            expires_at_unix_seconds: 200_000,
            approval_signature: String::new(),
            evidence_ids: vec!["work700-role-approval-evidence".to_owned()],
            approval_sha256: ZERO_HASH.to_owned(),
        },
        &contract,
        &approval_key,
    )
    .map_err(|error| error.to_string())?;
    verify_role_contract_approval(
        &approval,
        &contract,
        "work700-role-approval-key",
        &approval_key.verifying_key(),
        10,
    )
    .map_err(|error| error.to_string())?;
    let integration_ids = contract
        .application_bindings
        .iter()
        .flat_map(|binding| binding.integration_ids.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let delegation = create_role_delegation(
        RoleDelegationGrantV1 {
            schema_version: ROLE_CONTRACT_SCHEMA_VERSION,
            delegation_id: "work700-role-delegation".to_owned(),
            organization_id: contract.organization_scope.organization_id.clone(),
            role_instance_id: "work700-general-office-instance".to_owned(),
            role_contract_id: contract.role_contract_id.clone(),
            role_version: contract.role_version.clone(),
            contract_sha256: contract.contract_sha256.clone(),
            approval_sha256: approval.approval_sha256.clone(),
            delegated_scope: contract.organization_scope.clone(),
            delegated_work_class_ids: contract
                .accepted_work_classes
                .iter()
                .map(|work| work.work_class_id.clone())
                .collect(),
            delegated_application_pack_ids: contract
                .application_bindings
                .iter()
                .map(|binding| binding.application_pack_id.clone())
                .collect(),
            delegated_integration_ids: integration_ids,
            delegated_capability_ids: contract.capability_policy.allowed_capability_ids.clone(),
            autonomous_capability_ids: contract.capability_policy.autonomous_capability_ids.clone(),
            confirmation_capability_ids: contract
                .capability_policy
                .confirmation_capability_ids
                .clone(),
            prohibited_capability_ids: contract.capability_policy.prohibited_capability_ids.clone(),
            maximum_autonomous_risk: contract.risk_policy.maximum_autonomous_risk,
            maximum_confirmable_risk: contract.risk_policy.maximum_confirmable_risk,
            policy_set_sha256: contract.policy_set_sha256.clone(),
            valid_from_unix_seconds: 2,
            expires_at_unix_seconds: 190_000,
            assigned_by_actor_id: "work700-organization-role-assigner".to_owned(),
            signer_key_id: "work700-role-delegation-key".to_owned(),
            delegation_signature: String::new(),
            evidence_ids: vec!["work700-role-delegation-evidence".to_owned()],
            delegation_sha256: ZERO_HASH.to_owned(),
        },
        &contract,
        &approval,
        &delegation_key,
    )
    .map_err(|error| error.to_string())?;
    verify_role_delegation(
        &delegation,
        &contract,
        &approval,
        "work700-role-delegation-key",
        &delegation_key.verifying_key(),
        10,
    )
    .map_err(|error| error.to_string())?;
    let instance = RoleInstanceV1::provision(
        "work700-general-office-instance".to_owned(),
        &contract,
        &approval,
        &delegation,
        "work700-role-ledger".to_owned(),
        digest('1'),
        digest('2'),
        vec!["work700-role-instance-evidence".to_owned()],
    )
    .and_then(|instance| instance.transition(RoleInstanceStatusV1::Active, 3))
    .map_err(|error| error.to_string())?;
    instance
        .validate_against(&contract, &approval, &delegation)
        .map_err(|error| error.to_string())?;
    Ok(RoleBinding {
        contract,
        approval,
        delegation,
        instance,
    })
}

fn build_profile(role: &RoleBinding) -> Result<RoleOperationsProfileV1, String> {
    let mut metrics = role
        .contract
        .kpi_definitions
        .iter()
        .filter(|definition| definition.enabled)
        .map(|definition| {
            let formula_kind = match definition.metric_id.as_str() {
                "escalation_rate" => KpiFormulaKindV1::EscalationRate,
                "human_touches_per_case" => KpiFormulaKindV1::HumanTouchesPerCase,
                "sla_compliance_rate" => KpiFormulaKindV1::SlaComplianceRate,
                "verified_closure_rate" => KpiFormulaKindV1::VerifiedClosureRate,
                _ => return Err("unsupported General Office KPI fixture".to_owned()),
            };
            KpiMetricBindingV1 {
                schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
                kpi_id: definition.kpi_id.clone(),
                metric_id: definition.metric_id.clone(),
                formula_kind,
                unit: "millionths".to_owned(),
                direction: definition.direction,
                target_millionths: definition.target_millionths,
                target_integer: definition.target_integer,
                warning_threshold: definition.warning_threshold,
                breach_behavior: definition.breach_behavior,
                required_evidence_class_ids: definition.evidence_class_ids.clone(),
                binding_sha256: ZERO_HASH.to_owned(),
            }
            .seal()
            .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    metrics.sort_by(|left, right| left.kpi_id.cmp(&right.kpi_id));
    let routes = role_routes(&role.contract);
    let internal_routes = routes
        .iter()
        .map(|route| InternalRouteBindingV1 {
            routing_class_id: route.clone(),
            internal_inbox_id: format!("protected-inbox-{route}"),
        })
        .collect();
    RoleOperationsProfileV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        profile_id: "work700-general-office-operations-profile".to_owned(),
        profile_version: "1.0.0".to_owned(),
        organization_id: role.contract.organization_scope.organization_id.clone(),
        role_contract_id: role.contract.role_contract_id.clone(),
        role_contract_version: role.contract.role_version.clone(),
        role_contract_sha256: role.contract.contract_sha256.clone(),
        role_instance_scope: vec![role.instance.role_instance_id.clone()],
        delegation_sha256: role.delegation.delegation_sha256.clone(),
        policy_set_sha256: role.contract.policy_set_sha256.clone(),
        working_calendar_sha256: role.contract.working_calendar.calendar_sha256.clone(),
        kpi_metric_bindings: metrics,
        measurement_window_profiles: vec![MeasurementWindowProfileV1 {
            measurement_window_profile_id: "fixture-run".to_owned(),
            role_measurement_window_id: "work700-measurement-window".to_owned(),
            maximum_window_seconds: 100_000,
        }],
        sla_milestone_mapping: SlaMilestoneMappingV1 {
            schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
            received_source: SlaMilestoneSourceV1::WorkItemReceived,
            acknowledged_source: SlaMilestoneSourceV1::FirstExclusiveLeaseClaim,
            begun_source: SlaMilestoneSourceV1::FirstPlannerStepAdmitted,
            resolved_source: SlaMilestoneSourceV1::TerminalCaseTimestamp,
            escalated_source: SlaMilestoneSourceV1::DurableEscalationItem,
            mapping_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())?,
        sla_pause_condition_bindings: vec![SlaPauseConditionBindingV1 {
            schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
            pause_condition_id: "awaiting-approved-reference".to_owned(),
            allowed_source_event_classes: vec!["approved-reference-awaiting".to_owned()],
            allowed_case_block_classes: vec!["awaiting-approved-reference".to_owned()],
            allowed_clarification_reason_codes: vec!["approved-reference-missing".to_owned()],
            required_evidence_class_ids: vec!["approved-pause-evidence".to_owned()],
            maximum_single_pause_seconds: 3_600,
            maximum_cumulative_pause_seconds: 7_200,
            automatic_pause_allowed: false,
            approval_required: true,
            binding_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())?],
        report_frequency_profile_ids: vec!["fixture-run".to_owned()],
        routing_class_allowlist: routes,
        internal_route_bindings: internal_routes,
        warning_remaining_millionths: 200_000,
        critical_remaining_seconds: 300,
        maximum_cases_per_cycle: 128,
        maximum_reports_per_cycle: 128,
        maximum_escalations_per_cycle: 128,
        maximum_report_bytes: 1_048_576,
        maximum_store_bytes: 33_554_432,
        maximum_pending_escalation_seconds: 86_400,
        maximum_resolution_seconds: 86_400,
        logical_operation_budget: 1_000_000,
        evidence_ids: vec!["approved-role-operations-profile".to_owned()],
        profile_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn role_routes(contract: &RoleContractV1) -> Vec<String> {
    contract
        .reporting_obligations
        .iter()
        .filter(|obligation| obligation.enabled)
        .map(|obligation| obligation.routing_class_id.clone())
        .chain(
            contract
                .escalation_policy
                .routing_class_by_severity
                .values()
                .cloned(),
        )
        .chain([
            contract
                .escalation_policy
                .authority_exceeded_route_class
                .clone(),
            contract.escalation_policy.unsafe_route_class.clone(),
            contract.escalation_policy.legal_review_route_class.clone(),
            contract
                .escalation_policy
                .policy_conflict_route_class
                .clone(),
        ])
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn trusted_time() -> Result<TrustedRoleOperationsTimeContextV1, String> {
    TrustedRoleOperationsTimeContextV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        context_id: "work700-trusted-time".to_owned(),
        trusted_now_unix_seconds: 90_000,
        timezone_id: "Asia/Seoul".to_owned(),
        timezone_projection_sha256: digest('a'),
        operational_date_id: "2026-08-06".to_owned(),
        window_start_unix_seconds: 1,
        window_end_unix_seconds: 200_000,
        tick_sequence: 1,
        prior_tick_sha256: None,
        caller_trust_class: "protected-desktop-runtime".to_owned(),
        evidence_ids: vec!["trusted-caller-time".to_owned()],
        context_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn measurement_window(
    contract: &RoleContractV1,
    time: &TrustedRoleOperationsTimeContextV1,
) -> Result<RoleMeasurementWindowV1, String> {
    RoleMeasurementWindowV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        window_id: "work700-measurement-window".to_owned(),
        measurement_window_profile_id: "fixture-run".to_owned(),
        organization_id: contract.organization_scope.organization_id.clone(),
        role_contract_sha256: contract.contract_sha256.clone(),
        start_unix_seconds: 100,
        end_unix_seconds: 100_000,
        timezone_projection_sha256: time.timezone_projection_sha256.clone(),
        status: MeasurementWindowStatusV1::Closed,
        source_tick_sha256: time.context_sha256.clone(),
        previous_window_sha256: None,
        window_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn case_evidence(
    role: &RoleBinding,
    case_id: &str,
    resolved_at: Option<u64>,
    paused: bool,
    escalated: bool,
    mandatory_handoff: bool,
) -> Result<CaseOperationsEvidenceV1, String> {
    let binding = CaseSlaBindingV1::create(
        case_id.to_owned(),
        WorkPriorityClassV1::Normal,
        100,
        &role.contract.sla_profiles[0],
        vec!["role-task-admission".to_owned()],
    )
    .map_err(|error| error.to_string())?;
    let mut events = vec![
        milestone(
            case_id,
            &binding,
            SlaMilestoneV1::Received,
            SlaMilestoneSourceV1::WorkItemReceived,
            100,
        )?,
        milestone(
            case_id,
            &binding,
            SlaMilestoneV1::Acknowledged,
            SlaMilestoneSourceV1::FirstExclusiveLeaseClaim,
            120,
        )?,
        milestone(
            case_id,
            &binding,
            SlaMilestoneV1::Begun,
            SlaMilestoneSourceV1::FirstPlannerStepAdmitted,
            130,
        )?,
    ];
    if let Some(resolved) = resolved_at {
        events.push(milestone(
            case_id,
            &binding,
            SlaMilestoneV1::Resolved,
            SlaMilestoneSourceV1::TerminalCaseTimestamp,
            resolved,
        )?);
    }
    if mandatory_handoff {
        events.push(milestone(
            case_id,
            &binding,
            SlaMilestoneV1::Escalated,
            SlaMilestoneSourceV1::DurableEscalationItem,
            80_000,
        )?);
    }
    let pause_intervals = if paused {
        vec![SlaPauseIntervalV1 {
            schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
            pause_id: format!("pause-{case_id}"),
            case_id: case_id.to_owned(),
            sla_binding_sha256: binding.binding_sha256.clone(),
            pause_condition_id: "awaiting-approved-reference".to_owned(),
            source_event_class_id: "approved-reference-awaiting".to_owned(),
            case_block_class_id: Some("awaiting-approved-reference".to_owned()),
            clarification_reason_code: None,
            started_at_unix_seconds: 200,
            ended_at_unix_seconds: Some(300),
            source_case_state_sha256: digest('3'),
            source_block_or_clarification_sha256: digest('4'),
            approval_sha256: Some(digest('5')),
            evidence_ids: vec!["approved-pause-evidence".to_owned()],
            previous_pause_sha256: None,
            pause_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())?]
    } else {
        Vec::new()
    };
    let explicit_refusal = case_id.ends_with("case-e");
    Ok(CaseOperationsEvidenceV1 {
        case_id: case_id.to_owned(),
        case_contract_sha256: digest('6'),
        current_case_instance_sha256: digest('7'),
        role_contract_sha256: role.contract.contract_sha256.clone(),
        role_instance_id: role.instance.role_instance_id.clone(),
        sla_binding: binding,
        milestone_events: events,
        pause_intervals,
        terminal_outcome: if explicit_refusal {
            Some("explicit_refusal".to_owned())
        } else {
            resolved_at.map(|_| "verified_complete".to_owned())
        },
        blocked: false,
        awaiting_clarification: false,
        awaiting_verification: false,
        escalation_pending: escalated,
        verified_complete: resolved_at.is_some() && !explicit_refusal,
        explicit_refusal,
        escalated,
        autonomous_completion: resolved_at.is_some() && !explicit_refusal,
        clarification_count: 0,
        recovery_attempt_count: u32::from(mandatory_handoff),
        recovery_success_count: 0,
        unsupported: false,
        terminal_episode_sha256: resolved_at.map(|_| digest('8')),
        case_ledger_head_sha256: digest('9'),
        queue_ledger_head_sha256: digest('b'),
        planner_ledger_head_sha256: digest('c'),
        evidence_class_ids: vec!["authoritative-sla-runtime-state".to_owned()],
    })
}

fn milestone(
    case_id: &str,
    binding: &CaseSlaBindingV1,
    milestone_kind: SlaMilestoneV1,
    source: SlaMilestoneSourceV1,
    occurred_at: u64,
) -> Result<SlaMilestoneEventV1, String> {
    SlaMilestoneEventV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        event_id: format!("event-{case_id}-{milestone_kind:?}").to_ascii_lowercase(),
        case_id: case_id.to_owned(),
        sla_binding_sha256: binding.binding_sha256.clone(),
        milestone: milestone_kind,
        source,
        occurred_at_unix_seconds: occurred_at,
        source_artifact_sha256: digest('d'),
        source_ledger_head_sha256: digest('e'),
        evidence_ids: vec!["authoritative-ledger-event".to_owned()],
        event_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn build_registry(
    contract: &RoleContractV1,
    profile: &RoleOperationsProfileV1,
) -> Result<RoleRoutingRegistryV1, String> {
    let mut report_classes = contract
        .reporting_obligations
        .iter()
        .filter(|obligation| obligation.enabled)
        .map(|obligation| obligation.report_class_id.clone())
        .collect::<Vec<_>>();
    report_classes.sort();
    RoleRoutingRegistryV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        registry_id: "work700-internal-routes".to_owned(),
        registry_version: "1.0.0".to_owned(),
        organization_id: contract.organization_scope.organization_id.clone(),
        role_contract_sha256: contract.contract_sha256.clone(),
        allowed_routing_class_ids: profile.routing_class_allowlist.clone(),
        route_bindings: profile.internal_route_bindings.clone(),
        report_class_allowlist: report_classes,
        escalation_severity_allowlist: vec![
            RoleEscalationSeverityV1::Routine,
            RoleEscalationSeverityV1::Elevated,
            RoleEscalationSeverityV1::High,
            RoleEscalationSeverityV1::Unsafe,
        ],
        valid_from_unix_seconds: 1,
        valid_to_unix_seconds: 200_000,
        evidence_ids: vec!["organization-internal-routing-approval".to_owned()],
        registry_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn build_routed_escalation(
    trigger: &RoleEscalationTriggerV1,
    contract: &RoleContractV1,
    profile: &RoleOperationsProfileV1,
    routing: &ApprovedRoutingContext<'_>,
) -> Result<RoleEscalationItemV1, String> {
    validate_escalation_trigger(trigger, contract).map_err(|error| error.to_string())?;
    build_escalation_item(
        trigger,
        contract,
        profile,
        routing,
        digest('9'),
        digest('7'),
        digest('b'),
    )
    .map_err(|error| error.to_string())
}

fn build_reports(
    contract: &RoleContractV1,
    snapshot: &RoleOperationsSnapshotV1,
    breach: &SlaBreachRecordV1,
    escalation: &RoleEscalationItemV1,
) -> Result<Vec<RoleOperationsReportV1>, String> {
    let specifications = [
        (
            "report-office-work",
            ReportingTriggerKindV1::OnTaskComplete,
            Some("work700-case-a"),
            vec![digest('1')],
            vec!["verified-task-outcome".to_owned()],
        ),
        (
            "report-office-periodic",
            ReportingTriggerKindV1::Periodic,
            None,
            vec![snapshot.snapshot_sha256.clone()],
            vec!["operations-snapshot".to_owned()],
        ),
        (
            "report-office-sla-breach",
            ReportingTriggerKindV1::SlaBreach,
            Some("work700-case-c"),
            vec![breach.breach_sha256.clone()],
            vec!["sla-breach-record".to_owned()],
        ),
        (
            "report-office-escalation",
            ReportingTriggerKindV1::OnEscalation,
            Some("work700-case-d"),
            vec![escalation.item_sha256.clone()],
            vec!["operational-escalation-item".to_owned()],
        ),
    ];
    let mut reports = Vec::new();
    for (index, (obligation, kind, case_id, sources, evidence)) in
        specifications.into_iter().enumerate()
    {
        let trigger = ReportingTriggerEventV1 {
            schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
            trigger_id: format!("work700-report-trigger-{}", index + 1),
            trigger_kind: kind,
            role_contract_sha256: contract.contract_sha256.clone(),
            obligation_id: obligation.to_owned(),
            source_case_id: case_id.map(str::to_owned),
            source_artifact_hashes: sources,
            triggered_at_unix_seconds: 90_000,
            evidence_ids: evidence.clone(),
            trigger_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())?;
        let evaluation = evaluate_report_evidence(
            obligation.to_owned(),
            evidence.clone(),
            evidence,
            Vec::new(),
        )
        .map_err(|error| error.to_string())?;
        reports.push(
            build_role_report(
                contract,
                &trigger,
                snapshot,
                &evaluation,
                index as u64 + 1,
                vec![escalation.item_sha256.clone()],
                2,
            )
            .map_err(|error| error.to_string())?,
        );
    }
    Ok(reports)
}

fn publish_reports(
    reports: &[RoleOperationsReportV1],
    routing: &ApprovedRoutingContext<'_>,
) -> Result<
    (
        Vec<ReportPublicationEnvelopeV1>,
        Vec<ReportPublicationReceiptV1>,
    ),
    String,
> {
    let mut publications = Vec::new();
    let mut receipts = Vec::new();
    for (index, report) in reports.iter().enumerate() {
        let publication = build_report_publication(
            format!("work700-publication-{}", index + 1),
            report,
            routing,
        )
        .map_err(|error| error.to_string())?;
        let receipt = build_report_publication_receipt(
            &publication,
            digest('f'),
            index as u64 + 1,
            routing.trusted_now_unix_seconds,
        )
        .map_err(|error| error.to_string())?;
        publications.push(publication);
        receipts.push(receipt);
    }
    Ok((publications, receipts))
}

fn replay_hash() -> Result<String, String> {
    let case_hashes = (0..128)
        .map(|index| canonical_sha256(&format!("work700-replay-case-{index:03}")))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    let expected = canonical_sha256(&case_hashes).map_err(|error| error.to_string())?;
    for _ in 0..100 {
        let actual = canonical_sha256(&case_hashes).map_err(|error| error.to_string())?;
        if actual != expected {
            return Err("WORK-700 deterministic replay drifted".to_owned());
        }
    }
    Ok(expected)
}

fn read_hashed_json(path: &Path, hash_field: &str) -> Result<Value, String> {
    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    let value = parse_json_strict::<Value>(&bytes).map_err(|error| error.to_string())?;
    let declared = string_field(&value, hash_field)?;
    let calculated = hash_without(&value, &[hash_field]).map_err(|error| error.to_string())?;
    if declared != calculated {
        return Err(format!("{} canonical hash differs", path.display()));
    }
    Ok(value)
}

fn string_field(value: &Value, name: &str) -> Result<String, String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("field {name} is absent"))
}

fn require_bool(value: &Value, name: &str) -> Result<(), String> {
    if value.get(name).and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err(format!("WORK-600 field {name} is not true"))
    }
}

fn require_zero(value: &Value, name: &str) -> Result<(), String> {
    if value.get(name).and_then(Value::as_u64) == Some(0) {
        Ok(())
    } else {
        Err(format!("WORK-600 field {name} is not zero"))
    }
}

fn prepare_new_directory(path: &Path) -> Result<(), String> {
    if path.exists() {
        std::fs::remove_dir_all(path).map_err(|error| error.to_string())?;
    }
    std::fs::create_dir_all(path).map_err(|error| error.to_string())
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let bytes = canonical_json_bytes(value).map_err(|error| error.to_string())?;
    let parsed: Value = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let pretty = serde_json::to_vec_pretty(&parsed).map_err(|error| error.to_string())?;
    std::fs::write(path, pretty).map_err(|error| error.to_string())
}

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

#[allow(dead_code)]
fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
