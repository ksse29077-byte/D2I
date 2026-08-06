use d2i_role_contract::{KpiBreachBehaviorV1, KpiDirectionV1};
use serde::{Deserialize, Serialize};

/// Canonical SLA milestone understood by the v1 operations engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaMilestoneV1 {
    Received,
    Acknowledged,
    Begun,
    Resolved,
    Escalated,
}

/// Authoritative source selected by an operations profile for a milestone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaMilestoneSourceV1 {
    WorkItemReceived,
    FirstExclusiveLeaseClaim,
    ExplicitCaseAcknowledgement,
    FirstAcceptedCaseTask,
    FirstPlannerStepAdmitted,
    FirstKernelBinding,
    TerminalCaseTimestamp,
    DurableEscalationItem,
}

/// Per-milestone runtime status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaMilestoneStatusV1 {
    Pending,
    Paused,
    MetOnTime,
    MetLate,
    BreachedUnmet,
    NotApplicable,
}

/// Overall SLA status for one Case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverallSlaStatusV1 {
    Pending,
    AtRisk,
    Paused,
    Compliant,
    Breached,
    TerminalNoncompliant,
    InsufficientEvidence,
}

/// Integer-only urgency band derived from an effective deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaRiskBandV1 {
    Healthy,
    Warning,
    Critical,
    Breached,
}

/// Closed formulas available to profile-owned metric identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KpiFormulaKindV1 {
    AdmittedCaseCount,
    TerminalCaseCount,
    VerifiedCompleteCount,
    ExplicitRefusalCount,
    EscalatedCaseCount,
    AutonomousCaseCompletionRate,
    VerifiedClosureRate,
    SlaComplianceRate,
    EscalationRate,
    ClarificationRate,
    RecoverySuccessRate,
    HumanTouchesPerCase,
    HumanMinutesPerCase,
    AverageTimeToAcknowledge,
    AverageTimeToBegin,
    AverageTimeToResolve,
    FalseCompletionRate,
    UnsupportedCaseRate,
}

/// Evidence coverage status for a metric population.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricCoverageStatusV1 {
    Complete,
    Partial,
    Insufficient,
    Conflicting,
    NotApplicable,
}

/// Result of evaluating one declared KPI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleMetricResultStatusV1 {
    Met,
    Warning,
    Breached,
    InsufficientEvidence,
    ConflictingEvidence,
    Unsupported,
    NotApplicable,
}

/// Caller-supplied measurement window state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementWindowStatusV1 {
    Open,
    Closed,
}

/// Exact report trigger supported by Role Contract v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportingTriggerKindV1 {
    OnTaskComplete,
    OnTaskFailed,
    OnEscalation,
    OnRoleSuspend,
    Periodic,
    SlaBreach,
}

/// Completeness status for report evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportEvidenceStatusV1 {
    Complete,
    Incomplete,
    Conflicting,
    Unsupported,
}

/// Internal-only publication result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportPublicationStatusV1 {
    PublishedToInternalRoute,
    Duplicate,
    Rejected,
    RouteUnavailable,
    EvidenceIncomplete,
}

/// Source class for an operational escalation trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationTriggerSourceKindV1 {
    CaseMandatoryEscalation,
    RecoveryEscalation,
    AuthorityExceeded,
    PolicyUnknown,
    UnsafeVerification,
    LegalApproval,
    HighCriticality,
    SensitiveInput,
    SlaBreach,
    KpiBreach,
    ReportPublicationFailure,
    RoleSuspendedOrRevoked,
    EscalationPendingTimeout,
}

/// Distinguishes attention from a mandatory human exception handoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationKindV1 {
    OperationalAttention,
    HumanExceptionHandoff,
}

/// Closed operational escalation severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleEscalationSeverityV1 {
    Routine,
    Elevated,
    High,
    Unsafe,
}

/// Describes authority impact without creating authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationAuthorityImpactV1 {
    None,
    OperationalAttention,
    RequiresAuthorizedHuman,
}

/// Durable escalation lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationItemStatusV1 {
    Pending,
    Routed,
    Acknowledged,
    Resolved,
    Overdue,
    Rejected,
    RouteUnavailable,
    Superseded,
}

/// Authenticated acknowledgement kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationAcknowledgementKindV1 {
    AcceptedForReview,
    ClarificationRequested,
    TransferredToAuthorizedHumanProcess,
    DuplicateConfirmed,
}

/// Bounded resolution disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationResolutionDispositionV1 {
    HandledExternally,
    NoActionRequired,
    FollowUpWorkCreated,
    ExplicitRefusalConfirmed,
    EscalationAccepted,
    Superseded,
}

/// Exact fixed-window interpretation of a Role-owned frequency string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementWindowProfileV1 {
    pub measurement_window_profile_id: String,
    pub role_measurement_window_id: String,
    pub maximum_window_seconds: u64,
}

/// Exact internal routing target. It never contains a person or endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InternalRouteBindingV1 {
    pub routing_class_id: String,
    pub internal_inbox_id: String,
}

/// Runtime interpretation that can only narrow one immutable Role Contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleOperationsProfileV1 {
    pub schema_version: u32,
    pub profile_id: String,
    pub profile_version: String,
    pub organization_id: String,
    pub role_contract_id: String,
    pub role_contract_version: String,
    pub role_contract_sha256: String,
    pub role_instance_scope: Vec<String>,
    pub delegation_sha256: String,
    pub policy_set_sha256: String,
    pub working_calendar_sha256: String,
    pub kpi_metric_bindings: Vec<KpiMetricBindingV1>,
    pub measurement_window_profiles: Vec<MeasurementWindowProfileV1>,
    pub sla_milestone_mapping: SlaMilestoneMappingV1,
    pub sla_pause_condition_bindings: Vec<SlaPauseConditionBindingV1>,
    pub report_frequency_profile_ids: Vec<String>,
    pub routing_class_allowlist: Vec<String>,
    pub internal_route_bindings: Vec<InternalRouteBindingV1>,
    pub warning_remaining_millionths: u32,
    pub critical_remaining_seconds: u64,
    pub maximum_cases_per_cycle: u32,
    pub maximum_reports_per_cycle: u32,
    pub maximum_escalations_per_cycle: u32,
    pub maximum_report_bytes: u64,
    pub maximum_store_bytes: u64,
    pub maximum_pending_escalation_seconds: u64,
    pub maximum_resolution_seconds: u64,
    pub logical_operation_budget: u64,
    pub evidence_ids: Vec<String>,
    pub profile_sha256: String,
}

/// Signed organizational approval for one exact operations profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleOperationsProfileApprovalV1 {
    pub schema_version: u32,
    pub profile_sha256: String,
    pub organization_id: String,
    pub role_contract_sha256: String,
    pub signer_id: String,
    pub signing_key_id: String,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub nonce: String,
    pub evidence_ids: Vec<String>,
    pub approval_sha256: String,
    pub signature_hex: String,
}

/// Trusted caller time projection. Core never reads an OS clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedRoleOperationsTimeContextV1 {
    pub schema_version: u32,
    pub context_id: String,
    pub trusted_now_unix_seconds: u64,
    pub timezone_id: String,
    pub timezone_projection_sha256: String,
    pub operational_date_id: String,
    pub window_start_unix_seconds: u64,
    pub window_end_unix_seconds: u64,
    pub tick_sequence: u64,
    pub prior_tick_sha256: Option<String>,
    pub caller_trust_class: String,
    pub evidence_ids: Vec<String>,
    pub context_sha256: String,
}

/// Fixed measurement interval supplied by a trusted caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleMeasurementWindowV1 {
    pub schema_version: u32,
    pub window_id: String,
    pub measurement_window_profile_id: String,
    pub organization_id: String,
    pub role_contract_sha256: String,
    pub start_unix_seconds: u64,
    pub end_unix_seconds: u64,
    pub timezone_projection_sha256: String,
    pub status: MeasurementWindowStatusV1,
    pub source_tick_sha256: String,
    pub previous_window_sha256: Option<String>,
    pub window_sha256: String,
}

/// Exact milestone source mapping selected before a cycle starts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlaMilestoneMappingV1 {
    pub schema_version: u32,
    pub received_source: SlaMilestoneSourceV1,
    pub acknowledged_source: SlaMilestoneSourceV1,
    pub begun_source: SlaMilestoneSourceV1,
    pub resolved_source: SlaMilestoneSourceV1,
    pub escalated_source: SlaMilestoneSourceV1,
    pub mapping_sha256: String,
}

/// Hash-bound authoritative occurrence of one SLA milestone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlaMilestoneEventV1 {
    pub schema_version: u32,
    pub event_id: String,
    pub case_id: String,
    pub sla_binding_sha256: String,
    pub milestone: SlaMilestoneV1,
    pub source: SlaMilestoneSourceV1,
    pub occurred_at_unix_seconds: u64,
    pub source_artifact_sha256: String,
    pub source_ledger_head_sha256: String,
    pub evidence_ids: Vec<String>,
    pub event_sha256: String,
}

/// Role-declared authorization boundary for an SLA pause.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlaPauseConditionBindingV1 {
    pub schema_version: u32,
    pub pause_condition_id: String,
    pub allowed_source_event_classes: Vec<String>,
    pub allowed_case_block_classes: Vec<String>,
    pub allowed_clarification_reason_codes: Vec<String>,
    pub required_evidence_class_ids: Vec<String>,
    pub maximum_single_pause_seconds: u64,
    pub maximum_cumulative_pause_seconds: u64,
    pub automatic_pause_allowed: bool,
    pub approval_required: bool,
    pub binding_sha256: String,
}

/// Closed, evidence-backed SLA pause interval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlaPauseIntervalV1 {
    pub schema_version: u32,
    pub pause_id: String,
    pub case_id: String,
    pub sla_binding_sha256: String,
    pub pause_condition_id: String,
    pub source_event_class_id: String,
    pub case_block_class_id: Option<String>,
    pub clarification_reason_code: Option<String>,
    pub started_at_unix_seconds: u64,
    pub ended_at_unix_seconds: Option<u64>,
    pub source_case_state_sha256: String,
    pub source_block_or_clarification_sha256: String,
    pub approval_sha256: Option<String>,
    pub evidence_ids: Vec<String>,
    pub previous_pause_sha256: Option<String>,
    pub pause_sha256: String,
}

/// Additive runtime SLA projection; it never mutates the Case binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseSlaRuntimeStateV1 {
    pub schema_version: u32,
    pub sla_state_id: String,
    pub case_id: String,
    pub case_contract_sha256: String,
    pub current_case_instance_sha256: String,
    pub role_contract_sha256: String,
    pub sla_binding_sha256: String,
    pub sla_profile_id: String,
    pub priority_class: String,
    pub received_at_unix_seconds: u64,
    pub baseline_acknowledge_due_at_unix_seconds: u64,
    pub baseline_begin_due_at_unix_seconds: u64,
    pub baseline_resolve_due_at_unix_seconds: u64,
    pub baseline_escalation_due_at_unix_seconds: u64,
    pub acknowledged_at_unix_seconds: Option<u64>,
    pub begun_at_unix_seconds: Option<u64>,
    pub resolved_at_unix_seconds: Option<u64>,
    pub escalated_at_unix_seconds: Option<u64>,
    pub approved_pause_intervals: Vec<SlaPauseIntervalV1>,
    pub total_approved_pause_seconds: u64,
    pub effective_acknowledge_due_at_unix_seconds: u64,
    pub effective_begin_due_at_unix_seconds: u64,
    pub effective_resolve_due_at_unix_seconds: u64,
    pub effective_escalation_due_at_unix_seconds: u64,
    pub acknowledge_status: SlaMilestoneStatusV1,
    pub begin_status: SlaMilestoneStatusV1,
    pub resolve_status: SlaMilestoneStatusV1,
    pub escalation_status: SlaMilestoneStatusV1,
    pub overall_sla_status: OverallSlaStatusV1,
    pub risk_band: SlaRiskBandV1,
    pub current_clock_context_sha256: String,
    pub case_ledger_head_sha256: String,
    pub queue_ledger_head_sha256: String,
    pub planner_ledger_head_sha256: String,
    pub evidence_ids: Vec<String>,
    pub previous_state_sha256: Option<String>,
    pub state_sha256: String,
}

/// Exactly-once record for one breached Case milestone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlaBreachRecordV1 {
    pub schema_version: u32,
    pub breach_id: String,
    pub case_id: String,
    pub sla_state_sha256: String,
    pub sla_binding_sha256: String,
    pub milestone: SlaMilestoneV1,
    pub baseline_deadline_unix_seconds: u64,
    pub effective_deadline_unix_seconds: u64,
    pub detected_at_unix_seconds: u64,
    pub actual_milestone_at_unix_seconds: Option<u64>,
    pub breach_duration_seconds: u64,
    pub severity: RoleEscalationSeverityV1,
    pub reason_codes: Vec<String>,
    pub mandatory_escalation: bool,
    pub source_ledger_heads: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub breach_sha256: String,
}

/// Exact Role metric ID to closed-formula binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KpiMetricBindingV1 {
    pub schema_version: u32,
    pub kpi_id: String,
    pub metric_id: String,
    pub formula_kind: KpiFormulaKindV1,
    pub unit: String,
    pub direction: KpiDirectionV1,
    pub target_millionths: Option<i64>,
    pub target_integer: Option<i64>,
    pub warning_threshold: Option<i64>,
    pub breach_behavior: KpiBreachBehaviorV1,
    pub required_evidence_class_ids: Vec<String>,
    pub binding_sha256: String,
}

/// Coverage proof for one metric population.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricEvidenceCoverageV1 {
    pub schema_version: u32,
    pub metric_binding_sha256: String,
    pub measurement_window_sha256: String,
    pub expected_population_count: u64,
    pub observed_population_count: u64,
    pub covered_population_count: u64,
    pub missing_evidence_count: u64,
    pub conflicting_evidence_count: u64,
    pub coverage_millionths: Option<u32>,
    pub evidence_class_ids: Vec<String>,
    pub status: MetricCoverageStatusV1,
    pub coverage_sha256: String,
}

/// Authoritative review used only for false-completion measurement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FalseCompletionReviewRecordV1 {
    pub schema_version: u32,
    pub original_terminal_case_sha256: String,
    pub original_terminal_episode_sha256: String,
    pub review_covered: bool,
    pub authoritative_correction_or_incident_sha256: Option<String>,
    pub reviewer_trust_class: String,
    pub false_completion: Option<bool>,
    pub evidence_ids: Vec<String>,
    pub record_sha256: String,
}

/// Authenticated human interaction. Actor classes are opaque and non-personal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanInteractionEventV1 {
    pub schema_version: u32,
    pub interaction_id: String,
    pub case_id: String,
    pub interaction_kind: String,
    pub authenticated_actor_class: String,
    pub started_at_unix_seconds: u64,
    pub ended_at_unix_seconds: Option<u64>,
    pub source_artifact_sha256: String,
    pub evidence_ids: Vec<String>,
    pub interaction_sha256: String,
}

/// Evidence-backed result for one Role KPI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleMetricResultV1 {
    pub schema_version: u32,
    pub kpi_id: String,
    pub metric_id: String,
    pub metric_binding_sha256: String,
    pub measurement_window_sha256: String,
    pub formula_kind: KpiFormulaKindV1,
    pub numerator: Option<i64>,
    pub denominator: Option<i64>,
    pub integer_value: Option<i64>,
    pub millionths_value: Option<i64>,
    pub unit: String,
    pub direction: KpiDirectionV1,
    pub target_millionths: Option<i64>,
    pub target_integer: Option<i64>,
    pub warning_threshold: Option<i64>,
    pub result_status: RoleMetricResultStatusV1,
    pub evidence_coverage_sha256: String,
    pub evidence_ids: Vec<String>,
    pub result_sha256: String,
}

/// Non-authoritative evidence snapshot for Role reporting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleOperationsSnapshotV1 {
    pub schema_version: u32,
    pub snapshot_id: String,
    pub organization_id: String,
    pub role_contract_id: String,
    pub role_contract_version: String,
    pub role_contract_sha256: String,
    pub role_instance_ids: Vec<String>,
    pub measurement_window_sha256: String,
    pub operations_profile_sha256: String,
    pub total_cases: u32,
    pub active_cases: u32,
    pub blocked_cases: u32,
    pub awaiting_clarification_cases: u32,
    pub awaiting_verification_cases: u32,
    pub escalation_pending_cases: u32,
    pub terminal_cases: u32,
    pub verified_complete_cases: u32,
    pub explicit_refusal_cases: u32,
    pub escalated_cases: u32,
    pub sla_compliant_cases: u32,
    pub sla_at_risk_cases: u32,
    pub sla_paused_cases: u32,
    pub sla_breached_cases: u32,
    pub open_escalation_count: u32,
    pub acknowledged_escalation_count: u32,
    pub overdue_escalation_count: u32,
    pub metric_result_hashes: Vec<String>,
    pub case_sla_state_hashes: Vec<String>,
    pub breach_hashes: Vec<String>,
    pub terminal_episode_hashes: Vec<String>,
    pub role_ledger_head_sha256: String,
    pub case_ledger_head_sha256: String,
    pub queue_ledger_head_sha256: String,
    pub planner_ledger_head_sha256: String,
    pub memory_store_head_sha256: String,
    pub audit_ledger_head_sha256: String,
    pub evidence_ids: Vec<String>,
    pub snapshot_sha256: String,
}

/// Exact event that activates one declared reporting obligation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportingTriggerEventV1 {
    pub schema_version: u32,
    pub trigger_id: String,
    pub trigger_kind: ReportingTriggerKindV1,
    pub role_contract_sha256: String,
    pub obligation_id: String,
    pub source_case_id: Option<String>,
    pub source_artifact_hashes: Vec<String>,
    pub triggered_at_unix_seconds: u64,
    pub evidence_ids: Vec<String>,
    pub trigger_sha256: String,
}

/// Exact evidence completeness evaluation for a report obligation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportEvidenceEvaluationV1 {
    pub schema_version: u32,
    pub obligation_id: String,
    pub required_evidence_class_ids: Vec<String>,
    pub present_evidence_class_ids: Vec<String>,
    pub missing_evidence_class_ids: Vec<String>,
    pub conflicting_evidence_ids: Vec<String>,
    pub status: ReportEvidenceStatusV1,
    pub evaluation_sha256: String,
}

/// Aggregate report counts without raw Case content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleReportSummaryCountsV1 {
    pub total_cases: u32,
    pub verified_complete_cases: u32,
    pub explicit_refusal_cases: u32,
    pub escalated_cases: u32,
    pub sla_compliant_cases: u32,
    pub sla_breached_cases: u32,
    pub human_interaction_count: u32,
}

/// Authoritative structured Role report. It contains hashes, IDs, and counts only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleOperationsReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub report_generation: u64,
    pub organization_id: String,
    pub role_contract_id: String,
    pub role_contract_version: String,
    pub role_contract_sha256: String,
    pub report_class_id: String,
    pub reporting_obligation_id: String,
    pub trigger_sha256: String,
    pub measurement_window_sha256: Option<String>,
    pub role_operations_snapshot_sha256: String,
    pub included_metric_result_hashes: Vec<String>,
    pub included_sla_state_hashes: Vec<String>,
    pub included_breach_hashes: Vec<String>,
    pub included_escalation_hashes: Vec<String>,
    pub included_episode_hashes: Vec<String>,
    pub summary_counts: RoleReportSummaryCountsV1,
    pub data_class_ids: Vec<String>,
    pub redaction_proof_ids: Vec<String>,
    pub retention_class_id: String,
    pub routing_class_id: String,
    pub evidence_completeness_status: ReportEvidenceStatusV1,
    pub evidence_ids: Vec<String>,
    pub report_sha256: String,
}

/// Approved internal routing registry. It contains no external endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleRoutingRegistryV1 {
    pub schema_version: u32,
    pub registry_id: String,
    pub registry_version: String,
    pub organization_id: String,
    pub role_contract_sha256: String,
    pub allowed_routing_class_ids: Vec<String>,
    pub route_bindings: Vec<InternalRouteBindingV1>,
    pub report_class_allowlist: Vec<String>,
    pub escalation_severity_allowlist: Vec<RoleEscalationSeverityV1>,
    pub valid_from_unix_seconds: u64,
    pub valid_to_unix_seconds: u64,
    pub evidence_ids: Vec<String>,
    pub registry_sha256: String,
}

/// Signature approval for one exact internal routing registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleRoutingRegistryApprovalV1 {
    pub schema_version: u32,
    pub registry_sha256: String,
    pub organization_id: String,
    pub role_contract_sha256: String,
    pub signer_id: String,
    pub signing_key_id: String,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub nonce: String,
    pub evidence_ids: Vec<String>,
    pub approval_sha256: String,
    pub signature_hex: String,
}

/// Intent to publish one complete report to a protected internal route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportPublicationEnvelopeV1 {
    pub schema_version: u32,
    pub publication_id: String,
    pub report_sha256: String,
    pub reporting_obligation_id: String,
    pub report_class_id: String,
    pub routing_class_id: String,
    pub internal_inbox_id: String,
    pub registry_sha256: String,
    pub published_at_unix_seconds: u64,
    pub retention_class_id: String,
    pub evidence_ids: Vec<String>,
    pub publication_sha256: String,
}

/// Durable internal publication receipt; it is not an external delivery receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportPublicationReceiptV1 {
    pub schema_version: u32,
    pub publication_sha256: String,
    pub internal_inbox_ledger_head_sha256: String,
    pub durable_object_sha256: String,
    pub publication_sequence: u64,
    pub status: ReportPublicationStatusV1,
    pub recorded_at_unix_seconds: u64,
    pub receipt_sha256: String,
}

/// Hash-only operational trigger derived from an existing authoritative source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleEscalationTriggerV1 {
    pub schema_version: u32,
    pub trigger_id: String,
    pub organization_id: String,
    pub role_contract_sha256: String,
    pub case_id: Option<String>,
    pub trigger_source_kind: EscalationTriggerSourceKindV1,
    pub source_artifact_sha256: String,
    pub reason_codes: Vec<String>,
    pub safety_severity: RoleEscalationSeverityV1,
    pub authority_impact: EscalationAuthorityImpactV1,
    pub sla_breach_sha256: Option<String>,
    pub kpi_breach_sha256: Option<String>,
    pub case_escalation_request_sha256: Option<String>,
    pub detected_at_unix_seconds: u64,
    pub evidence_ids: Vec<String>,
    pub trigger_sha256: String,
}

/// Exactly-once internal escalation inbox item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleEscalationItemV1 {
    pub schema_version: u32,
    pub escalation_item_id: String,
    pub organization_id: String,
    pub role_contract_sha256: String,
    pub case_id: Option<String>,
    pub escalation_kind: EscalationKindV1,
    pub source_trigger_sha256: String,
    pub reason_codes: Vec<String>,
    pub severity: RoleEscalationSeverityV1,
    pub routing_class_id: Option<String>,
    pub internal_inbox_id: Option<String>,
    pub created_at_unix_seconds: u64,
    pub acknowledge_due_at_unix_seconds: u64,
    pub resolution_due_at_unix_seconds: u64,
    pub status: EscalationItemStatusV1,
    pub source_case_ledger_head_sha256: String,
    pub source_role_ledger_head_sha256: String,
    pub source_queue_ledger_head_sha256: String,
    pub evidence_ids: Vec<String>,
    pub previous_escalation_sha256: Option<String>,
    pub item_sha256: String,
}

/// Signed acknowledgement that grants no execution or Case authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscalationAcknowledgementV1 {
    pub schema_version: u32,
    pub acknowledgement_id: String,
    pub escalation_item_sha256: String,
    pub authenticated_actor_class_id: String,
    pub acknowledged_at_unix_seconds: u64,
    pub acknowledgement_kind: EscalationAcknowledgementKindV1,
    pub evidence_ids: Vec<String>,
    pub signer_key_id: String,
    pub acknowledgement_sha256: String,
    pub signature_hex: String,
}

/// Signed resolution record that cannot reopen a Case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscalationResolutionV1 {
    pub schema_version: u32,
    pub resolution_id: String,
    pub escalation_item_sha256: String,
    pub latest_acknowledgement_sha256: String,
    pub resolution_disposition: EscalationResolutionDispositionV1,
    pub resolved_at_unix_seconds: u64,
    pub follow_up_work_item_reference: Option<String>,
    pub external_handling_reference_sha256: Option<String>,
    pub evidence_ids: Vec<String>,
    pub signer_key_id: String,
    pub resolution_sha256: String,
    pub signature_hex: String,
}

/// Hash-bound one-shot operations cycle request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleOperationsCycleRequestV1 {
    pub schema_version: u32,
    pub cycle_id: String,
    pub organization_id: String,
    pub role_contract_sha256: String,
    pub role_instance_ids: Vec<String>,
    pub operations_profile_sha256: String,
    pub time_context: TrustedRoleOperationsTimeContextV1,
    pub measurement_window_sha256: String,
    pub role_ledger_head_sha256: String,
    pub intake_ledger_head_sha256: String,
    pub case_ledger_head_sha256: String,
    pub queue_ledger_head_sha256: String,
    pub planner_ledger_head_hashes: Vec<String>,
    pub memory_store_head_sha256: String,
    pub audit_ledger_head_sha256: String,
    pub maximum_cases: u32,
    pub maximum_reports: u32,
    pub maximum_escalations: u32,
    pub logical_operation_budget: u64,
    pub evidence_ids: Vec<String>,
    pub request_sha256: String,
}

/// Deterministic hash-only result of one operations cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleOperationsCycleResultV1 {
    pub schema_version: u32,
    pub request_sha256: String,
    pub processed_cases: u32,
    pub sla_state_hashes: Vec<String>,
    pub new_breach_hashes: Vec<String>,
    pub duplicate_breaches: u32,
    pub metric_result_hashes: Vec<String>,
    pub report_trigger_hashes: Vec<String>,
    pub generated_report_hashes: Vec<String>,
    pub published_report_hashes: Vec<String>,
    pub generated_escalation_hashes: Vec<String>,
    pub routed_escalation_hashes: Vec<String>,
    pub overdue_escalations: u32,
    pub rejected_artifacts: u32,
    pub logical_operations: u64,
    pub output_hashes: Vec<String>,
    pub cycle_sha256: String,
}

/// Reproducible large-cycle replay evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleOperationsReplayReportV1 {
    pub schema_version: u32,
    pub total_cases: u32,
    pub active_cases: u32,
    pub terminal_cases: u32,
    pub compliant_cases: u32,
    pub at_risk_cases: u32,
    pub paused_cases: u32,
    pub breached_cases: u32,
    pub verified_complete_cases: u32,
    pub explicit_refusal_cases: u32,
    pub escalated_cases: u32,
    pub reports_generated: u32,
    pub reports_published: u32,
    pub escalations_generated: u32,
    pub acknowledged_escalations: u32,
    pub resolved_escalations: u32,
    pub evidence_incomplete_metrics: u32,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub peak_records: u32,
    pub logical_operations: u64,
    pub critical_error_count: u32,
    pub sla_state_set_sha256: String,
    pub role_snapshot_sha256: String,
    pub metric_set_sha256: String,
    pub report_set_sha256: String,
    pub escalation_set_sha256: String,
    pub normalized_replay_sha256: String,
}

/// Authoritative, bounded Case projection consumed by a one-shot cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseOperationsEvidenceV1 {
    pub case_id: String,
    pub case_contract_sha256: String,
    pub current_case_instance_sha256: String,
    pub role_contract_sha256: String,
    pub role_instance_id: String,
    pub sla_binding: d2i_work_case::CaseSlaBindingV1,
    pub milestone_events: Vec<SlaMilestoneEventV1>,
    pub pause_intervals: Vec<SlaPauseIntervalV1>,
    pub terminal_outcome: Option<String>,
    pub blocked: bool,
    pub awaiting_clarification: bool,
    pub awaiting_verification: bool,
    pub escalation_pending: bool,
    pub verified_complete: bool,
    pub explicit_refusal: bool,
    pub escalated: bool,
    pub autonomous_completion: bool,
    pub clarification_count: u32,
    pub recovery_attempt_count: u32,
    pub recovery_success_count: u32,
    pub unsupported: bool,
    pub terminal_episode_sha256: Option<String>,
    pub case_ledger_head_sha256: String,
    pub queue_ledger_head_sha256: String,
    pub planner_ledger_head_sha256: String,
    pub evidence_class_ids: Vec<String>,
}

/// Complete population inputs used by generic KPI formulas.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleMetricPopulationV1 {
    pub admitted_cases: u64,
    pub terminal_cases: u64,
    pub verified_complete_cases: u64,
    pub explicit_refusal_cases: u64,
    pub escalated_cases: u64,
    pub autonomous_completed_cases: u64,
    pub sla_applicable_cases: u64,
    pub sla_compliant_cases: u64,
    pub clarified_cases: u64,
    pub recovery_attempts: u64,
    pub recovery_successes: u64,
    pub unsupported_cases: u64,
    pub acknowledge_seconds_total: u64,
    pub acknowledge_duration_count: u64,
    pub begin_seconds_total: u64,
    pub begin_duration_count: u64,
    pub resolve_seconds_total: u64,
    pub resolve_duration_count: u64,
    pub human_interaction_count: u64,
    pub human_interaction_seconds: u64,
    pub human_duration_covered_count: u64,
    pub false_completion_review_population: u64,
    pub false_completion_review_covered: u64,
    pub false_completion_count: u64,
    pub missing_evidence_count: u64,
    pub conflicting_evidence_count: u64,
}
