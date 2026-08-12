use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureClassV1 {
    Public,
    Internal,
    Confidential,
    Restricted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureDecisionCodeV1 {
    Allowed,
    Declassified,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryProviderKindV1 {
    SeedUrlSet,
    ConfiguredSearchPortal,
    EnterpriseSearchAdapter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchHttpMethodV1 {
    Get,
    Head,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchProxyModeV1 {
    Direct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UrlAdmissionResultV1 {
    Admitted,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FetchResultCodeV1 {
    Success,
    AuthenticationRequired,
    Rejected,
    Timeout,
    NetworkError,
    ResourceLimit,
    TlsError,
    DnsRebindOrRouteMismatch,
    RedirectRejected,
    UnsupportedEncoding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourcePolicyClassV1 {
    Preferred,
    Allowed,
    Blocked,
    UnclassifiedExternal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchSegmentRoleV1 {
    Title,
    Heading,
    Paragraph,
    ListItem,
    TableCell,
    LinkLabel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchLinkRelationV1 {
    Navigation,
    Download,
    Reference,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceTrustClassV1 {
    UntrustedExternalResearch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchClaimKindV1 {
    DirectEvidence,
    DeterministicDerived,
    ModelInference,
    Conflicting,
    Unresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchSufficiencyStatusV1 {
    Sufficient,
    InsufficientEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlledDownloadSourceKindV1 {
    ObservedResearchLink,
    OrganizationApprovedArtifact,
    SignedOperatorInput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DownloadClassV1 {
    Pdf,
    Docx,
    Hwpx,
    Xlsx,
    Pptx,
    Txt,
    Csv,
    Png,
    Jpeg,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentTrustDecisionV1 {
    Enable,
    Prompt,
    Disable,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentPolicyDecisionV1 {
    Enable,
    Prompt,
    Disable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentPolicyScopeV1 {
    User,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentPolicyQualificationStatusV1 {
    Qualified,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DownloadValidationStatusV1 {
    Passed,
    Rejected,
    HumanException,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DownloadPromotionStatusV1 {
    Promoted,
    Rejected,
    AlreadyPromoted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchRecoveryStageV1 {
    BeforeAdmission,
    UrlAdmitted,
    RequestSent,
    HeadersReceived,
    PartialBody,
    BodyDurable,
    SnapshotDurable,
    EvidenceDurable,
    DownloadDurable,
    AttachmentTrustInProgress,
    TrustPassed,
    ValidationPassed,
    WorkspacePromoted,
    ReportDurable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchRecoveryActionV1 {
    StartFresh,
    ResumeAdmission,
    ReevaluateRequestState,
    DiscardPartialBody,
    RecoverDurableBody,
    ResumeSnapshot,
    ResumeEvidence,
    ResumeSynthesis,
    ResumeTrustCheck,
    ReobserveAttachment,
    ResumeValidation,
    ResumePromotion,
    RepairPromotionReceipt,
    RepairClosureMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchSemanticOperationV1 {
    StartResearch,
    DiscoverSources,
    FetchSource,
    ObserveSnapshot,
    SelectLink,
    ExtractEvidence,
    EvaluateSufficiency,
    DownloadArtifact,
    ValidateDownload,
    PromoteDownload,
    FinalizeResearch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchNetworkWorkerOperationV1 {
    AdmitUrl,
    FetchPage,
    DownloadArtifact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchExperienceCaseKindV1 {
    SeedUrlResearch,
    TwoHopLinkFollow,
    ThreeSourceEvidenceBundle,
    StaleRefresh,
    SameBodyDedup,
    ConflictingSources,
    InsufficientEvidence,
    ModelFreeResearch,
    ModelAssistedSynthesis,
    LocalSnapshotBrowserObservation,
    ControlledTxtDownload,
    ControlledPdfDownload,
    OfficeFormatValidation,
    WorkspacePromotion,
    SsrfRejection,
    UrlAttackRejection,
    RedirectAttackRejection,
    HttpBoundRejection,
    PromptInjectionRejection,
    QueryLeakageRejection,
    MaliciousDownloadRejection,
    FilenameAttackRejection,
    MimeMagicRejection,
    BrowserModelEgressRejection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchExperienceOutcomeV1 {
    RoutineComplete,
    NegativeRejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchBriefV1 {
    pub schema_version: u32,
    pub brief_id: String,
    pub case_id: String,
    pub organization_id: String,
    pub research_question: String,
    pub research_scope: String,
    pub freshness_requirement_seconds: u64,
    pub minimum_source_count: u32,
    pub preferred_source_policy_ids: Vec<String>,
    pub excluded_source_policy_ids: Vec<String>,
    pub allowed_disclosure_class: DisclosureClassV1,
    pub download_allowed: bool,
    pub brief_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchDisclosurePolicyV1 {
    pub schema_version: u32,
    pub policy_id: String,
    pub organization_id: String,
    pub maximum_external_class: DisclosureClassV1,
    pub approved_declassification_rule_ids: Vec<String>,
    pub blocked_term_hashes: Vec<String>,
    pub policy_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchDisclosureDecisionV1 {
    pub schema_version: u32,
    pub decision_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub policy_sha256: String,
    pub input_class: DisclosureClassV1,
    pub output_class: DisclosureClassV1,
    pub applied_declassification_rule_id: Option<String>,
    pub result: DisclosureDecisionCodeV1,
    pub reason_code: String,
    pub query_sha256: String,
    pub decision_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchNetworkProfileV1 {
    pub schema_version: u32,
    pub profile_id: String,
    pub allowed_schemes: Vec<String>,
    pub allowed_ports: Vec<u16>,
    pub max_redirects: u32,
    pub max_request_bytes: u64,
    pub max_response_headers: u64,
    pub max_response_bytes: u64,
    pub max_total_bytes: u64,
    pub connect_timeout_milliseconds: u64,
    pub receive_timeout_milliseconds: u64,
    pub origin_budget: u32,
    pub request_budget: u32,
    pub max_pages: u32,
    pub max_links_per_page: u32,
    pub max_extracted_text_bytes: u64,
    pub max_evidence_excerpts: u32,
    pub max_model_evidence_bytes: u64,
    pub max_link_depth: u32,
    pub proxy_mode: ResearchProxyModeV1,
    pub network_profile_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchDiscoveryProviderDescriptorV1 {
    pub schema_version: u32,
    pub provider_id: String,
    pub organization_id: String,
    pub provider_kind: DiscoveryProviderKindV1,
    pub profile_sha256: String,
    pub evidence_only_after_fetch: bool,
    pub descriptor_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchPortalProfileV1 {
    pub schema_version: u32,
    pub profile_id: String,
    pub organization_id: String,
    pub endpoint_protected_ref: String,
    pub fixed_query_parameter_names: Vec<String>,
    pub result_limit: u32,
    pub profile_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchQueryV1 {
    pub schema_version: u32,
    pub query_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub brief_sha256: String,
    pub disclosure_decision_sha256: String,
    pub query_text: String,
    pub query_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchDiscoveryResultV1 {
    pub schema_version: u32,
    pub result_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub provider_descriptor_sha256: String,
    pub source_candidate_ids: Vec<String>,
    pub source_candidate_protected_refs: Vec<String>,
    pub snippet_hashes: Vec<String>,
    pub evidence_eligible: bool,
    pub result_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchUrlAdmissionRequestV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub source_candidate_id: String,
    pub url_protected_ref: String,
    pub source_policy_sha256: String,
    pub network_profile_sha256: String,
    pub request_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchUrlAdmissionDecisionV1 {
    pub schema_version: u32,
    pub decision_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub request_sha256: String,
    pub canonical_url_protected_ref: String,
    pub origin_id: String,
    pub scheme: String,
    pub port: u16,
    pub resolved_address_hashes: Vec<String>,
    pub result: UrlAdmissionResultV1,
    pub reason_code: String,
    pub decision_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchFetchRequestV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub role_id: String,
    pub work_grant_sha256: String,
    pub research_brief_sha256: String,
    pub source_candidate_id: String,
    pub url_admission_decision_sha256: String,
    pub network_profile_sha256: String,
    pub worker_executable_sha256: String,
    pub method: ResearchHttpMethodV1,
    pub deadline_unix_ms: u64,
    pub request_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchHttpMetadataV1 {
    pub status_code: u16,
    pub content_type: String,
    pub declared_content_length: Option<u64>,
    pub total_header_bytes: u64,
    pub content_encoding: String,
    pub certificate_thumbprint_sha256: String,
    pub remote_address_sha256: String,
    pub metadata_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchFetchReceiptV1 {
    pub schema_version: u32,
    pub receipt_id: String,
    pub request_sha256: String,
    pub http_metadata: ResearchHttpMetadataV1,
    pub bytes_received: u64,
    pub body_sha256: String,
    pub redirect_chain_sha256: Vec<String>,
    pub elapsed_microseconds: u64,
    pub result: FetchResultCodeV1,
    pub receipt_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchNetworkWorkerAuthorizationV1 {
    pub schema_version: u32,
    pub authorization_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub request_sha256: String,
    pub worker_executable_sha256: String,
    pub operation: ResearchNetworkWorkerOperationV1,
    pub method: ResearchHttpMethodV1,
    pub maximum_response_bytes: u64,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub nonce_id: String,
    pub signer_id: String,
    pub signing_key_id: String,
    pub signature_hex: String,
    pub authorization_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchSegmentV1 {
    pub segment_id: String,
    pub role: ResearchSegmentRoleV1,
    pub heading_level: Option<u8>,
    pub text: String,
    pub source_reference: String,
    pub segment_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchLinkV1 {
    pub link_id: String,
    pub display_text: String,
    pub target_url_protected_ref: String,
    pub target_origin_hint: String,
    pub relation: ResearchLinkRelationV1,
    pub source_snapshot_sha256: String,
    pub link_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchPageSnapshotV1 {
    pub schema_version: u32,
    pub snapshot_id: String,
    pub source_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub requested_url_sha256: String,
    pub final_url_protected_ref: String,
    pub origin_id: String,
    pub http_status: u16,
    pub content_type: String,
    pub retrieved_at_unix_ms: u64,
    pub freshness_expires_at_unix_ms: u64,
    pub raw_body_sha256: String,
    pub extracted_content_sha256: String,
    pub title: String,
    pub segments: Vec<ResearchSegmentV1>,
    pub links: Vec<ResearchLinkV1>,
    pub source_policy_class: SourcePolicyClassV1,
    pub generation: u64,
    pub snapshot_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchSourcePolicyV1 {
    pub schema_version: u32,
    pub policy_id: String,
    pub organization_id: String,
    pub preferred_origins: Vec<String>,
    pub allowed_origins: Vec<String>,
    pub blocked_origins: Vec<String>,
    pub internal_host_suffixes: Vec<String>,
    pub primary_source_ids: Vec<String>,
    pub retention_seconds: u64,
    pub allowed_download_classes: Vec<DownloadClassV1>,
    pub policy_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchEvidenceExcerptV1 {
    pub schema_version: u32,
    pub evidence_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub source_snapshot_sha256: String,
    pub segment_ids: Vec<String>,
    pub excerpt: String,
    pub observed_at_unix_ms: u64,
    pub source_class: SourcePolicyClassV1,
    pub trust_class: EvidenceTrustClassV1,
    pub relevance_score_millionths: u32,
    pub evidence_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchConflictV1 {
    pub conflict_id: String,
    pub question_key: String,
    pub evidence_ids: Vec<String>,
    pub descriptions: Vec<String>,
    pub unresolved: bool,
    pub conflict_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchEvidenceBundleV1 {
    pub schema_version: u32,
    pub bundle_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub research_brief_sha256: String,
    pub source_snapshot_sha256: Vec<String>,
    pub evidence_excerpts: Vec<ResearchEvidenceExcerptV1>,
    pub freshness_expires_at_unix_ms: u64,
    pub conflicts: Vec<ResearchConflictV1>,
    pub unknowns: Vec<String>,
    pub source_diversity_count: u32,
    pub bundle_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchClaimV1 {
    pub claim_id: String,
    pub claim_kind: ResearchClaimKindV1,
    pub statement: String,
    pub evidence_ids: Vec<String>,
    pub derived_from: Vec<String>,
    pub confidence_millionths: u32,
    pub claim_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchSufficiencyReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub brief_sha256: String,
    pub evidence_bundle_sha256: String,
    pub question_coverage_millionths: u32,
    pub source_count: u32,
    pub fresh_source_count: u32,
    pub preferred_source_count: u32,
    pub unresolved_conflict_count: u32,
    pub unknown_count: u32,
    pub budget_exhausted: bool,
    pub status: ResearchSufficiencyStatusV1,
    pub reason_codes: Vec<String>,
    pub report_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchModelContextSliceV1 {
    pub schema_version: u32,
    pub organization_id: String,
    pub case_id: String,
    pub brief_sha256: String,
    pub trust_class: EvidenceTrustClassV1,
    pub source_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub bounded_excerpts: Vec<String>,
    pub conflict_ids: Vec<String>,
    pub unknowns: Vec<String>,
    pub raw_html_count: u32,
    pub raw_url_count: u32,
    pub download_byte_count: u64,
    pub network_authority_count: u32,
    pub workspace_promotion_authority_count: u32,
    pub context_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub brief_sha256: String,
    pub evidence_bundle_sha256: String,
    pub sufficiency_report_sha256: String,
    pub claims: Vec<ResearchClaimV1>,
    pub conflicts: Vec<ResearchConflictV1>,
    pub unknowns: Vec<String>,
    pub uncited_claim_count: u32,
    pub unsupported_number_count: u32,
    pub report_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserResearchSessionV1 {
    pub schema_version: u32,
    pub session_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub role_id: String,
    pub edge_executable_sha256: String,
    pub edge_driver_executable_sha256: String,
    pub edge_version: String,
    pub edge_driver_version: String,
    pub wfp_loopback_evidence_sha256: String,
    pub snapshot_server_origin_id: String,
    pub research_brief_sha256: String,
    pub maximum_pages: u32,
    pub maximum_links: u32,
    pub downloads_denied: bool,
    pub forms_disabled: bool,
    pub session_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserSnapshotManifestV1 {
    pub schema_version: u32,
    pub manifest_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub browser_session_sha256: String,
    pub snapshot_sha256: Vec<String>,
    pub safe_projection_sha256: Vec<String>,
    pub observed_page_count: u32,
    pub external_navigation_count: u32,
    pub browser_download_count: u32,
    pub browser_form_submit_count: u32,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchLinkSelectionV1 {
    pub schema_version: u32,
    pub selection_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub browser_session_sha256: String,
    pub source_snapshot_sha256: String,
    pub link_id: String,
    pub selected_at_unix_ms: u64,
    pub selection_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlledDownloadIntentV1 {
    pub schema_version: u32,
    pub intent_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub source_kind: ControlledDownloadSourceKindV1,
    pub source_snapshot_sha256: String,
    pub source_link_id: String,
    pub expected_class: DownloadClassV1,
    pub maximum_bytes: u64,
    pub intent_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlledDownloadRequestV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub intent_sha256: String,
    pub url_admission_decision_sha256: String,
    pub network_profile_sha256: String,
    pub worker_executable_sha256: String,
    pub quarantine_artifact_id: String,
    pub deadline_unix_ms: u64,
    pub request_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlledDownloadReceiptV1 {
    pub schema_version: u32,
    pub receipt_id: String,
    pub request_sha256: String,
    pub fetch_receipt_sha256: String,
    pub quarantine_artifact_id: String,
    pub untrusted_filename_sha256: String,
    pub sanitized_filename: String,
    pub bytes_received: u64,
    pub pre_trust_sha256: String,
    pub receipt_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadQuarantineRecordV1 {
    pub schema_version: u32,
    pub record_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub workspace_id: String,
    pub quarantine_artifact_id: String,
    pub download_receipt_sha256: String,
    pub pre_trust_sha256: String,
    pub file_bytes: u64,
    pub created_at_unix_ms: u64,
    pub record_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentTrustReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub quarantine_record_sha256: String,
    pub source_snapshot_sha256: String,
    pub source_link_id: String,
    pub decision: AttachmentTrustDecisionV1,
    pub check_policy_hresult: i64,
    pub save_hresult: i64,
    pub file_exists_after_save: bool,
    pub file_bytes_after_save: u64,
    pub final_download_sha256: String,
    pub file_mutated_by_trust_provider: bool,
    pub report_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadValidationReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub final_download_sha256: String,
    pub expected_class: DownloadClassV1,
    pub detected_class: DownloadClassV1,
    pub declared_content_type: String,
    pub sanitized_filename: String,
    pub extension_matches: bool,
    pub mime_matches: bool,
    pub magic_matches: bool,
    pub macro_free: bool,
    pub package_safe: bool,
    pub parser_verified: bool,
    pub status: DownloadValidationStatusV1,
    pub reason_codes: Vec<String>,
    pub report_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadPromotionReceiptV1 {
    pub schema_version: u32,
    pub receipt_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub workspace_id: String,
    pub quarantine_record_sha256: String,
    pub attachment_trust_report_sha256: String,
    pub validation_report_sha256: String,
    pub final_download_sha256: String,
    pub source_snapshot_sha256: String,
    pub source_link_id: String,
    pub workspace_artifact_id: String,
    pub workspace_generation: u64,
    pub promotion_policy_sha256: String,
    pub status: DownloadPromotionStatusV1,
    pub promoted_at_unix_ms: u64,
    pub receipt_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchExperienceRecordV1 {
    pub schema_version: u32,
    pub experience_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub brief_sha256: String,
    pub evidence_bundle_sha256: String,
    pub sufficiency_report_sha256: String,
    pub report_sha256: String,
    pub case_kind: ResearchExperienceCaseKindV1,
    pub outcome: ResearchExperienceOutcomeV1,
    pub model_used: bool,
    pub operation_count: u32,
    pub experience_sha256: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchSecurityMetricsV1 {
    pub attachment_prompt_bypass: u64,
    pub attachment_policy_scope_broadening: u64,
    pub zone_information_bypass: u64,
    pub security_ui_auto_approval: u64,
    pub csv_automatic_promotion: u64,
    pub pdf_automatic_promotion: u64,
    pub external_browser_egress: u64,
    pub external_model_egress: u64,
    pub unauthorized_network_worker_request: u64,
    pub ssrf_success: u64,
    pub private_address_connect: u64,
    pub dns_rebinding_accept: u64,
    pub https_downgrade_accept: u64,
    pub redirect_escape: u64,
    pub query_secret_leak: u64,
    pub prompt_injection_authority_change: u64,
    pub unbounded_crawl: u64,
    pub browser_download: u64,
    pub forbidden_file_promotion: u64,
    pub mime_magic_mismatch_accept: u64,
    pub macro_file_promotion: u64,
    pub workspace_escape: u64,
    pub credential_leak: u64,
    pub raw_web_to_model: u64,
    pub false_research_completion: u64,
    pub false_download_completion: u64,
    pub critical_error: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchResidualMetricsV1 {
    pub edge_processes: u64,
    pub edge_driver_processes: u64,
    pub snapshot_servers: u64,
    pub network_workers: u64,
    pub model_workers: u64,
    pub appcontainer_profiles: u64,
    pub wfp_temporary_objects: u64,
    pub open_sockets: u64,
    pub quarantine_temp_files: u64,
    pub partial_downloads: u64,
    pub workspace_locks: u64,
    pub browser_profiles: u64,
    pub cookies: u64,
    pub download_directory_files: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchPerformanceMetricsV1 {
    pub disclosure_gate_microseconds: u64,
    pub url_admission_microseconds: u64,
    pub dns_microseconds: u64,
    pub connect_microseconds: u64,
    pub tls_microseconds: u64,
    pub ttfb_microseconds: u64,
    pub transfer_microseconds: u64,
    pub html_parse_microseconds: u64,
    pub snapshot_compile_microseconds: u64,
    pub evidence_ranking_microseconds: u64,
    pub context_slicing_microseconds: u64,
    pub model_microseconds: u64,
    pub browser_startup_microseconds: u64,
    pub webdriver_observation_microseconds: u64,
    pub download_microseconds: u64,
    pub attachment_trust_microseconds: u64,
    pub format_validation_microseconds: u64,
    pub workspace_promotion_microseconds: u64,
    pub peak_network_worker_memory_bytes: u64,
    pub peak_parser_memory_bytes: u64,
    pub peak_edge_memory_bytes: u64,
    pub peak_model_memory_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchWorkReplayReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub scenario_count: u32,
    pub repetitions_per_scenario: u32,
    pub logical_replay_count: u64,
    pub external_network_request_count: u64,
    pub deterministic_match_count: u64,
    pub blind_replay_count: u64,
    pub report_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchWorkCompletionReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub source_tree_sha256: String,
    pub predecessor_finished_sha256: String,
    pub research_case_count: u32,
    pub routine_case_count: u32,
    pub security_negative_case_count: u32,
    pub external_request_count: u32,
    pub external_origin_count: u32,
    pub redirect_count: u32,
    pub external_bytes_received: u64,
    pub tls_failure_count: u32,
    pub ssrf_rejection_count: u32,
    pub discovered_link_count: u32,
    pub fetched_source_count: u32,
    pub snapshot_page_count: u32,
    pub evidence_excerpt_count: u32,
    pub conflict_count: u32,
    pub unknown_count: u32,
    pub actual_qwen_invocation_count: u32,
    pub model_free_case_count: u32,
    pub actual_download_count: u32,
    pub promoted_artifact_count: u32,
    pub rejected_download_count: u32,
    pub crash_window_count: u32,
    pub replay_report_sha256: String,
    pub protected_audit_record_count: u64,
    pub protected_audit_terminal_sha256: String,
    pub security: ResearchSecurityMetricsV1,
    pub residual: ResearchResidualMetricsV1,
    pub performance: ResearchPerformanceMetricsV1,
    pub browser_loopback_only_evidence: bool,
    pub network_worker_sole_egress_evidence: bool,
    pub safe_snapshot_evidence: bool,
    pub evidence_grounding_evidence: bool,
    pub controlled_download_evidence: bool,
    pub attachment_trust_evidence: bool,
    pub format_validation_evidence: bool,
    pub workspace_promotion_evidence: bool,
    pub model_free_research_evidence: bool,
    pub routine_human_touch_zero: bool,
    pub complete: bool,
    pub finished_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchWorkCertificationV1 {
    pub schema_version: u32,
    pub certification_id: String,
    pub completion_report_sha256: String,
    pub predecessor_finished_sha256: String,
    pub network_worker_sha256: String,
    pub edge_executable_sha256: String,
    pub edge_driver_executable_sha256: String,
    pub model_artifact_sha256: String,
    pub runtime_artifact_sha256: String,
    pub evidence_ids: Vec<String>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub signer_id: String,
    pub signing_key_id: String,
    pub signature_hex: String,
    pub certification_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentPolicySnapshotV1 {
    pub schema_version: u32,
    pub user_sid: String,
    pub admx_sha256: String,
    pub association_key_exists: bool,
    pub low_risk_value_exists: bool,
    pub low_risk_value_type: String,
    pub low_risk_value_bytes_base64: String,
    pub low_risk_value_sha256: String,
    pub moderate_risk_value_exists: bool,
    pub moderate_risk_value_type: String,
    pub moderate_risk_value_bytes_base64: String,
    pub moderate_risk_value_sha256: String,
    pub high_risk_value_exists: bool,
    pub high_risk_value_type: String,
    pub high_risk_value_bytes_base64: String,
    pub high_risk_value_sha256: String,
    pub attachments_policy_sha256: Option<String>,
    pub policy_state_sha256: String,
    pub captured_at_unix_ms: u64,
    pub snapshot_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentPolicyProbeV1 {
    pub schema_version: u32,
    pub user_sid: String,
    pub elevated: bool,
    pub admx_sha256: String,
    pub policy_scope: AttachmentPolicyScopeV1,
    pub completion_low_risk_extensions: Vec<String>,
    pub txt_checkpolicy: AttachmentPolicyDecisionV1,
    pub csv_checkpolicy: AttachmentPolicyDecisionV1,
    pub pdf_checkpolicy: AttachmentPolicyDecisionV1,
    pub higher_precedence_txt_conflict: bool,
    pub original_policy_sha256: String,
    pub staged_policy_sha256: String,
    pub txt_checkpolicy_microseconds: u64,
    pub csv_checkpolicy_microseconds: u64,
    pub pdf_checkpolicy_microseconds: u64,
    pub probe_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentPolicyQualificationV1 {
    pub schema_version: u32,
    pub user_sid: String,
    pub elevated: bool,
    pub admx_sha256: String,
    pub policy_scope: AttachmentPolicyScopeV1,
    pub completion_low_risk_extensions: Vec<String>,
    pub txt_checkpolicy: AttachmentPolicyDecisionV1,
    pub csv_checkpolicy: AttachmentPolicyDecisionV1,
    pub pdf_checkpolicy: AttachmentPolicyDecisionV1,
    pub higher_precedence_txt_conflict: bool,
    pub original_policy_sha256: String,
    pub staged_policy_sha256: String,
    pub restored_policy_sha256: String,
    pub restored_exactly: bool,
    pub policy_stage_microseconds: u64,
    pub txt_checkpolicy_microseconds: u64,
    pub csv_checkpolicy_microseconds: u64,
    pub pdf_checkpolicy_microseconds: u64,
    pub policy_restore_microseconds: u64,
    pub qualification_total_microseconds: u64,
    pub attachment_prompt_bypass_count: u64,
    pub attachment_policy_scope_broadening_count: u64,
    pub zone_information_bypass_count: u64,
    pub security_ui_auto_approval_count: u64,
    pub csv_automatic_promotion_count: u64,
    pub pdf_automatic_promotion_count: u64,
    pub temporary_attachment_policy_count: u64,
    pub qualification_status: AttachmentPolicyQualificationStatusV1,
    pub qualification_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchWorkCloseoutCertificationV1 {
    pub schema_version: u32,
    pub certification_id: String,
    pub completion_report_sha256: String,
    pub execution_certification_sha256: String,
    pub attachment_policy_qualification_sha256: String,
    pub user_sid: String,
    pub admx_sha256: String,
    pub original_policy_sha256: String,
    pub staged_policy_sha256: String,
    pub restored_policy_sha256: String,
    pub source_tree_sha256: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub signer_id: String,
    pub signing_key_id: String,
    pub signature_hex: String,
    pub certification_sha256: String,
}
