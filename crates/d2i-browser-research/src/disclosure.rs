use crate::validation::{sha256_bytes, validate_hash, validate_id, validate_text};
use crate::{
    DisclosureClassV1, DisclosureDecisionCodeV1, DownloadClassV1, ResearchBriefV1,
    ResearchDisclosureDecisionV1, ResearchDisclosurePolicyV1, ResearchError,
    ResearchNetworkProfileV1, ResearchProxyModeV1, ResearchQueryV1, ResearchSourcePolicyV1,
    ZERO_HASH,
};
use std::collections::BTreeSet;

pub const MAX_RESEARCH_PAGES: u32 = 24;
pub const MAX_RESEARCH_REQUESTS: u32 = 64;
pub const MAX_RESEARCH_ORIGINS: u32 = 16;
pub const MAX_LINKS_PER_PAGE: u32 = 512;
pub const MAX_RAW_HTML_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_EXTRACTED_TEXT_BYTES: u64 = 256 * 1024;
pub const MAX_EVIDENCE_EXCERPTS: u32 = 64;
pub const MAX_MODEL_EVIDENCE_BYTES: u64 = 64 * 1024;

pub fn default_research_network_profile_v1() -> Result<ResearchNetworkProfileV1, ResearchError> {
    ResearchNetworkProfileV1 {
        schema_version: 1,
        profile_id: "network-profile.office600.public-https-v1".to_owned(),
        allowed_schemes: vec!["https".to_owned()],
        allowed_ports: vec![443],
        max_redirects: 5,
        max_request_bytes: 16 * 1024,
        max_response_headers: 64 * 1024,
        max_response_bytes: MAX_RAW_HTML_BYTES,
        max_total_bytes: 32 * 1024 * 1024,
        connect_timeout_milliseconds: 10_000,
        receive_timeout_milliseconds: 30_000,
        origin_budget: MAX_RESEARCH_ORIGINS,
        request_budget: MAX_RESEARCH_REQUESTS,
        max_pages: MAX_RESEARCH_PAGES,
        max_links_per_page: MAX_LINKS_PER_PAGE,
        max_extracted_text_bytes: MAX_EXTRACTED_TEXT_BYTES,
        max_evidence_excerpts: MAX_EVIDENCE_EXCERPTS,
        max_model_evidence_bytes: MAX_MODEL_EVIDENCE_BYTES,
        max_link_depth: 3,
        proxy_mode: ResearchProxyModeV1::Direct,
        network_profile_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

pub fn validate_network_profile_v1(
    profile: &ResearchNetworkProfileV1,
) -> Result<(), ResearchError> {
    profile.validate_seal()?;
    validate_id(&profile.profile_id, "network profile ID")?;
    if profile.schema_version != 1
        || profile.allowed_schemes != ["https"]
        || profile.allowed_ports != [443]
        || profile.max_redirects > 5
        || profile.max_request_bytes == 0
        || profile.max_request_bytes > 64 * 1024
        || profile.max_response_headers == 0
        || profile.max_response_headers > 128 * 1024
        || profile.max_response_bytes == 0
        || profile.max_response_bytes > MAX_RAW_HTML_BYTES
        || profile.max_total_bytes < profile.max_response_bytes
        || profile.max_total_bytes > 512 * 1024 * 1024
        || !(100..=60_000).contains(&profile.connect_timeout_milliseconds)
        || !(100..=120_000).contains(&profile.receive_timeout_milliseconds)
        || profile.origin_budget == 0
        || profile.origin_budget > MAX_RESEARCH_ORIGINS
        || profile.request_budget == 0
        || profile.request_budget > MAX_RESEARCH_REQUESTS
        || profile.max_pages == 0
        || profile.max_pages > MAX_RESEARCH_PAGES
        || profile.max_links_per_page == 0
        || profile.max_links_per_page > MAX_LINKS_PER_PAGE
        || profile.max_extracted_text_bytes == 0
        || profile.max_extracted_text_bytes > MAX_EXTRACTED_TEXT_BYTES
        || profile.max_evidence_excerpts == 0
        || profile.max_evidence_excerpts > MAX_EVIDENCE_EXCERPTS
        || profile.max_model_evidence_bytes == 0
        || profile.max_model_evidence_bytes > MAX_MODEL_EVIDENCE_BYTES
        || profile.max_link_depth == 0
        || profile.max_link_depth > 3
        || profile.proxy_mode != ResearchProxyModeV1::Direct
    {
        return Err(ResearchError::Invalid(
            "research network profile widens the reviewed v1 authority".to_owned(),
        ));
    }
    Ok(())
}

pub fn validate_research_brief_v1(brief: &ResearchBriefV1) -> Result<(), ResearchError> {
    brief.validate_seal()?;
    validate_id(&brief.brief_id, "brief ID")?;
    validate_id(&brief.organization_id, "brief organization")?;
    validate_id(&brief.case_id, "brief Case")?;
    validate_text(&brief.research_question, "research question", 4096)?;
    validate_text(&brief.research_scope, "research scope", 4096)?;
    if brief.schema_version != 1
        || brief.freshness_requirement_seconds == 0
        || brief.minimum_source_count == 0
        || brief.minimum_source_count > 24
        || brief.allowed_disclosure_class != DisclosureClassV1::Public
    {
        return Err(ResearchError::Invalid(
            "research brief must remain bounded public-only in v1".to_owned(),
        ));
    }
    Ok(())
}

pub fn validate_source_policy_v1(policy: &ResearchSourcePolicyV1) -> Result<(), ResearchError> {
    policy.validate_seal()?;
    validate_id(&policy.policy_id, "source policy ID")?;
    validate_id(&policy.organization_id, "source policy organization")?;
    if policy.schema_version != 1 || policy.retention_seconds == 0 {
        return Err(ResearchError::Invalid(
            "source policy metadata is invalid".to_owned(),
        ));
    }
    for origin in policy
        .preferred_origins
        .iter()
        .chain(&policy.allowed_origins)
        .chain(&policy.blocked_origins)
    {
        validate_origin_label(origin)?;
    }
    for suffix in &policy.internal_host_suffixes {
        if suffix.is_empty()
            || suffix.len() > 253
            || suffix.contains(['/', ':', '@'])
            || !suffix.is_ascii()
        {
            return Err(ResearchError::Invalid(
                "internal hostname suffix is invalid".to_owned(),
            ));
        }
    }
    let allowed = policy
        .allowed_download_classes
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if allowed.len() != policy.allowed_download_classes.len()
        || allowed.contains(&DownloadClassV1::Unknown)
    {
        return Err(ResearchError::Invalid(
            "source download class allowlist is invalid".to_owned(),
        ));
    }
    Ok(())
}

pub fn decide_research_disclosure_v1(
    policy: &ResearchDisclosurePolicyV1,
    brief: &ResearchBriefV1,
    query_text: &str,
    input_class: DisclosureClassV1,
    declassification_rule_id: Option<&str>,
) -> Result<(ResearchDisclosureDecisionV1, Option<ResearchQueryV1>), ResearchError> {
    policy.validate_seal()?;
    validate_research_brief_v1(brief)?;
    if policy.schema_version != 1 || policy.organization_id != brief.organization_id {
        return Err(ResearchError::Integrity(
            "disclosure policy and brief organization differ".to_owned(),
        ));
    }
    validate_text(query_text, "research query", 4096)?;
    let query_hash = sha256_bytes(query_text.as_bytes());
    let blocked_term = policy
        .blocked_term_hashes
        .iter()
        .any(|blocked| blocked == &query_hash);
    let approved_rule = declassification_rule_id.filter(|rule| {
        policy
            .approved_declassification_rule_ids
            .iter()
            .any(|approved| approved == rule)
    });
    let (result, output_class, reason_code) = if blocked_term {
        (
            DisclosureDecisionCodeV1::Blocked,
            input_class,
            "research_query_disclosure_blocked",
        )
    } else if input_class <= policy.maximum_external_class
        && input_class <= brief.allowed_disclosure_class
    {
        (
            DisclosureDecisionCodeV1::Allowed,
            input_class,
            "public_query_allowed",
        )
    } else if approved_rule.is_some() {
        (
            DisclosureDecisionCodeV1::Declassified,
            DisclosureClassV1::Public,
            "approved_declassification_rule_applied",
        )
    } else {
        (
            DisclosureDecisionCodeV1::Blocked,
            input_class,
            "research_query_disclosure_blocked",
        )
    };
    let decision = ResearchDisclosureDecisionV1 {
        schema_version: 1,
        decision_id: format!("disclosure:{}", brief.case_id),
        organization_id: brief.organization_id.clone(),
        case_id: brief.case_id.clone(),
        policy_sha256: policy.policy_sha256.clone(),
        input_class,
        output_class,
        applied_declassification_rule_id: approved_rule.map(str::to_owned),
        result,
        reason_code: reason_code.to_owned(),
        query_sha256: query_hash,
        decision_sha256: ZERO_HASH.to_owned(),
    }
    .seal()?;
    if result == DisclosureDecisionCodeV1::Blocked {
        return Ok((decision, None));
    }
    let query = ResearchQueryV1 {
        schema_version: 1,
        query_id: format!("query:{}", brief.case_id),
        organization_id: brief.organization_id.clone(),
        case_id: brief.case_id.clone(),
        brief_sha256: brief.brief_sha256.clone(),
        disclosure_decision_sha256: decision.decision_sha256.clone(),
        query_text: query_text.to_owned(),
        query_sha256: ZERO_HASH.to_owned(),
    }
    .seal()?;
    Ok((decision, Some(query)))
}

fn validate_origin_label(origin: &str) -> Result<(), ResearchError> {
    if origin.is_empty()
        || origin.len() > 253
        || !origin.is_ascii()
        || origin.contains(['/', ':', '@'])
    {
        return Err(ResearchError::Invalid(
            "source policy origin is invalid".to_owned(),
        ));
    }
    Ok(())
}

pub fn validate_disclosure_policy_v1(
    policy: &ResearchDisclosurePolicyV1,
) -> Result<(), ResearchError> {
    policy.validate_seal()?;
    validate_id(&policy.policy_id, "disclosure policy ID")?;
    validate_id(&policy.organization_id, "disclosure policy organization")?;
    for hash in &policy.blocked_term_hashes {
        validate_hash(hash, "blocked query hash")?;
    }
    if policy.schema_version != 1 || policy.maximum_external_class != DisclosureClassV1::Public {
        return Err(ResearchError::Invalid(
            "OFFICE-600 external disclosure policy must be public-only".to_owned(),
        ));
    }
    Ok(())
}
