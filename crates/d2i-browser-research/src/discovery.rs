use crate::validation::{sha256_bytes, validate_hash, validate_id, validate_text};
use crate::{
    DiscoveryProviderKindV1, ResearchDiscoveryProviderDescriptorV1, ResearchDiscoveryResultV1,
    ResearchError, ResearchQueryV1, SearchPortalProfileV1, ZERO_HASH,
};
use std::collections::BTreeSet;

const MAX_DISCOVERY_RESULTS: usize = 64;

#[derive(Debug, Clone)]
pub struct DiscoveryCandidateV1<'a> {
    pub candidate_id: &'a str,
    pub protected_ref: &'a str,
    pub snippet: &'a str,
}

pub fn validate_discovery_provider_v1(
    descriptor: &ResearchDiscoveryProviderDescriptorV1,
) -> Result<(), ResearchError> {
    descriptor.validate_seal()?;
    validate_id(&descriptor.provider_id, "discovery provider ID")?;
    validate_id(
        &descriptor.organization_id,
        "discovery provider organization",
    )?;
    validate_hash(&descriptor.profile_sha256, "discovery provider profile")?;
    if descriptor.schema_version != 1 || !descriptor.evidence_only_after_fetch {
        return Err(ResearchError::Invalid(
            "discovery provider must require a fetched page before evidence use".to_owned(),
        ));
    }
    Ok(())
}

pub fn validate_search_portal_profile_v1(
    profile: &SearchPortalProfileV1,
) -> Result<(), ResearchError> {
    profile.validate_seal()?;
    validate_id(&profile.profile_id, "search portal profile ID")?;
    validate_id(&profile.organization_id, "search portal organization")?;
    validate_id(
        &profile.endpoint_protected_ref,
        "search portal protected endpoint",
    )?;
    if profile.schema_version != 1
        || profile.result_limit == 0
        || profile.result_limit > MAX_DISCOVERY_RESULTS as u32
        || profile.fixed_query_parameter_names.is_empty()
        || profile.fixed_query_parameter_names.len() > 8
    {
        return Err(ResearchError::Invalid(
            "configured search portal bounds differ".to_owned(),
        ));
    }
    for parameter in &profile.fixed_query_parameter_names {
        if parameter.is_empty()
            || parameter.len() > 64
            || !parameter
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'_' | b'-'))
        {
            return Err(ResearchError::Invalid(
                "search portal parameter name is invalid".to_owned(),
            ));
        }
    }
    Ok(())
}

pub fn build_discovery_result_v1(
    descriptor: &ResearchDiscoveryProviderDescriptorV1,
    query: &ResearchQueryV1,
    candidates: &[DiscoveryCandidateV1<'_>],
) -> Result<ResearchDiscoveryResultV1, ResearchError> {
    validate_discovery_provider_v1(descriptor)?;
    query.validate_seal()?;
    if descriptor.organization_id != query.organization_id
        || candidates.is_empty()
        || candidates.len() > MAX_DISCOVERY_RESULTS
    {
        return Err(ResearchError::Invalid(
            "discovery result organization or candidate bounds differ".to_owned(),
        ));
    }
    let mut seen_ids = BTreeSet::new();
    let mut seen_refs = BTreeSet::new();
    let mut candidate_ids = Vec::with_capacity(candidates.len());
    let mut protected_refs = Vec::with_capacity(candidates.len());
    let mut snippet_hashes = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        validate_id(candidate.candidate_id, "discovery candidate ID")?;
        validate_id(candidate.protected_ref, "discovery candidate protected ref")?;
        validate_text(candidate.snippet, "discovery snippet", 4096)?;
        if !candidate.protected_ref.starts_with("source-store:sha256:")
            || !seen_ids.insert(candidate.candidate_id)
            || !seen_refs.insert(candidate.protected_ref)
        {
            return Err(ResearchError::Invalid(
                "discovery candidates must be unique protected source references".to_owned(),
            ));
        }
        candidate_ids.push(candidate.candidate_id.to_owned());
        protected_refs.push(candidate.protected_ref.to_owned());
        snippet_hashes.push(sha256_bytes(candidate.snippet.as_bytes()));
    }
    let result = ResearchDiscoveryResultV1 {
        schema_version: 1,
        result_id: format!("discovery-result:{}", query.query_id),
        organization_id: query.organization_id.clone(),
        case_id: query.case_id.clone(),
        provider_descriptor_sha256: descriptor.descriptor_sha256.clone(),
        source_candidate_ids: candidate_ids,
        source_candidate_protected_refs: protected_refs,
        snippet_hashes,
        evidence_eligible: false,
        result_sha256: ZERO_HASH.to_owned(),
    }
    .seal()?;
    validate_discovery_result_v1(&result, descriptor, query)?;
    Ok(result)
}

pub fn validate_discovery_result_v1(
    result: &ResearchDiscoveryResultV1,
    descriptor: &ResearchDiscoveryProviderDescriptorV1,
    query: &ResearchQueryV1,
) -> Result<(), ResearchError> {
    result.validate_seal()?;
    if result.schema_version != 1
        || result.organization_id != descriptor.organization_id
        || result.organization_id != query.organization_id
        || result.case_id != query.case_id
        || result.provider_descriptor_sha256 != descriptor.descriptor_sha256
        || result.source_candidate_ids.is_empty()
        || result.source_candidate_ids.len() != result.source_candidate_protected_refs.len()
        || result.source_candidate_ids.len() != result.snippet_hashes.len()
        || result.evidence_eligible
    {
        return Err(ResearchError::Integrity(
            "search discovery hints cannot be evidence and must preserve lineage".to_owned(),
        ));
    }
    Ok(())
}

pub fn seed_provider_descriptor_v1(
    provider_id: &str,
    organization_id: &str,
    profile_sha256: &str,
) -> Result<ResearchDiscoveryProviderDescriptorV1, ResearchError> {
    ResearchDiscoveryProviderDescriptorV1 {
        schema_version: 1,
        provider_id: provider_id.to_owned(),
        organization_id: organization_id.to_owned(),
        provider_kind: DiscoveryProviderKindV1::SeedUrlSet,
        profile_sha256: profile_sha256.to_owned(),
        evidence_only_after_fetch: true,
        descriptor_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}
