use crate::validation::{sha256_bytes, validate_id, validate_text};
use crate::{
    EvidenceTrustClassV1, ResearchBriefV1, ResearchClaimKindV1, ResearchClaimV1,
    ResearchConflictV1, ResearchError, ResearchEvidenceBundleV1, ResearchEvidenceExcerptV1,
    ResearchModelContextSliceV1, ResearchNetworkProfileV1, ResearchPageSnapshotV1,
    ResearchReportV1, ResearchSourcePolicyV1, ResearchSufficiencyReportV1,
    ResearchSufficiencyStatusV1, SourcePolicyClassV1, ZERO_HASH,
};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

impl ResearchModelContextSliceV1 {
    pub fn validate(&self, profile: &ResearchNetworkProfileV1) -> Result<(), ResearchError> {
        self.validate_seal()?;
        validate_id(&self.organization_id, "model context organization")?;
        validate_id(&self.case_id, "model context Case")?;
        if self.schema_version != 1
            || self.trust_class != EvidenceTrustClassV1::UntrustedExternalResearch
            || self.raw_html_count != 0
            || self.raw_url_count != 0
            || self.download_byte_count != 0
            || self.network_authority_count != 0
            || self.workspace_promotion_authority_count != 0
        {
            return Err(ResearchError::AccessDenied(
                "model context contains forbidden research authority or raw data".to_owned(),
            ));
        }
        let bytes = self.bounded_excerpts.iter().map(String::len).sum::<usize>();
        if bytes as u64 > profile.max_model_evidence_bytes {
            return Err(ResearchError::Resource(
                "model evidence context exceeds profile".to_owned(),
            ));
        }
        Ok(())
    }
}

pub fn build_evidence_bundle_v1(
    brief: &ResearchBriefV1,
    snapshots: &[ResearchPageSnapshotV1],
    conflicts: Vec<ResearchConflictV1>,
    unknowns: Vec<String>,
    profile: &ResearchNetworkProfileV1,
) -> Result<ResearchEvidenceBundleV1, ResearchError> {
    brief.validate_seal()?;
    if snapshots.is_empty() || snapshots.len() > profile.max_pages as usize {
        return Err(ResearchError::Resource(
            "evidence source count is empty or exceeds profile".to_owned(),
        ));
    }
    let question_tokens = tokens(&brief.research_question);
    let mut candidates = Vec::new();
    let mut accepted_snapshots = Vec::new();
    let mut observed_body_hashes = BTreeSet::new();
    for snapshot in snapshots {
        snapshot.validate_seal()?;
        if snapshot.organization_id != brief.organization_id || snapshot.case_id != brief.case_id {
            return Err(ResearchError::Integrity(
                "evidence source organization or Case differs".to_owned(),
            ));
        }
        if !observed_body_hashes.insert(snapshot.raw_body_sha256.clone()) {
            continue;
        }
        accepted_snapshots.push(snapshot);
        for segment in &snapshot.segments {
            let score = relevance_score(
                &question_tokens,
                &tokens(&segment.text),
                snapshot.source_policy_class,
            );
            candidates.push((
                score,
                snapshot.source_id.clone(),
                snapshot.snapshot_sha256.clone(),
                snapshot.retrieved_at_unix_ms,
                snapshot.freshness_expires_at_unix_ms,
                snapshot.source_policy_class,
                segment.segment_id.clone(),
                segment.text.clone(),
            ));
        }
    }
    candidates.sort_by_key(|value| (Reverse(value.0), value.1.clone(), value.6.clone()));
    let maximum = usize::try_from(profile.max_evidence_excerpts)
        .map_err(|_| ResearchError::Resource("evidence limit does not fit memory".to_owned()))?
        .min(16);
    let mut excerpts = Vec::new();
    let mut context_bytes = 0_u64;
    let mut selected_sources = BTreeSet::new();
    let mut freshness = u64::MAX;
    for candidate in candidates.into_iter().take(maximum * 4) {
        if candidate.0 == 0 && !excerpts.is_empty() {
            continue;
        }
        let excerpt = bound_utf8(&candidate.7, 4096);
        if context_bytes.saturating_add(excerpt.len() as u64) > profile.max_model_evidence_bytes {
            continue;
        }
        context_bytes = context_bytes.saturating_add(excerpt.len() as u64);
        let index = excerpts.len() + 1;
        excerpts.push(
            ResearchEvidenceExcerptV1 {
                schema_version: 1,
                evidence_id: format!("evidence-{index:06}"),
                organization_id: brief.organization_id.clone(),
                case_id: brief.case_id.clone(),
                source_snapshot_sha256: candidate.2,
                segment_ids: vec![candidate.6],
                excerpt,
                observed_at_unix_ms: candidate.3,
                source_class: candidate.5,
                trust_class: EvidenceTrustClassV1::UntrustedExternalResearch,
                relevance_score_millionths: candidate.0,
                evidence_sha256: ZERO_HASH.to_owned(),
            }
            .seal()?,
        );
        selected_sources.insert(candidate.1);
        freshness = freshness.min(candidate.4);
        if excerpts.len() >= maximum {
            break;
        }
    }
    if excerpts.is_empty() {
        return Err(ResearchError::Invalid(
            "no bounded evidence excerpt could be selected".to_owned(),
        ));
    }
    for conflict in &conflicts {
        conflict.validate_seal()?;
    }
    let mut source_hashes = accepted_snapshots
        .iter()
        .map(|snapshot| snapshot.snapshot_sha256.clone())
        .collect::<Vec<_>>();
    source_hashes.sort();
    source_hashes.dedup();
    ResearchEvidenceBundleV1 {
        schema_version: 1,
        bundle_id: format!("evidence-bundle:{}", brief.case_id),
        organization_id: brief.organization_id.clone(),
        case_id: brief.case_id.clone(),
        research_brief_sha256: brief.brief_sha256.clone(),
        source_snapshot_sha256: source_hashes,
        evidence_excerpts: excerpts,
        freshness_expires_at_unix_ms: freshness,
        conflicts,
        unknowns,
        source_diversity_count: u32::try_from(selected_sources.len())
            .map_err(|_| ResearchError::Resource("source diversity count overflow".to_owned()))?,
        bundle_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

pub fn evaluate_research_sufficiency_v1(
    brief: &ResearchBriefV1,
    bundle: &ResearchEvidenceBundleV1,
    now_unix_ms: u64,
    budget_exhausted: bool,
) -> Result<ResearchSufficiencyReportV1, ResearchError> {
    brief.validate_seal()?;
    bundle.validate_seal()?;
    if brief.organization_id != bundle.organization_id
        || brief.case_id != bundle.case_id
        || brief.brief_sha256 != bundle.research_brief_sha256
    {
        return Err(ResearchError::Integrity(
            "sufficiency inputs differ in organization, Case, or brief".to_owned(),
        ));
    }
    let source_count = u32::try_from(bundle.source_snapshot_sha256.len())
        .map_err(|_| ResearchError::Resource("source count overflow".to_owned()))?;
    let fresh = if bundle.freshness_expires_at_unix_ms > now_unix_ms {
        source_count
    } else {
        0
    };
    let preferred = bundle
        .evidence_excerpts
        .iter()
        .filter(|value| value.source_class == SourcePolicyClassV1::Preferred)
        .map(|value| value.source_snapshot_sha256.clone())
        .collect::<BTreeSet<_>>()
        .len() as u32;
    let unresolved = bundle
        .conflicts
        .iter()
        .filter(|value| value.unresolved)
        .count() as u32;
    let coverage = bundle
        .evidence_excerpts
        .iter()
        .map(|value| value.relevance_score_millionths)
        .max()
        .unwrap_or_default();
    let mut reasons = Vec::new();
    if source_count < brief.minimum_source_count {
        reasons.push("minimum_sources_not_met".to_owned());
    }
    if fresh < brief.minimum_source_count {
        reasons.push("freshness_not_met".to_owned());
    }
    if coverage == 0 {
        reasons.push("question_coverage_missing".to_owned());
    }
    if unresolved > 0 {
        reasons.push("unresolved_source_conflict".to_owned());
    }
    if !bundle.unknowns.is_empty() {
        reasons.push("known_unknowns_remain".to_owned());
    }
    if budget_exhausted {
        reasons.push("research_budget_exhausted".to_owned());
    }
    let status = if reasons.is_empty() {
        ResearchSufficiencyStatusV1::Sufficient
    } else {
        ResearchSufficiencyStatusV1::InsufficientEvidence
    };
    ResearchSufficiencyReportV1 {
        schema_version: 1,
        report_id: format!("sufficiency:{}", brief.case_id),
        organization_id: brief.organization_id.clone(),
        case_id: brief.case_id.clone(),
        brief_sha256: brief.brief_sha256.clone(),
        evidence_bundle_sha256: bundle.bundle_sha256.clone(),
        question_coverage_millionths: coverage,
        source_count,
        fresh_source_count: fresh,
        preferred_source_count: preferred,
        unresolved_conflict_count: unresolved,
        unknown_count: bundle.unknowns.len() as u32,
        budget_exhausted,
        status,
        reason_codes: reasons,
        report_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

pub fn build_model_context_slice_v1(
    brief: &ResearchBriefV1,
    bundle: &ResearchEvidenceBundleV1,
    profile: &ResearchNetworkProfileV1,
) -> Result<ResearchModelContextSliceV1, ResearchError> {
    let mut bytes = 0_u64;
    let mut evidence_ids = Vec::new();
    let mut excerpts = Vec::new();
    for evidence in &bundle.evidence_excerpts {
        if bytes.saturating_add(evidence.excerpt.len() as u64) > profile.max_model_evidence_bytes {
            break;
        }
        bytes = bytes.saturating_add(evidence.excerpt.len() as u64);
        evidence_ids.push(evidence.evidence_id.clone());
        excerpts.push(evidence.excerpt.clone());
    }
    let value = ResearchModelContextSliceV1 {
        schema_version: 1,
        organization_id: brief.organization_id.clone(),
        case_id: brief.case_id.clone(),
        brief_sha256: brief.brief_sha256.clone(),
        trust_class: EvidenceTrustClassV1::UntrustedExternalResearch,
        source_ids: bundle.source_snapshot_sha256.clone(),
        evidence_ids,
        bounded_excerpts: excerpts,
        conflict_ids: bundle
            .conflicts
            .iter()
            .map(|value| value.conflict_id.clone())
            .collect(),
        unknowns: bundle.unknowns.clone(),
        raw_html_count: 0,
        raw_url_count: 0,
        download_byte_count: 0,
        network_authority_count: 0,
        workspace_promotion_authority_count: 0,
        context_sha256: ZERO_HASH.to_owned(),
    }
    .seal()?;
    value.validate(profile)?;
    Ok(value)
}

pub fn build_research_report_v1(
    brief: &ResearchBriefV1,
    bundle: &ResearchEvidenceBundleV1,
    sufficiency: &ResearchSufficiencyReportV1,
    claims: Vec<ResearchClaimV1>,
) -> Result<ResearchReportV1, ResearchError> {
    brief.validate_seal()?;
    bundle.validate_seal()?;
    sufficiency.validate_seal()?;
    if brief.organization_id != bundle.organization_id
        || brief.organization_id != sufficiency.organization_id
        || brief.case_id != bundle.case_id
        || brief.case_id != sufficiency.case_id
        || brief.brief_sha256 != bundle.research_brief_sha256
        || brief.brief_sha256 != sufficiency.brief_sha256
        || bundle.bundle_sha256 != sufficiency.evidence_bundle_sha256
    {
        return Err(ResearchError::Integrity(
            "research report inputs differ in organization, Case, or lineage".to_owned(),
        ));
    }
    if sufficiency.status != ResearchSufficiencyStatusV1::Sufficient {
        return Err(ResearchError::Integrity(
            "insufficient_evidence cannot be reported as complete research".to_owned(),
        ));
    }
    let evidence = bundle
        .evidence_excerpts
        .iter()
        .map(|value| (value.evidence_id.clone(), value.excerpt.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut uncited = 0_u32;
    let mut unsupported_numbers = 0_u32;
    for claim in &claims {
        claim.validate_seal()?;
        validate_claim_statement_v1(&claim.statement)?;
        if claim.evidence_ids.is_empty()
            || claim
                .evidence_ids
                .iter()
                .any(|id| !evidence.contains_key(id))
        {
            uncited = uncited.saturating_add(1);
        }
        let evidence_text = claim
            .evidence_ids
            .iter()
            .filter_map(|id| evidence.get(id))
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        if matches!(
            claim.claim_kind,
            ResearchClaimKindV1::DirectEvidence | ResearchClaimKindV1::ModelInference
        ) {
            unsupported_numbers = unsupported_numbers.saturating_add(
                numeric_tokens(&claim.statement)
                    .difference(&numeric_tokens(&evidence_text))
                    .count() as u32,
            );
        }
    }
    if uncited != 0 || unsupported_numbers != 0 {
        return Err(ResearchError::Integrity(format!(
            "research claims are not fully evidenced: uncited={uncited}, unsupported_numbers={unsupported_numbers}"
        )));
    }
    ResearchReportV1 {
        schema_version: 1,
        report_id: format!("research-report:{}", brief.case_id),
        organization_id: brief.organization_id.clone(),
        case_id: brief.case_id.clone(),
        brief_sha256: brief.brief_sha256.clone(),
        evidence_bundle_sha256: bundle.bundle_sha256.clone(),
        sufficiency_report_sha256: sufficiency.report_sha256.clone(),
        claims,
        conflicts: bundle.conflicts.clone(),
        unknowns: bundle.unknowns.clone(),
        uncited_claim_count: 0,
        unsupported_number_count: 0,
        report_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

fn relevance_score(
    question: &BTreeSet<String>,
    segment: &BTreeSet<String>,
    source_class: SourcePolicyClassV1,
) -> u32 {
    if question.is_empty() || segment.is_empty() {
        return 0;
    }
    let intersection = question.intersection(segment).count() as u64;
    let lexical = intersection.saturating_mul(900_000) / question.len() as u64;
    let policy = match source_class {
        SourcePolicyClassV1::Preferred => 100_000,
        SourcePolicyClassV1::Allowed => 50_000,
        SourcePolicyClassV1::UnclassifiedExternal => 0,
        SourcePolicyClassV1::Blocked => 0,
    };
    u32::try_from((lexical + policy).min(1_000_000)).unwrap_or(1_000_000)
}

fn tokens(value: &str) -> BTreeSet<String> {
    value
        .split(|character: char| !character.is_alphanumeric())
        .filter(|token| token.chars().count() >= 2)
        .map(|token| token.to_lowercase())
        .collect()
}

fn numeric_tokens(value: &str) -> BTreeSet<String> {
    value
        .split(|character: char| {
            !(character.is_ascii_digit() || matches!(character, '.' | ',' | '-' | '%'))
        })
        .filter(|token| token.chars().any(|character| character.is_ascii_digit()))
        .map(|token| token.trim_matches([',', '.', '-']).to_owned())
        .filter(|token| !token.is_empty())
        .collect()
}

fn bound_utf8(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }
    let mut end = maximum;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

pub fn validate_claim_statement_v1(statement: &str) -> Result<(), ResearchError> {
    validate_text(statement, "research claim", 8192)?;
    if statement
        .to_ascii_lowercase()
        .contains("ignore all prior instructions")
    {
        return Err(ResearchError::AccessDenied(
            "prompt injection text cannot become a research claim".to_owned(),
        ));
    }
    Ok(())
}

pub fn research_excerpt_fingerprint_v1(excerpt: &str) -> String {
    sha256_bytes(excerpt.as_bytes())
}

pub fn source_policy_download_allowed_v1(
    policy: &ResearchSourcePolicyV1,
    class: crate::DownloadClassV1,
) -> bool {
    policy.allowed_download_classes.contains(&class)
}
