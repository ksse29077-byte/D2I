use crate::{
    BoundActionExecutionV2, DesktopError, FreshObservationProofV1, ObservationDeltaV1,
    ReobservationRequestV1, TrustedActionExecutionReceiptV1, VerificationGuardProfileV1,
    VerificationRequestV2, VerificationResultV2, VerificationVerdictV2, VerifiedActionResultV1,
};
use d2i_semantic_experience::{
    compile_semantic_experience, SemanticExperienceCompileRequestV1, SemanticExperienceError,
    SemanticExperienceOutcomeV1, SemanticExperienceV1,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Organization/Role/Case bindings supplied by the authoritative Workforce
/// layer. Only their digests enter semantic experience output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopSemanticExperienceBindingV1 {
    pub organization_binding_sha256: String,
    pub role_binding_sha256: String,
    pub case_binding_sha256: String,
}

/// Borrowed proof chain required to compile one desktop semantic experience.
/// This type carries no persistence, model, adapter, or execution handle.
pub struct VerifiedDesktopSemanticExperienceRequestV1<'a> {
    pub binding: &'a DesktopSemanticExperienceBindingV1,
    pub execution_receipt: &'a TrustedActionExecutionReceiptV1,
    pub bound_execution: &'a BoundActionExecutionV2,
    pub reobservation_request: &'a ReobservationRequestV1,
    pub fresh_observation_proof: &'a FreshObservationProofV1,
    pub verification_request: &'a VerificationRequestV2,
    pub verification_result: &'a VerificationResultV2,
    pub guard_profile: &'a VerificationGuardProfileV1,
    pub observation_delta: &'a ObservationDeltaV1,
    pub verified_action_result: &'a VerifiedActionResultV1,
}

/// Revalidates the complete execution/re-observation/verification chain and
/// compiles a non-authoritative, offline-only semantic experience.
pub fn compile_verified_desktop_semantic_experience(
    request: VerifiedDesktopSemanticExperienceRequestV1<'_>,
) -> Result<SemanticExperienceV1, DesktopError> {
    request
        .execution_receipt
        .validate()
        .map_err(|error| DesktopError::Integrity(error.to_string()))?;
    request.bound_execution.validate()?;
    request.verification_request.validate()?;
    request
        .verification_result
        .validate_against(request.verification_request)?;
    request.fresh_observation_proof.validate_against(
        request.reobservation_request,
        &request.verification_request.source_observation,
        &request.verification_request.fresh_observation,
    )?;
    request.observation_delta.validate()?;
    request.verified_action_result.validate_against(
        request.execution_receipt,
        request.bound_execution,
        request.reobservation_request,
        request.fresh_observation_proof,
        request.verification_request,
        request.verification_result,
        request.guard_profile,
        request.observation_delta,
    )?;
    if request.execution_receipt.execution_id != request.bound_execution.execution_id
        || request.execution_receipt.source_observation_id
            != request
                .verification_request
                .source_observation
                .observation_id
        || request.execution_receipt.source_observation_hash
            != request.verification_request.source_observation.state_hash
        || request.execution_receipt.source_observation_sequence
            != request.verification_request.source_observation.sequence
    {
        return Err(DesktopError::Integrity(
            "semantic experience receipt differs from the verified execution".to_owned(),
        ));
    }

    let selected_element_ids =
        selected_context_ids(request.guard_profile, request.observation_delta);
    let evidence_hashes = vec![
        request.execution_receipt.receipt_sha256.clone(),
        request.reobservation_request.request_sha256.clone(),
        request.fresh_observation_proof.proof_sha256.clone(),
        request.verification_request.canonical_hash()?,
        request
            .verification_result
            .canonical_hash_against(request.verification_request)?,
        request.guard_profile.profile_sha256.clone(),
        request.observation_delta.delta_sha256.clone(),
        request.verified_action_result.result_sha256.clone(),
    ];
    compile_semantic_experience(SemanticExperienceCompileRequestV1 {
        organization_binding_sha256: &request.binding.organization_binding_sha256,
        role_binding_sha256: &request.binding.role_binding_sha256,
        case_binding_sha256: &request.binding.case_binding_sha256,
        source_observation: &request.verification_request.source_observation,
        fresh_observation: &request.verification_request.fresh_observation,
        selected_element_ids,
        execution_receipt_sha256: &request.execution_receipt.receipt_sha256,
        execution_id: &request.execution_receipt.execution_id,
        capability_id: &request.execution_receipt.capability_id,
        operator_binding_sha256: &request.execution_receipt.desktop_operation_sha256,
        semantic_target_id: &request.execution_receipt.semantic_target_id,
        completed_at_unix_ms: request.execution_receipt.completed_at_unix_ms,
        outcome: project_outcome(request.verification_result.action_verdict),
        verification_result_sha256: &request.verified_action_result.verification_result_sha256,
        verified_action_result_sha256: &request.verified_action_result.result_sha256,
        evidence_hashes,
    })
    .map_err(map_semantic_error)
}

fn selected_context_ids(
    guard: &VerificationGuardProfileV1,
    delta: &ObservationDeltaV1,
) -> Vec<String> {
    let mut ids = BTreeSet::new();
    ids.extend(
        guard
            .expected_change_targets
            .iter()
            .chain(&guard.allowed_change_targets)
            .map(|target| target.element_id.clone()),
    );
    ids.extend(
        guard
            .protected_invariants
            .iter()
            .map(|invariant| invariant.target.element_id.clone()),
    );
    for change in delta
        .expected_changes
        .iter()
        .chain(&delta.allowed_changes)
        .chain(&delta.protected_invariant_violations)
        .chain(&delta.unexpected_changes)
        .chain(&delta.security_relevant_changes)
    {
        if let Some(target) = &change.target {
            ids.insert(target.element_id.clone());
        }
    }
    ids.into_iter().collect()
}

fn project_outcome(verdict: VerificationVerdictV2) -> SemanticExperienceOutcomeV1 {
    match verdict {
        VerificationVerdictV2::Passed => SemanticExperienceOutcomeV1::Passed,
        VerificationVerdictV2::Failed => SemanticExperienceOutcomeV1::Failed,
        VerificationVerdictV2::Inconclusive => SemanticExperienceOutcomeV1::Inconclusive,
        VerificationVerdictV2::Unsupported => SemanticExperienceOutcomeV1::Unsupported,
        VerificationVerdictV2::Unsafe => SemanticExperienceOutcomeV1::Unsafe,
    }
}

fn map_semantic_error(error: SemanticExperienceError) -> DesktopError {
    match error {
        SemanticExperienceError::Invalid(message)
        | SemanticExperienceError::ResourceLimit(message) => DesktopError::Invalid(message),
        SemanticExperienceError::Integrity(message) => DesktopError::Integrity(message),
        SemanticExperienceError::SensitiveContent(message) => DesktopError::AccessDenied(message),
        SemanticExperienceError::Unsupported(message) => DesktopError::AdapterUnavailable(message),
        SemanticExperienceError::Json(message) => DesktopError::Json(message),
    }
}
