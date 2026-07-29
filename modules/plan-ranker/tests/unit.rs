use d2i_module_sdk::{canonical_sha256, InvocationContext, Module, ModuleErrorCode};
use d2i_plan_ranker::{
    GateResults, GateStatus, PlanRanker, PlanRankerInput, RankingCandidate, RankingOutcome,
};
use std::collections::BTreeSet;

fn context(labels: &[&str]) -> InvocationContext {
    let labels = labels
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<BTreeSet<_>>();
    InvocationContext {
        current_logical_tick: 1,
        current_observation_hash: Some(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        ),
        current_plan_generation_id: Some("plan-generation-1".to_owned()),
        allowed_trust_labels: labels.clone(),
        invocation_trust_labels: labels,
    }
}

fn passed_gates() -> GateResults {
    GateResults {
        policy: GateStatus::Passed,
        activation: GateStatus::Passed,
        binding: GateStatus::Passed,
        input_schema: GateStatus::Passed,
        output_schema: GateStatus::Passed,
        risk: GateStatus::Passed,
        side_effect: GateStatus::Passed,
        network: GateStatus::Passed,
        credential: GateStatus::Passed,
        capability: GateStatus::Passed,
        quality: GateStatus::Passed,
    }
}

fn candidate(index: u32, cost: u32, success: u32) -> RankingCandidate {
    RankingCandidate {
        candidate_id: format!("candidate-{index:02}"),
        candidate_hash: format!("sha256:{index:064x}"),
        capability_id: "desktop.read".to_owned(),
        capability_version: "1.0.0".to_owned(),
        input_schema_id: "desktop-read-input-v1".to_owned(),
        input_schema_version: 1,
        output_schema_id: "desktop-read-output-v1".to_owned(),
        output_schema_version: 1,
        normalized_cost_millionths: cost,
        success_likelihood_millionths: success,
        gate_results: passed_gates(),
        evidence_ids: vec![format!("evidence-{index:02}")],
    }
}

fn invoke(
    input: PlanRankerInput,
) -> d2i_module_sdk::ModuleOutput<d2i_plan_ranker::PlanRankerOutput> {
    match PlanRanker.invoke(input, &context(&["fixture"])) {
        Ok(output) => output,
        Err(error) => panic!("valid Plan Ranker invocation failed: {error}"),
    }
}

#[test]
fn ranks_by_cost_success_hash_and_rejects_non_passed_gates() {
    let mut rejected = candidate(4, 1, 1_000_000);
    rejected.gate_results.policy = GateStatus::Failed;
    rejected.gate_results.network = GateStatus::Unknown;
    let output = invoke(PlanRankerInput {
        schema_version: 1,
        candidates: vec![
            candidate(3, 100, 900),
            candidate(2, 100, 900),
            candidate(1, 50, 100),
            rejected,
        ],
    });

    assert_eq!(output.value.outcome, RankingOutcome::Ranked);
    assert_eq!(
        output.value.selected_candidate_id.as_deref(),
        Some("candidate-01")
    );
    let ranked_ids = output
        .value
        .ranked_candidates
        .iter()
        .map(|item| item.candidate_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        ranked_ids,
        vec!["candidate-01", "candidate-02", "candidate-03"]
    );
    assert_eq!(output.value.rejected_candidates.len(), 1);
    let reasons = &output.value.rejected_candidates[0].reasons;
    assert_eq!(reasons.len(), 2);
    assert_eq!(reasons[0].status, GateStatus::Failed);
    assert_eq!(reasons[1].status, GateStatus::Unknown);
    assert!(output.logical_operations <= 4_096);
}

#[test]
fn reordered_input_has_identical_output_and_hash() {
    let first = invoke(PlanRankerInput {
        schema_version: 1,
        candidates: vec![
            candidate(3, 100, 700),
            candidate(1, 100, 900),
            candidate(2, 100, 900),
        ],
    });
    let second = invoke(PlanRankerInput {
        schema_version: 1,
        candidates: vec![
            candidate(2, 100, 900),
            candidate(3, 100, 700),
            candidate(1, 100, 900),
        ],
    });

    assert_eq!(first.value, second.value);
    assert_eq!(
        canonical_sha256(&first.value),
        canonical_sha256(&second.value)
    );
}

#[test]
fn duplicate_identity_empty_input_and_untrusted_authority_fail_closed() {
    let duplicate = candidate(1, 1, 1);
    let duplicate_error = PlanRanker
        .validate_input(
            &PlanRankerInput {
                schema_version: 1,
                candidates: vec![duplicate.clone(), duplicate],
            },
            &context(&["fixture"]),
        )
        .err()
        .map(|error| error.code);
    assert_eq!(duplicate_error, Some(ModuleErrorCode::InvalidInput));

    let empty_error = PlanRanker
        .validate_input(
            &PlanRankerInput {
                schema_version: 1,
                candidates: Vec::new(),
            },
            &context(&["fixture"]),
        )
        .err()
        .map(|error| error.code);
    assert_eq!(empty_error, Some(ModuleErrorCode::UnsupportedInput));

    let trust_error = PlanRanker
        .validate_input(
            &PlanRankerInput {
                schema_version: 1,
                candidates: vec![candidate(1, 1, 1)],
            },
            &context(&["untrusted_web_content"]),
        )
        .err()
        .map(|error| error.code);
    assert_eq!(trust_error, Some(ModuleErrorCode::UntrustedInputViolation));
}

#[test]
fn all_rejected_is_a_successful_no_eligible_metadata_result() {
    let mut policy_failed = candidate(2, 100, 900);
    policy_failed.gate_results.policy = GateStatus::Failed;
    let mut quality_unknown = candidate(1, 10, 900);
    quality_unknown.gate_results.quality = GateStatus::Unknown;

    let output = invoke(PlanRankerInput {
        schema_version: 1,
        candidates: vec![policy_failed, quality_unknown],
    });
    assert_eq!(output.value.outcome, RankingOutcome::NoEligibleCandidate);
    assert!(output.value.selected_candidate_id.is_none());
    assert!(output.value.selected_candidate_hash.is_none());
    assert!(output.value.ranked_candidates.is_empty());
    assert_eq!(output.value.rejected_candidates.len(), 2);
}

#[test]
fn maximum_candidate_set_stays_within_logical_operation_budget() {
    let candidates = (1..=64)
        .rev()
        .map(|index| candidate(index, 1_000_000 - index, index))
        .collect();
    let output = invoke(PlanRankerInput {
        schema_version: 1,
        candidates,
    });
    assert_eq!(output.value.ranked_candidates.len(), 64);
    assert!(output.logical_operations <= 4_096);
}
