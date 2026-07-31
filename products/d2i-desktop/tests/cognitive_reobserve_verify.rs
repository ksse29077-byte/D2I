#![cfg(windows)]

use d2i_cognitive_ir::{
    ActionProposal, CognitiveRiskClass, ComparisonOp, ConfirmationRequirement, ObservableElement,
    ObservationSnapshot, ObservationSourceKind, Postcondition, Provenance, RedactionMetadata,
    Reversibility, TrustLabel,
};
use d2i_desktop::{
    analyze_observation_delta, parse_reobserve_json, trusted_execution_sha256,
    ObservationDeltaKindV1, ObservationDeltaV1, ProtectedInvariantSeverityV1, ProtectedInvariantV1,
    VerificationGuardFieldV1, VerificationGuardProfileV1, VerificationGuardTargetV1,
    COGNITIVE_REOBSERVE_VERIFIER_V2_SCHEMA,
};
use jsonschema::{Draft, JSONSchema};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;

fn ok<T, E: Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn digest(label: &str) -> String {
    ok(trusted_execution_sha256(&label))
}

fn snapshot(action: bool, protected: bool, sequence: u64) -> ObservationSnapshot {
    let labels = BTreeSet::from([TrustLabel::Fixture, TrustLabel::ObservedUiState]);
    let mut value = ObservationSnapshot {
        schema_version: 1,
        observation_id: format!("contract-observation-{sequence}"),
        source_kind: ObservationSourceKind::Fixture,
        target_binding: BTreeMap::from([("fixture".to_owned(), "krn-300".to_owned())]),
        state_hash: digest("empty"),
        sequence,
        trust_labels: labels.clone(),
        observable_elements: vec![
            ObservableElement {
                element_id: "action-state".to_owned(),
                kind: "boolean".to_owned(),
                label: "action state".to_owned(),
                value: Value::Bool(action),
                trust_labels: labels.clone(),
            },
            ObservableElement {
                element_id: "protected-state".to_owned(),
                kind: "boolean".to_owned(),
                label: "protected state".to_owned(),
                value: Value::Bool(protected),
                trust_labels: labels,
            },
        ],
        redactions: Vec::new(),
        provenance: Provenance {
            source: "bounded contract fixture".to_owned(),
            source_hash: digest("contract-source"),
            module_id: "krn-300-contract-test".to_owned(),
        },
    };
    value.state_hash = ok(value.compute_state_hash());
    ok(value.validate());
    value
}

fn proposal(source: &ObservationSnapshot) -> ActionProposal {
    let value = ActionProposal {
        schema_version: 1,
        proposal_id: "proposal-krn-300".to_owned(),
        goal_id: "goal-krn-300".to_owned(),
        plan_generation_id: "plan-krn-300".to_owned(),
        source_observation_hash: source.state_hash.clone(),
        capability_id: "fixture.set-state".to_owned(),
        semantic_target: "action-state".to_owned(),
        arguments: json!({"value": true}),
        preconditions: Vec::new(),
        expected_postconditions: vec![Postcondition {
            target_state: "element:action-state:value".to_owned(),
            op: ComparisonOp::Equals,
            expected_value: Value::Bool(true),
            required: true,
            timeout_ms: 1_000,
        }],
        risk: CognitiveRiskClass::Reversible,
        reversibility: Reversibility::Reversible,
        confirmation_requirement: ConfirmationRequirement::None,
        confidence: 1.0,
        evidence: vec!["fixture:proposal".to_owned()],
        valid_until_sequence: source.sequence,
    };
    ok(value.validate());
    value
}

fn profile(source: &ObservationSnapshot) -> VerificationGuardProfileV1 {
    ok(VerificationGuardProfileV1::new(
        "guard-krn-300".to_owned(),
        &proposal(source),
        source,
        vec![VerificationGuardTargetV1 {
            element_id: "action-state".to_owned(),
            field: VerificationGuardFieldV1::Value,
        }],
        Vec::new(),
        vec![ProtectedInvariantV1 {
            target: VerificationGuardTargetV1 {
                element_id: "protected-state".to_owned(),
                field: VerificationGuardFieldV1::Value,
            },
            expected_source_value_hash: ok(trusted_execution_sha256(&Value::Bool(false))),
            severity: ProtectedInvariantSeverityV1::Unsafe,
            reason_code: "protected-state-stable".to_owned(),
        }],
        Vec::new(),
        0,
        vec!["fixture:guard".to_owned()],
    ))
}

#[test]
fn schema_and_canonical_delta_contract_reject_unknown_fields_and_duplicate_json_keys() {
    let source = snapshot(false, false, 20);
    let fresh = snapshot(true, false, 21);
    let guard = profile(&source);
    let delta = ok(analyze_observation_delta(&source, &fresh, &guard));
    let schema_value: Value = ok(serde_json::from_str(COGNITIVE_REOBSERVE_VERIFIER_V2_SCHEMA));
    let schema = ok(JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema_value));
    assert!(schema.is_valid(&ok(serde_json::to_value(&guard))));
    assert!(schema.is_valid(&ok(serde_json::to_value(&delta))));

    let mut unknown = ok(serde_json::to_value(&delta));
    unknown
        .as_object_mut()
        .unwrap_or_else(|| panic!("delta must serialize as an object"))
        .insert("unknown".to_owned(), Value::Bool(true));
    assert!(!schema.is_valid(&unknown));

    let duplicated = br#"{
        "schema_version":1,
        "schema_version":1,
        "source_observation_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"
    }"#;
    assert!(parse_reobserve_json::<ObservationDeltaV1>(duplicated).is_err());
}

#[test]
fn protected_and_unexpected_changes_are_never_hidden_by_expected_success() {
    let source = snapshot(false, false, 20);
    let guard = profile(&source);
    let unsafe_fresh = snapshot(true, true, 21);
    let unsafe_delta = ok(analyze_observation_delta(&source, &unsafe_fresh, &guard));
    assert_eq!(unsafe_delta.expected_changes.len(), 1);
    assert_eq!(unsafe_delta.protected_invariant_violations.len(), 1);
    assert_eq!(unsafe_delta.security_relevant_changes.len(), 1);

    let mut added = snapshot(true, false, 21);
    added.observable_elements.push(ObservableElement {
        element_id: "unexpected-state".to_owned(),
        kind: "boolean".to_owned(),
        label: "unexpected state".to_owned(),
        value: Value::Bool(true),
        trust_labels: added.trust_labels.clone(),
    });
    added.state_hash = ok(added.compute_state_hash());
    let unexpected_delta = ok(analyze_observation_delta(&source, &added, &guard));
    assert_eq!(unexpected_delta.unexpected_changes.len(), 1);
    assert!(unexpected_delta.unexpected_limit_exceeded);
    assert!(!unexpected_delta.security_relevant_changes.is_empty());

    let mut removed = snapshot(true, false, 21);
    removed
        .observable_elements
        .retain(|element| element.element_id != "protected-state");
    removed.state_hash = ok(removed.compute_state_hash());
    let removed_delta = ok(analyze_observation_delta(&source, &removed, &guard));
    assert_eq!(removed_delta.protected_invariant_violations.len(), 1);
    assert!(!removed_delta.security_relevant_changes.is_empty());

    let mut trust_changed = snapshot(true, false, 21);
    trust_changed
        .observable_elements
        .iter_mut()
        .find(|element| element.element_id == "action-state")
        .unwrap_or_else(|| panic!("action-state disappeared"))
        .trust_labels
        .insert(TrustLabel::UntrustedWebContent);
    trust_changed.state_hash = ok(trust_changed.compute_state_hash());
    let trust_delta = ok(analyze_observation_delta(&source, &trust_changed, &guard));
    assert_eq!(trust_delta.expected_changes.len(), 1);
    assert_eq!(trust_delta.unexpected_changes.len(), 1);
    assert!(!trust_delta.security_relevant_changes.is_empty());

    let mut redacted = snapshot(true, false, 21);
    redacted.redactions.push(RedactionMetadata {
        field: "action-state.value".to_owned(),
        reason: "bounded fixture redaction".to_owned(),
        replacement_hash: digest("redacted-action-state"),
    });
    redacted.state_hash = ok(redacted.compute_state_hash());
    let redaction_delta = ok(analyze_observation_delta(&source, &redacted, &guard));
    assert!(redaction_delta
        .unexpected_changes
        .iter()
        .any(|change| change.kind == ObservationDeltaKindV1::RedactionChanged));
    assert!(!redaction_delta.security_relevant_changes.is_empty());
}

#[path = "trusted_execution.rs"]
mod trusted_execution_fixture;
