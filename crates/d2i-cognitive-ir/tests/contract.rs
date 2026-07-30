use d2i_cognitive_ir::{
    CognitiveRiskClass, ComparisonOp, ConfirmationPolicy, GoalSpec, Postcondition, Provenance,
    WorkReport, COGNITIVE_IR_V1_SCHEMA,
};
use jsonschema::{Draft, JSONSchema};
use serde_json::{json, Value};
use std::collections::BTreeMap;

fn goal() -> GoalSpec {
    GoalSpec {
        schema_version: 1,
        goal_id: "goal-1".to_owned(),
        objective: "verify the pure contract".to_owned(),
        scope: BTreeMap::from([("surface".to_owned(), json!("fixture"))]),
        required_outcomes: vec!["contract remains compatible".to_owned()],
        constraints: vec!["no side effects".to_owned()],
        success_criteria: vec![Postcondition {
            target_state: "contract.valid".to_owned(),
            op: ComparisonOp::Equals,
            expected_value: json!(true),
            required: true,
            timeout_ms: 1_000,
        }],
        risk_class: CognitiveRiskClass::ReadOnly,
        confirmation_policy: ConfirmationPolicy::Never,
        provenance: Provenance {
            source: "fixture".to_owned(),
            source_hash: format!("sha256:{}", "11".repeat(32)),
            module_id: "cognitive-ir-test".to_owned(),
        },
    }
}

#[test]
fn goal_spec_matches_authoritative_schema_definition() {
    let schema: Value = match serde_json::from_str(COGNITIVE_IR_V1_SCHEMA) {
        Ok(schema) => schema,
        Err(error) => panic!("authoritative schema is invalid JSON: {error}"),
    };
    let wrapper = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/$defs/goal_spec",
        "$defs": schema["$defs"].clone()
    });
    let validator = match JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&wrapper)
    {
        Ok(validator) => validator,
        Err(error) => panic!("GoalSpec schema did not compile: {error}"),
    };
    let value = match serde_json::to_value(goal()) {
        Ok(value) => value,
        Err(error) => panic!("GoalSpec did not serialize: {error}"),
    };
    assert!(validator.is_valid(&value));
    let round_trip: GoalSpec = match serde_json::from_value(value) {
        Ok(value) => value,
        Err(error) => panic!("GoalSpec did not deserialize: {error}"),
    };
    assert!(round_trip.validate().is_ok());
}

#[test]
fn validation_and_unknown_field_behavior_remain_fail_closed() {
    let mut invalid = goal();
    invalid.schema_version = 2;
    assert!(invalid.validate().is_err());

    let mut value = match serde_json::to_value(goal()) {
        Ok(value) => value,
        Err(error) => panic!("GoalSpec did not serialize: {error}"),
    };
    value["unexpected"] = json!(true);
    assert!(serde_json::from_value::<GoalSpec>(value).is_err());
}

#[test]
fn work_report_hash_is_stable_and_compatible() {
    let report = WorkReport {
        schema_version: 1,
        confirmed_facts: vec!["ready".to_owned()],
        completed_actions: Vec::new(),
        incomplete_items: Vec::new(),
        opinions: Vec::new(),
        opinion_basis: Vec::new(),
        uncertainties: Vec::new(),
        user_decision_required: false,
        build_id: "build-1".to_owned(),
        module_ids: vec!["module-1".to_owned()],
        timings: Vec::new(),
        warnings: Vec::new(),
    };
    assert_eq!(
        report.report_hash().ok().as_deref(),
        Some("sha256:24e9f2c58713b185c7f03592c53f6b49a40cce2715d9f88628efb0795a428c6a")
    );
}
