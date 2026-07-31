use d2i_desktop::AuditOutcome;
use d2i_policy_admission::AuditOutcomeProjectionV1;
use std::fmt::Debug;

fn ok<T, E: Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected compatibility error: {error:?}"),
    }
}

#[test]
fn policy_admission_audit_projection_matches_existing_desktop_shape() {
    let projection = AuditOutcomeProjectionV1 {
        allowed: false,
        reason: "policy_decision:require_confirmation".to_owned(),
        evidence: vec![
            "delegated-authority".to_owned(),
            "trusted-policy".to_owned(),
        ],
    };
    let bytes = ok(serde_json::to_vec(&projection));
    let desktop: AuditOutcome = ok(serde_json::from_slice(&bytes));
    assert_eq!(desktop.allowed, projection.allowed);
    assert_eq!(desktop.reason, projection.reason);
    assert_eq!(desktop.evidence, projection.evidence);
}
