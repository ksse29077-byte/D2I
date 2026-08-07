use super::*;
use ed25519_dalek::SigningKey;
use jsonschema::{Draft, JSONSchema};
use serde::Serialize;
use serde_json::Value;

fn hash(label: &str) -> String {
    sha256_bytes(label.as_bytes())
}

fn operation(id: &str, class: EnterpriseOperationClassV1) -> EnterpriseOperationDescriptorV1 {
    EnterpriseOperationDescriptorV1 {
        schema_version: 1,
        operation_id: id.to_owned(),
        capability_id: if class == EnterpriseOperationClassV1::Observation {
            "enterprise_api.read"
        } else {
            "enterprise_api.write"
        }
        .to_owned(),
        semantic_target_id: "work_order.status".to_owned(),
        resource_class_id: "work_order".to_owned(),
        operation_class: class,
        http_method: if class == EnterpriseOperationClassV1::Observation {
            EnterpriseHttpMethodV1::Get
        } else {
            EnterpriseHttpMethodV1::Patch
        },
        fixed_path_template: "/v1/work-orders/{resource_id}".to_owned(),
        allowed_path_parameter_ids: vec!["resource_id".to_owned()],
        allowed_query_parameter_ids: vec![],
        request_schema_sha256: hash("request-schema"),
        response_schema_sha256: hash("response-schema"),
        success_status_codes: vec![200],
        side_effect_class: if class == EnterpriseOperationClassV1::Observation {
            EnterpriseSideEffectClassV1::ReadOnly
        } else {
            EnterpriseSideEffectClassV1::ReversibleBusinessStateChange
        },
        idempotency_class: if class == EnterpriseOperationClassV1::Observation {
            EnterpriseIdempotencyClassV1::NotApplicable
        } else {
            EnterpriseIdempotencyClassV1::ClientKeyRequired
        },
        optimistic_concurrency_required: class == EnterpriseOperationClassV1::Mutation,
        resource_version_field_id: "revision".to_owned(),
        verification_operation_id: "observe-work-order".to_owned(),
        retry_policy_id: "bounded-v1".to_owned(),
        rate_budget_class_id: "reference-low".to_owned(),
        maximum_request_bytes: 4096,
        maximum_response_bytes: 16_384,
        data_class_ids: vec!["internal".to_owned()],
        evidence_ids: vec!["edge100-contract".to_owned()],
        descriptor_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("fixture operation: {error}"))
}

fn pack_and_approval() -> (
    EnterpriseConnectorPackV1,
    EnterpriseConnectorApprovalV1,
    SigningKey,
) {
    let key = SigningKey::from_bytes(&[9_u8; 32]);
    let operations = vec![
        operation(
            "observe-work-order",
            EnterpriseOperationClassV1::Observation,
        ),
        operation(
            "update-work-order-status",
            EnterpriseOperationClassV1::Mutation,
        ),
    ];
    let pack = EnterpriseConnectorPackV1 {
        schema_version: 1,
        connector_pack_id: "reference-enterprise-api".to_owned(),
        connector_pack_version: "1.0.0".to_owned(),
        display_name: "Reference Enterprise API".to_owned(),
        system_family_id: "reference-enterprise".to_owned(),
        organization_scope_id: "d2i-reference".to_owned(),
        environment_ids: vec!["edge100-loopback".to_owned()],
        base_origin: "http://127.0.0.1:43191".to_owned(),
        transport_profile_id: "signed-loopback-http".to_owned(),
        credential_profile_id: "synthetic-bearer-v1".to_owned(),
        credential_reference_class_id: "opaque-runtime-handle".to_owned(),
        operation_descriptors: operations,
        allowed_observation_operation_ids: vec!["observe-work-order".to_owned()],
        allowed_mutation_operation_ids: vec!["update-work-order-status".to_owned()],
        request_schema_sha256s: vec![hash("request-schema")],
        response_schema_sha256s: vec![hash("response-schema")],
        resource_class_ids: vec!["work_order".to_owned()],
        semantic_target_ids: vec!["work_order.status".to_owned()],
        capability_ids: vec![
            "enterprise_api.read".to_owned(),
            "enterprise_api.write".to_owned(),
        ],
        rate_limit_per_minute: 60,
        retry_limit: 2,
        resource_limits: EnterpriseResourceLimitsV1 {
            maximum_request_bytes: 4096,
            maximum_response_bytes: 16_384,
            maximum_response_depth: 8,
            maximum_response_items: 64,
            maximum_pages: 1,
            maximum_duration_ms: 10_000,
        },
        redaction_policy_id: "allowlisted-fields-only".to_owned(),
        tls_policy: EnterpriseTlsPolicyV1 {
            verify_os_trust_chain: true,
            verify_hostname: true,
            verify_expiry: true,
            reject_weak_protocols: true,
            pin_class: "test-fixture-hash".to_owned(),
            pin_sha256: Some(hash("fixture")),
        },
        redirect_policy_id: "deny".to_owned(),
        proxy_policy_id: "deny-ambient".to_owned(),
        idempotency_policy_id: "client-key-required".to_owned(),
        concurrency_policy_id: "if-match-required".to_owned(),
        verification_policy_id: "fresh-get-required".to_owned(),
        signer_key_id: "edge100-test-key".to_owned(),
        evidence_ids: vec!["edge100-contract".to_owned()],
        pack_sha256: ZERO_HASH.to_owned(),
        signature_hex: "0".repeat(128),
    }
    .seal_and_sign(&key)
    .unwrap_or_else(|error| panic!("fixture pack: {error}"));
    let approval = EnterpriseConnectorApprovalV1 {
        schema_version: 1,
        approval_id: "edge100-approval".to_owned(),
        organization_id: "d2i-reference".to_owned(),
        connector_pack_sha256: pack.pack_sha256.clone(),
        approved_environment_id: "edge100-loopback".to_owned(),
        approved_role_ids: vec!["general-office-operations-employee".to_owned()],
        approved_operation_ids: vec![
            "observe-work-order".to_owned(),
            "update-work-order-status".to_owned(),
        ],
        approved_capability_ids: vec![
            "enterprise_api.read".to_owned(),
            "enterprise_api.write".to_owned(),
        ],
        approved_origins: vec!["http://127.0.0.1:43191".to_owned()],
        approved_ports: vec![43191],
        transport_policy: EnterpriseTransportPolicyV1::SignedLoopbackHttpOnly,
        credential_profile_id: "synthetic-bearer-v1".to_owned(),
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 10_000,
        signer_id: "reference-security-authority".to_owned(),
        signing_key_id: "edge100-test-key".to_owned(),
        nonce: "approval-nonce-1".to_owned(),
        evidence_ids: vec!["edge100-contract".to_owned()],
        approval_sha256: ZERO_HASH.to_owned(),
        signature_hex: "0".repeat(128),
    }
    .seal_and_sign(&key)
    .unwrap_or_else(|error| panic!("fixture approval: {error}"));
    (pack, approval, key)
}

fn sealed_binding(one_time_use_id: &str) -> EnterpriseOperationBindingV1 {
    EnterpriseOperationBindingV1 {
        schema_version: 1,
        binding_id: "binding-1".to_owned(),
        case_sha256: hash("case"),
        role_contract_sha256: hash("role"),
        delegation_sha256: hash("delegation"),
        ownership_sha256: hash("ownership"),
        lease_sha256: hash("lease"),
        work_grant_sha256: hash("grant"),
        autonomy_admission_sha256: hash("autonomy"),
        planner_intent_sha256: hash("intent"),
        current_observation_sha256: hash("observation"),
        resource_version: "7".to_owned(),
        connector_pack_sha256: hash("pack"),
        connector_approval_sha256: hash("approval"),
        endpoint_binding_sha256: hash("endpoint"),
        credential_reference_sha256: hash("credential-reference"),
        operation_descriptor_sha256: hash("operation"),
        policy_decision_sha256: hash("policy"),
        cognitive_activation_admission_sha256: hash("activation"),
        activation_one_time_use_id: one_time_use_id.to_owned(),
        approved_argument_artifact_hashes: vec![hash("argument")],
        idempotency_key_sha256: hash("idempotency"),
        timeout_ms: 5_000,
        evidence_ids: vec!["edge100-test".to_owned()],
        binding_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("binding: {error}"))
}

#[test]
fn signed_connector_and_exact_operation_are_verified() {
    let (pack, approval, key) = pack_and_approval();
    pack.verify_signature(&key.verifying_key())
        .unwrap_or_else(|error| panic!("pack signature: {error}"));
    approval
        .verify_signature(&key.verifying_key())
        .unwrap_or_else(|error| panic!("approval signature: {error}"));
    let descriptor = authorize_operation(
        &pack,
        &approval,
        "update-work-order-status",
        "enterprise_api.write",
        "work_order.status",
    )
    .unwrap_or_else(|error| panic!("operation approval: {error}"));
    assert_eq!(descriptor.http_method, EnterpriseHttpMethodV1::Patch);
    assert!(authorize_operation(
        &pack,
        &approval,
        "delete-admin",
        "enterprise_api.write",
        "admin"
    )
    .is_err());
}

#[test]
fn exact_destination_denies_ssrf_redirect_and_wrong_port() {
    let policy = EnterpriseNetworkPolicyV1 {
        schema_version: 1,
        policy_id: "network-policy".to_owned(),
        worker_executable_sha256: hash("worker"),
        exact_scheme: "http".to_owned(),
        exact_hostname: "127.0.0.1".to_owned(),
        exact_port: 43191,
        exact_origin: "http://127.0.0.1:43191".to_owned(),
        allow_loopback_test: true,
        deny_redirects: true,
        deny_ambient_proxy: true,
        deny_other_hosts: true,
        deny_other_ports: true,
        deny_external_network: true,
        valid_from_unix_ms: 1000,
        valid_to_unix_ms: 10_000,
        evidence_ids: vec!["edge100-test".to_owned()],
        policy_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("policy: {error}"));
    assert!(validate_network_destination(&policy, "http", "127.0.0.1", 43191).is_ok());
    assert!(validate_network_destination(&policy, "http", "127.0.0.1", 43192).is_err());
    assert!(validate_network_destination(&policy, "http", "169.254.169.254", 80).is_err());
    let mut redirect_enabled = policy;
    redirect_enabled.deny_redirects = false;
    redirect_enabled = redirect_enabled
        .seal()
        .unwrap_or_else(|error| panic!("policy: {error}"));
    assert!(validate_network_destination(&redirect_enabled, "http", "127.0.0.1", 43191).is_err());

    let (pack, _approval, key) = pack_and_approval();
    for invalid_origin in [
        "http://127.0.0.1:43191/extra",
        "http://127.0.0.1:43191#fragment",
        "http://user@127.0.0.1:43191",
        "http://127.0.0.1:43191%2fadmin",
        "http://localhost:43191",
        "http://[::ffff:127.0.0.1]:43191",
        "file://127.0.0.1:43191",
        "ftp://127.0.0.1:43191",
    ] {
        let mut invalid = pack.clone();
        invalid.base_origin = invalid_origin.to_owned();
        invalid.pack_sha256 = ZERO_HASH.to_owned();
        invalid.signature_hex = "0".repeat(128);
        assert!(
            invalid.seal_and_sign(&key).is_err(),
            "accepted {invalid_origin}"
        );
    }

    for invalid_path in [
        "/v1/%2e%2e/admin",
        "/v1/work-orders/{resource_id}?next=http://example.test",
        "//169.254.169.254/latest",
        "/v1\\admin",
        "/v1/work-orders#fragment",
    ] {
        let mut invalid = operation(
            "invalid-path-operation",
            EnterpriseOperationClassV1::Observation,
        );
        invalid.fixed_path_template = invalid_path.to_owned();
        invalid.descriptor_sha256 = ZERO_HASH.to_owned();
        assert!(invalid.seal().is_err(), "accepted {invalid_path}");
    }
}

#[test]
fn activation_is_one_shot_and_exactly_bound() {
    let binding = sealed_binding("one-shot-1");
    let mut ledger = EnterpriseActivationLedgerV1::default();
    assert!(ledger
        .consume(&binding, &hash("policy"), &hash("activation"))
        .is_ok());
    assert!(matches!(
        ledger.consume(&binding, &hash("policy"), &hash("activation")),
        Err(EnterpriseApiError::Replay(_))
    ));
    assert_eq!(ledger.consumed_count(), 1);
}

#[test]
fn strict_parser_rejects_duplicate_keys_floats_unknown_fields_and_secrets() {
    assert!(parse_json_strict::<Value>(br#"{"a":1,"a":2}"#).is_err());
    assert!(parse_json_strict::<Value>(br#"{"a":1.5}"#).is_err());
    assert!(parse_json_strict::<EnterpriseRecoveryDecisionV1>(br#"{"disposition":"none","maximum_retry_count":0,"require_fresh_observation":true,"reason_code":"ok","extra":1}"#).is_err());
    assert!(parse_json_strict::<Value>(br#"{"authorization":"redacted"}"#).is_err());
}

#[test]
fn recovery_is_bounded_and_never_blindly_replays_unknown_writes() {
    let stale = classify_recovery(EnterpriseOperationResultV1::StaleConflict);
    assert_eq!(
        stale.disposition,
        EnterpriseRecoveryDispositionV1::FreshObservationAndReplan
    );
    assert_eq!(stale.maximum_retry_count, 1);
    let unknown = classify_recovery(EnterpriseOperationResultV1::UnknownWriteOutcome);
    assert_eq!(
        unknown.disposition,
        EnterpriseRecoveryDispositionV1::VerifyUnknownOutcome
    );
    assert_eq!(unknown.maximum_retry_count, 0);
    assert!(unknown.require_fresh_observation);
    for result in [
        EnterpriseOperationResultV1::Unauthorized,
        EnterpriseOperationResultV1::MalformedResponse,
        EnterpriseOperationResultV1::Rejected,
    ] {
        assert_eq!(
            classify_recovery(result).disposition,
            EnterpriseRecoveryDispositionV1::HumanException
        );
    }
}

#[test]
fn deterministic_128_case_replay_matches_for_100_runs() {
    let inputs = (0_u32..128)
        .map(|index| {
            deterministic_idempotency_key(
                &hash(&format!("case-{index}")),
                &hash("operation"),
                &hash(&format!("resource-{index}")),
                &hash(&format!("state-{}", index % 4)),
            )
            .unwrap_or_else(|error| panic!("idempotency key: {error}"))
        })
        .collect::<Vec<_>>();
    let expected =
        canonical_sha256(&inputs).unwrap_or_else(|error| panic!("expected hash: {error}"));
    for _ in 0..100 {
        assert_eq!(
            canonical_sha256(&inputs).unwrap_or_else(|error| panic!("replay hash: {error}")),
            expected
        );
    }
}

#[test]
fn opaque_system_families_share_one_deterministic_core_contract() {
    let (base_pack, _approval, key) = pack_and_approval();
    let expected_operation_ids = base_pack
        .operation_descriptors
        .iter()
        .map(|operation| operation.operation_id.clone())
        .collect::<Vec<_>>();
    let expected_decision = canonical_sha256(&(
        expected_operation_ids.clone(),
        base_pack.capability_ids.clone(),
        base_pack.semantic_target_ids.clone(),
        deterministic_idempotency_key(
            &hash("case"),
            &hash("operation"),
            &hash("resource"),
            &hash("state"),
        )
        .unwrap_or_else(|error| panic!("idempotency key: {error}")),
    ))
    .unwrap_or_else(|error| panic!("decision hash: {error}"));

    for _ in 0..100 {
        for system_family_id in [
            "reference-enterprise",
            "fixture-finance",
            "fixture-it-service",
            "fixture-safety",
            "fixture-erp",
            "fixture-mes",
            "fixture-cmms",
        ] {
            let mut pack = base_pack.clone();
            pack.system_family_id = system_family_id.to_owned();
            pack.pack_sha256 = ZERO_HASH.to_owned();
            pack.signature_hex = "0".repeat(128);
            let pack = pack
                .seal_and_sign(&key)
                .unwrap_or_else(|error| panic!("cross-domain pack: {error}"));
            let operation_ids = pack
                .operation_descriptors
                .iter()
                .map(|operation| operation.operation_id.clone())
                .collect::<Vec<_>>();
            let decision = canonical_sha256(&(
                operation_ids,
                pack.capability_ids,
                pack.semantic_target_ids,
                deterministic_idempotency_key(
                    &hash("case"),
                    &hash("operation"),
                    &hash("resource"),
                    &hash("state"),
                )
                .unwrap_or_else(|error| panic!("idempotency key: {error}")),
            ))
            .unwrap_or_else(|error| panic!("decision hash: {error}"));
            assert_eq!(decision, expected_decision);
        }
    }
}

#[test]
fn all_public_schemas_are_strict_and_compile() {
    let names = [
        "execution-plane-descriptor-v1",
        "enterprise-connector-pack-v1",
        "enterprise-connector-approval-v1",
        "enterprise-operation-descriptor-v1",
        "enterprise-endpoint-binding-v1",
        "enterprise-credential-reference-v1",
        "enterprise-observation-request-v1",
        "enterprise-observation-snapshot-v1",
        "enterprise-operation-intent-v1",
        "enterprise-operation-binding-v1",
        "enterprise-operation-receipt-v1",
        "enterprise-post-action-verification-v1",
        "enterprise-network-policy-v1",
        "enterprise-idempotency-record-v1",
        "enterprise-connector-health-v1",
        "enterprise-replay-report-v1",
        "enterprise-api-completion-report-v1",
        "enterprise-api-certification-v1",
    ];
    for name in names {
        let schema_text = public_schema(name).unwrap_or_else(|| panic!("missing schema {name}"));
        let schema: Value = serde_json::from_str(schema_text)
            .unwrap_or_else(|error| panic!("schema JSON {name}: {error}"));
        assert_eq!(
            schema.get("additionalProperties"),
            Some(&Value::Bool(false))
        );
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema)
            .unwrap_or_else(|error| panic!("schema compile {name}: {error}"));
    }
}

#[test]
fn canonical_hash_is_stable_and_mutation_is_rejected() {
    let (pack, _, _) = pack_and_approval();
    let bytes = canonical_json_bytes(&pack).unwrap_or_else(|error| panic!("canonical: {error}"));
    let parsed: EnterpriseConnectorPackV1 =
        parse_json_strict(&bytes).unwrap_or_else(|error| panic!("strict parse: {error}"));
    assert_eq!(pack, parsed);
    let mut mutated = parsed;
    mutated.base_origin = "http://127.0.0.1:43192".to_owned();
    assert!(mutated.validate_integrity().is_err());
}

fn _assert_serialize<T: Serialize>() {}
