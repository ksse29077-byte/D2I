use d2i_embodied::{
    activate_certified_integration, certify_runtime_binding, check_integration_readiness,
    create_runtime_binding_evidence, initialize_activation_ledger, verify_activation_ledger,
    ActionKind, CallbackGroupContract, CallbackGroupKind, DeadlineClass, DurabilityPolicy,
    EndpointQos, ExecutorContract, ExecutorKind, HardwareIntegrationContract, HardwareProfile,
    HistoryPolicy, IntegrationManifest, LivelinessPolicy, NetworkPolicy,
    OfflineConformanceRos2Transport, ReliabilityPolicy, Ros2IntegrationContract, Ros2TopicMap,
    Ros2Transport, RuntimeBindingInput, RuntimeHardwareBinding, RuntimeRos2Binding,
    RuntimeSafetyBinding, RuntimeTopicBinding, SafetyIntegrationContract, SensorKind,
    TopicContract, TopicDirection,
};
use ed25519_dalek::SigningKey;
use jsonschema::{Draft, JSONSchema};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn ok<T, E: Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("test operation failed: {error:?}"),
    }
}

struct TempFile(PathBuf);

impl TempFile {
    fn new() -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "d2i-phase9-readiness-{}-{sequence}.json",
            std::process::id()
        )))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "d2i-phase9-activation-{}-{sequence}",
            std::process::id()
        )))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn qos() -> EndpointQos {
    EndpointQos {
        history: HistoryPolicy::KeepLast,
        depth: 8,
        reliability: ReliabilityPolicy::Reliable,
        durability: DurabilityPolicy::Volatile,
        deadline_nanos: 50_000_000,
        lifespan_nanos: 100_000_000,
        liveliness: LivelinessPolicy::Automatic,
        liveliness_lease_nanos: 500_000_000,
    }
}

fn topic(
    id: &str,
    name: &str,
    direction: TopicDirection,
    sensor_kind: Option<SensorKind>,
    callback_group_id: &str,
) -> TopicContract {
    TopicContract {
        contract_id: id.to_owned(),
        topic: name.to_owned(),
        direction,
        message_type: "d2i_msgs/msg/BoundedJson".to_owned(),
        message_type_hash: format!("sha256:{:064x}", id.len()),
        sensor_kind,
        deadline_class: DeadlineClass::Control,
        bypasses_d2i: false,
        callback_group_id: callback_group_id.to_owned(),
        adapter_qos: qos(),
        peer_qos: qos(),
    }
}

fn ready_manifest() -> IntegrationManifest {
    let topics = vec![
        topic(
            "lidar-input",
            "/robot_1/lidar",
            TopicDirection::Subscribe,
            Some(SensorKind::Lidar),
            "sensor-callbacks",
        ),
        topic(
            "action-output",
            "/robot_1/d2i/action_intent",
            TopicDirection::Publish,
            None,
            "output-callbacks",
        ),
        topic(
            "safety-output",
            "/robot_1/safety/assessment",
            TopicDirection::Publish,
            None,
            "output-callbacks",
        ),
    ];
    IntegrationManifest {
        schema_version: 1,
        integration_id: "warehouse-robot-1".to_owned(),
        owner: "robotics-platform".to_owned(),
        reviewed_at_unix_seconds: 1,
        package_signature_verifier: "offline-ed25519-verifier-v1".to_owned(),
        credential_provider: "robot-keystore-v1".to_owned(),
        binding_attestor_id: "integration-probe-v1".to_owned(),
        binding_attestor_public_key: signer_public_key(),
        ros2: Ros2IntegrationContract {
            distribution: "reviewed-distribution".to_owned(),
            version: "1.0.0".to_owned(),
            client_library: "reviewed-client".to_owned(),
            client_library_version: "1.0.0".to_owned(),
            rmw_implementation: "reviewed-rmw".to_owned(),
            domain_id: 42,
            node_name: "d2i_embodied".to_owned(),
            namespace: "/robot_1".to_owned(),
            network_policy: NetworkPolicy::LocalOnly,
            allowed_peers: BTreeSet::new(),
            topic_map: Ros2TopicMap {
                sensor_topics: BTreeMap::from([(SensorKind::Lidar, "/robot_1/lidar".to_owned())]),
                action_intent_topic: "/robot_1/d2i/action_intent".to_owned(),
                safety_assessment_topic: "/robot_1/safety/assessment".to_owned(),
            },
            topics,
            executor: ExecutorContract {
                kind: ExecutorKind::WaitSet,
                implementation: "reviewed-wait-set-v1".to_owned(),
                thread_count: 2,
                deterministic_ordering: true,
                bounded_callback_time: true,
                callback_groups: vec![
                    CallbackGroupContract {
                        callback_group_id: "sensor-callbacks".to_owned(),
                        kind: CallbackGroupKind::MutuallyExclusive,
                        dedicated_to_contract_ids: BTreeSet::from(["lidar-input".to_owned()]),
                        allows_blocking_calls: false,
                    },
                    CallbackGroupContract {
                        callback_group_id: "output-callbacks".to_owned(),
                        kind: CallbackGroupKind::MutuallyExclusive,
                        dedicated_to_contract_ids: BTreeSet::from([
                            "action-output".to_owned(),
                            "safety-output".to_owned(),
                        ]),
                        allows_blocking_calls: false,
                    },
                ],
                shutdown_timeout_millis: 1_000,
            },
        },
        safety: SafetyIntegrationContract {
            controller_id: "independent-safety-v1".to_owned(),
            protocol: "authenticated-local-ipc".to_owned(),
            protocol_version: "1.0.0".to_owned(),
            intent_hash_algorithm: "sha256".to_owned(),
            permit_authentication: "ed25519-one-use-token".to_owned(),
            permit_replay_protection: true,
            fail_closed: true,
            emergency_stop_independent: true,
            maximum_assessment_latency_micros: 10_000,
            monotonic_clock: true,
        },
        hardware: HardwareIntegrationContract {
            adapter_id: "warehouse-hardware-v1".to_owned(),
            api_version: "1.0.0".to_owned(),
            hardware_profile: HardwareProfile {
                profile_id: "mobile-inspector-v1".to_owned(),
                robot_id: "robot-1".to_owned(),
                robot_class: "mobile-inspector".to_owned(),
                sensor_kinds: BTreeSet::from([SensorKind::Lidar]),
                action_kinds: BTreeSet::from([ActionKind::Navigate]),
                safety_controller_required: true,
                maximum_command_bytes: 64 * 1024,
            },
            process_isolated: true,
            dispatch_idempotent: true,
            cancellation_supported: true,
            command_acknowledgement: true,
            health_telemetry: true,
            rollback_execution_supported: true,
        },
    }
}

fn signer_public_key() -> String {
    SigningKey::from_bytes(&[7_u8; 32])
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn assert_embodied_schema_valid(schema_name: &str, instance: &serde_json::Value) {
    let schema_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/embodied")
        .join(schema_name);
    let schema_json: serde_json::Value = ok(serde_json::from_slice(&ok(fs::read(schema_path))));
    let compiled_schema = ok(JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema_json));
    assert!(
        compiled_schema.is_valid(instance),
        "{schema_name} rejected a typed artifact"
    );
}

fn runtime_binding_input(
    manifest: &IntegrationManifest,
    observed_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
) -> RuntimeBindingInput {
    RuntimeBindingInput {
        schema_version: 1,
        binding_id: "robot-1-runtime-boot-1".to_owned(),
        integration_id: manifest.integration_id.clone(),
        observed_at_unix_seconds,
        expires_at_unix_seconds,
        attestor_id: manifest.binding_attestor_id.clone(),
        ros2: RuntimeRos2Binding {
            distribution: manifest.ros2.distribution.clone(),
            version: manifest.ros2.version.clone(),
            client_library: manifest.ros2.client_library.clone(),
            client_library_version: manifest.ros2.client_library_version.clone(),
            rmw_implementation: manifest.ros2.rmw_implementation.clone(),
            domain_id: manifest.ros2.domain_id,
            node_name: manifest.ros2.node_name.clone(),
            namespace: manifest.ros2.namespace.clone(),
            network_policy: manifest.ros2.network_policy,
            allowed_peers: manifest.ros2.allowed_peers.clone(),
            executor_kind: manifest.ros2.executor.kind.clone(),
            executor_implementation: manifest.ros2.executor.implementation.clone(),
            executor_thread_count: manifest.ros2.executor.thread_count,
            deterministic_ordering: manifest.ros2.executor.deterministic_ordering,
            bounded_callback_time: manifest.ros2.executor.bounded_callback_time,
            shutdown_timeout_millis: manifest.ros2.executor.shutdown_timeout_millis,
            topics: manifest
                .ros2
                .topics
                .iter()
                .map(|topic| RuntimeTopicBinding {
                    contract_id: topic.contract_id.clone(),
                    topic: topic.topic.clone(),
                    direction: topic.direction,
                    message_type: topic.message_type.clone(),
                    message_type_hash: topic.message_type_hash.clone(),
                    callback_group_id: topic.callback_group_id.clone(),
                    adapter_qos: topic.adapter_qos.clone(),
                    peer_qos: topic.peer_qos.clone(),
                })
                .collect(),
        },
        safety: RuntimeSafetyBinding {
            controller_id: manifest.safety.controller_id.clone(),
            protocol: manifest.safety.protocol.clone(),
            protocol_version: manifest.safety.protocol_version.clone(),
            intent_hash_algorithm: manifest.safety.intent_hash_algorithm.clone(),
            permit_authentication: manifest.safety.permit_authentication.clone(),
            permit_replay_protection: manifest.safety.permit_replay_protection,
            fail_closed: manifest.safety.fail_closed,
            emergency_stop_independent: manifest.safety.emergency_stop_independent,
            measured_maximum_assessment_latency_micros: 9_000,
            monotonic_clock: manifest.safety.monotonic_clock,
        },
        hardware: RuntimeHardwareBinding {
            adapter_id: manifest.hardware.adapter_id.clone(),
            api_version: manifest.hardware.api_version.clone(),
            hardware_profile_hash: ok(manifest.hardware.hardware_profile.content_hash()),
            process_isolated: manifest.hardware.process_isolated,
            dispatch_idempotent: manifest.hardware.dispatch_idempotent,
            cancellation_supported: manifest.hardware.cancellation_supported,
            command_acknowledgement: manifest.hardware.command_acknowledgement,
            health_telemetry: manifest.hardware.health_telemetry,
            rollback_execution_supported: manifest.hardware.rollback_execution_supported,
        },
    }
}

#[test]
fn complete_manifest_is_ready_and_cli_returns_success() {
    let manifest = ready_manifest();
    let report = ok(check_integration_readiness(&manifest));
    assert!(report.ready, "{:?}", report.issues);
    assert!(report.qos.iter().all(|result| result.compatible));

    let file = TempFile::new();
    ok(fs::write(
        file.path(),
        ok(serde_json::to_vec_pretty(&manifest)),
    ));
    let output = ok(Command::new(env!("CARGO_BIN_EXE_d2i-embodied"))
        .arg("readiness")
        .arg(file.path())
        .output());
    assert!(output.status.success());
    let cli_report: serde_json::Value = ok(serde_json::from_slice(&output.stdout));
    assert_eq!(cli_report["ready"], true);
}

#[test]
fn unresolved_safety_loop_and_incompatible_qos_are_actionable() {
    let mut manifest = ready_manifest();
    manifest.package_signature_verifier = "replace-me".to_owned();
    manifest.safety.fail_closed = false;
    manifest.hardware.process_isolated = false;
    manifest.ros2.topics[0].deadline_class = DeadlineClass::SafetyLoop;
    manifest.ros2.topics[0].peer_qos.reliability = ReliabilityPolicy::BestEffort;
    manifest.ros2.topics[0].adapter_qos.reliability = ReliabilityPolicy::Reliable;
    let report = ok(check_integration_readiness(&manifest));
    assert!(!report.ready);
    let codes = report
        .issues
        .iter()
        .map(|issue| issue.code.as_str())
        .collect::<BTreeSet<_>>();
    for code in ["D2IR9001", "D2IR9018", "D2IR9024", "D2IR9032", "D2IR9041"] {
        assert!(codes.contains(code), "missing readiness issue {code}");
    }
    assert!(report.qos.iter().any(|result| !result.compatible));
}

#[test]
fn signed_matching_runtime_mints_activation_and_cli_certifies() {
    let manifest = ready_manifest();
    let now = ok(SystemTime::now().duration_since(UNIX_EPOCH)).as_secs();
    let evidence = ok(create_runtime_binding_evidence(
        runtime_binding_input(&manifest, now.saturating_sub(1), now.saturating_add(60)),
        [7_u8; 32],
    ));
    assert_embodied_schema_valid(
        "runtime-binding-evidence.schema.json",
        &ok(serde_json::to_value(&evidence)),
    );
    let certification = ok(certify_runtime_binding(&manifest, &evidence, now));
    assert!(certification.report.certified);
    let certified = ok(certification.into_certified_integration());
    assert_eq!(certified.integration_id(), manifest.integration_id);
    assert_eq!(certified.binding_id(), evidence.binding_id);
    let ledger = TempDirectory::new();
    let initial = ok(initialize_activation_ledger(
        ledger.path(),
        "robot-1-activation",
        &manifest,
        BTreeSet::from(["deployment-agent-1".to_owned()]),
        100,
    ));
    assert_eq!(initial.entry_count, 0);
    let admission = ok(activate_certified_integration(
        ledger.path(),
        "deployment-agent-1",
        certified,
        now,
    ));
    assert_eq!(admission.verification.entry_count, 1);
    assert_eq!(
        ok(verify_activation_ledger(ledger.path())),
        admission.verification
    );
    let transport = ok(OfflineConformanceRos2Transport::new(
        &manifest.ros2.topic_map,
        2,
    ));
    let _adapter = ok(admission.activation.bind_ros2(transport, now));

    let manifest_file = TempFile::new();
    let evidence_file = TempFile::new();
    ok(fs::write(
        manifest_file.path(),
        ok(serde_json::to_vec_pretty(&manifest)),
    ));
    ok(fs::write(
        evidence_file.path(),
        ok(serde_json::to_vec_pretty(&evidence)),
    ));
    let output = ok(Command::new(env!("CARGO_BIN_EXE_d2i-embodied"))
        .arg("certify")
        .arg(manifest_file.path())
        .arg(evidence_file.path())
        .output());
    assert!(output.status.success());
    let cli_report: serde_json::Value = ok(serde_json::from_slice(&output.stdout));
    assert_eq!(cli_report["certified"], true);
}

#[test]
fn runtime_contract_drift_blocks_activation() {
    let manifest = ready_manifest();
    let mut input = runtime_binding_input(&manifest, 100, 200);
    input.ros2.topics[0].message_type_hash =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();
    input.safety.measured_maximum_assessment_latency_micros = 10_001;
    input.hardware.hardware_profile_hash =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned();
    let evidence = ok(create_runtime_binding_evidence(input, [7_u8; 32]));
    let certification = ok(certify_runtime_binding(&manifest, &evidence, 150));
    assert!(!certification.report.certified);
    assert!(certification.certified_integration().is_none());
    let codes = certification
        .report
        .issues
        .iter()
        .map(|issue| issue.code.as_str())
        .collect::<BTreeSet<_>>();
    for code in ["D2IC9113", "D2IC9122", "D2IC9130"] {
        assert!(codes.contains(code), "missing certification issue {code}");
    }
}

#[test]
fn expired_or_tampered_runtime_evidence_is_rejected() {
    let manifest = ready_manifest();
    let evidence = ok(create_runtime_binding_evidence(
        runtime_binding_input(&manifest, 100, 200),
        [7_u8; 32],
    ));
    let expired = ok(certify_runtime_binding(&manifest, &evidence, 200));
    assert!(!expired.report.certified);
    assert!(expired
        .report
        .issues
        .iter()
        .any(|issue| issue.code == "D2IC9103"));

    let mut tampered = evidence;
    let replacement = if tampered.signature.starts_with('0') {
        "1"
    } else {
        "0"
    };
    tampered.signature.replace_range(0..1, replacement);
    let rejected = ok(certify_runtime_binding(&manifest, &tampered, 150));
    assert!(!rejected.report.certified);
    assert!(rejected
        .report
        .issues
        .iter()
        .any(|issue| issue.code == "D2IC9104"));
}

#[test]
fn offline_conformance_transport_is_bounded_and_topic_scoped() {
    let manifest = ready_manifest();
    let mut transport = ok(OfflineConformanceRos2Transport::new(
        &manifest.ros2.topic_map,
        1,
    ));
    ok(transport.enqueue_sensor("/robot_1/lidar", vec![1]));
    assert!(transport.enqueue_sensor("/robot_1/lidar", vec![2]).is_err());
    assert_eq!(
        ok(Ros2Transport::receive(&mut transport, "/robot_1/lidar")),
        Some(vec![1])
    );
    ok(Ros2Transport::publish(
        &mut transport,
        "/robot_1/d2i/action_intent",
        &[3],
    ));
    assert_eq!(
        ok(transport.take_published("/robot_1/d2i/action_intent")),
        Some(vec![3])
    );
    assert!(Ros2Transport::publish(&mut transport, "/unreviewed", &[4]).is_err());
}

#[test]
fn activation_ledger_rejects_replay_rollback_expiry_and_tamper() {
    let manifest = ready_manifest();
    let ledger = TempDirectory::new();
    ok(initialize_activation_ledger(
        ledger.path(),
        "robot-1-activation",
        &manifest,
        BTreeSet::from(["deployment-agent-1".to_owned()]),
        10,
    ));
    let first_evidence = ok(create_runtime_binding_evidence(
        runtime_binding_input(&manifest, 100, 200),
        [7_u8; 32],
    ));
    let first = ok(certify_runtime_binding(&manifest, &first_evidence, 150));
    ok(activate_certified_integration(
        ledger.path(),
        "deployment-agent-1",
        ok(first.into_certified_integration()),
        150,
    ));
    let policy_json: serde_json::Value = ok(serde_json::from_slice(&ok(fs::read(
        ledger.path().join("activation-policy.json"),
    ))));
    assert_embodied_schema_valid("activation-ledger-policy.schema.json", &policy_json);
    let records = ok(fs::read(ledger.path().join("activation-records.jsonl")));
    let first_line = match records.split(|byte| *byte == b'\n').next() {
        Some(line) => line,
        None => panic!("activation ledger has no first record"),
    };
    let record_json: serde_json::Value = ok(serde_json::from_slice(first_line));
    assert_embodied_schema_valid("activation-record.schema.json", &record_json);

    let replay = ok(certify_runtime_binding(&manifest, &first_evidence, 151));
    assert!(activate_certified_integration(
        ledger.path(),
        "deployment-agent-1",
        ok(replay.into_certified_integration()),
        151,
    )
    .is_err());

    let mut rollback_input = runtime_binding_input(&manifest, 99, 199);
    rollback_input.binding_id = "robot-1-runtime-rollback".to_owned();
    let rollback_evidence = ok(create_runtime_binding_evidence(rollback_input, [7_u8; 32]));
    let rollback = ok(certify_runtime_binding(&manifest, &rollback_evidence, 151));
    assert!(activate_certified_integration(
        ledger.path(),
        "deployment-agent-1",
        ok(rollback.into_certified_integration()),
        151,
    )
    .is_err());

    let expiry_ledger = TempDirectory::new();
    ok(initialize_activation_ledger(
        expiry_ledger.path(),
        "robot-1-expiry",
        &manifest,
        BTreeSet::from(["deployment-agent-1".to_owned()]),
        10,
    ));
    let expiring = ok(certify_runtime_binding(&manifest, &first_evidence, 150));
    assert!(activate_certified_integration(
        expiry_ledger.path(),
        "deployment-agent-1",
        ok(expiring.into_certified_integration()),
        200,
    )
    .is_err());

    let records_path = ledger.path().join("activation-records.jsonl");
    let mut bytes = ok(fs::read(&records_path));
    let position = match bytes.iter().position(|byte| *byte == b'd') {
        Some(value) => value,
        None => panic!("activation record did not contain a mutable byte"),
    };
    bytes[position] = b'e';
    ok(fs::write(records_path, bytes));
    assert!(verify_activation_ledger(ledger.path()).is_err());
}

#[test]
fn activation_ledger_cli_initializes_and_verifies_empty_chain() {
    let manifest = ready_manifest();
    let manifest_file = TempFile::new();
    let ledger = TempDirectory::new();
    ok(fs::write(
        manifest_file.path(),
        ok(serde_json::to_vec_pretty(&manifest)),
    ));
    let initialized = ok(Command::new(env!("CARGO_BIN_EXE_d2i-embodied"))
        .arg("ledger-init")
        .arg(manifest_file.path())
        .arg(ledger.path())
        .arg("robot-1-cli-ledger")
        .arg("deployment-agent-1")
        .arg("100")
        .output());
    assert!(initialized.status.success());
    let initial_report: serde_json::Value = ok(serde_json::from_slice(&initialized.stdout));
    assert_eq!(initial_report["entry_count"], 0);

    let checked = ok(Command::new(env!("CARGO_BIN_EXE_d2i-embodied"))
        .arg("ledger-check")
        .arg(ledger.path())
        .output());
    assert!(checked.status.success());
    let checked_report: serde_json::Value = ok(serde_json::from_slice(&checked.stdout));
    assert_eq!(initial_report, checked_report);
}
