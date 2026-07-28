use crate::{
    read_bounded, validate_hash, validate_text, validate_token, DeadlineClass, EmbodiedError,
    HardwareProfile, Ros2TopicMap, SensorKind,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const MAX_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;

/// ROS 2 history policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryPolicy {
    KeepLast,
    KeepAll,
    SystemDefault,
}

/// ROS 2 reliability policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReliabilityPolicy {
    BestEffort,
    Reliable,
    SystemDefault,
}

/// ROS 2 durability policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurabilityPolicy {
    Volatile,
    TransientLocal,
    SystemDefault,
}

/// ROS 2 liveliness policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LivelinessPolicy {
    Automatic,
    ManualByTopic,
    SystemDefault,
}

/// Explicit endpoint QoS profile. Durations are nanoseconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointQos {
    pub history: HistoryPolicy,
    pub depth: u32,
    pub reliability: ReliabilityPolicy,
    pub durability: DurabilityPolicy,
    pub deadline_nanos: u64,
    pub lifespan_nanos: u64,
    pub liveliness: LivelinessPolicy,
    pub liveliness_lease_nanos: u64,
}

/// Direction of a topic from the embodied adapter's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopicDirection {
    Subscribe,
    Publish,
}

/// One fully specified ROS 2 topic and peer compatibility contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopicContract {
    pub contract_id: String,
    pub topic: String,
    pub direction: TopicDirection,
    pub message_type: String,
    pub message_type_hash: String,
    pub sensor_kind: Option<SensorKind>,
    pub deadline_class: DeadlineClass,
    pub bypasses_d2i: bool,
    pub callback_group_id: String,
    pub adapter_qos: EndpointQos,
    pub peer_qos: EndpointQos,
}

/// Callback concurrency mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackGroupKind {
    MutuallyExclusive,
    Reentrant,
}

/// Callback-group ownership and blocking contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallbackGroupContract {
    pub callback_group_id: String,
    pub kind: CallbackGroupKind,
    pub dedicated_to_contract_ids: BTreeSet<String>,
    pub allows_blocking_calls: bool,
}

/// Selected ROS 2 execution mechanism.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorKind {
    SingleThreaded,
    MultiThreaded,
    WaitSet,
    Rclc,
    Other,
}

/// Executor, threading, callback, and shutdown contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorContract {
    pub kind: ExecutorKind,
    pub implementation: String,
    pub thread_count: u16,
    pub deterministic_ordering: bool,
    pub bounded_callback_time: bool,
    pub callback_groups: Vec<CallbackGroupContract>,
    pub shutdown_timeout_millis: u64,
}

/// Network posture for ROS discovery and transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    Deny,
    LocalOnly,
    ManagedAllowlist,
}

/// Complete ROS 2 integration input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ros2IntegrationContract {
    pub distribution: String,
    pub version: String,
    pub client_library: String,
    pub client_library_version: String,
    pub rmw_implementation: String,
    pub domain_id: u32,
    pub node_name: String,
    pub namespace: String,
    pub network_policy: NetworkPolicy,
    pub allowed_peers: BTreeSet<String>,
    pub topic_map: Ros2TopicMap,
    pub topics: Vec<TopicContract>,
    pub executor: ExecutorContract,
}

/// External safety-controller protocol requirements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyIntegrationContract {
    pub controller_id: String,
    pub protocol: String,
    pub protocol_version: String,
    pub intent_hash_algorithm: String,
    pub permit_authentication: String,
    pub permit_replay_protection: bool,
    pub fail_closed: bool,
    pub emergency_stop_independent: bool,
    pub maximum_assessment_latency_micros: u64,
    pub monotonic_clock: bool,
}

/// External hardware adapter and rollout-observability requirements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareIntegrationContract {
    pub adapter_id: String,
    pub api_version: String,
    pub hardware_profile: HardwareProfile,
    pub process_isolated: bool,
    pub dispatch_idempotent: bool,
    pub cancellation_supported: bool,
    pub command_acknowledgement: bool,
    pub health_telemetry: bool,
    pub rollback_execution_supported: bool,
}

/// Versioned integration manifest supplied before concrete adapter work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationManifest {
    pub schema_version: u32,
    pub integration_id: String,
    pub owner: String,
    pub reviewed_at_unix_seconds: u64,
    pub package_signature_verifier: String,
    pub credential_provider: String,
    pub binding_attestor_id: String,
    pub binding_attestor_public_key: String,
    pub ros2: Ros2IntegrationContract,
    pub safety: SafetyIntegrationContract,
    pub hardware: HardwareIntegrationContract,
}

/// One actionable missing or incompatible integration requirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessIssue {
    pub code: String,
    pub message: String,
    pub remediation: String,
}

/// Publisher/subscriber QoS compatibility summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QosCompatibility {
    pub contract_id: String,
    pub compatible: bool,
    pub reasons: Vec<String>,
}

/// Deterministic readiness result for one integration manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationReadinessReport {
    pub schema_version: u32,
    pub integration_id: String,
    pub ready: bool,
    pub topic_count: u64,
    pub qos: Vec<QosCompatibility>,
    pub issues: Vec<ReadinessIssue>,
}

/// Loads one bounded strict JSON integration manifest.
pub fn load_integration_manifest(path: &Path) -> Result<IntegrationManifest, EmbodiedError> {
    serde_json::from_slice(&read_bounded(path, MAX_MANIFEST_BYTES)?)
        .map_err(|error| EmbodiedError::Json(error.to_string()))
}

/// Checks contract completeness without connecting to ROS 2 or hardware.
pub fn check_integration_readiness(
    manifest: &IntegrationManifest,
) -> Result<IntegrationReadinessReport, EmbodiedError> {
    if manifest.schema_version != 1 {
        return Err(EmbodiedError::Invalid(
            "integration manifest schema_version must be 1".to_owned(),
        ));
    }
    validate_token(&manifest.integration_id, "integration_id")?;
    validate_text(&manifest.owner, "owner")?;
    validate_text(
        &manifest.package_signature_verifier,
        "package_signature_verifier",
    )?;
    validate_text(&manifest.credential_provider, "credential_provider")?;
    validate_token(&manifest.binding_attestor_id, "binding_attestor_id")?;
    let _ = crate::hex_decode_array::<32>(&manifest.binding_attestor_public_key)?;
    validate_ros_identity(&manifest.ros2)?;
    manifest.ros2.topic_map.validate()?;
    manifest.hardware.hardware_profile.validate()?;

    let mut issues = Vec::new();
    let mut qos = Vec::new();
    if manifest.reviewed_at_unix_seconds == 0 {
        push_issue(
            &mut issues,
            "D2IR9000",
            "manifest has no review timestamp",
            "record the completed architecture and safety review time",
        );
    }
    reject_placeholder(
        &manifest.package_signature_verifier,
        "D2IR9001",
        "package signature verifier",
        &mut issues,
    );
    reject_placeholder(
        &manifest.credential_provider,
        "D2IR9002",
        "credential provider",
        &mut issues,
    );
    reject_placeholder(
        &manifest.binding_attestor_id,
        "D2IR9003",
        "runtime binding attestor",
        &mut issues,
    );
    if manifest.binding_attestor_public_key
        == "0000000000000000000000000000000000000000000000000000000000000000"
        || manifest.binding_attestor_public_key
            != manifest.binding_attestor_public_key.to_ascii_lowercase()
    {
        push_issue(
            &mut issues,
            "D2IR9004",
            "runtime binding attestor public key is unresolved or non-canonical",
            "record the reviewed probe's lowercase Ed25519 public key",
        );
    }
    validate_ros_contract(&manifest.ros2, &mut qos, &mut issues)?;
    validate_safety_contract(&manifest.safety, &mut issues)?;
    validate_hardware_contract(&manifest.hardware, &manifest.safety, &mut issues)?;
    issues.sort_by(|left, right| (&left.code, &left.message).cmp(&(&right.code, &right.message)));
    qos.sort_by(|left, right| left.contract_id.cmp(&right.contract_id));
    Ok(IntegrationReadinessReport {
        schema_version: 1,
        integration_id: manifest.integration_id.clone(),
        ready: issues.is_empty() && qos.iter().all(|result| result.compatible),
        topic_count: u64::try_from(manifest.ros2.topics.len()).unwrap_or(u64::MAX),
        qos,
        issues,
    })
}

fn validate_ros_identity(contract: &Ros2IntegrationContract) -> Result<(), EmbodiedError> {
    for (value, field) in [
        (&contract.distribution, "ROS distribution"),
        (&contract.version, "ROS version"),
        (&contract.client_library, "ROS client_library"),
        (
            &contract.client_library_version,
            "ROS client_library_version",
        ),
        (&contract.rmw_implementation, "ROS rmw_implementation"),
        (&contract.node_name, "ROS node_name"),
        (&contract.namespace, "ROS namespace"),
    ] {
        validate_text(value, field)?;
    }
    if contract.topics.is_empty() || contract.topics.len() > 10_000 {
        return Err(EmbodiedError::Invalid(
            "ROS topic contract count is outside bounds".to_owned(),
        ));
    }
    validate_text(&contract.executor.implementation, "executor implementation")?;
    if contract.executor.callback_groups.is_empty()
        || contract.executor.callback_groups.len() > 10_000
    {
        return Err(EmbodiedError::Invalid(
            "executor callback-group count is outside bounds".to_owned(),
        ));
    }
    Ok(())
}

fn validate_ros_contract(
    contract: &Ros2IntegrationContract,
    qos_results: &mut Vec<QosCompatibility>,
    issues: &mut Vec<ReadinessIssue>,
) -> Result<(), EmbodiedError> {
    for value in [
        &contract.distribution,
        &contract.version,
        &contract.client_library,
        &contract.client_library_version,
        &contract.rmw_implementation,
    ] {
        reject_placeholder(value, "D2IR9010", "ROS versioned dependency", issues);
    }
    if contract.network_policy == NetworkPolicy::ManagedAllowlist
        && contract.allowed_peers.is_empty()
    {
        push_issue(
            issues,
            "D2IR9011",
            "managed ROS network policy has no peer allowlist",
            "list every discovery and transport peer",
        );
    }
    if contract.network_policy == NetworkPolicy::Deny && !contract.allowed_peers.is_empty() {
        push_issue(
            issues,
            "D2IR9012",
            "deny-network ROS contract contains allowed peers",
            "remove peers or select the reviewed local/managed policy",
        );
    }
    let callback_groups = contract
        .executor
        .callback_groups
        .iter()
        .map(|group| (group.callback_group_id.as_str(), group))
        .collect::<BTreeMap<_, _>>();
    if callback_groups.len() != contract.executor.callback_groups.len() {
        push_issue(
            issues,
            "D2IR9013",
            "callback group IDs are duplicated",
            "assign a unique callback_group_id to every group",
        );
    }
    if contract.executor.thread_count == 0
        || contract.executor.shutdown_timeout_millis == 0
        || !contract.executor.deterministic_ordering
        || !contract.executor.bounded_callback_time
    {
        push_issue(
            issues,
            "D2IR9014",
            "executor thread, callback bound, or shutdown contract is incomplete",
            "declare positive bounds for threads, callbacks, and shutdown",
        );
    }
    let mut topic_ids = BTreeSet::new();
    let mut mapped_sensor_kinds = BTreeSet::new();
    for topic in &contract.topics {
        validate_token(&topic.contract_id, "topic contract_id")?;
        crate::ros2::validate_topic(&topic.topic)?;
        validate_text(&topic.message_type, "message_type")?;
        validate_hash(&topic.message_type_hash, "message_type_hash")?;
        validate_token(&topic.callback_group_id, "callback_group_id")?;
        if !topic_ids.insert(topic.contract_id.clone()) {
            push_issue(
                issues,
                "D2IR9015",
                format!("topic contract '{}' is duplicated", topic.contract_id),
                "assign unique topic contract IDs",
            );
        }
        if let Some(group) = callback_groups.get(topic.callback_group_id.as_str()) {
            if !group.dedicated_to_contract_ids.contains(&topic.contract_id) {
                push_issue(
                    issues,
                    "D2IR9017",
                    format!(
                        "callback group '{}' does not claim topic '{}'",
                        group.callback_group_id, topic.contract_id
                    ),
                    "bind each topic contract explicitly to its callback group",
                );
            }
            if topic.deadline_class <= DeadlineClass::Control && group.allows_blocking_calls {
                push_issue(
                    issues,
                    "D2IR9019",
                    format!(
                        "deadline-sensitive topic '{}' allows blocking callbacks",
                        topic.contract_id
                    ),
                    "use a bounded non-blocking callback path",
                );
            }
        } else {
            push_issue(
                issues,
                "D2IR9016",
                format!(
                    "topic '{}' references an unknown callback group",
                    topic.contract_id
                ),
                "declare the callback group in executor.callback_groups",
            );
        }
        if topic.deadline_class == DeadlineClass::SafetyLoop && !topic.bypasses_d2i {
            push_issue(
                issues,
                "D2IR9018",
                format!("safety-loop topic '{}' enters D2I", topic.contract_id),
                "route the safety loop directly to the external safety controller",
            );
        }
        if let Some(sensor_kind) = &topic.sensor_kind {
            mapped_sensor_kinds.insert(sensor_kind.clone());
            if topic.direction != TopicDirection::Subscribe {
                push_issue(
                    issues,
                    "D2IR9020",
                    format!("sensor topic '{}' is not a subscription", topic.contract_id),
                    "declare sensor inputs with direction=subscribe",
                );
            }
        }
        qos_results.push(qos_compatibility(topic));
    }
    validate_topic_map(contract, &mapped_sensor_kinds, issues);
    for group in &contract.executor.callback_groups {
        validate_token(&group.callback_group_id, "callback_group_id")?;
        if group.dedicated_to_contract_ids.is_empty() {
            push_issue(
                issues,
                "D2IR9023",
                format!(
                    "callback group '{}' has no owned contracts",
                    group.callback_group_id
                ),
                "bind at least one topic contract to the callback group",
            );
        }
        for contract_id in &group.dedicated_to_contract_ids {
            if !topic_ids.contains(contract_id) {
                push_issue(
                    issues,
                    "D2IR9025",
                    format!(
                        "callback group '{}' claims unknown contract '{}'",
                        group.callback_group_id, contract_id
                    ),
                    "remove the stale ownership entry or add the topic contract",
                );
            }
        }
    }
    for result in qos_results.iter().filter(|result| !result.compatible) {
        push_issue(
            issues,
            "D2IR9024",
            format!("topic '{}' has incompatible QoS", result.contract_id),
            "align offered and requested reliability, durability, and deadline",
        );
    }
    Ok(())
}

fn validate_topic_map(
    contract: &Ros2IntegrationContract,
    mapped_sensor_kinds: &BTreeSet<SensorKind>,
    issues: &mut Vec<ReadinessIssue>,
) {
    for (sensor_kind, topic) in &contract.topic_map.sensor_topics {
        if !mapped_sensor_kinds.contains(sensor_kind)
            || !contract.topics.iter().any(|entry| {
                &entry.topic == topic
                    && entry.sensor_kind.as_ref() == Some(sensor_kind)
                    && entry.direction == TopicDirection::Subscribe
            })
        {
            push_issue(
                issues,
                "D2IR9021",
                format!("sensor topic map entry '{topic}' has no matching contract"),
                "add a typed subscribe TopicContract for every sensor mapping",
            );
        }
    }
    for (topic, label) in [
        (&contract.topic_map.action_intent_topic, "action intent"),
        (
            &contract.topic_map.safety_assessment_topic,
            "safety assessment",
        ),
    ] {
        if !contract
            .topics
            .iter()
            .any(|entry| &entry.topic == topic && entry.direction == TopicDirection::Publish)
        {
            push_issue(
                issues,
                "D2IR9022",
                format!("required {label} output topic '{topic}' has no publish contract"),
                "add an explicit publish TopicContract for the required output",
            );
        }
    }
}

fn validate_safety_contract(
    contract: &SafetyIntegrationContract,
    issues: &mut Vec<ReadinessIssue>,
) -> Result<(), EmbodiedError> {
    validate_token(&contract.controller_id, "safety controller_id")?;
    for (value, label) in [
        (&contract.protocol, "safety protocol"),
        (&contract.protocol_version, "safety protocol version"),
        (
            &contract.permit_authentication,
            "safety permit authentication",
        ),
    ] {
        validate_text(value, label)?;
        reject_placeholder(value, "D2IR9030", label, issues);
    }
    if !contract
        .intent_hash_algorithm
        .eq_ignore_ascii_case("sha256")
    {
        push_issue(
            issues,
            "D2IR9031",
            "safety intent hash algorithm is not SHA-256",
            "bind permits to ActionIntent::content_hash",
        );
    }
    if !contract.permit_replay_protection
        || !contract.fail_closed
        || !contract.emergency_stop_independent
        || !contract.monotonic_clock
        || contract.maximum_assessment_latency_micros == 0
        || contract.maximum_assessment_latency_micros
            > DeadlineClass::SafetyLoop.maximum_latency_ms() * 1_000
    {
        push_issue(
            issues,
            "D2IR9032",
            "safety fail-closed, replay, emergency, clock, or latency contract is incomplete",
            "provide an independent fail-closed controller with authenticated one-use permits",
        );
    }
    Ok(())
}

fn validate_hardware_contract(
    contract: &HardwareIntegrationContract,
    safety: &SafetyIntegrationContract,
    issues: &mut Vec<ReadinessIssue>,
) -> Result<(), EmbodiedError> {
    validate_token(&contract.adapter_id, "hardware adapter_id")?;
    validate_text(&contract.api_version, "hardware api_version")?;
    reject_placeholder(
        &contract.api_version,
        "D2IR9040",
        "hardware API version",
        issues,
    );
    if !contract.hardware_profile.safety_controller_required
        || safety.controller_id.is_empty()
        || !contract.process_isolated
        || !contract.dispatch_idempotent
        || !contract.cancellation_supported
        || !contract.command_acknowledgement
        || !contract.health_telemetry
        || !contract.rollback_execution_supported
    {
        push_issue(
            issues,
            "D2IR9041",
            "hardware isolation, dispatch, cancellation, acknowledgement, health, or rollback contract is incomplete",
            "document and test every hardware lifecycle and recovery guarantee",
        );
    }
    Ok(())
}

fn qos_compatibility(topic: &TopicContract) -> QosCompatibility {
    let (publisher, subscriber) = match topic.direction {
        TopicDirection::Publish => (&topic.adapter_qos, &topic.peer_qos),
        TopicDirection::Subscribe => (&topic.peer_qos, &topic.adapter_qos),
    };
    let mut reasons = Vec::new();
    for (profile, label) in [(&topic.adapter_qos, "adapter"), (&topic.peer_qos, "peer")] {
        if matches!(profile.history, HistoryPolicy::SystemDefault)
            || matches!(profile.reliability, ReliabilityPolicy::SystemDefault)
            || matches!(profile.durability, DurabilityPolicy::SystemDefault)
            || matches!(profile.liveliness, LivelinessPolicy::SystemDefault)
        {
            reasons.push(format!("{label} QoS contains system_default"));
        }
        if profile.history == HistoryPolicy::KeepLast && profile.depth == 0 {
            reasons.push(format!("{label} keep_last depth is zero"));
        }
        if profile.deadline_nanos == 0
            || profile.lifespan_nanos == 0
            || profile.liveliness_lease_nanos == 0
        {
            reasons.push(format!("{label} QoS duration is unspecified"));
        }
    }
    if publisher.reliability == ReliabilityPolicy::BestEffort
        && subscriber.reliability == ReliabilityPolicy::Reliable
    {
        reasons.push("best-effort publisher cannot satisfy reliable subscriber".to_owned());
    }
    if publisher.durability == DurabilityPolicy::Volatile
        && subscriber.durability == DurabilityPolicy::TransientLocal
    {
        reasons.push("volatile publisher cannot satisfy transient-local subscriber".to_owned());
    }
    if publisher.deadline_nanos > subscriber.deadline_nanos {
        reasons.push("publisher deadline exceeds subscriber request".to_owned());
    }
    QosCompatibility {
        contract_id: topic.contract_id.clone(),
        compatible: reasons.is_empty(),
        reasons,
    }
}

fn reject_placeholder(value: &str, code: &str, label: &str, issues: &mut Vec<ReadinessIssue>) {
    let normalized = value.to_ascii_lowercase();
    if normalized.contains("todo")
        || normalized.contains("unresolved")
        || normalized.contains("replace-me")
        || normalized == "unknown"
    {
        push_issue(
            issues,
            code,
            format!("{label} is unresolved"),
            format!("replace the placeholder with a reviewed {label}"),
        );
    }
}

fn push_issue(
    issues: &mut Vec<ReadinessIssue>,
    code: &str,
    message: impl Into<String>,
    remediation: impl Into<String>,
) {
    issues.push(ReadinessIssue {
        code: code.to_owned(),
        message: message.into(),
        remediation: remediation.into(),
    });
}
