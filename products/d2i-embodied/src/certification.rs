use crate::{
    check_integration_readiness, hex_decode_array, hex_encode, json_bytes, read_bounded,
    sha256_bytes, validate_hash, validate_text, validate_token, EmbodiedError, EndpointQos,
    ExecutorKind, IntegrationManifest, NetworkPolicy, Ros2TopicMap, TopicDirection,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

const MAX_EVIDENCE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_EVIDENCE_LIFETIME_SECONDS: u64 = 15 * 60;

/// One ROS 2 endpoint observed by an integration probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTopicBinding {
    pub contract_id: String,
    pub topic: String,
    pub direction: TopicDirection,
    pub message_type: String,
    pub message_type_hash: String,
    pub callback_group_id: String,
    pub adapter_qos: EndpointQos,
    pub peer_qos: EndpointQos,
}

/// ROS 2 identity, execution, network, and endpoint state observed at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRos2Binding {
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
    pub executor_kind: ExecutorKind,
    pub executor_implementation: String,
    pub executor_thread_count: u16,
    pub deterministic_ordering: bool,
    pub bounded_callback_time: bool,
    pub shutdown_timeout_millis: u64,
    pub topics: Vec<RuntimeTopicBinding>,
}

/// External safety-controller properties measured by an integration probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSafetyBinding {
    pub controller_id: String,
    pub protocol: String,
    pub protocol_version: String,
    pub intent_hash_algorithm: String,
    pub permit_authentication: String,
    pub permit_replay_protection: bool,
    pub fail_closed: bool,
    pub emergency_stop_independent: bool,
    pub measured_maximum_assessment_latency_micros: u64,
    pub monotonic_clock: bool,
}

/// External hardware adapter properties observed by an integration probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeHardwareBinding {
    pub adapter_id: String,
    pub api_version: String,
    pub hardware_profile_hash: String,
    pub process_isolated: bool,
    pub dispatch_idempotent: bool,
    pub cancellation_supported: bool,
    pub command_acknowledgement: bool,
    pub health_telemetry: bool,
    pub rollback_execution_supported: bool,
}

/// Unsigned input collected by a reviewed runtime integration probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBindingInput {
    pub schema_version: u32,
    pub binding_id: String,
    pub integration_id: String,
    pub observed_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub attestor_id: String,
    pub ros2: RuntimeRos2Binding,
    pub safety: RuntimeSafetyBinding,
    pub hardware: RuntimeHardwareBinding,
}

/// Signed runtime binding evidence. Its key must match the manifest trust root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBindingEvidence {
    pub schema_version: u32,
    pub binding_id: String,
    pub integration_id: String,
    pub observed_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub attestor_id: String,
    pub ros2: RuntimeRos2Binding,
    pub safety: RuntimeSafetyBinding,
    pub hardware: RuntimeHardwareBinding,
    pub signer_public_key: String,
    pub signature: String,
}

/// One actionable runtime certification failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationIssue {
    pub code: String,
    pub message: String,
    pub remediation: String,
}

/// Serializable result of comparing a manifest with signed runtime evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingCertificationReport {
    pub schema_version: u32,
    pub integration_id: String,
    pub binding_id: String,
    pub certified: bool,
    pub manifest_hash: String,
    pub evidence_hash: String,
    pub issues: Vec<CertificationIssue>,
}

/// Opaque activation proof minted only after successful certification.
#[derive(Debug)]
pub struct CertifiedIntegration {
    pub(crate) integration_id: String,
    pub(crate) binding_id: String,
    pub(crate) manifest_hash: String,
    pub(crate) evidence_hash: String,
    pub(crate) observed_at_unix_seconds: u64,
    pub(crate) expires_at_unix_seconds: u64,
    pub(crate) topic_map: Ros2TopicMap,
}

impl CertifiedIntegration {
    /// Returns the reviewed integration identity.
    pub fn integration_id(&self) -> &str {
        &self.integration_id
    }

    /// Returns the signed runtime binding identity.
    pub fn binding_id(&self) -> &str {
        &self.binding_id
    }

    /// Returns the hash of the exact reviewed manifest.
    pub fn manifest_hash(&self) -> &str {
        &self.manifest_hash
    }

    /// Returns the hash of the exact signed observation.
    pub fn evidence_hash(&self) -> &str {
        &self.evidence_hash
    }

    /// Returns the exclusive Unix expiration time of this activation proof.
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }
}

/// Certification report plus an activation proof when every gate passes.
#[derive(Debug)]
pub struct BindingCertification {
    pub report: BindingCertificationReport,
    certified: Option<CertifiedIntegration>,
}

impl BindingCertification {
    /// Borrows the activation proof when certification succeeded.
    pub fn certified_integration(&self) -> Option<&CertifiedIntegration> {
        self.certified.as_ref()
    }

    /// Consumes the result and returns the activation proof.
    pub fn into_certified_integration(self) -> Result<CertifiedIntegration, EmbodiedError> {
        self.certified.ok_or_else(|| {
            EmbodiedError::AdapterUnavailable(
                "runtime binding has not passed integration certification".to_owned(),
            )
        })
    }
}

/// Probe boundary for a concrete ROS 2, safety, and hardware integration.
pub trait RuntimeBindingProbe {
    /// Collects a bounded signed snapshot without activating hardware.
    fn collect_binding_evidence(&self) -> Result<RuntimeBindingEvidence, EmbodiedError>;
}

#[derive(Serialize)]
struct SignedEvidencePayload<'a> {
    schema_version: u32,
    binding_id: &'a str,
    integration_id: &'a str,
    observed_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    attestor_id: &'a str,
    ros2: &'a RuntimeRos2Binding,
    safety: &'a RuntimeSafetyBinding,
    hardware: &'a RuntimeHardwareBinding,
    signer_public_key: &'a str,
}

/// Signs one runtime observation for offline certification.
pub fn create_runtime_binding_evidence(
    input: RuntimeBindingInput,
    secret_key: [u8; 32],
) -> Result<RuntimeBindingEvidence, EmbodiedError> {
    validate_binding_input(&input)?;
    let signing_key = SigningKey::from_bytes(&secret_key);
    let signer_public_key = hex_encode(&signing_key.verifying_key().to_bytes());
    let payload = signed_payload_from_input(&input, &signer_public_key);
    let signature = hex_encode(&signing_key.sign(&json_bytes(&payload)?).to_bytes());
    Ok(RuntimeBindingEvidence {
        schema_version: input.schema_version,
        binding_id: input.binding_id,
        integration_id: input.integration_id,
        observed_at_unix_seconds: input.observed_at_unix_seconds,
        expires_at_unix_seconds: input.expires_at_unix_seconds,
        attestor_id: input.attestor_id,
        ros2: input.ros2,
        safety: input.safety,
        hardware: input.hardware,
        signer_public_key,
        signature,
    })
}

/// Loads one bounded strict JSON runtime binding evidence file.
pub fn load_runtime_binding_evidence(path: &Path) -> Result<RuntimeBindingEvidence, EmbodiedError> {
    serde_json::from_slice(&read_bounded(path, MAX_EVIDENCE_BYTES)?)
        .map_err(|error| EmbodiedError::Json(error.to_string()))
}

/// Collects evidence from a probe and certifies it without activating hardware.
pub fn certify_probed_runtime(
    manifest: &IntegrationManifest,
    probe: &dyn RuntimeBindingProbe,
    now_unix_seconds: u64,
) -> Result<BindingCertification, EmbodiedError> {
    certify_runtime_binding(
        manifest,
        &probe.collect_binding_evidence()?,
        now_unix_seconds,
    )
}

/// Verifies signed runtime evidence against the exact reviewed manifest.
pub fn certify_runtime_binding(
    manifest: &IntegrationManifest,
    evidence: &RuntimeBindingEvidence,
    now_unix_seconds: u64,
) -> Result<BindingCertification, EmbodiedError> {
    validate_evidence(evidence)?;
    let readiness = check_integration_readiness(manifest)?;
    let manifest_hash = sha256_bytes(&json_bytes(manifest)?);
    let evidence_hash = sha256_bytes(&json_bytes(evidence)?);
    let mut issues = Vec::new();

    if !readiness.ready {
        push_issue(
            &mut issues,
            "D2IC9100",
            "integration manifest has unresolved readiness issues",
            "resolve every readiness issue before collecting runtime evidence",
        );
    }
    if evidence.integration_id != manifest.integration_id {
        push_issue(
            &mut issues,
            "D2IC9101",
            "runtime evidence integration_id does not match the manifest",
            "probe the reviewed integration and preserve its integration_id",
        );
    }
    if evidence.attestor_id != manifest.binding_attestor_id
        || evidence.signer_public_key != manifest.binding_attestor_public_key
    {
        push_issue(
            &mut issues,
            "D2IC9102",
            "runtime evidence is not bound to the manifest attestor",
            "sign the observation with the reviewed integration probe key",
        );
    }
    if now_unix_seconds < evidence.observed_at_unix_seconds
        || now_unix_seconds >= evidence.expires_at_unix_seconds
    {
        push_issue(
            &mut issues,
            "D2IC9103",
            "runtime evidence is not currently valid",
            "collect a fresh observation using the trusted monotonic deployment workflow",
        );
    }
    if !verify_evidence_signature(evidence)? {
        push_issue(
            &mut issues,
            "D2IC9104",
            "runtime evidence signature is invalid",
            "discard the evidence and collect a new signed probe observation",
        );
    }

    compare_ros2(manifest, evidence, &mut issues);
    compare_safety(manifest, evidence, &mut issues);
    compare_hardware(manifest, evidence, &mut issues)?;
    issues.sort_by(|left, right| (&left.code, &left.message).cmp(&(&right.code, &right.message)));
    let certified = issues.is_empty();
    let report = BindingCertificationReport {
        schema_version: 1,
        integration_id: manifest.integration_id.clone(),
        binding_id: evidence.binding_id.clone(),
        certified,
        manifest_hash: manifest_hash.clone(),
        evidence_hash: evidence_hash.clone(),
        issues,
    };
    let activation = certified.then(|| CertifiedIntegration {
        integration_id: manifest.integration_id.clone(),
        binding_id: evidence.binding_id.clone(),
        manifest_hash,
        evidence_hash,
        observed_at_unix_seconds: evidence.observed_at_unix_seconds,
        expires_at_unix_seconds: evidence.expires_at_unix_seconds,
        topic_map: manifest.ros2.topic_map.clone(),
    });
    Ok(BindingCertification {
        report,
        certified: activation,
    })
}

fn validate_binding_input(input: &RuntimeBindingInput) -> Result<(), EmbodiedError> {
    if input.schema_version != 1 {
        return Err(EmbodiedError::Invalid(
            "runtime binding schema_version must be 1".to_owned(),
        ));
    }
    validate_token(&input.binding_id, "binding_id")?;
    validate_token(&input.integration_id, "integration_id")?;
    validate_token(&input.attestor_id, "attestor_id")?;
    if input.observed_at_unix_seconds == 0
        || input.expires_at_unix_seconds <= input.observed_at_unix_seconds
        || input.expires_at_unix_seconds - input.observed_at_unix_seconds
            > MAX_EVIDENCE_LIFETIME_SECONDS
    {
        return Err(EmbodiedError::Invalid(
            "runtime binding validity window is invalid or exceeds 15 minutes".to_owned(),
        ));
    }
    validate_runtime_binding(input)
}

fn validate_evidence(evidence: &RuntimeBindingEvidence) -> Result<(), EmbodiedError> {
    validate_binding_input(&RuntimeBindingInput {
        schema_version: evidence.schema_version,
        binding_id: evidence.binding_id.clone(),
        integration_id: evidence.integration_id.clone(),
        observed_at_unix_seconds: evidence.observed_at_unix_seconds,
        expires_at_unix_seconds: evidence.expires_at_unix_seconds,
        attestor_id: evidence.attestor_id.clone(),
        ros2: evidence.ros2.clone(),
        safety: evidence.safety.clone(),
        hardware: evidence.hardware.clone(),
    })?;
    let _ = hex_decode_array::<32>(&evidence.signer_public_key)?;
    let _ = hex_decode_array::<64>(&evidence.signature)?;
    Ok(())
}

fn validate_runtime_binding(input: &RuntimeBindingInput) -> Result<(), EmbodiedError> {
    for (value, field) in [
        (&input.ros2.distribution, "runtime ROS distribution"),
        (&input.ros2.version, "runtime ROS version"),
        (&input.ros2.client_library, "runtime ROS client library"),
        (
            &input.ros2.client_library_version,
            "runtime ROS client library version",
        ),
        (
            &input.ros2.rmw_implementation,
            "runtime ROS RMW implementation",
        ),
        (&input.ros2.node_name, "runtime ROS node name"),
        (&input.ros2.namespace, "runtime ROS namespace"),
        (
            &input.ros2.executor_implementation,
            "runtime ROS executor implementation",
        ),
        (&input.safety.controller_id, "runtime safety controller"),
        (&input.safety.protocol, "runtime safety protocol"),
        (
            &input.safety.protocol_version,
            "runtime safety protocol version",
        ),
        (
            &input.safety.permit_authentication,
            "runtime permit authentication",
        ),
        (&input.hardware.adapter_id, "runtime hardware adapter"),
        (&input.hardware.api_version, "runtime hardware API version"),
    ] {
        validate_text(value, field)?;
    }
    validate_hash(
        &input.hardware.hardware_profile_hash,
        "runtime hardware profile hash",
    )?;
    if input.ros2.topics.is_empty() || input.ros2.topics.len() > 10_000 {
        return Err(EmbodiedError::Invalid(
            "runtime ROS endpoint count is outside bounds".to_owned(),
        ));
    }
    let mut ids = BTreeSet::new();
    for topic in &input.ros2.topics {
        validate_token(&topic.contract_id, "runtime topic contract_id")?;
        crate::ros2::validate_topic(&topic.topic)?;
        validate_text(&topic.message_type, "runtime message type")?;
        validate_hash(&topic.message_type_hash, "runtime message type hash")?;
        validate_token(&topic.callback_group_id, "runtime callback group")?;
        if !ids.insert(&topic.contract_id) {
            return Err(EmbodiedError::Invalid(
                "runtime topic contract IDs are duplicated".to_owned(),
            ));
        }
    }
    Ok(())
}

fn verify_evidence_signature(evidence: &RuntimeBindingEvidence) -> Result<bool, EmbodiedError> {
    let public_bytes = hex_decode_array::<32>(&evidence.signer_public_key)?;
    let signature_bytes = hex_decode_array::<64>(&evidence.signature)?;
    let verifying_key = VerifyingKey::from_bytes(&public_bytes)
        .map_err(|error| EmbodiedError::Signature(error.to_string()))?;
    Ok(verifying_key
        .verify_strict(
            &json_bytes(&signed_payload(evidence))?,
            &Signature::from_bytes(&signature_bytes),
        )
        .is_ok())
}

fn compare_ros2(
    manifest: &IntegrationManifest,
    evidence: &RuntimeBindingEvidence,
    issues: &mut Vec<CertificationIssue>,
) {
    let expected = &manifest.ros2;
    let actual = &evidence.ros2;
    if expected.distribution != actual.distribution
        || expected.version != actual.version
        || expected.client_library != actual.client_library
        || expected.client_library_version != actual.client_library_version
        || expected.rmw_implementation != actual.rmw_implementation
        || expected.domain_id != actual.domain_id
        || expected.node_name != actual.node_name
        || expected.namespace != actual.namespace
        || expected.network_policy != actual.network_policy
        || expected.allowed_peers != actual.allowed_peers
    {
        push_issue(
            issues,
            "D2IC9110",
            "observed ROS 2 identity or network posture differs from the manifest",
            "deploy the reviewed distribution, client, RMW, domain, node, and network policy",
        );
    }
    if expected.executor.kind != actual.executor_kind
        || expected.executor.implementation != actual.executor_implementation
        || expected.executor.thread_count != actual.executor_thread_count
        || expected.executor.deterministic_ordering != actual.deterministic_ordering
        || expected.executor.bounded_callback_time != actual.bounded_callback_time
        || expected.executor.shutdown_timeout_millis != actual.shutdown_timeout_millis
    {
        push_issue(
            issues,
            "D2IC9111",
            "observed ROS 2 executor differs from the manifest",
            "bind the reviewed executor, callback bounds, thread count, and shutdown timeout",
        );
    }
    let expected_ids = expected
        .topics
        .iter()
        .map(|topic| topic.contract_id.as_str())
        .collect::<BTreeSet<_>>();
    let actual_ids = actual
        .topics
        .iter()
        .map(|topic| topic.contract_id.as_str())
        .collect::<BTreeSet<_>>();
    if expected_ids != actual_ids {
        push_issue(
            issues,
            "D2IC9112",
            "observed ROS 2 endpoint set differs from the manifest",
            "remove unreviewed endpoints and instantiate every reviewed endpoint",
        );
    }
    for contract in &expected.topics {
        let Some(binding) = actual
            .topics
            .iter()
            .find(|binding| binding.contract_id == contract.contract_id)
        else {
            continue;
        };
        if contract.topic != binding.topic
            || contract.direction != binding.direction
            || contract.message_type != binding.message_type
            || contract.message_type_hash != binding.message_type_hash
            || contract.callback_group_id != binding.callback_group_id
        {
            push_issue(
                issues,
                "D2IC9113",
                format!(
                    "observed endpoint '{}' type, topic, direction, or callback differs",
                    contract.contract_id
                ),
                "regenerate the endpoint from the reviewed contract and message type hash",
            );
        }
        if contract.adapter_qos != binding.adapter_qos || contract.peer_qos != binding.peer_qos {
            push_issue(
                issues,
                "D2IC9114",
                format!("observed endpoint '{}' QoS differs", contract.contract_id),
                "apply and re-observe both reviewed endpoint QoS profiles",
            );
        }
    }
}

fn compare_safety(
    manifest: &IntegrationManifest,
    evidence: &RuntimeBindingEvidence,
    issues: &mut Vec<CertificationIssue>,
) {
    let expected = &manifest.safety;
    let actual = &evidence.safety;
    if expected.controller_id != actual.controller_id
        || expected.protocol != actual.protocol
        || expected.protocol_version != actual.protocol_version
        || !expected
            .intent_hash_algorithm
            .eq_ignore_ascii_case(&actual.intent_hash_algorithm)
        || expected.permit_authentication != actual.permit_authentication
    {
        push_issue(
            issues,
            "D2IC9120",
            "observed safety-controller identity or protocol differs from the manifest",
            "bind the reviewed controller, protocol, intent hash, and permit authentication",
        );
    }
    if expected.permit_replay_protection != actual.permit_replay_protection
        || expected.fail_closed != actual.fail_closed
        || expected.emergency_stop_independent != actual.emergency_stop_independent
        || expected.monotonic_clock != actual.monotonic_clock
    {
        push_issue(
            issues,
            "D2IC9121",
            "observed safety-controller guarantees differ from the manifest",
            "restore fail-closed replay protection, independent emergency stop, and monotonic time",
        );
    }
    if actual.measured_maximum_assessment_latency_micros == 0
        || actual.measured_maximum_assessment_latency_micros
            > expected.maximum_assessment_latency_micros
    {
        push_issue(
            issues,
            "D2IC9122",
            "measured safety assessment latency exceeds the reviewed maximum",
            "reduce and re-measure safety-controller latency before activation",
        );
    }
}

fn compare_hardware(
    manifest: &IntegrationManifest,
    evidence: &RuntimeBindingEvidence,
    issues: &mut Vec<CertificationIssue>,
) -> Result<(), EmbodiedError> {
    let expected = &manifest.hardware;
    let actual = &evidence.hardware;
    if expected.adapter_id != actual.adapter_id
        || expected.api_version != actual.api_version
        || expected.hardware_profile.content_hash()? != actual.hardware_profile_hash
    {
        push_issue(
            issues,
            "D2IC9130",
            "observed hardware adapter identity, API, or profile differs from the manifest",
            "bind the reviewed adapter and exact immutable hardware profile",
        );
    }
    if expected.process_isolated != actual.process_isolated
        || expected.dispatch_idempotent != actual.dispatch_idempotent
        || expected.cancellation_supported != actual.cancellation_supported
        || expected.command_acknowledgement != actual.command_acknowledgement
        || expected.health_telemetry != actual.health_telemetry
        || expected.rollback_execution_supported != actual.rollback_execution_supported
    {
        push_issue(
            issues,
            "D2IC9131",
            "observed hardware lifecycle guarantees differ from the manifest",
            "restore reviewed isolation, dispatch, cancellation, health, and rollback behavior",
        );
    }
    Ok(())
}

fn signed_payload_from_input<'a>(
    input: &'a RuntimeBindingInput,
    signer_public_key: &'a str,
) -> SignedEvidencePayload<'a> {
    SignedEvidencePayload {
        schema_version: input.schema_version,
        binding_id: &input.binding_id,
        integration_id: &input.integration_id,
        observed_at_unix_seconds: input.observed_at_unix_seconds,
        expires_at_unix_seconds: input.expires_at_unix_seconds,
        attestor_id: &input.attestor_id,
        ros2: &input.ros2,
        safety: &input.safety,
        hardware: &input.hardware,
        signer_public_key,
    }
}

fn signed_payload(evidence: &RuntimeBindingEvidence) -> SignedEvidencePayload<'_> {
    SignedEvidencePayload {
        schema_version: evidence.schema_version,
        binding_id: &evidence.binding_id,
        integration_id: &evidence.integration_id,
        observed_at_unix_seconds: evidence.observed_at_unix_seconds,
        expires_at_unix_seconds: evidence.expires_at_unix_seconds,
        attestor_id: &evidence.attestor_id,
        ros2: &evidence.ros2,
        safety: &evidence.safety,
        hardware: &evidence.hardware,
        signer_public_key: &evidence.signer_public_key,
    }
}

fn push_issue(
    issues: &mut Vec<CertificationIssue>,
    code: &str,
    message: impl Into<String>,
    remediation: impl Into<String>,
) {
    issues.push(CertificationIssue {
        code: code.to_owned(),
        message: message.into(),
        remediation: remediation.into(),
    });
}
