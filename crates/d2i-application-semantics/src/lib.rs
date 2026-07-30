//! Application Semantics Contract v1 and deterministic observation bridges.
//!
//! This crate owns no application adapter, module implementation, policy
//! authority, or side effect. It binds immutable application metadata to an
//! already validated Cognitive IR v1 observation and emits the module-owned
//! JSON payload expected by Element Grounder v1.

use d2i_cognitive_ir::{
    ObservableElement, ObservationSnapshot, ObservationSourceKind, Provenance, RedactionMetadata,
    TrustLabel,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Application Semantics Contract version.
pub const APPLICATION_SEMANTICS_SCHEMA_VERSION: u32 = 1;
/// Authoritative Application Semantics Contract v1 JSON Schema.
pub const APPLICATION_SEMANTICS_V1_SCHEMA: &str =
    include_str!("../../../schemas/cognitive/application-semantics-v1.schema.json");
/// Element Grounder v1 payload schema identifier.
pub const ELEMENT_GROUNDER_INPUT_SCHEMA_ID: &str = "element-grounding-input-v1";
/// Element Grounder v1 payload schema version.
pub const ELEMENT_GROUNDER_INPUT_SCHEMA_VERSION: u32 = 1;

const MAX_ID_BYTES: usize = 128;
const MAX_TEXT_BYTES: usize = 4_096;
const MAX_BINDINGS: usize = 64;
const MAX_TARGETS: usize = 256;
const MAX_TERMS: usize = 64;
const MAX_FIXTURE_CASES: usize = 256;
const MAX_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
const MAX_CANDIDATES: u32 = 64;

/// Structured Application Semantics failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationSemanticsError {
    /// A contract field is malformed or outside its bound.
    Invalid(String),
    /// A hash, binding, trust label, or source identity does not match.
    Integrity(String),
    /// A requested semantic target or expected element is absent.
    NotFound(String),
    /// A supposedly unique fixture binding is ambiguous.
    Ambiguous(String),
    /// Serialization failed.
    Json(String),
}

impl Display for ApplicationSemanticsError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid application semantics: {message}"),
            Self::Integrity(message) => {
                write!(
                    formatter,
                    "application semantics integrity failure: {message}"
                )
            }
            Self::NotFound(message) => {
                write!(
                    formatter,
                    "application semantics target not found: {message}"
                )
            }
            Self::Ambiguous(message) => {
                write!(
                    formatter,
                    "ambiguous application semantics binding: {message}"
                )
            }
            Self::Json(message) => {
                write!(formatter, "application semantics JSON failure: {message}")
            }
        }
    }
}

impl Error for ApplicationSemanticsError {}

impl From<d2i_cognitive_ir::CognitiveIrError> for ApplicationSemanticsError {
    fn from(error: d2i_cognitive_ir::CognitiveIrError) -> Self {
        Self::Integrity(error.to_string())
    }
}

/// Provenance for an immutable application pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationPackProvenance {
    pub source_id: String,
    pub source_sha256: String,
    pub producer: String,
}

/// One semantic target known to an application pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationSemanticTarget {
    pub target_id: String,
    pub canonical_label: String,
    pub aliases: Vec<String>,
    pub expected_kinds: Vec<String>,
    pub required_terms: Vec<String>,
    pub excluded_terms: Vec<String>,
    pub context_terms: Vec<String>,
}

/// Immutable application-specific semantic vocabulary and observation binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationPack {
    pub schema_version: u32,
    pub pack_id: String,
    pub pack_version: String,
    pub application_id: String,
    pub display_name: String,
    pub supported_source_kinds: Vec<ObservationSourceKind>,
    pub required_target_binding: BTreeMap<String, String>,
    pub targets: Vec<ApplicationSemanticTarget>,
    pub provenance: ApplicationPackProvenance,
    pub pack_sha256: String,
}

impl ApplicationPack {
    /// Computes the canonical pack hash with `pack_sha256` omitted.
    pub fn compute_pack_sha256(&self) -> Result<String, ApplicationSemanticsError> {
        let mut value =
            serde_json::to_value(self).map_err(|error| json_error("serialize pack", error))?;
        let object = value.as_object_mut().ok_or_else(|| {
            ApplicationSemanticsError::Json(
                "application pack did not serialize as an object".to_owned(),
            )
        })?;
        object.remove("pack_sha256");
        hash_value(&value)
    }

    /// Replaces `pack_sha256` with the canonical hash.
    pub fn seal(mut self) -> Result<Self, ApplicationSemanticsError> {
        self.pack_sha256 = self.compute_pack_sha256()?;
        Ok(self)
    }

    /// Validates all bounds, identities, uniqueness rules, and the pack hash.
    pub fn validate(&self) -> Result<(), ApplicationSemanticsError> {
        if self.schema_version != APPLICATION_SEMANTICS_SCHEMA_VERSION {
            return invalid("application pack schema_version must be 1");
        }
        validate_id(&self.pack_id, "pack_id")?;
        validate_version(&self.pack_version, "pack_version")?;
        validate_id(&self.application_id, "application_id")?;
        validate_text(&self.display_name, "display_name")?;
        validate_hash(&self.pack_sha256, "pack_sha256")?;
        validate_id(&self.provenance.source_id, "provenance source_id")?;
        validate_hash(&self.provenance.source_sha256, "provenance source_sha256")?;
        validate_id(&self.provenance.producer, "provenance producer")?;
        reject_raw_secret(&self.display_name, "display_name")?;

        if self.supported_source_kinds.is_empty() {
            return invalid("supported_source_kinds must not be empty");
        }
        let mut source_kinds = BTreeSet::new();
        for source_kind in &self.supported_source_kinds {
            if !matches!(
                source_kind,
                ObservationSourceKind::Uia | ObservationSourceKind::WebDriver
            ) {
                return invalid("application packs support only uia and web_driver observations");
            }
            let source = source_kind_token(*source_kind)?;
            if !source_kinds.insert(source) {
                return invalid("supported_source_kinds contains a duplicate");
            }
        }

        if self.required_target_binding.is_empty()
            || self.required_target_binding.len() > MAX_BINDINGS
        {
            return invalid("required_target_binding must contain between 1 and 64 entries");
        }
        for (key, value) in &self.required_target_binding {
            validate_id(key, "required target binding key")?;
            validate_text(value, "required target binding value")?;
            reject_raw_secret(value, "required target binding value")?;
        }

        if self.targets.is_empty() || self.targets.len() > MAX_TARGETS {
            return invalid("targets must contain between 1 and 256 entries");
        }
        let mut target_ids = BTreeSet::new();
        for target in &self.targets {
            target.validate()?;
            if !target_ids.insert(target.target_id.as_str()) {
                return invalid("application pack contains a duplicate target_id");
            }
        }

        if self.compute_pack_sha256()? != self.pack_sha256 {
            return Err(ApplicationSemanticsError::Integrity(
                "pack_sha256 does not match the canonical application pack".to_owned(),
            ));
        }
        Ok(())
    }

    fn target(
        &self,
        target_id: &str,
    ) -> Result<&ApplicationSemanticTarget, ApplicationSemanticsError> {
        let mut matches = self
            .targets
            .iter()
            .filter(|target| target.target_id == target_id);
        let target = matches.next().ok_or_else(|| {
            ApplicationSemanticsError::NotFound(format!(
                "semantic target '{target_id}' is absent from the application pack"
            ))
        })?;
        if matches.next().is_some() {
            return Err(ApplicationSemanticsError::Ambiguous(format!(
                "semantic target '{target_id}' is duplicated"
            )));
        }
        Ok(target)
    }

    fn verify_observation(
        &self,
        observation: &ObservationSnapshot,
    ) -> Result<(), ApplicationSemanticsError> {
        observation.validate()?;
        validate_observation_trust(observation)?;
        if !self
            .supported_source_kinds
            .contains(&observation.source_kind)
        {
            return Err(ApplicationSemanticsError::Integrity(
                "observation source kind is not supported by the application pack".to_owned(),
            ));
        }
        for (key, expected) in &self.required_target_binding {
            match observation.target_binding.get(key) {
                Some(actual) if actual == expected => {}
                Some(_) => {
                    return Err(ApplicationSemanticsError::Integrity(format!(
                        "observation target binding '{key}' differs from the application pack"
                    )));
                }
                None => {
                    return Err(ApplicationSemanticsError::Integrity(format!(
                        "observation target binding omits required key '{key}'"
                    )));
                }
            }
        }
        Ok(())
    }
}

impl ApplicationSemanticTarget {
    fn validate(&self) -> Result<(), ApplicationSemanticsError> {
        validate_id(&self.target_id, "semantic target_id")?;
        validate_text(&self.canonical_label, "semantic canonical_label")?;
        reject_raw_secret(&self.canonical_label, "semantic canonical_label")?;
        validate_text_collection(&self.aliases, "semantic aliases", true)?;
        validate_id_collection(&self.expected_kinds, "semantic expected_kinds", true)?;
        validate_text_collection(&self.required_terms, "semantic required_terms", false)?;
        validate_text_collection(&self.excluded_terms, "semantic excluded_terms", false)?;
        validate_text_collection(&self.context_terms, "semantic context_terms", false)?;
        for value in self
            .aliases
            .iter()
            .chain(self.required_terms.iter())
            .chain(self.excluded_terms.iter())
            .chain(self.context_terms.iter())
        {
            reject_raw_secret(value, "semantic term")?;
        }
        Ok(())
    }
}

/// One expected grounding result in a synthetic observation fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationGroundingCase {
    pub case_id: String,
    pub semantic_target_id: String,
    pub target_text: String,
    pub expected_element_id: String,
    pub max_candidates: u32,
}

/// Synthetic, side-effect-free observation fixture authoring contract.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationFixture {
    pub schema_version: u32,
    pub fixture_id: String,
    pub application_pack_sha256: String,
    pub observation_id: String,
    pub source_kind: ObservationSourceKind,
    pub target_binding: BTreeMap<String, String>,
    pub sequence: u64,
    pub trust_labels: BTreeSet<TrustLabel>,
    pub observable_elements: Vec<ObservableElement>,
    pub redactions: Vec<RedactionMetadata>,
    pub provenance: Provenance,
    pub grounding_cases: Vec<ObservationGroundingCase>,
}

impl ObservationFixture {
    /// Converts a fixture into a validated Cognitive IR v1 snapshot.
    pub fn build_snapshot(&self) -> Result<ObservationSnapshot, ApplicationSemanticsError> {
        if self.schema_version != APPLICATION_SEMANTICS_SCHEMA_VERSION {
            return invalid("observation fixture schema_version must be 1");
        }
        validate_id(&self.fixture_id, "fixture_id")?;
        validate_hash(&self.application_pack_sha256, "application_pack_sha256")?;
        validate_id(&self.observation_id, "observation_id")?;
        if !matches!(
            self.source_kind,
            ObservationSourceKind::Uia | ObservationSourceKind::WebDriver
        ) {
            return invalid("observation fixtures support only uia and web_driver sources");
        }
        if self.grounding_cases.is_empty() || self.grounding_cases.len() > MAX_FIXTURE_CASES {
            return invalid("grounding_cases must contain between 1 and 256 entries");
        }
        if self.target_binding.len() > MAX_BINDINGS {
            return invalid("observation fixture target_binding exceeds 64 entries");
        }
        let mut case_ids = BTreeSet::new();
        for case in &self.grounding_cases {
            case.validate()?;
            if !case_ids.insert(case.case_id.as_str()) {
                return invalid("observation fixture contains a duplicate case_id");
            }
        }
        let mut element_ids = BTreeSet::new();
        for element in &self.observable_elements {
            if !element_ids.insert(element.element_id.as_str()) {
                return Err(ApplicationSemanticsError::Ambiguous(format!(
                    "element_id '{}' is duplicated",
                    element.element_id
                )));
            }
        }
        for redaction in &self.redactions {
            let element_id = redaction_element_id(&redaction.field)?;
            if !element_ids.contains(element_id) {
                return Err(ApplicationSemanticsError::Integrity(
                    "fixture redaction references an unknown element".to_owned(),
                ));
            }
        }

        let mut snapshot = ObservationSnapshot {
            schema_version: 1,
            observation_id: self.observation_id.clone(),
            source_kind: self.source_kind,
            target_binding: self.target_binding.clone(),
            state_hash: empty_sha256(),
            sequence: self.sequence,
            trust_labels: self.trust_labels.clone(),
            observable_elements: self.observable_elements.clone(),
            redactions: self.redactions.clone(),
            provenance: self.provenance.clone(),
        };
        snapshot.state_hash = snapshot.compute_state_hash()?;
        snapshot.validate()?;
        validate_observation_trust(&snapshot)?;
        Ok(snapshot)
    }
}

impl ObservationGroundingCase {
    fn validate(&self) -> Result<(), ApplicationSemanticsError> {
        validate_id(&self.case_id, "grounding case_id")?;
        validate_id(&self.semantic_target_id, "grounding semantic_target_id")?;
        validate_text(&self.target_text, "grounding target_text")?;
        reject_raw_secret(&self.target_text, "grounding target_text")?;
        validate_id(&self.expected_element_id, "grounding expected_element_id")?;
        if self.max_candidates == 0 || self.max_candidates > MAX_CANDIDATES {
            return invalid("grounding max_candidates must be between 1 and 64");
        }
        Ok(())
    }
}

/// Runtime-neutral request for an Element Grounder v1 payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementGrounderBridgeRequest {
    pub schema_version: u32,
    pub application_pack_sha256: String,
    pub semantic_target_id: String,
    pub target_text: String,
    pub goal_id: String,
    pub plan_generation_id: String,
    pub max_candidates: u32,
    pub replay_id: String,
    pub replay_seed: u64,
}

impl ElementGrounderBridgeRequest {
    fn validate(&self) -> Result<(), ApplicationSemanticsError> {
        if self.schema_version != APPLICATION_SEMANTICS_SCHEMA_VERSION {
            return invalid("Element Grounder bridge request schema_version must be 1");
        }
        validate_hash(
            &self.application_pack_sha256,
            "bridge application_pack_sha256",
        )?;
        validate_id(&self.semantic_target_id, "bridge semantic_target_id")?;
        validate_text(&self.target_text, "bridge target_text")?;
        reject_raw_secret(&self.target_text, "bridge target_text")?;
        validate_id(&self.goal_id, "bridge goal_id")?;
        validate_id(&self.plan_generation_id, "bridge plan_generation_id")?;
        validate_id(&self.replay_id, "bridge replay_id")?;
        if self.max_candidates == 0 || self.max_candidates > MAX_CANDIDATES {
            return invalid("bridge max_candidates must be between 1 and 64");
        }
        Ok(())
    }
}

/// Stable Element Grounder payload and its canonical hash.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementGrounderPayload {
    pub schema_version: u32,
    pub schema_id: String,
    pub schema_revision: u32,
    pub application_pack_sha256: String,
    pub semantic_target_id: String,
    pub source_observation_hash: String,
    pub payload: Value,
    pub payload_sha256: String,
}

impl ElementGrounderPayload {
    /// Validates payload metadata and recomputes its canonical hash.
    pub fn validate(&self) -> Result<(), ApplicationSemanticsError> {
        if self.schema_version != APPLICATION_SEMANTICS_SCHEMA_VERSION
            || self.schema_id != ELEMENT_GROUNDER_INPUT_SCHEMA_ID
            || self.schema_revision != ELEMENT_GROUNDER_INPUT_SCHEMA_VERSION
        {
            return invalid("Element Grounder payload schema identity is invalid");
        }
        validate_hash(
            &self.application_pack_sha256,
            "payload application_pack_sha256",
        )?;
        validate_id(&self.semantic_target_id, "payload semantic_target_id")?;
        validate_hash(
            &self.source_observation_hash,
            "payload source_observation_hash",
        )?;
        validate_hash(&self.payload_sha256, "payload_sha256")?;
        let payload_bytes = canonical_json_bytes(&self.payload)?;
        if payload_bytes.len() > MAX_PAYLOAD_BYTES {
            return invalid("Element Grounder payload exceeds 8 MiB");
        }
        if sha256_bytes(&payload_bytes) != self.payload_sha256 {
            return Err(ApplicationSemanticsError::Integrity(
                "payload_sha256 does not match the Element Grounder payload".to_owned(),
            ));
        }
        if self
            .payload
            .get("source_observation_hash")
            .and_then(Value::as_str)
            != Some(self.source_observation_hash.as_str())
        {
            return Err(ApplicationSemanticsError::Integrity(
                "Element Grounder payload source hash differs from its envelope".to_owned(),
            ));
        }
        Ok(())
    }
}

/// One bridged fixture case with an oracle kept outside the module payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgedGroundingCase {
    pub case_id: String,
    pub expected_element_id: String,
    pub element_grounder: ElementGrounderPayload,
    pub evidence: Vec<String>,
}

/// Deterministic bundle generated from one application pack and observation fixture.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationFixtureBridge {
    pub schema_version: u32,
    pub fixture_id: String,
    pub application_pack_sha256: String,
    pub observation_snapshot: ObservationSnapshot,
    pub cases: Vec<BridgedGroundingCase>,
    pub bridge_sha256: String,
}

impl ObservationFixtureBridge {
    /// Computes the canonical bridge hash with `bridge_sha256` omitted.
    pub fn compute_bridge_sha256(&self) -> Result<String, ApplicationSemanticsError> {
        let mut value =
            serde_json::to_value(self).map_err(|error| json_error("serialize bridge", error))?;
        let object = value.as_object_mut().ok_or_else(|| {
            ApplicationSemanticsError::Json(
                "observation fixture bridge did not serialize as an object".to_owned(),
            )
        })?;
        object.remove("bridge_sha256");
        hash_value(&value)
    }

    /// Validates all case hashes and the bridge self-hash.
    pub fn validate(&self) -> Result<(), ApplicationSemanticsError> {
        if self.schema_version != APPLICATION_SEMANTICS_SCHEMA_VERSION {
            return invalid("observation fixture bridge schema_version must be 1");
        }
        validate_id(&self.fixture_id, "bridge fixture_id")?;
        validate_hash(
            &self.application_pack_sha256,
            "bridge application_pack_sha256",
        )?;
        validate_hash(&self.bridge_sha256, "bridge_sha256")?;
        self.observation_snapshot.validate()?;
        validate_observation_trust(&self.observation_snapshot)?;
        if self.cases.is_empty() || self.cases.len() > MAX_FIXTURE_CASES {
            return invalid("bridged cases must contain between 1 and 256 entries");
        }
        let mut case_ids = BTreeSet::new();
        for case in &self.cases {
            validate_id(&case.case_id, "bridged case_id")?;
            validate_id(&case.expected_element_id, "bridged expected_element_id")?;
            if !case_ids.insert(case.case_id.as_str()) {
                return invalid("bridged cases contain a duplicate case_id");
            }
            case.element_grounder.validate()?;
            if case.element_grounder.application_pack_sha256 != self.application_pack_sha256
                || case.element_grounder.source_observation_hash
                    != self.observation_snapshot.state_hash
            {
                return Err(ApplicationSemanticsError::Integrity(
                    "bridged case pack or observation hash differs from its bridge".to_owned(),
                ));
            }
            let element = unique_element(&self.observation_snapshot, &case.expected_element_id)?
                .ok_or_else(|| {
                    ApplicationSemanticsError::NotFound(format!(
                        "expected element '{}' is absent from the bridged observation",
                        case.expected_element_id
                    ))
                })?;
            ensure_expected_element_is_safe(&self.observation_snapshot, element)?;
            let expected_evidence = vec![
                format!("application-pack:{}", self.application_pack_sha256),
                format!("observation:{}", self.observation_snapshot.state_hash),
                format!(
                    "semantic-target:{}",
                    case.element_grounder.semantic_target_id
                ),
                format!("expected-element:{}", case.expected_element_id),
            ];
            if case.evidence != expected_evidence {
                return Err(ApplicationSemanticsError::Integrity(
                    "bridged case evidence differs from its bound identities".to_owned(),
                ));
            }
        }
        if self.compute_bridge_sha256()? != self.bridge_sha256 {
            return Err(ApplicationSemanticsError::Integrity(
                "bridge_sha256 does not match the canonical bridge".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Builds the module-owned Element Grounder v1 JSON payload.
pub fn build_element_grounder_payload(
    pack: &ApplicationPack,
    observation: &ObservationSnapshot,
    request: &ElementGrounderBridgeRequest,
) -> Result<ElementGrounderPayload, ApplicationSemanticsError> {
    pack.validate()?;
    request.validate()?;
    if request.application_pack_sha256 != pack.pack_sha256 {
        return Err(ApplicationSemanticsError::Integrity(
            "bridge request references a different application pack".to_owned(),
        ));
    }
    pack.verify_observation(observation)?;
    let target = pack.target(&request.semantic_target_id)?;

    let context_terms = stable_terms(target.aliases.iter().chain(target.context_terms.iter()));
    let payload = json!({
        "schema_version": 1,
        "goal_id": request.goal_id,
        "target_text": request.target_text,
        "observation_snapshot": observation,
        "world_state": null,
        "expected_kinds": target.expected_kinds,
        "required_terms": target.required_terms,
        "excluded_terms": target.excluded_terms,
        "context_terms": context_terms,
        "max_candidates": request.max_candidates,
        "source_observation_hash": observation.state_hash,
        "plan_generation_id": request.plan_generation_id,
        "trust_labels": observation.trust_labels,
        "replay_context": {
            "replay_id": request.replay_id,
            "seed": request.replay_seed
        }
    });
    let payload_bytes = canonical_json_bytes(&payload)?;
    if payload_bytes.len() > MAX_PAYLOAD_BYTES {
        return invalid("Element Grounder payload exceeds 8 MiB");
    }
    let result = ElementGrounderPayload {
        schema_version: 1,
        schema_id: ELEMENT_GROUNDER_INPUT_SCHEMA_ID.to_owned(),
        schema_revision: ELEMENT_GROUNDER_INPUT_SCHEMA_VERSION,
        application_pack_sha256: pack.pack_sha256.clone(),
        semantic_target_id: target.target_id.clone(),
        source_observation_hash: observation.state_hash.clone(),
        payload_sha256: sha256_bytes(&payload_bytes),
        payload,
    };
    result.validate()?;
    Ok(result)
}

/// Builds deterministic Element Grounder payloads from an observation fixture.
pub fn bridge_observation_fixture(
    pack: &ApplicationPack,
    fixture: &ObservationFixture,
    goal_id: &str,
    plan_generation_id: &str,
    replay_seed: u64,
) -> Result<ObservationFixtureBridge, ApplicationSemanticsError> {
    pack.validate()?;
    validate_id(goal_id, "fixture bridge goal_id")?;
    validate_id(plan_generation_id, "fixture bridge plan_generation_id")?;
    if fixture.application_pack_sha256 != pack.pack_sha256 {
        return Err(ApplicationSemanticsError::Integrity(
            "observation fixture references a different application pack".to_owned(),
        ));
    }
    let snapshot = fixture.build_snapshot()?;
    pack.verify_observation(&snapshot)?;

    let mut cases = Vec::with_capacity(fixture.grounding_cases.len());
    for fixture_case in &fixture.grounding_cases {
        let target = pack.target(&fixture_case.semantic_target_id)?;
        let element =
            unique_element(&snapshot, &fixture_case.expected_element_id)?.ok_or_else(|| {
                ApplicationSemanticsError::NotFound(format!(
                    "expected element '{}' is absent from the observation",
                    fixture_case.expected_element_id
                ))
            })?;
        ensure_expected_element_is_safe(&snapshot, element)?;
        if !target.expected_kinds.is_empty()
            && !target
                .expected_kinds
                .iter()
                .any(|kind| kind == &element.kind)
        {
            return Err(ApplicationSemanticsError::Integrity(format!(
                "expected element '{}' has kind '{}' outside semantic target '{}'",
                element.element_id, element.kind, target.target_id
            )));
        }
        let request = ElementGrounderBridgeRequest {
            schema_version: 1,
            application_pack_sha256: pack.pack_sha256.clone(),
            semantic_target_id: fixture_case.semantic_target_id.clone(),
            target_text: fixture_case.target_text.clone(),
            goal_id: goal_id.to_owned(),
            plan_generation_id: plan_generation_id.to_owned(),
            max_candidates: fixture_case.max_candidates,
            replay_id: format!("{}-{}", fixture.fixture_id, fixture_case.case_id),
            replay_seed,
        };
        let element_grounder = build_element_grounder_payload(pack, &snapshot, &request)?;
        let evidence = vec![
            format!("application-pack:{}", pack.pack_sha256),
            format!("observation:{}", snapshot.state_hash),
            format!("semantic-target:{}", target.target_id),
            format!("expected-element:{}", element.element_id),
        ];
        cases.push(BridgedGroundingCase {
            case_id: fixture_case.case_id.clone(),
            expected_element_id: element.element_id.clone(),
            element_grounder,
            evidence,
        });
    }
    cases.sort_by(|left, right| left.case_id.cmp(&right.case_id));

    let mut bridge = ObservationFixtureBridge {
        schema_version: 1,
        fixture_id: fixture.fixture_id.clone(),
        application_pack_sha256: pack.pack_sha256.clone(),
        observation_snapshot: snapshot,
        cases,
        bridge_sha256: empty_sha256(),
    };
    bridge.bridge_sha256 = bridge.compute_bridge_sha256()?;
    bridge.validate()?;
    Ok(bridge)
}

fn unique_element<'a>(
    observation: &'a ObservationSnapshot,
    element_id: &str,
) -> Result<Option<&'a ObservableElement>, ApplicationSemanticsError> {
    let mut matches = observation
        .observable_elements
        .iter()
        .filter(|element| element.element_id == element_id);
    let first = matches.next();
    if matches.next().is_some() {
        return Err(ApplicationSemanticsError::Ambiguous(format!(
            "element_id '{element_id}' is duplicated"
        )));
    }
    Ok(first)
}

fn ensure_expected_element_is_safe(
    observation: &ObservationSnapshot,
    element: &ObservableElement,
) -> Result<(), ApplicationSemanticsError> {
    if element.element_id == "observation.status" {
        return invalid("observation.status cannot be a grounding oracle");
    }
    if raw_secret_marker(&element.label) {
        return Err(ApplicationSemanticsError::Integrity(
            "secret-bearing observed labels cannot be grounding oracles".to_owned(),
        ));
    }
    if observation
        .redactions
        .iter()
        .filter_map(|redaction| redaction_element_id(&redaction.field).ok())
        .any(|redacted_element_id| redacted_element_id == element.element_id)
    {
        return Err(ApplicationSemanticsError::Integrity(
            "redacted elements cannot be grounding oracles".to_owned(),
        ));
    }
    Ok(())
}

fn redaction_element_id(field: &str) -> Result<&str, ApplicationSemanticsError> {
    field
        .rsplit_once('.')
        .filter(|(element_id, redacted_field)| !element_id.is_empty() && !redacted_field.is_empty())
        .map(|(element_id, _)| element_id)
        .ok_or_else(|| {
            ApplicationSemanticsError::Invalid(
                "fixture redaction field must be element_id.field".to_owned(),
            )
        })
}

fn validate_observation_trust(
    observation: &ObservationSnapshot,
) -> Result<(), ApplicationSemanticsError> {
    let required_untrusted = match observation.source_kind {
        ObservationSourceKind::Uia => TrustLabel::UntrustedDocumentContent,
        ObservationSourceKind::WebDriver => TrustLabel::UntrustedWebContent,
        _ => {
            return invalid("application semantics support only uia and web_driver observations");
        }
    };
    if !observation
        .trust_labels
        .contains(&TrustLabel::ObservedUiState)
        || !observation.trust_labels.contains(&required_untrusted)
    {
        return Err(ApplicationSemanticsError::Integrity(
            "observation omits required observed and untrusted-content labels".to_owned(),
        ));
    }
    if observation.trust_labels.iter().any(is_authority_label) {
        return Err(ApplicationSemanticsError::Integrity(
            "observation content cannot carry instruction or policy authority".to_owned(),
        ));
    }
    for element in &observation.observable_elements {
        if !element.trust_labels.contains(&TrustLabel::ObservedUiState)
            || !element.trust_labels.contains(&required_untrusted)
            || element.trust_labels.iter().any(is_authority_label)
        {
            return Err(ApplicationSemanticsError::Integrity(format!(
                "observed element '{}' has invalid trust authority",
                element.element_id
            )));
        }
    }
    Ok(())
}

fn is_authority_label(label: &TrustLabel) -> bool {
    matches!(
        label,
        TrustLabel::AuthenticatedUserInstruction
            | TrustLabel::ApprovedPolicy
            | TrustLabel::ApprovedProcedure
            | TrustLabel::VerifiedOperationalState
    )
}

fn stable_terms<'a>(values: impl Iterator<Item = &'a String>) -> Vec<String> {
    values
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn validate_text_collection(
    values: &[String],
    field: &str,
    require_nonempty: bool,
) -> Result<(), ApplicationSemanticsError> {
    if values.len() > MAX_TERMS || (require_nonempty && values.is_empty()) {
        return invalid(format!(
            "{field} must contain {} to {MAX_TERMS} entries",
            usize::from(require_nonempty)
        ));
    }
    let mut unique = BTreeSet::new();
    for value in values {
        validate_text(value, field)?;
        if !unique.insert(value.as_str()) {
            return invalid(format!("{field} contains a duplicate"));
        }
    }
    Ok(())
}

fn validate_id_collection(
    values: &[String],
    field: &str,
    require_nonempty: bool,
) -> Result<(), ApplicationSemanticsError> {
    validate_text_collection(values, field, require_nonempty)?;
    for value in values {
        validate_id(value, field)?;
    }
    Ok(())
}

fn validate_text(value: &str, field: &str) -> Result<(), ApplicationSemanticsError> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES || value.chars().any(char::is_control) {
        return invalid(format!(
            "{field} is empty, contains control characters, or exceeds 4096 bytes"
        ));
    }
    Ok(())
}

fn validate_id(value: &str, field: &str) -> Result<(), ApplicationSemanticsError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return invalid(format!("{field} is not a bounded stable identifier"));
    }
    Ok(())
}

fn validate_version(value: &str, field: &str) -> Result<(), ApplicationSemanticsError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
    {
        return invalid(format!("{field} is not a bounded version"));
    }
    Ok(())
}

fn validate_hash(value: &str, field: &str) -> Result<(), ApplicationSemanticsError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return invalid(format!("{field} must use sha256:<lowercase hex>"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return invalid(format!("{field} has invalid SHA-256 syntax"));
    }
    Ok(())
}

fn reject_raw_secret(value: &str, field: &str) -> Result<(), ApplicationSemanticsError> {
    if raw_secret_marker(value) {
        return Err(ApplicationSemanticsError::Integrity(format!(
            "{field} contains raw secret-like material"
        )));
    }
    Ok(())
}

fn raw_secret_marker(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    [
        "password=",
        "password:",
        "token=",
        "token:",
        "api_key=",
        "api-key=",
        "authorization:",
        "bearer ",
        "cookie:",
        "secret=",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

fn source_kind_token(
    source_kind: ObservationSourceKind,
) -> Result<&'static str, ApplicationSemanticsError> {
    match source_kind {
        ObservationSourceKind::Uia => Ok("uia"),
        ObservationSourceKind::WebDriver => Ok("web_driver"),
        _ => invalid("application semantics support only uia and web_driver sources"),
    }
}

fn hash_value<T: Serialize>(value: &T) -> Result<String, ApplicationSemanticsError> {
    Ok(sha256_bytes(&canonical_json_bytes(value)?))
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ApplicationSemanticsError> {
    let value = serde_json::to_value(value)
        .map_err(|error| json_error("convert canonical value", error))?;
    let canonical = canonicalize_value(value);
    serde_json::to_vec(&canonical).map_err(|error| json_error("serialize canonical value", error))
}

fn canonicalize_value(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let ordered = object
                .into_iter()
                .map(|(key, value)| (key, canonicalize_value(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(ordered.into_iter().collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(canonicalize_value).collect()),
        other => other,
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn empty_sha256() -> String {
    sha256_bytes(&[])
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ApplicationSemanticsError> {
    Err(ApplicationSemanticsError::Invalid(message.into()))
}

fn json_error(context: &str, error: serde_json::Error) -> ApplicationSemanticsError {
    ApplicationSemanticsError::Json(format!("{context}: {error}"))
}
