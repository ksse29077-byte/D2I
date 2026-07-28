use crate::{
    json_bytes, sha256_bytes, validate_hash, validate_text, validate_token, EmbodiedError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Timing class at the cognition/safety boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadlineClass {
    SafetyLoop,
    Control,
    Interactive,
    Mission,
}

impl DeadlineClass {
    /// Maximum end-to-end latency represented by the class.
    #[must_use]
    pub const fn maximum_latency_ms(self) -> u64 {
        match self {
            Self::SafetyLoop => 20,
            Self::Control => 100,
            Self::Interactive => 1_000,
            Self::Mission => 30_000,
        }
    }

    /// Whether the deadline permits the D2I cognition/planning path.
    #[must_use]
    pub const fn allows_d2i_planning(self) -> bool {
        !matches!(self, Self::SafetyLoop)
    }
}

/// Supported sensor families without binding to a ROS message package.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorKind {
    Camera,
    Lidar,
    Imu,
    JointState,
    ForceTorque,
    Proximity,
    Battery,
    Custom,
}

/// Versioned sensor observation accepted as untrusted data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SensorEvent {
    pub schema_version: u32,
    pub event_id: String,
    pub robot_id: String,
    pub sequence: u64,
    pub observed_at_unix_nanos: u64,
    pub frame_id: String,
    pub sensor_kind: SensorKind,
    pub deadline_class: DeadlineClass,
    pub payload: Value,
    pub payload_hash: String,
    pub quality_milli: u16,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

impl SensorEvent {
    /// Validates identity, bounds, and payload integrity.
    pub fn validate(&self) -> Result<(), EmbodiedError> {
        if self.schema_version != 1 || self.observed_at_unix_nanos == 0 || self.quality_milli > 1000
        {
            return Err(EmbodiedError::Invalid(
                "sensor schema, timestamp, or quality is outside bounds".to_owned(),
            ));
        }
        validate_token(&self.event_id, "event_id")?;
        validate_token(&self.robot_id, "robot_id")?;
        validate_token(&self.frame_id, "frame_id")?;
        validate_hash(&self.payload_hash, "payload_hash")?;
        if self.labels.len() > 256 {
            return Err(EmbodiedError::Invalid(
                "sensor labels exceed 256 entries".to_owned(),
            ));
        }
        for (key, value) in &self.labels {
            validate_token(key, "sensor label key")?;
            validate_text(value, "sensor label value")?;
        }
        if sha256_bytes(&json_bytes(&self.payload)?) != self.payload_hash {
            return Err(EmbodiedError::Integrity(
                "sensor payload hash does not match payload".to_owned(),
            ));
        }
        let _ = json_bytes(self)?;
        Ok(())
    }
}

/// High-level action kinds. These are intentions, never motor commands.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    Navigate,
    Inspect,
    Manipulate,
    Dock,
    Hold,
    StopRequest,
    Custom,
}

/// One explicit condition that the external safety controller must enforce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyConstraint {
    pub constraint_id: String,
    pub description: String,
    pub hard: bool,
}

/// D2I-produced high-level action intention.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionIntent {
    pub schema_version: u32,
    pub intent_id: String,
    pub robot_id: String,
    pub generated_at_unix_nanos: u64,
    pub expires_at_unix_nanos: u64,
    pub deadline_class: DeadlineClass,
    pub action_kind: ActionKind,
    pub parameters: Value,
    pub constraints: Vec<SafetyConstraint>,
    pub source_build_id: String,
    pub source_package_content_hash: String,
    pub evidence_hashes: Vec<String>,
}

impl ActionIntent {
    /// Validates that an intent is bounded, package-bound, and outside the safety loop.
    pub fn validate(&self) -> Result<(), EmbodiedError> {
        if self.schema_version != 1
            || self.generated_at_unix_nanos == 0
            || self.expires_at_unix_nanos <= self.generated_at_unix_nanos
        {
            return Err(EmbodiedError::Invalid(
                "action schema or timestamps are invalid".to_owned(),
            ));
        }
        if !self.deadline_class.allows_d2i_planning() {
            return Err(EmbodiedError::Deadline(
                "safety-loop actions must bypass D2I and remain in the safety controller"
                    .to_owned(),
            ));
        }
        let lifetime_ms = self
            .expires_at_unix_nanos
            .saturating_sub(self.generated_at_unix_nanos)
            / 1_000_000;
        if lifetime_ms == 0 || lifetime_ms > self.deadline_class.maximum_latency_ms() {
            return Err(EmbodiedError::Deadline(
                "action lifetime exceeds its deadline class".to_owned(),
            ));
        }
        validate_token(&self.intent_id, "intent_id")?;
        validate_token(&self.robot_id, "robot_id")?;
        validate_token(&self.source_build_id, "source_build_id")?;
        validate_hash(
            &self.source_package_content_hash,
            "source_package_content_hash",
        )?;
        if self.constraints.is_empty()
            || self.constraints.len() > 256
            || self.evidence_hashes.is_empty()
            || self.evidence_hashes.len() > 256
        {
            return Err(EmbodiedError::Invalid(
                "action constraints or evidence count is outside bounds".to_owned(),
            ));
        }
        for constraint in &self.constraints {
            validate_token(&constraint.constraint_id, "constraint_id")?;
            validate_text(&constraint.description, "constraint description")?;
        }
        for hash in &self.evidence_hashes {
            validate_hash(hash, "evidence_hash")?;
        }
        let _ = json_bytes(self)?;
        Ok(())
    }

    /// Returns the canonical content hash used by safety and replay records.
    pub fn content_hash(&self) -> Result<String, EmbodiedError> {
        self.validate()?;
        Ok(sha256_bytes(&json_bytes(self)?))
    }
}
