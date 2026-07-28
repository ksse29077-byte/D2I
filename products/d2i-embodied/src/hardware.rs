use crate::{
    validate_permit, validate_text, validate_token, ActionIntent, ActionKind, EmbodiedError,
    SafetyAssessment, SensorKind,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Explicit capability declaration for one robot hardware boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareProfile {
    pub profile_id: String,
    pub robot_id: String,
    pub robot_class: String,
    pub sensor_kinds: BTreeSet<SensorKind>,
    pub action_kinds: BTreeSet<ActionKind>,
    pub safety_controller_required: bool,
    pub maximum_command_bytes: u64,
}

impl HardwareProfile {
    /// Validates a complete, safety-separated hardware capability declaration.
    pub fn validate(&self) -> Result<(), EmbodiedError> {
        validate_token(&self.profile_id, "profile_id")?;
        validate_token(&self.robot_id, "robot_id")?;
        validate_text(&self.robot_class, "robot_class")?;
        if self.sensor_kinds.is_empty()
            || self.action_kinds.is_empty()
            || !self.safety_controller_required
            || self.maximum_command_bytes == 0
            || self.maximum_command_bytes > 2 * 1024 * 1024
        {
            return Err(EmbodiedError::Invalid(
                "hardware profile is incomplete or unsafe".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns the canonical hash used by fleet rollout records.
    pub fn content_hash(&self) -> Result<String, EmbodiedError> {
        self.validate()?;
        Ok(crate::sha256_bytes(&crate::json_bytes(self)?))
    }
}

/// Hardware dispatch port. Implementations remain outside D2I.
pub trait HardwarePort {
    /// Returns the immutable capability contract for this port.
    fn profile(&self) -> &HardwareProfile;

    /// Dispatches an intent after the caller has validated its safety permit.
    fn dispatch_authorized(
        &mut self,
        intent: &ActionIntent,
        assessment: &SafetyAssessment,
    ) -> Result<(), EmbodiedError>;
}

/// Placeholder that prevents accidental physical actuation.
#[derive(Debug)]
pub struct UnavailableHardwarePort {
    profile: HardwareProfile,
}

impl UnavailableHardwarePort {
    /// Creates a fail-closed port with a validated profile.
    pub fn new(profile: HardwareProfile) -> Result<Self, EmbodiedError> {
        profile.validate()?;
        Ok(Self { profile })
    }
}

impl HardwarePort for UnavailableHardwarePort {
    fn profile(&self) -> &HardwareProfile {
        &self.profile
    }

    fn dispatch_authorized(
        &mut self,
        _intent: &ActionIntent,
        _assessment: &SafetyAssessment,
    ) -> Result<(), EmbodiedError> {
        Err(EmbodiedError::AdapterUnavailable(
            "TODO: bind a documented hardware command API".to_owned(),
        ))
    }
}

/// Checks hardware capability and safety permit before crossing the hardware port.
pub fn dispatch_authorized(
    port: &mut dyn HardwarePort,
    intent: &ActionIntent,
    assessment: &SafetyAssessment,
    now_unix_nanos: u64,
) -> Result<(), EmbodiedError> {
    validate_permit(intent, assessment, now_unix_nanos)?;
    let profile = port.profile();
    profile.validate()?;
    if profile.robot_id != intent.robot_id || !profile.action_kinds.contains(&intent.action_kind) {
        return Err(EmbodiedError::Invalid(
            "intent is incompatible with the hardware profile".to_owned(),
        ));
    }
    let command_size = u64::try_from(crate::json_bytes(intent)?.len()).unwrap_or(u64::MAX);
    if command_size > profile.maximum_command_bytes {
        return Err(EmbodiedError::Invalid(
            "intent exceeds hardware command size".to_owned(),
        ));
    }
    port.dispatch_authorized(intent, assessment)
}
