use crate::{validate_hash, validate_text, validate_token, ActionIntent, EmbodiedError};
use serde::{Deserialize, Serialize};

/// External safety-controller disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyDecisionStatus {
    Permit,
    Deny,
    EmergencyStop,
    Expired,
}

/// Intent-bound result produced outside the D2I planning layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyAssessment {
    pub schema_version: u32,
    pub controller_id: String,
    pub intent_hash: String,
    pub status: SafetyDecisionStatus,
    pub evaluated_at_unix_nanos: u64,
    pub permit_expires_at_unix_nanos: u64,
    pub reasons: Vec<String>,
}

impl SafetyAssessment {
    /// Validates bounded controller metadata and timestamp ordering.
    pub fn validate(&self) -> Result<(), EmbodiedError> {
        if self.schema_version != 1
            || self.evaluated_at_unix_nanos == 0
            || self.permit_expires_at_unix_nanos < self.evaluated_at_unix_nanos
            || self.reasons.len() > 256
        {
            return Err(EmbodiedError::Invalid(
                "safety assessment is outside bounds".to_owned(),
            ));
        }
        validate_token(&self.controller_id, "controller_id")?;
        validate_hash(&self.intent_hash, "intent_hash")?;
        for reason in &self.reasons {
            validate_text(reason, "safety reason")?;
        }
        Ok(())
    }

    /// Validates that the assessment belongs to the exact intent.
    pub fn validate_for_intent(&self, intent: &ActionIntent) -> Result<(), EmbodiedError> {
        self.validate()?;
        if self.intent_hash != intent.content_hash()? {
            return Err(EmbodiedError::Integrity(
                "safety assessment is bound to another intent".to_owned(),
            ));
        }
        if self.permit_expires_at_unix_nanos > intent.expires_at_unix_nanos {
            return Err(EmbodiedError::Deadline(
                "safety assessment outlives the action intent".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Safety-controller port. Implementations own real-time and emergency behavior.
pub trait SafetyController {
    /// Evaluates one high-level intent without executing it.
    fn assess(
        &self,
        intent: &ActionIntent,
        now_unix_nanos: u64,
    ) -> Result<SafetyAssessment, EmbodiedError>;
}

/// Default controller used until a documented external safety system is bound.
#[derive(Debug, Default, Clone, Copy)]
pub struct FailClosedSafetyController;

impl SafetyController for FailClosedSafetyController {
    fn assess(
        &self,
        intent: &ActionIntent,
        now_unix_nanos: u64,
    ) -> Result<SafetyAssessment, EmbodiedError> {
        intent.validate()?;
        Ok(SafetyAssessment {
            schema_version: 1,
            controller_id: "unbound-safety-controller".to_owned(),
            intent_hash: intent.content_hash()?,
            status: SafetyDecisionStatus::Deny,
            evaluated_at_unix_nanos: now_unix_nanos,
            permit_expires_at_unix_nanos: now_unix_nanos,
            reasons: vec!["no documented safety controller is bound".to_owned()],
        })
    }
}

/// Verifies that a permit is current and bound to the exact action intent.
pub fn validate_permit(
    intent: &ActionIntent,
    assessment: &SafetyAssessment,
    now_unix_nanos: u64,
) -> Result<(), EmbodiedError> {
    intent.validate()?;
    assessment.validate_for_intent(intent)?;
    if assessment.status != SafetyDecisionStatus::Permit {
        return Err(EmbodiedError::SafetyDenied(assessment.reasons.join("; ")));
    }
    if now_unix_nanos < assessment.evaluated_at_unix_nanos
        || now_unix_nanos > assessment.permit_expires_at_unix_nanos
        || assessment.permit_expires_at_unix_nanos > intent.expires_at_unix_nanos
    {
        return Err(EmbodiedError::Deadline(
            "safety permit is not currently valid".to_owned(),
        ));
    }
    Ok(())
}
