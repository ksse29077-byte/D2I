use crate::{
    json_bytes, sha256_bytes, validate_hash, validate_token, ActionIntent, EmbodiedError,
    SafetyController, SafetyDecisionStatus, SensorEvent,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// One deterministic simulation tick and its expected planning/safety result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulationFrame {
    pub tick_unix_nanos: u64,
    pub sensor_event: SensorEvent,
    pub expected_intent_hash: Option<String>,
    pub expected_safety_status: Option<SafetyDecisionStatus>,
}

/// Immutable simulation replay input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulationTrace {
    pub schema_version: u32,
    pub simulation_id: String,
    pub world_content_hash: String,
    pub source_build_id: String,
    pub source_package_content_hash: String,
    pub frames: Vec<SimulationFrame>,
}

impl SimulationTrace {
    fn validate(&self) -> Result<(), EmbodiedError> {
        if self.schema_version != 1 || self.frames.is_empty() || self.frames.len() > 100_000 {
            return Err(EmbodiedError::Invalid(
                "simulation schema or frame count is outside bounds".to_owned(),
            ));
        }
        validate_token(&self.simulation_id, "simulation_id")?;
        validate_token(&self.source_build_id, "source_build_id")?;
        validate_hash(&self.world_content_hash, "world_content_hash")?;
        validate_hash(
            &self.source_package_content_hash,
            "source_package_content_hash",
        )?;
        let mut previous_tick = 0_u64;
        let mut previous_sequence = None;
        let mut event_ids = BTreeSet::new();
        for frame in &self.frames {
            frame.sensor_event.validate()?;
            if frame.tick_unix_nanos < frame.sensor_event.observed_at_unix_nanos
                || frame.tick_unix_nanos <= previous_tick
                || previous_sequence.is_some_and(|sequence| frame.sensor_event.sequence <= sequence)
                || !event_ids.insert(frame.sensor_event.event_id.clone())
            {
                return Err(EmbodiedError::Invalid(
                    "simulation ticks, event sequence, or IDs are not strictly ordered".to_owned(),
                ));
            }
            if let Some(hash) = &frame.expected_intent_hash {
                validate_hash(hash, "expected_intent_hash")?;
            }
            if frame.expected_intent_hash.is_some() != frame.expected_safety_status.is_some() {
                return Err(EmbodiedError::Invalid(
                    "expected intent and safety status must appear together".to_owned(),
                ));
            }
            previous_tick = frame.tick_unix_nanos;
            previous_sequence = Some(frame.sensor_event.sequence);
        }
        let _ = json_bytes(self)?;
        Ok(())
    }
}

/// Planning port exercised by deterministic simulation replay.
pub trait EmbodiedPlanner {
    /// Produces at most one high-level intent for a simulation frame.
    fn plan(
        &self,
        event: &SensorEvent,
        tick_unix_nanos: u64,
    ) -> Result<Option<ActionIntent>, EmbodiedError>;
}

/// Timing-independent simulation comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulationReplayReport {
    pub schema_version: u32,
    pub simulation_id: String,
    pub world_content_hash: String,
    pub source_build_id: String,
    pub source_package_content_hash: String,
    pub frame_count: u64,
    pub intent_count: u64,
    pub denied_count: u64,
    pub deadline_violation_count: u64,
    pub mismatches: Vec<String>,
    pub matched: bool,
    pub replay_hash: String,
}

/// Replays a trace without hardware dispatch or wall-clock dependencies.
pub fn replay_simulation(
    trace: &SimulationTrace,
    planner: &dyn EmbodiedPlanner,
    safety: &dyn SafetyController,
) -> Result<SimulationReplayReport, EmbodiedError> {
    trace.validate()?;
    let mut intent_count = 0_u64;
    let mut denied_count = 0_u64;
    let mut deadline_violation_count = 0_u64;
    let mut mismatches = Vec::new();
    let mut observed = Vec::new();
    for frame in &trace.frames {
        let intent = planner.plan(&frame.sensor_event, frame.tick_unix_nanos)?;
        match intent {
            Some(intent) => {
                intent_count = intent_count.saturating_add(1);
                let intent_hash = intent.content_hash()?;
                if intent.robot_id != frame.sensor_event.robot_id
                    || intent.source_build_id != trace.source_build_id
                    || intent.source_package_content_hash != trace.source_package_content_hash
                {
                    mismatches.push(format!(
                        "frame {} intent identity does not match trace",
                        frame.sensor_event.event_id
                    ));
                }
                if intent.expires_at_unix_nanos < frame.tick_unix_nanos {
                    deadline_violation_count = deadline_violation_count.saturating_add(1);
                }
                let assessment = safety.assess(&intent, frame.tick_unix_nanos)?;
                assessment.validate_for_intent(&intent)?;
                if assessment.status != SafetyDecisionStatus::Permit {
                    denied_count = denied_count.saturating_add(1);
                }
                if frame.expected_intent_hash.as_deref() != Some(intent_hash.as_str()) {
                    mismatches.push(format!(
                        "frame {} intent hash mismatch",
                        frame.sensor_event.event_id
                    ));
                }
                if frame.expected_safety_status != Some(assessment.status) {
                    mismatches.push(format!(
                        "frame {} safety status mismatch",
                        frame.sensor_event.event_id
                    ));
                }
                observed.push((
                    frame.sensor_event.event_id.clone(),
                    Some(intent_hash),
                    Some(assessment.status),
                ));
            }
            None => {
                if frame.expected_intent_hash.is_some() || frame.expected_safety_status.is_some() {
                    mismatches.push(format!(
                        "frame {} expected an action intent",
                        frame.sensor_event.event_id
                    ));
                }
                observed.push((frame.sensor_event.event_id.clone(), None, None));
            }
        }
    }
    if deadline_violation_count > 0 {
        mismatches.push("one or more action intents missed their simulation deadline".to_owned());
    }
    mismatches.sort();
    let replay_hash = sha256_bytes(&json_bytes(&(
        &trace.simulation_id,
        &trace.world_content_hash,
        &observed,
    ))?);
    Ok(SimulationReplayReport {
        schema_version: 1,
        simulation_id: trace.simulation_id.clone(),
        world_content_hash: trace.world_content_hash.clone(),
        source_build_id: trace.source_build_id.clone(),
        source_package_content_hash: trace.source_package_content_hash.clone(),
        frame_count: u64::try_from(trace.frames.len()).unwrap_or(u64::MAX),
        intent_count,
        denied_count,
        deadline_violation_count,
        matched: mismatches.is_empty(),
        mismatches,
        replay_hash,
    })
}
