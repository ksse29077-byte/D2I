use crate::{
    json_bytes, validate_text, ActionIntent, EmbodiedError, SafetyAssessment, SensorEvent,
    SensorKind,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const MAX_ROS_MESSAGE_BYTES: usize = 2 * 1024 * 1024;

/// ROS 2 topic mapping without assuming a client library or DDS vendor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ros2TopicMap {
    pub sensor_topics: BTreeMap<SensorKind, String>,
    pub action_intent_topic: String,
    pub safety_assessment_topic: String,
}

impl Ros2TopicMap {
    /// Validates every absolute topic and requires at least one sensor mapping.
    pub fn validate(&self) -> Result<(), EmbodiedError> {
        if self.sensor_topics.is_empty() {
            return Err(EmbodiedError::Invalid(
                "ROS 2 sensor topic map is empty".to_owned(),
            ));
        }
        for topic in self
            .sensor_topics
            .values()
            .chain([&self.action_intent_topic, &self.safety_assessment_topic])
        {
            validate_topic(topic)?;
        }
        Ok(())
    }
}

/// Minimal byte transport implemented by a reviewed ROS 2 integration.
pub trait Ros2Transport {
    /// Receives at most one serialized message from a fully qualified topic.
    fn receive(&mut self, topic: &str) -> Result<Option<Vec<u8>>, EmbodiedError>;
    /// Publishes one serialized message to a fully qualified topic.
    fn publish(&mut self, topic: &str, payload: &[u8]) -> Result<(), EmbodiedError>;
}

/// Nonfunctional transport used until a concrete ROS 2 API is supplied.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableRos2Transport;

impl Ros2Transport for UnavailableRos2Transport {
    fn receive(&mut self, _topic: &str) -> Result<Option<Vec<u8>>, EmbodiedError> {
        Err(EmbodiedError::AdapterUnavailable(
            "TODO: bind documented ROS 2 subscription and QoS APIs".to_owned(),
        ))
    }

    fn publish(&mut self, _topic: &str, _payload: &[u8]) -> Result<(), EmbodiedError> {
        Err(EmbodiedError::AdapterUnavailable(
            "TODO: bind documented ROS 2 publisher and QoS APIs".to_owned(),
        ))
    }
}

/// Bounded in-memory transport for offline adapter conformance tests only.
#[derive(Debug, Clone)]
pub struct OfflineConformanceRos2Transport {
    subscribable_topics: BTreeSet<String>,
    publishable_topics: BTreeSet<String>,
    inbound: BTreeMap<String, VecDeque<Vec<u8>>>,
    published: BTreeMap<String, VecDeque<Vec<u8>>>,
    maximum_messages_per_topic: usize,
}

impl OfflineConformanceRos2Transport {
    /// Creates queues from a validated topic map without contacting a ROS graph.
    pub fn new(
        topics: &Ros2TopicMap,
        maximum_messages_per_topic: usize,
    ) -> Result<Self, EmbodiedError> {
        topics.validate()?;
        if maximum_messages_per_topic == 0 || maximum_messages_per_topic > 10_000 {
            return Err(EmbodiedError::Invalid(
                "conformance queue bound is outside limits".to_owned(),
            ));
        }
        let subscribable_topics = topics.sensor_topics.values().cloned().collect();
        let publishable_topics = [
            topics.action_intent_topic.clone(),
            topics.safety_assessment_topic.clone(),
        ]
        .into_iter()
        .collect();
        Ok(Self {
            subscribable_topics,
            publishable_topics,
            inbound: BTreeMap::new(),
            published: BTreeMap::new(),
            maximum_messages_per_topic,
        })
    }

    /// Enqueues one serialized sensor message for a configured subscription.
    pub fn enqueue_sensor(&mut self, topic: &str, payload: Vec<u8>) -> Result<(), EmbodiedError> {
        validate_message(&payload)?;
        if !self.subscribable_topics.contains(topic) {
            return Err(EmbodiedError::Invalid(
                "topic is not a configured sensor subscription".to_owned(),
            ));
        }
        let queue = self.inbound.entry(topic.to_owned()).or_default();
        if queue.len() >= self.maximum_messages_per_topic {
            return Err(EmbodiedError::Deadline(
                "conformance sensor queue is full".to_owned(),
            ));
        }
        queue.push_back(payload);
        Ok(())
    }

    /// Removes the oldest payload published to a configured output topic.
    pub fn take_published(&mut self, topic: &str) -> Result<Option<Vec<u8>>, EmbodiedError> {
        if !self.publishable_topics.contains(topic) {
            return Err(EmbodiedError::Invalid(
                "topic is not a configured embodied output".to_owned(),
            ));
        }
        Ok(self.published.get_mut(topic).and_then(VecDeque::pop_front))
    }
}

impl Ros2Transport for OfflineConformanceRos2Transport {
    fn receive(&mut self, topic: &str) -> Result<Option<Vec<u8>>, EmbodiedError> {
        if !self.subscribable_topics.contains(topic) {
            return Err(EmbodiedError::Invalid(
                "receive attempted on an unconfigured topic".to_owned(),
            ));
        }
        Ok(self.inbound.get_mut(topic).and_then(VecDeque::pop_front))
    }

    fn publish(&mut self, topic: &str, payload: &[u8]) -> Result<(), EmbodiedError> {
        validate_message(payload)?;
        if !self.publishable_topics.contains(topic) {
            return Err(EmbodiedError::Invalid(
                "publish attempted on an unconfigured topic".to_owned(),
            ));
        }
        let queue = self.published.entry(topic.to_owned()).or_default();
        if queue.len() >= self.maximum_messages_per_topic {
            return Err(EmbodiedError::Deadline(
                "conformance publication queue is full".to_owned(),
            ));
        }
        queue.push_back(payload.to_vec());
        Ok(())
    }
}

/// Typed ROS 2 boundary that publishes intentions, never motor commands.
pub struct Ros2Adapter<T> {
    topics: Ros2TopicMap,
    transport: T,
}

impl<T: Ros2Transport> Ros2Adapter<T> {
    /// Creates an adapter after validating every topic mapping.
    pub fn new(topics: Ros2TopicMap, transport: T) -> Result<Self, EmbodiedError> {
        topics.validate()?;
        Ok(Self { topics, transport })
    }

    /// Receives and validates one typed sensor event.
    pub fn poll_sensor(
        &mut self,
        sensor_kind: &SensorKind,
    ) -> Result<Option<SensorEvent>, EmbodiedError> {
        let topic = self.topics.sensor_topics.get(sensor_kind).ok_or_else(|| {
            EmbodiedError::Invalid("sensor kind has no ROS 2 topic mapping".to_owned())
        })?;
        let Some(bytes) = self.transport.receive(topic)? else {
            return Ok(None);
        };
        if bytes.len() > MAX_ROS_MESSAGE_BYTES {
            return Err(EmbodiedError::Invalid(
                "ROS 2 sensor message exceeds size limit".to_owned(),
            ));
        }
        let event: SensorEvent = serde_json::from_slice(&bytes)
            .map_err(|error| EmbodiedError::Json(error.to_string()))?;
        event.validate()?;
        if &event.sensor_kind != sensor_kind {
            return Err(EmbodiedError::Integrity(
                "ROS 2 topic and sensor kind do not match".to_owned(),
            ));
        }
        Ok(Some(event))
    }

    /// Publishes a validated high-level action intention.
    pub fn publish_intent(&mut self, intent: &ActionIntent) -> Result<(), EmbodiedError> {
        intent.validate()?;
        self.transport
            .publish(&self.topics.action_intent_topic, &json_bytes(intent)?)
    }

    /// Publishes bounded safety-controller metadata.
    pub fn publish_safety_assessment(
        &mut self,
        assessment: &SafetyAssessment,
    ) -> Result<(), EmbodiedError> {
        assessment.validate()?;
        self.transport.publish(
            &self.topics.safety_assessment_topic,
            &json_bytes(assessment)?,
        )
    }

    /// Returns the owned transport for inspection or shutdown.
    pub fn into_transport(self) -> T {
        self.transport
    }
}

fn validate_message(payload: &[u8]) -> Result<(), EmbodiedError> {
    if payload.is_empty() || payload.len() > MAX_ROS_MESSAGE_BYTES {
        return Err(EmbodiedError::Invalid(
            "ROS 2 message is empty or exceeds size limit".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_topic(topic: &str) -> Result<(), EmbodiedError> {
    validate_text(topic, "ROS 2 topic")?;
    if !topic.starts_with('/')
        || topic.contains("//")
        || topic.contains("..")
        || !topic
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-'))
    {
        return Err(EmbodiedError::Invalid(
            "ROS 2 topic syntax is invalid".to_owned(),
        ));
    }
    Ok(())
}
