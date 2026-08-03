use crate::{WorkIntakeError, MAX_RECORD_BYTES};
use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;

struct DuplicateRejectingValue(Value);

impl<'de> serde::Deserialize<'de> for DuplicateRejectingValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ValueVisitor;
        impl<'de> Visitor<'de> for ValueVisitor {
            type Value = Value;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value without duplicate object keys")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(Value::Bool(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(Value::Number(value.into()))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(Value::Number(value.into()))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                serde_json::Number::from_f64(value)
                    .map(Value::Number)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Value::String(value.to_owned()))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(Value::String(value))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(Value::Null)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(Value::Null)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(DuplicateRejectingValue(value)) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(Value::Array(values))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut keys = BTreeSet::new();
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !keys.insert(key.clone()) {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate JSON key: {key}"
                        )));
                    }
                    let DuplicateRejectingValue(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(Value::Object(values))
            }
        }

        deserializer.deserialize_any(ValueVisitor).map(Self)
    }
}

/// Parses bounded JSON while rejecting duplicate and unknown fields.
pub fn parse_json_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, WorkIntakeError> {
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(WorkIntakeError::ResourceLimit(
            "JSON input exceeds the record byte limit".to_owned(),
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let DuplicateRejectingValue(value) = DuplicateRejectingValue::deserialize(&mut deserializer)
        .map_err(|error| WorkIntakeError::Json(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| WorkIntakeError::Json(error.to_string()))?;
    serde_json::from_value(value).map_err(|error| WorkIntakeError::Json(error.to_string()))
}

/// Returns canonical JSON with recursively sorted object keys.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, WorkIntakeError> {
    let value =
        serde_json::to_value(value).map_err(|error| WorkIntakeError::Json(error.to_string()))?;
    serde_json::to_vec(&canonicalize(value))
        .map_err(|error| WorkIntakeError::Json(error.to_string()))
}

/// Returns a lowercase prefixed SHA-256 of canonical JSON.
pub fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, WorkIntakeError> {
    let bytes = canonical_json_bytes(value)?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

pub(crate) fn hash_without<T: Serialize>(
    value: &T,
    omitted_fields: &[&str],
) -> Result<String, WorkIntakeError> {
    let mut value =
        serde_json::to_value(value).map_err(|error| WorkIntakeError::Json(error.to_string()))?;
    let object = value.as_object_mut().ok_or_else(|| {
        WorkIntakeError::Json("hash payload must serialize as an object".to_owned())
    })?;
    for field in omitted_fields {
        object.remove(*field);
    }
    canonical_sha256(&value)
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize).collect()),
        Value::Object(values) => {
            let mut entries = values.into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key, canonicalize(value)))
                    .collect(),
            )
        }
        other => other,
    }
}
