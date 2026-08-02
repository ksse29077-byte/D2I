use crate::{WorkCaseError, MAX_SOURCE_BYTES};
use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug)]
struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value without duplicate object keys")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(value.into())))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(value.into())))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                serde_json::Number::from_f64(value)
                    .map(|number| StrictValue(Value::Number(number)))
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(StrictValue(Value::String(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value)))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                StrictValue::deserialize(deserializer)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<StrictValue>()? {
                    values.push(value.0);
                }
                Ok(StrictValue(Value::Array(values)))
            }

            fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = Map::new();
                while let Some((key, value)) = access.next_entry::<String, StrictValue>()? {
                    if values.insert(key.clone(), value.0).is_some() {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate JSON object key: {key}"
                        )));
                    }
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

pub fn parse_json_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, WorkCaseError> {
    if bytes.is_empty() || bytes.len() > MAX_SOURCE_BYTES {
        return Err(WorkCaseError::Json(
            "JSON input is empty or exceeds the source bound".to_owned(),
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let strict = StrictValue::deserialize(&mut deserializer)
        .map_err(|error| WorkCaseError::Json(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| WorkCaseError::Json(error.to_string()))?;
    serde_json::from_value(strict.0).map_err(|error| WorkCaseError::Json(error.to_string()))
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            let mut output = Map::new();
            for (key, value) in entries {
                output.insert(key.clone(), canonicalize(value));
            }
            Value::Object(output)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        _ => value.clone(),
    }
}

pub fn canonical_json_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, WorkCaseError> {
    let value =
        serde_json::to_value(value).map_err(|error| WorkCaseError::Json(error.to_string()))?;
    serde_json::to_vec(&canonicalize(&value))
        .map_err(|error| WorkCaseError::Json(error.to_string()))
}

pub fn canonical_sha256<T: serde::Serialize>(value: &T) -> Result<String, WorkCaseError> {
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(canonical_json_bytes(value)?)
    ))
}

pub(crate) fn hash_without<T: serde::Serialize>(
    value: &T,
    omitted: &[&str],
) -> Result<String, WorkCaseError> {
    let mut value =
        serde_json::to_value(value).map_err(|error| WorkCaseError::Json(error.to_string()))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| WorkCaseError::Json("self-hash payload is not an object".to_owned()))?;
    for field in omitted {
        if object.remove(*field).is_none() {
            return Err(WorkCaseError::Integrity(format!(
                "self-hash field {field} is absent"
            )));
        }
    }
    canonical_sha256(&value)
}
