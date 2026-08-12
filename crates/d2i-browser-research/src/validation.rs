use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

pub const ZERO_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const MAX_CONTRACT_BYTES: usize = 2 * 1024 * 1024;
const MAX_CONTRACT_DEPTH: usize = 32;
const MAX_ARRAY_ITEMS: usize = 4096;
const MAX_TEXT_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResearchError {
    Invalid(String),
    AccessDenied(String),
    Resource(String),
    Integrity(String),
    Unsupported(String),
    Json(String),
    Io(String),
}

impl Display for ResearchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(value) => write!(formatter, "invalid research input: {value}"),
            Self::AccessDenied(value) => write!(formatter, "research access denied: {value}"),
            Self::Resource(value) => write!(formatter, "research resource limit: {value}"),
            Self::Integrity(value) => write!(formatter, "research integrity failure: {value}"),
            Self::Unsupported(value) => {
                write!(formatter, "unsupported research operation: {value}")
            }
            Self::Json(value) => write!(formatter, "research JSON failure: {value}"),
            Self::Io(value) => write!(formatter, "research I/O failure: {value}"),
        }
    }
}

impl Error for ResearchError {}

pub fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, ResearchError> {
    let value =
        serde_json::to_value(value).map_err(|error| ResearchError::Json(error.to_string()))?;
    let bytes =
        serde_json::to_vec(&value).map_err(|error| ResearchError::Json(error.to_string()))?;
    Ok(sha256_bytes(&bytes))
}

pub(crate) fn hash_without_field<T: Serialize>(
    value: &T,
    field: &str,
) -> Result<String, ResearchError> {
    let mut value =
        serde_json::to_value(value).map_err(|error| ResearchError::Json(error.to_string()))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| ResearchError::Invalid("sealed contract must be an object".to_owned()))?;
    object.insert(field.to_owned(), Value::String(ZERO_HASH.to_owned()));
    let bytes =
        serde_json::to_vec(&value).map_err(|error| ResearchError::Json(error.to_string()))?;
    Ok(sha256_bytes(&bytes))
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

pub fn validate_hash(value: &str, field: &str) -> Result<(), ResearchError> {
    if value.len() != 71
        || !value.starts_with("sha256:")
        || !value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ResearchError::Invalid(format!(
            "{field} must be a lowercase sha256 digest"
        )));
    }
    Ok(())
}

pub(crate) fn validate_id(value: &str, field: &str) -> Result<(), ResearchError> {
    if value.is_empty()
        || value.len() > 512
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
    {
        return Err(ResearchError::Invalid(format!(
            "{field} is not a bounded stable ID"
        )));
    }
    Ok(())
}

pub(crate) fn validate_text(value: &str, field: &str, maximum: usize) -> Result<(), ResearchError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(ResearchError::Invalid(format!(
            "{field} is not bounded clean text"
        )));
    }
    Ok(())
}

pub fn parse_json_strict<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, ResearchError> {
    if bytes.len() > MAX_CONTRACT_BYTES {
        return Err(ResearchError::Resource(
            "contract exceeds two MiB".to_owned(),
        ));
    }
    let value: T =
        serde_json::from_slice(bytes).map_err(|error| ResearchError::Json(error.to_string()))?;
    validate_bounded(&value)?;
    Ok(value)
}

pub(crate) fn validate_bounded<T: Serialize>(value: &T) -> Result<(), ResearchError> {
    let value =
        serde_json::to_value(value).map_err(|error| ResearchError::Json(error.to_string()))?;
    let bytes =
        serde_json::to_vec(&value).map_err(|error| ResearchError::Json(error.to_string()))?;
    if bytes.len() > MAX_CONTRACT_BYTES {
        return Err(ResearchError::Resource(
            "contract exceeds two MiB".to_owned(),
        ));
    }
    validate_value(&value, 0)
}

fn validate_value(value: &Value, depth: usize) -> Result<(), ResearchError> {
    if depth > MAX_CONTRACT_DEPTH {
        return Err(ResearchError::Resource(
            "contract nesting exceeds 32".to_owned(),
        ));
    }
    match value {
        Value::String(text) if text.len() > MAX_TEXT_BYTES => Err(ResearchError::Resource(
            "contract string exceeds 256 KiB".to_owned(),
        )),
        Value::Array(values) => {
            if values.len() > MAX_ARRAY_ITEMS {
                return Err(ResearchError::Resource(
                    "contract array exceeds 4096 items".to_owned(),
                ));
            }
            for value in values {
                validate_value(value, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for (field, value) in values {
                let lower = field.to_ascii_lowercase();
                let authority_bearing_name = lower.contains("password")
                    || lower.contains("credential")
                    || lower.contains("cookie")
                    || lower.contains("authorization_header")
                    || lower == "raw_html"
                    || lower == "raw_url"
                    || lower == "command"
                    || lower == "headers";
                let authority_bearing_value =
                    matches!(value, Value::String(_) | Value::Array(_) | Value::Object(_));
                if authority_bearing_name && authority_bearing_value {
                    return Err(ResearchError::AccessDenied(format!(
                        "forbidden authority-bearing field: {field}"
                    )));
                }
                validate_value(value, depth + 1)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
