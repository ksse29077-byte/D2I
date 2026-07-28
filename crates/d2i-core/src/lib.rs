//! Core contracts shared by the D2I compiler and runtime crates.
//!
//! Typed compiler IR extends the source-pack contracts. Package writing is
//! implemented by `d2i-compiler`; runtime contracts and the reference
//! implementation live in separate crates.

mod ir;
mod manifest;
mod parser;
mod source;
mod validate;

pub use ir::{
    AccessLabel, ActionPermission, CachePolicy, CompiledIr, ConfidenceThreshold,
    CriticalErrorCondition, Criticality, Document, DomainIr, EdgeKind, Entity, EvaluationCase,
    EvaluationIr, EvidenceRef, Example, ExecutionEdge, ExecutionGraph, ExecutionIr, ExecutionNode,
    Fact, MetricSpec, NodeKind, Outcome, PolicyIr, Procedure, ProcedureStep, Relation, RetryPolicy,
    Rule, SkillIr, Term,
};
pub use manifest::{
    load_manifest, DomainManifest, DomainMetadata, EvaluationConfig, ManifestLoad, ObjectiveConfig,
    PackageConfig, SkillManifest, SourceDeclaration, TargetConfig,
};
pub use parser::{parse_inventory, ParsedContent, ParsedDocument, SourceFormat};
pub use source::{
    build_inventory, write_source_lock, SourceEntry, SourceInventory, SourceLock,
    MAX_SOURCE_FILE_BYTES,
};
pub use validate::{validate_source_pack, ValidationReport};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

const MAX_ID_LEN: usize = 128;

/// Error returned when a typed identifier fails validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdError {
    message: String,
}

impl IdError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Human-readable validation failure.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Display for IdError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for IdError {}

fn validate_identifier(kind: &str, value: &str) -> Result<(), IdError> {
    if value.is_empty() {
        return Err(IdError::new(format!("{kind} must not be empty")));
    }

    if value.len() > MAX_ID_LEN {
        return Err(IdError::new(format!(
            "{kind} must be at most {MAX_ID_LEN} bytes"
        )));
    }

    let mut chars = value.chars();
    let first = match chars.next() {
        Some(first) => first,
        None => return Err(IdError::new(format!("{kind} must not be empty"))),
    };

    if !first.is_ascii_alphanumeric() {
        return Err(IdError::new(format!(
            "{kind} must start with an ASCII letter or digit"
        )));
    }

    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(IdError::new(format!(
            "{kind} may contain only ASCII letters, digits, '-', '_', and '.'"
        )));
    }

    Ok(())
}

macro_rules! define_id {
    ($name:ident, $kind:literal) => {
        #[doc = concat!("Typed identifier for ", $kind, ".")]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Creates a validated ", $kind, " identifier.")]
            pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
                let value = value.into();
                validate_identifier($kind, &value)?;
                Ok(Self(value))
            }

            #[doc = concat!("Returns the ", $kind, " identifier as a string slice.")]
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = IdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

define_id!(DomainId, "domain id");
define_id!(SkillId, "skill id");
define_id!(ExecutorId, "executor id");
define_id!(BuildId, "build id");
define_id!(ProvenanceId, "provenance id");
define_id!(NodeId, "execution node id");

/// Minimal semantic version wrapper used in manifests and contracts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SemanticVersion {
    major: u64,
    minor: u64,
    patch: u64,
}

impl SemanticVersion {
    /// Creates a semantic version from numeric components.
    #[must_use]
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Major version component.
    #[must_use]
    pub const fn major(&self) -> u64 {
        self.major
    }

    /// Minor version component.
    #[must_use]
    pub const fn minor(&self) -> u64 {
        self.minor
    }

    /// Patch version component.
    #[must_use]
    pub const fn patch(&self) -> u64 {
        self.patch
    }
}

impl Display for SemanticVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl FromStr for SemanticVersion {
    type Err = VersionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut parts = value.split('.');
        let major = parse_version_part(parts.next(), "major")?;
        let minor = parse_version_part(parts.next(), "minor")?;
        let patch = parse_version_part(parts.next(), "patch")?;

        if parts.next().is_some() {
            return Err(VersionError::new(
                "semantic version must contain exactly three numeric components",
            ));
        }

        Ok(Self::new(major, minor, patch))
    }
}

fn parse_version_part(part: Option<&str>, name: &str) -> Result<u64, VersionError> {
    let value = part.ok_or_else(|| {
        VersionError::new("semantic version must contain exactly three numeric components")
    })?;

    if value.is_empty() {
        return Err(VersionError::new(format!(
            "semantic version {name} component must not be empty"
        )));
    }

    value.parse::<u64>().map_err(|_| {
        VersionError::new(format!(
            "semantic version {name} component must be an unsigned integer"
        ))
    })
}

/// Error returned when a semantic version fails validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionError {
    message: String,
}

impl VersionError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Display for VersionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for VersionError {}

/// Supported content hash algorithms for source and package contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HashAlgorithm {
    /// SHA-256 represented as 64 lowercase hexadecimal characters.
    Sha256,
}

impl Display for HashAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha256 => f.write_str("sha256"),
        }
    }
}

/// A validated content hash string in `algorithm:hex` form.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentHash {
    algorithm: HashAlgorithm,
    hex: String,
}

impl ContentHash {
    /// Creates a SHA-256 content hash from a 64-character hexadecimal digest.
    pub fn sha256(hex: impl Into<String>) -> Result<Self, HashError> {
        let hex = hex.into();
        validate_sha256_hex(&hex)?;
        Ok(Self {
            algorithm: HashAlgorithm::Sha256,
            hex,
        })
    }

    /// Hash algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// Lowercase hexadecimal digest.
    #[must_use]
    pub fn hex(&self) -> &str {
        &self.hex
    }
}

impl Display for ContentHash {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm, self.hex)
    }
}

impl FromStr for ContentHash {
    type Err = HashError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some(hex) = value.strip_prefix("sha256:") else {
            return Err(HashError::new("content hash must start with 'sha256:'"));
        };

        Self::sha256(hex)
    }
}

fn validate_sha256_hex(hex: &str) -> Result<(), HashError> {
    if hex.len() != 64 {
        return Err(HashError::new(
            "sha256 digest must contain exactly 64 hexadecimal characters",
        ));
    }

    if !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(HashError::new(
            "sha256 digest must contain only hexadecimal characters",
        ));
    }

    if hex.chars().any(|ch| ch.is_ascii_uppercase()) {
        return Err(HashError::new(
            "sha256 digest must use lowercase hexadecimal characters",
        ));
    }

    Ok(())
}

/// Error returned when a content hash fails validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashError {
    message: String,
}

impl HashError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Display for HashError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for HashError {}

/// Location in a human-authored source file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceLocation {
    path: String,
    line: Option<u32>,
    column: Option<u32>,
}

impl SourceLocation {
    /// Creates a source location. Paths are stored as repository-relative text.
    pub fn new(path: impl Into<String>, line: Option<u32>, column: Option<u32>) -> Self {
        Self {
            path: path.into(),
            line,
            column,
        }
    }

    /// Repository-relative source path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// One-based line number when known.
    #[must_use]
    pub const fn line(&self) -> Option<u32> {
        self.line
    }

    /// One-based column number when known.
    #[must_use]
    pub const fn column(&self) -> Option<u32> {
        self.column
    }
}

impl Display for SourceLocation {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match (self.line, self.column) {
            (Some(line), Some(column)) => write!(f, "{}:{line}:{column}", self.path),
            (Some(line), None) => write!(f, "{}:{line}", self.path),
            _ => f.write_str(&self.path),
        }
    }
}

/// Diagnostic severity for source validation and compiler contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Informational message.
    Info,
    /// Non-fatal concern.
    Warning,
    /// Fatal validation or compilation error.
    Error,
}

impl Display for Severity {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => f.write_str("info"),
            Self::Warning => f.write_str("warning"),
            Self::Error => f.write_str("error"),
        }
    }
}

/// Structured diagnostic with an optional source location and remediation hint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    severity: Severity,
    code: String,
    message: String,
    location: Option<SourceLocation>,
    field: Option<String>,
    help: Option<String>,
}

impl Diagnostic {
    /// Creates a diagnostic.
    pub fn new(severity: Severity, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity,
            code: code.into(),
            message: message.into(),
            location: None,
            field: None,
            help: None,
        }
    }

    /// Attaches a source location.
    #[must_use]
    pub fn with_location(mut self, location: SourceLocation) -> Self {
        self.location = Some(location);
        self
    }

    /// Attaches a dotted field path within the source document.
    #[must_use]
    pub fn with_field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }

    /// Attaches a remediation hint.
    #[must_use]
    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    /// Diagnostic severity.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    /// Stable diagnostic code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Human-readable diagnostic message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Source location, when known.
    #[must_use]
    pub const fn location(&self) -> Option<&SourceLocation> {
        self.location.as_ref()
    }

    /// Dotted source field path, when known.
    #[must_use]
    pub fn field(&self) -> Option<&str> {
        self.field.as_deref()
    }

    /// Remediation hint, when available.
    #[must_use]
    pub fn help(&self) -> Option<&str> {
        self.help.as_deref()
    }
}

impl Display for Diagnostic {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(location) = &self.location {
            write!(
                f,
                "{}[{}] at {}: {}",
                self.severity, self.code, location, self.message
            )?;
        } else {
            write!(f, "{}[{}]: {}", self.severity, self.code, self.message)?;
        }

        if let Some(help) = &self.help {
            write!(f, " help: {help}")?;
        }

        if let Some(field) = &self.field {
            write!(f, " field: {field}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_parse_and_display() {
        let id = match DomainId::from_str("equipment-maintenance-demo") {
            Ok(id) => id,
            Err(error) => panic!("valid id rejected: {error}"),
        };

        assert_eq!(id.as_str(), "equipment-maintenance-demo");
        assert_eq!(id.to_string(), "equipment-maintenance-demo");
    }

    #[test]
    fn ids_reject_invalid_input() {
        assert!(SkillId::from_str("").is_err());
        assert!(SkillId::from_str("-bad").is_err());
        assert!(SkillId::from_str("bad/value").is_err());
    }

    #[test]
    fn semantic_version_requires_three_numeric_parts() {
        let version = match SemanticVersion::from_str("0.1.0") {
            Ok(version) => version,
            Err(error) => panic!("valid version rejected: {error}"),
        };

        assert_eq!(version.major(), 0);
        assert_eq!(version.minor(), 1);
        assert_eq!(version.patch(), 0);
        assert_eq!(version.to_string(), "0.1.0");
        assert!(SemanticVersion::from_str("0.1").is_err());
        assert!(SemanticVersion::from_str("0.1.x").is_err());
    }

    #[test]
    fn content_hash_validates_sha256_syntax() {
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let hash = match ContentHash::sha256(digest) {
            Ok(hash) => hash,
            Err(error) => panic!("valid hash rejected: {error}"),
        };

        assert_eq!(hash.algorithm(), HashAlgorithm::Sha256);
        assert_eq!(hash.hex(), digest);
        assert_eq!(hash.to_string(), format!("sha256:{digest}"));
        assert!(ContentHash::from_str("sha256:ABC").is_err());
        assert!(ContentHash::from_str("md5:0123").is_err());
    }

    #[test]
    fn diagnostic_carries_location_and_help() {
        let diagnostic = Diagnostic::new(Severity::Error, "D2I0001", "missing field")
            .with_location(SourceLocation::new("domain.yaml", Some(3), Some(5)))
            .with_help("add the required field");

        assert_eq!(diagnostic.severity(), Severity::Error);
        assert_eq!(diagnostic.code(), "D2I0001");
        assert_eq!(diagnostic.message(), "missing field");
        assert_eq!(diagnostic.help(), Some("add the required field"));
        assert_eq!(diagnostic.field(), None);
        assert!(diagnostic.to_string().contains("domain.yaml:3:5"));
    }
}
