use crate::{hash_value, validate_hash, validate_text, validate_token, DesktopError};
use d2i_runtime_api::{DecisionEnvelope, DecisionStatus};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A capability that a desktop adapter may expose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopCapability {
    ObserveDesktop,
    ListWindows,
    ReadFile,
    ListDirectory,
    WriteFile,
    CreateDirectory,
    MovePath,
    DeletePath,
    LaunchProcess,
    TerminateProcess,
    BrowserNavigate,
    BrowserInteract,
    UiInteract,
    ClipboardRead,
    ClipboardWrite,
}

/// Highest inherent risk assigned to an operation by trusted code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    ReadOnly,
    Reversible,
    ExternalCommunication,
    CredentialSensitive,
    Destructive,
    Privileged,
}

/// Stable identity for a window targeted by UI automation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowIdentity {
    pub process_id: u32,
    pub executable_hash: String,
    pub title_hash: String,
}

/// Browser interaction expressed without executable script.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrowserInteraction {
    Click {
        locator: String,
    },
    TypeText {
        locator: String,
        text_hash: String,
        secret_ref: Option<String>,
    },
    Select {
        locator: String,
        value_hash: String,
    },
}

/// Native UI interaction expressed without coordinates or executable script.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum UiInteraction {
    Invoke {
        automation_id: String,
    },
    SetText {
        automation_id: String,
        text_hash: String,
        secret_ref: Option<String>,
    },
    Toggle {
        automation_id: String,
        desired: bool,
    },
}

/// Closed set of operations accepted by the desktop execution boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DesktopOperation {
    ObserveDesktop {
        display_id: String,
    },
    ListWindows,
    ReadFile {
        path: String,
        maximum_bytes: u64,
    },
    ListDirectory {
        path: String,
        maximum_entries: u32,
    },
    WriteFile {
        path: String,
        payload_hash: String,
        expected_current_hash: Option<String>,
        create_new: bool,
    },
    CreateDirectory {
        path: String,
    },
    MovePath {
        source: String,
        destination: String,
        expected_source_hash: String,
    },
    DeletePath {
        path: String,
        expected_hash: String,
    },
    LaunchProcess {
        executable: String,
        executable_hash: String,
        arguments: Vec<String>,
        working_directory: String,
        network_requested: bool,
    },
    TerminateProcess {
        process_id: u32,
        expected_executable_hash: String,
    },
    BrowserNavigate {
        browser_session_id: String,
        url: String,
        origin: String,
    },
    BrowserInteract {
        browser_session_id: String,
        origin: String,
        interaction: BrowserInteraction,
    },
    UiInteract {
        window: WindowIdentity,
        interaction: UiInteraction,
    },
    ClipboardRead,
    ClipboardWrite {
        payload_hash: String,
        secret_ref: Option<String>,
    },
}

impl DesktopOperation {
    /// Returns the adapter capability required by this operation.
    #[must_use]
    pub fn capability(&self) -> DesktopCapability {
        match self {
            Self::ObserveDesktop { .. } => DesktopCapability::ObserveDesktop,
            Self::ListWindows => DesktopCapability::ListWindows,
            Self::ReadFile { .. } => DesktopCapability::ReadFile,
            Self::ListDirectory { .. } => DesktopCapability::ListDirectory,
            Self::WriteFile { .. } => DesktopCapability::WriteFile,
            Self::CreateDirectory { .. } => DesktopCapability::CreateDirectory,
            Self::MovePath { .. } => DesktopCapability::MovePath,
            Self::DeletePath { .. } => DesktopCapability::DeletePath,
            Self::LaunchProcess { .. } => DesktopCapability::LaunchProcess,
            Self::TerminateProcess { .. } => DesktopCapability::TerminateProcess,
            Self::BrowserNavigate { .. } => DesktopCapability::BrowserNavigate,
            Self::BrowserInteract { .. } => DesktopCapability::BrowserInteract,
            Self::UiInteract { .. } => DesktopCapability::UiInteract,
            Self::ClipboardRead => DesktopCapability::ClipboardRead,
            Self::ClipboardWrite { .. } => DesktopCapability::ClipboardWrite,
        }
    }

    /// Returns the risk class derived by trusted code, not by model output.
    #[must_use]
    pub fn risk_class(&self) -> RiskClass {
        match self {
            Self::ObserveDesktop { .. }
            | Self::ListWindows
            | Self::ReadFile { .. }
            | Self::ListDirectory { .. } => RiskClass::ReadOnly,
            Self::WriteFile { .. }
            | Self::CreateDirectory { .. }
            | Self::MovePath { .. }
            | Self::ClipboardWrite {
                secret_ref: None, ..
            } => RiskClass::Reversible,
            Self::BrowserNavigate { .. } => RiskClass::ExternalCommunication,
            Self::BrowserInteract { interaction, .. } => match interaction {
                BrowserInteraction::TypeText {
                    secret_ref: Some(_),
                    ..
                } => RiskClass::CredentialSensitive,
                _ => RiskClass::ExternalCommunication,
            },
            Self::ClipboardWrite {
                secret_ref: Some(_),
                ..
            } => RiskClass::CredentialSensitive,
            Self::DeletePath { .. } | Self::TerminateProcess { .. } => RiskClass::Destructive,
            Self::LaunchProcess { .. } | Self::UiInteract { .. } => RiskClass::Privileged,
            Self::ClipboardRead => RiskClass::CredentialSensitive,
        }
    }

    /// Reports whether successful execution can change host or external state.
    #[must_use]
    pub fn has_side_effect(&self) -> bool {
        !matches!(
            self,
            Self::ObserveDesktop { .. }
                | Self::ListWindows
                | Self::ReadFile { .. }
                | Self::ListDirectory { .. }
                | Self::ClipboardRead
        )
    }

    pub(crate) fn validate(&self) -> Result<(), DesktopError> {
        match self {
            Self::ObserveDesktop { display_id } => validate_token(display_id, "display_id"),
            Self::ListWindows | Self::ClipboardRead => Ok(()),
            Self::ReadFile {
                path,
                maximum_bytes,
            } => {
                validate_path(path, "path")?;
                if *maximum_bytes == 0 || *maximum_bytes > 8 * 1024 * 1024 {
                    return Err(DesktopError::Invalid(
                        "maximum_bytes is outside 1..=8388608".to_owned(),
                    ));
                }
                Ok(())
            }
            Self::ListDirectory {
                path,
                maximum_entries,
            } => {
                validate_path(path, "path")?;
                if *maximum_entries == 0 || *maximum_entries > 10_000 {
                    return Err(DesktopError::Invalid(
                        "maximum_entries is outside 1..=10000".to_owned(),
                    ));
                }
                Ok(())
            }
            Self::WriteFile {
                path,
                payload_hash,
                expected_current_hash,
                ..
            } => {
                validate_path(path, "path")?;
                validate_hash(payload_hash, "payload_hash")?;
                if let Some(hash) = expected_current_hash {
                    validate_hash(hash, "expected_current_hash")?;
                }
                Ok(())
            }
            Self::CreateDirectory { path } => validate_path(path, "path"),
            Self::MovePath {
                source,
                destination,
                expected_source_hash,
            } => {
                validate_path(source, "source")?;
                validate_path(destination, "destination")?;
                validate_hash(expected_source_hash, "expected_source_hash")
            }
            Self::DeletePath {
                path,
                expected_hash,
            } => {
                validate_path(path, "path")?;
                validate_hash(expected_hash, "expected_hash")
            }
            Self::LaunchProcess {
                executable,
                executable_hash,
                arguments,
                working_directory,
                ..
            } => {
                validate_path(executable, "executable")?;
                validate_hash(executable_hash, "executable_hash")?;
                validate_path(working_directory, "working_directory")?;
                if arguments.len() > 128 {
                    return Err(DesktopError::Invalid(
                        "process argument count exceeds 128".to_owned(),
                    ));
                }
                for argument in arguments {
                    validate_text(argument, "process argument")?;
                }
                Ok(())
            }
            Self::TerminateProcess {
                process_id,
                expected_executable_hash,
            } => {
                if *process_id == 0 {
                    return Err(DesktopError::Invalid(
                        "process_id must be nonzero".to_owned(),
                    ));
                }
                validate_hash(expected_executable_hash, "expected_executable_hash")
            }
            Self::BrowserNavigate {
                browser_session_id,
                url,
                origin,
            } => {
                validate_token(browser_session_id, "browser_session_id")?;
                validate_origin(origin)?;
                validate_text(url, "url")?;
                if url != origin && !url.starts_with(&format!("{origin}/")) {
                    return Err(DesktopError::Invalid(
                        "url is not bound to the declared origin".to_owned(),
                    ));
                }
                Ok(())
            }
            Self::BrowserInteract {
                browser_session_id,
                origin,
                interaction,
            } => {
                validate_token(browser_session_id, "browser_session_id")?;
                validate_origin(origin)?;
                validate_browser_interaction(interaction)
            }
            Self::UiInteract {
                window,
                interaction,
            } => {
                if window.process_id == 0 {
                    return Err(DesktopError::Invalid(
                        "window process_id must be nonzero".to_owned(),
                    ));
                }
                validate_hash(&window.executable_hash, "window executable_hash")?;
                validate_hash(&window.title_hash, "window title_hash")?;
                validate_ui_interaction(interaction)
            }
            Self::ClipboardWrite {
                payload_hash,
                secret_ref,
            } => {
                validate_hash(payload_hash, "payload_hash")?;
                if let Some(reference) = secret_ref {
                    validate_token(reference, "secret_ref")?;
                }
                Ok(())
            }
        }
    }

    pub(crate) fn path_targets(&self) -> Vec<(&str, bool)> {
        match self {
            Self::ReadFile { path, .. } | Self::ListDirectory { path, .. } => {
                vec![(path, false)]
            }
            Self::WriteFile { path, .. }
            | Self::CreateDirectory { path }
            | Self::DeletePath { path, .. } => vec![(path, true)],
            Self::MovePath {
                source,
                destination,
                ..
            } => vec![(source, true), (destination, true)],
            Self::LaunchProcess {
                executable,
                working_directory,
                ..
            } => vec![(executable, false), (working_directory, false)],
            _ => Vec::new(),
        }
    }

    pub(crate) fn origin(&self) -> Option<&str> {
        match self {
            Self::BrowserNavigate { origin, .. } | Self::BrowserInteract { origin, .. } => {
                Some(origin)
            }
            _ => None,
        }
    }
}

/// One immutable action proposed from a specific D2I decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopActionIntent {
    pub schema_version: u32,
    pub action_id: String,
    pub session_id: String,
    pub sequence: u64,
    pub generated_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub request_id: String,
    pub build_id: String,
    pub package_content_hash: String,
    pub decision_hash: String,
    pub evidence_hashes: Vec<String>,
    pub idempotency_key: String,
    pub rationale_hash: String,
    pub operation: DesktopOperation,
}

impl DesktopActionIntent {
    /// Validates bounds, identities, hashes, and expiration ordering.
    pub fn validate(&self) -> Result<(), DesktopError> {
        if self.schema_version != 1 {
            return Err(DesktopError::Invalid(
                "desktop action schema_version must be 1".to_owned(),
            ));
        }
        for (value, field) in [
            (&self.action_id, "action_id"),
            (&self.session_id, "session_id"),
            (&self.request_id, "request_id"),
            (&self.build_id, "build_id"),
            (&self.idempotency_key, "idempotency_key"),
        ] {
            validate_token(value, field)?;
        }
        if self.sequence == 0 {
            return Err(DesktopError::Invalid(
                "action sequence must be nonzero".to_owned(),
            ));
        }
        if self.generated_at_unix_ms >= self.expires_at_unix_ms
            || self.expires_at_unix_ms - self.generated_at_unix_ms > 15 * 60 * 1000
        {
            return Err(DesktopError::Invalid(
                "action lifetime must be positive and no longer than 15 minutes".to_owned(),
            ));
        }
        validate_hash(&self.package_content_hash, "package_content_hash")?;
        validate_hash(&self.decision_hash, "decision_hash")?;
        validate_hash(&self.rationale_hash, "rationale_hash")?;
        if self.evidence_hashes.len() > 256 {
            return Err(DesktopError::Invalid(
                "evidence hash count exceeds 256".to_owned(),
            ));
        }
        let mut unique = BTreeSet::new();
        for hash in &self.evidence_hashes {
            validate_hash(hash, "evidence_hash")?;
            if !unique.insert(hash) {
                return Err(DesktopError::Invalid(
                    "evidence hashes contain duplicates".to_owned(),
                ));
            }
        }
        self.operation.validate()
    }

    /// Computes the immutable identity consumed by policy, approval, and audit.
    pub fn action_hash(&self) -> Result<String, DesktopError> {
        self.validate()?;
        hash_value(self)
    }

    /// Proves that this action was derived from the exact accepted runtime result.
    pub fn validate_against_decision(
        &self,
        decision: &DecisionEnvelope,
    ) -> Result<(), DesktopError> {
        self.validate()?;
        if decision.status != DecisionStatus::Success
            || !decision.policy.allowed
            || decision.policy.human_review_required
        {
            return Err(DesktopError::AccessDenied(
                "runtime decision is not an unambiguously allowed success".to_owned(),
            ));
        }
        if self.request_id != decision.request_id
            || self.build_id != decision.build_id
            || self.package_content_hash != decision.package_content_hash
            || self.decision_hash != decision.decision_hash()
        {
            return Err(DesktopError::Integrity(
                "action is not bound to the supplied decision envelope".to_owned(),
            ));
        }
        let expected: BTreeSet<&str> = decision
            .evidence
            .iter()
            .map(|evidence| evidence.content_hash.as_str())
            .collect();
        let actual: BTreeSet<&str> = self.evidence_hashes.iter().map(String::as_str).collect();
        if expected != actual {
            return Err(DesktopError::Integrity(
                "action evidence set does not equal decision evidence".to_owned(),
            ));
        }
        Ok(())
    }
}

fn validate_path(value: &str, field: &str) -> Result<(), DesktopError> {
    validate_text(value, field)?;
    let path = std::path::Path::new(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(DesktopError::Invalid(format!(
            "{field} must be an absolute path without parent traversal"
        )));
    }
    Ok(())
}

fn validate_origin(origin: &str) -> Result<(), DesktopError> {
    validate_text(origin, "origin")?;
    let rest = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .ok_or_else(|| DesktopError::Invalid("origin must use HTTP or HTTPS".to_owned()))?;
    if rest.is_empty()
        || rest.contains('/')
        || rest.contains('?')
        || rest.contains('#')
        || rest.contains('@')
    {
        return Err(DesktopError::Invalid(
            "origin must contain only scheme and authority without credentials".to_owned(),
        ));
    }
    Ok(())
}

fn validate_browser_interaction(value: &BrowserInteraction) -> Result<(), DesktopError> {
    match value {
        BrowserInteraction::Click { locator } => validate_text(locator, "locator"),
        BrowserInteraction::TypeText {
            locator,
            text_hash,
            secret_ref,
        } => {
            validate_text(locator, "locator")?;
            validate_hash(text_hash, "text_hash")?;
            if let Some(reference) = secret_ref {
                validate_token(reference, "secret_ref")?;
            }
            Ok(())
        }
        BrowserInteraction::Select {
            locator,
            value_hash,
        } => {
            validate_text(locator, "locator")?;
            validate_hash(value_hash, "value_hash")
        }
    }
}

fn validate_ui_interaction(value: &UiInteraction) -> Result<(), DesktopError> {
    match value {
        UiInteraction::Invoke { automation_id } | UiInteraction::Toggle { automation_id, .. } => {
            validate_token(automation_id, "automation_id")
        }
        UiInteraction::SetText {
            automation_id,
            text_hash,
            secret_ref,
        } => {
            validate_token(automation_id, "automation_id")?;
            validate_hash(text_hash, "text_hash")?;
            if let Some(reference) = secret_ref {
                validate_token(reference, "secret_ref")?;
            }
            Ok(())
        }
    }
}
