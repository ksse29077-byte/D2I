use crate::{hex_encode, json_bytes, validate_token, DesktopError};
use d2i_windows_host::{host_identity, protect_current_user, unprotect_current_user};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

/// Deployment role that a protected Windows signing key may perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsSigningKeyPurpose {
    BindingAttestor,
    Certifier,
    BrowserEgressProvider,
}

/// Current-user DPAPI envelope for one purpose-bound Ed25519 key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsProtectedSigningKey {
    pub schema_version: u32,
    pub key_id: String,
    pub purpose: WindowsSigningKeyPurpose,
    pub user_sid: String,
    pub public_key: String,
    pub protected_key_hex: String,
}

#[derive(Serialize)]
struct ProtectionContext<'a> {
    schema_version: u32,
    key_id: &'a str,
    purpose: WindowsSigningKeyPurpose,
    user_sid: &'a str,
    public_key: &'a str,
}

/// Protects one signing key for the current Windows user and exact purpose.
pub fn protect_windows_signing_key(
    key_id: String,
    purpose: WindowsSigningKeyPurpose,
    signing_key: &SigningKey,
) -> Result<WindowsProtectedSigningKey, DesktopError> {
    validate_token(&key_id, "Windows signing key_id")?;
    let host = host_identity().map_err(|error| {
        DesktopError::AdapterUnavailable(format!("Windows token identity failed: {error}"))
    })?;
    if host.is_appcontainer {
        return Err(DesktopError::AccessDenied(
            "signing keys cannot be enrolled from an AppContainer token".to_owned(),
        ));
    }
    let public_key = hex_encode(&signing_key.verifying_key().to_bytes());
    let context = ProtectionContext {
        schema_version: 1,
        key_id: &key_id,
        purpose,
        user_sid: &host.user_sid,
        public_key: &public_key,
    };
    let protected = protect_current_user(&signing_key.to_bytes(), &json_bytes(&context)?)
        .map_err(|error| DesktopError::Integrity(format!("DPAPI protection failed: {error}")))?;
    Ok(WindowsProtectedSigningKey {
        schema_version: 1,
        key_id,
        purpose,
        user_sid: host.user_sid,
        public_key,
        protected_key_hex: hex_encode(&protected),
    })
}

/// Opens a purpose-bound key only for the same Windows user and verifies its public identity.
pub fn unprotect_windows_signing_key(
    protected: &WindowsProtectedSigningKey,
    expected_purpose: WindowsSigningKeyPurpose,
) -> Result<SigningKey, DesktopError> {
    protected.validate()?;
    if protected.purpose != expected_purpose {
        return Err(DesktopError::AccessDenied(
            "protected signing key purpose does not match the requested operation".to_owned(),
        ));
    }
    let host = host_identity().map_err(|error| {
        DesktopError::AdapterUnavailable(format!("Windows token identity failed: {error}"))
    })?;
    if host.is_appcontainer || host.user_sid != protected.user_sid {
        return Err(DesktopError::AccessDenied(
            "protected signing key belongs to a different Windows user token".to_owned(),
        ));
    }
    let context = ProtectionContext {
        schema_version: protected.schema_version,
        key_id: &protected.key_id,
        purpose: protected.purpose,
        user_sid: &protected.user_sid,
        public_key: &protected.public_key,
    };
    let mut plaintext = unprotect_current_user(
        &decode_hex(&protected.protected_key_hex, "protected_key_hex")?,
        &json_bytes(&context)?,
    )
    .map_err(|error| DesktopError::Integrity(format!("DPAPI unprotection failed: {error}")))?;
    if plaintext.len() != 32 {
        plaintext.fill(0);
        return Err(DesktopError::Integrity(
            "protected signing key plaintext length is invalid".to_owned(),
        ));
    }
    let mut secret = [0_u8; 32];
    secret.copy_from_slice(&plaintext);
    plaintext.fill(0);
    let signing_key = SigningKey::from_bytes(&secret);
    secret.fill(0);
    if hex_encode(&signing_key.verifying_key().to_bytes()) != protected.public_key {
        return Err(DesktopError::Integrity(
            "protected signing key does not match its public identity".to_owned(),
        ));
    }
    Ok(signing_key)
}

impl WindowsProtectedSigningKey {
    /// Validates the envelope before any DPAPI operation.
    pub fn validate(&self) -> Result<(), DesktopError> {
        if self.schema_version != 1 {
            return Err(DesktopError::Invalid(
                "protected Windows signing key schema_version must be 1".to_owned(),
            ));
        }
        validate_token(&self.key_id, "Windows signing key_id")?;
        if !self.user_sid.starts_with("S-1-")
            || self
                .user_sid
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !matches!(byte, b'S' | b'-'))
        {
            return Err(DesktopError::Invalid(
                "protected signing key user_sid is invalid".to_owned(),
            ));
        }
        if self.public_key.len() != 64
            || !self.public_key.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(DesktopError::Invalid(
                "protected signing key public_key must be 32-byte hex".to_owned(),
            ));
        }
        let bytes = decode_hex(&self.protected_key_hex, "protected_key_hex")?;
        if bytes.is_empty() || bytes.len() > 4 * 1024 {
            return Err(DesktopError::Invalid(
                "protected signing key DPAPI blob is outside its bound".to_owned(),
            ));
        }
        Ok(())
    }
}

fn decode_hex(value: &str, field: &str) -> Result<Vec<u8>, DesktopError> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DesktopError::Invalid(format!(
            "{field} must be even-length hexadecimal"
        )));
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    for offset in (0..value.len()).step_by(2) {
        output.push(
            u8::from_str_radix(&value[offset..offset + 2], 16)
                .map_err(|error| DesktopError::Invalid(error.to_string()))?,
        );
    }
    Ok(output)
}
