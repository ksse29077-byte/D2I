use crate::windows_binding::{WindowsWfpBrowserEgressPolicy, WINDOWS_WFP_LOOPBACK_PROVIDER_ID};
use crate::{
    read_bounded, sha256_bytes, DesktopError, SignedWindowsBrowserEgressEvidence,
    WindowsAdapterConfiguration, WindowsBrowserEgressInput,
};
use d2i_windows_host::WindowsWfpLoopbackPolicyIdentity;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_BROWSER_IMAGE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_VERIFIER_OUTPUT_BYTES: u64 = 64 * 1024;

/// Serializable identity of the concrete WFP objects verified on the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsWfpBrowserEgressObservation {
    pub schema_version: u32,
    pub enforcement_id: String,
    pub provider_id: String,
    pub policy_hash: String,
    pub browser_executable: String,
    pub browser_executable_hash: String,
    pub provider_key: String,
    pub sublayer_key: String,
    pub filter_keys: [String; 4],
    pub verifier_sid: String,
    pub policy_owner_sid: String,
    pub engine_security_descriptor_hash: String,
    pub object_security_descriptor_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsWfpVerifierOutput {
    schema_version: u32,
    provider_key: String,
    sublayer_key: String,
    filter_keys: [String; 4],
    verifier_sid: String,
    engine_security_descriptor_sddl: String,
    security_descriptor_sddl: String,
}

/// Creates a concrete WFP policy from the current canonical browser image.
pub fn create_windows_wfp_browser_egress_policy(
    enforcement_id: String,
    browser_executable: &Path,
    verifier_profile_name: &str,
) -> Result<WindowsWfpBrowserEgressPolicy, DesktopError> {
    let metadata =
        std::fs::symlink_metadata(browser_executable).map_err(|error| DesktopError::Io {
            path: browser_executable.display().to_string(),
            message: error.to_string(),
        })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_BROWSER_IMAGE_BYTES
        || d2i_windows_host::is_reparse_point(browser_executable).map_err(|error| {
            DesktopError::Integrity(format!("browser reparse-point check failed: {error}"))
        })?
    {
        return Err(DesktopError::Integrity(
            "browser executable must be a bounded regular non-reparse file".to_owned(),
        ));
    }
    let canonical =
        std::fs::canonicalize(browser_executable).map_err(|error| DesktopError::Io {
            path: browser_executable.display().to_string(),
            message: error.to_string(),
        })?;
    let verifier =
        d2i_windows_host::appcontainer_profile(verifier_profile_name).map_err(|error| {
            DesktopError::Precondition(format!(
                "WFP verifier AppContainer profile is not provisioned: {error}"
            ))
        })?;
    let owner = d2i_windows_host::host_identity().map_err(|error| {
        DesktopError::AdapterUnavailable(format!("WFP policy owner identity failed: {error}"))
    })?;
    let policy = WindowsWfpBrowserEgressPolicy {
        schema_version: 2,
        enforcement_id,
        provider_id: WINDOWS_WFP_LOOPBACK_PROVIDER_ID.to_owned(),
        browser_executable: canonical.display().to_string(),
        browser_executable_hash: sha256_bytes(&read_bounded(&canonical, MAX_BROWSER_IMAGE_BYTES)?),
        verifier_profile_name: verifier.profile_name,
        verifier_profile_sid: verifier.profile_sid,
        policy_owner_sid: owner.user_sid,
    };
    let _ = verify_browser_image(&policy)?;
    Ok(policy)
}

/// Installs and then exactly verifies the persistent browser WFP policy.
pub fn install_windows_wfp_browser_egress(
    policy: &WindowsWfpBrowserEgressPolicy,
) -> Result<WindowsWfpBrowserEgressObservation, DesktopError> {
    let browser = verify_browser_image(policy)?;
    let identity = d2i_windows_host::install_wfp_loopback_policy(
        &browser,
        &policy.verifier_profile_sid,
        &policy.policy_owner_sid,
    )
    .map_err(|error| {
        DesktopError::AccessDenied(format!(
            "Windows WFP loopback policy installation failed: {error}"
        ))
    })?;
    observation(policy, identity)
}

/// Verifies the browser image and every persistent WFP object and condition.
pub fn verify_windows_wfp_browser_egress(
    policy: &WindowsWfpBrowserEgressPolicy,
) -> Result<WindowsWfpBrowserEgressObservation, DesktopError> {
    let browser = verify_browser_image(policy)?;
    let identity = d2i_windows_host::verify_wfp_loopback_policy(
        &browser,
        &policy.verifier_profile_sid,
        &policy.policy_owner_sid,
    )
    .map_err(|error| {
        DesktopError::AdapterUnavailable(format!(
            "Windows WFP loopback policy verification failed: {error}"
        ))
    })?;
    observation(policy, identity)
}

/// Removes all fixed D2I WFP loopback-policy objects.
pub fn remove_windows_wfp_browser_egress(
    policy: &WindowsWfpBrowserEgressPolicy,
) -> Result<(), DesktopError> {
    policy.validate()?;
    d2i_windows_host::remove_wfp_loopback_policy(&policy.verifier_profile_sid).map_err(|error| {
        DesktopError::AccessDenied(format!(
            "Windows WFP loopback policy removal failed: {error}"
        ))
    })
}

/// Verifies live WFP state and signs a short-lived exact-scope observation.
pub fn attest_windows_wfp_browser_egress(
    _policy: &WindowsWfpBrowserEgressPolicy,
    _input: WindowsBrowserEgressInput,
    _signing_key: &SigningKey,
) -> Result<SignedWindowsBrowserEgressEvidence, DesktopError> {
    Err(DesktopError::AccessDenied(
        "legacy functional attestation v1 is rejected for the concrete WFP provider; use v2"
            .to_owned(),
    ))
}

pub(crate) fn verify_configured_windows_browser_egress(
    configuration: &WindowsAdapterConfiguration,
) -> Result<(), DesktopError> {
    if let Some(policy) = &configuration.browser_egress_policy {
        let _ = verify_windows_wfp_browser_egress_isolated(configuration, policy)?;
    }
    Ok(())
}

/// Verifies concrete WFP state through the dedicated least-privilege verifier.
pub fn verify_windows_wfp_browser_egress_runtime(
    configuration: &WindowsAdapterConfiguration,
) -> Result<WindowsWfpBrowserEgressObservation, DesktopError> {
    configuration.validate()?;
    let policy = configuration
        .browser_egress_policy
        .as_ref()
        .ok_or_else(|| {
            DesktopError::Invalid("runtime WFP check requires a concrete browser policy".to_owned())
        })?;
    verify_windows_wfp_browser_egress_isolated(configuration, policy)
}

/// Runs the exact-key verifier inside the dedicated zero-capability profile.
#[doc(hidden)]
pub fn run_windows_wfp_verifier_worker(
    browser: &Path,
    verifier_sid: &str,
    owner_sid: &str,
    output_path: &Path,
) -> Result<(), DesktopError> {
    let identity = d2i_windows_host::verify_wfp_loopback_policy(browser, verifier_sid, owner_sid)
        .map_err(|error| {
        DesktopError::AdapterUnavailable(format!(
            "isolated WFP exact-key verification failed: {error}"
        ))
    })?;
    let output = WindowsWfpVerifierOutput {
        schema_version: 1,
        provider_key: identity.provider_key,
        sublayer_key: identity.sublayer_key,
        filter_keys: identity.filter_keys,
        verifier_sid: identity.verifier_sid,
        engine_security_descriptor_sddl: identity.engine_security_descriptor_sddl,
        security_descriptor_sddl: identity.security_descriptor_sddl,
    };
    crate::write_new(output_path, &crate::json_bytes(&output)?)
}

fn verify_windows_wfp_browser_egress_isolated(
    configuration: &WindowsAdapterConfiguration,
    policy: &WindowsWfpBrowserEgressPolicy,
) -> Result<WindowsWfpBrowserEgressObservation, DesktopError> {
    let browser = verify_browser_image(policy)?;
    let profile =
        d2i_windows_host::appcontainer_profile(&policy.verifier_profile_name).map_err(|error| {
            DesktopError::AdapterUnavailable(format!(
                "WFP verifier profile resolution failed: {error}"
            ))
        })?;
    if profile.profile_sid != policy.verifier_profile_sid {
        return Err(DesktopError::Integrity(
            "WFP verifier profile SID differs from policy".to_owned(),
        ));
    }
    let nonce = d2i_windows_host::secure_random_bytes::<16>().map_err(|error| {
        DesktopError::AdapterUnavailable(format!("WFP verifier nonce failed: {error}"))
    })?;
    let nonce = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let root =
        std::env::temp_dir().join(format!("d2i-wfp-verifier-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&root).map_err(|error| DesktopError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    let cleanup = VerifierDirectory(root.clone());
    d2i_windows_host::grant_appcontainer_path_access(
        &policy.verifier_profile_name,
        &root,
        d2i_windows_host::WindowsAppContainerPathAccess::ReadWrite,
        true,
    )
    .map_err(|error| {
        DesktopError::Integrity(format!("WFP verifier output ACL grant failed: {error}"))
    })?;
    let output = root.join("observation.json");
    let worker = Path::new(&configuration.worker_executable);
    let arguments = vec![
        "__windows-wfp-verifier".to_owned(),
        browser.display().to_string(),
        policy.verifier_profile_sid.clone(),
        policy.policy_owner_sid.clone(),
        output.display().to_string(),
    ];
    let child = d2i_windows_host::spawn_zero_capability_appcontainer(
        &policy.verifier_profile_name,
        &policy.verifier_profile_sid,
        worker,
        &arguments,
        &root,
    )
    .map_err(|error| {
        DesktopError::AdapterUnavailable(format!("WFP verifier launch failed: {error}"))
    })?;
    let timeout = Duration::from_millis(configuration.request_timeout_ms.clamp(100, 60_000));
    let exit_code = match child.wait_timeout(timeout).map_err(|error| {
        DesktopError::AdapterUnavailable(format!("WFP verifier wait failed: {error}"))
    })? {
        Some(code) => code,
        None => {
            let _ = child.terminate();
            return Err(DesktopError::AdapterUnavailable(
                "WFP verifier exceeded its bounded deadline".to_owned(),
            ));
        }
    };
    if exit_code != 0 {
        let diagnostic_path = output.with_extension("error.txt");
        let diagnostic = if diagnostic_path.exists() {
            String::from_utf8_lossy(&read_bounded(&diagnostic_path, MAX_VERIFIER_OUTPUT_BYTES)?)
                .into_owned()
        } else {
            "no bounded verifier diagnostic was produced".to_owned()
        };
        return Err(DesktopError::AdapterUnavailable(format!(
            "WFP verifier exited with code {exit_code}: {diagnostic}"
        )));
    }
    let observed: WindowsWfpVerifierOutput =
        serde_json::from_slice(&read_bounded(&output, MAX_VERIFIER_OUTPUT_BYTES)?)
            .map_err(|error| DesktopError::Json(error.to_string()))?;
    if observed.schema_version != 1 {
        return Err(DesktopError::Integrity(
            "WFP verifier output version is invalid".to_owned(),
        ));
    }
    let identity = WindowsWfpLoopbackPolicyIdentity {
        provider_key: observed.provider_key,
        sublayer_key: observed.sublayer_key,
        filter_keys: observed.filter_keys,
        verifier_sid: observed.verifier_sid,
        engine_security_descriptor_sddl: observed.engine_security_descriptor_sddl,
        security_descriptor_sddl: observed.security_descriptor_sddl,
    };
    let result = observation(policy, identity)?;
    drop(cleanup);
    Ok(result)
}

struct VerifierDirectory(PathBuf);

impl Drop for VerifierDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn observation(
    policy: &WindowsWfpBrowserEgressPolicy,
    identity: WindowsWfpLoopbackPolicyIdentity,
) -> Result<WindowsWfpBrowserEgressObservation, DesktopError> {
    Ok(WindowsWfpBrowserEgressObservation {
        schema_version: 2,
        enforcement_id: policy.enforcement_id.clone(),
        provider_id: policy.provider_id.clone(),
        policy_hash: policy.policy_hash()?,
        browser_executable: policy.browser_executable.clone(),
        browser_executable_hash: policy.browser_executable_hash.clone(),
        provider_key: identity.provider_key,
        sublayer_key: identity.sublayer_key,
        filter_keys: identity.filter_keys,
        verifier_sid: identity.verifier_sid,
        policy_owner_sid: policy.policy_owner_sid.clone(),
        engine_security_descriptor_hash: sha256_bytes(
            identity.engine_security_descriptor_sddl.as_bytes(),
        ),
        object_security_descriptor_hash: sha256_bytes(identity.security_descriptor_sddl.as_bytes()),
    })
}

fn verify_browser_image(policy: &WindowsWfpBrowserEgressPolicy) -> Result<PathBuf, DesktopError> {
    policy.validate()?;
    let declared = Path::new(&policy.browser_executable);
    let metadata = std::fs::symlink_metadata(declared).map_err(|error| DesktopError::Io {
        path: declared.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || d2i_windows_host::is_reparse_point(declared).map_err(|error| {
            DesktopError::Integrity(format!("browser reparse-point check failed: {error}"))
        })?
    {
        return Err(DesktopError::Integrity(
            "browser executable must be a regular non-reparse file".to_owned(),
        ));
    }
    let canonical = std::fs::canonicalize(declared).map_err(|error| DesktopError::Io {
        path: declared.display().to_string(),
        message: error.to_string(),
    })?;
    if canonical.display().to_string() != policy.browser_executable {
        return Err(DesktopError::Integrity(
            "browser executable path is not its exact canonical path".to_owned(),
        ));
    }
    let actual_hash = sha256_bytes(&read_bounded(&canonical, MAX_BROWSER_IMAGE_BYTES)?);
    if actual_hash != policy.browser_executable_hash {
        return Err(DesktopError::Integrity(
            "browser executable hash differs from the WFP policy".to_owned(),
        ));
    }
    Ok(canonical)
}
