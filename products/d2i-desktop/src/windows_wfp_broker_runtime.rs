use crate::{
    create_signed_wfp_verification_receipt, hash_value, json_bytes,
    protect_wfp_verifier_signing_key, read_bounded, sha256_bytes,
    unprotect_wfp_verifier_signing_key, write_new, DesktopError, SignedWfpVerificationReceipt,
    SignedWindowsWfpFunctionalAttestationV2, WfpExpectedObjectGuids, WfpReceiptReplayLedger,
    WfpVerificationRequest, WfpVerifierOperation, WindowsAdapterConfiguration,
    WindowsDeploymentAuditEvent, WindowsDeploymentAuditEventKind, WindowsDeploymentAuditLedger,
    WindowsDeploymentAuditStatus, WindowsHostBinding, WindowsProtectedWfpVerifierKey,
    WindowsWfpBrowserEgressObservation, WindowsWfpBrowserEgressPolicy,
    WindowsWfpVerifierBrokerBinding, WindowsWfpVerifierBrokerServiceConfiguration,
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[cfg(test)]
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_BROKER_ARTIFACT_BYTES: u64 = 256 * 1024;
const MAX_BROKER_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_BROKER_MESSAGE_BYTES: u32 = 64 * 1024;
const MAX_BROKER_DIAGNOSTIC_BYTES: u64 = 64 * 1024;
const MAX_BROKER_REQUEST_SECONDS: u64 = 30;
const BROKER_EXECUTABLE_NAME: &str = "d2i-wfp-verifier-broker.exe";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppContainerBrokerClientInput {
    schema_version: u32,
    request: WfpVerificationRequest,
    broker: WindowsWfpVerifierBrokerBinding,
    functional_attestation: SignedWindowsWfpFunctionalAttestationV2,
    request_handoff_path: String,
    response_handoff_path: String,
    output_path: String,
    timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BrokerWireStatus {
    Verified,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerWireResponse {
    schema_version: u32,
    status: BrokerWireStatus,
    failure_code: String,
    receipt: Option<SignedWfpVerificationReceipt>,
}

impl BrokerWireResponse {
    fn verified(receipt: SignedWfpVerificationReceipt) -> Self {
        Self {
            schema_version: 1,
            status: BrokerWireStatus::Verified,
            failure_code: "none".to_owned(),
            receipt: Some(receipt),
        }
    }

    fn rejected(failure_code: &'static str) -> Self {
        Self {
            schema_version: 1,
            status: BrokerWireStatus::Rejected,
            failure_code: failure_code.to_owned(),
            receipt: None,
        }
    }

    fn into_receipt(self) -> Result<SignedWfpVerificationReceipt, DesktopError> {
        crate::validate_token(&self.failure_code, "WFP broker wire failure code")?;
        match (
            self.schema_version,
            self.status,
            self.failure_code.as_str(),
            self.receipt,
        ) {
            (1, BrokerWireStatus::Verified, "none", Some(receipt)) => Ok(receipt),
            (1, BrokerWireStatus::Rejected, code, None) if code != "none" => {
                Err(DesktopError::AccessDenied(format!(
                    "WFP verifier broker rejected the request with code {code}"
                )))
            }
            _ => Err(DesktopError::Integrity(
                "WFP verifier broker response shape is inconsistent".to_owned(),
            )),
        }
    }
}

struct BrokerServiceFailure {
    code: &'static str,
}

/// Complete result of one medium-runtime broker verification round trip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsWfpBrokerRuntimeVerification {
    pub schema_version: u32,
    pub observation: WindowsWfpBrowserEgressObservation,
    pub receipt: SignedWfpVerificationReceipt,
    pub receipt_hash: String,
}

/// Installs the demand-start service, creates its machine-bound signing key,
/// and upgrades a legacy policy declaration to the Service-SID v3 contract.
#[allow(clippy::too_many_arguments)]
pub fn provision_windows_wfp_verifier_broker(
    mut policy: WindowsWfpBrowserEgressPolicy,
    service_name: &str,
    pipe_name: &str,
    verifier_build_id: &str,
    verifier_executable: &Path,
    future_service_configuration: &Path,
    protected_key_path: &Path,
    signer_key_id: &str,
) -> Result<WindowsWfpBrowserEgressPolicy, DesktopError> {
    policy.validate()?;
    if policy.schema_version != 2 || policy.verifier_broker.is_some() {
        return Err(DesktopError::Invalid(
            "WFP verifier provisioning requires an unbound v2 policy".to_owned(),
        ));
    }
    if future_service_configuration.exists() || protected_key_path.exists() {
        return Err(DesktopError::Precondition(
            "WFP verifier configuration and protected key paths must be new".to_owned(),
        ));
    }
    let root = common_parent(future_service_configuration, protected_key_path)?;
    let executable = canonical_regular_file(verifier_executable, MAX_BROKER_EXECUTABLE_BYTES)?;
    if !executable
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case(BROKER_EXECUTABLE_NAME))
    {
        return Err(DesktopError::Invalid(format!(
            "WFP verifier service executable must be the dedicated {BROKER_EXECUTABLE_NAME}"
        )));
    }
    let executable_hash = sha256_bytes(&read_bounded(&executable, MAX_BROKER_EXECUTABLE_BYTES)?);
    std::fs::create_dir(&root).map_err(|error| DesktopError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    let service = d2i_windows_host::install_verifier_service(
        service_name,
        &executable,
        future_service_configuration,
        &policy.policy_owner_sid,
    )
    .map_err(|error| {
        DesktopError::AccessDenied(format!("WFP verifier service installation failed: {error}"))
    })?;
    let provisioned = (|| {
        let mut seed = d2i_windows_host::secure_random_bytes::<32>().map_err(|error| {
            DesktopError::AdapterUnavailable(format!(
                "WFP verifier signing-key generation failed: {error}"
            ))
        })?;
        let signing_key = SigningKey::from_bytes(&seed);
        seed.fill(0);
        let protected = protect_wfp_verifier_signing_key(signer_key_id.to_owned(), &signing_key)?;
        let broker = WindowsWfpVerifierBrokerBinding {
            schema_version: 1,
            service_name: service.service_name,
            service_sid: service.service_sid,
            pipe_name: pipe_name.to_owned(),
            verifier_build_id: verifier_build_id.to_owned(),
            verifier_executable: executable.display().to_string(),
            verifier_executable_hash: executable_hash,
            signer_key_id: protected.key_id.clone(),
            signer_public_key: protected.signer_public_key.clone(),
        };
        broker.validate()?;
        write_new(protected_key_path, &json_bytes(&protected)?)?;
        d2i_windows_host::harden_path_for_verifier_service(
            protected_key_path,
            &broker.service_sid,
            false,
        )
        .map_err(|error| {
            DesktopError::Integrity(format!(
                "WFP verifier protected-key ACL hardening failed: {error}"
            ))
        })?;
        d2i_windows_host::harden_path_for_verifier_service(&root, &broker.service_sid, true)
            .map_err(|error| {
                DesktopError::Integrity(format!(
                    "WFP verifier deployment-root ACL hardening failed: {error}"
                ))
            })?;
        d2i_windows_host::harden_executable_for_verifier_service(&executable, &broker.service_sid)
            .map_err(|error| {
                DesktopError::Integrity(format!(
                    "WFP verifier executable ACL hardening failed: {error}"
                ))
            })?;
        policy.schema_version = 3;
        policy.verifier_broker = Some(broker);
        policy.validate()?;
        Ok(policy)
    })();
    if provisioned.is_err() {
        let _ = d2i_windows_host::remove_verifier_service(service_name);
        let _ = std::fs::remove_file(protected_key_path);
        let _ = std::fs::remove_dir(&root);
    }
    provisioned
}

/// Writes the immutable service allowlist after functional attestation exists.
pub fn configure_windows_wfp_verifier_broker(
    policy: &WindowsWfpBrowserEgressPolicy,
    runtime: &WindowsAdapterConfiguration,
    functional_attestation: &SignedWindowsWfpFunctionalAttestationV2,
    protected_key_path: &Path,
    output: &Path,
    now_unix_seconds: u64,
) -> Result<WindowsWfpVerifierBrokerServiceConfiguration, DesktopError> {
    policy.validate()?;
    runtime.validate()?;
    crate::windows_attestation::validate_windows_wfp_functional_attestation_v2(
        functional_attestation,
    )?;
    let broker = policy.verifier_broker.as_ref().ok_or_else(|| {
        DesktopError::Invalid("WFP verifier configuration requires a v3 broker policy".to_owned())
    })?;
    if runtime.browser_egress_policy.as_ref() != Some(policy)
        || functional_attestation.runtime_binding_digest != runtime.configuration_hash()?
        || functional_attestation.machine_binding.is_appcontainer
        || functional_attestation.policy_hash != policy.policy_hash()?
        || functional_attestation.browser_executable_hash != policy.browser_executable_hash
        || functional_attestation.provider_key != crate::WINDOWS_WFP_PROVIDER_GUID
        || functional_attestation.sublayer_key != crate::WINDOWS_WFP_SUBLAYER_GUID
        || functional_attestation.filter_keys
            != WfpExpectedObjectGuids::d2i_browser_egress().filters
        || now_unix_seconds < functional_attestation.issued_at_unix_seconds
        || now_unix_seconds >= functional_attestation.expires_at_unix_seconds
    {
        return Err(DesktopError::Integrity(
            "functional attestation differs from the broker policy or runtime".to_owned(),
        ));
    }
    let protected_key_path = canonical_regular_file(protected_key_path, MAX_BROKER_ARTIFACT_BYTES)?;
    let protected: WindowsProtectedWfpVerifierKey = serde_json::from_slice(&read_bounded(
        &protected_key_path,
        MAX_BROKER_ARTIFACT_BYTES,
    )?)
    .map_err(|error| DesktopError::Json(error.to_string()))?;
    let signing_key = unprotect_wfp_verifier_signing_key(
        &protected,
        &broker.signer_key_id,
        &broker.signer_public_key,
    )?;
    drop(signing_key);
    let configuration = WindowsWfpVerifierBrokerServiceConfiguration {
        schema_version: 1,
        broker: broker.clone(),
        approved_appcontainer_sid: policy.verifier_profile_sid.clone(),
        approved_runtime_executable_hash: runtime.worker_executable_hash.clone(),
        expected_runtime_binding_digest: runtime.configuration_hash()?,
        expected_machine_session_binding: functional_attestation.machine_binding.clone(),
        policy: policy.clone(),
        edge_driver_hash: functional_attestation.driver_executable_hash.clone(),
        functional_report_hash: functional_attestation.self_test_report_hash.clone(),
        attestation_hash: functional_attestation.attestation_hash()?,
        protected_signing_key_path: protected_key_path.display().to_string(),
    };
    configuration.validate()?;
    write_new(output, &json_bytes(&configuration)?)?;
    d2i_windows_host::harden_path_for_verifier_service(output, &broker.service_sid, false)
        .map_err(|error| {
            DesktopError::Integrity(format!(
                "WFP verifier service-configuration ACL hardening failed: {error}"
            ))
        })?;
    Ok(configuration)
}

/// Removes the immutable broker configuration, DPAPI key, and staged image
/// after the service and WFP policy have been recalled.
pub fn remove_windows_wfp_verifier_broker_artifacts(
    policy: &WindowsWfpBrowserEgressPolicy,
    service_configuration_path: &Path,
) -> Result<(), DesktopError> {
    policy.validate()?;
    let broker = policy.verifier_broker.as_ref().ok_or_else(|| {
        DesktopError::Invalid("WFP broker artifact cleanup requires a v3 policy".to_owned())
    })?;
    let service_configuration_path =
        canonical_regular_file(service_configuration_path, MAX_BROKER_ARTIFACT_BYTES)?;
    let configuration = load_service_configuration(&service_configuration_path)?;
    if &configuration.broker != broker || &configuration.policy != policy {
        return Err(DesktopError::Integrity(
            "broker cleanup configuration differs from the policy".to_owned(),
        ));
    }
    let protected_key_path = canonical_regular_file(
        Path::new(&configuration.protected_signing_key_path),
        MAX_BROKER_ARTIFACT_BYTES,
    )?;
    let verifier_executable = canonical_regular_file(
        Path::new(&broker.verifier_executable),
        MAX_BROKER_EXECUTABLE_BYTES,
    )?;
    let broker_root = common_parent(&service_configuration_path, &protected_key_path)?;
    let image_root = verifier_executable.parent().ok_or_else(|| {
        DesktopError::Invalid("broker executable has no parent directory".to_owned())
    })?;
    if image_root == broker_root {
        return Err(DesktopError::AccessDenied(
            "broker configuration and image roots must be separate".to_owned(),
        ));
    }
    require_exact_cleanup_files(
        &broker_root,
        &[&service_configuration_path, &protected_key_path],
    )?;
    require_exact_cleanup_files(image_root, &[&verifier_executable])?;
    for path in [
        &service_configuration_path,
        &protected_key_path,
        &verifier_executable,
    ] {
        std::fs::remove_file(path).map_err(|error| DesktopError::Io {
            path: path.display().to_string(),
            message: format!("WFP broker artifact cleanup failed: {error}"),
        })?;
    }
    for root in [&broker_root, image_root] {
        std::fs::remove_dir(root).map_err(|error| DesktopError::Io {
            path: root.display().to_string(),
            message: format!("WFP broker artifact root cleanup failed: {error}"),
        })?;
    }
    Ok(())
}

/// Executes the SCM-hosted one-request verifier endpoint.
#[doc(hidden)]
pub fn run_windows_wfp_verifier_broker_service(
    configuration_path: &Path,
) -> Result<(), DesktopError> {
    let configuration = load_service_configuration(configuration_path)?;
    d2i_windows_host::run_verifier_service_dispatcher(
        &configuration.broker.service_name,
        verifier_service_entry,
    )
    .map_err(|error| {
        DesktopError::AdapterUnavailable(format!("WFP verifier service dispatcher failed: {error}"))
    })
}

fn verifier_service_entry() -> Result<(), u32> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let [mode, configuration_path] = arguments.as_slice() else {
        return Err(1001);
    };
    if mode != "__windows-wfp-broker-service" {
        return Err(1002);
    }
    run_verifier_service_once(Path::new(configuration_path))
        .map_err(|error| verifier_service_exit_code(&error))
}

fn verifier_service_exit_code(error: &DesktopError) -> u32 {
    let text = error.to_string();
    for (failure, code) in [
        ("GetNamedPipeClientProcessId", 1201),
        ("OpenProcess(pipe client)", 1202),
        ("OpenProcessToken(pipe client)", 1203),
        ("GetTokenInformation(pipe client)", 1204),
        ("ProcessIdToSessionId(pipe client)", 1205),
        ("QueryFullProcessImageNameW", 1206),
        ("ConnectNamedPipe", 1207),
        ("connect completion", 1208),
    ] {
        if text.contains(failure) {
            return code;
        }
    }
    for (failure, code) in [
        ("relay_identity", 1101),
        ("relay_executable", 1102),
        ("request_frame", 1103),
        ("request_malformed", 1104),
        ("request_not_authorized", 1105),
        ("relay_process_binding", 1106),
        ("appcontainer_identity", 1107),
        ("wfp_exact_verification", 1108),
        ("clock", 1109),
        ("monotonic_clock", 1110),
        ("receipt_creation", 1111),
        ("appcontainer_recheck", 1112),
    ] {
        if text.contains(failure) {
            return code;
        }
    }
    if text.contains("response write failed") {
        1190
    } else if text.contains("pipe accept failed") {
        1191
    } else if text.contains("Service SID") {
        1192
    } else if text.contains("protected") || text.contains("unprotect") {
        1193
    } else if text.contains("running verifier executable") {
        1194
    } else {
        1199
    }
}

fn run_verifier_service_once(configuration_path: &Path) -> Result<(), DesktopError> {
    let configuration = load_service_configuration(configuration_path)?;
    let broker = &configuration.broker;
    let current_executable = std::env::current_exe().map_err(|error| DesktopError::Io {
        path: "<current executable>".to_owned(),
        message: error.to_string(),
    })?;
    let current_executable =
        canonical_regular_file(&current_executable, MAX_BROKER_EXECUTABLE_BYTES)?;
    let executable_hash = sha256_bytes(&read_bounded(
        &current_executable,
        MAX_BROKER_EXECUTABLE_BYTES,
    )?);
    if current_executable.display().to_string() != broker.verifier_executable
        || executable_hash != broker.verifier_executable_hash
    {
        return Err(DesktopError::Integrity(
            "running verifier executable differs from installation binding".to_owned(),
        ));
    }
    if !d2i_windows_host::current_process_has_sid(&broker.service_sid).map_err(|error| {
        DesktopError::AccessDenied(format!("verifier Service SID check failed: {error}"))
    })? {
        return Err(DesktopError::AccessDenied(
            "verifier process token does not contain its dedicated Service SID".to_owned(),
        ));
    }
    let protected: WindowsProtectedWfpVerifierKey = serde_json::from_slice(&read_bounded(
        Path::new(&configuration.protected_signing_key_path),
        MAX_BROKER_ARTIFACT_BYTES,
    )?)
    .map_err(|error| DesktopError::Json(error.to_string()))?;
    let signing_key = unprotect_wfp_verifier_signing_key(
        &protected,
        &broker.signer_key_id,
        &broker.signer_public_key,
    )?;
    let timeout = Duration::from_secs(MAX_BROKER_REQUEST_SECONDS);
    let connection = d2i_windows_host::accept_verifier_pipe(
        &broker.pipe_name,
        &broker.service_sid,
        &configuration.expected_machine_session_binding.user_sid,
        MAX_BROKER_MESSAGE_BYTES,
        timeout,
    )
    .map_err(|error| {
        DesktopError::AdapterUnavailable(format!("WFP verifier pipe accept failed: {error}"))
    })?;
    let result = run_verifier_service_exchange(
        &configuration,
        &connection,
        &signing_key,
        &executable_hash,
        timeout,
    );
    let response = match &result {
        Ok(receipt) => BrokerWireResponse::verified(receipt.clone()),
        Err(failure) => BrokerWireResponse::rejected(failure.code),
    };
    connection
        .write_message(&json_bytes(&response)?, MAX_BROKER_MESSAGE_BYTES, timeout)
        .map_err(|error| {
            DesktopError::AdapterUnavailable(format!("WFP verifier response write failed: {error}"))
        })?;
    result.map(|_| ()).map_err(|failure| {
        DesktopError::AccessDenied(format!(
            "WFP verifier broker rejected the request with code {}",
            failure.code
        ))
    })
}

fn run_verifier_service_exchange(
    configuration: &WindowsWfpVerifierBrokerServiceConfiguration,
    connection: &d2i_windows_host::WindowsVerifierPipeConnection,
    signing_key: &SigningKey,
    executable_hash: &str,
    timeout: Duration,
) -> Result<SignedWfpVerificationReceipt, BrokerServiceFailure> {
    let caller = connection.caller();
    broker_step(
        validate_relay_identity(caller, &configuration.expected_machine_session_binding),
        "relay_identity",
    )?;
    let caller_executable = broker_step(
        canonical_regular_file(&caller.executable, MAX_BROKER_EXECUTABLE_BYTES),
        "relay_executable",
    )?;
    if sha256_bytes(
        &read_bounded(&caller_executable, MAX_BROKER_EXECUTABLE_BYTES).map_err(|_| {
            BrokerServiceFailure {
                code: "relay_executable",
            }
        })?,
    ) != configuration.approved_runtime_executable_hash
    {
        return Err(BrokerServiceFailure {
            code: "relay_executable",
        });
    }
    let request_bytes = connection
        .read_message(MAX_BROKER_MESSAGE_BYTES, timeout)
        .map_err(|_| BrokerServiceFailure {
            code: "request_frame",
        })?;
    let request: WfpVerificationRequest =
        serde_json::from_slice(&request_bytes).map_err(|_| BrokerServiceFailure {
            code: "request_malformed",
        })?;
    let started_at_unix_ms =
        now_unix_milliseconds().map_err(|_| BrokerServiceFailure { code: "clock" })?;
    broker_step(
        configuration.authorize_request(&request, started_at_unix_ms / 1_000),
        "request_not_authorized",
    )?;
    if request.relay_process_id != caller.process_id {
        return Err(BrokerServiceFailure {
            code: "relay_process_binding",
        });
    }
    let appcontainer_identity = broker_step(
        validate_appcontainer_child_identity(configuration, &request),
        "appcontainer_identity",
    )?;
    let observation = broker_step(
        crate::verify_windows_wfp_browser_egress(&configuration.policy),
        "wfp_exact_verification",
    )?;
    let completed_at_unix_ms =
        now_unix_milliseconds().map_err(|_| BrokerServiceFailure { code: "clock" })?;
    let monotonic_sequence =
        d2i_windows_host::monotonic_milliseconds().map_err(|_| BrokerServiceFailure {
            code: "monotonic_clock",
        })?;
    let receipt = broker_step(
        create_signed_wfp_verification_receipt(
            configuration,
            &request,
            &observation,
            signing_key,
            executable_hash,
            started_at_unix_ms,
            completed_at_unix_ms,
            monotonic_sequence,
            completed_at_unix_ms / 1_000,
        ),
        "receipt_creation",
    )?;
    let appcontainer_identity_after = broker_step(
        validate_appcontainer_child_identity(configuration, &request),
        "appcontainer_recheck",
    )?;
    if appcontainer_identity_after != appcontainer_identity {
        return Err(BrokerServiceFailure {
            code: "appcontainer_recheck",
        });
    }
    Ok(receipt)
}

fn broker_step<T>(
    result: Result<T, DesktopError>,
    code: &'static str,
) -> Result<T, BrokerServiceFailure> {
    result.map_err(|_| BrokerServiceFailure { code })
}

fn validate_relay_identity(
    caller: &d2i_windows_host::WindowsVerifierPipeCaller,
    expected_machine_session_binding: &WindowsHostBinding,
) -> Result<(), DesktopError> {
    if caller.is_appcontainer
        || caller.appcontainer_sid.is_some()
        || caller.user_sid != expected_machine_session_binding.user_sid
        || caller.session_id != expected_machine_session_binding.session_id
        || caller.integrity_level_rid != expected_machine_session_binding.integrity_level_rid
        || caller.elevation_type != expected_machine_session_binding.elevation_type
        || expected_machine_session_binding.is_appcontainer
    {
        return Err(DesktopError::AccessDenied(
            "WFP verifier pipe caller is not the approved medium-runtime identity".to_owned(),
        ));
    }
    Ok(())
}

fn validate_appcontainer_child_identity(
    configuration: &WindowsWfpVerifierBrokerServiceConfiguration,
    request: &WfpVerificationRequest,
) -> Result<d2i_windows_host::WindowsVerifierPipeCaller, DesktopError> {
    let identity = d2i_windows_host::inspect_verifier_process(request.appcontainer_process_id)
        .map_err(|error| {
            DesktopError::AccessDenied(format!(
                "AppContainer verifier process inspection failed: {error}"
            ))
        })?;
    let expected_host = &configuration.expected_machine_session_binding;
    if !identity.is_appcontainer
        || identity.appcontainer_sid.as_deref()
            != Some(configuration.approved_appcontainer_sid.as_str())
        || identity.user_sid != expected_host.user_sid
        || identity.session_id != expected_host.session_id
        || identity.integrity_level_rid >= expected_host.integrity_level_rid
        || identity.elevation_type != expected_host.elevation_type
    {
        return Err(DesktopError::AccessDenied(
            "WFP verifier child is not the approved AppContainer identity".to_owned(),
        ));
    }
    let parent =
        d2i_windows_host::process_parent_id(request.appcontainer_process_id).map_err(|error| {
            DesktopError::AccessDenied(format!(
                "AppContainer verifier parent inspection failed: {error}"
            ))
        })?;
    if parent != request.relay_process_id {
        return Err(DesktopError::AccessDenied(
            "WFP verifier AppContainer is not a direct child of the connected relay".to_owned(),
        ));
    }
    let executable = canonical_regular_file(&identity.executable, MAX_BROKER_EXECUTABLE_BYTES)?;
    let executable_hash = sha256_bytes(&read_bounded(&executable, MAX_BROKER_EXECUTABLE_BYTES)?);
    if executable_hash != configuration.approved_runtime_executable_hash {
        return Err(DesktopError::AccessDenied(
            "WFP verifier AppContainer executable hash is not approved".to_owned(),
        ));
    }
    Ok(identity)
}

/// Runs inside the approved AppContainer, validates the receipt, and emits it
/// only after every request/attestation comparison succeeds.
#[doc(hidden)]
pub fn run_windows_wfp_broker_client_worker(input_path: &Path) -> Result<(), DesktopError> {
    let input: AppContainerBrokerClientInput =
        serde_json::from_slice(&read_bounded(input_path, MAX_BROKER_ARTIFACT_BYTES)?)
            .map_err(|error| DesktopError::Json(error.to_string()))?;
    if input.schema_version != 1 || input.timeout_ms < 100 || input.timeout_ms > 30_000 {
        return Err(DesktopError::Invalid(
            "WFP broker client input bounds are invalid".to_owned(),
        ));
    }
    validate_client_handoff_paths(input_path, &input)?;
    input.broker.validate()?;
    if input.request.appcontainer_process_id != 0
        || input.request.relay_process_id == 0
        || d2i_windows_host::process_parent_id(std::process::id()).map_err(|error| {
            DesktopError::AccessDenied(format!(
                "AppContainer relay parent inspection failed: {error}"
            ))
        })? != input.request.relay_process_id
    {
        return Err(DesktopError::AccessDenied(
            "AppContainer broker input is not bound to its launching relay".to_owned(),
        ));
    }
    let mut request = input.request.clone();
    request.appcontainer_process_id = std::process::id();
    request.validate(now_unix_seconds()?)?;
    write_new(
        Path::new(&input.request_handoff_path),
        &json_bytes(&request)?,
    )?;
    let response = wait_for_bounded_file(
        Path::new(&input.response_handoff_path),
        MAX_BROKER_ARTIFACT_BYTES,
        Duration::from_millis(input.timeout_ms),
        "broker relay response",
    )?;
    let receipt: SignedWfpVerificationReceipt = serde_json::from_slice(&response)
        .map_err(|error| DesktopError::Invalid(format!("malformed WFP receipt: {error}")))?;
    let mut replay = WfpReceiptReplayLedger::default();
    let _ = replay.validate_and_consume(
        &receipt,
        &request,
        &input.broker,
        &input.functional_attestation,
        now_unix_seconds()?,
    )?;
    write_new(Path::new(&input.output_path), &json_bytes(&receipt)?)
}

/// Runs one broker-backed verification outside binding collection.
pub fn verify_windows_wfp_browser_egress_through_broker(
    runtime: &WindowsAdapterConfiguration,
    functional_attestation: &SignedWindowsWfpFunctionalAttestationV2,
    now_unix_seconds: u64,
) -> Result<WindowsWfpBrokerRuntimeVerification, DesktopError> {
    let host = crate::current_windows_host_binding()?;
    let mut replay = WfpReceiptReplayLedger::default();
    let (observation, receipt) = verify_windows_wfp_through_broker(
        runtime,
        &host,
        functional_attestation,
        &mut replay,
        now_unix_seconds,
    )?;
    let receipt_hash = receipt.receipt_hash()?;
    Ok(WindowsWfpBrokerRuntimeVerification {
        schema_version: 1,
        observation,
        receipt,
        receipt_hash,
    })
}

/// Performs the medium-runtime to service to AppContainer receipt round trip.
pub(crate) fn verify_windows_wfp_through_broker(
    runtime: &WindowsAdapterConfiguration,
    host: &WindowsHostBinding,
    functional_attestation: &SignedWindowsWfpFunctionalAttestationV2,
    replay: &mut WfpReceiptReplayLedger,
    request_time_unix_seconds: u64,
) -> Result<
    (
        WindowsWfpBrowserEgressObservation,
        SignedWfpVerificationReceipt,
    ),
    DesktopError,
> {
    runtime.validate()?;
    let policy = runtime.browser_egress_policy.as_ref().ok_or_else(|| {
        DesktopError::Invalid("WFP broker verification requires a concrete policy".to_owned())
    })?;
    let broker = policy.verifier_broker.as_ref().ok_or_else(|| {
        DesktopError::AccessDenied(
            "legacy direct-AppContainer WFP verification is rejected; broker v3 is required"
                .to_owned(),
        )
    })?;
    let attestation_hash = functional_attestation.attestation_hash()?;
    let request_template = new_request_template(
        runtime,
        policy,
        host,
        functional_attestation,
        &attestation_hash,
        std::process::id(),
        request_time_unix_seconds,
    )?;
    let nonce = random_hex::<16>()?;
    let root = std::env::temp_dir().join(format!(
        "d2i-wfp-broker-client-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&root).map_err(|error| DesktopError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    let cleanup = BrokerClientDirectory(root.clone());
    d2i_windows_host::harden_path_for_current_user(&root).map_err(|error| {
        DesktopError::Integrity(format!(
            "WFP broker client root ACL hardening failed: {error}"
        ))
    })?;
    d2i_windows_host::grant_appcontainer_path_access(
        &policy.verifier_profile_name,
        &root,
        d2i_windows_host::WindowsAppContainerPathAccess::ReadWrite,
        true,
    )
    .map_err(|error| {
        DesktopError::Integrity(format!("WFP broker client directory ACL failed: {error}"))
    })?;
    let input_path = root.join("request.json");
    let request_handoff_path = root.join("relay-request.json");
    let response_handoff_path = root.join("relay-response.json");
    let output_path = root.join("receipt.json");
    let input = AppContainerBrokerClientInput {
        schema_version: 1,
        request: request_template.clone(),
        broker: broker.clone(),
        functional_attestation: functional_attestation.clone(),
        request_handoff_path: request_handoff_path.display().to_string(),
        response_handoff_path: response_handoff_path.display().to_string(),
        output_path: output_path.display().to_string(),
        timeout_ms: runtime.request_timeout_ms.min(30_000),
    };
    write_new(&input_path, &json_bytes(&input)?)?;
    let worker = Path::new(&runtime.worker_executable);
    let arguments = vec![
        "__windows-wfp-broker-client".to_owned(),
        input_path.display().to_string(),
    ];
    let child = d2i_windows_host::spawn_zero_capability_appcontainer(
        &policy.verifier_profile_name,
        &policy.verifier_profile_sid,
        worker,
        &arguments,
        &root,
    )
    .map_err(|error| {
        DesktopError::AdapterUnavailable(format!("WFP broker client launch failed: {error}"))
    })?;
    d2i_windows_host::grant_current_process_query_to_verifier(&broker.service_sid).map_err(
        |error| {
            DesktopError::AccessDenied(format!("WFP relay process query grant failed: {error}"))
        },
    )?;
    d2i_windows_host::grant_appcontainer_child_query_to_verifier(&child, &broker.service_sid)
        .map_err(|error| {
            DesktopError::AccessDenied(format!(
                "WFP AppContainer process query grant failed: {error}"
            ))
        })?;
    let request_bytes = wait_for_bounded_file(
        &request_handoff_path,
        MAX_BROKER_ARTIFACT_BYTES,
        Duration::from_millis(runtime.request_timeout_ms.min(30_000)),
        "AppContainer relay request",
    )?;
    let request: WfpVerificationRequest = serde_json::from_slice(&request_bytes)
        .map_err(|error| DesktopError::Invalid(format!("malformed relay request: {error}")))?;
    let mut expected_request = request_template;
    expected_request.appcontainer_process_id = child.id();
    expected_request.validate(now_unix_seconds()?)?;
    if request != expected_request {
        return Err(DesktopError::Integrity(
            "AppContainer relay request differs from its parent-pinned template".to_owned(),
        ));
    }
    d2i_windows_host::start_verifier_service(&broker.service_name).map_err(|error| {
        DesktopError::AdapterUnavailable(format!("WFP verifier service start failed: {error}"))
    })?;
    let stream = d2i_windows_host::connect_verifier_pipe(
        &broker.pipe_name,
        Duration::from_millis(runtime.request_timeout_ms.min(30_000)),
    )
    .map_err(|error| {
        DesktopError::AdapterUnavailable(format!("WFP broker relay connection failed: {error}"))
    })?;
    let pipe_timeout = Duration::from_millis(runtime.request_timeout_ms.min(30_000));
    d2i_windows_host::write_verifier_pipe_message(
        &stream,
        &json_bytes(&request)?,
        MAX_BROKER_MESSAGE_BYTES,
        pipe_timeout,
    )
    .map_err(|error| {
        DesktopError::AdapterUnavailable(format!("WFP broker relay write failed: {error}"))
    })?;
    let response = d2i_windows_host::read_verifier_pipe_message(
        &stream,
        MAX_BROKER_MESSAGE_BYTES,
        pipe_timeout,
    )
    .map_err(|error| {
        DesktopError::AdapterUnavailable(format!("WFP broker relay read failed: {error}"))
    })?;
    let response: BrokerWireResponse = serde_json::from_slice(&response)
        .map_err(|error| DesktopError::Invalid(format!("malformed broker response: {error}")))?;
    let broker_receipt = response.into_receipt()?;
    write_new(&response_handoff_path, &json_bytes(&broker_receipt)?)?;
    let timeout = Duration::from_millis(runtime.request_timeout_ms.min(30_000))
        .saturating_add(Duration::from_secs(2));
    let exit_code = match child.wait_timeout(timeout).map_err(|error| {
        DesktopError::AdapterUnavailable(format!("WFP broker client wait failed: {error}"))
    })? {
        Some(code) => code,
        None => {
            let _ = child.terminate();
            return Err(DesktopError::AdapterUnavailable(
                "WFP broker client exceeded its deadline".to_owned(),
            ));
        }
    };
    if exit_code != 0 {
        let diagnostic = input_path.with_extension("error.txt");
        let diagnostic = if diagnostic.exists() {
            String::from_utf8_lossy(&read_bounded(&diagnostic, MAX_BROKER_DIAGNOSTIC_BYTES)?)
                .into_owned()
        } else {
            "no bounded broker-client diagnostic was produced".to_owned()
        };
        return Err(DesktopError::AdapterUnavailable(format!(
            "WFP broker client exited with code {exit_code}: {diagnostic}"
        )));
    }
    let receipt: SignedWfpVerificationReceipt =
        serde_json::from_slice(&read_bounded(&output_path, MAX_BROKER_ARTIFACT_BYTES)?)
            .map_err(|error| DesktopError::Json(error.to_string()))?;
    if receipt != broker_receipt {
        return Err(DesktopError::Integrity(
            "AppContainer-emitted receipt differs from the broker response".to_owned(),
        ));
    }
    let _ = replay.validate_and_consume(
        &receipt,
        &request,
        broker,
        functional_attestation,
        now_unix_seconds()?,
    )?;
    drop(child);
    cleanup.remove()?;
    record_broker_success_audit(runtime, &request, &receipt)?;
    let observation = receipt_observation(policy, &receipt)?;
    Ok((observation, receipt))
}

pub(crate) fn record_binding_evidence_audit(
    runtime: &WindowsAdapterConfiguration,
    evidence_hash: Option<&str>,
    failure: Option<&DesktopError>,
    now_unix_seconds: u64,
) -> Result<(), DesktopError> {
    let root = required_audit_root(runtime)?;
    let (kind, status, artifact_hashes, detail_hash, suffix) =
        if let Some(evidence_hash) = evidence_hash {
            (
                WindowsDeploymentAuditEventKind::BindingEvidenceCreated,
                WindowsDeploymentAuditStatus::Succeeded,
                BTreeMap::from([("binding_evidence".to_owned(), evidence_hash.to_owned())]),
                hash_value(&("binding_evidence_created", evidence_hash))?,
                "created",
            )
        } else {
            let failure = failure.ok_or_else(|| {
                DesktopError::Invalid("binding audit failure has no error".to_owned())
            })?;
            (
                WindowsDeploymentAuditEventKind::BindingEvidenceRejected,
                WindowsDeploymentAuditStatus::Failed,
                BTreeMap::new(),
                hash_value(&("binding_evidence_rejected", failure.to_string()))?,
                "rejected",
            )
        };
    let mut ledger = WindowsDeploymentAuditLedger::open(root)?;
    let event = WindowsDeploymentAuditEvent {
        schema_version: 1,
        event_id: format!("wfp-binding-{suffix}-{now_unix_seconds}"),
        kind,
        status,
        artifact_hashes,
        detail_hash,
        recorded_at_unix_ms: now_unix_seconds.saturating_mul(1_000),
    };
    let _ = ledger.append(event)?;
    let _ = crate::verify_windows_deployment_audit(root)?;
    Ok(())
}

pub(crate) fn record_broker_failure_audit(
    runtime: &WindowsAdapterConfiguration,
    failure: &DesktopError,
    now_unix_seconds: u64,
) -> Result<(), DesktopError> {
    let root = required_audit_root(runtime)?;
    let mut artifact_hashes = BTreeMap::new();
    if let Some(policy) = &runtime.browser_egress_policy {
        artifact_hashes.insert("policy".to_owned(), policy.policy_hash()?);
    }
    let mut ledger = WindowsDeploymentAuditLedger::open(root)?;
    let event = WindowsDeploymentAuditEvent {
        schema_version: 1,
        event_id: format!("wfp-broker-rejected-{now_unix_seconds}"),
        kind: WindowsDeploymentAuditEventKind::VerifierRequestRejected,
        status: WindowsDeploymentAuditStatus::Failed,
        artifact_hashes,
        detail_hash: hash_value(&("wfp_broker_rejected", failure.to_string()))?,
        recorded_at_unix_ms: now_unix_seconds.saturating_mul(1_000),
    };
    let _ = ledger.append(event)?;
    let _ = crate::verify_windows_deployment_audit(root)?;
    Ok(())
}

fn record_broker_success_audit(
    runtime: &WindowsAdapterConfiguration,
    request: &WfpVerificationRequest,
    receipt: &SignedWfpVerificationReceipt,
) -> Result<(), DesktopError> {
    let root = required_audit_root(runtime)?;
    let request_hash = hash_value(request)?;
    let receipt_hash = receipt.receipt_hash()?;
    let policy_hash = receipt.verified_policy_canonical_digest.clone();
    let events = [
        (
            WindowsDeploymentAuditEventKind::VerifierBrokerStarted,
            "broker-started",
            &receipt.verifier_executable_hash,
        ),
        (
            WindowsDeploymentAuditEventKind::VerifierCallerVerified,
            "caller-verified",
            &receipt.runtime_binding_digest,
        ),
        (
            WindowsDeploymentAuditEventKind::VerifierRequestAccepted,
            "request-accepted",
            &request_hash,
        ),
        (
            WindowsDeploymentAuditEventKind::VerifierChallengeConsumed,
            "challenge-consumed",
            &request_hash,
        ),
        (
            WindowsDeploymentAuditEventKind::VerifierEngineOpened,
            "engine-opened",
            &policy_hash,
        ),
        (
            WindowsDeploymentAuditEventKind::VerifierObjectExactlyVerified,
            "objects-verified",
            &policy_hash,
        ),
        (
            WindowsDeploymentAuditEventKind::VerifierAclVerified,
            "acl-verified",
            &policy_hash,
        ),
        (
            WindowsDeploymentAuditEventKind::VerifierPolicyDigestCreated,
            "policy-digest",
            &policy_hash,
        ),
        (
            WindowsDeploymentAuditEventKind::VerifierReceiptCreated,
            "receipt-created",
            &receipt_hash,
        ),
        (
            WindowsDeploymentAuditEventKind::VerifierReceiptSigned,
            "receipt-signed",
            &receipt_hash,
        ),
        (
            WindowsDeploymentAuditEventKind::VerifierReceiptValidated,
            "receipt-validated",
            &receipt_hash,
        ),
        (
            WindowsDeploymentAuditEventKind::VerifierBrokerStopped,
            "broker-stopped",
            &receipt_hash,
        ),
    ];
    let mut ledger = WindowsDeploymentAuditLedger::open(root)?;
    for (index, (kind, suffix, artifact_hash)) in events.into_iter().enumerate() {
        let artifact_name = match kind {
            WindowsDeploymentAuditEventKind::VerifierRequestAccepted
            | WindowsDeploymentAuditEventKind::VerifierChallengeConsumed => "request",
            WindowsDeploymentAuditEventKind::VerifierReceiptCreated
            | WindowsDeploymentAuditEventKind::VerifierReceiptSigned
            | WindowsDeploymentAuditEventKind::VerifierReceiptValidated
            | WindowsDeploymentAuditEventKind::VerifierBrokerStopped => "receipt",
            WindowsDeploymentAuditEventKind::VerifierBrokerStarted => "verifier",
            WindowsDeploymentAuditEventKind::VerifierCallerVerified => "runtime_binding",
            _ => "policy",
        };
        let event = WindowsDeploymentAuditEvent {
            schema_version: 1,
            event_id: format!("{}-{suffix}", request.request_id),
            kind,
            status: WindowsDeploymentAuditStatus::Succeeded,
            artifact_hashes: BTreeMap::from([(artifact_name.to_owned(), artifact_hash.to_owned())]),
            detail_hash: hash_value(&(
                request.request_id.as_str(),
                suffix,
                artifact_hash.as_str(),
            ))?,
            recorded_at_unix_ms: receipt
                .verification_completed_at_unix_ms
                .saturating_add(index as u64),
        };
        let _ = ledger.append(event)?;
    }
    let _ = crate::verify_windows_deployment_audit(root)?;
    Ok(())
}

fn required_audit_root(runtime: &WindowsAdapterConfiguration) -> Result<&Path, DesktopError> {
    runtime
        .deployment_audit_root
        .as_deref()
        .map(Path::new)
        .ok_or_else(|| {
            DesktopError::AccessDenied(
                "broker-backed WFP verification requires a protected audit sink".to_owned(),
            )
        })
}

fn new_request_template(
    runtime: &WindowsAdapterConfiguration,
    policy: &WindowsWfpBrowserEgressPolicy,
    host: &WindowsHostBinding,
    functional_attestation: &SignedWindowsWfpFunctionalAttestationV2,
    attestation_hash: &str,
    relay_process_id: u32,
    now_unix_seconds: u64,
) -> Result<WfpVerificationRequest, DesktopError> {
    if relay_process_id == 0 {
        return Err(DesktopError::Invalid(
            "WFP verifier relay process ID is zero".to_owned(),
        ));
    }
    let deadline = now_unix_seconds
        .checked_add(
            runtime
                .request_timeout_ms
                .div_ceil(1_000)
                .clamp(1, MAX_BROKER_REQUEST_SECONDS),
        )
        .ok_or_else(|| DesktopError::Invalid("WFP request deadline overflow".to_owned()))?;
    let request = WfpVerificationRequest {
        schema_version: 1,
        operation: WfpVerifierOperation::VerifyD2iBrowserEgressV1,
        request_id: format!("wfp-{}", random_hex::<16>()?),
        one_time_challenge: random_hex::<32>()?,
        relay_process_id,
        appcontainer_process_id: 0,
        expected_runtime_binding_digest: runtime.configuration_hash()?,
        expected_machine_session_binding: host.clone(),
        expected_wfp_policy_digest: policy.policy_hash()?,
        expected_object_guids: WfpExpectedObjectGuids::d2i_browser_egress(),
        expected_edge_hash: policy.browser_executable_hash.clone(),
        expected_edge_driver_hash: functional_attestation.driver_executable_hash.clone(),
        expected_functional_report_hash: functional_attestation.self_test_report_hash.clone(),
        expected_attestation_hash: attestation_hash.to_owned(),
        issued_at_unix_seconds: now_unix_seconds,
        deadline_unix_seconds: deadline,
    };
    let mut validation_copy = request.clone();
    validation_copy.appcontainer_process_id = relay_process_id
        .checked_add(1)
        .filter(|process_id| *process_id != 0)
        .unwrap_or(1);
    validation_copy.validate(now_unix_seconds)?;
    Ok(request)
}

fn validate_client_handoff_paths(
    input_path: &Path,
    input: &AppContainerBrokerClientInput,
) -> Result<(), DesktopError> {
    let root = input_path
        .parent()
        .ok_or_else(|| DesktopError::Invalid("WFP broker client input has no parent".to_owned()))?;
    for (path, expected_name) in [
        (&input.request_handoff_path, "relay-request.json"),
        (&input.response_handoff_path, "relay-response.json"),
        (&input.output_path, "receipt.json"),
    ] {
        let path = Path::new(path);
        if !path.is_absolute()
            || path.parent() != Some(root)
            || path.file_name().and_then(|name| name.to_str()) != Some(expected_name)
        {
            return Err(DesktopError::AccessDenied(
                "WFP broker handoff path escaped its one-time client root".to_owned(),
            ));
        }
    }
    Ok(())
}

fn wait_for_bounded_file(
    path: &Path,
    maximum: u64,
    timeout: Duration,
    field: &str,
) -> Result<Vec<u8>, DesktopError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| DesktopError::Invalid(format!("{field} deadline overflow")))?;
    loop {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || metadata.len() == 0
                    || metadata.len() > maximum
                    || d2i_windows_host::is_reparse_point(path).map_err(|error| {
                        DesktopError::Integrity(format!(
                            "{field} reparse-point inspection failed: {error}"
                        ))
                    })?
                {
                    return Err(DesktopError::Integrity(format!(
                        "{field} is not a bounded regular file"
                    )));
                }
                return read_bounded(path, maximum);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if Instant::now() >= deadline {
                    return Err(DesktopError::AdapterUnavailable(format!(
                        "{field} exceeded its deadline"
                    )));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                return Err(DesktopError::Io {
                    path: path.display().to_string(),
                    message: error.to_string(),
                });
            }
        }
    }
}

fn receipt_observation(
    policy: &WindowsWfpBrowserEgressPolicy,
    receipt: &SignedWfpVerificationReceipt,
) -> Result<WindowsWfpBrowserEgressObservation, DesktopError> {
    Ok(WindowsWfpBrowserEgressObservation {
        schema_version: 3,
        enforcement_id: policy.enforcement_id.clone(),
        provider_id: policy.provider_id.clone(),
        policy_hash: receipt.verified_policy_canonical_digest.clone(),
        browser_executable: policy.browser_executable.clone(),
        browser_executable_hash: receipt.edge_hash.clone(),
        provider_key: receipt.object_guids.provider.clone(),
        sublayer_key: receipt.object_guids.sublayer.clone(),
        filter_keys: receipt.object_guids.filters.clone(),
        verifier_sid: receipt.verifier_identity.clone(),
        policy_owner_sid: policy.policy_owner_sid.clone(),
        engine_security_descriptor_hash: hash_value(&(
            "engine_acl_verified",
            receipt.object_acl_verification_passed,
        ))?,
        object_security_descriptor_hash: hash_value(&receipt.object_results)?,
    })
}

fn load_service_configuration(
    path: &Path,
) -> Result<WindowsWfpVerifierBrokerServiceConfiguration, DesktopError> {
    let configuration: WindowsWfpVerifierBrokerServiceConfiguration =
        serde_json::from_slice(&read_bounded(path, MAX_BROKER_ARTIFACT_BYTES)?)
            .map_err(|error| DesktopError::Json(error.to_string()))?;
    configuration.validate()?;
    Ok(configuration)
}

#[cfg(test)]
fn read_sync_message(stream: &mut impl Read) -> Result<Vec<u8>, DesktopError> {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length).map_err(|error| {
        DesktopError::AdapterUnavailable(format!("broker response was truncated: {error}"))
    })?;
    let length = u32::from_le_bytes(length);
    if length == 0 || length > MAX_BROKER_MESSAGE_BYTES {
        return Err(DesktopError::Invalid(
            "WFP broker response length is outside its bound".to_owned(),
        ));
    }
    let mut response = vec![0_u8; length as usize];
    stream.read_exact(&mut response).map_err(|error| {
        DesktopError::AdapterUnavailable(format!("broker response was truncated: {error}"))
    })?;
    Ok(response)
}

fn canonical_regular_file(path: &Path, maximum: u64) -> Result<PathBuf, DesktopError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > maximum
        || d2i_windows_host::is_reparse_point(path).map_err(|error| {
            DesktopError::Integrity(format!("broker path reparse check failed: {error}"))
        })?
    {
        return Err(DesktopError::Integrity(
            "broker artifact must be a bounded regular non-reparse file".to_owned(),
        ));
    }
    std::fs::canonicalize(path).map_err(|error| DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })
}

fn common_parent(first: &Path, second: &Path) -> Result<PathBuf, DesktopError> {
    if !first.is_absolute() || !second.is_absolute() || first.parent() != second.parent() {
        return Err(DesktopError::Invalid(
            "WFP broker configuration and key must share one absolute deployment root".to_owned(),
        ));
    }
    first
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| DesktopError::Invalid("WFP broker deployment root is missing".to_owned()))
}

fn require_exact_cleanup_files(root: &Path, expected: &[&PathBuf]) -> Result<(), DesktopError> {
    let mut observed = Vec::new();
    for entry in std::fs::read_dir(root).map_err(|error| DesktopError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })? {
        if observed.len() >= 8 {
            return Err(DesktopError::AccessDenied(
                "broker cleanup root contains too many entries".to_owned(),
            ));
        }
        let entry = entry.map_err(|error| DesktopError::Io {
            path: root.display().to_string(),
            message: error.to_string(),
        })?;
        let metadata =
            std::fs::symlink_metadata(entry.path()).map_err(|error| DesktopError::Io {
                path: entry.path().display().to_string(),
                message: error.to_string(),
            })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(DesktopError::AccessDenied(
                "broker cleanup root contains an unexpected entry".to_owned(),
            ));
        }
        observed.push(
            std::fs::canonicalize(entry.path()).map_err(|error| DesktopError::Io {
                path: root.display().to_string(),
                message: error.to_string(),
            })?,
        );
    }
    observed.sort();
    let mut expected = expected
        .iter()
        .map(|path| (**path).clone())
        .collect::<Vec<_>>();
    expected.sort();
    if observed != expected {
        return Err(DesktopError::AccessDenied(
            "broker cleanup root differs from its exact artifact allowlist".to_owned(),
        ));
    }
    Ok(())
}

fn random_hex<const N: usize>() -> Result<String, DesktopError> {
    let bytes = d2i_windows_host::secure_random_bytes::<N>().map_err(|error| {
        DesktopError::AdapterUnavailable(format!("WFP broker random challenge failed: {error}"))
    })?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn now_unix_seconds() -> Result<u64, DesktopError> {
    Ok(now_unix_milliseconds()? / 1_000)
}

fn now_unix_milliseconds() -> Result<u64, DesktopError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            DesktopError::AdapterUnavailable(format!("system clock failed: {error}"))
        })?;
    u64::try_from(duration.as_millis())
        .map_err(|_| DesktopError::AdapterUnavailable("system clock overflow".to_owned()))
}

struct BrokerClientDirectory(PathBuf);

impl BrokerClientDirectory {
    fn remove(mut self) -> Result<(), DesktopError> {
        let path = std::mem::take(&mut self.0);
        std::fs::remove_dir_all(&path).map_err(|error| DesktopError::Io {
            path: path.display().to_string(),
            message: format!("WFP broker client cleanup failed: {error}"),
        })
    }
}

impl Drop for BrokerClientDirectory {
    fn drop(&mut self) {
        if !self.0.as_os_str().is_empty() {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WindowsAdapterKind;
    use std::collections::BTreeSet;
    use std::io::Cursor;

    fn host() -> WindowsHostBinding {
        WindowsHostBinding {
            major_version: 10,
            minor_version: 0,
            build_number: 26_200,
            architecture: "x86_64".to_owned(),
            session_id: 1,
            user_sid: "S-1-5-21-1-2-3-1001".to_owned(),
            integrity_level_rid: 8_192,
            elevation_type: "limited".to_owned(),
            is_appcontainer: false,
        }
    }

    fn caller(
        is_appcontainer: bool,
        appcontainer_sid: Option<&str>,
        integrity_level_rid: u32,
        elevation_type: &str,
    ) -> d2i_windows_host::WindowsVerifierPipeCaller {
        d2i_windows_host::WindowsVerifierPipeCaller {
            process_id: 42,
            user_sid: host().user_sid,
            session_id: host().session_id,
            integrity_level_rid,
            elevation_type: elevation_type.to_owned(),
            is_appcontainer,
            appcontainer_sid: appcontainer_sid.map(str::to_owned),
            executable: PathBuf::from(r"C:\D2I\d2i-desktop.exe"),
        }
    }

    #[test]
    fn pipe_identity_rejects_medium_admin_spoof_and_unapproved_appcontainer() {
        let approved = "S-1-15-2-1-2-3-4";
        assert!(validate_relay_identity(&caller(false, None, 8_192, "limited"), &host()).is_ok());
        assert!(validate_relay_identity(&caller(false, None, 12_288, "full"), &host()).is_err());
        assert!(
            validate_relay_identity(&caller(true, Some(approved), 4_096, "default"), &host())
                .is_err()
        );
        assert!(validate_relay_identity(
            &caller(true, Some("S-1-15-2-9-9-9-9"), 4_096, "default"),
            &host()
        )
        .is_err());
    }

    #[test]
    fn length_prefixed_response_truncation_is_rejected() {
        let mut missing_payload = Cursor::new([8_u8, 0, 0, 0, b'{', b'}']);
        assert!(read_sync_message(&mut missing_payload).is_err());
        let mut oversized = Cursor::new((MAX_BROKER_MESSAGE_BYTES + 1).to_le_bytes());
        assert!(read_sync_message(&mut oversized).is_err());
    }

    #[test]
    fn broker_wire_response_rejects_inconsistent_and_unknown_payloads() {
        let rejected = BrokerWireResponse::rejected("request_not_authorized");
        assert!(matches!(
            rejected.into_receipt(),
            Err(DesktopError::AccessDenied(_))
        ));
        let inconsistent = BrokerWireResponse {
            schema_version: 1,
            status: BrokerWireStatus::Verified,
            failure_code: "none".to_owned(),
            receipt: None,
        };
        assert!(matches!(
            inconsistent.into_receipt(),
            Err(DesktopError::Integrity(_))
        ));
        let unknown = br#"{"schema_version":1,"status":"rejected","failure_code":"test","receipt":null,"extra":true}"#;
        assert!(serde_json::from_slice::<BrokerWireResponse>(unknown).is_err());
    }

    #[test]
    fn unavailable_audit_sink_prevents_failure_recording() {
        let root =
            std::env::temp_dir().join(format!("d2i-missing-wfp-audit-{}", std::process::id()));
        let configuration = WindowsAdapterConfiguration {
            schema_version: 1,
            adapter_kind: WindowsAdapterKind::WebDriver,
            worker_executable: r"C:\D2I\d2i-desktop.exe".to_owned(),
            worker_executable_hash: format!("sha256:{}", "11".repeat(32)),
            request_timeout_ms: 1_000,
            active_process_limit: 1,
            per_process_memory_bytes: 64 * 1024 * 1024,
            write_roots: Vec::new(),
            webdriver_endpoint: Some("http://127.0.0.1:9515".to_owned()),
            browser_session_ids: BTreeSet::from(["session-1".to_owned()]),
            browser_allowed_origins: BTreeSet::from(["http://127.0.0.1:8080".to_owned()]),
            browser_egress_policy: None,
            deployment_audit_root: Some(root.display().to_string()),
            ui_allowed_executable_hashes: BTreeSet::new(),
            process_isolation: None,
        };
        let failure = DesktopError::AccessDenied("negative test".to_owned());
        assert!(record_broker_failure_audit(&configuration, &failure, 1).is_err());
    }
}
