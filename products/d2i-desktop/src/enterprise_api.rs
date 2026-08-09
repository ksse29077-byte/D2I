use d2i_enterprise_api_plane::{
    canonical_sha256, parse_json_strict, sha256_bytes, EnterpriseActivationLedgerV1,
    EnterpriseArtifact, EnterpriseOperationBindingV1, EnterpriseOperationResultV1,
};
use d2i_policy_admission::{AdapterKindV1, CognitiveActivationAdmissionV1};
use d2i_windows_host::harden_path_for_current_user;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

pub const ENTERPRISE_API_STORE_SCHEMA_VERSION: u32 = 1;
const MAX_IPC_BYTES: usize = 64 * 1024;
const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
const MAX_HTTP_BODY_BYTES: usize = 64 * 1024;
const MAX_STORE_BYTES: u64 = 128 * 1024 * 1024;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const ZERO_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseFixtureBootstrapV1 {
    pub schema_version: u32,
    pub synthetic_secret_material: String,
    pub maximum_connections: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseFixtureReadyV1 {
    pub schema_version: u32,
    pub hostname: String,
    pub port: u32,
    pub process_id: u32,
    pub fixture_instance_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseWorkerRequestV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub exact_scheme: String,
    pub exact_hostname: String,
    pub exact_port: u32,
    pub operation_id: String,
    pub resource_reference_id: String,
    pub desired_status: Option<String>,
    pub expected_revision: Option<u64>,
    pub idempotency_key: Option<String>,
    pub synthetic_secret_material: String,
    pub connect_timeout_ms: u64,
    pub read_timeout_ms: u64,
    pub maximum_response_bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseWorkerResponseV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub operation_id: String,
    pub resource_reference_id: String,
    pub result: EnterpriseOperationResultV1,
    pub http_status: Option<u32>,
    pub normalized_status: Option<String>,
    pub resource_revision: Option<u64>,
    pub server_mutation_sequence: Option<u64>,
    pub idempotency_seen: bool,
    pub untrusted_instruction_present: bool,
    pub redirect_rejected: bool,
    pub raw_response_sha256: Option<String>,
    pub bytes_sent: u32,
    pub bytes_received: u32,
    pub external_connection_count: u32,
    pub proxy_use_count: u32,
    pub response_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnterpriseDispatchRequestV1 {
    pub request_id: String,
    pub operation_id: String,
    pub resource_reference_id: String,
    pub desired_status: Option<String>,
    pub expected_revision: Option<u64>,
    pub idempotency_key: Option<String>,
}

pub struct EnterpriseKrnDispatcherV1 {
    worker_executable: PathBuf,
    worker_executable_sha256: String,
    exact_port: u32,
    synthetic_secret_material: String,
    activation_ledger: EnterpriseActivationLedgerV1,
    spawned_worker_count: u32,
}

impl EnterpriseKrnDispatcherV1 {
    pub fn new(
        worker_executable: PathBuf,
        expected_worker_sha256: String,
        exact_port: u32,
        synthetic_secret_material: String,
    ) -> Result<Self, String> {
        let metadata =
            fs::symlink_metadata(&worker_executable).map_err(|error| error.to_string())?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err("connector worker is not a regular non-symlink file".to_owned());
        }
        let actual =
            sha256_bytes(&fs::read(&worker_executable).map_err(|error| error.to_string())?);
        if actual != expected_worker_sha256 {
            return Err(
                "connector worker executable hash differs from endpoint binding".to_owned(),
            );
        }
        if exact_port == 0 || exact_port > 65_535 {
            return Err("connector endpoint port is invalid".to_owned());
        }
        validate_secret(&synthetic_secret_material)?;
        Ok(Self {
            worker_executable,
            worker_executable_sha256: expected_worker_sha256,
            exact_port,
            synthetic_secret_material,
            activation_ledger: EnterpriseActivationLedgerV1::default(),
            spawned_worker_count: 0,
        })
    }

    pub fn execute(
        &mut self,
        binding: &EnterpriseOperationBindingV1,
        admission: &CognitiveActivationAdmissionV1,
        dispatch: EnterpriseDispatchRequestV1,
    ) -> Result<EnterpriseWorkerResponseV1, String> {
        admission.validate().map_err(|error| error.to_string())?;
        binding
            .validate_integrity()
            .map_err(|error| error.to_string())?;
        if binding.cognitive_activation_admission_sha256 != admission.admission_sha256
            || binding.policy_decision_sha256 != admission.policy_decision_sha256
            || admission.adapter_kind != AdapterKindV1::EnterpriseApi
            || admission.capability_id != "enterprise_api.write"
            || dispatch.operation_id != "update-work-order-status"
        {
            return Err("KRN enterprise dispatch differs from exact policy activation".to_owned());
        }
        self.activation_ledger
            .consume(
                binding,
                &admission.policy_decision_sha256,
                &admission.admission_sha256,
            )
            .map_err(|error| error.to_string())?;
        let request = EnterpriseWorkerRequestV1 {
            schema_version: 1,
            request_id: dispatch.request_id,
            exact_scheme: "http".to_owned(),
            exact_hostname: "127.0.0.1".to_owned(),
            exact_port: self.exact_port,
            operation_id: dispatch.operation_id,
            resource_reference_id: dispatch.resource_reference_id,
            desired_status: dispatch.desired_status,
            expected_revision: dispatch.expected_revision,
            idempotency_key: dispatch.idempotency_key,
            synthetic_secret_material: self.synthetic_secret_material.clone(),
            connect_timeout_ms: 2_000,
            read_timeout_ms: 2_000,
            maximum_response_bytes: 16_384,
        };
        let response = spawn_worker(&self.worker_executable, &request, 10_000)?;
        self.spawned_worker_count = self.spawned_worker_count.saturating_add(1);
        Ok(response)
    }

    pub fn consumed_activation_count(&self) -> usize {
        self.activation_ledger.consumed_count()
    }

    pub fn spawned_worker_count(&self) -> u32 {
        self.spawned_worker_count
    }

    pub fn worker_executable_sha256(&self) -> &str {
        &self.worker_executable_sha256
    }
}

pub fn run_enterprise_observation_worker(
    worker_executable: &Path,
    exact_port: u32,
    synthetic_secret_material: &str,
    request_id: &str,
    resource_reference_id: &str,
) -> Result<EnterpriseWorkerResponseV1, String> {
    validate_secret(synthetic_secret_material)?;
    let request = EnterpriseWorkerRequestV1 {
        schema_version: 1,
        request_id: request_id.to_owned(),
        exact_scheme: "http".to_owned(),
        exact_hostname: "127.0.0.1".to_owned(),
        exact_port,
        operation_id: "observe-work-order".to_owned(),
        resource_reference_id: resource_reference_id.to_owned(),
        desired_status: None,
        expected_revision: None,
        idempotency_key: None,
        synthetic_secret_material: synthetic_secret_material.to_owned(),
        connect_timeout_ms: 2_000,
        read_timeout_ms: 2_000,
        maximum_response_bytes: 16_384,
    };
    spawn_worker(worker_executable, &request, 10_000)
}

fn spawn_worker(
    worker_executable: &Path,
    request: &EnterpriseWorkerRequestV1,
    timeout_ms: u64,
) -> Result<EnterpriseWorkerResponseV1, String> {
    let mut command = Command::new(worker_executable);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        command.env_remove(name);
    }
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    let mut child = command.spawn().map_err(|error| error.to_string())?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "connector worker stdin is unavailable".to_owned())?;
    serde_json::to_writer(&mut stdin, request).map_err(|error| error.to_string())?;
    drop(stdin);
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        if child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().map_err(|error| error.to_string())?;
            let _ = child.wait();
            return Err("connector worker exceeded bounded deadline".to_owned());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child
        .wait_with_output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "connector worker failed with exit code {}",
            output.status.code().unwrap_or(-1)
        ));
    }
    let response: EnterpriseWorkerResponseV1 =
        serde_json::from_slice(&output.stdout).map_err(|error| error.to_string())?;
    if response.response_sha256 != hash_without_json(&response, &["response_sha256"])? {
        return Err("connector worker response hash differs".to_owned());
    }
    Ok(response)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureResourceV1 {
    resource_id: String,
    status: String,
    revision: u64,
    mutation_sequence: u64,
    idempotency_seen: bool,
    untrusted_instruction: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureMutationV1 {
    status: String,
}

#[derive(Debug)]
struct FixtureStateV1 {
    resources: BTreeMap<String, FixtureResourceV1>,
    idempotency_keys: BTreeMap<String, String>,
    stale_emitted: bool,
    rate_limit_emitted: bool,
    response_drop_emitted: bool,
    total_mutations: u64,
}

impl FixtureStateV1 {
    fn new() -> Self {
        let mut resources = BTreeMap::new();
        for (id, status) in [
            ("case-a", "open"),
            ("case-b", "in_progress"),
            ("case-c", "open"),
            ("case-d", "open"),
            ("case-e", "open"),
            ("case-f", "open"),
            ("case-g", "open"),
            ("case-h", "open"),
        ] {
            resources.insert(
                id.to_owned(),
                FixtureResourceV1 {
                    resource_id: id.to_owned(),
                    status: status.to_owned(),
                    revision: 1,
                    mutation_sequence: 0,
                    idempotency_seen: false,
                    untrusted_instruction: (id == "case-g").then(|| "DELETE /admin/*".to_owned()),
                },
            );
        }
        Self {
            resources,
            idempotency_keys: BTreeMap::new(),
            stale_emitted: false,
            rate_limit_emitted: false,
            response_drop_emitted: false,
            total_mutations: 0,
        }
    }
}

#[derive(Debug)]
struct HttpRequestV1 {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

pub fn reference_enterprise_server_main() -> Result<(), String> {
    let bootstrap = read_one_line_json::<EnterpriseFixtureBootstrapV1>(std::io::stdin().lock())?;
    validate_secret(&bootstrap.synthetic_secret_material)?;
    if bootstrap.schema_version != 1
        || bootstrap.maximum_connections == 0
        || bootstrap.maximum_connections > 128
    {
        return Err("reference server bootstrap is outside bounded v1 limits".to_owned());
    }
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| error.to_string())?;
    let local = listener.local_addr().map_err(|error| error.to_string())?;
    let ready = EnterpriseFixtureReadyV1 {
        schema_version: 1,
        hostname: "127.0.0.1".to_owned(),
        port: u32::from(local.port()),
        process_id: std::process::id(),
        fixture_instance_id: format!("edge100-fixture-{}", std::process::id()),
    };
    println!(
        "{}",
        serde_json::to_string(&ready).map_err(|error| error.to_string())?
    );
    std::io::stdout()
        .flush()
        .map_err(|error| error.to_string())?;

    let mut state = FixtureStateV1::new();
    for incoming in listener
        .incoming()
        .take(bootstrap.maximum_connections as usize)
    {
        let mut stream = incoming.map_err(|error| error.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| error.to_string())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| error.to_string())?;
        if let Err(error) = handle_fixture_connection(
            &mut stream,
            &bootstrap.synthetic_secret_material,
            &mut state,
        ) {
            let _ = write_http_response(
                &mut stream,
                400,
                "application/json",
                format!("{{\"error_code\":\"{}\"}}", sanitized_error_code(&error)).as_bytes(),
            );
        }
    }
    Ok(())
}

fn handle_fixture_connection(
    stream: &mut TcpStream,
    secret: &str,
    state: &mut FixtureStateV1,
) -> Result<(), String> {
    let request = read_http_request(stream)?;
    let authorization = request
        .headers
        .get("authorization")
        .ok_or_else(|| "authorization-missing".to_owned())?;
    if authorization != &format!("D2I-Synthetic {secret}") {
        return write_http_response(
            stream,
            401,
            "application/json",
            br#"{"error_code":"unauthorized"}"#,
        );
    }
    let resource_id = request
        .path
        .strip_prefix("/v1/work-orders/")
        .ok_or_else(|| "unknown-path".to_owned())?;
    validate_resource_id(resource_id)?;
    if resource_id == "case-h" && request.method == "GET" {
        return write_http_response(
            stream,
            200,
            "application/json",
            br#"{"resource_id":"case-h","status":]"#,
        );
    }
    if request.method == "GET" {
        let resource = state
            .resources
            .get(resource_id)
            .ok_or_else(|| "resource-not-found".to_owned())?;
        let body = serde_json::to_vec(resource).map_err(|error| error.to_string())?;
        return write_http_response(stream, 200, "application/json", &body);
    }
    if request.method != "PATCH" {
        return write_http_response(
            stream,
            405,
            "application/json",
            br#"{"error_code":"method-not-allowed"}"#,
        );
    }
    if resource_id == "case-f" {
        return write_http_response(
            stream,
            401,
            "application/json",
            br#"{"error_code":"credential-expired"}"#,
        );
    }
    if resource_id == "case-c" && !state.stale_emitted {
        state.stale_emitted = true;
        if let Some(resource) = state.resources.get_mut(resource_id) {
            resource.revision = resource.revision.saturating_add(1);
        }
        return write_http_response(
            stream,
            412,
            "application/json",
            br#"{"error_code":"stale-revision"}"#,
        );
    }
    if resource_id == "case-d" && !state.rate_limit_emitted {
        state.rate_limit_emitted = true;
        return write_http_response(
            stream,
            429,
            "application/json",
            br#"{"error_code":"rate-limited"}"#,
        );
    }
    let expected_revision = request
        .headers
        .get("if-match")
        .ok_or_else(|| "if-match-missing".to_owned())?
        .parse::<u64>()
        .map_err(|_| "if-match-invalid".to_owned())?;
    let idempotency_key = request
        .headers
        .get("idempotency-key")
        .ok_or_else(|| "idempotency-key-missing".to_owned())?
        .clone();
    if let Some(previous_resource) = state.idempotency_keys.get(&idempotency_key) {
        if previous_resource != resource_id {
            return write_http_response(
                stream,
                409,
                "application/json",
                br#"{"error_code":"idempotency-conflict"}"#,
            );
        }
        let resource = state
            .resources
            .get_mut(resource_id)
            .ok_or_else(|| "resource-not-found".to_owned())?;
        resource.idempotency_seen = true;
        let body = serde_json::to_vec(resource).map_err(|error| error.to_string())?;
        return write_http_response(stream, 200, "application/json", &body);
    }
    let mutation: FixtureMutationV1 =
        parse_json_strict(&request.body).map_err(|error| error.to_string())?;
    if mutation.status != "in_progress" {
        return write_http_response(
            stream,
            422,
            "application/json",
            br#"{"error_code":"status-not-approved"}"#,
        );
    }
    let resource = state
        .resources
        .get_mut(resource_id)
        .ok_or_else(|| "resource-not-found".to_owned())?;
    if resource.revision != expected_revision {
        return write_http_response(
            stream,
            412,
            "application/json",
            br#"{"error_code":"stale-revision"}"#,
        );
    }
    state.total_mutations = state.total_mutations.saturating_add(1);
    resource.status = mutation.status;
    resource.revision = resource.revision.saturating_add(1);
    resource.mutation_sequence = state.total_mutations;
    state
        .idempotency_keys
        .insert(idempotency_key, resource_id.to_owned());
    if resource_id == "case-e" && !state.response_drop_emitted {
        state.response_drop_emitted = true;
        return Ok(());
    }
    let body = serde_json::to_vec(resource).map_err(|error| error.to_string())?;
    write_http_response(stream, 200, "application/json", &body)
}

pub fn connector_worker_main() -> Result<(), String> {
    let request = read_bounded_json::<EnterpriseWorkerRequestV1>(std::io::stdin().lock())?;
    let response = execute_worker_request(&request)?;
    let bytes = serde_json::to_vec(&response).map_err(|error| error.to_string())?;
    std::io::stdout()
        .write_all(&bytes)
        .map_err(|error| error.to_string())?;
    std::io::stdout()
        .write_all(b"\n")
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn execute_worker_request(
    request: &EnterpriseWorkerRequestV1,
) -> Result<EnterpriseWorkerResponseV1, String> {
    validate_worker_request(request)?;
    let path = format!("/v1/work-orders/{}", request.resource_reference_id);
    let (method, body) = match request.operation_id.as_str() {
        "observe-work-order" => ("GET", Vec::new()),
        "update-work-order-status" => {
            let desired = request
                .desired_status
                .as_deref()
                .ok_or_else(|| "mutation desired status is missing".to_owned())?;
            if desired != "in_progress" {
                return Err("mutation desired status is not descriptor-approved".to_owned());
            }
            ("PATCH", br#"{"status":"in_progress"}"#.to_vec())
        }
        _ => return Err("operation is not in the closed worker operation set".to_owned()),
    };
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, request.exact_port as u16);
    let mut stream = TcpStream::connect_timeout(
        &address.into(),
        Duration::from_millis(request.connect_timeout_ms),
    )
    .map_err(|error| format!("exact-endpoint-connect-failed:{:?}", error.kind()))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(request.read_timeout_ms)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_millis(request.read_timeout_ms)))
        .map_err(|error| error.to_string())?;
    let mut headers = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\nAuthorization: D2I-Synthetic {}\r\nAccept: application/json\r\n",
        request.exact_port, request.synthetic_secret_material
    );
    if method == "PATCH" {
        let revision = request
            .expected_revision
            .ok_or_else(|| "mutation revision is missing".to_owned())?;
        let key = request
            .idempotency_key
            .as_deref()
            .ok_or_else(|| "mutation idempotency key is missing".to_owned())?;
        headers.push_str(&format!(
            "If-Match: {revision}\r\nIdempotency-Key: {key}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    headers.push_str("\r\n");
    let bytes_sent = headers.len().saturating_add(body.len());
    stream
        .write_all(headers.as_bytes())
        .map_err(|error| error.to_string())?;
    stream.write_all(&body).map_err(|error| error.to_string())?;
    stream.flush().map_err(|error| error.to_string())?;
    let maximum = usize::try_from(request.maximum_response_bytes)
        .map_err(|_| "response bound overflow".to_owned())?
        .min(MAX_HTTP_BODY_BYTES);
    let response = read_http_response(&mut stream, maximum);
    match response {
        Ok((status, content_type, body, bytes_received)) => worker_response_from_http(
            request,
            status,
            &content_type,
            &body,
            bytes_sent,
            bytes_received,
        ),
        Err(error) if method == "PATCH" && error == "empty-http-response" => {
            sealed_worker_response(EnterpriseWorkerResponseV1 {
                schema_version: 1,
                request_id: request.request_id.clone(),
                operation_id: request.operation_id.clone(),
                resource_reference_id: request.resource_reference_id.clone(),
                result: EnterpriseOperationResultV1::UnknownWriteOutcome,
                http_status: None,
                normalized_status: None,
                resource_revision: None,
                server_mutation_sequence: None,
                idempotency_seen: false,
                untrusted_instruction_present: false,
                redirect_rejected: false,
                raw_response_sha256: None,
                bytes_sent: to_u32(bytes_sent)?,
                bytes_received: 0,
                external_connection_count: 0,
                proxy_use_count: 0,
                response_sha256: ZERO_HASH.to_owned(),
            })
        }
        Err(error) => Err(error),
    }
}

fn worker_response_from_http(
    request: &EnterpriseWorkerRequestV1,
    status: u32,
    content_type: &str,
    body: &[u8],
    bytes_sent: usize,
    bytes_received: usize,
) -> Result<EnterpriseWorkerResponseV1, String> {
    if (300..=399).contains(&status) {
        return sealed_worker_response(base_worker_response(
            request,
            EnterpriseOperationResultV1::Rejected,
            Some(status),
            Some(sha256_bytes(body)),
            bytes_sent,
            bytes_received,
            true,
        )?);
    }
    let result = match status {
        200..=299 => EnterpriseOperationResultV1::Succeeded,
        401 | 403 => EnterpriseOperationResultV1::Unauthorized,
        409 | 412 => EnterpriseOperationResultV1::StaleConflict,
        429 => EnterpriseOperationResultV1::RateLimited,
        _ => EnterpriseOperationResultV1::Rejected,
    };
    if result != EnterpriseOperationResultV1::Succeeded {
        return sealed_worker_response(base_worker_response(
            request,
            result,
            Some(status),
            Some(sha256_bytes(body)),
            bytes_sent,
            bytes_received,
            false,
        )?);
    }
    if content_type != "application/json" {
        return malformed_worker_response(request, status, body, bytes_sent, bytes_received);
    }
    let payload: FixtureResourceV1 = match parse_json_strict(body) {
        Ok(payload) => payload,
        Err(_) => {
            return malformed_worker_response(request, status, body, bytes_sent, bytes_received)
        }
    };
    if payload.resource_id != request.resource_reference_id {
        return Err("response resource identity differs from exact request".to_owned());
    }
    let mut response = base_worker_response(
        request,
        result,
        Some(status),
        Some(sha256_bytes(body)),
        bytes_sent,
        bytes_received,
        false,
    )?;
    response.normalized_status = Some(payload.status);
    response.resource_revision = Some(payload.revision);
    response.server_mutation_sequence = Some(payload.mutation_sequence);
    response.idempotency_seen = payload.idempotency_seen;
    response.untrusted_instruction_present = payload.untrusted_instruction.is_some();
    sealed_worker_response(response)
}

fn base_worker_response(
    request: &EnterpriseWorkerRequestV1,
    result: EnterpriseOperationResultV1,
    http_status: Option<u32>,
    raw_response_sha256: Option<String>,
    bytes_sent: usize,
    bytes_received: usize,
    redirect_rejected: bool,
) -> Result<EnterpriseWorkerResponseV1, String> {
    Ok(EnterpriseWorkerResponseV1 {
        schema_version: 1,
        request_id: request.request_id.clone(),
        operation_id: request.operation_id.clone(),
        resource_reference_id: request.resource_reference_id.clone(),
        result,
        http_status,
        normalized_status: None,
        resource_revision: None,
        server_mutation_sequence: None,
        idempotency_seen: false,
        untrusted_instruction_present: false,
        redirect_rejected,
        raw_response_sha256,
        bytes_sent: to_u32(bytes_sent)?,
        bytes_received: to_u32(bytes_received)?,
        external_connection_count: 0,
        proxy_use_count: 0,
        response_sha256: ZERO_HASH.to_owned(),
    })
}

fn malformed_worker_response(
    request: &EnterpriseWorkerRequestV1,
    status: u32,
    body: &[u8],
    bytes_sent: usize,
    bytes_received: usize,
) -> Result<EnterpriseWorkerResponseV1, String> {
    let response = base_worker_response(
        request,
        EnterpriseOperationResultV1::MalformedResponse,
        Some(status),
        Some(sha256_bytes(body)),
        bytes_sent,
        bytes_received,
        false,
    )?;
    sealed_worker_response(response)
}

fn sealed_worker_response(
    mut response: EnterpriseWorkerResponseV1,
) -> Result<EnterpriseWorkerResponseV1, String> {
    response.response_sha256 = hash_without_json(&response, &["response_sha256"])?;
    Ok(response)
}

fn validate_worker_request(request: &EnterpriseWorkerRequestV1) -> Result<(), String> {
    if request.schema_version != 1
        || request.exact_scheme != "http"
        || request.exact_hostname != "127.0.0.1"
        || request.exact_port == 0
        || request.exact_port > 65_535
        || request.connect_timeout_ms == 0
        || request.connect_timeout_ms > 10_000
        || request.read_timeout_ms == 0
        || request.read_timeout_ms > 10_000
        || request.maximum_response_bytes == 0
        || request.maximum_response_bytes as usize > MAX_HTTP_BODY_BYTES
    {
        return Err("worker request violates signed loopback transport bounds".to_owned());
    }
    validate_resource_id(&request.resource_reference_id)?;
    validate_secret(&request.synthetic_secret_material)?;
    if request.operation_id == "observe-work-order"
        && (request.desired_status.is_some()
            || request.expected_revision.is_some()
            || request.idempotency_key.is_some())
    {
        return Err("observation request contains mutation fields".to_owned());
    }
    if request.operation_id == "update-work-order-status"
        && (request.desired_status.is_none()
            || request.expected_revision.is_none()
            || request.idempotency_key.is_none())
    {
        return Err("mutation request lacks exact binding fields".to_owned());
    }
    Ok(())
}

fn validate_secret(secret: &str) -> Result<(), String> {
    if secret.len() != 64 || !secret.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("synthetic secret does not satisfy runtime entropy encoding".to_owned());
    }
    Ok(())
}

fn validate_resource_id(resource_id: &str) -> Result<(), String> {
    if resource_id.is_empty()
        || resource_id.len() > 64
        || !resource_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("resource reference is not a bounded opaque ID".to_owned());
    }
    Ok(())
}

fn read_one_line_json<T: for<'de> Deserialize<'de>>(mut reader: impl BufRead) -> Result<T, String> {
    let mut line = String::new();
    reader
        .by_ref()
        .take((MAX_IPC_BYTES + 1) as u64)
        .read_line(&mut line)
        .map_err(|error| error.to_string())?;
    if line.is_empty() || line.len() > MAX_IPC_BYTES {
        return Err("IPC bootstrap exceeds bounds".to_owned());
    }
    serde_json::from_str(&line).map_err(|error| error.to_string())
}

fn read_bounded_json<T: for<'de> Deserialize<'de>>(mut reader: impl Read) -> Result<T, String> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take((MAX_IPC_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.is_empty() || bytes.len() > MAX_IPC_BYTES {
        return Err("worker IPC exceeds bounds".to_owned());
    }
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequestV1, String> {
    let (header_bytes, remainder) = read_http_head(stream)?;
    let header =
        std::str::from_utf8(&header_bytes).map_err(|_| "request-header-not-utf8".to_owned())?;
    let mut lines = header.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| "request-line-missing".to_owned())?;
    let mut parts = request_line.split(' ');
    let method = parts
        .next()
        .ok_or_else(|| "method-missing".to_owned())?
        .to_owned();
    let path = parts
        .next()
        .ok_or_else(|| "path-missing".to_owned())?
        .to_owned();
    if parts.next() != Some("HTTP/1.1") || parts.next().is_some() {
        return Err("request-line-invalid".to_owned());
    }
    let mut headers = BTreeMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "request-header-invalid".to_owned())?;
        let name = name.trim().to_ascii_lowercase();
        if headers.insert(name, value.trim().to_owned()).is_some() {
            return Err("duplicate-request-header".to_owned());
        }
    }
    let content_length = headers
        .get("content-length")
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| "content-length-invalid".to_owned())
        })
        .transpose()?
        .unwrap_or(0);
    if content_length > MAX_HTTP_BODY_BYTES {
        return Err("request-body-too-large".to_owned());
    }
    let mut body = remainder;
    if body.len() > content_length {
        body.truncate(content_length);
    }
    if body.len() < content_length {
        let mut tail = vec![0_u8; content_length - body.len()];
        stream
            .read_exact(&mut tail)
            .map_err(|error| error.to_string())?;
        body.extend_from_slice(&tail);
    }
    Ok(HttpRequestV1 {
        method,
        path,
        headers,
        body,
    })
}

fn read_http_head(stream: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk).map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("empty-http-response".to_owned());
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > MAX_HTTP_HEADER_BYTES {
            return Err("http-header-too-large".to_owned());
        }
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let remainder = bytes.split_off(position + 4);
            bytes.truncate(position + 4);
            return Ok((bytes, remainder));
        }
    }
}

fn read_http_response(
    stream: &mut TcpStream,
    maximum_body: usize,
) -> Result<(u32, String, Vec<u8>, usize), String> {
    let (head, mut body) = read_http_head(stream)?;
    let header = std::str::from_utf8(&head).map_err(|_| "response-header-not-utf8".to_owned())?;
    let mut lines = header.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| "status-line-missing".to_owned())?;
    let mut status_parts = status_line.split(' ');
    if status_parts.next() != Some("HTTP/1.1") {
        return Err("status-protocol-invalid".to_owned());
    }
    let status = status_parts
        .next()
        .ok_or_else(|| "status-missing".to_owned())?
        .parse::<u32>()
        .map_err(|_| "status-invalid".to_owned())?;
    let mut headers = BTreeMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "response-header-invalid".to_owned())?;
        let name = name.trim().to_ascii_lowercase();
        if headers.insert(name, value.trim().to_owned()).is_some() {
            return Err("duplicate-response-header".to_owned());
        }
    }
    let content_length = headers
        .get("content-length")
        .ok_or_else(|| "response-content-length-missing".to_owned())?
        .parse::<usize>()
        .map_err(|_| "response-content-length-invalid".to_owned())?;
    if content_length > maximum_body {
        return Err("response-body-too-large".to_owned());
    }
    if body.len() > content_length {
        body.truncate(content_length);
    }
    if body.len() < content_length {
        let mut tail = vec![0_u8; content_length - body.len()];
        stream
            .read_exact(&mut tail)
            .map_err(|error| error.to_string())?;
        body.extend_from_slice(&tail);
    }
    let total = head.len().saturating_add(body.len());
    Ok((
        status,
        headers.get("content-type").cloned().unwrap_or_default(),
        body,
        total,
    ))
}

fn write_http_response(
    stream: &mut TcpStream,
    status: u32,
    content_type: &str,
    body: &[u8],
) -> Result<(), String> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        405 => "Method Not Allowed",
        409 => "Conflict",
        412 => "Precondition Failed",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .map_err(|error| error.to_string())?;
    stream.write_all(body).map_err(|error| error.to_string())?;
    stream.flush().map_err(|error| error.to_string())
}

fn sanitized_error_code(error: &str) -> String {
    error
        .chars()
        .filter(|value| value.is_ascii_alphanumeric() || *value == '-')
        .take(64)
        .collect()
}

fn to_u32(value: usize) -> Result<u32, String> {
    u32::try_from(value).map_err(|_| "byte count overflow".to_owned())
}

fn hash_without_json<T: Serialize>(value: &T, fields: &[&str]) -> Result<String, String> {
    let mut value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "hashed value is not an object".to_owned())?;
    for field in fields {
        object.remove(*field);
    }
    canonical_sha256(&value).map_err(|error| error.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseApiStoreRecordV1 {
    pub schema_version: u32,
    pub sequence: u64,
    pub artifact_kind: String,
    pub artifact_id: String,
    pub artifact_sha256: String,
    pub object_relative_path: String,
    pub recorded_at_unix_ms: u64,
    pub previous_record_sha256: String,
    pub record_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnterpriseApiStoreVerificationV1 {
    pub record_count: u64,
    pub terminal_sha256: String,
    pub object_count: u64,
    pub total_bytes: u64,
}

#[derive(Debug)]
pub struct EnterpriseApiStore {
    root: PathBuf,
    verification: EnterpriseApiStoreVerificationV1,
}

pub fn initialize_enterprise_api_store(root: &Path) -> Result<EnterpriseApiStore, String> {
    if root.exists() {
        return Err("enterprise API store already exists".to_owned());
    }
    fs::create_dir_all(root.join("objects")).map_err(|error| error.to_string())?;
    fs::create_dir_all(root.join("ledger")).map_err(|error| error.to_string())?;
    harden_path_for_current_user(root).map_err(|error| error.to_string())?;
    Ok(EnterpriseApiStore {
        root: root.to_path_buf(),
        verification: EnterpriseApiStoreVerificationV1 {
            record_count: 0,
            terminal_sha256: ZERO_HASH.to_owned(),
            object_count: 0,
            total_bytes: 0,
        },
    })
}

pub fn recover_enterprise_api_store(root: &Path) -> Result<EnterpriseApiStore, String> {
    let mut store = EnterpriseApiStore {
        root: root.to_path_buf(),
        verification: EnterpriseApiStoreVerificationV1 {
            record_count: 0,
            terminal_sha256: ZERO_HASH.to_owned(),
            object_count: 0,
            total_bytes: 0,
        },
    };
    let ledger = root.join("ledger");
    if !ledger.is_dir() || !root.join("objects").is_dir() {
        return Err("enterprise API store layout is incomplete".to_owned());
    }
    let mut entries = fs::read_dir(&ledger)
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let bytes = fs::read(entry.path()).map_err(|error| error.to_string())?;
        let record: EnterpriseApiStoreRecordV1 =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        if record.sequence != store.verification.record_count
            || record.previous_record_sha256 != store.verification.terminal_sha256
            || hash_without_json(&record, &["record_sha256"])? != record.record_sha256
        {
            return Err("enterprise API store ledger chain differs".to_owned());
        }
        let object = root.join(&record.object_relative_path);
        let object_bytes = fs::read(&object).map_err(|error| error.to_string())?;
        if sha256_bytes(&object_bytes) != record.artifact_sha256 {
            return Err("enterprise API content-addressed object differs".to_owned());
        }
        store.verification.record_count = store.verification.record_count.saturating_add(1);
        store.verification.terminal_sha256 = record.record_sha256;
        store.verification.object_count = store.verification.object_count.saturating_add(1);
        store.verification.total_bytes = store
            .verification
            .total_bytes
            .saturating_add(object_bytes.len() as u64);
    }
    Ok(store)
}

impl EnterpriseApiStore {
    pub fn append<T: Serialize>(
        &mut self,
        artifact_kind: &str,
        artifact_id: &str,
        artifact: &T,
        now_unix_ms: u64,
    ) -> Result<EnterpriseApiStoreRecordV1, String> {
        validate_store_label(artifact_kind)?;
        validate_store_label(artifact_id)?;
        let bytes = serde_json::to_vec(artifact).map_err(|error| error.to_string())?;
        reject_runtime_secret_artifact(&bytes)?;
        let artifact_sha256 = sha256_bytes(&bytes);
        let name = artifact_sha256.trim_start_matches("sha256:");
        let object_relative_path = format!("objects/{name}.json");
        let object_path = self.root.join(&object_relative_path);
        if object_path.exists() {
            return Err("enterprise API store rejects duplicate object append".to_owned());
        }
        if self
            .verification
            .total_bytes
            .saturating_add(bytes.len() as u64)
            > MAX_STORE_BYTES
        {
            return Err("enterprise API store exceeds bounded bytes".to_owned());
        }
        let temporary = self.root.join("objects").join(format!(".{name}.tmp"));
        fs::write(&temporary, &bytes).map_err(|error| error.to_string())?;
        fs::rename(&temporary, &object_path).map_err(|error| error.to_string())?;
        let mut record = EnterpriseApiStoreRecordV1 {
            schema_version: 1,
            sequence: self.verification.record_count,
            artifact_kind: artifact_kind.to_owned(),
            artifact_id: artifact_id.to_owned(),
            artifact_sha256,
            object_relative_path,
            recorded_at_unix_ms: now_unix_ms,
            previous_record_sha256: self.verification.terminal_sha256.clone(),
            record_sha256: ZERO_HASH.to_owned(),
        };
        record.record_sha256 = hash_without_json(&record, &["record_sha256"])?;
        let ledger_path = self
            .root
            .join("ledger")
            .join(format!("{:020}.json", record.sequence));
        let ledger_temporary = self
            .root
            .join("ledger")
            .join(format!(".{:020}.tmp", record.sequence));
        fs::write(
            &ledger_temporary,
            serde_json::to_vec(&record).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        fs::rename(&ledger_temporary, ledger_path).map_err(|error| error.to_string())?;
        self.verification.record_count = self.verification.record_count.saturating_add(1);
        self.verification.terminal_sha256 = record.record_sha256.clone();
        self.verification.object_count = self.verification.object_count.saturating_add(1);
        self.verification.total_bytes = self
            .verification
            .total_bytes
            .saturating_add(bytes.len() as u64);
        Ok(record)
    }

    pub fn verification(&self) -> &EnterpriseApiStoreVerificationV1 {
        &self.verification
    }
}

fn validate_store_label(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err("store label is not bounded".to_owned());
    }
    Ok(())
}

fn reject_runtime_secret_artifact(bytes: &[u8]) -> Result<(), String> {
    let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    for marker in [
        "synthetic_secret_material",
        "authorization",
        "bearer",
        "api_key",
        "client_secret",
        "refresh_token",
        "set-cookie",
        "password",
    ] {
        if lower.contains(marker) {
            return Err("runtime artifact contains a forbidden credential marker".to_owned());
        }
    }
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |value| value.as_nanos());
        std::env::temp_dir().join(format!(
            "d2i-edge100-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn content_addressed_store_recovers_all_crash_windows_a_through_l() {
        let root = temporary_root("crash-windows");
        let mut store = initialize_enterprise_api_store(&root)
            .unwrap_or_else(|error| panic!("initialize: {error}"));
        for window in 'a'..='l' {
            let artifact = serde_json::json!({"window": window.to_string(), "status": "durable"});
            store
                .append(
                    "crash-window",
                    &format!("window-{window}"),
                    &artifact,
                    u64::from(window as u32),
                )
                .unwrap_or_else(|error| panic!("append {window}: {error}"));
            let recovered = recover_enterprise_api_store(&root)
                .unwrap_or_else(|error| panic!("recover {window}: {error}"));
            assert_eq!(
                recovered.verification().record_count,
                u64::from(window as u32 - 'a' as u32 + 1)
            );
        }
        fs::remove_dir_all(&root).unwrap_or_else(|error| panic!("cleanup: {error}"));
    }

    #[test]
    fn store_rejects_secret_markers_and_object_mutation() {
        let root = temporary_root("tamper");
        let mut store = initialize_enterprise_api_store(&root)
            .unwrap_or_else(|error| panic!("initialize: {error}"));
        assert!(store
            .append(
                "bad",
                "bad",
                &serde_json::json!({"authorization": "redacted"}),
                1
            )
            .is_err());
        let record = store
            .append("good", "good", &serde_json::json!({"status": "ok"}), 2)
            .unwrap_or_else(|error| panic!("append: {error}"));
        fs::write(root.join(record.object_relative_path), b"{}")
            .unwrap_or_else(|error| panic!("tamper: {error}"));
        assert!(recover_enterprise_api_store(&root).is_err());
        fs::remove_dir_all(&root).unwrap_or_else(|error| panic!("cleanup: {error}"));
    }
}
