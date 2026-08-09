#![cfg(windows)]

use d2i_desktop::{
    EnterpriseFixtureBootstrapV1, EnterpriseFixtureReadyV1, EnterpriseWorkerRequestV1,
    EnterpriseWorkerResponseV1,
};
use d2i_enterprise_api_plane::EnterpriseOperationResultV1;
use d2i_windows_host::secure_random_bytes;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

struct FixtureProcess {
    child: Child,
    ready: EnterpriseFixtureReadyV1,
    secret: String,
}

impl Drop for FixtureProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn separate_server_and_worker_enforce_exact_loopback_and_verify_fresh_state() {
    let mut fixture = start_fixture();
    let observed = run_worker(
        &fixture,
        request(
            &fixture,
            "observe-a",
            "observe-work-order",
            "case-a",
            None,
            None,
        ),
    );
    assert_eq!(observed.result, EnterpriseOperationResultV1::Succeeded);
    assert_eq!(observed.normalized_status.as_deref(), Some("open"));
    assert_eq!(observed.resource_revision, Some(1));

    let updated = run_worker(
        &fixture,
        request(
            &fixture,
            "update-a",
            "update-work-order-status",
            "case-a",
            Some(1),
            Some("edge100-case-a-idempotency"),
        ),
    );
    assert_eq!(updated.result, EnterpriseOperationResultV1::Succeeded);
    assert_eq!(updated.server_mutation_sequence, Some(1));

    let verified = run_worker(
        &fixture,
        request(
            &fixture,
            "verify-a",
            "observe-work-order",
            "case-a",
            None,
            None,
        ),
    );
    assert_eq!(verified.normalized_status.as_deref(), Some("in_progress"));
    assert_eq!(verified.resource_revision, Some(2));
    assert_eq!(verified.external_connection_count, 0);
    assert_eq!(verified.proxy_use_count, 0);

    let mut wrong_port = request(
        &fixture,
        "wrong-port",
        "observe-work-order",
        "case-a",
        None,
        None,
    );
    wrong_port.exact_port = if fixture.ready.port == 65_535 {
        fixture.ready.port - 1
    } else {
        fixture.ready.port + 1
    };
    let output = run_worker_output(&wrong_port);
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(&fixture.secret));

    fixture
        .child
        .kill()
        .unwrap_or_else(|error| panic!("stop fixture: {error}"));
    let status = fixture
        .child
        .wait()
        .unwrap_or_else(|error| panic!("wait fixture: {error}"));
    assert!(!status.success());
}

fn start_fixture() -> FixtureProcess {
    let secret =
        hex(&secure_random_bytes::<32>().unwrap_or_else(|error| panic!("random secret: {error}")));
    let mut command = Command::new(env!("CARGO_BIN_EXE_d2i-edge100-enterprise-fixture"));
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    hide_window(&mut command);
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("spawn fixture: {error}"));
    let bootstrap = EnterpriseFixtureBootstrapV1 {
        schema_version: 1,
        synthetic_secret_material: secret.clone(),
        maximum_connections: 32,
    };
    let mut stdin = child
        .stdin
        .take()
        .unwrap_or_else(|| panic!("fixture stdin missing"));
    serde_json::to_writer(&mut stdin, &bootstrap)
        .unwrap_or_else(|error| panic!("bootstrap JSON: {error}"));
    stdin
        .write_all(b"\n")
        .unwrap_or_else(|error| panic!("bootstrap newline: {error}"));
    drop(stdin);
    let stdout = child
        .stdout
        .take()
        .unwrap_or_else(|| panic!("fixture stdout missing"));
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .unwrap_or_else(|error| panic!("fixture ready: {error}"));
    let ready =
        serde_json::from_str(&line).unwrap_or_else(|error| panic!("fixture ready JSON: {error}"));
    FixtureProcess {
        child,
        ready,
        secret,
    }
}

fn request(
    fixture: &FixtureProcess,
    request_id: &str,
    operation_id: &str,
    resource_id: &str,
    expected_revision: Option<u64>,
    idempotency_key: Option<&str>,
) -> EnterpriseWorkerRequestV1 {
    EnterpriseWorkerRequestV1 {
        schema_version: 1,
        request_id: request_id.to_owned(),
        exact_scheme: "http".to_owned(),
        exact_hostname: fixture.ready.hostname.clone(),
        exact_port: fixture.ready.port,
        operation_id: operation_id.to_owned(),
        resource_reference_id: resource_id.to_owned(),
        desired_status: (operation_id == "update-work-order-status")
            .then(|| "in_progress".to_owned()),
        expected_revision,
        idempotency_key: idempotency_key.map(str::to_owned),
        synthetic_secret_material: fixture.secret.clone(),
        connect_timeout_ms: 2_000,
        read_timeout_ms: 2_000,
        maximum_response_bytes: 16_384,
    }
}

fn run_worker(
    fixture: &FixtureProcess,
    request: EnterpriseWorkerRequestV1,
) -> EnterpriseWorkerResponseV1 {
    let output = run_worker_output(&request);
    assert!(
        output.status.success(),
        "worker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&fixture.secret));
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("worker response: {error}"))
}

fn run_worker_output(request: &EnterpriseWorkerRequestV1) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_d2i-edge100-connector-worker"));
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
    hide_window(&mut command);
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("spawn worker: {error}"));
    let mut stdin = child
        .stdin
        .take()
        .unwrap_or_else(|| panic!("worker stdin missing"));
    serde_json::to_writer(&mut stdin, request)
        .unwrap_or_else(|error| panic!("worker request JSON: {error}"));
    drop(stdin);
    child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("worker output: {error}"))
}

fn hide_window(command: &mut Command) {
    #[cfg(windows)]
    {
        command.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    {
        let _ = command;
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 15) as usize] as char);
    }
    output
}
