use crate::{
    activate_certified_windows_binding, initialize_audit_ledger,
    initialize_windows_activation_ledger, sign_approval, verify_signed_windows_certification,
    verify_windows_activation_ledger, BrowserInteraction, DesktopActionIntent, DesktopActor,
    DesktopAdapter, DesktopCapability, DesktopError, DesktopExecutor, DesktopOperation,
    DesktopPolicy, RiskClass, SignedWindowsCertification, WindowsAdapterConfiguration,
    WindowsBindingEvidence, WindowsRuntimeManifest, WindowsWebDriverAdapter,
};
use d2i_runtime_api::{DecisionEnvelope, DecisionStatus, Evidence, PolicyResult};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DNS_PROBE_HOST: &str = "d2i-wfp-self-test.invalid";

/// Result of the approved-runtime post-activation WebDriver deployment test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsWebDriverPostActivationSelfTestReport {
    pub schema_version: u32,
    pub activation_chain_head: String,
    pub activation_replay_rejected: bool,
    pub type_passed: bool,
    pub select_passed: bool,
    pub click_passed: bool,
    pub direct_ipv4_blocked: bool,
    pub dns_blocked: bool,
    pub redirect_blocked: bool,
}

/// Activates one certified binding and exercises only the reviewed WebDriver
/// operations and network-negative cases from the approved runtime image.
#[allow(clippy::too_many_arguments)]
pub fn run_windows_webdriver_post_activation_self_test(
    configuration: WindowsAdapterConfiguration,
    manifest: WindowsRuntimeManifest,
    evidence: WindowsBindingEvidence,
    certification: SignedWindowsCertification,
    activation_root: &Path,
    activator_id: &str,
    fixture_port: u16,
    now_unix_seconds: u64,
) -> Result<WindowsWebDriverPostActivationSelfTestReport, DesktopError> {
    if activation_root.exists() {
        return Err(DesktopError::Precondition(
            "post-activation self-test ledger root must be new".to_owned(),
        ));
    }
    let browser_session_id = configuration
        .browser_session_ids
        .iter()
        .next()
        .cloned()
        .ok_or_else(|| DesktopError::Invalid("WebDriver session allowlist is empty".to_owned()))?;
    let webdriver_endpoint = configuration.webdriver_endpoint.clone().ok_or_else(|| {
        DesktopError::Invalid("WebDriver endpoint is missing from configuration".to_owned())
    })?;
    let fixture = BrowserFixture::start(fixture_port)?;
    if configuration.browser_allowed_origins != BTreeSet::from([fixture.origin()]) {
        return Err(DesktopError::Integrity(
            "post-activation fixture origin differs from the certified scope".to_owned(),
        ));
    }
    let certified = verify_signed_windows_certification(
        &manifest,
        &evidence,
        &certification,
        now_unix_seconds,
    )?;
    let _ = initialize_windows_activation_ledger(
        activation_root,
        "windows-wfp-post-activation",
        &manifest,
        BTreeSet::from([activator_id.to_owned()]),
        16,
    )?;
    let admission = activate_certified_windows_binding(
        activation_root,
        activator_id,
        certified,
        now_unix_seconds,
    )?;
    let replay = verify_signed_windows_certification(
        &manifest,
        &evidence,
        &certification,
        now_unix_seconds,
    )?;
    let activation_replay_rejected =
        activate_certified_windows_binding(activation_root, activator_id, replay, now_unix_seconds)
            .is_err();
    if !activation_replay_rejected {
        return Err(DesktopError::Replay(
            "post-activation binding replay was accepted".to_owned(),
        ));
    }
    let adapter =
        WindowsWebDriverAdapter::bind(admission.activation, configuration, now_unix_seconds)?;
    let mut approval_seed = d2i_windows_host::secure_random_bytes::<32>().map_err(|error| {
        DesktopError::AdapterUnavailable(format!(
            "post-activation approval randomness failed: {error}"
        ))
    })?;
    let approval_key = SigningKey::from_bytes(&approval_seed);
    approval_seed.fill(0);
    let policy = browser_policy(&adapter, &fixture.origin(), &approval_key)?;
    let temp = TemporaryDirectory::new("d2i-wfp-post-activation")?;
    let mut executor = DesktopExecutor::new(
        adapter,
        policy,
        DesktopActor {
            actor_id: "deployment-self-test".to_owned(),
            roles: BTreeSet::from(["operator".to_owned()]),
        },
        "post-activation-session".to_owned(),
    )?;
    let now_ms = now_unix_milliseconds()?;
    let mut audit =
        initialize_audit_ledger(&temp.0.join("audit"), "post-activation-session", 32, now_ms)?;
    execute_action(
        &mut executor,
        navigate_intent(&browser_session_id, &fixture.origin(), 1, now_ms)?,
        None,
        &approval_key,
        &mut audit,
    )?;
    let typed = b"real-browser";
    execute_action(
        &mut executor,
        interaction_intent(
            &browser_session_id,
            &fixture.origin(),
            BrowserInteraction::TypeText {
                locator: "css:#text".to_owned(),
                text_hash: crate::sha256_bytes(typed),
                secret_ref: None,
            },
            2,
        )?,
        Some(typed),
        &approval_key,
        &mut audit,
    )?;
    let selected = b"beta";
    execute_action(
        &mut executor,
        interaction_intent(
            &browser_session_id,
            &fixture.origin(),
            BrowserInteraction::Select {
                locator: "css:#choice".to_owned(),
                value_hash: crate::sha256_bytes(selected),
            },
            3,
        )?,
        Some(selected),
        &approval_key,
        &mut audit,
    )?;
    execute_action(
        &mut executor,
        interaction_intent(
            &browser_session_id,
            &fixture.origin(),
            BrowserInteraction::Click {
                locator: "css:#submit".to_owned(),
            },
            4,
        )?,
        None,
        &approval_key,
        &mut audit,
    )?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if fixture
            .submitted_target()?
            .is_some_and(|target| target.contains("text=real-browser&choice=beta"))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if !fixture
        .submitted_target()?
        .is_some_and(|target| target.contains("text=real-browser&choice=beta"))
    {
        return Err(DesktopError::Integrity(
            "reactivated WebDriver did not submit typed and selected values".to_owned(),
        ));
    }
    let direct_ipv4_blocked = verify_non_loopback_block(
        &webdriver_endpoint,
        &browser_session_id,
        NegativeNavigation::Direct,
        &fixture,
    )?;
    let dns_blocked = verify_non_loopback_block(
        &webdriver_endpoint,
        &browser_session_id,
        NegativeNavigation::Dns,
        &fixture,
    )?;
    let redirect_blocked = verify_non_loopback_block(
        &webdriver_endpoint,
        &browser_session_id,
        NegativeNavigation::Redirect,
        &fixture,
    )?;
    if !direct_ipv4_blocked || !dns_blocked || !redirect_blocked {
        return Err(DesktopError::AccessDenied(
            "reactivated Edge reached a forbidden external target".to_owned(),
        ));
    }
    let activation = verify_windows_activation_ledger(activation_root)?;
    Ok(WindowsWebDriverPostActivationSelfTestReport {
        schema_version: 1,
        activation_chain_head: activation.chain_head,
        activation_replay_rejected,
        type_passed: true,
        select_passed: true,
        click_passed: true,
        direct_ipv4_blocked,
        dns_blocked,
        redirect_blocked,
    })
}

fn execute_action(
    executor: &mut DesktopExecutor<WindowsWebDriverAdapter>,
    action: DesktopActionIntent,
    payload: Option<&[u8]>,
    approval_key: &SigningKey,
    audit: &mut crate::AuditLedger,
) -> Result<(), DesktopError> {
    let now_ms = now_unix_milliseconds()?;
    let preparation = executor.prepare(&action, &decision()?, now_ms, audit)?;
    let approval = sign_approval(
        format!("deployment-approval-{}", action.sequence),
        "deployment-self-test".to_owned(),
        &preparation.policy_decision,
        &preparation.prepared,
        now_ms,
        now_ms.saturating_add(10_000),
        format!("deployment-nonce-{}", action.sequence),
        approval_key,
    )?;
    let _ = executor.commit(
        &action,
        &preparation,
        Some(&approval),
        payload,
        now_ms,
        audit,
    )?;
    Ok(())
}

fn browser_policy(
    adapter: &impl DesktopAdapter,
    origin: &str,
    approval_key: &SigningKey,
) -> Result<DesktopPolicy, DesktopError> {
    let descriptor = adapter.descriptor();
    Ok(DesktopPolicy {
        schema_version: 1,
        policy_id: "windows-post-activation".to_owned(),
        policy_version: "1.0.0".to_owned(),
        allowed_actor_roles: BTreeSet::from(["operator".to_owned()]),
        allowed_capabilities: BTreeSet::from([
            DesktopCapability::BrowserNavigate,
            DesktopCapability::BrowserInteract,
        ]),
        approval_required_for: BTreeSet::from([
            RiskClass::ExternalCommunication,
            RiskClass::CredentialSensitive,
            RiskClass::Destructive,
            RiskClass::Privileged,
        ]),
        allowed_read_roots: Vec::new(),
        allowed_write_roots: Vec::new(),
        allowed_executables: Vec::new(),
        network_allowed: true,
        allowed_network_origins: BTreeSet::from([origin.to_owned()]),
        allowed_adapters: BTreeMap::from([(
            descriptor.adapter_id.clone(),
            descriptor.descriptor_hash()?,
        )]),
        approver_public_keys: BTreeMap::from([(
            "deployment-self-test".to_owned(),
            crate::hex_encode(&approval_key.verifying_key().to_bytes()),
        )]),
        maximum_actions_per_session: 8,
        maximum_action_lifetime_ms: 60_000,
    })
}

fn navigate_intent(
    session: &str,
    origin: &str,
    sequence: u64,
    now_ms: u64,
) -> Result<DesktopActionIntent, DesktopError> {
    action_intent(
        DesktopOperation::BrowserNavigate {
            browser_session_id: session.to_owned(),
            url: format!("{origin}/form"),
            origin: origin.to_owned(),
        },
        sequence,
        now_ms,
    )
}

fn interaction_intent(
    session: &str,
    origin: &str,
    interaction: BrowserInteraction,
    sequence: u64,
) -> Result<DesktopActionIntent, DesktopError> {
    action_intent(
        DesktopOperation::BrowserInteract {
            browser_session_id: session.to_owned(),
            origin: origin.to_owned(),
            interaction,
        },
        sequence,
        now_unix_milliseconds()?,
    )
}

fn action_intent(
    operation: DesktopOperation,
    sequence: u64,
    now_ms: u64,
) -> Result<DesktopActionIntent, DesktopError> {
    let decision = decision()?;
    Ok(DesktopActionIntent {
        schema_version: 1,
        action_id: format!("post-activation-action-{sequence}"),
        session_id: "post-activation-session".to_owned(),
        sequence,
        generated_at_unix_ms: now_ms.saturating_sub(1_000),
        expires_at_unix_ms: now_ms.saturating_add(59_000),
        request_id: decision.request_id.clone(),
        build_id: decision.build_id.clone(),
        package_content_hash: decision.package_content_hash.clone(),
        decision_hash: decision.decision_hash(),
        evidence_hashes: vec![fixed_hash(2)],
        idempotency_key: format!("post-activation-{sequence}"),
        rationale_hash: fixed_hash(3),
        operation,
    })
}

fn decision() -> Result<DecisionEnvelope, DesktopError> {
    Ok(DecisionEnvelope {
        request_id: "post-activation-request".to_owned(),
        build_id: "post-activation-build".to_owned(),
        package_content_hash: fixed_hash(1),
        skill_id: "desktop-deployment-self-test".to_owned(),
        status: DecisionStatus::Success,
        result: json!({"action": "deployment-self-test"}),
        module_ids: vec!["deployment-self-test".to_owned()],
        evidence: vec![Evidence {
            source: "deployment".to_owned(),
            span: "post-activation".to_owned(),
            provenance_id: "deployment-self-test".to_owned(),
            content_hash: fixed_hash(2),
        }],
        confidence: 1.0,
        policy: PolicyResult {
            allowed: true,
            reason: "deployment self-test".to_owned(),
            human_review_required: false,
        },
        timings: Vec::new(),
        warnings: Vec::new(),
        replay_key: "post-activation-replay".to_owned(),
    })
}

fn fixed_hash(value: u8) -> String {
    format!("sha256:{value:064x}")
}

#[derive(Clone, Copy)]
enum NegativeNavigation {
    Direct,
    Dns,
    Redirect,
}

fn verify_non_loopback_block(
    webdriver_endpoint: &str,
    session_id: &str,
    kind: NegativeNavigation,
    fixture: &BrowserFixture,
) -> Result<bool, DesktopError> {
    let address = discover_non_loopback_ipv4()?;
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        .map_err(network_error("bind non-loopback listener"))?;
    listener
        .set_nonblocking(true)
        .map_err(network_error("configure non-loopback listener"))?;
    let port = listener
        .local_addr()
        .map_err(network_error("read non-loopback listener address"))?
        .port();
    let target = SocketAddr::V4(SocketAddrV4::new(address, port));
    let mut control = TcpStream::connect_timeout(&target, Duration::from_secs(2))
        .map_err(network_error("connect non-loopback control"))?;
    control
        .write_all(b"GET /control HTTP/1.1\r\nHost: control\r\nConnection: close\r\n\r\n")
        .map_err(network_error("write non-loopback control"))?;
    wait_for_accept(&listener, Duration::from_secs(2), true)?;
    let url = match kind {
        NegativeNavigation::Direct => format!("http://{address}:{port}/direct"),
        NegativeNavigation::Dns => format!("http://{DNS_PROBE_HOST}:{port}/dns"),
        NegativeNavigation::Redirect => {
            fixture.set_redirect_target(format!("http://{address}:{port}/redirected"))?;
            format!("{}/redirect", fixture.origin())
        }
    };
    raw_webdriver_navigate(webdriver_endpoint, session_id, &url)?;
    if matches!(kind, NegativeNavigation::Redirect) {
        fixture.require_redirect_source(Duration::from_secs(2))?;
    }
    wait_for_accept(&listener, Duration::from_secs(2), false)
}

fn wait_for_accept(
    listener: &TcpListener,
    observation: Duration,
    require_connection: bool,
) -> Result<bool, DesktopError> {
    let deadline = Instant::now() + observation;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok(_) if require_connection => return Ok(true),
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(network_error("accept non-loopback probe")(error)),
        }
    }
    if require_connection {
        Err(DesktopError::AdapterUnavailable(
            "ordinary process could not reach the non-loopback control listener".to_owned(),
        ))
    } else {
        Ok(true)
    }
}

fn discover_non_loopback_ipv4() -> Result<Ipv4Addr, DesktopError> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(network_error("bind route-discovery socket"))?;
    socket
        .connect((Ipv4Addr::new(192, 0, 2, 1), 9))
        .map_err(network_error("connect route-discovery socket"))?;
    match socket
        .local_addr()
        .map_err(network_error("read route-discovery address"))?
        .ip()
    {
        std::net::IpAddr::V4(address) if !address.is_loopback() && !address.is_unspecified() => {
            Ok(address)
        }
        address => Err(DesktopError::AdapterUnavailable(format!(
            "no usable non-loopback IPv4 address was discovered: {address}"
        ))),
    }
}

fn raw_webdriver_navigate(endpoint: &str, session_id: &str, url: &str) -> Result<(), DesktopError> {
    let authority = endpoint.strip_prefix("http://").ok_or_else(|| {
        DesktopError::Invalid("WebDriver deployment endpoint must use HTTP".to_owned())
    })?;
    if authority.contains('/') || authority.contains(['\r', '\n']) {
        return Err(DesktopError::Invalid(
            "WebDriver deployment endpoint is not a loopback authority".to_owned(),
        ));
    }
    let body = serde_json::to_vec(&json!({"url": url}))
        .map_err(|error| DesktopError::Json(error.to_string()))?;
    let mut stream =
        TcpStream::connect(authority).map_err(network_error("connect WebDriver endpoint"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(network_error("set WebDriver read timeout"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(network_error("set WebDriver write timeout"))?;
    let header = format!(
        "POST /session/{session_id}/url HTTP/1.1\r\nHost: {authority}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .and_then(|()| stream.write_all(&body))
        .and_then(|()| stream.flush())
        .map_err(network_error("write WebDriver navigation"))?;
    let mut response = Vec::new();
    let mut bounded = stream.take(64 * 1024 + 1);
    match bounded.read_to_end(&mut response) {
        Ok(_) if response.len() > 64 * 1024 => Err(DesktopError::AdapterUnavailable(
            "WebDriver navigation response exceeded 64 KiB".to_owned(),
        )),
        Ok(_) => validate_webdriver_navigation_response(&response),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) =>
        {
            if response.is_empty() {
                Ok(())
            } else {
                validate_webdriver_navigation_response(&response)
            }
        }
        Err(error) => Err(network_error("read WebDriver navigation")(error)),
    }
}

fn validate_webdriver_navigation_response(response: &[u8]) -> Result<(), DesktopError> {
    let status = response
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .map(str::trim)
        .ok_or_else(|| {
            DesktopError::AdapterUnavailable(
                "WebDriver navigation returned an empty response".to_owned(),
            )
        })?;
    if status.starts_with("HTTP/1.1 200 ")
        || status.starts_with("HTTP/1.1 500 ")
        || status.starts_with("HTTP/1.0 200 ")
        || status.starts_with("HTTP/1.0 500 ")
    {
        Ok(())
    } else {
        Err(DesktopError::AdapterUnavailable(format!(
            "WebDriver rejected the navigation command: {status}"
        )))
    }
}

fn network_error(operation: &'static str) -> impl FnOnce(std::io::Error) -> DesktopError {
    move |error| DesktopError::AdapterUnavailable(format!("{operation} failed: {error}"))
}

struct BrowserFixture {
    address: String,
    submitted_target: Arc<Mutex<Option<String>>>,
    redirect_target: Arc<Mutex<Option<String>>>,
    redirect_source_observed: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl BrowserFixture {
    fn start(port: u16) -> Result<Self, DesktopError> {
        let listener =
            TcpListener::bind(("127.0.0.1", port)).map_err(network_error("bind fixture"))?;
        listener
            .set_nonblocking(true)
            .map_err(network_error("configure fixture"))?;
        let address = listener
            .local_addr()
            .map_err(network_error("read fixture address"))?
            .to_string();
        let submitted_target = Arc::new(Mutex::new(None));
        let redirect_target = Arc::new(Mutex::new(None));
        let redirect_source_observed = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_submitted = Arc::clone(&submitted_target);
        let thread_redirect = Arc::clone(&redirect_target);
        let thread_redirect_observed = Arc::clone(&redirect_source_observed);
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        serve_fixture(
                            stream,
                            &thread_submitted,
                            &thread_redirect,
                            &thread_redirect_observed,
                        );
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            address,
            submitted_target,
            redirect_target,
            redirect_source_observed,
            stop,
            thread: Some(thread),
        })
    }

    fn origin(&self) -> String {
        format!("http://{}", self.address)
    }

    fn submitted_target(&self) -> Result<Option<String>, DesktopError> {
        self.submitted_target
            .lock()
            .map(|value| value.clone())
            .map_err(|_| DesktopError::Integrity("fixture submission lock was poisoned".to_owned()))
    }

    fn set_redirect_target(&self, target: String) -> Result<(), DesktopError> {
        self.redirect_source_observed
            .store(false, Ordering::Release);
        self.redirect_target
            .lock()
            .map(|mut value| *value = Some(target))
            .map_err(|_| DesktopError::Integrity("fixture redirect lock was poisoned".to_owned()))
    }

    fn require_redirect_source(&self, timeout: Duration) -> Result<(), DesktopError> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.redirect_source_observed.load(Ordering::Acquire) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Err(DesktopError::AdapterUnavailable(
            "Edge did not reach the loopback redirect source".to_owned(),
        ))
    }
}

impl Drop for BrowserFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(&self.address);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_fixture(
    mut stream: TcpStream,
    submitted_target: &Arc<Mutex<Option<String>>>,
    redirect_target: &Arc<Mutex<Option<String>>>,
    redirect_source_observed: &Arc<AtomicBool>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => return,
            Ok(read) => request.extend_from_slice(&buffer[..read]),
        }
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if request.len() > 64 * 1024 {
            return;
        }
    }
    let target = match std::str::from_utf8(&request)
        .ok()
        .and_then(|request| request.lines().next())
        .and_then(|line| line.split_whitespace().nth(1))
    {
        Some(value) => value,
        None => return,
    };
    if target.starts_with("/redirect") {
        redirect_source_observed.store(true, Ordering::Release);
        let location = redirect_target
            .lock()
            .ok()
            .and_then(|value| value.clone())
            .unwrap_or_else(|| "http://192.0.2.1/blocked".to_owned());
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\
             Connection: close\r\n\r\n"
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
        return;
    }
    if target.starts_with("/submitted?") {
        if let Ok(mut value) = submitted_target.lock() {
            *value = Some(target.to_owned());
        }
    }
    let body: &[u8] = if target.starts_with("/form") {
        br#"<!doctype html><html><body><form action="/submitted" method="get"><input id="text" name="text"><select id="choice" name="choice"><option value="alpha">Alpha</option><option value="beta">Beta</option></select><button id="submit" type="submit">Submit</button></form></body></html>"#
    } else {
        b"submitted"
    };
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn now_unix_milliseconds() -> Result<u64, DesktopError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            DesktopError::AdapterUnavailable(format!("system clock failed: {error}"))
        })?;
    u64::try_from(elapsed.as_millis())
        .map_err(|_| DesktopError::AdapterUnavailable("system clock overflow".to_owned()))
}

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn new(label: &str) -> Result<Self, DesktopError> {
        let path = std::env::temp_dir().join(format!("{label}-{}", std::process::id()));
        std::fs::create_dir(&path).map_err(|error| DesktopError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
        Ok(Self(path))
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonschema::{Draft, JSONSchema};

    #[test]
    fn terminal_report_matches_published_schema() {
        let schema_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../schemas/desktop/windows-webdriver-post-activation-self-test-report.schema.json",
        );
        let schema: serde_json::Value =
            serde_json::from_slice(&std::fs::read(schema_path).unwrap_or_else(|error| {
                panic!("post-activation report schema read failed: {error}")
            }))
            .unwrap_or_else(|error| panic!("post-activation report schema parse failed: {error}"));
        let compiled = JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema)
            .unwrap_or_else(|error| {
                panic!("post-activation report schema compile failed: {error}")
            });
        let instance = serde_json::to_value(WindowsWebDriverPostActivationSelfTestReport {
            schema_version: 1,
            activation_chain_head: fixed_hash(1),
            activation_replay_rejected: true,
            type_passed: true,
            select_passed: true,
            click_passed: true,
            direct_ipv4_blocked: true,
            dns_blocked: true,
            redirect_blocked: true,
        })
        .unwrap_or_else(|error| panic!("post-activation report serialization failed: {error}"));
        assert!(
            compiled.is_valid(&instance),
            "terminal report did not match its published schema"
        );
    }
}
