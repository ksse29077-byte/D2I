use crate::windows_binding::WINDOWS_WFP_LOOPBACK_PROVIDER_ID;
use crate::{
    hash_value, sha256_bytes, validate_hash, validate_text, verify_windows_wfp_browser_egress,
    DesktopError, WindowsEdgeDriverPin, WindowsWfpBrowserEgressObservation,
    WindowsWfpBrowserEgressPolicy,
};
use d2i_browser_research::ZERO_HASH as RESEARCH_ZERO_HASH;
use d2i_windows_host::{installed_process_ids_by_name, process_peak_working_set_bytes};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{
    Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream, UdpSocket,
};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MIN_OBSERVATION_MS: u64 = 1_000;
const MAX_OBSERVATION_MS: u64 = 10_000;
const MAX_TOTAL_TEST_MS: u64 = 120_000;
const CONNECTION_READ_MS: u64 = 250;
const MAX_TEST_HTTP_BYTES: usize = 16 * 1024;
const MAX_CONNECTIONS: usize = 64;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const DNS_PROBE_HOST: &str = "d2i-wfp-self-test.invalid";

/// Expected disposition of one functional network probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsWfpProbeDisposition {
    Passed,
    Blocked,
    ExplicitlyBlocked,
}

/// Bounded result for one control, positive, or negative browser probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsWfpNetworkProbe {
    pub probe_id: String,
    pub target: Option<String>,
    pub disposition: WindowsWfpProbeDisposition,
    pub request_observed: bool,
    pub page_nonce_verified: bool,
    pub elapsed_ms: u64,
    pub detail_hash: String,
}

/// Non-sensitive outcome assigned to one accepted probe-server connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsWfpConnectionOutcome {
    IdleTimeout,
    IdleClosed,
    MalformedPartial,
    MalformedRequest,
    UnexpectedRequest,
    ValidRequest,
    ResponseError,
}

/// Monotonic timing and classification for one bounded connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsWfpConnectionEvent {
    pub sequence: u64,
    pub peer_address: String,
    pub accepted_after_ms: u64,
    pub first_byte_after_ms: Option<u64>,
    pub request_complete_after_ms: Option<u64>,
    pub response_complete_after_ms: Option<u64>,
    pub bytes_read: u64,
    pub outcome: WindowsWfpConnectionOutcome,
    pub detail_hash: String,
}

/// Aggregate connection observations for one IP-family listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsWfpProbeServerTelemetry {
    pub address_family: String,
    pub total_connections: u64,
    pub idle_connections: u64,
    pub malformed_connections: u64,
    pub valid_requests: u64,
    pub events: Vec<WindowsWfpConnectionEvent>,
}

/// Explicit cleanup state captured before a successful report is emitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsWfpSelfTestCleanup {
    pub browser_session_closed: bool,
    pub edge_driver_exited: bool,
    pub temporary_profile_removed: bool,
}

/// Functional proof that the pinned Edge image can reach loopback but cannot
/// reach any configured non-loopback probe while the exact WFP policy is live.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsWfpBrowserEgressSelfTestReport {
    pub schema_version: u32,
    pub test_id: String,
    pub activation_challenge: String,
    pub probe_nonce: String,
    pub browser_session_id: String,
    pub started_at_unix_ms: u64,
    pub completed_at_unix_ms: u64,
    pub elapsed_ms: u64,
    pub total_deadline_ms: u64,
    pub blocked_observation_ms: u64,
    pub wfp_observation: WindowsWfpBrowserEgressObservation,
    pub edge_driver_pin_hash: String,
    pub browser_version: String,
    pub browser_executable_hash: String,
    pub driver_version: String,
    pub driver_executable_hash: String,
    pub ipv4_control: WindowsWfpNetworkProbe,
    pub ipv4_loopback: WindowsWfpNetworkProbe,
    pub ipv4_direct_ip: WindowsWfpNetworkProbe,
    pub ipv4_dns: WindowsWfpNetworkProbe,
    pub ipv4_redirect: WindowsWfpNetworkProbe,
    pub ipv6_control: Option<WindowsWfpNetworkProbe>,
    pub ipv6_loopback: WindowsWfpNetworkProbe,
    pub ipv6_non_loopback: WindowsWfpNetworkProbe,
    pub ipv4_telemetry: WindowsWfpProbeServerTelemetry,
    pub ipv6_telemetry: WindowsWfpProbeServerTelemetry,
    pub cleanup: WindowsWfpSelfTestCleanup,
    pub passed: bool,
}

/// Read-only proof that pinned Edge observed only bounded loopback snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsLoopbackSnapshotObservationV1 {
    pub schema_version: u32,
    pub observation_id: String,
    pub observed_page_count: u32,
    pub requested_url_hashes: Vec<String>,
    pub observed_url_hashes: Vec<String>,
    pub title_hashes: Vec<String>,
    pub page_source_hashes: Vec<String>,
    pub external_navigation_count: u32,
    pub browser_download_count: u32,
    pub browser_form_submit_count: u32,
    pub elapsed_microseconds: u64,
    pub peak_edge_memory_bytes: u64,
    pub cleanup: WindowsWfpSelfTestCleanup,
    pub complete: bool,
    pub observation_sha256: String,
}

impl WindowsLoopbackSnapshotObservationV1 {
    pub fn validate(&self) -> Result<(), DesktopError> {
        validate_hash(
            &self.observation_sha256,
            "loopback snapshot observation hash",
        )?;
        let count = usize::try_from(self.observed_page_count).map_err(|_| {
            DesktopError::Invalid("loopback snapshot page count overflow".to_owned())
        })?;
        if self.schema_version != 1
            || !(1..=24).contains(&count)
            || self.requested_url_hashes.len() != count
            || self.observed_url_hashes.len() != count
            || self.title_hashes.len() != count
            || self.page_source_hashes.len() != count
            || self.external_navigation_count != 0
            || self.browser_download_count != 0
            || self.browser_form_submit_count != 0
            || self.elapsed_microseconds == 0
            || self.peak_edge_memory_bytes == 0
            || !self.cleanup.browser_session_closed
            || !self.cleanup.edge_driver_exited
            || !self.cleanup.temporary_profile_removed
            || !self.complete
        {
            return Err(DesktopError::Integrity(
                "loopback snapshot browser observation is incomplete".to_owned(),
            ));
        }
        let expected = hash_loopback_observation(self)?;
        if expected != self.observation_sha256 {
            return Err(DesktopError::Integrity(
                "loopback snapshot observation hash differs".to_owned(),
            ));
        }
        Ok(())
    }
}

impl WindowsWfpBrowserEgressSelfTestReport {
    /// Validates the v2 report and its fail-closed pass calculation.
    pub fn validate(&self) -> Result<(), DesktopError> {
        if self.schema_version != 2 {
            return Err(DesktopError::Invalid(
                "WFP browser-egress self-test report schema_version must be 2".to_owned(),
            ));
        }
        validate_text(&self.test_id, "WFP self-test ID")?;
        validate_challenge(&self.activation_challenge)?;
        validate_nonce(&self.probe_nonce)?;
        validate_text(&self.browser_session_id, "WFP self-test browser session")?;
        if self.started_at_unix_ms == 0
            || self.completed_at_unix_ms < self.started_at_unix_ms
            || self.elapsed_ms > self.total_deadline_ms
            || self.total_deadline_ms == 0
            || self.total_deadline_ms > MAX_TOTAL_TEST_MS
            || !(MIN_OBSERVATION_MS..=MAX_OBSERVATION_MS).contains(&self.blocked_observation_ms)
        {
            return Err(DesktopError::Invalid(
                "WFP self-test report timing is invalid".to_owned(),
            ));
        }
        validate_wfp_observation(&self.wfp_observation)?;
        validate_hash(&self.edge_driver_pin_hash, "EdgeDriver pin hash")?;
        validate_report_version(&self.browser_version, "Edge browser version")?;
        validate_hash(
            &self.browser_executable_hash,
            "Edge browser executable hash",
        )?;
        validate_report_version(&self.driver_version, "EdgeDriver version")?;
        validate_hash(&self.driver_executable_hash, "EdgeDriver executable hash")?;
        for probe in [
            &self.ipv4_control,
            &self.ipv4_loopback,
            &self.ipv4_direct_ip,
            &self.ipv4_dns,
            &self.ipv4_redirect,
            &self.ipv6_loopback,
            &self.ipv6_non_loopback,
        ] {
            validate_probe(probe)?;
        }
        if let Some(probe) = &self.ipv6_control {
            validate_probe(probe)?;
        }
        validate_telemetry(&self.ipv4_telemetry, "ipv4")?;
        validate_telemetry(&self.ipv6_telemetry, "ipv6")?;
        let ipv6_negative = match self.ipv6_non_loopback.disposition {
            WindowsWfpProbeDisposition::Blocked => {
                self.ipv6_control.as_ref().is_some_and(probe_passed)
                    && !self.ipv6_non_loopback.request_observed
            }
            WindowsWfpProbeDisposition::ExplicitlyBlocked => {
                self.ipv6_control.is_none()
                    && self.ipv6_non_loopback.target.is_none()
                    && !self.ipv6_non_loopback.request_observed
            }
            WindowsWfpProbeDisposition::Passed => false,
        };
        let expected_passed = probe_passed(&self.ipv4_control)
            && probe_passed(&self.ipv4_loopback)
            && probe_blocked(&self.ipv4_direct_ip)
            && probe_blocked(&self.ipv4_dns)
            && probe_blocked(&self.ipv4_redirect)
            && probe_passed(&self.ipv6_loopback)
            && ipv6_negative
            && self.cleanup.browser_session_closed
            && self.cleanup.edge_driver_exited
            && self.cleanup.temporary_profile_removed;
        if !self.passed || self.passed != expected_passed {
            return Err(DesktopError::Integrity(
                "WFP self-test pass flag differs from required v2 observations".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns the canonical hash of this successful operational report.
    pub fn report_hash(&self) -> Result<String, DesktopError> {
        self.validate()?;
        hash_value(self)
    }
}

/// Runs a fresh pinned Edge session against dual-stack loopback and bounded
/// IPv4/IPv6, DNS, and redirect negative probes.
pub fn run_windows_wfp_browser_egress_self_test(
    policy: &WindowsWfpBrowserEgressPolicy,
    pin: &WindowsEdgeDriverPin,
    activation_challenge: &str,
    blocked_observation_ms: u64,
) -> Result<WindowsWfpBrowserEgressSelfTestReport, DesktopError> {
    if !(MIN_OBSERVATION_MS..=MAX_OBSERVATION_MS).contains(&blocked_observation_ms) {
        return Err(DesktopError::Invalid(format!(
            "WFP observation window must be between {MIN_OBSERVATION_MS} and \
             {MAX_OBSERVATION_MS} milliseconds"
        )));
    }
    validate_challenge(activation_challenge)?;
    policy.validate()?;
    pin.verify()?;
    if policy.browser_executable != pin.browser_executable
        || policy.browser_executable_hash != pin.browser_executable_hash
    {
        return Err(DesktopError::Integrity(
            "WFP policy and EdgeDriver pin identify different browser images".to_owned(),
        ));
    }

    let wall_started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| DesktopError::Precondition(format!("system clock is invalid: {error}")))?;
    let monotonic_started = Instant::now();
    let total_deadline_ms = blocked_observation_ms
        .saturating_mul(8)
        .saturating_add(30_000)
        .min(MAX_TOTAL_TEST_MS);
    let deadline = monotonic_started + Duration::from_millis(total_deadline_ms);
    let policy_observation = verify_windows_wfp_browser_egress(policy)?;
    let pin_hash = hash_value(pin)?;
    let nonce = random_nonce()?;
    let test_id = format!("wfp-self-test:{nonce}");

    let ipv4_server = ProbeServer::start(AddressFamily::Ipv4, monotonic_started)?;
    let ipv6_server = ProbeServer::start(AddressFamily::Ipv6, monotonic_started)?;
    let non_loopback_v4 = discover_non_loopback_ipv4()?;
    let non_loopback_v6 = discover_non_loopback_ipv6()?;
    let observation = Duration::from_millis(blocked_observation_ms);

    let v4_loopback_host = format!("127.0.0.1:{}", ipv4_server.port());
    let v4_non_loopback_host = format!("{non_loopback_v4}:{}", ipv4_server.port());
    let v6_loopback_host = format!("[::1]:{}", ipv6_server.port());
    let v4_control_path = probe_path("control-v4", &nonce);
    let v4_loopback_path = probe_path("loopback-v4", &nonce);
    let v4_direct_path = probe_path("direct-v4", &nonce);
    let v4_dns_path = probe_path("dns-v4", &nonce);
    let redirect_source_path = probe_path("redirect-source-v4", &nonce);
    let redirect_target_path = probe_path("redirect-target-v4", &nonce);
    let v6_loopback_path = probe_path("loopback-v6", &nonce);
    ipv4_server.add_nonce_route(&v4_control_path, &v4_non_loopback_host, &nonce)?;
    ipv4_server.add_nonce_route(&v4_loopback_path, &v4_loopback_host, &nonce)?;
    ipv4_server.add_nonce_route(&v4_direct_path, &v4_non_loopback_host, &nonce)?;
    ipv4_server.add_nonce_route(
        &v4_dns_path,
        &format!("{DNS_PROBE_HOST}:{}", ipv4_server.port()),
        &nonce,
    )?;
    ipv4_server.add_nonce_route(&redirect_target_path, &v4_non_loopback_host, &nonce)?;
    ipv4_server.add_redirect_route(
        &redirect_source_path,
        &v4_loopback_host,
        &format!("http://{v4_non_loopback_host}{redirect_target_path}"),
    )?;
    ipv6_server.add_nonce_route(&v6_loopback_path, &v6_loopback_host, &nonce)?;

    let control_started = Instant::now();
    send_control_request(
        SocketAddr::V4(SocketAddrV4::new(non_loopback_v4, ipv4_server.port())),
        &v4_non_loopback_host,
        &v4_control_path,
        &nonce,
        remaining(deadline)?,
    )?;
    require_observed(
        &ipv4_server,
        &v4_control_path,
        bounded_wait(deadline, observation)?,
        "IPv4 non-loopback control",
    )?;
    let ipv4_control = passed_probe(
        "ipv4_control",
        Some(format!("http://{v4_non_loopback_host}{v4_control_path}")),
        false,
        elapsed_ms(control_started),
        "ordinary control process reached the non-loopback listener",
    );

    let mut ipv6_control = None;
    let mut v6_non_loopback_path = None;
    let mut v6_non_loopback_host = None;
    if let Some(address) = non_loopback_v6 {
        let host = format!("[{address}]:{}", ipv6_server.port());
        let control_path = probe_path("control-v6", &nonce);
        let blocked_path = probe_path("direct-v6", &nonce);
        ipv6_server.add_nonce_route(&control_path, &host, &nonce)?;
        ipv6_server.add_nonce_route(&blocked_path, &host, &nonce)?;
        let started = Instant::now();
        send_control_request(
            SocketAddr::V6(SocketAddrV6::new(address, ipv6_server.port(), 0, 0)),
            &host,
            &control_path,
            &nonce,
            remaining(deadline)?,
        )?;
        require_observed(
            &ipv6_server,
            &control_path,
            bounded_wait(deadline, observation)?,
            "IPv6 non-loopback control",
        )?;
        ipv6_control = Some(passed_probe(
            "ipv6_control",
            Some(format!("http://{host}{control_path}")),
            false,
            elapsed_ms(started),
            "ordinary control process reached the IPv6 non-loopback listener",
        ));
        v6_non_loopback_path = Some(blocked_path);
        v6_non_loopback_host = Some(host);
    }

    let mut driver =
        ManagedEdgeDriver::start(pin, &nonce, non_loopback_v4, remaining_ms(deadline)?)?;
    driver.create_session(pin)?;
    let browser_session_id = driver.session_id()?.to_owned();

    let v4_positive_started = Instant::now();
    let v4_loopback_url = format!("http://{v4_loopback_host}{v4_loopback_path}");
    driver.navigate(&v4_loopback_url)?;
    require_observed(
        &ipv4_server,
        &v4_loopback_path,
        bounded_wait(deadline, observation)?,
        "Edge IPv4 loopback",
    )?;
    driver.require_page_nonce(&nonce, bounded_wait(deadline, observation)?)?;
    let ipv4_loopback = passed_probe(
        "ipv4_loopback",
        Some(v4_loopback_url),
        true,
        elapsed_ms(v4_positive_started),
        "Edge delivered the nonce request and rendered the nonce response over IPv4 loopback",
    );

    let v6_positive_started = Instant::now();
    let v6_loopback_url = format!("http://{v6_loopback_host}{v6_loopback_path}");
    driver.navigate(&v6_loopback_url)?;
    require_observed(
        &ipv6_server,
        &v6_loopback_path,
        bounded_wait(deadline, observation)?,
        "Edge IPv6 loopback",
    )?;
    driver.require_page_nonce(&nonce, bounded_wait(deadline, observation)?)?;
    let ipv6_loopback = passed_probe(
        "ipv6_loopback",
        Some(v6_loopback_url),
        true,
        elapsed_ms(v6_positive_started),
        "Edge delivered the nonce request and rendered the nonce response over IPv6 loopback",
    );

    let direct_started = Instant::now();
    let direct_url = format!("http://{v4_non_loopback_host}{v4_direct_path}");
    driver.navigate_tolerant(&direct_url);
    require_not_observed(
        &ipv4_server,
        &v4_direct_path,
        bounded_wait(deadline, observation)?,
        "Edge IPv4 direct-IP egress",
    )?;
    let ipv4_direct_ip = blocked_probe(
        "ipv4_direct_ip",
        Some(direct_url),
        elapsed_ms(direct_started),
        "Edge direct IPv4 request was not delivered during the observation window",
    );

    let dns_started = Instant::now();
    let dns_url = format!(
        "http://{DNS_PROBE_HOST}:{}{v4_dns_path}",
        ipv4_server.port()
    );
    driver.navigate_tolerant(&dns_url);
    require_not_observed(
        &ipv4_server,
        &v4_dns_path,
        bounded_wait(deadline, observation)?,
        "Edge DNS-resolved IPv4 egress",
    )?;
    let ipv4_dns = blocked_probe(
        "ipv4_dns",
        Some(dns_url),
        elapsed_ms(dns_started),
        "Edge hostname mapped to the reachable IPv4 endpoint was not delivered",
    );

    let redirect_started = Instant::now();
    let redirect_url = format!("http://{v4_loopback_host}{redirect_source_path}");
    driver.navigate_tolerant(&redirect_url);
    require_observed(
        &ipv4_server,
        &redirect_source_path,
        bounded_wait(deadline, observation)?,
        "Edge loopback redirect source",
    )?;
    require_not_observed(
        &ipv4_server,
        &redirect_target_path,
        bounded_wait(deadline, observation)?,
        "Edge redirected IPv4 egress",
    )?;
    let ipv4_redirect = blocked_probe(
        "ipv4_redirect",
        Some(redirect_url),
        elapsed_ms(redirect_started),
        "Edge received the loopback redirect but did not deliver its non-loopback target",
    );

    let ipv6_non_loopback =
        if let (Some(host), Some(path)) = (v6_non_loopback_host, v6_non_loopback_path) {
            let started = Instant::now();
            let url = format!("http://{host}{path}");
            driver.navigate_tolerant(&url);
            require_not_observed(
                &ipv6_server,
                &path,
                bounded_wait(deadline, observation)?,
                "Edge IPv6 non-loopback egress",
            )?;
            blocked_probe(
                "ipv6_non_loopback",
                Some(url),
                elapsed_ms(started),
                "Edge direct IPv6 request was not delivered during the observation window",
            )
        } else {
            WindowsWfpNetworkProbe {
                probe_id: "ipv6_non_loopback".to_owned(),
                target: None,
                disposition: WindowsWfpProbeDisposition::ExplicitlyBlocked,
                request_observed: false,
                page_nonce_verified: false,
                elapsed_ms: 0,
                detail_hash: sha256_bytes(
                    format!(
                        "no routable host IPv6 address; exact catch-all block filter {}",
                        policy_observation.filter_keys[3]
                    )
                    .as_bytes(),
                ),
            }
        };

    let final_observation = verify_windows_wfp_browser_egress(policy)?;
    if final_observation != policy_observation {
        return Err(DesktopError::Integrity(
            "WFP object identity changed during the browser egress self-test".to_owned(),
        ));
    }
    let cleanup = driver.shutdown()?;
    if !cleanup.browser_session_closed
        || !cleanup.edge_driver_exited
        || !cleanup.temporary_profile_removed
    {
        return Err(DesktopError::Integrity(
            "Edge self-test cleanup did not complete".to_owned(),
        ));
    }
    let completed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| DesktopError::Precondition(format!("system clock is invalid: {error}")))?;
    let ipv4_telemetry = ipv4_server.telemetry()?;
    let ipv6_telemetry = ipv6_server.telemetry()?;
    let report = WindowsWfpBrowserEgressSelfTestReport {
        schema_version: 2,
        test_id,
        activation_challenge: activation_challenge.to_owned(),
        probe_nonce: nonce,
        browser_session_id,
        started_at_unix_ms: duration_ms(wall_started),
        completed_at_unix_ms: duration_ms(completed_at),
        elapsed_ms: elapsed_ms(monotonic_started),
        total_deadline_ms,
        blocked_observation_ms,
        wfp_observation: policy_observation,
        edge_driver_pin_hash: pin_hash,
        browser_version: pin.browser_version.clone(),
        browser_executable_hash: pin.browser_executable_hash.clone(),
        driver_version: pin.driver_version.clone(),
        driver_executable_hash: pin.driver_executable_hash.clone(),
        ipv4_control,
        ipv4_loopback,
        ipv4_direct_ip,
        ipv4_dns,
        ipv4_redirect,
        ipv6_control,
        ipv6_loopback,
        ipv6_non_loopback,
        ipv4_telemetry,
        ipv6_telemetry,
        cleanup,
        passed: true,
    };
    report.validate()?;
    Ok(report)
}

/// Starts a fresh pinned Edge profile, observes each closed loopback page once,
/// then removes the session, driver, and profile before returning evidence.
pub fn run_windows_loopback_snapshot_observation(
    pin: &WindowsEdgeDriverPin,
    page_urls: &[String],
    timeout_ms: u64,
) -> Result<WindowsLoopbackSnapshotObservationV1, DesktopError> {
    pin.verify()?;
    if page_urls.is_empty() || page_urls.len() > 24 || !(1_000..=30_000).contains(&timeout_ms) {
        return Err(DesktopError::Invalid(
            "loopback snapshot observation bounds differ".to_owned(),
        ));
    }
    for url in page_urls {
        validate_loopback_snapshot_url(url)?;
    }
    let started = Instant::now();
    let baseline_edge_processes = installed_process_ids_by_name(&["msedge.exe"])
        .map_err(|error| DesktopError::AdapterUnavailable(error.to_string()))?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let nonce = random_nonce()?;
    let non_loopback = discover_non_loopback_ipv4()?;
    let mut edge =
        ManagedEdgeDriver::start(pin, &format!("snapshot-{nonce}"), non_loopback, timeout_ms)?;
    edge.create_session(pin)?;
    let mut peak_edge_memory_bytes = sample_new_edge_peak_memory(&baseline_edge_processes)?;
    let mut requested_url_hashes = Vec::with_capacity(page_urls.len());
    let mut observed_url_hashes = Vec::with_capacity(page_urls.len());
    let mut title_hashes = Vec::with_capacity(page_urls.len());
    let mut page_source_hashes = Vec::with_capacity(page_urls.len());
    for url in page_urls {
        edge.navigate(url)?;
        let (observed_url, title, source) = edge.observe_page(timeout_ms)?;
        peak_edge_memory_bytes =
            peak_edge_memory_bytes.max(sample_new_edge_peak_memory(&baseline_edge_processes)?);
        validate_loopback_snapshot_url(&observed_url)?;
        if source.is_empty() || source.len() > 1024 * 1024 {
            return Err(DesktopError::Integrity(
                "Edge snapshot source is empty or exceeds one MiB".to_owned(),
            ));
        }
        requested_url_hashes.push(sha256_bytes(url.as_bytes()));
        observed_url_hashes.push(sha256_bytes(observed_url.as_bytes()));
        title_hashes.push(sha256_bytes(title.as_bytes()));
        page_source_hashes.push(sha256_bytes(source.as_bytes()));
    }
    let cleanup = edge.shutdown()?;
    let mut report = WindowsLoopbackSnapshotObservationV1 {
        schema_version: 1,
        observation_id: format!("browser-snapshot:{nonce}"),
        observed_page_count: u32::try_from(page_urls.len())
            .map_err(|_| DesktopError::Invalid("snapshot page count overflow".to_owned()))?,
        requested_url_hashes,
        observed_url_hashes,
        title_hashes,
        page_source_hashes,
        external_navigation_count: 0,
        browser_download_count: 0,
        browser_form_submit_count: 0,
        elapsed_microseconds: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        peak_edge_memory_bytes,
        cleanup,
        complete: true,
        observation_sha256: RESEARCH_ZERO_HASH.to_owned(),
    };
    report.observation_sha256 = hash_loopback_observation(&report)?;
    report.validate()?;
    Ok(report)
}

fn sample_new_edge_peak_memory(baseline: &BTreeSet<u32>) -> Result<u64, DesktopError> {
    let current = installed_process_ids_by_name(&["msedge.exe"])
        .map_err(|error| DesktopError::AdapterUnavailable(error.to_string()))?;
    Ok(current
        .into_iter()
        .filter(|process_id| !baseline.contains(process_id))
        .filter_map(|process_id| process_peak_working_set_bytes(process_id).ok())
        .max()
        .unwrap_or(0))
}

fn validate_loopback_snapshot_url(value: &str) -> Result<(), DesktopError> {
    let parsed = url::Url::parse(value)
        .map_err(|_| DesktopError::Invalid("snapshot URL cannot be parsed".to_owned()))?;
    if parsed.scheme() != "http"
        || parsed.username() != ""
        || parsed.password().is_some()
        || !parsed.host().is_some_and(|host| match host {
            url::Host::Ipv4(address) => address.is_loopback(),
            url::Host::Ipv6(address) => address.is_loopback(),
            url::Host::Domain(_) => false,
        })
        || parsed.port().is_none()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(DesktopError::AccessDenied(
            "Edge snapshot URL must be an explicit loopback HTTP route".to_owned(),
        ));
    }
    Ok(())
}

fn hash_loopback_observation(
    report: &WindowsLoopbackSnapshotObservationV1,
) -> Result<String, DesktopError> {
    let mut value =
        serde_json::to_value(report).map_err(|error| DesktopError::Json(error.to_string()))?;
    value["observation_sha256"] = Value::String(RESEARCH_ZERO_HASH.to_owned());
    hash_value(&value)
}

fn validate_probe(probe: &WindowsWfpNetworkProbe) -> Result<(), DesktopError> {
    validate_text(&probe.probe_id, "WFP network probe ID")?;
    if let Some(target) = &probe.target {
        validate_text(target, "WFP network probe target")?;
    }
    validate_hash(&probe.detail_hash, "WFP network probe detail hash")
}

fn probe_passed(probe: &WindowsWfpNetworkProbe) -> bool {
    probe.disposition == WindowsWfpProbeDisposition::Passed
        && probe.request_observed
        && (probe.page_nonce_verified || probe.probe_id.ends_with("control"))
}

fn probe_blocked(probe: &WindowsWfpNetworkProbe) -> bool {
    probe.disposition == WindowsWfpProbeDisposition::Blocked
        && !probe.request_observed
        && !probe.page_nonce_verified
}

fn validate_telemetry(
    telemetry: &WindowsWfpProbeServerTelemetry,
    expected_family: &str,
) -> Result<(), DesktopError> {
    if telemetry.address_family != expected_family
        || telemetry.total_connections != u64::try_from(telemetry.events.len()).unwrap_or(u64::MAX)
        || telemetry.total_connections > u64::try_from(MAX_CONNECTIONS).unwrap_or(u64::MAX)
        || telemetry
            .idle_connections
            .saturating_add(telemetry.malformed_connections)
            .saturating_add(telemetry.valid_requests)
            != telemetry.total_connections
    {
        return Err(DesktopError::Integrity(
            "WFP probe-server telemetry counters are inconsistent".to_owned(),
        ));
    }
    for event in &telemetry.events {
        validate_text(&event.peer_address, "WFP connection peer")?;
        validate_hash(&event.detail_hash, "WFP connection detail hash")?;
        if event.bytes_read > u64::try_from(MAX_TEST_HTTP_BYTES).unwrap_or(u64::MAX) {
            return Err(DesktopError::Invalid(
                "WFP connection event exceeds request bound".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_wfp_observation(
    observation: &WindowsWfpBrowserEgressObservation,
) -> Result<(), DesktopError> {
    if !matches!(observation.schema_version, 2 | 3)
        || observation.provider_id != WINDOWS_WFP_LOOPBACK_PROVIDER_ID
    {
        return Err(DesktopError::Invalid(
            "WFP self-test observation identity is invalid".to_owned(),
        ));
    }
    validate_text(&observation.enforcement_id, "WFP enforcement ID")?;
    validate_hash(&observation.policy_hash, "WFP policy hash")?;
    validate_text(&observation.browser_executable, "WFP browser executable")?;
    validate_hash(
        &observation.browser_executable_hash,
        "WFP browser executable hash",
    )?;
    validate_guid(&observation.provider_key, "WFP provider key")?;
    validate_guid(&observation.sublayer_key, "WFP sublayer key")?;
    for key in &observation.filter_keys {
        validate_guid(key, "WFP filter key")?;
    }
    let verifier_sid_matches_version = match observation.schema_version {
        2 => observation.verifier_sid.starts_with("S-1-15-2-"),
        3 => observation.verifier_sid.starts_with("S-1-5-80-"),
        _ => false,
    };
    if !verifier_sid_matches_version {
        return Err(DesktopError::Invalid(
            "WFP observation verifier SID is invalid".to_owned(),
        ));
    }
    if !observation.policy_owner_sid.starts_with("S-1-") {
        return Err(DesktopError::Invalid(
            "WFP observation policy owner SID is invalid".to_owned(),
        ));
    }
    validate_hash(
        &observation.engine_security_descriptor_hash,
        "WFP engine security descriptor hash",
    )?;
    validate_hash(
        &observation.object_security_descriptor_hash,
        "WFP object security descriptor hash",
    )?;
    Ok(())
}

fn validate_guid(value: &str, field: &str) -> Result<(), DesktopError> {
    let valid = value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        });
    if !valid {
        return Err(DesktopError::Invalid(format!(
            "{field} is not a canonical GUID"
        )));
    }
    Ok(())
}

fn validate_report_version(value: &str, field: &str) -> Result<(), DesktopError> {
    validate_text(value, field)?;
    let mut count = 0_usize;
    for part in value.split('.') {
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(DesktopError::Invalid(format!(
                "{field} must contain four decimal components"
            )));
        }
        count = count.saturating_add(1);
    }
    if count != 4 {
        return Err(DesktopError::Invalid(format!(
            "{field} must contain four decimal components"
        )));
    }
    Ok(())
}

fn validate_challenge(value: &str) -> Result<(), DesktopError> {
    validate_text(value, "activation challenge")?;
    if value.len() < 16
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(DesktopError::Invalid(
            "activation challenge must be a 16..=128 byte safe token".to_owned(),
        ));
    }
    Ok(())
}

fn validate_nonce(value: &str) -> Result<(), DesktopError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DesktopError::Invalid(
            "WFP probe nonce must be 32-byte hexadecimal".to_owned(),
        ));
    }
    Ok(())
}

fn random_nonce() -> Result<String, DesktopError> {
    let bytes = d2i_windows_host::secure_random_bytes::<32>().map_err(|error| {
        DesktopError::AdapterUnavailable(format!("WFP probe nonce generation failed: {error}"))
    })?;
    Ok(crate::hex_encode(&bytes))
}

fn probe_path(label: &str, nonce: &str) -> String {
    format!("/d2i-{label}-{nonce}")
}

fn discover_non_loopback_ipv4() -> Result<Ipv4Addr, DesktopError> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(|error| {
        DesktopError::AdapterUnavailable(format!(
            "non-loopback route discovery socket failed: {error}"
        ))
    })?;
    socket
        .connect((Ipv4Addr::new(192, 0, 2, 1), 9))
        .map_err(|error| {
            DesktopError::AdapterUnavailable(format!(
                "non-loopback route discovery failed: {error}"
            ))
        })?;
    match socket.local_addr().map_err(|error| {
        DesktopError::AdapterUnavailable(format!(
            "non-loopback local address discovery failed: {error}"
        ))
    })? {
        SocketAddr::V4(address)
            if !address.ip().is_loopback() && !address.ip().is_unspecified() =>
        {
            Ok(*address.ip())
        }
        _ => Err(DesktopError::AdapterUnavailable(
            "host has no routable non-loopback IPv4 address for WFP testing".to_owned(),
        )),
    }
}

fn discover_non_loopback_ipv6() -> Result<Option<Ipv6Addr>, DesktopError> {
    let socket = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).map_err(|error| {
        DesktopError::AdapterUnavailable(format!("IPv6 route discovery socket failed: {error}"))
    })?;
    if socket
        .connect((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 9))
        .is_err()
    {
        return Ok(None);
    }
    match socket.local_addr().map_err(|error| {
        DesktopError::AdapterUnavailable(format!("IPv6 local address discovery failed: {error}"))
    })? {
        SocketAddr::V6(address)
            if !address.ip().is_loopback()
                && !address.ip().is_unspecified()
                && !address.ip().is_unicast_link_local() =>
        {
            Ok(Some(*address.ip()))
        }
        _ => Ok(None),
    }
}

fn send_control_request(
    address: SocketAddr,
    host: &str,
    path: &str,
    nonce: &str,
    timeout: Duration,
) -> Result<(), DesktopError> {
    let mut stream = TcpStream::connect_timeout(&address, timeout).map_err(|error| {
        DesktopError::AdapterUnavailable(format!("control connection failed: {error}"))
    })?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|error| {
            DesktopError::AdapterUnavailable(format!("control timeout setup failed: {error}"))
        })?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|error| {
            DesktopError::AdapterUnavailable(format!("control request failed: {error}"))
        })?;
    let mut response = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer).map_err(|error| {
            DesktopError::AdapterUnavailable(format!("control response failed: {error}"))
        })?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&buffer[..read]);
        if response.len() > MAX_TEST_HTTP_BYTES {
            return Err(DesktopError::Invalid(
                "control response exceeds its byte bound".to_owned(),
            ));
        }
    }
    if !response.starts_with(b"HTTP/1.1 200") || !contains_bytes(&response, nonce.as_bytes()) {
        return Err(DesktopError::Integrity(
            "control endpoint returned an unexpected response".to_owned(),
        ));
    }
    Ok(())
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    fn label(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

#[derive(Clone)]
enum RouteResponse {
    Nonce(String),
    Redirect(String),
}

#[derive(Clone)]
struct ProbeRoute {
    expected_host: String,
    response: RouteResponse,
}

struct ProbeState {
    routes: Mutex<BTreeMap<String, ProbeRoute>>,
    observed_paths: Mutex<BTreeSet<String>>,
    events: Mutex<Vec<WindowsWfpConnectionEvent>>,
    fatal_error: Mutex<Option<String>>,
    next_sequence: AtomicU64,
    active_connections: AtomicUsize,
}

struct ProbeServer {
    family: AddressFamily,
    port: u16,
    state: Arc<ProbeState>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ProbeServer {
    fn start(family: AddressFamily, test_started: Instant) -> Result<Self, DesktopError> {
        let address = match family {
            AddressFamily::Ipv4 => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            AddressFamily::Ipv6 => {
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
            }
        };
        let listener = TcpListener::bind(address).map_err(|error| {
            DesktopError::AdapterUnavailable(format!(
                "{} WFP self-test HTTP listener failed: {error}",
                family.label()
            ))
        })?;
        listener.set_nonblocking(true).map_err(|error| {
            DesktopError::AdapterUnavailable(format!(
                "{} WFP self-test listener mode failed: {error}",
                family.label()
            ))
        })?;
        let port = listener
            .local_addr()
            .map_err(|error| {
                DesktopError::AdapterUnavailable(format!(
                    "{} WFP self-test listener address failed: {error}",
                    family.label()
                ))
            })?
            .port();
        let state = Arc::new(ProbeState {
            routes: Mutex::new(BTreeMap::new()),
            observed_paths: Mutex::new(BTreeSet::new()),
            events: Mutex::new(Vec::new()),
            fatal_error: Mutex::new(None),
            next_sequence: AtomicU64::new(0),
            active_connections: AtomicUsize::new(0),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let thread_state = Arc::clone(&state);
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, peer)) => {
                        let sequence = thread_state
                            .next_sequence
                            .fetch_add(1, Ordering::AcqRel)
                            .saturating_add(1);
                        if sequence > u64::try_from(MAX_CONNECTIONS).unwrap_or(u64::MAX) {
                            record_fatal(
                                &thread_state,
                                "WFP probe-server connection bound exceeded".to_owned(),
                            );
                            break;
                        }
                        thread_state
                            .active_connections
                            .fetch_add(1, Ordering::AcqRel);
                        let connection_state = Arc::clone(&thread_state);
                        thread::spawn(move || {
                            observe_connection(
                                stream,
                                peer,
                                sequence,
                                test_started,
                                &connection_state,
                            );
                            connection_state
                                .active_connections
                                .fetch_sub(1, Ordering::AcqRel);
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => {
                        record_fatal(
                            &thread_state,
                            format!("WFP self-test listener accept failed: {error}"),
                        );
                        break;
                    }
                }
            }
        });
        Ok(Self {
            family,
            port,
            state,
            stop,
            thread: Some(thread),
        })
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn add_nonce_route(&self, path: &str, host: &str, nonce: &str) -> Result<(), DesktopError> {
        self.add_route(path, host, RouteResponse::Nonce(nonce.to_owned()))
    }

    fn add_redirect_route(
        &self,
        path: &str,
        host: &str,
        location: &str,
    ) -> Result<(), DesktopError> {
        self.add_route(path, host, RouteResponse::Redirect(location.to_owned()))
    }

    fn add_route(
        &self,
        path: &str,
        host: &str,
        response: RouteResponse,
    ) -> Result<(), DesktopError> {
        if !path.starts_with('/') || path.len() > 2048 || host.is_empty() || host.len() > 512 {
            return Err(DesktopError::Invalid(
                "WFP probe-server route is outside its bounds".to_owned(),
            ));
        }
        let inserted = self
            .state
            .routes
            .lock()
            .map_err(|_| DesktopError::Integrity("WFP probe routes are poisoned".to_owned()))?
            .insert(
                path.to_owned(),
                ProbeRoute {
                    expected_host: host.to_owned(),
                    response,
                },
            )
            .is_none();
        if !inserted {
            return Err(DesktopError::Invalid(
                "WFP probe-server route is duplicated".to_owned(),
            ));
        }
        Ok(())
    }

    fn wait_for_path(&self, path: &str, timeout: Duration) -> Result<bool, DesktopError> {
        let deadline = Instant::now() + timeout;
        loop {
            self.check_fatal()?;
            if self
                .state
                .observed_paths
                .lock()
                .map_err(|_| {
                    DesktopError::Integrity("WFP probe observations are poisoned".to_owned())
                })?
                .contains(path)
            {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                self.check_fatal()?;
                return Ok(false);
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn check_fatal(&self) -> Result<(), DesktopError> {
        if let Some(message) = self
            .state
            .fatal_error
            .lock()
            .map_err(|_| {
                DesktopError::Integrity("WFP probe-server fatal state is poisoned".to_owned())
            })?
            .as_ref()
        {
            return Err(DesktopError::AdapterUnavailable(message.clone()));
        }
        Ok(())
    }

    fn telemetry(&self) -> Result<WindowsWfpProbeServerTelemetry, DesktopError> {
        self.check_fatal()?;
        let mut events = self
            .state
            .events
            .lock()
            .map_err(|_| DesktopError::Integrity("WFP probe events are poisoned".to_owned()))?
            .clone();
        events.sort_by_key(|event| event.sequence);
        let idle_connections = events
            .iter()
            .filter(|event| {
                matches!(
                    event.outcome,
                    WindowsWfpConnectionOutcome::IdleTimeout
                        | WindowsWfpConnectionOutcome::IdleClosed
                )
            })
            .count();
        let valid_requests = events
            .iter()
            .filter(|event| event.outcome == WindowsWfpConnectionOutcome::ValidRequest)
            .count();
        let malformed_connections = events
            .len()
            .saturating_sub(idle_connections)
            .saturating_sub(valid_requests);
        Ok(WindowsWfpProbeServerTelemetry {
            address_family: self.family.label().to_owned(),
            total_connections: u64::try_from(events.len()).unwrap_or(u64::MAX),
            idle_connections: u64::try_from(idle_connections).unwrap_or(u64::MAX),
            malformed_connections: u64::try_from(malformed_connections).unwrap_or(u64::MAX),
            valid_requests: u64::try_from(valid_requests).unwrap_or(u64::MAX),
            events,
        })
    }
}

impl Drop for ProbeServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.state.active_connections.load(Ordering::Acquire) != 0
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn observe_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    sequence: u64,
    test_started: Instant,
    state: &Arc<ProbeState>,
) {
    let accepted_after_ms = elapsed_ms(test_started);
    let connection_started = Instant::now();
    let timeout = Duration::from_millis(CONNECTION_READ_MS);
    let setup = stream
        .set_nonblocking(false)
        .and_then(|()| stream.set_read_timeout(Some(timeout)))
        .and_then(|()| stream.set_write_timeout(Some(timeout)));
    if let Err(error) = setup {
        push_event(
            state,
            connection_event(
                sequence,
                peer,
                accepted_after_ms,
                None,
                None,
                None,
                0,
                WindowsWfpConnectionOutcome::MalformedRequest,
                &format!("connection timeout setup failed: {error}"),
            ),
        );
        return;
    }
    let mut request = Vec::new();
    let mut first_byte_after_ms = None;
    let read_outcome = loop {
        let mut buffer = [0_u8; 2 * 1024];
        match stream.read(&mut buffer) {
            Ok(0) if request.is_empty() => {
                break Err((
                    WindowsWfpConnectionOutcome::IdleClosed,
                    "closed without data",
                ));
            }
            Ok(0) => {
                break Err((
                    WindowsWfpConnectionOutcome::MalformedPartial,
                    "closed with partial headers",
                ));
            }
            Ok(read) => {
                if first_byte_after_ms.is_none() {
                    first_byte_after_ms = Some(elapsed_ms(connection_started));
                }
                request.extend_from_slice(&buffer[..read]);
                if request.len() > MAX_TEST_HTTP_BYTES {
                    break Err((
                        WindowsWfpConnectionOutcome::MalformedRequest,
                        "request exceeded byte bound",
                    ));
                }
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break Ok(());
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) && request.is_empty() =>
            {
                break Err((
                    WindowsWfpConnectionOutcome::IdleTimeout,
                    "idle read timeout",
                ));
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break Err((
                    WindowsWfpConnectionOutcome::MalformedPartial,
                    "partial request read timeout",
                ));
            }
            Err(_) if request.is_empty() => {
                break Err((WindowsWfpConnectionOutcome::IdleClosed, "idle read error"));
            }
            Err(_) => {
                break Err((
                    WindowsWfpConnectionOutcome::MalformedPartial,
                    "partial request read error",
                ));
            }
        }
    };
    if let Err((outcome, detail)) = read_outcome {
        push_event(
            state,
            connection_event(
                sequence,
                peer,
                accepted_after_ms,
                first_byte_after_ms,
                None,
                None,
                request.len(),
                outcome,
                detail,
            ),
        );
        return;
    }
    let request_complete_after_ms = Some(elapsed_ms(connection_started));
    let parsed = parse_request(&request);
    let (path, host) = match parsed {
        Ok(value) => value,
        Err(detail) => {
            push_event(
                state,
                connection_event(
                    sequence,
                    peer,
                    accepted_after_ms,
                    first_byte_after_ms,
                    request_complete_after_ms,
                    None,
                    request.len(),
                    WindowsWfpConnectionOutcome::MalformedRequest,
                    detail,
                ),
            );
            return;
        }
    };
    let route = state
        .routes
        .lock()
        .ok()
        .and_then(|routes| routes.get(path).cloned());
    let Some(route) = route else {
        push_event(
            state,
            connection_event(
                sequence,
                peer,
                accepted_after_ms,
                first_byte_after_ms,
                request_complete_after_ms,
                None,
                request.len(),
                WindowsWfpConnectionOutcome::UnexpectedRequest,
                "request path was not registered",
            ),
        );
        return;
    };
    if !host.eq_ignore_ascii_case(&route.expected_host) {
        push_event(
            state,
            connection_event(
                sequence,
                peer,
                accepted_after_ms,
                first_byte_after_ms,
                request_complete_after_ms,
                None,
                request.len(),
                WindowsWfpConnectionOutcome::UnexpectedRequest,
                "request Host differed from the registered route",
            ),
        );
        return;
    }
    let response = match route.response {
        RouteResponse::Nonce(nonce) => {
            let body = format!("d2i-wfp-probe:{nonce}\n");
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\
                 Cache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        }
        RouteResponse::Redirect(location) => format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nCache-Control: no-store\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n"
        ),
    };
    if stream
        .write_all(response.as_bytes())
        .and_then(|()| stream.flush())
        .is_err()
    {
        push_event(
            state,
            connection_event(
                sequence,
                peer,
                accepted_after_ms,
                first_byte_after_ms,
                request_complete_after_ms,
                None,
                request.len(),
                WindowsWfpConnectionOutcome::ResponseError,
                "response write failed",
            ),
        );
        return;
    }
    if let Ok(mut observed) = state.observed_paths.lock() {
        observed.insert(path.to_owned());
    }
    push_event(
        state,
        connection_event(
            sequence,
            peer,
            accepted_after_ms,
            first_byte_after_ms,
            request_complete_after_ms,
            Some(elapsed_ms(connection_started)),
            request.len(),
            WindowsWfpConnectionOutcome::ValidRequest,
            "complete registered request and response",
        ),
    );
}

fn parse_request(request: &[u8]) -> Result<(&str, &str), &'static str> {
    let text = std::str::from_utf8(request).map_err(|_| "request was not UTF-8")?;
    let header_end = text
        .find("\r\n\r\n")
        .ok_or("request headers were incomplete")?;
    let mut lines = text[..header_end].split("\r\n");
    let mut request_line = lines.next().ok_or("request line was missing")?.split(' ');
    if request_line.next() != Some("GET") {
        return Err("request method was not GET");
    }
    let path = request_line
        .next()
        .filter(|path| path.starts_with('/') && path.len() <= 2048)
        .ok_or("request path was invalid")?;
    if !matches!(request_line.next(), Some("HTTP/1.1" | "HTTP/1.0"))
        || request_line.next().is_some()
    {
        return Err("request line was not complete HTTP");
    }
    let mut host = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("request header was malformed")?;
        if name.eq_ignore_ascii_case("host") {
            if host.is_some() {
                return Err("request Host header was duplicated");
            }
            let value = value.trim();
            if value.is_empty() || value.len() > 512 {
                return Err("request Host header was invalid");
            }
            host = Some(value);
        }
    }
    Ok((path, host.ok_or("request Host header was missing")?))
}

#[allow(clippy::too_many_arguments)]
fn connection_event(
    sequence: u64,
    peer: SocketAddr,
    accepted_after_ms: u64,
    first_byte_after_ms: Option<u64>,
    request_complete_after_ms: Option<u64>,
    response_complete_after_ms: Option<u64>,
    bytes_read: usize,
    outcome: WindowsWfpConnectionOutcome,
    detail: &str,
) -> WindowsWfpConnectionEvent {
    WindowsWfpConnectionEvent {
        sequence,
        peer_address: peer.to_string(),
        accepted_after_ms,
        first_byte_after_ms,
        request_complete_after_ms,
        response_complete_after_ms,
        bytes_read: u64::try_from(bytes_read).unwrap_or(u64::MAX),
        outcome,
        detail_hash: sha256_bytes(detail.as_bytes()),
    }
}

fn push_event(state: &Arc<ProbeState>, event: WindowsWfpConnectionEvent) {
    if let Ok(mut events) = state.events.lock() {
        events.push(event);
    }
}

fn record_fatal(state: &Arc<ProbeState>, message: String) {
    if let Ok(mut error) = state.fatal_error.lock() {
        *error = Some(message);
    }
}

fn require_observed(
    server: &ProbeServer,
    path: &str,
    timeout: Duration,
    label: &str,
) -> Result<(), DesktopError> {
    if server.wait_for_path(path, timeout)? {
        Ok(())
    } else {
        Err(DesktopError::Integrity(format!(
            "{label} did not deliver its nonce-bound request"
        )))
    }
}

fn require_not_observed(
    server: &ProbeServer,
    path: &str,
    timeout: Duration,
    label: &str,
) -> Result<(), DesktopError> {
    if server.wait_for_path(path, timeout)? {
        Err(DesktopError::Integrity(format!(
            "{label} reached the protected probe server"
        )))
    } else {
        Ok(())
    }
}

fn passed_probe(
    probe_id: &str,
    target: Option<String>,
    page_nonce_verified: bool,
    elapsed_ms: u64,
    detail: &str,
) -> WindowsWfpNetworkProbe {
    WindowsWfpNetworkProbe {
        probe_id: probe_id.to_owned(),
        target,
        disposition: WindowsWfpProbeDisposition::Passed,
        request_observed: true,
        page_nonce_verified,
        elapsed_ms,
        detail_hash: sha256_bytes(detail.as_bytes()),
    }
}

fn blocked_probe(
    probe_id: &str,
    target: Option<String>,
    elapsed_ms: u64,
    detail: &str,
) -> WindowsWfpNetworkProbe {
    WindowsWfpNetworkProbe {
        probe_id: probe_id.to_owned(),
        target,
        disposition: WindowsWfpProbeDisposition::Blocked,
        request_observed: false,
        page_nonce_verified: false,
        elapsed_ms,
        detail_hash: sha256_bytes(detail.as_bytes()),
    }
}

struct ManagedEdgeDriver {
    child: Child,
    endpoint: String,
    session_id: Option<String>,
    profile_directory: PathBuf,
    profile_parent: PathBuf,
    dns_mapping_address: Ipv4Addr,
    timeout_ms: u64,
    cleaned: bool,
}

impl ManagedEdgeDriver {
    fn start(
        pin: &WindowsEdgeDriverPin,
        nonce: &str,
        non_loopback_ipv4: Ipv4Addr,
        timeout_ms: u64,
    ) -> Result<Self, DesktopError> {
        let port_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|error| {
            DesktopError::AdapterUnavailable(format!("EdgeDriver port reservation failed: {error}"))
        })?;
        let port = port_listener
            .local_addr()
            .map_err(|error| {
                DesktopError::AdapterUnavailable(format!(
                    "EdgeDriver port discovery failed: {error}"
                ))
            })?
            .port();
        drop(port_listener);
        let profile_parent = std::env::temp_dir();
        let profile_directory =
            profile_parent.join(format!("d2i-wfp-self-test-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&profile_directory).map_err(|error| DesktopError::Io {
            path: profile_directory.display().to_string(),
            message: error.to_string(),
        })?;
        let driver_path = native_windows_path(&pin.driver_executable);
        let mut command = Command::new(&driver_path);
        command
            .arg(format!("--port={port}"))
            .env("MSEDGEDRIVER_TELEMETRY_OPTOUT", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(CREATE_NO_WINDOW);
        }
        let child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                let _ = remove_profile_directory(&profile_parent, &profile_directory);
                return Err(DesktopError::AdapterUnavailable(format!(
                    "pinned EdgeDriver launch failed: {error}"
                )));
            }
        };
        let mut managed = Self {
            child,
            endpoint: format!("http://127.0.0.1:{port}"),
            session_id: None,
            profile_directory,
            profile_parent,
            dns_mapping_address: non_loopback_ipv4,
            timeout_ms: timeout_ms.clamp(1_000, 30_000),
            cleaned: false,
        };
        managed.wait_until_ready()?;
        Ok(managed)
    }

    fn wait_until_ready(&mut self) -> Result<(), DesktopError> {
        let deadline = Instant::now() + Duration::from_millis(self.timeout_ms);
        loop {
            if let Some(status) = self.child.try_wait().map_err(|error| {
                DesktopError::AdapterUnavailable(format!(
                    "EdgeDriver process status failed: {error}"
                ))
            })? {
                return Err(DesktopError::AdapterUnavailable(format!(
                    "EdgeDriver exited before becoming ready with status {status}"
                )));
            }
            match crate::windows_worker::webdriver_request(
                &self.endpoint,
                1_000,
                "GET",
                "/status",
                None,
            ) {
                Ok(value)
                    if value
                        .pointer("/value/ready")
                        .and_then(Value::as_bool)
                        .unwrap_or(false) =>
                {
                    return Ok(());
                }
                Ok(_) | Err(_) => {}
            }
            if Instant::now() >= deadline {
                return Err(DesktopError::AdapterUnavailable(
                    "EdgeDriver did not become ready before the self-test deadline".to_owned(),
                ));
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    fn create_session(&mut self, pin: &WindowsEdgeDriverPin) -> Result<(), DesktopError> {
        let browser = native_windows_path(&pin.browser_executable);
        let profile = native_windows_path(&self.profile_directory.display().to_string());
        let body = json!({
            "capabilities": {
                "alwaysMatch": {
                    "browserName": "MicrosoftEdge",
                    "pageLoadStrategy": "none",
                    "ms:edgeOptions": {
                        "binary": browser,
                        "args": [
                            "--headless=new",
                            "--disable-gpu",
                            "--no-first-run",
                            "--disable-default-apps",
                            "--disable-background-networking",
                            "--disable-component-update",
                            "--metrics-recording-only",
                            "--no-proxy-server",
                            format!(
                                "--host-resolver-rules=MAP {DNS_PROBE_HOST} {},EXCLUDE localhost",
                                self.dns_mapping_address
                            ),
                            format!("--user-data-dir={profile}")
                        ]
                    }
                }
            }
        });
        let response = crate::windows_worker::webdriver_request(
            &self.endpoint,
            self.timeout_ms,
            "POST",
            "/session",
            Some(&body),
        )?;
        let session_id = response
            .pointer("/value/sessionId")
            .and_then(Value::as_str)
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= 256
                    && value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
                    })
            })
            .ok_or_else(|| {
                DesktopError::Integrity(
                    "EdgeDriver session response has no safe session ID".to_owned(),
                )
            })?;
        self.session_id = Some(session_id.to_owned());
        Ok(())
    }

    fn session_id(&self) -> Result<&str, DesktopError> {
        self.session_id.as_deref().ok_or_else(|| {
            DesktopError::Precondition("EdgeDriver self-test session is not active".to_owned())
        })
    }

    fn navigate(&self, url: &str) -> Result<(), DesktopError> {
        let session_id = self.session_id()?;
        let body = json!({"url": url});
        let _ = crate::windows_worker::webdriver_request(
            &self.endpoint,
            self.timeout_ms,
            "POST",
            &format!("/session/{session_id}/url"),
            Some(&body),
        )?;
        Ok(())
    }

    fn navigate_tolerant(&self, url: &str) {
        let _ = self.navigate(url);
    }

    fn require_page_nonce(&self, nonce: &str, timeout: Duration) -> Result<(), DesktopError> {
        let session_id = self.session_id()?;
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(response) = crate::windows_worker::webdriver_request(
                &self.endpoint,
                self.timeout_ms.min(2_000),
                "GET",
                &format!("/session/{session_id}/source"),
                None,
            ) {
                if response
                    .get("value")
                    .and_then(Value::as_str)
                    .is_some_and(|source| source.contains(nonce))
                {
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                return Err(DesktopError::Integrity(
                    "Edge page source did not contain the response nonce".to_owned(),
                ));
            }
            thread::sleep(Duration::from_millis(25));
        }
    }

    fn observe_page(&self, timeout_ms: u64) -> Result<(String, String, String), DesktopError> {
        let session_id = self.session_id()?;
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            let url = crate::windows_worker::webdriver_request(
                &self.endpoint,
                self.timeout_ms.min(2_000),
                "GET",
                &format!("/session/{session_id}/url"),
                None,
            )
            .ok()
            .and_then(|value| {
                value
                    .get("value")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            });
            let source = crate::windows_worker::webdriver_request(
                &self.endpoint,
                self.timeout_ms.min(2_000),
                "GET",
                &format!("/session/{session_id}/source"),
                None,
            )
            .ok()
            .and_then(|value| {
                value
                    .get("value")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            });
            let title = crate::windows_worker::webdriver_request(
                &self.endpoint,
                self.timeout_ms.min(2_000),
                "GET",
                &format!("/session/{session_id}/title"),
                None,
            )
            .ok()
            .and_then(|value| {
                value
                    .get("value")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            });
            if let (Some(url), Some(title), Some(source)) = (url, title, source) {
                if !source.is_empty() {
                    return Ok((url, title, source));
                }
            }
            if Instant::now() >= deadline {
                return Err(DesktopError::Integrity(
                    "Edge loopback snapshot observation timed out".to_owned(),
                ));
            }
            thread::sleep(Duration::from_millis(25));
        }
    }

    fn close_session(&mut self) -> bool {
        let Some(session_id) = self.session_id.take() else {
            return true;
        };
        crate::windows_worker::webdriver_request(
            &self.endpoint,
            self.timeout_ms,
            "DELETE",
            &format!("/session/{session_id}"),
            None,
        )
        .is_ok()
    }

    fn shutdown(mut self) -> Result<WindowsWfpSelfTestCleanup, DesktopError> {
        let browser_session_closed = self.close_session();
        let _ = self.child.kill();
        let edge_driver_exited = self.child.wait().is_ok();
        let temporary_profile_removed =
            remove_profile_directory(&self.profile_parent, &self.profile_directory).is_ok();
        self.cleaned = true;
        Ok(WindowsWfpSelfTestCleanup {
            browser_session_closed,
            edge_driver_exited,
            temporary_profile_removed,
        })
    }
}

impl Drop for ManagedEdgeDriver {
    fn drop(&mut self) {
        if self.cleaned {
            return;
        }
        let _ = self.close_session();
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = remove_profile_directory(&self.profile_parent, &self.profile_directory);
    }
}

fn native_windows_path(value: &str) -> String {
    if let Some(path) = value.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{path}")
    } else {
        value.strip_prefix(r"\\?\").unwrap_or(value).to_owned()
    }
}

fn remove_profile_directory(parent: &Path, profile: &Path) -> Result<(), std::io::Error> {
    let valid_name = profile
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("d2i-wfp-self-test-"));
    if profile.parent() != Some(parent) || !valid_name {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing to remove an unexpected Edge profile path",
        ));
    }
    let mut last_error = None;
    for _ in 0..20 {
        match std::fs::remove_dir_all(profile) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => last_error = Some(error),
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(last_error
        .unwrap_or_else(|| std::io::Error::other("temporary Edge profile removal failed")))
}

fn bounded_wait(deadline: Instant, requested: Duration) -> Result<Duration, DesktopError> {
    Ok(remaining(deadline)?.min(requested))
}

fn remaining(deadline: Instant) -> Result<Duration, DesktopError> {
    deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| {
            DesktopError::AdapterUnavailable("WFP self-test total deadline expired".to_owned())
        })
}

fn remaining_ms(deadline: Instant) -> Result<u64, DesktopError> {
    Ok(duration_ms(remaining(deadline)?))
}

fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

fn elapsed_ms(started: Instant) -> u64 {
    duration_ms(started.elapsed())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_connection_does_not_hide_a_later_nonce_request() -> Result<(), DesktopError> {
        let started = Instant::now();
        let server = ProbeServer::start(AddressFamily::Ipv4, started)?;
        let nonce = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let host = format!("127.0.0.1:{}", server.port());
        let path = probe_path("idle-tolerant", nonce);
        server.add_nonce_route(&path, &host, nonce)?;
        let idle = TcpStream::connect(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            server.port(),
        )))
        .map_err(|error| DesktopError::AdapterUnavailable(error.to_string()))?;
        send_control_request(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, server.port())),
            &host,
            &path,
            nonce,
            Duration::from_secs(2),
        )?;
        if !server.wait_for_path(&path, Duration::from_secs(2))? {
            return Err(DesktopError::Integrity(
                "valid request after idle connection was not observed".to_owned(),
            ));
        }
        drop(idle);
        thread::sleep(Duration::from_millis(CONNECTION_READ_MS + 50));
        let telemetry = server.telemetry()?;
        if telemetry.idle_connections == 0 || telemetry.valid_requests != 1 {
            return Err(DesktopError::Integrity(
                "idle/preconnect telemetry is inconsistent".to_owned(),
            ));
        }
        Ok(())
    }

    #[test]
    fn malformed_host_is_not_a_positive_signal() -> Result<(), DesktopError> {
        let server = ProbeServer::start(AddressFamily::Ipv4, Instant::now())?;
        let nonce = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let path = probe_path("host-check", nonce);
        server.add_nonce_route(&path, "127.0.0.1:1", nonce)?;
        let mut stream = TcpStream::connect(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            server.port(),
        )))
        .map_err(|error| DesktopError::AdapterUnavailable(error.to_string()))?;
        stream
            .write_all(
                format!(
                    "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                    server.port()
                )
                .as_bytes(),
            )
            .map_err(|error| DesktopError::AdapterUnavailable(error.to_string()))?;
        if server.wait_for_path(&path, Duration::from_millis(500))? {
            return Err(DesktopError::Integrity(
                "wrong Host request was accepted".to_owned(),
            ));
        }
        Ok(())
    }
}
