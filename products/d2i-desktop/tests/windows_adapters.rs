#![cfg(windows)]

use d2i_desktop::{
    activate_certified_windows_binding, certify_windows_binding,
    create_windows_browser_egress_evidence, initialize_audit_ledger,
    initialize_windows_activation_ledger, run_windows_wfp_browser_egress_self_test, sign_approval,
    unprotect_windows_signing_key, verify_audit_ledger, verify_signed_windows_certification,
    verify_windows_activation_ledger, ActivatedWindowsBinding, AllowedExecutable,
    BrowserInteraction, ConcreteWindowsRuntimeBindingProbe, DesktopActionIntent, DesktopActor,
    DesktopAdapter, DesktopCapability, DesktopExecutor, DesktopOperation, DesktopPolicy, RiskClass,
    SignedWindowsCertification, UiInteraction, WindowIdentity, WindowsActivationLedgerPolicy,
    WindowsActivationRecord, WindowsAdapterConfiguration, WindowsAdapterKind,
    WindowsBindingEvidence, WindowsBrowserEgressInput, WindowsBrowserEgressRequirement,
    WindowsEdgeDriverPin, WindowsFileWriteAdapter, WindowsProcessAdapter, WindowsProcessIsolation,
    WindowsProtectedSigningKey, WindowsRuntimeBindingProbe, WindowsRuntimeManifest,
    WindowsSigningKeyPurpose, WindowsUiAutomationAdapter, WindowsWebDriverAdapter,
    WindowsWfpBrowserEgressObservation, WindowsWfpBrowserEgressPolicy,
    WindowsWfpBrowserEgressSelfTestReport, WindowsWfpNetworkProbe, WindowsWfpProbeDisposition,
    WindowsWfpProbeServerTelemetry, WindowsWfpSelfTestCleanup,
};
use d2i_runtime_api::{DecisionEnvelope, DecisionStatus, Evidence, PolicyResult};
use ed25519_dalek::SigningKey;
use jsonschema::{Draft, JSONSchema};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn ok<T, E: Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("test operation failed: {error:?}"),
    }
}

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(label: &str) -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "d2i-windows-{label}-{}-{sequence}",
            std::process::id()
        ));
        ok(fs::create_dir(&path));
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct CertifiedFixture {
    activation: ActivatedWindowsBinding,
    manifest: WindowsRuntimeManifest,
    evidence: WindowsBindingEvidence,
    certification: SignedWindowsCertification,
    ledger_root: PathBuf,
}

struct AppContainerProfile(String);

impl Drop for AppContainerProfile {
    fn drop(&mut self) {
        let _ = d2i_windows_host::delete_appcontainer_profile(&self.0);
    }
}

struct ChildGuard(std::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn fixed_hash(value: u8) -> String {
    format!("sha256:{value:064x}")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn now_seconds() -> u64 {
    ok(SystemTime::now().duration_since(UNIX_EPOCH)).as_secs()
}

fn worker_identity() -> (String, String) {
    let path = ok(fs::canonicalize(env!("CARGO_BIN_EXE_d2i-desktop")));
    let hash = sha(&ok(fs::read(&path)));
    (path.display().to_string(), hash)
}

fn base_configuration(kind: WindowsAdapterKind) -> WindowsAdapterConfiguration {
    let (worker_executable, worker_executable_hash) = worker_identity();
    WindowsAdapterConfiguration {
        schema_version: 1,
        adapter_kind: kind,
        worker_executable,
        worker_executable_hash,
        request_timeout_ms: 10_000,
        active_process_limit: if kind == WindowsAdapterKind::Process {
            4
        } else {
            1
        },
        per_process_memory_bytes: 256 * 1024 * 1024,
        write_roots: Vec::new(),
        webdriver_endpoint: None,
        browser_session_ids: BTreeSet::new(),
        browser_allowed_origins: BTreeSet::new(),
        browser_egress_policy: None,
        ui_allowed_executable_hashes: BTreeSet::new(),
        process_isolation: None,
    }
}

fn process_configuration(label: &str) -> (WindowsAdapterConfiguration, AppContainerProfile) {
    let profile_name = format!("D2I.Test.Desktop.{label}.{}", std::process::id());
    let profile = ok(d2i_windows_host::provision_appcontainer_profile(
        &profile_name,
    ));
    let mut configuration = base_configuration(WindowsAdapterKind::Process);
    configuration.process_isolation = Some(WindowsProcessIsolation {
        profile_name: profile.profile_name.clone(),
        profile_sid: profile.profile_sid,
    });
    (configuration, AppContainerProfile(profile.profile_name))
}

fn certify_and_activate(
    configuration: &WindowsAdapterConfiguration,
    temp: &TempDirectory,
    label: &str,
    observed_at: u64,
) -> CertifiedFixture {
    let attestor_key = SigningKey::from_bytes(&[31_u8; 32]);
    let certifier_key = SigningKey::from_bytes(&[32_u8; 32]);
    let integration_id = format!("windows-{label}");
    let binding_id = format!("binding-{label}");
    let mut probe = ok(ConcreteWindowsRuntimeBindingProbe::new(
        configuration.clone(),
        binding_id,
        integration_id.clone(),
        observed_at,
        observed_at + 600,
        "runtime-attestor".to_owned(),
        attestor_key.clone(),
    ));
    let browser_egress_requirement = if configuration.adapter_kind == WindowsAdapterKind::WebDriver
    {
        let provider_key = SigningKey::from_bytes(&[33_u8; 32]);
        let policy_hash = fixed_hash(33);
        let egress = ok(create_windows_browser_egress_evidence(
            WindowsBrowserEgressInput {
                schema_version: 1,
                enforcement_id: "test-browser-egress".to_owned(),
                policy_hash: policy_hash.clone(),
                provider_id: "test-egress-provider".to_owned(),
                observed_at_unix_seconds: observed_at,
                expires_at_unix_seconds: observed_at + 600,
                browser_session_ids: configuration.browser_session_ids.clone(),
                allowed_origins: configuration.browser_allowed_origins.clone(),
                deny_by_default: true,
            },
            &provider_key,
        ));
        probe = ok(probe.with_browser_egress_evidence(egress));
        Some(WindowsBrowserEgressRequirement {
            enforcement_id: "test-browser-egress".to_owned(),
            policy_hash,
            provider_id: "test-egress-provider".to_owned(),
            provider_public_key: hex(&provider_key.verifying_key().to_bytes()),
            browser_session_ids: configuration.browser_session_ids.clone(),
            allowed_origins: configuration.browser_allowed_origins.clone(),
            functional_attestation_hash: None,
            edge_driver_executable_hash: None,
            self_test_report_hash: None,
            activation_challenge: None,
        })
    } else {
        None
    };
    let evidence = ok(probe.collect_binding_evidence());
    let manifest = WindowsRuntimeManifest {
        schema_version: 1,
        integration_id,
        adapter_kind: configuration.adapter_kind,
        adapter_descriptor: ok(configuration.descriptor()),
        configuration_hash: ok(configuration.configuration_hash()),
        worker_executable_hash: configuration.worker_executable_hash.clone(),
        process_isolation: configuration.process_isolation.clone(),
        browser_egress_requirement,
        host: evidence.host.clone(),
        interactive_session_required: configuration.adapter_kind
            == WindowsAdapterKind::UiAutomation,
        binding_attestor_id: "runtime-attestor".to_owned(),
        binding_attestor_public_key: hex(&attestor_key.verifying_key().to_bytes()),
        certifier_id: "release-certifier".to_owned(),
        certifier_public_key: hex(&certifier_key.verifying_key().to_bytes()),
    };
    let result = ok(certify_windows_binding(
        &manifest,
        &evidence,
        format!("certificate-{label}"),
        "release-certifier".to_owned(),
        &certifier_key,
        observed_at + 1,
    ));
    assert!(result.report.certified, "{:?}", result.report.issues);
    let certification = match result.signed_certification {
        Some(value) => value,
        None => panic!("clean certification did not produce a signature"),
    };
    let certified = ok(verify_signed_windows_certification(
        &manifest,
        &evidence,
        &certification,
        observed_at + 2,
    ));
    let ledger_root = temp.path().join(format!("activation-{label}"));
    let _ = ok(initialize_windows_activation_ledger(
        &ledger_root,
        &format!("ledger-{label}"),
        &manifest,
        BTreeSet::from(["test-activator".to_owned()]),
        32,
    ));
    let admission = ok(activate_certified_windows_binding(
        &ledger_root,
        "test-activator",
        certified,
        observed_at + 2,
    ));
    assert_eq!(admission.verification.entry_count, 1);
    CertifiedFixture {
        activation: admission.activation,
        manifest,
        evidence,
        certification,
        ledger_root,
    }
}

fn decision() -> DecisionEnvelope {
    DecisionEnvelope {
        request_id: "request-1".to_owned(),
        build_id: "build-1".to_owned(),
        package_content_hash: fixed_hash(1),
        skill_id: "desktop-task".to_owned(),
        status: DecisionStatus::Success,
        result: json!({"action": "approved-plan"}),
        module_ids: vec!["planner-1".to_owned()],
        evidence: vec![Evidence {
            source: "test".to_owned(),
            span: "1".to_owned(),
            provenance_id: "evidence-1".to_owned(),
            content_hash: fixed_hash(2),
        }],
        confidence: 0.99,
        policy: PolicyResult {
            allowed: true,
            reason: "test".to_owned(),
            human_review_required: false,
        },
        timings: Vec::new(),
        warnings: Vec::new(),
        replay_key: "replay-1".to_owned(),
    }
}

fn intent(operation: DesktopOperation, sequence: u64, now_unix_ms: u64) -> DesktopActionIntent {
    let decision = decision();
    DesktopActionIntent {
        schema_version: 1,
        action_id: format!("action-{sequence}"),
        session_id: "session-1".to_owned(),
        sequence,
        generated_at_unix_ms: now_unix_ms.saturating_sub(1_000),
        expires_at_unix_ms: now_unix_ms.saturating_add(59_000),
        request_id: decision.request_id.clone(),
        build_id: decision.build_id.clone(),
        package_content_hash: decision.package_content_hash.clone(),
        decision_hash: decision.decision_hash(),
        evidence_hashes: vec![fixed_hash(2)],
        idempotency_key: format!("idempotency-{sequence}"),
        rationale_hash: fixed_hash(3),
        operation,
    }
}

fn actor() -> DesktopActor {
    DesktopActor {
        actor_id: "desktop-agent-1".to_owned(),
        roles: BTreeSet::from(["operator".to_owned()]),
    }
}

#[allow(clippy::too_many_arguments)]
fn policy(
    adapter: &impl DesktopAdapter,
    capabilities: BTreeSet<DesktopCapability>,
    read_roots: Vec<String>,
    write_roots: Vec<String>,
    executables: Vec<AllowedExecutable>,
    network_allowed: bool,
    origins: BTreeSet<String>,
    approval_key: &SigningKey,
) -> DesktopPolicy {
    DesktopPolicy {
        schema_version: 1,
        policy_id: "windows-policy".to_owned(),
        policy_version: "1.0.0".to_owned(),
        allowed_actor_roles: BTreeSet::from(["operator".to_owned()]),
        allowed_capabilities: capabilities,
        approval_required_for: BTreeSet::from([
            RiskClass::ExternalCommunication,
            RiskClass::CredentialSensitive,
            RiskClass::Destructive,
            RiskClass::Privileged,
        ]),
        allowed_read_roots: read_roots,
        allowed_write_roots: write_roots,
        allowed_executables: executables,
        network_allowed,
        allowed_network_origins: origins,
        allowed_adapters: BTreeMap::from([(
            adapter.descriptor().adapter_id.clone(),
            ok(adapter.descriptor().descriptor_hash()),
        )]),
        approver_public_keys: BTreeMap::from([(
            "approver-1".to_owned(),
            hex(&approval_key.verifying_key().to_bytes()),
        )]),
        maximum_actions_per_session: 10,
        maximum_action_lifetime_ms: 60_000,
    }
}

fn approve_and_commit<A: DesktopAdapter>(
    executor: &mut DesktopExecutor<A>,
    action: &DesktopActionIntent,
    payload: Option<&[u8]>,
    approval_id: &str,
    now_unix_ms: u64,
    approval_key: &SigningKey,
    audit: &mut d2i_desktop::AuditLedger,
) -> d2i_desktop::AdapterExecution {
    let preparation = ok(executor.prepare(action, &decision(), now_unix_ms, audit));
    let approval = ok(sign_approval(
        approval_id.to_owned(),
        "approver-1".to_owned(),
        &preparation.policy_decision,
        &preparation.prepared,
        now_unix_ms,
        now_unix_ms + 30_000,
        format!("nonce-{approval_id}"),
        approval_key,
    ));
    ok(executor.commit(
        action,
        &preparation,
        Some(&approval),
        payload,
        now_unix_ms,
        audit,
    ))
}

#[test]
fn signed_file_binding_activates_atomic_write_adapter() {
    let temp = TempDirectory::new("file");
    let now = now_seconds();
    let now_ms = now * 1_000;
    let root = ok(fs::canonicalize(temp.path()));
    let mut configuration = base_configuration(WindowsAdapterKind::FileWrite);
    configuration.write_roots = vec![root.display().to_string()];
    let fixture = certify_and_activate(&configuration, &temp, "file", now);
    validate_schema(
        "desktop/windows-adapter-configuration.schema.json",
        &configuration,
    );
    validate_schema(
        "desktop/windows-runtime-manifest.schema.json",
        &fixture.manifest,
    );
    validate_schema(
        "desktop/windows-binding-evidence.schema.json",
        &fixture.evidence,
    );
    validate_schema(
        "desktop/windows-signed-certification.schema.json",
        &fixture.certification,
    );
    let ledger_policy: WindowsActivationLedgerPolicy = ok(serde_json::from_slice(&ok(fs::read(
        fixture.ledger_root.join("windows-activation-policy.json"),
    ))));
    validate_schema(
        "desktop/windows-activation-ledger-policy.schema.json",
        &ledger_policy,
    );
    let record_bytes = ok(fs::read(
        fixture.ledger_root.join("windows-activation-records.jsonl"),
    ));
    let record: WindowsActivationRecord = ok(serde_json::from_slice(record_bytes.trim_ascii()));
    validate_schema("desktop/windows-activation-record.schema.json", &record);
    assert_eq!(
        ok(verify_windows_activation_ledger(&fixture.ledger_root)).entry_count,
        1
    );
    let mut tampered = fixture.certification.clone();
    let replacement = if tampered.signature_hex.starts_with('0') {
        "1"
    } else {
        "0"
    };
    tampered.signature_hex.replace_range(0..1, replacement);
    assert!(verify_signed_windows_certification(
        &fixture.manifest,
        &fixture.evidence,
        &tampered,
        now + 3,
    )
    .is_err());
    let replay = ok(verify_signed_windows_certification(
        &fixture.manifest,
        &fixture.evidence,
        &fixture.certification,
        now + 3,
    ));
    assert!(activate_certified_windows_binding(
        &fixture.ledger_root,
        "test-activator",
        replay,
        now + 3,
    )
    .is_err());

    let adapter = ok(WindowsFileWriteAdapter::bind(
        fixture.activation,
        configuration,
        now + 2,
    ));
    let approval_key = SigningKey::from_bytes(&[41_u8; 32]);
    let policy = policy(
        &adapter,
        BTreeSet::from([DesktopCapability::WriteFile]),
        Vec::new(),
        vec![root.display().to_string()],
        Vec::new(),
        false,
        BTreeSet::new(),
        &approval_key,
    );
    let mut executor = ok(DesktopExecutor::new(
        adapter,
        policy,
        actor(),
        "session-1".to_owned(),
    ));
    let audit_root = temp.path().join("audit");
    let mut audit = ok(initialize_audit_ledger(
        &audit_root,
        "session-1",
        20,
        now_ms,
    ));
    let target = root.join("created.txt");
    let action = intent(
        DesktopOperation::WriteFile {
            path: target.display().to_string(),
            payload_hash: sha(b"certified write"),
            expected_current_hash: None,
            create_new: true,
        },
        1,
        now_ms + 2_000,
    );
    let result = ok(executor.execute(
        &action,
        &decision(),
        Some(b"certified write"),
        now_ms + 2_000,
        &mut audit,
    ));
    assert!(!result.payload.is_empty());
    assert_eq!(ok(fs::read(target)), b"certified write");
}

#[test]
fn concrete_wfp_contract_is_loopback_only_and_cannot_use_generic_signing() {
    let policy = WindowsWfpBrowserEgressPolicy {
        schema_version: 2,
        enforcement_id: "edge-loopback-test".to_owned(),
        provider_id: "d2i.windows.wfp.loopback.v1".to_owned(),
        browser_executable: r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
            .to_owned(),
        browser_executable_hash: fixed_hash(81),
        verifier_profile_name: "d2i-wfp-verifier-test".to_owned(),
        verifier_profile_sid: "S-1-15-2-1".to_owned(),
        policy_owner_sid: "S-1-5-21-1".to_owned(),
    };
    validate_schema(
        "desktop/windows-wfp-browser-egress-policy.schema.json",
        &policy,
    );
    let mut configuration = base_configuration(WindowsAdapterKind::WebDriver);
    configuration.webdriver_endpoint = Some("http://127.0.0.1:4444".to_owned());
    configuration
        .browser_session_ids
        .insert("wfp-session".to_owned());
    configuration
        .browser_allowed_origins
        .insert("http://127.0.0.1:8080".to_owned());
    configuration.browser_egress_policy = Some(policy.clone());
    ok(configuration.validate());
    validate_schema(
        "desktop/windows-adapter-configuration.schema.json",
        &configuration,
    );

    configuration.browser_allowed_origins = BTreeSet::from(["https://example.invalid".to_owned()]);
    assert!(configuration.validate().is_err());

    let evidence = create_windows_browser_egress_evidence(
        WindowsBrowserEgressInput {
            schema_version: 1,
            enforcement_id: policy.enforcement_id.clone(),
            policy_hash: ok(policy.policy_hash()),
            provider_id: policy.provider_id,
            observed_at_unix_seconds: 1,
            expires_at_unix_seconds: 2,
            browser_session_ids: BTreeSet::from(["wfp-session".to_owned()]),
            allowed_origins: BTreeSet::from(["http://127.0.0.1:8080".to_owned()]),
            deny_by_default: true,
        },
        &SigningKey::from_bytes(&[81_u8; 32]),
    );
    assert!(evidence.is_err());
}

#[test]
fn edge_driver_pin_schema_and_version_compatibility_are_strict() {
    let pin = WindowsEdgeDriverPin {
        schema_version: 1,
        browser_name: "MicrosoftEdge".to_owned(),
        browser_executable: r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
            .to_owned(),
        browser_version: "150.0.4078.99".to_owned(),
        browser_executable_hash: fixed_hash(82),
        driver_executable: r"C:\D2I\msedgedriver.exe".to_owned(),
        driver_version: "150.0.4078.99".to_owned(),
        driver_executable_hash: fixed_hash(83),
        compatibility_version: "150.0.4078".to_owned(),
    };
    let passed_control = WindowsWfpNetworkProbe {
        probe_id: "ipv4_control".to_owned(),
        target: Some("http://192.0.2.10:49152/control".to_owned()),
        disposition: WindowsWfpProbeDisposition::Passed,
        request_observed: true,
        page_nonce_verified: false,
        elapsed_ms: 10,
        detail_hash: fixed_hash(86),
    };
    let passed_loopback = |probe_id: &str, target: &str, marker| WindowsWfpNetworkProbe {
        probe_id: probe_id.to_owned(),
        target: Some(target.to_owned()),
        disposition: WindowsWfpProbeDisposition::Passed,
        request_observed: true,
        page_nonce_verified: true,
        elapsed_ms: 10,
        detail_hash: fixed_hash(marker),
    };
    let blocked = |probe_id: &str, target: &str, marker| WindowsWfpNetworkProbe {
        probe_id: probe_id.to_owned(),
        target: Some(target.to_owned()),
        disposition: WindowsWfpProbeDisposition::Blocked,
        request_observed: false,
        page_nonce_verified: false,
        elapsed_ms: 5_000,
        detail_hash: fixed_hash(marker),
    };
    let empty_telemetry = |family: &str| WindowsWfpProbeServerTelemetry {
        address_family: family.to_owned(),
        total_connections: 0,
        idle_connections: 0,
        malformed_connections: 0,
        valid_requests: 0,
        events: Vec::new(),
    };
    validate_schema("desktop/windows-edge-driver-pin.schema.json", &pin);
    let report = WindowsWfpBrowserEgressSelfTestReport {
        schema_version: 2,
        test_id: "wfp-self-test:contract".to_owned(),
        activation_challenge: "activation-challenge-contract-0001".to_owned(),
        probe_nonce: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        browser_session_id: "edge-session-contract".to_owned(),
        started_at_unix_ms: 1,
        completed_at_unix_ms: 20_001,
        elapsed_ms: 20_000,
        total_deadline_ms: 70_000,
        blocked_observation_ms: 5_000,
        wfp_observation: WindowsWfpBrowserEgressObservation {
            schema_version: 2,
            enforcement_id: "edge-loopback-test".to_owned(),
            provider_id: "d2i.windows.wfp.loopback.v1".to_owned(),
            policy_hash: fixed_hash(84),
            browser_executable: pin.browser_executable.clone(),
            browser_executable_hash: pin.browser_executable_hash.clone(),
            provider_key: "effa5c68-709d-4311-9a4c-1ff4f3c20bf0".to_owned(),
            sublayer_key: "f328c32f-dba5-4527-bcc0-c3763b734590".to_owned(),
            filter_keys: [
                "769fcfb8-8dc3-4685-8e70-49deff9012d9".to_owned(),
                "faab358b-8445-488e-8836-ce1173cd6000".to_owned(),
                "5433444c-fc9f-4845-9139-f83e316cbac2".to_owned(),
                "17ddc305-ac3a-4799-886e-0990bed1f105".to_owned(),
            ],
            verifier_sid: "S-1-15-2-1".to_owned(),
            policy_owner_sid: "S-1-5-21-1".to_owned(),
            engine_security_descriptor_hash: fixed_hash(94),
            object_security_descriptor_hash: fixed_hash(93),
        },
        edge_driver_pin_hash: fixed_hash(85),
        browser_version: pin.browser_version.clone(),
        browser_executable_hash: pin.browser_executable_hash.clone(),
        driver_version: pin.driver_version.clone(),
        driver_executable_hash: pin.driver_executable_hash.clone(),
        ipv4_control: passed_control,
        ipv4_loopback: passed_loopback("ipv4_loopback", "http://127.0.0.1:49152/loopback", 87),
        ipv4_direct_ip: blocked("ipv4_direct_ip", "http://192.0.2.10:49152/direct", 88),
        ipv4_dns: blocked("ipv4_dns", "http://d2i-wfp-self-test.invalid:49152/dns", 89),
        ipv4_redirect: blocked("ipv4_redirect", "http://127.0.0.1:49152/redirect", 90),
        ipv6_control: None,
        ipv6_loopback: passed_loopback("ipv6_loopback", "http://[::1]:49153/loopback", 91),
        ipv6_non_loopback: WindowsWfpNetworkProbe {
            probe_id: "ipv6_non_loopback".to_owned(),
            target: None,
            disposition: WindowsWfpProbeDisposition::ExplicitlyBlocked,
            request_observed: false,
            page_nonce_verified: false,
            elapsed_ms: 0,
            detail_hash: fixed_hash(92),
        },
        ipv4_telemetry: empty_telemetry("ipv4"),
        ipv6_telemetry: empty_telemetry("ipv6"),
        cleanup: WindowsWfpSelfTestCleanup {
            browser_session_closed: true,
            edge_driver_exited: true,
            temporary_profile_removed: true,
        },
        passed: true,
    };
    ok(report.validate());
    validate_schema(
        "desktop/windows-wfp-browser-egress-self-test-report.schema.json",
        &report,
    );
    let mut inconsistent_report = report;
    inconsistent_report.ipv4_direct_ip.request_observed = true;
    assert!(inconsistent_report.validate().is_err());
    let mut incompatible = pin;
    incompatible.driver_version = "149.0.4000.1".to_owned();
    assert!(incompatible.verify().is_err());
}

#[test]
fn protected_ledgers_reject_security_descriptor_drift() {
    let temp = TempDirectory::new("ledger-security");
    let now = now_seconds();
    let mut configuration = base_configuration(WindowsAdapterKind::FileWrite);
    configuration
        .write_roots
        .push(ok(fs::canonicalize(temp.path())).display().to_string());
    let fixture = certify_and_activate(&configuration, &temp, "ledger-security", now);
    let (profile_configuration, _profile) = process_configuration("ledger-security");
    let profile_name = profile_configuration
        .process_isolation
        .as_ref()
        .map(|isolation| isolation.profile_name.as_str())
        .unwrap_or_default();

    let activation_root = temp.path().join("activation-security-drift");
    let _ = ok(initialize_windows_activation_ledger(
        &activation_root,
        "ledger-security-drift",
        &fixture.manifest,
        BTreeSet::from(["test-activator".to_owned()]),
        8,
    ));
    ok(d2i_windows_host::grant_appcontainer_path_access(
        profile_name,
        &activation_root.join("windows-activation-records.jsonl"),
        d2i_windows_host::WindowsAppContainerPathAccess::ReadWrite,
        false,
    ));
    assert!(verify_windows_activation_ledger(&activation_root).is_err());

    let audit_root = temp.path().join("audit-security-drift");
    let _ = ok(initialize_audit_ledger(
        &audit_root,
        "security-session",
        8,
        now * 1_000,
    ));
    ok(d2i_windows_host::grant_appcontainer_path_access(
        profile_name,
        &audit_root.join("audit-records.jsonl"),
        d2i_windows_host::WindowsAppContainerPathAccess::ReadWrite,
        false,
    ));
    assert!(verify_audit_ledger(&audit_root).is_err());
}

#[test]
fn signed_process_binding_manages_only_its_child() {
    let temp = TempDirectory::new("process");
    let now = now_seconds();
    let now_ms = now * 1_000;
    let (configuration, _profile) = process_configuration("process");
    let fixture = certify_and_activate(&configuration, &temp, "process", now);
    let adapter = ok(WindowsProcessAdapter::bind(
        fixture.activation,
        configuration.clone(),
        now + 2,
    ));
    let ping = ok(fs::canonicalize(
        Path::new(&std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_owned()))
            .join("System32")
            .join("ping.exe"),
    ));
    let executable_hash = sha(&ok(fs::read(&ping)));
    let working_directory = ok(fs::canonicalize(temp.path()));
    ok(d2i_windows_host::grant_appcontainer_path_access(
        configuration
            .process_isolation
            .as_ref()
            .map(|isolation| isolation.profile_name.as_str())
            .unwrap_or_default(),
        &working_directory,
        d2i_windows_host::WindowsAppContainerPathAccess::ReadWrite,
        true,
    ));
    let arguments = vec!["-n".to_owned(), "30".to_owned(), "127.0.0.1".to_owned()];
    let approval_key = SigningKey::from_bytes(&[42_u8; 32]);
    let policy = policy(
        &adapter,
        BTreeSet::from([
            DesktopCapability::LaunchProcess,
            DesktopCapability::TerminateProcess,
        ]),
        vec![
            ping.parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("C:\\Windows\\System32"))
                .display()
                .to_string(),
            working_directory.display().to_string(),
        ],
        Vec::new(),
        vec![AllowedExecutable {
            path: ping.display().to_string(),
            content_hash: executable_hash.clone(),
            arguments_prefix: arguments.clone(),
            may_request_network: false,
        }],
        false,
        BTreeSet::new(),
        &approval_key,
    );
    let mut executor = ok(DesktopExecutor::new(
        adapter,
        policy,
        actor(),
        "session-1".to_owned(),
    ));
    let audit_root = temp.path().join("audit");
    let mut audit = ok(initialize_audit_ledger(
        &audit_root,
        "session-1",
        20,
        now_ms,
    ));
    let launch = intent(
        DesktopOperation::LaunchProcess {
            executable: ping.display().to_string(),
            executable_hash: executable_hash.clone(),
            arguments,
            working_directory: working_directory.display().to_string(),
            network_requested: false,
        },
        1,
        now_ms + 2_000,
    );
    let launched = approve_and_commit(
        &mut executor,
        &launch,
        None,
        "approval-launch",
        now_ms + 2_000,
        &approval_key,
        &mut audit,
    );
    let output: Value = ok(serde_json::from_slice(&launched.payload));
    let process_id = match output.get("process_id").and_then(Value::as_u64) {
        Some(value) => u32::try_from(value).unwrap_or(u32::MAX),
        None => panic!("process adapter did not return a process ID"),
    };
    assert_ne!(process_id, 0);
    let terminate = intent(
        DesktopOperation::TerminateProcess {
            process_id,
            expected_executable_hash: executable_hash,
        },
        2,
        now_ms + 3_000,
    );
    let terminated = approve_and_commit(
        &mut executor,
        &terminate,
        None,
        "approval-terminate",
        now_ms + 3_000,
        &approval_key,
        &mut audit,
    );
    let output: Value = ok(serde_json::from_slice(&terminated.payload));
    assert_eq!(
        output.get("terminated").and_then(Value::as_bool),
        Some(true)
    );
}

#[test]
fn signed_uia_binding_lists_windows_through_isolated_worker() {
    let temp = TempDirectory::new("uia");
    let now = now_seconds();
    let now_ms = now * 1_000;
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_owned());
    let powershell = ok(fs::canonicalize(
        Path::new(&system_root)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe"),
    ));
    let executable_hash = sha(&ok(fs::read(&powershell)));
    let title = format!("D2I UI List Fixture {}", std::process::id());
    let script = ok(fs::canonicalize(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("support")
            .join("windows_ui_fixture.ps1"),
    ));
    let child = ok(std::process::Command::new(&powershell)
        .args(["-NoProfile", "-STA", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(&script)
        .arg("-WindowTitle")
        .arg(&title)
        .arg("-OutputPath")
        .arg(temp.path().join("uia-list-value.txt"))
        .spawn());
    let process_id = child.id();
    let mut fixture_process = ChildGuard(child);
    std::thread::sleep(Duration::from_millis(1_500));
    assert!(
        ok(fixture_process.0.try_wait()).is_none(),
        "Windows Forms list fixture exited before UI Automation"
    );
    let mut configuration = base_configuration(WindowsAdapterKind::UiAutomation);
    configuration
        .ui_allowed_executable_hashes
        .insert(executable_hash.clone());
    let fixture = certify_and_activate(&configuration, &temp, "uia", now);
    let adapter = ok(WindowsUiAutomationAdapter::bind(
        fixture.activation,
        configuration,
        now + 2,
    ));
    let approval_key = SigningKey::from_bytes(&[43_u8; 32]);
    let policy = policy(
        &adapter,
        BTreeSet::from([DesktopCapability::ListWindows]),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        false,
        BTreeSet::new(),
        &approval_key,
    );
    let mut executor = ok(DesktopExecutor::new(
        adapter,
        policy,
        actor(),
        "session-1".to_owned(),
    ));
    let audit_root = temp.path().join("audit");
    let mut audit = ok(initialize_audit_ledger(
        &audit_root,
        "session-1",
        20,
        now_ms,
    ));
    let action = intent(DesktopOperation::ListWindows, 1, now_ms + 2_000);
    let result = ok(executor.execute(&action, &decision(), None, now_ms + 2_000, &mut audit));
    let windows: Vec<WindowIdentity> = ok(serde_json::from_slice(&result.payload));
    assert!(
        windows.iter().any(|window| {
            window.process_id == process_id
                && window.executable_hash == executable_hash
                && window.title_hash == sha(title.as_bytes())
        }),
        "fixture window was not observed through the isolated UIA worker: {windows:?}"
    );
    assert!(
        windows
            .iter()
            .all(|window| window.executable_hash == executable_hash),
        "ListWindows returned a process outside the certified executable allowlist"
    );
}

#[test]
fn signed_uia_binding_mutates_actual_windows_form_text() {
    let temp = TempDirectory::new("uia-mutation");
    let now = now_seconds();
    let now_ms = now * 1_000;
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_owned());
    let powershell = ok(fs::canonicalize(
        Path::new(&system_root)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe"),
    ));
    let executable_hash = sha(&ok(fs::read(&powershell)));
    let title = format!("D2I UI Fixture {}", std::process::id());
    let output_path = temp.path().join("uia-value.txt");
    let script = ok(fs::canonicalize(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("support")
            .join("windows_ui_fixture.ps1"),
    ));
    let child = ok(std::process::Command::new(&powershell)
        .args(["-NoProfile", "-STA", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(&script)
        .arg("-WindowTitle")
        .arg(&title)
        .arg("-OutputPath")
        .arg(&output_path)
        .spawn());
    let process_id = child.id();
    let mut fixture_process = ChildGuard(child);
    std::thread::sleep(Duration::from_millis(1_500));
    assert!(
        ok(fixture_process.0.try_wait()).is_none(),
        "Windows Forms fixture exited before UI Automation"
    );

    let mut configuration = base_configuration(WindowsAdapterKind::UiAutomation);
    configuration
        .ui_allowed_executable_hashes
        .insert(executable_hash.clone());
    let fixture = certify_and_activate(&configuration, &temp, "uia-mutation", now);
    let adapter = ok(WindowsUiAutomationAdapter::bind(
        fixture.activation,
        configuration,
        now + 2,
    ));
    let approval_key = SigningKey::from_bytes(&[45_u8; 32]);
    let policy = policy(
        &adapter,
        BTreeSet::from([DesktopCapability::UiInteract]),
        Vec::new(),
        Vec::new(),
        vec![AllowedExecutable {
            path: powershell.display().to_string(),
            content_hash: executable_hash.clone(),
            arguments_prefix: Vec::new(),
            may_request_network: false,
        }],
        false,
        BTreeSet::new(),
        &approval_key,
    );
    let mut executor = ok(DesktopExecutor::new(
        adapter,
        policy,
        actor(),
        "session-1".to_owned(),
    ));
    let mut audit = ok(initialize_audit_ledger(
        &temp.path().join("audit"),
        "session-1",
        20,
        now_ms,
    ));
    let payload = b"actual UI Automation mutation";
    let action = intent(
        DesktopOperation::UiInteract {
            window: WindowIdentity {
                process_id,
                executable_hash,
                title_hash: sha(title.as_bytes()),
            },
            interaction: UiInteraction::SetText {
                automation_id: "D2IText".to_owned(),
                text_hash: sha(payload),
                secret_ref: None,
            },
        },
        1,
        now_ms + 2_000,
    );
    let result = approve_and_commit(
        &mut executor,
        &action,
        Some(payload),
        "approval-uia-mutation",
        now_ms + 2_000,
        &approval_key,
        &mut audit,
    );
    assert!(!result.payload.is_empty());
    for _ in 0..50 {
        if fs::read(&output_path).is_ok_and(|bytes| bytes == payload) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("Windows Forms text change was not observed");
}

#[test]
fn signed_webdriver_binding_navigates_allowlisted_origin() {
    let server = FakeWebDriver::start();
    let temp = TempDirectory::new("webdriver");
    let now = now_seconds();
    let now_ms = now * 1_000;
    let origin = "http://example.test".to_owned();
    let mut configuration = base_configuration(WindowsAdapterKind::WebDriver);
    configuration.webdriver_endpoint = Some(server.endpoint());
    configuration
        .browser_session_ids
        .insert("test-session".to_owned());
    configuration.browser_allowed_origins.insert(origin.clone());
    let fixture = certify_and_activate(&configuration, &temp, "webdriver", now);
    if let Some(egress) = &fixture.evidence.browser_egress_evidence {
        validate_schema(
            "desktop/windows-browser-egress-evidence.schema.json",
            egress,
        );
    } else {
        panic!("WebDriver binding lacks browser-egress evidence");
    }
    let mut tampered_evidence = fixture.evidence.clone();
    if let Some(egress) = &mut tampered_evidence.browser_egress_evidence {
        egress
            .allowed_origins
            .insert("https://tampered.invalid".to_owned());
    }
    let tampered_result = ok(certify_windows_binding(
        &fixture.manifest,
        &tampered_evidence,
        "certificate-tampered-egress".to_owned(),
        "release-certifier".to_owned(),
        &SigningKey::from_bytes(&[32_u8; 32]),
        now + 3,
    ));
    assert!(!tampered_result.report.certified);
    assert!(tampered_result
        .report
        .issues
        .iter()
        .any(|issue| issue.code == "D2IWC113"));
    let adapter = ok(WindowsWebDriverAdapter::bind(
        fixture.activation,
        configuration,
        now + 2,
    ));
    let approval_key = SigningKey::from_bytes(&[44_u8; 32]);
    let policy = policy(
        &adapter,
        BTreeSet::from([DesktopCapability::BrowserNavigate]),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        true,
        BTreeSet::from([origin.clone()]),
        &approval_key,
    );
    let mut executor = ok(DesktopExecutor::new(
        adapter,
        policy,
        actor(),
        "session-1".to_owned(),
    ));
    let audit_root = temp.path().join("audit");
    let mut audit = ok(initialize_audit_ledger(
        &audit_root,
        "session-1",
        20,
        now_ms,
    ));
    let action = intent(
        DesktopOperation::BrowserNavigate {
            browser_session_id: "test-session".to_owned(),
            url: format!("{origin}/target"),
            origin,
        },
        1,
        now_ms + 2_000,
    );
    let result = approve_and_commit(
        &mut executor,
        &action,
        None,
        "approval-browser",
        now_ms + 2_000,
        &approval_key,
        &mut audit,
    );
    assert!(!result.payload.is_empty());
    assert_eq!(server.current_url(), "http://example.test/target");
}

#[test]
fn signed_webdriver_binding_mutates_click_text_and_select_state() {
    let server = FakeWebDriver::start();
    let temp = TempDirectory::new("webdriver-mutations");
    let now = now_seconds();
    let now_ms = now * 1_000;
    let origin = "http://example.test".to_owned();
    server.set_current_url("http://example.test/form");
    let mut configuration = base_configuration(WindowsAdapterKind::WebDriver);
    configuration.webdriver_endpoint = Some(server.endpoint());
    configuration
        .browser_session_ids
        .insert("test-session".to_owned());
    configuration.browser_allowed_origins.insert(origin.clone());
    let fixture = certify_and_activate(&configuration, &temp, "webdriver-mutations", now);
    let adapter = ok(WindowsWebDriverAdapter::bind(
        fixture.activation,
        configuration,
        now + 2,
    ));
    let approval_key = SigningKey::from_bytes(&[46_u8; 32]);
    let policy = policy(
        &adapter,
        BTreeSet::from([DesktopCapability::BrowserInteract]),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        true,
        BTreeSet::from([origin.clone()]),
        &approval_key,
    );
    let mut executor = ok(DesktopExecutor::new(
        adapter,
        policy,
        actor(),
        "session-1".to_owned(),
    ));
    let mut audit = ok(initialize_audit_ledger(
        &temp.path().join("audit"),
        "session-1",
        20,
        now_ms,
    ));
    let click = intent(
        DesktopOperation::BrowserInteract {
            browser_session_id: "test-session".to_owned(),
            origin: origin.clone(),
            interaction: BrowserInteraction::Click {
                locator: "css:#button".to_owned(),
            },
        },
        1,
        now_ms + 2_000,
    );
    let _ = approve_and_commit(
        &mut executor,
        &click,
        None,
        "approval-browser-click",
        now_ms + 2_000,
        &approval_key,
        &mut audit,
    );
    let text = b"typed through W3C WebDriver";
    let type_text = intent(
        DesktopOperation::BrowserInteract {
            browser_session_id: "test-session".to_owned(),
            origin: origin.clone(),
            interaction: BrowserInteraction::TypeText {
                locator: "css:#text".to_owned(),
                text_hash: sha(text),
                secret_ref: None,
            },
        },
        2,
        now_ms + 3_000,
    );
    let _ = approve_and_commit(
        &mut executor,
        &type_text,
        Some(text),
        "approval-browser-type",
        now_ms + 3_000,
        &approval_key,
        &mut audit,
    );
    let selected = b"beta";
    let select = intent(
        DesktopOperation::BrowserInteract {
            browser_session_id: "test-session".to_owned(),
            origin,
            interaction: BrowserInteraction::Select {
                locator: "css:#select".to_owned(),
                value_hash: sha(selected),
            },
        },
        3,
        now_ms + 4_000,
    );
    let _ = approve_and_commit(
        &mut executor,
        &select,
        Some(selected),
        "approval-browser-select",
        now_ms + 4_000,
        &approval_key,
        &mut audit,
    );
    assert_eq!(
        server.mutation_state(),
        (
            1,
            "typed through W3C WebDriver".to_owned(),
            "beta".to_owned()
        )
    );
}

#[test]
#[ignore = "requires an installed D2I WFP policy and pinned Edge/EdgeDriver artifacts"]
fn installed_wfp_policy_blocks_real_edge_non_loopback_egress() {
    let policy_path = std::env::var("D2I_TEST_WFP_POLICY")
        .unwrap_or_else(|_| panic!("D2I_TEST_WFP_POLICY is required"));
    let pin_path = std::env::var("D2I_TEST_EDGE_DRIVER_PIN")
        .unwrap_or_else(|_| panic!("D2I_TEST_EDGE_DRIVER_PIN is required"));
    let policy: WindowsWfpBrowserEgressPolicy =
        ok(serde_json::from_slice(&ok(fs::read(policy_path))));
    let pin: WindowsEdgeDriverPin = ok(serde_json::from_slice(&ok(fs::read(pin_path))));
    let report = ok(run_windows_wfp_browser_egress_self_test(
        &policy,
        &pin,
        "test-activation-challenge-0001",
        5_000,
    ));
    assert!(
        report.passed,
        "non-loopback request reached the probe server: {report:?}"
    );
    validate_schema(
        "desktop/windows-wfp-browser-egress-self-test-report.schema.json",
        &report,
    );
}

#[test]
#[ignore = "requires D2I_TEST_WEBDRIVER_ENDPOINT and D2I_TEST_WEBDRIVER_SESSION_ID"]
fn real_webdriver_mutates_and_submits_local_html_form() {
    let webdriver_endpoint = std::env::var("D2I_TEST_WEBDRIVER_ENDPOINT")
        .unwrap_or_else(|_| panic!("D2I_TEST_WEBDRIVER_ENDPOINT is required"));
    let browser_session_id = std::env::var("D2I_TEST_WEBDRIVER_SESSION_ID")
        .unwrap_or_else(|_| panic!("D2I_TEST_WEBDRIVER_SESSION_ID is required"));
    let web = RealBrowserFixture::start();
    let temp = TempDirectory::new("real-webdriver");
    let now = now_seconds();
    let origin = web.origin();
    let mut configuration = base_configuration(WindowsAdapterKind::WebDriver);
    configuration.request_timeout_ms = 30_000;
    configuration.webdriver_endpoint = Some(webdriver_endpoint);
    configuration
        .browser_session_ids
        .insert(browser_session_id.clone());
    configuration.browser_allowed_origins.insert(origin);
    let fixture = certify_and_activate(&configuration, &temp, "real-webdriver", now);
    let adapter = ok(WindowsWebDriverAdapter::bind(
        fixture.activation,
        configuration,
        now + 2,
    ));
    exercise_real_webdriver_form(adapter, &browser_session_id, &web, &temp, now);
}

#[test]
#[ignore = "requires fresh concrete WFP v2 deployment artifacts and a live pinned Edge session"]
fn deployed_wfp_v2_binding_reactivates_webdriver_and_preserves_egress_denial() {
    let configuration_path = required_env("D2I_TEST_WINDOWS_CONFIG");
    let manifest_path = required_env("D2I_TEST_WINDOWS_MANIFEST");
    let evidence_path = required_env("D2I_TEST_WINDOWS_EVIDENCE");
    let certification_path = required_env("D2I_TEST_WINDOWS_CERTIFICATION");
    let activation_root = PathBuf::from(required_env("D2I_TEST_WINDOWS_ACTIVATION_ROOT"));
    let fixture_port = required_env("D2I_TEST_LOOPBACK_FIXTURE_PORT")
        .parse::<u16>()
        .unwrap_or_else(|error| panic!("D2I_TEST_LOOPBACK_FIXTURE_PORT is invalid: {error}"));
    let activator_id = required_env("D2I_TEST_WINDOWS_ACTIVATOR_ID");
    let configuration: WindowsAdapterConfiguration = read_test_json(&configuration_path);
    let manifest: WindowsRuntimeManifest = read_test_json(&manifest_path);
    let evidence: WindowsBindingEvidence = read_test_json(&evidence_path);
    let certification: SignedWindowsCertification = read_test_json(&certification_path);
    let browser_session_id = configuration
        .browser_session_ids
        .iter()
        .next()
        .cloned()
        .unwrap_or_else(|| panic!("concrete WebDriver configuration has no browser session"));
    let webdriver_endpoint = configuration
        .webdriver_endpoint
        .clone()
        .unwrap_or_else(|| panic!("concrete WebDriver configuration has no endpoint"));
    let web = RealBrowserFixture::start_on_port(fixture_port);
    assert_eq!(
        configuration.browser_allowed_origins,
        BTreeSet::from([web.origin()]),
        "fixture origin differs from the functionally attested scope"
    );
    assert!(
        !activation_root.exists(),
        "activation root must be absent before one-shot initialization"
    );

    let now = now_seconds();
    let certified = ok(verify_signed_windows_certification(
        &manifest,
        &evidence,
        &certification,
        now,
    ));
    let initial = ok(initialize_windows_activation_ledger(
        &activation_root,
        "windows-wfp-v2-deployment",
        &manifest,
        BTreeSet::from([activator_id.clone()]),
        16,
    ));
    assert_eq!(initial.entry_count, 0);
    let admission = ok(activate_certified_windows_binding(
        &activation_root,
        &activator_id,
        certified,
        now,
    ));
    assert_eq!(admission.verification.entry_count, 1);
    let adapter = ok(WindowsWebDriverAdapter::bind(
        admission.activation,
        configuration,
        now,
    ));
    let temp = TempDirectory::new("deployed-wfp-v2");
    exercise_real_webdriver_form(adapter, &browser_session_id, &web, &temp, now);
    assert_real_edge_ipv4_non_loopback_blocked(
        &webdriver_endpoint,
        &browser_session_id,
        Duration::from_millis(2_000),
    );

    let final_ledger = ok(verify_windows_activation_ledger(&activation_root));
    assert_eq!(final_ledger.entry_count, 1);
    let replay = ok(verify_signed_windows_certification(
        &manifest,
        &evidence,
        &certification,
        now_seconds(),
    ));
    let replay_error =
        activate_certified_windows_binding(&activation_root, &activator_id, replay, now_seconds())
            .err()
            .unwrap_or_else(|| {
                panic!("identical attestation-backed activation replay was accepted")
            });
    assert!(
        replay_error.to_string().contains("replay"),
        "activation replay failed for an unexpected reason: {replay_error}"
    );
}

fn exercise_real_webdriver_form(
    adapter: WindowsWebDriverAdapter,
    browser_session_id: &str,
    web: &RealBrowserFixture,
    temp: &TempDirectory,
    now: u64,
) {
    let now_ms = now * 1_000;
    let origin = web.origin();
    let approval_key = SigningKey::from_bytes(&[47_u8; 32]);
    let policy = policy(
        &adapter,
        BTreeSet::from([
            DesktopCapability::BrowserNavigate,
            DesktopCapability::BrowserInteract,
        ]),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        true,
        BTreeSet::from([origin.clone()]),
        &approval_key,
    );
    let mut executor = ok(DesktopExecutor::new(
        adapter,
        policy,
        actor(),
        "session-1".to_owned(),
    ));
    let mut audit = ok(initialize_audit_ledger(
        &temp.path().join("audit"),
        "session-1",
        32,
        now_ms,
    ));
    let navigate = intent(
        DesktopOperation::BrowserNavigate {
            browser_session_id: browser_session_id.to_owned(),
            url: format!("{origin}/form"),
            origin: origin.clone(),
        },
        1,
        now_ms + 2_000,
    );
    let _ = approve_and_commit(
        &mut executor,
        &navigate,
        None,
        "approval-real-navigate",
        now_ms + 2_000,
        &approval_key,
        &mut audit,
    );
    let text = b"real-browser";
    let type_text = intent(
        DesktopOperation::BrowserInteract {
            browser_session_id: browser_session_id.to_owned(),
            origin: origin.clone(),
            interaction: BrowserInteraction::TypeText {
                locator: "css:#text".to_owned(),
                text_hash: sha(text),
                secret_ref: None,
            },
        },
        2,
        now_ms + 3_000,
    );
    let _ = approve_and_commit(
        &mut executor,
        &type_text,
        Some(text),
        "approval-real-type",
        now_ms + 3_000,
        &approval_key,
        &mut audit,
    );
    let selected = b"beta";
    let select = intent(
        DesktopOperation::BrowserInteract {
            browser_session_id: browser_session_id.to_owned(),
            origin: origin.clone(),
            interaction: BrowserInteraction::Select {
                locator: "css:#choice".to_owned(),
                value_hash: sha(selected),
            },
        },
        3,
        now_ms + 4_000,
    );
    let _ = approve_and_commit(
        &mut executor,
        &select,
        Some(selected),
        "approval-real-select",
        now_ms + 4_000,
        &approval_key,
        &mut audit,
    );
    let submit = intent(
        DesktopOperation::BrowserInteract {
            browser_session_id: browser_session_id.to_owned(),
            origin,
            interaction: BrowserInteraction::Click {
                locator: "css:#submit".to_owned(),
            },
        },
        4,
        now_ms + 5_000,
    );
    let _ = approve_and_commit(
        &mut executor,
        &submit,
        None,
        "approval-real-submit",
        now_ms + 5_000,
        &approval_key,
        &mut audit,
    );
    for _ in 0..50 {
        if web
            .submitted_target()
            .is_some_and(|target| target.contains("text=real-browser&choice=beta"))
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("real browser did not submit the mutated form state");
}

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}

fn read_test_json<T: serde::de::DeserializeOwned>(path: &str) -> T {
    ok(serde_json::from_slice(&ok(fs::read(path))))
}

fn assert_real_edge_ipv4_non_loopback_blocked(
    webdriver_endpoint: &str,
    browser_session_id: &str,
    observation: Duration,
) {
    let local_address = discover_test_non_loopback_ipv4();
    let listener = ok(TcpListener::bind(SocketAddrV4::new(
        Ipv4Addr::UNSPECIFIED,
        0,
    )));
    ok(listener.set_nonblocking(true));
    let port = ok(listener.local_addr()).port();
    let target = SocketAddr::V4(SocketAddrV4::new(local_address, port));

    let mut control = ok(TcpStream::connect_timeout(&target, Duration::from_secs(2)));
    ok(control.write_all(b"GET /control HTTP/1.1\r\nHost: control\r\nConnection: close\r\n\r\n"));
    let control_deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut request = [0_u8; 256];
                let read = ok(stream.read(&mut request));
                assert!(request[..read].starts_with(b"GET /control "));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    std::time::Instant::now() < control_deadline,
                    "ordinary process could not reach the non-loopback control listener"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("non-loopback control listener failed: {error}"),
        }
    }
    drop(control);

    let url = format!("http://{local_address}:{port}/blocked-after-activation");
    raw_webdriver_navigate(webdriver_endpoint, browser_session_id, &url);
    let deadline = std::time::Instant::now() + observation;
    while std::time::Instant::now() < deadline {
        match listener.accept() {
            Ok(_) => panic!("reactivated Edge reached a non-loopback IPv4 listener"),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("non-loopback negative listener failed: {error}"),
        }
    }
}

fn discover_test_non_loopback_ipv4() -> Ipv4Addr {
    let socket = ok(UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)));
    ok(socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9)));
    match ok(socket.local_addr()).ip() {
        std::net::IpAddr::V4(address) if !address.is_loopback() && !address.is_unspecified() => {
            address
        }
        address => panic!("no usable non-loopback IPv4 address was discovered: {address}"),
    }
}

fn raw_webdriver_navigate(endpoint: &str, session_id: &str, url: &str) {
    let authority = endpoint
        .strip_prefix("http://")
        .unwrap_or_else(|| panic!("test WebDriver endpoint must use http"));
    assert!(
        !authority.contains('/') && !authority.contains(['\r', '\n']),
        "test WebDriver endpoint must contain only an authority"
    );
    let body = ok(serde_json::to_vec(&json!({"url": url})));
    let mut stream = ok(TcpStream::connect(authority));
    ok(stream.set_read_timeout(Some(Duration::from_secs(2))));
    ok(stream.set_write_timeout(Some(Duration::from_secs(2))));
    let header = format!(
        "POST /session/{session_id}/url HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    ok(stream.write_all(header.as_bytes()));
    ok(stream.write_all(&body));
    ok(stream.flush());
    let mut response = Vec::new();
    match stream.read_to_end(&mut response) {
        Ok(_) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) => {}
        Err(error) => panic!("WebDriver negative navigation request failed: {error}"),
    }
}

#[test]
fn windows_certification_cli_runs_the_complete_activation_sequence() {
    let temp = TempDirectory::new("certification-cli");
    let now = now_seconds();
    let (configuration, _profile) = process_configuration("cli");
    let configuration_path = temp.path().join("configuration.json");
    write_json_file(&configuration_path, &configuration);
    let attestor_key = SigningKey::from_bytes(&[51_u8; 32]);
    let certifier_key = SigningKey::from_bytes(&[52_u8; 32]);
    let attestor_key_path = temp.path().join("attestor-key.hex");
    let certifier_key_path = temp.path().join("certifier-key.hex");
    ok(fs::write(&attestor_key_path, hex(&attestor_key.to_bytes())));
    ok(fs::write(
        &certifier_key_path,
        hex(&certifier_key.to_bytes()),
    ));
    let protected_attestor_key_path = temp.path().join("attestor-key.protected.json");
    let protected_certifier_key_path = temp.path().join("certifier-key.protected.json");
    let _ = run_cli(&[
        "windows-key-protect".to_owned(),
        attestor_key_path.display().to_string(),
        "runtime-attestor-key".to_owned(),
        "binding_attestor".to_owned(),
        protected_attestor_key_path.display().to_string(),
    ]);
    let _ = run_cli(&[
        "windows-key-protect".to_owned(),
        certifier_key_path.display().to_string(),
        "release-certifier-key".to_owned(),
        "certifier".to_owned(),
        protected_certifier_key_path.display().to_string(),
    ]);
    assert!(!ok(fs::read_to_string(&protected_attestor_key_path))
        .contains(&hex(&attestor_key.to_bytes())));
    assert!(!ok(fs::read_to_string(&protected_certifier_key_path))
        .contains(&hex(&certifier_key.to_bytes())));
    let protected_key: WindowsProtectedSigningKey = ok(serde_json::from_slice(&ok(fs::read(
        &protected_attestor_key_path,
    ))));
    validate_schema(
        "desktop/windows-protected-signing-key.schema.json",
        &protected_key,
    );
    assert!(
        unprotect_windows_signing_key(&protected_key, WindowsSigningKeyPurpose::Certifier).is_err()
    );
    ok(fs::remove_file(&attestor_key_path));
    ok(fs::remove_file(&certifier_key_path));
    let evidence_path = temp.path().join("evidence.json");
    let probe_output = run_cli(&[
        "windows-probe".to_owned(),
        configuration_path.display().to_string(),
        "binding-cli".to_owned(),
        "integration-cli".to_owned(),
        now.to_string(),
        (now + 600).to_string(),
        "runtime-attestor".to_owned(),
        protected_attestor_key_path.display().to_string(),
        evidence_path.display().to_string(),
    ]);
    assert!(!probe_output.contains(&hex(&attestor_key.to_bytes())));
    let evidence: WindowsBindingEvidence =
        ok(serde_json::from_slice(&ok(fs::read(&evidence_path))));
    let manifest = WindowsRuntimeManifest {
        schema_version: 1,
        integration_id: "integration-cli".to_owned(),
        adapter_kind: WindowsAdapterKind::Process,
        adapter_descriptor: ok(configuration.descriptor()),
        configuration_hash: ok(configuration.configuration_hash()),
        worker_executable_hash: configuration.worker_executable_hash.clone(),
        process_isolation: configuration.process_isolation.clone(),
        browser_egress_requirement: None,
        host: evidence.host.clone(),
        interactive_session_required: false,
        binding_attestor_id: "runtime-attestor".to_owned(),
        binding_attestor_public_key: hex(&attestor_key.verifying_key().to_bytes()),
        certifier_id: "release-certifier".to_owned(),
        certifier_public_key: hex(&certifier_key.verifying_key().to_bytes()),
    };
    let manifest_path = temp.path().join("manifest.json");
    write_json_file(&manifest_path, &manifest);
    let report_path = temp.path().join("report.json");
    let certification_path = temp.path().join("certification.json");
    let certify_output = run_cli(&[
        "windows-certify".to_owned(),
        manifest_path.display().to_string(),
        evidence_path.display().to_string(),
        "certificate-cli".to_owned(),
        "release-certifier".to_owned(),
        protected_certifier_key_path.display().to_string(),
        (now + 1).to_string(),
        report_path.display().to_string(),
        certification_path.display().to_string(),
    ]);
    assert!(!certify_output.contains(&hex(&certifier_key.to_bytes())));
    let _ = run_cli(&[
        "windows-certification-check".to_owned(),
        manifest_path.display().to_string(),
        evidence_path.display().to_string(),
        certification_path.display().to_string(),
        (now + 2).to_string(),
    ]);
    let ledger_root = temp.path().join("activation-cli");
    let _ = run_cli(&[
        "windows-activation-init".to_owned(),
        ledger_root.display().to_string(),
        "ledger-cli".to_owned(),
        manifest_path.display().to_string(),
        "test-activator".to_owned(),
        "32".to_owned(),
    ]);
    let activation_output = run_cli(&[
        "windows-activate".to_owned(),
        ledger_root.display().to_string(),
        "test-activator".to_owned(),
        manifest_path.display().to_string(),
        evidence_path.display().to_string(),
        certification_path.display().to_string(),
        (now + 2).to_string(),
    ]);
    assert!(activation_output.contains("\"entry_count\": 1"));
    let check_output = run_cli(&[
        "windows-activation-check".to_owned(),
        ledger_root.display().to_string(),
    ]);
    assert!(check_output.contains("\"entry_count\": 1"));
}

fn run_cli(arguments: &[String]) -> String {
    let output = ok(
        std::process::Command::new(env!("CARGO_BIN_EXE_d2i-desktop"))
            .args(arguments)
            .output(),
    );
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    ok(String::from_utf8(output.stdout))
}

fn write_json_file(path: &Path, value: &impl Serialize) {
    let mut bytes = ok(serde_json::to_vec_pretty(value));
    bytes.push(b'\n');
    ok(fs::write(path, bytes));
}

fn validate_schema(relative: &str, instance: &impl Serialize) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas")
        .join(relative);
    let schema: Value = ok(serde_json::from_slice(&ok(fs::read(path))));
    let compiled = ok(JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema));
    let value = ok(serde_json::to_value(instance));
    let errors: Vec<String> = match compiled.validate(&value) {
        Ok(()) => Vec::new(),
        Err(errors) => errors.map(|error| error.to_string()).collect(),
    };
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}

struct RealBrowserFixture {
    address: String,
    submitted_target: Arc<Mutex<Option<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl RealBrowserFixture {
    fn start() -> Self {
        Self::start_on_port(0)
    }

    fn start_on_port(port: u16) -> Self {
        let listener = ok(TcpListener::bind(("127.0.0.1", port)));
        ok(listener.set_nonblocking(true));
        let address = ok(listener.local_addr()).to_string();
        let submitted_target = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_target = Arc::clone(&submitted_target);
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => serve_real_browser_fixture(stream, &thread_target),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            address,
            submitted_target,
            stop,
            thread: Some(thread),
        }
    }

    fn origin(&self) -> String {
        format!("http://{}", self.address)
    }

    fn submitted_target(&self) -> Option<String> {
        match self.submitted_target.lock() {
            Ok(value) => value.clone(),
            Err(_) => panic!("real browser fixture lock was poisoned"),
        }
    }
}

impl Drop for RealBrowserFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(&self.address);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_real_browser_fixture(
    mut stream: TcpStream,
    submitted_target: &Arc<Mutex<Option<String>>>,
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
    let request = match std::str::from_utf8(&request) {
        Ok(value) => value,
        Err(_) => return,
    };
    let target = match request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
    {
        Some(value) => value,
        None => return,
    };
    if target.starts_with("/submitted?") {
        match submitted_target.lock() {
            Ok(mut value) => *value = Some(target.to_owned()),
            Err(_) => return,
        }
    }
    let body: &[u8] = if target.starts_with("/form") {
        br#"<!doctype html><html><body><form action="/submitted" method="get"><input id="text" name="text"><select id="choice" name="choice"><option value="alpha">Alpha</option><option value="beta">Beta</option></select><button id="submit" type="submit">Submit</button></form></body></html>"#
    } else {
        b"submitted"
    };
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

struct FakeWebDriver {
    address: String,
    current_url: Arc<Mutex<String>>,
    mutations: Arc<Mutex<FakeBrowserMutations>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

#[derive(Default)]
struct FakeBrowserMutations {
    click_count: u32,
    typed_text: String,
    selected_value: String,
}

impl FakeWebDriver {
    fn start() -> Self {
        let listener = ok(TcpListener::bind("127.0.0.1:0"));
        ok(listener.set_nonblocking(true));
        let address = ok(listener.local_addr()).to_string();
        let current_url = Arc::new(Mutex::new("about:blank".to_owned()));
        let mutations = Arc::new(Mutex::new(FakeBrowserMutations::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_url = Arc::clone(&current_url);
        let thread_mutations = Arc::clone(&mutations);
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        serve_webdriver(stream, &thread_url, &thread_mutations);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            address,
            current_url,
            mutations,
            stop,
            thread: Some(thread),
        }
    }

    fn endpoint(&self) -> String {
        format!("http://{}", self.address)
    }

    fn current_url(&self) -> String {
        match self.current_url.lock() {
            Ok(value) => value.clone(),
            Err(_) => panic!("fake WebDriver URL lock was poisoned"),
        }
    }

    fn set_current_url(&self, url: &str) {
        match self.current_url.lock() {
            Ok(mut value) => url.clone_into(&mut value),
            Err(_) => panic!("fake WebDriver URL lock was poisoned"),
        }
    }

    fn mutation_state(&self) -> (u32, String, String) {
        match self.mutations.lock() {
            Ok(value) => (
                value.click_count,
                value.typed_text.clone(),
                value.selected_value.clone(),
            ),
            Err(_) => panic!("fake WebDriver mutation lock was poisoned"),
        }
    }
}

impl Drop for FakeWebDriver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(&self.address);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_webdriver(
    mut stream: TcpStream,
    current_url: &Arc<Mutex<String>>,
    mutations: &Arc<Mutex<FakeBrowserMutations>>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    let header_end = loop {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => return,
            Ok(read) => request.extend_from_slice(&buffer[..read]),
        }
        if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        if request.len() > 64 * 1024 {
            return;
        }
    };
    let headers = match std::str::from_utf8(&request[..header_end]) {
        Ok(value) => value.to_owned(),
        Err(_) => return,
    };
    let content_length = headers
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
        })
        .unwrap_or(0);
    while request.len() < header_end.saturating_add(content_length) {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => return,
            Ok(read) => request.extend_from_slice(&buffer[..read]),
        }
    }
    let request_line = match headers.lines().next() {
        Some(value) => value,
        None => return,
    };
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    let body = &request[header_end..header_end + content_length];
    let response = if method == "GET" && path == "/status" {
        json!({"value": {"ready": true, "message": "test"}})
    } else if method == "GET" && path == "/session/test-session/url" {
        let value = match current_url.lock() {
            Ok(value) => value.clone(),
            Err(_) => return,
        };
        json!({"value": value})
    } else if method == "POST" && path == "/session/test-session/url" {
        let value: Value = match serde_json::from_slice(body) {
            Ok(value) => value,
            Err(_) => return,
        };
        let url = match value.get("url").and_then(Value::as_str) {
            Some(value) => value.to_owned(),
            None => return,
        };
        match current_url.lock() {
            Ok(mut value) => *value = url,
            Err(_) => return,
        }
        json!({"value": null})
    } else if method == "POST" && path == "/session/test-session/element" {
        let value: Value = match serde_json::from_slice(body) {
            Ok(value) => value,
            Err(_) => return,
        };
        let element_id = match value.get("value").and_then(Value::as_str) {
            Some("#text") => "text-element",
            Some("#button") => "button-element",
            Some("#select") => "select-element",
            _ => "unknown-element",
        };
        json!({"value": {"element-6066-11e4-a52e-4f735466cecf": element_id}})
    } else if method == "POST" && path == "/session/test-session/element/select-element/elements" {
        json!({"value": [
            {"element-6066-11e4-a52e-4f735466cecf": "option-alpha"},
            {"element-6066-11e4-a52e-4f735466cecf": "option-beta"}
        ]})
    } else if method == "GET"
        && path == "/session/test-session/element/option-alpha/attribute/value"
    {
        json!({"value": "alpha"})
    } else if method == "GET" && path == "/session/test-session/element/option-beta/attribute/value"
    {
        json!({"value": "beta"})
    } else if method == "POST" && path == "/session/test-session/element/text-element/value" {
        let value: Value = match serde_json::from_slice(body) {
            Ok(value) => value,
            Err(_) => return,
        };
        let text = match value.get("text").and_then(Value::as_str) {
            Some(value) => value.to_owned(),
            None => return,
        };
        match mutations.lock() {
            Ok(mut state) => state.typed_text = text,
            Err(_) => return,
        }
        json!({"value": null})
    } else if method == "POST" && path == "/session/test-session/element/button-element/click" {
        match mutations.lock() {
            Ok(mut state) => state.click_count = state.click_count.saturating_add(1),
            Err(_) => return,
        }
        json!({"value": null})
    } else if method == "POST" && path == "/session/test-session/element/option-beta/click" {
        match mutations.lock() {
            Ok(mut state) => state.selected_value = "beta".to_owned(),
            Err(_) => return,
        }
        json!({"value": null})
    } else {
        json!({"value": {"error": "unknown command", "message": "unsupported test command"}})
    };
    let bytes = match serde_json::to_vec(&response) {
        Ok(value) => value,
        Err(_) => return,
    };
    let status = if response.pointer("/value/error").is_some() {
        "404 Not Found"
    } else {
        "200 OK"
    };
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(&bytes);
    let _ = stream.flush();
}
