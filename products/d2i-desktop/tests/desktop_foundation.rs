use d2i_desktop::{
    evaluate_policy, initialize_audit_ledger, replay_audit, sign_approval, verify_audit_ledger,
    AuditReplayExpectation, DesktopActionIntent, DesktopActor, DesktopAdapter, DesktopCapability,
    DesktopExecutor, DesktopOperation, DesktopPolicy, LocalReadOnlyDesktopAdapter,
    OfflineConformanceDesktopAdapter, PolicyDecisionStatus, RiskClass, UiInteraction,
    WindowIdentity,
};
use d2i_runtime_api::{DecisionEnvelope, DecisionStatus, Evidence, PolicyResult};
use ed25519_dalek::SigningKey;
use jsonschema::{Draft, JSONSchema};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

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
            "d2i-desktop-{label}-{}-{sequence}",
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

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn fixed_hash(value: u8) -> String {
    format!("sha256:{value:064x}")
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

fn intent(operation: DesktopOperation, sequence: u64) -> DesktopActionIntent {
    let decision = decision();
    DesktopActionIntent {
        schema_version: 1,
        action_id: format!("action-{sequence}"),
        session_id: "session-1".to_owned(),
        sequence,
        generated_at_unix_ms: 1_000,
        expires_at_unix_ms: 10_000,
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

fn policy(
    adapter: &impl DesktopAdapter,
    capabilities: BTreeSet<DesktopCapability>,
    read_roots: Vec<String>,
    write_roots: Vec<String>,
    signing_key: &SigningKey,
) -> DesktopPolicy {
    let mandatory = BTreeSet::from([
        RiskClass::ExternalCommunication,
        RiskClass::CredentialSensitive,
        RiskClass::Destructive,
        RiskClass::Privileged,
    ]);
    DesktopPolicy {
        schema_version: 1,
        policy_id: "desktop-policy".to_owned(),
        policy_version: "1.0.0".to_owned(),
        allowed_actor_roles: BTreeSet::from(["operator".to_owned()]),
        allowed_capabilities: capabilities,
        approval_required_for: mandatory,
        allowed_read_roots: read_roots,
        allowed_write_roots: write_roots,
        allowed_executables: Vec::new(),
        network_allowed: false,
        allowed_network_origins: BTreeSet::new(),
        allowed_adapters: BTreeMap::from([(
            adapter.descriptor().adapter_id.clone(),
            ok(adapter.descriptor().descriptor_hash()),
        )]),
        approver_public_keys: BTreeMap::from([(
            "approver-1".to_owned(),
            signing_key
                .verifying_key()
                .to_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        )]),
        maximum_actions_per_session: 10,
        maximum_action_lifetime_ms: 60_000,
    }
}

#[cfg(windows)]
#[test]
fn decision_bound_local_read_is_audited_without_payload_leakage() {
    let temp = TempDirectory::new("local-read");
    let file = temp.path().join("note.txt");
    ok(fs::write(&file, b"classified example"));
    let adapter = ok(LocalReadOnlyDesktopAdapter::new(&[temp
        .path()
        .to_path_buf()]));
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let policy = policy(
        &adapter,
        BTreeSet::from([DesktopCapability::ReadFile]),
        vec![ok(fs::canonicalize(temp.path())).display().to_string()],
        Vec::new(),
        &signing_key,
    );
    let mut executor = ok(DesktopExecutor::new(
        adapter,
        policy,
        actor(),
        "session-1".to_owned(),
    ));
    let audit_root = temp.path().join("audit");
    let mut audit = ok(initialize_audit_ledger(&audit_root, "session-1", 20, 1_000));
    let action = intent(
        DesktopOperation::ReadFile {
            path: ok(fs::canonicalize(&file)).display().to_string(),
            maximum_bytes: 1024,
        },
        1,
    );

    let result = ok(executor.execute(&action, &decision(), None, 2_000, &mut audit));
    assert_eq!(result.payload, b"classified example");
    let audit_bytes = ok(fs::read(audit_root.join("audit-records.jsonl")));
    assert!(!audit_bytes
        .windows(b"classified example".len())
        .any(|window| window == b"classified example"));
    let verification = ok(verify_audit_ledger(&audit_root));
    assert_eq!(verification.record_count, 2);
    assert!(verification.pending_prepared_actions.is_empty());
    let replay = ok(replay_audit(
        &audit_root,
        &AuditReplayExpectation {
            session_id: "session-1".to_owned(),
            record_count: verification.record_count,
            terminal_record_hash: verification.terminal_record_hash,
            require_no_pending_actions: true,
        },
    ));
    assert!(replay.matched);
}

#[cfg(windows)]
#[test]
fn approval_is_bound_to_preparation_and_cannot_be_reused() {
    let virtual_root = if cfg!(windows) {
        r"C:\virtual".to_owned()
    } else {
        "/virtual".to_owned()
    };
    let target = format!("{virtual_root}{}note.txt", std::path::MAIN_SEPARATOR);
    let adapter = OfflineConformanceDesktopAdapter::new(
        BTreeMap::new(),
        BTreeSet::from([virtual_root.clone()]),
    );
    let signing_key = SigningKey::from_bytes(&[8_u8; 32]);
    let mut policy = policy(
        &adapter,
        BTreeSet::from([DesktopCapability::WriteFile]),
        Vec::new(),
        vec![virtual_root.clone()],
        &signing_key,
    );
    policy.approval_required_for.insert(RiskClass::Reversible);
    let action = intent(
        DesktopOperation::WriteFile {
            path: target,
            payload_hash: sha(b"hello"),
            expected_current_hash: None,
            create_new: true,
        },
        1,
    );
    let policy_decision = ok(evaluate_policy(
        &policy,
        &actor(),
        adapter.descriptor(),
        &action,
    ));
    assert_eq!(
        policy_decision.status,
        PolicyDecisionStatus::ApprovalRequired
    );
    let temp = TempDirectory::new("approval");
    let audit_root = temp.path().join("audit");
    let mut audit = ok(initialize_audit_ledger(&audit_root, "session-1", 20, 1_000));
    let mut executor = ok(DesktopExecutor::new(
        adapter,
        policy.clone(),
        actor(),
        "session-1".to_owned(),
    ));
    let preparation = ok(executor.prepare(&action, &decision(), 2_000, &mut audit));
    let approval = ok(sign_approval(
        "approval-1".to_owned(),
        "approver-1".to_owned(),
        &preparation.policy_decision,
        &preparation.prepared,
        2_000,
        5_000,
        "nonce-1".to_owned(),
        &signing_key,
    ));
    let result = ok(executor.commit(
        &action,
        &preparation,
        Some(&approval),
        Some(b"hello"),
        2_000,
        &mut audit,
    ));
    assert!(!result.payload.is_empty());
    let second_action = intent(
        DesktopOperation::WriteFile {
            path: format!("{virtual_root}{}second.txt", std::path::MAIN_SEPARATOR),
            payload_hash: sha(b"hello"),
            expected_current_hash: None,
            create_new: true,
        },
        2,
    );
    let second_preparation = ok(executor.prepare(&second_action, &decision(), 2_002, &mut audit));
    assert!(executor
        .commit(
            &second_action,
            &second_preparation,
            Some(&approval),
            Some(b"hello"),
            2_002,
            &mut audit,
        )
        .is_err());
}

#[cfg(windows)]
#[test]
fn local_adapter_rejects_change_after_prepare() {
    let temp = TempDirectory::new("toctou");
    let file = temp.path().join("note.txt");
    ok(fs::write(&file, b"before"));
    let adapter = ok(LocalReadOnlyDesktopAdapter::new(&[temp
        .path()
        .to_path_buf()]));
    let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
    let policy = policy(
        &adapter,
        BTreeSet::from([DesktopCapability::ReadFile]),
        vec![ok(fs::canonicalize(temp.path())).display().to_string()],
        Vec::new(),
        &signing_key,
    );
    let action = intent(
        DesktopOperation::ReadFile {
            path: ok(fs::canonicalize(&file)).display().to_string(),
            maximum_bytes: 1024,
        },
        1,
    );
    let audit_root = temp.path().join("audit");
    let mut audit = ok(initialize_audit_ledger(&audit_root, "session-1", 20, 1_000));
    let mut executor = ok(DesktopExecutor::new(
        adapter,
        policy,
        actor(),
        "session-1".to_owned(),
    ));
    let preparation = ok(executor.prepare(&action, &decision(), 2_000, &mut audit));
    ok(fs::write(&file, b"after"));
    assert!(executor
        .commit(&action, &preparation, None, None, 2_001, &mut audit)
        .is_err());
}

#[cfg(windows)]
#[test]
fn audit_verification_detects_tampering() {
    let temp = TempDirectory::new("audit-tamper");
    let audit_root = temp.path().join("audit");
    let _audit = ok(initialize_audit_ledger(&audit_root, "session-1", 20, 1_000));
    let manifest_path = audit_root.join("audit-manifest.json");
    let mut manifest = ok(fs::read(&manifest_path));
    if let Some(byte) = manifest.iter_mut().find(|byte| **byte == b's') {
        *byte = b'x';
    }
    ok(fs::write(&manifest_path, manifest));
    assert!(verify_audit_ledger(&audit_root).is_err());
}

#[test]
fn high_risk_policy_cannot_disable_human_approval() {
    let adapter = OfflineConformanceDesktopAdapter::new(BTreeMap::new(), BTreeSet::new());
    let signing_key = SigningKey::from_bytes(&[10_u8; 32]);
    let mut policy = policy(
        &adapter,
        BTreeSet::from([DesktopCapability::DeletePath]),
        Vec::new(),
        Vec::new(),
        &signing_key,
    );
    policy.approval_required_for.remove(&RiskClass::Destructive);
    assert!(policy.validate().is_err());
}

#[test]
fn policy_denies_unpinned_ui_process_and_allows_network_denied_launch() {
    let adapter = OfflineConformanceDesktopAdapter::new(BTreeMap::new(), BTreeSet::new());
    let signing_key = SigningKey::from_bytes(&[12_u8; 32]);
    let mut policy = policy(
        &adapter,
        BTreeSet::from([
            DesktopCapability::UiInteract,
            DesktopCapability::TerminateProcess,
            DesktopCapability::LaunchProcess,
        ]),
        Vec::new(),
        Vec::new(),
        &signing_key,
    );
    let ui = intent(
        DesktopOperation::UiInteract {
            window: WindowIdentity {
                process_id: 42,
                executable_hash: fixed_hash(20),
                title_hash: fixed_hash(21),
            },
            interaction: UiInteraction::Invoke {
                automation_id: "submit".to_owned(),
            },
        },
        1,
    );
    let ui_decision = ok(evaluate_policy(
        &policy,
        &actor(),
        adapter.descriptor(),
        &ui,
    ));
    assert_eq!(ui_decision.status, PolicyDecisionStatus::Denied);
    assert!(ui_decision
        .reasons
        .iter()
        .any(|reason| reason.contains("executable identity")));

    let terminate = intent(
        DesktopOperation::TerminateProcess {
            process_id: 42,
            expected_executable_hash: fixed_hash(22),
        },
        1,
    );
    let terminate_decision = ok(evaluate_policy(
        &policy,
        &actor(),
        adapter.descriptor(),
        &terminate,
    ));
    assert_eq!(terminate_decision.status, PolicyDecisionStatus::Denied);

    let executable_root = if cfg!(windows) {
        r"C:\Windows".to_owned()
    } else {
        "/usr/bin".to_owned()
    };
    let executable = format!("{executable_root}{}tool", std::path::MAIN_SEPARATOR);
    policy.allowed_read_roots = vec![executable_root.clone()];
    policy.allowed_executables = vec![d2i_desktop::AllowedExecutable {
        path: executable.clone(),
        content_hash: fixed_hash(23),
        arguments_prefix: Vec::new(),
        may_request_network: false,
    }];
    let launch = intent(
        DesktopOperation::LaunchProcess {
            executable,
            executable_hash: fixed_hash(23),
            arguments: Vec::new(),
            working_directory: executable_root,
            network_requested: false,
        },
        1,
    );
    let launch_decision = ok(evaluate_policy(
        &policy,
        &actor(),
        adapter.descriptor(),
        &launch,
    ));
    assert_eq!(
        launch_decision.status,
        PolicyDecisionStatus::ApprovalRequired
    );
    assert!(!launch_decision
        .reasons
        .iter()
        .any(|reason| reason == "network is denied by policy"));
}

#[test]
fn published_action_and_policy_schemas_accept_runtime_contracts() {
    let adapter = OfflineConformanceDesktopAdapter::new(BTreeMap::new(), BTreeSet::new());
    let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
    let virtual_root = if cfg!(windows) {
        r"C:\virtual".to_owned()
    } else {
        "/virtual".to_owned()
    };
    let policy = policy(
        &adapter,
        BTreeSet::from([DesktopCapability::ReadFile]),
        vec![virtual_root.clone()],
        Vec::new(),
        &signing_key,
    );
    let action = intent(
        DesktopOperation::ReadFile {
            path: format!("{virtual_root}{}note.txt", std::path::MAIN_SEPARATOR),
            maximum_bytes: 1024,
        },
        1,
    );
    validate_schema(
        "desktop/desktop-policy.schema.json",
        ok(serde_json::to_value(policy)),
    );
    validate_schema(
        "desktop/desktop-action-intent.schema.json",
        ok(serde_json::to_value(action)),
    );
}

fn validate_schema(relative: &str, instance: serde_json::Value) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas")
        .join(relative);
    let schema: serde_json::Value = ok(serde_json::from_slice(&ok(fs::read(path))));
    let compiled = ok(JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema));
    let errors: Vec<String> = match compiled.validate(&instance) {
        Ok(()) => Vec::new(),
        Err(errors) => errors.map(|error| error.to_string()).collect(),
    };
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}
