use d2i_compiler::compile_package;
use d2i_core::{build_inventory, write_source_lock};
use d2i_embodied::{
    append_robot_episode, create_fleet_promotion, dispatch_authorized, initialize_robot_memory,
    read_robot_episodes, replay_simulation, validate_permit, verify_fleet_promotion,
    verify_robot_memory, ActionIntent, ActionKind, DeadlineClass, EmbodiedError, EmbodiedPlanner,
    FleetApproval, FleetCohort, FleetPromotionInput, HardwarePort, HardwareProfile, MemoryActor,
    PackageSignatureAttestation, RobotEpisode, RobotMemoryPolicy, RobotOutcome, Ros2Adapter,
    Ros2TopicMap, Ros2Transport, SafetyAssessment, SafetyConstraint, SafetyController,
    SafetyDecisionStatus, SensorEvent, SensorKind, SimulationFrame, SimulationQualification,
    SimulationTrace,
};
use jsonschema::{Draft, JSONSchema};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn ok<T, E: Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("test operation failed: {error:?}"),
    }
}

fn some<T>(value: Option<T>, label: &str) -> T {
    match value {
        Some(value) => value,
        None => panic!("expected {label}"),
    }
}

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(label: &str) -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "d2i-phase9-{label}-{}-{sequence}",
            std::process::id()
        ));
        ok(fs::create_dir_all(&path));
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

fn sha(value: &impl serde::Serialize) -> String {
    let bytes = ok(serde_json::to_vec(value));
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn fixed_hash(value: u8) -> String {
    format!("sha256:{value:064x}")
}

fn example_pack() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/equipment-maintenance")
}

fn copy_directory(source: &Path, destination: &Path) {
    ok(fs::create_dir_all(destination));
    for entry in ok(fs::read_dir(source)) {
        let entry = ok(entry);
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if source_path.is_dir() {
            copy_directory(&source_path, &destination_path);
        } else {
            ok(fs::copy(source_path, destination_path));
        }
    }
}

fn sensor(sequence: u64, observed_at: u64) -> SensorEvent {
    let payload = json!({"range_millimeters": 850, "obstacle": false});
    SensorEvent {
        schema_version: 1,
        event_id: format!("sensor-{sequence}"),
        robot_id: "robot-1".to_owned(),
        sequence,
        observed_at_unix_nanos: observed_at,
        frame_id: "base-link".to_owned(),
        sensor_kind: SensorKind::Lidar,
        deadline_class: DeadlineClass::Control,
        payload_hash: sha(&payload),
        payload,
        quality_milli: 995,
        labels: BTreeMap::from([("simulation".to_owned(), "phase9".to_owned())]),
    }
}

fn intent(event: &SensorEvent, tick: u64, build_id: &str, package_hash: &str) -> ActionIntent {
    ActionIntent {
        schema_version: 1,
        intent_id: format!("intent-{}", event.sequence),
        robot_id: event.robot_id.clone(),
        generated_at_unix_nanos: tick,
        expires_at_unix_nanos: tick.saturating_add(100_000_000),
        deadline_class: DeadlineClass::Control,
        action_kind: ActionKind::Navigate,
        parameters: json!({"target": "inspection-bay", "maximum_speed_mps": 0.3}),
        constraints: vec![SafetyConstraint {
            constraint_id: "clearance".to_owned(),
            description: "maintain configured obstacle clearance".to_owned(),
            hard: true,
        }],
        source_build_id: build_id.to_owned(),
        source_package_content_hash: package_hash.to_owned(),
        evidence_hashes: vec![event.payload_hash.clone()],
    }
}

#[derive(Clone)]
struct PermitController;

impl SafetyController for PermitController {
    fn assess(
        &self,
        intent: &ActionIntent,
        now_unix_nanos: u64,
    ) -> Result<SafetyAssessment, EmbodiedError> {
        Ok(SafetyAssessment {
            schema_version: 1,
            controller_id: "simulation-safety".to_owned(),
            intent_hash: intent.content_hash()?,
            status: SafetyDecisionStatus::Permit,
            evaluated_at_unix_nanos: now_unix_nanos,
            permit_expires_at_unix_nanos: intent.expires_at_unix_nanos,
            reasons: vec!["simulation constraints satisfied".to_owned()],
        })
    }
}

struct TestPlanner {
    build_id: String,
    package_hash: String,
}

impl EmbodiedPlanner for TestPlanner {
    fn plan(
        &self,
        event: &SensorEvent,
        tick_unix_nanos: u64,
    ) -> Result<Option<ActionIntent>, EmbodiedError> {
        Ok(Some(intent(
            event,
            tick_unix_nanos,
            &self.build_id,
            &self.package_hash,
        )))
    }
}

#[derive(Default)]
struct MemoryTransport {
    received: BTreeMap<String, VecDeque<Vec<u8>>>,
    published: Vec<(String, Vec<u8>)>,
}

impl Ros2Transport for MemoryTransport {
    fn receive(&mut self, topic: &str) -> Result<Option<Vec<u8>>, EmbodiedError> {
        Ok(self.received.get_mut(topic).and_then(VecDeque::pop_front))
    }

    fn publish(&mut self, topic: &str, payload: &[u8]) -> Result<(), EmbodiedError> {
        self.published.push((topic.to_owned(), payload.to_vec()));
        Ok(())
    }
}

struct TestHardware {
    profile: HardwareProfile,
    dispatched: bool,
}

impl HardwarePort for TestHardware {
    fn profile(&self) -> &HardwareProfile {
        &self.profile
    }

    fn dispatch_authorized(
        &mut self,
        _intent: &ActionIntent,
        _assessment: &SafetyAssessment,
    ) -> Result<(), EmbodiedError> {
        self.dispatched = true;
        Ok(())
    }
}

fn file_hashes(root: &Path) -> BTreeMap<String, String> {
    fn visit(root: &Path, path: &Path, output: &mut BTreeMap<String, String>) {
        for entry in ok(fs::read_dir(path)) {
            let entry = ok(entry);
            let path = entry.path();
            if path.is_dir() {
                visit(root, &path, output);
            } else {
                let relative = ok(path.strip_prefix(root))
                    .to_string_lossy()
                    .replace('\\', "/");
                output.insert(
                    relative,
                    format!("sha256:{:x}", Sha256::digest(ok(fs::read(path)))),
                );
            }
        }
    }
    let mut output = BTreeMap::new();
    visit(root, root, &mut output);
    output
}

#[test]
fn sensor_and_action_schemas_match_typed_contracts_and_exclude_safety_loop_actions() {
    let schema_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/embodied");
    let event = sensor(1, 1_000_000_000);
    let action = intent(&event, 1_010_000_000, "build-1", &fixed_hash(1));
    for (file, value) in [
        ("sensor-event.schema.json", ok(serde_json::to_value(&event))),
        (
            "action-intent.schema.json",
            ok(serde_json::to_value(&action)),
        ),
    ] {
        let schema: serde_json::Value = ok(serde_json::from_slice(&ok(fs::read(
            schema_root.join(file),
        ))));
        let mut options = JSONSchema::options();
        options.with_draft(Draft::Draft202012);
        assert!(ok(options.compile(&schema)).is_valid(&value));
    }
    ok(event.validate());
    ok(action.validate());

    let mut unsafe_action = action;
    unsafe_action.deadline_class = DeadlineClass::SafetyLoop;
    unsafe_action.expires_at_unix_nanos = unsafe_action
        .generated_at_unix_nanos
        .saturating_add(10_000_000);
    assert!(matches!(
        unsafe_action.validate(),
        Err(EmbodiedError::Deadline(_))
    ));
}

#[test]
fn ros_replay_and_hardware_dispatch_preserve_the_safety_boundary() {
    let build_id = "build-robot-1";
    let package_hash = fixed_hash(2);
    let first = sensor(1, 1_000_000_000);
    let second = sensor(2, 2_000_000_000);
    let first_tick = 1_010_000_000;
    let second_tick = 2_010_000_000;
    let first_intent = intent(&first, first_tick, build_id, &package_hash);
    let second_intent = intent(&second, second_tick, build_id, &package_hash);
    let trace = SimulationTrace {
        schema_version: 1,
        simulation_id: "warehouse-replay-1".to_owned(),
        world_content_hash: fixed_hash(3),
        source_build_id: build_id.to_owned(),
        source_package_content_hash: package_hash.clone(),
        frames: vec![
            SimulationFrame {
                tick_unix_nanos: first_tick,
                sensor_event: first.clone(),
                expected_intent_hash: Some(ok(first_intent.content_hash())),
                expected_safety_status: Some(SafetyDecisionStatus::Permit),
            },
            SimulationFrame {
                tick_unix_nanos: second_tick,
                sensor_event: second,
                expected_intent_hash: Some(ok(second_intent.content_hash())),
                expected_safety_status: Some(SafetyDecisionStatus::Permit),
            },
        ],
    };
    let planner = TestPlanner {
        build_id: build_id.to_owned(),
        package_hash,
    };
    let first_report = ok(replay_simulation(&trace, &planner, &PermitController));
    let second_report = ok(replay_simulation(&trace, &planner, &PermitController));
    assert!(first_report.matched);
    assert_eq!(first_report.replay_hash, second_report.replay_hash);

    let assessment = ok(PermitController.assess(&first_intent, first_tick));
    ok(validate_permit(&first_intent, &assessment, first_tick));
    let profile = HardwareProfile {
        profile_id: "warehouse-mobile-v1".to_owned(),
        robot_id: "robot-1".to_owned(),
        robot_class: "mobile-inspector".to_owned(),
        sensor_kinds: BTreeSet::from([SensorKind::Lidar]),
        action_kinds: BTreeSet::from([ActionKind::Navigate]),
        safety_controller_required: true,
        maximum_command_bytes: 64 * 1024,
    };
    let mut hardware = TestHardware {
        profile,
        dispatched: false,
    };
    ok(dispatch_authorized(
        &mut hardware,
        &first_intent,
        &assessment,
        first_tick,
    ));
    assert!(hardware.dispatched);

    let topics = Ros2TopicMap {
        sensor_topics: BTreeMap::from([(SensorKind::Lidar, "/robot_1/lidar".to_owned())]),
        action_intent_topic: "/robot_1/d2i/action_intent".to_owned(),
        safety_assessment_topic: "/robot_1/safety/assessment".to_owned(),
    };
    let mut transport = MemoryTransport::default();
    transport.received.insert(
        "/robot_1/lidar".to_owned(),
        VecDeque::from([ok(serde_json::to_vec(&first))]),
    );
    let mut adapter = ok(Ros2Adapter::new(topics, transport));
    assert_eq!(
        some(
            ok(adapter.poll_sensor(&SensorKind::Lidar)),
            "ROS sensor event"
        ),
        first
    );
    ok(adapter.publish_intent(&first_intent));
    ok(adapter.publish_safety_assessment(&assessment));
    assert_eq!(adapter.into_transport().published.len(), 2);
}

#[test]
fn robot_memory_and_signed_fleet_promotion_are_auditable_and_package_immutable() {
    let temporary = TempDirectory::new("fleet");
    let package = temporary.path().join("robot-package.d2ip");
    let compile = compile_package(&example_pack(), &package);
    assert!(
        !compile.has_errors(),
        "compile diagnostics: {:?} {:?}",
        compile.diagnostics,
        compile.package_error
    );
    let build = some(compile.build, "build report");
    let package_before = file_hashes(&package);
    let rollback_source = temporary.path().join("rollback-source");
    copy_directory(&example_pack(), &rollback_source);
    let rollback_readme = rollback_source.join("README.md");
    let mut rollback_readme_text = ok(fs::read_to_string(&rollback_readme));
    rollback_readme_text.push_str("\nRollback baseline fixture.\n");
    ok(fs::write(&rollback_readme, rollback_readme_text));
    let (inventory, diagnostics) = build_inventory(&rollback_source);
    assert!(
        diagnostics.is_empty(),
        "rollback inventory diagnostics: {diagnostics:?}"
    );
    ok(write_source_lock(&some(
        inventory,
        "rollback source inventory",
    )));
    let rollback_package = temporary.path().join("rollback-package.d2ip");
    let rollback_compile = compile_package(&rollback_source, &rollback_package);
    assert!(
        !rollback_compile.has_errors(),
        "rollback compile diagnostics: {:?} {:?}",
        rollback_compile.diagnostics,
        rollback_compile.package_error
    );
    let rollback_build = some(rollback_compile.build, "rollback build report");
    assert_ne!(build.build_id, rollback_build.build_id);
    let actor = MemoryActor {
        actor_id: "robot-memory-curator".to_owned(),
        roles: BTreeSet::from(["robot-memory".to_owned()]),
    };
    let memory = temporary.path().join("robot-memory");
    ok(initialize_robot_memory(
        &memory,
        &RobotMemoryPolicy {
            schema_version: 1,
            memory_id: "fleet-memory-1".to_owned(),
            allowed_robot_ids: BTreeSet::from(["robot-1".to_owned()]),
            append_roles: BTreeSet::from(["robot-memory".to_owned()]),
            read_roles: BTreeSet::from(["robot-memory".to_owned()]),
            maximum_entries: 100,
            maximum_age_seconds: 3600,
        },
    ));
    let event = sensor(1, 1_000_000_000);
    let tick = 1_010_000_000;
    let action = intent(&event, tick, &build.build_id, &build.package_content_hash);
    let assessment = ok(PermitController.assess(&action, tick));
    let recorded_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |duration| duration.as_secs());
    ok(append_robot_episode(
        &memory,
        &actor,
        RobotEpisode {
            schema_version: 1,
            episode_id: "robot-episode-1".to_owned(),
            robot_id: "robot-1".to_owned(),
            recorded_at_unix_seconds: recorded_at,
            build_id: build.build_id.clone(),
            package_content_hash: build.package_content_hash.clone(),
            sensor_event_ids: vec![event.event_id],
            action_intent: Some(action),
            safety_assessment: Some(assessment),
            outcome: RobotOutcome::Completed,
            correction: None,
            simulation_id: Some("warehouse-replay-1".to_owned()),
            provenance_hashes: vec![fixed_hash(4)],
        },
    ));
    assert_eq!(ok(verify_robot_memory(&memory)).entry_count, 1);
    assert_eq!(ok(read_robot_episodes(&memory, &actor)).len(), 1);

    let replay_hash = fixed_hash(5);
    let promotion_input = FleetPromotionInput {
        fleet_id: "warehouse-fleet".to_owned(),
        rollout_id: "rollout-2026-07-27".to_owned(),
        created_at_unix_seconds: 100,
        hardware_profile_hashes: vec![fixed_hash(6), fixed_hash(7)],
        safety_controller_contract_id: "safety-controller-v1".to_owned(),
        package_signature: PackageSignatureAttestation {
            verifier_id: "offline-package-verifier".to_owned(),
            signature_scheme: "external-ed25519".to_owned(),
            package_content_hash: build.package_content_hash.clone(),
            verified_at_unix_seconds: 90,
            verified: true,
        },
        simulation: SimulationQualification {
            simulation_id: "warehouse-replay-1".to_owned(),
            source_build_id: build.build_id.clone(),
            source_package_content_hash: build.package_content_hash.clone(),
            replay_hash,
            matched: true,
            critical_failure_count: 0,
        },
        cohorts: vec![
            FleetCohort {
                cohort_id: "canary".to_owned(),
                cumulative_percent: 5,
                robot_classes: BTreeSet::from(["mobile-inspector".to_owned()]),
                observation_seconds: 3600,
            },
            FleetCohort {
                cohort_id: "fleet".to_owned(),
                cumulative_percent: 100,
                robot_classes: BTreeSet::from(["mobile-inspector".to_owned()]),
                observation_seconds: 86_400,
            },
        ],
        rollback_build_id: rollback_build.build_id.clone(),
        rollback_package_content_hash: rollback_build.package_content_hash.clone(),
        approval: FleetApproval {
            approver_id: "fleet-safety-owner".to_owned(),
            approved_at_unix_seconds: 100,
            rationale: "verified package, simulation, safety, and rollback evidence".to_owned(),
        },
    };
    let record = ok(create_fleet_promotion(
        &package,
        &rollback_package,
        promotion_input.clone(),
        [9_u8; 32],
    ));
    ok(verify_fleet_promotion(&record));
    assert_eq!(record.state, "approved_for_staged_rollout");
    assert_eq!(record.build_id, build.build_id);

    let mut invalid_input = promotion_input;
    invalid_input.package_signature.verified = false;
    assert!(
        create_fleet_promotion(&package, &rollback_package, invalid_input, [9_u8; 32]).is_err()
    );
    let mut tampered = record;
    tampered.rollout_id = "rollout-tampered".to_owned();
    assert!(verify_fleet_promotion(&tampered).is_err());

    let episodes_path = memory.join("robot-episodes.jsonl");
    let mut bytes = ok(fs::read(&episodes_path));
    if let Some(byte) = bytes.iter_mut().find(|byte| **byte == b'r') {
        *byte = b's';
    }
    ok(fs::write(&episodes_path, bytes));
    assert!(verify_robot_memory(&memory).is_err());
    assert_eq!(file_hashes(&package), package_before);
}
