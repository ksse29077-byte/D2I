use d2i_compiler::compile_package;
use d2i_learning::{
    append_episode, append_promotion, build_candidate_package, evaluate_candidate_package,
    export_store, initialize_store, read_verified_episodes, verify_promotion_ledger, verify_store,
    ActionRecord, Actor, Approval, CanaryPlan, CandidateBuildOptions, CorrectionRecord, Episode,
    EpisodeOutcome, EpisodePolicy, EpisodeProvenance, ExperienceStorePolicy, LearningError,
    OutcomeStatus, PromotionPolicy, RolePolicy, RollbackPlan, SelectedRoute, Situation, TrustLevel,
};
use jsonschema::{Draft, JSONSchema};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
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
            "d2i-phase8-{label}-{}-{sequence}",
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

fn example_pack() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/equipment-maintenance")
}

fn roles(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn actor() -> Actor {
    Actor {
        actor_id: "phase8-test-runner".to_owned(),
        roles: roles(&["experience-curator"]),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |duration| duration.as_secs())
}

fn episode(
    index: u32,
    build_id: &str,
    package_hash: &str,
    status: OutcomeStatus,
    trust: TrustLevel,
) -> Episode {
    let correction = if matches!(status, OutcomeStatus::Corrected | OutcomeStatus::Failed) {
        Some(CorrectionRecord {
            corrected_output: json!({"fault_code": "bearing-wear", "reviewed": true}),
            reason: "reviewed field correction".to_owned(),
            reviewer_id: "reviewer-1".to_owned(),
        })
    } else {
        None
    };
    Episode {
        schema_version: 1,
        episode_id: format!("episode-{index:03}"),
        recorded_at_unix_seconds: now(),
        build_id: build_id.to_owned(),
        package_content_hash: package_hash.to_owned(),
        situation: Situation {
            category: "equipment-diagnosis".to_owned(),
            request: json!({
                "equipment_id": format!("pump-{index}"),
                "symptom": "vibration",
                "error_code": "E101"
            }),
            context_labels: BTreeMap::from([("site".to_owned(), "offline-lab".to_owned())]),
            edge_case: index == 11,
        },
        selected_route: SelectedRoute {
            skill_id: "diagnose_fault".to_owned(),
            node_ids: vec!["normalize-request".to_owned(), "case-retriever".to_owned()],
            module_ids: vec!["case-retriever-compact".to_owned()],
        },
        action: ActionRecord {
            kind: "decision".to_owned(),
            summary: "offline equipment diagnosis".to_owned(),
            side_effect_requested: false,
        },
        output: json!({"fault_code": "bearing-wear", "human_review": false}),
        outcome: EpisodeOutcome {
            status,
            reward_milli: 900,
            critical_error: false,
            labels: BTreeMap::from([("review".to_owned(), "accepted".to_owned())]),
        },
        correction,
        policy: EpisodePolicy {
            result: "allow".to_owned(),
            policy_ids: vec!["maintenance-safety".to_owned()],
            human_approved: false,
        },
        provenance: vec![EpisodeProvenance {
            source: "manual-001".to_owned(),
            span: "section-2".to_owned(),
            content_hash: format!("sha256:{index:064x}"),
        }],
        trust,
    }
}

fn file_hashes(root: &Path) -> BTreeMap<String, String> {
    fn visit(root: &Path, path: &Path, output: &mut BTreeMap<String, String>) {
        for entry in ok(fs::read_dir(path)) {
            let entry = ok(entry);
            let entry_path = entry.path();
            if entry_path.is_dir() {
                visit(root, &entry_path, output);
            } else {
                let relative = ok(entry_path.strip_prefix(root))
                    .to_string_lossy()
                    .replace('\\', "/");
                let bytes = ok(fs::read(&entry_path));
                output.insert(relative, format!("sha256:{:x}", Sha256::digest(bytes)));
            }
        }
    }

    let mut output = BTreeMap::new();
    visit(root, root, &mut output);
    output
}

#[test]
fn episode_schema_accepts_typed_records_and_rejects_missing_provenance() {
    let schema_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/learning/episode.schema.json");
    let schema: serde_json::Value = ok(serde_json::from_slice(&ok(fs::read(schema_path))));
    let mut options = JSONSchema::options();
    options.with_draft(Draft::Draft202012);
    let validator = ok(options.compile(&schema));
    let value = ok(serde_json::to_value(episode(
        1,
        "build-1",
        &format!("sha256:{:064x}", 1),
        OutcomeStatus::Success,
        TrustLevel::Reviewed,
    )));
    assert!(validator.is_valid(&value));

    let mut incomplete = value;
    if let Some(object) = incomplete.as_object_mut() {
        object.remove("provenance");
    }
    assert!(!validator.is_valid(&incomplete));
}

#[test]
fn controlled_learning_pipeline_is_auditable_and_never_mutates_production() {
    let temporary = TempDirectory::new("pipeline");
    let base = temporary.path().join("production.d2ip");
    let compile = compile_package(&example_pack(), &base);
    assert!(
        !compile.has_errors(),
        "compile diagnostics: {:?} {:?}",
        compile.diagnostics,
        compile.package_error
    );
    let build = some(compile.build, "base build report");
    let production_before = file_hashes(&base);

    let role_policy = RolePolicy {
        append: roles(&["experience-curator"]),
        export: roles(&["experience-curator"]),
        build_candidate: roles(&["experience-curator"]),
    };
    let store_policy = ExperienceStorePolicy {
        schema_version: 1,
        store_id: "equipment-experience".to_owned(),
        roles: role_policy,
        allowed_build_ids: roles(&[&build.build_id]),
        maximum_entries: 100,
        maximum_age_seconds: 3600,
    };
    let store = temporary.path().join("experience-store");
    ok(initialize_store(&store, &store_policy));

    for index in 0..12 {
        let status = if index == 2 {
            OutcomeStatus::Corrected
        } else {
            OutcomeStatus::Success
        };
        ok(append_episode(
            &store,
            &actor(),
            episode(
                index,
                &build.build_id,
                &build.package_content_hash,
                status,
                TrustLevel::Reviewed,
            ),
        ));
    }
    let mut duplicate = episode(
        100,
        &build.build_id,
        &build.package_content_hash,
        OutcomeStatus::Success,
        TrustLevel::Reviewed,
    );
    duplicate.situation = episode(
        0,
        &build.build_id,
        &build.package_content_hash,
        OutcomeStatus::Success,
        TrustLevel::Reviewed,
    )
    .situation;
    ok(append_episode(&store, &actor(), duplicate));
    ok(append_episode(
        &store,
        &actor(),
        episode(
            101,
            &build.build_id,
            &build.package_content_hash,
            OutcomeStatus::Success,
            TrustLevel::Untrusted,
        ),
    ));
    let conflict_left = episode(
        102,
        &build.build_id,
        &build.package_content_hash,
        OutcomeStatus::Success,
        TrustLevel::Reviewed,
    );
    let mut conflict_right = episode(
        103,
        &build.build_id,
        &build.package_content_hash,
        OutcomeStatus::Success,
        TrustLevel::Reviewed,
    );
    conflict_right.situation = conflict_left.situation.clone();
    conflict_right.output = json!({"fault_code": "cooling-failure", "human_review": false});
    ok(append_episode(&store, &actor(), conflict_left));
    ok(append_episode(&store, &actor(), conflict_right));

    let verification = ok(verify_store(&store));
    assert_eq!(verification.entry_count, 16);
    let denied_actor = Actor {
        actor_id: "observer".to_owned(),
        roles: roles(&["read-only"]),
    };
    assert!(matches!(
        read_verified_episodes(&store, &denied_actor),
        Err(LearningError::AccessDenied(_))
    ));
    let export = temporary.path().join("episodes-export.jsonl");
    let export_hash = ok(export_store(&store, &export, &actor()));
    assert!(export_hash.starts_with("sha256:"));

    let candidate_root = temporary.path().join("candidate.d2ic");
    let candidate = ok(build_candidate_package(
        &store,
        &base,
        &candidate_root,
        &actor(),
        &CandidateBuildOptions {
            candidate_id: "candidate-2026-07-27".to_owned(),
            created_at_unix_seconds: now(),
            builder_id: "offline-builder-1".to_owned(),
        },
    ));
    assert_eq!(candidate.manifest.state, "candidate");
    assert_eq!(candidate.dataset_report.clean_episode_count, 12);
    assert_eq!(candidate.dataset_report.duplicate_count, 1);
    assert_eq!(candidate.dataset_report.quarantined_count, 3);
    assert_eq!(candidate.dataset_report.poisoning_flag_count, 3);
    assert_eq!(candidate.dataset_report.leakage_group_overlap_count, 0);
    assert!(candidate.dataset_report.training_count > 0);
    assert!(candidate.dataset_report.validation_count > 0);
    assert!(candidate.dataset_report.test_count > 0);
    assert!(candidate.dataset_report.distribution_shift_flags.is_empty());
    assert!(!candidate.adaptations.retrieval_weights.is_empty());
    assert!(!candidate.adaptations.rule_candidates.is_empty());
    assert!(!candidate.adaptations.executor_refits.is_empty());
    assert!(!candidate.adaptations.routing_thresholds.is_empty());
    assert!(matches!(
        build_candidate_package(
            &store,
            &base,
            &base.join("nested-candidate"),
            &actor(),
            &CandidateBuildOptions {
                candidate_id: "invalid-nested-candidate".to_owned(),
                created_at_unix_seconds: now(),
                builder_id: "offline-builder-1".to_owned(),
            },
        ),
        Err(LearningError::Invalid(_))
    ));

    let evaluated_at = now();
    let evaluation = ok(evaluate_candidate_package(
        &candidate_root,
        &base,
        "offline-evaluator-1",
        evaluated_at,
        1,
        PromotionPolicy::default(),
    ));
    assert!(evaluation.gate.passed, "{:?}", evaluation.gate.reasons);
    assert_eq!(evaluation.gold_dataset_id, "eval/gold.jsonl");
    assert_ne!(evaluation.gold_dataset_hash, build.package_content_hash);

    let approval = Approval {
        approver_id: "release-manager-1".to_owned(),
        approved_at_unix_seconds: evaluated_at,
        rationale: "gold set and hard gates passed".to_owned(),
    };
    let canary = CanaryPlan {
        shadow_required: true,
        canary_percent: 5,
        observation_seconds: 3600,
        stop_on_critical_error: true,
    };
    let rollback = RollbackPlan {
        rollback_build_id: build.build_id.clone(),
        rollback_package_content_hash: build.package_content_hash.clone(),
        maximum_critical_errors: 0,
        minimum_task_success_rate_milli: 1000,
    };

    let mut altered_evaluation = evaluation.clone();
    altered_evaluation.candidate.critical_error_rate = 1.0;
    assert!(matches!(
        append_promotion(
            &temporary.path().join("rejected-ledger"),
            &candidate_root,
            &altered_evaluation,
            approval.clone(),
            canary.clone(),
            rollback.clone(),
            [7_u8; 32],
        ),
        Err(LearningError::Integrity(_))
    ));

    let ledger = temporary.path().join("promotion-ledger");
    let record = ok(append_promotion(
        &ledger,
        &candidate_root,
        &evaluation,
        approval,
        canary,
        rollback,
        [7_u8; 32],
    ));
    assert_eq!(record.state, "approved_for_next_build");
    assert_eq!(record.dataset_hash, candidate.dataset_report.dataset_hash);
    assert_eq!(record.gold_dataset_hash, evaluation.gold_dataset_hash);
    let records = ok(verify_promotion_ledger(&ledger));
    assert_eq!(records, vec![record]);
    assert_eq!(file_hashes(&base), production_before);

    let ledger_file = ledger.join("promotions.jsonl");
    let mut ledger_bytes = ok(fs::read(&ledger_file));
    if let Some(byte) = ledger_bytes.iter_mut().find(|byte| **byte == b'a') {
        *byte = b'b';
    }
    ok(fs::write(&ledger_file, ledger_bytes));
    assert!(verify_promotion_ledger(&ledger).is_err());

    let store_file = store.join("episodes.jsonl");
    let mut store_bytes = ok(fs::read(&store_file));
    if let Some(byte) = store_bytes.iter_mut().find(|byte| **byte == b'e') {
        *byte = b'f';
    }
    ok(fs::write(&store_file, store_bytes));
    assert!(verify_store(&store).is_err());
    assert_eq!(file_hashes(&base), production_before);
}
