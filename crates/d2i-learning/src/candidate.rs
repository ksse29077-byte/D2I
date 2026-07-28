use crate::{
    json_bytes, pretty_json_bytes, read_bounded, sha256_bytes, write_new, Actor, Episode,
    LearningError, OutcomeStatus, TrustLevel,
};
use d2i_compiler::verify_package;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MANIFEST_FILE: &str = "candidate.json";
const HASHES_FILE: &str = "hashes.sha256";
const TRAIN_FILE: &str = "dataset/train.jsonl";
const VALIDATION_FILE: &str = "dataset/validation.jsonl";
const TEST_FILE: &str = "dataset/test.jsonl";
const QUARANTINE_FILE: &str = "dataset/quarantine.json";
const DATASET_REPORT_FILE: &str = "reports/dataset.json";
const ADAPTATIONS_FILE: &str = "adaptations/proposals.json";
const MAX_CANDIDATE_FILE_BYTES: u64 = 64 * 1024 * 1024;
static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Explicit deterministic identity and creation metadata for a candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateBuildOptions {
    pub candidate_id: String,
    pub created_at_unix_seconds: u64,
    pub builder_id: String,
}

/// Quarantined episode and machine-readable poisoning reasons.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineRecord {
    pub episode_id: String,
    pub reasons: Vec<String>,
}

/// Dataset hygiene, split, edge-case, and shift observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateDatasetReport {
    pub source_episode_count: u64,
    pub clean_episode_count: u64,
    pub duplicate_count: u64,
    pub quarantined_count: u64,
    pub poisoning_flag_count: u64,
    pub training_count: u64,
    pub validation_count: u64,
    pub test_count: u64,
    pub edge_case_count: u64,
    pub leakage_group_overlap_count: u64,
    pub unresolved_poisoning_flag_count: u64,
    pub distribution_shift_flags: Vec<String>,
    pub dataset_hash: String,
}

/// Retrieval weighting proposal derived from reviewed outcomes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetrievalWeightProposal {
    pub module_id: String,
    pub weight_delta_basis_points: i32,
    pub supporting_episode_count: u64,
}

/// Non-executable rule candidate requiring a later compiler review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleCandidateProposal {
    pub proposal_id: String,
    pub source_episode_id: String,
    pub rationale: String,
    pub requires_human_review: bool,
}

/// Framework-neutral refit request; no model training occurs in this crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorRefitProposal {
    pub module_id: String,
    pub dataset_hash: String,
    pub adapter_contract: String,
    pub requires_offline_evaluation: bool,
}

/// Bounded routing-threshold proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingThresholdProposal {
    pub skill_id: String,
    pub current_threshold_milli: u16,
    pub proposed_threshold_milli: u16,
    pub supporting_episode_count: u64,
}

/// Four adaptation levels retained as data rather than applied changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdaptationProposals {
    pub retrieval_weights: Vec<RetrievalWeightProposal>,
    pub rule_candidates: Vec<RuleCandidateProposal>,
    pub executor_refits: Vec<ExecutorRefitProposal>,
    pub routing_thresholds: Vec<RoutingThresholdProposal>,
}

/// Immutable candidate manifest bound to a verified base package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidatePackageManifest {
    pub schema_version: u32,
    pub state: String,
    pub candidate_id: String,
    pub created_at_unix_seconds: u64,
    pub builder_id: String,
    pub base_build_id: String,
    pub base_package_content_hash: String,
    pub dataset_hash: String,
    pub adaptation_hash: String,
    pub payload_hash: String,
}

/// Fully verified candidate package data.
#[derive(Debug, Clone)]
pub struct CandidatePackage {
    pub root: PathBuf,
    pub manifest: CandidatePackageManifest,
    pub dataset_report: CandidateDatasetReport,
    pub adaptations: AdaptationProposals,
    pub candidate_content_hash: String,
}

/// Builds a physically separate immutable candidate bundle from verified episodes.
pub fn build_candidate_package(
    store_root: &Path,
    base_package: &Path,
    output: &Path,
    actor: &Actor,
    options: &CandidateBuildOptions,
) -> Result<CandidatePackage, LearningError> {
    validate_candidate_options(options)?;
    if output.exists() {
        return Err(LearningError::Invalid(
            "candidate output path already exists".to_owned(),
        ));
    }
    let base =
        verify_package(base_package).map_err(|error| LearningError::Package(error.to_string()))?;
    ensure_separate_output(base_package, output)?;
    let episodes = crate::read_verified_episodes(store_root, actor)?;
    let dataset = build_dataset(episodes, &base.build_id, &base.package_content_hash)?;
    let adaptations = build_adaptations(&dataset.clean, &dataset.report.dataset_hash);
    let adaptation_bytes = pretty_json_bytes(&adaptations)?;
    let adaptation_hash = sha256_bytes(&adaptation_bytes);

    let parent = output
        .parent()
        .ok_or_else(|| LearningError::Invalid("candidate output has no parent".to_owned()))?;
    let file_name = output
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| LearningError::Invalid("candidate output name is invalid".to_owned()))?;
    let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let staging = parent.join(format!(
        ".{file_name}.candidate-staging-{}-{sequence}",
        std::process::id()
    ));
    if staging.exists() {
        return Err(LearningError::Invalid(
            "candidate staging path already exists".to_owned(),
        ));
    }
    std::fs::create_dir(&staging).map_err(|error| LearningError::Io {
        path: staging.display().to_string(),
        message: error.to_string(),
    })?;
    let result = write_candidate(
        &staging,
        &base.build_id,
        &base.package_content_hash,
        options,
        &dataset,
        &adaptation_bytes,
        &adaptation_hash,
    );
    let package = match result.and_then(|()| load_candidate_package(&staging)) {
        Ok(package) => package,
        Err(error) => {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(error);
        }
    };
    if let Err(error) = std::fs::rename(&staging, output) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(LearningError::Io {
            path: output.display().to_string(),
            message: error.to_string(),
        });
    }
    Ok(CandidatePackage {
        root: output.to_path_buf(),
        ..package
    })
}

/// Verifies every candidate artifact and returns typed metadata.
pub fn load_candidate_package(root: &Path) -> Result<CandidatePackage, LearningError> {
    verify_candidate_root(root)?;
    let expected_paths = expected_artifact_paths();
    let actual_paths = candidate_paths(root)?;
    if actual_paths != expected_paths {
        return Err(LearningError::Integrity(
            "candidate contains missing or unexpected artifacts".to_owned(),
        ));
    }
    let hashes_bytes = read_bounded(&root.join(HASHES_FILE), MAX_CANDIDATE_FILE_BYTES)?;
    let recorded_hashes = parse_hashes(&hashes_bytes)?;
    let hashed_paths = expected_paths
        .iter()
        .filter(|path| path.as_str() != HASHES_FILE)
        .cloned()
        .collect::<BTreeSet<_>>();
    if recorded_hashes.keys().cloned().collect::<BTreeSet<_>>() != hashed_paths {
        return Err(LearningError::Integrity(
            "candidate hash allowlist does not match artifacts".to_owned(),
        ));
    }
    for (path, expected_hash) in &recorded_hashes {
        let actual = sha256_bytes(&read_bounded(&root.join(path), MAX_CANDIDATE_FILE_BYTES)?);
        if &actual != expected_hash {
            return Err(LearningError::Integrity(format!(
                "candidate artifact hash mismatch: {path}"
            )));
        }
    }
    let manifest: CandidatePackageManifest = serde_json::from_slice(&read_bounded(
        &root.join(MANIFEST_FILE),
        MAX_CANDIDATE_FILE_BYTES,
    )?)
    .map_err(|error| LearningError::Json(error.to_string()))?;
    if manifest.schema_version != 1 || manifest.state != "candidate" {
        return Err(LearningError::Integrity(
            "candidate manifest version or state is invalid".to_owned(),
        ));
    }
    let payload_hash = payload_hash(
        &recorded_hashes
            .iter()
            .filter(|(path, _)| path.as_str() != MANIFEST_FILE)
            .map(|(path, hash)| (path.clone(), hash.clone()))
            .collect(),
    );
    if manifest.payload_hash != payload_hash {
        return Err(LearningError::Integrity(
            "candidate payload hash mismatch".to_owned(),
        ));
    }
    let report: CandidateDatasetReport = serde_json::from_slice(&read_bounded(
        &root.join(DATASET_REPORT_FILE),
        MAX_CANDIDATE_FILE_BYTES,
    )?)
    .map_err(|error| LearningError::Json(error.to_string()))?;
    let adaptations_bytes = read_bounded(&root.join(ADAPTATIONS_FILE), MAX_CANDIDATE_FILE_BYTES)?;
    let adaptations: AdaptationProposals = serde_json::from_slice(&adaptations_bytes)
        .map_err(|error| LearningError::Json(error.to_string()))?;
    if manifest.dataset_hash != report.dataset_hash
        || manifest.adaptation_hash != sha256_bytes(&adaptations_bytes)
    {
        return Err(LearningError::Integrity(
            "candidate typed artifact hash mismatch".to_owned(),
        ));
    }
    verify_dataset_artifacts(root, &manifest, &report)?;
    Ok(CandidatePackage {
        root: root.to_path_buf(),
        manifest,
        dataset_report: report,
        adaptations,
        candidate_content_hash: sha256_bytes(&hashes_bytes),
    })
}

struct BuiltDataset {
    clean: Vec<Episode>,
    training: Vec<Episode>,
    validation: Vec<Episode>,
    test: Vec<Episode>,
    quarantine: Vec<QuarantineRecord>,
    report: CandidateDatasetReport,
}

fn build_dataset(
    mut episodes: Vec<Episode>,
    base_build_id: &str,
    base_package_hash: &str,
) -> Result<BuiltDataset, LearningError> {
    episodes.sort_by(|left, right| left.episode_id.cmp(&right.episode_id));
    let source_count = episodes.len();
    let mut groups = BTreeMap::<String, Vec<Episode>>::new();
    let mut quarantine = Vec::new();
    for episode in episodes {
        let mut reasons = Vec::new();
        if episode.build_id != base_build_id || episode.package_content_hash != base_package_hash {
            reasons.push("base_package_mismatch".to_owned());
        }
        if episode.trust == TrustLevel::Untrusted {
            reasons.push("untrusted_source".to_owned());
        }
        if episode.outcome.status == OutcomeStatus::Unknown {
            reasons.push("unknown_outcome".to_owned());
        }
        if reasons.is_empty() {
            let group_hash = sha256_bytes(&json_bytes(&episode.situation)?);
            groups.entry(group_hash).or_default().push(episode);
        } else {
            quarantine.push(QuarantineRecord {
                episode_id: episode.episode_id,
                reasons,
            });
        }
    }
    let mut duplicate_count = 0_u64;
    let mut grouped = Vec::new();
    for (group_hash, mut episodes) in groups {
        episodes.sort_by(|left, right| left.episode_id.cmp(&right.episode_id));
        let observation_hashes = episodes
            .iter()
            .map(|episode| {
                json_bytes(&(&episode.output, &episode.correction))
                    .map(|bytes| sha256_bytes(&bytes))
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if observation_hashes.len() > 1 {
            quarantine.extend(episodes.into_iter().map(|episode| QuarantineRecord {
                episode_id: episode.episode_id,
                reasons: vec!["conflicting_duplicate_observation".to_owned()],
            }));
            continue;
        }
        duplicate_count = duplicate_count
            .saturating_add(u64::try_from(episodes.len().saturating_sub(1)).unwrap_or(u64::MAX));
        if let Some(episode) = episodes.into_iter().next() {
            grouped.push((group_hash, episode));
        }
    }
    grouped.sort_by(|left, right| left.0.cmp(&right.0));
    if grouped.len() < 3 {
        return Err(LearningError::Invalid(
            "candidate building requires at least three clean leakage groups".to_owned(),
        ));
    }
    let mut training = Vec::new();
    let mut validation = Vec::new();
    let mut test = Vec::new();
    let mut clean = Vec::new();
    let mut train_groups = BTreeSet::new();
    let mut validation_groups = BTreeSet::new();
    let mut test_groups = BTreeSet::new();
    for (index, (group_hash, episode)) in grouped.into_iter().enumerate() {
        clean.push(episode.clone());
        match index % 10 {
            0 => {
                test_groups.insert(group_hash);
                test.push(episode);
            }
            1 => {
                validation_groups.insert(group_hash);
                validation.push(episode);
            }
            _ => {
                train_groups.insert(group_hash);
                training.push(episode);
            }
        }
    }
    let overlap = train_groups
        .intersection(&validation_groups)
        .count()
        .saturating_add(train_groups.intersection(&test_groups).count())
        .saturating_add(validation_groups.intersection(&test_groups).count());
    let training_categories = training
        .iter()
        .map(|episode| episode.situation.category.as_str())
        .collect::<BTreeSet<_>>();
    let mut shift_flags = validation
        .iter()
        .chain(&test)
        .filter(|episode| !training_categories.contains(episode.situation.category.as_str()))
        .map(|episode| {
            format!(
                "category_absent_from_training:{}",
                episode.situation.category
            )
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    shift_flags.sort();
    let dataset_hash = dataset_hash(&training, &validation, &test)?;
    let report = CandidateDatasetReport {
        source_episode_count: u64::try_from(source_count).unwrap_or(u64::MAX),
        clean_episode_count: u64::try_from(clean.len()).unwrap_or(u64::MAX),
        duplicate_count,
        quarantined_count: u64::try_from(quarantine.len()).unwrap_or(u64::MAX),
        poisoning_flag_count: u64::try_from(quarantine.len()).unwrap_or(u64::MAX),
        training_count: u64::try_from(training.len()).unwrap_or(u64::MAX),
        validation_count: u64::try_from(validation.len()).unwrap_or(u64::MAX),
        test_count: u64::try_from(test.len()).unwrap_or(u64::MAX),
        edge_case_count: u64::try_from(
            clean
                .iter()
                .filter(|episode| episode.situation.edge_case)
                .count(),
        )
        .unwrap_or(u64::MAX),
        leakage_group_overlap_count: u64::try_from(overlap).unwrap_or(u64::MAX),
        unresolved_poisoning_flag_count: 0,
        distribution_shift_flags: shift_flags,
        dataset_hash,
    };
    Ok(BuiltDataset {
        clean,
        training,
        validation,
        test,
        quarantine,
        report,
    })
}

fn verify_dataset_artifacts(
    root: &Path,
    manifest: &CandidatePackageManifest,
    report: &CandidateDatasetReport,
) -> Result<(), LearningError> {
    let training = read_episode_jsonl(&root.join(TRAIN_FILE))?;
    let validation = read_episode_jsonl(&root.join(VALIDATION_FILE))?;
    let test = read_episode_jsonl(&root.join(TEST_FILE))?;
    let quarantine: Vec<QuarantineRecord> = serde_json::from_slice(&read_bounded(
        &root.join(QUARANTINE_FILE),
        MAX_CANDIDATE_FILE_BYTES,
    )?)
    .map_err(|error| LearningError::Json(error.to_string()))?;
    let calculated_hash = dataset_hash(&training, &validation, &test)?;
    if calculated_hash != report.dataset_hash {
        return Err(LearningError::Integrity(
            "candidate dataset hash does not match split contents".to_owned(),
        ));
    }

    let splits = [&training, &validation, &test];
    let expected_counts = [
        report.training_count,
        report.validation_count,
        report.test_count,
    ];
    let mut episode_ids = BTreeSet::new();
    let mut group_sets = Vec::new();
    for (split, expected_count) in splits.into_iter().zip(expected_counts) {
        if u64::try_from(split.len()).unwrap_or(u64::MAX) != expected_count {
            return Err(LearningError::Integrity(
                "candidate split count does not match dataset report".to_owned(),
            ));
        }
        let mut groups = BTreeSet::new();
        for episode in split {
            episode.validate()?;
            if episode.build_id != manifest.base_build_id
                || episode.package_content_hash != manifest.base_package_content_hash
                || !episode_ids.insert(episode.episode_id.clone())
            {
                return Err(LearningError::Integrity(
                    "candidate episode identity or base binding is invalid".to_owned(),
                ));
            }
            groups.insert(sha256_bytes(&json_bytes(&episode.situation)?));
        }
        group_sets.push(groups);
    }
    let overlap = group_sets[0]
        .intersection(&group_sets[1])
        .count()
        .saturating_add(group_sets[0].intersection(&group_sets[2]).count())
        .saturating_add(group_sets[1].intersection(&group_sets[2]).count());
    let clean = training
        .iter()
        .chain(&validation)
        .chain(&test)
        .collect::<Vec<_>>();
    let training_categories = training
        .iter()
        .map(|episode| episode.situation.category.as_str())
        .collect::<BTreeSet<_>>();
    let shift_flags = validation
        .iter()
        .chain(&test)
        .filter(|episode| !training_categories.contains(episode.situation.category.as_str()))
        .map(|episode| {
            format!(
                "category_absent_from_training:{}",
                episode.situation.category
            )
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let quarantine_ids = quarantine
        .iter()
        .map(|record| record.episode_id.as_str())
        .collect::<BTreeSet<_>>();
    if quarantine.iter().any(|record| record.reasons.is_empty())
        || quarantine_ids.len() != quarantine.len()
        || quarantine_ids
            .iter()
            .any(|episode_id| episode_ids.contains(*episode_id))
    {
        return Err(LearningError::Integrity(
            "candidate quarantine metadata is invalid".to_owned(),
        ));
    }
    let clean_count = u64::try_from(clean.len()).unwrap_or(u64::MAX);
    let quarantine_count = u64::try_from(quarantine.len()).unwrap_or(u64::MAX);
    let edge_count = u64::try_from(
        clean
            .iter()
            .filter(|episode| episode.situation.edge_case)
            .count(),
    )
    .unwrap_or(u64::MAX);
    if report.clean_episode_count != clean_count
        || report.quarantined_count != quarantine_count
        || report.poisoning_flag_count != quarantine_count
        || report.edge_case_count != edge_count
        || report.leakage_group_overlap_count != u64::try_from(overlap).unwrap_or(u64::MAX)
        || report.distribution_shift_flags != shift_flags
        || report.source_episode_count
            != clean_count
                .saturating_add(report.duplicate_count)
                .saturating_add(quarantine_count)
    {
        return Err(LearningError::Integrity(
            "candidate dataset report does not match verified artifacts".to_owned(),
        ));
    }
    Ok(())
}

fn read_episode_jsonl(path: &Path) -> Result<Vec<Episode>, LearningError> {
    let bytes = read_bounded(path, MAX_CANDIDATE_FILE_BYTES)?;
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            serde_json::from_slice(line).map_err(|error| LearningError::Json(error.to_string()))
        })
        .collect()
}

fn build_adaptations(episodes: &[Episode], dataset_hash: &str) -> AdaptationProposals {
    let mut module_rewards = BTreeMap::<String, (i64, u64)>::new();
    let mut skill_success = BTreeMap::<String, (u64, u64)>::new();
    let mut rule_candidates = Vec::new();
    for episode in episodes {
        for module in &episode.selected_route.module_ids {
            let entry = module_rewards.entry(module.clone()).or_default();
            entry.0 = entry
                .0
                .saturating_add(i64::from(episode.outcome.reward_milli));
            entry.1 = entry.1.saturating_add(1);
        }
        let skill = skill_success
            .entry(episode.selected_route.skill_id.clone())
            .or_default();
        skill.1 = skill.1.saturating_add(1);
        if episode.outcome.status == OutcomeStatus::Success {
            skill.0 = skill.0.saturating_add(1);
        }
        if let Some(correction) = &episode.correction {
            rule_candidates.push(RuleCandidateProposal {
                proposal_id: format!("rule-candidate-{}", episode.episode_id),
                source_episode_id: episode.episode_id.clone(),
                rationale: correction.reason.clone(),
                requires_human_review: true,
            });
        }
    }
    let retrieval_weights = module_rewards
        .iter()
        .map(|(module_id, (reward, count))| {
            let average = if *count == 0 {
                0
            } else {
                reward / i64::try_from(*count).unwrap_or(i64::MAX)
            };
            RetrievalWeightProposal {
                module_id: module_id.clone(),
                weight_delta_basis_points: i32::try_from(average.clamp(-100, 100)).unwrap_or(0),
                supporting_episode_count: *count,
            }
        })
        .collect::<Vec<_>>();
    let executor_refits = module_rewards
        .keys()
        .map(|module_id| ExecutorRefitProposal {
            module_id: module_id.clone(),
            dataset_hash: dataset_hash.to_owned(),
            adapter_contract: "offline-refit-adapter-v1".to_owned(),
            requires_offline_evaluation: true,
        })
        .collect::<Vec<_>>();
    let routing_thresholds = skill_success
        .into_iter()
        .map(|(skill_id, (successes, count))| {
            let failure_rate_milli = if count == 0 {
                0
            } else {
                1000_u64.saturating_sub(successes.saturating_mul(1000) / count)
            };
            RoutingThresholdProposal {
                skill_id,
                current_threshold_milli: 800,
                proposed_threshold_milli: u16::try_from(
                    800_u64
                        .saturating_add(failure_rate_milli / 2)
                        .clamp(500, 950),
                )
                .unwrap_or(950),
                supporting_episode_count: count,
            }
        })
        .collect();
    AdaptationProposals {
        retrieval_weights,
        rule_candidates,
        executor_refits,
        routing_thresholds,
    }
}

fn write_candidate(
    root: &Path,
    base_build_id: &str,
    base_package_hash: &str,
    options: &CandidateBuildOptions,
    dataset: &BuiltDataset,
    adaptation_bytes: &[u8],
    adaptation_hash: &str,
) -> Result<(), LearningError> {
    std::fs::create_dir(root.join("dataset")).map_err(io_error("dataset directory"))?;
    std::fs::create_dir(root.join("reports")).map_err(io_error("reports directory"))?;
    std::fs::create_dir(root.join("adaptations")).map_err(io_error("adaptations directory"))?;
    let artifacts = BTreeMap::from([
        (TRAIN_FILE.to_owned(), jsonl_bytes(&dataset.training)?),
        (
            VALIDATION_FILE.to_owned(),
            jsonl_bytes(&dataset.validation)?,
        ),
        (TEST_FILE.to_owned(), jsonl_bytes(&dataset.test)?),
        (
            QUARANTINE_FILE.to_owned(),
            pretty_json_bytes(&dataset.quarantine)?,
        ),
        (
            DATASET_REPORT_FILE.to_owned(),
            pretty_json_bytes(&dataset.report)?,
        ),
        (ADAPTATIONS_FILE.to_owned(), adaptation_bytes.to_vec()),
    ]);
    for (path, bytes) in &artifacts {
        write_new(&root.join(path), bytes)?;
    }
    let payload_records = artifacts
        .iter()
        .map(|(path, bytes)| (path.clone(), sha256_bytes(bytes)))
        .collect::<BTreeMap<_, _>>();
    let manifest = CandidatePackageManifest {
        schema_version: 1,
        state: "candidate".to_owned(),
        candidate_id: options.candidate_id.clone(),
        created_at_unix_seconds: options.created_at_unix_seconds,
        builder_id: options.builder_id.clone(),
        base_build_id: base_build_id.to_owned(),
        base_package_content_hash: base_package_hash.to_owned(),
        dataset_hash: dataset.report.dataset_hash.clone(),
        adaptation_hash: adaptation_hash.to_owned(),
        payload_hash: payload_hash(&payload_records),
    };
    let manifest_bytes = pretty_json_bytes(&manifest)?;
    write_new(&root.join(MANIFEST_FILE), &manifest_bytes)?;
    let mut all_records = payload_records;
    all_records.insert(MANIFEST_FILE.to_owned(), sha256_bytes(&manifest_bytes));
    write_new(&root.join(HASHES_FILE), &hash_records(&all_records))?;
    Ok(())
}

fn dataset_hash(
    training: &[Episode],
    validation: &[Episode],
    test: &[Episode],
) -> Result<String, LearningError> {
    let records = BTreeMap::from([
        (TRAIN_FILE.to_owned(), sha256_bytes(&jsonl_bytes(training)?)),
        (
            VALIDATION_FILE.to_owned(),
            sha256_bytes(&jsonl_bytes(validation)?),
        ),
        (TEST_FILE.to_owned(), sha256_bytes(&jsonl_bytes(test)?)),
    ]);
    Ok(payload_hash(&records))
}

fn jsonl_bytes(episodes: &[Episode]) -> Result<Vec<u8>, LearningError> {
    let mut bytes = Vec::new();
    for episode in episodes {
        bytes.extend_from_slice(&json_bytes(episode)?);
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn payload_hash(records: &BTreeMap<String, String>) -> String {
    let bytes = records
        .iter()
        .flat_map(|(path, hash)| format!("{path}\0{hash}\n").into_bytes())
        .collect::<Vec<_>>();
    sha256_bytes(&bytes)
}

fn hash_records(records: &BTreeMap<String, String>) -> Vec<u8> {
    records
        .iter()
        .flat_map(|(path, hash)| format!("{hash}  {path}\n").into_bytes())
        .collect()
}

fn parse_hashes(bytes: &[u8]) -> Result<BTreeMap<String, String>, LearningError> {
    let text =
        std::str::from_utf8(bytes).map_err(|error| LearningError::Integrity(error.to_string()))?;
    let mut records = BTreeMap::new();
    for line in text.lines() {
        let (hash, path) = line
            .split_once("  ")
            .ok_or_else(|| LearningError::Integrity("malformed candidate hash line".to_owned()))?;
        crate::episode::validate_hash(hash, "candidate artifact hash")?;
        if !expected_artifact_paths().contains(path)
            || records.insert(path.to_owned(), hash.to_owned()).is_some()
        {
            return Err(LearningError::Integrity(
                "duplicate or unexpected candidate hash path".to_owned(),
            ));
        }
    }
    Ok(records)
}

fn candidate_paths(root: &Path) -> Result<BTreeSet<String>, LearningError> {
    let mut paths = BTreeSet::new();
    collect_paths(root, root, &mut paths)?;
    Ok(paths)
}

fn collect_paths(
    root: &Path,
    directory: &Path,
    paths: &mut BTreeSet<String>,
) -> Result<(), LearningError> {
    for entry in std::fs::read_dir(directory).map_err(|error| LearningError::Io {
        path: directory.display().to_string(),
        message: error.to_string(),
    })? {
        let entry = entry.map_err(|error| LearningError::Io {
            path: directory.display().to_string(),
            message: error.to_string(),
        })?;
        let metadata = entry.file_type().map_err(|error| LearningError::Io {
            path: entry.path().display().to_string(),
            message: error.to_string(),
        })?;
        if metadata.is_symlink() {
            return Err(LearningError::Integrity(
                "candidate symlinks are forbidden".to_owned(),
            ));
        }
        if metadata.is_dir() {
            collect_paths(root, &entry.path(), paths)?;
        } else if metadata.is_file() {
            let entry_path = entry.path();
            let relative = entry_path.strip_prefix(root).map_err(|error| {
                LearningError::Integrity(format!("candidate path escape: {error}"))
            })?;
            paths.insert(relative.to_string_lossy().replace('\\', "/"));
        } else {
            return Err(LearningError::Integrity(
                "candidate contains a non-regular artifact".to_owned(),
            ));
        }
    }
    Ok(())
}

fn expected_artifact_paths() -> BTreeSet<String> {
    [
        MANIFEST_FILE,
        HASHES_FILE,
        TRAIN_FILE,
        VALIDATION_FILE,
        TEST_FILE,
        QUARANTINE_FILE,
        DATASET_REPORT_FILE,
        ADAPTATIONS_FILE,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn verify_candidate_root(root: &Path) -> Result<(), LearningError> {
    let metadata = std::fs::symlink_metadata(root).map_err(|error| LearningError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LearningError::Integrity(
            "candidate root must be a regular directory".to_owned(),
        ));
    }
    Ok(())
}

fn ensure_separate_output(base_package: &Path, output: &Path) -> Result<(), LearningError> {
    let base = std::fs::canonicalize(base_package).map_err(|error| LearningError::Io {
        path: base_package.display().to_string(),
        message: error.to_string(),
    })?;
    let parent = output
        .parent()
        .ok_or_else(|| LearningError::Invalid("candidate output has no parent".to_owned()))?;
    let canonical_parent = std::fs::canonicalize(parent).map_err(|error| LearningError::Io {
        path: parent.display().to_string(),
        message: error.to_string(),
    })?;
    let candidate =
        canonical_parent.join(output.file_name().ok_or_else(|| {
            LearningError::Invalid("candidate output name is invalid".to_owned())
        })?);
    if candidate.starts_with(&base) || base.starts_with(&candidate) {
        return Err(LearningError::Invalid(
            "candidate and base package must be physically separate".to_owned(),
        ));
    }
    Ok(())
}

fn validate_candidate_options(options: &CandidateBuildOptions) -> Result<(), LearningError> {
    if options.candidate_id.is_empty()
        || options.builder_id.is_empty()
        || options.created_at_unix_seconds == 0
    {
        return Err(LearningError::Invalid(
            "candidate build options are incomplete".to_owned(),
        ));
    }
    Ok(())
}

fn io_error(context: &'static str) -> impl FnOnce(std::io::Error) -> LearningError {
    move |error| LearningError::Io {
        path: context.to_owned(),
        message: error.to_string(),
    }
}
