use d2i_core::{
    validate_source_pack, AccessLabel, ActionPermission, CachePolicy, CompiledIr,
    ConfidenceThreshold, CriticalErrorCondition, Criticality, Diagnostic, Document, DomainId,
    DomainIr, DomainManifest, EdgeKind, Entity, EvaluationCase, EvaluationIr, EvidenceRef, Example,
    ExecutionEdge, ExecutionGraph, ExecutionIr, ExecutionNode, ExecutorId, Fact, MetricSpec,
    NodeId, NodeKind, Outcome, PolicyIr, Procedure, ProcedureStep, ProvenanceId, Relation,
    RetryPolicy, Rule, Severity, SkillId, SkillIr, SourceInventory, SourceLocation, SourceLock,
    Term,
};
use d2i_eval::{
    optimize_graph, select_executor, BenchmarkProfile, ExecutorDescriptor, ExecutorKind,
    OptimizationReport, SelectionConfig, SelectionReport, SelectionRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_yaml::Value as YamlValue;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Result of source validation and typed IR construction.
#[derive(Debug)]
pub struct IrBuildReport {
    pub ir: Option<CompiledIr>,
    pub manifest: Option<DomainManifest>,
    pub source_lock: Option<SourceLock>,
    pub phase4: Option<Phase4BuildData>,
    pub diagnostics: Vec<Diagnostic>,
}

/// Executor selection and graph optimization data retained by package builds.
#[derive(Debug, Clone, Serialize)]
pub struct Phase4BuildData {
    pub descriptors: Vec<ExecutorDescriptor>,
    pub benchmark_profiles: Vec<BenchmarkProfile>,
    pub selection_config: SelectionConfig,
    pub selections: BTreeMap<String, SelectionReport>,
    pub optimizations: Vec<OptimizationReport>,
}

struct LoweredOutput {
    ir: CompiledIr,
    phase4: Phase4BuildData,
}

impl IrBuildReport {
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity() == Severity::Error)
    }
}

/// Validates a source pack and lowers supported Phase 1 sources into typed IR.
#[must_use]
pub fn build_ir(root: &Path) -> IrBuildReport {
    let validation = validate_source_pack(root);
    let mut diagnostics = validation.diagnostics;
    if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity() == Severity::Error)
    {
        return IrBuildReport {
            ir: None,
            manifest: validation.manifest,
            source_lock: validation.inventory.as_ref().map(SourceLock::from),
            phase4: None,
            diagnostics,
        };
    }

    let Some(manifest) = validation.manifest else {
        diagnostics.push(internal_error("validated source pack has no manifest"));
        return IrBuildReport {
            ir: None,
            manifest: None,
            source_lock: validation.inventory.as_ref().map(SourceLock::from),
            phase4: None,
            diagnostics,
        };
    };
    let Some(inventory) = validation.inventory else {
        diagnostics.push(internal_error("validated source pack has no inventory"));
        return IrBuildReport {
            ir: None,
            manifest: Some(manifest),
            source_lock: None,
            phase4: None,
            diagnostics,
        };
    };
    let source_lock = SourceLock::from(&inventory);

    let lowered = lower_validated(&manifest, &inventory, &validation.documents);
    let mut phase4 = None;
    let ir = match lowered {
        Ok(lowered) => {
            diagnostics.extend(lowered.ir.validate());
            phase4 = Some(lowered.phase4);
            (!diagnostics
                .iter()
                .any(|diagnostic| diagnostic.severity() == Severity::Error))
            .then_some(lowered.ir)
        }
        Err(mut errors) => {
            diagnostics.append(&mut errors);
            None
        }
    };
    diagnostics.sort_by_key(diagnostic_key);

    IrBuildReport {
        ir,
        manifest: Some(manifest),
        source_lock: Some(source_lock),
        phase4,
        diagnostics,
    }
}

fn lower_validated(
    manifest: &DomainManifest,
    inventory: &SourceInventory,
    documents: &[d2i_core::ParsedDocument],
) -> Result<LoweredOutput, Vec<Diagnostic>> {
    let mut diagnostics = Vec::new();
    let (provenance, provenance_by_path) = build_provenance(inventory, &mut diagnostics);
    let Some(manifest_provenance) = provenance_by_path.get("domain.yaml").cloned() else {
        diagnostics.push(internal_error("domain.yaml provenance is missing"));
        return Err(diagnostics);
    };

    let domain_id = match DomainId::new(manifest.domain.id.clone()) {
        Ok(id) => id,
        Err(error) => {
            diagnostics.push(internal_error(format!(
                "validated domain id failed to lower: {error}"
            )));
            return Err(diagnostics);
        }
    };

    let (descriptors, benchmark_profiles, selection_config) =
        lower_executor_inputs(documents, &mut diagnostics);
    let procedures = lower_procedures(documents, &provenance_by_path, &mut diagnostics);
    let rules = lower_rules(documents, &provenance_by_path, &mut diagnostics);
    let default_skill = manifest.skills.first().and_then(|skill| {
        SkillId::new(skill.id.clone())
            .map_err(|error| {
                diagnostics.push(internal_error(format!(
                    "validated skill id failed to lower: {error}"
                )));
            })
            .ok()
    });
    let (examples, outcomes, evaluation_cases) = lower_examples_and_outcomes(
        documents,
        &provenance_by_path,
        default_skill.as_ref(),
        &mut diagnostics,
    );
    let domain_parts = lower_domain_sources(documents, &provenance_by_path, &mut diagnostics);

    let mut skills = Vec::new();
    let executor_ids = descriptors
        .iter()
        .filter_map(|descriptor| ExecutorId::new(descriptor.id.clone()).ok())
        .collect::<Vec<_>>();
    for skill in &manifest.skills {
        let id = match SkillId::new(skill.id.clone()) {
            Ok(id) => id,
            Err(error) => {
                diagnostics.push(internal_error(format!(
                    "validated skill id failed to lower: {error}"
                )));
                continue;
            }
        };
        skills.push(SkillIr {
            id,
            version: skill.version.clone(),
            input_schema: skill.input_schema.clone(),
            output_schema: skill.output_schema.clone(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
            criticality: parse_criticality(&skill.criticality),
            fallback: skill.fallback.clone(),
            evidence_required: skill.evidence_required,
            evaluation_dataset: manifest.evaluation.dataset.clone(),
            evaluation_thresholds: manifest.evaluation.thresholds.clone(),
            candidate_executors: executor_ids.clone(),
            provenance_id: manifest_provenance.clone(),
        });
    }

    let selections = select_executors(
        manifest,
        &skills,
        &procedures,
        &descriptors,
        &benchmark_profiles,
        &selection_config,
        documents,
        &mut diagnostics,
    );
    let mut execution = lower_execution(
        &skills,
        &procedures,
        &descriptors,
        &selections,
        &manifest_provenance,
        &mut diagnostics,
    );
    let descriptor_map = descriptors
        .iter()
        .cloned()
        .map(|descriptor| (descriptor.id.clone(), descriptor))
        .collect::<BTreeMap<_, _>>();
    let mut optimizations = Vec::new();
    for graph in &mut execution.graphs {
        let graph_selections = selections
            .iter()
            .filter(|(key, _)| key.starts_with(&format!("{}:", graph.skill_id)))
            .map(|(key, report)| (key.clone(), report.clone()))
            .collect::<BTreeMap<_, _>>();
        optimizations.push(optimize_graph(
            graph,
            &descriptor_map,
            &graph_selections,
            &selection_config,
        ));
    }
    let policy = lower_policy(
        manifest,
        &skills,
        &descriptors,
        documents,
        &provenance_by_path,
        &manifest_provenance,
        &mut diagnostics,
    );
    let evaluation = lower_evaluation(
        manifest,
        evaluation_cases,
        documents,
        &provenance_by_path,
        &manifest_provenance,
        &mut diagnostics,
    );

    if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity() == Severity::Error)
    {
        return Err(diagnostics);
    }

    let ir = CompiledIr {
        domain: DomainIr {
            domain_id,
            version: manifest.domain.version.clone(),
            name: manifest.domain.name.clone(),
            languages: manifest.domain.languages.clone(),
            entities: domain_parts.entities,
            relations: domain_parts.relations,
            terms: domain_parts.terms,
            facts: domain_parts.facts,
            documents: domain_parts.documents,
            procedures,
            rules,
            examples,
            outcomes,
        },
        skills,
        execution,
        policy,
        evaluation,
        provenance,
    };
    Ok(LoweredOutput {
        ir,
        phase4: Phase4BuildData {
            descriptors,
            benchmark_profiles,
            selection_config,
            selections,
            optimizations,
        },
    })
}

fn build_provenance(
    inventory: &SourceInventory,
    diagnostics: &mut Vec<Diagnostic>,
) -> (Vec<EvidenceRef>, BTreeMap<String, ProvenanceId>) {
    let mut provenance = Vec::new();
    let mut by_path = BTreeMap::new();
    for (index, entry) in inventory.entries().iter().enumerate() {
        let id = match ProvenanceId::new(format!("p{index:06}")) {
            Ok(id) => id,
            Err(error) => {
                diagnostics.push(internal_error(format!(
                    "cannot create provenance id: {error}"
                )));
                continue;
            }
        };
        by_path.insert(entry.path().to_owned(), id.clone());
        provenance.push(EvidenceRef {
            id,
            source_path: entry.path().to_owned(),
            line: None,
            field: None,
            content_hash: entry.content_hash().to_owned(),
        });
    }
    (provenance, by_path)
}

#[derive(Debug, Deserialize)]
struct BindingFile {
    bindings: Vec<ExecutorDescriptor>,
}

#[derive(Debug, Deserialize)]
struct BenchmarkFile {
    benchmarks: Vec<BenchmarkProfile>,
}

fn lower_executor_inputs(
    documents: &[d2i_core::ParsedDocument],
    diagnostics: &mut Vec<Diagnostic>,
) -> (
    Vec<ExecutorDescriptor>,
    Vec<BenchmarkProfile>,
    SelectionConfig,
) {
    let mut descriptors = Vec::new();
    let mut benchmarks = Vec::new();
    let mut config = None;
    for document in documents {
        let Some(value) = yaml_value(document) else {
            continue;
        };
        let parsed = match document.path() {
            "models/bindings.yaml" => serde_yaml::from_value::<BindingFile>(value.clone())
                .map(|file| descriptors = file.bindings)
                .map_err(|error| error.to_string()),
            "models/benchmarks.yaml" => serde_yaml::from_value::<BenchmarkFile>(value.clone())
                .map(|file| benchmarks = file.benchmarks)
                .map_err(|error| error.to_string()),
            "models/selection.yaml" => serde_yaml::from_value::<SelectionConfig>(value.clone())
                .map(|value| config = Some(value))
                .map_err(|error| error.to_string()),
            _ => continue,
        };
        if let Err(error) = parsed {
            diagnostics.push(lowering_error(
                document.path(),
                "D2I2200",
                format!("cannot lower executor input: {error}"),
            ));
        }
    }
    descriptors.sort_by(|left, right| left.id.cmp(&right.id));
    benchmarks.sort_by(|left, right| left.executor_id.cmp(&right.executor_id));
    if descriptors.is_empty() {
        diagnostics.push(lowering_error(
            "models/bindings.yaml",
            "D2I2300",
            "executor descriptor registry is empty",
        ));
    }
    if benchmarks.is_empty() {
        diagnostics.push(lowering_error(
            "models/benchmarks.yaml",
            "D2I2301",
            "benchmark profile registry is empty",
        ));
    }
    (
        descriptors,
        benchmarks,
        config.unwrap_or_else(|| {
            diagnostics.push(lowering_error(
                "models/selection.yaml",
                "D2I2302",
                "selection configuration is missing",
            ));
            SelectionConfig::default()
        }),
    )
}

#[allow(clippy::too_many_arguments)]
fn select_executors(
    manifest: &DomainManifest,
    skills: &[SkillIr],
    procedures: &[Procedure],
    descriptors: &[ExecutorDescriptor],
    benchmarks: &[BenchmarkProfile],
    config: &SelectionConfig,
    documents: &[d2i_core::ParsedDocument],
    diagnostics: &mut Vec<Diagnostic>,
) -> BTreeMap<String, SelectionReport> {
    let min_field_accuracy = metric_threshold(documents, "field_accuracy")
        .unwrap_or(manifest.objectives.min_task_success_rate);
    let min_repeatability = metric_threshold(documents, "deterministic_replay_rate").unwrap_or(
        if manifest.objectives.deterministic {
            1.0
        } else {
            0.0
        },
    );
    let max_memory_bytes = manifest.target.max_memory_mb.saturating_mul(1024 * 1024);
    let mut reports = BTreeMap::new();
    for skill in skills {
        let preferred = skill.id.as_str().replace('_', "-");
        let procedure = procedures
            .iter()
            .find(|procedure| procedure.id == preferred)
            .or_else(|| procedures.first());
        let Some(procedure) = procedure else {
            continue;
        };
        for capability in procedure
            .steps
            .iter()
            .filter(|step| node_kind(&step.kind) != NodeKind::Return)
            .map(|step| step.kind.clone())
            .collect::<BTreeSet<_>>()
        {
            let request = SelectionRequest {
                capability: capability.clone(),
                input_schema: skill.input_schema.clone(),
                output_schema: skill.output_schema.clone(),
                target_os: manifest.target.os.clone(),
                target_arch: manifest.target.arch.clone(),
                max_memory_bytes,
                min_task_success_rate: manifest.objectives.min_task_success_rate,
                min_field_accuracy,
                max_critical_error_rate: manifest.objectives.max_critical_error_rate,
                min_repeatability_rate: min_repeatability,
                network_allowed: false,
                side_effects_allowed: false,
            };
            let report = select_executor(&request, descriptors, benchmarks, config);
            if report.selected.is_none() && report.fallback.is_none() {
                diagnostics.push(lowering_error(
                    "models/bindings.yaml",
                    "D2I2303",
                    format!(
                        "no safe executor or fallback is available for capability '{capability}'"
                    ),
                ));
            }
            if report.selected.is_none()
                && report.rejected.iter().any(|candidate| {
                    candidate.reasons.iter().any(|reason| {
                        reason.starts_with("task success")
                            || reason.starts_with("field accuracy")
                            || reason.starts_with("critical error")
                            || reason.starts_with("repeatability")
                    })
                })
            {
                diagnostics.push(lowering_error(
                    "models/benchmarks.yaml",
                    "D2I2304",
                    format!(
                        "quality regression leaves capability '{capability}' without a binding"
                    ),
                ));
            }
            reports.insert(format!("{}:{capability}", skill.id), report);
        }
    }
    reports
}

fn metric_threshold(documents: &[d2i_core::ParsedDocument], metric: &str) -> Option<f64> {
    documents
        .iter()
        .filter(|document| document.path().starts_with("eval/"))
        .filter_map(yaml_value)
        .find_map(|value| find_number_for_key(value, metric))
}

#[derive(Debug, Deserialize)]
struct ProcedureSource {
    id: String,
    version: String,
    steps: Vec<ProcedureStepSource>,
}

#[derive(Debug, Deserialize)]
struct ProcedureStepSource {
    id: String,
    kind: String,
    next: Option<String>,
    failure: Option<String>,
    max_iterations: Option<u32>,
}

fn lower_procedures(
    documents: &[d2i_core::ParsedDocument],
    provenance: &BTreeMap<String, ProvenanceId>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<Procedure> {
    let mut procedures = Vec::new();
    for document in documents {
        if !document.path().starts_with("procedures/") {
            continue;
        }
        let Some(value) = yaml_value(document) else {
            continue;
        };
        let Some(provenance_id) = provenance.get(document.path()).cloned() else {
            diagnostics.push(internal_error(format!(
                "missing provenance for {}",
                document.path()
            )));
            continue;
        };
        match serde_yaml::from_value::<ProcedureSource>(value.clone()) {
            Ok(source) => procedures.push(Procedure {
                id: source.id,
                version: source.version,
                steps: source
                    .steps
                    .into_iter()
                    .map(|step| ProcedureStep {
                        id: step.id,
                        kind: step.kind,
                        next: step.next,
                        failure: step.failure,
                        max_iterations: step.max_iterations,
                        provenance_id: provenance_id.clone(),
                    })
                    .collect(),
                provenance_id,
            }),
            Err(error) => diagnostics.push(lowering_error(
                document.path(),
                "D2I2201",
                format!("cannot lower procedure: {error}"),
            )),
        }
    }
    procedures.sort_by(|left, right| left.id.cmp(&right.id));
    procedures
}

#[derive(Debug, Deserialize)]
struct RuleFileSource {
    id: String,
    #[serde(default)]
    rules: Vec<RuleSource>,
    constraints: Option<YamlValue>,
}

#[derive(Debug, Deserialize)]
struct RuleSource {
    id: String,
    when: Option<YamlValue>,
    then: Option<YamlValue>,
    #[serde(default)]
    exception: bool,
}

fn lower_rules(
    documents: &[d2i_core::ParsedDocument],
    provenance: &BTreeMap<String, ProvenanceId>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<Rule> {
    let mut rules = Vec::new();
    for document in documents {
        if !document.path().starts_with("rules/") {
            continue;
        }
        let Some(value) = yaml_value(document) else {
            continue;
        };
        let Some(provenance_id) = provenance.get(document.path()).cloned() else {
            diagnostics.push(internal_error(format!(
                "missing provenance for {}",
                document.path()
            )));
            continue;
        };
        match serde_yaml::from_value::<RuleFileSource>(value.clone()) {
            Ok(source) => {
                for rule in source.rules {
                    rules.push(Rule {
                        id: rule.id,
                        condition: yaml_to_json(rule.when.unwrap_or(YamlValue::Bool(true))),
                        action: yaml_to_json(rule.then.unwrap_or(YamlValue::Null)),
                        exception: rule.exception,
                        provenance_id: provenance_id.clone(),
                    });
                }
                if let Some(constraints) = source.constraints {
                    rules.push(Rule {
                        id: source.id,
                        condition: Value::Bool(true),
                        action: yaml_to_json(constraints),
                        exception: false,
                        provenance_id,
                    });
                }
            }
            Err(error) => diagnostics.push(lowering_error(
                document.path(),
                "D2I2202",
                format!("cannot lower rule: {error}"),
            )),
        }
    }
    rules.sort_by(|left, right| left.id.cmp(&right.id));
    rules
}

struct DomainParts {
    entities: Vec<Entity>,
    relations: Vec<Relation>,
    facts: Vec<Fact>,
    terms: Vec<Term>,
    documents: Vec<Document>,
}

fn lower_domain_sources(
    documents: &[d2i_core::ParsedDocument],
    provenance: &BTreeMap<String, ProvenanceId>,
    diagnostics: &mut Vec<Diagnostic>,
) -> DomainParts {
    let mut entities = Vec::new();
    let mut relations = Vec::new();
    let mut facts = Vec::new();
    let mut terms = Vec::new();
    let mut text_documents = Vec::new();

    for document in documents {
        let Some(provenance_id) = provenance.get(document.path()).cloned() else {
            continue;
        };
        match document.content() {
            d2i_core::ParsedContent::Text(text) => {
                let id = stable_path_id(document.path());
                let title = text.lines().find_map(|line| {
                    line.strip_prefix("# ")
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_owned)
                });
                text_documents.push(Document {
                    id: id.clone(),
                    path: document.path().to_owned(),
                    title,
                    provenance_id: provenance_id.clone(),
                });
                for (index, term) in text
                    .lines()
                    .filter_map(|line| line.trim().strip_prefix("- "))
                    .filter(|term| !term.trim().is_empty())
                    .enumerate()
                {
                    terms.push(Term {
                        id: format!("{id}-term-{index:04}"),
                        canonical: term.trim().to_owned(),
                        aliases: Vec::new(),
                        provenance_id: provenance_id.clone(),
                    });
                }
            }
            d2i_core::ParsedContent::Csv { headers, records } => {
                let id_index = headers
                    .iter()
                    .position(|header| matches!(header.as_str(), "id" | "case_id"));
                let canonical_index = headers.iter().position(|header| header == "canonical");
                let aliases_index = headers.iter().position(|header| header == "aliases");
                if let Some(canonical_index) = canonical_index {
                    for (row_index, record) in records.iter().enumerate() {
                        let Some(canonical) = record
                            .get(canonical_index)
                            .filter(|value| !value.trim().is_empty())
                        else {
                            continue;
                        };
                        let id = id_index
                            .and_then(|index| record.get(index))
                            .filter(|value| !value.is_empty())
                            .cloned()
                            .unwrap_or_else(|| {
                                format!("{}-term-{row_index:06}", stable_path_id(document.path()))
                            });
                        let aliases = aliases_index
                            .and_then(|index| record.get(index))
                            .map(|value| {
                                value
                                    .split('|')
                                    .map(str::trim)
                                    .filter(|value| !value.is_empty())
                                    .map(str::to_owned)
                                    .collect()
                            })
                            .unwrap_or_default();
                        terms.push(Term {
                            id,
                            canonical: canonical.trim().to_owned(),
                            aliases,
                            provenance_id: provenance_id.clone(),
                        });
                    }
                    continue;
                }
                for (row_index, record) in records.iter().enumerate() {
                    let id = id_index
                        .and_then(|index| record.get(index))
                        .filter(|value| !value.is_empty())
                        .cloned()
                        .unwrap_or_else(|| {
                            format!("{}-row-{row_index:06}", stable_path_id(document.path()))
                        });
                    let attributes = headers
                        .iter()
                        .zip(record)
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect::<BTreeMap<_, _>>();
                    entities.push(Entity {
                        id: id.clone(),
                        entity_type: stable_path_id(document.path()),
                        attributes: attributes.clone(),
                        provenance_id: provenance_id.clone(),
                    });
                    for (key, value) in &attributes {
                        if Some(key) != id_index.and_then(|index| headers.get(index)) {
                            facts.push(Fact {
                                id: format!("{id}-{key}"),
                                subject: id.clone(),
                                predicate: key.clone(),
                                object: value.clone(),
                                provenance_id: provenance_id.clone(),
                            });
                        }
                    }
                    if let Some(target) = attributes.get("fault_code") {
                        relations.push(Relation {
                            id: format!("{id}-has-fault"),
                            relation_type: "has_fault".to_owned(),
                            source: id,
                            target: target.clone(),
                            provenance_id: provenance_id.clone(),
                        });
                    }
                }
            }
            _ => {}
        }
    }
    if entities.iter().any(|entity| entity.id.is_empty()) {
        diagnostics.push(internal_error("lowered entity has an empty id"));
    }
    entities.sort_by(|left, right| left.id.cmp(&right.id));
    relations.sort_by(|left, right| left.id.cmp(&right.id));
    facts.sort_by(|left, right| left.id.cmp(&right.id));
    terms.sort_by(|left, right| left.id.cmp(&right.id));
    text_documents.sort_by(|left, right| left.path.cmp(&right.path));
    DomainParts {
        entities,
        relations,
        facts,
        terms,
        documents: text_documents,
    }
}

fn lower_examples_and_outcomes(
    documents: &[d2i_core::ParsedDocument],
    provenance: &BTreeMap<String, ProvenanceId>,
    default_skill: Option<&SkillId>,
    diagnostics: &mut Vec<Diagnostic>,
) -> (Vec<Example>, Vec<Outcome>, Vec<EvaluationCase>) {
    let mut examples = Vec::new();
    let mut outcomes = Vec::new();
    let mut cases = Vec::new();
    for document in documents {
        let d2i_core::ParsedContent::JsonLines(records) = document.content() else {
            continue;
        };
        let Some(provenance_id) = provenance.get(document.path()).cloned() else {
            continue;
        };
        if document.path().starts_with("examples/") {
            let positive = document.path().contains("positive");
            for (index, record) in records.iter().enumerate() {
                let Some(skill_id) = skill_for_record(record, default_skill, diagnostics) else {
                    continue;
                };
                examples.push(Example {
                    id: record_id(record, document.path(), index),
                    skill_id,
                    positive,
                    request: record.get("request").cloned().unwrap_or(Value::Null),
                    provenance_id: provenance_id.clone(),
                });
            }
        } else if document.path().starts_with("eval/") {
            for (index, record) in records.iter().enumerate() {
                let Some(skill_id) = skill_for_record(record, default_skill, diagnostics) else {
                    continue;
                };
                let id = record_id(record, document.path(), index);
                let expected = record.get("expected").cloned().unwrap_or(Value::Null);
                outcomes.push(Outcome {
                    id: id.clone(),
                    expected: expected.clone(),
                    provenance_id: provenance_id.clone(),
                });
                cases.push(EvaluationCase {
                    id,
                    skill_id,
                    request: record.get("request").cloned().unwrap_or(Value::Null),
                    expected,
                    provenance_id: provenance_id.clone(),
                });
            }
        }
    }
    examples.sort_by(|left, right| left.id.cmp(&right.id));
    outcomes.sort_by(|left, right| left.id.cmp(&right.id));
    cases.sort_by(|left, right| left.id.cmp(&right.id));
    (examples, outcomes, cases)
}

fn lower_execution(
    skills: &[SkillIr],
    procedures: &[Procedure],
    descriptors: &[ExecutorDescriptor],
    selections: &BTreeMap<String, SelectionReport>,
    manifest_provenance: &ProvenanceId,
    diagnostics: &mut Vec<Diagnostic>,
) -> ExecutionIr {
    let mut graphs = Vec::new();
    for skill in skills {
        let preferred = skill.id.as_str().replace('_', "-");
        let procedure = procedures
            .iter()
            .find(|procedure| procedure.id == preferred)
            .or_else(|| procedures.first());
        let Some(procedure) = procedure else {
            diagnostics.push(lowering_error(
                "domain.yaml",
                "D2I2203",
                format!("skill '{}' has no procedure to lower", skill.id),
            ));
            continue;
        };
        if let Some(graph) = lower_graph(
            skill,
            procedure,
            descriptors,
            selections,
            manifest_provenance,
            diagnostics,
        ) {
            graphs.push(graph);
        }
    }
    graphs.sort_by(|left, right| left.skill_id.cmp(&right.skill_id));
    ExecutionIr { graphs }
}

fn lower_graph(
    skill: &SkillIr,
    procedure: &Procedure,
    descriptors: &[ExecutorDescriptor],
    selections: &BTreeMap<String, SelectionReport>,
    manifest_provenance: &ProvenanceId,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<ExecutionGraph> {
    let mut nodes = Vec::new();
    for step in &procedure.steps {
        let id = match NodeId::new(step.id.clone()) {
            Ok(id) => id,
            Err(error) => {
                diagnostics.push(lowering_error(
                    "<execution-ir>",
                    "D2I2204",
                    format!("invalid procedure step id: {error}"),
                ));
                continue;
            }
        };
        let selection_key = format!("{}:{}", skill.id, step.kind);
        let selection = selections.get(&selection_key);
        let selected = selection.and_then(|report| report.selected.as_deref());
        let descriptor = selected.and_then(|selected| {
            descriptors
                .iter()
                .find(|descriptor| descriptor.id == selected)
        });
        let executor_id = selected.and_then(|selected| ExecutorId::new(selected.to_owned()).ok());
        let kind = descriptor.map_or_else(
            || {
                if selection
                    .and_then(|report| report.fallback.as_deref())
                    .is_some_and(|fallback| fallback == "human_review")
                {
                    NodeKind::HumanReview
                } else {
                    node_kind(&step.kind)
                }
            },
            |descriptor| executor_node_kind(descriptor.kind),
        );
        let failure_target = step
            .failure
            .as_ref()
            .and_then(|target| NodeId::new(target.clone()).ok());
        nodes.push(ExecutionNode {
            id,
            kind,
            input_type: "record".to_owned(),
            output_type: "record".to_owned(),
            timeout_ms: 1_000,
            expected_memory_bytes: 1_048_576,
            executor_id,
            min_confidence: 0.0,
            failure_target,
            retry: RetryPolicy { limit: 0 },
            cache: CachePolicy {
                cacheable: matches!(kind, NodeKind::Lookup | NodeKind::Retrieve),
            },
            side_effect: false,
            parallel_group: None,
            evidence_required: skill.evidence_required,
            loop_max_iterations: (kind == NodeKind::LoopBounded)
                .then_some(step.max_iterations.unwrap_or(1)),
            provenance_id: step.provenance_id.clone(),
        });
    }

    let mut edges = Vec::new();
    for step in &procedure.steps {
        if let Some(next) = &step.next {
            if let (Ok(from), Ok(to)) = (NodeId::new(step.id.clone()), NodeId::new(next.clone())) {
                edges.push(ExecutionEdge {
                    from,
                    to,
                    kind: EdgeKind::Success,
                    condition: None,
                    provenance_id: step.provenance_id.clone(),
                });
            }
        }
        if let Some(failure) = &step.failure {
            if let (Ok(from), Ok(to)) = (NodeId::new(step.id.clone()), NodeId::new(failure.clone()))
            {
                edges.push(ExecutionEdge {
                    from,
                    to,
                    kind: EdgeKind::Failure,
                    condition: None,
                    provenance_id: step.provenance_id.clone(),
                });
            }
        }
    }

    if matches!(skill.criticality, Criticality::High | Criticality::Critical) {
        add_safety_gate(
            skill,
            &mut nodes,
            &mut edges,
            manifest_provenance,
            diagnostics,
        );
    }

    let entry_node = procedure
        .steps
        .first()
        .and_then(|step| NodeId::new(step.id.clone()).ok());
    let Some(entry_node) = entry_node else {
        diagnostics.push(lowering_error(
            "<execution-ir>",
            "D2I2205",
            format!("procedure '{}' has no entry step", procedure.id),
        ));
        return None;
    };
    edges.sort_by(|left, right| {
        (
            left.from.as_str(),
            left.to.as_str(),
            edge_kind_order(left.kind),
        )
            .cmp(&(
                right.from.as_str(),
                right.to.as_str(),
                edge_kind_order(right.kind),
            ))
    });
    Some(ExecutionGraph {
        skill_id: skill.id.clone(),
        entry_node,
        nodes,
        edges,
    })
}

fn add_safety_gate(
    skill: &SkillIr,
    nodes: &mut Vec<ExecutionNode>,
    edges: &mut Vec<ExecutionEdge>,
    provenance_id: &ProvenanceId,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(return_node) = nodes
        .iter()
        .find(|node| node.kind == NodeKind::Return)
        .map(|node| node.id.clone())
    else {
        diagnostics.push(lowering_error(
            "<execution-ir>",
            "D2I2206",
            format!("high-criticality skill '{}' has no return node", skill.id),
        ));
        return;
    };
    let gate_id = match NodeId::new(format!("d2i-policy-gate-{}", skill.id)) {
        Ok(id) => id,
        Err(error) => {
            diagnostics.push(internal_error(format!(
                "cannot create policy gate id: {error}"
            )));
            return;
        }
    };
    let human_id = match NodeId::new(format!("d2i-human-review-{}", skill.id)) {
        Ok(id) => id,
        Err(error) => {
            diagnostics.push(internal_error(format!(
                "cannot create human review id: {error}"
            )));
            return;
        }
    };
    for edge in edges.iter_mut().filter(|edge| edge.to == return_node) {
        edge.to = gate_id.clone();
    }
    nodes.push(ExecutionNode {
        id: gate_id.clone(),
        kind: NodeKind::PolicyGate,
        input_type: "record".to_owned(),
        output_type: "record".to_owned(),
        timeout_ms: 100,
        expected_memory_bytes: 65_536,
        executor_id: None,
        min_confidence: 0.8,
        failure_target: Some(human_id.clone()),
        retry: RetryPolicy { limit: 0 },
        cache: CachePolicy { cacheable: false },
        side_effect: false,
        parallel_group: None,
        evidence_required: true,
        loop_max_iterations: None,
        provenance_id: provenance_id.clone(),
    });
    nodes.push(ExecutionNode {
        id: human_id.clone(),
        kind: NodeKind::HumanReview,
        input_type: "record".to_owned(),
        output_type: "record".to_owned(),
        timeout_ms: 0,
        expected_memory_bytes: 65_536,
        executor_id: None,
        min_confidence: 0.0,
        failure_target: None,
        retry: RetryPolicy { limit: 0 },
        cache: CachePolicy { cacheable: false },
        side_effect: true,
        parallel_group: None,
        evidence_required: true,
        loop_max_iterations: None,
        provenance_id: provenance_id.clone(),
    });
    edges.push(ExecutionEdge {
        from: gate_id.clone(),
        to: return_node.clone(),
        kind: EdgeKind::Success,
        condition: Some("policy_allow".to_owned()),
        provenance_id: provenance_id.clone(),
    });
    edges.push(ExecutionEdge {
        from: gate_id,
        to: human_id.clone(),
        kind: EdgeKind::Failure,
        condition: Some("policy_deny_or_low_confidence".to_owned()),
        provenance_id: provenance_id.clone(),
    });
    edges.push(ExecutionEdge {
        from: human_id,
        to: return_node,
        kind: EdgeKind::Success,
        condition: Some("human_approved".to_owned()),
        provenance_id: provenance_id.clone(),
    });
}

fn lower_policy(
    manifest: &DomainManifest,
    skills: &[SkillIr],
    descriptors: &[ExecutorDescriptor],
    documents: &[d2i_core::ParsedDocument],
    provenance: &BTreeMap<String, ProvenanceId>,
    manifest_provenance: &ProvenanceId,
    diagnostics: &mut Vec<Diagnostic>,
) -> PolicyIr {
    let mut minimum = 0.0;
    for document in documents {
        if document.path().starts_with("rules/") {
            if let Some(value) = yaml_value(document) {
                minimum = find_number_for_key(value, "confidence_below").unwrap_or(minimum);
            }
        }
    }
    let access_labels = manifest
        .sources
        .iter()
        .map(|source| AccessLabel {
            resource: source.path.clone(),
            label: source.trust.clone(),
            provenance_id: manifest_provenance.clone(),
        })
        .collect();
    let confidence_thresholds = skills
        .iter()
        .map(|skill| ConfidenceThreshold {
            skill_id: skill.id.clone(),
            minimum,
            fallback: skill.fallback.clone().unwrap_or_else(|| "deny".to_owned()),
            provenance_id: manifest_provenance.clone(),
        })
        .collect();
    let policy_provenance = provenance
        .get("security/policy.yaml")
        .cloned()
        .unwrap_or_else(|| manifest_provenance.clone());
    let action_permissions = vec![
        ActionPermission {
            action: "network".to_owned(),
            allowed: false,
            requires_human_review: false,
            provenance_id: policy_provenance.clone(),
        },
        ActionPermission {
            action: "side_effect".to_owned(),
            allowed: false,
            requires_human_review: true,
            provenance_id: policy_provenance,
        },
    ];
    let allowed_executors = descriptors
        .iter()
        .filter_map(|descriptor| match ExecutorId::new(descriptor.id.clone()) {
            Ok(id) => Some(id),
            Err(error) => {
                diagnostics.push(internal_error(format!(
                    "validated executor id failed to lower: {error}"
                )));
                None
            }
        })
        .collect();
    PolicyIr {
        default_action: "deny".to_owned(),
        network_allowed: false,
        access_labels,
        confidence_thresholds,
        action_permissions,
        allowed_executors,
    }
}

fn lower_evaluation(
    manifest: &DomainManifest,
    cases: Vec<EvaluationCase>,
    documents: &[d2i_core::ParsedDocument],
    provenance: &BTreeMap<String, ProvenanceId>,
    manifest_provenance: &ProvenanceId,
    diagnostics: &mut Vec<Diagnostic>,
) -> EvaluationIr {
    let mut metrics = Vec::new();
    for document in documents {
        if document.path() != manifest.evaluation.thresholds {
            continue;
        }
        let Some(value) = yaml_value(document) else {
            continue;
        };
        let Some(provenance_id) = provenance.get(document.path()).cloned() else {
            continue;
        };
        if let Some(mapping) = value.as_mapping() {
            for (key, value) in mapping {
                let Some(id) = key.as_str() else {
                    continue;
                };
                let Some(threshold) = value.as_f64() else {
                    diagnostics.push(lowering_error(
                        document.path(),
                        "D2I2207",
                        format!("metric '{id}' threshold is not numeric"),
                    ));
                    continue;
                };
                metrics.push(MetricSpec {
                    id: id.to_owned(),
                    threshold,
                    higher_is_better: !id.contains("error"),
                    provenance_id: provenance_id.clone(),
                });
            }
        }
    }
    metrics.sort_by(|left, right| left.id.cmp(&right.id));
    EvaluationIr {
        cases,
        metrics,
        critical_errors: vec![CriticalErrorCondition {
            id: "critical-error-rate".to_owned(),
            expression: "critical_error == true".to_owned(),
            maximum_rate: manifest.objectives.max_critical_error_rate,
            provenance_id: manifest_provenance.clone(),
        }],
    }
}

fn skill_for_record(
    record: &Value,
    default_skill: Option<&SkillId>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<SkillId> {
    if let Some(skill) = record.get("skill").and_then(Value::as_str) {
        return match SkillId::new(skill.to_owned()) {
            Ok(id) => Some(id),
            Err(error) => {
                diagnostics.push(internal_error(format!(
                    "validated example skill id failed to lower: {error}"
                )));
                None
            }
        };
    }
    default_skill.cloned()
}

fn record_id(record: &Value, path: &str, index: usize) -> String {
    record.get("id").and_then(Value::as_str).map_or_else(
        || format!("{}-{index:06}", stable_path_id(path)),
        str::to_owned,
    )
}

fn node_kind(kind: &str) -> NodeKind {
    match kind {
        "read_input" => NodeKind::ReadInput,
        "normalize" | "term-normalizer" => NodeKind::Normalize,
        "lookup" => NodeKind::Lookup,
        "retrieve" | "sparse-retrieval" | "case-retriever" => NodeKind::Retrieve,
        "rule_eval" | "rules" | "procedure-decider" => NodeKind::RuleEval,
        "native_call" => NodeKind::NativeCall,
        "model_call" => NodeKind::ModelCall,
        "parallel" => NodeKind::Parallel,
        "join" => NodeKind::Join,
        "branch" => NodeKind::Branch,
        "loop_bounded" => NodeKind::LoopBounded,
        "validate" => NodeKind::Validate,
        "policy_gate" => NodeKind::PolicyGate,
        "human_review" => NodeKind::HumanReview,
        "return" => NodeKind::Return,
        _ => NodeKind::NativeCall,
    }
}

fn executor_node_kind(kind: ExecutorKind) -> NodeKind {
    match kind {
        ExecutorKind::Constant | ExecutorKind::Cache | ExecutorKind::Lookup => NodeKind::Lookup,
        ExecutorKind::Rule => NodeKind::RuleEval,
        ExecutorKind::Search => NodeKind::Retrieve,
        ExecutorKind::NativeFunction | ExecutorKind::DeviceAdapter => NodeKind::NativeCall,
        ExecutorKind::ClassicalModel
        | ExecutorKind::NeuralExpert
        | ExecutorKind::LanguageExpert => NodeKind::ModelCall,
        ExecutorKind::Planner => NodeKind::Branch,
        ExecutorKind::HumanReview => NodeKind::HumanReview,
    }
}

fn parse_criticality(value: &str) -> Criticality {
    match value {
        "medium" => Criticality::Medium,
        "high" => Criticality::High,
        "critical" => Criticality::Critical,
        _ => Criticality::Low,
    }
}

fn edge_kind_order(kind: EdgeKind) -> u8 {
    match kind {
        EdgeKind::Success => 0,
        EdgeKind::Failure => 1,
        EdgeKind::BranchTrue => 2,
        EdgeKind::BranchFalse => 3,
        EdgeKind::Parallel => 4,
        EdgeKind::Join => 5,
    }
}

fn yaml_value(document: &d2i_core::ParsedDocument) -> Option<&YamlValue> {
    match document.content() {
        d2i_core::ParsedContent::Yaml(value) => Some(value),
        _ => None,
    }
}

fn yaml_to_json(value: YamlValue) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

fn find_number_for_key(value: &YamlValue, target: &str) -> Option<f64> {
    match value {
        YamlValue::Mapping(mapping) => mapping.iter().find_map(|(key, value)| {
            if key.as_str() == Some(target) {
                value.as_f64()
            } else {
                find_number_for_key(value, target)
            }
        }),
        YamlValue::Sequence(values) => values
            .iter()
            .find_map(|value| find_number_for_key(value, target)),
        _ => None,
    }
}

fn stable_path_id(path: &str) -> String {
    path.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned()
}

fn lowering_error(path: &str, code: &str, message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(Severity::Error, code, message)
        .with_location(SourceLocation::new(path, None, None))
        .with_help("fix the source contract before compiling the package")
}

fn internal_error(message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(Severity::Error, "D2I2299", message)
        .with_help("report this deterministic lowering invariant failure")
}

fn diagnostic_key(diagnostic: &Diagnostic) -> (String, Option<u32>, String) {
    (
        diagnostic
            .location()
            .map_or_else(String::new, |location| location.path().to_owned()),
        diagnostic.location().and_then(SourceLocation::line),
        diagnostic.code().to_owned(),
    )
}
