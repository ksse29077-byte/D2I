use crate::package::{normalize, KnowledgeIndex, RuntimePackage};
use d2i_core::ExecutorId;
use d2i_kernel::{score_match_masks_into, MATCH_EQUIPMENT, MATCH_ERROR_CODE, MATCH_SYMPTOM};
use d2i_runtime_api::{
    Evidence, Executor, ExecutorOutput, ExecutorRequest, RuntimeError, TaskContext,
};
use serde_json::{json, Map, Value};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::sync::Arc;

pub(crate) fn register_mvp_executors(
    registry: &mut d2i_runtime_api::ExecutorRegistry,
    knowledge: Arc<KnowledgeIndex>,
    package: &RuntimePackage,
) -> Result<(), RuntimeError> {
    let mut registered = BTreeSet::new();
    for skill_id in package.skill_ids() {
        let Some(graph) = package.graph(skill_id) else {
            continue;
        };
        for node in &graph.nodes {
            let Some(id) = node.executor_id.as_deref() else {
                continue;
            };
            if !registered.insert(id.to_owned()) {
                continue;
            }
            match node.kind {
                d2i_schema::d2i::package::NodeKind::Normalize
                | d2i_schema::d2i::package::NodeKind::Lookup => {
                    registry.register(Arc::new(TermNormalizer::new(id, knowledge.clone())?))?;
                }
                d2i_schema::d2i::package::NodeKind::Retrieve => {
                    registry.register(Arc::new(CaseRetriever::new(id, knowledge.clone())?))?;
                }
                d2i_schema::d2i::package::NodeKind::RuleEval => {
                    registry.register(Arc::new(ProcedureDecider::new(id)?))?;
                }
                _ => return Err(RuntimeError::MissingExecutor(id.to_owned())),
            }
        }
    }
    Ok(())
}

struct TermNormalizer {
    id: ExecutorId,
    knowledge: Arc<KnowledgeIndex>,
}

impl TermNormalizer {
    fn new(id: &str, knowledge: Arc<KnowledgeIndex>) -> Result<Self, RuntimeError> {
        Ok(Self {
            id: executor_id(id)?,
            knowledge,
        })
    }
}

impl Executor for TermNormalizer {
    fn id(&self) -> &ExecutorId {
        &self.id
    }

    fn execute(
        &self,
        _context: &TaskContext,
        request: ExecutorRequest,
    ) -> Result<ExecutorOutput, RuntimeError> {
        let mut payload = object(request.payload)?;
        let symptom = payload
            .get("symptom")
            .and_then(Value::as_str)
            .ok_or_else(|| RuntimeError::InvalidRequest("symptom must be a string".to_owned()))?;
        let normalized = normalize(symptom);
        let (canonical, evidence) = self.knowledge.aliases.get(&normalized).map_or_else(
            || (normalized, Vec::new()),
            |(value, evidence)| (value.clone(), vec![evidence.clone()]),
        );
        payload.insert(
            "normalized_symptoms".to_owned(),
            Value::Array(vec![Value::String(canonical.clone())]),
        );
        payload.insert("_normalized_symptom".to_owned(), Value::String(canonical));
        Ok(ExecutorOutput {
            payload: Value::Object(payload),
            confidence: 1.0,
            evidence,
            warnings: Vec::new(),
        })
    }
}

struct CaseRetriever {
    id: ExecutorId,
    knowledge: Arc<KnowledgeIndex>,
}

impl CaseRetriever {
    fn new(id: &str, knowledge: Arc<KnowledgeIndex>) -> Result<Self, RuntimeError> {
        Ok(Self {
            id: executor_id(id)?,
            knowledge,
        })
    }
}

impl Executor for CaseRetriever {
    fn id(&self) -> &ExecutorId {
        &self.id
    }

    fn execute(
        &self,
        _context: &TaskContext,
        request: ExecutorRequest,
    ) -> Result<ExecutorOutput, RuntimeError> {
        let mut payload = object(request.payload)?;
        let symptom = payload
            .get("_normalized_symptom")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let error_code = payload
            .get("error_code")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let equipment = payload
            .get("equipment_id")
            .and_then(Value::as_str)
            .and_then(|value| value.split('-').next())
            .unwrap_or_default();
        let normalized_symptom = normalize(symptom);
        let matches = self
            .knowledge
            .cases
            .iter()
            .filter_map(|case| {
                let case_symptom = case
                    .attributes
                    .get("symptom")
                    .map_or_else(String::new, |value| normalize(value));
                let mut mask = 0_u8;
                if !normalized_symptom.is_empty() && normalized_symptom == case_symptom {
                    mask |= MATCH_SYMPTOM;
                }
                if !error_code.is_empty()
                    && case.attributes.get("error_code").map(String::as_str) == Some(error_code)
                {
                    mask |= MATCH_ERROR_CODE;
                }
                if !equipment.is_empty()
                    && case.attributes.get("equipment_type").map(String::as_str) == Some(equipment)
                {
                    mask |= MATCH_EQUIPMENT;
                }
                (mask != 0).then_some((mask, case))
            })
            .collect::<Vec<_>>();
        let match_masks = matches.iter().map(|(mask, _)| *mask).collect::<Vec<_>>();
        let mut score_points = vec![0_u16; match_masks.len()];
        score_match_masks_into(&match_masks, &mut score_points).map_err(|error| {
            RuntimeError::Executor {
                executor_id: self.id.as_str().to_owned(),
                message: error.to_string(),
            }
        })?;
        let mut candidates = matches
            .into_iter()
            .zip(score_points)
            .map(|((_, case), score)| (f64::from(score) / 100.0, case))
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            right
                .0
                .partial_cmp(&left.0)
                .unwrap_or(Ordering::Equal)
                .then_with(|| left.1.id.cmp(&right.1.id))
        });
        candidates.truncate(3);
        let confidence = candidates.first().map_or(0.0, |candidate| candidate.0);
        let evidence = candidates
            .iter()
            .map(|(_, case)| case.evidence.clone())
            .collect::<Vec<_>>();
        let values = candidates
            .iter()
            .map(|(score, case)| {
                json!({
                    "case_id": case.id,
                    "fault_code": case.attributes.get("fault_code"),
                    "recommended_step": case.attributes.get("recommended_step"),
                    "score": score,
                    "source": case.evidence.source,
                    "span": case.id,
                })
            })
            .collect();
        payload.insert("_candidates".to_owned(), Value::Array(values));
        payload.insert("_confidence".to_owned(), json!(confidence));
        Ok(ExecutorOutput {
            payload: Value::Object(payload),
            confidence,
            evidence,
            warnings: (confidence == 0.0)
                .then(|| "no supported maintenance case matched the request".to_owned())
                .into_iter()
                .collect(),
        })
    }
}

struct ProcedureDecider {
    id: ExecutorId,
}

impl ProcedureDecider {
    fn new(id: &str) -> Result<Self, RuntimeError> {
        Ok(Self {
            id: executor_id(id)?,
        })
    }
}

impl Executor for ProcedureDecider {
    fn id(&self) -> &ExecutorId {
        &self.id
    }

    fn execute(
        &self,
        _context: &TaskContext,
        request: ExecutorRequest,
    ) -> Result<ExecutorOutput, RuntimeError> {
        let payload = object(request.payload)?;
        let normalized = payload
            .get("normalized_symptoms")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new()));
        let candidates = payload
            .get("_candidates")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let confidence = payload
            .get("_confidence")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let critical_temperature = payload
            .get("sensor_snapshot")
            .and_then(|snapshot| snapshot.get("temperature_c"))
            .and_then(Value::as_f64)
            .is_some_and(|temperature| temperature >= 120.0);
        let confidence = if critical_temperature {
            confidence.min(0.79)
        } else {
            confidence
        };
        let fault_codes = string_values(&candidates, "fault_code");
        let steps = string_values(&candidates, "recommended_step");
        let result_evidence = candidates
            .iter()
            .filter_map(|candidate| {
                Some(json!({
                    "source": candidate.get("source")?.as_str()?,
                    "span": candidate.get("span")?.as_str()?,
                }))
            })
            .collect::<Vec<_>>();
        Ok(ExecutorOutput {
            payload: json!({
                "normalized_symptoms": normalized,
                "candidate_fault_codes": fault_codes,
                "recommended_check_sequence": steps,
                "evidence": result_evidence,
                "confidence": confidence,
                "human_review": false,
            }),
            confidence,
            evidence: Vec::new(),
            warnings: critical_temperature
                .then(|| "critical sensor reading requires human review".to_owned())
                .into_iter()
                .collect(),
        })
    }
}

fn object(value: Value) -> Result<Map<String, Value>, RuntimeError> {
    value
        .as_object()
        .cloned()
        .ok_or_else(|| RuntimeError::InvalidRequest("payload must be a JSON object".to_owned()))
}

fn string_values(candidates: &[Value], key: &str) -> Vec<String> {
    candidates
        .iter()
        .filter_map(|candidate| candidate.get(key).and_then(Value::as_str))
        .map(str::to_owned)
        .collect()
}

fn executor_id(value: &str) -> Result<ExecutorId, RuntimeError> {
    ExecutorId::new(value.to_owned())
        .map_err(|error| RuntimeError::MissingExecutor(error.to_string()))
}

pub(crate) fn deduplicate_evidence(evidence: &mut Vec<Evidence>) {
    evidence.sort_by(|left, right| {
        (
            left.provenance_id.as_str(),
            left.source.as_str(),
            left.span.as_str(),
        )
            .cmp(&(
                right.provenance_id.as_str(),
                right.source.as_str(),
                right.span.as_str(),
            ))
    });
    evidence.dedup();
}
