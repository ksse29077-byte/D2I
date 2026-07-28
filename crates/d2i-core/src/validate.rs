use crate::manifest::find_field_line;
use crate::source::resolve_reference;
use crate::{
    load_manifest, parse_inventory, Diagnostic, DomainManifest, ParsedContent, ParsedDocument,
    Severity, SourceInventory, SourceLocation,
};
use jsonschema::{Draft, JSONSchema};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Aggregated result of Phase 1 source-pack validation.
#[derive(Debug)]
pub struct ValidationReport {
    pub manifest: Option<DomainManifest>,
    pub inventory: Option<SourceInventory>,
    pub documents: Vec<ParsedDocument>,
    pub diagnostics: Vec<Diagnostic>,
}

impl ValidationReport {
    /// True when one or more diagnostics are fatal.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity() == Severity::Error)
    }
}

/// Runs Phase 1 loading, secure discovery, parsing, and reference validation.
#[must_use]
pub fn validate_source_pack(root: &Path) -> ValidationReport {
    let manifest_load = load_manifest(root);
    let mut diagnostics = manifest_load.diagnostics;
    let manifest_source = manifest_load.source.unwrap_or_default();
    let manifest = manifest_load.manifest;

    let (inventory, mut inventory_diagnostics) = crate::build_inventory(root);
    diagnostics.append(&mut inventory_diagnostics);

    let (documents, mut parse_diagnostics) = inventory
        .as_ref()
        .map_or_else(|| (Vec::new(), Vec::new()), parse_inventory);
    diagnostics.append(&mut parse_diagnostics);

    if let (Some(manifest), Some(inventory)) = (&manifest, &inventory) {
        validate_references(
            manifest,
            &manifest_source,
            inventory,
            &documents,
            &mut diagnostics,
        );
    }

    diagnostics.sort_by_key(diagnostic_key);

    ValidationReport {
        manifest,
        inventory,
        documents,
        diagnostics,
    }
}

fn validate_references(
    manifest: &DomainManifest,
    manifest_source: &str,
    inventory: &SourceInventory,
    documents: &[ParsedDocument],
    diagnostics: &mut Vec<Diagnostic>,
) {
    let root = inventory.root();
    let mut declared_paths = BTreeSet::new();
    for (index, source) in manifest.sources.iter().enumerate() {
        let field = format!("sources[{index}].path");
        if !declared_paths.insert(source.path.as_str()) {
            push_manifest_diagnostic(
                diagnostics,
                manifest_source,
                &field,
                "D2I1300",
                format!("duplicate source path '{}'", source.path),
                "remove the duplicate source declaration",
            );
        }
        validate_path_reference(root, &source.path, &field, manifest_source, diagnostics);
    }

    let mut skill_ids = BTreeMap::new();
    let mut fallbacks = BTreeSet::from(["human_review".to_owned()]);
    for (index, skill) in manifest.skills.iter().enumerate() {
        let field = format!("skills[{index}].id");
        if let Some(previous) = skill_ids.insert(skill.id.as_str(), index) {
            push_manifest_diagnostic(
                diagnostics,
                manifest_source,
                &field,
                "D2I1301",
                format!(
                    "duplicate skill id '{}' (first declared at skills[{previous}])",
                    skill.id
                ),
                "give every skill a unique id",
            );
        }

        if matches!(skill.criticality.as_str(), "high" | "critical")
            && skill.fallback.as_deref().is_none_or(str::is_empty)
        {
            push_manifest_diagnostic(
                diagnostics,
                manifest_source,
                &format!("skills[{index}].fallback"),
                "D2I1302",
                format!(
                    "{} skill '{}' requires a fallback",
                    skill.criticality, skill.id
                ),
                "set fallback to human_review or another declared fallback executor",
            );
        }
        if let Some(fallback) = &skill.fallback {
            fallbacks.insert(fallback.clone());
        }

        validate_path_reference(
            root,
            &skill.input_schema,
            &format!("skills[{index}].input_schema"),
            manifest_source,
            diagnostics,
        );
        validate_path_reference(
            root,
            &skill.output_schema,
            &format!("skills[{index}].output_schema"),
            manifest_source,
            diagnostics,
        );
    }

    validate_path_reference(
        root,
        &manifest.evaluation.dataset,
        "evaluation.dataset",
        manifest_source,
        diagnostics,
    );
    validate_path_reference(
        root,
        &manifest.evaluation.thresholds,
        "evaluation.thresholds",
        manifest_source,
        diagnostics,
    );

    validate_structured_references(manifest, documents, &skill_ids, &fallbacks, diagnostics);
    validate_json_schemas(manifest, root, documents, diagnostics);
}

fn validate_path_reference(
    root: &Path,
    reference: &str,
    field: &str,
    manifest_source: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if let Err(error) = resolve_reference(root, reference) {
        push_manifest_diagnostic(
            diagnostics,
            manifest_source,
            field,
            "D2I1303",
            format!("invalid reference '{reference}': {error}"),
            "use an existing relative path that remains inside the source-pack root",
        );
    }
}

#[derive(Debug, Deserialize)]
struct BindingFile {
    bindings: Vec<Binding>,
}

#[derive(Debug, Deserialize)]
struct Binding {
    id: String,
    #[serde(default)]
    capabilities: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ProcedureFile {
    id: String,
    steps: Vec<ProcedureStep>,
}

#[derive(Debug, Deserialize)]
struct ProcedureStep {
    id: String,
    kind: String,
    next: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RuleFile {
    id: String,
    rules: Option<Vec<RuleEntry>>,
}

#[derive(Debug, Deserialize)]
struct RuleEntry {
    id: String,
    then: Option<RuleAction>,
}

#[derive(Debug, Deserialize)]
struct RuleAction {
    fallback: Option<String>,
    target: Option<String>,
}

fn validate_structured_references(
    manifest: &DomainManifest,
    documents: &[ParsedDocument],
    skill_ids: &BTreeMap<&str, usize>,
    fallbacks: &BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut binding_ids = BTreeMap::<String, String>::new();
    let mut binding_capabilities = BTreeSet::<String>::new();
    let mut procedures = Vec::<(String, ProcedureFile)>::new();
    let mut rules = Vec::<(String, RuleFile)>::new();

    for document in documents {
        let Some(yaml) = yaml_content(document) else {
            continue;
        };
        if document.path() == "models/bindings.yaml" {
            match serde_yaml::from_value::<BindingFile>(yaml.clone()) {
                Ok(file) => {
                    for binding in file.bindings {
                        binding_capabilities.extend(binding.capabilities);
                        insert_unique(
                            &mut binding_ids,
                            binding.id,
                            document.path(),
                            "executor binding",
                            diagnostics,
                        );
                    }
                }
                Err(error) => diagnostics.push(structure_error(
                    document.path(),
                    "D2I1304",
                    format!("invalid model bindings: {error}"),
                    "provide a bindings list with a non-empty id for each executor",
                )),
            }
        } else if document.path().starts_with("procedures/") {
            match serde_yaml::from_value::<ProcedureFile>(yaml.clone()) {
                Ok(file) => procedures.push((document.path().to_owned(), file)),
                Err(error) => diagnostics.push(structure_error(
                    document.path(),
                    "D2I1305",
                    format!("invalid procedure: {error}"),
                    "provide an id and a steps list with id and kind fields",
                )),
            }
        } else if document.path().starts_with("rules/") {
            match serde_yaml::from_value::<RuleFile>(yaml.clone()) {
                Ok(file) => rules.push((document.path().to_owned(), file)),
                Err(error) => diagnostics.push(structure_error(
                    document.path(),
                    "D2I1306",
                    format!("invalid rule file: {error}"),
                    "provide an id and an optional rules list",
                )),
            }
        }
    }

    let mut procedure_ids = BTreeMap::<String, String>::new();
    for (path, procedure) in &procedures {
        insert_unique(
            &mut procedure_ids,
            procedure.id.clone(),
            path,
            "procedure",
            diagnostics,
        );
    }

    for (path, procedure) in &procedures {
        let mut step_ids = BTreeSet::new();
        for step in &procedure.steps {
            if !step_ids.insert(step.id.as_str()) {
                diagnostics.push(
                    structure_error(
                        path,
                        "D2I1307",
                        format!(
                            "duplicate step id '{}' in procedure '{}'",
                            step.id, procedure.id
                        ),
                        "give every step in a procedure a unique id",
                    )
                    .with_field("steps[].id"),
                );
            }
        }

        for step in &procedure.steps {
            if let Some(next) = &step.next {
                if !step_ids.contains(next.as_str()) {
                    diagnostics.push(
                        structure_error(
                            path,
                            "D2I1308",
                            format!("procedure step '{}' targets missing step '{next}'", step.id),
                            "change next to an existing step id",
                        )
                        .with_field("steps[].next"),
                    );
                }
            }
            if !is_builtin_step_kind(&step.kind)
                && !binding_ids.contains_key(&step.kind)
                && !binding_capabilities.contains(&step.kind)
            {
                diagnostics.push(
                    structure_error(
                        path,
                        "D2I1309",
                        format!(
                            "procedure step '{}' references unknown executor '{}'",
                            step.id, step.kind
                        ),
                        "declare the executor in models/bindings.yaml or use a built-in step kind",
                    )
                    .with_field("steps[].kind"),
                );
            }
        }
    }

    let mut rule_file_ids = BTreeMap::<String, String>::new();
    let mut rule_ids = BTreeMap::<String, String>::new();
    for (path, rule_file) in rules {
        insert_unique(
            &mut rule_file_ids,
            rule_file.id,
            &path,
            "rule file",
            diagnostics,
        );
        for rule in rule_file.rules.unwrap_or_default() {
            insert_unique(&mut rule_ids, rule.id, &path, "rule", diagnostics);
            if let Some(action) = rule.then {
                if let Some(fallback) = action.fallback {
                    if !fallbacks.contains(&fallback) {
                        diagnostics.push(
                            structure_error(
                                &path,
                                "D2I1310",
                                format!("rule references unknown fallback '{fallback}'"),
                                "use a fallback declared by a skill or human_review",
                            )
                            .with_field("rules[].then.fallback"),
                        );
                    }
                }
                if let Some(target) = action.target {
                    let known = skill_ids.contains_key(target.as_str())
                        || procedure_ids.contains_key(&target)
                        || binding_ids.contains_key(&target);
                    if !known {
                        diagnostics.push(
                            structure_error(
                                &path,
                                "D2I1311",
                                format!("rule references unknown target '{target}'"),
                                "target a declared skill, procedure, or executor binding",
                            )
                            .with_field("rules[].then.target"),
                        );
                    }
                }
            }
        }
    }

    for skill in &manifest.skills {
        if let Some(fallback) = &skill.fallback {
            if fallback != "human_review"
                && !binding_ids.contains_key(fallback)
                && !procedure_ids.contains_key(fallback)
            {
                diagnostics.push(
                    Diagnostic::new(
                        Severity::Error,
                        "D2I1312",
                        format!(
                            "skill '{}' references undeclared fallback '{fallback}'",
                            skill.id
                        ),
                    )
                    .with_location(SourceLocation::new("domain.yaml", None, None))
                    .with_field("skills[].fallback")
                    .with_help("declare the fallback as an executor/procedure or use human_review"),
                );
            }
        }
    }
}

fn validate_json_schemas(
    manifest: &DomainManifest,
    root: &Path,
    documents: &[ParsedDocument],
    diagnostics: &mut Vec<Diagnostic>,
) {
    let json_documents = documents
        .iter()
        .filter_map(|document| match document.content() {
            ParsedContent::Json(value) => Some((document.path(), value)),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let jsonl_documents = documents
        .iter()
        .filter_map(|document| match document.content() {
            ParsedContent::JsonLines(values) => Some((document.path(), values)),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();

    let mut input_schemas = BTreeMap::<String, JSONSchema>::new();
    for skill in &manifest.skills {
        validate_one_schema(
            root,
            &skill.input_schema,
            &skill.id,
            true,
            &json_documents,
            &mut input_schemas,
            diagnostics,
        );
        let mut ignored = BTreeMap::new();
        validate_one_schema(
            root,
            &skill.output_schema,
            &skill.id,
            false,
            &json_documents,
            &mut ignored,
            diagnostics,
        );
    }

    validate_examples(
        "examples/positive.jsonl",
        true,
        manifest,
        &input_schemas,
        &jsonl_documents,
        diagnostics,
    );
    validate_examples(
        "examples/negative.jsonl",
        false,
        manifest,
        &input_schemas,
        &jsonl_documents,
        diagnostics,
    );
}

#[allow(clippy::too_many_arguments)]
fn validate_one_schema(
    root: &Path,
    reference: &str,
    skill_id: &str,
    retain: bool,
    json_documents: &BTreeMap<&str, &JsonValue>,
    compiled: &mut BTreeMap<String, JSONSchema>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if resolve_reference(root, reference).is_err() {
        return;
    }
    let Some(schema) = json_documents.get(reference).copied() else {
        diagnostics.push(structure_error(
            reference,
            "D2I1313",
            "JSON Schema reference did not parse as JSON",
            "use a valid .json schema file",
        ));
        return;
    };
    if has_external_ref(schema) {
        diagnostics.push(structure_error(
            reference,
            "D2I1314",
            "external or root-absolute $ref is not allowed in offline validation",
            "use an in-document fragment reference or bundle referenced schemas locally",
        ));
        return;
    }
    if let Some(missing) = missing_local_ref(reference, schema, json_documents) {
        diagnostics.push(structure_error(
            reference,
            "D2I1322",
            format!("JSON Schema references missing local schema '{missing}'"),
            "add the referenced schema under the source-pack root",
        ));
        return;
    }
    let schema_for_compilation = schema_with_local_id(reference, schema);
    let mut options = JSONSchema::options();
    options.with_draft(Draft::Draft202012);
    for (path, document) in json_documents {
        if path.starts_with("schemas/") && *path != reference {
            options.with_document(
                format!("d2i://local/{path}"),
                schema_with_local_id(path, document),
            );
        }
    }
    match options.compile(&schema_for_compilation) {
        Ok(schema) => {
            if retain {
                compiled.insert(skill_id.to_owned(), schema);
            }
        }
        Err(error) => diagnostics.push(structure_error(
            reference,
            "D2I1315",
            format!("invalid JSON Schema: {error}"),
            "fix the schema keyword or value",
        )),
    }
}

fn validate_examples(
    path: &str,
    expected_valid: bool,
    manifest: &DomainManifest,
    schemas: &BTreeMap<String, JSONSchema>,
    documents: &BTreeMap<&str, &Vec<JsonValue>>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(records) = documents.get(path).copied() else {
        return;
    };
    for (index, record) in records.iter().enumerate() {
        let Some(request) = record.get("request") else {
            diagnostics.push(
                structure_error(
                    path,
                    "D2I1316",
                    "example record is missing request",
                    "add a request object to each example",
                )
                .with_location(SourceLocation::new(
                    path,
                    u32::try_from(index + 1).ok(),
                    None,
                ))
                .with_field("request"),
            );
            continue;
        };
        let skill_id = record
            .get("skill")
            .and_then(JsonValue::as_str)
            .or_else(|| (manifest.skills.len() == 1).then(|| manifest.skills[0].id.as_str()));
        let Some(skill_id) = skill_id else {
            diagnostics.push(
                structure_error(
                    path,
                    "D2I1317",
                    "example must identify a skill when the manifest declares multiple skills",
                    "add a skill field containing a declared skill id",
                )
                .with_location(SourceLocation::new(
                    path,
                    u32::try_from(index + 1).ok(),
                    None,
                )),
            );
            continue;
        };
        let Some(schema) = schemas.get(skill_id) else {
            diagnostics.push(
                structure_error(
                    path,
                    "D2I1318",
                    format!("example references missing or invalid skill schema '{skill_id}'"),
                    "use a declared skill whose input schema is valid",
                )
                .with_location(SourceLocation::new(
                    path,
                    u32::try_from(index + 1).ok(),
                    None,
                )),
            );
            continue;
        };
        let actual_valid = schema.is_valid(request);
        if actual_valid != expected_valid {
            let expectation = if expected_valid {
                "must satisfy"
            } else {
                "must be rejected by"
            };
            let mut diagnostic = structure_error(
                path,
                "D2I1319",
                format!("example {expectation} skill '{skill_id}' input schema"),
                if expected_valid {
                    "fix the positive request or its input schema"
                } else {
                    "make the negative request exercise an invalid input"
                },
            )
            .with_location(SourceLocation::new(
                path,
                u32::try_from(index + 1).ok(),
                None,
            ))
            .with_field("request");
            if expected_valid {
                if let Err(mut errors) = schema.validate(request) {
                    if let Some(error) = errors.next() {
                        diagnostic = diagnostic.with_help(format!(
                            "schema rejected request at {}: {error}",
                            error.instance_path
                        ));
                    }
                }
            }
            diagnostics.push(diagnostic);
        }
    }
}

fn has_external_ref(value: &JsonValue) -> bool {
    match value {
        JsonValue::Object(object) => object.iter().any(|(key, value)| {
            if key == "$ref" {
                value.as_str().is_some_and(|reference| {
                    reference.contains("://")
                        || reference.starts_with('/')
                        || reference.split('/').any(|component| component == "..")
                })
            } else {
                has_external_ref(value)
            }
        }),
        JsonValue::Array(values) => values.iter().any(has_external_ref),
        _ => false,
    }
}

fn missing_local_ref(
    schema_path: &str,
    schema: &JsonValue,
    documents: &BTreeMap<&str, &JsonValue>,
) -> Option<String> {
    let mut references = Vec::new();
    collect_refs(schema, &mut references);
    for reference in references {
        if reference.starts_with('#') {
            continue;
        }
        let file_part = reference.split('#').next().unwrap_or_default();
        if file_part.is_empty() {
            continue;
        }
        let parent = Path::new(schema_path)
            .parent()
            .unwrap_or_else(|| Path::new(""));
        let joined = parent.join(file_part);
        if crate::source::validate_relative_reference(joined.to_string_lossy().as_ref()).is_err() {
            return Some(reference.to_owned());
        }
        let normalized = joined
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        if !documents.contains_key(normalized.as_str()) {
            return Some(normalized);
        }
    }
    None
}

fn collect_refs<'a>(value: &'a JsonValue, references: &mut Vec<&'a str>) {
    match value {
        JsonValue::Object(object) => {
            for (key, value) in object {
                if key == "$ref" {
                    if let Some(reference) = value.as_str() {
                        references.push(reference);
                    }
                } else {
                    collect_refs(value, references);
                }
            }
        }
        JsonValue::Array(values) => {
            for value in values {
                collect_refs(value, references);
            }
        }
        _ => {}
    }
}

fn schema_with_local_id(path: &str, schema: &JsonValue) -> JsonValue {
    let mut local = schema.clone();
    if let Some(object) = local.as_object_mut() {
        let needs_local_id = object
            .get("$id")
            .and_then(JsonValue::as_str)
            .is_none_or(|id| !id.contains(':'));
        if needs_local_id {
            object.insert(
                "$id".to_owned(),
                JsonValue::String(format!("d2i://local/{path}")),
            );
        }
    }
    local
}

fn yaml_content(document: &ParsedDocument) -> Option<&YamlValue> {
    match document.content() {
        ParsedContent::Yaml(value) => Some(value),
        _ => None,
    }
}

fn insert_unique(
    ids: &mut BTreeMap<String, String>,
    id: String,
    path: &str,
    kind: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if id.trim().is_empty() {
        diagnostics.push(structure_error(
            path,
            "D2I1320",
            format!("{kind} id must not be empty"),
            "provide a stable non-empty id",
        ));
    } else if let Some(previous) = ids.insert(id.clone(), path.to_owned()) {
        diagnostics.push(structure_error(
            path,
            "D2I1321",
            format!("duplicate {kind} id '{id}' (first declared in {previous})"),
            format!("give every {kind} a unique id"),
        ));
    }
}

fn is_builtin_step_kind(kind: &str) -> bool {
    matches!(
        kind,
        "read_input"
            | "normalize"
            | "lookup"
            | "retrieve"
            | "rule_eval"
            | "native_call"
            | "model_call"
            | "parallel"
            | "join"
            | "branch"
            | "loop_bounded"
            | "validate"
            | "policy_gate"
            | "human_review"
            | "return"
    )
}

fn push_manifest_diagnostic(
    diagnostics: &mut Vec<Diagnostic>,
    source: &str,
    field: &str,
    code: &str,
    message: impl Into<String>,
    help: impl Into<String>,
) {
    diagnostics.push(
        Diagnostic::new(Severity::Error, code, message)
            .with_location(SourceLocation::new(
                "domain.yaml",
                find_field_line(source, field),
                None,
            ))
            .with_field(field)
            .with_help(help),
    );
}

fn structure_error(
    path: &str,
    code: &str,
    message: impl Into<String>,
    help: impl Into<String>,
) -> Diagnostic {
    Diagnostic::new(Severity::Error, code, message)
        .with_location(SourceLocation::new(path, None, None))
        .with_help(help)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_schema_references_are_detected_recursively() {
        let schema = serde_json::json!({
            "properties": {
                "value": {"$ref": "https://example.invalid/schema.json"}
            }
        });
        assert!(has_external_ref(&schema));
        assert!(!has_external_ref(
            &serde_json::json!({"$ref": "#/$defs/value"})
        ));
    }

    #[test]
    fn report_error_state_uses_severity() {
        let report = ValidationReport {
            manifest: None,
            inventory: None,
            documents: Vec::new(),
            diagnostics: vec![Diagnostic::new(Severity::Warning, "D2I", "warning")],
        };
        assert!(!report.has_errors());
    }
}
