use crate::{Diagnostic, DomainId, SemanticVersion, Severity, SkillId, SourceLocation};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

const SUPPORTED_D2I_VERSION: &str = "0.1";

/// Top-level contract loaded from `domain.yaml`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DomainManifest {
    pub d2i_version: String,
    pub domain: DomainMetadata,
    pub target: TargetConfig,
    pub objectives: ObjectiveConfig,
    pub sources: Vec<SourceDeclaration>,
    pub skills: Vec<SkillManifest>,
    pub evaluation: EvaluationConfig,
    pub package: PackageConfig,
}

/// Human-facing domain identity and supported languages.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DomainMetadata {
    pub id: String,
    pub version: String,
    pub name: String,
    pub languages: Vec<String>,
}

/// Intended deployment target and hard resource policy.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TargetConfig {
    pub os: String,
    pub arch: String,
    pub network_policy: String,
    pub max_memory_mb: u64,
    pub preferred_device: String,
}

/// Quality and latency objectives declared by the source pack.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveConfig {
    pub min_task_success_rate: f64,
    pub max_critical_error_rate: f64,
    pub target_p95_latency_ms: u64,
    pub deterministic: bool,
}

/// A trusted source path declared by the manifest.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceDeclaration {
    pub path: String,
    pub kind: String,
    pub trust: String,
}

/// Skill-level schema, criticality, and fallback contract.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SkillManifest {
    pub id: String,
    pub version: String,
    pub input_schema: String,
    pub output_schema: String,
    pub criticality: String,
    pub fallback: Option<String>,
    pub evidence_required: bool,
}

/// Evaluation dataset and thresholds references.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluationConfig {
    pub dataset: String,
    pub thresholds: String,
}

/// Package policy retained for later compilation phases.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackageConfig {
    pub signing: String,
    pub include_source_data: bool,
    pub include_eval_data: bool,
}

/// Result of loading and semantically checking `domain.yaml`.
#[derive(Debug)]
pub struct ManifestLoad {
    pub manifest: Option<DomainManifest>,
    pub diagnostics: Vec<Diagnostic>,
    pub source: Option<String>,
    pub root: Option<PathBuf>,
}

/// Loads `domain.yaml`, rejects unknown fields, and accumulates semantic diagnostics.
#[must_use]
pub fn load_manifest(root: &Path) -> ManifestLoad {
    let mut diagnostics = Vec::new();
    let canonical_root = match fs::canonicalize(root) {
        Ok(path) if path.is_dir() => path,
        Ok(_) => {
            diagnostics.push(
                Diagnostic::new(
                    Severity::Error,
                    "D2I1000",
                    "source-pack root is not a directory",
                )
                .with_location(SourceLocation::new(root.display().to_string(), None, None))
                .with_help("pass a directory containing domain.yaml"),
            );
            return ManifestLoad {
                manifest: None,
                diagnostics,
                source: None,
                root: None,
            };
        }
        Err(error) => {
            diagnostics.push(
                Diagnostic::new(
                    Severity::Error,
                    "D2I1000",
                    format!("cannot open source-pack root: {error}"),
                )
                .with_location(SourceLocation::new(root.display().to_string(), None, None))
                .with_help("check that the directory exists and is readable"),
            );
            return ManifestLoad {
                manifest: None,
                diagnostics,
                source: None,
                root: None,
            };
        }
    };

    let manifest_path = canonical_root.join("domain.yaml");
    let source = match fs::read_to_string(&manifest_path) {
        Ok(source) => source,
        Err(error) => {
            diagnostics.push(
                Diagnostic::new(
                    Severity::Error,
                    "D2I1001",
                    format!("cannot read domain.yaml as UTF-8: {error}"),
                )
                .with_location(SourceLocation::new("domain.yaml", None, None))
                .with_help("add a UTF-8 encoded domain.yaml at the source-pack root"),
            );
            return ManifestLoad {
                manifest: None,
                diagnostics,
                source: None,
                root: Some(canonical_root),
            };
        }
    };

    let manifest = match serde_yaml::from_str::<DomainManifest>(&source) {
        Ok(manifest) => {
            validate_manifest(&manifest, &source, &mut diagnostics);
            Some(manifest)
        }
        Err(error) => {
            let (line, column) = error.location().map_or((None, None), |location| {
                (
                    u32::try_from(location.line()).ok(),
                    u32::try_from(location.column()).ok(),
                )
            });
            diagnostics.push(
                Diagnostic::new(
                    Severity::Error,
                    "D2I1002",
                    format!("invalid domain.yaml: {error}"),
                )
                .with_location(SourceLocation::new("domain.yaml", line, column))
                .with_help("fix the YAML syntax and remove unknown or mistyped fields"),
            );
            None
        }
    };

    ManifestLoad {
        manifest,
        diagnostics,
        source: Some(source),
        root: Some(canonical_root),
    }
}

fn validate_manifest(manifest: &DomainManifest, source: &str, diagnostics: &mut Vec<Diagnostic>) {
    if manifest.d2i_version != SUPPORTED_D2I_VERSION {
        push_field_error(
            diagnostics,
            source,
            "d2i_version",
            "D2I1003",
            format!("unsupported d2i_version '{}'", manifest.d2i_version),
            format!("use the supported version '{SUPPORTED_D2I_VERSION}'"),
        );
    }

    if let Err(error) = DomainId::from_str(&manifest.domain.id) {
        push_field_error(
            diagnostics,
            source,
            "domain.id",
            "D2I1004",
            error.to_string(),
            "use a stable ASCII identifier such as equipment-maintenance",
        );
    }

    if let Err(error) = SemanticVersion::from_str(&manifest.domain.version) {
        push_field_error(
            diagnostics,
            source,
            "domain.version",
            "D2I1005",
            error.to_string(),
            "use major.minor.patch numeric syntax",
        );
    }

    if manifest.domain.name.trim().is_empty() {
        push_field_error(
            diagnostics,
            source,
            "domain.name",
            "D2I1006",
            "domain name must not be empty",
            "provide a human-readable domain name",
        );
    }

    if manifest.domain.languages.is_empty()
        || manifest
            .domain
            .languages
            .iter()
            .any(|language| language.trim().is_empty())
    {
        push_field_error(
            diagnostics,
            source,
            "domain.languages",
            "D2I1007",
            "at least one non-empty language tag is required",
            "add a language tag such as en or ko",
        );
    }

    if manifest.target.network_policy != "deny" {
        push_field_error(
            diagnostics,
            source,
            "target.network_policy",
            "D2I1008",
            "Phase 1 source packs must deny network access",
            "set network_policy to deny",
        );
    }

    validate_unit_interval(
        manifest.objectives.min_task_success_rate,
        "objectives.min_task_success_rate",
        source,
        diagnostics,
    );
    validate_unit_interval(
        manifest.objectives.max_critical_error_rate,
        "objectives.max_critical_error_rate",
        source,
        diagnostics,
    );

    if manifest.sources.is_empty() {
        push_field_error(
            diagnostics,
            source,
            "sources",
            "D2I1009",
            "at least one source declaration is required",
            "declare a relative source file or directory",
        );
    }

    if manifest.skills.is_empty() {
        push_field_error(
            diagnostics,
            source,
            "skills",
            "D2I1010",
            "at least one skill is required",
            "declare a skill with input and output schemas",
        );
    }

    for (index, source_declaration) in manifest.sources.iter().enumerate() {
        for (name, value) in [
            ("path", source_declaration.path.as_str()),
            ("kind", source_declaration.kind.as_str()),
            ("trust", source_declaration.trust.as_str()),
        ] {
            if value.trim().is_empty() {
                let field = format!("sources[{index}].{name}");
                push_field_error(
                    diagnostics,
                    source,
                    &field,
                    "D2I1012",
                    format!("source {name} must not be empty"),
                    "provide a non-empty source declaration value",
                );
            }
        }
    }

    for (index, skill) in manifest.skills.iter().enumerate() {
        if let Err(error) = SkillId::from_str(&skill.id) {
            let field = format!("skills[{index}].id");
            push_field_error(
                diagnostics,
                source,
                &field,
                "D2I1013",
                error.to_string(),
                "use a stable ASCII skill identifier",
            );
        }
        if skill.version.trim().is_empty() {
            let field = format!("skills[{index}].version");
            push_field_error(
                diagnostics,
                source,
                &field,
                "D2I1014",
                "skill version must not be empty",
                "provide an immutable skill version",
            );
        }
    }
}

fn validate_unit_interval(
    value: f64,
    field: &str,
    source: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        push_field_error(
            diagnostics,
            source,
            field,
            "D2I1011",
            "objective rate must be between 0 and 1",
            "use a finite decimal value in the inclusive range 0..1",
        );
    }
}

fn push_field_error(
    diagnostics: &mut Vec<Diagnostic>,
    source: &str,
    field: &str,
    code: &str,
    message: impl Into<String>,
    help: impl Into<String>,
) {
    let line = find_field_line(source, field);
    diagnostics.push(
        Diagnostic::new(Severity::Error, code, message)
            .with_location(SourceLocation::new("domain.yaml", line, None))
            .with_field(field)
            .with_help(help),
    );
}

pub(crate) fn find_field_line(source: &str, field: &str) -> Option<u32> {
    let key = field.rsplit('.').next()?;
    let needle = format!("{key}:");
    let section = field
        .split(['.', '['])
        .next()
        .filter(|section| *section != key);
    let occurrence = field
        .split_once('[')
        .and_then(|(_, suffix)| suffix.split_once(']'))
        .and_then(|(index, _)| index.parse::<usize>().ok())
        .unwrap_or(0);
    let lines = source.lines().collect::<Vec<_>>();
    let (start, end) = section.map_or((0, lines.len()), |section| {
        let section_needle = format!("{section}:");
        let start = lines
            .iter()
            .position(|line| line.trim_end() == section_needle)
            .map_or(0, |index| index + 1);
        let end = lines
            .iter()
            .enumerate()
            .skip(start)
            .find(|(_, line)| {
                !line.trim().is_empty() && !line.starts_with(' ') && !line.starts_with('\t')
            })
            .map_or(lines.len(), |(index, _)| index);
        (start, end)
    });

    lines[start..end]
        .iter()
        .enumerate()
        .filter(|(_, line)| {
            let trimmed = line.trim_start().trim_start_matches("- ");
            trimmed.starts_with(&needle)
        })
        .nth(occurrence)
        .and_then(|(offset, _)| u32::try_from(start + offset + 1).ok())
}
