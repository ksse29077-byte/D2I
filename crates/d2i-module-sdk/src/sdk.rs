use crate::contract::{
    canonical_json_bytes, canonical_sha256, reject_sensitive_fields, result_payload_hash,
    ConfidenceSemantics, DeterministicReplayMetadata, ModuleCapability, ModuleError,
    ModuleErrorCode, ModuleInvocationEnvelope, ModuleProvenance, ModuleResultEnvelope,
    ModuleResultStatus, ResourceUsage, TimingRecord, CONTRACT_VERSION_V1,
};
use crate::manifest::{read_bounded, LoadedModuleManifest};
use jsonschema::{Draft, JSONSchema};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Static metadata returned by a Rust reference module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleMetadata {
    pub module_id: String,
    pub module_version: String,
    pub build_id: String,
}

/// Result of an optional bounded module self-check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfCheck {
    pub healthy: bool,
    pub details: Vec<String>,
}

/// Trusted invocation context supplied by the caller, never by payload text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationContext {
    pub current_logical_tick: u64,
    pub current_observation_hash: Option<String>,
    pub current_plan_generation_id: Option<String>,
    pub allowed_trust_labels: BTreeSet<String>,
    pub invocation_trust_labels: BTreeSet<String>,
}

/// Typed module output before envelope construction.
#[derive(Debug, Clone, PartialEq)]
pub struct ModuleOutput<T> {
    pub value: T,
    pub confidence: Option<f64>,
    pub evidence: Vec<String>,
    pub warnings: Vec<String>,
    pub peak_memory_bytes: u64,
    pub logical_operations: u64,
    pub logical_elapsed_ticks: u64,
    pub provenance: ModuleProvenance,
}

impl<T> ModuleOutput<T> {
    /// Creates a deterministic output with explicit logical resource usage.
    #[must_use]
    pub fn new(value: T, provenance: ModuleProvenance) -> Self {
        Self {
            value,
            confidence: None,
            evidence: Vec::new(),
            warnings: Vec::new(),
            peak_memory_bytes: 0,
            logical_operations: 1,
            logical_elapsed_ticks: 1,
            provenance,
        }
    }
}

/// Minimal Rust reference module contract.
pub trait Module {
    type Input: DeserializeOwned + Serialize;
    type Output: DeserializeOwned + Serialize;

    /// Immutable module metadata.
    fn metadata(&self) -> ModuleMetadata;

    /// Capabilities implemented by this module.
    fn capabilities(&self) -> Vec<ModuleCapability>;

    /// Performs module-specific typed input validation.
    fn validate_input(
        &self,
        input: &Self::Input,
        context: &InvocationContext,
    ) -> Result<(), ModuleError>;

    /// Executes pure module logic without host side-effect authority.
    fn invoke(
        &self,
        input: Self::Input,
        context: &InvocationContext,
    ) -> Result<ModuleOutput<Self::Output>, ModuleError>;

    /// Optional bounded health check.
    fn self_check(&self) -> SelfCheck {
        SelfCheck {
            healthy: true,
            details: Vec::new(),
        }
    }
}

/// JSON Schema catalog loaded from a validated module directory.
#[derive(Debug, Clone)]
pub struct SchemaCatalog {
    schemas: BTreeMap<(String, u32), Value>,
}

impl SchemaCatalog {
    /// Loads and compiles all schema references from a validated manifest.
    pub fn from_loaded(loaded: &LoadedModuleManifest) -> Result<Self, ModuleError> {
        let mut schemas = BTreeMap::new();
        for reference in &loaded.manifest.schemas {
            let path = loaded.root.join(&reference.path);
            let bytes = read_bounded(&path, 2 * 1024 * 1024)?;
            let schema: Value = crate::parse_json_strict(&bytes)?;
            JSONSchema::options()
                .with_draft(Draft::Draft202012)
                .compile(&schema)
                .map_err(|error| {
                    ModuleError::new(
                        ModuleErrorCode::SchemaMismatch,
                        format!("cannot compile schema '{}': {error}", reference.schema_id),
                    )
                })?;
            let key = (reference.schema_id.clone(), reference.schema_version);
            if schemas.insert(key, schema).is_some() {
                return Err(ModuleError::new(
                    ModuleErrorCode::SchemaMismatch,
                    "duplicate schema identity in catalog",
                ));
            }
        }
        Ok(Self { schemas })
    }

    /// Validates a JSON value against an exact schema ID and version.
    pub fn validate(
        &self,
        schema_id: &str,
        schema_version: u32,
        value: &Value,
    ) -> Result<(), ModuleError> {
        let schema = self
            .schemas
            .get(&(schema_id.to_owned(), schema_version))
            .ok_or_else(|| {
                ModuleError::new(
                    ModuleErrorCode::SchemaMismatch,
                    format!("schema '{schema_id}' version {schema_version} is unavailable"),
                )
            })?;
        let validator = JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(schema)
            .map_err(|error| {
                ModuleError::new(
                    ModuleErrorCode::SchemaMismatch,
                    format!("cannot compile schema '{schema_id}': {error}"),
                )
            })?;
        if let Err(errors) = validator.validate(value) {
            let messages = errors
                .take(4)
                .map(|error| error.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(ModuleError::new(
                ModuleErrorCode::SchemaMismatch,
                format!("schema '{schema_id}' rejected payload: {messages}"),
            ));
        }
        Ok(())
    }
}

/// Guard that prevents untrusted data from being interpreted as instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntrustedContentGuard {
    contains_untrusted_content: bool,
}

impl UntrustedContentGuard {
    /// Builds a guard from invocation trust labels.
    #[must_use]
    pub fn from_labels(labels: &BTreeSet<String>) -> Self {
        Self {
            contains_untrusted_content: labels.iter().any(|label| {
                matches!(
                    label.as_str(),
                    "untrusted_web_content"
                        | "untrusted_document_content"
                        | "untrusted_email_content"
                        | "observed_ui_state"
                )
            }),
        }
    }

    /// True when the payload includes content that must remain data.
    #[must_use]
    pub const fn contains_untrusted_content(&self) -> bool {
        self.contains_untrusted_content
    }

    /// Fails if a module attempts to derive executable instruction authority.
    pub fn reject_instruction_derivation(&self) -> Result<(), ModuleError> {
        if self.contains_untrusted_content {
            return Err(ModuleError::new(
                ModuleErrorCode::UntrustedInputViolation,
                "untrusted content cannot be promoted to executable instruction",
            ));
        }
        Ok(())
    }
}

/// Validates caller lifecycle state, manifest binding, capability, and trust.
pub fn validate_invocation(
    loaded: &LoadedModuleManifest,
    invocation: &ModuleInvocationEnvelope,
    context: &InvocationContext,
) -> Result<(), ModuleError> {
    invocation.validate()?;
    if invocation.module != loaded.identifier {
        return Err(ModuleError::new(
            ModuleErrorCode::ArtifactMismatch,
            "invocation module identifier does not match loaded manifest and artifact",
        ));
    }
    if invocation.deadline_logical_tick <= context.current_logical_tick {
        return Err(ModuleError::new(
            ModuleErrorCode::Timeout,
            "invocation deadline has expired in caller context",
        ));
    }
    if invocation.source_observation_hash != context.current_observation_hash {
        return Err(ModuleError::new(
            ModuleErrorCode::DeterministicReplayMismatch,
            "stale source observation hash",
        ));
    }
    if invocation.plan_generation_id != context.current_plan_generation_id {
        return Err(ModuleError::new(
            ModuleErrorCode::DeterministicReplayMismatch,
            "stale plan generation",
        ));
    }
    if !invocation
        .trust_labels
        .iter()
        .all(|label| context.allowed_trust_labels.contains(label))
    {
        return Err(ModuleError::new(
            ModuleErrorCode::UntrustedInputViolation,
            "invocation contains a trust label not accepted by caller context",
        ));
    }
    if invocation.trust_labels != context.invocation_trust_labels {
        return Err(ModuleError::new(
            ModuleErrorCode::UntrustedInputViolation,
            "invocation trust labels do not match trusted caller context",
        ));
    }
    let capability = loaded
        .manifest
        .capabilities
        .iter()
        .find(|item| item.capability.capability_id == invocation.requested_capability)
        .ok_or_else(|| {
            ModuleError::new(
                ModuleErrorCode::UnsupportedCapability,
                "requested capability is not declared by the module",
            )
        })?;
    if !capability
        .input_schemas
        .iter()
        .any(|schema| schema == &invocation.input_schema_id)
    {
        return Err(ModuleError::new(
            ModuleErrorCode::SchemaMismatch,
            "input schema is not declared for requested capability",
        ));
    }
    if invocation.resource_budget.max_input_bytes > loaded.manifest.execution.maximum_input_bytes
        || invocation.resource_budget.max_output_bytes
            > loaded.manifest.execution.maximum_output_bytes
        || invocation.resource_budget.memory_bytes > loaded.manifest.execution.memory_limit_bytes
        || invocation.resource_budget.logical_operation_budget
            > loaded.manifest.execution.logical_operation_budget
    {
        return Err(ModuleError::new(
            ModuleErrorCode::ResourceExhausted,
            "invocation resource budget exceeds manifest limits",
        ));
    }
    Ok(())
}

/// Confirms that a result belongs to the exact invocation and replay context.
pub fn validate_result_binding(
    invocation: &ModuleInvocationEnvelope,
    result: &ModuleResultEnvelope,
) -> Result<(), ModuleError> {
    result.validate()?;
    if result.invocation_id != invocation.invocation_id {
        return Err(ModuleError::new(
            ModuleErrorCode::DeterministicReplayMismatch,
            "result invocation_id does not match invocation",
        ));
    }
    if result.module != invocation.module {
        return Err(ModuleError::new(
            ModuleErrorCode::ArtifactMismatch,
            "result module identity does not match invocation",
        ));
    }
    if result.replay.replay_id != invocation.replay.replay_id
        || result.replay.seed != invocation.replay.seed
        || result.replay.invocation_hash != canonical_sha256(invocation)?
    {
        return Err(ModuleError::new(
            ModuleErrorCode::DeterministicReplayMismatch,
            "result replay metadata does not match invocation",
        ));
    }
    Ok(())
}

/// Invokes a Rust module through strict typed and schema boundaries.
pub fn invoke_module<M: Module>(
    module: &M,
    loaded: &LoadedModuleManifest,
    schemas: &SchemaCatalog,
    invocation: &ModuleInvocationEnvelope,
    context: &InvocationContext,
) -> Result<ModuleResultEnvelope, ModuleError> {
    let capability = loaded
        .manifest
        .capabilities
        .iter()
        .find(|item| item.capability.capability_id == invocation.requested_capability);
    let output_schema = capability
        .and_then(|item| item.output_schemas.first())
        .cloned()
        .unwrap_or_else(|| "unknown-output".to_owned());
    let output_schema_version = loaded
        .manifest
        .schemas
        .iter()
        .find(|schema| schema.schema_id == output_schema)
        .map_or(1, |schema| schema.schema_version);

    if let Err(error) = validate_invocation(loaded, invocation, context) {
        return failed_result(
            loaded,
            invocation,
            &output_schema,
            output_schema_version,
            error,
        );
    }
    if let Err(error) = schemas.validate(
        &invocation.input_schema_id,
        invocation.input_schema_version,
        &invocation.payload,
    ) {
        return failed_result(
            loaded,
            invocation,
            &output_schema,
            output_schema_version,
            error,
        );
    }

    let metadata = module.metadata();
    if metadata.module_id != loaded.identifier.module_id
        || metadata.module_version != loaded.identifier.module_version
        || metadata.build_id != loaded.identifier.build_id
    {
        return failed_result(
            loaded,
            invocation,
            &output_schema,
            output_schema_version,
            ModuleError::new(
                ModuleErrorCode::ArtifactMismatch,
                "Rust module metadata does not match loaded manifest",
            ),
        );
    }
    if !module
        .capabilities()
        .iter()
        .any(|item| item.capability_id == invocation.requested_capability)
    {
        return unsupported_result(
            loaded,
            invocation,
            &output_schema,
            output_schema_version,
            "Rust module does not implement the requested capability",
        );
    }
    let input: M::Input = match serde_json::from_value(invocation.payload.clone()) {
        Ok(value) => value,
        Err(error) => {
            return failed_result(
                loaded,
                invocation,
                &output_schema,
                output_schema_version,
                ModuleError::new(
                    ModuleErrorCode::SchemaMismatch,
                    format!("typed input conversion failed: {error}"),
                ),
            )
        }
    };
    if let Err(error) = module.validate_input(&input, context) {
        return module_error_result(
            loaded,
            invocation,
            &output_schema,
            output_schema_version,
            error,
        );
    }

    let invoked = catch_unwind(AssertUnwindSafe(|| module.invoke(input, context)));
    let output = match invoked {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            return module_error_result(
                loaded,
                invocation,
                &output_schema,
                output_schema_version,
                error,
            )
        }
        Err(_) => {
            return failed_result(
                loaded,
                invocation,
                &output_schema,
                output_schema_version,
                ModuleError::new(
                    ModuleErrorCode::PanicOrAbnormalTermination,
                    "module panicked inside the SDK boundary",
                ),
            )
        }
    };

    if output.logical_elapsed_ticks > loaded.manifest.execution.timeout_logical_ticks
        || context
            .current_logical_tick
            .saturating_add(output.logical_elapsed_ticks)
            >= invocation.deadline_logical_tick
    {
        return failed_result(
            loaded,
            invocation,
            &output_schema,
            output_schema_version,
            ModuleError::new(ModuleErrorCode::Timeout, "module exceeded logical timeout")
                .retryable(true),
        );
    }
    if output.peak_memory_bytes > invocation.resource_budget.memory_bytes
        || output.logical_operations > invocation.resource_budget.logical_operation_budget
    {
        return failed_result(
            loaded,
            invocation,
            &output_schema,
            output_schema_version,
            ModuleError::new(
                ModuleErrorCode::ResourceExhausted,
                "module exceeded invocation resource budget",
            ),
        );
    }
    let confidence_semantics = &capability
        .ok_or_else(|| {
            ModuleError::new(
                ModuleErrorCode::UnsupportedCapability,
                "capability disappeared during invocation",
            )
        })?
        .capability
        .confidence_semantics;
    match (confidence_semantics, output.confidence) {
        (ConfidenceSemantics::NotApplicable, Some(_)) => {
            return failed_result(
                loaded,
                invocation,
                &output_schema,
                output_schema_version,
                ModuleError::new(
                    ModuleErrorCode::InvalidInput,
                    "capability declares confidence not applicable but module returned confidence",
                ),
            )
        }
        (ConfidenceSemantics::NotApplicable, None) => {}
        (_, Some(value)) if value.is_finite() && (0.0..=1.0).contains(&value) => {}
        _ => {
            return failed_result(
                loaded,
                invocation,
                &output_schema,
                output_schema_version,
                ModuleError::new(
                    ModuleErrorCode::InvalidInput,
                    "capability requires finite confidence within 0..1",
                ),
            )
        }
    }

    let payload = serde_json::to_value(output.value).map_err(|error| {
        ModuleError::new(
            ModuleErrorCode::InternalFailure,
            format!("typed output conversion failed: {error}"),
        )
    })?;
    if let Err(error) = reject_sensitive_fields(&payload, "output payload", true) {
        return failed_result(
            loaded,
            invocation,
            &output_schema,
            output_schema_version,
            error,
        );
    }
    if let Err(error) = schemas.validate(&output_schema, output_schema_version, &payload) {
        return failed_result(
            loaded,
            invocation,
            &output_schema,
            output_schema_version,
            error,
        );
    }
    let output_bytes = u64::try_from(canonical_json_bytes(&payload)?.len()).map_err(|_| {
        ModuleError::new(
            ModuleErrorCode::ResourceExhausted,
            "output size is not representable",
        )
    })?;
    if output_bytes > invocation.resource_budget.max_output_bytes
        || output_bytes > loaded.manifest.execution.maximum_output_bytes
    {
        return failed_result(
            loaded,
            invocation,
            &output_schema,
            output_schema_version,
            ModuleError::new(
                ModuleErrorCode::ResourceExhausted,
                "module output exceeds byte limit",
            ),
        );
    }
    let input_bytes =
        u64::try_from(canonical_json_bytes(&invocation.payload)?.len()).map_err(|_| {
            ModuleError::new(
                ModuleErrorCode::ResourceExhausted,
                "input size is not representable",
            )
        })?;
    let output_hash =
        result_payload_hash(ModuleResultStatus::Succeeded, Some(&payload), None, None)?;
    let result = ModuleResultEnvelope {
        contract_version: CONTRACT_VERSION_V1,
        invocation_id: invocation.invocation_id.clone(),
        module: loaded.identifier.clone(),
        status: ModuleResultStatus::Succeeded,
        output_schema_id: output_schema,
        output_schema_version,
        payload: Some(payload),
        confidence: output.confidence,
        evidence: output.evidence,
        warnings: output.warnings,
        unsupported_reason: None,
        error: None,
        resource_usage: ResourceUsage {
            input_bytes,
            output_bytes,
            peak_memory_bytes: output.peak_memory_bytes,
            logical_operations: output.logical_operations,
        },
        timings: vec![
            TimingRecord {
                phase: "invoke_start".to_owned(),
                logical_tick: context.current_logical_tick,
            },
            TimingRecord {
                phase: "invoke_complete".to_owned(),
                logical_tick: context
                    .current_logical_tick
                    .saturating_add(output.logical_elapsed_ticks),
            },
        ],
        replay: DeterministicReplayMetadata {
            replay_id: invocation.replay.replay_id.clone(),
            seed: invocation.replay.seed,
            invocation_hash: canonical_sha256(invocation)?,
        },
        output_hash,
        provenance: output.provenance,
    };
    validate_result_binding(invocation, &result)?;
    Ok(result)
}

fn module_error_result(
    loaded: &LoadedModuleManifest,
    invocation: &ModuleInvocationEnvelope,
    output_schema: &str,
    output_schema_version: u32,
    error: ModuleError,
) -> Result<ModuleResultEnvelope, ModuleError> {
    if matches!(
        error.code,
        ModuleErrorCode::UnsupportedInput | ModuleErrorCode::UnsupportedCapability
    ) {
        unsupported_result(
            loaded,
            invocation,
            output_schema,
            output_schema_version,
            &error.message,
        )
    } else {
        failed_result(
            loaded,
            invocation,
            output_schema,
            output_schema_version,
            error,
        )
    }
}

fn unsupported_result(
    loaded: &LoadedModuleManifest,
    invocation: &ModuleInvocationEnvelope,
    output_schema: &str,
    output_schema_version: u32,
    reason: &str,
) -> Result<ModuleResultEnvelope, ModuleError> {
    terminal_result(
        loaded,
        invocation,
        output_schema,
        output_schema_version,
        ModuleResultStatus::Unsupported,
        None,
        Some(reason.to_owned()),
    )
}

fn failed_result(
    loaded: &LoadedModuleManifest,
    invocation: &ModuleInvocationEnvelope,
    output_schema: &str,
    output_schema_version: u32,
    error: ModuleError,
) -> Result<ModuleResultEnvelope, ModuleError> {
    terminal_result(
        loaded,
        invocation,
        output_schema,
        output_schema_version,
        ModuleResultStatus::Failed,
        Some(error),
        None,
    )
}

fn terminal_result(
    loaded: &LoadedModuleManifest,
    invocation: &ModuleInvocationEnvelope,
    output_schema: &str,
    output_schema_version: u32,
    status: ModuleResultStatus,
    error: Option<ModuleError>,
    unsupported_reason: Option<String>,
) -> Result<ModuleResultEnvelope, ModuleError> {
    let output_hash =
        result_payload_hash(status, None, error.as_ref(), unsupported_reason.as_deref())?;
    let result = ModuleResultEnvelope {
        contract_version: CONTRACT_VERSION_V1,
        invocation_id: invocation.invocation_id.clone(),
        module: loaded.identifier.clone(),
        status,
        output_schema_id: output_schema.to_owned(),
        output_schema_version,
        payload: None,
        confidence: None,
        evidence: Vec::new(),
        warnings: Vec::new(),
        unsupported_reason,
        error,
        resource_usage: ResourceUsage::default(),
        timings: vec![TimingRecord {
            phase: "rejected".to_owned(),
            logical_tick: 0,
        }],
        replay: DeterministicReplayMetadata {
            replay_id: invocation.replay.replay_id.clone(),
            seed: invocation.replay.seed,
            invocation_hash: canonical_sha256(invocation)?,
        },
        output_hash,
        provenance: ModuleProvenance {
            source_id: "sdk-boundary".to_owned(),
            source_sha256: canonical_sha256(invocation)?,
            producer: "d2i-module-sdk".to_owned(),
        },
    };
    result.validate()?;
    Ok(result)
}
