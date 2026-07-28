//! Language-neutral Cognitive Module Contract v1 and Rust reference SDK.
//!
//! This crate has no production loader and grants no adapter, filesystem, or
//! network authority to modules. It provides strict envelopes, manifests,
//! deterministic invocation helpers, fixture execution, and conformance
//! reporting.

mod conformance;
mod contract;
mod manifest;
mod sdk;

pub use conformance::{
    run_fixture_suite, ConformanceCheck, ConformanceReport, ConformanceStatus, FixtureExpectation,
    FixtureReport, FixtureSpec, CONFORMANCE_EXIT_FAILED, CONFORMANCE_EXIT_INTERNAL,
    CONFORMANCE_EXIT_PASSED, CONFORMANCE_EXIT_UNSUPPORTED,
};
pub use contract::{
    canonical_json_bytes, canonical_sha256, parse_json_strict, ConfidenceSemantics,
    DeterministicReplayMetadata, ExecutionMode, ModuleCapability, ModuleCategory, ModuleError,
    ModuleErrorCode, ModuleIdentifier, ModuleInvocationEnvelope, ModuleProvenance,
    ModuleResultEnvelope, ModuleResultStatus, NetworkRequirement, RedactionMarker, ReplayContext,
    ResourceBudget, ResourceUsage, SchemaReference, TimingRecord, CONTRACT_VERSION_V1,
};
pub use manifest::{
    load_module_manifest, validate_module_manifest, AuditRequirement, CapabilityManifest,
    DataRetention, DependencyDeclaration, EvaluationManifest, ExecutionManifest, FailPolicy,
    LicenseManifest, LoadedModuleManifest, ManifestIdentity, ManifestValidationIssue,
    ModuleManifest, SecurityManifest, UntrustedContentPolicy, MODULE_MANIFEST_VERSION_V1,
};
pub use sdk::{
    invoke_module, validate_invocation, validate_result_binding, InvocationContext, Module,
    ModuleMetadata, ModuleOutput, SchemaCatalog, SelfCheck, UntrustedContentGuard,
};
