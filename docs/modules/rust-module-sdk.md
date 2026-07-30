# Rust Module SDK

Create a standalone workspace with `scripts/modules/new-module.ps1`. Add
`d2i-module-sdk` as a path dependency and implement `Module`:

```rust
pub trait Module {
    type Input: DeserializeOwned + Serialize;
    type Output: DeserializeOwned + Serialize;

    fn metadata(&self) -> ModuleMetadata;
    fn capabilities(&self) -> Vec<ModuleCapability>;
    fn validate_input(
        &self,
        input: &Self::Input,
        context: &InvocationContext,
    ) -> Result<(), ModuleError>;
    fn invoke(
        &self,
        input: Self::Input,
        context: &InvocationContext,
    ) -> Result<ModuleOutput<Self::Output>, ModuleError>;
    fn self_check(&self) -> SelfCheck;
}
```

`invoke_module` performs envelope validation, stale lifecycle checks, input
schema validation, typed conversion, metadata/capability matching, panic
containment, typed invocation, logical timeout/resource checks, confidence
validation, output schema validation, secret-field rejection, result
construction, and output hashing.

`SchemaCatalog` loads only hash-verified schemas. `ModuleOutput` records
logical operations, elapsed ticks, peak memory declaration, evidence, warnings,
confidence, and provenance. `UntrustedContentGuard` marks payload content as
data and rejects attempts to derive instruction authority.

The v1 SDK does not preempt an in-process thread. Timeout conformance uses
deterministic logical ticks. Modules that require hard process termination need
the future isolated-process loader RFC.

Do not add arbitrary I/O to `Module`. Declare a dependency or capability need
in the manifest and return `DependencyUnavailable`, `NetworkProhibited`, or
`UnsupportedInput` as appropriate.

Modules that exchange Cognitive IR v1 data depend on the pure
`d2i-cognitive-ir` crate. They do not depend on `d2i-desktop` or any runtime,
adapter, CLI, FFI, Windows, UIA, WebDriver, WFP, policy, activation, or audit
implementation.
