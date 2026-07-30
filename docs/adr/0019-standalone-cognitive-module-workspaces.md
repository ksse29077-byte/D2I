# ADR 0019: Standalone Cognitive Module Workspaces And Core Decoupling

## Status

Accepted.

## Context

Cognitive modules were root Cargo workspace members. A new module therefore
changed the shared `Cargo.toml` and `Cargo.lock`, while Core CLI code directly
linked one reference module. Parallel module branches collided in shared
manifests and every module-only pull request paid for unrelated Core and
Windows checks.

The Cognitive IR v1 data contract also lived in `d2i-desktop`, forcing a pure
module to depend on a product crate that owns executors and Windows adapters.

## Decision

The root workspace contains Core crates, products, and explicit Core tools
only. It declares `exclude = ["modules/*"]`. Every `modules/<module-id>` is a
one-package standalone workspace with an explicit dependency set and local
`Cargo.lock`.

Modules may directly depend on:

- `d2i-module-sdk`
- `d2i-cognitive-ir`
- ordinary declared third-party libraries

They may not depend on products, runtime implementations, CLI, FFI, Windows
host, UIA, WebDriver, WFP, policy, activation, or audit implementations.

`d2i-cognitive-ir` owns only Cognitive IR v1 public data types, pure
validation, canonical hashing, and the authoritative schema reference.
`d2i-desktop` depends on and re-exports those same Rust types, preserving
source and JSON compatibility. Executors, providers, policy, activation,
audit, I/O, and platform code remain in product crates.

The Core CLI can validate a module manifest but never links a module
implementation. Its generic conformance command returns structured
`unsupported` and points to `scripts/modules/check-module.ps1`.

Module tooling is repository-owned:

- `new-module.ps1` creates only `modules/<module-id>` and its local lockfile.
- `check-module.ps1` runs locked metadata, dependency-boundary validation,
  formatting, Clippy, tests, manifest/conformance/replay tests, and a release
  build for one module.
- `check-all-modules.ps1` discovers manifests dynamically and invokes every
  module independently.

CI classifies changes as `module_only`, `core_only`, `core_contract`, or
`mixed_core_migration`. Required jobs always report. Module-only changes run
only the changed module checker; Core contract and migration changes run the
root gates plus all standalone module compatibility checks.

Root `Cargo.toml` and root `Cargo.lock` have no module exception and are always
Core-owned. A module-only branch must match
`module/<issue-number>-<module-id>` and change exactly one module directory.
Core migrations may update modules only on a Core branch under the normal
non-author CODEOWNER gate.

## Rejected Alternatives

### Keep Modules In The Root Workspace

This preserves convenient root commands but retains shared manifest and
lockfile conflicts, unnecessary CI fan-out, and Core ownership ambiguity.

### Add A Shared Module Workspace Or Registry File

A `modules/Cargo.toml`, shared lockfile, index, or registry recreates the same
coordination bottleneck at another path.

### Let Modules Depend On `d2i-desktop`

That grants an architectural dependency on executor and platform code and
makes a pure contract consumer build Windows-oriented product dependencies.

### Add A Production Loader

Repository decoupling does not establish an ABI, registry, package embedding,
or production authority boundary. Those require a separate approved contract.

## Consequences

- Independent module additions have disjoint paths and lockfiles.
- Module-only checks are faster and do not wait for Windows or full Core jobs.
- Core contract changes explicitly prove compatibility with every module.
- Dependency versions are duplicated in module manifests and locks; the
  module checker and license declarations make that duplication visible.
- Root workspace commands intentionally do not test modules.
- No production module loader or runtime behavior is added by this decision.

## Verification

The repository tests:

- root workspace metadata excludes `modules/*`;
- each module has one workspace member and a local lockfile;
- forbidden D2I dependencies are rejected;
- Cognitive IR schema, validation, serialization, and stable hashes remain
  compatible;
- `d2i-desktop` re-exports the exact Core Cognitive IR types;
- two synthetic module additions have zero changed-path intersection, rebase
  and merge without conflict, preserve independent locks, and leave the root
  lock unchanged;
- module-only, Core-only, Core-contract, and mixed migration classification;
- strict module branch scope and non-author Core approval.
