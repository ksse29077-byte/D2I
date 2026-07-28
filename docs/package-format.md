# D2I Package Format 1.0.0

## Status and Boundary

The deterministic directory package contains typed FlatBuffers-compatible
metadata, executor selection evidence, and compiler provenance. It contains no
native executable module, signature, or self-learning state. Phase 6 native
libraries remain separately installed and hash-allowlisted host artifacts.

Four versions remain independent:

- `compiler_version`: `0.9.0`
- `package_format_version`: `1.0.0`
- `runtime_abi_version`: `1.0.0`
- domain version from `domain.yaml`

Verification requires exact package-format and runtime-ABI matches. Compiler
versions must be valid semantic versions.

## Layout

```text
domain.d2ip/
|-- manifest.fb
|-- ir/
|   |-- domain.fb
|   |-- skills.fb
|   |-- execution.fb
|   |-- policies.fb
|   `-- evaluation.fb
|-- executors/descriptors.json
|-- reports/
|   |-- selection.json
|   `-- optimization.json
|-- schemas/referenced JSON Schema files
|-- eval/
|   |-- benchmark-profiles.json
|   |-- report.json
|   `-- source/...
|-- provenance/
|   |-- sources.lock
|   `-- build.json
`-- hashes.sha256
```

Evaluation source files are included only when `include_eval_data` is true.
Source data inclusion beyond schema and evaluation contracts remains deferred.

## FlatBuffers Sections

Schema sources live in `schemas/flatbuffers`. Rust bindings are generated with
Planus 1.1.1 and committed under `d2i-schema`; normal builds do not require
`flatc`, CMake, or a code generator.

| File | Identifier | Root |
| --- | --- | --- |
| `manifest.fb` | `D2PM` | `PackageManifest` |
| `ir/domain.fb` | `D2DM` | `DomainBundle` |
| `ir/skills.fb` | `D2SK` | `SkillBundle` |
| `ir/execution.fb` | `D2EX` | `ExecutionBundle` |
| `ir/policies.fb` | `D2PL` | `PolicyBundle` |
| `ir/evaluation.fb` | `D2EV` | `EvaluationBundle` |

Every root has `schema_version = 1`. The compiler normalizes Planus 1.x output
to the standard FlatBuffers header order.

## Phase 4 Artifacts

- `executors/descriptors.json` retains typed executor capability, schema, ABI,
  target, resource, security, license, and artifact hash contracts.
- `eval/benchmark-profiles.json` retains source benchmark observations used
  for compile-time gates and cost comparison.
- `reports/selection.json` maps `skill:capability` to feasible, rejected,
  Pareto, selected, forced, fallback, normalized cost, and explanation data.
- `reports/optimization.json` records deterministic typed-graph optimization
  actions by skill.

These are package payload artifacts and are covered by all normal package
hashes. The runtime reads them from the verified in-memory artifact map.

## Determinism

Artifact paths use `/` and are sorted lexicographically. FlatBuffer vectors are
populated from sorted IR. JSON support files use stable struct and
`BTreeMap` field order with a trailing newline.

The build ID hashes a version tag, domain identity, source inventory hash,
compiler version, package format, and runtime ABI. It is prefixed with `b`.

The payload hash covers sorted `path -> sha256:<hex>` entries for every file
except `manifest.fb` and `hashes.sha256`. The manifest records the payload hash
and table. `hashes.sha256` covers the manifest and every payload artifact. The
package content hash is the SHA-256 of the exact `hashes.sha256` bytes.

No hash input includes timestamps, absolute paths, enumeration order, staging
directory names, or host temporary paths. Runtime benchmark timestamps are
emitted by `d2ic benchmark` and are not written into the compiled package.

## Writer Contract

The output path must not exist and must not be inside the source pack. The
writer creates a unique sibling staging directory, writes all artifacts,
verifies the complete staged package, and renames it only after success. A
failed build removes only its validated staging path.

## Verification

The reader rejects:

- missing, duplicate, or unexpected artifacts
- absolute, traversal, backslash, or symlink package paths
- files larger than 64 MiB
- malformed hash records or hash mismatches
- wrong FlatBuffers identifiers or corrupt required fields
- unsupported root schema, package-format, or runtime-ABI versions
- invalid compiler semantic-version syntax
- manifest file-table, size, or payload-hash mismatches

`read_package` performs the same verification as `verify_package`.
`load_verified_package` additionally returns decoded sections and exact
hash-verified artifact bytes in an immutable map. The runtime does not reopen
schema, descriptor, report, or evaluation artifacts after verification.

## Compatibility

Readers support schema version 1 only. Adding optional fields may retain schema
version 1 if default behavior is unchanged. Removing fields, changing meanings
or defaults, or changing identifiers requires a new schema and package-format
compatibility decision.

Signature creation and verification remain future work. A source manifest that
requests signing records policy intent, but current output must not be treated
as a signed production package.

Phase 8 does not change package format 1.0.0. Candidate `.d2ic` directories and
the signed promotion ledger are separate learning artifacts documented in
`experience-learning.md`; neither is accepted by the production package
reader. Promotion signatures authenticate audit records, not `.d2ip` package
contents.

Phase 9 does not change package format 1.0.0. Sensor events, action intents,
simulation traces, robot memory, and fleet rollout records are external
embodied-product artifacts. They are not accepted as `.d2ip` contents.
