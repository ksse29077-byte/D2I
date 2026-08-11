# B_Core Semantic Experience Integration

## Imported Package

The external artifact is identified only by
`fixtures/learning/b-core-package-descriptor-v1.json`. The descriptor pins:

- package `B_Core_PORTABLE_682306c_WIN64`
- source commit `682306c474073452070733ecb92d57c1df220103`
- package manifest SHA-256
  `e00556cc68f82cc238a9b40c4028455f7d2b9ec3ed6d80e687f10d811350ad70`
- 4,373 manifest entries, all size/hash verified without executing binaries
- public core ABI 1 and semantic state `SEMANTIC-STATE-SEM8-1`
- source license `UNLICENSED`
- failed clean-reconstruction and full-workspace test declarations
- no public semantic-experience ingestion API

The local artifact path is deployment state and is intentionally absent from
repository contracts. The portable package, its 81 executables, source, and
vendored dependencies are not part of the D2I workspace or release.

## D2I Contract

`d2i-semantic-experience` consumes two valid `ObservationSnapshot` values and
an exact verified action binding. Callers explicitly select at most 256 element
IDs. The compiler:

1. checks source/fresh sequence, target, kind, state hashes, and identities;
2. rejects duplicate elements, secret-bearing fields, raw credentials, and
   unbounded context;
3. preserves safe boolean and signed-integer values;
4. canonical-hashes all strings, URLs, paths, objects, and arrays;
5. derives collision-checked numeric entities, axes, operators, and targets;
6. emits a sorted typed delta and exact evidence hashes;
7. seals the result with a deterministic canonical SHA-256 digest;
8. marks it quarantined and execution-free.

`d2i-desktop::compile_verified_desktop_semantic_experience` is the only current
PC bridge. It accepts no browser/UIA handle and performs no observation or
action. It merely revalidates artifacts already produced by the Safe Execution
Kernel and invokes the pure compiler.

## B_Core Compatibility

The optional projection mirrors the numeric atom and state-delta shape seen in
the package's SEM31/SEM32 research contracts. It is useful for deterministic
fixture and future adapter design only. The B_Core dockable API currently has
no matching ingest operation, so compatibility reports include:

- `clean_reconstruction_failed`
- `full_workspace_tests_failed`
- `missing_public_experience_ingest`
- `external_license_not_approved`

No B_Core process is launched, no file is written into its package, and no
semantic state is mutated.
