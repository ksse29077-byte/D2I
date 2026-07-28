# Module Versioning and Compatibility

Contract, module, capability, schema, artifact, manifest, and build identities
are independent and explicit.

- Contract version changes when envelope or safety semantics are incompatible.
- Module semantic version changes with module behavior or supported cases.
- Capability semantic version changes with capability-specific behavior.
- Schema version changes when typed input/output compatibility changes.
- Build ID and artifact hash change for every distinct executable artifact.
- Manifest hash changes for any canonical manifest content change.

V1 readers reject unknown fields and any contract version other than `1`.
Optional v1 fields may be added only when old readers can reject them without
changing safety decisions. New categories use `x-` but still require manifest
and reviewer approval.

Changing side-effect authority, network policy, trust semantics, production
package embedding, Runtime ABI, native loader, or irreversible-action support
requires an ADR or RFC. Do not silently reuse an old schema or capability
version for changed semantics.

Canonical JSON and SHA-256 are the cross-language compatibility anchor.
