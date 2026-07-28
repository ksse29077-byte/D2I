# Module Manifest v1

Use one `module-manifest.yaml` or `module-manifest.json` at the module root.
Unknown fields and duplicate typed fields are rejected.

## Sections

`identity` binds human metadata, semantic version, contract/build IDs,
repository-relative artifact filename, artifact hash, optional manifest
self-hash, author, and maintainer.

`capabilities` declares capability/version, extensible category, supported
input/output/risk kinds, determinism, side effects, network, streaming,
confidence semantics, exact schemas, unsupported behavior, and fallback.
Custom categories use an `x-` prefix.

`schemas` binds every schema ID/version to a relative path and SHA-256.

`execution` declares mode and bounded timeout, input/output, memory, logical
operations, retries, and concurrency. It also declares network, filesystem,
environment, side effects, and reversibility.

`security` declares accepted trust labels, untrusted-content handling, secret
and privilege requirements, dependencies, audit requirement, fail policy, and
retention.

`evaluation` declares the evaluation set, metrics, thresholds, critical error,
unsupported cases, benchmark reference, and replay requirement.

`provenance_and_license` declares source/artifact/dataset licenses, commercial
use, attribution, dependencies, supply-chain metadata, model card, data card,
and threat model.

## Secure Defaults

Reference v1 requires network denied, side effects false, filesystem false,
environment variables false, secrets false, raw secret input false, privilege
false, fail-closed, and no persistent retention. Reserved execution modes fail
validation because no production loader exists.

## Manifest Hash

The canonical manifest hash omits `identity.manifest_sha256` to avoid a
self-reference. A loader computes it and checks the optional declared value.
The resulting `ModuleIdentifier` always contains the computed value.

Artifact and schema paths are canonicalized, must remain below the module root,
must be regular bounded files, and must match their declared hashes.
