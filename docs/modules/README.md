# Cognitive Module Platform

The Cognitive Module Platform lets teams build side-effect-free cognitive
transformations against a versioned contract without importing `d2i-core` or
receiving runtime adapter authority.

Start with:

1. [Cognitive Module Contract v1](cognitive-module-contract-v1.md)
2. [Module Manifest v1](module-manifest-v1.md)
3. [Rust Module SDK](rust-module-sdk.md)
4. [Example module walkthrough](example-module-walkthrough.md)
5. [Conformance Suite](conformance-suite.md)
6. [Module submission checklist](submission-checklist.md)

Reference artifacts:

- `crates/d2i-module-sdk`
- `modules/example-module`
- `modules/rule-based-work-reporter`
- `schemas/modules`

No module loader is connected to the production `CognitiveExecutor`. That
integration requires a separate RFC.
