# Offline Learning Dataset Registry

## Boundary

`d2i-learning` records external datasets as candidates but never downloads,
executes, transforms, or trains on them. A dataset becomes eligible for a
future offline pipeline only after immutable source and license revisions,
human reviews, compliance plans, and local artifact hashes all pass admission.

The user-prioritized candidate list is stored at
`examples/learning/dataset-registry.candidates.json`. It intentionally reports
`admissible: false`.

Desktop, mobile, web, function-calling, shell, and code candidates are stored
separately at
`examples/learning/desktop-agent-dataset-registry.candidates.json`. Their
source-specific review notes and normalization boundary are documented in
`docs/dataset-intake-desktop-agents.md`. This list also intentionally reports
`admissible: false`.

## Candidate Sources

The following observations were checked against official project pages on
2026-07-27. They are source observations, not legal advice or approval.

| Priority | Dataset | Observed license statement | Admission note |
| ---: | --- | --- | --- |
| 1 | OASST2 | Apache-2.0 | User conversations, multilingual safety labels, and synthetic messages require privacy, provenance, security, and generation-terms review. |
| 2 | Super-NaturalInstructions | Mixed/component-specific | Instructions and metadata are Apache-2.0, but task instances retain each original dataset license. A task-level license inventory is mandatory. |
| 3 | HelpSteer2 | CC-BY-4.0 | Mostly user-contributed ShareGPT prompts and in-house model responses require source-chain and privacy review. |
| 4 | KoAlpaca-RealQA | CC-BY-SA-4.0 | Real ChatKoAlpaca questions and GPT-4o-generated answers require privacy, generation-terms, attribution, and share-alike review. |
| 5 | Gorilla/APIBench | Unresolved at dataset-component level | The repository has an Apache-2.0 license, but APIBench incorporates API documentation from several upstream hubs. Repository licensing alone is not treated as component clearance. |
| 6 | Aegis 2.0 | CC-BY-4.0 | Human prompts, multiple upstream datasets, synthetic responses/labels, possible residual personal data, and harmful content require enhanced review and restricted handling. |

Official evidence:

- [OpenAssistant OASST2 dataset card](https://huggingface.co/datasets/OpenAssistant/oasst2)
- [Super-NaturalInstructions repository license note](https://github.com/allenai/natural-instructions#license)
- [NVIDIA HelpSteer2 dataset card](https://huggingface.co/datasets/nvidia/HelpSteer2/blob/main/README.md)
- [KoAlpaca-RealQA dataset card](https://huggingface.co/datasets/beomi/KoAlpaca-RealQA/blob/main/README.md)
- [Gorilla/APIBench repository](https://github.com/ShishirPatil/gorilla)
- [NVIDIA Aegis 2.0 dataset card](https://huggingface.co/datasets/nvidia/Aegis-AI-Content-Safety-Dataset-2.0/blob/main/README.md)

## Admission Contract

`schemas/learning/dataset-registry.schema.json` defines strict registry v2.
Version 2 adds mandatory third-party, executable, and credential/session risk
declarations; v1 inputs are rejected instead of receiving permissive defaults.
The Rust validator additionally requires:

- a unique, strictly increasing priority and stable dataset ID
- HTTPS source and license-evidence URLs
- immutable 40-64 digit hexadecimal source and evidence revisions
- dataset-wide license coverage or a hashed component-license inventory
- hashed attribution and share-alike plans where required
- approved legal and provenance attestations
- privacy review for user or personal-data-bearing content
- component-specific license accounting for third-party content
- security review for sensitive safety, executable, or credential/session
  content
- generation-system identity and terms review for model-generated content
- normalized local artifact paths, positive sizes, and SHA-256 hashes
- explicit `approved_for_offline_use` status

The verifier canonicalizes every local path beneath the approved root, rejects
symlinks and escapes, streams SHA-256 with a bounded buffer, checks declared
sizes and the total-byte budget, and emits a deterministic aggregate hash.

## CLI

Inspect the current candidate list:

```text
cargo run -p d2i-learning -- dataset-check examples/learning/dataset-registry.candidates.json
cargo run -p d2i-learning -- dataset-check examples/learning/desktop-agent-dataset-registry.candidates.json
```

After reviews, revision pinning, and offline artifact staging:

```text
cargo run -p d2i-learning -- dataset-verify approved-registry.json local-dataset-root
```

Neither command performs network access. Dataset verification is an admission
step only; model-framework training remains deferred.
