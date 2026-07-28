# Desktop-Agent Dataset Intake

## Boundary

The desktop-agent candidate registry is
`examples/learning/desktop-agent-dataset-registry.candidates.json`. It records
potential offline evaluation and training inputs for desktop, mobile, web,
function-calling, shell, and code capabilities. Every entry is intentionally a
non-admissible candidate. The registry does not download data, run benchmark
environments, execute commands, render active web content, or start training.

The observations below were checked against official project pages on
2026-07-27. They are intake evidence, not legal advice or approval.

## Candidate Sources

| Priority | Dataset | Purpose | Observed license statement | Intake decision |
| ---: | --- | --- | --- | --- |
| 1 | OSWorld | Desktop interaction | Repository Apache-2.0 | Component-specific candidate. VM images, task files, sites, application content, accounts, and any trajectory release require separate inventory. |
| 2 | AndroidControl | Mobile interaction | Dataset CC-BY-4.0; repository source code Apache-2.0 | Component-specific candidate. Screens, accessibility trees, app content, and session material require privacy and rights review. |
| 3 | Android in the Wild | Mobile interaction | Dataset CC-BY-4.0; repository source code Apache-2.0 | Component-specific candidate. Human demonstrations and embedded app content require attribution, privacy, and session review. |
| 4 | Mind2Web | Web automation | Dataset CC-BY-4.0; repository code MIT | Component-specific candidate. Test splits remain evaluation-only; DOM, MHTML, HAR, storage state, screenshots, and videos require content and session review. |
| 5 | Mind2Web 2 | Web automation | Repository MIT; dataset-wide coverage unresolved | Evaluation-only candidate with `NOASSERTION` until a pinned dataset license and component inventory are reviewed. |
| 6 | WebArena | Web automation | Repository Apache-2.0 | Isolated evaluation candidate. Self-hosted services, images, seeded records, authentication state, and mutating tasks remain component-specific. |
| 7 | Glaive Function Calling v2 | Function calling | Dataset card Apache-2.0 | Candidate. Function names and arguments are inert data; generation provenance and API documentation sources require review. |
| 8 | NL2Bash | Shell mapping | `data/bash` MIT | Component-specific candidate because commands were collected from upstream websites. No command may execute during intake. |
| 9 | The Stack v2 permissive subset | Code generation | Dataset card `other`; original file-level licenses and access terms apply | `NOASSERTION` candidate. A new subset must retain per-file provenance, license evidence, attribution, opt-out state, and removal synchronization. |
| 10 | Magicoder OSS-Instruct 75K | Code generation | Dataset card MIT | Component-specific candidate. The card identifies `gpt-3.5-turbo-1106` generation; generation terms, seed-code licenses, secrets, malware, and contamination require review. |

Official evidence:

- [OSWorld repository](https://github.com/xlang-ai/OSWorld)
- [Google Research license statement](https://github.com/google-research/google-research#license)
- [Mind2Web licensing information](https://github.com/OSU-NLP-Group/Mind2Web#licensing-information)
- [Mind2Web 2 repository](https://github.com/OSU-NLP-Group/Mind2Web-2)
- [WebArena repository](https://github.com/web-arena-x/webarena)
- [Glaive Function Calling v2 dataset card](https://huggingface.co/datasets/glaiveai/glaive-function-calling-v2)
- [NL2Bash repository license note](https://github.com/TellinaTool/nl2bash#license)
- [The Stack v2 dataset card](https://huggingface.co/datasets/bigcode/the-stack-v2)
- [Magicoder OSS-Instruct 75K dataset card](https://huggingface.co/datasets/ise-uiuc/Magicoder-OSS-Instruct-75K)

`Bash-Instruct` and `CodeLlama-Instruct-Dataset` are not registry entries
because those names do not identify a unique official dataset and pinned
license evidence. They remain unresolved source-discovery tasks. Code Llama
model licensing must not be substituted for a dataset license.

## Normalization Contract

An admitted artifact will still require a separate, deterministic normalizer:

```text
verified local source artifact
  -> format-specific parser with record and byte limits
  -> provenance and split-policy attachment
  -> secret, personal-data, unsafe-content, and license filters
  -> inert observation / action / result records
  -> typed transition IR candidate
  -> semantic and safety validation
  -> offline evaluation
  -> reviewed candidate build input
```

The future transition IR must preserve source dataset, artifact hash, record
identity, episode/task identity, split, observation hash, action type, bounded
parameters, result hash, and terminal/error state. Dataset actions never map
directly to `DesktopOperation`.

- Screen coordinates and gestures require viewport, scaling, application, and
  observation bindings. Raw coordinates alone are not portable actions.
- DOM actions require origin, frame, document revision, and stable locator
  evidence. Dataset HTML and scripts remain inert.
- Function calls require a reviewed local tool schema and typed arguments.
  Dataset function names do not grant capabilities.
- Shell and code records are tokenized data. They are never passed to a shell,
  interpreter, compiler, package manager, or dynamic loader during intake.
- Credentials, cookies, storage state, tokens, and account identifiers are
  quarantined and may not become model inputs or audit payloads.
- Evaluation-only benchmark splits and environments are excluded from
  fine-tuning and retrieval indexes.

## Admission Gates

Registry schema v2 requires immutable source and evidence
revisions, legal and provenance attestations, local artifact hashes, and
explicit approval. Desktop-agent sources add three risk declarations:

- `contains_third_party_content`
- `contains_executable_content`
- `contains_credentials_or_session_data`

Third-party content requires component-specific license accounting. Executable
or session-bearing content requires a security review, and session-bearing
content also requires a personal-data review. These checks are fail-closed.

Inspect the candidate registry locally:

```text
cargo run -p d2i-learning -- dataset-check examples/learning/desktop-agent-dataset-registry.candidates.json
```

The expected result is `admissible: false` until evidence revisions, reviews,
component inventories, compliance plans, and artifact hashes are supplied.
