# Document Work Source Survey v1

OFFICE-200 follows the OFFICE-100 authority order: official API/specification,
official open source, then community compatibility material. Public MCPs are
never production execution dependencies.

## Selected Sources

| Source | Revision/version | Use | License/runtime decision |
| --- | --- | --- | --- |
| Hancom HWPX/OWPML public format material | OFFICE-100 pinned source record | Format authority | Documentation/reference |
| `hancom-io/hwpx-owpml-model` | `1453388472c703a4b299a0834f425cdac16644b9` | Object-model and edge-case design | Apache-2.0; design/offline conformance only |
| `hancom-io/dvc` | `19a985ec047df629240cbcbe2cec17f19ad1a014` | Validation strategy | Public reference; offline conformance only |
| HWPX fixture from `neolord0/hwpxlib` | `473d9d6aa82d8896f4f464b52d801e5691dc7cf3` | Deterministic package fixture | Apache-2.0; fixture only |
| Microsoft Word Object Model documentation | current at implementation | Fixed reviewed COM lowering | Documentation; installed client only |
| Office security automation property documentation | current at implementation | Force macro security | Documentation; fixed worker behavior |
| `quick-xml` | `0.41.0` | Streaming bounded XML mechanics | MIT; pinned production dependency |
| `zip` | `4.6.1` | Bounded ZIP read/write | MIT; default features off, deflate only |

The selected Rust crates add no application automation, network client, model,
script engine, Python, or Node runtime. Their transitive graph is locked. D2I
performs its own entry-name validation, decompression accounting, XML
declaration denial, active-content denial, semantic lowering, authority, and
fresh verification. Replacement is localized to the two file adapters.

## Rejected Runtime Paths

Community HWP and Office MCP servers, broad COM wrappers, Python document
libraries, model-generated OOXML/HWPX, and UI macro automation are excluded
from production. They either expose caller-selected paths and methods, add a
large runtime/supply-chain surface, or bypass one-operation Policy/KRN
admission. UIA remains a future exception fallback, not an OFFICE-200 backend.

Hancom Automation remains disabled because no explicit commercial automation
license evidence exists in the repository or deployment environment. The
installed HWP executable is inventory evidence only.
