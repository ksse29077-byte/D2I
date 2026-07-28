# Dependency Policy

## Current Locked Dependencies

All versions are exact workspace pins and are also recorded in `Cargo.lock`.

| Crate | Version | License | Purpose | Offline and replacement strategy |
| --- | --- | --- | --- | --- |
| `serde` | 1.0.217 | MIT OR Apache-2.0 | Typed manifest and lock data | Pure serialization; replace with manual decoding only if contract risk requires it |
| `serde_json` | 1.0.138 | MIT OR Apache-2.0 | JSON/JSONL parsing and CLI JSON | No I/O beyond supplied streams; replace with another bounded Rust JSON parser |
| `serde_yaml` | 0.9.34 | MIT OR Apache-2.0 | YAML manifest/source parsing | Deprecated upstream and depends on `unsafe-libyaml`; migrate after an actively maintained compatible parser is selected |
| `csv` | 1.3.1 | MIT OR Unlicense | Bounded CSV record parsing | Stream parser with no network behavior; replace with a compatible RFC-oriented parser |
| `sha2` | 0.10.8 | MIT OR Apache-2.0 | SHA-256 source fingerprints | Pure hashing; replace with a vetted RustCrypto-compatible implementation |
| `jsonschema` | 0.18.3 | MIT | Draft 2020-12 validation | Default features are disabled; external refs are rejected; replace behind the validation module if maintenance or transitive size becomes unacceptable |
| `planus` | 1.1.1 | MIT OR Apache-2.0 | Safe FlatBuffers-compatible runtime for generated package bindings | No network behavior; generated bindings are committed; replace with official generated bindings behind `d2i-schema` when native `flatc` is available in the build toolchain |
| `libloading` | 0.8.9 | ISC | Cross-platform loading and fixed-symbol lookup for hash-allowlisted native modules | No network behavior; isolated in `d2i-ffi`; replace with reviewed `LoadLibrary`/`dlopen` platform wrappers |
| `ed25519-dalek` | 2.1.1 | BSD-3-Clause | Ed25519 promotion-record signatures | Pure Rust with default features disabled; isolated in `d2i-learning`; replace behind the promotion ledger contract with a reviewed offline signing provider |

`jsonschema` has the largest transitive surface (URL, regex, numeric, and time
support). Its HTTP and filesystem resolution features are not compiled. Phase
4 reuses it to validate requests against hash-verified in-memory schemas. Both
CLIs remain standard-library based except for JSON serialization and existing
core validation libraries.

Planus-generated code contains the generator's low-level unsafe serialization
implementations and is isolated in `d2i-schema`. Handwritten `d2i-core`,
`d2i-compiler`, and `d2i-cli` continue to forbid unsafe code. Planus is not a
runtime network dependency; the separately installed generator is not needed
for normal builds.

## Dependency Rules

Before adding a production dependency, document:

- purpose
- license
- package version
- transitive risk
- offline behavior
- replacement strategy

Dependencies must not introduce default network access, hidden external model
calls, proprietary runtime coupling, or Python requirements in compiler,
runtime, verifier, or hot-path package code.

Phase 6 adds `libloading` 0.8.9. Its small platform-specific dependency surface
is confined to `d2i-ffi`; loading still executes a platform loader and may
resolve transitive native dependencies. Version 0.8.9 is pinned because the
workspace uses Rust 1.86 while libloading 0.9 requires Rust 1.88. All other
Phase 6 dependencies are existing internal workspace or locked crates.

Phase 7 adds no Cargo dependency. `d2i-kernel` reuses locked `serde`,
`serde_json`, and optional `d2i-ffi`. The optional external build tool is Mojo
1.0.0b2 under the Modular Community License, plus the host linker. Neither is
downloaded or invoked by Cargo. Removing `backends/mojo` and the
`mojo-backend` feature leaves the Rust kernel, package format, and runtime
contracts intact.

Phase 8 adds exact `ed25519-dalek` 2.1.1 with only `std` and `zeroize`.
Transitive cryptographic crates include `curve25519-dalek`, `ed25519`,
`signature`, `subtle`, and `zeroize`. No network, PKI, keystore, or operating
system service is invoked. Secret keys are caller-provided bytes and are never
serialized by the learning API or printed by its CLI.

The Phase 8 dataset registry adds no dependency. It reuses locked Serde and
SHA-256 crates and performs local streaming verification only. It does not
include a dataset hub client, downloader, archive extractor, dataframe engine,
tokenizer, or model-training framework.

Phase 9 adds no third-party dependency. The separate `d2i-embodied` product
reuses the locked compiler verifier, Serde, SHA-256, and Ed25519 implementation.
It intentionally has no ROS 2, DDS, hardware SDK, simulation-engine, network,
or async-runtime dependency.

The desktop-autonomy foundation adds no third-party dependency. It reuses
locked Serde, SHA-256, and Ed25519 dependencies plus the internal
`d2i-runtime-api` decision contract. It introduces no OS automation, browser,
network, shell, or async-runtime dependency.

The signed Windows adapter implementation adds exact `windows` 0.62.2 under
MIT OR Apache-2.0 and `uiautomation` 0.25.0 under Apache-2.0. `windows` is the
Microsoft-maintained projection used only by `d2i-windows-host` for Job
Objects, host/session identity, process image and PE version identity, reparse
attributes, atomic moves, and the concrete WFP loopback policy. Unsafe Win32
calls are isolated in that crate. It can be replaced
by an equivalent reviewed `windows-sys` or direct FFI layer without changing
the desktop contracts.

`uiautomation` supplies safe COM wrappers for UI Automation control patterns.
Only its `control`, `input`, and `pattern` features are enabled; the three are
required together by its current feature graph. It can be replaced by direct
`windows` UI Automation projections behind the worker protocol. No general
HTTP client is added: the WebDriver adapter implements a bounded HTTP/1.1
client that resolves and connects only to loopback.
