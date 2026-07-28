# Runtime ABI

## Status

Phase 6 defines native ABI v1 in `d2i-ffi` and publishes
`crates/d2i-ffi/include/d2i_abi_v1.h`. Packages use
`runtime_abi_version = "1.0.0"`. This is a compatibility break from Phase 5
development packages.

## Boundary

The reference runtime is implemented in Rust. Optional native executors in
Mojo, C, or C++ must eventually cross a versioned C-compatible ABI. The package
format must not depend on any specific backend language.

## ABI v1 Contract

- The module exports `d2i_module_v1`, which returns an immutable
  `D2iModuleV1` function table.
- The table declares ABI version, struct size, bounded UTF-8 identity, and
  `init`, `run`, `reset`, and `destroy` functions.
- Input is a borrowed immutable `D2iBufferView`. Output is a host-owned
  `D2iBufferMut`; a module may change only its bytes and logical length.
- A module must not retain, free, replace, or resize host buffers.
- The host owns the opaque handle and calls `destroy` at most once after a
  successful `init`.
- Panics and foreign exceptions must be contained by the module and never cross
  the ABI.
- The run boundary carries bytes, not JSON objects or backend-specific types.

## Loading Policy

Before native code executes, the loader rejects symlinks, root escapes,
non-regular or oversized files, SHA-256 mismatches, missing symbols, unsupported
ABI versions, truncated tables, invalid metadata, and null functions. Native
code is in-process and is therefore limited to trusted, explicitly
hash-allowlisted modules.

`AbiCopyMetrics` records borrowed input/output views, host output allocations,
and copies attributable to the ABI boundary. ABI v1 performs no boundary copy;
module-internal copies are outside this metric.

## Optional Views

The `arrow-c-data` and `dlpack` crate features expose validated opaque borrowed
views. ABI v1 does not call release functions, assume ownership, or define
device synchronization. See `native-abi-v1.md` for the complete host/module
contract.

## Phase 7 Isolated Kernel

The optional `d2i_score_match_masks_v1` symbol is a stateless C ABI extension,
not a new package/runtime ABI. It accepts borrowed `uint8_t` match masks and
host-owned `uint16_t` scores. Bits 0, 1, and 2 contribute 45, 45, and 10 points;
all other bits are invalid.

The `score-kernel` feature in `d2i-ffi` loads this fixed symbol only after the
normal path, size, and SHA-256 checks. The `mojo-backend` feature in
`d2i-kernel` enables that loader but does not invoke or require the Mojo
compiler.
