# D2I Native ABI v1

## Files

- Rust contract: `crates/d2i-ffi/src/abi.rs`
- Host loader: `crates/d2i-ffi/src/loader.rs`
- C11 header: `crates/d2i-ffi/include/d2i_abi_v1.h`

ABI v1 supports 64-bit hosts. The C fixture uses compile-time size and offset
assertions, while Rust tests assert the matching `repr(C)` layout.

## Entry And Lifecycle

A module exports:

```c
const D2iModuleV1 *d2i_module_v1(void);
```

The returned table and identity bytes must remain valid until the library is
unloaded. The host calls `init` once, zero or more `run`/`reset` calls, and
`destroy` once for a successfully initialized handle. Module functions must
contain all panics or exceptions. A failed `init` must leave its output handle
null. The safe host API requires mutable access for `run` and `reset`, so calls
for one handle are serialized and the module need not be reentrant.

## Buffer Ownership

`D2iBufferView` is an immutable borrowed span. `D2iBufferMut` points to a
host-owned writable allocation. During `run`, a module may write at most
`capacity` bytes and update only `len`. It must not change the pointer,
capacity, alignment, memory kind, flags, or reserved field.

The module must not free, reallocate, retain, or access either buffer after the
call returns. When capacity is insufficient, it returns
`D2I_STATUS_BUFFER_TOO_SMALL`, writes the required size to `len`, and does not
write past capacity.

After shutdown, the host removes the handle before calling `destroy`; later
calls are rejected and repeated shutdown is a no-op. A cooperative
`D2I_TIMEOUT` return leaves the handle owned by the host so normal shutdown or
`Drop` still destroys it once. ABI v1 cannot forcibly cancel a blocked
in-process function.

## Loading

`NativeModulePolicy` requires an allowed root, exact `sha256:<hex>`, and size
limits. `NativeModule::load` verifies the file before invoking the platform
loader, then validates the fixed symbol and descriptor. Input/output limits
are enforced on every call.

The platform may load native dependencies referenced by the primary library.
ABI v1 does not verify that dependency closure, and in-process native code is
not sandboxed. Only trusted build outputs may be placed on the allowlist.

## Optional Adapters

The `arrow-c-data` feature exposes an opaque borrowed Arrow array/schema pair.
The `dlpack` feature exposes an opaque borrowed managed-tensor pointer. Both
validate non-null interface pointers and transfer no ownership. Release,
device synchronization, and asynchronous retention are outside ABI v1.

The Phase 7 `d2i_score_match_masks_v1` extension is a stateless specialized
symbol. It uses two borrowed arrays and performs no allocation or ownership
transfer. Removing the `d2i-kernel` native feature removes the complete host
adapter without changing the generic module ABI.

## Compatibility

The loader requires `abi_version == 1` and
`struct_size >= sizeof(D2iModuleV1)`. New table fields may be appended while
remaining on ABI v1 if existing behavior is unchanged. Layout changes,
ownership changes, or changed function meanings require a new ABI version.
