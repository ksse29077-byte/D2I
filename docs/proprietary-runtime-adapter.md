# Proprietary Runtime Adapter Integration

## Current Status

`ProprietaryRuntimeAdapterPlaceholder` is intentionally nonfunctional. It
checks package compatibility, then returns `AdapterUnavailable`. Replace TODOs
only from reviewed runtime documentation or source code.

## Required Inputs

The runtime integration owner must provide:

1. Package load/unload API and handle ownership.
2. Request invocation and response retrieval signatures.
3. Error code table with retryability and severity.
4. Cancellation, timeout, and thread-safety guarantees.
5. Supported package format and D2I runtime ABI versions.
6. Supported executor kinds, targets, memory limits, and network behavior.
7. Evidence, confidence, policy, timing, and module identity mapping.

## Integration Steps

1. Construct an `AdapterContract` from documented capabilities.
2. Run `d2ic adapter-check PACKAGE_DIR --json`.
3. Implement `RuntimeAdapter::load_package` using the real package API.
4. Implement `RuntimeAdapter::execute` and map every response field into a
   `DecisionEnvelope`.
5. Map every external error to one `RuntimeErrorCode`; preserve external codes
   only as bounded diagnostics.
6. Run `d2ic adapter-conformance PACKAGE_DIR --iterations N --json`.
7. Review every vector mismatch and output-schema failure.
8. Record controlled-host performance separately; do not use mock results as a
   proprietary-runtime benchmark.

## Acceptance

- All bundled evaluation vectors have identical timing-independent decisions.
- Both outputs validate against the same bundled output schema.
- Invalid request and unsupported skill map to identical stable error
  categories.
- Compatibility and conformance reports are retained with build ID and adapter
  identity.

The Phase 6 native ABI remains a separate executor boundary in `d2i-ffi`.
Connecting the proprietary runtime to that ABI still requires its reviewed
package, request, error, cancellation, and threading contracts; the generic
native loader does not fill in those undocumented details.
