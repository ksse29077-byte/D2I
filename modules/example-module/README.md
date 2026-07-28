# Cognitive Module Starter

Copy this directory, rename the package/module/capability IDs, replace
`ExampleInput`, `ExampleOutput`, and `ExampleModule`, then update the schemas,
artifact descriptor hashes, manifest, fixtures, and documentation.

The `Module` trait receives typed input and a bounded invocation context. It
does not receive adapters, policy or activation implementations, audit
storage, filesystem handles, environment variables, or network clients.

Run:

```text
cargo test -p d2i-example-module
cargo run -p d2i-cli -- module validate modules/example-module --json
```

The production CLI intentionally does not dynamically load arbitrary module
artifacts. This starter's conformance suite runs from its Rust tests until a
separate production loader RFC is accepted.
