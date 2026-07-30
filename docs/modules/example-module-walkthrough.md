# Example Module Walkthrough

Run `scripts/modules/new-module.ps1 -ModuleId <module-id>`, then:

1. Rename the Cargo package, module ID, build ID, and capability ID.
2. Replace `ExampleInput` and `ExampleOutput` with strict typed contracts.
3. Implement pure validation and invocation logic.
4. Keep untrusted content as data with `UntrustedContentGuard`.
5. Update input/output JSON Schema and compute their SHA-256 values.
6. Update the reference artifact descriptor and hash.
7. Complete every manifest security, evaluation, provenance, and license field.
8. Add valid, invalid, unsupported, replay, and security fixtures.
9. Run `scripts/modules/check-module.ps1 -ModulePath modules/<module-id>`.

The starter normalizes whitespace and records whether the input was untrusted.
It does not act on text, call a model, access the network, or execute a side
effect.

`RuleBasedWorkReporter` is the complete example. It consumes existing Cognitive
IR types and emits `WorkReport`, while omitting untrusted event text from
confirmed actions.
