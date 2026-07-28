# RuleBasedWorkReporter

This reference module converts typed Cognitive IR verification, recovery, and
execution summaries into a deterministic `WorkReport`. It has no model,
network, filesystem, adapter, policy, activation, audit-storage, or side-effect
authority.

Run its contract checks from the repository root:

```text
cargo run -p d2i-cli -- module validate modules/rule-based-work-reporter --json
cargo run -p d2i-cli -- module conformance modules/rule-based-work-reporter --json
```

The module deliberately omits untrusted event summaries from
`completed_actions`. It records only a count in warnings, so embedded
instructions remain data.
