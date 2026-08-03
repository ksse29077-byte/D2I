# AI Safety Work Intake Fixture

This bounded local feed is an optional domain-specific cross-domain fixture for
the AI Safety Operations Employee Role. It demonstrates that the same generic
WORK-300 contracts accept Role-owned safety vocabulary without Core taxonomy.
It performs no API call and is not the canonical product E2E.

The approved source is `safety-records`, the only event class is
`safety-record-updated`, and the exact mapping targets
`safety.training.compliance_followup` through `safety-records-read`,
`safety-operations-shadow`, `enterprise_api.read`, and `safety-record`.

All source content is represented by immutable hashes or opaque references.
The fixture contains no raw document, credential, command, locator, network
authority, Task, activation, or adapter invocation.
