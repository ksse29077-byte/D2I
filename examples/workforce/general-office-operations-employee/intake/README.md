# General Office Work Intake Fixture

This bounded local feed is the canonical WORK-300 product fixture. A signed
`WorkSourceApprovalV1` binds its exact source registration before the one-shot
fixture adapter may scan it. The event maps exactly to `office.record.update`,
passes existing WORK-200 admission, and creates one persistent Case.

The feed contains only immutable hashes and opaque references. It performs no
network request and grants no Task, process, credential, UI, or action authority.
