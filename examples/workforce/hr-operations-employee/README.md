# HR Operations Employee Compatibility Fixture

`hr.employee.record.review` is an opaque Role Pack-owned work class used to
prove WORK-400 cross-domain compatibility. It follows the same Queue,
Scheduler, lease, and ownership contracts as the General Office reference.
No HR taxonomy or branch exists in Core, and this fixture performs no action.

WORK-800 additionally uses this opaque Role/work-class pair as a signed,
model-backed Shadow trace. The generic comparison, adjudication, metric, and
readiness engine receives only typed IDs and hashes; no HR branch is added.
