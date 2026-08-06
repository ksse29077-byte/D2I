# General Office Operations Employee

This is the canonical cross-product reference Role for D2I Workforce examples.
Its WORK-300 fixture maps one approved `internal-record-updated` source event to
the opaque `office.record.update` work class and stops after persistent Case
creation. The referenced `kernel-e2e-name-save` Application Pack is not executed
by Work Radar or Work Intake.

WORK-400 uses four distinct approved events to create urgent, elevated,
normal, and routine persistent Cases. The protected Queue selects exactly one,
recovers its exclusive lease after restart, and reassigns a suspended owner to
an exact approved standby Role. It produces only a non-executable Work Grant.

WORK-500 consumes an exact Work Grant and approved hash-only Case context. Its
actual local provider interprets the fresh name-save state and chooses one
semantic action at a time. An incorrect value follows SetValue then Save; an
already-correct value skips SetValue and follows Save. Both paths cross the
existing Safe Execution Kernel and require independent verified closure.

WORK-600 seals both terminal paths as reference-only Episodes. This canonical
`1.0.0` Role remains `hash_reference_only` with learning candidates disabled;
the separately compiled `general-office-operations-employee-memory-v1`
fixture alone tests signed summaries and quarantined offline candidates.

WORK-700 uses a third separately compiled `1.2.0` fixture in
`general-office-operations-employee-operations-v1`. It adds report obligations
and KPI declarations only; it reuses the same read-only capability and
authority ceiling. New approval, delegation, and Role Instance artifacts are
required for that version.

All identifiers in this directory are example-owned domain vocabulary. The
generic Radar, Intake, Work Item, and Case crates do not interpret these names.
