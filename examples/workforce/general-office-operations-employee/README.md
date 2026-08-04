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

All identifiers in this directory are example-owned domain vocabulary. The
generic Radar, Intake, Work Item, and Case crates do not interpret these names.
