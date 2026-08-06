# General Office Operations Employee Memory Fixture

This fixture is a new version 1.1.0 Role source used only by WORK-600. It grants no
new execution capability. It changes the memory boundary to
approved_summary_only and permits quarantined learning candidates so signed,
redacted Episode summaries and offline export can be tested.

The canonical version 1.0.0 Role remains hash_reference_only with learning disabled.
Its approval, delegation, and Role Instance are never reused by this fixture.
The WORK-600 runner compiles both versions independently and binds this
fixture's exact contract hash to a new signed approval, subset delegation, and
active Role Instance before creating the memory namespace.
