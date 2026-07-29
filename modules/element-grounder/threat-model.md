# Element Grounder Threat Model

## Assets

- Correct binding to the current observation and plan generation.
- Candidate IDs that refer only to the supplied snapshot.
- Deterministic ranking and terminal status.
- Confidentiality of redacted and secret-like values.
- Separation between observed text and executable authority.

## Threats And Controls

| Threat | Control |
| --- | --- |
| Stale observation or plan | Exact payload, caller-context, and optional WorldState binding checks; fail closed. |
| Prompt injection in labels or values | Text is ranked only as data and cannot create capabilities or actions. |
| Wrong selection under ambiguity | Fixed score and margin thresholds; non-unique statuses never contain a selected ID. |
| Invented element ID | Result validation checks every candidate and selection against snapshot IDs. |
| Secret disclosure | Raw values are never emitted; redacted and secret-like values are excluded from scoring; secret-like labels are omitted. |
| Resource exhaustion | Bounded bytes, elements, hints, candidates, JSON depth, JSON nodes, operations, and logical time. |
| Replay drift | Stable normalization, integer scoring, total ordering, canonical SDK hashes, and no clock or randomness. |
| Hidden side effects | Manifest denies network, filesystem, environment, privilege, persistence, and side effects. |

## Residual Risk

The v1 observation contract has no visibility, geometry, DOM-path, or
AutomationId fields. Distinctions absent from `kind`, `label`, scalar `value`,
and trust labels cannot be inferred safely and remain ambiguous or not found.
