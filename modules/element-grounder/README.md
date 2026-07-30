# Deterministic Element Grounder

`element-grounder` is the model-free Rust reference implementation of the
`cognitive.element-ground` capability. It ranks only `ObservableElement`
records supplied in a Cognitive IR v1 `ObservationSnapshot`. It cannot observe
a host, resolve UI handles, execute actions, access the network, or produce an
element ID that was absent from the snapshot.

## Contracts

- Input schema: `element-grounding-input-v1`, version 1.
- Output schema: `element-grounding-result-v1`, version 1.
- Maximum returned candidates: 64.
- Candidate score: deterministic ranking score in `0.0..=1.0`, not a
  probability.
- Unique threshold: 0.650.
- Unique top-two margin: 0.150.
- Not-found threshold: 0.350.

The input schema mirrors the Cognitive IR v1 `ObservationSnapshot` and optional
`WorldState` because the v1 SDK schema catalog compiles module schemas without
an external reference resolver. Tests compare the mirrored definitions with
the Core schema. A Core schema change that affects these types must fail the
drift test and be reviewed before a module schema version is released.

## Ranking Policy

Scores use integer thousandths internally and are serialized as decimal
numbers:

| Feature | Points |
| --- | ---: |
| normalized label exact | 700 |
| raw trimmed label exact bonus | 50 |
| target phrase in label | 550 |
| target token overlap | up to 450 |
| expected kind | 200 |
| all required terms | 180 |
| context term coverage | up to 180 |
| safe scalar value clue | 80 |

Scores are clamped at 1000. An excluded term removes the candidate. Secret-like
labels are omitted. Redacted or secret-like values are never used as clues.
Ordering is score descending, match strength descending, expected-kind match
first, then `element_id` lexical order. Input array order therefore cannot
change ranking or output hashes.

`unique_match` requires the score and margin thresholds, all required terms,
an expected kind when one was supplied, and a selected ID present in the
snapshot. Otherwise the module returns `ambiguous`, `not_found`, or
`unsupported` without selecting an element.

## Confidence

The manifest declares `relative_ranking`. Envelope confidence describes
confidence in the returned status, not task-success probability:

- unique: `(top_score + margin) / 2`
- ambiguous: `1 - margin`
- not found: `1 - top_score`
- unsupported: `1`

All operands are integer thousandths before conversion to `f64`.

## Trust Boundary

Labels and values are data regardless of their wording. Trust labels are
preserved on candidates. Untrusted content never grants instruction or action
authority. The module emits only stable rule identifiers and observation or
element IDs as evidence; it never emits raw values. No wall clock, randomness,
model, filesystem, process, UI, browser, or network API is used.

Run its complete standalone gate from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/modules/check-module.ps1 `
  -ModulePath modules/element-grounder
```
