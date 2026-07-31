# Deterministic Goal Compiler

The Goal Compiler converts explicit authenticated `ko-KR` instructions into
either a complete Cognitive IR v1 `GoalSpec` or a typed request for
clarification. It uses no model, network, clock, randomness, adapter, or side
effect.

## Result Contract

`GoalCompilationResult v1` is a strict tagged union:

- `compiled` contains only `status` and a complete `goal_spec`.
- `clarification_required` contains only `status`, `missing_fields`,
  `ambiguities`, `questions`, and stable `reason_codes`.

Both are successful Module Contract v1 payloads. Outer `unsupported` is
reserved for unsupported locale, grammar, or capability. Contract/schema,
secret, trust-authority, timeout, resource, and internal errors are outer
failures. Clarification is never encoded into `unsupported_reason`, and the
module never returns an incomplete or low-confidence `GoalSpec`.

## Grammar

One declaration appears per line:

```text
목표: 교육 현황을 조회
범위: 2026년 교육 포털
결과: 수료 상태 목록
제약: 읽기 전용
```

`목표`, `범위`, and `결과` are required. Typed `success_criteria` are supplied
in the structured input; free-text `성공조건` cannot be converted into a
Postcondition and therefore produces clarification. Scope hints may replace a
single `범위` declaration.

Risk is classified conservatively from explicit objective terms. Read-only
operations default to `confirmation_policy: never`. Reversible, business-state,
and high-criticality operations require an explicit `before_risky_action` or
`always` policy. Unknown operations are outside the supported grammar.

`goal_id` is the first 32 hexadecimal characters of the canonical input hash,
prefixed with `goal-`. Source provenance binds the exact instruction, locale,
and source ID. Confidence is not applicable; clarification replaces
low-confidence compilation.

## Compatibility

The module owns its boundary schemas. Its output `$defs/goal_spec` is compared
field-for-field with the Core Cognitive IR v1 schema, and compiled JSON is
round-tripped through `d2i_cognitive_ir::GoalSpec` in tests.

Run its complete standalone gate from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/modules/check-module.ps1 `
  -ModulePath modules/goal-compiler
```

## E2E Host Boundary

`e2e-host` is test/evaluation transport for KRN-500. It reads one bounded
Module Contract v1 invocation from stdin, calls this module's actual
implementation once, writes one canonical result envelope, and exits. It is
not a production loader, Core dependency, package ABI, or execution authority.

## E2E Host Boundary

`e2e-host` is test/evaluation transport for KRN-500. It reads one bounded
Module Contract v1 invocation from stdin, calls this module's actual
implementation once, writes one canonical result envelope, and exits. It is
not a production loader, Core dependency, package ABI, or execution authority.
