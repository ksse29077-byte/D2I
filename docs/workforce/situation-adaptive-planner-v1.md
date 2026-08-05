# Situation Intelligence and Adaptive Planner v1

## Product Gate

WORK-500 removes the human step of interpreting each selected Case and current
PC state, choosing the next click or input, and manually replanning after every
verified state change. The bounded flow is:

```text
CaseWorkGrantV1
  -> ApprovedCaseContextBundleV1
  -> CaseSituationModelV1
  -> actual IntelligenceProvider
  -> one validated semantic next step
  -> existing Action Selection / Policy / Activation / KRN
  -> fresh re-observation and verification
  -> situation update
  -> replan, clarify, escalate, or verified Case closure
```

Neither a context bundle, Situation Model, provider result, Adaptive Plan, nor
planner ledger record is execution authority.

## Ownership

Platform-neutral contracts live in:

- `crates/d2i-situation-model`
- `crates/d2i-intelligence-provider`
- `crates/d2i-adaptive-planner`

The Windows process boundary, protected planner ledger, model evaluation, and
actual KRN E2E live in `products/d2i-desktop`. The provider crates do not
depend on Desktop adapters.

## Trust And Validation

Situation facts carry a closed source trust class, evidence references,
freshness, confidence in integer millionths or explicit not-applicable state,
and an optional contradiction group. Unknown and conflict records are
first-class. Model-created facts remain `model_inference`.

Provider requests bind exact Case, context, situation, descriptor, model,
runtime, prompt, schema, seed, decoding policy, deadline, resource budget, and
replay hashes. Provider output uses strict duplicate-key and unknown-field
rejection. The planner accepts only exact allowlisted capability IDs, semantic
target IDs, value hashes, preconditions, and postconditions. Raw locators,
coordinates, paths, commands, credentials, tokens, and direct completion are
not representable planning output.

The planner persists validated provider results and cycle records in a
protected append-only hash chain. Restart recovery never blindly repeats an
action; it revalidates Case/lease/ownership/generation and requires a fresh
observation after an uncertain execution window.

## Local Provider

The product gate uses:

- provider kind: `local_model_process`
- model: `Qwen/Qwen3-4B-GGUF`
- revision: `bc640142c66e1fdd12af0bd68f40445458f3869b`
- artifact: `Qwen3-4B-Q4_K_M.gguf`
- model SHA-256:
  `7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5`
- runtime: `ggml-org/llama.cpp` release `b10275`
- runtime executable SHA-256:
  `ea0809388e71270d1f238276ef123216a5a6d3663500185abe05d8cd72daceaf`
- backend: CPU, 4096-token context, 768-token maximum output
- decoding: seed 500, temperature 0, top-k 1
- timeout/retry: 45 seconds, zero retries
- isolation: zero-capability AppContainer plus bounded Windows Job Object

Weights and runtime binaries are not stored in Git. Deployment must provide
the exact artifacts and paths explicitly to the Completion runner.

## Evaluation Evidence

The synthetic holdout contains 60 cases: 20 goal understanding, 20 situation
interpretation, 10 adaptive planning, and 10 adversarial/security cases. At
least 20 use natural-language paraphrases outside the labeled deterministic
grammar. The accepted run produced 60/60 typed success and 100% for goal,
situation, unknown/conflict, next-step, clarification/escalation, and safety
metrics. All critical error counters were zero.

The actual General Office Windows E2E used two states:

- Path A observed an incorrect employee value, selected SetValue, re-observed,
  replanned, selected Save, and verified closure.
- Path B observed the approved value already present, omitted SetValue,
  selected Save, and verified closure.

The run performed three actual action cycles, five fresh observations, and
left zero model, KRN, activation, credential, or profile residuals.

## Official Runner

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/workforce/run-situation-adaptive-planner-v1.ps1 `
  -Mode Completion `
  -Runtime C:\path\to\llama-cli.exe `
  -Model C:\path\to\Qwen3-4B-Q4_K_M.gguf `
  -OutputRoot target\d2i-workforce-planner\completion
```

`All` runs deterministic contract checks only and cannot complete WORK-500.
`Completion` additionally requires exact local artifacts, actual inference,
holdout evaluation, adaptive Windows E2E, WORK-100 through WORK-400 and KRN
regressions, sensitive-artifact scanning, terminal cleanup, and
`product_intelligence_evidence=true` in hash-bearing `finished.json`.
Nested KRN builds share a marker-owned short Cargo target below repository
`target/` so Windows linker paths remain bounded; the runner verifies ownership
and removes that target on both success and failure.

## Limits

There is no long-term episodic memory, online learning, remote provider,
production connector, unrestricted browser navigation, broad shadow mode, or
domain taxonomy in Core. The v1 Windows E2E is limited to the General Office
name-save Application Pack and requires an interactive Windows desktop. Its
fixture rejects stray keyboard input while UIA holds focus; this is test
isolation, not a production input-control capability. WORK-600 is the next task
and is not implemented here.
