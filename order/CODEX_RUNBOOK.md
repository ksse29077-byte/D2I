# Codex Active Roadmap Runbook

## Current Product Direction

D2I is an Open Autonomous Digital Workforce OS that compiles Domain, Role,
Authority, Application Semantics, Organizational Memory, Work Sources, and
execution means into bounded digital employees for general office and computer
work. `General Office Operations Employee` is the canonical reference Role;
domain-specific Roles remain optional packs.

Safe Execution Kernel은
단일 작업을 안전하게 완료하는 하위 계층이고, Workforce Layer는 Role
Instance가 Work Radar와 Case Queue를 통해 업무를 찾아 verified closure까지
소유하게 한다. 운영 원칙은 Human-by-exception이다.

## Track K - Safe Execution Kernel Closure

- `D2I-KRN-100` Cognitive Policy Admission v1 - **complete**
- `D2I-KRN-200` Trusted Action Execution Binding v1 - **complete**
- `D2I-KRN-300` Reobserve and Cognitive Verifier v2 - **complete**
- `D2I-KRN-400` Recovery, Retry, Replan, Clarification and Escalation - **complete**
- `D2I-KRN-500` First Complete Verified Single-Task E2E - **complete**

Track K is complete. Do not create KRN-600.

첫 E2E는 로컬 테스트 폼의 이름 필드 변경과 저장이다. stale target
거부, 정확한 element, state hash 변화, postcondition, audit evidence,
잔류 상태 0을 증명한다.

## Track W - Autonomous Workforce Layer

- `D2I-WORK-100` Role Contract v1 - **complete**
- `D2I-WORK-200` Work Item / Case Contract v1 - **complete**
- `D2I-WORK-300` Work Radar and Work Intake - **complete**
- `D2I-WORK-400` Work Queue, Scheduler and Case Ownership - **complete**
- `D2I-WORK-500` Situation Model and Adaptive Planner - **complete**
- `D2I-WORK-600` Episodic Memory and Case Learning Records - **complete**
- `D2I-WORK-700` Role-level Reporting, SLA and Escalation - **complete**
- `D2I-WORK-800` Open Digital Employee Shadow Mode - **complete**
- `D2I-WORK-900` Limited Autonomy and Human-by-Exception Operation - **active**

WORK-700's completed official gate is:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/workforce/run-role-reporting-sla-escalation-v1.ps1 `
  -Mode Completion `
  -Runtime C:\path\to\llama-cli.exe `
  -Model C:\path\to\Qwen3-4B-Q4_K_M.gguf `
  -OutputRoot target\d2i-workforce-operations\completion
```

`All` is deterministic and model-free. `Completion` reruns WORK-600 with the
approved local runtime/model, then proves five General Office Cases, protected
operations persistence/audit, internal-only publication, escalation
acknowledgement/resolution, 128 Case x 100 replay, and terminal cleanup. It is
complete only when `finished.json` has `role_operations_evidence=true`.
WORK-800 Completion is resumable only through canonical, exact-bound safe
checkpoints. Use `-Resume`; use `-Fresh` to discard all WORK-800 checkpoints;
and use `-ReuseVerifiedPredecessorEvidence` only for sealed WORK-700 evidence.
The next active task is
`D2I-WORK-900 - Limited Autonomy and Human-by-Exception Operation`.

## Track X - Execution Plane Expansion

- `D2I-EDGE-100` Enterprise API / ERP / MES / CMMS planes
- `D2I-EDGE-200` Sensor / Camera / IoT observation planes
- `D2I-EDGE-300` PLC / SCADA / OT supervised execution
- `D2I-EDGE-400` Robot / AMR / Drone adapters

## Solo Direct-to-Main

각 active task는 독립 worktree에서 범위 검사와 전체 검사를 마친 뒤
commit한다. 최신 `origin/main`에 rebase하고 검사를 다시 실행한 다음
force 없이 `git push origin HEAD:main`한다. PR, 승인 대기, 웹 병합은
완료조건이 아니다. 의미 충돌이 있으면 push를 중단한다.

`D2I-KRN-400` completes deterministic bounded recovery over KRN-100 through
KRN-300 evidence. It persists budget and replay state before mutation and
requires a wholly fresh trust chain for retry. The next prompt is
`D2I-KRN-500` now assembles the first complete verified single-task E2E.
WORK-100 defines immutable approved Role Contracts, persistent bounded Role
Instances, and one-time role-bound Kernel admission. WORK-200 defines
immutable admitted Work Items, deterministic deduplication, persistent
accountable Cases, exact role-bound KRN attempts, typed evidence evaluation,
and verified terminal disposition. WORK-300 adds exact source registration,
signed `WorkSourceApprovalV1`, typed hash-only signals, deterministic Intake,
General Office Case creation, cross-domain replay, protected
receipts/checkpoints, and exactly-one Case crash recovery. The next prompt is
WORK-400 adds deterministic Queue projection, one-shot scheduling, exclusive
lease chains, signed-pool reassignment, protected recovery, and a
non-executable planner handoff without changing WORK-300 source authority.

Official WORK-200 checks:

```powershell
cargo test -p d2i-work-case --all-features
cargo test -p d2i-desktop --test work_item_case

powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/workforce/run-work-item-case-v1.ps1 `
  -Mode All
```

Official WORK-300 checks:

```powershell
cargo test -p d2i-work-intake --all-features
cargo test -p d2i-desktop --test work_radar_intake

powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/workforce/run-work-radar-intake-v1.ps1 `
  -Mode All
```

Official WORK-400 checks:

```powershell
cargo test -p d2i-work-queue --all-features
cargo test -p d2i-desktop --test work_queue_scheduler

powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/workforce/run-work-queue-scheduler-v1.ps1 `
  -Mode All
```

Official WORK-500 checks require approved local artifacts:

```powershell
cargo test -p d2i-situation-model --all-features
cargo test -p d2i-intelligence-provider --all-features
cargo test -p d2i-adaptive-planner --all-features
cargo test -p d2i-desktop --test adaptive_case

powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/workforce/run-situation-adaptive-planner-v1.ps1 `
  -Mode Completion `
  -Runtime C:\path\to\llama-cli.exe `
  -Model C:\path\to\Qwen3-4B-Q4_K_M.gguf `
  -OutputRoot target\d2i-workforce-planner\completion
```

`All` is deterministic contract evidence only. WORK-500 completion requires
`Completion` with `product_intelligence_evidence=true`.

Inspection-only CLI examples:

```powershell
cargo run -p d2i-work-case --bin d2i-case -- work-item validate --input work-item.json
cargo run -p d2i-work-case --bin d2i-case -- case inspect --case case-instance.json
cargo run -p d2i-work-case --bin d2i-case -- terminal verify --input terminal-record.json
cargo run -p d2i-work-queue --bin d2i-queue -- snapshot verify --input snapshot.json
cargo run -p d2i-work-queue --bin d2i-queue -- decision verify --input decision.json
```

---

# Legacy Compiler Track Runbook
## 이미 구현된 기능을 재생성하지 않기 위한 참조

아래 Phase 1~8 프롬프트는 역사적 Compiler 구현 기록이다. 현재 active
roadmap보다 우선하지 않는다.

원칙:

- 매 프롬프트는 새 Phase를 시작할 때 사용한다.
- 앞 Phase 종료조건이 충족되지 않았다면 다음 프롬프트를 실행하지 않는다.
- Codex가 한 번에 전체 프로젝트를 구현하지 않도록 Phase 범위를 강제한다.
- 각 실행 전 Git checkpoint를 만든다.
- 세부 작업 ID는 `TASKS.md`를 따른다.

---

# Phase 1 프롬프트 — Source Pack Loader and Validator

```text
AGENTS.md, D2I_COMPILER_MASTER_WORK_ORDER.md, TASKS.md와 현재 docs/ADR을 읽어라.
Phase 1(D2I-100~D2I-105)만 수행하라.

목표:
- domain.yaml 계약
- 안전한 source inventory
- 콘텐츠 fingerprint와 source lock
- Markdown/text/CSV/JSON/JSONL/YAML 파서
- schema/reference validation
- d2ic validate / inspect

요구:
1. 기존 Phase 0 코드를 먼저 설명하고 보존하라.
2. path traversal, symlink escape, file-size limit, deterministic ordering을 테스트하라.
3. diagnostic을 누적하고 파일·라인·필드·help를 출력하라.
4. --json 출력과 stable exit code를 제공하라.
5. 네트워크를 사용하지 마라.
6. Domain IR, package writer, runtime은 아직 구현하지 마라.
7. 정상·오류·악성 fixture를 추가하라.
8. 같은 입력 inventory의 hash가 재현되는 테스트를 추가하라.
9. fmt/clippy/test/release build를 실행하라.
10. Phase 1 종료조건을 체크리스트로 보고하고 Phase 2는 시작하지 마라.
```

---

# Phase 2 프롬프트 — Typed IR and Deterministic Package

```text
AGENTS.md, 마스터 작업지시서, TASKS.md, Phase 1 문서와 테스트를 읽어라.
Phase 2(D2I-200~D2I-206)만 수행하라.

목표:
- typed Domain/Skill/Execution/Policy/Evaluation IR
- DAG validation
- provenance 연결
- versioned FlatBuffers package metadata
- deterministic package writer/reader
- d2ic compile / verify / diff

요구:
1. 새 DSL을 만들지 마라. YAML/JSON 소스를 typed Rust IR로 변환하라.
2. 모든 IR 요소에 source/provenance를 연결할 수 있게 하라.
3. Execution IR에는 branch, parallel, validate, policy gate, human review, bounded loop를 표현하라.
4. package format version, runtime ABI version, compiler version을 분리하라.
5. 패키지 경로를 검증하고 corruption/version mismatch/hash mismatch를 거부하라.
6. 동일 콘텐츠·다른 파일 수정시간·다른 traversal order에서 동일 content hash를 검증하라.
7. 아직 실제 모델 inference, FFI, Mojo, self-learning을 구현하지 마라.
8. package-format.md와 ADR을 갱신하라.
9. fmt/clippy/test/release build를 실행하라.
10. Phase 2 종료조건을 보고하고 Phase 3은 시작하지 마라.
```

---

# Phase 3 프롬프트 — Reference Runtime

```text
AGENTS.md, 마스터 작업지시서, TASKS.md, package format과 runtime ABI 문서를 읽어라.
Phase 3(D2I-300~D2I-306)만 수행하라.

목표:
- package loader
- Runtime / Executor / Registry 계약
- TaskContext / DecisionEnvelope
- DAG scheduler
- equipment-maintenance 데모 모듈 3개
- gold evaluation 50건 이상

모듈:
- term-normalizer
- sparse case-retriever
- procedure-decider
- 선택적 template explanation

요구:
1. reference runtime은 정확성 기준선이며 독자 고효율 runtime을 대체하지 않는다.
2. 필요한 모듈만 호출되는지 테스트하라.
3. timeout, failure edge, fallback, policy gate를 테스트하라.
4. 모든 결과에 build ID, modules, evidence, confidence, timings, policy 결과가 있어야 한다.
5. 생성형 모델과 외부 API 없이 데모를 완성하라.
6. deterministic replay를 제공하라.
7. 아직 executor 자동 선택, C ABI, Mojo, self-learning은 구현하지 마라.
8. fmt/clippy/test/release build를 실행하라.
9. Phase 3 종료조건을 보고하고 Phase 4는 시작하지 마라.
```

---

# Phase 4 프롬프트 — Evaluation and Executor Lowering

```text
AGENTS.md, 마스터 작업지시서, TASKS.md, benchmark methodology를 읽어라.
Phase 4(D2I-400~D2I-405)만 수행하라.

목표:
- ExecutorDescriptor/Registry
- hard constraint matching
- quality/safety evaluation
- Pareto front
- target profile 기반 최소 비용 선택
- execution graph optimization
- d2ic eval / benchmark / explain

요구:
1. 정확도·치명 오류 기준은 hard constraint로 처리하라.
2. 품질 통과 후보만 비용 비교하라.
3. 단순 가중합 결과뿐 아니라 Pareto 후보를 build report에 남겨라.
4. forced binding과 fallback을 지원하라.
5. constant folding, duplicate lookup removal, parallelization, cache annotation, small-first cascade를 구현하라.
6. 동일 업무·동등 품질 벤치마크 원칙을 지켜라.
7. p50/p95/p99, cold/warm, RSS, allocation, copy metrics를 가능한 범위에서 수집하라.
8. 어떤 1,000배 성능 주장도 추가하지 마라.
9. fmt/clippy/test/release build를 실행하라.
10. Phase 4 종료조건을 보고하고 Phase 5는 시작하지 마라.
```

---

# Phase 5 프롬프트 — Existing Runtime Adapter

```text
AGENTS.md, 마스터 작업지시서, TASKS.md와 실제로 제공된 독자 런타임 API 문서를 읽어라.
Phase 5(D2I-500~D2I-503)만 수행하라.

중요:
실제 API가 저장소나 문서에 없다면 가짜 API를 발명하지 마라.
그 경우 RuntimeAdapter trait, mock adapter, conformance test 골격까지만 구현하고
필요한 계약을 docs/open-decisions.md에 정확히 기록하라.

목표:
- RuntimeAdapter trait
- reference adapter
- proprietary adapter boundary
- common conformance vectors
- error/schema/metrics mapping
- reference vs proprietary benchmark report

요구:
1. 기존 proprietary runtime 코드를 보존하라.
2. package format이 특정 runtime 구현에 종속되지 않게 하라.
3. 동일 package와 동일 test vector를 사용하라.
4. 결과 차이를 숨기지 마라.
5. fmt/clippy/test/release build를 실행하라.
6. Phase 5 종료조건을 보고하고 Phase 6은 시작하지 마라.
```

---

# Phase 6 프롬프트 — Native ABI and Data Exchange

```text
AGENTS.md, 마스터 작업지시서, TASKS.md, runtime-abi.md와 관련 ADR을 읽어라.
Phase 6(D2I-600~D2I-604)만 수행하라.

목표:
- versioned C-compatible D2I ABI v1
- dynamic expert loading
- D2iBufferView
- ownership contract
- optional Arrow/DLPack adapters
- ABI/fuzz/security tests

요구:
1. #[repr(C)], fixed-width types, explicit version을 사용하라.
2. host-owned allocation을 기본으로 하라.
3. Rust panic/foreign exception이 ABI를 넘지 않게 하라.
4. symbol/hash/version을 검증한 뒤 로드하라.
5. unsafe를 d2i-ffi와 승인된 low-level 모듈에 한정하고 SAFETY 주석을 작성하라.
6. hot path에 JSON을 사용하지 마라.
7. Arrow/DLPack은 optional adapter로 구현하라.
8. copy count와 bytes를 측정하라.
9. fmt/clippy/test/release build와 ABI/fuzz tests를 실행하라.
10. Phase 6 종료조건을 보고하고 Phase 7은 시작하지 마라.
```

---

# Phase 7 프롬프트 — Mojo Backend Experiment

```text
AGENTS.md, 마스터 작업지시서, TASKS.md를 읽어라.
Phase 7(D2I-700~D2I-702)만 수행하라.

먼저 실제 benchmark에서 확인된 병목 하나를 선택하고 ADR/RFC를 작성하라.
Rust 기준 구현이 없는 경우 Mojo 구현을 시작하지 마라.

목표:
- optional Mojo feature
- C ABI 뒤의 isolated kernel 하나
- Rust baseline과 동일 결과
- 반복 가능한 benchmark
- 제거 가능한 backend 구조

요구:
1. Mojo 미설치 환경에서도 core workspace가 빌드되어야 한다.
2. package format과 Rust kernel을 Mojo에 종속시키지 마라.
3. 같은 데이터, 같은 결과, 같은 hardware에서 비교하라.
4. 빌드 복잡성도 비용으로 기록하라.
5. 성능 이득이 없으면 채택하지 말고 결과를 문서화하라.
6. Phase 7 종료조건을 보고하고 Phase 8은 시작하지 마라.
```

---

# Phase 8 프롬프트 — Controlled Learning Compiler

```text
AGENTS.md, 마스터 작업지시서, TASKS.md, threat model을 읽어라.
Phase 8(D2I-800~D2I-804)만 수행하라.

목표:
- episode/outcome/correction schema
- append-only experience store
- candidate dataset builder
- retrieval/rule/expert/routing adaptation adapters
- candidate package
- offline evaluation and promotion gate
- rollback metadata

금지:
- production package in-place mutation
- 평가 없는 weight update
- 운영 데이터 전체를 자동 정답으로 사용
- 안전·정책 규칙의 자동 삭제
- online arbitrary code generation

요구:
1. production과 candidate를 물리·논리적으로 분리하라.
2. poisoning, leakage, duplicates, distribution shift를 검사하라.
3. 이전 gold set 회귀를 필수로 하라.
4. critical error 증가 시 승격을 거부하라.
5. 모든 승격에 build ID, dataset hash, evaluator, approval, signature를 기록하라.
6. Phase 8 종료조건을 보고하고 로봇 통합은 별도 RFC로 남겨라.
```

---

# 리뷰 전용 프롬프트

```text
현재 변경사항을 수정하지 말고 리뷰만 수행하라.
AGENTS.md의 Code Review Rules를 기준으로 다음을 우선 확인하라.

- compile/runtime 경계 훼손
- default network access
- package verification 우회
- reproducibility 위반
- provenance 누락
- FFI ownership/ABI 문제
- unsafe 확산
- hot-path JSON 또는 불필요한 copy
- 모델 backend와 package format 결합
- high-criticality policy gate 누락
- benchmark 없는 성능 주장
- 테스트 약화
- production self-modification

발견사항을 critical/high/medium/low로 정렬하고,
각 항목에 파일·라인·영향·재현·안전한 수정방향을 제시하라.
```
