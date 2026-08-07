# D2I Active Product Roadmap

D2I is an Open Autonomous Digital Workforce OS for bounded general office and
computer work. `General Office Operations Employee` is the canonical reference
Role; Finance/HR, IT, and Safety Roles are optional domain-owned packs.

## Current Completed Baseline

작업 시작 기준 commit `866a53926016824f2664dfab4e9bc600fade1cc6`까지 Cognitive IR
v1, deterministic CognitiveExecutor, Module Contract/SDK/Conformance,
Repository Decoupling, Windows trust/activation/WFP/audit, read-only
UIA/Web Observation Plane, Goal Compiler, Application Semantics, Element
Grounder, Action Candidate Provider, Plan Ranker, Cognitive Action Selection
Pipeline이 완료됐다.

`D2I-KRN-100` Cognitive Policy Admission v1도 완료됐다.
`PolicyReadyActionV1`, `PolicyDecisionV1`, confirmation, eligibility,
`CognitiveActivationAdmissionV1` 어느 것도 adapter execution authority를
포함하지 않는다.

## Human Dependency Gate

사람은 Role, delegated authority, 금지사항, KPI, 위험 한도, 보고와
escalation을 설계하고 법적·비가역·고위험·불확실·정책 충돌 예외에
개입한다. 각 Case마다 업무 탐색, prompt, 자료 정리, 실행 판단, 결과
검토, 완료 처리를 사람이 대신하는 의존성은 제거한다.

모든 신규 Core 작업은 제거하는 human touch 또는 여는 E2E gate를
기록해야 한다. 완료는 verified outcome과 audit evidence로 판정하며
애매한 상태를 성공으로 보고하지 않는다.

## Track K - Safe Execution Kernel Closure

- [x] `D2I-KRN-100` Cognitive Policy Admission v1
- [x] `D2I-KRN-200` Trusted Action Execution Binding v1
- [x] `D2I-KRN-300` Reobserve and Cognitive Verifier v2
- [x] `D2I-KRN-400` Recovery, Retry, Replan, Clarification and Escalation
- [x] `D2I-KRN-500` First Complete Verified Single-Task E2E

**Track K complete.**

첫 E2E는 로컬 테스트 폼 이름 필드 변경/저장이다. stale target 거부,
잘못된 element 선택 0, state hash 변화, postcondition, audit evidence,
잔류 process/credential/activation 0이 필수다.

## Track W - Autonomous Workforce Layer

- [x] `D2I-WORK-100` Role Contract v1
- [x] `D2I-WORK-200` Work Item / Case Contract v1
- [x] `D2I-WORK-300` Work Radar and Work Intake
- [x] `D2I-WORK-400` Work Queue, Scheduler and Case Ownership
- [x] `D2I-WORK-500` Situation Model and Adaptive Planner
- [x] `D2I-WORK-600` Episodic Memory and Case Learning Records
- [x] `D2I-WORK-700` Role-level Reporting, SLA and Escalation
- [x] `D2I-WORK-800` Open Digital Employee Shadow Mode
- [x] `D2I-WORK-900` Limited Autonomy and Human-by-Exception Operation

**Track W complete.**

## Track X - Execution Plane Expansion

- [ ] `D2I-EDGE-100` Enterprise API / ERP / MES / CMMS planes - **first active task**
- [ ] `D2I-EDGE-200` Sensor / Camera / IoT observation planes
- [ ] `D2I-EDGE-300` PLC / SCADA / OT supervised execution
- [ ] `D2I-EDGE-400` Robot / AMR / Drone adapters

## KPI

기술 KPI: binding integrity, policy correctness, stale rejection,
deterministic replay, verification accuracy, critical error rate, recovery
success.

사업 KPI: Autonomous Case Completion Rate, Human Touches/Minutes per Case,
Verified Closure Rate, Reopen Rate, Exception Rate, Time to Resolution, Cost
per Completed Case, Cases per Human Supervisor, SLA Compliance, False
Completion Rate, New Workflow Onboarding Cost.

핵심 방향 지표는 한 번의 사람 개입으로 verified closure에 도달하는
Case 수다.

---

# Legacy Compiler Track - Codex 단계별 작업 백로그

아래 Phase 0~9는 구현 역사와 회귀 참조다. Active Track K/W/X보다
우선하지 않으며 이미 구현된 기능을 재생성하지 않는다.

이 문서는 구현 순서를 통제한다.  
각 Phase는 앞 Phase의 종료조건을 충족한 뒤 시작한다.

---

## 공통 완료 절차

각 작업마다:

- [ ] 관련 `AGENTS.md`, 마스터 작업지시서, ADR 읽기
- [ ] 현재 상태 조사
- [ ] 구현 범위 요약
- [ ] 코드 및 문서 변경
- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace --all-features`
- [ ] release build
- [ ] 변경 요약·위험·다음 작업 보고

---

# Phase 0 — Repository and Contract Freeze

## D2I-000 저장소 조사

- [ ] 기존 파일과 코드를 보존한 상태로 tree 출력
- [ ] 기존 Rust/Mojo/C/C++ 코드 위치 파악
- [ ] 독자 런타임의 공개된 계약만 목록화
- [ ] 불명확한 부분을 `docs/open-decisions.md`에 기록

완료조건:

- 코드 수정 없이 조사 결과 문서화
- 추측한 API 없음

## D2I-001 Rust workspace 초기화

- [ ] root `Cargo.toml`
- [ ] `rust-toolchain.toml`
- [ ] `crates/d2i-core`
- [ ] `crates/d2i-cli`
- [ ] 최소 빌드
- [ ] dependency policy 문서

완료조건:

- workspace build/test 성공
- CLI `d2ic --help` 실행

## D2I-002 문서 골격

- [ ] `docs/architecture.md`
- [ ] `docs/package-format.md`
- [ ] `docs/runtime-abi.md`
- [ ] `docs/threat-model.md`
- [ ] `docs/benchmark-methodology.md`
- [ ] `docs/adr/0000-template.md`

## D2I-003 핵심 공통 타입

- [ ] `DomainId`
- [ ] `SkillId`
- [ ] `ExecutorId`
- [ ] `BuildId`
- [ ] semantic version wrapper
- [ ] content hash
- [ ] source span
- [ ] structured diagnostic
- [ ] tests

## D2I-004 예제 source pack 골격

- [ ] `examples/equipment-maintenance/domain.yaml`
- [ ] schema files
- [ ] sample docs
- [ ] sample procedures
- [ ] sample rules
- [ ] sample eval data placeholder

Phase 0 종료조건:

- [ ] workspace checks 통과
- [ ] compiler/runtime boundary 문서화
- [ ] 다음 Phase 구현 없음

---

# Phase 1 — Source Pack Loader and Validator

## D2I-100 manifest schema

- [ ] `domain.yaml` Rust type
- [ ] version validation
- [ ] unknown field 정책
- [ ] good/bad fixtures

## D2I-101 secure source inventory

- [ ] root canonicalization
- [ ] path traversal 거부
- [ ] symlink escape 정책
- [ ] file size limit
- [ ] allowed extension
- [ ] deterministic file ordering

## D2I-102 fingerprint and source lock

- [ ] content hash
- [ ] inventory hash
- [ ] `sources.lock`
- [ ] timestamps가 content hash에 영향을 주지 않는 테스트

## D2I-103 format parsers

MVP 형식:

- [ ] Markdown
- [ ] text
- [ ] CSV
- [ ] JSON
- [ ] JSONL
- [ ] YAML

## D2I-104 schema and reference validation

- [ ] JSON Schema validation
- [ ] duplicate ID
- [ ] broken reference
- [ ] procedure step target
- [ ] rule target
- [ ] fallback requirement
- [ ] diagnostic aggregation

## D2I-105 CLI

- [ ] `d2ic validate`
- [ ] `d2ic inspect`
- [ ] `--json`
- [ ] stable exit codes
- [ ] remediation hints

Phase 1 종료조건:

- [ ] 정상 source pack 통과
- [ ] 악성·오류 fixture 거부
- [ ] inventory hash 재현
- [ ] 외부 네트워크 호출 없음

---

# Phase 2 — Typed IR and Package Format

## D2I-200 Domain IR

- [ ] entities
- [ ] relations
- [ ] terms
- [ ] facts
- [ ] procedures
- [ ] rules
- [ ] examples
- [ ] outcomes
- [ ] provenance

## D2I-201 Skill IR

- [ ] input/output schema refs
- [ ] pre/post conditions
- [ ] criticality
- [ ] fallback
- [ ] evidence requirement
- [ ] evaluation spec

## D2I-202 Execution IR

- [ ] typed node enum
- [ ] edges
- [ ] DAG validation
- [ ] bounded loop representation
- [ ] failure edge
- [ ] parallel group
- [ ] policy gate
- [ ] human review

## D2I-203 Policy IR and Evaluation IR

- [ ] access labels
- [ ] confidence thresholds
- [ ] action permission
- [ ] eval case
- [ ] metric spec
- [ ] critical-error condition

## D2I-204 FlatBuffers package schemas

- [ ] manifest
- [ ] domain
- [ ] skills
- [ ] execution
- [ ] policies
- [ ] evaluation
- [ ] compatibility tests

## D2I-205 package writer/reader

- [ ] deterministic layout
- [ ] hashes
- [ ] provenance
- [ ] evaluation bundle
- [ ] package verifier
- [ ] corruption tests

## D2I-206 CLI

- [ ] `d2ic compile`
- [ ] `d2ic verify`
- [ ] `d2ic diff`
- [ ] build report

Phase 2 종료조건:

- [ ] 동일 입력의 content hash 동일
- [ ] round-trip 성공
- [ ] corruption/version mismatch 검출
- [ ] package format 문서 최신

---

# Phase 3 — Reference Runtime

## D2I-300 runtime API

- [ ] `Runtime`
- [ ] `Executor`
- [ ] `ExecutorRegistry`
- [ ] `TaskContext`
- [ ] `DecisionEnvelope`
- [ ] errors/status

## D2I-301 package loader

- [ ] verify before load
- [ ] target compatibility
- [ ] executor binding
- [ ] index memory map
- [ ] safe failure

## D2I-302 scheduler

- [ ] DAG execution
- [ ] parallel nodes
- [ ] timeout
- [ ] failure branch
- [ ] bounded retry
- [ ] policy gate
- [ ] module timing

## D2I-303 MVP expert modules

- [ ] term normalizer
- [ ] sparse case retriever
- [ ] procedure decider
- [ ] optional template explanation

## D2I-304 evidence and provenance

- [ ] source span
- [ ] module IDs
- [ ] build ID
- [ ] confidence
- [ ] timings
- [ ] warnings

## D2I-305 gold evaluation data

- [ ] 최소 50 cases
- [ ] normal
- [ ] negative
- [ ] ambiguous
- [ ] edge
- [ ] unsupported
- [ ] critical

## D2I-306 runtime CLI

- [ ] package load
- [ ] request JSON input
- [ ] decision envelope output
- [ ] replay mode
- [ ] local-only

Phase 3 종료조건:

- [ ] selective module activation 검증
- [ ] deterministic replay
- [ ] timeout/fallback 검증
- [ ] 모든 결과에 evidence와 timing

---

# Phase 4 — Evaluation and Executor Lowering

## D2I-400 executor descriptor

- [ ] capability
- [ ] I/O schema
- [ ] target
- [ ] ABI
- [ ] resource profile
- [ ] security
- [ ] license
- [ ] artifact hash

## D2I-401 candidate matcher

- [ ] hard constraints
- [ ] compatibility diagnostics
- [ ] fallback behavior

## D2I-402 evaluator

- [ ] task success
- [ ] field metrics
- [ ] critical error
- [ ] latency percentiles
- [ ] peak memory
- [ ] copy metrics
- [ ] repeatability

## D2I-403 Pareto selection

- [ ] feasible set
- [ ] Pareto front
- [ ] configurable cost
- [ ] forced binding
- [ ] selection explanation

## D2I-404 graph optimizer

- [ ] constant folding
- [ ] common preprocessing
- [ ] duplicate lookup removal
- [ ] parallelization
- [ ] cache annotation
- [ ] small-first cascade
- [ ] unnecessary generation removal

## D2I-405 CLI

- [ ] `d2ic eval`
- [ ] `d2ic benchmark`
- [ ] `d2ic explain`

Phase 4 종료조건:

- [ ] 품질 미달 후보 제외
- [ ] target profile에 따라 다른 후보 선택
- [ ] 선택 근거 재현
- [ ] regression build gate

---

# Phase 5 — Existing Proprietary Runtime Adapter

## D2I-500 공개 계약 확인

- [ ] 실제 runtime API 문서 입력
- [ ] 모델 descriptor 매핑
- [ ] lifecycle 매핑
- [ ] error 매핑
- [ ] threading contract
- [ ] memory ownership

## D2I-501 `RuntimeAdapter` trait

- [ ] reference adapter
- [ ] mock existing adapter
- [ ] package capability query
- [ ] execution bridge
- [ ] metrics bridge

## D2I-502 conformance suite

- [ ] common test vectors
- [ ] output schema
- [ ] policy result
- [ ] errors
- [ ] evidence
- [ ] deterministic behavior

## D2I-503 comparison benchmark

- [ ] same package
- [ ] same tasks
- [ ] reference vs proprietary runtime
- [ ] end-to-end and module-level report

Phase 5 종료조건:

- [ ] API 추측 없음
- [ ] conformance 통과
- [ ] 차이 명시
- [ ] benchmark artifact 생성

---

# Phase 6 — Native ABI and Data Exchange

## D2I-600 C ABI v1

- [ ] header
- [ ] Rust bindings
- [ ] ABI version
- [ ] status codes
- [ ] module descriptor
- [ ] lifecycle
- [ ] buffer view
- [ ] allocator contract

## D2I-601 dynamic loading

- [ ] allowlist
- [ ] hash verification
- [ ] symbol validation
- [ ] version rejection
- [ ] panic/exception containment

## D2I-602 ownership and memory tests

- [ ] alignment
- [ ] lifetime
- [ ] double-free
- [ ] use-after-free prevention
- [ ] timeout cleanup
- [ ] concurrent calls

## D2I-603 optional data adapters

- [ ] Arrow C Data adapter
- [ ] DLPack adapter
- [ ] copy metrics
- [ ] fallback byte view

## D2I-604 fuzz and security

- [ ] malformed descriptors
- [ ] invalid pointers simulated where safe
- [ ] oversized dimensions
- [ ] corrupted module
- [ ] resource limit

Phase 6 종료조건:

- [ ] Rust/C-compatible module 교차 실행
- [ ] ABI conformance
- [ ] ownership 문서
- [ ] copy measurement

---

# Phase 7 — Mojo Backend Experiment

## D2I-700 backend RFC

- [ ] target bottleneck
- [ ] Rust baseline
- [ ] expected gain
- [ ] version/toolchain
- [ ] license
- [ ] removal strategy

## D2I-701 one isolated kernel

- [ ] C ABI export/import
- [ ] same input/output
- [ ] deterministic result
- [ ] feature flag

## D2I-702 benchmark

- [ ] Rust baseline
- [ ] Mojo candidate
- [ ] latency
- [ ] memory
- [ ] copy
- [ ] build complexity

Phase 7 종료조건:

- [ ] core builds without Mojo
- [ ] correctness equal
- [ ] gain is reproducible or backend is rejected

---

# Phase 8 — Experience and Learning Compiler

## D2I-800 episode schema

- [ ] situation
- [ ] selected route
- [ ] action
- [ ] output
- [ ] outcome
- [ ] correction
- [ ] policy
- [ ] provenance

## D2I-801 experience store

- [ ] append-only
- [ ] tamper evidence
- [ ] access policy
- [ ] retention
- [ ] export

## D2I-802 candidate builder

- [ ] dataset split
- [ ] leakage control
- [ ] duplicates
- [ ] edge cases
- [ ] poisoning flags

## D2I-803 adaptation levels

- [ ] retrieval weighting
- [ ] rule candidate
- [ ] executor refit adapter
- [ ] routing threshold optimization

## D2I-804 promotion pipeline

- [ ] candidate package
- [ ] offline eval
- [ ] regression
- [ ] critical-error gate
- [ ] signature
- [ ] shadow/canary metadata
- [ ] rollback

Phase 8 종료조건:

- [ ] production in-place mutation 없음
- [ ] candidate/production 분리
- [ ] 모든 승격 감사 가능

---

# Phase 9 — Embodied Intelligence Extension

별도 제품 백로그로 전환:

- [ ] ROS 2 adapter
- [ ] sensor schema
- [ ] action schema
- [ ] deadline classes
- [ ] simulation replay
- [ ] safety controller boundary
- [ ] episodic robot memory
- [ ] hardware abstraction
- [ ] fleet package promotion

D2I 인지 계층과 로봇의 안전·모터 제어 계층을 혼합하지 않는다.
