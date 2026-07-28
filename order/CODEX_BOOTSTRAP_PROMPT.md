# Codex 첫 실행 프롬프트
## D2I Compiler Phase 0 전용

아래 프롬프트를 D2I 저장소 루트에서 Codex에 입력한다.

---

당신은 시스템 소프트웨어·컴파일러·Rust 아키텍처를 담당하는 리드 엔지니어다.

먼저 다음 파일을 순서대로 읽어라.

1. `AGENTS.md`
2. `D2I_COMPILER_MASTER_WORK_ORDER.md`
3. `TASKS.md`
4. 저장소에 이미 존재하는 `README`, `docs`, `Cargo.toml`, Rust/Mojo/C/C++ 코드

이번 작업에서는 **Phase 0만 수행**한다. Phase 1 이후의 기능은 구현하지 마라.

## 목표

기존 코드를 보존하면서 Domain-to-Intelligence Compiler 프로젝트의 저장소 기준선을 만든다.

생성 또는 정리할 항목:

- Rust Cargo workspace
- `d2i-core`
- `d2i-cli`
- 핵심 공통 타입의 최소 골격
- 아키텍처 문서
- ADR template
- 위협모델 문서 골격
- benchmark 방법론 문서 골격
- `equipment-maintenance` 예제 source pack 골격
- 기본 테스트와 품질 검사 명령

## 시작 절차

1. 저장소 전체 구조를 조사한다.
2. 기존 독자 런타임, 라우터, 기능 모델, Mojo/C/C++ 코드가 있는지 찾는다.
3. 존재하는 코드를 삭제하거나 재작성하지 않는다.
4. 확인된 사실과 불명확한 계약을 구분해 `docs/open-decisions.md`에 기록한다.
5. 구현 전에 이번 변경 계획을 10줄 이내로 제시한다.

## 반드시 지킬 경계

- 기존 고효율 런타임 API를 추측하지 마라.
- 기존 아키텍처를 새 Rust runtime으로 대체하지 마라.
- 아직 compiler pass, package writer, FFI, Mojo backend, MLIR, self-learning을 구현하지 마라.
- production runtime에 Python을 추가하지 마라.
- 외부 LLM API 또는 네트워크 의존성을 추가하지 마라.
- 새 DSL을 만들지 마라.
- 불필요하게 많은 crate를 만들지 마라.
- 성능 수치를 주장하지 마라.

## Phase 0 구현 세부사항

### 1. Workspace

필요 시 다음을 만든다.

```text
Cargo.toml
rust-toolchain.toml
crates/d2i-core/
crates/d2i-cli/
docs/
docs/adr/
examples/equipment-maintenance/
```

Rust toolchain은 현재 환경에서 검증된 stable 버전을 고정하되, 버전을 임의로 추측하지 말고 설치된 toolchain을 확인한 뒤 선택 근거를 기록한다.

### 2. `d2i-core`

최소 타입만 구현한다.

- `DomainId`
- `SkillId`
- `ExecutorId`
- `BuildId`
- `ContentHash`
- `SourceLocation`
- `Diagnostic`
- `Severity`

요구사항:

- typed newtype
- parse/display
- invalid input test
- serde가 필요하면 dependency 목적을 설명
- 구조화된 diagnostic에 code, message, location, help 포함
- 아직 Domain IR 전체를 구현하지 않음

### 3. `d2i-cli`

- 실행 파일 이름 `d2ic`
- `--help`
- `version`
- 아직 `validate`/`compile`을 실제 구현하지 않음
- 향후 command 구조를 추가하기 쉬운 형태
- core logic을 CLI crate에 넣지 않음

### 4. 문서

최소 다음 문서를 작성한다.

- `docs/architecture.md`
  - compiler/runtime/existing runtime adapter 경계
  - compile-time vs runtime
  - source pack → IR → package → runtime 흐름
- `docs/package-format.md`
  - “미정” 항목을 명확히 표시
- `docs/runtime-abi.md`
  - C ABI를 후보로 두되 아직 확정하지 않음
- `docs/threat-model.md`
  - 악성 입력, path traversal, package tampering, plugin, data leakage
- `docs/benchmark-methodology.md`
  - 동등 업무·동등 품질 비교 원칙
- `docs/adr/0000-template.md`
- `docs/open-decisions.md`

### 5. 예제 source pack 골격

```text
examples/equipment-maintenance/
├─ domain.yaml
├─ README.md
├─ schemas/
├─ data/documents/
├─ data/tables/
├─ procedures/
├─ rules/
├─ examples/
├─ eval/
├─ models/
└─ security/
```

아직 실제 compiler가 읽는다고 가장하지 말고 “Phase 1 계약 후보”임을 README에 표시한다.

### 6. 품질

가능한 범위에서 다음을 실행한다.

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --workspace --release
```

환경에 없어 실행하지 못한 도구가 있다면 숨기지 말고 정확한 오류를 보고한다.

## 출력 보고 형식

작업 후 다음 형식으로 보고한다.

1. 조사 결과
2. Phase 0 완료 범위
3. 생성·변경 파일
4. 핵심 설계 선택
5. 실행한 명령과 결과
6. 추가한 테스트
7. 기존 아키텍처와의 접점
8. 미결정 사항
9. 보안·성능 위험
10. 다음 작업으로 권장하는 `D2I-100`, 단 아직 시작하지 않음

작업 중 문서와 코드가 충돌하면 `AGENTS.md`와 마스터 작업지시서를 우선하고, 충돌 내용을 보고하라.
