# D2I Compiler Codex 작업지시서 패키지

이 폴더는 Domain-to-Intelligence Compiler를 Codex로 단계적으로 구현하기 위한 문서 세트다.

## 읽는 순서

1. `D2I_COMPILER_MASTER_WORK_ORDER.md`  
   제품 정의, 전체 구조, IR, 컴파일 패스, 런타임/ABI, 보안, 평가, 로드맵을 담은 기준 문서.

2. `AGENTS.md`  
   저장소 루트에 복사할 Codex 전용 불변 지침. 장문 설계서를 반복해 넣지 않고 구현 규칙과 금지사항을 유지한다.

3. `TASKS.md`  
   Phase별 작업 ID와 종료조건.

4. `CODEX_BOOTSTRAP_PROMPT.md`  
   새 저장소 또는 기존 저장소에서 Phase 0을 시작하는 첫 프롬프트.

5. `CODEX_RUNBOOK.md`  
   Phase 1 이후를 순차 실행하기 위한 복사·붙여넣기 프롬프트.

## 권장 사용법

```text
<repository-root>/
├─ AGENTS.md
├─ D2I_COMPILER_MASTER_WORK_ORDER.md
├─ TASKS.md
├─ CODEX_RUNBOOK.md
└─ ...
```

- `AGENTS.md`는 저장소 루트에 둔다.
- 마스터 작업지시서는 설계 기준 문서로 유지한다.
- Codex에는 한 번에 한 Phase만 지시한다.
- 각 Phase 완료 뒤 Git checkpoint와 코드 리뷰를 수행한다.
- 기존 독자 고효율 런타임이 이미 있다면 이를 재작성하지 않고 `RuntimeAdapter` 경계로 연결한다.
