# 대시보드 기술명세서 v1

## 1. 기준 문서

- 전체 흐름: `docs/project-flow.md`
- 데이터 계약: `docs/data-contracts-v1.md`
- 기능 요구사항: `docs/dashboard-functional-spec.md`

이 문서는 Streamlit 대시보드와 진단 결과 Excel 초안 구현 방법을 정의한다. 공통 데이터 모델과 enum은 `analysis/models.py`에서 한 번만 정의하고 생산자·소비자가 함께 사용한다.

## 2. 모듈 경계

| 모듈 | 책임 |
| --- | --- |
| `analysis/models.py` | 계약 v1 envelope, Finding, scan·AI 상태와 오류 모델 |
| `analysis/ai_triage.py` | raw 검증, AI 판정과 processed JSON 생성 |
| `dashboard/metrics.py` | 필터된 결과 집계와 조건부 평가 지표 계산 |
| `dashboard/report_builder.py` | Excel 4개 시트와 안전한 cell 값 생성 |
| `dashboard/app.py` | 파일 선택, 검증 결과, 필터, 차트, 상세 보기와 다운로드 |

Streamlit 코드에 데이터 검증, 지표 산식과 Excel 생성 로직을 중복 작성하지 않는다.

## 3. 파일 경로

| 용도 | 경로 |
| --- | --- |
| target manifest 샘플 | `configs/targets.example.json` |
| raw 샘플 | `configs/raw-findings.example.json` |
| processed 샘플 | `configs/triaged-results.example.json` |
| ground-truth 샘플 | `configs/ground-truth.example.json` |
| 실제 raw | `data/raw/<scan_run_id>/findings.json` |
| 실제 processed | `data/processed/<scan_run_id>/results.json` |
| 실제 response HTML | `data/raw/<scan_run_id>/responses/` |

실제 raw·processed·response·Excel 파일은 Git에 등록하지 않는다.

## 4. 로딩과 검증

### 4.1 입력 순서

1. JSON 문법 확인
2. `schema_version == "1.0"` 확인
3. envelope 필드와 run status 확인
4. Finding 필수 필드와 자료형 확인
5. enum과 상태별 null 불변 조건 확인
6. `(scan_run_id, finding_id)` 중복 확인
7. `case_id` 중복 확인
8. response HTML 상대 경로 안전성 확인
9. 검증된 모델을 표 또는 view model로 변환

알 수 없는 버전, enum과 누락 필드를 임의 변환하지 않는다.

### 4.2 run 상태

- `COMPLETED`: 정상 검토·평가·Excel 허용
- `PARTIAL`: 불완전 경고 후 검토·평가·Excel 허용, 실패 건수 명시
- `FAILED`: 오류 표시만 허용하고 지표·Excel 차단

자동 발견과 terminal CTA는 `RunStore.load_reviewable_processed_run(scan_run_id)`의
결합 검증을 통과한 final path만 읽는다. 이 검증은 request·status·processed
envelope의 `scan_run_id`와 `target_set_id`가 모두 같고, status와 envelope의 값이
동일한 `COMPLETED` 또는 `PARTIAL`인지 확인한다. 경로는 정확히
`processed/<scan_run_id>/results.json`이어야 하며 data root 안의 기존 일반 파일이어야
한다. `FAILED`, 잘못된 JSON, 불일치 envelope 및 symlink escape는 자동 검토 후보와
CTA에서 제외한다. 샘플과 사용자가 업로드한 JSON은 명시적 입력이므로 이 자동 발견
결합 조건과 별도로 계속 지원한다.

실행 중 UI의 active source는 run directory 순회가 아니라
`RunStore.active_run_status()`가 확인한 live advisory-lock owner뿐이다. lock 없는
`QUEUED`/`RUNNING` orphan은 설정 화면을 가리지 않으며, orphan과 live owner가
공존하면 owner만 표시한다. rediscovery한 owner ID는 session selection에 보존하여
fragment polling 중 terminal 전환 후에도 terminal summary와 검토 CTA를 유지한다.

### 4.3 Finding 상태

- scan 실패와 AI 실패는 판정 label이 아니다.
- `ai.status=NOT_REQUESTED`의 `status_reason`을 반드시 표시한다.
- `ai.status=FAILED`와 `COMPLETED+INCONCLUSIVE`를 별도 집계한다.
- null을 빈 문자열이나 0으로 변환해 통계에 포함하지 않는다.

## 5. 내부 view model

대시보드에서 표와 필터를 만들 때 nested 계약을 다음 열로 평탄화할 수 있다.

- lineage: `scan_run_id`, `target_set_id`, `case_id`, `finding_id`, `scanned_at`
- 요청: `vuln_type`, `url`, `method`, `input_location`, `parameter`, `payload`
- scan: `scan_status`, `http_status`, `elapsed_ms`, `baseline_elapsed_ms`, `rule_label`, `rule_reason`, `scan_evidence`, `scan_error`
- AI: `ai_status`, `ai_status_reason`, `ai_label`, `confidence`, `needs_human_review`, `assessment_summary`, `source_evidence`, `impact`, `recommendation`, `manual_check`, `report_paragraph`, `ai_error`

평탄화된 DataFrame은 UI 내부 표현이며 저장 계약으로 다시 사용하지 않는다.

## 6. 필터와 집계

모든 필터는 하나의 DataFrame에 순서대로 적용하고 그 결과를 카드, 차트, 목록과 Excel에 전달한다.

`dashboard/metrics.py`는 최소 다음 함수를 제공한다.

```python
def build_summary(df): ...
def build_type_counts(df): ...
def build_ai_verdict_counts(df): ...
def build_rule_ai_comparison(df): ...
def build_evaluation(df, ground_truth): ...
```

### 6.1 요약 규칙

- 전체: 필터된 행 수
- AI 취약: `ai_status == "COMPLETED"`이고 `ai_label == "VULNERABLE"`
- 판정 불가: `ai_status == "COMPLETED"`이고 `ai_label == "INCONCLUSIVE"`
- AI 실패: `ai_status == "FAILED"`
- 수동 검토 필요: `needs_human_review is True`
- 규칙 취약 의심: `scan_status == "COMPLETED"`이고 `rule_label == "SUSPECTED"`

confidence 평균은 핵심 KPI로 제공하지 않는다.

## 7. ground truth와 평가

- ground truth는 processed JSON과 별도로 읽는다.
- `(target_set_id, case_id)`로 결합하고 결합 cardinality와 `vuln_type` 일치를 검증한다.
- 결합 오류가 있어도 일반 결과 검토는 유지하고 평가만 중단한다.
- positive class는 `VULNERABLE`이다.
- 평가 cohort는 binary ground truth, `ai.status=COMPLETED`, binary AI label을 모두 만족한 항목이다.
- `INCONCLUSIVE`, `NOT_REQUESTED`, scan·AI 실패는 confusion matrix에서 제외한다.

다음을 함께 반환한다.

- Accuracy·Precision·Recall
- TP·FP·TN·FN
- `N_labeled`, `N_scored`
- positive·negative support
- scored coverage
- 상태별 제외 건수
- 오탐·미탐 case 목록

Precision·Recall 분모가 0이면 `None`을 반환하고 UI에서 `N/A`로 표시한다.

## 8. Streamlit 구성

- 사이드바: 결과 선택, 테스트용 업로드와 필터
- 헤더: 실행 ID, 대상, 시각, run status와 초안 경고
- 요약: KPI 카드
- 분석: 필수 차트 3개와 조건부 혼동행렬
- 검토: 우선순위 작업목록과 Finding 상세
- 평가: SQLi ground truth가 있을 때만 표시
- 다운로드: 현재 필터 범위의 Excel 초안

HTML response 원문을 `unsafe_allow_html=True`로 렌더링하지 않는다. payload와 증거는 escaped text 또는 code block으로 표시한다.

## 9. Excel 생성

```python
def build_excel_report(df, run_metadata, evaluation=None) -> bytes: ...
```

- 임시 파일 대신 `BytesIO`에 생성한다.
- 시트는 `진단요약`, `상세결과`, `조치권고`, `판정비교`로 고정한다.
- 제목·생성 시각, 헤더 서식, 첫 행 고정, 자동 필터와 열 너비를 적용한다.
- AI 실패·수동 검토 필요 항목을 강조한다.
- 모든 시트에 검토용 초안 문구를 표시한다.

### 9.1 수식 삽입 방어

URL, payload, 증거, 오류와 AI 문장을 비신뢰 문자열로 취급한다. 값이 `=`, `+`, `-`, `@`로 시작하면 literal text로 저장하고 formula cell을 생성하지 않는다. 저장 후 workbook을 다시 열어 formula cell이 없는지 테스트한다.

## 10. 오류 표시

- 검증 오류에는 JSON 경로와 원인을 포함한다.
- 내부 stack trace, API 키와 로컬 절대 경로를 화면에 노출하지 않는다.
- 오류가 있는 파일을 이전 정상 데이터로 조용히 대체하지 않는다.
- 필터 0건은 검증 오류와 구분하고 필터 초기화를 제공한다.
- `PARTIAL` 결과의 Excel에는 실패·제외 건수를 명시한다.

## 11. 테스트 계약

### 모델·로더

- 정상 envelope
- schema version 불일치
- 필수 필드·enum·자료형 오류
- 중복 ID
- 상태별 null 불변 조건 위반
- 위험한 response HTML 경로

### 지표

- 모든 판정 분기
- 0분모 Precision·Recall
- 부분 ground truth
- 제외 상태와 scored coverage
- 결합 누락·중복·vuln type 불일치

### Excel

- 4개 시트 생성
- 필터 범위 반영
- 검토용 초안 문구
- 수동 검토 강조
- 비신뢰 문자열의 formula 차단

### Streamlit 통합

- `COMPLETED`, `PARTIAL`, `FAILED` 상태
- 파일 없음·잘못된 JSON·빈 Finding
- ground truth 유·무
- AI 미요청·실패·판정 불가 표시
