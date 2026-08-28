# AI-Triage Shield 데이터 계약 v1

## 1. 목적과 효력

이 문서는 환경 구축팀, XSS·SQLi 담당, OpenAI·데이터 처리 담당, 대시보드·Excel 담당 사이의 데이터 전달 규격을 정의한다.

- RawRun은 `1.0`을 유지한다. ProcessedRun은 기존 reader용 `1.0`과 근거 기반 writer용 `1.1`을 지원한다.
- JSON이 기준 형식이며 CSV와 Excel은 파생 export다.
- 생산자와 소비자는 같은 필드명, 자료형, enum과 null 규칙을 사용한다.
- 계약 변경 시 문서와 샘플을 같은 커밋에서 수정하고 버전을 올린다.
- 실제 진단 결과, 응답 HTML, 인증정보와 보고서는 Git에 등록하지 않는다.

### 1.1 기존 `SCHEMA.md` 초안 반영

`origin/feature/dashboard-ai-report`의 `SCHEMA.md`에 정의된 자동화팀 → AI 백엔드 → 대시보드 필드는 v1 계약에 다음과 같이 반영한다.

| 기존 필드 | v1 위치 | 반영 방식 |
| --- | --- | --- |
| `finding_id` | `finding_id` | 원본 ID 그대로 보존 |
| `vuln_type` | `vuln_type` | `XSS`, `SQLI` enum으로 고정 |
| `url` | `scan.request.url` | 원본 요청 정보로 보존 |
| `parameter` | `scan.request.parameter` | 원본 요청 정보로 보존 |
| `payload` | `scan.request.payload` | 원본 요청 정보로 보존 |
| `rule_label` | `scan.rule.label` | `SUSPECTED`, `SAFE`, `null`로 고정 |
| `response_body` | `scan.response.html_path`, `scan.response.evidence_summary` | 전체 본문은 sidecar 파일로 저장하고 JSON에는 안전한 상대 경로와 요약만 기록 |
| `ai_label` | `ai.label` | AI 완료 시에만 기록 |
| `confidence` | `ai.confidence` | 문자열 대신 `0.0`~`1.0` 숫자로 고정 |
| `evidence_summary` | `ai.assessment_summary` | raw 증거 요약과 이름이 충돌하지 않게 분리 |
| `recommendation` | `ai.recommendation` | AI 생성 권고로 반영 |

기존 초안의 핵심 필드는 삭제하지 않고 namespace와 상태 정보를 추가하여 확장한다. 다음 두 부분은 안전성과 실행 추적을 위해 변경한다.

- `CSV 또는 JSON 리스트` 대신 실행 metadata와 null·상태를 보존할 수 있는 envelope JSON을 canonical 형식으로 사용한다. CSV가 필요하면 adapter 또는 export로 생성한다.
- `response_body` 전체를 JSON이나 AI 요청에 그대로 넣지 않는다. 원문은 run별 sidecar로 저장하고, AI에는 민감정보 제거와 길이 제한을 거친 근거만 전달한다.

## 2. 공통 규칙

### 2.1 식별자

| 식별자 | 범위 | 용도 |
| --- | --- | --- |
| `target_set_id` | 대상 명세 버전 | 어떤 실습 환경 명세를 사용했는지 구분 |
| `case_id` | 실행 간 안정적 | 대상·파라미터·테스트 케이스와 ground truth 결합 |
| `scan_run_id` | 실행 1회 | 서로 다른 스캔 실행 구분 |
| `finding_id` | 실행 안에서 유일 | raw와 AI 결과의 lineage 결합 |

- raw와 AI 결과는 `(scan_run_id, finding_id)`로 결합한다.
- ground truth는 `(target_set_id, case_id)`로 결합한다.
- 중복, 누락과 다대다 결합은 오류로 처리한다.
- `case_id`와 `finding_id`는 AI가 생성하거나 수정하지 않는다.

### 2.2 시간

- 모든 시각은 timezone offset을 포함한 ISO 8601 문자열을 사용한다.
- 예: `2026-08-27T09:30:00+09:00`
- 응답 시간은 정수 millisecond로 기록한다.

### 2.3 null과 오류

- 값이 없으면 빈 문자열, `0`, `N/A` 대신 JSON `null`을 사용한다.
- 처리 상태와 취약점 판정은 별도 필드로 관리한다.
- 실패를 `SAFE`, `INCONCLUSIVE` 또는 confidence `0.0`으로 대체하지 않는다.
- 오류는 다음 구조를 사용한다.

```json
{
  "code": "AI_TIMEOUT",
  "message": "AI 판정 요청 시간이 초과되었습니다.",
  "retryable": true
}
```

### 2.4 판정 enum

| 영역 | 허용값 |
| --- | --- |
| `vuln_type` | `XSS`, `SQLI` |
| run status | `COMPLETED`, `PARTIAL`, `FAILED` |
| scan status | `COMPLETED`, `FAILED` |
| rule label | `SUSPECTED`, `SAFE`, `null` |
| AI status | `NOT_REQUESTED`, `COMPLETED`, `FAILED` |
| AI label | `VULNERABLE`, `SAFE`, `INCONCLUSIVE`, `null` |
| ground-truth label | `VULNERABLE`, `SAFE` |

화면에서만 다음과 같이 변환한다.

| 저장값 | 화면 표시 |
| --- | --- |
| `VULNERABLE` | 취약 |
| `SAFE` | 양호 |
| `INCONCLUSIVE` | 판정 불가 |
| `SUSPECTED` | 취약 의심 |
| `NOT_REQUESTED` | AI 미요청 |
| `FAILED` | 처리 실패 |

## 3. Contract A: target manifest

### 3.1 생산자와 소비자

- 생산자: 환경 구축팀
- 소비자: XSS·SQLi 스캐너
- Git 샘플: `configs/targets.example.json`

### 3.2 최상위 필드

| 필드 | 자료형 | 필수 | 규칙 |
| --- | --- | --- | --- |
| `schema_version` | string | 예 | `1.0` |
| `target_set_id` | string | 예 | Git에서 버전 관리하는 안정적 ID |
| `base_url` | string | 예 | 허가된 `http` 또는 `https` origin |
| `request_policy` | object | 예 | 공통 timeout·redirect 정책 |
| `targets` | array | 예 | 1건 이상, `case_id` 중복 금지 |

### 3.3 target 필드

| 필드 | 자료형 | 필수 | 규칙 |
| --- | --- | --- | --- |
| `case_id` | string | 예 | 실행 간 변경하지 않는 케이스 ID |
| `vuln_type` | string | 예 | `XSS`, `SQLI` |
| `path` | string | 예 | `/`로 시작하는 상대 경로 |
| `method` | string | 예 | `GET`, `POST` |
| `input.location` | string | 예 | `query`, `form`, `json` |
| `input.parameters` | object | 예 | 비밀값이 아닌 정상 기준값 |
| `input.attack_parameter` | string | 예 | `parameters`에 존재해야 함 |
| `requires_pre_auth` | boolean | 예 | 사전 로그인 필요 여부 |
| `auth_profile` | string/null | 예 | 비밀값이 아닌 프로필 ID만 기록 |
| `payload_profile` | string | 예 | 버전이 고정된 payload 목록 ID |
| `manual_verification_profile` | string | 예 | 수동 확인 절차 ID |

### 3.4 불변 조건

- `requires_pre_auth=false`이면 `auth_profile=null`이어야 한다.
- `requires_pre_auth=true`이면 `auth_profile`이 있어야 한다.
- manifest에는 비밀번호, 쿠키, API 키와 취약·안전 정답값을 넣지 않는다.
- 취약·안전 정답은 별도 ground truth로 유지한다.

## 4. Contract B: raw findings

### 4.1 생산자와 소비자

- 생산자: XSS·SQLi 스캐너
- 소비자: OpenAI·데이터 처리 담당
- Git 샘플: `configs/raw-findings.example.json`
- 실제 경로: `data/raw/<scan_run_id>/findings.json`

### 4.2 최상위 envelope

| 필드 | 자료형 | 필수 | 규칙 |
| --- | --- | --- | --- |
| `schema_version` | string | 예 | `1.0` |
| `scan_run_id` | string | 예 | 실행별 유일 ID |
| `target_set_id` | string | 예 | target manifest와 일치 |
| `started_at` | string | 예 | ISO 8601 |
| `completed_at` | string/null | 예 | 미완료 시 `null` |
| `status` | string | 예 | run status enum |
| `findings` | array | 예 | 모든 시도 결과 보존 |

### 4.3 RawFinding

```json
{
  "case_id": "xss-reflected-a",
  "finding_id": "XSS-001",
  "scanned_at": "2026-08-27T09:30:10+09:00",
  "vuln_type": "XSS",
  "scan": {
    "status": "COMPLETED",
    "request": {
      "url": "http://127.0.0.1:5000/case/xss-a",
      "method": "GET",
      "input_location": "query",
      "parameter": "name",
      "payload": "<script>alert(1)</script>"
    },
    "response": {
      "http_status": 200,
      "elapsed_ms": 182,
      "baseline_elapsed_ms": 175,
      "evidence_summary": "입력값이 인코딩 없이 응답에 반사되었습니다.",
      "html_path": "responses/XSS-001.html"
    },
    "rule": {
      "label": "SUSPECTED",
      "reason": "페이로드가 실행 가능한 HTML 영역에 반사되었습니다."
    },
    "error": null
  }
}
```

### 4.4 상태별 불변 조건

#### `scan.status=COMPLETED`

- `scan.error=null`
- request 필드는 모두 필수다.
- `response.http_status`, `elapsed_ms`, `evidence_summary`가 있어야 한다.
- `scan.rule.label`은 `SUSPECTED` 또는 `SAFE`다.
- SQLi는 `baseline_elapsed_ms`가 필수고 XSS는 `null`을 허용한다.

#### `scan.status=FAILED`

- `scan.error`가 필수다.
- `scan.rule.label`과 `reason`은 `null`이다.
- 수집하지 못한 response 필드는 `null`이다.
- 실패 Finding도 삭제하지 않는다.

### 4.5 응답 HTML 경로

- `html_path`는 해당 run 디렉터리 기준 상대 경로다.
- 절대 경로, `..`와 run 디렉터리 밖의 경로를 거부한다.
- HTML 원문은 Git에 등록하지 않는다.

## 5. Contract C: processed results

### 5.1 생산자와 소비자

- 생산자: OpenAI·데이터 처리 담당
- 소비자: 대시보드·Excel 담당
- Git 샘플: `configs/triaged-results.example.json`
- 실제 경로: `data/processed/<scan_run_id>/results.json`

### 5.2 최상위 envelope

raw envelope의 식별·시각·상태 필드를 유지한다. `findings`는 raw의 모든 Finding을 1:1 보존한다.

```json
{
  "schema_version": "1.1",
  "scan_run_id": "run-20260827-01",
  "target_set_id": "local-lab-v1",
  "started_at": "2026-08-27T09:30:00+09:00",
  "completed_at": "2026-08-27T09:31:00+09:00",
  "status": "PARTIAL",
  "findings": []
}
```

### 5.3 ProcessedFinding

- `case_id`, `finding_id`, `scanned_at`, `vuln_type`을 raw에서 복사한다.
- `scan` 객체를 손실 없이 복사한다.
- `ai` 객체만 추가한다.

```json
{
  "ai": {
    "status": "COMPLETED",
    "status_reason": null,
    "label": "VULNERABLE",
    "confidence": 0.98,
    "needs_human_review": false,
    "assessment_summary": "스크립트가 실행 가능한 영역에 인코딩 없이 포함되었습니다.",
    "source_evidence": "응답 HTML에서 원본 script 태그를 확인했습니다.",
    "impact": "사용자 브라우저에서 임의 스크립트가 실행될 수 있습니다.",
    "recommendation": "출력 컨텍스트에 맞는 인코딩과 CSP를 적용합니다.",
    "manual_check": "격리된 브라우저에서 실제 실행 여부를 확인합니다.",
    "report_paragraph": "해당 입력 지점에서 반사형 XSS 취약 가능성이 확인되었습니다.",
    "error": null
  }
}
```

### 5.4 AI 상태별 불변 조건

#### `ai.status=COMPLETED`

- `status_reason=null`, `error=null`
- `label`, `confidence`, `needs_human_review`와 생성 문장이 필수다.
- confidence는 `0.0` 이상 `1.0` 이하다.
- `label=INCONCLUSIVE`이면 `needs_human_review=true`다.

#### `ai.status=NOT_REQUESTED`

- `status_reason`은 `RULE_NOT_SUSPECTED`, `SCAN_FAILED`, `POLICY_EXCLUDED` 중 하나다.
- label, confidence와 모든 생성 문장은 `null`이다.
- scan 실패라면 `needs_human_review=true`, 규칙상 미선택이면 false를 허용한다.
- `error=null`

#### `ai.status=FAILED`

- `status_reason=null`
- label, confidence와 모든 생성 문장은 `null`이다.
- `needs_human_review=true`
- `error`가 필수다.

### 5.4.1 ProcessedRun 1.1 근거 기반 AI 결과

`schema_version=1.1`의 모든 Finding은
`ai.role=EVIDENCE_GROUNDED_REPORTING`이어야 한다. 이 role의 AI는 최종
승인자가 아니라 2차 보조 분류기다. `GROUNDED` 결과는 `VULNERABLE`, `SAFE`,
`INCONCLUSIVE`와 `0.0..1.0` confidence를 생성할 수 있지만
`needs_human_review=true`를 유지한다. ground truth는 AI 입력, 모델 출력,
ProcessedRun에 포함하지 않는다.

`claims`는 `claim_id`, `claim_type`, `text`, `evidence_ids`, `reference_ids`로
구성한다. `claim_id`는 Finding 안에서 유일하고 비어 있지 않으며,
`claim_type`은 `OBSERVATION`, `IMPACT`, `RECOMMENDATION`, `MANUAL_CHECK` 중
하나다. `GROUNDED` 결과에는 네 종류가 각각 하나 이상 필요하다.
`evidence_ids`는 `E` 뒤에 양의 정수를 붙인 형식이고, 모든
`reference_ids`는 같은 Finding의 `references.reference_id`를 가리켜야 한다.

`references`의 `reference_id`는 Finding 안에서 유일하다. official reference
metadata는 애플리케이션이 생성하며 모델 출력의 값을 신뢰하지 않는다.
각 reference에는 `source_id`, `publisher`, `title`, `version`, `section`,
`canonical_url`, `file_id`, 64자 소문자 SHA-256 `document_sha256`가 필요하다.
`canonical_url`은 자격증명·query·fragment가 없는 HTTPS OWASP 또는 KISA
allowlist 도메인 URL이어야 한다.

`provenance`는 `model`, `prompt_version`, `knowledge_base_version`,
`output_schema_version="1.1"`, `retrieval_policy_version`,
`vector_store_ids`, `retrieved_file_ids`, timezone이 있는 `generated_at`을
기록한다.

| AI 상태와 grounding 상태 | 필수 불변 조건 |
| --- | --- |
| `COMPLETED` + `GROUNDED` | `label=VULNERABLE/SAFE/INCONCLUSIVE`, confidence 필수, human review 필수, `status_reason/error=null`, 모든 생성 문장 nonblank, claims와 references가 각각 하나 이상, provenance 필수 |
| `COMPLETED` + `INSUFFICIENT` | `status_reason=POLICY_EXCLUDED`, `assessment_summary`만 nonblank, `impact/recommendation/manual_check/report_paragraph=null`, references 비어 있음, provenance 필수 |
| `NOT_REQUESTED` + `NOT_APPLICABLE` | 기존 NOT_REQUESTED 규칙을 따르고 claims, references, provenance가 없음 |
| `FAILED` + `NOT_APPLICABLE` | 생성 문장, claims, references가 없고 안전한 `error`가 필수; provenance는 허용 |

`schema_version=1.0` Finding은 `ai.role=null`이어야 하며 기존 1.0 상태
불변 조건을 그대로 적용한다. 1.0과 1.1 AI 결과를 하나의 ProcessedRun에
섞을 수 없다.

### 5.5 run status

| 상태 | 규칙 |
| --- | --- |
| `COMPLETED` | 모든 Finding이 terminal 상태이고 scan·AI 실패가 없음 |
| `PARTIAL` | 유효한 결과가 있으나 하나 이상의 scan 또는 AI 실패가 있음 |
| `FAILED` | 실행 수준 오류로 정상적인 결과 집합을 만들지 못함 |

대시보드는 `COMPLETED`와 `PARTIAL`을 열 수 있으나 `PARTIAL`에는 불완전 경고를 표시한다. `FAILED`는 오류 정보만 표시하고 통계·Excel 생성을 막는다.

### 5.6 AI 입력 보안

- AI 요청은 raw Finding에서 명시적으로 허용한 필드만 직렬화한다.
- 응답 HTML은 필요한 근거만 추출하고 쿠키, 인증 헤더와 개인정보를 제거한다.
- 입력 길이를 제한하고 대상 응답을 신뢰할 수 없는 데이터로 구획한다.
- ground truth를 AI 입력과 processed 생성 단계에 전달하지 않는다.

## 6. Contract D: SQLi ground truth

### 6.1 생산자와 소비자

- 생산자: SQLi 담당
- 소비자: 대시보드 metrics 모듈
- Git 샘플: `configs/ground-truth.example.json`
- 실제 정답표는 Git에 등록하지 않는다.

### 6.2 구조

```json
{
  "schema_version": "1.0",
  "assessment_set_id": "sqli-burp-v1",
  "target_set_id": "local-lab-v1",
  "assessor_tool": "Burp Suite",
  "created_at": "2026-08-27T10:00:00+09:00",
  "cases": [
    {
      "case_id": "sqli-search-a",
      "vuln_type": "SQLI",
      "label": "VULNERABLE",
      "evidence_summary": "참·거짓 조건에 따라 응답 결과가 달라졌습니다.",
      "assessed_at": "2026-08-27T09:55:00+09:00"
    }
  ]
}
```

### 6.3 결합과 평가

- `(target_set_id, case_id)`로 processed 결과와 결합한다.
- `vuln_type`이 일치하지 않으면 오류다.
- XSS ground truth는 담당과 산출물이 정해질 때까지 지원하지 않는다.
- ground truth가 없으면 평가 영역을 숨긴다.

AI 조건부 지표의 대상은 다음 조건을 모두 만족한 항목이다.

- ground-truth label이 binary다.
- `ai.status=COMPLETED`다.
- AI label이 `VULNERABLE` 또는 `SAFE`다.

`INCONCLUSIVE`, `NOT_REQUESTED`, scan·AI 실패는 TP·FP·TN·FN에서 제외하고 제외 건수를 표시한다.

지표와 함께 다음 값을 표시한다.

- `N_labeled`
- `N_scored`
- 취약·양호 support
- `scored_coverage = N_scored / N_labeled`

Precision 또는 Recall 분모가 0이면 `N/A`로 표시한다.

## 7. 대시보드 소비 규칙

- loader는 전체 envelope와 Finding을 먼저 검증한 뒤 화면을 구성한다.
- 알 수 없는 schema version과 enum은 자동 변환하지 않고 오류로 처리한다.
- 중복 ID, 필수 필드 누락과 상태 불변 조건 위반 시 통계와 Excel 생성을 막는다.
- 집계는 검증된 데이터에서 deterministic하게 계산하며 LLM으로 계산하지 않는다.
- confidence 평균은 핵심 성능 지표로 사용하지 않는다.
- 필터가 적용되면 카드, 차트, 목록과 Excel에 동일한 범위를 사용한다.
- AI 결과와 Excel은 담당자 검토용 초안임을 명시한다.

## 8. 변경 절차

1. 변경 제안에 영향받는 생산자와 소비자를 명시한다.
2. 문서, 샘플 JSON과 공통 모델을 같은 변경에서 수정한다.
3. 필수 필드 삭제·이름 변경·enum 변경은 schema version을 올린다.
4. 생산자·소비자 계약 테스트가 모두 통과한 뒤 병합한다.
5. 런타임에서 구버전 fallback이나 임의 변환을 추가하지 않는다.
