# AI-Triage Shield 실행 계약 v1

## 1. 목적과 적용 범위

이 문서는 Streamlit 대시보드 또는 CLI가 허가된 XSS·SQL Injection 진단을 요청하고, `main.py`가 스캐너와 OpenAI 처리 파이프라인을 실행하여 결과를 게시하기 위한 실행 규격을 정의한다.

- 계약 버전은 `1.0`이다.
- 팀 간 데이터 필드 규격은 `docs/data-contracts-v1.md`를 따른다.
- 이 문서는 실행 요청, 상태, 단계, 진행률, 결과 경로, 오류와 중복 실행 방지 규칙을 정의한다.
- 스캐너 내부 탐지 알고리즘과 OpenAI 프롬프트 구현은 각 담당자의 책임이다.
- 계약 변경 시 실행 계약 문서, 샘플, 공통 모델과 관련 테스트를 같은 변경에서 수정한다.

## 2. 역할과 책임

| 담당 | 책임 | 금지 사항 |
| --- | --- | --- |
| 대시보드 | 허가된 대상·진단 유형 선택, 실행 요청, 상태·결과 표시 | 임의 URL 실행, 스캐너 로직 직접 구현 |
| `main.py` | 실행 ID·lock·상태 관리, 스캐너·AI 단계 호출, 결과 게시 | 취약점별 탐지 로직 중복 구현 |
| XSS 스캐너 | XSS 요청·증거 수집·1차 규칙 판정 | OpenAI 호출, 대시보드 상태 직접 수정 |
| SQLi 스캐너 | SQLi 요청·증거 수집·1차 규칙 판정 | OpenAI 호출, 대시보드 상태 직접 수정 |
| OpenAI·데이터 처리 | raw 검증, 후보 AI 판정, processed JSON 생성 | ground truth 입력 사용 |

`main.py`만 실행 상태 파일을 갱신한다. 스캐너와 AI 모듈이 같은 상태 파일을 직접 수정하면 안 된다.

## 3. MVP 실행 구조

```text
Streamlit 또는 CLI
        │ 실행 요청
        ▼
main.py
├── target manifest 검증
├── scan_run_id 생성·run lock 획득
├── XSS 스캐너 호출
├── SQLi 스캐너 호출
├── canonical raw JSON 게시
├── OpenAI 2차 판정 호출
├── canonical processed JSON 게시
└── terminal 상태 기록·lock 해제
        │
        ▼
data/processed/<scan_run_id>/results.json
```

MVP에서는 스캐너와 OpenAI 처리를 `main.py`가 순서대로 실행한다. 병렬 실행, 원격 worker와 queue는 후속 범위다.

## 4. 허가된 실행 입력

### 4.1 target manifest와 deployment descriptor

실행 대상은 `docs/data-contracts-v1.md` Contract A를 통과한 manifest만 허용한다.

- Git의 `configs/target-registry.json`은 `target_set_id`와 진단 케이스 manifest를 관리한다.
- 실제 구축환경 주소는 환경구축팀이 비공개로 전달한 Deployment Descriptor JSON으로 등록한다.
- 대시보드는 descriptor schema와 `/health` identity를 검증한 뒤 Git에서 제외된
  `configs/deployments.local.json`에 원자적으로 저장한다.
- MVP의 `base_url`은 DNS rebinding을 차단하기 위해 public 또는 loopback literal IP
  origin만 허용한다. hostname, link-local, metadata, reserved 주소는 거부한다.
- `ACTIVE` 또는 `TEMPORARY` deployment만 선택할 수 있다.
- 실행 시 `deployment_id`로 등록 정보를 다시 해석하고 trusted manifest의
  `base_url`만 검증된 deployment origin으로 교체한다.
- 실행 화면에서 임의 URL, IP 또는 인증정보를 직접 입력할 수 없게 한다.
- 실제 인증정보는 manifest가 아닌 서버 측 `auth_profile` 저장소에서 읽는다.

### 4.2 실행 요청

```json
{
  "schema_version": "1.0",
  "target_set_id": "novastream-2",
  "deployment_id": "novastream-aws-mysql-v1",
  "vuln_types": ["XSS", "SQLI"]
}
```

| 필드 | 자료형 | 필수 | 규칙 |
| --- | --- | --- | --- |
| `schema_version` | string | 예 | `1.0` |
| `target_set_id` | string | 예 | 등록된 manifest ID와 정확히 일치 |
| `deployment_id` | string | 예 | 검증·등록된 deployment ID와 정확히 일치 |
| `vuln_types` | string array | 예 | `XSS`, `SQLI` 중 하나 이상, 중복 금지 |

MVP에서는 payload 직접 입력, 임의 URL, 동시 실행 수와 AI 모델을 실행 요청으로 받지 않는다.

### 4.3 실행 전 사전점검

대시보드는 실행 버튼을 활성화하기 전에 선택 deployment로 해석한 manifest를 대상으로 읽기 전용 사전점검을 수행한다. 이 점검은 스캐너를 호출하거나 공격 payload를 전송하지 않는다.

- descriptor 등록 시 `/health`가 `target_set_id`, `service`, `database_engine`,
  `deployment_version`과 일치하는지 검증한다.
- 실행 preflight는 해석된 manifest의 `base_url`에만 `/health`를 붙여 GET 요청하고,
  1초 이하 timeout, redirect 금지, 인증정보 미전송으로 HTTP `200`만 준비 상태로 판단한다.
- 선택한 모든 진단 유형이 manifest에 존재하고, 해당 scanner의 `scan` callable 및 `analysis.ai_triage.triage` callable이 있어야 한다.
- 전역 pipeline lock이 비활성이며 data root에 쓸 수 있어야 한다.
- fingerprint는 `deployment_id`, `deployment_version`, 선택 유형을 포함한다. 입력이 바뀌면
  이전 preflight는 stale이다.
- 하나라도 차단되면 실행 버튼을 비활성화하고 launch 직전에 deployment를 다시 해석해 점검한다.

## 5. Python 실행 인터페이스

대시보드와 CLI는 같은 blocking orchestration core를 사용한다.

```python
def run_pipeline(
    target_set_id: str,
    deployment_id: str,
    vuln_types: list[str],
) -> RunStatusDocument:
    """terminal 상태까지 실행하고 최종 상태를 반환한다."""
```

대시보드는 별도 launcher를 통해 core를 백그라운드 프로세스로 시작한다.

```python
def start_run(
    target_set_id: str,
    deployment_id: str,
    vuln_types: list[str],
) -> str:
    """실행을 시작하고 새 scan_run_id를 반환한다."""
```

장시간 실행은 Streamlit 요청 thread에서 직접 수행하지 않는다. `start_run`은 `run_pipeline`을 백그라운드 프로세스로 시작하고 즉시 `scan_run_id`를 반환해야 한다.

상태 조회는 파일 기반으로 수행한다.

```python
def get_run_status(scan_run_id: str) -> RunStatusDocument:
    """검증된 실행 상태를 반환한다."""
```

CLI는 `run_pipeline`을 foreground에서 호출하고 terminal 상태까지 기다린다. MVP에서는 취소·재시도 함수를 제공하지 않는다. 실패한 실행은 새로운 `scan_run_id`로 다시 시작한다.

## 6. CLI 계약

```bash
python main.py run \
  --target-set-id novastream-2 \
  --deployment-id novastream-aws-mysql-v1 \
  --types XSS SQLI
```

### 표준 출력

실행 요청이 승인되면 표준 출력에 `scan_run_id`를 한 줄로 먼저 출력하고, CLI는 terminal 상태까지 기다린 뒤 최종 종료 코드를 반환한다.

```text
run-20260827-111500-a1b2c3
```

상세 진행 상황과 민감하지 않은 오류는 상태 파일에 기록한다. API 키, 쿠키, 인증 헤더, payload 전체와 응답 HTML을 콘솔에 출력하지 않는다.

### 종료 코드

| 코드 | 의미 |
| --- | --- |
| `0` | `COMPLETED` |
| `2` | `PARTIAL` |
| `3` | 다른 실행이 진행 중이어서 거부 |
| `4` | target manifest 또는 실행 요청이 잘못됨 |
| `5` | 실행 수준 오류로 `FAILED` |

## 7. scan_run_id 규칙

형식:

```text
run-<YYYYMMDD>-<HHMMSS>-<6자리 소문자 hex>
```

예:

```text
run-20260827-111500-a1b2c3
```

- 시간은 실행 호스트의 timezone offset이 반영된 현재 시각을 사용한다.
- 같은 초의 충돌을 막기 위해 난수 suffix를 포함한다.
- 실행 디렉터리가 이미 존재하면 새 ID를 생성한다.
- 사용자가 임의 ID를 지정할 수 없다.

## 8. 실행 디렉터리

```text
data/
├── runs/
│   └── <scan_run_id>/
│       ├── request.json
│       └── status.json
├── raw/
│   └── <scan_run_id>/
│       ├── findings.json
│       └── responses/
└── processed/
    └── <scan_run_id>/
        └── results.json
```

실제 request, status, raw, response와 processed 파일은 Git에 등록하지 않는다.

모든 문서 안의 파일 경로는 프로젝트 data root 기준 상대 경로를 사용한다. 절대 경로와 `..`를 거부한다.

## 9. 실행 상태 문서

경로:

```text
data/runs/<scan_run_id>/status.json
```

예시:

```json
{
  "schema_version": "1.0",
  "scan_run_id": "run-20260827-111500-a1b2c3",
  "target_set_id": "novastream-2",
  "deployment_id": "novastream-aws-mysql-v1",
  "requested_vuln_types": ["XSS", "SQLI"],
  "status": "RUNNING",
  "stage": "SCANNING_XSS",
  "progress": {
    "completed": 3,
    "total": 10
  },
  "started_at": "2026-08-27T11:15:00+09:00",
  "updated_at": "2026-08-27T11:15:08+09:00",
  "completed_at": null,
  "raw_result_path": null,
  "processed_result_path": null,
  "error": null
}
```

### 9.1 필드

| 필드 | 자료형 | 필수 | 규칙 |
| --- | --- | --- | --- |
| `schema_version` | string | 예 | `1.0` |
| `scan_run_id` | string | 예 | 실행 디렉터리 ID와 일치 |
| `target_set_id` | string | 예 | 실행 요청과 일치 |
| `deployment_id` | string | 예 | 실행 요청과 일치하며 실행 중 변경 불가 |
| `requested_vuln_types` | string array | 예 | 요청한 유형만 포함 |
| `status` | string | 예 | 실행 상태 enum |
| `stage` | string/null | 예 | terminal 이전 현재 단계 |
| `progress.completed` | integer | 예 | 0 이상 |
| `progress.total` | integer | 예 | 0 이상, 확정 전에는 0 허용 |
| `started_at` | string | 예 | timezone offset 포함 ISO 8601 |
| `updated_at` | string | 예 | 마지막 원자적 갱신 시각 |
| `completed_at` | string/null | 예 | terminal 상태에서 필수 |
| `raw_result_path` | string/null | 예 | raw 게시 뒤 상대 경로 |
| `processed_result_path` | string/null | 예 | processed 게시 뒤 상대 경로 |
| `error` | object/null | 예 | 실행 수준 실패 정보 |

`progress.total > 0`이면 `completed <= total`이어야 한다.

## 10. 실행 상태와 단계

### 10.1 상태 enum

| 상태 | 의미 |
| --- | --- |
| `QUEUED` | 실행 요청과 디렉터리를 만들었으나 작업 시작 전 |
| `RUNNING` | 하나 이상의 실행 단계 진행 중 |
| `COMPLETED` | 모든 요청 단계 완료, scan·AI 항목 실패 없음 |
| `PARTIAL` | 결과는 게시됐지만 하나 이상의 scan·AI 항목 실패 존재 |
| `FAILED` | 정상적인 processed 결과 집합을 게시하지 못함 |

### 10.2 단계 enum

| 단계 | 담당 |
| --- | --- |
| `VALIDATING_TARGET` | `main.py` |
| `SCANNING_XSS` | XSS 스캐너 |
| `SCANNING_SQLI` | SQLi 스캐너 |
| `PUBLISHING_RAW` | `main.py` |
| `AI_TRIAGE` | OpenAI·데이터 처리 |
| `PUBLISHING_RESULT` | `main.py` |

terminal 상태에서는 `stage=null`로 기록한다.

### 10.3 허용 상태 전이

```text
QUEUED
→ RUNNING / VALIDATING_TARGET
→ RUNNING / SCANNING_XSS 또는 SCANNING_SQLI
→ RUNNING / PUBLISHING_RAW
→ RUNNING / AI_TRIAGE
→ RUNNING / PUBLISHING_RESULT
→ COMPLETED 또는 PARTIAL
```

실행 수준 오류가 발생하면 어느 비terminal 단계에서도 `FAILED`로 전이할 수 있다. terminal 상태에서 다른 상태로 되돌아가면 안 된다.

## 11. 스캐너 모듈 계약

XSS·SQLi 스캐너는 동일한 호출 형태와 RawFinding 계약을 사용한다.

```python
from collections.abc import Callable
from orchestration import ScanContext

ProgressCallback = Callable[[int, int], None]


def scan(
    targets: list[TargetCase],
    context: ScanContext,
    on_progress: ProgressCallback,
) -> list[RawFinding]:
    """대상들을 진단하고 모든 시도 결과를 반환한다."""
```

### 11.1 입력

- `targets`: manifest에서 해당 취약점 유형으로 필터링된 허가 대상
- `context`: registry에서 재검증된 `base_url`, 요청 정책, 읽기 전용 `scan_run_id`,
  해당 run 내부의 응답 증거 저장 경로, 인증 profile resolver만 제공하는 블랙박스 실행 문맥
- `on_progress`: 현재 단계의 절대 `completed`, `total` 건수를 `main.py`에 전달하는 callback

기존 `scan(targets, scan_run_id, on_progress)` 계약에서 이전하는 방법과 담당자별
확인 목록은 [`scanner-integration-migration.md`](scanner-integration-migration.md)를 참고한다.

### 11.2 출력

- `docs/data-contracts-v1.md` Contract B와 일치하는 RawFinding 목록
- `SAFE`, `SUSPECTED`, 요청 실패를 모두 보존
- 예외가 발생한 개별 시도도 `scan.status=FAILED` Finding으로 반환

### 11.3 payload와 case_id

Finding 1건은 **대상 1개와 payload 1개를 실행한 결과**다.

payload profile이 단일 payload를 제공하면 출력 `case_id`는 manifest의 `case_id`를 그대로 사용한다.

payload profile에 여러 payload가 있으면 각 payload 항목은 안정적인 `payload_case_id`를 가져야 한다. 이 경우 출력 `case_id`는 다음 규칙으로 생성한다.

```text
<manifest case_id>::<payload_case_id>
```

예:

```text
xss-reflected-a::script-basic
sqli-search-a::boolean-true
```

- 같은 target·payload 조합은 재실행해도 같은 `case_id`를 사용한다.
- `finding_id`는 실행 안에서만 유일하며 `case_id`와 별개다.
- ground truth도 확장된 `case_id`를 사용한다.
- payload 원문을 ID에 직접 포함하지 않는다.

### 11.4 증거 저장

- 응답 HTML은 `data/raw/<scan_run_id>/responses/<finding_id>.html`에 저장한다.
- RawFinding에는 `responses/<finding_id>.html` 상대 경로만 기록한다.
- 응답 파일은 임시 파일에 쓴 뒤 rename한다.
- 쿠키, 인증 헤더와 불필요한 개인정보를 원문 저장 전에 제거한다.
- 스캐너는 응답 HTML을 Git에 등록하지 않는다.

### 11.5 금지 사항

- 스캐너가 OpenAI API를 호출하지 않는다.
- 스캐너가 `status.json`을 직접 수정하지 않는다.
- 스캐너가 임의 외부 URL로 redirect된 요청을 계속하지 않는다.
- 스캐너가 ground truth 또는 취약·안전 정답값을 판정 입력으로 사용하지 않는다.
- 한 대상의 실패로 전체 프로세스를 즉시 종료하지 않는다.

## 12. raw·processed 결과 게시

### 12.1 raw

두 스캐너의 결과를 `main.py`가 하나의 canonical raw envelope로 결합한다.

```text
data/raw/<scan_run_id>/findings.json
```

- 요청한 취약점 유형의 모든 Finding을 포함한다.
- 스키마 검증을 통과한 뒤 게시한다.
- raw 게시 후 `status.raw_result_path`를 갱신한다.

### 12.2 processed

OpenAI·데이터 처리 담당은 raw의 모든 Finding을 1:1 보존한 processed envelope를 생성한다.

```text
data/processed/<scan_run_id>/results.json
```

- AI 후보가 아닌 Finding도 유지한다.
- AI 미요청·실패·판정 불가를 구분한다.
- processed 검증과 게시 완료 후에만 `status.processed_result_path`를 기록한다.

### 12.3 원자적 게시

최종 파일을 직접 작성하지 않는다.

```text
results.json.tmp 작성
→ flush·close
→ 스키마 검증
→ results.json으로 atomic rename
→ status.json 갱신
```

상태 파일도 같은 방식으로 원자적으로 교체한다. 대시보드가 부분 JSON을 읽게 해서는 안 된다.

## 13. 중복 실행과 lock

MVP에서는 전체 시스템에서 한 번에 하나의 run만 허용한다.

```text
data/runs/.pipeline.lock
```

- `main.py`가 atomic create로 lock을 획득한다.
- lock 획득 실패 시 실행을 시작하지 않고 종료 코드 `3`을 반환한다.
- 정상·부분·실패 terminal 처리 후 lock을 해제한다.
- 프로세스 비정상 종료에 대비해 lock에 PID, `scan_run_id`, 생성 시각을 기록한다.
- stale lock 제거는 프로세스 생존 여부와 run 상태를 확인한 후에만 수행한다.
- Streamlit session state만으로 중복 실행을 제어하지 않는다.

## 14. 오류 계약

오류 구조는 데이터 계약과 동일하다.

```json
{
  "code": "TARGET_VALIDATION_FAILED",
  "message": "허가된 대상 명세를 확인할 수 없습니다.",
  "retryable": false
}
```

### 14.1 실행 수준 오류 코드

| code | retryable | 의미 |
| --- | --- | --- |
| `RUN_ALREADY_ACTIVE` | true | 다른 실행 진행 중 |
| `TARGET_VALIDATION_FAILED` | false | manifest 또는 허가 검증 실패 |
| `RUN_DIRECTORY_FAILED` | true | 실행 디렉터리 생성 실패 |
| `SCANNER_CONTRACT_FAILED` | false | 스캐너가 요청 대상 결과를 누락했거나 잘못된 결과를 반환 |
| `RAW_PUBLISH_FAILED` | true | raw 검증·게시 실패 |
| `PROCESSED_PUBLISH_FAILED` | true | processed 검증·게시 실패 |
| `PIPELINE_CRASHED` | true | 예상하지 못한 실행 수준 오류 |

개별 HTTP 요청과 AI 요청 오류는 해당 Finding의 `scan.error`와 `ai.error`에 기록한다. 개별 오류만 존재하고 유효한 결과가 있으면 run은 `PARTIAL`이다.

오류 메시지에 API 키, 쿠키, 인증 헤더, 실제 고정 IP, 응답 HTML 원문과 로컬 절대 경로를 포함하지 않는다.

## 15. 대시보드 진단 실행 view 계약

대시보드는 `진단 실행`과 `결과 검토` navigation view를 제공하며 선택된 view만 렌더한다. 첫 방문은 진단 실행 view다. 실행 view는 다음 순서로 동작한다.

1. 등록된 target manifest 목록을 표시한다.
2. XSS·SQLi 진단 유형을 선택한다.
3. 허가된 격리 환경임을 확인하는 체크를 요구한다.
4. 실행 버튼을 한 번 누르면 `start_run`을 한 번만 호출한다.
5. 반환된 `scan_run_id`는 session state의 현재 선택 hint로만 보관한다. active run의 authoritative source는 RunStore이며 새로고침 뒤에도 재발견한다.
6. ACTIVE (`QUEUED`, `RUNNING`)에서만 `status.json`을 일정 간격으로 읽어 run ID, target set, 요청 유형, 상태, 단계, 진행률과 updated_at을 읽기 전용으로 표시한다.
7. terminal 상태가 되면 polling을 중단한다.
8. `COMPLETED`·`PARTIAL`이고 canonical `processed/<scan_run_id>/results.json` artifact가 실제로 안전하게 존재할 때만 명시적 결과 검토 CTA를 표시한다. CTA callback은 다음 rerun 전에 navigation을 결과 검토 view로 바꾸고 해당 `scan_run_id`를 persistent review selection state에 저장한다. review 진입 시 artifact를 다시 검증한다.
9. `FAILED`와 artifact unavailable은 결과 검토 CTA가 없으며 자동으로 view를 이동하지 않는다. `새 진단 준비`는 session selection만 정리하고 RunStore artifact를 삭제하지 않는다.

버튼을 여러 번 누르거나 브라우저를 새로고침해도 같은 요청이 중복 실행되지 않도록 lock과 현재 run 상태를 확인한다.

## 16. 완료 조건

### 스캐너 담당

- 허가된 manifest 대상만 호출한다.
- 동일한 함수 입력·출력 계약을 따른다.
- 모든 시도 결과와 개별 실패를 RawFinding으로 반환한다.
- stable payload case ID를 사용한다.
- 증거 sidecar를 안전한 상대 경로로 저장한다.
- 진행 callback을 호출하되 상태 파일은 수정하지 않는다.

### `main.py`·통합 담당

- run ID·디렉터리·lock을 안전하게 생성한다.
- 상태 전이가 계약과 일치한다.
- 스캐너 결과를 하나의 raw envelope로 결합한다.
- raw·processed·status 파일을 원자적으로 게시한다.
- terminal 상태와 종료 코드가 일치한다.
- 한 Finding 실패 시 가능한 나머지 처리를 계속한다.

### 대시보드 담당

- 등록 대상만 선택할 수 있다.
- 실행 중 버튼 중복 요청을 막는다.
- 상태와 단계·진행률을 구분해 표시한다.
- canonical artifact가 있는 COMPLETED·PARTIAL만 CTA 기반으로 결과 검토 화면에 연결한다.
- 임의 URL, 인증정보와 내부 예외를 화면에 노출하지 않는다.

## 17. 스캐너팀 확인 요청 사항

스캐너 담당자는 구현 전에 다음 항목을 확인한다.

1. `scan(targets, context, on_progress)` 형태로 구현 가능한가?
2. 모든 정상·의심·실패 시도를 공통 RawFinding으로 반환할 수 있는가?
3. payload profile에 안정적인 `payload_case_id`를 부여할 수 있는가?
4. 요청·응답 증거를 run별 sidecar로 저장할 수 있는가?
5. 대상 하나가 실패해도 나머지 진단을 계속할 수 있는가?
- 진행 완료·전체 건수를 callback으로 전달할 수 있는가?
7. 계약상 부족하거나 구현하기 어려운 필드·상태가 있는가?

변경 의견은 스캐너 구현 전에 합의한다. 승인된 계약 이후 필드·상태를 변경할 때는 실행 계약 버전을 올리고 생산자·소비자 테스트를 함께 수정한다.
