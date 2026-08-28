# 스캐너 통합 계약 변경 안내

적용 기준: `feature/dashboard-contracts` 커밋 `4d75a90`

이 문서는 XSS·SQLi 스캐너 담당자가 기존 실행 계약에서 현재 계약으로 옮길 때
필요한 변경만 정리한다. 기존 구현이 잘못되어 인터페이스를 바꾼 것이 아니라,
최초 계약에서 빠졌던 실행 문맥 전달 방법을 보완한 변경이다.

## 1. 변경 배경

최초 실행 계약은 다음 인터페이스를 정의했다.

```python
def scan(
    targets: list[TargetCase],
    scan_run_id: str,
    on_progress: ProgressCallback,
) -> list[RawFinding]:
    ...
```

하지만 실제 HTTP 진단에 필요한 다음 정보의 전달 방법이 없었다.

- registry에서 허가된 `base_url`
- timeout과 redirect 여부를 담은 `request_policy`
- 해당 run에 허가된 응답 증거 저장 경로
- 실제 비밀값을 manifest에 넣지 않고 인증 profile을 조회하는 방법

`base_url`은 `TargetManifest` 최상위에 있고 스캐너에는 필터링된
`TargetCase` 목록만 전달되므로, 기존 시그니처만으로는 요청 URL을 안전하게
구성할 수 없었다. 스캐너마다 임의 키워드 인자와 자체 경로 규칙을 추가하면
XSS·SQLi의 호출 계약이 달라지고 registry 검증도 우회될 수 있다.

이를 해결하기 위해 실행에 필요한 최소 정보만 `ScanContext`로 묶었다.

## 2. 현재 인터페이스

```python
from orchestration import ScanContext


def scan(
    targets: list[TargetCase],
    context: ScanContext,
    on_progress: ProgressCallback,
) -> list[RawFinding]:
    ...
```

`ScanContext`가 제공하는 값은 다음과 같다.

| 기존 사용 값 | 현재 사용 값 | 용도 |
| --- | --- | --- |
| `scan_run_id` | `context.scan_run_id` | 실행 ID |
| 별도 `base_url` 인자 | `context.base_url` | registry에서 재검증된 origin |
| 자체 timeout 상수 | `context.request_policy.timeout_seconds` | manifest의 요청 제한 |
| requests 기본 redirect | `context.request_policy.follow_redirects` | redirect 허용 여부 |
| `data/raw/...` 직접 조합 | `context.responses_dir` | 해당 run 내부의 증거 저장 경로 |
| 자체 인증정보 로드 | `context.resolve_auth_profile(profile_id)` | 서버 측 인증 profile 조회 |

스캐너는 pipeline 상태 파일, target registry 또는 다른 스캐너의 내부 구현을 알
필요가 없다. 전달된 context 범위 안에서 HTTP 요청과 `RawFinding` 생산만 담당한다.

## 3. 최소 마이그레이션 형태

`main.py`와 사전점검은 다음 진입점을 찾는다.

```text
scanners.xss.scan
scanners.sqli.scan
```

내부 구현을 `scanners/pipeline/xss.py` 등에 유지한다면 `scanners/xss.py`에서
현재 계약을 만족하는 `scan`을 공개해야 한다. 단순 re-export를 하더라도 내부
함수의 시그니처와 동작이 현재 계약을 만족해야 한다.

```python
from urllib.parse import urljoin

from orchestration import ScanContext


def scan(targets, context: ScanContext, on_progress):
    timeout = context.request_policy.timeout_seconds
    follow_redirects = context.request_policy.follow_redirects

    for target in targets:
        url = urljoin(context.base_url, target.path)
        auth = (
            context.resolve_auth_profile(target.auth_profile)
            if target.requires_pre_auth
            else None
        )
        # timeout, redirect 정책과 auth를 실제 요청에 적용한다.
        # 응답 증거는 context.responses_dir 아래에만 저장한다.
        # 각 시도 결과는 성공·실패와 관계없이 RawFinding으로 보존한다.
        ...
```

진행률 callback은 증분이 아니라 현재 단계의 절대값을 전달한다.

```python
on_progress(completed, total)
```

## 4. 응답 증거 저장

스캐너가 다음과 같이 경로를 직접 재구성하면 안 된다.

```python
Path("data/raw") / scan_run_id
```

반드시 `context.responses_dir` 아래에 저장한다.

```text
context.responses_dir/<finding_id>.html
```

`RawFinding.scan.response.html_path`에는 run 디렉터리 기준 상대 경로만 기록한다.

```text
responses/<finding_id>.html
```

저장 전 쿠키, 인증 헤더와 불필요한 개인정보를 제거하고 임시 파일 작성 후
atomic rename한다. payload와 응답 HTML 원문은 콘솔에 출력하지 않는다.

## 5. payload profile 규칙

런타임 스캐너는 OpenAI API를 호출하지 않는다.

XSS에서 AI로 payload 후보를 만들고 싶다면 다음 두 단계를 분리한다.

```text
별도 사전 생성 도구
→ 사람이 후보 검토
→ 안정적인 payload_case_id 부여
→ 버전이 고정된 payload profile 저장
→ 런타임 스캐너는 고정 목록만 로드
```

캐시·고정 목록이 없거나 손상된 경우 OpenAI를 대신 호출하거나 임의 fallback으로
계속 실행하지 않는다. 원인을 숨기지 말고 실행 준비 실패로 처리한다.

각 payload에는 재실행해도 바뀌지 않는 `payload_case_id`가 있어야 한다.

```text
<manifest case_id>::<payload_case_id>
```

## 6. target manifest와 registry

manifest는 target 배열만 저장하는 파일이 아니라 정식 `TargetManifest` envelope여야
한다.

```json
{
  "schema_version": "1.0",
  "target_set_id": "local-lab-v1",
  "base_url": "http://127.0.0.1:5000",
  "request_policy": {
    "timeout_seconds": 10,
    "follow_redirects": false
  },
  "targets": []
}
```

신규 manifest는 `configs/target-registry.json`에도 등록한다.

```json
{
  "target_set_id": "local-lab-v1",
  "manifest": "targets.example.json",
  "allowed_base_url": "http://127.0.0.1:5000"
}
```

실행 시 registry의 ID, manifest의 ID와 허용 `base_url`이 모두 정확히 일치해야
한다. `verification_mode`, `verify_path`처럼 현재 공통 모델에 없는 필드는 manifest에
임의로 추가할 수 없다. Stored XSS 자동화에 새로운 필드가 필요하면 데이터 계약,
공통 모델, 샘플과 검증 테스트를 함께 변경한 뒤 사용한다.

## 7. RawFinding 완료 조건

- 전달받은 모든 target은 최소 한 개 이상의 Finding을 반환한다.
- payload가 여러 개면 모든 target·payload 조합을 보존한다.
- `case_id`는 manifest case와 안정적인 payload case의 조합이다.
- `finding_id`는 한 run 안에서 유일해야 한다.
- 요청 실패도 삭제하지 않고 `scan.status=FAILED`로 반환한다.
- SQLi 완료 Finding에는 `baseline_elapsed_ms`가 필요하다.
- 스캐너는 `findings.json`과 `status.json`을 직접 게시하거나 수정하지 않는다.

요청 target이 누락되거나 schema가 잘못된 결과를 반환하면 pipeline은
`SCANNER_CONTRACT_FAILED`로 실행을 종료한다.

## 8. 담당자별 확인 목록

### XSS

- [ ] `scanners.xss.scan` 진입점 제공
- [ ] `base_url`, run ID, timeout, redirect와 저장 경로를 context에서 사용
- [ ] OpenAI payload 생성 코드를 런타임 scan 경로 밖으로 이동
- [ ] 고정 payload profile과 안정적인 `payload_case_id` 사용
- [ ] Stored XSS 확장 필드는 공통 계약 합의 후 반영
- [ ] canonical `analysis.models`를 교체하지 않고 그대로 사용

### SQLi

- [ ] `scanners.sqli.scan` 진입점 제공
- [ ] 기존 flat dict 대신 canonical `RawFinding` 반환
- [ ] TargetCase의 `path`, `method`, `input` 사용
- [ ] context의 timeout·redirect·인증·저장 경로 적용
- [ ] 정적 payload에 안정적인 `payload_case_id` 부여
- [ ] 404와 요청 실패를 SAFE가 아닌 실패 Finding으로 보존

## 9. 통합 전 검증

```bash
pytest -q
ruff check .
```

추가로 최소한 다음 통합 테스트가 필요하다.

- `scanners.xss.scan`, `scanners.sqli.scan` import 가능
- context의 base URL과 request policy가 실제 요청에 적용됨
- 외부 redirect를 허가 없이 따라가지 않음
- 모든 target·payload 결과가 canonical `RawFinding` 검증을 통과함
- 누락 target, 404, timeout과 요청 예외가 안전하게 실패 처리됨
- 증거 파일이 `context.responses_dir` 밖에 생성되지 않음
