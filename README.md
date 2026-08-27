# AI 기반 웹 취약점 진단 자동화

XSS와 SQL Injection 진단 결과를 수집하고, 규칙 기반 1차 판정과 OpenAI 기반 보조 분석을 거쳐 Streamlit 대시보드와 Excel 보고서로 제공하는 교육용 프로젝트입니다. 팀 협업과 결과 공유를 위한 Public 저장소로 운영합니다.

> 이 저장소의 스캐너는 팀이 직접 구축하고 접근 권한을 가진 격리된 실습 환경에서만 사용합니다. 외부 서비스나 허가받지 않은 시스템을 대상으로 실행하지 마세요.

## 주요 기능

- Flask 기반 XSS·SQLi 취약/방어 실습 환경
- `requests` 기반 자동 진단 및 증거 수집
- 공통 Finding 스키마와 규칙 기반 판정
- OpenAI Responses API 기반 보조 분석
- Streamlit 대시보드 및 Plotly 시각화
- pandas/openpyxl 기반 Excel 보고서 생성
- Burp Suite 수동 진단 결과와 자동 판정 비교

## 프로젝트 구조

```text
.
├── analysis/              # 데이터 모델, 프롬프트, AI 보조 판정
├── configs/               # 진단 대상 등 공유 가능한 설정 예시
├── dashboard/             # Streamlit UI, 통계, Excel 보고서
├── data/
│   ├── raw/               # 스캐너 원시 결과 (Git 제외)
│   ├── processed/         # AI 분석 완료 결과 (Git 제외)
│   └── exports/           # 생성된 Excel 보고서 (Git 제외)
├── docs/                  # 아키텍처와 팀 문서
├── lab_app/               # 격리된 Flask 실습 웹앱
├── scanners/              # XSS·SQLi 스캐너와 공통 로직
│   ├── base.py            # 인증 세션(LabSession), CSV 저장 등 공통 헬퍼
│   ├── xss_config.py      # XSS 스캐너 설정(호스트/계정/타겟 목록) 로딩
│   ├── xss_payloads.py    # AI 페이로드 생성 + 캐시 조회/저장
│   ├── payload_cache.py   # 범용 페이로드 캐시 파일 입출력
│   ├── xss_rules.py       # 반사 여부 내부 판정 로직
│   ├── xss_report.py      # 내부 판정 -> Contract B(raw findings) 조립 + sidecar 저장
│   ├── xss.py             # bWAPP 대상 탐색용 샷건 스캐너 (계약 준수 대상 아님, 임시 검증용)
│   └── pipeline/          # main.py가 실제로 호출하는 계약 준수 스캐너
│       └── xss.py         # scan(targets, scan_run_id, on_progress) -- lab_app(Lumi Market) 대상
├── tests/                 # 자동화 테스트
├── main.py                # 로컬 통합 실행 진입점
└── requirements.txt
```

## 시작하기

### 1. 개발 환경 준비

Python 3.11 이상을 권장합니다.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 2. 환경 변수 설정

저장소 루트에 `.env` 파일을 직접 만들고 아래 값을 채웁니다(예시 파일 없이 직접 작성).

```bash
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o
XSS_LAB_HOST=http://127.0.0.1
XSS_LAB_LOGIN=bee
XSS_LAB_PASSWORD=bug
```

API 키, 비밀번호, 세션 키는 커밋하지 않습니다(`.env`는 `.gitignore`에 이미 등록되어 있음).

XSS 스캐너는 AI 페이로드를 매 실행마다 새로 생성하지 않습니다. `scanners/xss_payloads.py`가 `data/raw/xss_ai_payloads.json`(Git 제외)에 저장된 캐시를 확인해서, 파일이 있으면 그대로 재사용하고 없을 때만 OpenAI를 호출해 새로 생성 후 저장합니다. 최신 페이로드가 필요하면 `--refresh-payloads` 옵션으로 강제 재생성할 수 있습니다.

이 저장소는 공개되므로 실습 서버의 실제 주소, AWS 계정 정보, 고정 IP, 세션 값, 원본 HTTP 응답에 포함된 개인정보도 커밋하지 않습니다.

### 3. 실습 웹앱 실행

```bash
flask --app lab_app.app run --debug
```

### 4. 통합 진단 실행

```bash
python main.py --targets configs/targets.example.json
```

### 4-1. XSS 스캐너 단독 실행

```bash
python scanners/xss.py --targets configs/xss_lab_targets.example.json
```

주요 옵션:

- `--count`: 캐시가 없을 때 AI에게 요청할 페이로드 개수 (기본 100)
- `--refresh-payloads`: 캐시를 무시하고 AI 페이로드를 새로 생성
- `--payload-cache`: 캐시 파일 경로 (기본 `data/raw/xss_ai_payloads.json`)
- `--output-dir`: 결과를 저장할 상위 디렉터리 (기본 `data/raw`). 실제 결과는 이 아래 `<scan_run_id>/findings.json`에 기록된다
- `--target-set-id`: 이번 스캔에 사용한 타겟 목록을 식별하는 ID (기본 `bwapp-xss-lab-v1`)
- `--delay`: 매 HTTP 요청 사이에 대기할 시간(초). 실습 서버(가상머신)가 샷건식 요청 폭주로 500 에러를 내거나 멈추는 것을 막고 싶을 때 사용 (예: `--delay 0.5`). 기본값은 0(대기 없음)
- `--timeout`: 요청 하나당 타임아웃(초). 응답이 이 시간 안에 안 오면 그 요청만 포기하고 다음으로 넘어감 (기본 5초)

각 페이로드는 파라미터/헤더(`firstname`, `lastname`, ..., `User-Agent`, `Referer`, `bWAPP`)마다, 그리고 GET/POST 메서드마다 각각 별도의 요청으로 개별 실행됩니다("요청 1번 = Finding 1건" 원칙). 대신 요청 수는 (URL × 페이로드 × 파라미터/헤더 수 × 2)만큼 늘어나므로, 대상이 많거나 `--count`를 크게 잡으면 스캔 시간이 길어집니다.

**세션 만료 자동 대응**: 스캔 시간이 길어지면(공격 조합이 많을 때 30분 이상 걸릴 수 있음) 타겟 서버의 로그인 세션이 중간에 만료될 수 있습니다. `scanners/base.py`의 `LabSession`은 매 응답이 로그인 페이지로 리다이렉트됐는지 자동으로 확인하고, 그렇다면 즉시 재로그인한 뒤 같은 요청을 다시 시도합니다. 별도 옵션 없이 항상 동작합니다.

**Stored XSS(저장형 XSS) 검증 범위**: 이 스캐너는 기본적으로 Reflected 방식(요청 1번 → 응답 1번)의 단일 응답 기반 판정에 집중합니다. 다만 타겟 목록 JSON에서 `"mode": "stored"`로 명시한 대상에 한해서는, 페이로드를 주입(POST/GET)한 뒤 별도의 조회 요청을 한 번 더 보내 실제로 저장되어 남아있는지까지 2단계로 확인합니다(조회 페이지가 다르면 `"verify_path"`로 지정 가능). 예시는 `configs/xss_lab_targets.example.json`의 `xss_stored_*.php` 항목을 참고하세요.

```json
{ "path": "/bWAPP/xss_stored_1.php", "mode": "stored" }
```

`mode`를 지정하지 않은 대상은 여전히 Reflected 판정만 수행하므로, 즉시 반사되지 않는 저장형 취약점은 놓칠 수 있습니다.

#### 결과 파일 형식 (Contract B: raw findings)

이 스캐너의 출력은 팀 공통 데이터 계약 [`docs/data-contracts-v1.md`](docs/data-contracts-v1.md)의 **Contract B(raw findings)** 규격을 따릅니다. 실제 경로는 `data/raw/<scan_run_id>/findings.json`이며, 응답 본문 전체는 JSON에 넣지 않고 같은 디렉터리의 `responses/<finding_id>.html`에 sidecar 파일로 따로 저장합니다(Git에는 올라가지 않음).

최상위 envelope:

| 필드 | 설명 |
| --- | --- |
| `schema_version` | 계약 버전 (`"1.0"`) |
| `scan_run_id` | 이번 실행을 식별하는 유일 ID |
| `target_set_id` | `--target-set-id`로 지정한 값 |
| `started_at` / `completed_at` | ISO 8601 시각(타임존 포함) |
| `status` | `COMPLETED` / `PARTIAL`(일부 요청 실패) / `FAILED`(로그인 실패 등으로 결과 자체를 못 만듦) |
| `findings` | 아래 RawFinding 배열 |

RawFinding 1건 = 요청 1번:

```json
{
  "case_id": "xss-bwapp-xss-get-php-firstname-get",
  "finding_id": "XSS-000001",
  "scanned_at": "2026-08-27T09:30:10+09:00",
  "vuln_type": "XSS",
  "scan": {
    "status": "COMPLETED",
    "request": {"url": "...", "method": "GET", "input_location": "query", "parameter": "firstname", "payload": "<script>alert(1)</script>"},
    "response": {"http_status": 200, "elapsed_ms": 182, "baseline_elapsed_ms": null, "evidence_summary": "...", "html_path": "responses/XSS-000001.html"},
    "rule": {"label": "SUSPECTED", "reason": "..."},
    "error": null
  }
}
```

- `case_id`는 (대상 경로, 파라미터, 메서드) 조합으로 결정적으로 생성되어 실행마다 바뀌지 않습니다.
- `rule.label`은 계약이 정한 `SUSPECTED`/`SAFE`/`null` 세 값만 사용합니다. 내부적으로는 더 세분화된 판정(그대로 반사/이스케이프되어 반사/저장 확인됨/반사 안 됨, `scanners/xss_rules.py`)을 쓰지만, 그 세부 내용은 `rule.reason`과 `response.evidence_summary` 텍스트로 남기고 공개 필드는 계약값으로 압축합니다.
- 요청 자체가 실패하면(타임아웃 등) `scan.status="FAILED"`이고 `response`/`rule`은 모두 `null`, `error`에 `{code, message, retryable}`이 채워집니다. 실패한 시도도 삭제하지 않고 그대로 기록합니다.

**계약과의 알려진 차이점**: 계약의 `input_location`은 `query`/`form`/`json`만 정의하지만, 이 스캐너는 bWAPP의 User-Agent/Referer/커스텀 헤더 기반 반사도 탐지하므로 편의상 `"header"` 값을 추가로 씁니다. 아직 팀 합의를 거치지 않은 확장이니, 이 값을 소비하는 다음 단계(OpenAI·데이터 처리 담당)가 생기면 계약 문서 갱신과 버전업 절차(계약 8장)를 거쳐야 합니다.

> **주의**: 위 `scanners/xss.py`(bWAPP 대상)는 공식 실습 환경이 없던 시기에 팀이 임시로 검증용으로 쓰던 서버를 대상으로 하며, 아래 실행 계약을 지킬 의무가 없는 별도 도구입니다. 실제 파이프라인이 호출하는 스캐너는 아래 `scanners/pipeline/xss.py`입니다.

### 4-2. 파이프라인용 XSS 스캐너 (`scanners/pipeline/xss.py`, lab_app 대상)

`main.py`(통합 담당)가 실제로 호출할 것을 전제로, 실행 계약이 정의한 `scan(targets, scan_run_id, on_progress) -> list[RawFinding]` 인터페이스를 구현합니다. 대상은 `feature/vulnerable-lab` 브랜치의 `lab_app/`(Lumi Market, 1번 실습 환경, `docs/vulnerable-lab-1.md`)이며, 현재 아래 두 케이스를 다룹니다.

- **XSS-01 (Reflected)**: `GET /search`, query 파라미터 `q`
- **XSS-02 (Stored)**: `POST` 후 `GET /reviews`, form 파라미터 `content`

타겟 매니페스트 예시: `configs/lumi_market_1_xss_targets.example.json` (Contract A 형식).

로컬에서 직접 확인해보려면(main.py 통합 전 임시 실행 경로, 실제 파이프라인은 이 CLI가 아니라 `scan()` 함수를 직접 import해서 씀):

```bash
python -m scanners.pipeline.xss --targets configs/lumi_market_1_xss_targets.example.json --base-url http://127.0.0.1:5001
```

`lab_app`의 기본 포트는 `LAB_1_PORT` 환경변수로 정해지며 기본값은 `5001`입니다(`docs/vulnerable-lab-1.md`). 다른 포트로 띄웠다면 `--base-url`을 맞춰서 넘기면 됩니다.

**실행 계약에 명시되지 않아 실용적으로 채운 부분** (통합 담당과 추후 확인 필요):

- `base_url`: 계약의 target manifest에는 최상위에 `base_url`이 있지만, `scan()` 함수 시그니처 자체에는 전달 방법이 없어 키워드 인자로 받습니다.
- `TargetCase.verification_mode`(`"reflected"`/`"stored"`): Stored XSS의 2단계 검증(주입 후 별도 조회) 여부를 정하는 값인데, Contract A의 정식 필드에는 이를 표현할 곳이 없어 매니페스트 JSON에 추가 필드로 넣었습니다.
- `auth_profile`/`requires_pre_auth=true` 케이스의 인증 흐름은 아직 설계하지 않았습니다. 지금 두 케이스는 모두 인증이 필요 없어 문제가 안 되지만, 해당 케이스를 만나면 `NotImplementedError`를 던지도록 명시적으로 막아뒀습니다.
- `payload_profile`(AI가 안정적인 `payload_case_id`를 부여해 생성하는 방식)은 아직 합의되지 않아 이번 구현에서 완전히 배제했습니다. 대신 고정된 소규모 페이로드 목록을 기본값으로 사용합니다.

### 5. 대시보드 실행

```bash
streamlit run dashboard/app.py
```

## 데이터 흐름

```text
Flask 실습 환경
  -> XSS/SQLi 스캐너
  -> 규칙 기반 판정 및 raw JSON
  -> OpenAI 보조 판정 및 processed JSON
  -> Streamlit 대시보드 / Excel 보고서
```

사람이 만든 `ground_truth_label`은 AI 입력에서 제외하고, 최종 평가 단계에서만 비교합니다. 웹 응답과 소스 코드 조각은 신뢰할 수 없는 데이터로 취급하며 프롬프트 지시로 실행하지 않습니다.

## 브랜치 및 협업 규칙

- 기본 브랜치: `main`
- 작업 브랜치 예시: `feature/xss-scanner`, `feature/ai-triage`, `feature/dashboard`
- 기능 단위 Pull Request 사용
- PR 전에 `pytest`, `ruff check .` 실행
- `.env`, 진단 원본, 생성 보고서, DB 파일 커밋 금지

## 역할별 권장 담당 경로

- 환경 구축: `lab_app/`, `configs/`
- XSS/SQLi 진단: `scanners/`
- AI 및 데이터 계약: `analysis/`
- 대시보드 및 보고서: `dashboard/`
- 통합과 검증: `main.py`, `tests/`, `docs/`

## 현재 상태

초기 저장소 골격 단계입니다. 각 모듈은 인터페이스만 준비되어 있으며 실제 진단·AI 분석·보고서 기능은 이후 구현합니다.
