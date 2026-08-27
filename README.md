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
├── lab_app/               # 이 브랜치의 자리표시자 스켈레톤(health 체크만 있음, 아래 참고)
├── scanners/              # XSS·SQLi 스캐너와 공통 로직
│   ├── base.py            # 공용 HTTP 헬퍼(같은 호스트로만 리다이렉트 추적 등)
│   ├── xss_rules.py       # 반사 여부 내부 판정 로직
│   ├── xss_report.py      # 내부 판정 -> Contract B(raw findings) 조립 + sidecar 저장
│   └── pipeline/          # main.py가 실제로 호출하는 계약 준수 스캐너
│       └── xss.py         # scan(targets, scan_run_id, on_progress) -- 실제 실습 환경 대상
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
```

API 키, 비밀번호, 세션 키는 커밋하지 않습니다(`.env`는 `.gitignore`에 이미 등록되어 있음). 이 저장소는 공개되므로 실습 서버의 실제 주소, AWS 계정 정보, 고정 IP, 세션 값, 원본 HTTP 응답에 포함된 개인정보도 커밋하지 않습니다.

### 3. 실습 웹앱 실행

실제로 XSS 취약점이 있는 실습 앱은 이 브랜치가 아니라 별도 브랜치에 있습니다(이 브랜치의 `lab_app/`은 `/health`만 있는 자리표시자 스켈레톤입니다).

| 환경 | 브랜치 | 앱 폴더 | 기본 주소 |
| --- | --- | --- | --- |
| 1번 (Lumi Market) | `feature/vulnerable-lab` | `lab_app/` | `http://127.0.0.1:5001` (`LAB_1_PORT`) |
| 2번 (NovaStream) | `feature/vulnerable-lab-2` | `lab_app_2/` | `http://127.0.0.1:5000` (`LAB2_PORT`) |

로컬에서 확인하려면(이 브랜치는 그대로 두고, 별도 워크트리로 체크아웃):

```bash
git worktree add ../vulnerable-lab-1 origin/feature/vulnerable-lab
cd ../vulnerable-lab-1 && pip install -r lab_app/requirements.txt
python -m lab_app.app   # http://127.0.0.1:5001
```

```bash
git worktree add ../vulnerable-lab-2 origin/feature/vulnerable-lab-2
cd ../vulnerable-lab-2 && pip install -r lab_app_2/requirements.txt
python -m lab_app_2.app   # http://127.0.0.1:5000
```

두 환경 모두 지금은 로컬에서 돌리지만 이후 서버에 배포될 예정입니다. 스캐너는 대상 주소를 코드에 고정하지 않고 항상 `--base-url`로 받으므로, 배포 후에는 그 서버 주소만 넘기면 그대로 재사용할 수 있습니다.

### 4. 통합 진단 실행

```bash
python main.py --targets configs/targets.example.json
```

### 4-1. 파이프라인용 XSS 스캐너 (`scanners/pipeline/xss.py`)

`main.py`(통합 담당)가 실제로 호출할 것을 전제로, 실행 계약이 정의한 `scan(targets, scan_run_id, on_progress) -> list[RawFinding]` 인터페이스를 구현합니다. 각 실습 환경에서 **실제로 XSS 취약점이 확인된 페이지·입력칸만** 대상으로 하며(짐작으로 아무 입력창이나 찌르지 않음), 페이로드를 어느 파라미터에 넣어야 하는지는 타겟 매니페스트 JSON에 정확히 명시되어 있습니다.

| 환경 | 매니페스트 | 케이스 |
| --- | --- | --- |
| 1번 (Lumi Market) | `configs/lumi_market_1_xss_targets.example.json` | Reflected: `GET /search` query `q` · Stored: `POST /reviews` form `content` (같은 `/reviews`에서 확인) |
| 2번 (NovaStream) | `configs/novastream_2_xss_targets.example.json` | Reflected: `GET /discover` query `q` · Stored: `POST /titles/1/reviews` form `body` (다른 페이지 `GET /admin/reviews`에서 확인) |

로컬에서 직접 확인해보려면(main.py 통합 전 임시 실행 경로, 실제 파이프라인은 이 CLI가 아니라 `scan()` 함수를 직접 import해서 씀):

```bash
python -m scanners.pipeline.xss \
  --targets configs/lumi_market_1_xss_targets.example.json \
  --base-url http://127.0.0.1:5001 \
  --target-set-id lumi-market-1

python -m scanners.pipeline.xss \
  --targets configs/novastream_2_xss_targets.example.json \
  --base-url http://127.0.0.1:5000 \
  --target-set-id novastream-2
```

**실행 계약에 명시되지 않아 실용적으로 채운 부분** (통합 담당과 추후 확인 필요):

- `base_url`: 계약의 target manifest에는 최상위에 `base_url`이 있지만, `scan()` 함수 시그니처 자체에는 전달 방법이 없어 키워드 인자로 받습니다.
- `TargetCase.verification_mode`(`"reflected"`/`"stored"`)와 `verify_path`: Stored XSS의 2단계 검증(주입 후 별도 조회) 여부와, 작성 페이지와 확인 페이지가 다를 때(NovaStream처럼) 어디를 조회할지를 정하는 값인데, Contract A의 정식 필드에는 이를 표현할 곳이 없어 매니페스트 JSON에 추가 필드로 넣었습니다. 작성·확인 페이지가 같으면 `verify_path`는 생략합니다.
- `auth_profile`/`requires_pre_auth=true` 케이스의 인증 흐름은 아직 설계하지 않았습니다. 지금까지 확인된 케이스는 모두 인증이 필요 없어 문제가 안 되지만, 해당 케이스를 만나면 `NotImplementedError`를 던지도록 명시적으로 막아뒀습니다.
- `payload_profile`(AI가 안정적인 `payload_case_id`를 부여해 생성하는 방식)은 아직 합의되지 않아 이번 구현에서 완전히 배제했습니다. 대신 고정된 소규모 페이로드 목록을 기본값으로 사용합니다.

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
  "case_id": "xss-discover-reflected::script-basic",
  "finding_id": "XSS-000001",
  "scanned_at": "2026-08-27T09:30:10+09:00",
  "vuln_type": "XSS",
  "scan": {
    "status": "COMPLETED",
    "request": {"url": "http://127.0.0.1:5000/discover", "method": "GET", "input_location": "query", "parameter": "q", "payload": "<script>alert(1)</script>"},
    "response": {"http_status": 200, "elapsed_ms": 12, "baseline_elapsed_ms": null, "evidence_summary": "...", "html_path": "responses/XSS-000001.html"},
    "rule": {"label": "SUSPECTED", "reason": "..."},
    "error": null
  }
}
```

- `case_id`는 `<매니페스트 case_id>::<payload_case_id>` 형태입니다(계약 11.3). 매니페스트의 `case_id`는 (대상 경로, 파라미터, 메서드)에 대해 실행마다 바뀌지 않습니다.
- `rule.label`은 계약이 정한 `SUSPECTED`/`SAFE`/`null` 세 값만 사용합니다. 내부적으로는 더 세분화된 판정(그대로 반사/이스케이프되어 반사/저장 확인됨/반사 안 됨, `scanners/xss_rules.py`)을 쓰지만, 그 세부 내용은 `rule.reason`과 `response.evidence_summary` 텍스트로 남기고 공개 필드는 계약값으로 압축합니다.
- 요청 자체가 실패하면(타임아웃 등) `scan.status="FAILED"`이고 `response`/`rule`은 모두 `null`, `error`에 `{code, message, retryable}`이 채워집니다. 실패한 시도도 삭제하지 않고 그대로 기록합니다.

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
