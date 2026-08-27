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
│   ├── xss.py             # 공개 진입점: scanners.xss.scan (main.py가 찾는 경로)
│   ├── base.py            # 공용 HTTP 헬퍼(같은 호스트로만 리다이렉트 추적 등)
│   ├── payload_cache.py   # payload_profile별 페이로드 캐시 파일 입출력(순수 I/O)
│   ├── payload_profiles.py # 런타임 스캐너용 payload_profile 로더 (OpenAI 호출 없음)
│   ├── tools/
│   │   └── generate_xss_payload_profile.py  # AI 페이로드 생성(사람이 직접 실행하는 오프라인 도구)
│   ├── xss_rules.py       # 반사 여부 내부 판정 로직
│   ├── xss_report.py      # 내부 판정 -> canonical RawFinding 조립 + sidecar 저장
│   └── pipeline/
│       └── xss.py         # scan(targets, context, on_progress)의 실제 구현
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

### 4-1. 파이프라인용 XSS 스캐너 (`scanners.xss.scan`)

`main.py`(통합 담당)의 `orchestration.PipelineOrchestrator`가 실제로 호출하는 진입점입니다. 시그니처는 팀 실행 계약이 정의한 대로입니다.

```python
def scan(targets: list[TargetCase], context: ScanContext, on_progress: ProgressCallback) -> list[RawFinding]:
```

`scanners/xss.py`는 실제 구현이 있는 `scanners/pipeline/xss.py`의 `scan`을 그대로 재수출합니다. `ScanContext`는 `orchestration` 패키지(통합 담당 소유, `feature/dashboard-contracts`)가 제공하며 `scan_run_id`, registry에서 재검증된 `base_url`, `request_policy`(timeout·redirect 정책), `responses_dir`, `resolve_auth_profile()`을 담고 있습니다. 이 스캐너는 파일 경로나 호스트를 스스로 계산하지 않고 전부 `context`에서 받습니다.

각 실습 환경에서 **실제로 XSS 취약점이 확인된 페이지·입력칸만** 대상으로 하며, 페이로드를 어느 파라미터에 넣어야 하는지는 타겟 매니페스트 JSON에 정확히 명시되어 있습니다.

| 환경 | target_set_id | 매니페스트 | 케이스 |
| --- | --- | --- | --- |
| 1번 (Lumi Market) | `lumi-market-1` | `configs/lumi_market_1_xss_targets.example.json` | Reflected: `GET /search` query `q` · Stored: `POST /reviews` form `content` (같은 `/reviews`에서 확인) |
| 2번 (NovaStream) | `novastream-2` | `configs/novastream_2_xss_targets.example.json` | Reflected: `GET /discover` query `q` · Stored: `POST /titles/1/reviews` form `body` (다른 페이지 `GET /admin/reviews`에서 확인) |

두 매니페스트 모두 `configs/target-registry.json`에 등록되어 있고(등록된 `base_url`과 매니페스트 자체의 `base_url`이 정확히 일치해야 함), 지금은 로컬 주소를 가리킵니다. 이후 서버에 배포되면 이 두 값을 실제 서버 주소로 갱신하면 됩니다.

**AI 페이로드 생성은 런타임과 분리되어 있습니다.** 실행 계약은 "런타임 스캐너는 OpenAI API를 호출하지 않는다"고 명시합니다. 그래서 페이로드 생성은 사람이 직접 실행하는 별도 도구로 뺐습니다.

```bash
python -m scanners.tools.generate_xss_payload_profile --profile xss-v1 --count 100
```

이 명령은 `data/raw/payload_profiles/xss-v1.json`(Git 제외)에 실제 공격 페이로드와 오탐 유도용 무해한 텍스트를 절반씩 섞어 저장하고, 각 항목에 안정적인 `payload_case_id`(`ai-001`, ...)를 붙입니다. **생성 후에는 이 파일을 사람이 열어 후보를 검토**해야 합니다(필요하면 직접 수정/삭제). 이미 파일이 있으면 `--force` 없이는 덮어쓰지 않습니다. 두 매니페스트 모두 `payload_profile: "xss-v1"`을 쓰므로 한 번만 생성하면 두 환경이 공유합니다.

런타임 스캐너(`scanners/payload_profiles.py`)는 이 파일이 없거나 손상되면 `PayloadProfileMissingError`를 던지고 멈춥니다 -- AI를 대신 호출하거나 임의 값으로 조용히 계속 실행하지 않습니다.

로컬에서 직접 확인해보려면(main.py/orchestration 통합 전 임시 실행 경로 -- `orchestration.ScanContext`와 같은 모양의 로컬 대역을 직접 만들어 `scan()`을 호출함):

```bash
python -m scanners.pipeline.xss --targets configs/lumi_market_1_xss_targets.example.json
python -m scanners.pipeline.xss --targets configs/novastream_2_xss_targets.example.json
```

(`--base-url`을 추가로 주면 매니페스트 자체의 `base_url` 대신 그 주소로 실행합니다. 아직 로컬에서 `pip install`할 수 있는 `orchestration` 패키지가 이 브랜치엔 없으므로, main.py/orchestration과 실제로 통합된 뒤에는 이 CLI 대신 `scanners.xss.scan`을 직접 import해서 씁니다.)

**계약을 따르며 실용적으로 채운 부분** (통합 담당과 추후 확인 필요):

- Stored XSS 2단계 검증 여부는 `target.manual_verification_profile == "xss-stored"` 네이밍 규칙으로 판단합니다. `TargetCase`에는 이를 위한 전용 필드가 없어서(계약에 없는 필드는 추가할 수 없음), 원래 자유 문자열인 `manual_verification_profile` 값을 규칙으로 재사용했습니다.
- 작성 페이지와 조회 페이지가 다른 경우(NovaStream)의 조회 경로는 `scanners/pipeline/xss.py`의 `KNOWN_VERIFY_PATHS`(case_id -> 조회 경로) 조회 표로 해결합니다. 마찬가지로 `TargetCase` 확장 없이 스캐너 쪽에서만 아는 정보로 처리했습니다.
- `resolve_auth_profile()`이 반환하는 값은 HTTP 헤더로 간주해 요청에 그대로 병합합니다. 계약 문서가 정확한 반환 형태를 명시하지 않아 가장 보편적인 해석을 취했습니다. 현재 모든 타겟이 `requires_pre_auth: false`라 이 경로를 실제로 타는 케이스는 아직 없습니다.

#### 결과 데이터 모델 (canonical `analysis.models`)

이 스캐너의 출력(`RawFinding`)은 `analysis/models.py`의 canonical pydantic 모델을 그대로 씁니다(별도 모델을 만들지 않음). 응답 본문 전체는 JSON에 넣지 않고 `context.responses_dir/<finding_id>.html`에 sidecar 파일로 저장하며(쿠키·인증 헤더·비밀번호로 보이는 패턴은 저장 전 마스킹), `findings.json` 게시 자체는 스캐너가 하지 않고 `orchestration.RunStore`가 XSS·SQLi 결과를 합쳐서 원자적으로 게시합니다.

RawFinding 1건 = 요청 1번:

```json
{
  "case_id": "nova-discover-reflected::ai-001",
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

- `case_id`는 `<매니페스트 case_id>::<payload_case_id>` 형태입니다. 매니페스트의 `case_id`는 실행마다 바뀌지 않고, `payload_case_id`는 payload_profile 안에서 안정적입니다.
- `rule.label`은 `RuleLabel.SUSPECTED`/`RuleLabel.SAFE`/`null`만 씁니다. 내부적으로는 더 세분화된 판정(그대로 반사/이스케이프되어 반사/저장 확인됨/반사 안 됨, `scanners/xss_rules.py`)을 쓰지만, 세부 내용은 `rule.reason`과 `response.evidence_summary` 텍스트로 남기고 공개 필드는 계약값으로 압축합니다.
- 요청 자체가 실패하면(타임아웃, 연결 실패 등) `scan.status="FAILED"`이고 `response`/`rule`은 모두 `null`, `error`에 `{code, message, retryable}`이 채워집니다. 실패한 시도도 삭제하지 않고 그대로 기록합니다.
- 대상 경로가 **404**를 반환하면(주입 지점 자체가 없음) `SAFE`로 판정하지 않고 위와 같은 실패 Finding(`error.code="SCAN_TARGET_NOT_FOUND"`)으로 보존합니다. 스캐너 통합 계약 변경 안내(8·9장) 요구사항으로, 테스트가 실제로 수행되지 않았는데 안전하다고 오판(거짓 음성)하는 것을 막기 위함입니다.

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
