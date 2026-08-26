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
│   └── xss.py             # XSS 스캔 오케스트레이션(로그인 → 스캔 → CSV)
├── tests/                 # 자동화 테스트
├── .env.example
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

```bash
cp .env.example .env
```

`.env`의 `OPENAI_API_KEY`, `OPENAI_MODEL`, `XSS_LAB_HOST`, `XSS_LAB_LOGIN`, `XSS_LAB_PASSWORD`를 설정합니다. API 키, 비밀번호, 세션 키는 커밋하지 않습니다.

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
- `--output`: 결과 CSV 저장 경로 (기본 `data/raw/raw-findings-xss-multi.csv`)

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
