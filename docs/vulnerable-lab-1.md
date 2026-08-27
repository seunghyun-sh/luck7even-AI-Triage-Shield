# Lumi Market 취약 웹 환경 1 안내

`lab_app/`은 환경구축팀의 첫 번째 Flask·SQLite 교육용 웹서비스입니다.
일반 쇼핑몰처럼 보이도록 구성했으며 메인 화면에는 취약점 선택 메뉴를 노출하지 않습니다.
자동화팀은 아래 고정 경로와 입력 규격을 사용합니다.

## 1번 환경 식별 규칙

| 구분 | 1번 환경 |
| --- | --- |
| 애플리케이션 폴더 | `lab_app/` |
| 상세 문서 | `docs/vulnerable-lab-1.md` |
| 전용 테스트 | `tests/test_lab_app_1.py` |
| 기본 포트 | `5001` |
| 환경변수 접두사 | `LAB_1_` |
| SQLite 파일 | `lab_app/instance/lumi_market_1.sqlite3` |
| 초기화 API | `POST /internal/lab-1/reset` |

앱 폴더 자체가 구분 경계이므로 `lab_app/` 안에서는 `app.py`, `README.md`,
`requirements.txt`, `Dockerfile`처럼 접미사 없는 일반 파일명을 사용합니다.

## 서비스 페이지

| 기능 | 경로 |
| --- | --- |
| 홈 | `/` |
| 상품 목록·카테고리 | `/products` |
| 상품 상세 | `/products/<id>` |
| 통합검색 | `/search?q=` |
| 장바구니 | `/cart` |
| 로그인 | `/account/login` |
| 회원가입 | `/account/register` |
| 마이페이지 | `/account` |
| 구매후기 | `/reviews` |
| 고객센터 | `/support` |
| 상태 확인 | `/health` |

## 자동화팀 테스트 대상

| ID | 취약점 | Method | 경로 | 입력 위치 | 재현 특성 |
| --- | --- | --- | --- | --- | --- |
| XSS-01 | Reflected XSS | GET | `/search` | Query `q` | 검색 요약 영역에 HTML 인코딩 없이 출력 |
| XSS-02 | Stored XSS | POST 후 GET | `/reviews` | Form `content` | SQLite 저장 후 후기 본문에 인코딩 없이 출력 |
| SQLI-01 | 로그인 SQL Injection | POST | `/account/login` | Form `username`, `password` | 입력을 로그인 SQL 문자열에 직접 결합 |
| SQLI-02 | 검색 SQL Injection | GET | `/search` | Query `q` | 입력을 상품 검색 SQL 문자열에 직접 결합하고 DB 오류 노출 |

데이터베이스 엔진은 SQLite입니다. 자동화 페이로드는 MySQL 전용 함수 대신 SQLite에서
지원되는 문법과 응답 차이를 기준으로 구성해야 합니다.

## 로컬 실행

저장소 최상위 폴더에서 실행합니다.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r lab_app\requirements.txt
.\.venv\Scripts\python.exe -m lab_app.app
```

브라우저에서 `http://127.0.0.1:5001`로 접속합니다.

## DB 초기화

로컬에서 가장 간단한 초기화 방법은 다음 명령입니다.

```powershell
.\.venv\Scripts\python.exe -m flask --app lab_app.app init-db
```

자동화된 반복 진단에서는 `LAB_1_RESET_TOKEN`을 설정한 뒤 다음 API를 사용할 수 있습니다.

- Method: `POST`
- 경로: `/internal/lab-1/reset`
- 헤더: `X-Lab-1-Reset-Token: <LAB_1_RESET_TOKEN 값>`

SQLite 파일은 `lab_app/instance/lumi_market_1.sqlite3`에 생성되며 `*.sqlite3`
무시 규칙에 따라 Git에 포함되지 않습니다.

## 안전 수칙

- 팀이 소유하거나 명시적으로 허가받은 격리 환경에서만 실행합니다.
- AWS 배포 시 웹 포트를 실습 참여자와 자동화 서버 IP로 제한합니다.
- 실제 개인정보, 운영 계정, 비밀키를 입력하거나 커밋하지 않습니다.
- 발표와 검증 종료 후 인스턴스를 중지하거나 삭제합니다.
