# NovaStream Vulnerable Lab

자동화 스캐너의 SQL Injection, Reflected XSS, Stored XSS 탐지를 검증하기 위한
가상 OTT 콘텐츠 카탈로그입니다. 실제 서비스가 아니라 격리된 교육·테스트
환경에서만 사용합니다.

## 제공 기능

| 기능 | 경로 | 의도된 취약점 |
|---|---|---|
| 콘텐츠 DB 검색 | `GET /catalog?q=` | SQL Injection |
| 키워드 탐색 | `GET /discover?q=` | Reflected XSS |
| 리뷰 등록 | `POST /titles/<id>/reviews` | Stored XSS 입력 저장 |
| 운영자 리뷰 검토 | `GET /admin/reviews` | Stored XSS 실행 지점 |
| 상태 확인 | `GET /health` | 스캐너 헬스 체크 |

일반 콘텐츠 상세 화면은 리뷰를 HTML escape하지만 운영자 검토 화면은 교육
목적으로 의도적으로 escape하지 않습니다. 실제 데이터나 계정을 입력하지 마세요.

## 로컬 실행

저장소 루트에서 Git Bash를 사용합니다.

```bash
python -m venv .venv
source .venv/Scripts/activate
python -m pip install -r lab_app_2/requirements.txt
python -m lab_app_2.app
```

기본 주소는 `http://127.0.0.1:5000`입니다.

## 테스트

```bash
python -m pytest tests/test_lab_app_2.py -q
```

## MySQL 전환

현재 기본값은 `sqlite:///lab_app_2/novastream.db`입니다. RDS for MySQL로
옮길 때는 애플리케이션 코드를 바꾸지 않고 `LAB2_DATABASE_URL`을 설정합니다.

```text
mysql+pymysql://DB_USER:DB_PASSWORD@RDS_ENDPOINT:3306/DB_NAME
```

RDS에는 전용 최소 권한 DB 사용자를 만들고, 비밀번호나 실제 엔드포인트를
저장소에 커밋하지 않습니다.
