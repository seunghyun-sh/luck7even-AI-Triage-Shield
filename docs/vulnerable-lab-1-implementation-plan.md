# Lumi Market 취약 웹 환경 1 — 구현 계획

## 1. 문서 목적

이 문서는 환경구축팀 1번 담당자의 `lab_app/`을 최종 발표·제출 가능한
**Flask + MySQL + Docker + AWS 기반 취약 웹 환경**으로 발전시키기 위한 실행 계획이다.

핵심 목표는 자동화팀이 반복적으로 진단할 수 있는 현실적인 쇼핑몰을 제공하고,
XSS 3건과 SQL Injection 3건을 명확한 입력·처리·판정 기준으로 재현하는 것이다.

> 이 환경은 팀이 소유하거나 명시적으로 허가받은 격리 실습 환경에서만 사용한다.
> 실제 개인정보·운영 계정·비밀키를 넣지 않으며 발표 종료 후 AWS 자원을 중지하거나 삭제한다.

## 2. 최종 결정 요약

| 항목 | 결정 |
| --- | --- |
| 서비스 콘셉트 | 기존 Lumi Market의 현실적인 쇼핑몰 UI와 일반 사용자 흐름 유지 |
| 기술 스택 | HTML·CSS·JavaScript, Python·Flask, MySQL, Docker Compose, AWS EC2·RDS |
| 취약점 범위 | XSS 3건 + SQL Injection 3건, 총 6건 |
| 정상 기능 | 홈·상품 목록·상세·장바구니·회원가입·마이페이지·고객센터 등은 정상 동작 |
| 비교 방식 | 동일 코드·동일 UI를 `vulnerable` 모드와 `secure` 모드로 각각 실행 |
| 로컬 포트 | 1번 앱 취약 모드 `5001`, 안전 모드 `5101` |
| 팀원 포트 | 2번 앱은 팀원과 합의한 `5000`; 안전 모드는 필요 시 `5100` |
| 외부 포트 | 1차 검증은 `5001`; 최종 시연은 여유가 있을 때 80/443 프록시 적용 |
| DB 구성 | 로컬은 Docker MySQL, AWS는 RDS MySQL. 동일 초기 스키마 파일 사용 |
| 초기화 | 화면에 노출된 관리자 메뉴 대신 CLI와 토큰 기반 내부 초기화 API 사용 |
| AWS 구성 | Public EC2 + Private RDS, RDS 3306은 EC2 Security Group에서만 허용 |
| Git 충돌 방지 | 앱 파일은 `lab_app/`, 문서는 `*-1.md`, 테스트는 `*_1.py`, 환경변수는 `LAB_1_*` |

## 3. 범위와 성공 기준

### 필수 범위

1. 쇼핑몰의 일반적인 화면과 이동 흐름이 자연스럽게 동작한다.
2. MySQL 기준 XSS 3건과 SQL Injection 3건을 의도적으로 재현할 수 있다.
3. 자동화팀이 URL, Method, 파라미터, 성공 판정 근거를 보고 바로 테스트할 수 있다.
4. Docker Compose 한 번으로 Flask와 MySQL을 로컬에서 실행할 수 있다.
5. 테스트 후 DB를 동일한 더미 데이터 상태로 되돌릴 수 있다.
6. EC2의 Flask 컨테이너가 Private RDS MySQL에 연결된다.
7. 취약 모드와 안전 모드에서 같은 요청의 결과 차이를 설명할 수 있다.

### 완료 판정

- 취약 모드: 의도한 6개 항목이 모두 재현되어 `취약 6/6`로 판정된다.
- 안전 모드: 같은 6개 항목이 실행되지 않아 `양호 6/6`로 판정된다.
- `N/A`는 기능이 구현되지 않았거나 테스트 조건이 성립하지 않을 때만 사용한다.
- 일반 페이지가 정상이라는 사실과 취약점 판정은 별도로 기록한다.

## 4. 페이지 구성 원칙

모든 페이지를 취약하게 만들 필요는 없다. 실제 쇼핑몰처럼 대부분의 기능은 정상적으로
동작하고, 자동화 대상이 되는 6개의 입력 지점에만 의도적으로 취약한 데이터 흐름을 둔다.

### 정상 쇼핑몰 기능

- 홈, 상품 목록, 카테고리, 상품 상세
- 장바구니, 회원가입, 마이페이지
- 공지사항, 고객센터 문의 등록
- 상태 확인 `/health`

### 자동화 대상 취약 기능

| ID | 분류 | 쇼핑몰 기능 | 입력 위치 | 취약 모드 핵심 | 안전 모드 핵심 |
| --- | --- | --- | --- | --- | --- |
| XSS-01 | Reflected XSS | 통합 검색 결과 요약 | `GET /search?q=` | 검색어를 응답 HTML에 그대로 출력 | Jinja 기본 이스케이프·출력 인코딩 |
| XSS-02 | Stored XSS | 상품 구매후기 | `POST /reviews`, `content` | DB 저장 후 후기 HTML에 그대로 출력 | 입력은 데이터로 저장하고 출력 시 인코딩 |
| XSS-03 | DOM-based XSS | 고객센터 미리보기 | `GET /support/preview#message=` | JavaScript가 URL fragment를 `innerHTML`에 대입 | `textContent` 등 안전한 DOM API 사용 |
| SQLI-01 | 인증 우회 | 로그인 | `POST /account/login` | 입력값을 인증 SQL 문자열에 직접 결합 | 파라미터 바인딩 |
| SQLI-02 | Boolean-based Blind | 상품 재고 확인 | `GET /products/stock?product_id=` | 참·거짓 조건에 따라 응답 내용이 달라짐 | 정수 검증 + 파라미터 바인딩 |
| SQLI-03 | Time-based Blind | 쿠폰 확인 | `GET /coupon/check?code=` | MySQL 조건식에 의해 통제된 응답 지연 발생 | 파라미터 바인딩 + 제한된 DB 권한 |

XSS 세 항목은 단순히 페이로드 문자열만 바꾸는 것이 아니라
**서버 반사, DB 저장, 브라우저 DOM 처리**라는 서로 다른 데이터 흐름을 보여준다.
Time-based 항목은 실습 부하를 줄이기 위해 1~2초 수준의 지연과 낮은 요청 횟수로 검증한다.

`/search` 하나에 XSS와 SQL Injection을 동시에 넣지 않는다. 한 요청에 여러 취약 원인이
섞이면 자동화팀의 판정과 발표 설명이 모호해지기 때문이다.

## 5. 보안 레벨 재설계

처음 제안한 `AWS 보안설정 X/O`와 `시큐어 코딩 X/O` 조합은 다음처럼 단순화한다.

| 비교 단계 | 애플리케이션 | AWS 인프라 | 목적 |
| --- | --- | --- | --- |
| Baseline | 취약 모드 | 최소 격리 적용 | 자동화팀의 6개 취약점 탐지 대상 |
| Secure Coding | 안전 모드 | Baseline과 동일 | 시큐어 코딩 후 6개 항목이 차단되는지 비교 |
| Defense-in-Depth(선택) | 취약 또는 안전 모드 | WAF·HTTPS 추가 | 시간이 남을 때 보조 통제 효과 확인 |

AWS 인프라 보호는 모든 단계에서 유지한다.

- Security Group: 웹 포트는 실습 참여자·Scanner IP만 허용한다.
- RDS: Private Subnet, Public access 비활성화, 3306은 EC2 Security Group만 소스로 허용한다.
- IAM: EC2가 필요한 AWS API에 접근할 때만 최소 권한 역할을 사용한다.
- 데이터: 더미 계정과 더미 상품만 사용한다.

IAM과 Security Group은 XSS·SQL Injection 페이로드를 직접 막지 않는다. IAM은 AWS 자원
권한을, Security Group은 네트워크 출발지·포트를 통제한다. 필요하면 AWS WAF를 보조 계층으로
추가할 수 있지만, 취약점의 일차 해결책은 출력 인코딩과 파라미터 바인딩이다.

## 6. 코드와 파일 구성

```text
lab_app/
├─ app.py
├─ db.py
├─ schema_mysql.sql
├─ seed_mysql.sql                 # 선택: 스키마와 더미 데이터를 분리할 때
├─ requirements.txt
├─ Dockerfile
├─ Dockerfile.dockerignore
├─ compose.yml
├─ .env.example                  # 실제 비밀번호 없이 변수 이름만 제공
├─ routes/
├─ templates/
├─ static/
└─ README.md

docs/
├─ vulnerable-lab-1.md
└─ vulnerable-lab-1-implementation-plan.md

tests/
└─ test_lab_app_1.py
```

`lab_app/`이라는 상위 경로가 이미 1번 앱을 구분하므로 그 안의 `app.py`, `db.py`,
`Dockerfile`에는 `_1`을 반복해 붙이지 않는다. 폴더 밖에 놓이는 문서·테스트만 `-1` 또는
`_1`을 사용한다. 루트 `README.md`, `.gitignore`, 루트 `docker-compose.yml`, `configs/`는
통합 담당자가 관리한다.

### 환경변수 규칙

```text
LAB_1_SECURITY_MODE=vulnerable
LAB_1_DB_HOST=mysql-1
LAB_1_DB_PORT=3306
LAB_1_DB_NAME=lumi_market_1
LAB_1_DB_USER=lumi_app_1
LAB_1_DB_PASSWORD=로컬_env_또는_배포_환경에서만_설정
LAB_1_RESET_TOKEN=로컬_env_또는_배포_환경에서만_설정
```

실제 값이 든 `.env`, AWS 키, RDS 비밀번호, 고정 공인 IP는 Git에 올리지 않는다.

## 7. MySQL과 Docker 동작 방식

Codex가 `schema_mysql.sql`, `compose.yml`, Flask DB 연결 코드를 저장소에 파일로 만들면
VMware 공유 폴더를 통해 Kali에서도 같은 파일이 바로 보인다. SQL을 매번 터미널에 직접
복사해 넣을 필요는 없다.

### 로컬 Kali

1. `docker compose`가 Flask 이미지와 MySQL 이미지를 준비한다.
2. 빈 MySQL 볼륨이 처음 생성될 때 `schema_mysql.sql`을 초기화 디렉터리에서 실행한다.
3. Flask는 `LAB_1_DB_HOST=mysql-1`로 MySQL 컨테이너에 접속한다.
4. DB 데이터는 Docker volume에 저장되므로 Flask 이미지를 다시 만들어도 유지된다.

### AWS

1. Flask 코드만 Docker 이미지로 만들어 EC2에서 실행한다.
2. MySQL 자체는 Flask 이미지에 넣지 않고 RDS MySQL을 사용한다.
3. `schema_mysql.sql`은 배포 시 1회 실행하는 초기화 명령 또는 스크립트에서 RDS에 적용한다.
4. EC2의 환경변수 `LAB_1_DB_HOST`만 RDS endpoint로 바꾼다.

즉, 로컬과 AWS는 DB 서버의 위치만 다르고 테이블 구조와 Flask 코드는 동일하게 유지한다.
로컬 Docker MySQL의 실제 데이터 파일을 RDS로 복사하지 않고, 스키마·더미 데이터를 다시
초기화한다. 발표용 데이터가 꼭 필요하면 `mysqldump`/복원 절차를 별도로 사용한다.

DB 애플리케이션 계정은 필요한 SELECT·INSERT·UPDATE·DELETE 권한만 부여하고 MySQL root를
Flask 연결 계정으로 사용하지 않는다.

## 8. 초기화 기능

일반 사용자의 화면에는 관리자 메뉴나 취약점 선택 메뉴를 노출하지 않는다.

### 권장 순서

1. 운영자 CLI: `flask reset-db`로 스키마와 더미 데이터를 초기화한다.
2. 자동화팀용 API: `POST /internal/lab-1/reset`을 유지한다.
3. API는 `X-Lab-1-Reset-Token`이 일치할 때만 실행하고, 가능하면 Scanner/팀 IP에서만 접근한다.
4. 토큰이 없거나 틀리면 존재 여부를 드러내지 않도록 404 또는 일반 오류를 반환한다.

Security Group은 URL 경로를 구분하지 못하므로 초기화 API에는 별도의 토큰 검증이 필요하다.
시각적인 관리자 페이지는 내일 12시 이전 필수 범위에서 제외한다.

## 9. Docker·EC2·포트 설계

하나의 EC2에서도 포트가 겹치지 않으면 여러 Flask 컨테이너를 동시에 실행할 수 있다.
웹앱마다 별도 EC2를 만들 필요는 없다.

| 컨테이너 | 권장 호스트 포트 | 내부 Flask 포트 |
| --- | ---: | ---: |
| 팀원 2번 앱 취약 모드 | 5000 | 팀원 설정값 |
| 사용자 1번 앱 취약 모드 | 5001 | 5001 |
| 팀원 2번 앱 안전 모드(선택) | 5100 | 팀원 설정값 |
| 사용자 1번 앱 안전 모드 | 5101 | 5001 |

개발·자동화 연결은 5000/5001을 그대로 사용한다. 최종 발표에서 주소를 깔끔하게 만들 시간이
있으면 Nginx 또는 Application Load Balancer가 외부 80/443을 받고 내부 컨테이너로 전달하게
한다. 443은 도메인과 인증서 준비가 필요하므로 내일 기본 테스트의 선행 조건으로 두지 않는다.

EC2 단위 Security Group 규칙은 그 EC2의 모든 컨테이너에 함께 적용된다. 컨테이너마다
`AWS 보안설정 O/X`를 엄밀히 비교하려면 별도 EC2나 별도 네트워크 구성이 필요하지만,
이번 프로젝트의 XSS·SQL Injection 목표에는 불필요한 복잡도이므로 채택하지 않는다.

## 10. AWS 최종 배치

```text
실습 사용자·자동화 Scanner
          |
          | 허용된 IP에서 웹 포트 접근
          v
Public Subnet
└─ EC2
   ├─ lab_app_2 컨테이너 :5000
   ├─ lab_app 컨테이너   :5001
   └─ 선택: 안전 비교 컨테이너 :5100/:5101
          |
          | MySQL TCP 3306, EC2 SG → RDS SG만 허용
          v
Private Subnet
└─ RDS MySQL
   ├─ lumi_market_1_vulnerable
   └─ 선택: lumi_market_1_secure
```

안전 비교 모드는 같은 RDS 인스턴스 안에서 별도 schema를 사용하면 데이터 초기화와 증거
비교가 쉽다. 단, 내일 P0에서는 `lumi_market_1` 하나만 먼저 완성해도 된다.

## 11. 구현 일정과 우선순위

### P0 — 2026-08-29 12:00 전 기본 테스트 가능 상태

- [ ] 현재 Lumi Market 디자인과 일반 페이지 유지
- [ ] SQLite 접근 코드를 MySQL 연결 계층으로 전환
- [ ] `schema_mysql.sql`과 더미 계정·상품·후기 작성
- [ ] `lab_app/compose.yml`에 Flask + MySQL + volume + health check 구성
- [ ] XSS 3건과 SQL Injection 3건 구현
- [ ] DB 초기화 CLI와 토큰 기반 내부 API 동작
- [ ] Kali에서 Docker Compose 빌드·기동·6개 항목 수동 검증
- [ ] `/health`와 기본 smoke test 통과
- [ ] 자동화팀에 endpoint·parameter·판정표 1차 공유

P0에서는 안전 비교 모드, WAF, HTTPS, 시각적 관리자 페이지보다 **MySQL 기반 취약 6건의
재현성과 반복 초기화**를 우선한다.

### P1 — 2026-08-29 오후~2026-08-30

- [ ] `LAB_1_SECURITY_MODE=secure` 비교 모드 구현
- [ ] 동일 6개 요청이 안전 모드에서 모두 차단되는지 검증
- [ ] EC2 Docker 배포 및 Private RDS 연결
- [ ] 웹 포트·SSH 출발지 제한, RDS public access 비활성화
- [ ] 팀원 앱과 포트·환경변수·DB schema 통합 확인
- [ ] 자동화팀 결과 형식과 초기화 API 연동 확인

### P2 — 2026-08-30~2026-08-31 제출·발표

- [ ] 수동 진단과 자동화 결과 비교표 작성
- [ ] 취약/양호 판정 근거, 대응 방안, N/A 기준 정리
- [ ] AWS 구조도, Docker 흐름, 화면·로그 증거 캡처
- [ ] 실행·배포·초기화 문서와 테스트 계정 명세 완성
- [ ] 최종 시연 순서 연습 및 AWS 자원 종료 계획 확인
- [ ] 시간이 남으면 80/443 프록시 또는 WAF를 선택 구현

## 12. 자동화팀 전달 명세

각 취약점은 다음 필드를 한 줄씩 제공한다.

- ID, 취약점 유형, URL, HTTP Method
- 입력 파라미터와 입력 위치(Query/Form/Fragment)
- 정상 입력 예시와 취약 진단용 입력 유형
- 취약 판정 증거: 응답 반영, DOM 실행, 로그인 결과, 참·거짓 차이, 응답 시간 차이
- 안전 모드 기대 결과
- 초기화 필요 여부와 호출 방법
- 테스트 계정·더미 상품 ID
- 요청 제한 또는 대기 시간

판정값은 `취약`, `양호`, `N/A`, `오류`를 구분한다. 네트워크 오류나 서버 오류를 취약으로
잘못 세지 않도록 HTTP 상태, 응답 본문, 시간 기준을 함께 명시한다.

## 13. 테스트와 증거 수집

### 기능 테스트

- 홈·상품·회원 흐름의 정상 응답
- MySQL 연결 실패 시 명확한 health 상태
- 초기화 전후 동일한 seed 데이터 확인
- 취약 모드 6건 재현
- 안전 모드 6건 비재현

### 발표용 결과표

| ID | 수동 결과 | 자동화 결과 | 취약 모드 근거 | 안전 모드 근거 | 대응 방안 |
| --- | --- | --- | --- | --- | --- |
| XSS-01~03 | 취약/양호 | 취약/양호 | 반영·저장·DOM 실행 | 출력 인코딩·안전 DOM API | 컨텍스트별 인코딩 |
| SQLI-01~03 | 취약/양호 | 취약/양호 | 인증·응답·시간 차이 | 바인딩 후 차이 없음 | Prepared Statement |

## 14. 주요 위험과 대응

| 위험 | 대응 |
| --- | --- |
| MySQL 전환으로 기존 UI 기능이 깨짐 | DB adapter를 먼저 교체하고 기존 route smoke test 수행 |
| 여섯 취약점 구현이 지연됨 | P0는 취약 모드만 우선하고 안전 모드는 P1로 이동 |
| Docker 공유 폴더 권한·캐시 문제 | 빌드 컨텍스트를 `lab_app/`으로 한정하고 생성 파일을 Git에 넣지 않음 |
| 팀원 파일 충돌 | `lab_app/`, `docs/*-1.md`, `tests/*_1.py`만 수정 |
| RDS 연결 실패 | VPC, Private Subnet, RDS SG의 3306 source=EC2 SG, 환경변수 순서로 확인 |
| 공개 취약 서버 악용 | 허용 IP 제한, 더미 데이터, 짧은 운영, 종료 후 EC2/RDS 중지·삭제 |
| 비밀정보 커밋 | `.env` 제외, commit 전 `git diff --staged` 검사 |

## 15. Git 작업 원칙

- 브랜치: 팀 규칙에 따라 `feature/vulnerable-lab`에서 작업한다.
- `main`, `develop`에는 직접 Push하지 않는다.
- Push 전 `git pull --rebase origin feature/vulnerable-lab`로 같은 팀 변경을 반영한다.
- `git add .` 대신 1번 앱 파일만 선택한다.
- 한 커밋에는 하나의 논리적 변경만 넣는다.

권장 커밋 예시:

```text
refactor: lab app 데이터베이스를 MySQL 연결 방식으로 전환
chore: lab app Docker Compose MySQL 환경 추가
feat: XSS 및 SQL Injection 실습 경로 6종 구성
feat: lab app 데이터 초기화 기능 추가
test: lab app MySQL 취약점 재현 테스트 추가
docs: lab app 실행 및 자동화 연동 명세 작성
```

## 16. 구현을 맡길 때 사용할 Codex 프롬프트

```text
현재 저장소의 lab_app/은 현실적인 쇼핑몰 디자인을 가진 Lumi Market Flask 앱이다.
기존 UI와 일반 사용자 흐름을 유지하면서 SQLite를 MySQL로 전환하고, Kali의 Docker
Compose에서 Flask와 MySQL을 함께 실행할 수 있게 구현하라.

필수 조건:
1. 수정 범위는 lab_app/, docs/vulnerable-lab-1.md,
   docs/vulnerable-lab-1-implementation-plan.md, tests/test_lab_app_1.py로 제한한다.
2. 팀원 앱 lab_app_2와 겹치지 않게 기본 포트 5001, 환경변수 접두사 LAB_1_,
   초기화 경로 /internal/lab-1/reset을 사용한다.
3. XSS 3건(Reflected, Stored, DOM-based)과 MySQL SQL Injection 3건
   (로그인 인증 우회, Boolean-based Blind, Time-based Blind)을 서로 다른 기능에 구현한다.
4. 취약 모드는 LAB_1_SECURITY_MODE=vulnerable, 안전 비교 모드는 secure로 동작하게 한다.
5. MySQL schema/seed 파일, compose.yml, .env.example을 파일로 생성한다.
   실제 비밀번호와 AWS 정보는 커밋하지 않는다.
6. 초기화는 flask reset-db CLI와 토큰 기반 POST /internal/lab-1/reset으로 제공한다.
7. 먼저 P0 범위인 MySQL 취약 모드 6건, 초기화, health check, smoke test를 완성하고
   검증한 뒤 안전 모드를 구현한다.
8. 각 취약점의 URL, Method, 파라미터, 취약/양호 판정 기준을 문서화한다.
9. 기존 사용자 변경을 보존하고 Git commit/push는 하지 않는다.
10. 팀 소유의 격리된 실습 환경에서만 동작하도록 안전 수칙을 문서화한다.
```

## 17. 참고 기준

- 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드의 웹 애플리케이션 항목 중
  SQL Injection과 XSS의 기본 판정 개념만 참고한다.
- AWS 공식 문서:
  - [EC2 Security Group](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/creating-security-group.html)
  - [EC2 IAM Role](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html)
  - [RDS public/private access](https://docs.aws.amazon.com/AmazonRDS/latest/gettingstartedguide/security-public-private.html)
  - [RDS Security Group](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.RDSSecurityGroups.html)
  - [AWS WAF managed rules](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-use-case.html)
