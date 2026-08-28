# Lumi Market 취약 웹 환경 1 기술 명세

`lab_app/`은 환경구축팀 1번 담당자의 Flask·MySQL 교육용 쇼핑몰입니다. 메인 화면에는
취약점 선택 메뉴를 노출하지 않으며, 자동화팀은 아래 고정 경로와 입력 규격을 사용합니다.

## 환경 식별

| 구분 | 값 |
| --- | --- |
| 애플리케이션 폴더 | `lab_app/` |
| Docker Compose | `lab_app/compose.yml` |
| 취약 모드 포트 | `5001` |
| 안전 모드 포트 | `5101` |
| 환경변수 접두사 | `LAB_1_*` |
| DB 엔진 | MySQL 8.0 |
| DB 이름 | `lumi_market_1` |
| 초기화 API | `POST /internal/lab-1/reset` |

## 일반 서비스 페이지

| 기능 | 경로 |
| --- | --- |
| 홈 | `/` |
| 상품 목록·카테고리 | `/products` |
| 상품 상세 | `/products/<id>` |
| 통합검색 | `/search?q=` |
| 상품 재고 API | `/products/stock?product_id=` |
| 장바구니 | `/cart` |
| 쿠폰 확인 | `/coupon/check?code=` |
| 로그인·회원가입·마이페이지 | `/account/*` |
| 구매후기 | `/reviews` |
| 고객센터 | `/support` |
| 문의 미리보기 | `/support/preview#message=` |
| 상태 확인 | `/health` |

## 자동화팀 테스트 대상 6종

| ID | 분류 | Method | 경로 | 입력 | 취약 판정 핵심 |
| --- | --- | --- | --- | --- | --- |
| XSS-01 | Reflected XSS | GET | `/search` | Query `q` | 검색 요약에서 입력 HTML이 인코딩 없이 반사되고 브라우저에서 실행됨 |
| XSS-02 | Stored XSS | POST 후 GET | `/reviews` | Form `content` | MySQL 저장 후 후기 본문에서 입력 HTML이 실행됨 |
| XSS-03 | DOM-based XSS | GET/브라우저 | `/support/preview` | URL fragment `message` | JavaScript가 fragment 값을 `innerHTML`에 넣어 브라우저에서 실행됨 |
| SQLI-01 | 로그인 인증 우회 | POST | `/account/login` | Form `username`, `password` | 조건식 변조 후 정상 비밀번호 없이 로그인됨 |
| SQLI-02 | Boolean-based Blind | GET | `/products/stock` | Query `product_id` | 참·거짓 조건에 따라 JSON의 `available` 값이 달라짐 |
| SQLI-03 | Time-based Blind | GET | `/coupon/check` | Query `code` | MySQL 조건식에 따라 응답 시간이 통제된 범위에서 증가함 |

DOM-based XSS의 fragment는 HTTP 요청으로 서버에 전송되지 않습니다. 따라서 Python
`requests`만으로는 실행 여부를 판정할 수 없으며 Playwright 또는 Selenium 같은 브라우저
자동화가 필요합니다.

## 취약 모드와 안전 모드

| 항목 | 취약 모드 `5001` | 안전 모드 `5101` |
| --- | --- | --- |
| Reflected·Stored XSS | HTML을 인코딩 없이 출력 | Jinja 출력 인코딩 |
| DOM XSS | `innerHTML` 사용 | `textContent` 사용 |
| 로그인 SQLi | SQL 문자열 직접 결합 | 파라미터 바인딩 |
| Boolean Blind SQLi | 숫자 표현식 직접 결합 | 정수 검증 + 바인딩 |
| Time Blind SQLi | 쿠폰 문자열 직접 결합 | 파라미터 바인딩 |

취약 모드는 6개 항목을 `취약`으로, 안전 모드는 같은 6개 항목을 `양호`로 판정하는 것이
기대 결과입니다. 기능이 존재하고 공격이 차단된 경우는 `N/A`가 아니라 `양호`입니다.

## 실행과 초기화

```bash
sudo docker compose -f lab_app/compose.yml up --build
sudo docker compose -f lab_app/compose.yml --profile safe up --build
sudo docker compose -f lab_app/compose.yml exec web-1 \
  flask --app lab_app.app reset-db
```

초기화 API:

- Method: `POST`
- 경로: `/internal/lab-1/reset`
- 헤더: `X-Lab-1-Reset-Token: <LAB_1_RESET_TOKEN 값>`
- 성공 응답: `200 {"status":"reset"}`
- 토큰 누락·불일치: `404`

## MySQL 초기 데이터

- 테스트 계정: `admin`, `analyst`, `guest`
- 대표 상품 ID: `1`~`8`
- 정상 쿠폰: `WELCOME10`, `LUMI20`
- 초기 후기: 3건

비밀번호와 토큰의 실제 배포값은 자동화팀에 별도 안전한 채널로 전달하고 Git에는 커밋하지
않습니다.

## 판정 공통 규칙

- `취약`: 의도한 실행·인증 변화·응답 차이·시간 차이가 반복 확인됨
- `양호`: 동일 입력을 시도했으나 인코딩·검증·바인딩으로 차단됨
- `N/A`: 기능이 없거나 사전 조건이 성립하지 않아 진단할 수 없음
- `오류`: 네트워크 단절, 서버 장애, 예상하지 않은 5xx 등으로 판정할 수 없음

## 안전 수칙

- 팀 소유의 격리된 실습 환경에서만 진단합니다.
- AWS 배포 시 웹 포트는 팀·Scanner IP로 제한합니다.
- RDS는 Private Subnet에 배치하고 3306은 EC2 Security Group에서만 허용합니다.
- 실제 개인정보, 운영 계정, 비밀키를 사용하지 않습니다.
- Time-based 테스트는 1~2초와 낮은 요청 횟수로 제한합니다.
- 발표 종료 후 EC2와 RDS를 중지하거나 삭제합니다.
