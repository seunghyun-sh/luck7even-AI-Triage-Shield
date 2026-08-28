# Lumi Market — 취약 웹 환경 1

환경구축팀 첫 번째 담당자의 Flask·MySQL 웹 애플리케이션입니다. 실제 쇼핑몰처럼
동작하는 화면 안에 XSS 3종과 SQL Injection 3종을 의도적으로 구성했습니다.

## 담당 파일 범위

- 애플리케이션 전체: `lab_app/`
- 상세 명세: `docs/vulnerable-lab-1.md`
- 구현 계획: `docs/vulnerable-lab-1-implementation-plan.md`
- 전용 테스트: `tests/test_lab_app_1.py`

루트 `README.md`, 루트 `.env.example`, 루트 `requirements.txt`, `.gitignore`,
`configs/`, 루트 `docker-compose.yml`은 공용 파일이므로 통합 담당자가 관리합니다.

## Kali Docker 실행

저장소 최상위 폴더에서 실행합니다.

처음 clone한 환경에는 Git에서 제외되는 `.env`가 없으므로 예제 파일을 복사하고 로컬
실습용 값을 설정합니다. 현재 공유 폴더에는 이 파일이 이미 생성되어 있습니다.

```bash
cp lab_app/.env.example lab_app/.env
```

```bash
sudo docker compose -f lab_app/compose.yml up --build
```

최초 실행 시 Docker가 다음 작업을 자동으로 수행합니다.

1. MySQL 8.0 이미지를 준비합니다.
2. `schema_mysql.sql`과 `seed_mysql.sql`로 테이블·더미 데이터를 생성합니다.
3. Flask 이미지를 빌드합니다.
4. MySQL이 정상 상태가 된 후 Flask를 5001번 포트에서 실행합니다.

취약 모드 주소는 `http://<Kali-IP>:5001`입니다. Windows 호스트에서 접속할 때는
`127.0.0.1` 대신 Kali의 IP를 사용합니다.

로그 확인과 종료 명령은 다음과 같습니다.

```bash
sudo docker compose -f lab_app/compose.yml ps
sudo docker compose -f lab_app/compose.yml logs -f web-1
sudo docker compose -f lab_app/compose.yml down
```

## 안전 비교 모드 동시 실행

안전 비교 컨테이너까지 함께 실행하려면 `safe` profile을 사용합니다.

```bash
sudo docker compose -f lab_app/compose.yml --profile safe up --build
```

- 취약 모드: `http://<Kali-IP>:5001`
- 안전 모드: `http://<Kali-IP>:5101`

두 컨테이너는 동일한 UI·코드·MySQL 데이터를 사용하며 시큐어 코딩 적용 여부만 다릅니다.

## 데이터 초기화

공격 테스트 후 후기·문의·계정 등을 최초 더미 데이터 상태로 되돌립니다.

```bash
sudo docker compose -f lab_app/compose.yml exec web-1 \
  flask --app lab_app.app reset-db
```

자동화팀은 기본 로컬 토큰을 변경한 뒤 내부 API를 사용할 수 있습니다.

```bash
curl -X POST http://<Kali-IP>:5001/internal/lab-1/reset \
  -H "X-Lab-1-Reset-Token: <설정한 토큰>"
```

MySQL volume까지 완전히 삭제하는 명령은 다음과 같습니다. 이 명령은 로컬 실습 데이터를
모두 제거하므로 일반적인 반복 테스트에서는 사용하지 않습니다.

```bash
sudo docker compose -f lab_app/compose.yml down -v
```

## Docker를 사용하지 않는 단위 테스트

Windows Codex 환경에서는 SQLite 호환 모드로 빠른 단위 테스트를 실행할 수 있습니다.
실제 제출·자동화 검증 환경은 Docker MySQL입니다.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r lab_app\requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest tests\test_lab_app_1.py -q
```

## 2번 환경과 겹치지 않는 기준

| 구분 | 이 앱(1번) | 다른 팀원 앱(2번) |
| --- | --- | --- |
| 앱 폴더 | `lab_app/` | `lab_app_2/` |
| 문서 | `vulnerable-lab-1.md` | `vulnerable-lab-2.md` |
| 테스트 | `test_lab_app_1.py` | `test_lab_app_2.py` |
| 취약 모드 포트 | `5001` | `5000` |
| 안전 모드 포트 | `5101` | `5100` 권장 |
| 환경변수 | `LAB_1_*` | `LAB_2_*` |
| 초기화 API | `/internal/lab-1/reset` | `/internal/lab-2/reset` |

## 안전 수칙

- 팀이 소유하거나 명시적으로 허가받은 격리 환경에서만 실행합니다.
- AWS 웹 포트는 실습 참여자와 자동화 서버 IP로 제한합니다.
- MySQL 3306 포트를 인터넷에 공개하지 않습니다.
- 실제 개인정보·운영 계정·비밀키를 사용하거나 Git에 커밋하지 않습니다.
- 발표와 검증 종료 후 EC2와 RDS를 중지하거나 삭제합니다.
