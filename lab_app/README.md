# Lumi Market — 취약 웹 환경 1

환경구축팀 첫 번째 담당자의 Flask·SQLite 웹 애플리케이션입니다. 이 폴더 안 파일은
상위 폴더 `lab_app/`으로 이미 구분되므로 파일명에 `_1`을 반복해서 붙이지 않습니다.

## 담당 파일 범위

- 애플리케이션 전체: `lab_app/`
- 상세 문서: `docs/vulnerable-lab-1.md`
- 전용 테스트: `tests/test_lab_app_1.py`

루트 `README.md`, 루트 `.env.example`, 루트 `requirements.txt`, `.gitignore`,
`configs/`, `docker-compose.yml`, `tests/test_smoke.py`는 공용 파일이므로 통합 담당자가 관리합니다.

## 로컬 실행

저장소 최상위 폴더에서 다음 명령을 실행합니다.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r lab_app\requirements.txt
.\.venv\Scripts\python.exe -m lab_app.app
```

접속 주소는 `http://127.0.0.1:5001`입니다.

## Docker 실행

Docker 빌드 컨텍스트는 저장소 최상위 폴더입니다.

```powershell
docker build -f lab_app/Dockerfile -t vulnerable-lab-1 .
docker run --rm -p 127.0.0.1:5001:5001 --name vulnerable-lab-1 vulnerable-lab-1
```

## 2번 환경과 겹치지 않는 기준

| 구분 | 이 앱(1번) | 다른 팀원 권장값(2번) |
| --- | --- | --- |
| 앱 폴더 | `lab_app/` | `lab_app_2/` |
| 문서 | `vulnerable-lab-1.md` | `vulnerable-lab-2.md` |
| 테스트 | `test_lab_app_1.py` | `test_lab_app_2.py` |
| 포트 | `5001` | `5002` |
| 환경변수 | `LAB_1_*` | `LAB_2_*` |
| DB 파일 | `lumi_market_1.sqlite3` | 팀원 앱 전용 `_2.sqlite3` 파일 |
| 초기화 API | `/internal/lab-1/reset` | `/internal/lab-2/reset` |

취약점 경로와 자동화팀 입력 규격은 `docs/vulnerable-lab-1.md`를 확인합니다.
