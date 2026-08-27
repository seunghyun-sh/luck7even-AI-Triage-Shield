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

## Docker 실행

Kali의 공유 폴더에서 `lab_app_2`로 이동한 뒤 이미지를 빌드합니다.

```bash
sudo docker build -t novastream-lab:local .
```

로컬 SQLite 데이터를 Docker 볼륨에 보존하면서 실행합니다.

```bash
sudo docker run --rm \
  --name novastream-lab \
  -p 5000:5000 \
  -v novastream-data:/data \
  novastream-lab:local
```

브라우저에서 `http://127.0.0.1:5000/health`를 열어 상태를 확인합니다.
코드를 수정한 뒤에는 이미지를 다시 빌드해야 변경사항이 반영됩니다.

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

Docker 이미지는 DB를 포함하지 않습니다. EC2에서 실행할 때 RDS 연결 문자열을
환경변수 파일로 전달합니다. 아래 파일은 EC2에만 만들고 GitHub에 올리지 않습니다.

```dotenv
# .env.aws
LAB2_DATABASE_URL=mysql+pymysql://DB_USER:DB_PASSWORD@RDS_ENDPOINT:3306/DB_NAME
LAB2_SECRET_KEY=replace-with-a-long-random-value
```

```bash
chmod 600 .env.aws
sudo docker run --rm \
  --name novastream-lab \
  --env-file .env.aws \
  -p 5000:5000 \
  novastream-lab:local
```

RDS의 데이터베이스 자체는 미리 생성해야 합니다. 현재 앱은 최초 실행 때 테이블과
샘플 콘텐츠를 자동 생성하므로 초기 구성에 사용하는 DB 사용자에게는 해당
데이터베이스 범위의 `CREATE`, `SELECT`, `INSERT`, `DELETE` 권한이 필요합니다.
운영 구성이 정해지면 초기화용 사용자와 웹앱용 최소 권한 사용자를 분리할 수 있습니다.

RDS는 Private Subnet에 두고 3306 인바운드를 인터넷에 공개하지 않습니다. RDS
보안 그룹의 3306 인바운드 소스에는 EC2의 보안 그룹만 지정합니다.
