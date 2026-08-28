# NovaStream Weak-Defense Lab

자동화 스캐너의 SQL Injection, Reflected XSS, Stored XSS 탐지를 검증하기 위한
가상 OTT 콘텐츠 카탈로그입니다. 단순 문자열 블랙리스트가 적용되어 있지만
의도적으로 우회 가능한 교육용 환경입니다. 인터넷에 공개하거나 실제 데이터와
계정을 입력하지 마세요.

## 이번 보강 내역

- 일반 사용자·운영자 로그인과 로그아웃, 세션 기반 역할 구분을 추가했습니다.
- 운영자만 `/admin`과 `/admin/reviews`에 접근할 수 있도록 변경했습니다.
- 콘텐츠 검색과 로그인에 의도적으로 우회 가능한 SQLi 블랙리스트를 추가했습니다.
- Reflected XSS와 Stored XSS 입력에 소문자 `script` 1회 제거 필터를 추가했습니다.
- `users`, `subscribers`, `lab_flags` 테이블과 가짜 초기 데이터를 추가했습니다.
- SQLite 기본 실행을 유지하면서 환경변수로 RDS MySQL을 선택할 수 있게 했습니다.
- 로그인, 접근 제어, 필터 차단·우회, FLAG 추출, XSS 저장·출력을 자동 테스트합니다.

## 제공 기능

| 기능 | 경로 | 의도된 취약점 |
|---|---|---|
| 콘텐츠 DB 검색 | `GET /catalog?q=` | 약한 블랙리스트 + SQL Injection |
| 로그인 | `POST /login` | 약한 블랙리스트 + SQL Injection 인증 우회 |
| 키워드 탐색 | `GET /discover?q=` | 약한 `script` 제거 + Reflected XSS |
| 리뷰 등록 | `POST /titles/<id>/reviews` | 약한 `script` 제거 + Stored XSS 저장 |
| 운영자 리뷰 검토 | `GET /admin/reviews` | Stored XSS 실행 지점 |
| 상태 확인 | `GET /health` | 스캐너 헬스 체크 |

일반 콘텐츠 상세 화면은 리뷰를 HTML escape하지만 운영자 검토 화면은 교육
목적으로 의도적으로 escape하지 않습니다.

## 실습 계정과 데이터

모든 값은 가짜 데이터입니다.

| 역할 | 아이디 | 비밀번호 |
|---|---|---|
| 일반 사용자 | `viewer` | `viewer123` |
| 운영자 | `admin` | `admin123` |

DB에는 정상 화면에서 전체 조회할 수 없는 `subscribers`와 `lab_flags` 테이블도
생성됩니다. 데이터 추출형 SQLi 스캐너의 성공 여부는 다음 값으로 검증할 수 있습니다.

```text
FLAG{NOVASTREAM_SQLI_EXTRACTION_SUCCESS}
```

## 의도적으로 약한 필터

SQLi 입력은 일반 ASCII 공백 한 칸과 대문자 `UNION`, `SELECT`만 차단합니다.
대소문자 변형과 탭·줄바꿈 같은 다른 구분 문자를 정규화하지 않습니다.

XSS 입력은 소문자 `script`를 한 번의 치환 과정으로 제거한 뒤 다시 검사하지
않습니다. 대소문자 변형, 겹친 문자열, 다른 실행 가능한 HTML 구조를 막지 못합니다.
이 필터들은 실제 서비스에 사용하면 안 됩니다.

## 권장 테스트 순서

1. `/catalog`에서 정상적인 영화 제목·장르 검색을 확인합니다.
2. SQLi 스캐너로 대문자 키워드와 일반 공백 차단 여부, 변형 입력의 우회 여부를
   비교합니다.
3. `/login`에서 정상 계정 로그인과 POST 로그인 폼의 SQLi 인증 우회를 확인합니다.
4. `/discover`에서 Reflected XSS 필터 차단·우회를 확인합니다.
5. 영화 상세 페이지에서 Stored XSS 테스트 리뷰를 등록합니다.
6. 운영자 계정으로 로그인한 뒤 `/admin/reviews`에서 저장된 입력의 실행 여부를
   확인합니다.
7. 테스트가 끝나면 아래 절차로 리뷰 데이터를 초기화합니다.

## Stored XSS 리뷰 초기화

Stored XSS 테스트에서 `alert()`를 실행하는 리뷰를 여러 개 저장하면 운영자 리뷰
화면을 열 때 저장된 개수만큼 경고창이 반복될 수 있습니다. 이는 서버 오류가 아니라
저장된 입력이 운영자 화면에서 실행되고 있다는 실험 결과입니다.

일반적인 초기화 방법:

1. `admin / admin123`으로 로그인합니다.
2. `/admin/reviews`로 이동합니다.
3. 이미 저장된 경고창을 모두 닫습니다.
4. 화면 상단의 **테스트 리뷰 초기화** 버튼을 누릅니다.
5. 리뷰 목록이 비어 있는지 확인합니다.

경고창이 너무 많아 버튼을 누르기 어렵다면 브라우저의 JavaScript를 잠시 비활성화한
후 `/admin/reviews`를 새로고침하고 **테스트 리뷰 초기화** 버튼을 누릅니다. 초기화가
끝나면 다음 XSS 테스트를 위해 JavaScript를 다시 활성화합니다.

Docker 컨테이너에서 화면을 거치지 않고 전체 테스트 리뷰만 삭제하는 비상 초기화
명령은 다음과 같습니다. 이 명령은 현재 컨테이너가 연결한 SQLite 또는 RDS의
`reviews` 테이블 내용을 모두 삭제하며, 영화·사용자·구독자·FLAG 데이터는 유지합니다.

```bash
sudo docker exec novastream-lab python -c "from lab_app_2.app import create_app; app=create_app(); app.extensions['novastream_db'].clear_reviews()"
```

로컬 Python 실행 환경에서는 저장소 루트에서 다음 명령을 사용할 수 있습니다.

```bash
python -c "from lab_app_2.app import create_app; app=create_app(); app.extensions['novastream_db'].clear_reviews()"
```

리뷰 초기화는 되돌릴 수 없으므로 실제 데이터가 아닌 실습용 리뷰에만 사용합니다.

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
mysql+pymysql://DB_USER:URL_ENCODED_PASSWORD@RDS_ENDPOINT:3306/DB_NAME?charset=utf8mb4&connect_timeout=10
```

RDS에는 전용 최소 권한 DB 사용자를 만들고, 비밀번호나 실제 엔드포인트를
저장소에 커밋하지 않습니다.

### 1. RDS 안에 전용 DB와 사용자 생성

RDS 마스터 사용자로 접속한 뒤 각 웹사이트에 서로 다른 DB와 사용자를 만듭니다.
아래 값과 비밀번호는 실제 환경에 맞게 바꿉니다.

```sql
CREATE DATABASE vulnerable_lab_2
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER 'lab2_user'@'%' IDENTIFIED BY 'REPLACE_WITH_STRONG_PASSWORD';

GRANT SELECT, INSERT, DELETE, CREATE
  ON vulnerable_lab_2.* TO 'lab2_user'@'%';

FLUSH PRIVILEGES;
```

이 사용자는 `vulnerable_lab_2` 밖의 다른 팀원 DB에는 권한을 주지 않습니다.
초기 실행 시 SQLAlchemy가 테이블과 가짜 데이터를 자동 생성합니다. 초기화가 끝난
뒤에는 필요에 따라 `CREATE` 권한을 회수할 수 있습니다.

### 2. EC2 전용 환경변수 파일 생성

Docker 이미지는 DB를 포함하지 않습니다. `lab_app_2/.env.aws.example`을 참고하여
EC2에 `.env.aws`를 만들고 실제 값을 입력합니다. `.env.aws`는 GitHub에 올리지
않습니다. 비밀번호에 특수문자가 있으면 URL 인코딩해야 합니다.

```dotenv
# .env.aws (EC2에만 저장)
LAB2_DATABASE_URL=mysql+pymysql://lab2_user:URL_ENCODED_PASSWORD@RDS_ENDPOINT:3306/vulnerable_lab_2?charset=utf8mb4&connect_timeout=10
LAB2_SECRET_KEY=replace-with-a-long-random-value
```

```bash
chmod 600 .env.aws
```

### 3. RDS를 사용하는 컨테이너 실행

```bash
sudo docker run -d \
  --name novastream-lab \
  --restart unless-stopped \
  --env-file .env.aws \
  -p 5000:5000 \
  novastream-lab:local
```

RDS 사용 시에는 SQLite용 `-v novastream-data:/data` 옵션이 필요하지 않습니다.
컨테이너가 정상 실행되면 다음 명령으로 확인합니다.

```bash
sudo docker logs novastream-lab
curl http://127.0.0.1:5000/health
```

RDS는 Private Subnet에 두고 3306 인바운드를 인터넷에 공개하지 않습니다. RDS
보안 그룹의 3306 인바운드 소스에는 EC2의 보안 그룹만 지정합니다.
