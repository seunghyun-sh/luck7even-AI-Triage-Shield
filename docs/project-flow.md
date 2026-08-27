# AI-Triage Shield 전체 프로젝트 흐름

## 1. 문서 상태와 목적

이 문서는 취약 실습 환경 구축부터 XSS·SQL Injection 자동 진단, OpenAI 2차 판정, Streamlit 결과 검토와 Excel 보고서 초안 생성까지의 목표 흐름을 정의한다.

### 현재 구현 상태

- 저장소는 대부분 모듈 골격만 포함한다.
- `main.py`는 대상 설정 경로를 출력할 뿐 스캐너·AI·저장을 아직 실행하지 않는다.
- Streamlit은 안내 화면만 제공하며 processed 결과를 아직 읽지 않는다.
- 따라서 아래 명령과 흐름은 **구현 목표**이며 현재 동작을 보장하지 않는다.

### MVP 권장 결정

- AWS에는 허가된 Flask·MySQL 실습 환경만 배포한다.
- 스캐너, OpenAI 처리와 Streamlit은 동일한 로컬 호스트·저장소에서 실행하고 `data/`를 공유한다.
- 대시보드는 스캔을 실행하지 않고 완료된 processed JSON을 조회·검토한다.
- raw와 processed의 기준 형식은 JSON으로 통일하고 CSV는 사람이 확인하기 위한 파생 export로만 사용한다.
- Excel은 최종 보안 보고서가 아닌 **담당자 검토용 초안**으로 제공한다.
- S3, 대시보드 내 스캔 실행, 승인·반려와 최종 보고서 발행은 MVP에서 제외한다.

이 권장안을 기준으로 `data-contracts-v1.md`, `execution-contract-v1.md`, 기능명세서, 기술명세서와 샘플 데이터를 동기화했다. 팀 승인 전까지 v1 후보 계약으로 취급한다.

## 2. 프로젝트 정의와 제품 경계

AI-Triage Shield는 허가된 실습 환경을 대상으로 XSS·SQL Injection 후보를 규칙 기반으로 넓게 탐지하고, 선택된 후보를 OpenAI로 2차 판정한 뒤 담당자가 결과를 검토·분석하고 Excel 보고서 초안을 생성할 수 있게 하는 교육용 자동 진단 플랫폼이다.

프로젝트 전체 자동화와 대시보드의 책임은 구분한다.

- **전체 파이프라인:** 대상 설정 → 스캔 → 1차 판정 → AI 2차 판정 → processed JSON 생성
- **대시보드:** completed processed JSON 조회 → 결과 검토 → 조건부 성능 평가 → Excel 초안 생성

processed JSON은 파이프라인의 표준 통합 산출물이지 사람의 최종 보안 판정이 아니다.

## 3. 액터와 책임

| 액터 | 책임 | 입력 | 출력 |
| --- | --- | --- | --- |
| 환경 구축팀 | AWS Flask·RDS 실습 환경과 대상 명세 제공 | 프로젝트 요구사항 | 비밀을 제외한 target manifest·수동 판정 기준 |
| XSS 담당 | XSS 요청, 증거 수집과 1차 규칙 판정 | target manifest | 공통 RawFinding·응답 HTML |
| SQLi 담당 | SQLi 요청, 증거 수집·1차 규칙 판정과 Burp Suite 정답표 작성 | target manifest·수동 테스트 시나리오 | 공통 RawFinding·응답 HTML·SQLi ground truth |
| OpenAI·데이터 처리 담당 | 공통 2차 판정, 오류 격리, processed 생성 | 모든 raw Findings | 전체 Finding을 보존한 processed JSON |
| 대시보드·Excel 담당 | 데이터 검증, 통계, 시각화와 진단 결과 Excel 생성 | processed JSON·별도 ground truth | Streamlit 결과 검토 화면·진단 결과 Excel 초안 |

대시보드 사용자의 주 역할은 **진단 결과 검토자**다. 강사·멘토·발표 청중은 결과를 확인하는 보조 사용자이며, MVP 화면을 별도로 분리하지 않는다.

## 4. 전체 시스템 흐름

```text
[1. AWS 취약 실습 환경]
Flask Web EC2 + RDS MySQL
        │
        │ target manifest
        ▼
[2. XSS·SQLi 스캐너]
정상·공격 요청 + 1차 규칙 판정
        │
        │ 모든 raw Findings + evidence sidecar
        ▼
[3. OpenAI·데이터 처리]
후보 선택 + 증거 정제 + AI 2차 판정
        │
        │ 모든 원시 Finding과 AI 상태 결합
        ▼
[4. completed processed JSON]
실행별 표준 통합 산출물
        │
        ├─────────────────────┐
        ▼                     ▼
[5. Streamlit 결과 검토]   [6. Excel 검토용 초안]
```

Burp Suite 정답은 AI 입력과 분리한다.

```text
Burp Suite 수동 검증 → 별도 ground truth ┐
                                         ├→ 조건부 평가 지표
completed processed JSON ────────────────┘
```

## 5. 단계별 흐름

### 5.1 환경 구축과 target manifest

환경 구축팀은 다음 환경을 제공한다.

```text
AWS VPC
├── Public Subnet
│   └── Web EC2: Flask 취약·안전 비교 웹사이트
└── Private Subnet
    └── RDS MySQL: 로그인·검색·게시판 더미 데이터
```

Scanner EC2와 S3는 MVP의 필수 구성으로 확정하지 않는다. 로컬 통합이 검증된 뒤 별도 배포가 필요할 때 추가한다.

실습 환경은 다음을 포함한다.

- Reflected·Stored XSS 취약 페이지
- 로그인 우회·검색 조건 변조 SQL Injection 취약 페이지
- 출력 인코딩과 매개변수화 쿼리를 적용한 안전 비교 페이지
- 반복 시연을 위한 더미 데이터와 초기화 기능

`configs/targets.example.json`은 아래 최소 항목을 표현하는 target manifest v1 후보 예시다. 팀 승인 전까지 확정 계약으로 간주하지 않는다.

- `schema_version`, `target_set_id`, 허가된 `base_url`
- 안정적인 `case_id`와 취약점 유형
- 상대 경로, HTTP 메서드와 입력 위치(query·form·JSON)
- 파라미터와 정상 기준값
- 사전 로그인 필요 여부와 비밀값이 아닌 인증 프로필 참조
- timeout·redirect 정책
- 수동 판정 기준

취약·안전 정답값은 target manifest에 넣지 않고 별도 ground truth로 관리하며 AI 입력에도 포함하지 않는다. 실제 서비스 주소, 고정 IP, 비밀번호, 세션 값과 인증정보는 Git에 등록하지 않는다.

### 5.2 파이프라인 실행

MVP에서는 대시보드 밖에서 `main.py`를 실행한다.

```bash
python main.py run --target-set-id local-lab-v1 --types XSS SQLI
```

위 명령은 현재 골격이며, 구현 후 다음 순서를 오케스트레이션해야 한다.

```text
target manifest 검증
→ scan_run_id·run manifest 생성
→ XSS·SQLi 스캐너 실행
→ raw 결과 검증·원자적 게시
→ AI 후보 선택(모든 raw Finding은 유지)
→ AI 입력 증거 정제·2차 판정
→ processed 결과 검증·원자적 게시
→ 실행 상태 completed·partial·failed 기록
→ 의미 있는 종료 코드 반환
```

중간 파일을 최종 경로에 직접 쓰지 않는다. 임시 파일을 완성·검증한 뒤 rename하여 대시보드가 부분 JSON을 읽지 않게 한다.

### 5.3 XSS·SQLi 1차 진단

#### XSS 스캐너

1. 정상 기준값을 전송한다.
2. 사람이 검토하고 버전을 고정한 XSS 페이로드를 전송한다.
3. 응답 HTML에서 페이로드의 반사 위치와 인코딩 여부를 확인한다.
4. 재현율 우선의 느슨한 1차 규칙 판정을 수행한다.
5. 요청·응답 메타데이터, 규칙 근거와 응답 HTML을 저장한다.

#### SQL Injection 스캐너

1. 정상 요청의 응답과 응답 시간을 기준선으로 측정한다.
2. 정적 SQL Injection 페이로드를 전송한다.
3. DB 오류, 응답 본문·건수 차이, 참·거짓 쌍 차이, 반복 시간 지연과 인증 우회·비정상 노출을 확인한다.
4. 여러 신호를 종합하여 느슨한 1차 규칙 판정을 수행한다.
5. 요청·응답 메타데이터, 측정값, 규칙 근거와 응답 HTML을 저장한다.

두 스캐너는 같은 RawFinding 모델을 사용한다. scan 실패는 취약점 판정이 아니므로 오류 상태와 판정값을 분리한다.

### 5.4 canonical raw 결과

기준 형식은 실행별 envelope JSON으로 통일한다.

```text
data/raw/<scan_run_id>/
├── findings.json
└── responses/
    ├── XSS-001.html
    └── SQLI-001.html
```

최상위 envelope에는 다음 정보가 필요하다.

- `schema_version`
- `scan_run_id`
- `target_set_id`
- 생성 시각과 실행 상태
- `findings`

각 Finding은 최소한 다음 정보를 보존한다.

- 안정적인 평가 단위 `case_id`
- 실행 내 식별자 `finding_id`
- `vuln_type`
- URL, method, 입력 위치, parameter와 payload
- HTTP status, elapsed와 baseline elapsed
- `scan.status`: `COMPLETED` 또는 `FAILED`
- 규칙 판정과 규칙 근거
- 원시 증거 요약
- 응답 HTML 상대 경로
- scan 오류

`response_html_path`는 해당 run 디렉터리 기준 상대 경로만 허용한다. 절대 경로, `..`와 run 디렉터리 밖의 파일은 거부한다.

CSV가 필요하면 canonical JSON에서 생성하는 export로 제공한다. JSON과 CSV를 동시에 입력 source of truth로 지원하지 않는다.

### 5.5 OpenAI 2차 판정

OpenAI·데이터 처리 담당은 다음 순서로 처리한다.

1. raw envelope와 모든 Finding을 검증한다.
2. 정책에 따라 AI 후보를 선택한다.
3. 응답 HTML에서 판정에 필요한 근거만 allowlist 방식으로 추출한다.
4. 쿠키, 인증 헤더, 개인정보와 불필요한 본문을 deterministic하게 제거한다.
5. 입력 길이를 제한하고 외부 응답은 신뢰할 수 없는 데이터로 명확히 구획한다.
6. 취약점 유형별 프롬프트로 구조화된 AI 판정을 수행한다.
7. 응답 스키마를 검증하고 항목별 실패를 격리한다.
8. 후보가 아닌 항목을 포함한 모든 raw Finding을 processed 결과에 1:1 보존한다.

AI는 다음 분석 정보만 생성한다.

- 판정 label과 confidence
- 수동 검토 필요 여부
- 근거 요약과 예상 영향도
- 조치 권고와 수동 확인 방법
- 보고서 문장 초안

AI는 `scan_run_id`, `case_id`, `finding_id`, 취약점 유형과 요청 정보를 생성하거나 수정하지 않는다. ground truth도 AI 입력에 포함하지 않는다.

### 5.6 AI 상태와 판정 분리

AI 처리 상태와 판정 label은 서로 다른 의미다.

- `ai.status=NOT_REQUESTED`: 정책상 AI 후보가 아니거나 scan이 실패함
- `ai.status=COMPLETED`: AI 요청과 결과 검증이 완료됨
- `ai.status=FAILED`: API·파싱·검증이 실패함

`COMPLETED`일 때만 AI label을 기록한다.

- `VULNERABLE`
- `SAFE`
- `INCONCLUSIVE`

`NOT_REQUESTED`와 `FAILED`에서는 AI label, confidence와 생성 문장을 `null`로 둔다. 실패를 `INCONCLUSIVE`나 confidence `0.0`으로 위장하지 않는다.

### 5.7 canonical processed 결과

```text
data/processed/<scan_run_id>/results.json
```

processed envelope는 raw의 실행 정보와 모든 Finding을 보존하고 각 Finding에 namespace를 나누어 기록한다.

- 공통 lineage: `scan_run_id`, `case_id`, `finding_id`, `scanned_at`
- `scan`: 요청·응답·규칙 판정·증거·오류
- `ai`: 상태·판정·신뢰도·근거·영향·권고·오류

raw와 AI의 결합은 `(scan_run_id, finding_id)`를 사용한다. ground truth는 processed JSON에 포함하지 않고 별도 artifact로 유지한다.

processed JSON은 전체 모집단을 보존해야 한다. AI가 처리한 후보만 저장하면 1차 미탐과 true negative가 사라져 전체 Accuracy·Recall을 계산할 수 없다.

### 5.8 ground truth와 평가 지표

Burp Suite 정답은 별도 artifact로 유지한다.

- 현재 기획 기준으로 SQLi 담당이 Burp Suite를 이용해 `case_id`, label, 출처와 평가 시각을 기록한다.
- 대시보드의 metrics 모듈이 processed 결과와 ground truth를 `case_id`로 검증·결합하고 합의된 산식으로 지표를 계산한다.
- XSS ground truth는 현재 담당과 산출물이 정해지지 않았으므로 제공되기 전까지 XSS 평가 지표를 표시하지 않는다.
- 중복·누락·다대다 결합은 오류로 처리하며 ground truth를 AI 입력이나 processed 생성 단계에 전달하지 않는다.

AI 조건부 Accuracy·Precision·Recall은 다음 항목만 대상으로 한다.

- ground truth가 `VULNERABLE` 또는 `SAFE`
- `ai.status=COMPLETED`
- AI label이 `VULNERABLE` 또는 `SAFE`

`INCONCLUSIVE`, `NOT_REQUESTED`, scan·AI 실패는 TP·FP·TN·FN에서 제외하고 상태별 제외 건수로 표시한다. 지표에는 다음 모수도 함께 표시한다.

- `N_labeled`
- `N_scored`
- 취약·양호 support
- `scored_coverage = N_scored / N_labeled`

Precision·Recall의 분모가 0이면 0으로 표시하지 않고 `N/A`로 표시한다. 전체 파이프라인 지표는 최종 판정 정책을 별도로 확정한 뒤 계산한다.

## 6. 대시보드 사용자 흐름

대시보드는 스캔·AI 재실행이나 결과 수정을 수행하지 않는다.

1. 기본 completed processed 결과를 연다.
2. 테스트·시연 시에만 로컬 JSON 업로드를 보조 진입점으로 사용한다.
3. 실행 ID, 대상, 생성 시각, 실행 상태와 데이터 유효성을 확인한다.
4. 전체, 취약 의심, 판정 불가, 수동 검토 필요와 AI 실패 건수를 확인한다.
5. 수동 검토 필요·AI 실패 항목을 우선 정렬하거나 필터링한다.
6. Finding을 선택해 원본 사실, 규칙 근거, AI 초안, 영향도, 권고와 수동 확인 방법을 검토한다.
7. ground truth가 있을 때만 별도 평가 영역에서 지표와 오탐·미탐을 확인한다.
8. 현재 필터 범위를 명시한 Excel 검토용 초안을 내려받는다.
9. 최종 확인·수정·승인은 대시보드 밖에서 담당자가 수행한다.

### 대시보드 예외 흐름

- 파일 없음·읽기 실패: 기대 경로와 다시 선택하는 방법을 표시한다.
- JSON·스키마·자료형·중복 ID 오류: 조회와 내보내기를 막고 문제 필드를 표시한다.
- Finding 0건: 정상적인 빈 실행인지 실행 실패인지 run 상태로 구분한다.
- 필터 결과 0건: 필터 초기화 동작을 제공한다.
- AI 개별 실패: Finding을 보존하고 실패 사유와 식별자를 표시한다.
- ground truth 없음: 평가 영역을 숨기고 일반 검토는 계속한다.
- 부분 실행: partial 상태와 완료·실패 건수를 표시하고 결과가 완전하지 않음을 경고한다.

## 7. Excel 검토용 초안

MVP에서 `dashboard/report_builder.py`는 processed 결과를 받아 메모리상의 workbook bytes를 생성하고 Streamlit 다운로드 버튼에 제공한다. `main.py`는 Excel을 생성하지 않는다.

| 시트 | 내용 |
| --- | --- |
| 진단요약 | 실행 정보, 상태별 건수, 평가 모수와 AI 종합 요약문 |
| 상세결과 | 원본 요청·응답 정보, 규칙·AI 판정과 근거 |
| 조치권고 | Finding별 영향도, 권고사항과 수동 확인 방법 |
| 판정비교 | 규칙·AI·정답 판정, 일치 여부와 제외 사유 |

모든 시트에 AI 생성 검토용 초안이며 최종 확인이 필요하다는 문구를 표시한다. URL, payload, 증거와 AI 문장 등 신뢰할 수 없는 문자열이 `=`, `+`, `-`, `@`로 시작하면 Excel 수식으로 실행되지 않도록 literal cell로 안전하게 기록한다.

## 8. MVP 배치와 후속 확장

### MVP 기준 토폴로지

```text
AWS 허가된 실습 웹사이트
        ↑ HTTP 요청
동일 로컬 호스트·checkout
├── main.py
├── data/raw
├── analysis/ai_triage.py
├── data/processed
└── Streamlit
```

### 후속 검토 범위

- Scanner EC2 분리
- S3 raw·processed·export 저장
- IAM, 암호화, 실행별 경로와 보존 정책
- 대시보드 내 스캔 실행·취소·재시도와 실시간 진행률
- 결과 수정, 승인·반려, 버전과 감사 이력
- 로그인·권한 관리, API 서버와 데이터베이스
- 다중 실행 비교, 협업 코멘트와 알림
- 최종 보고서 발행

후속 기능은 로컬 end-to-end 흐름과 데이터 계약을 먼저 검증한 뒤 추가한다.

## 9. 통합 완료 조건

- target manifest만으로 허가된 대상에 정상·공격 요청을 구성할 수 있다.
- XSS·SQLi 스캐너가 같은 RawFinding 모델을 사용한다.
- canonical raw·processed JSON이 실행별 envelope와 schema version을 가진다.
- 모든 raw Finding이 processed에 1:1 보존된다.
- AI 후보가 아닌 항목, AI 실패와 실제 판정 불가를 구분한다.
- raw 증거가 정제·제한된 뒤에만 OpenAI로 전달된다.
- 한 Finding의 실패가 전체 처리를 중단하지 않는다.
- 부분 파일이 최종 결과로 노출되지 않는다.
- 대시보드는 completed·partial·failed 실행을 구분한다.
- 평가 지표에 support, scored coverage와 제외 건수가 함께 표시된다.
- Excel 초안의 비신뢰 문자열이 수식으로 실행되지 않는다.
- 실제 결과, 응답 HTML, 보고서와 민감정보를 Git에 등록하지 않는다.

## 10. 권장 구현 순서

1. target manifest v1과 안정적인 `case_id` 규칙 확정
2. 공통 RawFinding·processed envelope·상태 모델 확정
3. ground truth schema, 평가 cohort와 산식 확정
4. 동기화된 계약 문서와 샘플 JSON 검토·승인
5. 두 스캐너를 mock 대상과 공통 모델로 구현
6. OpenAI 증거 정제·구조화 출력·항목별 오류 처리 구현
7. `main.py` 원자적 오케스트레이션과 run 상태 구현
8. 대시보드 검증·검토 흐름 구현
9. deterministic metrics와 Excel 안전 출력 구현
10. 실제 AWS 실습 환경으로 end-to-end 통합 검증

## 11. 팀 승인 전에 남은 결정

1. `case_id` 생성·버전 규칙
2. target manifest의 인증 프로필과 입력 위치 표현
3. 규칙 판정 enum과 AI 후보 선택 정책
4. AI 근거 추출·민감정보 제거·크기 제한 기준
5. XSS ground truth의 필요 여부와 SQLi 최소 표본
6. 전체 파이프라인의 최종 판정 정책과 end-to-end 지표 정의
7. partial 실행을 대시보드에서 허용할지 여부

팀은 `data-contracts-v1.md`, `execution-contract-v1.md`, `dashboard-functional-spec.md`, `dashboard-technical-spec.md`와 테스트용 JSON을 함께 검토하고 승인한다. 승인 후 필드 변경은 계약 변경 절차를 따른다.
