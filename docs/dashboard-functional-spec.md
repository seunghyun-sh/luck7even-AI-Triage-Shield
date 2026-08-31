# 대시보드 기능명세서 v1

## 1. 문서 상태

이 문서는 `docs/project-flow.md`와 `docs/data-contracts-v1.md`를 기준으로 대시보드 MVP 기능을 정의한다.

대시보드는 스캐너 로직이나 OpenAI 판정 로직을 직접 실행하지 않는다. 환경구축팀이 비공개 전달한 Deployment Descriptor를 검증·등록하고, 허가된 구축환경과 유형에 한해 launcher에 실행을 요청한다. 이후 `RunStore`의 상태와 파이프라인이 게시한 `COMPLETED` 또는 `PARTIAL` processed JSON을 조회·검토하며 진단 결과 Excel 초안을 생성한다.

## 2. 주 사용자와 목적

주 사용자는 자동 진단 결과를 확인하는 **진단 결과 검토자**다.

사용자는 대시보드에서 다음 작업을 완료한다.

- 실행 상태와 데이터 유효성을 확인한다.
- 취약 의심, 판정 불가, AI 실패와 수동 검토 필요 항목을 찾는다.
- 개별 Finding의 원본 사실, 규칙 근거와 AI 분석 초안을 확인한다.
- SQLi ground truth가 있으면 조건부 평가 지표를 확인한다.
- 현재 필터 결과를 진단 결과 Excel 초안으로 내려받는다.

AI 판정과 Excel은 최종 보안 판정이나 프로젝트 결과보고서가 아니다. 최종 확인·수정·승인은 대시보드 밖에서 담당자가 수행한다.

## 3. 입력과 출력

### 입력

- 기본 경로: `data/processed/<scan_run_id>/results.json`
- 테스트·시연 보조 입력: 로컬 processed JSON 업로드
- 선택 입력: 별도 SQLi ground-truth JSON

데이터 규격은 `docs/data-contracts-v1.md`를 따른다.

### 출력

- Streamlit 진단 결과 검토 화면
- 현재 필터가 적용된 진단 결과 Excel 초안

## 4. 화면 구성

### 4.1 Navigation과 진단 실행

- 최상위 navigation은 session-state key를 가진 `진단 실행`과 `결과 검토` segmented control이다. 첫 방문은 `진단 실행`이며, 선택된 view만 렌더한다.
- `결과 검토`가 선택되지 않으면 결과 선택 sidebar, 지표, chart, Excel 초안과 결과 검토 입력을 만들지 않는다. `진단 실행`이 선택되지 않으면 preflight를 실행하지 않는다.
- SETUP 화면 상단에는 `배포환경 관리` 영역을 두고 Deployment Descriptor JSON 업로드,
  허가 확인, health identity 검증과 등록 목록을 제공한다. 임의 URL 직접 입력은 제공하지 않는다.
- SETUP 화면은 3:2 card layout이다. 왼쪽은 허가된 deployment, 유형, 허가 확인과 실행 CTA이고 오른쪽은 readiness다.
- readiness는 명시적인 `준비 상태 확인/새로고침`으로만 실행한다. 선택
  `deployment_id`, `deployment_version`, 유형 fingerprint가 같은 결과만 사용하며,
  입력 변경 뒤에는 다시 확인해야 한다.
- readiness는 `준비 N · 차단 N`, 차단 항목 우선 compact row, 통과 항목 expander로 표시한다. 실행 직전에도 preflight를 다시 수행하며 READY가 아니면 launcher를 호출하지 않는다.
- 실행 CTA 아래에는 우선순위에 따라 `유형 미선택`, `허가 미확인`, `준비 확인 필요`, `차단 해결`, `active run` 중 현재 비활성 사유를 한 줄로 표시한다.
- ACTIVE (`QUEUED`, `RUNNING`)에서는 setup control을 숨기고 RunStore에서 재발견한
  run ID, target set, deployment ID, 요청 유형, 상태, stage, progress, updated_at을
  읽기 전용으로 표시한다. 적용 단계의 완료·현재·대기 상태를 시각화하고 AI 단계는
  판단 기준 문서 준비, cache 재사용, batch 완료 수를 표시한다. total이 0이면
  `후보 계산 중`과 `AI 후보 없음`을 progress detail로 구분한다.
- TERMINAL은 `COMPLETED`(완료, green), `PARTIAL`(부분 완료, amber), `FAILED`(실패, red)의 의미를 텍스트로 표시한다. 안전한 canonical processed artifact가 있는 COMPLETED에는 `이 결과 검토`, PARTIAL에는 `부분 결과 검토` CTA만 제공한다. CTA는 `scan_run_id`를 persistent review selection state에 저장하고 결과 검토 view로 이동한다.
- FAILED 또는 artifact unavailable에는 결과 검토 CTA가 없다. `새 진단 준비`는 session의 run selection만 정리하고 RunStore artifact는 삭제하지 않는다. 자동 결과 이동은 하지 않는다.
- 결과 검토에 active run이 있으면 작은 banner와 `실행 상태 보기` CTA를 표시하되 hidden polling은 하지 않는다.

### 4.2 결과 선택·상태 헤더

- 자동 발견 결과는 `COMPLETED`를 먼저, `PARTIAL`을 다음으로 정렬하고 각 상태 그룹에서는 완료 시각 최신순으로 정렬한다. 따라서 더 최근의 PARTIAL이 있어도 기본값은 최신 COMPLETED다. terminal CTA가 저장한 명시적 `scan_run_id`는 PARTIAL이어도 이 기본값보다 우선한다.
- 자동 발견 결과 선택지는 `scan_run_id`와 상태 표시어(완료 또는 부분 완료)를 함께 표시한다.
- 테스트·시연 시 로컬 JSON을 업로드할 수 있다.
- `scan_run_id`, `target_set_id`, 시작·완료 시각과 run 상태 표시어를 표시한다.
- `PARTIAL`이면 부분 완료 경고와 함께 **필터 적용 전 전체 Finding 기준** 스캔 실패, AI 미요청, AI 실패, 수동 검토 필요 건수를 이 순서로 표시한다.
- `FAILED`이면 오류만 표시하고 통계와 Excel 생성을 막는다.
- AI 분석과 Excel이 담당자 검토용 초안임을 표시한다.

### 4.3 요약 카드

활성 필터를 기준으로 다음 값을 표시한다.

- 전체 Finding
- AI 취약 판정
- AI 판정 불가
- 수동 검토 필요
- AI 처리 실패
- 1차 규칙 취약 의심

카드는 검증된 데이터에서 pandas로 계산하며 LLM을 사용하지 않는다.

### 4.4 검토 필터와 표시어

저장 JSON, 필터 반환 값, DataFrame 집계·평가·Excel은 canonical English enum을 그대로 사용한다. 화면 경계에서만 아래 표시어로 바꾼다. Finding/run ID와 오류 code는 번역하지 않는다.

| canonical 값 | 화면 표시 |
| --- | --- |
| run `COMPLETED`, `PARTIAL`, `FAILED`, `QUEUED`, `RUNNING` | 완료, 부분 완료, 실패, 대기, 실행 중 |
| scan `COMPLETED`, `FAILED` | 완료, 실패 |
| rule `SUSPECTED`, `SAFE`, `SCAN_FAILED` | 취약 의심, 양호, 스캔 실패 |
| AI status `COMPLETED`, `NOT_REQUESTED`, `FAILED` | 완료, 미요청, 실패 |
| AI label `VULNERABLE`, `SAFE`, `INCONCLUSIVE`, `null` | 취약, 양호, 판정 불가, 미판정 |
| AI 미요청 사유 `RULE_NOT_SUSPECTED`, `SCAN_FAILED`, `POLICY_EXCLUDED` | 규칙상 의심되지 않음, 스캔 실패, 정책 제외 |
| vuln type `XSS`, `SQLI` | 크로스 사이트 스크립팅 (XSS), SQL 삽입 (SQLI) |

- 취약점 유형: 전체, 크로스 사이트 스크립팅 (XSS), SQL 삽입 (SQLI)
- 규칙 판정: 전체, 취약 의심, 양호, 스캔 실패
- AI 상태: 전체, 완료, 미요청, 실패
- AI 판정: 전체, 취약, 양호, 판정 불가, 미판정
- 수동 검토: 전체, 필요, 불필요
- URL·`case_id`·`finding_id` 검색

각 sidebar option은 위 표시어로 보이지만 선택·반환 값은 canonical enum(또는 AI label의 `null`)이다. 필터 변경 시 canonical filtered DataFrame으로 카드, 차트, 목록과 Excel에 같은 범위를 적용한다.

### 4.5 차트

MVP 필수 차트는 다음 세 가지다.

- 취약점 유형별 Finding 건수
- AI 판정 결과 분포
- 규칙 판정과 AI 판정 비교

SQLi ground truth가 있으면 조건부 혼동행렬을 추가한다. 평균 confidence는 성능 지표로 사용하지 않는다.

### 4.6 검토 작업목록

기본 정렬은 다음 우선순위를 사용한다.

1. AI 실패
2. 수동 검토 필요
3. AI 판정 불가
4. AI 취약 판정
5. 나머지 결과

목록에는 다음 항목을 표시한다.

- `finding_id`, `case_id`
- 취약점 유형 표시어
- URL과 파라미터
- scan 상태·규칙 판정과 AI 상태·AI 판정 표시어
- confidence
- 수동 검토 필요 여부

### 4.7 Finding 상세

- 요청 URL, method, 입력 위치, 파라미터와 payload
- HTTP status, 응답 시간과 기준 응답 시간
- 규칙 판정, 규칙 근거와 원시 증거 요약
- AI 상태, 판정, 미요청 사유와 confidence
- AI 분석 요약과 소스 증거
- 예상 영향도와 조치 권고
- 수동 확인 방법과 보고서 문장 초안
- scan 또는 AI 오류

응답 HTML 전체는 화면에 직접 렌더링하지 않는다.

### 4.8 조건부 평가

SQLi ground truth가 제공될 때만 다음을 표시한다.

- Accuracy
- Precision
- Recall
- `N_labeled`, `N_scored`
- 취약·양호 support
- scored coverage
- 오탐·미탐 목록
- 평가에서 제외된 상태별 건수

XSS ground truth가 없으면 XSS 평가 지표를 표시하지 않는다. Precision·Recall 분모가 0이면 `N/A`로 표시한다.

### 4.9 진단 결과 Excel 초안

현재 필터 결과로 다음 네 시트를 생성한다.

| 시트 | 내용 |
| --- | --- |
| 진단요약 | 실행 정보, 상태별 건수, 조건부 평가 지표와 초안 안내 |
| 상세결과 | 원본 요청·응답, 규칙·AI 판정과 근거 |
| 조치권고 | Finding별 영향도, 권고사항과 수동 확인 방법 |
| 판정비교 | 규칙·AI·정답 판정, 일치 여부와 제외 사유 |

- 메모리에서 생성하여 다운로드 버튼으로 제공한다.
- 파일명은 `vulnerability_review_<scan_run_id>.xlsx` 형식을 사용한다.
- 모든 시트에 “AI 생성 검토용 초안이며 최종 확인이 필요함”을 표시한다.
- 비신뢰 문자열을 Excel 수식으로 실행하지 않게 처리한다.

## 5. 오류와 빈 상태

- 파일 없음·읽기 실패: 기대 경로와 다시 선택하는 방법 표시
- JSON 문법·스키마·enum·자료형 오류: 통계와 Excel 생성을 막고 문제 필드 표시
- 중복 `case_id`·`finding_id`: 결합과 화면 구성 중단
- Finding 0건: 정상적인 빈 실행인지 run 실패인지 구분
- 필터 결과 0건: 필터 초기화 제공
- AI 미요청: 미요청 사유 표시
- AI 실패: Finding을 보존하고 오류와 수동 검토 필요 표시
- ground truth 없음: 평가 영역만 숨김
- ground-truth 결합 오류: 일반 검토는 유지하고 평가 영역에 오류 표시

## 6. MVP 완료 조건

- 계약 v1의 정상·부분·실패 fixture를 정확히 검증한다.
- 모든 raw Finding이 목록에서 보존된다.
- AI 미요청, 실패와 실제 판정 불가를 서로 다르게 표시한다.
- 필터 변경 시 카드, 차트, 목록과 Excel이 같은 범위로 갱신된다.
- SQLi 평가 지표가 수작업 계산과 일치한다.
- ground truth가 없을 때 평가 영역을 숨긴다.
- 잘못된 데이터가 앱을 종료시키지 않고 원인을 표시한다.
- 생성한 Excel을 정상적으로 열 수 있고 수식 삽입이 실행되지 않는다.

## 7. MVP 제외 범위

- 대시보드의 스캐너·AI 로직 직접 실행, 취소와 재시도
- 결과 수정, 승인·반려와 감사 이력
- 최종 보안 보고서·프로젝트 결과보고서 발행
- 로그인·권한 관리, API 서버와 데이터베이스
- S3·클라우드 배포
- 다중 실행 비교, 협업 코멘트와 알림
