# 전체 파이프라인 데이터 연동 규격서 (v1.0)

각 파트의 원활한 병렬 개발을 위해, 팀 간 데이터를 주고받을 때 사용할 공통 필드명과 규격을 정의합니다.

## 자동화 팀 ➔ AI 백엔드
- **형식:** CSV 또는 JSON 리스트
- **필수 포함 필드:** 이 필드들은 AI가 문맥을 분석하기 위해 반드시 필요합니다.
  - `finding_id`: (String) 발견된 취약점 고유 ID 
  - `vuln_type`: (String) 취약점 종류 
  - `url`: (String) 공격 대상 URL
  - `parameter`: (String) 공격에 사용된 파라미터명
  - `payload`: (String) 실제 주입한 공격 페이로드 
  - `rule_label`: (String) 1차 탐지 결과 
  - `response_body`: (String) 공격 후 돌아온 HTML 또는 에러 메시지 원본 텍스트 전체

## AI 백엔드 ➔ 대시보드 
- **형식:** JSON 
- **필수 포함 필드:** Contract A의 데이터를 받아, AI가 아래 필드를 추가하여 프론트로 전달합니다.
  - `ai_label`: (String) AI 최종 판정 결과
  - `confidence`: (String) AI 판정 신뢰도 
  - `evidence_summary`: (String) AI의 판정 사유 및 근거 텍스트
  - `recommendation`: (String) 취약점 조치 및 방어 권고 방안
