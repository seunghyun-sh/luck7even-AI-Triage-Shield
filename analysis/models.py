from pydantic import BaseModel, Field
from typing import Literal

class AIAnalysisResult(BaseModel):
    label: Literal["VULNERABLE", "SAFE", "INCONCLUSIVE"]
    confidence: float = Field(description="0.0 ~ 1.0 사이의 숫자 (예: 0.98)")
    assessment_summary: str = Field(description="raw 증거 요약 (예: 스크립트가 실행 가능한 영역에 인코딩 없이 포함됨)")
    source_evidence: str = Field(description="응답 HTML에서 발견한 원본 증거 (예: 원본 script 태그 확인)")
    impact: str = Field(description="취약점이 미치는 영향도 설명")
    recommendation: str = Field(description="출력 컨텍스트에 맞는 조치 권고 방안")
    manual_check: str = Field(description="수동 검증 방법 (예: 격리된 브라우저에서 실제 실행 여부 확인)")
    report_paragraph: str = Field(description="최종 보고서에 들어갈 문장")