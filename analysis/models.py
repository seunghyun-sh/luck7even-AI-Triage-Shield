from pydantic import BaseModel, Field
from typing import Literal

# 출력 구조
class TriageResult(BaseModel):
    finding_id: str
    vuln_type: str
    ai_label: Literal["취약 의심", "양호", "N/A"] 
    confidence: Literal["high", "medium", "low"]
    evidence_summary: str = Field(description="판단 근거 요약")
    recommendation: str = Field(description="조치 권고 방안")