import os
import json
from dotenv import load_dotenv
from openai import OpenAI

from analysis.models import AIAnalysisResult
from analysis.prompts import get_triage_prompt

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def analyze_finding(finding, base_dir):
    """단일 Finding 객체를 분석하고 ai 필드를 덧붙여 반환합니다."""
    scan_data = finding.get('scan', {})
    req_data = scan_data.get('request', {})
    res_data = scan_data.get('response', {})

    # 1. Contract 4.5: HTML 원문 파일 읽기
    html_path = res_data.get('html_path')
    html_content = ""
    if html_path:
        full_html_path = os.path.normpath(os.path.join(base_dir, html_path))
        try:
            with open(full_html_path, 'r', encoding='utf-8') as f:
                html_content = f.read()
        except Exception as e:
            html_content = f"[HTML 파일 읽기 실패: {str(e)}]"

    # 2. AI 프롬프트 생성 및 요청
    prompt = get_triage_prompt(
        url=req_data.get('url', 'N/A'),
        parameter=req_data.get('parameter', 'N/A'),
        payload=req_data.get('payload', 'N/A'),
        html_content=html_content
    )

    try:
        response = client.beta.chat.completions.parse(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "보안 취약점 진단 도우미입니다."},
                {"role": "user", "content": prompt}
            ],
            response_format=AIAnalysisResult,
            temperature=0
        )
        
        ai_result = json.loads(response.choices[0].message.content)
        
        # 3. Contract 5.3: AI 객체 조립
        needs_review = True if ai_result["label"] == "INCONCLUSIVE" else False
        
        finding["ai"] = {
            "status": "COMPLETED",
            "status_reason": None,
            "label": ai_result["label"],
            "confidence": ai_result["confidence"],
            "needs_human_review": needs_review,
            "assessment_summary": ai_result["assessment_summary"],
            "source_evidence": ai_result["source_evidence"],
            "impact": ai_result["impact"],
            "recommendation": ai_result["recommendation"],
            "manual_check": ai_result["manual_check"],
            "report_paragraph": ai_result["report_paragraph"],
            "error": None
        }
    except Exception as e:
        # Contract 5.4: AI 실패 시 규격 
        finding["ai"] = {
            "status": "FAILED",
            "status_reason": None,
            "label": None,
            "confidence": None,
            "needs_human_review": True,
            "assessment_summary": None,
            "source_evidence": None,
            "impact": None,
            "recommendation": None,
            "manual_check": None,
            "report_paragraph": None,
            "error": {"code": "AI_ERROR", "message": str(e), "retryable": True}
        }
        
    return finding

def main():
    print("AI 분석 파이프라인 가동...")
    
    # 1. 실행 ID 및 경로 설정 (임시 테스트용)
    run_id = "run-test-01" 
    base_dir = os.path.join("data", "raw", run_id)
    input_file = os.path.join(base_dir, "findings.json")
    
    # 2. Envelope JSON 읽기
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            envelope = json.load(f)
    except FileNotFoundError:
        print(f"원시 데이터가 없습니다: {input_file} 경로를 확인하세요.")
        return

    processed_findings = []
    
    # 3. 각 Finding 처리
    for finding in envelope.get("findings", []):
        finding_id = finding.get('finding_id', 'Unknown')
        print(f"분석 중: {finding_id}...")
        
        # Contract 5.4: scan.status가 FAILED면 AI 요청 안 함
        if finding.get("scan", {}).get("status") == "COMPLETED":
            updated_finding = analyze_finding(finding, base_dir)
        else:
            updated_finding = finding
            updated_finding["ai"] = {
                "status": "NOT_REQUESTED",
                "status_reason": "SCAN_FAILED",
                "label": None,
                "confidence": None,
                "needs_human_review": True,
                "assessment_summary": None,
                "source_evidence": None,
                "impact": None,
                "recommendation": None,
                "manual_check": None,
                "report_paragraph": None,
                "error": None
            }
        processed_findings.append(updated_finding)
        
    # 4. Envelope 결과 덮어쓰기
    envelope["findings"] = processed_findings
    
    # 5. Processed 경로에 저장
    output_dir = os.path.join("data", "processed", run_id)
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "results.json")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(envelope, f, ensure_ascii=False, indent=2)
        
    print(f"분석 완료! '{output_file}' 파일이 생성되었습니다.")

if __name__ == "__main__":
    main()