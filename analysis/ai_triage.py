import os
import json
import hashlib
import re
from dotenv import load_dotenv
from openai import OpenAI

from analysis.models import AIAnalysisResult
from analysis.prompts import get_triage_prompt

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def load_cache(cache_path):
    if os.path.exists(cache_path):
        with open(cache_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_cache(cache_path, cache_dict):
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    with open(cache_path, 'w', encoding='utf-8') as f:
        json.dump(cache_dict, f, ensure_ascii=False, indent=2)

def sanitize_and_extract_html(html_content, payload, max_length=1500):
    if not html_content:
        return ""

    safe_html = html_content
    safe_html = re.sub(r'01[0-9]-\d{3,4}-\d{4}', '01X-****-****', safe_html)
    safe_html = re.sub(r'\d{6}-[1-4]\d{6}', '******-*******', safe_html)
    safe_html = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[EMAIL_REDACTED]', safe_html)
    safe_html = re.sub(r'\d{4}-\d{4}-\d{4}-\d{4}', '****-****-****-****', safe_html)
    safe_html = re.sub(r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*', '[JWT_REDACTED]', safe_html)
    safe_html = re.sub(r'(?i)(session_id|csrf_token|auth_token|access_token)["\'\s:=]+([a-zA-Z0-9_\-]{16,})', r'\1: [TOKEN_REDACTED]', safe_html)

    payload_idx = safe_html.find(payload)
    if payload_idx != -1:
        start = max(0, payload_idx - (max_length // 2))
        end = min(len(safe_html), payload_idx + len(payload) + (max_length // 2))
        snippet = safe_html[start:end]
        return f"...[보안 필터링됨(전략)]...\n{snippet}\n...[보안 필터링됨(후략)]..."
    else:
        return safe_html[:max_length] + ("...[길이 초과로 절삭됨]" if len(safe_html) > max_length else "")

def analyze_finding(finding, base_dir, cache_dict):
    scan_data = finding.get('scan', {})
    req_data = scan_data.get('request', {})
    res_data = scan_data.get('response', {})

    payload = req_data.get('payload', '')
    html_path = res_data.get('html_path')
    raw_html_content = ""
    
    if html_path:
        full_html_path = os.path.normpath(os.path.join(base_dir, html_path))
        try:
            with open(full_html_path, 'r', encoding='utf-8') as f:
                raw_html_content = f.read()
        except Exception as e:
            raw_html_content = f"[HTML 파일 읽기 실패: {str(e)}]"

    safe_html_snippet = sanitize_and_extract_html(raw_html_content, payload)
    hash_input = f"{payload}|||{safe_html_snippet}"
    cache_key = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()

    if cache_key in cache_dict:
        finding["ai"] = cache_dict[cache_key]
        return finding

    prompt = get_triage_prompt(
        url=req_data.get('url', 'N/A'),
        parameter=req_data.get('parameter', 'N/A'),
        payload=payload,
        html_content=safe_html_snippet 
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
        
        cache_dict[cache_key] = finding["ai"]
        
    except Exception as e:
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
    print("실무 데이터(Contract v1) AI 파이프라인 가동...")
    
    run_id = "run-xss-20260827-103719" 
    base_dir = os.path.join("data", "raw", run_id)
    input_file = os.path.join(base_dir, "findings.json")
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            envelope = json.load(f)
    except FileNotFoundError:
        print(f"원시 데이터가 없습니다: {input_file} 경로를 확인하세요.")
        return

    target_set_id = envelope.get("target_set_id", "default_target")
    cache_path = os.path.join("data", "cache", f"{target_set_id}_ai_cache.json")
    cache_dict = load_cache(cache_path)

    findings_list = envelope.get("findings", [])
    total_count = len(findings_list)
    print(f"총 {total_count}개의 데이터를 처리합니다... (1,000개 단위로 진행상황 출력)")

    processed_findings = []
    
    for idx, finding in enumerate(findings_list, start=1):
        # 문구를 '처리 완료'에서 '처리 중'으로 변경
        if idx % 1000 == 0:
            print(f"▶ 진행 상황: {idx} / {total_count} 처리 중...")
            
        scan_status = finding.get("scan", {}).get("status")
        rule_label = finding.get("scan", {}).get("rule", {}).get("label")
        
        if scan_status == "COMPLETED":
            # 'SUSPECTED'일 때만 명확하게 AI를 호출하도록 변경 (Whitelist 방식)
            if rule_label == "SUSPECTED":
                updated_finding = analyze_finding(finding, base_dir, cache_dict)
                processed_findings.append(updated_finding)
            else:
                # SAFE이거나 null 등 알 수 없는 값이면 모두 건너뜀 (안전 지향)
                finding["ai"] = {
                    "status": "NOT_REQUESTED",
                    "status_reason": "RULE_NOT_SUSPECTED",
                    "label": None,
                    "confidence": None,
                    "needs_human_review": False,
                    "assessment_summary": None,
                    "source_evidence": None,
                    "impact": None,
                    "recommendation": None,
                    "manual_check": None,
                    "report_paragraph": None,
                    "error": None
                }
                processed_findings.append(finding)
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
            
    # scan.status 와 ai.status 중 하나라도 FAILED가 있으면 PARTIAL로 처리
    has_failed = any(
        f.get("scan", {}).get("status") == "FAILED" or f.get("ai", {}).get("status") == "FAILED"
        for f in processed_findings
    )
    if has_failed and envelope.get("status") == "COMPLETED":
        envelope["status"] = "PARTIAL"
        
    envelope["findings"] = processed_findings
    
    save_cache(cache_path, cache_dict)
    
    output_dir = os.path.join("data", "processed", run_id)
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "results.json")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(envelope, f, ensure_ascii=False, indent=2)
        
    print(f"\n분석 및 캐시 저장 완료! '{output_file}'")

if __name__ == "__main__":
    main()