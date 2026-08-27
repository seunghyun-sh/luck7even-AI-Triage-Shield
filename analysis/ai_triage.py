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

# 1. 보안 필터링 함수
def sanitize_and_extract_html(html_content, payload, max_length=1500):
    """HTML 전체를 보내지 않고, 페이로드 주변부만 추출 및 다양한 민감정보를 완벽히 마스킹합니다."""
    if not html_content:
        return ""

    safe_html = html_content

    #1. PII (개인식별정보) 마스킹
    # 전화번호 (010, 011, 02 등 광범위 적용)
    safe_html = re.sub(r'01[0-9]-\d{3,4}-\d{4}', '01X-****-****', safe_html)
    # 주민등록번호 형태 (6자리-7자리)
    safe_html = re.sub(r'\d{6}-[1-4]\d{6}', '******-*******', safe_html)
    # 이메일 주소
    safe_html = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[EMAIL_REDACTED]', safe_html)
    # 신용카드 번호 (16자리)
    safe_html = re.sub(r'\d{4}-\d{4}-\d{4}-\d{4}', '****-****-****-****', safe_html)

    # 2. Security Credentials (인증/보안 토큰) 마스킹
    # JWT 토큰 (ey... 로 시작하는 긴 문자열)
    safe_html = re.sub(r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*', '[JWT_REDACTED]', safe_html)
    # CSRF, Session, Auth Token 등 (변수명 뒤에 오는 16자리 이상의 영문숫자)
    safe_html = re.sub(r'(?i)(session_id|csrf_token|auth_token|access_token)["\'\s:=]+([a-zA-Z0-9_\-]{16,})', r'\1: [TOKEN_REDACTED]', safe_html)

    # 3. 페이로드가 발견된 구간만 앞뒤로 잘라내기 (토큰 절약 및 구획화)
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

    # 2. 전체 HTML 대신 필터링된 조각(Snippet) 생성
    safe_html_snippet = sanitize_and_extract_html(raw_html_content, payload)

    # 3. 캐시 지문은 필터링된 안전한 본문 기준으로 생성
    hash_input = f"{payload}|||{safe_html_snippet}"
    cache_key = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()

    if cache_key in cache_dict:
        print(f"동일한 패턴 발견")
        finding["ai"] = cache_dict[cache_key]
        return finding

    print(f"새로운 패턴. OpenAI API를 호출합니다.")
    # 전체 HTML 대신 필터링된 증거(safe_html_snippet)만 AI에게 전달
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
    #보안 필터링 및 로컬 캐싱 추가
    print("AI 파이프라인 가동...")
    
    run_id = "run-test-01" 
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

    processed_findings = []
    
    findings_list = envelope.get("findings", [])
    total_count = len(findings_list)
    print(f"총 {total_count}개의 데이터를 처리합니다... (터미널 랙 방지를 위해 1,000개 단위로 진행상황 출력)")

    processed_findings = []
    
    for idx, finding in enumerate(findings_list, start=1):
        finding_id = finding.get('finding_id', 'Unknown')
        
        # 1,000개마다 한 번씩만 출력
        if idx % 1000 == 0:
            print(f"진행 상황: {idx} / {total_count} 처리 완료...")
            
        scan_status = finding.get("scan", {}).get("status")
        rule_label = finding.get("scan", {}).get("rule", {}).get("label")
        
        if scan_status == "COMPLETED":
            # 스캐너가 SAFE 판정 시 AI 스킵 (출력 제거)
            if rule_label == "SAFE":
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
                updated_finding = analyze_finding(finding, base_dir, cache_dict)
                processed_findings.append(updated_finding)
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
            
    # AI 처리에 하나라도 FAILED가 있으면 봉투 상태를 PARTIAL로 하향 조정
    has_failed = any(f.get("ai", {}).get("status") == "FAILED" for f in processed_findings)
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