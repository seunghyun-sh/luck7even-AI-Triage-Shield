import os
import json
import hashlib
import re
import asyncio
from dotenv import load_dotenv
from openai import AsyncOpenAI  # 비동기 클라이언트로 변경

from analysis.models import AIAnalysisResult
from analysis.prompts import get_triage_prompt

load_dotenv()
# 동기식 Client 대신 AsyncOpenAI 사용
aclient = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))

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
    # 1. 민감정보 마스킹 (기존 동일)
    safe_html = re.sub(r'01[0-9]-\d{3,4}-\d{4}', '01X-****-****', safe_html)
    safe_html = re.sub(r'\d{6}-[1-4]\d{6}', '******-*******', safe_html)
    safe_html = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[EMAIL_REDACTED]', safe_html)
    safe_html = re.sub(r'\d{4}-\d{4}-\d{4}-\d{4}', '****-****-****-****', safe_html)
    safe_html = re.sub(r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*', '[JWT_REDACTED]', safe_html)
    safe_html = re.sub(r'(?i)(session_id|csrf_token|auth_token|access_token)["\'\s:=]+([a-zA-Z0-9_\-]{16,})', r'\1: [TOKEN_REDACTED]', safe_html)

    # 페이로드 다중 검색 로직 (최대 3곳)
    snippets = []
    search_start = 0
    max_occurrences = 3  # 최대 3곳의 위치를 찾음
    # 토큰 한도를 맞추기 위해, 한 곳당 앞뒤로 자를 길이를 N등분 함
    window_size = max_length // max_occurrences // 2 

    # 페이로드가 빈 문자열이 아닐 때만 다중 검색 수행
    if payload:
        while len(snippets) < max_occurrences:
            idx = safe_html.find(payload, search_start)
            if idx == -1:
                break  # 더 이상 페이로드가 없으면 탐색 종료
                
            start = max(0, idx - window_size)
            end = min(len(safe_html), idx + len(payload) + window_size)
            snippets.append(safe_html[start:end])
            
            # 다음 검색은 지금 찾은 페이로드의 바로 뒷부분부터 시작
            search_start = idx + len(payload)

    # 3. 추출된 조각들을 하나로 조립
    if snippets:
        combined_snippet = "\n\n...[다른 위치에 반사된 페이로드 발견]...\n\n".join(snippets)
        return f"...[보안 필터링됨(전략)]...\n{combined_snippet}\n...[보안 필터링됨(후략)]..."
    else:
        # 페이로드를 아예 못 찾았거나 페이로드가 없는 경우 앞부분만 절삭
        return safe_html[:max_length] + ("...[길이 초과로 절삭됨]" if len(safe_html) > max_length else "")

# async def로 변경 및 동시성 제어 추가
async def analyze_finding_async(finding, base_dir, cache_dict, semaphore):
    async with semaphore:  # 한 번에 지정된 개수까지만 동시 실행 허용
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

        # 재시도 및 지수 백오프 로직
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = await aclient.beta.chat.completions.parse(
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
                
                break  # 성공했으므로 반복문(재시도) 즉시 탈출
                
            except Exception as e:
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt  # 1초, 2초 (점점 길어지는 대기 시간)
                    finding_id = finding.get('finding_id', 'Unknown')
                    print(f"{finding_id} - {wait_time}초 후 재시도 ({attempt+1}/{max_retries})")
                    await asyncio.sleep(wait_time)
                else:
                    # 3번 다 실패했을 경우에만 최종 FAILED 처리
                    finding["ai"] = {
                        "status": "FAILED",
                        "status_reason": None,
                        "label": None,
                        "confidence": None,
                        "needs_human_review": True,
                        "error": {"code": "AI_ERROR", "message": str(e), "retryable": True}
                    }
                    
        return finding

async def run_pipeline():
    print("AI 파이프라인 가동...")
    
    run_id = "run-20260827-150540-000000" 
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
    print(f"총 {total_count}개의 데이터를 병렬 처리합니다...")

    # 동시 실행 제한: 한 번에 20개씩만 API 통신
    semaphore = asyncio.Semaphore(20)
    coroutines = []

    # 태스크 예약
    for idx, finding in enumerate(findings_list, start=1):
        scan_status = finding.get("scan", {}).get("status")
        rule_label = finding.get("scan", {}).get("rule", {}).get("label")
        
        if scan_status == "COMPLETED":
            if rule_label == "SUSPECTED":
                coroutines.append(analyze_finding_async(finding, base_dir, cache_dict, semaphore))
            else:
                finding["ai"] = {"status": "NOT_REQUESTED", "status_reason": "RULE_NOT_SUSPECTED"}
                coroutines.append(asyncio.sleep(0, result=finding))
        else:
            finding["ai"] = {"status": "NOT_REQUESTED", "status_reason": "SCAN_FAILED"}
            coroutines.append(asyncio.sleep(0, result=finding))

    # 청크 단위 병렬 처리 및 체크포인트 중간 저장
    batch_size = 500  # 500개 처리할 때마다 로컬에 저장
    processed_findings = []

    for i in range(0, total_count, batch_size):
        # 500개씩 코루틴을 잘라서 병렬 실행
        batch = coroutines[i:i + batch_size]
        batch_results = await asyncio.gather(*batch)
        processed_findings.extend(batch_results)
        
        # 중간 저장 (체크포인트) - 스크립트가 죽어도 여기까지의 캐시는 안전하게 보존
        save_cache(cache_path, cache_dict)
        
        current_processed = min(i + batch_size, total_count)
        print(f"  [Checkpoint] {current_processed} / {total_count} 완료 (캐시 중간 저장 완료)")

    # 3. 상태 하향 및 저장 로직 유지
    has_failed = any(
        f.get("scan", {}).get("status") == "FAILED" or f.get("ai", {}).get("status") == "FAILED"
        for f in processed_findings
    )
    if has_failed and envelope.get("status") == "COMPLETED":
        envelope["status"] = "PARTIAL"
        
    envelope["findings"] = list(processed_findings)
    
    # 최종 결과물 저장
    output_dir = os.path.join("data", "processed", run_id)
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "results.json")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(envelope, f, ensure_ascii=False, indent=2)
        
    print(f"\n분석 및 캐시 저장 완료! '{output_file}'")
def main():
    # 비동기 이벤트 루프 실행
    asyncio.run(run_pipeline())

if __name__ == "__main__":
    main()