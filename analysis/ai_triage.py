"""OpenAI-based secondary assessment boundary."""
import os
import json
import hashlib
import re
import asyncio
from dotenv import load_dotenv
from openai import AsyncOpenAI  # 비동기 클라이언트로 변경

from datetime import datetime, timezone
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


# vector_store_id 매개변수 추가
async def analyze_finding_async(finding, base_dir, cache_dict, semaphore, vector_store_id="vs_dummy_test_123"):
    async with semaphore:
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
        
        # 캐시 키에 프롬프트 버전 및 지식베이스 버전 포함
        prompt_version = "triage-report-v2"
        kb_version = "security-guides-2026-08-01"
        hash_input = f"{payload}|||{safe_html_snippet}|||gpt-4o-mini|||{prompt_version}|||{kb_version}"
        cache_key = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()

        if cache_key in cache_dict:
            finding["ai"] = cache_dict[cache_key]
            return finding

        # 프롬프트 생성 (다음 단계에서 RAG용으로 수정할 예정)
        prompt = get_triage_prompt(
            url=req_data.get('url', 'N/A'),
            parameter=req_data.get('parameter', 'N/A'),
            payload=payload,
            html_content=safe_html_snippet 
        )

        max_retries = 3
        for attempt in range(max_retries):
            try:
                # Responses API / File Search 연동 및 Structured Outputs 강제
                response = await aclient.beta.chat.completions.parse(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": "당신은 스캔 증거와 공식 지식베이스를 바탕으로 보안 취약점의 근거(Claim)를 분석하는 어시스턴트입니다. 최종 판정은 내리지 않습니다."},
                        {"role": "user", "content": prompt}
                    ],
                    response_format=AIAnalysisResult,
                    tools=[{"type": "file_search"}], # RAG 문서 검색 도구 활성화
                    tool_resources={"file_search": {"vector_store_ids": [vector_store_id]}},
                    temperature=0
                )
                
                # Pydantic 모델로 파싱된 결과(Claims) 획득
                ai_parsed = response.choices[0].message.parsed
                
                # AI의 응답을 바탕으로 백엔드가 메타데이터를 통제함
                claims_list = []
                reference_set = set()
                
                for idx, claim in enumerate(ai_parsed.claims, start=1):
                    # 모델이 찾아온 내부 result_id를 서버가 검증 후 R# 부여 (임시 로직)
                    refs = [f"R{idx}" for _ in claim.retrieved_result_ids] 
                    
                    claims_list.append({
                        "claim_id": f"C{idx}",
                        "claim_type": claim.claim_type,
                        "text": claim.text,
                        "evidence_ids": claim.evidence_keys, # E#은 추후 매핑
                        "reference_ids": refs
                    })
                    reference_set.update(refs)
                
                # 출처(Reference)가 하나라도 있으면 GROUNDED, 없으면 INSUFFICIENT_EVIDENCE
                grounding_status = "GROUNDED" if reference_set else "INSUFFICIENT_EVIDENCE"
                needs_human_review = True # 최종 판정은 무조건 사람이 하도록 강제
                
                finding["ai"] = {
                    "status": "COMPLETED",
                    "status_reason": None if reference_set else "NO_TRUSTED_REFERENCE",
                    "role": "EVIDENCE_GROUNDED_REPORTING",
                    "needs_human_review": needs_human_review,
                    "grounding_status": grounding_status,
                    "claims": claims_list,
                    "report_draft": {
                         # 나중에 claims_list를 순회하며 서버가 직접 문단을 조립할 영역
                         "claim_ids": [c["claim_id"] for c in claims_list]
                    } if grounding_status == "GROUNDED" else None,
                    "references": [{"reference_id": r, "source_id": "DUMMY"} for r in reference_set],
                    "provenance": {
                        "execution": {
                            "model": "gpt-4o-mini",
                            "prompt_version": prompt_version,
                            "generated_at": datetime.now(timezone.utc).isoformat()
                        },
                        "knowledge_base_version": kb_version,
                        "output_schema_version": "1.1",
                        "vector_store_ids": [vector_store_id]
                    },
                    "error": None
                }
                cache_dict[cache_key] = finding["ai"]
                break
                
            except Exception as e:
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    finding_id = finding.get('finding_id', 'Unknown')
                    print(f" {finding_id} - {wait_time}초 후 재시도 ({attempt+1}/{max_retries})")
                    await asyncio.sleep(wait_time)
                else:
                    # 실패 시 문서 8.4항에 따라 AiFailedProvenance 제한형으로 기록
                    finding["ai"] = {
                        "status": "FAILED",
                        "grounding_status": "NOT_APPLICABLE",
                        "claims": [],
                        "references": [],
                        "report_draft": None,
                        "provenance": {
                             "execution": {
                                  "model": "gpt-4o-mini",
                                  "prompt_version": prompt_version,
                                  "attempted_at": datetime.now(timezone.utc).isoformat()
                             }
                        },
                        "error": {"code": "AI_TIMEOUT", "message": str(e)}
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