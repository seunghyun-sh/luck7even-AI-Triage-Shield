"""SQL injection assessment logic."""

import time
import requests

DB_ERROR_KEYWORDS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unknown column",
    "sql syntax",
]


def _looks_like_db_error(response_text: str) -> bool:
    lowered = response_text.lower()
    return any(keyword in lowered for keyword in DB_ERROR_KEYWORDS)


def run_case(base_url: str, path: str, parameter: str, payload: str,
             baseline_value: str = "laptop", timeout: int = 10) -> dict:
    """하나의 대상(path+parameter)에 대해 payload 1개를 테스트하고 Finding 1건을 반환한다.
    반환 형식은 docs/data_contract_v1.md의 Contract A를 따른다.
    """
    url = f"{base_url}{path}"

    baseline_started = time.monotonic()
    baseline_resp = requests.get(url, params={parameter: baseline_value}, timeout=timeout)
    baseline_elapsed_ms = int((time.monotonic() - baseline_started) * 1000)

    started = time.monotonic()
    resp = requests.get(url, params={parameter: payload}, timeout=timeout)
    elapsed_ms = int((time.monotonic() - started) * 1000)

    db_error = _looks_like_db_error(resp.text)
    time_delay = elapsed_ms > baseline_elapsed_ms + 3000  # 3초 이상 더 걸리면 의심

    if db_error:
        rule_label, rule_reason = "취약 의심", "DB 오류 메시지가 응답에 노출됨"
    elif time_delay:
        rule_label, rule_reason = "취약 의심", "정상 요청보다 응답이 3초 이상 지연됨(시간 지연 의심)"
    else:
        rule_label, rule_reason = "양호", "DB 오류·시간 지연 신호가 관찰되지 않음"

    return {
        # --- Contract A 필수 필드 (docs/data_contract_v1.md) ---
        "finding_id": f"SQLI-{int(time.time() * 1000)}",
        "vuln_type": "SQLI",
        "url": url,
        "parameter": parameter,
        "payload": payload,
        "rule_label": rule_label,
        "response_body": resp.text,
        # --- 필수는 아니지만 판정에 필요해서 추가로 남기는 값들 ---
        "rule_reason": rule_reason,
        "http_status": resp.status_code,
        "elapsed_ms": elapsed_ms,
        "baseline_elapsed_ms": baseline_elapsed_ms,
    }


if __name__ == "__main__":
    # 스스로 켜둔 lab_app(/health)을 대상으로 동작만 확인하는 간단한 테스트.
    # 실제 SQLi 판정 테스트는 1팀의 취약 페이지가 준비된 뒤 의미가 있습니다.
    result = run_case("http://127.0.0.1:5000", "/health", "q", "' OR '1'='1")
    print(result["rule_label"], "-", result["rule_reason"])