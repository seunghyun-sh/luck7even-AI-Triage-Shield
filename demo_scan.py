import tempfile
from pathlib import Path
from analysis.models import TargetCase, TargetInput, RequestPolicy
from orchestration.pipeline import ScanContext
from scanners.sqli import scan as sqli_scan

def ctx(base_url):
    return ScanContext(
        scan_run_id="demo", base_url=base_url,
        request_policy=RequestPolicy(timeout_seconds=10, follow_redirects=False),
        responses_dir=Path(tempfile.mkdtemp()),
        resolve_auth_profile=lambda pid: (_ for _ in ()).throw(KeyError(pid)),
    )

scenarios = [
    ("① Lumi Market 로그인 우회", "http://127.0.0.1:5001", TargetCase(
        case_id="demo-login", vuln_type="SQLI", path="/account/login", method="POST",
        input=TargetInput(location="form", parameters={"username": "not_a_user", "password": "wrong"}, attack_parameter="username"),
        requires_pre_auth=False, auth_profile=None,
        payload_profile="sqli-default", manual_verification_profile="sqli-response-difference",
    )),
    ("② Lumi Market 검색창 에러 노출", "http://127.0.0.1:5001", TargetCase(
        case_id="demo-search", vuln_type="SQLI", path="/search", method="GET",
        input=TargetInput(location="query", parameters={"q": "헤드폰"}, attack_parameter="q"),
        requires_pre_auth=False, auth_profile=None,
        payload_profile="sqli-default", manual_verification_profile="sqli-response-difference",
    )),
        ("③④ NovaStream 에러 노출 + OR 1=1 데이터 전체 유출", "http://127.0.0.1:5000", TargetCase(
        case_id="demo-catalog", vuln_type="SQLI", path="/catalog", method="GET",
        input=TargetInput(location="query", parameters={"q": "SF"}, attack_parameter="q"),
        requires_pre_auth=False, auth_profile=None,
        payload_profile="sqli-waf-bypass", manual_verification_profile="sqli-response-difference",
    )),
        ("⑤ Lumi Market /products/stock (신규 Boolean-based)", "http://127.0.0.1:5001", TargetCase(
        case_id="demo-stock", vuln_type="SQLI", path="/products/stock", method="GET",
        input=TargetInput(location="query", parameters={"product_id": "1"}, attack_parameter="product_id"),
        requires_pre_auth=False, auth_profile=None,
        payload_profile="sqli-default", manual_verification_profile="sqli-response-difference",
    )),
]

for title, base_url, target in scenarios:
    print(f"\n{'='*72}\n{title}\n{'='*72}")
    for f in sqli_scan([target], ctx(base_url), lambda c, t: None):
        pc = f.case_id.split("::", 1)[1]
        rule = f.scan.rule.label.value if f.scan.rule.label else "-"
        mark = "🚨 SUSPECTED" if rule == "SUSPECTED" else "   safe     "
        print(f"  {mark} | {pc:22s} | {f.scan.rule.reason}")