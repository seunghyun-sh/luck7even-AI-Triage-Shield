"""scanners/sqli.py의 판정 로직을 실제 서버 없이 검증하는 자동 테스트."""

from scanners import sqli


class FakeResponse:
    def __init__(self, text="", status_code=200):
        self.text = text
        self.status_code = status_code


def test_run_case_flags_db_error(monkeypatch):
    def fake_get(url, params=None, timeout=None):
        payload = params.get("id", "")
        if "union" in payload.lower():
            return FakeResponse("Error: you have an error in your sql syntax", 500)
        return FakeResponse("검색 결과가 없습니다", 200)

    monkeypatch.setattr(sqli.requests, "get", fake_get)

    finding = sqli.run_case("http://fake", "/case/x", "id", "' UNION SELECT NULL--")

    assert finding["rule_label"] == "취약 의심"
    assert "DB 오류" in finding["rule_reason"]


def test_run_case_flags_normal_value_as_safe(monkeypatch):
    def fake_get(url, params=None, timeout=None):
        return FakeResponse("검색 결과가 없습니다", 200)

    monkeypatch.setattr(sqli.requests, "get", fake_get)

    finding = sqli.run_case("http://fake", "/case/x", "id", "laptop")

    assert finding["rule_label"] == "양호"


def test_check_boolean_pair_detects_difference(monkeypatch):
    def fake_get(url, params=None, timeout=None):
        payload = params.get("id", "")
        if "1=1" in payload:
            return FakeResponse("검색 결과 3건: laptop, phone, keyboard", 200)
        return FakeResponse("검색 결과 0건", 200)

    monkeypatch.setattr(sqli.requests, "get", fake_get)

    finding = sqli.check_boolean_pair("http://fake", "/case/x", "id", "' AND 1=1--", "' AND 1=2--")

    assert finding["rule_label"] == "취약 의심"


def test_check_login_bypass_detects_bypass(monkeypatch):
    def fake_post(url, data=None, timeout=None):
        username = data.get("username", "")
        if "' or '1'='1" in username.lower():
            return FakeResponse("로그인 성공! 환영합니다.", 200)
        return FakeResponse("로그인 실패", 401)

    monkeypatch.setattr(sqli.requests, "post", fake_post)

    finding = sqli.check_login_bypass(
        "http://fake", "/case/sqli-login", "username", "password", "' OR '1'='1'-- -"
    )

    assert finding["rule_label"] == "취약 의심"