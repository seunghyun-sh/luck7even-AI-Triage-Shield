from pathlib import Path
from time import perf_counter

import pytest

from lab_app.app import create_app


@pytest.fixture()
def client(tmp_path: Path):
    app = create_app(
        {
            "TESTING": True,
            "DB_ENGINE": "sqlite",
            "DATABASE": str(tmp_path / "lumi_market_1.sqlite3"),
            "SECRET_KEY": "test-session-key-1",
            "LAB_1_RESET_TOKEN": "test-reset-token-1",
            "LAB_1_SECURITY_MODE": "vulnerable",
        }
    )
    return app.test_client()


@pytest.fixture()
def secure_client(tmp_path: Path):
    app = create_app(
        {
            "TESTING": True,
            "DB_ENGINE": "sqlite",
            "DATABASE": str(tmp_path / "lumi_market_1_secure.sqlite3"),
            "SECRET_KEY": "test-session-key-1",
            "LAB_1_RESET_TOKEN": "test-reset-token-1",
            "LAB_1_SECURITY_MODE": "secure",
        }
    )
    return app.test_client()


def test_health_endpoint(client) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/products",
        "/products/1",
        "/search",
        "/cart",
        "/coupon/check",
        "/account/login",
        "/account/register",
        "/reviews",
        "/support",
        "/support/preview",
    ],
)
def test_storefront_pages_render(client, path: str) -> None:
    response = client.get(path)
    assert response.status_code == 200
    assert b"LUMI" in response.data


def test_reflected_xss_marker_is_unescaped_in_search_summary(client) -> None:
    marker = "<xss-reflection-marker>"
    response = client.get("/search", query_string={"q": marker})
    assert response.status_code == 200
    assert f"“{marker}”".encode() in response.data


def test_stored_xss_marker_is_persisted_unescaped(client) -> None:
    marker = "<stored-xss-marker>"
    response = client.post(
        "/reviews",
        data={"author": "tester", "title": "test", "content": marker, "rating": "5"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert marker.encode() in response.data


def test_login_sqli_changes_authentication_result(client) -> None:
    normal = client.post(
        "/account/login",
        data={"username": "admin", "password": "wrong"},
    )
    assert b'data-testid="login-failure"' in normal.data

    injected = client.post(
        "/account/login",
        data={"username": "' OR '1'='1' -- ", "password": "anything"},
        follow_redirects=True,
    )
    assert injected.status_code == 200
    assert b"MY LUMI" in injected.data


def test_boolean_blind_sqli_changes_stock_response(client) -> None:
    true_condition = client.get(
        "/products/stock",
        query_string={"product_id": "1 AND 1=1"},
    )
    false_condition = client.get(
        "/products/stock",
        query_string={"product_id": "1 AND 1=2"},
    )
    assert true_condition.get_json()["available"] is True
    assert false_condition.get_json()["available"] is False


def test_time_blind_sqli_creates_controlled_response_delay(client) -> None:
    slow_code = "NOPE' OR (CASE WHEN 1=1 THEN SLEEP(0.08) ELSE 0 END)=0 -- "
    fast_code = "NOPE' OR (CASE WHEN 1=2 THEN SLEEP(0.08) ELSE 0 END)=0 -- "

    started = perf_counter()
    slow_response = client.get("/coupon/check", query_string={"code": slow_code})
    slow_elapsed = perf_counter() - started

    started = perf_counter()
    fast_response = client.get("/coupon/check", query_string={"code": fast_code})
    fast_elapsed = perf_counter() - started

    assert slow_response.status_code == 200
    assert fast_response.status_code == 200
    assert slow_elapsed - fast_elapsed >= 0.05


def test_dom_xss_preview_exposes_intentional_browser_sink(client) -> None:
    response = client.get("/support/preview")
    assert b'data-security-mode="vulnerable"' in response.data
    script = Path("lab_app/static/js/store.js").read_text(encoding="utf-8")
    assert "output.innerHTML = message" in script


def test_cart_adds_product(client) -> None:
    response = client.post("/cart/add/1", follow_redirects=True)
    assert response.status_code == 200
    assert "Nova 무선 헤드폰".encode() in response.data


def test_reset_endpoint_requires_token(client) -> None:
    assert client.post("/internal/lab-1/reset").status_code == 404
    marker = "reset-me-marker"
    client.post(
        "/reviews",
        data={"author": "tester", "title": "test", "content": marker, "rating": "5"},
    )
    response = client.post(
        "/internal/lab-1/reset",
        headers={"X-Lab-1-Reset-Token": "test-reset-token-1"},
    )
    assert response.status_code == 200
    assert response.get_json() == {"status": "reset"}
    assert marker.encode() not in client.get("/reviews").data


def test_secure_mode_blocks_the_six_training_flows(secure_client) -> None:
    xss_marker = "<img src=x onerror=alert(1)>"

    reflected = secure_client.get("/search", query_string={"q": xss_marker})
    assert xss_marker.encode() not in reflected.data
    assert b"&lt;img" in reflected.data

    stored = secure_client.post(
        "/reviews",
        data={"author": "tester", "title": "safe", "content": xss_marker, "rating": "5"},
        follow_redirects=True,
    )
    assert xss_marker.encode() not in stored.data
    assert b"&lt;img" in stored.data

    dom_preview = secure_client.get("/support/preview")
    assert b'data-security-mode="secure"' in dom_preview.data

    login = secure_client.post(
        "/account/login",
        data={"username": "' OR '1'='1' -- ", "password": "anything"},
    )
    assert b'data-testid="login-failure"' in login.data

    boolean_blind = secure_client.get(
        "/products/stock",
        query_string={"product_id": "1 AND 1=1"},
    )
    assert boolean_blind.status_code == 400

    time_blind = secure_client.get(
        "/coupon/check",
        query_string={
            "code": "NOPE' OR (SELECT SLEEP(1))=0 -- ",
        },
    )
    assert b'data-testid="coupon-invalid"' in time_blind.data


def test_mysql_delivery_files_define_the_expected_services() -> None:
    compose = Path("lab_app/compose.yml").read_text(encoding="utf-8")
    schema = Path("lab_app/schema_mysql.sql").read_text(encoding="utf-8")
    assert "mysql-1:" in compose
    assert "web-1:" in compose
    assert "LAB_1_DB_ENGINE: mysql" in compose
    assert "CREATE TABLE IF NOT EXISTS coupons" in schema
