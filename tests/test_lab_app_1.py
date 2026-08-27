from pathlib import Path

import pytest

from lab_app.app import create_app


@pytest.fixture()
def client(tmp_path: Path):
    app = create_app(
        {
            "TESTING": True,
            "DATABASE": str(tmp_path / "lumi_market_1.sqlite3"),
            "SECRET_KEY": "test-session-key-1",
            "LAB_1_RESET_TOKEN": "test-reset-token-1",
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
        "/account/login",
        "/account/register",
        "/reviews",
        "/support",
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


def test_search_sqli_surfaces_database_error(client) -> None:
    response = client.get("/search", query_string={"q": "' OR"})
    assert response.status_code == 200
    assert b'data-testid="sql-error"' in response.data


def test_cart_adds_product(client) -> None:
    response = client.post("/cart/add/1", follow_redirects=True)
    assert response.status_code == 200
    assert "Nova 무선 헤드폰".encode() in response.data


def test_reset_endpoint_requires_token(client) -> None:
    assert client.post("/internal/lab-1/reset").status_code == 404
    response = client.post(
        "/internal/lab-1/reset",
        headers={"X-Lab-1-Reset-Token": "test-reset-token-1"},
    )
    assert response.status_code == 200
    assert response.get_json() == {"status": "reset"}
