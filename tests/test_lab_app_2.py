from __future__ import annotations

from lab_app_2.app import create_app


def make_client(tmp_path):
    db_path = (tmp_path / "novastream-test.db").as_posix()
    app = create_app(
        {
            "TESTING": True,
            "DATABASE_URL": f"sqlite:///{db_path}",
            "SECRET_KEY": "test-only",
        }
    )
    return app.test_client()


def test_health_endpoint(tmp_path):
    response = make_client(tmp_path).get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"service": "novastream", "status": "ok"}


def test_home_shows_seeded_catalog(tmp_path):
    response = make_client(tmp_path).get("/")
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "우주의 경계" in body
    assert "심해의 기록" in body


def test_sqli_boolean_payload_returns_all_titles(tmp_path):
    response = make_client(tmp_path).get(
        "/catalog", query_string={"q": "' OR 1=1 -- "}
    )
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "우주의 경계" in body
    assert "시간의 문" in body


def test_reflected_xss_is_not_escaped(tmp_path):
    payload = "<script>window.__scanner_marker=1</script>"
    response = make_client(tmp_path).get("/discover", query_string={"q": payload})
    assert payload in response.get_data(as_text=True)


def test_stored_xss_is_escaped_for_viewer_but_raw_for_admin(tmp_path):
    client = make_client(tmp_path)
    payload = '<img src=x onerror="window.__stored_marker=1">'
    client.post(
        "/titles/1/reviews",
        data={"nickname": "scanner", "body": payload},
    )

    viewer_page = client.get("/titles/1").get_data(as_text=True)
    admin_page = client.get("/admin/reviews").get_data(as_text=True)

    assert payload not in viewer_page
    assert "&lt;img" in viewer_page
    assert payload in admin_page


def test_review_reset_removes_stored_payloads(tmp_path):
    client = make_client(tmp_path)
    client.post(
        "/titles/1/reviews",
        data={"nickname": "scanner", "body": "stored-marker"},
    )
    response = client.post("/admin/reviews/clear", follow_redirects=True)
    assert response.status_code == 200
    assert "stored-marker" not in response.get_data(as_text=True)
