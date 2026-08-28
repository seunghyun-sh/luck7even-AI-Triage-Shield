from lab_app.app import create_app


def test_health_endpoint() -> None:
    client = create_app().test_client()

    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"
