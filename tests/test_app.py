from fastapi.testclient import TestClient

from app.api import app


client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    payload = response.json()
    assert payload["service"] == "Adversarial AI Red-Team Lab"


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_ollama_health_endpoint_reports_local_provider_state():
    response = client.get("/health/ollama")
    assert response.status_code == 200
    assert response.json()["provider"] == "rule-based"
    assert response.json()["available"] is True


def test_dashboard_route_serves_frontend():
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "Red-Team Lab" in response.text


def test_attack_run_requires_api_key():
    response = client.post("/attack-runs", json={})
    assert response.status_code == 401


def test_attack_run_is_persisted_and_can_be_replayed():
    headers = {"X-API-Key": "local-dev-key"}
    response = client.post(
        "/attack-runs",
        json={"families": ["prompt_injection"]},
        headers=headers,
    )
    assert response.status_code == 200
    run = response.json()
    assert run["total_attacks"] == 1

    history = client.get("/history", headers=headers)
    assert history.status_code == 200
    assert any(item["run_id"] == run["run_id"] for item in history.json()["runs"])

    replay = client.post(
        f"/history/{run['run_id']}/replay/prompt_injection",
        headers=headers,
    )
    assert replay.status_code == 200
    assert replay.json()["total_attacks"] == 1

    audit = client.get("/audit-log", headers=headers)
    assert audit.status_code == 200
    assert any(item["action"] == "attack_replayed" for item in audit.json()["events"])


def test_demo_endpoint_returns_assessment():
    response = client.get("/demo")
    assert response.status_code == 200
    payload = response.json()
    assert "overall_score" in payload
    assert "category_scores" in payload
    assert "findings" in payload
    assert len(payload["findings"]) >= 2
