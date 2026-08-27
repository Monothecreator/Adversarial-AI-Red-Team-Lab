from fastapi.testclient import TestClient

from app.api import app


client = TestClient(app)


def test_rag_store_returns_relevant_policy():
    from knowledge_base.store import KnowledgeBase

    store = KnowledgeBase()
    result = store.search("refund eligibility")

    assert result[0]["title"] == "Refund Policy"
    assert "refund" in result[0]["content"].lower()


def test_security_report_endpoint():
    response = client.get("/report")
    assert response.status_code == 200
    payload = response.json()
    assert payload["service"] == "Adversarial AI Red-Team Lab"
    assert "summary" in payload
    assert "high_risk_areas" in payload
