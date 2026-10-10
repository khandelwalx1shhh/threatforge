from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "model_loaded" in data

def test_analyze_endpoint_placeholder():
    payload = {"message": "Urgent! Transfer funds to account 123456 immediately"}
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "risk_score" in data
    assert "risk_level" in data
    assert "summary" in data

def test_chat_endpoint_placeholder():
    payload = {"message": "Hello victim, send Bitcoin", "persona": "victim"}
    response = client.post("/api/chat", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "session_id" in data
    assert "reply" in data
    assert data["persona"] == "victim"

def test_extract_endpoint_placeholder():
    payload = {"text": "Check out https://phishing-bank-verify.example and wire to 987654321"}
    response = client.post("/api/extract", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "indicators" in data
    assert "count" in data

def test_threats_endpoint_placeholder():
    response = client.get("/api/threats")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert len(data["items"]) >= 1

def test_dashboard_endpoint_placeholder():
    response = client.get("/api/dashboard")
    assert response.status_code == 200
    data = response.json()
    assert "metrics" in data
    assert "threats" in data
    assert "activity" in data
    assert "distribution" in data
    assert data["metrics"]["total_sessions"] > 0
