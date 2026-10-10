import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_full_system_workflow():
    # 1. Check Health Endpoint
    health_res = client.get("/health")
    assert health_res.status_code == 200
    assert health_res.json()["status"] == "ok"
    assert "model_loaded" in health_res.json()

    # 2. Analyze a suspicious scam message
    scam_msg = (
        "URGENT POLICE NOTICE: Your bank account is compromised! "
        "Pay $100 fine to support-tax@upi or click http://fake-cbi-verify.top immediately or legal warrant will be issued."
    )
    analyze_res = client.post("/api/analyze", json={"message": scam_msg})
    assert analyze_res.status_code == 200
    analysis_data = analyze_res.json()
    assert analysis_data["risk_score"] >= 80
    assert analysis_data["risk_level"] == "critical"
    assert len(analysis_data["indicators"]) >= 2

    # 3. Engage scammer in honeypot chat
    chat_res1 = client.post("/api/chat", json={
        "message": "Send 0.2 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa right now!",
        "persona": "victim"
    })
    assert chat_res1.status_code == 200
    chat_data1 = chat_res1.json()
    session_id = chat_data1["session_id"]
    assert chat_data1["reply"] is not None
    assert chat_data1["turn_count"] == 1

    # Second turn in same session
    chat_res2 = client.post("/api/chat", json={
        "session_id": session_id,
        "message": "Do it now or account locked!",
        "persona": "victim"
    })
    assert chat_res2.status_code == 200
    chat_data2 = chat_res2.json()
    assert chat_data2["session_id"] == session_id
    assert chat_data2["turn_count"] == 2

    # 4. Extract IOCs directly
    extract_res = client.post("/api/extract", json={
        "text": "Phishing link http://evil-login.xyz and UPI payment@okicici"
    })
    assert extract_res.status_code == 200
    extract_data = extract_res.json()
    assert extract_data["count"] == 2

    # 5. Query Threat Intelligence DB
    threats_res = client.get("/api/threats")
    assert threats_res.status_code == 200
    threats_data = threats_res.json()
    assert threats_data["total"] >= 2
    assert len(threats_data["items"]) >= 2

    # 6. Check Dashboard Aggregated Metrics
    dash_res = client.get("/api/dashboard")
    assert dash_res.status_code == 200
    dash_data = dash_res.json()
    assert dash_data["metrics"]["total_sessions"] >= 1
    assert dash_data["metrics"]["indicators_captured"] >= 2
    assert len(dash_data["threats"]) >= 1
    assert len(dash_data["activity"]) >= 1
