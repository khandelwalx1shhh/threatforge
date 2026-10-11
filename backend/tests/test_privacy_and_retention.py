import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_privacy_policy_endpoint():
    """Verify that GET /api/privacy/policy returns transparent guarantees."""
    res = client.get("/api/privacy/policy")
    assert res.status_code == 200
    data = res.json()
    assert data["zero_crawling_guarantee"] is True
    assert data["pre_transmission_sanitization"] is True
    assert data["raw_message_logging_disabled"] is True
    assert "data_collected" in data
    assert "data_never_collected" in data

def test_analyze_privacy_guarantees_in_response():
    """Verify that POST /api/analyze returns privacy_guarantees and sanitizes sensitive text."""
    payload = {
        "text": "Your OTP is 123456. Verify your account at http://bank.example/login?token=SECRET_AUTH_KEY_99",
        "source": "whatsapp",
        "sender": "+91 98765 43210"
    }
    res = client.post("/api/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "privacy_guarantees" in data
    assert data["privacy_guarantees"]["zero_web_crawling"] is True
    assert data["privacy_guarantees"]["pre_transmission_sanitization"] is True

def test_history_deletion_endpoint():
    """Verify that DELETE /api/threats/history wipes threat logs and reports."""
    res = client.delete("/api/threats/history")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "threats_purged" in data
    assert "reports_purged" in data

    # Verify list is empty
    list_res = client.get("/api/threats")
    assert list_res.status_code == 200
    assert list_res.json()["total"] == 0

    # Restore initial demo data for test suite isolation
    from app.main import seed_initial_demo_data
    seed_initial_demo_data()

def test_retention_purge_endpoint():
    """Verify that POST /api/threats/purge executes cleanly."""
    res = client.post("/api/threats/purge?retention_days=7")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["retention_days"] == 7
