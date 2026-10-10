import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.analyzer import analyze_scam_risk
from app.schemas.common import SeverityEnum

client = TestClient(app)

def test_analyze_benign_control_message():
    message = "Hi mom, I will be home for dinner around 7pm. Love you!"
    response = analyze_scam_risk(message)

    assert response.risk_score < 25.0
    assert response.risk_level == SeverityEnum.LOW
    assert len(response.breakdown) == 0
    assert len(response.indicators) == 0
    assert "LOW RISK" in response.summary

def test_analyze_suspicious_sample_message():
    message = (
        "URGENT NOTICE! Your bank support account is suspended! "
        "Visit http://phishing-bank.xyz immediately and share your 6-digit OTP to verify or legal action will be taken."
    )
    response = analyze_scam_risk(message)

    assert response.risk_score >= 80.0
    assert response.risk_level == SeverityEnum.CRITICAL
    assert len(response.breakdown) >= 3
    assert len(response.indicators) >= 1
    assert any("Urgency" in f.factor for f in response.breakdown)
    assert any("Credential" in f.factor for f in response.breakdown)
    assert any("Phishing" in f.factor for f in response.breakdown)

def test_analyze_score_87_maps_to_critical():
    # Message triggering Urgency (+25), Payment (+25), Phishing Link (+22), Impersonation (+15) = 87.0
    message = (
        "URGENT: Income tax department refund pending. Pay processing fee of $50 via http://tax-refund.net or account will be blocked."
    )
    response = analyze_scam_risk(message)

    assert response.risk_score >= 80.0
    assert response.risk_level == SeverityEnum.CRITICAL
    assert len(response.breakdown) >= 3

def test_analyze_endpoint_http_call():
    payload = {
        "message": "Urgent! Send 0.1 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or your password will be leaked."
    }
    res = client.post("/api/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()

    assert data["risk_score"] > 50.0
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    assert len(data["breakdown"]) >= 2
    assert len(data["indicators"]) >= 1

def test_analyze_endpoint_empty_input_validation():
    res_empty = client.post("/api/analyze", json={"message": ""})
    assert res_empty.status_code == 422

    res_whitespace = client.post("/api/analyze", json={"message": "   \t\n  "})
    assert res_whitespace.status_code == 422
