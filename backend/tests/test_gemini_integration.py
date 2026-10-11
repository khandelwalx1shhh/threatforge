import pytest
from unittest.mock import MagicMock
from fastapi.testclient import TestClient
from app.main import app
from app.services.gemini_detector import GeminiDetector

client = TestClient(app)

def test_gemini_service_graceful_when_no_key(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "")
    detector = GeminiDetector()
    # Without valid key in test environment, should be unavailable
    assert detector.is_available is False
    assert detector.analyze("Test message") is None

def test_health_reports_gemini_status():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert "gemini_configured" in data
    assert "gemini_model" in data

def test_analyze_without_cloud_consent_skips_gemini(monkeypatch):
    """When cloud_analysis is False, Gemini must never be invoked."""
    mock_analyze = MagicMock()
    from app.services.analyzer import gemini_detector
    monkeypatch.setattr(gemini_detector, "analyze", mock_analyze)

    payload = {
        "text": "Your account has been suspended! Click http://bank-update.xyz to verify.",
        "source": "whatsapp",
        "cloud_analysis": False
    }
    res = client.post("/api/analyze", json=payload)
    assert res.status_code == 200
    mock_analyze.assert_not_called()

def test_analyze_with_cloud_consent_and_mock_gemini(monkeypatch):
    """When cloud_analysis is True and Gemini is available, blends AI intelligence."""
    mock_gemini_return = {
        "engine": "Google Gemini",
        "model": "gemini-1.5-flash",
        "risk_score": 92,
        "risk_level": "critical",
        "intent_category": "Credential Harvesting",
        "psychological_tactics": ["Artificial Urgency", "Fear of Suspension"],
        "summary": "AI detected a fraudulent phishing attempt targeting online banking.",
        "reasons": ["Urgent threat of account deactivation", "Deceptive domain link"],
        "recommended_action": "Do not enter credentials. Verify via official banking app.",
        "confidence": 0.95
    }

    from app.services.analyzer import gemini_detector
    monkeypatch.setattr(gemini_detector, "is_available", True)
    monkeypatch.setattr(gemini_detector, "analyze", lambda text: mock_gemini_return)

    payload = {
        "text": "FINAL NOTICE: Your bank account is locked! Click http://sbi-login.xyz to verify immediately.",
        "source": "whatsapp",
        "cloud_analysis": True
    }
    res = client.post("/api/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_score"] >= 80
    assert data["risk_level"] == "critical"
    assert "gemini_analysis" in data
    assert data["gemini_analysis"] is not None
    assert data["gemini_analysis"]["intent_category"] == "Credential Harvesting"
    assert "Artificial Urgency" in data["gemini_analysis"]["psychological_tactics"]
    assert any("Gemini Threat Analysis" in b["label"] for b in data["breakdown"])
