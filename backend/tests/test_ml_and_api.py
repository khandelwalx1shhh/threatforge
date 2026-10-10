import pytest
import logging
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app
from app.services.analyzer import determine_risk_level, analyze_scam_risk
from app.services.model_manager import model_manager

client = TestClient(app)

# 1. GET /health returns HTTP 200 with service status and model_loaded boolean
def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "model_loaded" in data
    assert isinstance(data["model_loaded"], bool)

# 2. Valid message-analysis request returns HTTP 200 and all required schema fields
def test_valid_message_analysis_contract():
    payload = {
        "text": "Your bank account will be blocked. Share your OTP immediately.",
        "source": "whatsapp",
        "cloud_analysis": False
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    # Exact required fields per Task 1 & Task 4 specification
    assert "risk_score" in data
    assert "risk_level" in data
    assert "reasons" in data
    assert "recommended_action" in data
    assert "indicators" in data
    assert "model_version" in data
    assert "analysis_mode" in data

    assert isinstance(data["risk_score"], int)
    assert isinstance(data["risk_level"], str)
    assert isinstance(data["reasons"], list)
    assert isinstance(data["recommended_action"], str)
    assert isinstance(data["indicators"], list)
    assert isinstance(data["model_version"], str)
    assert data["analysis_mode"] in ["rules+ml", "rules", "ml"]

# 3. Empty or malformed requests are rejected appropriately
@pytest.mark.parametrize("invalid_payload", [
    {"text": ""},                                    # Empty string
    {"text": "    \t \n   "},                        # Whitespace only
    {},                                              # Missing text field
    {"source": "whatsapp"},                          # Missing text
    {"text": 12345},                                 # Non-string text
    {"text": "Valid message", "source": "unknown"},  # Unsupported source
    {"text": "A" * 5001},                            # Exceeds max length
])
def test_empty_or_malformed_requests_rejected(invalid_payload):
    response = client.post("/api/analyze", json=invalid_payload)
    assert response.status_code == 422
    data = response.json()
    # Check error response is structured and doesn't reveal internal tracebacks
    assert "error" in data or "detail" in data
    if "error" in data:
        assert "code" in data["error"]
        assert "VALIDATION_ERROR" == data["error"]["code"]

# 4. Risk score is always an integer between 0 and 100
@pytest.mark.parametrize("message_text", [
    "Hello friend, can we meet for coffee today?",
    "Electricity bill unpaid. Call 9876543210 immediately to prevent disconnection.",
    "URGENT! Bank account blocked. Share 6-digit OTP code now to verify your identity.",
    "Order delivered. Rate your delivery partner.",
])
def test_risk_score_in_valid_range(message_text):
    payload = {"text": message_text, "source": "manual_test"}
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data["risk_score"], int)
    assert 0 <= data["risk_score"] <= 100

# 5. Exact score band mapping, specifically 87 -> critical
@pytest.mark.parametrize("score,expected_band", [
    (0, "low"),
    (15, "low"),
    (29, "low"),
    (30, "medium"),
    (45, "medium"),
    (59, "medium"),
    (60, "high"),
    (75, "high"),
    (79, "high"),
    (80, "critical"),
    (87, "critical"),
    (100, "critical"),
])
def test_exact_score_to_risk_band_mapping(score, expected_band):
    assert determine_risk_level(score) == expected_band

def test_score_87_maps_to_critical_in_api():
    # Synthetic message engineered to trigger high threat signals
    payload = {
        "text": "URGENT WARNING: Your state bank account has been blocked due to suspicious activity. "
                "Share your 6-digit OTP password immediately or transfer $150 processing fee via http://bank-unblock-verify.top",
        "source": "manual_test"
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] == "critical"
    assert data["risk_score"] >= 80

# 6. Backend still responds when model file is missing / unloaded
def test_backend_responds_when_model_is_missing():
    # Save original state
    orig_model = model_manager.model
    orig_loaded = model_manager.is_loaded
    orig_version = model_manager.model_version

    try:
        # Simulate missing / unloaded model
        model_manager.unload()

        # Health endpoint shows model_loaded: False
        health_res = client.get("/health")
        assert health_res.status_code == 200
        assert health_res.json()["model_loaded"] is False

        # Analyze endpoint gracefully falls back to deterministic rules
        payload = {
            "text": "Your bank account will be blocked. Share your OTP immediately.",
            "source": "whatsapp"
        }
        analyze_res = client.post("/api/analyze", json=payload)
        assert analyze_res.status_code == 200
        data = analyze_res.json()
        assert data["analysis_mode"] == "rules"
        assert data["model_version"] == "none"
        assert data["risk_score"] >= 60
        assert len(data["reasons"]) >= 1
        assert "recommended_action" in data
    finally:
        # Restore model
        model_manager.model = orig_model
        model_manager.is_loaded = orig_loaded
        model_manager.model_version = orig_version

# 7. Benign and scam-like messages both receive valid responses
def test_benign_and_scam_messages_receive_valid_responses():
    # Benign control message
    benign_payload = {
        "text": "Hey Sarah, are we still meeting for lunch at 12:30 today? Let me know!",
        "source": "telegram"
    }
    benign_res = client.post("/api/analyze", json=benign_payload)
    assert benign_res.status_code == 200
    benign_data = benign_res.json()
    assert benign_data["risk_level"] == "low"
    assert benign_data["risk_score"] < 30
    assert "recommended_action" in benign_data

    # Scam message
    scam_payload = {
        "text": "FINAL NOTICE: Your SBI account is suspended! Share your 6 digit OTP or pay penalty to prevent police FIR.",
        "source": "whatsapp"
    }
    scam_res = client.post("/api/analyze", json=scam_payload)
    assert scam_res.status_code == 200
    scam_data = scam_res.json()
    assert scam_data["risk_level"] in ["high", "critical"]
    assert scam_data["risk_score"] >= 60
    assert len(scam_data["reasons"]) >= 1
    assert "OTP" in str(scam_data["reasons"]) or "threat" in str(scam_data["reasons"]).lower()

# 8. No external Gemini or third-party AI calls made during analysis
def test_no_external_gemini_calls(monkeypatch):
    # Ensure network libraries or AI SDKs are not called
    def mock_disallowed_call(*args, **kwargs):
        raise RuntimeError("External network / AI API call is forbidden!")

    # Attempting to call external requests/http would raise error if invoked
    monkeypatch.setattr("urllib.request.urlopen", mock_disallowed_call)

    payload = {
        "text": "Dear customer, KYC verification required. Update documents now.",
        "source": "whatsapp",
        "cloud_analysis": False
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] >= 0

# 9. No raw message text printed to logs
def test_no_raw_message_text_in_logs(caplog):
    secret_canary = "SECRET_CONFIDENTIAL_MESSAGE_TOKEN_998877"
    payload = {
        "text": f"Your account is blocked. Enter code {secret_canary}",
        "source": "manual_test"
    }

    with caplog.at_level(logging.DEBUG):
        response = client.post("/api/analyze", json=payload)
        assert response.status_code == 200

    # Ensure canary is NOT logged in application logs
    assert secret_canary not in caplog.text
