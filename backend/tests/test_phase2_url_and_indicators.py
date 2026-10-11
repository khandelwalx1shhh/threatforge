import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.model_manager import model_manager
from app.services.url_analyzer import url_classifier_service
from app.services.extractor import extract_indicators, sanitize_url, sanitize_snippet

client = TestClient(app)

# 1. GET /health works and accurately reports model availability
def test_item1_health_reports_model_availability():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "model_loaded" in data
    assert "url_model_loaded" in data
    assert "url_model_version" in data
    assert isinstance(data["url_model_loaded"], bool)

# 2. POST /api/analyze handles a suspicious-looking synthetic message
def test_item2_analyze_suspicious_synthetic_message():
    payload = {
        "text": "URGENT: Your bank account will be blocked within 24 hours. Verify immediately: http://192.168.1.50/login.php",
        "source": "manual_test"
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] >= 60
    assert data["risk_level"] in ["high", "critical"]
    assert len(data["reasons"]) > 0
    assert "recommended_action" in data
    assert len(data["indicators"]) > 0

# 3. POST /api/analyze handles a benign synthetic message
def test_item3_analyze_benign_synthetic_message():
    payload = {
        "text": "Hi team, please find the meeting notes attached. See you tomorrow at 10 AM.",
        "source": "email"
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] <= 29
    assert data["risk_level"] == "low"
    assert "recommended_action" in data

# 4. A message with a URL invokes URL analysis when appropriate
def test_item4_message_with_url_invokes_url_analysis():
    payload = {
        "text": "Important update from billing team: please review http://verify-secure-account.xyz/billing",
        "source": "manual_test"
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    # Check that URL indicator is present
    url_iocs = [i for i in data["indicators"] if "URL" in i["type"]]
    assert len(url_iocs) >= 1
    # Check that reasons reflect URL characteristics (e.g. suspicious TLD)
    has_url_reason = any(".xyz" in r.lower() or "link" in r.lower() or "url" in r.lower() or "auth" in r.lower() for r in data["reasons"])
    assert has_url_reason

# 5. A URL-only or URL-containing input returns valid output
def test_item5_url_only_input():
    payload = {
        "text": "https://secure-login.suspicious-bank.sbs/verify?account=test",
        "source": "manual_test"
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert 0 <= data["risk_score"] <= 100
    assert data["risk_level"] in ["low", "medium", "high", "critical"]
    assert len(data["reasons"]) >= 1
    assert "recommended_action" in data
    assert data["model_version"] is not None

# 6. Malformed input returns an appropriate error
@pytest.mark.parametrize("invalid_payload", [
    {},  # missing text/message
    {"text": ""},  # empty string
    {"text": "   "},  # whitespace only
    {"text": 12345},  # non-string
    {"text": "Valid message", "source": "unsupported_channel"}  # invalid source
])
def test_item6_malformed_input_rejected(invalid_payload):
    response = client.post("/api/analyze", json=invalid_payload)
    assert response.status_code == 422
    data = response.json()
    assert "error" in data or "detail" in data

# 7. Scores remain within 0–100
@pytest.mark.parametrize("test_text", [
    "Hello world!",
    "URGENT: BANK BLOCKED! CALL +919876543210 SEND OTP NOW! PAY 5000 USDT TO 0x71C841832049902347b01b63",
    "http://192.168.1.1/admin/login?token=abc",
    "Meeting rescheduled to 3 PM."
])
def test_item7_scores_bounded_0_to_100(test_text):
    response = client.post("/api/analyze", json={"text": test_text})
    assert response.status_code == 200
    data = response.json()
    assert 0 <= data["risk_score"] <= 100

# 8. Risk band boundaries are correct, including 29, 30, 59, 60, 79, and 80
from app.services.analyzer import determine_risk_level

def test_item8_exact_risk_band_boundaries():
    assert determine_risk_level(0) == "low"
    assert determine_risk_level(29) == "low"
    assert determine_risk_level(30) == "medium"
    assert determine_risk_level(59) == "medium"
    assert determine_risk_level(60) == "high"
    assert determine_risk_level(79) == "high"
    assert determine_risk_level(80) == "critical"
    assert determine_risk_level(100) == "critical"

# 9. Score 87 returns critical
def test_item9_score_87_returns_critical():
    assert determine_risk_level(87) == "critical"

# 10. The service still responds if text model or URL model is unavailable
def test_item10_service_responds_when_models_unavailable():
    # Save original states
    orig_text_loaded = model_manager.is_loaded
    orig_text_model = model_manager.model
    orig_url_loaded = url_classifier_service.is_loaded
    orig_url_pipe = url_classifier_service.pipeline

    try:
        # Unload both models
        model_manager.unload()
        url_classifier_service.unload()

        # Service still responds gracefully using rules fallback
        response = client.post("/api/analyze", json={
            "text": "URGENT! Account suspended. Visit http://update-kyc.sbs immediately to unfreeze.",
            "source": "manual_test"
        })
        assert response.status_code == 200
        data = response.json()
        assert data["analysis_mode"] == "rules"
        assert data["risk_score"] >= 60
        assert data["risk_level"] in ["high", "critical"]
        assert len(data["reasons"]) >= 1
    finally:
        # Restore models
        model_manager.is_loaded = orig_text_loaded
        model_manager.model = orig_text_model
        url_classifier_service.is_loaded = orig_url_loaded
        url_classifier_service.pipeline = orig_url_pipe

# 11. Indicator extraction does not duplicate values within a result
def test_item11_indicator_extraction_no_duplicates():
    text = (
        "Send funds to 0x71C841832049902347b01b63b21b79f88d22d3b2 or visit https://example.com/pay. "
        "Also visit https://example.com/pay and pay 0x71C841832049902347b01b63b21b79f88d22d3b2. "
        "Contact user@example.com or user@example.com."
    )
    indicators = extract_indicators(text)
    seen_tuples = set()
    for ind in indicators:
        tup = (ind.type, ind.value.lower())
        assert tup not in seen_tuples, f"Duplicate indicator found: {tup}"
        seen_tuples.add(tup)
        # Ensure status is unverified
        assert ind.metadata.get("status") == "unverified"
        assert ind.metadata.get("is_verified") is False

# 12. Tests do not access the internet or open suspicious URLs
def test_item12_local_string_parsing_no_network(monkeypatch):
    import urllib.request
    def block_network(*args, **kwargs):
        raise RuntimeError("Network calls strictly forbidden during analysis!")
    
    monkeypatch.setattr(urllib.request, "urlopen", block_network)
    
    analysis = url_classifier_service.analyze_url("http://192.168.1.1/malicious/phish")
    assert analysis["risk_score"] >= 60
    assert analysis["risk_category"] in ["high", "critical"]

# 13. Raw message text is not printed to logs / sensitive tokens redacted
def test_item13_sensitive_tokens_redacted():
    url_with_token = "https://bank.example/login?token=SECRET_AUTH_9999&user=123"
    sanitized, domain = sanitize_url(url_with_token)
    assert "SECRET_AUTH_9999" not in sanitized
    assert "REDACTED" in sanitized
    assert domain == "bank.example"

    snippet_with_otp = "Your OTP is 987654. Do not share."
    clean_snip = sanitize_snippet(snippet_with_otp)
    assert "987654" not in clean_snip
    assert "[REDACTED]" in clean_snip
