import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
import torch

from app.main import app
from app.services.distilbert_detector import distilbert_detector, DistilBertPrediction

client = TestClient(app)

# 1. Valid email/text input returns correct response structure
def test_distilbert_valid_email_prediction():
    payload = {
        "text": "URGENT: Your account has been suspended. Verify your credentials immediately at http://secure-verify.example."
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    # Core required fields per Task 3 specification
    assert "model_name" in data
    assert "predicted_class_index" in data
    assert "predicted_class_label" in data
    assert "candidate_class_label" in data
    assert "class_probabilities" in data
    assert "verification_status" in data
    assert "concise_explanation" in data
    assert "distilbert" in data

    # Validate types and values
    assert data["model_name"] == "cybersectony/phishing-email-detection-distilbert_v2.4.1"
    assert isinstance(data["predicted_class_index"], int)
    assert isinstance(data["class_probabilities"], dict)
    assert len(data["class_probabilities"]) == 4
    assert data["verification_status"] == "unverified"
    assert data["warning"] is not None
    assert "unverified" in data["warning"].lower()

# 2. Empty or whitespace-only input
def test_distilbert_empty_input_rejected():
    res_empty = client.post("/api/analyze", json={"text": ""})
    assert res_empty.status_code == 422
    err_data = res_empty.json()
    assert "error" in err_data or "detail" in err_data

def test_distilbert_whitespace_input_rejected():
    res_ws = client.post("/api/analyze", json={"text": "   \n\t  "})
    assert res_ws.status_code == 422

# 3. Extremely long input and oversized requests
def test_distilbert_oversized_request_rejected():
    # Input exceeding 5000 character limit
    oversized = "Suspicious phishing email content " * 200  # > 6000 chars
    res = client.post("/api/analyze", json={"text": oversized})
    assert res.status_code == 422

def test_distilbert_truncation_on_long_valid_input():
    # Long valid email text (around 1500 chars) within max_length 5000,
    # should be safely truncated to 512 tokens during tokenization without error
    long_email = (
        "Dear valued customer,\n\n"
        "We detected unusual sign-in activity on your enterprise account from an unrecognized IP address. "
        "Please review the security alert and confirm your identity to prevent temporary account suspension. "
    ) * 8
    res = client.post("/api/analyze", json={"text": long_email})
    assert res.status_code == 200
    data = res.json()
    assert data["predicted_class_index"] is not None
    assert len(data["class_probabilities"]) == 4

# 4. Invalid request formats
@pytest.mark.parametrize("invalid_body", [
    {},
    {"text": None},
    {"text": 12345},
    {"text": ["array", "not", "string"]},
    {"message": 500},
])
def test_distilbert_invalid_request_formats(invalid_body):
    res = client.post("/api/analyze", json=invalid_body)
    assert res.status_code == 422

# 5. Verified vs Unverified model class mappings
def test_unverified_model_mapping_behavior():
    # The actual Hugging Face model config has LABEL_0..3 without verified id2label
    pred = distilbert_detector.predict("Sample email body for testing.")
    assert pred.verification_status == "unverified"
    assert pred.verified_class_label is None
    assert pred.risk_assessment is None
    assert pred.warning is not None
    assert "unverified" in pred.warning.lower()

def test_verified_model_mapping_mock():
    # Test behavior when model has verified semantic id2label
    with patch.object(distilbert_detector, "is_label_mapping_verified", True):
        with patch.object(distilbert_detector, "raw_id2label", {0: "legitimate", 1: "phishing"}):
            payload = {"text": "Click here to login."}
            res = client.post("/api/analyze", json=payload)
            assert res.status_code == 200
            data = res.json()
            assert data["verification_status"] == "verified"
            assert data["warning"] is None
            assert data["verified_class_label"] is not None
            assert data["risk_assessment"] is not None

# 6. Model-loading and inference failures (Graceful Fallback)
def test_model_loading_failure_fallback():
    # Simulate DistilBERT being offline or failing to load
    orig_loaded = distilbert_detector.is_loaded
    try:
        distilbert_detector.is_loaded = False
        payload = {"text": "Your bank account blocked. Share OTP immediately."}
        res = client.post("/api/analyze", json=payload)
        assert res.status_code == 200
        data = res.json()

        # Backend remains functional via deterministic rules
        assert data["risk_score"] >= 60
        assert data["risk_level"] in ["high", "critical"]
        assert data["verification_status"] == "unavailable"
        assert "DistilBERT model is currently not loaded" in data["warning"]
        assert len(data["reasons"]) >= 1
    finally:
        distilbert_detector.is_loaded = orig_loaded

def test_inference_exception_graceful_handling():
    # Simulate torch inference throwing an unexpected runtime exception
    with patch.object(distilbert_detector, "predict") as mock_predict:
        mock_predict.return_value = DistilBertPrediction(
            is_available=False,
            verification_status="inference_error",
            warning="Inference error encountered: RuntimeError",
            explanation="DistilBERT inference failed; risk computed via fallback."
        )
        res = client.post("/api/analyze", json={"text": "Suspicious email text"})
        assert res.status_code == 200
        data = res.json()
        assert data["verification_status"] == "inference_error"
        assert "Inference error" in data["warning"]

# 7. Security: Never falsely label an email as safe
def test_never_falsely_label_safe_when_rules_flag_threat():
    # Force DistilBERT to predict class 0 (candidate "legitimate_email")
    with patch.object(distilbert_detector, "predict") as mock_predict:
        mock_predict.return_value = DistilBertPrediction(
            is_available=True,
            predicted_class_index=0,
            predicted_class_label="LABEL_0",
            candidate_class_label="legitimate_email",
            class_probabilities={"LABEL_0": 0.99, "LABEL_1": 0.01, "LABEL_2": 0.0, "LABEL_3": 0.0},
            confidence=0.99,
            verification_status="unverified",
            warning="Model config.id2label exposes generic labels. Do NOT classify as safe solely based on model."
        )
        # Message has dangerous OTP credential harvesting and account threats
        scam_email = "URGENT: Your account will be blocked! Share your 6-digit OTP code immediately."
        res = client.post("/api/analyze", json={"text": scam_email})
        assert res.status_code == 200
        data = res.json()

        # Security check: MUST NOT be labeled low risk or safe despite DistilBERT predicting class 0
        assert data["risk_level"] in ["high", "critical"]
        assert data["risk_score"] >= 60
        assert any("OTP" in r for r in data["reasons"])

# 8. Quantization and Latency Performance
def test_distilbert_quantization_and_latency_fields():
    res = client.post("/api/analyze", json={"text": "Please verify your PayPal details."})
    assert res.status_code == 200
    data = response_data = res.json()
    assert "is_quantized" in response_data
    assert "latency_ms" in response_data
    assert isinstance(response_data["is_quantized"], bool)
    assert response_data["latency_ms"] is None or isinstance(response_data["latency_ms"], (int, float))

