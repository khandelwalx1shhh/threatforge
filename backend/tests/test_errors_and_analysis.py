import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app, raise_server_exceptions=False)

def test_phase5_reasons_have_code_label_evidence():
    payload = {
        "message": "URGENT! Share your OTP for bank support immediately or your account will be suspended."
    }
    res = client.post("/api/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()

    # Check uncertainty metrics
    assert "confidence_score" in data
    assert "uncertainty_range" in data
    assert data["confidence_score"] > 0.8
    assert "%" in data["uncertainty_range"]

    # Check stable breakdown factors
    assert len(data["breakdown"]) >= 2
    for factor in data["breakdown"]:
        assert "code" in factor and factor["code"] != ""
        assert "label" in factor and factor["label"] != ""
        assert "evidence" in factor and factor["evidence"] is not None

def test_phase5_validation_error_shape():
    # Invalid payload (missing required message parameter)
    res = client.post("/api/analyze", json={})
    assert res.status_code == 422
    data = res.json()

    assert "error" in data
    assert data["error"]["code"] == "VALIDATION_ERROR"
    assert "message" in data["error"]
    assert len(data["error"]["message"]) > 0

def test_phase5_empty_text_error_shape():
    # Empty string text validation
    res = client.post("/api/extract", json={"text": "   "})
    assert res.status_code == 422
    data = res.json()

    assert "error" in data
    assert data["error"]["code"] == "VALIDATION_ERROR"
    assert "message" in data["error"]

def test_phase5_500_server_error_privacy():
    # Simulate internal server error route for testing
    from fastapi import APIRouter
    test_router = APIRouter()

    @test_router.get("/test-500-error")
    def trigger_error():
        raise Exception("Secret DB Password: super_secret_pass_123! Raw Message Payload: secret_data")

    app.include_router(test_router)

    res = client.get("/test-500-error")
    assert res.status_code == 500
    data = res.json()

    assert "error" in data
    assert data["error"]["code"] == "INTERNAL_SERVER_ERROR"
    assert "An unexpected server error occurred" in data["error"]["message"]
    # Verify secrets or raw details are NOT exposed
    assert "super_secret_pass_123" not in str(data)
    assert "secret_data" not in str(data)
