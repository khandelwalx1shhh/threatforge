import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.extractor import extract_indicators
from app.schemas.common import IndicatorTypeEnum

client = TestClient(app)

def test_extract_service_url_email_upi():
    sample_text = (
        "Urgent! Please verify your account at https://secure-bank-login.top "
        "or contact support@phish-bank.com. Alternatively send money to support-alert@upi or paytm@okaxis."
    )
    indicators = extract_indicators(sample_text)
    types = [i.type for i in indicators]
    values = [i.value for i in indicators]

    assert IndicatorTypeEnum.URL.value in types
    assert IndicatorTypeEnum.EMAIL.value in types
    assert IndicatorTypeEnum.UPI.value in types
    assert "https://secure-bank-login.top" in values
    assert "support@phish-bank.com" in values
    assert "support-alert@upi" in values

def test_extract_crypto_ip_phone_bank():
    sample_text = (
        "Send 0.5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or ETH 0x71C7656EC7ab88b098defB751B7401B5f6d8976F. "
        "Server IP is 45.33.21.109. Call +91 9876543210 or wire to Account: 9876543210123."
    )
    indicators = extract_indicators(sample_text)
    types = [i.type for i in indicators]

    assert IndicatorTypeEnum.CRYPTO.value in types
    assert IndicatorTypeEnum.IP.value in types
    assert IndicatorTypeEnum.PHONE.value in types
    assert IndicatorTypeEnum.BANK.value in types

def test_extract_deduplication():
    sample_text = (
        "Pay to user@upi. Duplicate: user@upi and USER@UPI. "
        "Visit https://example.com and https://example.com again."
    )
    indicators = extract_indicators(sample_text)
    upi_indicators = [i for i in indicators if i.type == IndicatorTypeEnum.UPI.value]
    url_indicators = [i for i in indicators if i.type == IndicatorTypeEnum.URL.value]

    assert len(upi_indicators) == 1
    assert len(url_indicators) == 1

def test_extract_api_endpoint_success():
    payload = {
        "text": "Phishing alert: Visit http://fake-login.xyz or mail admin@fake.com. UPI: pay@ybl"
    }
    response = client.post("/api/extract", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 3
    assert len(data["indicators"]) == 3

def test_extract_api_endpoint_empty_input_validation():
    # Empty string test
    response_empty = client.post("/api/extract", json={"text": ""})
    assert response_empty.status_code == 422

    # Whitespace only string test
    response_whitespace = client.post("/api/extract", json={"text": "   \n\t  "})
    assert response_whitespace.status_code == 422

def test_no_guilt_or_owner_inference():
    sample_text = "Suspicious email from attacker@domain.com claiming to be John Doe."
    indicators = extract_indicators(sample_text)
    for ind in indicators:
        # Check that no owner identity or legal guilt is attributed
        assert "guilty" not in str(ind).lower()
        assert "owner_name" not in (ind.metadata or {})
