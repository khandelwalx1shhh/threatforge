import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.payload_scanner import payload_scanner

client = TestClient(app)

def test_upi_reverse_charge_detection():
    text = "Dear customer, click to receive your ₹4999 refund: upi://pay?pa=fraud99@ybl&pn=State%20Bank%20Support&am=4999&cu=INR&tn=Refund"
    result = payload_scanner.audit_upi_payload(text)
    assert result is not None
    assert result.is_upi_deeplink is True
    assert result.payee_vpa == "fraud99@ybl"
    assert result.payee_name == "State Bank Support"
    assert result.amount == 4999.0
    assert result.is_reverse_charge_lure is True
    assert result.is_brand_spoofing is True
    assert result.risk_boost >= 60
    assert "Reverse-Charge Fraud" in str(result.anomalies)

def test_upi_benign_payment_intent():
    text = "Please split the dinner bill: upi://pay?pa=arjun@okaxis&pn=Arjun&am=350&cu=INR&tn=Dinner"
    result = payload_scanner.audit_upi_payload(text)
    assert result is not None
    assert result.is_upi_deeplink is True
    assert result.payee_vpa == "arjun@okaxis"
    assert result.is_reverse_charge_lure is False
    assert result.is_brand_spoofing is False

def test_apk_wedding_invitation_detection():
    text = "Hey! Please check out my wedding invitation card here: http://download-storage.xyz/wedding_invitation.apk"
    result = payload_scanner.audit_apk_threat(text)
    assert result is not None
    assert result.has_apk_dropper is True
    assert "wedding_invitation.apk" in result.filename
    assert "Wedding Invitation" in result.lure_category
    assert result.risk_score >= 90
    assert result.is_critical_threat is True
    assert "banking trojan" in result.defensive_warning.lower() or "spyware" in result.defensive_warning.lower()

def test_apk_sbi_rewards_detection():
    text = "SBI Rewards points expiring! Install sbi_rewards_update.apk now to claim ₹9,500 cashback."
    result = payload_scanner.audit_apk_threat(text)
    assert result is not None
    assert result.has_apk_dropper is True
    assert "Banking Trojan Dropper" in result.lure_category
    assert result.risk_score >= 90

def test_api_analyze_with_apk_dropper():
    payload = {
        "text": "Your traffic police e-challan is pending. Download e_challan_parivahan.apk immediately.",
        "source": "whatsapp"
    }
    res = client.post("/api/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_score"] >= 80
    assert data["risk_level"] == "critical"
    assert data["apk_audit"] is not None
    assert data["apk_audit"]["has_apk_dropper"] is True
    assert "E-Challan Police" in data["apk_audit"]["lure_category"]
    assert "CRITICAL" in data["recommended_action"]
    assert any("Sideloaded APK Package" in b["label"] for b in data["breakdown"])

def test_api_analyze_with_upi_reverse_charge():
    payload = {
        "text": "Claim your ₹3000 lottery reward! Click upi://pay?pa=fakehelp@paytm&pn=Electricity%20Board&am=3000&cu=INR",
        "source": "whatsapp"
    }
    res = client.post("/api/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_score"] >= 75
    assert data["upi_audit"] is not None
    assert data["upi_audit"]["is_reverse_charge_lure"] is True
    assert "debit your account" in data["recommended_action"].lower()
