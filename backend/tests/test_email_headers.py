import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.email_header_analyzer import (
    email_header_analyzer,
    detect_raw_email_headers,
    EmailHeaderAnalysisResult
)

client = TestClient(app)

def test_spf_and_dkim_failures_detected():
    raw_headers = (
        "Received-SPF: fail (google.com: domain of phisher@scam.com does not designate sender IP) client-ip=1.2.3.4;\n"
        "Authentication-Results: mx.google.com; dkim=fail; dmarc=fail\n"
        "From: alerts@scam.com\n"
        "Return-Path: phisher@scam.com\n"
        "Subject: Alert"
    )
    result = email_header_analyzer.analyze(raw_headers=raw_headers)
    assert result.has_headers is True
    assert result.spf_status == "fail"
    assert result.dkim_status == "fail"
    assert result.dmarc_status == "fail"
    assert result.risk_boost > 0
    assert any("SPF" in a for a in result.anomalies)
    assert any("DKIM" in a for a in result.anomalies)
    assert any("DMARC" in a for a in result.anomalies)

def test_return_path_domain_mismatch_detected():
    raw_headers = (
        "From: Service Team <service@paypal.com>\n"
        "Return-Path: <bounce@evil-server.org>\n"
        "Subject: Account Update"
    )
    result = email_header_analyzer.analyze(raw_headers=raw_headers)
    assert result.domain_alignment is False
    assert result.from_domain == "paypal.com"
    assert result.return_path_domain == "evil-server.org"
    assert any("Domain mismatch" in a for a in result.anomalies)

def test_display_name_spoofing_detected():
    raw_headers = (
        "From: \"Microsoft 365 Security Alert\" <attacker99@unrelated-hacker-site.ru>\n"
        "Return-Path: <attacker99@unrelated-hacker-site.ru>\n"
        "Subject: Urgent Password Expiration Notice"
    )
    result = email_header_analyzer.analyze(raw_headers=raw_headers)
    assert result.display_name_spoofing is True
    assert any("Display Name Spoofing" in a for a in result.anomalies)
    assert result.risk_boost >= 35

def test_clean_legitimate_headers():
    raw_headers = (
        "Received-SPF: pass (google.com: domain of support@paypal.com designates 173.224.160.0 as permitted sender)\n"
        "Authentication-Results: mx.google.com; dkim=pass header.i=@paypal.com; dmarc=pass header.from=paypal.com\n"
        "From: \"PayPal Support\" <support@paypal.com>\n"
        "Return-Path: <support@paypal.com>\n"
        "Subject: Monthly Statement"
    )
    result = email_header_analyzer.analyze(raw_headers=raw_headers)
    assert result.spf_status == "pass"
    assert result.dkim_status == "pass"
    assert result.dmarc_status == "pass"
    assert result.domain_alignment is True
    assert result.display_name_spoofing is False
    assert len(result.anomalies) == 0
    assert result.risk_boost == 0

def test_detect_raw_email_headers_splitter():
    full_email = (
        "From: attacker@evil.com\n"
        "Subject: Fake notice\n"
        "To: victim@company.com\n"
        "\n"
        "Please click this link: http://steal-login.xyz to verify your bank credentials immediately."
    )
    headers_part, body_part = detect_raw_email_headers(full_email)
    assert headers_part is not None
    assert "From: attacker@evil.com" in headers_part
    assert "Please click this link" in body_part

def test_api_analyze_with_raw_headers_field():
    payload = {
        "text": "Your account is temporarily suspended. Click to restore.",
        "raw_headers": (
            "Received-SPF: fail\n"
            "Authentication-Results: mx.google.com; dkim=fail; dmarc=fail\n"
            "From: \"PayPal Support\" <scammer@evil-relay.net>\n"
            "Return-Path: <bounce@other-attacker.org>\n"
        )
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["header_analysis"] is not None
    assert data["header_analysis"]["has_headers"] is True
    assert data["header_analysis"]["spf_status"] == "fail"
    assert data["header_analysis"]["display_name_spoofing"] is True
    assert data["header_analysis"]["domain_alignment"] is False
    assert data["risk_score"] >= 60

def test_api_analyze_with_inline_email():
    full_email = (
        "From: \"Bank Support\" <fraud@scamcenter.xyz>\n"
        "Subject: Urgent Account Suspension\n"
        "Return-Path: <bounce@relay.org>\n"
        "\n"
        "URGENT: Your bank account has been blocked. Enter your OTP code now."
    )
    response = client.post("/api/analyze", json={"text": full_email})
    assert response.status_code == 200
    data = response.json()
    assert data["header_analysis"] is not None
    assert data["header_analysis"]["has_headers"] is True
    assert data["risk_score"] >= 80
    assert data["risk_level"] == "critical"
    assert any("Display Name Spoofing" in r or "Display name" in r for r in data["reasons"])
