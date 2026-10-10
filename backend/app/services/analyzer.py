import re
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from app.schemas.analyze import AnalyzeResponse
from app.schemas.common import ExtractedIndicator, RiskBreakdownFactor, SeverityEnum
from app.services.extractor import extract_indicators

# Keyword & Regex Risk Rules
URGENCY_PATTERNS = re.compile(
    r'\b(urgent|immediately|within \d+ (?:hours?|mins?|minutes?)|account suspended|account blocked|police action|legal action|warrant|penalty|jail|arrest|final notice|deactivated?|action required)\b',
    re.IGNORECASE
)

OTP_PATTERNS = re.compile(
    r'\b(otp|one time password|passcode|pin|cvv|password|login credentials|verification code|share code|send code|security code)\b',
    re.IGNORECASE
)

PAYMENT_PATTERNS = re.compile(
    r'\b(transfer money|pay now|send funds|wire transfer|deposit|fine|fee|gift card|refund fee|processing fee|payment|send money)\b',
    re.IGNORECASE
)

IMPERSONATION_PATTERNS = re.compile(
    r'\b(bank support|income tax|customer service|helpdesk|fedex|customs|microsoft support|apple security|cbi|police|security team|support team|official team)\b',
    re.IGNORECASE
)

CRYPTO_PATTERNS = re.compile(
    r'\b(bitcoin|btc|ethereum|eth|usdt|tron|crypto|wallet|binance|coinbase)\b',
    re.IGNORECASE
)

def analyze_scam_risk(message: str, sender: Optional[str] = None) -> AnalyzeResponse:
    """
    Evaluates suspicious message text for scam risk using deterministic rule-based explainable scoring.
    Evaluates Urgency/Pressure, OTP/Credential Requests, Financial Demands, Suspicious Links, Impersonation, and Crypto.
    """
    if not message or not message.strip():
        # Benign default for empty string
        return AnalyzeResponse(
            risk_score=0.0,
            risk_level=SeverityEnum.LOW,
            summary="Empty input analyzed. No risk indicators detected.",
            breakdown=[],
            indicators=[],
            recommendations=["No action required."],
            analyzed_at=datetime.now(timezone.utc).isoformat()
        )

    # 1. Extract IOCs first
    indicators: List[ExtractedIndicator] = extract_indicators(message)

    breakdown: List[RiskBreakdownFactor] = []
    recommendations: List[str] = []

    # 2. Evaluate Risk Factors

    # Factor A: Urgency / Coercion
    urgency_matches = URGENCY_PATTERNS.findall(message)
    if urgency_matches:
        breakdown.append(RiskBreakdownFactor(
            factor="Urgency & Pressure Tactics",
            score=25.0,
            description=f"Message uses high-pressure or coercive language ('{urgency_matches[0]}').",
            severity=SeverityEnum.HIGH
        ))
        recommendations.append("Do not succumb to artificial urgency or threats of legal/account action.")

    # Factor B: OTP / Credential Request
    otp_matches = OTP_PATTERNS.findall(message)
    if otp_matches:
        breakdown.append(RiskBreakdownFactor(
            factor="Credential & OTP Harvesting",
            score=30.0,
            description=f"Explicitly requests sensitive authentication data ('{otp_matches[0]}').",
            severity=SeverityEnum.CRITICAL
        ))
        recommendations.append("NEVER share OTPs, passwords, or PINs with anyone. Legitimate entities never ask for them.")

    # Factor C: Unsolicited Financial Demand
    payment_matches = PAYMENT_PATTERNS.findall(message)
    has_bank_or_upi = any(i.type in ["Bank Account", "UPI ID"] for i in indicators)
    if payment_matches or has_bank_or_upi:
        payment_detail = payment_matches[0] if payment_matches else "payment details detected"
        breakdown.append(RiskBreakdownFactor(
            factor="Unsolicited Payment Request",
            score=25.0,
            description=f"Requests monetary transfer or provides direct payment details ('{payment_detail}').",
            severity=SeverityEnum.HIGH
        ))
        recommendations.append("Do not send money or initiate UPI transfers to unverified accounts.")

    # Factor D: Phishing Link & Domain Infrastructure
    urls = [i for i in indicators if i.type == "Phishing URL"]
    if urls:
        suspicious_urls = [u for u in urls if u.severity in [SeverityEnum.HIGH, SeverityEnum.CRITICAL]]
        link_score = 30.0 if suspicious_urls else 20.0
        breakdown.append(RiskBreakdownFactor(
            factor="Suspicious Links & Phishing URL",
            score=link_score,
            description=f"Contains {len(urls)} link(s) pointing to external or unverified web domains.",
            severity=SeverityEnum.HIGH if not suspicious_urls else SeverityEnum.CRITICAL
        ))
        recommendations.append("Do not click links in unsolicited messages. Access banking portals directly via official apps or bookmarks.")

    # Factor E: Impersonation of Authority
    impersonation_matches = IMPERSONATION_PATTERNS.findall(message)
    if impersonation_matches:
        breakdown.append(RiskBreakdownFactor(
            factor="Authority Impersonation",
            score=15.0,
            description=f"Claims affiliation with an official organization or support service ('{impersonation_matches[0]}').",
            severity=SeverityEnum.MEDIUM
        ))
        recommendations.append("Verify the sender's identity independently through official public telephone directories.")

    # Factor F: Cryptocurrency Payment Request
    crypto_matches = CRYPTO_PATTERNS.findall(message)
    has_crypto_ioc = any(i.type == "Crypto Wallet" for i in indicators)
    if crypto_matches or has_crypto_ioc:
        breakdown.append(RiskBreakdownFactor(
            factor="Cryptocurrency Demand",
            score=25.0,
            description="Demands payment or transfer via irreversible cryptocurrency assets.",
            severity=SeverityEnum.CRITICAL
        ))
        recommendations.append("Exercise extreme caution: Cryptocurrency transfers cannot be reversed once completed.")

    # 3. Calculate Overall Risk Score & Level
    raw_score = sum(f.score for f in breakdown)
    risk_score = round(min(100.0, raw_score), 1)

    # Risk Level Thresholds: >=80 CRITICAL, >=50 HIGH, >=25 MEDIUM, <25 LOW
    if risk_score >= 80.0:
        risk_level = SeverityEnum.CRITICAL
    elif risk_score >= 50.0:
        risk_level = SeverityEnum.HIGH
    elif risk_score >= 25.0:
        risk_level = SeverityEnum.MEDIUM
    else:
        risk_level = SeverityEnum.LOW

    # 4. Executive Summary Generation
    if risk_score >= 80.0:
        summary = f"CRITICAL RISK (Score: {risk_score}/100): High probability of malicious scam/phishing attempt. Multiple critical risk indicators present."
    elif risk_score >= 50.0:
        summary = f"HIGH RISK (Score: {risk_score}/100): Suspicious patterns detected. Exercise heightened vigilance before interacting."
    elif risk_score >= 25.0:
        summary = f"MEDIUM RISK (Score: {risk_score}/100): Minor suspicious signals identified. Proceed with standard caution."
    else:
        summary = f"LOW RISK (Score: {risk_score}/100): No high-risk scam indicators found in message body."

    if not recommendations:
        recommendations.append("Message appears benign. Maintain standard cyber hygiene practices.")

    return AnalyzeResponse(
        risk_score=risk_score,
        risk_level=risk_level,
        summary=summary,
        breakdown=breakdown,
        indicators=indicators,
        recommendations=recommendations,
        analyzed_at=datetime.now(timezone.utc).isoformat()
    )
