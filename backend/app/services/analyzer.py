import re
from datetime import datetime, timezone
from typing import List, Optional

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
    Provides stable reason codes, evidence snippets, confidence metrics, and uncertainty range.
    """
    if not message or not message.strip():
        return AnalyzeResponse(
            risk_score=0.0,
            risk_level=SeverityEnum.LOW,
            confidence_score=0.95,
            uncertainty_range="±2%",
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

    # 2. Evaluate Risk Factors with stable reason codes & evidence snippets

    # Factor A: Urgency / Coercion
    urgency_matches = URGENCY_PATTERNS.findall(message)
    if urgency_matches:
        match_snippet = urgency_matches[0]
        breakdown.append(RiskBreakdownFactor(
            code="URGENT_TACTICS",
            label="Urgency & Pressure Tactics",
            factor="Urgency & Pressure Tactics",
            score=25.0,
            description=f"Message uses high-pressure or coercive language ('{match_snippet}').",
            severity=SeverityEnum.HIGH,
            evidence=match_snippet
        ))
        recommendations.append("Do not succumb to artificial urgency or threats of legal/account action.")

    # Factor B: OTP / Credential Request
    otp_matches = OTP_PATTERNS.findall(message)
    if otp_matches:
        match_snippet = otp_matches[0]
        breakdown.append(RiskBreakdownFactor(
            code="OTP_HARVESTING",
            label="Credential & OTP Harvesting",
            factor="Credential & OTP Harvesting",
            score=30.0,
            description=f"Explicitly requests sensitive authentication data ('{match_snippet}').",
            severity=SeverityEnum.CRITICAL,
            evidence=match_snippet
        ))
        recommendations.append("NEVER share OTPs, passwords, or PINs with anyone. Legitimate entities never ask for them.")

    # Factor C: Unsolicited Financial Demand
    payment_matches = PAYMENT_PATTERNS.findall(message)
    has_bank_or_upi = any(i.type in ["Bank Account", "UPI ID"] for i in indicators)
    if payment_matches or has_bank_or_upi:
        evidence_str = payment_matches[0] if payment_matches else (indicators[0].value if indicators else "financial request")
        breakdown.append(RiskBreakdownFactor(
            code="UNSOLICITED_PAYMENT",
            label="Unsolicited Payment Request",
            factor="Unsolicited Payment Request",
            score=25.0,
            description=f"Requests monetary transfer or provides direct payment details ('{evidence_str}').",
            severity=SeverityEnum.HIGH,
            evidence=evidence_str
        ))
        recommendations.append("Do not send money or initiate UPI transfers to unverified accounts.")

    # Factor D: Phishing Link & Domain Infrastructure
    urls = [i for i in indicators if i.type == "Phishing URL"]
    if urls:
        suspicious_urls = [u for u in urls if u.severity in [SeverityEnum.HIGH, SeverityEnum.CRITICAL]]
        link_score = 30.0 if suspicious_urls else 20.0
        evidence_str = urls[0].value
        breakdown.append(RiskBreakdownFactor(
            code="SUSPICIOUS_LINK",
            label="Suspicious Links & Phishing URL",
            factor="Suspicious Links & Phishing URL",
            score=link_score,
            description=f"Contains {len(urls)} link(s) pointing to external or unverified web domains ('{evidence_str}').",
            severity=SeverityEnum.HIGH if not suspicious_urls else SeverityEnum.CRITICAL,
            evidence=evidence_str
        ))
        recommendations.append("Do not click links in unsolicited messages. Access banking portals directly via official apps or bookmarks.")

    # Factor E: Impersonation of Authority
    impersonation_matches = IMPERSONATION_PATTERNS.findall(message)
    if impersonation_matches:
        match_snippet = impersonation_matches[0]
        breakdown.append(RiskBreakdownFactor(
            code="AUTHORITY_IMPERSONATION",
            label="Authority Impersonation",
            factor="Authority Impersonation",
            score=15.0,
            description=f"Claims affiliation with an official organization or support service ('{match_snippet}').",
            severity=SeverityEnum.MEDIUM,
            evidence=match_snippet
        ))
        recommendations.append("Verify the sender's identity independently through official public telephone directories.")

    # Factor F: Cryptocurrency Payment Request
    crypto_matches = CRYPTO_PATTERNS.findall(message)
    crypto_iocs = [i for i in indicators if i.type == "Crypto Wallet"]
    if crypto_matches or crypto_iocs:
        evidence_str = crypto_iocs[0].value if crypto_iocs else (crypto_matches[0] if crypto_matches else "crypto transfer")
        breakdown.append(RiskBreakdownFactor(
            code="CRYPTO_DEMAND",
            label="Cryptocurrency Demand",
            factor="Cryptocurrency Demand",
            score=25.0,
            description=f"Demands payment or transfer via irreversible cryptocurrency assets ('{evidence_str}').",
            severity=SeverityEnum.CRITICAL,
            evidence=evidence_str
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

    # 4. Uncertainty & Confidence metrics
    if len(breakdown) >= 3:
        confidence_score = 0.94
        uncertainty_range = "±3%"
    elif len(breakdown) >= 1:
        confidence_score = 0.90
        uncertainty_range = "±5%"
    else:
        confidence_score = 0.95
        uncertainty_range = "±2%"

    # 5. Executive Summary Generation
    if risk_score >= 80.0:
        summary = f"CRITICAL RISK (Score: {risk_score}/100, Confidence: {int(confidence_score*100)}% {uncertainty_range}): High probability of malicious scam/phishing attempt."
    elif risk_score >= 50.0:
        summary = f"HIGH RISK (Score: {risk_score}/100, Confidence: {int(confidence_score*100)}% {uncertainty_range}): Suspicious threat patterns detected."
    elif risk_score >= 25.0:
        summary = f"MEDIUM RISK (Score: {risk_score}/100, Confidence: {int(confidence_score*100)}% {uncertainty_range}): Minor suspicious signals identified."
    else:
        summary = f"LOW RISK (Score: {risk_score}/100, Confidence: {int(confidence_score*100)}% {uncertainty_range}): No high-risk scam indicators found."

    if not recommendations:
        recommendations.append("Message appears benign. Maintain standard cyber hygiene practices.")

    return AnalyzeResponse(
        risk_score=risk_score,
        risk_level=risk_level,
        confidence_score=confidence_score,
        uncertainty_range=uncertainty_range,
        summary=summary,
        breakdown=breakdown,
        indicators=indicators,
        recommendations=recommendations,
        analyzed_at=datetime.now(timezone.utc).isoformat()
    )
