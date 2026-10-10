import re
from datetime import datetime, timezone
from typing import List, Optional

from app.schemas.analyze import AnalyzeResponse
from app.schemas.common import ExtractedIndicator, RiskBreakdownFactor, SeverityEnum
from app.services.extractor import extract_indicators
from app.services.model_manager import model_manager

# Keyword & Pattern Matching Rules
URGENCY_PATTERNS = re.compile(
    r'\b(account.*(?:blocked|suspended|deactivated|frozen|terminated)|'
    r'urgent.*(?:notice|action|alert|warning)?|'
    r'immediately|within \d+ (?:hours?|mins?|minutes?)|'
    r'police action|legal action|court warrant|warrant|penalty|jail|arrest|'
    r'final notice|action required|suspended immediately)\b',
    re.IGNORECASE
)

OTP_PATTERNS = re.compile(
    r'\b(otp|one time password|passcode|pin|cvv|password|login credentials|'
    r'verification code|share code|send code|security code)\b',
    re.IGNORECASE
)

PAYMENT_PATTERNS = re.compile(
    r'\b(transfer money|pay now|send funds|wire transfer|deposit|'
    r'fine|fee|gift card|refund fee|processing fee|payment required|send money)\b',
    re.IGNORECASE
)

IMPERSONATION_PATTERNS = re.compile(
    r'\b(bank support|income tax|customer service|helpdesk|fedex|customs|'
    r'microsoft support|apple security|cbi|police|security team|support team)\b',
    re.IGNORECASE
)

CRYPTO_PATTERNS = re.compile(
    r'\b(bitcoin|btc|ethereum|eth|usdt|tron|crypto|wallet|binance|coinbase)\b',
    re.IGNORECASE
)

def determine_risk_level(score: int) -> str:
    """
    Maps an integer risk score to exact required risk bands:
    - 0–29: low
    - 30–59: medium
    - 60–79: high
    - 80–100: critical
    """
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 30:
        return "medium"
    else:
        return "low"

def analyze_scam_risk(
    message: str,
    sender: Optional[str] = None,
    source: Optional[str] = "manual_test",
    cloud_analysis: bool = False
) -> AnalyzeResponse:
    """
    Analyzes message for scam/fraud risk using hybrid ML classifier + explainable deterministic rules.
    Gracefully falls back to rules-only mode if the ML model is not loaded.
    """
    clean_text = (message or "").strip()
    if not clean_text:
        return AnalyzeResponse(
            risk_score=0,
            risk_level="low",
            reasons=[],
            recommended_action="No action required.",
            indicators=[],
            model_version=model_manager.model_version if model_manager.is_loaded else "none",
            analysis_mode="rules+ml" if model_manager.is_loaded else "rules",
            summary="Empty input. No risk indicators detected.",
            breakdown=[],
            recommendations=["No action required."],
            analyzed_at=datetime.now(timezone.utc).isoformat()
        )

    # 1. Extract IOCs
    indicators: List[ExtractedIndicator] = extract_indicators(clean_text)

    # 2. Evaluate Rule Signals
    rule_score = 0
    reasons: List[str] = []
    breakdown: List[RiskBreakdownFactor] = []

    # Signal A: OTP / Credential Request
    otp_matches = OTP_PATTERNS.findall(clean_text)
    if otp_matches:
        rule_score += 35
        reasons.append("Requests an OTP or authentication code")
        breakdown.append(RiskBreakdownFactor(
            code="OTP_HARVESTING",
            label="Credential & OTP Harvesting",
            factor="Credential & OTP Harvesting",
            score=35.0,
            description=f"Requests sensitive verification credentials ('{otp_matches[0]}').",
            severity=SeverityEnum.CRITICAL,
            evidence=otp_matches[0]
        ))

    # Signal B: Urgent account suspension or account-blocking threats
    urgency_matches = URGENCY_PATTERNS.findall(clean_text)
    if urgency_matches:
        rule_score += 30
        reasons.append("Uses an urgent account threat")
        breakdown.append(RiskBreakdownFactor(
            code="URGENT_TACTICS",
            label="Urgency & Coercion Tactics",
            factor="Urgency & Pressure Tactics",
            score=30.0,
            description=f"Creates artificial urgency or threatens account blocking ('{urgency_matches[0]}').",
            severity=SeverityEnum.HIGH,
            evidence=urgency_matches[0]
        ))

    # Signal C: Unexpected payments or transfers
    payment_matches = PAYMENT_PATTERNS.findall(clean_text)
    has_bank_or_upi = any(i.type in ["Bank Account", "UPI ID"] for i in indicators)
    if payment_matches or has_bank_or_upi:
        evidence_str = payment_matches[0] if payment_matches else (indicators[0].value if indicators else "payment request")
        rule_score += 25
        reasons.append("Requests an unexpected payment or transfer")
        breakdown.append(RiskBreakdownFactor(
            code="UNSOLICITED_PAYMENT",
            label="Payment Demand",
            factor="Unsolicited Payment Request",
            score=25.0,
            description=f"Requests monetary transfer or provides direct payment details ('{evidence_str}').",
            severity=SeverityEnum.HIGH,
            evidence=evidence_str
        ))

    # Signal D: Suspicious links combined with urgency or credential requests
    urls = [i for i in indicators if i.type == "Phishing URL"]
    if urls:
        if otp_matches or urgency_matches or payment_matches:
            rule_score += 25
            reasons.append("Contains suspicious link with coercive context")
            breakdown.append(RiskBreakdownFactor(
                code="SUSPICIOUS_LINK_COERCION",
                label="Suspicious Link with Threat",
                factor="Suspicious Links & Phishing URL",
                score=25.0,
                description=f"Directs to unverified link '{urls[0].value}' combined with urgent or credential demands.",
                severity=SeverityEnum.CRITICAL,
                evidence=urls[0].value
            ))
        else:
            # Standalone URL without urgency or credential harvesting (mere presence does not prove scam)
            rule_score += 10
            breakdown.append(RiskBreakdownFactor(
                code="EXTERNAL_LINK",
                label="External URL Detected",
                factor="External URL Presence",
                score=10.0,
                description=f"Contains external web link '{urls[0].value}'.",
                severity=SeverityEnum.LOW,
                evidence=urls[0].value
            ))

    # Signal E: Impersonation of Authority
    impersonation_matches = IMPERSONATION_PATTERNS.findall(clean_text)
    if impersonation_matches:
        rule_score += 15
        reasons.append("Impersonates official banking or legal authority")
        breakdown.append(RiskBreakdownFactor(
            code="AUTHORITY_IMPERSONATION",
            label="Authority Impersonation",
            factor="Authority Impersonation",
            score=15.0,
            description=f"Claims affiliation with an official body ('{impersonation_matches[0]}').",
            severity=SeverityEnum.MEDIUM,
            evidence=impersonation_matches[0]
        ))

    # Signal F: Cryptocurrency Payment Request
    crypto_matches = CRYPTO_PATTERNS.findall(clean_text)
    crypto_iocs = [i for i in indicators if i.type == "Crypto Wallet"]
    if crypto_matches or crypto_iocs:
        evidence_str = crypto_iocs[0].value if crypto_iocs else (crypto_matches[0] if crypto_matches else "crypto")
        rule_score += 25
        reasons.append("Demands cryptocurrency transfer")
        breakdown.append(RiskBreakdownFactor(
            code="CRYPTO_DEMAND",
            label="Cryptocurrency Demand",
            factor="Cryptocurrency Demand",
            score=25.0,
            description=f"Demands transfer via cryptocurrency assets ('{evidence_str}').",
            severity=SeverityEnum.CRITICAL,
            evidence=evidence_str
        ))

    # 3. Model Inference & Hybrid Blending
    ml_prob = model_manager.predict_scam_probability(clean_text)

    if model_manager.is_loaded and ml_prob is not None:
        model_version = model_manager.model_version
        if len(reasons) > 0:
            analysis_mode = "rules+ml"
            # Blend rule score with ML confirmation
            blended_score = rule_score + int(round(ml_prob * 15))
        else:
            # No rules triggered
            if ml_prob >= 0.70:
                analysis_mode = "ml"
                reasons.append("Flagged by text classification model")
                blended_score = int(round(ml_prob * 100))
            else:
                analysis_mode = "rules+ml"
                blended_score = 0  # Benign message confirmed by both rules and model
    else:
        # Graceful fallback when model is missing or fails
        model_version = "none"
        analysis_mode = "rules"
        blended_score = rule_score

    # Final score bounded to integer 0–100
    final_score = max(0, min(100, int(round(blended_score))))

    # Exact score bands
    risk_level = determine_risk_level(final_score)

    # 4. Safe Recommended Action
    if otp_matches:
        recommended_action = "Do not share your OTP. Verify through your bank's official app."
    elif urls and urgency_matches:
        recommended_action = "Do not click unverified links. Access the service directly through official verified channels."
    elif payment_matches or has_bank_or_upi:
        recommended_action = "Do not transfer money or initiate UPI payments to unverified accounts."
    elif final_score >= 60:
        recommended_action = "Treat this message with high caution. Independently verify the sender's identity."
    elif final_score >= 30:
        recommended_action = "Proceed with caution. Do not follow unverified instructions without verification."
    else:
        recommended_action = "No immediate threat detected. Maintain standard cyber hygiene practices."

    # 5. Summary & Backward Compatibility
    summary = f"{risk_level.upper()} RISK (Score: {final_score}/100): "
    if reasons:
        summary += f"Detected signals: {', '.join(reasons[:2])}."
    else:
        summary += "No suspicious scam patterns detected."

    return AnalyzeResponse(
        risk_score=final_score,
        risk_level=risk_level,
        reasons=reasons,
        recommended_action=recommended_action,
        indicators=indicators,
        model_version=model_version,
        analysis_mode=analysis_mode,
        summary=summary,
        breakdown=breakdown,
        recommendations=[recommended_action],
        analyzed_at=datetime.now(timezone.utc).isoformat(),
        confidence_score=0.92 if analysis_mode == "rules+ml" else 0.85,
        uncertainty_range="±4%" if final_score >= 60 else "±2%"
    )
