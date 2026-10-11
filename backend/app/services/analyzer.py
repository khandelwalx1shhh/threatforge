import re
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

from app.schemas.analyze import AnalyzeResponse
from app.schemas.common import ExtractedIndicator, RiskBreakdownFactor, SeverityEnum
from app.services.extractor import extract_indicators
from app.services.model_manager import model_manager
from app.services.distilbert_detector import distilbert_detector
from app.services.email_header_analyzer import (
    email_header_analyzer,
    detect_raw_email_headers,
    EmailHeaderAnalysisResult
)
from app.services.url_analyzer import url_classifier_service
from app.services.gemini_detector import gemini_detector
from app.services.payload_scanner import payload_scanner

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

def is_input_primarily_url(text: str) -> bool:
    clean = text.strip()
    # Check if text is just a URL or starts with http/www without many extra words
    if re.match(r'^(?:https?://|www\.)[^\s]+$', clean, re.IGNORECASE):
        return True
    words = clean.split()
    if len(words) <= 3 and any(w.lower().startswith(("http://", "https://", "www.")) for w in words):
        return True
    return False

def analyze_scam_risk(
    message: str,
    sender: Optional[str] = None,
    source: Optional[str] = "manual_test",
    cloud_analysis: bool = False,
    raw_headers: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None
) -> AnalyzeResponse:
    """
    Analyzes message for scam/fraud risk using hybrid ML classifier + lexical URL model
    + explainable deterministic rules + DistilBERT phishing transformer + dedicated RFC 822 Email Header security audit.
    Gracefully falls back to rules-only mode if ML models are not loaded.
    """
    clean_text = (message or "").strip()
    if not clean_text:
        return AnalyzeResponse(
            risk_score=0,
            risk_level="low",
            reasons=[],
            recommended_action="No action required.",
            indicators=[],
            model_version=model_manager.model_version if model_manager.is_loaded else "rules-fallback",
            analysis_mode="rules",
            summary="Empty input. No risk indicators detected.",
            breakdown=[],
            recommendations=["No action required."],
            analyzed_at=datetime.now(timezone.utc).isoformat(),
            model_name="cybersectony/phishing-email-detection-distilbert_v2.4.1",
            predicted_class_index=None,
            predicted_class_label=None,
            candidate_class_label=None,
            class_probabilities={},
            candidate_probabilities={},
            verification_status="unverified",
            is_quantized=False,
            latency_ms=None,
            warning=None,
            concise_explanation="No content provided for analysis.",
            header_analysis=None
        )

    # 1. Email Header Detection & Analysis
    target_body = clean_text
    header_res: Optional[EmailHeaderAnalysisResult] = None

    effective_raw_headers = raw_headers
    if not effective_raw_headers and not headers:
        detected_h, detected_b = detect_raw_email_headers(clean_text)
        if detected_h:
            effective_raw_headers = detected_h
            if detected_b:
                target_body = detected_b

    if effective_raw_headers or headers:
        header_res = email_header_analyzer.analyze(
            raw_headers=effective_raw_headers,
            headers_dict=headers
        )

    # 2. Extract IOCs from the body (or full text)
    indicators: List[ExtractedIndicator] = extract_indicators(target_body)

    # 3. URL Analysis via URL Classifier Service
    url_results: List[Dict[str, Any]] = []
    max_url_score = 0
    highest_risk_url_result: Optional[Dict[str, Any]] = None

    url_indicators = [i for i in indicators if i.type in ("Phishing URL", "Suspicious URL")]
    for u_ind in url_indicators:
        analysis = url_classifier_service.analyze_url(u_ind.value)
        url_results.append(analysis)
        u_score = analysis.get("risk_score", 0)
        if u_score > max_url_score:
            max_url_score = u_score
            highest_risk_url_result = analysis
        
        # Update indicator severity and metadata with URL model insights
        if u_score >= 80:
            u_ind.severity = SeverityEnum.CRITICAL
            u_ind.type = "Phishing URL"
        elif u_score >= 60:
            u_ind.severity = SeverityEnum.HIGH
            u_ind.type = "Phishing URL"
        elif u_score >= 30:
            u_ind.severity = SeverityEnum.MEDIUM
            u_ind.type = "Suspicious URL"
        else:
            u_ind.severity = SeverityEnum.LOW
            u_ind.type = "Phishing URL" if u_ind.metadata.get("suspicious_tld") else "Suspicious URL"
        
        if analysis.get("ml_probability") is not None:
            u_ind.confidence = round(analysis["ml_probability"], 2)
        if analysis.get("features"):
            u_ind.metadata.update({
                "entropy": round(analysis["features"].get("entropy", 0), 2),
                "is_ip_host": bool(analysis["features"].get("is_ip_host")),
                "brand_spoofing": bool(analysis["features"].get("brand_spoofing_count", 0) > 0)
            })

    # 4. Evaluate Rule Signals
    rule_score = 0
    reasons: List[str] = []
    breakdown: List[RiskBreakdownFactor] = []

    # Signal A: Header Anomalies (SPF/DKIM/DMARC / Spoofing)
    if header_res and header_res.has_headers:
        if header_res.display_name_spoofing:
            reasons.append("Display name impersonates known institution while sender domain differs")
            breakdown.append(RiskBreakdownFactor(
                code="HEADER_DISPLAY_NAME_SPOOF",
                label="Display Name Spoofing",
                factor="Email Header Authenticity",
                score=35.0,
                description=f"Display name '{header_res.display_name}' spoofed on domain '{header_res.from_domain}'.",
                severity=SeverityEnum.CRITICAL,
                evidence=header_res.display_name or ""
            ))
        if not header_res.domain_alignment:
            reasons.append("Sender domain in From header does not align with Return-Path")
            breakdown.append(RiskBreakdownFactor(
                code="HEADER_DOMAIN_MISMATCH",
                label="Return-Path Domain Mismatch",
                factor="Email Header Authenticity",
                score=30.0,
                description=f"From: @{header_res.from_domain} mismatches Return-Path: @{header_res.return_path_domain}.",
                severity=SeverityEnum.HIGH,
                evidence=header_res.return_path_domain or ""
            ))
        if header_res.spf_status in ["fail", "softfail"]:
            reasons.append(f"SPF email authentication check failed ({header_res.spf_status})")
            breakdown.append(RiskBreakdownFactor(
                code="HEADER_SPF_FAIL",
                label="SPF Authentication Failure",
                factor="Email Security Record Verification",
                score=30.0,
                description=f"Sender server not authorized in domain SPF record ({header_res.spf_status}).",
                severity=SeverityEnum.HIGH,
                evidence=header_res.spf_status
            ))
        if header_res.dmarc_status in ["fail"]:
            reasons.append("DMARC domain policy validation failed")
            breakdown.append(RiskBreakdownFactor(
                code="HEADER_DMARC_FAIL",
                label="DMARC Policy Failure",
                factor="Email Security Record Verification",
                score=35.0,
                description="Message failed domain DMARC authentication policy.",
                severity=SeverityEnum.CRITICAL,
                evidence="dmarc=fail"
            ))
        if header_res.dkim_status in ["fail"]:
            reasons.append("DKIM cryptographic signature verification failed")
            breakdown.append(RiskBreakdownFactor(
                code="HEADER_DKIM_FAIL",
                label="DKIM Signature Failure",
                factor="Email Security Record Verification",
                score=25.0,
                description="Email cryptographic signature is invalid or tampered.",
                severity=SeverityEnum.HIGH,
                evidence="dkim=fail"
            ))
        rule_score += header_res.risk_boost

    # Signal B: OTP / Credential Request
    otp_matches = OTP_PATTERNS.findall(target_body)
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

    # Signal C: Urgent account suspension or account-blocking threats
    urgency_matches = URGENCY_PATTERNS.findall(target_body)
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

    # Signal D: Unexpected payments or transfers
    payment_matches = PAYMENT_PATTERNS.findall(target_body)
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

    # Signal E: URL Classifier Signals (Integrated Text + URL analysis)
    if highest_risk_url_result:
        u_score = highest_risk_url_result["risk_score"]
        u_reasons = highest_risk_url_result.get("reasons", [])
        
        # Deduplicate reasons from URL analysis
        for r in u_reasons:
            if r not in reasons and "standard benign" not in r:
                reasons.append(r)

        if u_score >= 60:
            # Phishing or highly suspicious URL
            if otp_matches or urgency_matches or payment_matches:
                rule_score += 25
                if "Contains suspicious link with coercive context" not in reasons:
                    reasons.append("Contains suspicious link with coercive context")
                breakdown.append(RiskBreakdownFactor(
                    code="SUSPICIOUS_LINK_COERCION",
                    label="Suspicious Link with Threat",
                    factor="Suspicious Links & Phishing URL",
                    score=25.0,
                    description=f"Directs to unverified link '{highest_risk_url_result['url']}' combined with urgent or credential demands.",
                    severity=SeverityEnum.CRITICAL,
                    evidence=highest_risk_url_result['url']
                ))
            else:
                rule_score += 30
                breakdown.append(RiskBreakdownFactor(
                    code="MALICIOUS_URL_SIGNAL",
                    label="Suspicious / Phishing URL Detected",
                    factor="URL Threat Classifier",
                    score=30.0,
                    description=f"URL classifier identified high phishing risk on '{highest_risk_url_result['url']}'.",
                    severity=SeverityEnum.HIGH,
                    evidence=highest_risk_url_result['url']
                ))
        elif u_score >= 30:
            # Moderate / uncertain URL
            rule_score += 15
            breakdown.append(RiskBreakdownFactor(
                code="UNCERTAIN_URL_SIGNAL",
                label="Unfamiliar or Unverified Link",
                factor="URL Threat Classifier",
                score=15.0,
                description=f"URL '{highest_risk_url_result['url']}' is unfamiliar or has moderate lexical anomalies.",
                severity=SeverityEnum.MEDIUM,
                evidence=highest_risk_url_result['url']
            ))
        else:
            # Benign URL: No rule score penalty.
            pass

    # Signal F: Impersonation of Authority
    impersonation_matches = IMPERSONATION_PATTERNS.findall(target_body)
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

    # Signal G: Cryptocurrency Payment Request
    crypto_matches = CRYPTO_PATTERNS.findall(target_body)
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

    # Signal H: UPI Deep Link & QR Code Audit
    upi_audit = payload_scanner.audit_upi_payload(target_body)
    if upi_audit:
        rule_score += upi_audit.risk_boost
        for a in upi_audit.anomalies:
            if a not in reasons:
                reasons.append(a)
        breakdown.append(RiskBreakdownFactor(
            code="UPI_DEEPLINK_RISK",
            label="UPI Deep Link Deception",
            factor="UPI Payment Intent",
            score=float(upi_audit.risk_boost),
            description=upi_audit.anomalies[0] if upi_audit.anomalies else f"Contains direct UPI payment URI targeting {upi_audit.payee_vpa}.",
            severity=SeverityEnum.CRITICAL if upi_audit.risk_boost >= 60 else SeverityEnum.HIGH,
            evidence=upi_audit.payee_vpa or upi_audit.raw_uri or "upi://pay"
        ))

    # Signal I: Malicious Sideloaded APK Package Dropper
    apk_audit = payload_scanner.audit_apk_threat(target_body)
    if apk_audit:
        rule_score += 65
        for r in apk_audit.reasons[:2]:
            if r not in reasons:
                reasons.append(r)
        breakdown.append(RiskBreakdownFactor(
            code="MALICIOUS_APK_DROPPER",
            label="Sideloaded APK Package",
            factor="Android Malware Dropper",
            score=45.0,
            description=f"Identified {apk_audit.lure_category} distributing '{apk_audit.filename}' ({apk_audit.targeted_threat_family}).",
            severity=SeverityEnum.CRITICAL,
            evidence=apk_audit.filename or ".apk dropper"
        ))

    # 5. DistilBERT Phishing Transformer Inference
    distil_pred = distilbert_detector.predict(target_body)
    if distil_pred.is_available and distil_pred.predicted_class_index in {1, 3} and distil_pred.confidence >= 0.70:
        distil_reason = f"Flagged by DistilBERT model ({distil_pred.candidate_class_label}, confidence: {distil_pred.confidence:.1%})"
        if distil_reason not in reasons:
            reasons.append(distil_reason)
        breakdown.append(RiskBreakdownFactor(
            code="DISTILBERT_TRANSFORMER",
            label="Transformer Phishing Detection",
            factor="DistilBERT Phishing Model",
            score=25.0,
            description=(
                f"DistilBERT classified text into index {distil_pred.predicted_class_index} "
                f"('{distil_pred.candidate_class_label}' with {distil_pred.confidence:.1%} confidence). "
                f"Verification: {distil_pred.verification_status}."
            ),
            severity=SeverityEnum.HIGH,
            evidence=target_body[:60]
        ))
        rule_score += 25

    # 6. Baseline Scikit-Learn Text Model Inference & Hybrid Blending
    ml_prob = model_manager.predict_scam_probability(target_body)

    # Determine analysis mode and model version based on whether text ML or URL ML was active
    text_model_loaded = model_manager.is_loaded
    url_model_used = len(url_results) > 0 and url_classifier_service.is_available()

    if text_model_loaded and url_model_used:
        effective_model_version = model_manager.model_version
        effective_analysis_mode = "rules+ml"
    elif text_model_loaded:
        effective_model_version = model_manager.model_version
        effective_analysis_mode = "rules+ml"
    elif url_model_used:
        effective_model_version = url_classifier_service.model_version
        effective_analysis_mode = "rules+ml"
    else:
        effective_model_version = "none"
        effective_analysis_mode = "rules"

    # Hybrid Score Blending
    if text_model_loaded and ml_prob is not None:
        if len(reasons) > 0 or max_url_score >= 30:
            blended_score = rule_score + int(round(ml_prob * 15))
        else:
            if ml_prob >= 0.70:
                reasons.append("Flagged by text classification model")
                blended_score = int(round(ml_prob * 100))
                effective_analysis_mode = "ml"
            else:
                blended_score = 0  # Benign message confirmed by rules, URL, and model
    else:
        blended_score = rule_score

    # Check for direct URL-only or URL-dominant input
    if is_input_primarily_url(target_body) and highest_risk_url_result:
        # For URL-dominant input, preserve the URL model's assessment directly
        u_score = highest_risk_url_result["risk_score"]
        blended_score = max(blended_score, u_score)

    # 6b. Cloud AI Detection via Google Gemini (active when cloud_analysis=True and GEMINI_API_KEY is configured)
    gemini_result = None
    if cloud_analysis and gemini_detector.is_available:
        gemini_result = gemini_detector.analyze(target_body)
        if gemini_result:
            effective_analysis_mode = "hybrid+gemini"
            g_score = gemini_result.get("risk_score", 0)
            if g_score > blended_score:
                blended_score = int(round((blended_score * 0.3) + (g_score * 0.7)))

            for r in gemini_result.get("reasons", []):
                if r not in reasons:
                    reasons.append(r)

            g_level = determine_risk_level(g_score).upper()
            breakdown.append(RiskBreakdownFactor(
                code="GEMINI_AI_REASONING",
                label="Gemini Threat Analysis",
                factor="Generative AI Intent Analysis",
                score=float(g_score),
                description=gemini_result.get("summary") or f"Gemini classified intent: {gemini_result.get('intent_category')}",
                severity=SeverityEnum(g_level) if g_level in SeverityEnum.__members__ else SeverityEnum.MEDIUM,
                evidence=", ".join(gemini_result.get("psychological_tactics", [])) or "Gemini LLM Reasoning"
            ))

    # Final score bounded to integer 0–100
    final_score = max(0, min(100, int(round(blended_score))))

    # Exact score bands:
    # 0–29: low
    # 30–59: medium
    # 60–79: high
    # 80–100: critical
    risk_level = determine_risk_level(final_score)

    # 7. Safe Recommended Action
    if apk_audit:
        recommended_action = "CRITICAL: Do NOT download or install this .apk file. It is a trojanized spyware or banking stealer."
    elif upi_audit and upi_audit.is_reverse_charge_lure:
        recommended_action = "Do NOT approve this UPI transaction. UPI pay links debit your account, they cannot receive or refund money."
    elif otp_matches:
        recommended_action = "Do not share your OTP. Verify through your bank's official app."
    elif header_res and (header_res.display_name_spoofing or not header_res.domain_alignment):
        recommended_action = "Sender address and headers are spoofed. Do not open attachments or reply."
    elif max_url_score >= 60 and urgency_matches:
        recommended_action = "Do not click unverified links. Access the service directly through official verified channels."
    elif max_url_score >= 60:
        recommended_action = "Do not click unverified links. Inspect the domain and navigate to official verified sites directly."
    elif payment_matches or has_bank_or_upi:
        recommended_action = "Do not transfer money or initiate UPI payments to unverified accounts."
    elif final_score >= 80:
        recommended_action = "Critical risk detected. Do not interact with the sender, click links, or provide information."
    elif final_score >= 60:
        recommended_action = "Treat this message with high caution. Independently verify the sender's identity."
    elif final_score >= 30:
        recommended_action = "Proceed with caution. Do not follow unverified instructions without verification."
    else:
        recommended_action = "No immediate threat detected. Maintain standard cyber hygiene practices."

    # 8. Summary & Backward Compatibility
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
        model_version=effective_model_version,
        analysis_mode=effective_analysis_mode,
        summary=summary,
        breakdown=breakdown,
        recommendations=[recommended_action],
        analyzed_at=datetime.now(timezone.utc).isoformat(),
        confidence_score=round(distil_pred.confidence, 4) if (distil_pred.is_available and distil_pred.confidence > 0) else (round(ml_prob, 4) if ml_prob is not None else 0.85),
        uncertainty_range="±4%" if final_score >= 60 else "±2%",
        # DistilBERT specific response fields
        model_name=distil_pred.model_name,
        predicted_class_index=distil_pred.predicted_class_index,
        predicted_class_label=distil_pred.predicted_class_label,
        verified_class_label=distil_pred.verified_class_label,
        candidate_class_label=distil_pred.candidate_class_label,
        class_probabilities=distil_pred.class_probabilities,
        candidate_probabilities=distil_pred.candidate_probabilities,
        verification_status=distil_pred.verification_status,
        risk_assessment=distil_pred.risk_assessment,
        is_quantized=distil_pred.is_quantized,
        latency_ms=distil_pred.latency_ms,
        warning=distil_pred.warning,
        concise_explanation=distil_pred.explanation,
        distilbert=distil_pred.model_dump(),
        # Dedicated Email Header Security Analysis
        header_analysis=header_res,
        # Gemini AI Threat Intelligence
        gemini_analysis=gemini_result,
        # UPI Deep Link & QR Code Audit
        upi_audit=upi_audit,
        # Malicious APK Dropper Audit
        apk_audit=apk_audit
    )
