import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs, unquote
from pydantic import BaseModel, Field

# High-profile APK social engineering lures commonly distributed across WhatsApp / SMS in India
APK_LURE_PATTERNS = [
    (r'(?i)(?:wedding|shadi|invitation|patrika).*\.apk\b', "Wedding Invitation RAT Stealer", "Trojan-Spy.AndroidOS.Agent"),
    (r'(?i)(?:sbi|yono|hdfc|icici|pnb|axis|bob|canara|bank|kyc|reward|points).*\.apk\b', "Banking Trojan Dropper", "Trojan.AndroidOS.FakeBank"),
    (r'(?i)(?:e[_-]?challan|traffic|challan|parivahan|vahan).*\.apk\b', "E-Challan Police Phishing Dropper", "Trojan.AndroidOS.SmsStealer"),
    (r'(?i)(?:pm[_-]?kisan|yojana|ration|aadhaar|subsid[y|i]).*\.apk\b', "Government Scheme Fraud Dropper", "Trojan.AndroidOS.Dropper"),
    (r'(?i)(?:electricity|bijli|bill|power|discom).*\.apk\b', "Electricity Disconnection Trojan", "Trojan-Banker.AndroidOS.FakeDiscom"),
    (r'(?i)(?:gift|cashback|lottery|recharge|bonus).*\.apk\b', "Financial Scam Dropper", "Trojan.AndroidOS.Lure"),
    (r'(?i)[a-zA-Z0-9_\-\.]+\.apk\b', "Generic Sideloaded Android APK", "Riskware.AndroidOS.Sideload")
]

OFFICIAL_BRAND_KEYWORDS = [
    "sbi", "state bank", "hdfc", "icici", "axis", "kotak", "punjab national", "pnb",
    "electricity", "discom", "power", "bescom", "tneb", "uppcl", "mahadiscom",
    "police", "traffic", "challan", "court", "income tax", "cyber crime", "trai", "airtel", "jio"
]

class UpiAuditResult(BaseModel):
    is_upi_deeplink: bool = Field(default=False, description="Whether a UPI URI/deep link was detected")
    raw_uri: Optional[str] = Field(default=None, description="The extracted raw or normalized UPI URI")
    payee_vpa: Optional[str] = Field(default=None, description="The virtual payment address (pa)")
    payee_name: Optional[str] = Field(default=None, description="Payee name declared in link (pn)")
    amount: Optional[float] = Field(default=None, description="Pre-filled payment amount (am)")
    currency: Optional[str] = Field(default="INR", description="Currency (cu)")
    transaction_note: Optional[str] = Field(default=None, description="Transaction note/reference (tn)")
    is_reverse_charge_lure: bool = Field(default=False, description="Whether user was told they are receiving money while link debits them")
    is_brand_spoofing: bool = Field(default=False, description="Whether payee name impersonates a bank/govt body on a personal VPA")
    risk_boost: int = Field(default=0, description="Risk score contribution from UPI inspection")
    anomalies: List[str] = Field(default_factory=list, description="List of detected deceptive anomalies")
    warning_message: Optional[str] = Field(default=None, description="Actionable defensive alert for recipient")

class ApkAuditResult(BaseModel):
    has_apk_dropper: bool = Field(default=False, description="Whether sideloaded Android APK download was detected")
    filename: Optional[str] = Field(default=None, description="Extracted .apk package filename")
    download_url: Optional[str] = Field(default=None, description="Hosting link or download URL")
    lure_category: Optional[str] = Field(default=None, description="Social engineering lure taxonomy")
    targeted_threat_family: Optional[str] = Field(default=None, description="Associated trojan/spyware malware family")
    risk_score: int = Field(default=0, description="Risk rating (typically 85-100 for sideloaded droppers)")
    is_critical_threat: bool = Field(default=False, description="Whether threat warrants immediate block")
    reasons: List[str] = Field(default_factory=list, description="Findings explaining why this APK is malicious")
    defensive_warning: Optional[str] = Field(default=None, description="Safety advisory against installing file")

class PayloadScanner:
    """
    Service for static analysis of UPI deep links / QR payloads and
    trojanized sideloaded APK droppers.
    """

    def audit_upi_payload(self, text: str) -> Optional[UpiAuditResult]:
        """
        Extracts and inspects upi://pay deep links or QR code payment intents.
        Detects reverse-charge debit fraud, payee impersonation, and arbitrary pre-filled amounts.
        """
        match = re.search(r'upi://pay\?[a-zA-Z0-9_\-=&%\.\+\@\:\/]+', text, re.IGNORECASE)
        if not match:
            return None

        raw_uri = match.group(0)
        parsed = urlparse(raw_uri)
        params = parse_qs(parsed.query)

        payee_vpa = unquote(params.get('pa', [''])[0]).strip()
        payee_name = unquote(params.get('pn', [''])[0]).strip()
        tn = unquote(params.get('tn', [''])[0]).strip()
        cu = params.get('cu', ['INR'])[0].strip()

        amount_val = None
        if 'am' in params:
            try:
                amount_val = float(params['am'][0])
            except ValueError:
                amount_val = None

        anomalies = []
        risk_boost = 30
        is_reverse_charge = False
        is_brand_spoofing = False

        # Check 1: Reverse Charge Scam
        # Scammers tell victims: "Click to receive ₹5000 cashback / prize", but UPI pay always debits.
        lower_context = text.lower()
        receive_keywords = ["receive", "refund", "credit", "cashback", "lottery", "claim", "deposit into your", "get money", "collect"]
        if any(kw in lower_context for kw in receive_keywords):
            is_reverse_charge = True
            risk_boost += 45
            anomalies.append("Reverse-Charge Fraud: Message claims you will receive funds, but link will execute a DEBIT payment from your account.")

        # Check 2: Payee Name vs VPA Spoofing
        # E.g. pn="SBI Customer Support", but pa="rahul987@ybl"
        lower_pn = payee_name.lower()
        claims_official_brand = any(brand in lower_pn for brand in OFFICIAL_BRAND_KEYWORDS)
        if claims_official_brand:
            # Check if VPA looks like personal handle rather than verified merchant
            if not any(payee_vpa.lower().endswith(domain) for domain in [".bank", "sbi.org", "hdfcbank.com", "gov.in"]):
                is_brand_spoofing = True
                risk_boost += 25
                anomalies.append(f"Payee Impersonation: Display name '{payee_name}' claims to be official institution, but VPA '{payee_vpa}' is an unverified personal handle.")

        # Check 3: Arbitrary High Amount
        if amount_val is not None and amount_val >= 10000:
            risk_boost += 15
            anomalies.append(f"High Pre-filled Debit: Requests automatic debit of ₹{amount_val:,.2f}.")

        warning = None
        if is_reverse_charge or is_brand_spoofing:
            warning = "CRITICAL PAYMENT WARNING: Do NOT approve this UPI transaction or enter your UPI PIN. This request will immediately transfer money out of your account to an unverified third party."
        elif anomalies:
            warning = "Verify the payee VPA and amount carefully in your banking app before authorizing this payment."

        return UpiAuditResult(
            is_upi_deeplink=True,
            raw_uri=raw_uri,
            payee_vpa=payee_vpa or None,
            payee_name=payee_name or None,
            amount=amount_val,
            currency=cu,
            transaction_note=tn or None,
            is_reverse_charge_lure=is_reverse_charge,
            is_brand_spoofing=is_brand_spoofing,
            risk_boost=min(85, risk_boost),
            anomalies=anomalies,
            warning_message=warning
        )

    def audit_apk_threat(self, text: str) -> Optional[ApkAuditResult]:
        """
        Scans message or URLs for trojanized sideloaded Android APK droppers
        (e.g. wedding_card.apk, sbi_rewards.apk, e_challan.apk).
        """
        # Look for APK in URL or standalone filename
        apk_url_match = re.search(r'https?://[^\s<>"\'()]+\.apk(?:\?[^\s<>"\'()]*)?', text, re.IGNORECASE)
        apk_file_match = re.search(r'\b([a-zA-Z0-9_\-\.]+\.apk)\b', text, re.IGNORECASE)

        if not apk_url_match and not apk_file_match:
            return None

        filename = None
        download_url = None
        if apk_url_match:
            download_url = apk_url_match.group(0)
            parsed_path = urlparse(download_url).path
            filename = parsed_path.split('/')[-1] if '/' in parsed_path else parsed_path
        elif apk_file_match:
            filename = apk_file_match.group(1)

        filename = filename or "unnamed_package.apk"

        # Match against known Indian social engineering lure families
        lure_category = "Sideloaded Android APK Dropper"
        threat_family = "Trojan-Spy.AndroidOS.Generic"

        for pattern, cat, family in APK_LURE_PATTERNS:
            if re.search(pattern, filename) or (download_url and re.search(pattern, download_url)):
                lure_category = cat
                threat_family = family
                break

        reasons = [
            f"Message distributes an Android application package (.apk): '{filename}'.",
            f"Social Engineering Lure identified: {lure_category}.",
            "Sideloaded APKs bypass Google Play Protect and can silently hijack SMS, OTPs, and Accessibility Services.",
            f"Associated malware taxonomy: {threat_family}."
        ]

        if download_url:
            parsed = urlparse(download_url)
            host = parsed.netloc.lower()
            if any(host.endswith(tld) for tld in [".xyz", ".top", ".click", ".icu", ".buzz", ".site", ".ru"]):
                reasons.append(f"APK is hosted on a high-risk untrusted distribution domain: '{host}'.")

        warning = (
            "CRITICAL MALWARE WARNING: Do NOT download, open, or install this .apk file! "
            "Legitimate organizations, banks, police departments, and event organizers never distribute APK installation packages via WhatsApp or SMS. "
            "Installing this file may install a banking trojan or keylogger on your smartphone."
        )

        return ApkAuditResult(
            has_apk_dropper=True,
            filename=filename,
            download_url=download_url,
            lure_category=lure_category,
            targeted_threat_family=threat_family,
            risk_score=95,
            is_critical_threat=True,
            reasons=reasons,
            defensive_warning=warning
        )

payload_scanner = PayloadScanner()
