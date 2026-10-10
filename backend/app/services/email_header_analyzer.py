import re
import email
from email.utils import parseaddr
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel, Field

WELL_KNOWN_TARGET_BRANDS: Dict[str, List[str]] = {
    "paypal": ["paypal.com", "paypal.co.uk", "intl.paypal.com"],
    "microsoft": ["microsoft.com", "office.com", "outlook.com", "live.com", "office365.com"],
    "google": ["google.com", "accounts.google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com", "email.apple.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "wells fargo": ["wellsfargo.com"],
    "bank of america": ["bankofamerica.com", "bofa.com"],
    "citibank": ["citi.com", "citibank.com"],
    "dhl": ["dhl.com", "dhl.de"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "meta": ["meta.com", "facebookmail.com", "instagram.com"],
    "facebook": ["facebookmail.com", "meta.com"],
    "instagram": ["instagram.com", "meta.com"],
    "bank": ["bank", "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "hsbc.com"],
    "security team": ["microsoft.com", "google.com", "apple.com", "paypal.com"],
    "support team": ["microsoft.com", "google.com", "apple.com", "paypal.com"],
    "irs": ["irs.gov"],
    "usps": ["usps.com", "usps.gov"],
}

REPORTED_AUTH_DISCLAIMER = (
    "Authentication results (SPF/DKIM/DMARC) are parsed from self-reported message headers. "
    "They reflect the upstream MTA's reported status if untampered, but were not independently verified by THREATFORGE against live DNS/cryptographic records."
)

class EmailHeaderAnalysisResult(BaseModel):
    has_headers: bool = Field(default=False, description="Whether email headers were detected or provided")
    authentication_mode: str = Field(
        default="parsed_reported_headers",
        description="Mode of authentication analysis: parsed_reported_headers (not independent live DNS resolution)"
    )
    verification_disclaimer: str = Field(
        default=REPORTED_AUTH_DISCLAIMER,
        description="Explicit notice that header security results are parsed from reported headers, not verified live"
    )
    from_header: Optional[str] = Field(default=None, description="Full From header value")
    from_address: Optional[str] = Field(default=None, description="Parsed email address in From header")
    from_domain: Optional[str] = Field(default=None, description="Sender domain extracted from From header")
    display_name: Optional[str] = Field(default=None, description="Display name extracted from From header")
    return_path: Optional[str] = Field(default=None, description="Return-Path address")
    return_path_domain: Optional[str] = Field(default=None, description="Return-Path domain")
    reply_to: Optional[str] = Field(default=None, description="Reply-To address")
    reply_to_domain: Optional[str] = Field(default=None, description="Reply-To domain")
    spf_status: Optional[str] = Field(default=None, description="SPF result: pass, fail, softfail, neutral, none, permerror")
    dkim_status: Optional[str] = Field(default=None, description="DKIM result: pass, fail, neutral, none")
    dmarc_status: Optional[str] = Field(default=None, description="DMARC result: pass, fail, none")
    domain_alignment: bool = Field(default=True, description="True if From domain aligns with Return-Path / Reply-To")
    display_name_spoofing: bool = Field(default=False, description="True if display name claims well-known brand but domain differs")
    anomalies: List[str] = Field(default_factory=list, description="List of detected anomalies in email headers")
    risk_boost: int = Field(default=0, description="Risk score addition based on header findings")
    summary: str = Field(default="", description="Summary of header security posture")

def parse_auth_results(auth_val: str) -> Dict[str, str]:
    """Extracts spf, dkim, dmarc statuses from Authentication-Results or Received-SPF headers."""
    results = {}
    auth_lower = auth_val.lower()

    # SPF
    spf_match = re.search(r'\bspf=(pass|fail|softfail|neutral|none|permerror|temperror)\b', auth_lower)
    if spf_match:
        results["spf"] = spf_match.group(1)

    # DKIM
    dkim_match = re.search(r'\bdkim=(pass|fail|neutral|none|permerror|temperror)\b', auth_lower)
    if dkim_match:
        results["dkim"] = dkim_match.group(1)

    # DMARC
    dmarc_match = re.search(r'\bdmarc=(pass|fail|none|action=reject|action=quarantine)\b', auth_lower)
    if dmarc_match:
        val = dmarc_match.group(1)
        if "action=" in val:
            results["dmarc"] = "fail"
        else:
            results["dmarc"] = val

    return results

def detect_raw_email_headers(text: str) -> Tuple[Optional[str], str]:
    """
    Checks if the supplied text begins with RFC 822 email headers.
    If yes, separates the header block and the message body.
    Returns (header_text, body_text).
    """
    if not text:
        return None, text

    # Common email header starting line patterns
    header_start_pattern = re.compile(
        r'^(From|Received|Return-Path|Authentication-Results|Delivered-To|Subject|Date|To|Message-ID):',
        re.IGNORECASE
    )

    first_line = text.lstrip().split('\n', 1)[0].strip()
    if not header_start_pattern.match(first_line):
        return None, text

    # Search for header-body delimiter (double newline)
    parts = re.split(r'\r?\n\r?\n', text, maxsplit=1)
    if len(parts) == 2:
        header_part, body_part = parts
        # Confirm header_part has at least 2 header lines or a colon header separator
        if "\n" in header_part or ":" in header_part:
            return header_part.strip(), body_part.strip()
    
    return None, text

class EmailHeaderAnalyzer:
    """Analyzes email headers for SPF/DKIM/DMARC status, domain alignment, and display name spoofing."""

    def analyze(
        self,
        raw_headers: Optional[str] = None,
        headers_dict: Optional[Dict[str, str]] = None
    ) -> EmailHeaderAnalysisResult:
        if not raw_headers and not headers_dict:
            return EmailHeaderAnalysisResult(
                has_headers=False,
                summary="No email headers provided."
            )

        # Collect list of (header_key, header_val) preserving duplicates
        headers_list: List[Tuple[str, str]] = []
        if raw_headers:
            parsed = email.message_from_string(raw_headers)
            for k, v in parsed.items():
                headers_list.append((k.lower(), str(v)))
        
        if headers_dict:
            for k, v in headers_dict.items():
                headers_list.append((k.lower(), str(v)))

        if not headers_list:
            return EmailHeaderAnalysisResult(
                has_headers=False,
                summary="No valid headers parsed."
            )

        anomalies: List[str] = []
        risk_boost = 0

        # Helper to get first header value
        def get_first(key: str) -> str:
            for k, v in headers_list:
                if k == key:
                    return v
            return ""

        # Helper to get all header values for a key
        def get_all(key: str) -> List[str]:
            return [v for k, v in headers_list if k == key]

        # 1. From Header
        from_hdr = get_first("from")
        display_name, from_addr = parseaddr(from_hdr)
        from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else None

        # 2. Return-Path
        return_path_hdr = get_first("return-path")
        _, return_path_addr = parseaddr(return_path_hdr)
        return_path_domain = return_path_addr.split("@")[-1].lower() if "@" in return_path_addr else None

        # 3. Reply-To
        reply_to_hdr = get_first("reply-to")
        _, reply_to_addr = parseaddr(reply_to_hdr)
        reply_to_domain = reply_to_addr.split("@")[-1].lower() if "@" in reply_to_addr else None

        # 4. SPF: search all Received-SPF and Authentication-Results headers
        spf_status = None
        for rec_spf in get_all("received-spf"):
            spf_match = re.search(r'\b(pass|fail|softfail|neutral|none|permerror)\b', rec_spf.lower())
            if spf_match:
                spf_status = spf_match.group(1)
                if spf_status in ["fail", "softfail"]:
                    break

        # 5. Authentication-Results: search all Authentication-Results headers
        dkim_status = None
        dmarc_status = None
        for auth_entry in get_all("authentication-results"):
            parsed_auth = parse_auth_results(auth_entry)
            if not spf_status and "spf" in parsed_auth:
                spf_status = parsed_auth["spf"]
            if not dkim_status and "dkim" in parsed_auth:
                dkim_status = parsed_auth["dkim"]
            if not dmarc_status and "dmarc" in parsed_auth:
                dmarc_status = parsed_auth["dmarc"]

        if not dkim_status and any(k == "dkim-signature" for k, _ in headers_list):
            dkim_status = "present"

        # Check SPF failure
        if spf_status in ["fail", "softfail"]:
            anomalies.append(f"SPF authentication failed ({spf_status}) - sender IP unauthorized")
            risk_boost += 30 if spf_status == "fail" else 20

        # Check DKIM failure
        if dkim_status in ["fail"]:
            anomalies.append("DKIM cryptographic signature verification failed")
            risk_boost += 25

        # Check DMARC failure
        if dmarc_status in ["fail"]:
            anomalies.append("DMARC policy validation failed - domain alignment failure")
            risk_boost += 35

        # 6. Domain Alignment & Mismatched Return-Path / Reply-To
        domain_alignment = True
        if from_domain and return_path_domain:
            from_root = ".".join(from_domain.split(".")[-2:])
            return_root = ".".join(return_path_domain.split(".")[-2:])
            if from_root != return_root:
                domain_alignment = False
                anomalies.append(
                    f"Domain mismatch: 'From' header is @{from_domain} but 'Return-Path' is @{return_path_domain}"
                )
                risk_boost += 30

        if from_domain and reply_to_domain:
            from_root = ".".join(from_domain.split(".")[-2:])
            reply_root = ".".join(reply_to_domain.split(".")[-2:])
            if from_root != reply_root:
                anomalies.append(
                    f"Reply-To mismatch: Replies directed to @{reply_to_domain} instead of sender domain @{from_domain}"
                )
                risk_boost += 25

        # 7. Display Name Spoofing Check
        display_name_spoofing = False
        if display_name and from_domain:
            disp_lower = display_name.lower()
            for brand, legit_domains in WELL_KNOWN_TARGET_BRANDS.items():
                if brand in disp_lower:
                    is_legit = any(from_domain == d or from_domain.endswith("." + d) for d in legit_domains)
                    if not is_legit:
                        display_name_spoofing = True
                        anomalies.append(
                            f"Display Name Spoofing: Display name claims '{display_name}' but sender domain is '{from_domain}'"
                        )
                        risk_boost += 35
                        break

        # Summary
        if anomalies:
            summary = f"Flagged {len(anomalies)} email header anomalies (SPF: {spf_status or 'n/a'}, DKIM: {dkim_status or 'n/a'}, DMARC: {dmarc_status or 'n/a'})."
        else:
            summary = f"Email headers verified (SPF: {spf_status or 'none'}, DKIM: {dkim_status or 'none'}, DMARC: {dmarc_status or 'none'}). No spoofing detected."

        return EmailHeaderAnalysisResult(
            has_headers=True,
            authentication_mode="parsed_reported_headers",
            verification_disclaimer=REPORTED_AUTH_DISCLAIMER,
            from_header=from_hdr or None,
            from_address=from_addr or None,
            from_domain=from_domain,
            display_name=display_name or None,
            return_path=return_path_addr or None,
            return_path_domain=return_path_domain,
            reply_to=reply_to_addr or None,
            reply_to_domain=reply_to_domain,
            spf_status=spf_status,
            dkim_status=dkim_status,
            dmarc_status=dmarc_status,
            domain_alignment=domain_alignment,
            display_name_spoofing=display_name_spoofing,
            anomalies=anomalies,
            risk_boost=min(60, risk_boost),
            summary=summary
        )

# Singleton instance
email_header_analyzer = EmailHeaderAnalyzer()
