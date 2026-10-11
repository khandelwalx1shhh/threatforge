import re
from typing import List, Set, Tuple, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from app.schemas.common import ExtractedIndicator, SeverityEnum, IndicatorTypeEnum

# Known UPI Suffixes (India UPI ecosystem)
UPI_SUFFIXES = {
    "upi", "okaxis", "okicici", "okhdfcbank", "ybl", "axl", "ibl",
    "paytm", "postbank", "sbi", "barodampay", "dlb", "idfcbank", "kvb",
    "mahb", "pingpay", "rbl", "yesbank", "icici", "axis", "hdfc", "kotak"
}

# Known high-risk/suspicious TLDs
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".link",
    ".online", ".site", ".icu", ".buzz", ".club", ".info", ".work", ".zip", ".sbs", ".click"
}

SENSITIVE_PARAM_KEYS = {
    "token", "auth", "key", "secret", "password", "pwd", "pass", "otp",
    "code", "access_token", "api_key", "session", "credential", "pin"
}

def sanitize_url(raw_url: str) -> Tuple[str, str]:
    """
    Normalizes URL and sanitizes sensitive private query tokens.
    Returns (sanitized_url, domain).
    """
    raw_url = raw_url.strip(".,;:()\"'<>")
    norm_url = raw_url if "://" in raw_url else ("http://" + raw_url)
    try:
        parsed = urlparse(norm_url)
        domain = (parsed.netloc or parsed.path.split("/")[0]).split(":")[0].lower()
        if parsed.query:
            query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
            sanitized_pairs = []
            for k, v in query_pairs:
                if k.lower() in SENSITIVE_PARAM_KEYS:
                    sanitized_pairs.append((k, "REDACTED"))
                else:
                    sanitized_pairs.append((k, v))
            new_query = urlencode(sanitized_pairs)
            # Reconstruct
            sanitized_url = urlunparse((
                parsed.scheme,
                parsed.netloc.lower(),
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment
            ))
            return sanitized_url, domain
        return raw_url, domain
    except Exception:
        return raw_url, raw_url.split("/")[0].lower()

def sanitize_snippet(snippet: str) -> str:
    """
    Redacts any 4-8 digit verification codes or tokens from snippet to prevent logging leaks.
    """
    if not snippet:
        return ""
    # Redact obvious auth codes / OTPs
    sanitized = re.sub(
        r'\b(?:otp|code|pin|passcode|token)\s*(?:is|[:=])?\s*([0-9a-zA-Z]{4,8})\b',
        r'code: [REDACTED]',
        snippet,
        flags=re.IGNORECASE
    )
    # Redact private url query tokens in snippet
    sanitized = re.sub(
        r'([?&](?:token|auth|key|password|otp)=)[^&\s]+',
        r'\1REDACTED',
        sanitized,
        flags=re.IGNORECASE
    )
    return sanitized

def extract_indicators(text: str) -> List[ExtractedIndicator]:
    """
    Extracts threat indicators (IOCs) from text using conservative rule-based matching.
    Includes URLs, Domains, Emails, UPI IDs, Phone numbers, Crypto wallets, IP addresses, and Bank accounts.
    Strictly deduplicates within a single result.
    Treats extracted indicators as unverified and does not make identity or guilt inferences.
    """
    if not text or not text.strip():
        return []

    indicators: List[ExtractedIndicator] = []
    seen: Set[Tuple[str, str]] = set()

    # 1. Extract URLs and Domains
    url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>"]*)?', re.IGNORECASE)
    for match in url_pattern.finditer(text):
        raw_match = match.group(0)
        sanitized_url, domain = sanitize_url(raw_match)
        norm_val = sanitized_url.lower()
        key = (IndicatorTypeEnum.URL.value, norm_val)
        if key not in seen:
            seen.add(key)
            is_suspicious_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
            severity = SeverityEnum.HIGH if is_suspicious_tld else SeverityEnum.MEDIUM
            context_snip = sanitize_snippet(text[max(0, match.start() - 20):min(len(text), match.end() + 20)])
            indicators.append(ExtractedIndicator(
                type=IndicatorTypeEnum.URL.value,
                value=sanitized_url,
                severity=severity,
                confidence=0.92 if is_suspicious_tld else 0.85,
                context=context_snip,
                metadata={
                    "domain": domain,
                    "suspicious_tld": is_suspicious_tld,
                    "is_verified": False,
                    "status": "unverified"
                }
            ))

    # 2. Extract Emails & UPI IDs
    email_upi_pattern = re.compile(r'\b[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|[a-zA-Z0-9_-]+)\b')
    for match in email_upi_pattern.finditer(text):
        full_match = match.group(0).strip(".,;:()\"'<>")
        domain_or_handle = match.group(1).lower()
        norm_val = full_match.lower()

        # Check if UPI handle vs Standard Email
        if domain_or_handle in UPI_SUFFIXES or ("." not in domain_or_handle and len(domain_or_handle) <= 15):
            key = (IndicatorTypeEnum.UPI.value, norm_val)
            if key not in seen:
                seen.add(key)
                context_snip = sanitize_snippet(text[max(0, match.start() - 20):min(len(text), match.end() + 20)])
                indicators.append(ExtractedIndicator(
                    type=IndicatorTypeEnum.UPI.value,
                    value=full_match,
                    severity=SeverityEnum.MEDIUM,
                    confidence=0.90,
                    context=context_snip,
                    metadata={
                        "upi_handle": domain_or_handle,
                        "is_verified": False,
                        "status": "unverified"
                    }
                ))
        else:
            key = (IndicatorTypeEnum.EMAIL.value, norm_val)
            if key not in seen:
                seen.add(key)
                context_snip = sanitize_snippet(text[max(0, match.start() - 20):min(len(text), match.end() + 20)])
                indicators.append(ExtractedIndicator(
                    type=IndicatorTypeEnum.EMAIL.value,
                    value=full_match,
                    severity=SeverityEnum.LOW,
                    confidence=0.88,
                    context=context_snip,
                    metadata={
                        "domain": domain_or_handle,
                        "is_verified": False,
                        "status": "unverified"
                    }
                ))

    # 3. Extract IP Addresses (IPv4)
    ip_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    for match in ip_pattern.finditer(text):
        ip = match.group(0)
        norm_val = ip
        key = (IndicatorTypeEnum.IP.value, norm_val)
        if key not in seen:
            seen.add(key)
            is_private = ip.startswith(("127.", "10.", "192.168.", "172.16."))
            context_snip = sanitize_snippet(text[max(0, match.start() - 20):min(len(text), match.end() + 20)])
            indicators.append(ExtractedIndicator(
                type=IndicatorTypeEnum.IP.value,
                value=ip,
                severity=SeverityEnum.HIGH if not is_private else SeverityEnum.LOW,
                confidence=0.95,
                context=context_snip,
                metadata={
                    "is_private_ip": is_private,
                    "is_verified": False,
                    "status": "unverified"
                }
            ))

    # 4. Extract Crypto Wallet Addresses (BTC, ETH, TRON/USDT)
    eth_pattern = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
    btc_pattern = re.compile(r'\b(?:1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-Z0-9]{8,87})\b')
    tron_pattern = re.compile(r'\bT[A-Za-z1-9]{33}\b')

    for match in eth_pattern.finditer(text):
        addr = match.group(0)
        key = (IndicatorTypeEnum.CRYPTO.value, addr.lower())
        if key not in seen:
            seen.add(key)
            context_snip = sanitize_snippet(text[max(0, match.start() - 20):min(len(text), match.end() + 20)])
            indicators.append(ExtractedIndicator(
                type=IndicatorTypeEnum.CRYPTO.value,
                value=addr,
                severity=SeverityEnum.HIGH,
                confidence=0.98,
                context=context_snip,
                metadata={"network": "Ethereum/EVM", "is_verified": False, "status": "unverified"}
            ))

    for match in btc_pattern.finditer(text):
        addr = match.group(0)
        key = (IndicatorTypeEnum.CRYPTO.value, addr)
        if key not in seen:
            seen.add(key)
            context_snip = sanitize_snippet(text[max(0, match.start() - 20):min(len(text), match.end() + 20)])
            indicators.append(ExtractedIndicator(
                type=IndicatorTypeEnum.CRYPTO.value,
                value=addr,
                severity=SeverityEnum.HIGH,
                confidence=0.96,
                context=context_snip,
                metadata={"network": "Bitcoin", "is_verified": False, "status": "unverified"}
            ))

    for match in tron_pattern.finditer(text):
        addr = match.group(0)
        key = (IndicatorTypeEnum.CRYPTO.value, addr)
        if key not in seen:
            seen.add(key)
            context_snip = sanitize_snippet(text[max(0, match.start() - 20):min(len(text), match.end() + 20)])
            indicators.append(ExtractedIndicator(
                type=IndicatorTypeEnum.CRYPTO.value,
                value=addr,
                severity=SeverityEnum.HIGH,
                confidence=0.94,
                context=context_snip,
                metadata={"network": "TRON / USDT", "is_verified": False, "status": "unverified"}
            ))

    # 5. Extract Phone-like Strings (Validates international and standard phone structures)
    # Reject ordinary standalone numbers (e.g. order numbers, amounts, dates, 6-digit OTPs)
    phone_pattern = re.compile(
        r'(?:(?:\+|00)\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,5}[\s.-]?\d{3,5}\b'
    )
    for match in phone_pattern.finditer(text):
        phone_str = match.group(0).strip(".,;:()\"'<>")
        digits_only = re.sub(r'\D', '', phone_str)
        # Avoid treating ordinary numbers (e.g. 4-digit years like 2024, 6-digit OTPs, 8-digit order IDs) as phones
        if len(digits_only) < 10 or len(digits_only) > 15:
            continue
        
        # Don't capture numbers immediately preceded by currency or date markers
        start_idx = match.start()
        prefix_slice = text[max(0, start_idx - 6):start_idx].lower()
        if any(prefix in prefix_slice for prefix in ["$", "€", "₹", "rs", "inr", "order", "txn", "ref", "id:", "#"]):
            continue

        key = (IndicatorTypeEnum.PHONE.value, digits_only)
        if key not in seen:
            seen.add(key)
            context_snip = sanitize_snippet(text[max(0, match.start() - 20):min(len(text), match.end() + 20)])
            indicators.append(ExtractedIndicator(
                type=IndicatorTypeEnum.PHONE.value,
                value=phone_str,
                severity=SeverityEnum.MEDIUM,
                confidence=0.85,
                context=context_snip,
                metadata={
                    "digits": digits_only,
                    "is_verified": False,
                    "status": "unverified"
                }
            ))

    # 6. Extract Bank Account / Routing numbers
    bank_pattern = re.compile(r'(?i)(?:account|a/c|acc|bank|routing|ifsc|no\.?)\s*[:#-]?\s*([0-9]{9,18})')
    for match in bank_pattern.finditer(text):
        account_num = match.group(1)
        key = (IndicatorTypeEnum.BANK.value, account_num)
        if key not in seen:
            seen.add(key)
            context_snip = sanitize_snippet(text[max(0, match.start() - 20):min(len(text), match.end() + 20)])
            indicators.append(ExtractedIndicator(
                type=IndicatorTypeEnum.BANK.value,
                value=account_num,
                severity=SeverityEnum.HIGH,
                confidence=0.89,
                context=context_snip,
                metadata={
                    "account_number": account_num,
                    "is_verified": False,
                    "status": "unverified"
                }
            ))

    # 7. Extract UPI Deep Links (upi://pay?...)
    upi_deeplink_pattern = re.compile(r'upi://pay\?[a-zA-Z0-9_\-=&%\.\+\@\:\/]+', re.IGNORECASE)
    for match in upi_deeplink_pattern.finditer(text):
        raw_uri = match.group(0)
        key = (IndicatorTypeEnum.UPI_DEEPLINK.value, raw_uri.lower())
        if key not in seen:
            seen.add(key)
            context_snip = sanitize_snippet(text[max(0, match.start() - 20):min(len(text), match.end() + 20)])
            indicators.append(ExtractedIndicator(
                type=IndicatorTypeEnum.UPI_DEEPLINK.value,
                value=raw_uri,
                severity=SeverityEnum.HIGH,
                confidence=0.96,
                context=context_snip,
                metadata={
                    "is_verified": False,
                    "status": "unverified"
                }
            ))

    # 8. Extract Malicious Sideloaded APK Files
    apk_pattern = re.compile(r'\b(?:https?://[^\s<>"\'()]+\.apk(?:\?[^\s<>"\'()]*)?|\b[a-zA-Z0-9_\-\.]+\.apk)\b', re.IGNORECASE)
    for match in apk_pattern.finditer(text):
        apk_val = match.group(0).strip(".,;:()\"'<>")
        key = (IndicatorTypeEnum.APK.value, apk_val.lower())
        if key not in seen:
            seen.add(key)
            context_snip = sanitize_snippet(text[max(0, match.start() - 20):min(len(text), match.end() + 20)])
            indicators.append(ExtractedIndicator(
                type=IndicatorTypeEnum.APK.value,
                value=apk_val,
                severity=SeverityEnum.CRITICAL,
                confidence=0.98,
                context=context_snip,
                metadata={
                    "package_type": "Android Sideload APK",
                    "is_verified": False,
                    "status": "unverified"
                }
            ))

    return indicators
