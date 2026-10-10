import re
from typing import List, Set, Tuple
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
    ".online", ".site", ".icu", ".buzz", ".club", ".info", ".work", ".zip"
}

def extract_indicators(text: str) -> List[ExtractedIndicator]:
    """
    Extracts threat indicators (IOCs) from text using conservative rule-based matching.
    Includes URLs, Emails, UPI IDs, Phone numbers, Crypto wallets, IP addresses, and Bank accounts.
    Deduplicates indicators strictly without making identity or guilt inferences.
    """
    if not text or not text.strip():
        return []

    indicators: List[ExtractedIndicator] = []
    seen: Set[Tuple[str, str]] = set()

    # 1. Extract URLs
    url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>"]*)?', re.IGNORECASE)
    for match in url_pattern.finditer(text):
        url = match.group(0).strip(".,;:()")
        norm_val = url.lower()
        key = (IndicatorTypeEnum.URL.value, norm_val)
        if key not in seen:
            seen.add(key)
            is_suspicious_tld = any(norm_val.endswith(tld) or (tld + "/") in norm_val for tld in SUSPICIOUS_TLDS)
            severity = SeverityEnum.HIGH if is_suspicious_tld else SeverityEnum.MEDIUM
            indicators.append(ExtractedIndicator(
                type=IndicatorTypeEnum.URL.value,
                value=url,
                severity=severity,
                confidence=0.95 if is_suspicious_tld else 0.88,
                context=text[max(0, match.start() - 20):min(len(text), match.end() + 20)],
                metadata={"suspicious_tld": is_suspicious_tld}
            ))

    # 2. Extract Emails & UPI IDs
    email_upi_pattern = re.compile(r'\b[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|[a-zA-Z0-9_-]+)\b')
    for match in email_upi_pattern.finditer(text):
        full_match = match.group(0).strip()
        domain_or_handle = match.group(1).lower()
        norm_val = full_match.lower()

        # Check if UPI handle vs Standard Email
        if domain_or_handle in UPI_SUFFIXES or ("." not in domain_or_handle):
            key = (IndicatorTypeEnum.UPI.value, norm_val)
            if key not in seen:
                seen.add(key)
                indicators.append(ExtractedIndicator(
                    type=IndicatorTypeEnum.UPI.value,
                    value=full_match,
                    severity=SeverityEnum.MEDIUM,
                    confidence=0.92,
                    context=text[max(0, match.start() - 20):min(len(text), match.end() + 20)],
                    metadata={"upi_handle": domain_or_handle}
                ))
        else:
            key = (IndicatorTypeEnum.EMAIL.value, norm_val)
            if key not in seen:
                seen.add(key)
                indicators.append(ExtractedIndicator(
                    type=IndicatorTypeEnum.EMAIL.value,
                    value=full_match,
                    severity=SeverityEnum.LOW,
                    confidence=0.90,
                    context=text[max(0, match.start() - 20):min(len(text), match.end() + 20)],
                    metadata={"domain": domain_or_handle}
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
            indicators.append(ExtractedIndicator(
                type=IndicatorTypeEnum.IP.value,
                value=ip,
                severity=SeverityEnum.HIGH if not is_private else SeverityEnum.LOW,
                confidence=0.95,
                context=text[max(0, match.start() - 20):min(len(text), match.end() + 20)],
                metadata={"is_private_ip": is_private}
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
            indicators.append(ExtractedIndicator(
                type=IndicatorTypeEnum.CRYPTO.value,
                value=addr,
                severity=SeverityEnum.HIGH,
                confidence=0.98,
                context=text[max(0, match.start() - 20):min(len(text), match.end() + 20)],
                metadata={"network": "Ethereum/EVM"}
            ))

    for match in btc_pattern.finditer(text):
        addr = match.group(0)
        key = (IndicatorTypeEnum.CRYPTO.value, addr)
        if key not in seen:
            seen.add(key)
            indicators.append(ExtractedIndicator(
                type=IndicatorTypeEnum.CRYPTO.value,
                value=addr,
                severity=SeverityEnum.HIGH,
                confidence=0.96,
                context=text[max(0, match.start() - 20):min(len(text), match.end() + 20)],
                metadata={"network": "Bitcoin"}
            ))

    for match in tron_pattern.finditer(text):
        addr = match.group(0)
        key = (IndicatorTypeEnum.CRYPTO.value, addr)
        if key not in seen:
            seen.add(key)
            indicators.append(ExtractedIndicator(
                type=IndicatorTypeEnum.CRYPTO.value,
                value=addr,
                severity=SeverityEnum.HIGH,
                confidence=0.94,
                context=text[max(0, match.start() - 20):min(len(text), match.end() + 20)],
                metadata={"network": "TRON / USDT"}
            ))

    # 5. Extract Phone-like Strings
    phone_pattern = re.compile(r'(?:\+?\d{1,3}[\s-]?)?\(?\d{2,4}\)?[\s-]?\d{3,4}[\s-]?\d{3,4}')
    for match in phone_pattern.finditer(text):
        phone_str = match.group(0).strip()
        digits_only = re.sub(r'\D', '', phone_str)
        # Ensure it has between 10 and 15 digits (valid phone number length)
        if 10 <= len(digits_only) <= 15:
            key = (IndicatorTypeEnum.PHONE.value, digits_only)
            if key not in seen:
                seen.add(key)
                indicators.append(ExtractedIndicator(
                    type=IndicatorTypeEnum.PHONE.value,
                    value=phone_str,
                    severity=SeverityEnum.MEDIUM,
                    confidence=0.85,
                    context=text[max(0, match.start() - 20):min(len(text), match.end() + 20)],
                    metadata={"digits": digits_only}
                ))

    # 6. Extract Bank Account / Routing numbers
    bank_pattern = re.compile(r'(?i)(?:account|a/c|acc|bank|routing|ifsc|no\.?)\s*[:#-]?\s*([0-9]{9,18})')
    for match in bank_pattern.finditer(text):
        account_num = match.group(1)
        key = (IndicatorTypeEnum.BANK.value, account_num)
        if key not in seen:
            seen.add(key)
            indicators.append(ExtractedIndicator(
                type=IndicatorTypeEnum.BANK.value,
                value=account_num,
                severity=SeverityEnum.HIGH,
                confidence=0.89,
                context=text[max(0, match.start() - 20):min(len(text), match.end() + 20)],
                metadata={"account_number": account_num}
            ))

    return indicators
