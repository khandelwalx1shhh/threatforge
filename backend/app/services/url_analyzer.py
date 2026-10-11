import os
import re
import math
import logging
from typing import Dict, Any, List, Optional
from collections import Counter
from urllib.parse import urlparse
import joblib

logger = logging.getLogger(__name__)

# Known verified top-level authority domains (when exact or legitimate suffix)
VERIFIED_SAFE_DOMAINS = {
    "google.com", "google.co.in", "github.com", "microsoft.com", "apple.com",
    "amazon.com", "amazon.in", "wikipedia.org", "gov.in", "nic.in",
    "youtube.com", "linkedin.com", "twitter.com", "x.com", "who.int"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "online", "site", "sbs", "click",
    "tk", "ml", "ga", "cf", "gq", "icu", "vip", "work", "fit", "buzz", "rest", "cam"
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "bank", "update",
    "signin", "confirm", "paypal", "wallet", "webscr", "password",
    "credential", "suspend", "kyc", "otp", "billing", "recover"
]

TARGETED_BRANDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "wellsfargo", "chase", "binance"
]

def shannon_entropy(text: str) -> float:
    text = str(text)
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())

def extract_lexical_features(url_str: str) -> dict:
    url = str(url_str).strip()
    norm_url = url if "://" in url else ("http://" + url)
    parsed = urlparse(norm_url)
    
    host = parsed.netloc or parsed.path.split("/")[0]
    if ":" in host:
        host = host.split(":")[0]
    path = parsed.path
    query = parsed.query

    dots_in_host = host.count(".")
    subdomain_count = max(0, dots_in_host - 1)

    host_parts = host.split(".")
    tld = host_parts[-1].lower() if len(host_parts) > 1 else ""
    is_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    is_ip = 1 if (re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host) or 
                  re.search(r"//\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url)) else 0

    has_punycode = 1 if "xn--" in host.lower() else 0

    digit_count = sum(c.isdigit() for c in url)
    digit_ratio = digit_count / max(len(url), 1)

    special_chars = [c for c in url if not c.isalnum() and c not in [":", "/", "."]]
    special_count = len(special_chars)
    special_ratio = special_count / max(len(url), 1)

    primary_domain = ".".join(host_parts[-2:]) if len(host_parts) >= 2 else host
    brand_spoofing = 0
    for brand in TARGETED_BRANDS:
        if brand in url.lower() and brand not in primary_domain.lower():
            brand_spoofing += 1

    url_lower = url.lower()
    keyword_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    double_slash_path = 1 if "//" in path else 0
    at_symbol_present = 1 if "@" in url else 0

    return {
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": url.count("."),
        "num_subdomains": subdomain_count,
        "num_hyphens": url.count("-"),
        "num_slashes": url.count("/"),
        "num_at": url.count("@"),
        "num_question": url.count("?"),
        "num_equal": url.count("="),
        "num_ampersand": url.count("&"),
        "num_percent": url.count("%"),
        "num_digits": digit_count,
        "digit_ratio": digit_ratio,
        "special_char_count": special_count,
        "special_char_ratio": special_ratio,
        "is_ip_host": is_ip,
        "has_punycode": has_punycode,
        "entropy": shannon_entropy(url),
        "host_entropy": shannon_entropy(host),
        "suspicious_keyword_count": keyword_hits,
        "brand_spoofing_count": brand_spoofing,
        "suspicious_tld": is_suspicious_tld,
        "double_slash_in_path": double_slash_path,
        "at_symbol": at_symbol_present,
        "is_https": 1 if url.lower().startswith("https://") else 0
    }

class URLClassifierService:
    def __init__(self, model_path: Optional[str] = None):
        if model_path is None:
            backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            model_path = os.path.join(backend_dir, "models", "url_classifier_v1.joblib")
        
        self.model_path = model_path
        self.pipeline = None
        self.model_version = "url-rules-v1"
        self.feature_names = []
        self.is_loaded = False
        self._load_model()

    def _load_model(self):
        try:
            if os.path.exists(self.model_path):
                artifact = joblib.load(self.model_path)
                if isinstance(artifact, dict) and "pipeline" in artifact:
                    self.pipeline = artifact["pipeline"]
                    self.model_version = artifact.get("model_version", "url-v1")
                    self.feature_names = artifact.get("feature_names", [])
                    self.is_loaded = True
                    logger.info("URLClassifierService successfully loaded ML model %s", self.model_version)
                    return
        except Exception as e:
            logger.warning("Failed to load URL model from %s: %s. Using deterministic fallback.", self.model_path, e)
        
        self.pipeline = None
        self.model_version = "url-rules-v1"
        self.is_loaded = False

    def is_available(self) -> bool:
        return self.is_loaded and self.pipeline is not None

    def reload(self):
        """Attempts to reload the URL classifier from disk."""
        self._load_model()

    def unload(self):
        """Forces model unload for testing deterministic fallback behavior."""
        self.pipeline = None
        self.model_version = "url-rules-v1"
        self.is_loaded = False

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Safely inspects a URL string locally without network access.
        Returns risk assessment, explainable reasons, indicators, and metadata.
        Treats unfamiliar domains as uncertain rather than automatically malicious.
        """
        raw_url = str(url).strip()
        norm_url = raw_url if "://" in raw_url else ("http://" + raw_url)
        parsed = urlparse(norm_url)
        host = (parsed.netloc or parsed.path.split("/")[0]).split(":")[0].lower()

        feats = extract_lexical_features(raw_url)
        reasons: List[str] = []
        indicators: List[Dict[str, Any]] = []

        # 1. Deterministic Heuristics & Specific Red Flags
        deterministic_score = 0
        
        # IP Host
        if feats["is_ip_host"]:
            deterministic_score += 40
            reasons.append("Host is a raw numerical IP address instead of a domain name")
            indicators.append({
                "type": "IP Host",
                "value": host,
                "severity": "HIGH",
                "confidence": 0.95
            })

        # Punycode / Homograph
        if feats["has_punycode"]:
            deterministic_score += 35
            reasons.append("Domain uses punycode (xn--) encoding, a common phishing homograph technique")
            indicators.append({
                "type": "Punycode Obfuscation",
                "value": host,
                "severity": "HIGH",
                "confidence": 0.90
            })

        # @ symbol in URL
        if feats["at_symbol"]:
            deterministic_score += 25
            reasons.append("URL contains '@' symbol to obfuscate true destination authority")

        # Double slash in path
        if feats["double_slash_in_path"]:
            deterministic_score += 20
            reasons.append("URL contains embedded '//' in path indicating redirection trick")

        # Suspicious TLD
        if feats["suspicious_tld"]:
            deterministic_score += 15
            reasons.append(f"Domain uses high-abuse top-level domain (.{host.split('.')[-1]})")

        # Brand spoofing (e.g. paypal in subdomain of non-paypal domain)
        if feats["brand_spoofing_count"] > 0:
            deterministic_score += 30
            reasons.append("URL references trusted brand keywords within an untrusted subdomain or path")

        # Suspicious keywords in path/query (login, verify, bank, otp)
        if feats["suspicious_keyword_count"] > 0:
            deterministic_score += min(20, feats["suspicious_keyword_count"] * 10)
            reasons.append(f"URL path or query contains {feats['suspicious_keyword_count']} sensitive authentication/billing keywords")

        # High entropy hostname (DGA-like random string)
        if feats["host_entropy"] > 4.2 and len(host) > 15:
            deterministic_score += 15
            reasons.append("Domain name exhibits unusually high character entropy (possible algorithmic domain)")

        # Verified Safe Domain exemption
        is_verified_safe = any(host == safe_d or host.endswith("." + safe_d) for safe_d in VERIFIED_SAFE_DOMAINS)
        if is_verified_safe and feats["brand_spoofing_count"] == 0 and not feats["is_ip_host"]:
            # Well-known benign domain: keep very low risk
            deterministic_score = max(0, min(10, deterministic_score))

        # 2. Machine Learning Prediction if available
        ml_score = None
        ml_prob = None
        if self.is_available() and self.feature_names:
            try:
                import numpy as np
                import pandas as pd
                feature_vec = pd.DataFrame([feats])[self.feature_names].values
                ml_prob = float(self.pipeline.predict_proba(feature_vec)[0][1])
                ml_score = int(round(ml_prob * 100))
            except Exception as e:
                logger.debug("URL ML inference exception: %s", e)
                ml_score = None

        # 3. Blended Score calculation
        if ml_score is not None:
            analysis_mode = "rules+ml"
            model_ver = self.model_version
            # Blend: weighted average with ceiling protection
            if is_verified_safe:
                final_score = min(15, deterministic_score)
            else:
                # ML model probability blended with deterministic red flags
                final_score = int(round(0.6 * ml_score + 0.4 * min(100, deterministic_score)))
                if deterministic_score >= 50:
                    final_score = max(final_score, min(100, deterministic_score))
        else:
            analysis_mode = "rules"
            model_ver = "url-rules-v1"
            if is_verified_safe:
                final_score = min(15, deterministic_score)
            else:
                # If unfamiliar domain without explicit red flags: uncertain (moderate/low, e.g. 20-30), NOT critical
                if deterministic_score == 0:
                    final_score = 15  # Unfamiliar domain is uncertain / low baseline, NOT automatically malicious
                else:
                    final_score = min(100, deterministic_score)

        # Ensure bound within 0-100
        final_score = max(0, min(100, final_score))

        # 4. Map Risk Category according to required bands:
        # 0–29: low
        # 30–59: medium
        # 60–79: high
        # 80–100: critical
        if final_score <= 29:
            risk_category = "low"
        elif final_score <= 59:
            risk_category = "medium"
        elif final_score <= 79:
            risk_category = "high"
        else:
            risk_category = "critical"

        # Provide a default reason if benign or uncertain
        if not reasons:
            if final_score <= 29:
                reasons.append("Domain and URL structure exhibit standard benign lexical patterns")
            else:
                reasons.append("Unfamiliar domain structure requires standard user verification")

        # Threat indicator payload for URL
        severity = "CRITICAL" if final_score >= 80 else ("HIGH" if final_score >= 60 else ("MEDIUM" if final_score >= 30 else "LOW"))
        indicators.append({
            "type": "Phishing URL" if final_score >= 60 else "Suspicious URL",
            "value": raw_url,
            "severity": severity,
            "confidence": round(ml_prob, 2) if ml_prob is not None else round(final_score / 100.0, 2),
            "metadata": {
                "domain": host,
                "is_ip_host": bool(feats["is_ip_host"]),
                "suspicious_tld": bool(feats["suspicious_tld"]),
                "is_https": bool(feats["is_https"])
            }
        })

        return {
            "url": raw_url,
            "domain": host,
            "risk_score": final_score,
            "risk_category": risk_category,
            "reasons": reasons,
            "model_version": model_ver,
            "analysis_mode": analysis_mode,
            "ml_probability": round(ml_prob, 4) if ml_prob is not None else None,
            "indicators": indicators,
            "features": feats
        }

    def analyze_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        return [self.analyze_url(u) for u in urls if u and isinstance(u, str)]

# Global singleton
url_classifier_service = URLClassifierService()
