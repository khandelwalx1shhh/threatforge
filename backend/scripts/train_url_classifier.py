import os
import re
import math
import json
from collections import Counter
from urllib.parse import urlparse
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support, accuracy_score
import joblib

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BACKEND_DIR, "models")
DATA_DIR = os.path.join(BACKEND_DIR, "data")
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

NORMALIZED_DATA_PATH = os.path.join(DATA_DIR, "urls_normalized.csv")
RAW_DATA_PATH = os.path.join(DATA_DIR, "urls_dataset.csv")

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

    # Subdomains & Host dots
    dots_in_host = host.count(".")
    subdomain_count = max(0, dots_in_host - 1)

    # TLD
    host_parts = host.split(".")
    tld = host_parts[-1].lower() if len(host_parts) > 1 else ""
    is_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    # IP address host detection
    is_ip = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host) or re.search(r"//\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url) else 0

    # Punycode indicator
    has_punycode = 1 if "xn--" in host.lower() else 0

    # Character counts
    digit_count = sum(c.isdigit() for c in url)
    digit_ratio = digit_count / max(len(url), 1)

    # Special characters
    special_chars = [c for c in url if not c.isalnum() and c not in [":", "/", "."]]
    special_count = len(special_chars)
    special_ratio = special_count / max(len(url), 1)

    # Brand spoofing (brand appears outside primary domain)
    primary_domain = ".".join(host_parts[-2:]) if len(host_parts) >= 2 else host
    brand_spoofing = 0
    for brand in TARGETED_BRANDS:
        if brand in url.lower() and brand not in primary_domain.lower():
            brand_spoofing += 1

    # Suspicious keywords
    url_lower = url.lower()
    keyword_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    # Unusual patterns
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

FEATURE_NAMES = list(extract_lexical_features("http://example.com/test").keys())

def train_and_evaluate():
    data_file = None
    for candidate in [
        NORMALIZED_DATA_PATH,
        RAW_DATA_PATH,
        r"C:\Users\Vansh\Downloads\cyberrakshak (2)\cyberrakshak\phishing_ml\datasets.csv"
    ]:
        if os.path.exists(candidate):
            data_file = candidate
            break

    if not data_file:
        raise FileNotFoundError("No URL dataset found to train URL classifier.")

    print(f"Loading URL dataset from {data_file}...")
    df = pd.read_csv(data_file)
    col_map = {c: c.strip().lower() for c in df.columns}
    df.rename(columns=col_map, inplace=True)
    
    url_col = "url" if "url" in df.columns else df.columns[0]
    label_col = "label" if "label" in df.columns else df.columns[1]

    raw_count = len(df)
    df = df.dropna(subset=[url_col, label_col]).copy()
    df[url_col] = df[url_col].astype(str).str.strip()
    df = df[df[url_col] != ""]
    df = df.drop_duplicates(subset=[url_col]).copy()
    dedup_count = len(df)

    def clean_label(val):
        s = str(val).strip().lower()
        if s in ["1", "malicious", "phishing", "scam", "bad", "1.0"]:
            return 1
        elif s in ["0", "benign", "legitimate", "good", "safe", "0.0"]:
            return 0
        return None

    df["clean_label"] = df[label_col].apply(clean_label)
    df = df[df["clean_label"].notnull()].copy()
    df["clean_label"] = df["clean_label"].astype(int)

    # Balance if single class is over-represented
    counts = df["clean_label"].value_counts().to_dict()
    min_count = min(counts.get(0, 0), counts.get(1, 0))
    if min_count < 100:
        raise ValueError(f"Insufficient samples for training: {counts}")
    
    # Cap at 35,000 per class for rapid, robust training
    sample_per_class = min(min_count, 35000)
    df_0 = df[df["clean_label"] == 0].sample(n=sample_per_class, random_state=42)
    df_1 = df[df["clean_label"] == 1].sample(n=sample_per_class, random_state=42)
    df_balanced = pd.concat([df_0, df_1]).sample(frac=1.0, random_state=42)

    class_distribution = df_balanced["clean_label"].value_counts().to_dict()
    print(f"Balanced class distribution for training: {class_distribution}")

    print("Extracting lexical features...")
    features_list = [extract_lexical_features(u) for u in df_balanced[url_col]]
    X = pd.DataFrame(features_list)[FEATURE_NAMES].values
    y = df_balanced["clean_label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"Train samples: {len(X_train)}, Test samples: {len(X_test)}")

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", LogisticRegression(max_iter=1000, random_state=42, C=1.0))
    ])

    print("Fitting Logistic Regression pipeline...")
    pipeline.fit(X_train, y_train)

    print("Evaluating on test set...")
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary")
    cm = confusion_matrix(y_test, y_pred).tolist()
    cls_report = classification_report(y_test, y_pred, target_names=["benign", "malicious"], output_dict=True)

    print(f"Test Accuracy: {acc:.4f}")
    print(f"Precision: {float(prec):.4f}, Recall: {float(rec):.4f}, F1: {float(f1):.4f}")
    print(f"Confusion Matrix: {cm}")

    model_version = "url-v1"
    artifact_payload = {
        "model_version": model_version,
        "pipeline": pipeline,
        "feature_names": FEATURE_NAMES,
        "algorithm": "StandardScaler + LogisticRegression",
        "suspicious_tlds": sorted(list(SUSPICIOUS_TLDS)),
        "suspicious_keywords": SUSPICIOUS_KEYWORDS,
        "targeted_brands": TARGETED_BRANDS,
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "confusion_matrix": cm,
            "test_samples": len(y_test),
            "train_samples": len(y_train)
        }
    }

    model_save_path = os.path.join(MODEL_DIR, "url_classifier_v1.joblib")
    joblib.dump(artifact_payload, model_save_path)
    print(f"Saved model artifact to {model_save_path}")

    report_data = {
        "model_version": model_version,
        "dataset_source": os.path.basename(data_file),
        "raw_samples": raw_count,
        "deduplicated_samples": dedup_count,
        "balanced_training_total": len(df_balanced),
        "class_distribution": {
            "benign_0": int(class_distribution.get(0, 0)),
            "malicious_1": int(class_distribution.get(1, 0))
        },
        "train_set_size": len(y_train),
        "test_set_size": len(y_test),
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "confusion_matrix": {
                "true_negative": cm[0][0],
                "false_positive": cm[0][1],
                "false_negative": cm[1][0],
                "true_positive": cm[1][1]
            }
        },
        "classification_report": cls_report,
        "feature_names": FEATURE_NAMES,
        "coefficients": {
            feat: round(float(coef), 4)
            for feat, coef in zip(FEATURE_NAMES, pipeline.named_steps["classifier"].coef_[0])
        }
    }

    report_path = os.path.join(MODEL_DIR, "url_training_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    print(f"Saved evaluation report to {report_path}")

    return report_data

if __name__ == "__main__":
    train_and_evaluate()
