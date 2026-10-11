<div align="center">
  <img src="frontend/public/logo_transparent.png" width="120" alt="Argus Logo" />
  <h1>ARGUS</h1>
  <p><strong>Autonomous Cyber Threat Intelligence, On-Device Fraud Prevention & Adaptive Phishing Defense System</strong></p>
</div>

Built for hackathons and production prototypes with a FastAPI backend, Scikit-Learn & PyTorch ML classifiers, INT8 Quantized DistilBERT Transformer, native Android on-device real-time fraud defense agent, and a React + TypeScript SOC dashboard.

> 📘 **Full Architecture & Technical Dossier**: For in-depth engineering specifications, on-device detection pipelines, and API contracts, see [PROJECT_DOCUMENTATION.md](PROJECT_DOCUMENTATION.md).

---

## Phase 2 Architecture & Status Summary

### 1. Model Matrix & Fallback Status

| Component | Architecture | Model Version | Artifact Path | Status | Fallback Mode |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Message Text Classifier** | `TfidfVectorizer` + `LogisticRegression` | `text-v1` | `backend/models/scam_classifier_v1.joblib` | **Trained & Active** | Deterministic urgency/credential heuristics (`none`) |
| **URL Phishing Classifier** | `StandardScaler` + `LogisticRegression` (23 safe lexical features) | `url-v1` | `backend/models/url_classifier_v1.joblib` | **Trained & Active** | Deterministic lexical rules (`url-rules-v1`) |
| **Deep Email Transformer** | `cybersectony/phishing-email-detection-distilbert_v2.4.1` (INT8 Quantized) | `v2.4.1` | Hugging Face cache | **Active** (20–50ms CPU latency) | Graceful bypass if PyTorch/weights unavailable |
| **Email Header Security** | RFC 822 Parser (SPF, DKIM, DMARC, Display Name Spoofing) | Rules | `app/services/email_header_analyzer.py` | **Active** | Graceful bypass if no headers supplied |
| **Threat IOC Extractor** | Conservative Regex Parser with Sanitization & Deduplication | Rules | `app/services/extractor.py` | **Active** | Standard regex matching |

---

## Evaluation Metrics & Dataset Analysis

### URL Classifier (`url-v1`)
- **Dataset**: `backend/data/urls_normalized.csv` (balanced sample of 60,000 real URLs from verified online sources).
- **Training Set**: 48,000 URLs (24,000 benign, 24,000 malicious).
- **Evaluation Set**: 12,000 URLs (6,000 benign, 6,000 malicious).
- **Features**: 23 safe local lexical string features (length, hostname length, subdomain count, dots, hyphens, slashes, digit ratio, special character ratio, entropy, host entropy, IP address host detection, punycode `xn--`, brand spoofing detection, sensitive keywords count, high-risk TLDs). **Zero network requests or URL crawling.**
- **Actual Evaluation Metrics**:
  - **Accuracy**: `75.08%`
  - **Precision**: `79.82%`
  - **Recall**: `67.12%`
  - **F1-Score**: `0.7292`
  - **Confusion Matrix**: True Negative: `4,982`, False Positive: `1,018`, False Negative: `1,973`, True Positive: `4,027`
- **Report File**: `backend/models/url_training_report.json`

### Message Text Classifier (`text-v1`)
- **Dataset**: `backend/data/normalized_messages.csv`
- **Samples**: 275 labeled messages (scam vs. benign).
- **Report File**: `backend/models/training_report.json`

---

## API Contract (For Android & Client Developers)

### Base URL & Port
- **Base URL**: `http://localhost:8000` (or `http://<HOST_IP>:8000`)
- **Port**: `8000`
- **Interactive OpenAPI Docs**: `http://localhost:8000/docs`

### 1. Health Endpoint: `GET /health`

**Response Example:**
```json
{
  "status": "ok",
  "model_loaded": true,
  "url_model_loaded": true,
  "url_model_version": "url-v1",
  "distilbert_loaded": true,
  "distilbert_quantized": true
}
```

---

### 2. Threat Analysis Endpoint: `POST /api/analyze`

#### Request Payload Specification

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `text` | string | **Yes** | Message text or URL to analyze (max 5000 characters). |
| `source` | string | No | Source channel: `"whatsapp"`, `"telegram"`, `"manual_test"`, `"email"` (default: `"manual_test"`). |
| `sender` | string | No | Sender identifier (phone, email, or handle). |
| `raw_headers` | string | No | Optional raw RFC 822 email headers. |
| `cloud_analysis` | boolean | No | Flag for cloud analysis (default: `false`). |

#### Request Example (JSON)
```json
{
  "text": "URGENT: Your account will be suspended. Verify immediately at http://192.168.1.50/login.php?update=bank",
  "source": "whatsapp"
}
```

#### Response Payload Specification

| Field | Type | Description |
| :--- | :--- | :--- |
| `risk_score` | integer | Risk score strictly bounded between `0` and `100`. |
| `risk_level` | string | Exact risk category: `"low"` (0–29), `"medium"` (30–59), `"high"` (60–79), `"critical"` (80–100). Score `87` maps to `"critical"`. |
| `reasons` | string[] | Explainable human-readable reasons for detected threat signals. |
| `recommended_action` | string | Actionable safe next step for the user. |
| `indicators` | object[] | Deduplicated threat indicators (URLs, domains, emails, phones, UPIs, IPs, crypto addresses). |
| `model_version` | string | Model identifier (e.g. `"text-v1"`, `"url-v1"`, or fallback `"none"`). |
| `analysis_mode` | string | Mode identifier: `"rules+ml"`, `"rules"`, or `"ml"`. |

#### Response Example (JSON)
```json
{
  "risk_score": 87,
  "risk_level": "critical",
  "reasons": [
    "Uses an urgent account threat",
    "Contains suspicious link with coercive context",
    "Host is a raw numerical IP address instead of a domain name",
    "URL path or query contains 3 sensitive authentication/billing keywords"
  ],
  "recommended_action": "Do not click unverified links. Access the service directly through official verified channels.",
  "indicators": [
    {
      "type": "Phishing URL",
      "value": "http://192.168.1.50/login.php?update=bank",
      "severity": "CRITICAL",
      "confidence": 0.95,
      "context": "Verify immediately at http://192.168.1.50/login.php?update=bank",
      "metadata": {
        "domain": "192.168.1.50",
        "is_ip_host": true,
        "status": "unverified",
        "is_verified": false
      }
    }
  ],
  "model_version": "text-v1",
  "analysis_mode": "rules+ml"
}
```

---

## Retraining & Model Management

### Retrain the URL Classifier
```bash
python backend/scripts/train_url_classifier.py
```
Outputs model artifact to `backend/models/url_classifier_v1.joblib` and evaluation metrics to `backend/models/url_training_report.json`.

### Retrain the Text Classifier
```bash
python backend/scripts/prepare_and_train.py
```
Outputs model artifact to `backend/models/scam_classifier_v1.joblib` and metrics to `backend/models/training_report.json`.

---

## Running Automated Tests

All 99 automated tests execute locally without requiring internet access or opening untrusted links:

```bash
cd backend
pytest -v
```

Tests verify:
1. `GET /health` model reporting.
2. Suspicious synthetic message handling.
3. Benign message control handling.
4. URL extraction and lexical analysis invocation.
5. URL-only inputs.
6. Malformed input validation (HTTP 422).
7. Risk score bounding within 0–100.
8. Exact boundary threshold checks (29, 30, 59, 60, 79, 80).
9. Score 87 maps to `"critical"`.
10. Graceful fallback when models are missing/unloaded.
11. Indicator deduplication without repeated items.
12. Zero network requests or URL fetching.
13. Sensitive token and credential redaction from logs and storage.

---

## Starting Backend and Frontend

### Start FastAPI Backend
```bash
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Start React Dashboard
```bash
cd frontend
npm run dev
```
Frontend runs at `http://localhost:5173`. CORS is preconfigured for local dev ports `5173`, `3000`, and `8000`.

---

## Privacy & Security Protections

1. **Local Analysis Only**: No outbound HTTP requests or crawlers visit submitted URLs.
2. **Sensitive Token Redaction**: Private query tokens (`?token=...`, `?key=...`, `?auth=...`, `?otp=...`) and verification codes are scrubbed and replaced with `REDACTED`.
3. **Unverified Status**: Newly extracted indicators are marked `status: "unverified"` to prevent false accusations.
4. **No Raw Logging**: Full unbounded message texts and passwords are never written to server logs.
5. **Deterministic Fallbacks**: If any ML model is unavailable, the system transparently falls back to deterministic rule-based analysis without failing.
