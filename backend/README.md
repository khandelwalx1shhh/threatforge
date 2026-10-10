# THREATFORGE Backend API

AI-powered honeypot cybersecurity MVP API built with Python, FastAPI, Pydantic, and SQLite/SQLAlchemy.

## Quick Start

### 1. Requirements
- Python 3.10+

### 2. Setup Environment
```bash
cd backend
python -m venv venv
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1
# On Linux/macOS:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
python -m pip install -r requirements.txt
```

### 4. Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Key configuration settings:
- `DISTILBERT_MODEL_ID`: `cybersectony/phishing-email-detection-distilbert_v2.4.1`
- `INFERENCE_DEVICE`: `cpu` (or `cuda` if GPU available)
- `DISTILBERT_QUANTIZE`: `true` (enables 8-bit dynamic INT8 CPU quantization for ~3–4x speedup, latency ~20–55ms)

### 5. Run API Server
```bash
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 6. Interactive Documentation
- OpenAPI Docs (Swagger UI): [http://localhost:8000/docs](http://localhost:8000/docs)
- ReDoc: [http://localhost:8000/redoc](http://localhost:8000/redoc)

## Endpoints Summary

- `GET /health`: Health check endpoint (`{"status": "ok", "model_loaded": true, "distilbert_loaded": true}`)
- `POST /api/analyze`: Explainable scam risk scoring with DistilBERT Phishing Email Detection (`cybersectony/phishing-email-detection-distilbert_v2.4.1`), INT8 Dynamic Quantization, RFC 822 Email Header Security Audit (SPF/DKIM/DMARC/Spoofing), and deterministic rules
- `POST /api/chat`: Simulated honeypot persona engagement
- `POST /api/extract`: Structured IOC extraction and validation
- `GET /api/threats`: Threat log listing with filtering and search
- `GET /api/dashboard`: Threat intelligence dashboard metrics

## DistilBERT Phishing Detection & Header Security Integration

The backend loads Hugging Face's `cybersectony/phishing-email-detection-distilbert_v2.4.1` locally during startup in `torch.inference_mode()`. When running on CPU, it dynamically quantizes linear layers to INT8 (`torch.quantization.quantize_dynamic`), reducing inference latency down to ~20–55ms.

It also includes a dedicated **Email Header Security Analyzer** that audits:
- **SPF**: Checks `Received-SPF` and `Authentication-Results` for `fail`/`softfail`.
- **DKIM**: Verifies cryptographic signature status (`pass`/`fail`).
- **DMARC**: Checks domain alignment policy adherence (`pass`/`fail`).
- **Domain Alignment**: Validates `From` domain against `Return-Path` and `Reply-To`.
- **Display Name Spoofing**: Detects display names claiming legitimate institutions (PayPal, Microsoft, Google, banks, etc.) paired with mismatched untrusted domains.

### Example Analysis Request (with Email Headers)
```bash
curl -X POST "http://localhost:8000/api/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Your account will be suspended. Verify your details immediately at http://secure-verify.example",
    "raw_headers": "From: \"PayPal Security\" <alert@evilphish.org>\nReceived-SPF: fail\nAuthentication-Results: mx.google.com; dkim=fail; dmarc=fail\nReturn-Path: <scam@badrelay.ru>\n"
  }'
```

### Example Analysis Response
```json
{
  "risk_score": 100,
  "risk_level": "critical",
  "reasons": [
    "Display name impersonates known institution while sender domain differs",
    "Sender domain in From header does not align with Return-Path",
    "SPF email authentication check failed (fail)",
    "DMARC domain policy validation failed",
    "DKIM cryptographic signature verification failed",
    "Uses an urgent account threat",
    "Flagged by DistilBERT model (phishing_url, confidence: 100.0%)"
  ],
  "recommended_action": "Sender address and headers are spoofed. Do not open attachments or reply.",
  "indicators": [
    {
      "type": "Phishing URL",
      "value": "http://secure-verify.example",
      "severity": "HIGH",
      "confidence": 0.95
    }
  ],
  "model_name": "cybersectony/phishing-email-detection-distilbert_v2.4.1",
  "predicted_class_index": 1,
  "predicted_class_label": "LABEL_1",
  "candidate_class_label": "phishing_url",
  "is_quantized": true,
  "latency_ms": 23.95,
  "class_probabilities": {
    "LABEL_0": 0.000025,
    "LABEL_1": 0.999975,
    "LABEL_2": 0.00000001,
    "LABEL_3": 0.00000002
  },
  "verification_status": "unverified",
  "warning": "Model config.id2label exposes generic labels (LABEL_0..3). Author-suggested labels ('legitimate_email', 'phishing_url') are unverified. Do NOT classify an email as safe solely because this model predicts a non-phishing class.",
  "concise_explanation": "DistilBERT classified input with 100.0% confidence into class index 1 (LABEL_1, candidate: phishing_url) in 24.0ms. Status: unverified.",
  "header_analysis": {
    "has_headers": true,
    "from_header": "\"PayPal Security\" <alert@evilphish.org>",
    "from_domain": "evilphish.org",
    "display_name": "PayPal Security",
    "return_path": "scam@badrelay.ru",
    "return_path_domain": "badrelay.ru",
    "spf_status": "fail",
    "dkim_status": "fail",
    "dmarc_status": "fail",
    "domain_alignment": false,
    "display_name_spoofing": true,
    "anomalies": [
      "SPF authentication failed (fail) - sender IP unauthorized",
      "DKIM cryptographic signature verification failed",
      "DMARC policy validation failed - domain alignment failure",
      "Domain mismatch: 'From' header is @evilphish.org but 'Return-Path' is @badrelay.ru",
      "Display Name Spoofing: Display name claims 'PayPal Security' but sender domain is 'evilphish.org'"
    ],
    "risk_boost": 60,
    "summary": "Flagged 5 email header anomalies (SPF: fail, DKIM: fail, DMARC: fail)."
  }
}
```

## Testing
Run the complete automated test suite (79 tests across analyzer, DistilBERT, email headers, extractors, honeypot, and routers):
```bash
pytest
```
