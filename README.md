<div align="center">
  <img src="frontend/public/logo_transparent.png" width="130" alt="Argus Logo" />
  <h1>ARGUS</h1>
  <p><strong>Autonomous Cyber Threat Intelligence, On-Device Fraud Prevention & Adaptive Phishing Defense System</strong></p>

  [![Python](https://img.shields.io/badge/Python-3.12-blue.svg?logo=python&logoColor=white)](https://python.org)
  [![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
  [![PyTorch](https://img.shields.io/badge/PyTorch-2.14_INT8-EE4C2C.svg?logo=pytorch&logoColor=white)](https://pytorch.org)
  [![Android](https://img.shields.io/badge/Android-Kotlin_Compose-3DDC84.svg?logo=android&logoColor=white)](https://developer.android.com)
  [![React](https://img.shields.io/badge/React-19_TypeScript-61DAFB.svg?logo=react&logoColor=black)](https://react.dev)
  [![Tests](https://img.shields.io/badge/Tests-113%20Passed-brightgreen.svg?logo=pytest&logoColor=white)](https://pytest.org)
  [![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
</div>

---

> 📘 **Looking for the in-depth system specification?** Check out [PROJECT_DOCUMENTATION.md](PROJECT_DOCUMENTATION.md) for complete algorithmic breakdowns, dataset training reports, and privacy architecture.

---

## 🌟 Key Highlights

- 🛡️ **Native Android 24/7 On-Device Agent**: Real-time background notification inspection (`NotificationListenerService`) for **WhatsApp** and **Telegram** with zero battery drain.
- 🛑 **Sideloaded APK Package Inspector**: Detects deceptive dropper URLs distributing malicious Android packages (e.g. `wedding_card.apk`, `e-challan_update.apk`, banking trojans).
- 💸 **UPI Deep Link & QR Intent Auditor**: Neutralizes reverse-charge payment manipulation attacks (`upi://pay?pa=...&am=...`) pretending to be refunds or cashback.
- ⚡ **INT8 Quantized DistilBERT Transformer**: Sub-30ms on-device neural network CPU inference classifying urgency, social engineering, and phishing patterns.
- 🌐 **Offline Lexical URL Classifier (23 Features)**: Evaluates URL structure without outbound network requests or crawling (100% target-silent).
- 🧠 **Gemini GenAI Multi-Turn Reasoning**: Explains attack psychology, extracts Indicators of Compromise (IOCs), and formulates customized countermeasures.
- 🔒 **Zero-Leakage Privacy Gate**: Redacts OTPs, auth tokens, and credentials client-side; whitelist filters family and friends directly from local contacts.
- 🖥️ **Modern SOC Command Center**: Dark cyber glassmorphism operations dashboard with real-time telemetry, threat radar, and manual content investigation.

---

## 🏗️ System Architecture

```mermaid
flowchart TD
    subgraph MobileDevice["Android Client (Edge Defense Layer)"]
        A["Incoming Notification: WhatsApp / Telegram"] --> B[NotificationListenerService]
        B --> C{Package & Contact Whitelist}
        C -- "Ignored / Family Contact" --> D[Discard Event Immediately]
        C -- "Unknown Sender" --> E[Client-Side PII Scrubber]
        E --> F[Event Deduplicator (SHA-256 / 3m)]
        F --> G[On-Device Heuristic Engine]
        G --> H{Local Only Mode?}
        H -- "Yes" --> I[Local Alert & Storage]
        H -- "No (Consent Enabled)" --> J[Encrypted Transport to Backend]
    end

    subgraph BackendAPI["Cloud SOC Service (FastAPI / Machine Learning)"]
        J --> K["POST /api/analyze"]
        WebInput["Web Dashboard Scan"] --> K
        K --> L[APK Dropper & Trojan Inspector]
        K --> M[UPI Intent Fraud Auditor]
        K --> N[Lexical URL Classifier: url-v1]
        K --> O[Quantized DistilBERT Transformer: INT8]
        K --> P[Gemini GenAI Reasoning Agent]
        K --> Q[RFC 822 Email Header Inspector]
        
        L & M & N & O & P & Q --> R[Weighted Risk Scoring Engine (0-100)]
        R --> S[(Argus Threat Intelligence DB)]
        R --> T[Standardized Assessment Output]
    end

    subgraph DefenseOutput["Multi-Channel Response"]
        T --> U["Android System Heads-Up Alert (HIGH / CRITICAL)"]
        T --> V["Encrypted Local Persistent Storage"]
        T --> W["SOC Telemetry Web Dashboard"]
    end
```

---

## 📁 Repository Structure

```
threatforge/
├── android/                        # Native Android Application (Kotlin + Jetpack Compose)
│   ├── app/src/main/
│   │   ├── java/com/threatforge/android/
│   │   │   ├── analyzer/           # LocalRiskAnalyzer.kt (On-device heuristics)
│   │   │   ├── filter/             # PackageFilter.kt & ContactFilter.kt
│   │   │   ├── privacy/            # PrivacyScrubber.kt (PII / OTP redaction)
│   │   │   ├── service/            # NotificationListenerService & AlertNotificationHelper
│   │   │   ├── storage/            # ThreatStorageManager.kt (Local cache & retention)
│   │   │   └── MainActivity.kt     # Jetpack Compose UI & Setup Wizard
│   │   └── res/                    # Custom Argus icons, drawables, and themes
│   └── build.gradle.kts            # Android build configuration
├── backend/                        # High-Performance FastAPI SOC Backend
│   ├── app/
│   │   ├── routers/                # REST endpoints (/api/analyze, /api/threats, /health)
│   │   ├── schemas/                # Pydantic v2 schemas
│   │   └── services/               # ML, Transformer, Gemini, URL, APK, and UPI engines
│   ├── data/                       # Normalized benign/malicious datasets
│   ├── models/                     # Trained Scikit-Learn models and evaluation reports
│   └── tests/                      # Pytest suite (113 automated unit & integration tests)
├── frontend/                       # React 19 + TypeScript + Vite SOC Dashboard
│   ├── public/                     # Argus transparent logos and favicons
│   ├── src/                        # Dashboard components, threat radar, and live telemetry
│   └── index.html                  # Branded single-page application entrypoint
├── PROJECT_DOCUMENTATION.md        # Comprehensive system engineering specification
└── README.md                       # Master overview & developer guide
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- **Python**: 3.12+
- **Node.js**: 18+ and `npm`
- **Java**: JDK 17 (Microsoft OpenJDK 17 recommended)
- **Android Platform Tools**: `adb` installed in PATH

---

### 2. Start the Backend API
```bash
cd threatforge/backend

# Create and activate virtual environment
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# (Optional) Set Google Gemini API Key in .env:
# GEMINI_API_KEY=your_key_here

# Launch FastAPI server
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```
- API Docs: `http://localhost:8000/docs`
- Health Check: `http://localhost:8000/health`

---

### 3. Start the React SOC Dashboard
```bash
cd threatforge/frontend

# Install dependencies
npm install

# Launch Vite dev server
npm run dev
```
- Dashboard URL: `http://localhost:5173`

---

### 4. Build & Install Android Mobile Agent
```bash
cd threatforge/android

# Build Debug APK
.\gradlew.bat assembleDebug

# Connect Android phone via USB (with USB Debugging enabled) and install:
adb install -r app/build/outputs/apk/debug/app-debug.apk

# Forward device network calls to your local backend server:
adb reverse tcp:8000 tcp:8000
```

---

## 📡 API Reference

### Analyze Content: `POST /api/analyze`

#### Request Payload:
```json
{
  "text": "download wedding_card.apk from https://files-host.me/wedding_card.apk",
  "source": "whatsapp",
  "sender": "+91 80580 87045",
  "cloud_analysis": true
}
```

#### Response:
```json
{
  "risk_score": 100,
  "risk_level": "critical",
  "reasons": [
    "Unfamiliar domain structure requires standard user verification",
    "Message distributes an Android application package (.apk): 'wedding_card.apk'."
  ],
  "recommended_action": "DO NOT install or download this APK file. Sideloaded packages from instant messages frequently contain Trojans, keyloggers, or banking fraud droppers.",
  "indicators": [
    {
      "type": "Malicious Payload",
      "value": "wedding_card.apk",
      "severity": "CRITICAL",
      "confidence": 1.0,
      "context": "Message distributes an Android application package (.apk): 'wedding_card.apk'."
    }
  ],
  "model_version": "distilbert-quantized+rules",
  "analysis_mode": "rules+ml"
}
```

---

## 🧪 Automated Testing & Verification

Argus includes a comprehensive test suite of **113 passing tests** covering ML models, API contracts, PII scrubbing, UPI deep links, APK inspectors, and email RFC 822 parsers:

```bash
cd threatforge/backend
pytest -v
```
```
======================= 113 passed, 1 warning in 23.77s =======================
```

---

## 🛡️ Security, Privacy & Trust Guarantees

1. **Zero Outbound URL Crawling**: URL classification is performed 100% offline using 23 lexical structural features. The system never connects to or visits malicious links.
2. **Pre-Transmission Redaction**: Private OTPs, session tokens, and credit cards are scrubbed client-side before any network transmission.
3. **Strict Whitelisting**: The Android listener strictly monitors only WhatsApp and Telegram. Banking notifications, SMS, system alerts, and personal emails are discarded immediately.
4. **Local-Only Agency**: Users can enable **Local-Only Shield** at any time to run purely on on-device heuristics with zero external cloud connectivity.
5. **Configurable Data Retention**: Users can configure retention (Memory Only, 24 Hours, 7 Days, 30 Days) and purge cached alerts with a single tap.

---

## 👥 Contributors & Acknowledgements

Developed for hackathons and production cybersecurity prototypes. Built with FastAPI, PyTorch, Hugging Face, Android Jetpack Compose, and React.

<div align="center">
  <small>© 2026 Argus Cybersecurity. All rights reserved.</small>
</div>
