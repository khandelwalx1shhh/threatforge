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

> 📘 **Detailed Technical Specification**: For complete algorithmic mathematics, feature weights, dataset training reports, and privacy contracts, refer to [PROJECT_DOCUMENTATION.md](PROJECT_DOCUMENTATION.md).

---

## 💡 What is Argus?

**Argus** is an autonomous cybersecurity platform engineered to protect users from social engineering, instant messaging fraud, malicious Android APK droppers, and deceptive payment schemes in real time. 

Named after the all-seeing guardian of myth, Argus acts as an intelligent sentinel combining:
1. **An On-Device Android Agent** that continuously screens incoming messages on WhatsApp and Telegram in the background, issuing instant warning banners before users click malicious links or install malicious files.
2. **A High-Performance AI & ML Cloud SOC Backend** executing quantized transformer inference, offline lexical URL classification, and Google Gemini GenAI multi-turn reasoning.
3. **A Centralized SOC Web Command Dashboard** allowing security analysts to monitor live threat telemetry, review intercepted indicators, and manually dissect suspicious payloads.

---

## 🎯 The Problem Argus Solves

Traditional cybersecurity tools (such as desktop antivirus and browser security extensions) are ineffective against modern mobile cyber attacks:
- **Sideloaded Trojan Droppers**: Attackers disguise malicious `.apk` packages as wedding invitations (`wedding_card.apk`), courier shipment trackers, or traffic e-challan notices sent via WhatsApp. Once installed, these trojans steal OTPs and hijack bank accounts.
- **Reverse-Charge UPI Intent Fraud**: Scammers send deep links (`upi://pay?pa=...&am=5000`) claiming the user is "receiving a cash prize or cashback refund". In reality, approving the prompt immediately debits money from the victim's account.
- **Urgency-Driven Social Engineering**: Phishing messages manipulate fear and artificial deadlines ("Account suspended within 24 hours", "Verify KYC immediately") using typosquatted domains (`bank-secure.xyz`).
- **Privacy Intrusion by Security Tools**: Users hesitate to install security software that logs full personal chat histories, reads contact books, or inspects banking SMS notifications.

**Argus solves all four challenges** with on-device package whitelisting, client-side PII scrubbing, zero outbound web crawling, and sub-30ms multi-model detection.

---

## 🌟 Core Capabilities

- 🛡️ **24/7 Sticky Android Edge Shield**: Runs in the background via `NotificationListenerService` with automatic recovery and near-zero battery consumption.
- 🛑 **Sideloaded APK Package Inspector**: Detects deceptive `.apk` download links and dropper nomenclature across messaging platforms.
- 💸 **UPI Deep Link & QR Code Intent Auditor**: Parses `upi://pay` query parameters and flags reverse-charge payment intents before the victim approves them.
- ⚡ **INT8 Quantized DistilBERT Transformer**: Lightweight on-device neural network CPU inference classifying urgency, social engineering, and phishing patterns in ~28ms.
- 🌐 **Offline Lexical URL Classifier (23 Features)**: Inspects structural URL properties (entropy, digit ratio, brand typosquatting, high-risk TLDs) without making outbound HTTP requests.
- 🧠 **Google Gemini GenAI Cognitive Engine**: Explains novel attack strategies, extracts Indicators of Compromise (IOCs), and provides immediate user remediation steps.
- 🔒 **Zero-Leakage Privacy Gate**: Redacts OTPs, auth tokens, and cards client-side; whitelist filters family and friends directly from saved contacts.
- 💾 **Persistent On-Device Storage & Retention**: Local storage of threat logs with user-configurable retention policies (`Memory Only`, `24 Hours`, `7 Days`, `30 Days`) and one-tap history wiping.

---

## 🏗️ System Architecture

```mermaid
flowchart TD
    subgraph MobileDevice["Android Client (Edge Defense Layer)"]
        A["Incoming Notification: WhatsApp / Telegram"] --> B[NotificationListenerService]
        B --> C{Package & Contact Whitelist}
        C -- "Ignored App / Family Contact" --> D[Discard Event Immediately]
        C -- "Unknown Sender" --> E[Client-Side PII Scrubber]
        E --> F[Event Deduplicator (SHA-256 / 3m)]
        F --> G[On-Device Heuristic Engine]
        G --> H{Local Only Mode?}
        H -- "Yes" --> I[Local Alert & Encrypted Storage]
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
- Interactive OpenAPI Docs: `http://localhost:8000/docs`
- Health Endpoint: `http://localhost:8000/health`

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

### 4. Build & Install the Android Mobile Agent
```bash
cd threatforge/android

# Build Debug APK
.\gradlew.bat assembleDebug

# Connect phone via USB with USB Debugging enabled, then install:
adb install -r app/build/outputs/apk/debug/app-debug.apk

# Forward device network calls to your local backend server:
adb reverse tcp:8000 tcp:8000
```

---

## 🧪 Real-World Attack Scenarios & How to Test

You can test Argus using either the **Android app's Manual Audit tab**, the **Web Dashboard**, or `curl`:

### Scenario 1: Malicious APK Dropper (`wedding_card.apk`)
- **Input Text**: `"Please download wedding_card.apk from https://files-host.me/wedding_card.apk to view the invitation"`
- **Argus Detection**: **CRITICAL RISK (100/100)**
- **Response**: Emits an alert warning the user that sideloaded APK files from messages frequently deliver banking trojans and keyloggers.

### Scenario 2: Deceptive Reverse-Charge UPI Intent
- **Input Text**: `"Congratulations! You won cashback. Receive Rs 2500 now: upi://pay?pa=scammer@upi&pn=RewardsDesk&am=2500&cu=INR"`
- **Argus Detection**: **CRITICAL RISK (90/100)**
- **Response**: Explains that UPI deep links with positive amounts debit money from the user instead of crediting funds.

### Scenario 3: Bank Impersonation with Typosquatted Domain
- **Input Text**: `"URGENT: Your bank account will be locked within 2 hours. Verify your PAN and KYC now at http://hdfc-kyc-verify.xyz/login"`
- **Argus Detection**: **CRITICAL RISK (92/100)**
- **Response**: Flags artificial urgency, suspicious `.xyz` TLD, brand spoofing, and credential harvesting triggers.

### Scenario 4: Clean Benign Peer Message
- **Input Text**: `"Hey, are we still meeting for lunch at 1 PM today?"`
- **Argus Detection**: **LOW RISK (0/100)**
- **Response**: Evaluated as benign. No alert is triggered.

---

## 📡 API Reference

### Analyze Content: `POST /api/analyze`

#### Request:
```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "text": "download wedding_card.apk from https://files-host.me/wedding_card.apk",
    "source": "whatsapp",
    "sender": "+91 80580 87045",
    "cloud_analysis": true
  }'
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

## 🔬 Automated Testing Suite

Argus includes **113 automated unit and integration tests** verifying ML models, URL features, APK inspectors, UPI parsers, PII scrubbing, and API endpoints:

```bash
cd threatforge/backend
pytest -v
```
```
======================= 113 passed, 1 warning in 23.77s =======================
```

---

## 🔒 Security, Privacy & Trust Guarantees

1. **Zero Outbound URL Crawling**: URL analysis is performed 100% offline using 23 structural lexical features. Argus never pings or visits malicious links, avoiding target confirmation.
2. **Pre-Transmission Redaction**: Private OTPs, verification codes, session tokens, and credit cards are scrubbed client-side before any network transmission.
3. **Strict Whitelisting**: The Android listener strictly monitors WhatsApp and Telegram. Personal SMS, banking notifications, system alerts, and emails are discarded immediately.
4. **Local-Only Agency**: Users can enable **Local-Only Shield** at any time to run entirely on on-device heuristics with zero external cloud connectivity.
5. **Configurable Data Retention**: Users can configure local storage retention (`Memory Only`, `24 Hours`, `7 Days`, `30 Days`) and wipe cached threat history with a single tap.

---

<div align="center">
  <small>© 2026 Argus Cybersecurity. Autonomous Cyber Threat Intelligence & Phishing Defense Platform.</small>
</div>
