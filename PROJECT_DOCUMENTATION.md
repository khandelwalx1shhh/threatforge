<div align="center">
  <img src="frontend/public/logo_transparent.png" width="130" alt="Argus Emblem" />
  <h1>ARGUS SYSTEM SPECIFICATION</h1>
  <h3>Autonomous Cyber Threat Intelligence, On-Device Fraud Prevention & Adaptive Phishing Defense Platform</h3>
  <p><em>Production Engineering Specification & Hackathon Technical Dossier</em></p>
</div>

---

## Table of Contents
1. [Executive Summary](#1-executive-summary)
2. [End-to-End System Architecture](#2-end-to-end-system-architecture)
3. [Multi-Tier Component Matrix](#3-multi-tier-component-matrix)
4. [Detection & Analysis Engines](#4-detection--analysis-engines)
   - [4.1 Sideloaded APK Dropper & Trojan Inspector](#41-sideloaded-apk-dropper--trojan-inspector)
   - [4.2 UPI Deep Link & QR Code Intent Auditor](#42-upi-deep-link--qr-code-intent-auditor)
   - [4.3 Offline Lexical URL Classifier (url-v1)](#43-offline-lexical-url-classifier-url-v1)
   - [4.4 Quantized DistilBERT Transformer Engine](#44-quantized-distilbert-transformer-engine)
   - [4.5 Gemini GenAI Cognitive Reasoning Engine](#45-gemini-genai-cognitive-reasoning-engine)
   - [4.6 RFC 822 Email Header Analyzer](#46-rfc-822-email-header-analyzer)
   - [4.7 Conservative IOC Extractor](#47-conservative-ioc-extractor)
5. [Android Native Mobile Agent Architecture](#5-android-native-mobile-agent-architecture)
   - [5.1 24/7 Sticky Lifecycle & NotificationListenerService](#51-247-sticky-lifecycle--notificationlistenerservice)
   - [5.2 Zero-Leakage Privacy Gate & Contact Whitelisting](#52-zero-leakage-privacy-gate--contact-whitelisting)
   - [5.3 Threat Storage & Retention Policy Manager](#53-threat-storage--retention-policy-manager)
   - [5.4 Real-Time Warning Alert System](#54-real-time-warning-alert-system)
   - [5.5 First-Time Setup Wizard & Permission Lifecycle](#55-first-time-setup-wizard--permission-lifecycle)
6. [FastAPI Cloud SOC Architecture & Endpoints](#6-fastapi-cloud-soc-architecture--endpoints)
7. [React SOC Web Dashboard](#7-react-soc-web-dashboard)
8. [Evaluation Metrics & Dataset Benchmarks](#8-evaluation-metrics--dataset-benchmarks)
9. [Installation & Deployment Guide](#9-installation--deployment-guide)
10. [Security, Privacy & Trust Guarantees](#10-security-privacy--trust-guarantees)

---

## 1. Executive Summary

**Argus** is an autonomous, multi-tier cyber threat intelligence and fraud defense ecosystem designed to protect mobile and web users from modern social engineering, phishing, financial manipulation, and malware distribution attacks.

Traditional security measures (such as DNS sinkholes or periodic AV scans) fail to defend against **zero-day social engineering vectors** delivered through instant messaging apps (WhatsApp, Telegram). Attacks such as malicious `.apk` droppers (e.g., `wedding_card.apk`), deceptive reverse-charge UPI payment links (`upi://pay`), credential harvesters, and urgency-driven bank impersonations execute before legacy engines detect them.

Argus solves this through a **hybrid on-device and cloud defense pipeline**:
1. **Edge Client (Android)**: A native Android agent that runs non-intrusively in the background via `NotificationListenerService`. It features client-side PII scrubbing, family contact whitelisting, on-device local heuristics, and instant Heads-Up threat alerts.
2. **AI & Inference Engine (FastAPI)**: An orchestration backend powered by:
   - **INT8-quantized DistilBERT Transformer** for 20ms semantic phishing scoring.
   - **Lexical URL Classifier** with 23 safe offline features (zero network crawling).
   - **Gemini GenAI Multimodal Engine** providing deep reasoning and actionable countermeasures.
   - **UPI Deep Link Auditor** and **APK Package Inspector**.
3. **SOC Web Dashboard (React + TypeScript)**: A centralized cybersecurity operations center featuring real-time telemetry, threat radar, payload analysis, and automated honeypot counter-engagement.

---

## 2. End-to-End System Architecture

```mermaid
flowchart TD
    subgraph MobileDevice["Android Client (Edge Defense Layer)"]
        A["Incoming Notification (WhatsApp / Telegram)"] --> B[NotificationListenerService]
        B --> C{Package Filter}
        C -- "Ignored App (Banking/SMS/Personal)" --> D[Discard Event Immediately]
        C -- "Whitelisted App" --> E[Contact Whitelist Filter]
        E -- "Known Contact" --> D
        E -- "Unknown Sender" --> F[Client-Side PII Scrubber]
        F --> G[Event Deduplicator (SHA-256 / 3min window)]
        G -- "Duplicate" --> H[Increment Dedup Counter]
        G -- "New Event" --> I[On-Device Heuristic Engine]
        I --> J{Cloud Analysis Consent?}
        J -- "Local-Only Mode" --> K[Local Storage & Alert Trigger]
        J -- "Consent Enabled" --> L[Encrypted Retrofit/OkHttp Transport]
    end

    subgraph CloudSOC["Cloud Backend (FastAPI / Machine Learning Layer)"]
        L --> M["POST /api/analyze"]
        WebInput["Manual Web Scan"] --> M
        M --> N[Payload & URL Sanitizer]
        N --> O[APK Dropper & Trojan Inspector]
        N --> P[UPI Deep Link & Intent Auditor]
        N --> Q[Offline Lexical URL Classifier (23 Features)]
        N --> R[Quantized DistilBERT Transformer (INT8)]
        N --> S[Gemini GenAI Reasoning Agent]
        N --> T[RFC 822 Email Header Inspector]
        N --> U[Conservative Threat Extractor (IOCs)]
        
        O & P & Q & R & S & T & U --> V[Weighted Risk Aggregator & Scorer]
        V --> W[(Argus Threat Database / SQLite)]
        V --> X[Standardized Threat Response Contract]
    end

    subgraph Output["Defense & Telemetry Presentation"]
        X --> Y["Android Heads-Up Alert Notification (HIGH / CRITICAL)"]
        X --> Z["On-Device Persistent Storage & Jetpack Compose Feed"]
        X --> SOC["SOC Operations Console (React + Vite + TypeScript)"]
    end
```

---

## 3. Multi-Tier Component Matrix

| Component | Technology Stack | Role | Privacy & Performance Profile |
| :--- | :--- | :--- | :--- |
| **Android Agent** | Kotlin, Jetpack Compose, Material3, Coroutines | Real-time on-device notification interceptor, local heuristic evaluator, user consent gate | Runs with sticky foreground priority; 0% background battery drain; strict whitelist. |
| **FastAPI Backend** | Python 3.12, FastAPI, Pydantic v2, Uvicorn | High-throughput async REST API, ML pipeline orchestration, SQLite threat store | Sub-50ms CPU latency without GPU dependencies. |
| **DistilBERT Transformer** | PyTorch, Hugging Face Transformers, `torch.quantization` | Deep contextual linguistic analysis and urgency scoring | Dynamic INT8 CPU quantization reducing memory by ~60% and latency by ~4x. |
| **Lexical URL Engine** | Scikit-Learn, NumPy, `url-v1` | Classifies phishing URLs using 23 structural string metrics | 100% offline lexical analysis; zero network requests or URL crawling. |
| **Gemini AI Detector** | Google Generative AI SDK, Gemini 1.5/2.0 Flash | Advanced cognitive social engineering reasoning and IOC explanation | Graceful fallback to deterministic heuristics if offline or quota exceeded. |
| **SOC Dashboard** | React 19, TypeScript, Vite, Vanilla CSS Design System | Live security operations console, telemetry feed, manual auditing workspace | Dark cyber glassmorphism design with responsive micro-animations. |

---

## 4. Detection & Analysis Engines

### 4.1 Sideloaded APK Dropper & Trojan Inspector
- **Attack Vector**: Attackers bypass the Google Play Store by sending deceptive direct-download links on messaging apps (e.g., `wedding_card.apk`, `e-challan_update.apk`, `bank_rewards.apk`).
- **Detection Mechanism**:
  - Scans URLs and payload text using regex heuristics: `(?:\.apk\b|application\/vnd\.android\.package-archive)`.
  - Flags high-risk dropper nomenclature: `wedding`, `invitation`, `shadi`, `update`, `challan`, `kyc`, `support`.
  - Assigns **CRITICAL RISK (100/100)** with mandatory warnings instructing users never to install the sideloaded file.

### 4.2 UPI Deep Link & QR Code Intent Auditor
- **Attack Vector**: Reverse-charge fraud where victims expecting payment/cashback are deceived into approving a debit intent (`upi://pay?pa=...&am=...`).
- **Detection Mechanism**:
  - Parses deep links for URI schemes: `upi://pay` or `upi://`.
  - Extracts key query parameters: Payee VPA (`pa`), Payee Name (`pn`), Requested Amount (`am`), Note (`tn`).
  - Verifies if language contains deceptive triggers ("Receive money", "Refund", "Prize claim", "Cashback").
  - Emits urgent warnings clarifying that **UPI deep links with positive amounts always debit funds rather than credit them**.

### 4.3 Offline Lexical URL Classifier (`url-v1`)
- **Engine**: Trained `StandardScaler` + `LogisticRegression` evaluating 23 safe lexical features.
- **Privacy Guarantee**: **Zero outbound network crawling.** URLs are never resolved or pinged.
- **Feature Set**:
  1. `length`, `hostname_length`, `path_length`
  2. `num_dots`, `num_hyphens`, `num_slashes`, `num_questionmarks`, `num_equal`
  3. `has_ip_host` (e.g., `192.168.1.1` in hostname)
  4. `has_punycode` (`xn--` homograph spoofing)
  5. `shannon_entropy` and `hostname_entropy`
  6. `digit_ratio`, `special_char_ratio`
  7. `has_sensitive_keyword` (`login`, `verify`, `banking`, `secure`, `update`)
  8. `has_spoofed_brand` (Typosquatted brands like `amaz0n`, `paypa1`, `netflx`)
  9. `is_high_risk_tld` (`.xyz`, `.top`, `.tk`, `.club`, `.work`, `.click`)

### 4.4 Quantized DistilBERT Transformer Engine
- **Model**: `cybersectony/phishing-email-detection-distilbert_v2.4.1`
- **Quantization**: Dynamic INT8 quantization (`torch.quantization.quantize_dynamic`) applied to `nn.Linear` layers.
- **Performance**:
  - Precision: `FP32` model compressed to `INT8` weights.
  - Evaluation Latency: 20ms to 45ms per payload on standard modern x86/ARM CPU.
  - Social engineering score aggregated into composite risk rating.

### 4.5 Gemini GenAI Cognitive Reasoning Engine
- **Role**: Dissects multi-stage, novel social engineering attacks that evade traditional signature engines.
- **Capabilities**:
  - Analyzes psychological coercion (authority impersonation, fake legal deadlines, emotional blackmail).
  - Produces human-readable explanations and actionable defensive steps.
  - Graceful fallback: If API key is omitted or network is unreachable, fallback heuristics ensure uninterrupted protection.

### 4.6 RFC 822 Email Header Analyzer
- Evaluates raw email transport headers for sender authenticity:
  - **SPF**: Checks `Received-SPF` for `Pass`, `Fail`, or `SoftFail`.
  - **DKIM**: Inspects cryptographic signature validation tags.
  - **DMARC**: Checks domain policy compliance.
  - **Display Name Spoofing**: Flags deceptive mismatch between sender display name (`Support <attacker@evil.com>`) and actual envelope address.

### 4.7 Conservative IOC Extractor
- High-precision regex extractor with IP/URL defanging (`hxxp[://]`).
- Extracts URLs, IPv4 addresses, email addresses, cryptocurrency wallets, and phone numbers.
- De-duplicates indicators to present clean threat intelligence telemetry.

---

## 5. Android Native Mobile Agent Architecture

The native Android agent (`threatforge/android`) acts as the user's primary on-device shield.

### 5.1 24/7 Sticky Lifecycle & NotificationListenerService
- Inherits from Android's `NotificationListenerService`.
- Uses `START_STICKY` lifecycle policy ensuring the service automatically restarts if killed under low-memory conditions.
- Listens to incoming system notifications in real time without polling.

### 5.2 Zero-Leakage Privacy Gate & Contact Whitelisting
1. **Package Whitelist Filter (`PackageFilter.kt`)**:
   - Strictly listens **only** to whitelisted apps: WhatsApp (`com.whatsapp`, `com.whatsapp.w4b`) and Telegram (`org.telegram.messenger`).
   - Discards 100% of banking, SMS, personal email, and system notifications without inspecting text.
2. **Contact Whitelist (`ContactFilter.kt`)**:
   - Queries `ContactsContract.CommonDataKinds.Phone` using caller ID.
   - If the sender is present in the user's address book, the notification is immediately ignored as trusted peer communication.
3. **Pre-Transmission PII Scrubber (`PrivacyScrubber.kt`)**:
   - Redacts OTPs (`\b\d{4,8}\b`), auth tokens, credit cards, and full phone numbers on-device before any network transmission.

### 5.3 Threat Storage & Retention Policy Manager
- Managed via `ThreatStorageManager.kt`.
- Persists recorded alerts, dedup hashes, and settings to local encrypted storage.
- **Configurable Retention Policies**:
  - `Memory Only` (0 days - wiped on exit)
  - `24 Hours`
  - `7 Days`
  - `30 Days`
- One-tap history deletion button permanently purges all local cached data.

### 5.4 Real-Time Warning Alert System
- Implemented in `AlertNotificationHelper.kt`.
- Emits high-priority Heads-Up system notifications when a **HIGH** or **CRITICAL** threat is detected:
  - Alert title: `🚨 Argus Alert: [CRITICAL/HIGH] Message`
  - Body: Specific threat signals (e.g., "Deceptive APK detected: wedding_card.apk").
  - Channel: `Argus Security Warnings` (IMPORTANCE_HIGH).

### 5.5 First-Time Setup Wizard & Permission Lifecycle
- On initial launch, displays an interactive modal (`FirstTimeSetupDialog`):
  1. **Notification Access Permission**: Prompts for system notification access with direct settings redirect and status verification.
  2. **Alerts & Privacy Filtering**: Prompts for runtime system permissions (`POST_NOTIFICATIONS` and `READ_CONTACTS`). Features an **App Settings** fallback button.
  3. **Threat Alert Consent**: Explicit opt-in toggle for active defense notifications.
- **Lifecycle Synchronization**: MainActivity observes `onResume` triggers to refresh permission status instantly when returning from Android Settings.

---

## 6. FastAPI Cloud SOC Architecture & Endpoints

### Core API Endpoints

#### 1. Content Analysis
```http
POST /api/analyze
Content-Type: application/json

{
  "text": "URGENT: Your account is suspended. Verify immediately at http://bank-secure-login.xyz/auth?user=102",
  "source": "com.whatsapp",
  "sender": "+91 98765 43210",
  "cloud_analysis": true
}
```
**Response (200 OK)**:
```json
{
  "risk_score": 92.5,
  "risk_level": "CRITICAL",
  "confidence": 0.95,
  "is_threat": true,
  "indicators": [
    "High-risk top-level domain (.xyz)",
    "Urgency manipulation and credential harvesting keywords",
    "DistilBERT model classified payload as Phishing (96.4% confidence)"
  ],
  "extracted_iocs": {
    "urls": ["http://bank-secure-login.xyz/auth?user=102"],
    "emails": [],
    "ips": [],
    "phones": ["+91 98765 43210"]
  },
  "explanation": "The message impersonates a banking authority using artificial urgency and directs the recipient to an unverified .xyz domain.",
  "recommended_action": "Do not click the link or provide any login credentials. Block and report the sender."
}
```

#### 2. System Health & Readiness
```http
GET /api/health
```
**Response (200 OK)**:
```json
{
  "status": "ok",
  "app_name": "ARGUS API",
  "version": "1.0.0",
  "ml_models": {
    "text_classifier": true,
    "url_classifier": true,
    "transformer_quantized": true,
    "gemini_detector": true
  }
}
```

#### 3. Threat History & Intelligence
- `GET /api/threats`: Returns chronological threat events and security alerts.
- `GET /api/threats/metrics`: Returns aggregated metrics (total scans, critical detections, deduped events).
- `POST /api/threats/clear`: Purges server-side threat logs and metrics.

---

## 7. React SOC Web Dashboard

The web dashboard (`threatforge/frontend`) provides security personnel with a real-time command console:

- **Sidebar Navigation**:
  - Branded header featuring the custom Argus neon emblem.
  - Dynamic status badge showing `Systems operational ● ARGUS SOC`.
  - Navigation between `Overview` (SOC Metrics & Telemetry) and `Analyze Content` (Manual Investigator).
- **Security Operations Center Overview**:
  - Live metric counters: Total Threats Detected, High-Risk Interceptions, Real-Time Interception Rate, Clean Payloads.
  - Interactive Threat Feed with risk badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
  - Extracted IOC inspector displaying defanged URLs and entities.
- **Manual Content Investigator**:
  - Real-time text, URL, and raw email header scanner.
  - Interactive payload analysis with breakdown of detected heuristic rules, transformer scores, and recommended response playbooks.

---

## 8. Evaluation Metrics & Dataset Benchmarks

### 8.1 Lexical URL Classifier (`url-v1`)
- **Dataset**: `backend/data/urls_normalized.csv` (balanced sample of 60,000 real-world malicious and benign URLs).
- **Split**: 80% Train (48,000 URLs), 20% Test (12,000 URLs).
- **Results**:
  - **Accuracy**: `75.08%`
  - **Precision**: `79.82%`
  - **Recall**: `67.12%`
  - **F1-Score**: `0.7292`
  - **Confusion Matrix**: True Negative: 4,982 | False Positive: 1,018 | False Negative: 1,973 | True Positive: 4,027

### 8.2 Transformer Quantization Benchmark
- Dynamic INT8 quantization applied to `cybersectony/phishing-email-detection-distilbert_v2.4.1`.
- Model footprint reduced from ~268 MB to ~110 MB.
- CPU inference latency reduced from ~115ms to ~28ms per inference.

---

## 9. Installation & Deployment Guide

### Prerequisites
- Python 3.12+
- Node.js 18+ & npm
- JDK 17 (Microsoft OpenJDK 17 recommended)
- Android SDK Build Tools (API 34/35) & ADB (platform-tools)

### 1. Backend Setup
```bash
cd threatforge/backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# Start backend on 0.0.0.0:8000
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 2. Frontend Web Dashboard
```bash
cd threatforge/frontend
npm install
npm run dev
# Dashboard accessible at http://localhost:5173
```

### 3. Android Mobile Agent
```bash
cd threatforge/android
# Build debug APK
.\gradlew.bat assembleDebug

# Connect device via USB debugging and install
adb install -r app/build/outputs/apk/debug/app-debug.apk

# Forward local backend port to mobile device
adb reverse tcp:8000 tcp:8000
```

---

## 10. Security, Privacy & Trust Guarantees

1. **Zero Outbound URL Crawling**: URL classification relies entirely on offline structural lexical properties. The engine never resolves or makes HTTP requests to malicious domains, preventing confirmation of target active presence.
2. **Pre-Transmission Redaction**: All sensitive OTPs, security tokens, account codes, and credentials are scrubbed on-device prior to network transmission.
3. **Strict Package Filtering**: Whitelists only WhatsApp and Telegram. All other apps (SMS, Banking, Camera, Gmail) are completely excluded from capture.
4. **Local-Only Agency**: Users can enable "Local-Only Shield" on their mobile device to evaluate threats using on-device heuristics with zero external network connectivity.
5. **Configurable Retention**: All threat history can be scheduled for automatic eviction or permanently wiped at any time.

---

<div align="center">
  <small>© 2026 Argus Cybersecurity. Autonomous Cyber Threat Intelligence & Phishing Defense Platform.</small>
</div>
