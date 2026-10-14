# 🛎️ Ring-DeskPass: Zero-Trust Physical Security & Compliance Kiosk

[![Python Version](https://img.shields.io/badge/Python-3.10+-blue.svg?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![LangGraph](https://img.shields.io/badge/LangGraph-Agentic_Orchestration-orange.svg)]()
[![AWS](https://img.shields.io/badge/AWS-CloudWatch-232F3E.svg?logo=amazon-aws&logoColor=white)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

> **An enterprise-grade, privacy-first access control system designed as a cloud-native integration for the Ring Appstore.**

Ring-DeskPass transforms existing Ring doorbell hardware into a B2B zero-trust physical security kiosk. By combining multimodal document intelligence, PII redaction, and autonomous LangGraph AI orchestration, it fully automates visitor verification and front-desk compliance without the need for expensive, proprietary badge scanners.

---

## ✨ Key Features

*   **🛡️ Edge-Level Privacy Firewall:** Automated PII redaction (`ComplianceSanitizer`) strips sensitive data (e.g., government ID serials, phone numbers) from OCR output before it is logged or processed.
*   **🧠 Agentic Orchestration:** A LangGraph ReAct agent powered by Gemini 3.8 Flash autonomously evaluates verification context to execute physical security tools (e.g., unlocking doors, triggering live Slack DMs, or alerting reception).
*   **📜 Dual-Layer Immutable Audit Logs:** All sanitized access events are atomically recorded locally (SQLite) and shipped directly to **AWS CloudWatch** for enterprise compliance and non-repudiation.
*   **👁️ Resilient Vision Pipeline:** Custom YOLOv8 badge detection paired with OpenCV dynamic contrast preprocessing and EasyOCR guarantees high-accuracy reads even under webcam glare.
*   **📊 B2B Reception Dashboard:** A live-updating Streamlit portal providing historical analytics, daily visitor metrics, and realtime access logs.

---

## 🏗️ System Architecture

Because enterprise Ring devices operate within a gated cloud ecosystem, **Ring-DeskPass is engineered as a cloud-native webhook backend** (simulating the Ring Partner API).

1.  **Trigger:** A visitor presses the Ring doorbell. Amazon's cloud routes an HMAC-secured webhook to our FastAPI backend.
2.  **Vision Inference:** YOLO isolates the visitor's ID badge, crops it, and passes it to EasyOCR.
3.  **Verification & Sanitization:** The text is fuzzy-matched against authorized personnel. The raw text is instantly scrubbed of PII.
4.  **Audit Trail:** The sanitized record is shipped to AWS CloudWatch and the local SQLite database.
5.  **Agentic Routing:** The LangGraph Agent reasons about the context and autonomously fires a live Slack Webhook to the appropriate channel.
6.  **UI Update:** The Streamlit dashboard instantly reflects the new visitor state.

---

## 🛠️ Tech Stack

*   **Backend Routing:** FastAPI, Uvicorn, Python 3.11
*   **Computer Vision:** Ultralytics YOLOv8, OpenCV (Headless), EasyOCR
*   **AI Orchestration:** LangGraph, LangChain, Google Gemini API
*   **Compliance & Logging:** AWS CloudWatch (`boto3`), SQLite3
*   **Integrations:** Slack Webhooks, HMAC-SHA256 Auth
*   **Frontend UI:** Streamlit, Pandas

---

## 🚀 Setup & Installation

### 1. Clone the Repository
```bash
git clone [https://github.com/YOUR_USERNAME/Ring-DeskPass.git](https://github.com/YOUR_USERNAME/Ring-DeskPass.git)
cd Ring-DeskPass

```

### 2. Configure the Virtual Environment

```bash
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate

pip install -r requirements.txt

```

### 3. Environment Variables

Create a `.env` file in the root directory and add the following keys. *(See `.env.example` for reference).*

```env
RING_HMAC_SIGN_KEY="your_ring_webhook_secret"
AWS_REGION="us-east-1"
CLOUDWATCH_LOG_GROUP="RingSecureKioskLogs"
GEMINI_API_KEY="your_google_gemini_api_key"
SLACK_WEBHOOK_URL="[https://hooks.slack.com/services/YOUR/WEBHOOK/URL](https://hooks.slack.com/services/YOUR/WEBHOOK/URL)"

```

> **Note:** Ensure your AWS CLI is configured locally (`aws configure`) or your environment has valid AWS credentials exported to enable CloudWatch logging.

---

## 💻 Running the System

To run the full Ring-DeskPass suite locally, you will need to open three separate terminal windows.

**Terminal 1: Start the FastAPI Orchestration Server**

```bash
uvicorn main:app --reload

```

**Terminal 2: Launch the Reception Management Dashboard**

```bash
streamlit run dashboard.py

```

**Terminal 3: Trigger the Doorbell Simulator**
*(Because Ring does not send LAN webhooks, we use a custom simulator to inject high-res ID payloads into the webhook pipeline for testing).*

```bash
python live_demo_simulator.py

```

*Press `Spacebar` while focused on the simulator window to trigger a visitor event.*

---

## 📖 Friction Logs

We documented our engineering hurdles, architecture pivots, and edge-case resolutions (including AWS account blocks, hardware driver lockouts, and API rate limiting) during the hackathon.

👉 **[Read the full Friction Log here](https://www.google.com/search?q=FRICTION_LOG.md)**

---

## 🤝 Contributing & Hackathon Details

Built for the **Amazon AppDev Hackathon 2026** (Ring Track).

* **Developers:** Malaika Junaid

* **License:** MIT License
