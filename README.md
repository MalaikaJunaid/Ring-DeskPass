# Ring-DeskPass: Visitor Verification Prototype

[![Python Version](https://img.shields.io/badge/Python-3.10+-blue.svg?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![AWS](https://img.shields.io/badge/AWS-CloudWatch-232F3E.svg?logo=amazon-aws&logoColor=white)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

Ring-DeskPass has two separate paths: a local visitor-verification prototype in [`prototype/`](./prototype/) and an AWS-backed Ring Partner API implementation in [`deployable/`](./deployable/). **For local demonstration, use the prototype:** it runs without AWS account access or a Ring device and includes a synthetic event flow. The deployable SAM template validates and its Python 3.12 ARM64 Lambda packages build locally, but there is no AWS account role available for deployment and Ring OAuth/device delivery has not been tested.

---

## ✨ Key Features

*   **Signed intake:** Webhook signatures and a configured signing key are required before events are accepted.
*   **Durable processing:** Events and validated image snapshots are queued in SQLite, deduplicated by event ID, and retried after transient processing failures or server restarts.
*   **Conservative verification:** Uncertain matches require an authenticated receptionist decision. Without local YOLO weights, OCR-only results are never auto-approved.
*   **Data minimization:** Raw OCR is not logged, persisted, sent to Slack, or sent to an external AI service.
*   **Local audit history:** Decisions are recorded in SQLite. CloudWatch forwarding is optional and disabled by default.
*   **Reception dashboard:** A live Streamlit portal with operational metrics, access history, review actions, and a no-device demo flow.

---

## 🏗️ System Architecture

The webhook accepts the Ring Partner API JSON:API event envelope (`meta` and `data.id/type/attributes`) and the documented `X-Signature` HMAC header. For local testing, it also supports the older demo envelope and `X-Ring-Signature`. This payload parsing does not establish a live Ring Partner API integration. The dashboard and CLI can exercise the workflow without a Ring device:

1.  **Trigger:** The FastAPI backend verifies the HMAC signature and rejects requests when the signing key or signature is missing.
2.  **Durable intake:** The event-associated image must be supplied as the local adapter's base64 `snapshot_data` field; it is validated, stored locally, and queued in SQLite. Ring `thumbnail_url` values are not fetched. Repeated event IDs are not processed again.
3.  **Vision inference:** If `best.pt` is present locally, YOLO attempts badge detection and EasyOCR reads both the original and preprocessed badge crop. When OCR interpretations disagree, the strongest candidate is sent for review rather than auto-approved. If weights are absent, OCR-only mode is used and possible matches require manual review.
4.  **Decision:** A unique allowlist match scoring at least 95, with every name token meeting that threshold, is approved. Scores from 45 to 94 are marked for receptionist review; lower scores are denied. A close tie between candidates is never auto-approved.
5.  **Audit and notification:** Sanitized evidence and each decision are appended to the local audit log. The app sends status-only Slack notifications; no AI model chooses access decisions and this prototype does not control a physical lock.
6.  **UI update:** The dashboard shows current state and provides token-authenticated approval or denial for pending matches.

---

## 🛠️ Tech Stack

*   **Backend Routing:** FastAPI, Uvicorn, Python 3.11
*   **Computer Vision:** Ultralytics YOLOv8 (optional local `best.pt` weights), OpenCV (Headless), EasyOCR
*   **Event Processing:** SQLite-backed durable queue and deterministic allowlist matching
*   **Compliance & Logging:** AWS CloudWatch (`boto3`), SQLite3
*   **Integrations:** Slack Webhooks, HMAC-SHA256 Auth
*   **Frontend UI:** Streamlit, Pandas

---

## 🚀 Setup & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/MalaikaJunaid/Ring-DeskPass.git
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

Copy `.env.example` to `.env`, then set separate random values for the signing and review tokens. AWS credentials are not required for the local demo.

```env
RING_HMAC_SIGN_KEY="your_ring_webhook_secret"
DESKPASS_REVIEW_TOKEN="a-long-random-secret-shared-with-the-dashboard"
DESKPASS_API_URL="http://localhost:8000"
AWS_REGION="us-east-1"
CLOUDWATCH_LOG_GROUP="RingSecureKioskLogs"
ENABLE_CLOUDWATCH=false
SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

```

> **CloudWatch is optional:** It is disabled by default. If explicitly enabled, configure AWS credentials through the standard AWS credential chain and create the named log group first. The app forwards metadata only and caps attempts at 100 per local database; this is a conservative guard, not a guarantee of zero spend. No Bedrock calls are made.
> **Security:** Configure separate strong values for `RING_HMAC_SIGN_KEY` and `DESKPASS_REVIEW_TOKEN`. Keep the dashboard on a trusted network or behind an authenticated proxy; the review token is not a substitute for dashboard user authentication.

---

## 💻 Running the System

To run the local prototype from the repository root, open two terminals. Root `requirements.txt` contains its dependencies.

To preserve the prototype's existing root-level SQLite state after moving its source files, set the database path in each terminal before starting a process:

```powershell
$env:DESKPASS_DB_FILE = (Join-Path (Get-Location) "ring_deskpass.db")
```

**Terminal 1: Start the FastAPI API and queue worker**

```bash
uvicorn main:app --app-dir prototype --reload

```

**Terminal 2: Launch the Reception Management Dashboard**

```bash
streamlit run prototype/dashboard.py

```

Open **Run a device-free demo event** in the dashboard and submit the synthetic sample or an image you have permission to use. Alternatively, send the generated sample from a third terminal:

```bash
python prototype/live_demo_simulator.py

```

The CLI generates a synthetic badge image in memory; it does not need a Ring device, camera, or bundled sample image. To provide an image file instead, run `python prototype/live_demo_simulator.py --image path\to\badge.jpg`. The demo client signs the exact request body using `RING_HMAC_SIGN_KEY`; the dashboard reads `DESKPASS_REVIEW_TOKEN` from `.env`. For persistent jobs, use one Uvicorn worker with durable local disk; do not run multiple server processes against the same queue database.

The local prototype is not evidence of runtime use of Ring APIs, the official Ring simulator, or an AWS Builder service. These integrations and any challenge eligibility should be verified before describing them in a submission. For a clean clone, `best.pt` is not included; OCR-only mode is the supported fallback.

An optional [`prototype/ring_listener.py`](./prototype/ring_listener.py) adapter uses the third-party `ring_doorbell` package; it is not the official Ring integration. For the separate AWS/Ring path, see [`deployable/README.md`](./deployable/README.md). It calls the Ring Partner API and AWS services, but needs your own Ring portal setup, AWS deployment, and live validation before it can be described as production-ready.

### Current pivot: record the local prototype

Do not attempt an AWS deployment for the current demo. Start the local API and dashboard using the commands above, then use **Run a device-free demo event** or `python prototype/live_demo_simulator.py` to create a synthetic signed event. This demonstrates the local visitor-verification workflow; it does not demonstrate live Ring hardware, official Ring event delivery, or AWS runtime usage.

### Hackathon submission check

The saved Amazon Developer Hackathon rules specify that a Ring entry must use Ring APIs, an SDK, a simulator, or a device at runtime, and the demo video must show it working through a simulator or device. The local synthetic webhook is not an official Ring simulator and does not satisfy that demonstration requirement. The Ring/AWS path in `deployable/` has not been verified with Ring credentials or a test device, so do not describe the current demo as a working Ring integration. Confirm the current rules in Devpost before submission.

The rules also require a working demonstration video under three minutes, publicly hosted on YouTube or Vimeo, and product feedback for each developer tool/API/SDK used. The Ring submission must identify the primary track. AWS Builder is a separate mini-challenge: it requires an AWS service integration with documentation, or qualifying Kiro Crew use; do not claim it unless the actual requirement is met. [Product feedback](./PRODUCT_FEEDBACK.md) and [friction notes](./FRICTION_LOG.md) are maintained separately; friction notes do not guarantee a judging bonus.

For a public GitHub submission, this repository includes an MIT license. The repository and video links still need to be entered in the Devpost submission form.

### Continuous integration

GitHub Actions runs the deployable unit tests, Python compilation, SAM template lint, and a containerized ARM64 Lambda build on pushes and pull requests to `main`. It uses no AWS credentials and has **no deploy job**. See [`.github/workflows/ci.yml`](./.github/workflows/ci.yml).

---

## 📖 Friction Logs

We documented engineering hurdles and workarounds, including the local-demo boundary, AWS access limitations, the container build, and dependency isolation.

See [FRICTION_LOG.md](./FRICTION_LOG.md) for recorded development issues and workarounds.

See [PRODUCT_FEEDBACK.md](./PRODUCT_FEEDBACK.md) for evidence-based feedback on the tools and integrations used or evaluated.

---

## 🤝 Contributing & Hackathon Details

Built for the **Amazon AppDev Hackathon 2026** (Ring Track).

* **Developers:** Malaika Junaid

* **License:** MIT License
