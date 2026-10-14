
### Entry 01: Ring Ecosystem Constraints & Webhook Architecture

* **Task Attempted:** Clone the `ring-api-helloworld` starter code, query API endpoints locally, and design a LAN-based integration for SMB front-desk execution.


* **Steps Taken:**
* Attempted `gh repo clone` but lacked the GitHub CLI executable, requiring a standard HTTPS clone.


* Generated a Playground Bearer token and tested the FastAPI server on `localhost:8000/webhook/ring`.




* **Actual Result:** The Playground token expired strictly after 30 minutes, blocking continuous testing. More critically, Ring devices operate exclusively in a gated cloud ecosystem and cannot send local LAN webhooks, requiring HTTPS cloud endpoints and OAuth 2.0.


* **Severity Rating:** Critical (Pitch Level)
* **Workaround Implemented:** Stored the `device_id` locally in `.env` to minimize API calls during inference testing. Pivoted the business pitch from a "local script" to a cloud-native prototype designed for the Ring Appstore, utilizing our existing HMAC-SHA256 signature verification to mimic Ring's production security.


* **Actionable Suggestion for Ring:** Provide 24-hour sandbox tokens for local development and explicitly document that local LAN event polling is unsupported.



### Entry 02: Hardware Resource Locks & OpenCV Stream Detachment

* **Task Attempted:** Initialize a live webcam feed via OpenCV inside a FastAPI background process to capture visitor snapshots upon receiving a doorbell webhook.


* **Steps Taken:**
* Configured `cv2.VideoCapture(0)` across multiple Windows backends (DSHOW, MSMF).


* Triggered the webhook, resulting in an unhandled exception during the read step.




* **Actual Result:** The FastAPI crash left zombie Python processes running. Windows DirectShow aggressively locked the camera hardware to the dangling process, returning `[ERROR] Camera index out of range` and preventing subsequent initializations.


* **Severity Rating:** High
* **Workaround Implemented:** Used PowerShell (`Stop-Process -Force`) to kill hanging processes. Abandoned the live webcam feed for a `live_demo_simulator.py` static image pipeline to bypass Windows hardware drivers entirely.


* **Actionable Suggestion for Framework Maintainers:** OpenCV Python bindings require a strict context manager (e.g., `with cv2.VideoCapture(0) as cap:`) to guarantee hardware release on thread exceptions.



### Entry 03: Edge OCR Reliability on Holographic Substrates

* **Task Attempted:** Extract an English name from a UAE government ID card using local edge inference (EasyOCR) following YOLO bounding box detection.


* **Steps Taken:**
* Detected the badge via `best.pt`, applied OpenCV preprocessing (CLAHE, bilateral filtering, high-pass sharpening), and passed the crop to EasyOCR.




* **Actual Result:** EasyOCR failed on the ID's microprint, multi-language text, and holographic overlays, outputting mangled strings (e.g., `datara /ta du4karnad`). This triggered a 60% fuzzy match failure and a false "ACCESS DENIED" state.


* **Severity Rating:** Medium
* **Workaround Implemented:** Substituted the real ID with a synthetic, high-contrast digital badge for the demo, ensuring 100% accuracy and eliminating PII exposure risks for the public Devpost submission.


* **Actionable Suggestion for Edge Deployment:** Standard OCR is insufficient for complex documents; production deployments require Multimodal LLM Vision pipelines natively trained to ignore holographic noise.



### Entry 04: Cloud AI Volatility & Service Access Blocks

* **Task Attempted:** Execute LLM orchestration via AWS Bedrock (Claude) with a fallback to Google Gemini to route security system logic.


* **Steps Taken:**
* Initialized `boto3` for Bedrock and integrated the `google-genai` SDK for Gemini.




* **Actual Result:** AWS immediately rejected the Bedrock call (`Error 002`) due to new-account model access blocks and delayed hackathon credits. When falling back to Gemini, rapid sequential testing triggered `503 UNAVAILABLE` API spikes, throwing `errors.APIError` and crashing the FastAPI server.


* **Severity Rating:** High (Strategic)
* **Workaround Implemented:** Broadened the `try/except` block to catch `google.genai.errors` and engineered a zero-latency "Hackathon Safety Net." If APIs spike, the server catches the error, injects a hardcoded local fallback plan, and returns a 200 OK to keep the dashboard alive.


* **Actionable Suggestion for AWS & System Architecture:** AWS should provide a frictionless sandbox tier for base models. Developers must always decouple external LLM volatility from core physical security routing servers.



### Entry 05: Compliance Telemetry IAM Friction

* **Task Attempted:** Ship immutable, PII-scrubbed access trails to AWS CloudWatch Logs.


* **Steps Taken:**
* Configured `ComplianceAuditLogger` to automatically call `create_log_group` and `put_log_events`.




* **Actual Result:** Strict AWS IAM defaults (missing `logs:CreateLogGroup` policies) caused `boto3` to throw fatal exceptions, crashing the entire webhook response cycle.


* **Severity Rating:** Medium
* **Workaround Implemented:** Wrapped cloud logging initializations in strict `try/except` blocks. If IAM permissions fail, the system toggles a `cloudwatch_enabled = False` flag and gracefully degrades to saving records in a local SQLite database (`ring_deskpass.db`).


* **Actionable Suggestion for Architecture:** Secondary compliance telemetry must never break the primary physical security pipeline; Boto3 cloud logging should always be strictly decoupled.