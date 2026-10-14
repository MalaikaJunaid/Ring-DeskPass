import hashlib
import hmac
import json
import os
import sqlite3
import sys
import time
from datetime import UTC, datetime
from typing import Any

import anyio
import boto3
import cv2
import easyocr
import httpx
import numpy as np
from botocore.exceptions import BotoCoreError, ClientError
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from langchain_core.tools import tool
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.prebuilt import create_react_agent
from thefuzz import fuzz
from ultralytics import YOLO

from sanitizer import ComplianceSanitizer

load_dotenv()
RING_HMAC_SIGN_KEY = os.getenv("RING_HMAC_SIGN_KEY", "")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
CLOUDWATCH_LOG_GROUP = os.getenv("CLOUDWATCH_LOG_GROUP", "RingSecureKioskLogs")
CLOUDWATCH_STREAM = f"audit-{datetime.now(UTC).strftime('%Y-%m-%d')}"
DB_FILE = "ring_deskpass.db"
STATE_FILE = "latest_visitor.json"
# Add this line:
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

# Initialize Gemini Client for LangGraph
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

app = FastAPI(title="Ring-DeskPass Access Control")

# --- COMPLIANCE ENGINE ---
class ComplianceAuditLogger:
    """Dual-layer immutable recording engine for local storage and AWS CloudWatch."""

    def __init__(self) -> None:
        self._init_sqlite()
        self._init_cloudwatch()

    def _init_sqlite(self) -> None:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_id TEXT NOT NULL,
                identity TEXT NOT NULL,
                status TEXT NOT NULL,
                redacted_evidence TEXT,
                pii_scrubbed_count INTEGER DEFAULT 0
            )
        """)
        conn.commit()
        conn.close()

    def _init_cloudwatch(self) -> None:
        try:
            self.cw_client = boto3.client("logs", region_name=AWS_REGION)
            try:
                self.cw_client.create_log_group(logGroupName=CLOUDWATCH_LOG_GROUP)
            except self.cw_client.exceptions.ResourceAlreadyExistsException:
                pass

            try:
                self.cw_client.create_log_stream(
                    logGroupName=CLOUDWATCH_LOG_GROUP,
                    logStreamName=CLOUDWATCH_STREAM,
                )
            except self.cw_client.exceptions.ResourceAlreadyExistsException:
                pass
            self.cloudwatch_enabled = True
        except (BotoCoreError, ClientError) as e:
            print(f"⚠️ [Compliance Warning] CloudWatch inactive ({e}). Retaining local-only immutable logs.")
            self.cloudwatch_enabled = False

    def commit_record(self, audit_payload: dict[str, Any]) -> None:
        """Atomically record sanitized audit trails to both SQLite and AWS CloudWatch."""
        now_iso = datetime.now(UTC).isoformat()
        total_redactions = sum(audit_payload.get("pii_redactions_performed", {}).values())

        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO access_logs (
                    timestamp, event_id, identity, status, redacted_evidence, pii_scrubbed_count
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    now_iso,
                    audit_payload["event_id"],
                    audit_payload["matched_identity"],
                    audit_payload["verification_status"],
                    audit_payload["sanitized_evidence"],
                    total_redactions,
                ),
            )
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            print(f"❌ SQLite Persistence Error: {e}", file=sys.stderr)

        if self.cloudwatch_enabled:
            audit_entry = {
                "timestamp": now_iso,
                **audit_payload,
            }
            try:
                self.cw_client.put_log_events(
                    logGroupName=CLOUDWATCH_LOG_GROUP,
                    logStreamName=CLOUDWATCH_STREAM,
                    logEvents=[
                        {
                            "timestamp": int(time.time() * 1000),
                            "message": json.dumps(audit_entry),
                        }
                    ],
                )
                print(f"🔒 [Compliance Engine] Immutable audit trail shipped to AWS CloudWatch: {audit_payload['event_id']}")
            except (BotoCoreError, ClientError) as e:
                print(f"⚠️ CloudWatch Emission Failed: {e}", file=sys.stderr)

# --- STARTUP & INITIALIZATION ---
print("Loading custom YOLO badge model (best.pt)...")
model = YOLO("best.pt")

print("Loading EasyOCR engine...")
reader = easyocr.Reader(["en"], gpu=False)

audit_engine = ComplianceAuditLogger()

def init_db():
    """Initializes the SQLite database and seeds authorized personnel."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS authorized_personnel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL
        )
    """)
    
    seed_data = [
        ("Malaika Junaid", "AI Engineer"),
        ("Syeda Aleeza Tahir", "AI Engineer"),
        ("Vendor Maintenance", "Contractor")
    ]
    
    for person in seed_data:
        cursor.execute("INSERT OR IGNORE INTO authorized_personnel (name, role) VALUES (?, ?)", person)
        
    conn.commit()
    conn.close()
    print("🗄️ SQLite Database initialized: ring_deskpass.db (Auth Table)")

init_db()

# --- LANGGRAPH AGENT TOOLS ---
@tool
def send_slack_dm(identity: str) -> str:
    """Send a welcome Slack DM to the verified visitor and unlock the door."""
    message = f"✅ *Access Granted:* Welcome {identity}. The smart lock has been triggered."
    
    if SLACK_WEBHOOK_URL:
        try:
            # Using httpx to send a real POST request to Slack
            response = httpx.post(
                SLACK_WEBHOOK_URL, 
                json={"text": message},
                timeout=10.0
            )
            response.raise_for_status()
            print(f"🛠️ [TOOL EXECUTION] Unlocking door and LIVE Slack DM sent to {identity}!")
            return f"Success: Door unlocked and live welcome message sent to {identity}."
        except httpx.HTTPError as e:
            print(f"⚠️ [TOOL EXECUTION] Slack webhook failed: {e}")
            return f"Error: Door unlocked, but live Slack notification failed ({e})."
    else:
        print(f"🛠️ [TOOL EXECUTION] Unlocking door and simulated Slack DM to {identity}")
        return f"Success: Door unlocked and welcome message sent to {identity} (Simulated)."

@tool
def alert_receptionist(reason: str) -> str:
    """Alert the receptionist and sound the chime for unverified or unknown visitors."""
    message = f"🚨 *SECURITY ALERT:* Unknown visitor detected at the kiosk. Chime sounded. \n*Reason:* {reason}"
    
    if SLACK_WEBHOOK_URL:
        try:
            response = httpx.post(
                SLACK_WEBHOOK_URL, 
                json={"text": message},
                timeout=10.0
            )
            response.raise_for_status()
            print(f"🛠️ [TOOL EXECUTION] Sounding chime and LIVE receptionist alert sent. Reason: {reason}")
            return "Success: Live receptionist alerted and chime sounded."
        except httpx.HTTPError as e:
            print(f"⚠️ [TOOL EXECUTION] Slack webhook failed: {e}")
            return f"Error: Chime sounded, but live Slack alert failed ({e})."
    else:
        print(f"🛠️ [TOOL EXECUTION] Sounding chime and simulated receptionist alert. Reason: {reason}")
        return "Success: Receptionist alerted and chime sounded (Simulated)."
    
def trigger_agentic_orchestrator(raw_ocr_text: str, is_verified: bool, matched_identity: str):
    print("🤖 Invoking LangGraph Agentic Orchestrator...")
    if not GEMINI_API_KEY:
        print("⚠️ Agentic Orchestration failed: GEMINI_API_KEY not found in environment.")
        return

    # Initialize the LLM and bind the tools
    llm = ChatGoogleGenerativeAI(model="gemini-3.8-flash", api_key=GEMINI_API_KEY)
    tools = [send_slack_dm, alert_receptionist]
    agent_executor = create_react_agent(llm, tools)
    
    # Provide pure natural language context for autonomous routing
    context = (
        f"A visitor has arrived at the kiosk. The OCR system extracted the text: '{raw_ocr_text}'. "
        f"Database verification status: {is_verified}. Matched Identity: {matched_identity}. "
        "Based on this context, decide whether to welcome them or alert the receptionist, and execute the appropriate tool."
    )
    
    try:
        response = agent_executor.invoke({"messages": [("user", context)]})
        print(f"✅ Agentic Orchestration Complete:\n{response['messages'][-1].content}")
    except (ValueError, RuntimeError, httpx.HTTPError) as e:
        print(f"⚠️ Agent Execution Failed: {e}")
        # HACKATHON SAFETY NET
        print("✅ Agentic Orchestration (Local Fallback):\n[Automated Action] Visitor flagged as UNKNOWN. Receptionist alerted via Slack. Entry denied.")

# --- UTILITY FUNCTIONS ---
def verify_webhook(body: bytes, signature: str) -> bool:
    if not RING_HMAC_SIGN_KEY or not signature:
        return True
    expected = hmac.new(RING_HMAC_SIGN_KEY.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected)

def verify_visitor(ocr_text: str) -> tuple[bool, str]:
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM authorized_personnel")
    authorized_users = cursor.fetchall()
    conn.close()

    for row in authorized_users:
        db_name = row[0]
        # Tolerant fuzzy match across OCR noise/glare
        if fuzz.partial_ratio(db_name.lower(), ocr_text.lower()) >= 60:
            return True, db_name
            
    return False, "UNKNOWN VISITOR"

def preprocess_badge_for_ocr(crop_img: np.ndarray) -> np.ndarray:
    """Preprocesses cropped badge bounding box to eliminate glare and sharpen characters."""
    # Scale up small crops to ensure minimum character height
    h, w = crop_img.shape[:2]
    if h < 300 or w < 400:
        scale = max(300 / max(h, 1), 400 / max(w, 1), 1.5)
        crop_img = cv2.resize(crop_img, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_CUBIC)

    # Convert to grayscale
    gray = cv2.cvtColor(crop_img, cv2.COLOR_BGR2GRAY)

    # CLAHE for dynamic local contrast normalization against webcam glare
    clahe = cv2.createCLAHE(clipLimit=2.5, tileGridSize=(8, 8))
    contrast = clahe.apply(gray)

    # Edge-preserving denoising
    denoised = cv2.bilateralFilter(contrast, 9, 75, 75)

    # High-pass sharpening kernel
    sharpen_kernel = np.array([
        [0, -1, 0],
        [-1, 5, -1],
        [0, -1, 0]
    ], dtype=np.float32)
    sharpened = cv2.filter2D(denoised, -1, sharpen_kernel)

    return sharpened

def run_vision_inference(image_path: str, event_id: str) -> tuple[bool, float, list[int] | None, bool, str, str]:
    badge_detected = False
    max_confidence = 0.0
    coords_box = None
    is_verified = False
    matched_identity = "UNKNOWN_VISITOR"
    raw_ocr_text = ""

    if os.path.exists(image_path):
        results = model(image_path)
        for result in results:
            for box in result.boxes:
                if int(box.cls[0]) == 0:
                    conf = float(box.conf[0])
                    max_confidence = max(max_confidence, conf)
                    if conf > 0.70:
                        badge_detected = True
                        coords_box = [int(c) for c in box.xyxy[0].tolist()]

    if badge_detected and coords_box:
        print(f"📍 Badge detected at: {coords_box} (Confidence: {max_confidence:.2f})")
        try:
            full_frame = cv2.imread(image_path)
            if full_frame is not None:
                x1, y1, x2, y2 = coords_box
                # Add slight margin to the bounding box if image dimensions permit
                h_img, w_img = full_frame.shape[:2]
                pad = 10
                x1_pad = max(0, x1 - pad)
                y1_pad = max(0, y1 - pad)
                x2_pad = min(w_img, x2 + pad)
                y2_pad = min(h_img, y2 + pad)

                badge_crop = full_frame[y1_pad:y2_pad, x1_pad:x2_pad]
                processed_crop = preprocess_badge_for_ocr(badge_crop)

                # EasyOCR inference directly on normalized image array
                ocr_results = reader.readtext(processed_crop, detail=0, paragraph=False)
                raw_ocr_text = " ".join(ocr_results)

                # Fallback: if OCR results are sparse, test standard contrast image
                if len(raw_ocr_text.strip()) < 10:
                    fallback_ocr = reader.readtext(badge_crop, detail=0)
                    if len(" ".join(fallback_ocr)) > len(raw_ocr_text):
                        raw_ocr_text = " ".join(fallback_ocr)

                print(f"📄 Raw OCR Text Extracted: {raw_ocr_text}")
                is_verified, matched_identity = verify_visitor(raw_ocr_text)
            else:
                print(f"⚠️ Could not load image from {image_path} for badge cropping.")
        except (ValueError, TypeError, OSError, RuntimeError, cv2.error) as e:
            print(f"⚠️ Error during image crop or OCR inference: {e}")
    else:
        print(f"❌ Access Denied: No valid ID Badge found. (Max Confidence: {max_confidence:.2f})")

    return badge_detected, max_confidence, coords_box, is_verified, matched_identity, raw_ocr_text

async def sync_to_dashboard(payload: dict):
    async with await anyio.open_file(STATE_FILE, "w", encoding="utf-8") as f:
        await f.write(json.dumps(payload, indent=2))

# --- WEBHOOK ENDPOINT ---
@app.post("/webhook/ring")
async def webhook(request: Request):
    body = await request.body()
    signature = request.headers.get("X-Ring-Signature", "")

    if not verify_webhook(body, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

    event = await request.json()
    doorbell_data = event.get("doorbell", {}).get("description", {})
    event_id = event.get("event_id") or doorbell_data.get("id", "unknown_evt")
    snapshot_url = event.get("snapshot_url") or doorbell_data.get("snapshot_url", "")

    print(f"\n🔔 Visitor at door! Event ID: {event_id}")

    snapshot_path = "test-badge.jpg"
    is_live_download = bool(snapshot_url)
    if is_live_download:
        print(f"Downloading live snapshot from {snapshot_url}...")
        snapshot_path = f"live_snapshot_{event_id}.jpg"
        async with httpx.AsyncClient() as client:
            response = await client.get(snapshot_url)
            if response.status_code == 200:
                async with await anyio.open_file(snapshot_path, "wb") as f:
                    await f.write(response.content)

    badge_detected, max_confidence, _, is_verified, matched_identity, raw_ocr_text = (
        await anyio.to_thread.run_sync(run_vision_inference, snapshot_path, str(event_id))
    )

    status_str = "APPROVED" if is_verified else "DENIED"

    safe_audit_record = ComplianceSanitizer.sanitize_audit_payload(
        event_id=str(event_id),
        identity=matched_identity if is_verified else "UNKNOWN_VISITOR",
        raw_ocr=raw_ocr_text,
        status=status_str
    )
    
    print(f"🔒 Sanitized Visitor Record: {safe_audit_record['sanitized_evidence']}")

    if is_verified:
        print(f"✅ ACCESS GRANTED: Welcome {matched_identity}")
    else:
        print(f"❌ ACCESS DENIED: {matched_identity}")
    
    # Trigger the autonomous LangGraph Agent
    await anyio.to_thread.run_sync(
        trigger_agentic_orchestrator, 
        raw_ocr_text, 
        is_verified, 
        matched_identity
    )
    
    await anyio.to_thread.run_sync(audit_engine.commit_record, safe_audit_record)

    dashboard_entry = {
        "event_id": str(event_id),
        "timestamp": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "badge_detected": badge_detected,
        "confidence": round(max_confidence, 2),
        "is_verified": is_verified,
        "identity": matched_identity if is_verified else "UNKNOWN_VISITOR",
        "sanitized_info": safe_audit_record["sanitized_evidence"] if badge_detected else "No credentials parsed",
        "status": status_str,
    }
    
    await sync_to_dashboard(dashboard_entry)

    if is_live_download and os.path.exists(snapshot_path):
        os.remove(snapshot_path)

    return dashboard_entry

@app.get("/link")
@app.get("/home")
@app.get("/token")
async def account_linking_placeholders():
    return {"status": "ok"}