import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import sqlite3
from contextlib import closing, suppress
from io import BytesIO
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

import anyio
import cv2
import easyocr
import httpx
import numpy as np
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request
from PIL import Image, UnidentifiedImageError
from pydantic import BaseModel, Field, field_validator
from ultralytics import YOLO

from audit_logger import DB_FILE, ComplianceAuditLogger
from sanitizer import ComplianceSanitizer
from visitor_verification import classify_name_match

load_dotenv()
RING_HMAC_SIGN_KEY = os.getenv("RING_HMAC_SIGN_KEY", "")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
DESKPASS_REVIEW_TOKEN = os.getenv("DESKPASS_REVIEW_TOKEN", "")
MAX_SNAPSHOT_BYTES = 10 * 1024 * 1024
MAX_WEBHOOK_BYTES = 14 * 1024 * 1024
MAX_JOB_ATTEMPTS = 3
SNAPSHOT_DIR = Path(
    os.getenv("DESKPASS_SNAPSHOT_DIR", str(DB_FILE.with_name("queued_snapshots")))
)
logger = logging.getLogger("ring_deskpass")
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpx2").setLevel(logging.WARNING)

# --- STARTUP & INITIALIZATION ---
model_path = Path(os.getenv("DESKPASS_MODEL_PATH", "best.pt"))
if model_path.is_file():
    print(f"Loading YOLO badge model from {model_path}...")
    model = YOLO(str(model_path))
else:
    print(
        "YOLO weights are not bundled. Using OCR-only mode; every possible match "
        "will require receptionist approval."
    )
    model = None

print("Loading EasyOCR engine...")
reader = easyocr.Reader(["en"], gpu=False)

audit_engine = ComplianceAuditLogger()
app = FastAPI(title="Ring-DeskPass Access Control")

def init_db():
    """Initializes the SQLite database and seeds authorized personnel."""
    with closing(sqlite3.connect(DB_FILE)) as conn, conn:
        conn.execute("""
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
        conn.executemany(
            "INSERT OR IGNORE INTO authorized_personnel (name, role) VALUES (?, ?)",
            seed_data,
        )
    print("🗄️ SQLite Database initialized: ring_deskpass.db (Auth Table)")

init_db()

# --- DETERMINISTIC ACCESS NOTIFICATIONS ---
def send_slack_dm(event_id: str) -> None:
    """Notify reception that an event passed the local allowlist."""
    message = f"*Access approved:* Event {event_id} passed visitor verification."
    if SLACK_WEBHOOK_URL:
        try:
            response = httpx.post(
                SLACK_WEBHOOK_URL,
                json={"text": message},
                timeout=10.0,
            )
            response.raise_for_status()
        except httpx.HTTPError as error:
            logger.warning("Slack notification failed (%s).", type(error).__name__)
    else:
        logger.info("Access approved for event %s; Slack notification is not configured.", event_id)

def alert_receptionist(reason: str) -> None:
    """Send a status-only alert to reception without sharing OCR evidence."""
    message = f"*Reception review required:* {reason}"
    if SLACK_WEBHOOK_URL:
        try:
            response = httpx.post(
                SLACK_WEBHOOK_URL,
                json={"text": message},
                timeout=10.0,
            )
            response.raise_for_status()
        except httpx.HTTPError as error:
            logger.warning("Reception notification failed (%s).", type(error).__name__)
    else:
        logger.info("Reception notification not sent because Slack is not configured.")


class ReviewRequest(BaseModel):
    decision: Literal["APPROVED", "DENIED"]
    reviewer: str = Field(min_length=2, max_length=80)

    @field_validator("reviewer")
    @classmethod
    def validate_reviewer(cls, value: str) -> str:
        reviewer = value.strip()
        if len(reviewer) < 2 or any(ord(character) < 32 for character in reviewer):
            raise ValueError("Enter a valid reviewer name.")
        return reviewer

# --- UTILITY FUNCTIONS ---
def verify_webhook(body: bytes, signature: str) -> bool:
    if not RING_HMAC_SIGN_KEY or not signature:
        return False
    if signature.startswith("sha256="):
        signature = signature.removeprefix("sha256=")
    expected = hmac.new(RING_HMAC_SIGN_KEY.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected)

def verify_visitor(ocr_text: str) -> tuple[str, str, int | None]:
    with closing(sqlite3.connect(DB_FILE)) as conn:
        authorized_users = conn.execute(
            "SELECT name FROM authorized_personnel"
        ).fetchall()
    return classify_name_match(ocr_text, (row[0] for row in authorized_users))

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

def run_vision_inference(
    image_path: str,
) -> tuple[bool, float, str, str, str, int | None]:
    image_readable = False
    max_confidence = 0.0
    coords_box = None
    decision = "DENIED"
    matched_identity = "UNKNOWN_VISITOR"
    raw_ocr_text = ""
    match_score = None

    if model is None:
        full_frame = cv2.imread(image_path)
        if full_frame is not None:
            image_readable = True
            try:
                raw_ocr_text = " ".join(
                    reader.readtext(full_frame, detail=0, paragraph=False)
                )
                decision, matched_identity, match_score = verify_visitor(raw_ocr_text)
                if decision == "APPROVED":
                    decision = "PENDING_REVIEW"
            except (ValueError, TypeError, OSError, RuntimeError, cv2.error) as error:
                logger.warning("OCR-only inference failed (%s).", type(error).__name__)
        return image_readable, max_confidence, decision, matched_identity, raw_ocr_text, match_score

    if os.path.exists(image_path):
        results = model(image_path)
        for result in results:
            for box in result.boxes:
                if int(box.cls[0]) == 0:
                    conf = float(box.conf[0])
                    max_confidence = max(max_confidence, conf)
                    if conf > 0.70:
                        image_readable = True
                        coords_box = [int(c) for c in box.xyxy[0].tolist()]

    if image_readable and coords_box:
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

                processed_text = " ".join(
                    reader.readtext(processed_crop, detail=0, paragraph=False)
                )
                original_text = " ".join(
                    reader.readtext(badge_crop, detail=0, paragraph=False)
                )
                processed_match = verify_visitor(processed_text)
                original_match = verify_visitor(original_text)
                selected_match = max(
                    (processed_match, original_match),
                    key=lambda match: match[2] if match[2] is not None else -1,
                )
                decision, matched_identity, match_score = selected_match
                raw_ocr_text = (
                    processed_text if selected_match is processed_match else original_text
                )

                if (
                    processed_match[1] != original_match[1]
                    or processed_match[0] != original_match[0]
                ) and decision == "APPROVED":
                    decision = "PENDING_REVIEW"
            else:
                print(f"⚠️ Could not load image from {image_path} for badge cropping.")
        except (ValueError, TypeError, OSError, RuntimeError, cv2.error) as e:
            logger.warning("Vision inference failed (%s).", type(e).__name__)
    if not image_readable:
        full_frame = cv2.imread(image_path)
        if full_frame is not None:
            image_readable = True
            try:
                raw_ocr_text = " ".join(
                    reader.readtext(full_frame, detail=0, paragraph=False)
                )
                decision, matched_identity, match_score = verify_visitor(raw_ocr_text)
                if decision == "APPROVED":
                    decision = "PENDING_REVIEW"
            except (ValueError, TypeError, OSError, RuntimeError, cv2.error) as error:
                logger.warning("Full-frame OCR fallback failed (%s).", type(error).__name__)
        if not image_readable:
            logger.info("No readable badge image (confidence %.2f).", max_confidence)
            match_score = None

    return image_readable, max_confidence, decision, matched_identity, raw_ocr_text, match_score

async def persist_snapshot(snapshot_bytes: bytes) -> Path:
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    snapshot_path = SNAPSHOT_DIR / f"{uuid4().hex}.jpg"
    try:
        if not snapshot_bytes or len(snapshot_bytes) > MAX_SNAPSHOT_BYTES:
            raise HTTPException(status_code=413, detail="Snapshot must be between 1 byte and 10 MB.")
        try:
            with Image.open(BytesIO(snapshot_bytes)) as image:
                if image.format not in {"JPEG", "PNG"}:
                    raise HTTPException(status_code=415, detail="Snapshot must be a JPEG or PNG image.")
                if image.width * image.height > 40_000_000:
                    raise HTTPException(status_code=415, detail="Snapshot must be under 40 megapixels.")
                image.verify()
        except HTTPException:
            raise
        except (UnidentifiedImageError, OSError, ValueError, SyntaxError, Image.DecompressionBombError) as error:
            raise HTTPException(status_code=415, detail="Snapshot must be a valid JPEG or PNG image.") from error
        decoded = cv2.imdecode(np.frombuffer(snapshot_bytes, dtype=np.uint8), cv2.IMREAD_COLOR)
        if decoded is None:
            raise HTTPException(status_code=415, detail="Snapshot must be a valid image under 40 megapixels.")
        await anyio.to_thread.run_sync(snapshot_path.write_bytes, snapshot_bytes)
    except HTTPException:
        snapshot_path.unlink(missing_ok=True)
        raise
    except OSError as error:
        snapshot_path.unlink(missing_ok=True)
        logger.exception("Could not persist uploaded snapshot.")
        raise HTTPException(status_code=503, detail="Unable to persist the snapshot.") from error

    return snapshot_path


async def process_event(job: dict[str, Any]) -> None:
    event_id = job["event_id"]
    snapshot_path = job["snapshot_path"]
    badge_detected, confidence, decision, identity, raw_ocr, match_score = (
        await anyio.to_thread.run_sync(run_vision_inference, snapshot_path)
    )
    status = decision
    if not badge_detected:
        status = "DENIED"

    audit_record = ComplianceSanitizer.sanitize_audit_payload(
        event_id=event_id,
        identity=identity if status in {"APPROVED", "PENDING_REVIEW"} else "UNKNOWN_VISITOR",
        raw_ocr=raw_ocr,
        status=status,
    )
    if status == "PENDING_REVIEW":
        audit_record["decision_detail"] = f"Possible allowlist match ({match_score}%). Receptionist decision required."
    elif status == "APPROVED":
        audit_record["decision_detail"] = f"High-confidence allowlist match ({match_score}%)."
    else:
        audit_record["decision_detail"] = "No sufficiently confident allowlist match."

    audit_engine.complete_event(audit_record)
    Path(snapshot_path).unlink(missing_ok=True)
    logger.info("Event %s processed with status %s (badge confidence %.2f).", event_id, status, confidence)

    if status == "APPROVED":
        await anyio.to_thread.run_sync(send_slack_dm, event_id)
    elif status == "PENDING_REVIEW":
        await anyio.to_thread.run_sync(
            alert_receptionist,
            f"Event {event_id} has a possible visitor match and is awaiting dashboard review.",
        )
    else:
        await anyio.to_thread.run_sync(
            alert_receptionist,
            f"Event {event_id} could not be verified. Access remains denied.",
        )


async def queue_worker() -> None:
    while True:
        job = await anyio.to_thread.run_sync(audit_engine.claim_next_event)
        if job is None:
            await asyncio.sleep(1)
            continue
        try:
            await process_event(job)
        except Exception as error:  # noqa: BLE001 - isolate job failures and apply queue retries.
            logger.error(
                "Queued event %s failed (%s).",
                job["event_id"],
                type(error).__name__,
            )
            failed, snapshot_path = await anyio.to_thread.run_sync(
                audit_engine.fail_event,
                job["event_id"],
                type(error).__name__,
                job["attempts"],
                MAX_JOB_ATTEMPTS,
            )
            if failed and snapshot_path:
                Path(snapshot_path).unlink(missing_ok=True)


@app.on_event("startup")
async def start_queue_worker() -> None:
    await anyio.to_thread.run_sync(audit_engine.recover_interrupted_events)
    app.state.queue_worker_task = asyncio.create_task(queue_worker())


@app.on_event("shutdown")
async def stop_queue_worker() -> None:
    task = getattr(app.state, "queue_worker_task", None)
    if task is not None:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


@app.post("/webhook/ring", status_code=202)
async def webhook(request: Request) -> dict[str, Any]:
    if not RING_HMAC_SIGN_KEY:
        raise HTTPException(status_code=503, detail="Webhook signing key is not configured.")
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_WEBHOOK_BYTES:
                raise HTTPException(status_code=413, detail="Webhook payload exceeds the 14 MB limit.")
        except ValueError as error:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header.") from error
    chunks = []
    body_size = 0
    async for chunk in request.stream():
        body_size += len(chunk)
        if body_size > MAX_WEBHOOK_BYTES:
            raise HTTPException(status_code=413, detail="Webhook payload exceeds the 14 MB limit.")
        chunks.append(chunk)
    body = b"".join(chunks)
    signature = request.headers.get("X-Signature") or request.headers.get(
        "X-Ring-Signature",
        "",
    )
    if not verify_webhook(body, signature):
        raise HTTPException(status_code=401, detail="Invalid or missing webhook signature.")
    try:
        event = json.loads(body)
    except json.JSONDecodeError as error:
        raise HTTPException(status_code=400, detail="Webhook body must be valid JSON.") from error
    if not isinstance(event, dict):
        raise HTTPException(status_code=400, detail="Webhook body must be a JSON object.")

    ring_data = event.get("data")
    ring_attributes: dict[str, Any] = {}
    event_type = event.get("event_type") or event.get("event") or "legacy"
    if ring_data is not None:
        if not isinstance(ring_data, dict):
            raise HTTPException(status_code=400, detail="data must be a JSON object.")
        ring_meta = event.get("meta")
        if not isinstance(ring_meta, dict) or any(
            not isinstance(ring_meta.get(field), str) or not ring_meta[field].strip()
            for field in ("version", "time", "request_id")
        ):
            raise HTTPException(
                status_code=400,
                detail="Ring webhook meta must include version, time, and request_id strings.",
            )
        raw_attributes = ring_data.get("attributes", {})
        if not isinstance(raw_attributes, dict):
            raise HTTPException(status_code=400, detail="data.attributes must be a JSON object.")
        ring_attributes = raw_attributes
        if any(
            not isinstance(ring_attributes.get(field), str)
            or not ring_attributes[field].strip()
            for field in ("source", "source_type")
        ):
            raise HTTPException(
                status_code=400,
                detail="Ring webhook attributes must include source and source_type strings.",
            )
        timestamp = ring_attributes.get("timestamp")
        if not isinstance(timestamp, (int, str)) or isinstance(timestamp, bool):
            raise HTTPException(
                status_code=400,
                detail="Ring webhook attributes must include a string or integer timestamp.",
            )
        event_type = ring_data.get("type")
        if not isinstance(event_type, str) or not event_type.strip():
            raise HTTPException(status_code=400, detail="data.type must be a non-empty string.")
        event_id = event.get("event_id") or ring_data.get("id")
    else:
        doorbell = event.get("doorbell", {})
        if not isinstance(doorbell, dict):
            raise HTTPException(status_code=400, detail="doorbell must be a JSON object.")
        doorbell_data = doorbell.get("description", {})
        if not isinstance(doorbell_data, dict):
            doorbell_data = {}
        event_id = event.get("event_id") or doorbell_data.get("id")
        event_type = event.get("event") or "legacy"

    if not isinstance(event_id, str) or not event_id.strip() or len(event_id) > 200:
        raise HTTPException(status_code=400, detail="A valid event_id is required.")
    event_id = event_id.strip()
    encoded_snapshot = event.get("snapshot_data") or ring_attributes.get("snapshot_data")
    snapshot_url = (
        event.get("snapshot_url")
        or ring_attributes.get("snapshot_url")
        or ring_attributes.get("thumbnail_url")
    )
    if not isinstance(encoded_snapshot, str) and snapshot_url:
        raise HTTPException(
            status_code=422,
            detail=(
                "Snapshot and thumbnail URLs are not fetched. Attach validated image bytes "
                "as snapshot_data using the local adapter."
            ),
        )
    if not isinstance(encoded_snapshot, str):
        raise HTTPException(
            status_code=422,
            detail=(
                "Ring event received, but no image was attached. Provide base64 snapshot_data "
                "through the local adapter; Ring thumbnail URLs are not fetched."
            ),
        )
    try:
        snapshot_bytes = base64.b64decode(encoded_snapshot, validate=True)
    except (ValueError, binascii.Error) as error:
        raise HTTPException(status_code=400, detail="snapshot_data must be valid base64.") from error
    if len(snapshot_bytes) > MAX_SNAPSHOT_BYTES:
        raise HTTPException(status_code=413, detail="Snapshot exceeds the 10 MB limit.")
    snapshot_path = await persist_snapshot(snapshot_bytes)
    try:
        job_status, inserted = await anyio.to_thread.run_sync(
            audit_engine.enqueue_event, event_id, str(snapshot_path)
        )
    except sqlite3.Error as error:
        snapshot_path.unlink(missing_ok=True)
        logger.exception("Could not enqueue a signed webhook event.")
        raise HTTPException(status_code=503, detail="Unable to queue the event.") from error
    if not inserted:
        snapshot_path.unlink(missing_ok=True)
    return {
        "event_id": event_id,
        "event_type": str(event_type),
        "status": job_status,
        "duplicate": not inserted,
    }


@app.post("/review/{event_id}")
async def review_event(
    event_id: str,
    review: ReviewRequest,
    authorization: str = Header(default=""),
) -> dict[str, str]:
    if not DESKPASS_REVIEW_TOKEN:
        raise HTTPException(status_code=503, detail="Dashboard review authentication is not configured.")
    scheme, _, supplied_token = authorization.partition(" ")
    if scheme.casefold() != "bearer":
        supplied_token = ""
    supplied_token = supplied_token.strip()
    if not hmac.compare_digest(supplied_token, DESKPASS_REVIEW_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid reviewer authorization.")

    with closing(sqlite3.connect(DB_FILE)) as conn:
        pending_record = conn.execute(
            """
            SELECT identity, redacted_evidence
            FROM access_logs
            WHERE event_id = ? AND status = 'PENDING_REVIEW'
            ORDER BY id DESC
            LIMIT 1
            """,
            (event_id,),
        ).fetchone()
    if pending_record is None:
        raise HTTPException(status_code=404, detail="Pending review event not found.")

    identity = pending_record[0] if review.decision == "APPROVED" else "UNKNOWN_VISITOR"
    audit_record = {
        "compliance_standard": "SOC2-CC6.1 / GDPR-Minimised",
        "event_id": event_id,
        "matched_identity": identity,
        "sanitized_evidence": pending_record[1] or "",
        "pii_redactions_performed": {},
        "verification_status": review.decision,
        "reviewed_by": review.reviewer,
        "decision_detail": f"Receptionist {review.decision.lower()} the pending event.",
    }
    recorded = await anyio.to_thread.run_sync(audit_engine.record_review, audit_record)
    if not recorded:
        raise HTTPException(status_code=409, detail="This event has already been reviewed.")

    if review.decision == "APPROVED":
        await anyio.to_thread.run_sync(send_slack_dm, event_id)
    else:
        await anyio.to_thread.run_sync(
            alert_receptionist,
            f"Receptionist denied access for event {event_id}.",
        )
    return {"event_id": event_id, "status": review.decision}

@app.get("/link")
@app.get("/home")
@app.get("/token")
async def account_linking_placeholders():
    return {"status": "ok"}