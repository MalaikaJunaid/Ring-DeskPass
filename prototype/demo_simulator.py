import base64
import hashlib
import hmac
import json
import os
from io import BytesIO
from pathlib import Path
from uuid import uuid4

import httpx
from dotenv import load_dotenv
from PIL import Image, ImageDraw, ImageFont

load_dotenv()

API_URL = os.getenv("DESKPASS_API_URL", "http://localhost:8000").rstrip("/")
RING_HMAC_SIGN_KEY = os.getenv("RING_HMAC_SIGN_KEY", "")
MAX_SNAPSHOT_BYTES = 10 * 1024 * 1024


def create_sample_badge() -> bytes:
    image = Image.new("RGB", (1200, 720), "#eaf0f6")
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default(size=42)
    small_font = ImageFont.load_default(size=25)

    draw.rounded_rectangle((72, 62, 1128, 658), radius=32, fill="#ffffff", outline="#c9d5e3", width=4)
    draw.rounded_rectangle((72, 62, 1128, 190), radius=32, fill="#1c3454")
    draw.rectangle((72, 150, 1128, 190), fill="#1c3454")
    draw.text((120, 100), "DESKPASS  |  VISITOR CREDENTIAL", font=small_font, fill="#ffffff")
    draw.text((120, 255), "Vendor Maintenance", font=font, fill="#17253a")
    draw.text((120, 340), "VISITOR ACCESS DEMO", font=small_font, fill="#53647b")
    draw.line((120, 420, 1080, 420), fill="#d9e2ec", width=3)
    draw.text((120, 470), "SYNTHETIC SAMPLE - NO PERSONAL ID DATA", font=small_font, fill="#718096")
    draw.rounded_rectangle((120, 555, 410, 610), radius=18, fill="#e8f7ef")
    draw.text((150, 568), "DEMO CREDENTIAL", font=small_font, fill="#14764c")

    output = BytesIO()
    image.save(output, format="PNG", optimize=True)
    return output.getvalue()


def submit_demo_event(snapshot_bytes: bytes) -> dict[str, str | bool]:
    if not RING_HMAC_SIGN_KEY:
        raise ValueError("Set RING_HMAC_SIGN_KEY in .env before sending demo events.")
    if not snapshot_bytes or len(snapshot_bytes) > MAX_SNAPSHOT_BYTES:
        raise ValueError("Choose a valid image smaller than 10 MB.")

    event_id = f"demo_{uuid4().hex}"
    payload = {
        "event_id": event_id,
        "source": "deskpass-local-demo",
        "snapshot_data": base64.b64encode(snapshot_bytes).decode("ascii"),
    }
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(
        RING_HMAC_SIGN_KEY.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()
    response = httpx.post(
        f"{API_URL}/webhook/ring",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Signature": signature,
        },
        timeout=30.0,
    )
    response.raise_for_status()
    return response.json()


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Send a signed, no-device DeskPass demo event.")
    parser.add_argument("--image", type=Path, help="Optional visitor badge image; defaults to a synthetic sample.")
    parser.add_argument("--url", help="Override the API URL (defaults to DESKPASS_API_URL).")
    args = parser.parse_args()

    global API_URL
    if args.url:
        API_URL = args.url.rstrip("/")
    if args.image and args.image.stat().st_size > MAX_SNAPSHOT_BYTES:
        parser.error("The image must be 10 MB or smaller.")
    snapshot_bytes = args.image.read_bytes() if args.image else create_sample_badge()
    result = submit_demo_event(snapshot_bytes)
    print(f"Event {result['event_id']} accepted: {result['status']}")


if __name__ == "__main__":
    main()
