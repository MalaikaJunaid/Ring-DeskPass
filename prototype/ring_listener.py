import base64
import hashlib
import hmac
import json
import os
import time

import httpx
from dotenv import load_dotenv
from ring_doorbell import Auth, Requires2FAError, Ring

load_dotenv()

RING_USERNAME = os.getenv("RING_USERNAME")
RING_PASSWORD = os.getenv("RING_PASSWORD")
RING_HMAC_SIGN_KEY = os.getenv("RING_HMAC_SIGN_KEY", "")
API_URL = os.getenv("DESKPASS_API_URL", "http://localhost:8000").rstrip("/")
WEBHOOK_URL = f"{API_URL}/webhook/ring"
TOKEN_CACHE_FILE = os.path.join(os.path.dirname(__file__), "ring_token.cache")
MAX_SNAPSHOT_BYTES = 10 * 1024 * 1024

def token_updated(token):
    """Callback to save the Ring auth token to avoid repeated 2FA prompts."""
    with open(TOKEN_CACHE_FILE, "w", encoding="utf-8") as token_file:
        json.dump(token, token_file)

def get_auth():
    """Authenticate with Ring, handling cached tokens and 2FA."""
    if os.path.isfile(TOKEN_CACHE_FILE):
        with open(TOKEN_CACHE_FILE, encoding="utf-8") as token_file:
            cached_token = json.load(token_file)
        auth = Auth("Ring-DeskPass/1.0", cached_token, token_updated)
    else:
        auth = Auth("Ring-DeskPass/1.0", None, token_updated)
        if not RING_USERNAME or not RING_PASSWORD:
            raise RuntimeError("Set RING_USERNAME and RING_PASSWORD in .env to use the Ring listener.")
        try:
            auth.fetch_token(RING_USERNAME, RING_PASSWORD)
        except Requires2FAError:
            # If 2FA is required, the terminal will prompt you for the code on first run
            auth.fetch_token(RING_USERNAME, RING_PASSWORD, input("Enter Ring 2FA Code: "))
    return auth

def main():
    if not RING_HMAC_SIGN_KEY:
        raise RuntimeError("Set RING_HMAC_SIGN_KEY in .env before using the Ring listener.")
    print("Initializing Ring SDK listener...")
    auth = get_auth()
    ring = Ring(auth)
    ring.update_data()

    devices = ring.devices()
    doorbells = devices['doorbots']

    if not doorbells:
        print("No Ring doorbells found on this account.")
        return

    doorbell = doorbells[0]
    print(f"Connected to Ring doorbell: {doorbell.name}")
    print("Polling for active doorbell rings...")

    last_alert_id = None

    while True:
        try:
            ring.update_dings()
            alerts = ring.active_alerts()

            if alerts:
                alert = alerts[0]
                alert_id = alert.get("id")

                # Ensure we only process new rings
                if alert.get("kind") == "ding" and alert_id != last_alert_id:
                    print(f"\nLive ding detected: {alert_id}")

                    # Pause briefly to allow Ring hardware to upload the snapshot/video frame
                    time.sleep(2)

                    # Download the frame locally and avoid retaining it after webhook submission.
                    snapshot_bytes = doorbell.get_snapshot()
                    if not snapshot_bytes or len(snapshot_bytes) > MAX_SNAPSHOT_BYTES:
                        print("Snapshot is empty or exceeds the 10 MB upload limit; skipping event.")
                        time.sleep(3)
                        continue
                    payload = {
                        "event_id": str(alert_id),
                        "source": "ring_doorbell_sdk",
                        "snapshot_data": base64.b64encode(snapshot_bytes).decode("ascii"),
                    }
                    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                    signature = hmac.new(
                        RING_HMAC_SIGN_KEY.encode("utf-8"),
                        body,
                        hashlib.sha256,
                    ).hexdigest()
                    response = httpx.post(
                        WEBHOOK_URL,
                        content=body,
                        headers={
                            "Content-Type": "application/json",
                            "X-Signature": signature,
                        },
                        timeout=30.0,
                    )
                    response.raise_for_status()
                    last_alert_id = alert_id
                    print(f"Ring event queued: {response.json().get('event_id')}")

            time.sleep(3) # Poll every 3 seconds

        except (httpx.HTTPError, ConnectionError, TimeoutError) as e:
            print(f"Polling or webhook error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()