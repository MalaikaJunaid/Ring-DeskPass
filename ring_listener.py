import json
import os
import time
from pathlib import Path

import httpx
from dotenv import load_dotenv
from ring_doorbell import Auth, Requires2FAError, Ring

load_dotenv()

RING_USERNAME = os.getenv("RING_USERNAME")
RING_PASSWORD = os.getenv("RING_PASSWORD")
LOCAL_WEBHOOK_URL = "http://localhost:8000/webhook/ring"
TOKEN_CACHE_FILE = Path("ring_token.cache")

def token_updated(token):
    """Callback to save the Ring auth token to avoid repeated 2FA prompts."""
    TOKEN_CACHE_FILE.write_text(json.dumps(token))

def get_auth():
    """Authenticate with Ring, handling cached tokens and 2FA."""
    if TOKEN_CACHE_FILE.is_file():
        auth = Auth("Ring-DeskPass/1.0", json.loads(TOKEN_CACHE_FILE.read_text()), token_updated)
    else:
        auth = Auth("Ring-DeskPass/1.0", None, token_updated)
        try:
            auth.fetch_token(RING_USERNAME, RING_PASSWORD)
        except Requires2FAError:
            # If 2FA is required, the terminal will prompt you for the code on first run
            auth.fetch_token(RING_USERNAME, RING_PASSWORD, input("Enter Ring 2FA Code: "))
    return auth

def main():
    print("🔄 Initializing Ring Hardware SDK...")
    auth = get_auth()
    ring = Ring(auth)
    ring.update_data()
    
    devices = ring.devices()
    doorbells = devices['doorbots']
    
    if not doorbells:
        print("❌ No Ring doorbells found on this account.")
        return
        
    doorbell = doorbells[0]
    print(f"✅ Connected to physical hardware: {doorbell.name}")
    print("📡 Polling for active doorbell rings...")

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
                    print(f"\n🔔 LIVE DING DETECTED! Event ID: {alert_id}")
                    last_alert_id = alert_id
                    
                    # Pause briefly to allow Ring hardware to upload the snapshot/video frame
                    time.sleep(2) 
                    
                    # Download the latest frame captured by the hardware
                    snapshot_bytes = doorbell.get_snapshot()
                    snapshot_path = f"ring_capture_{alert_id}.jpg"
                    
                    with open(snapshot_path, "wb") as f:
                        f.write(snapshot_bytes)
                    
                    # Construct the payload for your FastAPI backend
                    payload = {
                        "event_id": str(alert_id),
                        "doorbell": {
                            "id": str(alert_id),
                            "description": "Hardware Ring Event"
                        },
                        # In a production cloud setup, this would be an S3 URL. 
                        # Locally, we pass the file path or mock URL for main.py to handle.
                        "snapshot_url": f"local://{snapshot_path}" 
                    }
                    
                    print("🚀 Pushing hardware event to FastAPI backend...")
                    httpx.post(LOCAL_WEBHOOK_URL, json=payload, timeout=10.0)

            time.sleep(3) # Poll every 3 seconds
            
        except (httpx.RequestError, ConnectionError, TimeoutError) as e:
            print(f"⚠️ Polling Error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()