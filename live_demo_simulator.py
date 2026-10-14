import os
import time

import cv2
import httpx

WEBHOOK_ENDPOINT = "http://localhost:8000/webhook/ring"
DUMMY_IMAGE_PATH = "dummy_badge.jpg"

def run_static_feed():
    if not os.path.exists(DUMMY_IMAGE_PATH):
        print(f"❌ Could not find '{DUMMY_IMAGE_PATH}' in the project folder.")
        print("💡 FIX: Save a picture of an ID badge as 'dummy_badge.jpg' and try again.")
        return

    print("🟢 Static Image Simulator Active.")
    print("👉 Press [SPACEBAR] to trigger the Ring-DeskPass webhook. Press [Q] to exit.")

    # Load the static image
    frame = cv2.imread(DUMMY_IMAGE_PATH)

    while True:
        cv2.imshow("Ring-DeskPass (Static Simulator)", frame)
        key = cv2.waitKey(1) & 0xFF

        if key == 32:  # Spacebar
            print("📸 Triggering snapshot dispatch to FastAPI webhook...")
            
            # Save a copy as test-badge.jpg so main.py can process it
            cv2.imwrite("test-badge.jpg", frame)
            
            event_id = f"sim_{int(time.time())}"
            payload = {
                "event_id": event_id,
                "doorbell": {"description": {"id": event_id}},
                "snapshot_url": "", 
            }

            try:
                res = httpx.post(WEBHOOK_ENDPOINT, json=payload, timeout=20.0)
                print(f"✅ Webhook response: {res.status_code}")
            except httpx.HTTPError as e:
                print(f"❌ Webhook connection error: {e}")

        elif key == ord("q"):
            break

    cv2.destroyAllWindows()

if __name__ == "__main__":
    run_static_feed()