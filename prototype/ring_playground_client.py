import os

import httpx
from dotenv import load_dotenv

load_dotenv()

PLAYGROUND_BASE_URL = "https://api.amazonvision.com"
AUTH_TOKEN = os.getenv("RING_PLAYGROUND_TOKEN")  # Your Playground bearer/API token

headers = {
    "Authorization": f"Bearer {AUTH_TOKEN}",
    "Content-Type": "application/json",
}

def get_playground_devices():
    """Fetch discovered devices from the developer sandbox."""
    url = f"{PLAYGROUND_BASE_URL}/v1/devices"
    try:
        response = httpx.get(url, headers=headers, timeout=10.0)
        response.raise_for_status()
        return response.json()
    except httpx.HTTPError as err:
        print(f"⚠️ Playground connection note: {err}")
        return None

def fetch_recent_events(device_id: str):
    """Query recent history using plural event_types syntax."""
    url = f"{PLAYGROUND_BASE_URL}/v1/history/devices/{device_id}/events"
    params = {"event_types": "motion.human,motion.vehicle,ding,on_demand"}
    try:
        response = httpx.get(url, headers=headers, params=params, timeout=10.0)
        return response.json()
    except httpx.HTTPError as err:
        print(f"⚠️ Event fetch note: {err}")
        return None