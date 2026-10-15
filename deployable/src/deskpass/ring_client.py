from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

import httpx

from .common import secrets, update_secret

_access_token = ""
_access_expires_at = datetime.min.replace(tzinfo=UTC)


def _access_token_for_request() -> str:
    global _access_token, _access_expires_at
    if _access_token and datetime.now(UTC) < _access_expires_at - timedelta(minutes=2):
        return _access_token

    credentials = secrets()
    playground_token = credentials.get("playground_access_token")
    if playground_token:
        return str(playground_token)

    required = ("client_id", "client_secret", "refresh_token")
    if any(not credentials.get(key) for key in required):
        raise RuntimeError(
            "Ring secret needs client_id, client_secret, and refresh_token, "
            "or a temporary playground_access_token."
        )

    response = httpx.post(
        os.environ["RING_OAUTH_URL"],
        data={
            "grant_type": "refresh_token",
            "refresh_token": credentials["refresh_token"],
            "client_id": credentials["client_id"],
            "client_secret": credentials["client_secret"],
        },
        timeout=15.0,
    )
    response.raise_for_status()
    token_payload = response.json()
    token = token_payload.get("access_token")
    if not isinstance(token, str) or not token:
        raise RuntimeError("Ring OAuth response did not contain an access token.")
    expires_in = int(token_payload.get("expires_in", 14_400))
    _access_token = token
    _access_expires_at = datetime.now(UTC) + timedelta(seconds=expires_in)

    rotated_refresh_token = token_payload.get("refresh_token")
    if rotated_refresh_token and rotated_refresh_token != credentials["refresh_token"]:
        credentials["refresh_token"] = rotated_refresh_token
        update_secret(credentials)
    return token


def download_snapshot(device_id: str, component_ids: list[str] | None = None) -> bytes:
    url = (
        f"{os.environ['RING_API_BASE_URL'].rstrip('/')}/v1/devices/"
        f"{quote(device_id, safe='')}/media/image/download"
    )
    request_body = {"components": component_ids} if component_ids else None
    response = _download_request(url, request_body)
    if response.status_code == 401:
        global _access_token, _access_expires_at
        _access_token = ""
        _access_expires_at = datetime.min.replace(tzinfo=UTC)
        response = _download_request(url, request_body)
    response.raise_for_status()
    content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
    if content_type not in {"image/jpeg", "image/png"}:
        raise RuntimeError("Ring snapshot endpoint did not return a JPEG or PNG image.")
    if not response.content or len(response.content) > 5 * 1024 * 1024:
        raise RuntimeError("Ring snapshot must be non-empty and no larger than 5 MB.")
    return response.content


def _download_request(url: str, request_body: dict[str, list[str]] | None) -> httpx.Response:
    return httpx.post(
        url,
        headers={"Authorization": f"Bearer {_access_token_for_request()}"},
        json=request_body,
        timeout=20.0,
    )
