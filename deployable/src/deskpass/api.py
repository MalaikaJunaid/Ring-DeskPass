from __future__ import annotations

import base64
import binascii
import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import BotoCoreError, ClientError

from .common import (
    _events_table,
    _site_id,
    append_signed_audit,
    get_event,
    lambda_response,
    parse_ring_event,
    put_received_event,
    secrets,
    verify_ring_signature,
)

_sqs = boto3.client("sqs")
_bedrock = boto3.client("bedrock-runtime")
_queue_url = os.environ["RING_EVENT_QUEUE_URL"]
_logger = logging.getLogger(__name__)


def _body_bytes(event: dict[str, Any]) -> bytes:
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        return base64.b64decode(body, validate=True)
    return body.encode("utf-8")


def _headers(event: dict[str, Any]) -> dict[str, str]:
    return {
        str(key).lower(): str(value)
        for key, value in (event.get("headers") or {}).items()
    }


def _receptionist_username(event: dict[str, Any]) -> str | None:
    request_context = event.get("requestContext")
    authorizer = request_context.get("authorizer") if isinstance(request_context, dict) else None
    claims = authorizer.get("claims") if isinstance(authorizer, dict) else None
    if not isinstance(claims, dict) or not isinstance(claims.get("sub"), str):
        return None
    username = claims.get("cognito:username")
    if not isinstance(username, str) or not username.strip():
        return None
    groups = claims.get("cognito:groups", [])
    if isinstance(groups, str):
        try:
            parsed_groups = json.loads(groups)
        except json.JSONDecodeError:
            parsed_groups = groups.split(",")
        groups = parsed_groups
    if not isinstance(groups, list) or "Receptionists" not in groups:
        return None
    return username.strip()


def _handle_webhook(event: dict[str, Any]) -> dict[str, Any]:
    try:
        body = _body_bytes(event)
    except (binascii.Error, ValueError, TypeError):
        return lambda_response(400, {"error": "Webhook body encoding is invalid."})
    if len(body) > 1_048_576:
        return lambda_response(413, {"error": "Ring webhook payload exceeds the 1 MB limit."})
    signing_key = secrets().get("webhook_secret")
    if not isinstance(signing_key, str) or not verify_ring_signature(
        body, _headers(event).get("x-signature"), signing_key
    ):
        return lambda_response(401, {"error": "Invalid Ring webhook signature."})
    try:
        payload = json.loads(body)
        ring_event = parse_ring_event(payload)
    except (json.JSONDecodeError, ValueError, TypeError) as error:
        return lambda_response(400, {"error": str(error)})
    if ring_event is None:
        return lambda_response(202, {"status": "ignored"})

    is_new = False
    try:
        is_new = put_received_event(ring_event)
        if is_new:
            _sqs.send_message(
                QueueUrl=_queue_url,
                MessageBody=json.dumps(
                    {
                        **ring_event,
                        "component_ids": _component_ids(payload),
                    }
                ),
            )
    except (BotoCoreError, ClientError) as error:
        if is_new:
            try:
                _events_table.delete_item(
                    Key={"site_id": _site_id, "event_id": ring_event["event_id"]}
                )
            except (BotoCoreError, ClientError) as cleanup_error:
                _logger.exception(
                    "Failed to remove unqueued Ring event %s (%s).",
                    ring_event["event_id"],
                    type(cleanup_error).__name__,
                )
        _logger.exception("Could not enqueue Ring event %s (%s).", ring_event["event_id"], type(error).__name__)
        raise
    return lambda_response(
        202,
        {"event_id": ring_event["event_id"], "status": "queued" if is_new else "duplicate"},
    )


def _component_ids(payload: dict[str, Any]) -> list[str]:
    data = payload.get("data", {})
    attributes = data.get("attributes", {}) if isinstance(data, dict) else {}
    values = attributes.get("component_ids", []) if isinstance(attributes, dict) else []
    return [str(value) for value in values] if isinstance(values, list) else []


def _list_events() -> dict[str, Any]:
    result = _events_table.query(
        IndexName="by_site_created_at",
        KeyConditionExpression=Key("site_id").eq(_site_id),
        ScanIndexForward=False,
        Limit=100,
    )
    return lambda_response(200, {"events": result.get("Items", [])})


def _review_event(event_id: str, body: bytes, reviewer: str) -> dict[str, Any]:
    payload = json.loads(body or b"{}")
    if not isinstance(payload, dict):
        return lambda_response(400, {"error": "Request body must be a JSON object."})
    decision = payload.get("decision")
    if decision not in {"APPROVED", "DENIED"}:
        return lambda_response(400, {"error": "decision must be APPROVED or DENIED."})
    if len(reviewer) > 128 or any(ord(character) < 32 for character in reviewer):
        return lambda_response(401, {"error": "Receptionist identity is invalid."})
    try:
        _events_table.update_item(
            Key={"site_id": _site_id, "event_id": event_id},
            UpdateExpression="SET #status = :decision, reviewed_by = :reviewer, reviewed_at = :now",
            ConditionExpression="#status = :pending",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":decision": decision,
                ":pending": "PENDING_REVIEW",
                ":reviewer": reviewer,
                ":now": datetime.now(UTC).isoformat(),
            },
        )
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            current = _events_table.get_item(
                Key={"site_id": _site_id, "event_id": event_id}
            ).get("Item")
            if (
                current is None
                or current.get("status") != decision
                or current.get("reviewed_by") != reviewer
            ):
                return lambda_response(409, {"error": "Event is missing or no longer awaiting review."})
        else:
            raise
    append_signed_audit(
        event_id,
        "REVIEW",
        {"decision": decision, "reviewer": reviewer},
    )
    return lambda_response(200, {"event_id": event_id, "status": decision})


def _event_summary(event_id: str) -> dict[str, Any]:
    record = get_event(event_id)
    if record is None:
        return lambda_response(404, {"error": "Event not found."})
    prompt = (
        "Write one brief, neutral receptionist dashboard note from these fields only. "
        "Do not infer identity, intent, or whether access should be granted. "
        f"Event status: {record.get('status', 'unknown')}. "
        f"Allowlist match score: {record.get('match_score', 'not available')}."
    )
    try:
        response = _bedrock.converse(
            modelId=os.environ["BEDROCK_MODEL_ID"],
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={"maxTokens": 100, "temperature": 0.1},
        )
    except ClientError as error:
        _logger.warning("Bedrock summary request failed (%s).", type(error).__name__)
        return lambda_response(
            503,
            {"error": "Bedrock summary is unavailable; the access decision is unchanged."},
        )
    text = response["output"]["message"]["content"][0]["text"]
    return lambda_response(200, {"event_id": event_id, "summary": text})


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    path = event.get("path", "")
    method = event.get("httpMethod", "")
    if path == "/healthz" and method == "GET":
        return lambda_response(200, {"status": "ok"})
    if path == "/webhook/ring" and method == "POST":
        return _handle_webhook(event)

    reviewer = _receptionist_username(event)
    if reviewer is None:
        return lambda_response(401, {"error": "Receptionist authorization required."})
    if path == "/admin/events" and method == "GET":
        return _list_events()
    path_parts = path.strip("/").split("/")
    if len(path_parts) == 4 and path_parts[:2] == ["admin", "events"]:
        event_id = path_parts[2]
        action = path_parts[3]
        if action == "review" and method == "POST":
            try:
                return _review_event(event_id, _body_bytes(event), reviewer)
            except (binascii.Error, json.JSONDecodeError, UnicodeDecodeError, ValueError):
                return lambda_response(400, {"error": "Request body must be valid JSON."})
        if action == "summary" and method == "POST":
            return _event_summary(event_id)
    return lambda_response(404, {"error": "Route not found."})
