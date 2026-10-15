from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

_secrets_client = boto3.client("secretsmanager")
_dynamodb = boto3.resource("dynamodb")
_events_table = _dynamodb.Table(os.environ["EVENTS_TABLE"])
_audit_table = _dynamodb.Table(os.environ["AUDIT_TABLE"])
_visitors_table = _dynamodb.Table(os.environ["VISITORS_TABLE"])
_site_id = os.environ["SITE_ID"]
_retention_days = int(os.environ.get("EVENT_RETENTION_DAYS", "30"))
_secret_cache: dict[str, Any] | None = None

def secrets() -> dict[str, Any]:
    global _secret_cache
    if _secret_cache is None:
        response = _secrets_client.get_secret_value(
            SecretId=os.environ["RING_CREDENTIALS_SECRET_ARN"]
        )
        secret_string = response.get("SecretString")
        if not secret_string:
            raise RuntimeError("Ring credentials secret must contain a JSON SecretString.")
        parsed = json.loads(secret_string)
        if not isinstance(parsed, dict):
            raise RuntimeError("Ring credentials secret must be a JSON object.")
        _secret_cache = parsed
    return _secret_cache


def update_secret(updated: dict[str, Any]) -> None:
    _secrets_client.put_secret_value(
        SecretId=os.environ["RING_CREDENTIALS_SECRET_ARN"],
        SecretString=json.dumps(updated),
    )
    global _secret_cache
    _secret_cache = updated


def verify_ring_signature(body: bytes, signature: str | None, secret: str) -> bool:
    if not signature or not secret:
        return False
    supplied = signature.removeprefix("sha256=")
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(supplied, expected)


def parse_ring_event(payload: dict[str, Any]) -> dict[str, str] | None:
    if not isinstance(payload, dict):
        raise ValueError("Ring event payload must be a JSON object.")
    data = payload.get("data")
    if not isinstance(data, dict):
        data = payload
    attributes = data.get("attributes")
    if not isinstance(attributes, dict):
        attributes = data
    relationships = data.get("relationships")
    device_relationship = (
        relationships.get("device", {}) if isinstance(relationships, dict) else {}
    )
    device_data = (
        device_relationship.get("data", {})
        if isinstance(device_relationship, dict)
        else {}
    )
    event_id = data.get("id") or attributes.get("event_id")
    event_type = data.get("type") or attributes.get("event_type")
    device_id = attributes.get("device_id") or (
        device_data.get("id") if isinstance(device_data, dict) else None
    )
    timestamp = attributes.get("timestamp") or datetime.now(UTC).isoformat()
    if not isinstance(event_type, str):
        raise ValueError("Ring event type must be a string.")
    if event_type not in {"button_press", "motion_detected"}:
        return None
    if not all(isinstance(value, str) and value.strip() for value in (event_id, device_id)):
        raise ValueError("Ring event must include string event and device identifiers.")
    if len(event_id) > 200 or len(device_id) > 200:
        raise ValueError("Ring event identifiers must not exceed 200 characters.")
    if not isinstance(timestamp, str):
        raise ValueError("Ring event timestamp must be a string.")
    event_timestamp(timestamp)
    return {
        "event_id": event_id.strip(),
        "event_type": event_type,
        "device_id": device_id.strip(),
        "timestamp": str(timestamp),
    }


def get_event(event_id: str) -> dict[str, Any] | None:
    result = _events_table.get_item(Key={"site_id": _site_id, "event_id": event_id})
    return result.get("Item")


def _audit_signature(record: dict[str, Any], key: str) -> str:
    def json_default(value: Any) -> int:
        if isinstance(value, Decimal) and value == value.to_integral_value():
            return int(value)
        raise TypeError(f"Unsupported audit field type: {type(value).__name__}")

    unsigned_record = {name: value for name, value in record.items() if name != "signature"}
    canonical_payload = json.dumps(
        unsigned_record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=json_default,
    ).encode("utf-8")
    return hmac.new(key.encode("utf-8"), canonical_payload, hashlib.sha256).hexdigest()


def verify_audit_record(record: dict[str, Any], key: str) -> bool:
    signature = record.get("signature")
    return (
        isinstance(signature, str)
        and hmac.compare_digest(signature, _audit_signature(record, key))
    )


def append_signed_audit(event_id: str, action: str, details: dict[str, Any]) -> None:
    signing_key = secrets().get("audit_hmac_key")
    if not isinstance(signing_key, str) or len(signing_key) < 32:
        raise RuntimeError("Ring credentials secret needs an audit_hmac_key of at least 32 characters.")
    record = {
        "site_id": _site_id,
        "audit_id": f"{event_id}#{action}",
        "event_id": event_id,
        "action": action,
        "created_at": datetime.now(UTC).isoformat(),
        "details": details,
        "expires_at": int(
            (datetime.now(UTC) + timedelta(days=_retention_days)).timestamp()
        ),
    }
    record["signature"] = _audit_signature(record, signing_key)
    try:
        _audit_table.put_item(
            Item=record,
            ConditionExpression="attribute_not_exists(audit_id)",
        )
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
            raise
        existing = _audit_table.get_item(
            Key={"site_id": _site_id, "audit_id": record["audit_id"]}
        ).get("Item")
        if (
            existing is None
            or existing.get("event_id") != event_id
            or existing.get("action") != action
            or existing.get("details") != details
            or not verify_audit_record(existing, signing_key)
        ):
            raise RuntimeError("An existing audit record failed signature or content validation.") from error


def put_received_event(event: dict[str, str]) -> bool:
    now = datetime.now(UTC)
    try:
        _events_table.put_item(
            Item={
                "site_id": _site_id,
                "event_id": event["event_id"],
                "event_type": event["event_type"],
                "device_id": event["device_id"],
                "event_timestamp": event["timestamp"],
                "created_at": now.isoformat(),
                "created_at_event": f"{now.isoformat()}#{event['event_id']}",
                "status": "RECEIVED",
                "expires_at": int((now + timedelta(days=_retention_days)).timestamp()),
            },
            ConditionExpression="attribute_not_exists(event_id)",
        )
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        raise
    return True


def visitor_records_at(moment: datetime) -> list[dict[str, str]]:
    visitors: list[dict[str, str]] = []
    last_key = None
    while True:
        query_args: dict[str, Any] = {
            "KeyConditionExpression": Key("site_id").eq(_site_id),
        }
        if last_key:
            query_args["ExclusiveStartKey"] = last_key
        response = _visitors_table.query(**query_args)
        for visitor in response.get("Items", []):
            if visitor.get("status", "ACTIVE") != "ACTIVE":
                continue
            start = visitor.get("valid_from")
            end = visitor.get("valid_until")
            if start and moment < event_timestamp(start):
                continue
            if end and moment > event_timestamp(end):
                continue
            name = visitor.get("name")
            if isinstance(name, str) and name.strip():
                record = {"name": name.strip()}
                company = visitor.get("company")
                if isinstance(company, str) and company.strip():
                    record["company"] = company.strip()
                visitors.append(record)
        last_key = response.get("LastEvaluatedKey")
        if not last_key:
            return visitors


def event_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def lambda_response(status: int, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(payload, default=str),
    }
