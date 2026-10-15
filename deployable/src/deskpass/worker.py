from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

import boto3
from thefuzz import fuzz

from .common import (
    _events_table,
    _site_id,
    append_signed_audit,
    event_timestamp,
    visitor_records_at,
)
from .ring_client import download_snapshot

_rekognition = boto3.client("rekognition")
_logger = logging.getLogger(__name__)


def _classify(text: str, names: list[str]) -> tuple[str, str | None, int | None]:
    tokens = re.findall(r"[a-z0-9]+", text.casefold())
    if not tokens or not names:
        return "DENIED", None, None
    candidates: list[tuple[int, str]] = []
    for name in names:
        name_tokens = re.findall(r"[a-z0-9]+", name.casefold())
        if not name_tokens:
            continue
        score = round(
            sum(max(fuzz.ratio(part, token) for token in tokens) for part in name_tokens)
            / len(name_tokens)
        )
        candidates.append((score, name))
    if not candidates:
        return "DENIED", None, None
    candidates.sort(reverse=True)
    best_score, best_name = candidates[0]
    second_score = candidates[1][0] if len(candidates) > 1 else 0
    if best_score >= 45 and best_score - second_score >= 5:
        return "PENDING_REVIEW", best_name, best_score
    if best_score >= 45:
        return "PENDING_REVIEW", None, best_score
    return "DENIED", None, best_score


def process_message(message: dict[str, Any]) -> None:
    ring_event = json.loads(message["body"])
    event_id = ring_event["event_id"]
    image = download_snapshot(
        ring_event["device_id"],
        ring_event.get("component_ids") or None,
    )
    response = _rekognition.detect_text(Image={"Bytes": image})
    raw_text = " ".join(
        item["DetectedText"]
        for item in response.get("TextDetections", [])
        if item.get("Type") == "LINE" and item.get("DetectedText")
    )
    visitors = visitor_records_at(event_timestamp(ring_event["timestamp"]))
    status, identity, score = _classify(
        raw_text,
        [visitor["name"] for visitor in visitors],
    )
    company = next(
        (visitor.get("company") for visitor in visitors if visitor["name"] == identity),
        None,
    )
    _events_table.update_item(
        Key={"site_id": _site_id, "event_id": event_id},
        UpdateExpression=(
            "SET #status = :status, matched_identity = :identity, "
            "matched_company = :company, match_score = :score, processed_at = :now"
        ),
        ConditionExpression="attribute_exists(event_id)",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":status": status,
            ":identity": identity or "UNKNOWN_VISITOR",
            ":company": company or "UNKNOWN_COMPANY",
            ":score": score,
            ":now": datetime.now(UTC).isoformat(),
        },
    )
    append_signed_audit(
        event_id,
        "PROCESSING",
        {
            "status": status,
            "matched_identity": identity or "UNKNOWN_VISITOR",
            "matched_company": company or "UNKNOWN_COMPANY",
            "match_score": score,
        },
    )


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    failures = []
    for record in event.get("Records", []):
        try:
            process_message(record)
        except Exception as error:
            _logger.exception(
                "Ring event processing failed (message ID %s, error type %s).",
                record.get("messageId", "unknown"),
                type(error).__name__,
            )
            failures.append({"itemIdentifier": record["messageId"]})
    return {"batchItemFailures": failures}
