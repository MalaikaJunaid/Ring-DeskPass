import hashlib
import hmac
import json
import os
import unittest
from decimal import Decimal
from unittest.mock import patch

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("EVENTS_TABLE", "events-test")
os.environ.setdefault("AUDIT_TABLE", "audit-test")
os.environ.setdefault("VISITORS_TABLE", "visitors-test")
os.environ.setdefault("SITE_ID", "test-site")
os.environ.setdefault("RING_CREDENTIALS_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:000000000000:secret:test")
os.environ.setdefault("RING_EVENT_QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/000000000000/test")
from deployable.src.deskpass.common import (
    _audit_signature,
    parse_ring_event,
    verify_audit_record,
    verify_ring_signature,
)
from deployable.src.deskpass import api
from deployable.src.deskpass.worker import _classify


class RingEventTests(unittest.TestCase):
    def test_health_route_is_available(self) -> None:
        response = api.lambda_handler({"path": "/healthz", "httpMethod": "GET"}, None)
        self.assertEqual(response["statusCode"], 200)

    def test_webhook_rejects_invalid_signature(self) -> None:
        event = {
            "path": "/webhook/ring",
            "httpMethod": "POST",
            "headers": {"X-Signature": "invalid"},
            "body": "{}",
        }
        with patch.object(api, "secrets", return_value={"webhook_secret": "secret"}):
            response = api.lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 401)

    def test_valid_webhook_queues_once(self) -> None:
        payload = {
            "data": {
                "id": "event-1",
                "type": "button_press",
                "attributes": {"device_id": "camera-1"},
            }
        }
        event = {
            "path": "/webhook/ring",
            "httpMethod": "POST",
            "headers": {"X-Signature": "sha256=verified"},
            "body": json.dumps(payload),
        }
        with (
            patch.object(api, "secrets", return_value={"webhook_secret": "secret"}),
            patch.object(api, "verify_ring_signature", return_value=True),
            patch.object(api, "put_received_event", return_value=True),
            patch.object(api._sqs, "send_message") as send_message,
        ):
            response = api.lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 202)
        send_message.assert_called_once()

    def test_valid_ring_signature(self) -> None:
        body = b'{"data":{"id":"event-1","type":"button_press"}}'
        digest = hmac.new(b"secret", body, hashlib.sha256).hexdigest()
        self.assertTrue(verify_ring_signature(body, f"sha256={digest}", "secret"))
        self.assertFalse(verify_ring_signature(body, digest, "wrong"))

    def test_parse_supported_event(self) -> None:
        result = parse_ring_event(
            {
                "data": {
                    "id": "event-1",
                    "type": "button_press",
                    "attributes": {"device_id": "camera-1", "timestamp": "2026-01-01T00:00:00Z"},
                }
            }
        )
        self.assertEqual(result["device_id"], "camera-1")
        self.assertEqual(result["event_type"], "button_press")

    def test_ignores_non_access_event(self) -> None:
        self.assertIsNone(parse_ring_event({"data": {"id": "x", "type": "device_online"}}))

    def test_audit_record_signature_detects_tampering(self) -> None:
        record = {
            "site_id": "test",
            "audit_id": "event-1#REVIEW",
            "event_id": "event-1",
            "action": "REVIEW",
            "created_at": "2026-01-01T00:00:00+00:00",
            "expires_at": Decimal("1"),
            "details": {"decision": "APPROVED", "score": Decimal("98")},
        }
        record["signature"] = _audit_signature(record, "s" * 32)
        self.assertTrue(verify_audit_record(record, "s" * 32))
        record["details"]["decision"] = "DENIED"
        self.assertFalse(verify_audit_record(record, "s" * 32))

    def test_match_requires_receptionist_review(self) -> None:
        status, name, _ = _classify("Malaika Junaid", ["Malaika Junaid"])
        self.assertEqual((status, name), ("PENDING_REVIEW", "Malaika Junaid"))

    def test_ambiguous_match_does_not_identify_person(self) -> None:
        with patch("deployable.src.deskpass.worker.fuzz.ratio", return_value=90):
            status, name, _ = _classify("Al", ["Alex Kim", "Alec Kim"])
        self.assertEqual(status, "PENDING_REVIEW")
        self.assertIsNone(name)


class ReceptionistAuthorizationTests(unittest.TestCase):
    def test_admin_route_rejects_missing_cognito_claims(self) -> None:
        response = api.lambda_handler(
            {"path": "/admin/events", "httpMethod": "GET"},
            None,
        )
        self.assertEqual(response["statusCode"], 401)

    def test_admin_route_rejects_users_outside_receptionists_group(self) -> None:
        response = api.lambda_handler(
            {
                "path": "/admin/events",
                "httpMethod": "GET",
                "requestContext": {
                    "authorizer": {
                        "claims": {
                            "sub": "user-id",
                            "cognito:username": "operator",
                            "cognito:groups": ["OtherGroup"],
                        }
                    }
                },
            },
            None,
        )
        self.assertEqual(response["statusCode"], 401)

    def test_review_identity_comes_from_cognito_claims(self) -> None:
        event = {
            "path": "/admin/events/event-1/review",
            "httpMethod": "POST",
            "body": json.dumps({"decision": "APPROVED", "reviewer": "forged-user"}),
            "requestContext": {
                "authorizer": {
                    "claims": {
                        "sub": "user-id",
                        "cognito:username": "reception-operator",
                        "cognito:groups": ["Receptionists"],
                    }
                }
            },
        }
        with (
            patch.object(api._events_table, "update_item") as update_item,
            patch.object(api, "append_signed_audit") as append_audit,
        ):
            response = api.lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(
            update_item.call_args.kwargs["ExpressionAttributeValues"][":reviewer"],
            "reception-operator",
        )
        self.assertEqual(
            append_audit.call_args.args[2]["reviewer"],
            "reception-operator",
        )


if __name__ == "__main__":
    unittest.main()
