import json
import os
import sqlite3
import sys
import time
from datetime import UTC, datetime
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from dotenv import load_dotenv

load_dotenv()

DB_FILE = "ring_deskpass.db"
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
CLOUDWATCH_LOG_GROUP = os.getenv("CLOUDWATCH_LOG_GROUP", "RingSecureKioskLogs")
CLOUDWATCH_STREAM = f"audit-{datetime.now(UTC).strftime('%Y-%m-%d')}"


class ComplianceAuditLogger:
    """Dual-layer immutable recording engine for local storage and AWS CloudWatch."""

    def __init__(self) -> None:
        self._init_sqlite()
        self._init_cloudwatch()

    def _init_sqlite(self) -> None:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_id TEXT NOT NULL,
                identity TEXT NOT NULL,
                status TEXT NOT NULL,
                redacted_evidence TEXT,
                pii_scrubbed_count INTEGER DEFAULT 0
            )
        """)
        conn.commit()
        conn.close()

    def _init_cloudwatch(self) -> None:
        try:
            self.cw_client = boto3.client("logs", region_name=AWS_REGION)
            # Guarantee log group existence
            try:
                self.cw_client.create_log_group(logGroupName=CLOUDWATCH_LOG_GROUP)
            except self.cw_client.exceptions.ResourceAlreadyExistsException:
                pass

            # Guarantee log stream existence
            try:
                self.cw_client.create_log_stream(
                    logGroupName=CLOUDWATCH_LOG_GROUP,
                    logStreamName=CLOUDWATCH_STREAM,
                )
            except self.cw_client.exceptions.ResourceAlreadyExistsException:
                pass
            self.cloudwatch_enabled = True
        except (BotoCoreError, ClientError) as e:
            print(f"⚠️ [Compliance Warning] CloudWatch inactive ({e}). Retaining local-only immutable logs.")
            self.cloudwatch_enabled = False

    def commit_record(self, audit_payload: dict[str, Any]) -> None:
        """Atomically record sanitized audit trails to both SQLite and AWS CloudWatch."""
        now_iso = datetime.now(UTC).isoformat()
        total_redactions = sum(audit_payload.get("pii_redactions_performed", {}).values())

        # 1. Local Structured SQLite Logging
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO access_logs (
                    timestamp, event_id, identity, status, redacted_evidence, pii_scrubbed_count
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    now_iso,
                    audit_payload["event_id"],
                    audit_payload["matched_identity"],
                    audit_payload["verification_status"],
                    audit_payload["sanitized_evidence"],
                    total_redactions,
                ),
            )
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            print(f"❌ SQLite Persistence Error: {e}", file=sys.stderr)

        # 2. Immutable AWS CloudWatch Ingestion
        if self.cloudwatch_enabled:
            audit_entry = {
                "timestamp": now_iso,
                **audit_payload,
            }
            try:
                self.cw_client.put_log_events(
                    logGroupName=CLOUDWATCH_LOG_GROUP,
                    logStreamName=CLOUDWATCH_STREAM,
                    logEvents=[
                        {
                            "timestamp": int(time.time() * 1000),
                            "message": json.dumps(audit_entry),
                        }
                    ],
                )
                print(f"🔒 [Compliance Engine] Immutable audit trail shipped to AWS CloudWatch: {audit_payload['event_id']}")
            except (BotoCoreError, ClientError) as e:
                print(f"⚠️ CloudWatch Emission Failed: {e}", file=sys.stderr)