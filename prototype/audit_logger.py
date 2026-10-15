import json
import os
import sqlite3
import sys
import time
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from dotenv import load_dotenv

load_dotenv()

DB_FILE = Path(
    os.getenv("DESKPASS_DB_FILE", str(Path(__file__).resolve().with_name("ring_deskpass.db")))
)
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
CLOUDWATCH_LOG_GROUP = os.getenv("CLOUDWATCH_LOG_GROUP", "RingSecureKioskLogs")
CLOUDWATCH_ENABLED = os.getenv("ENABLE_CLOUDWATCH", "").casefold() == "true"
CLOUDWATCH_EVENT_LIMIT = 100


class ComplianceAuditLogger:
    """Persist append-only access decisions locally and forward them to CloudWatch."""

    def __init__(self) -> None:
        self._init_sqlite()
        self.cloudwatch_enabled = False
        self.cw_client = None
        if CLOUDWATCH_ENABLED:
            self._init_cloudwatch()

    def _connect(self) -> sqlite3.Connection:
        DB_FILE.parent.mkdir(parents=True, exist_ok=True)
        return sqlite3.connect(DB_FILE, timeout=30)

    @contextmanager
    def _connection(self) -> Generator[sqlite3.Connection, None, None]:
        conn = self._connect()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_sqlite(self) -> None:
        with self._connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS access_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    identity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    redacted_evidence TEXT,
                    pii_scrubbed_count INTEGER DEFAULT 0,
                    reviewed_by TEXT,
                    decision_detail TEXT
                )
            """)
            existing_columns = {
                row[1] for row in conn.execute("PRAGMA table_info(access_logs)")
            }
            for column in ("reviewed_by", "decision_detail"):
                if column not in existing_columns:
                    conn.execute(f"ALTER TABLE access_logs ADD COLUMN {column} TEXT")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS processing_jobs (
                    event_id TEXT PRIMARY KEY,
                    snapshot_path TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_error TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cloudwatch_usage (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    attempted_events INTEGER NOT NULL DEFAULT 0
                )
            """)
            conn.execute(
                "INSERT OR IGNORE INTO cloudwatch_usage (id, attempted_events) VALUES (1, 0)"
            )

    def _init_cloudwatch(self) -> None:
        try:
            self.cw_client = boto3.client("logs", region_name=AWS_REGION)
        except (BotoCoreError, ClientError) as error:
            print(
                f"CloudWatch audit logging unavailable ({error}); retaining local audit records.",
                file=sys.stderr,
            )
            return
        if self.cw_client is None:
            return
        self.cloudwatch_enabled = True

    def enqueue_event(self, event_id: str, snapshot_path: str) -> tuple[str, bool]:
        now = datetime.now(UTC).isoformat()
        with self._connection() as conn:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO processing_jobs (
                    event_id, snapshot_path, status, created_at, updated_at
                ) VALUES (?, ?, 'QUEUED', ?, ?)
                """,
                (event_id, snapshot_path, now, now),
            )
            row = conn.execute(
                "SELECT status FROM processing_jobs WHERE event_id = ?", (event_id,)
            ).fetchone()
        if row is None:
            raise sqlite3.DatabaseError("The event could not be queued.")
        return str(row[0]), cursor.rowcount == 1

    def recover_interrupted_events(self) -> None:
        with self._connection() as conn:
            conn.execute(
                """
                UPDATE processing_jobs
                SET status = 'QUEUED', updated_at = ?, last_error = NULL
                WHERE status = 'PROCESSING'
                """,
                (datetime.now(UTC).isoformat(),),
            )

    def claim_next_event(self) -> dict[str, Any] | None:
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT event_id, snapshot_path, attempts
                FROM processing_jobs
                WHERE status = 'QUEUED'
                ORDER BY created_at, event_id
                LIMIT 1
                """
            ).fetchone()
            if row is None:
                return None
            conn.execute(
                """
                UPDATE processing_jobs
                SET status = 'PROCESSING', attempts = attempts + 1, updated_at = ?
                WHERE event_id = ? AND status = 'QUEUED'
                """,
                (datetime.now(UTC).isoformat(), row[0]),
            )
        return {"event_id": row[0], "snapshot_path": row[1], "attempts": row[2] + 1}

    def complete_event(self, audit_payload: dict[str, Any]) -> None:
        now = datetime.now(UTC).isoformat()
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                """
                UPDATE processing_jobs
                SET status = ?, updated_at = ?, last_error = NULL
                WHERE event_id = ? AND status = 'PROCESSING'
                """,
                (audit_payload["verification_status"], now, audit_payload["event_id"]),
            )
            if cursor.rowcount != 1:
                raise sqlite3.IntegrityError("The processing job is no longer active.")
            self._insert_audit_record(conn, audit_payload, now)
        self._emit_cloudwatch(audit_payload, now)

    def fail_event(
        self, event_id: str, error_type: str, attempts: int, max_attempts: int
    ) -> tuple[bool, str | None]:
        now = datetime.now(UTC).isoformat()
        final_failure = attempts >= max_attempts
        new_status = "FAILED" if final_failure else "QUEUED"
        failed_payload = None
        with self._connection() as conn:
            row = conn.execute(
                "SELECT snapshot_path, status FROM processing_jobs WHERE event_id = ?",
                (event_id,),
            ).fetchone()
            cursor = conn.execute(
                """
                UPDATE processing_jobs
                SET status = ?, updated_at = ?, last_error = ?
                WHERE event_id = ? AND status = 'PROCESSING'
                """,
                (new_status, now, error_type, event_id),
            )
            if cursor.rowcount != 1:
                return False, None
            if final_failure:
                failed_payload = {
                    "compliance_standard": "SOC2-CC6.1 / GDPR-Minimised",
                    "event_id": event_id,
                    "matched_identity": "UNKNOWN_VISITOR",
                    "sanitized_evidence": "Event processing failed.",
                    "pii_redactions_performed": {},
                    "verification_status": "FAILED",
                    "decision_detail": error_type,
                }
                self._insert_audit_record(conn, failed_payload, now)
        if failed_payload is not None:
            self._emit_cloudwatch(failed_payload, now)
        return final_failure, str(row[0]) if row else None

    def record_review(self, audit_payload: dict[str, Any]) -> bool:
        now = datetime.now(UTC).isoformat()
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                """
                UPDATE processing_jobs
                SET status = ?, updated_at = ?
                WHERE event_id = ? AND status = 'PENDING_REVIEW'
                """,
                (
                    audit_payload["verification_status"],
                    now,
                    audit_payload["event_id"],
                ),
            )
            if cursor.rowcount != 1:
                return False
            self._insert_audit_record(conn, audit_payload, now)
        self._emit_cloudwatch(audit_payload, now)
        return True

    @staticmethod
    def _insert_audit_record(
        conn: sqlite3.Connection, audit_payload: dict[str, Any], timestamp: str
    ) -> None:
        redactions = audit_payload.get("pii_redactions_performed", {})
        conn.execute(
            """
            INSERT INTO access_logs (
                timestamp, event_id, identity, status, redacted_evidence,
                pii_scrubbed_count, reviewed_by, decision_detail
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                audit_payload["event_id"],
                audit_payload["matched_identity"],
                audit_payload["verification_status"],
                audit_payload.get("sanitized_evidence", ""),
                sum(redactions.values()),
                audit_payload.get("reviewed_by"),
                audit_payload.get("decision_detail"),
            ),
        )

    def _emit_cloudwatch(self, audit_payload: dict[str, Any], timestamp: str) -> None:
        if not self.cloudwatch_enabled or self.cw_client is None:
            return
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            attempted = conn.execute(
                "SELECT attempted_events FROM cloudwatch_usage WHERE id = 1"
            ).fetchone()[0]
            if attempted >= CLOUDWATCH_EVENT_LIMIT:
                return
            conn.execute(
                "UPDATE cloudwatch_usage SET attempted_events = attempted_events + 1 WHERE id = 1"
            )

        stream_name = f"audit-{datetime.now(UTC).strftime('%Y-%m-%d')}"
        try:
            try:
                self.cw_client.create_log_stream(
                    logGroupName=CLOUDWATCH_LOG_GROUP,
                    logStreamName=stream_name,
                )
            except self.cw_client.exceptions.ResourceAlreadyExistsException:
                pass
            self.cw_client.put_log_events(
                logGroupName=CLOUDWATCH_LOG_GROUP,
                logStreamName=stream_name,
                logEvents=[
                    {
                        "timestamp": int(time.time() * 1000),
                        "message": json.dumps(
                            {
                                "timestamp": timestamp,
                                "event_id": audit_payload["event_id"],
                                "verification_status": audit_payload["verification_status"],
                                "pii_redaction_count": sum(
                                    audit_payload.get("pii_redactions_performed", {}).values()
                                ),
                            },
                            separators=(",", ":"),
                        ),
                    }
                ],
            )
        except (BotoCoreError, ClientError) as error:
            print(f"CloudWatch audit emission failed: {error}", file=sys.stderr)

    def commit_record(self, audit_payload: dict[str, Any]) -> None:
        now = datetime.now(UTC).isoformat()
        with self._connection() as conn:
            self._insert_audit_record(conn, audit_payload, now)
        self._emit_cloudwatch(audit_payload, now)
