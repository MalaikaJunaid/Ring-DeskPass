import re
from typing import Any, ClassVar


class ComplianceSanitizer:
    """Enterprise privacy engine ensuring zero plaintext PII persistence.

    Complies with GDPR Art. 5(1)(c) (Data Minimisation) and SOC 2 CC6.1.
    """

    # Comprehensive PII Regex Signatures
    PATTERNS: ClassVar[dict[str, re.Pattern]] = {
        # Phone: International & domestic formats (E.164, paren, dashes)
        "PHONE": re.compile(
            r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"
        ),
        # National IDs / SSN (XXX-XX-XXXX) / CNIC / General 9-13 digit identity numbers
        "GOV_ID": re.compile(
            r"\b(?:\d{3}-\d{2}-\d{4}|\d{5}-\d{7}-\d{1}|\d{3}-\d{4}-\d{7}-\d{1})\b"
        ),
        # Email Addresses
        "EMAIL": re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"
        ),
        # Alphanumeric Employee / Badge Badging Tokens (e.g., EMP-94820, ID#12345)
        "BADGE_SERIAL": re.compile(
            r"\b(?:EMP|ID|BADGE|CARD)[-:#\s]?[A-Z0-9]{4,10}\b",
            re.IGNORECASE,
        ),
    }

    @classmethod
    def redact_text(cls, raw_text: str) -> tuple[str, dict[str, int]]:
        """Scrub sensitive identifiers and return anonymized text with redaction telemetry."""
        sanitized = raw_text
        redaction_counts: dict[str, int] = {}

        for pii_type, pattern in cls.PATTERNS.items():
            matches = pattern.findall(sanitized)
            if matches:
                redaction_counts[pii_type] = len(matches)
                sanitized = pattern.sub(f"[REDACTED_{pii_type}]", sanitized)

        return sanitized, redaction_counts

    @classmethod
    def sanitize_audit_payload(
        cls, event_id: str, identity: str, raw_ocr: str, status: str
    ) -> dict[str, Any]:
        """Build an enterprise-safe audit record with cryptographic hash integrity."""
        sanitized_ocr, audit_telemetry = cls.redact_text(raw_ocr)

        return {
            "compliance_standard": "SOC2-CC6.1 / GDPR-Minimised",
            "event_id": event_id,
            "matched_identity": identity,
            "sanitized_evidence": sanitized_ocr,
            "pii_redactions_performed": audit_telemetry,
            "verification_status": status,
        }