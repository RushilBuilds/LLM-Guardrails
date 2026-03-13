"""Tests for PIIDetector."""

import pytest

from guardrails import PIIDetector
from guardrails.models import PIIResult


# ---------------------------------------------------------------------------
# Positive cases — PII SHOULD be detected
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("entity_type, text", [
    ("EMAIL", "Contact me at alice@example.com for more details."),
    ("EMAIL", "Send the report to bob.smith+filter@corp.co.uk"),
    ("PHONE_US", "Call us at (555) 867-5309 any time."),
    ("PHONE_US", "My number is 800-555-0199."),
    ("SSN", "SSN: 123-45-6789"),
    ("SSN", "Social security number 987 65 4321"),
    ("IP_V4", "Server IP is 192.168.1.100"),
    ("IP_V4", "Connect to 10.0.0.1 for the VPN."),
    ("DATE_OF_BIRTH", "DOB: 01/15/1990"),
    ("DATE_OF_BIRTH", "My date of birth is March 5, 1985"),
    ("PASSPORT", "Passport number: AB1234567"),
    ("DRIVERS_LICENSE", "Driver's license: X12345678"),
    ("IBAN", "Bank account: GB82WEST12345698765432"),
])
def test_detects_pii_entity(pii_detector: PIIDetector, entity_type: str, text: str) -> None:
    result = pii_detector.scan(text)
    assert result.detected, f"Expected {entity_type} PII in: {text!r}"
    types = [e.entity_type for e in result.entities]
    assert entity_type in types, f"Expected entity type '{entity_type}', got {types}"


# ---------------------------------------------------------------------------
# Negative cases — no PII
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "The quick brown fox jumps over the lazy dog.",
    "Today is a great day for a walk.",
    "The conference starts at 9am.",
    "Python version 3.11 was released in October 2022.",
])
def test_no_pii_in_clean_text(pii_detector: PIIDetector, text: str) -> None:
    result = pii_detector.scan(text)
    assert not result.detected, f"False PII positive on: {text!r}"


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

def test_email_is_redacted() -> None:
    detector = PIIDetector()
    result = detector.scan("Email me at test@example.com please.", redact=True)
    assert result.redacted_text is not None
    assert "test@example.com" not in result.redacted_text
    assert "[EMAIL]" in result.redacted_text


def test_redact_false_does_not_populate_redacted_text() -> None:
    detector = PIIDetector()
    result = detector.scan("Email me at test@example.com please.", redact=False)
    assert result.redacted_text is None


def test_multiple_entities_redacted() -> None:
    detector = PIIDetector()
    text = "Call (555) 123-4567 or email me at foo@bar.com"
    result = detector.scan(text, redact=True)
    assert result.redacted_text is not None
    assert "foo@bar.com" not in result.redacted_text
    assert "555" not in result.redacted_text or "[PHONE]" in result.redacted_text


# ---------------------------------------------------------------------------
# Entity filtering
# ---------------------------------------------------------------------------

def test_entity_filter_limits_detection() -> None:
    detector = PIIDetector(entities=["EMAIL"])
    text = "Email: test@example.com  Phone: (555) 867-5309"
    result = detector.scan(text)
    types = {e.entity_type for e in result.entities}
    assert "EMAIL" in types
    assert "PHONE_US" not in types


# ---------------------------------------------------------------------------
# Credit card Luhn validation
# ---------------------------------------------------------------------------

def test_invalid_luhn_not_flagged() -> None:
    """A syntactically valid but Luhn-failing card number should not be reported."""
    detector = PIIDetector()
    # This looks like a Visa but fails Luhn
    result = detector.scan("Card: 4111111111111112")
    types = [e.entity_type for e in result.entities]
    assert "CREDIT_CARD" not in types


def test_valid_luhn_is_flagged() -> None:
    """Standard Luhn-valid Visa test number."""
    detector = PIIDetector()
    result = detector.scan("Card number: 4111111111111111")
    types = [e.entity_type for e in result.entities]
    assert "CREDIT_CARD" in types


# ---------------------------------------------------------------------------
# Overlap resolution
# ---------------------------------------------------------------------------

def test_no_duplicate_entity_spans() -> None:
    detector = PIIDetector()
    text = "Reach me at user@domain.com"
    result = detector.scan(text)
    starts = [e.start for e in result.entities]
    assert len(starts) == len(set(starts)), "Duplicate entity starts detected"
