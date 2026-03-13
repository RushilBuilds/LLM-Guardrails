"""PII (Personally Identifiable Information) detector.

Detects and optionally redacts the following entity types:

+-----------------+--------------------------------------------------+
| Entity type     | What it matches                                  |
+=================+==================================================+
| EMAIL           | RFC-5321-style email addresses                   |
| PHONE_US        | US phone numbers (various formats)               |
| SSN             | US Social Security Numbers  (NNN-NN-NNNN)        |
| CREDIT_CARD     | Visa / MC / Amex / Discover (Luhn validated)     |
| IP_V4           | IPv4 addresses                                   |
| IP_V6           | Abbreviated / full IPv6 addresses                |
| DATE_OF_BIRTH   | Dates labelled as DOB / "date of birth" / etc.   |
| PASSPORT        | Passport numbers (keyword-prefixed)              |
| DRIVERS_LICENSE | US driver's licence numbers (keyword-prefixed)   |
| US_ADDRESS      | Street addresses ending with a US ZIP code       |
| IBAN            | International Bank Account Numbers               |
+-----------------+--------------------------------------------------+
"""

from __future__ import annotations

import re
from typing import Optional

from .models import PIIEntity, PIIResult


# ---------------------------------------------------------------------------
# Pattern definitions  (entity_type, compiled_pattern, redaction_placeholder)
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "EMAIL",
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        "[EMAIL]",
    ),
    (
        "PHONE_US",
        re.compile(
            r"(?<!\d)(\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}(?!\d)"
        ),
        "[PHONE]",
    ),
    (
        "SSN",
        re.compile(r"(?<!\d)\d{3}[\s\-]\d{2}[\s\-]\d{4}(?!\d)"),
        "[SSN]",
    ),
    (
        "CREDIT_CARD",
        re.compile(
            r"(?<!\d)"
            r"("
            r"4\d{3}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}"        # Visa
            r"|5[1-5]\d{2}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}"  # Mastercard
            r"|3[47]\d{2}[\s\-]?\d{6}[\s\-]?\d{5}"                # Amex
            r"|6(?:011|5\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}"  # Discover
            r")"
            r"(?!\d)"
        ),
        "[CREDIT_CARD]",
    ),
    (
        "IP_V4",
        re.compile(
            r"(?<!\d)"
            r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
            r"(?!\d)"
        ),
        "[IP_ADDRESS]",
    ),
    (
        "IP_V6",
        re.compile(
            r"(?i)(?<![:\w])"
            r"(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}"
            r"|(?:[0-9a-f]{1,4}:){1,7}:"
            r"|:(?::[0-9a-f]{1,4}){1,7}"
            r"(?![:\w])"
        ),
        "[IP_ADDRESS]",
    ),
    (
        "DATE_OF_BIRTH",
        re.compile(
            r"(?i)\b(dob|date\s+of\s+birth|born\s+on|birthday)\b.{0,20}"
            r"("
            r"\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}"
            r"|\b(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?"
            r"|jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
            r"\s+\d{1,2},?\s+\d{4}"
            r")"
        ),
        "[DATE_OF_BIRTH]",
    ),
    (
        "PASSPORT",
        re.compile(r"(?i)\bpassport\s*(?:number|no|#|num)?[:\s]*[A-Z]{1,2}\d{6,9}\b"),
        "[PASSPORT]",
    ),
    (
        "DRIVERS_LICENSE",
        re.compile(
            r"(?i)\bdriver'?s?\s*licen[sc]e\s*(?:number|no|#|num)?[:\s]*[A-Z0-9]{5,15}\b"
        ),
        "[DL_NUMBER]",
    ),
    (
        "US_ADDRESS",
        re.compile(
            r"\b\d{1,6}\s+[A-Za-z0-9\s]{3,40}"
            r"(?:street|st|avenue|ave|boulevard|blvd|road|rd|lane|ln"
            r"|drive|dr|court|ct|way|wy|place|pl|circle|cir)\b"
            r".{0,60}[A-Z]{2}\s+\d{5}(?:-\d{4})?\b",
            re.IGNORECASE,
        ),
        "[ADDRESS]",
    ),
    (
        "IBAN",
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b"),
        "[IBAN]",
    ),
]


# ---------------------------------------------------------------------------
# Luhn algorithm for credit-card validation
# ---------------------------------------------------------------------------

def _luhn_valid(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 13:
        return False
    odd = digits[-1::-2]
    even = digits[-2::-2]
    return (sum(odd) + sum(sum(divmod(d * 2, 10)) for d in even)) % 10 == 0


# ---------------------------------------------------------------------------
# Overlap resolver
# ---------------------------------------------------------------------------

def _resolve_overlaps(entities: list[PIIEntity]) -> list[PIIEntity]:
    """Keep the longest non-overlapping span when matches collide."""
    if not entities:
        return entities
    sorted_ents = sorted(entities, key=lambda e: (e.start, -(e.end - e.start)))
    result: list[PIIEntity] = []
    last_end = -1
    for e in sorted_ents:
        if e.start >= last_end:
            result.append(e)
            last_end = e.end
    return result


def _apply_redaction(text: str, entities: list[PIIEntity]) -> str:
    parts: list[str] = []
    cursor = 0
    for e in sorted(entities, key=lambda x: x.start):
        parts.append(text[cursor : e.start])
        parts.append(e.redacted_value)
        cursor = e.end
    parts.append(text[cursor:])
    return "".join(parts)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class PIIDetector:
    """Detect and optionally redact PII from text.

    Parameters
    ----------
    entities:
        Whitelist of entity types to scan for.  ``None`` (default) enables
        all built-in types.
    validate_credit_cards:
        Run Luhn check on matched card numbers.  Default ``True``.
    """

    def __init__(
        self,
        entities: Optional[list[str]] = None,
        validate_credit_cards: bool = True,
    ) -> None:
        self.validate_credit_cards = validate_credit_cards
        active = set(entities) if entities else {p[0] for p in _PATTERNS}
        self._patterns = [(t, p, r) for t, p, r in _PATTERNS if t in active]

    def scan(self, text: str, redact: bool = True) -> PIIResult:
        """Scan *text* for PII.

        Parameters
        ----------
        text:
            Input text to scan.
        redact:
            When ``True`` (default), populate ``PIIResult.redacted_text``
            with entity values replaced by placeholder tokens.

        Returns
        -------
        PIIResult
        """
        found: list[PIIEntity] = []

        for entity_type, pattern, placeholder in self._patterns:
            for m in pattern.finditer(text):
                value = m.group(0)

                if entity_type == "CREDIT_CARD" and self.validate_credit_cards:
                    if not _luhn_valid(value):
                        continue

                found.append(
                    PIIEntity(
                        entity_type=entity_type,
                        value=value,
                        start=m.start(),
                        end=m.end(),
                        redacted_value=placeholder,
                    )
                )

        found = _resolve_overlaps(found)

        redacted_text: Optional[str] = None
        if redact:
            redacted_text = _apply_redaction(text, found)

        return PIIResult(
            detected=bool(found),
            entities=found,
            redacted_text=redacted_text,
        )
