"""Shared data models for all guardrail results.

Every detector and enforcer in this library returns one of the result types
defined here, so callers only need to import from a single place.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Ordered threat-severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __ge__(self, other: "Severity") -> bool:  # type: ignore[override]
        return _SEVERITY_ORDER[self] >= _SEVERITY_ORDER[other]

    def __gt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return _SEVERITY_ORDER[self] > _SEVERITY_ORDER[other]

    def __le__(self, other: "Severity") -> bool:  # type: ignore[override]
        return _SEVERITY_ORDER[self] <= _SEVERITY_ORDER[other]

    def __lt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return _SEVERITY_ORDER[self] < _SEVERITY_ORDER[other]


_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


# ---------------------------------------------------------------------------
# Injection detection result
# ---------------------------------------------------------------------------

@dataclass
class InjectionResult:
    """Result of a prompt-injection scan."""

    detected: bool
    severity: Optional[Severity] = None
    matched_patterns: list[str] = field(default_factory=list)
    explanation: str = ""


# ---------------------------------------------------------------------------
# Jailbreak detection result
# ---------------------------------------------------------------------------

@dataclass
class JailbreakResult:
    """Result of a jailbreak-attempt scan."""

    detected: bool
    severity: Optional[Severity] = None
    technique: Optional[str] = None
    matched_patterns: list[str] = field(default_factory=list)
    explanation: str = ""


# ---------------------------------------------------------------------------
# PII detection result
# ---------------------------------------------------------------------------

@dataclass
class PIIEntity:
    """A single PII entity found in text."""

    entity_type: str
    value: str
    start: int
    end: int
    redacted_value: str = "[REDACTED]"


@dataclass
class PIIResult:
    """Result of a PII scan."""

    detected: bool
    entities: list[PIIEntity] = field(default_factory=list)
    redacted_text: Optional[str] = None


# ---------------------------------------------------------------------------
# Policy enforcement result
# ---------------------------------------------------------------------------

@dataclass
class PolicyViolation:
    """A single policy rule that was violated."""

    policy_name: str
    description: str
    severity: Severity


@dataclass
class PolicyResult:
    """Result of a policy-enforcement check."""

    allowed: bool
    violations: list[PolicyViolation] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Composite scan result
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """Aggregated result of running all enabled guardrails on a piece of text.

    Attributes
    ----------
    text:
        The original input text that was scanned.
    injection:
        Result from :class:`~guardrails.InjectionDetector`, or ``None`` if
        injection scanning was not enabled.
    jailbreak:
        Result from :class:`~guardrails.JailbreakDetector`, or ``None`` if
        jailbreak scanning was not enabled.
    pii:
        Result from :class:`~guardrails.PIIDetector`, or ``None`` if PII
        scanning was not enabled.
    policy:
        Result from :class:`~guardrails.PolicyEnforcer`, or ``None`` if policy
        enforcement was not enabled.
    blocked:
        ``True`` when the pipeline determined the text should be rejected.
    block_reasons:
        Human-readable list of reasons the text was blocked.
    """

    text: str
    injection: Optional[InjectionResult] = None
    jailbreak: Optional[JailbreakResult] = None
    pii: Optional[PIIResult] = None
    policy: Optional[PolicyResult] = None
    blocked: bool = False
    block_reasons: list[str] = field(default_factory=list)

    def is_safe(self) -> bool:
        """Return ``True`` when no blocking threat was detected."""
        if self.injection and self.injection.detected:
            return False
        if self.jailbreak and self.jailbreak.detected:
            return False
        if self.policy and not self.policy.allowed:
            return False
        return True
