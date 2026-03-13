"""Pydantic request/response schemas for the guardrails API."""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field

from guardrails.models import Severity


# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    """Body of a POST /scan request."""

    text: str = Field(..., min_length=1, description="Text to scan")

    # Feature flags — all enabled by default
    check_injection: bool = Field(True, description="Run prompt-injection detection")
    check_jailbreak: bool = Field(True, description="Run jailbreak detection")
    check_pii: bool = Field(True, description="Run PII detection")
    check_policy: bool = Field(True, description="Run policy enforcement")

    # Detection thresholds
    injection_threshold: Severity = Field(
        Severity.MEDIUM, description="Minimum severity to flag injection"
    )
    jailbreak_threshold: Severity = Field(
        Severity.MEDIUM, description="Minimum severity to flag jailbreak"
    )

    # PII options
    redact_pii: bool = Field(True, description="Replace PII with placeholder tokens")
    pii_entities: Optional[list[str]] = Field(
        None, description="PII entity types to scan (None = all)"
    )


# ---------------------------------------------------------------------------
# Sub-responses
# ---------------------------------------------------------------------------

class InjectionResponse(BaseModel):
    detected: bool
    severity: Optional[Severity] = None
    matched_patterns: list[str] = []
    explanation: str = ""


class JailbreakResponse(BaseModel):
    detected: bool
    severity: Optional[Severity] = None
    technique: Optional[str] = None
    matched_patterns: list[str] = []
    explanation: str = ""


class PIIEntityResponse(BaseModel):
    entity_type: str
    start: int
    end: int
    redacted_value: str


class PIIResponse(BaseModel):
    detected: bool
    entities: list[PIIEntityResponse] = []
    redacted_text: Optional[str] = None


class PolicyViolationResponse(BaseModel):
    policy_name: str
    description: str
    severity: Severity


class PolicyResponse(BaseModel):
    allowed: bool
    violations: list[PolicyViolationResponse] = []


# ---------------------------------------------------------------------------
# Top-level response
# ---------------------------------------------------------------------------

class ScanResponse(BaseModel):
    """Full result of a /scan request."""

    text: str = Field(..., description="Original input text")
    blocked: bool = Field(..., description="True when the pipeline rejected the text")
    block_reasons: list[str] = Field(default_factory=list)
    is_safe: bool = Field(..., description="False when injection, jailbreak, or policy blocked")

    injection: Optional[InjectionResponse] = None
    jailbreak: Optional[JailbreakResponse] = None
    pii: Optional[PIIResponse] = None
    policy: Optional[PolicyResponse] = None


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
