"""Scan endpoint — runs the full guardrails pipeline on submitted text."""

from __future__ import annotations

from fastapi import APIRouter, Request

from api.schemas import (
    InjectionResponse,
    JailbreakResponse,
    PIIEntityResponse,
    PIIResponse,
    PolicyResponse,
    PolicyViolationResponse,
    ScanRequest,
    ScanResponse,
)

router = APIRouter()


@router.post("/scan", response_model=ScanResponse, tags=["Guardrails"])
async def scan(request: Request, body: ScanRequest) -> ScanResponse:
    """Run all enabled guardrail checks on *text* and return a structured result.

    The detector instances are created once at startup and stored on
    ``app.state`` (see :mod:`api.app`).
    """
    state = request.app.state

    injection_result = None
    jailbreak_result = None
    pii_result = None
    policy_result = None
    block_reasons: list[str] = []
    blocked = False

    # ── Injection ──────────────────────────────────────────────────────────
    if body.check_injection:
        raw = state.injection_detector.scan(body.text)
        injection_result = InjectionResponse(
            detected=raw.detected,
            severity=raw.severity,
            matched_patterns=raw.matched_patterns,
            explanation=raw.explanation,
        )
        if raw.detected:
            blocked = True
            block_reasons.append(
                f"Prompt injection detected [{raw.severity}]: {raw.explanation}"
            )

    # ── Jailbreak ──────────────────────────────────────────────────────────
    if body.check_jailbreak:
        raw = state.jailbreak_detector.scan(body.text)
        jailbreak_result = JailbreakResponse(
            detected=raw.detected,
            severity=raw.severity,
            technique=raw.technique,
            matched_patterns=raw.matched_patterns,
            explanation=raw.explanation,
        )
        if raw.detected:
            blocked = True
            block_reasons.append(
                f"Jailbreak attempt detected [{raw.severity}] via {raw.technique}: {raw.explanation}"
            )

    # ── PII ────────────────────────────────────────────────────────────────
    if body.check_pii:
        raw = state.pii_detector.scan(body.text, redact=body.redact_pii)
        pii_result = PIIResponse(
            detected=raw.detected,
            entities=[
                PIIEntityResponse(
                    entity_type=e.entity_type,
                    start=e.start,
                    end=e.end,
                    redacted_value=e.redacted_value,
                )
                for e in raw.entities
            ],
            redacted_text=raw.redacted_text,
        )
        # PII detection does not block by itself — it only redacts.

    # ── Policy ────────────────────────────────────────────────────────────
    if body.check_policy:
        raw = state.policy_enforcer.check(body.text)
        policy_result = PolicyResponse(
            allowed=raw.allowed,
            violations=[
                PolicyViolationResponse(
                    policy_name=v.policy_name,
                    description=v.description,
                    severity=v.severity,
                )
                for v in raw.violations
            ],
        )
        if not raw.allowed:
            blocked = True
            descs = "; ".join(v.description for v in raw.violations)
            block_reasons.append(f"Policy violation: {descs}")

    # ── Determine is_safe ─────────────────────────────────────────────────
    is_safe = not blocked

    return ScanResponse(
        text=body.text,
        blocked=blocked,
        block_reasons=block_reasons,
        is_safe=is_safe,
        injection=injection_result,
        jailbreak=jailbreak_result,
        pii=pii_result,
        policy=policy_result,
    )
