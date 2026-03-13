"""FastAPI application factory for the LLM Guardrails microservice.

Usage (development)::

    uvicorn api.app:app --reload

Environment variables
---------------------
INJECTION_THRESHOLD
    Minimum severity for injection detection (low/medium/high/critical).
    Default: ``medium``.
JAILBREAK_THRESHOLD
    Minimum severity for jailbreak detection.  Default: ``medium``.
PII_ENTITIES
    Comma-separated list of PII entity types to scan.
    Default: all built-in types.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from guardrails import (
    InjectionDetector,
    JailbreakDetector,
    PIIDetector,
    PolicyEnforcer,
    Severity,
    DEFAULT_POLICY,
)
from api.routes.health import router as health_router
from api.routes.scan import router as scan_router
import guardrails


# ---------------------------------------------------------------------------
# Lifespan — initialise detectors once at startup
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    injection_threshold = Severity(
        os.getenv("INJECTION_THRESHOLD", "medium").lower()
    )
    jailbreak_threshold = Severity(
        os.getenv("JAILBREAK_THRESHOLD", "medium").lower()
    )
    raw_pii_entities = os.getenv("PII_ENTITIES", "")
    pii_entities = [e.strip().upper() for e in raw_pii_entities.split(",") if e.strip()] or None

    app.state.injection_detector = InjectionDetector(threshold=injection_threshold)
    app.state.jailbreak_detector = JailbreakDetector(threshold=jailbreak_threshold)
    app.state.pii_detector = PIIDetector(entities=pii_entities)
    app.state.policy_enforcer = PolicyEnforcer(policy=DEFAULT_POLICY)

    yield  # application runs here

    # Cleanup (nothing stateful to release for pure-Python detectors)


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    application = FastAPI(
        title="LLM Guardrails",
        description=(
            "A microservice that detects prompt injection attacks, "
            "jailbreak attempts, PII leakage, and policy violations "
            "in text destined for or produced by an LLM."
        ),
        version=guardrails.__version__,
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.include_router(health_router)
    application.include_router(scan_router)

    return application


app = create_app()
