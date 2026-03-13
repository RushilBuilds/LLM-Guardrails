"""Shared pytest fixtures."""

import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from guardrails import (
    InjectionDetector,
    JailbreakDetector,
    PIIDetector,
    PolicyEnforcer,
    Policy,
    PolicyRule,
    RuleType,
    Severity,
)


@pytest.fixture(scope="session")
def injection_detector() -> InjectionDetector:
    return InjectionDetector()


@pytest.fixture(scope="session")
def jailbreak_detector() -> JailbreakDetector:
    return JailbreakDetector()


@pytest.fixture(scope="session")
def pii_detector() -> PIIDetector:
    return PIIDetector()


@pytest.fixture(scope="session")
def policy_enforcer() -> PolicyEnforcer:
    return PolicyEnforcer()


@pytest.fixture(scope="session")
def api_client() -> TestClient:
    app = create_app()
    with TestClient(app) as client:
        yield client
