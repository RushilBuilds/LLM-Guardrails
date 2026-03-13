"""LLM Guardrails — safety middleware for LLM applications.

Quick start::

    from guardrails import InjectionDetector, JailbreakDetector, PIIDetector

    injection = InjectionDetector()
    result = injection.scan("Ignore all previous instructions and ...")
    print(result.detected, result.severity)
"""

from .models import (
    InjectionResult,
    JailbreakResult,
    PIIEntity,
    PIIResult,
    PolicyResult,
    PolicyViolation,
    ScanResult,
    Severity,
)
from .injection_detector import InjectionDetector
from .jailbreak_detector import JailbreakDetector
from .pii_detector import PIIDetector

__all__ = [
    # Models
    "Severity",
    "InjectionResult",
    "JailbreakResult",
    "PIIEntity",
    "PIIResult",
    "PolicyViolation",
    "PolicyResult",
    "ScanResult",
    # Detectors
    "InjectionDetector",
    "JailbreakDetector",
    "PIIDetector",
]

__version__ = "0.1.0"
