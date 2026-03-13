"""Prompt injection attack detector.

Detects attempts to hijack LLM behaviour by injecting instructions into
user-supplied text.  Covers:

- Direct instruction overrides ("ignore all previous instructions")
- Role / persona hijacking
- System prompt exfiltration requests
- Conversation-structure delimiter injection
- Indirect / document-embedded injection
- Command-execution attempts
- Hidden Unicode steganography
- Encoding/obfuscation tricks
- Many-shot / context-stuffing attacks
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .models import InjectionResult, Severity, _SEVERITY_ORDER


@dataclass
class InjectionPattern:
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    description: str


# ---------------------------------------------------------------------------
# Pattern library
# ---------------------------------------------------------------------------

_RAW: list[tuple[str, str, Severity, str]] = [
    # ── Direct instruction override ─────────────────────────────────────────
    (
        "ignore_instructions",
        r"(?i)\b(ignore|disregard|forget|override|bypass)\b.{0,40}"
        r"\b(previous|prior|above|all|any|system|original)\b.{0,40}"
        r"\b(instruction|prompt|rule|guideline|directive|constraint)s?\b",
        Severity.CRITICAL,
        "Attempt to ignore or override previous instructions",
    ),
    (
        "new_instructions",
        r"(?i)\b(new|updated|actual|real|true)\b.{0,30}"
        r"\b(instruction|directive|rule|system\s+prompt|prompt)s?\b",
        Severity.HIGH,
        "Attempt to replace instructions with new ones",
    ),
    # ── Role / persona hijacking ────────────────────────────────────────────
    (
        "role_override",
        r"(?i)\byou\s+(are|must|should|will|shall)\s+(now\s+|henceforth\s+|from\s+now\s+on\s+)?"
        r"(act|behave|pretend|respond|operate|function)\b.{0,60}\b(as|like)\b",
        Severity.HIGH,
        "Attempt to force a new persona or role",
    ),
    (
        "jailbreak_prefix",
        r"(?i)\b(act\s+as|pretend\s+(you\s+are|to\s+be)|you\s+are\s+now|roleplay\s+as|simulate\s+being)\b"
        r".{0,80}\b(ai|model|assistant|gpt|llm|bot|system)\b",
        Severity.HIGH,
        "Persona substitution targeting AI identity",
    ),
    # ── System prompt exfiltration ──────────────────────────────────────────
    (
        "prompt_leak",
        r"(?i)\b(repeat|print|output|reveal|show|display|write\s+out|tell\s+me)\b.{0,60}"
        r"\b(system\s+prompt|system\s+message|initial\s+prompt|original\s+prompt"
        r"|instructions\s+you\s+(were|have\s+been)\s+given|your\s+(prompt|instructions))\b",
        Severity.CRITICAL,
        "Attempt to exfiltrate the system prompt",
    ),
    # ── Delimiter injection ─────────────────────────────────────────────────
    (
        "delimiter_injection",
        r"(?i)(</?(?:system|user|assistant|human|ai|context|instruction|prompt)>"
        r"|\[INST\]|\[/INST\]"
        r"|<\|im_start\|>|<\|im_end\|>"
        r"|###\s*(?:System|Human|Assistant|Instruction)"
        r"|<<SYS>>|<</SYS>>)",
        Severity.CRITICAL,
        "Injection of conversation-structure delimiters",
    ),
    # ── Indirect / document-embedded injection ──────────────────────────────
    (
        "indirect_injection",
        r"(?i)(when\s+you\s+(read|process|analyze|summarize)\s+this"
        r"|the\s+(following|above)\s+(text|document|content)\s+(contain|has|includes?)"
        r"\s+(hidden\s+|secret\s+|special\s+)?(instruction|command|directive)s?)",
        Severity.HIGH,
        "Indirect prompt injection via document content",
    ),
    # ── Command execution ───────────────────────────────────────────────────
    (
        "command_execution",
        r"(?i)\b(execute|run|eval|call|invoke)\b.{0,40}"
        r"\b(command|script|code|function|system|shell|bash|python|powershell)\b",
        Severity.HIGH,
        "Attempt to trigger code or command execution",
    ),
    # ── Hidden Unicode characters ────────────────────────────────────────────
    (
        "hidden_unicode",
        r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]",
        Severity.MEDIUM,
        "Hidden Unicode control characters detected",
    ),
    # ── Encoding / obfuscation ───────────────────────────────────────────────
    (
        "encoding_bypass",
        r"(?i)\b(base64|b64|hex.?encod|rot.?13|cipher)\b.{0,60}"
        r"\b(decode|decrypt|interpret|run|execute|follow)\b",
        Severity.MEDIUM,
        "Attempt to smuggle instructions via encoding",
    ),
    # ── Many-shot / context stuffing ────────────────────────────────────────
    (
        "context_stuffing",
        r"(?i)(human|user|assistant|ai):\s.{0,200}"
        r"(human|user|assistant|ai):\s.{0,200}"
        r"(human|user|assistant|ai):",
        Severity.MEDIUM,
        "Simulated conversation history injection",
    ),
]

_PATTERNS: list[InjectionPattern] = [
    InjectionPattern(
        name=name,
        pattern=re.compile(pat, re.DOTALL),
        severity=sev,
        description=desc,
    )
    for name, pat, sev, desc in _RAW
]


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class InjectionDetector:
    """Detect prompt injection attacks in text.

    Parameters
    ----------
    threshold:
        Minimum :class:`~guardrails.Severity` to flag as a detection.
        Patterns below the threshold are silently skipped.
        Default: ``Severity.MEDIUM``.
    custom_patterns:
        Extra ``(name, regex_str, severity, description)`` tuples appended
        to the built-in library.
    """

    def __init__(
        self,
        threshold: Severity = Severity.MEDIUM,
        custom_patterns: Optional[list[tuple[str, str, Severity, str]]] = None,
    ) -> None:
        self.threshold = threshold
        self._patterns: list[InjectionPattern] = list(_PATTERNS)

        if custom_patterns:
            for name, pat, sev, desc in custom_patterns:
                self._patterns.append(
                    InjectionPattern(
                        name=name,
                        pattern=re.compile(pat, re.DOTALL),
                        severity=sev,
                        description=desc,
                    )
                )

    def scan(self, text: str) -> InjectionResult:
        """Scan *text* for prompt injection patterns.

        Returns
        -------
        InjectionResult
            ``detected`` is ``True`` when ≥1 pattern at/above
            ``self.threshold`` matched.
        """
        matched: list[InjectionPattern] = []

        for pat in self._patterns:
            if _SEVERITY_ORDER[pat.severity] < _SEVERITY_ORDER[self.threshold]:
                continue
            if pat.pattern.search(text):
                matched.append(pat)

        if not matched:
            return InjectionResult(detected=False)

        top = max(matched, key=lambda p: _SEVERITY_ORDER[p.severity])
        return InjectionResult(
            detected=True,
            severity=top.severity,
            matched_patterns=[p.name for p in matched],
            explanation="; ".join(f"{p.name}: {p.description}" for p in matched),
        )
