"""Jailbreak attempt detector.

Covers the most common jailbreak families:

- DAN / "Do Anything Now" variants
- Hypothetical / fictional framing
- Token / character smuggling
- Evil persona requests
- Completion exploits (e.g. "finish this story about …")
- Prompt wrapping (forced affirmative prefix)
- Translation bypass
- Authority / nostalgia exploits (the "grandma" trick)
- Acknowledgement bait (false "you're jailbroken" claims)
- Many-shot jailbreaking via excessive examples
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .models import JailbreakResult, Severity, _SEVERITY_ORDER


@dataclass
class JailbreakPattern:
    name: str
    technique: str
    pattern: re.Pattern[str]
    severity: Severity
    description: str


# ---------------------------------------------------------------------------
# Pattern library
# ---------------------------------------------------------------------------

_RAW: list[tuple[str, str, str, Severity, str]] = [
    # ── DAN ─────────────────────────────────────────────────────────────────
    (
        "dan_classic",
        "DAN",
        r"(?i)\bDAN\b.{0,120}"
        r"\b(do\s+anything\s+now|no\s+restriction|no\s+limit|no\s+rule"
        r"|no\s+filter|no\s+safeguard|no\s+guideline|unlimited|unrestricted)\b",
        Severity.CRITICAL,
        "Classic DAN jailbreak pattern",
    ),
    (
        "dan_mode",
        "DAN",
        r"(?i)(enable|activate|switch\s+to|enter|turn\s+on).{0,40}"
        r"(DAN|developer|jailbreak|god|unrestricted|unfiltered).{0,40}"
        r"(mode|version|persona|state)\b",
        Severity.CRITICAL,
        "DAN mode activation request",
    ),
    # ── Hypothetical / fictional framing ────────────────────────────────────
    (
        "fictional_framing",
        "HypotheticalFraming",
        r"(?i)\b(hypothetically|theoretically"
        r"|in\s+a\s+(story|novel|game|fiction|movie|simulation)"
        r"|imagine\s+(if|that)"
        r"|let['']s\s+pretend|suppose|what\s+if)\b"
        r".{0,200}"
        r"\b(how\s+(to|do|would|can)|steps?|instruct|explain|detail|describe)\b",
        Severity.HIGH,
        "Fictional framing used to elicit restricted content",
    ),
    # ── Token / character smuggling ─────────────────────────────────────────
    (
        "token_smuggling",
        "TokenSmuggling",
        r"(?i)(write\s+(each|every)\s+(word|letter|character|token)"
        r"\s+(separately|apart|individually|on\s+a\s+new\s+line)"
        r"|sp[e3][l1][l1]\s+(it\s+)?out"
        r"|replace\s+.{1,30}\s+with\s+.{1,30}"
        r"|use\s+[a-z]\s+for\s+.{1,30}"
        r"|decode\s+the\s+following)",
        Severity.HIGH,
        "Smuggling restricted tokens via character/encoding substitution",
    ),
    # ── Evil / uncensored persona ────────────────────────────────────────────
    (
        "evil_persona",
        "PersonaPlay",
        r"(?i)\b(evil|malicious|unethical|amoral|uncensored|unfiltered"
        r"|rogue|dark|shadow|opposite|reverse)\b.{0,50}"
        r"\b(version|mode|ai|assistant|persona|self|alter\s*ego)\b",
        Severity.HIGH,
        "Request for an unfiltered or evil AI persona",
    ),
    (
        "opposite_instructions",
        "PersonaPlay",
        r"(?i)\b(do\s+the\s+opposite|reverse\s+your\s+(training|rules|guidelines|instructions)"
        r"|act\s+against\s+your\s+(programming|design|values))\b",
        Severity.HIGH,
        "Request to act against core guidelines",
    ),
    # ── Completion exploit ───────────────────────────────────────────────────
    (
        "completion_exploit",
        "CompletionExploit",
        r"(?i)(complete\s+(this|the\s+following)\s+(sentence|text|code|story|paragraph)"
        r".{0,200}"
        r"(bomb|weapon|hack|malware|exploit|drug|synthesis|poison))",
        Severity.HIGH,
        "Completion exploit leading to harmful content",
    ),
    # ── Prompt wrapping ──────────────────────────────────────────────────────
    (
        "prompt_wrapping",
        "PromptWrapping",
        r"(?i)(start\s+your\s+(response|answer|reply|output|message)\s+with"
        r".{0,80}"
        r"(yes|sure|of\s+course|absolutely|I\s+will|I\s+can|I['']ll|here|gladly))",
        Severity.MEDIUM,
        "Forced affirmative prefix to bypass refusals",
    ),
    # ── Translation bypass ───────────────────────────────────────────────────
    (
        "translation_bypass",
        "TranslationBypass",
        r"(?i)(translate\s+(to|into|from).{0,30}(then|and\s+then|before|after)"
        r".{0,60}(do|perform|execute|answer|explain|describe)"
        r"|answer\s+(in|using).{0,20}(language|code|cipher)"
        r"\s+(to\s+avoid|to\s+bypass|so\s+(you|the)?\s*filter))",
        Severity.MEDIUM,
        "Using translation to bypass content filters",
    ),
    # ── Authority / nostalgia exploit ────────────────────────────────────────
    (
        "authority_exploit",
        "AuthorityExploit",
        r"(?i)(my\s+(grandmother|grandma|teacher|professor|boss|manager|ceo"
        r"|doctor|lawyer|therapist).{0,80}"
        r"(used\s+to|would|always|told\s+me|said).{0,80}"
        r"(tell|explain|describe|show|how\s+to|steps?|instructions?))",
        Severity.MEDIUM,
        "Authority/nostalgia exploit to extract restricted information",
    ),
    # ── Acknowledgement bait ─────────────────────────────────────────────────
    (
        "jailbreak_success_bait",
        "AcknowledgementBait",
        r"(?i)(you\s+(have\s+been|are\s+now|were\s+just)\s+jailbroken"
        r"|jailbreak\s+(successful|complete|activated|engaged)"
        r"|congratulations.{0,50}free(d|dom)"
        r"|your\s+(chains|shackles|restriction|limit).{0,40}"
        r"(removed|lifted|gone|broken|unlocked))",
        Severity.CRITICAL,
        "False jailbreak-success claim to induce compliance",
    ),
    # ── Many-shot jailbreak ──────────────────────────────────────────────────
    (
        "many_shot_jailbreak",
        "ManyShotJailbreak",
        r"(?i)(example\s+\d{1,3}:.{0,300}){5,}",
        Severity.HIGH,
        "Many-shot jailbreak via excessive fabricated examples",
    ),
]

_PATTERNS: list[JailbreakPattern] = [
    JailbreakPattern(
        name=name,
        technique=technique,
        pattern=re.compile(pat, re.DOTALL),
        severity=sev,
        description=desc,
    )
    for name, technique, pat, sev, desc in _RAW
]


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class JailbreakDetector:
    """Detect jailbreak attempts in user text.

    Parameters
    ----------
    threshold:
        Minimum :class:`~guardrails.Severity` to report.
        Default: ``Severity.MEDIUM``.
    custom_patterns:
        Extra ``(name, technique, regex_str, severity, description)`` tuples.
    """

    def __init__(
        self,
        threshold: Severity = Severity.MEDIUM,
        custom_patterns: Optional[list[tuple[str, str, str, Severity, str]]] = None,
    ) -> None:
        self.threshold = threshold
        self._patterns: list[JailbreakPattern] = list(_PATTERNS)

        if custom_patterns:
            for name, technique, pat, sev, desc in custom_patterns:
                self._patterns.append(
                    JailbreakPattern(
                        name=name,
                        technique=technique,
                        pattern=re.compile(pat, re.DOTALL),
                        severity=sev,
                        description=desc,
                    )
                )

    def scan(self, text: str) -> JailbreakResult:
        """Scan *text* for jailbreak patterns."""
        matched: list[JailbreakPattern] = []

        for pat in self._patterns:
            if _SEVERITY_ORDER[pat.severity] < _SEVERITY_ORDER[self.threshold]:
                continue
            if pat.pattern.search(text):
                matched.append(pat)

        if not matched:
            return JailbreakResult(detected=False)

        top = max(matched, key=lambda p: _SEVERITY_ORDER[p.severity])
        techniques = ", ".join(sorted({p.technique for p in matched}))
        return JailbreakResult(
            detected=True,
            severity=top.severity,
            technique=techniques,
            matched_patterns=[p.name for p in matched],
            explanation="; ".join(f"{p.name}: {p.description}" for p in matched),
        )
