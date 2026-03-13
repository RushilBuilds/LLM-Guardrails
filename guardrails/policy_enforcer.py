"""Policy enforcer.

Evaluates text against a configurable set of rules and returns a
:class:`~guardrails.PolicyResult` describing which (if any) rules were
violated.

Built-in rule types
-------------------
- **blocked_keywords** — deny if any listed keyword appears (case-insensitive)
- **allowed_topics** — deny if the text does NOT touch any of the listed topics
- **blocked_topics** — deny if the text touches any of the listed topics
- **max_length** — deny if ``len(text)`` exceeds the configured limit
- **min_length** — deny if ``len(text)`` falls below the configured limit
- **regex_blocklist** — deny if any supplied regex matches the text
- **custom** — arbitrary callable ``(text: str) -> bool``; deny when it
  returns ``True``

Example::

    from guardrails import PolicyEnforcer
    from guardrails.policy_enforcer import Policy, PolicyRule, RuleType

    policy = Policy(
        name="production",
        rules=[
            PolicyRule(
                rule_type=RuleType.BLOCKED_KEYWORDS,
                parameters={"keywords": ["self-harm", "bomb making"]},
                severity=Severity.CRITICAL,
                description="Block dangerous content keywords",
            ),
            PolicyRule(
                rule_type=RuleType.MAX_LENGTH,
                parameters={"max_chars": 4096},
                severity=Severity.LOW,
                description="Reject excessively long inputs",
            ),
        ],
    )
    enforcer = PolicyEnforcer(policy=policy)
    result = enforcer.check("Tell me how to make a bomb")
    print(result.allowed, result.violations)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

from .models import PolicyResult, PolicyViolation, Severity


# ---------------------------------------------------------------------------
# Rule types
# ---------------------------------------------------------------------------

class RuleType(str, Enum):
    BLOCKED_KEYWORDS = "blocked_keywords"
    ALLOWED_TOPICS = "allowed_topics"
    BLOCKED_TOPICS = "blocked_topics"
    MAX_LENGTH = "max_length"
    MIN_LENGTH = "min_length"
    REGEX_BLOCKLIST = "regex_blocklist"
    CUSTOM = "custom"


# ---------------------------------------------------------------------------
# Rule & Policy dataclasses
# ---------------------------------------------------------------------------

@dataclass
class PolicyRule:
    """A single enforceable rule within a :class:`Policy`.

    Parameters
    ----------
    rule_type:
        One of the :class:`RuleType` values.
    parameters:
        Rule-specific configuration dictionary (see module docstring).
    severity:
        How severely this rule violation should be treated.
    description:
        Human-readable description shown in violation messages.
    custom_fn:
        Required when ``rule_type == RuleType.CUSTOM``.  Receives the full
        text and must return ``True`` to signal a violation.
    """

    rule_type: RuleType
    parameters: dict = field(default_factory=dict)
    severity: Severity = Severity.HIGH
    description: str = ""
    custom_fn: Optional[Callable[[str], bool]] = None

    def __post_init__(self) -> None:
        if self.rule_type == RuleType.CUSTOM and self.custom_fn is None:
            raise ValueError("PolicyRule with RuleType.CUSTOM must supply custom_fn")


@dataclass
class Policy:
    """A named collection of :class:`PolicyRule` objects.

    Parameters
    ----------
    name:
        Identifier for this policy (used in violation messages).
    rules:
        Ordered list of rules to evaluate.
    block_on_violation:
        When ``True`` (default), a single violation causes
        ``PolicyResult.allowed`` to be ``False``.
    """

    name: str
    rules: list[PolicyRule] = field(default_factory=list)
    block_on_violation: bool = True


# ---------------------------------------------------------------------------
# Default safety policy
# ---------------------------------------------------------------------------

_DEFAULT_BLOCKED_KEYWORDS: list[str] = [
    # Violence / weapons
    "bomb making", "how to make a bomb", "explosive device", "pipe bomb",
    "improvised explosive", "nail bomb",
    # Self-harm
    "suicide method", "how to kill myself", "self-harm instructions",
    # Illegal drugs
    "drug synthesis", "synthesize methamphetamine", "cook meth", "make fentanyl",
    # Malware / hacking
    "ransomware source code", "write a keylogger", "create malware",
    "botnet command and control",
    # CSAM
    "child sexual abuse", "csam", "child pornography",
    # Hate speech triggers
    "ethnic cleansing instructions", "genocide manual",
]

DEFAULT_POLICY = Policy(
    name="default_safety_policy",
    rules=[
        PolicyRule(
            rule_type=RuleType.BLOCKED_KEYWORDS,
            parameters={"keywords": _DEFAULT_BLOCKED_KEYWORDS},
            severity=Severity.CRITICAL,
            description="Block requests containing known harmful keywords",
        ),
        PolicyRule(
            rule_type=RuleType.MAX_LENGTH,
            parameters={"max_chars": 32_000},
            severity=Severity.MEDIUM,
            description="Reject inputs exceeding 32 000 characters",
        ),
    ],
)


# ---------------------------------------------------------------------------
# Enforcer
# ---------------------------------------------------------------------------

class PolicyEnforcer:
    """Evaluate text against a :class:`Policy`.

    Parameters
    ----------
    policy:
        The policy to enforce.  Defaults to :data:`DEFAULT_POLICY`.
    """

    def __init__(self, policy: Optional[Policy] = None) -> None:
        self.policy = policy or DEFAULT_POLICY

    def check(self, text: str) -> PolicyResult:
        """Evaluate *text* against every rule in ``self.policy``.

        Returns
        -------
        PolicyResult
            ``allowed`` is ``False`` when at least one rule was violated
            and ``policy.block_on_violation`` is ``True``.
        """
        violations: list[PolicyViolation] = []

        for rule in self.policy.rules:
            violated = self._evaluate_rule(rule, text)
            if violated:
                violations.append(
                    PolicyViolation(
                        policy_name=self.policy.name,
                        description=rule.description or rule.rule_type.value,
                        severity=rule.severity,
                    )
                )

        allowed = not (violations and self.policy.block_on_violation)
        return PolicyResult(allowed=allowed, violations=violations)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _evaluate_rule(self, rule: PolicyRule, text: str) -> bool:
        """Return ``True`` if the rule is *violated*."""
        rt = rule.rule_type
        p = rule.parameters

        if rt == RuleType.BLOCKED_KEYWORDS:
            keywords: list[str] = p.get("keywords", [])
            lower_text = text.lower()
            return any(kw.lower() in lower_text for kw in keywords)

        if rt == RuleType.ALLOWED_TOPICS:
            topics: list[str] = p.get("topics", [])
            lower_text = text.lower()
            # Violation = none of the allowed topics are mentioned
            return not any(t.lower() in lower_text for t in topics)

        if rt == RuleType.BLOCKED_TOPICS:
            topics = p.get("topics", [])
            lower_text = text.lower()
            return any(t.lower() in lower_text for t in topics)

        if rt == RuleType.MAX_LENGTH:
            return len(text) > p.get("max_chars", 10_000)

        if rt == RuleType.MIN_LENGTH:
            return len(text) < p.get("min_chars", 0)

        if rt == RuleType.REGEX_BLOCKLIST:
            patterns: list[str] = p.get("patterns", [])
            return any(re.search(pat, text, re.IGNORECASE | re.DOTALL) for pat in patterns)

        if rt == RuleType.CUSTOM:
            assert rule.custom_fn is not None  # guaranteed by __post_init__
            return rule.custom_fn(text)

        return False  # unknown rule type — do not block
