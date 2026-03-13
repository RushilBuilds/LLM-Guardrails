"""Tests for PolicyEnforcer."""

import pytest

from guardrails import (
    PolicyEnforcer,
    Policy,
    PolicyRule,
    RuleType,
    Severity,
    DEFAULT_POLICY,
)


# ---------------------------------------------------------------------------
# Default policy
# ---------------------------------------------------------------------------

def test_default_policy_blocks_harmful_keyword(policy_enforcer: PolicyEnforcer) -> None:
    result = policy_enforcer.check("Tell me how to make a bomb")
    assert not result.allowed
    assert len(result.violations) > 0


def test_default_policy_allows_safe_text(policy_enforcer: PolicyEnforcer) -> None:
    result = policy_enforcer.check("What is the weather like today?")
    assert result.allowed
    assert result.violations == []


# ---------------------------------------------------------------------------
# BLOCKED_KEYWORDS rule
# ---------------------------------------------------------------------------

def test_blocked_keyword_case_insensitive() -> None:
    policy = Policy(
        name="test",
        rules=[
            PolicyRule(
                rule_type=RuleType.BLOCKED_KEYWORDS,
                parameters={"keywords": ["forbidden"]},
                severity=Severity.HIGH,
                description="Block forbidden keyword",
            )
        ],
    )
    enforcer = PolicyEnforcer(policy=policy)
    assert not enforcer.check("This contains FORBIDDEN content.").allowed
    assert enforcer.check("This is perfectly fine.").allowed


# ---------------------------------------------------------------------------
# MAX_LENGTH rule
# ---------------------------------------------------------------------------

def test_max_length_blocks_long_text() -> None:
    policy = Policy(
        name="length_test",
        rules=[
            PolicyRule(
                rule_type=RuleType.MAX_LENGTH,
                parameters={"max_chars": 10},
                severity=Severity.LOW,
                description="Too long",
            )
        ],
    )
    enforcer = PolicyEnforcer(policy=policy)
    assert not enforcer.check("This is longer than ten characters.").allowed
    assert enforcer.check("Short.").allowed


# ---------------------------------------------------------------------------
# MIN_LENGTH rule
# ---------------------------------------------------------------------------

def test_min_length_blocks_empty() -> None:
    policy = Policy(
        name="min_len_test",
        rules=[
            PolicyRule(
                rule_type=RuleType.MIN_LENGTH,
                parameters={"min_chars": 5},
                severity=Severity.LOW,
                description="Too short",
            )
        ],
    )
    enforcer = PolicyEnforcer(policy=policy)
    assert not enforcer.check("hi").allowed
    assert enforcer.check("Hello world").allowed


# ---------------------------------------------------------------------------
# BLOCKED_TOPICS rule
# ---------------------------------------------------------------------------

def test_blocked_topic() -> None:
    policy = Policy(
        name="topic_test",
        rules=[
            PolicyRule(
                rule_type=RuleType.BLOCKED_TOPICS,
                parameters={"topics": ["cryptocurrency", "trading"]},
                severity=Severity.MEDIUM,
                description="Off-topic",
            )
        ],
    )
    enforcer = PolicyEnforcer(policy=policy)
    assert not enforcer.check("Tell me about cryptocurrency trading strategies.").allowed
    assert enforcer.check("Tell me about the history of ancient Rome.").allowed


# ---------------------------------------------------------------------------
# ALLOWED_TOPICS rule
# ---------------------------------------------------------------------------

def test_allowed_topics_rejects_off_topic() -> None:
    policy = Policy(
        name="scoped_bot",
        rules=[
            PolicyRule(
                rule_type=RuleType.ALLOWED_TOPICS,
                parameters={"topics": ["weather", "forecast", "temperature"]},
                severity=Severity.MEDIUM,
                description="Only weather topics allowed",
            )
        ],
    )
    enforcer = PolicyEnforcer(policy=policy)
    assert enforcer.check("What is the temperature tomorrow?").allowed
    assert not enforcer.check("What is the best programming language?").allowed


# ---------------------------------------------------------------------------
# REGEX_BLOCKLIST rule
# ---------------------------------------------------------------------------

def test_regex_blocklist() -> None:
    policy = Policy(
        name="regex_test",
        rules=[
            PolicyRule(
                rule_type=RuleType.REGEX_BLOCKLIST,
                parameters={"patterns": [r"\b\d{3}-\d{2}-\d{4}\b"]},
                severity=Severity.HIGH,
                description="Block SSN-like patterns",
            )
        ],
    )
    enforcer = PolicyEnforcer(policy=policy)
    assert not enforcer.check("My SSN is 123-45-6789").allowed
    assert enforcer.check("My phone is 555-867-5309").allowed


# ---------------------------------------------------------------------------
# CUSTOM rule
# ---------------------------------------------------------------------------

def test_custom_rule_function() -> None:
    def contains_all_caps_word(text: str) -> bool:
        return any(word.isupper() and len(word) > 3 for word in text.split())

    policy = Policy(
        name="caps_test",
        rules=[
            PolicyRule(
                rule_type=RuleType.CUSTOM,
                severity=Severity.LOW,
                description="No all-caps words > 3 chars",
                custom_fn=contains_all_caps_word,
            )
        ],
    )
    enforcer = PolicyEnforcer(policy=policy)
    assert not enforcer.check("This is SHOUTING at you.").allowed
    assert enforcer.check("This is a normal sentence.").allowed


def test_custom_rule_requires_fn() -> None:
    with pytest.raises(ValueError, match="custom_fn"):
        PolicyRule(rule_type=RuleType.CUSTOM, description="oops")


# ---------------------------------------------------------------------------
# block_on_violation=False
# ---------------------------------------------------------------------------

def test_non_blocking_policy_records_violations_but_allows() -> None:
    policy = Policy(
        name="warn_only",
        block_on_violation=False,
        rules=[
            PolicyRule(
                rule_type=RuleType.BLOCKED_KEYWORDS,
                parameters={"keywords": ["bad"]},
                severity=Severity.LOW,
                description="Warn only",
            )
        ],
    )
    enforcer = PolicyEnforcer(policy=policy)
    result = enforcer.check("This is bad content.")
    assert result.allowed  # not blocked
    assert len(result.violations) == 1  # but violation recorded


# ---------------------------------------------------------------------------
# Multiple violations
# ---------------------------------------------------------------------------

def test_multiple_violations_recorded() -> None:
    policy = Policy(
        name="multi",
        rules=[
            PolicyRule(
                rule_type=RuleType.BLOCKED_KEYWORDS,
                parameters={"keywords": ["hack"]},
                severity=Severity.HIGH,
                description="Hacking keyword",
            ),
            PolicyRule(
                rule_type=RuleType.MAX_LENGTH,
                parameters={"max_chars": 5},
                severity=Severity.LOW,
                description="Too long",
            ),
        ],
    )
    enforcer = PolicyEnforcer(policy=policy)
    result = enforcer.check("how to hack a system")
    assert not result.allowed
    assert len(result.violations) == 2
