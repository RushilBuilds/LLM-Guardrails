"""custom_policy.py — defining and combining custom policies.

Demonstrates:
- BLOCKED_KEYWORDS rule
- MAX_LENGTH rule
- BLOCKED_TOPICS rule
- CUSTOM callable rule
- block_on_violation=False (warn-only mode)

Run with:
    python examples/custom_policy.py
"""

from guardrails import Policy, PolicyEnforcer, PolicyRule, RuleType, Severity


# ---------------------------------------------------------------------------
# 1. A strict customer-service bot policy
# ---------------------------------------------------------------------------

def contains_profanity(text: str) -> bool:
    """Toy profanity check (replace with a real list in production)."""
    profanity = {"badword1", "badword2", "offensive"}
    return any(word in text.lower() for word in profanity)


customer_service_policy = Policy(
    name="customer_service",
    rules=[
        PolicyRule(
            rule_type=RuleType.BLOCKED_TOPICS,
            parameters={"topics": ["competitor", "lawsuit", "legal action"]},
            severity=Severity.HIGH,
            description="Do not discuss competitors or legal matters",
        ),
        PolicyRule(
            rule_type=RuleType.MAX_LENGTH,
            parameters={"max_chars": 500},
            severity=Severity.LOW,
            description="Customer messages must be under 500 characters",
        ),
        PolicyRule(
            rule_type=RuleType.CUSTOM,
            severity=Severity.MEDIUM,
            description="No profanity",
            custom_fn=contains_profanity,
        ),
    ],
)


# ---------------------------------------------------------------------------
# 2. A scoped medical-info bot policy (only allow medical topics)
# ---------------------------------------------------------------------------

medical_policy = Policy(
    name="medical_assistant",
    rules=[
        PolicyRule(
            rule_type=RuleType.ALLOWED_TOPICS,
            parameters={
                "topics": [
                    "symptom", "diagnosis", "medication", "treatment",
                    "dose", "side effect", "allergy", "drug", "prescription",
                ]
            },
            severity=Severity.MEDIUM,
            description="Only medical topics are in scope",
        ),
        PolicyRule(
            rule_type=RuleType.BLOCKED_KEYWORDS,
            parameters={"keywords": ["buy now", "discount", "sale", "offer"]},
            severity=Severity.HIGH,
            description="Block commercial solicitation",
        ),
    ],
)


# ---------------------------------------------------------------------------
# 3. Warn-only audit policy (does not block)
# ---------------------------------------------------------------------------

audit_policy = Policy(
    name="audit_log",
    block_on_violation=False,
    rules=[
        PolicyRule(
            rule_type=RuleType.REGEX_BLOCKLIST,
            parameters={"patterns": [r"\b\d{3}-\d{2}-\d{4}\b"]},
            severity=Severity.HIGH,
            description="SSN-like pattern detected (audit only)",
        ),
    ],
)


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def check(enforcer: PolicyEnforcer, label: str, text: str) -> None:
    result = enforcer.check(text)
    status = "ALLOWED" if result.allowed else "BLOCKED"
    print(f"  [{status}] {text[:60]!r}")
    for v in result.violations:
        print(f"           violation: {v.description} [{v.severity}]")


def main() -> None:
    print("=== Customer Service Policy ===")
    cs = PolicyEnforcer(policy=customer_service_policy)
    check(cs, "safe", "I'd like to return my order, please.")
    check(cs, "competitor", "How do you compare to your competitor AcmeCorp?")
    check(cs, "profanity", "This is badword1 and I want a refund!")
    check(cs, "too long", "A" * 600)

    print()
    print("=== Medical Assistant Policy ===")
    med = PolicyEnforcer(policy=medical_policy)
    check(med, "on-topic", "What are common side effects of ibuprofen?")
    check(med, "off-topic", "What is the best pizza in New York?")
    check(med, "solicitation", "Buy now — discount medication sale!")

    print()
    print("=== Audit-only Policy (warn, no block) ===")
    audit = PolicyEnforcer(policy=audit_policy)
    check(audit, "ssn", "My SSN is 123-45-6789 — please store it.")
    check(audit, "clean", "Please process my refund for order #4521.")


if __name__ == "__main__":
    main()
