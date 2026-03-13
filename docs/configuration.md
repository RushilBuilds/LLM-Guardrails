# Configuration Reference

## Library configuration

All detectors are instantiated directly in Python. There is no global config file — pass parameters to each constructor.

### InjectionDetector

```python
from guardrails import InjectionDetector, Severity

detector = InjectionDetector(
    threshold=Severity.MEDIUM,   # LOW | MEDIUM | HIGH | CRITICAL
    custom_patterns=[            # optional extra patterns
        (
            "my_pattern",        # unique name
            r"(?i)secret_token", # regex string
            Severity.HIGH,       # severity
            "Description",       # human-readable description
        )
    ],
)
```

**threshold** — Patterns with severity *below* this value are silently skipped.
Default: `Severity.MEDIUM`.

---

### JailbreakDetector

```python
from guardrails import JailbreakDetector, Severity

detector = JailbreakDetector(
    threshold=Severity.MEDIUM,
    custom_patterns=[
        (
            "name",       # pattern name
            "Technique",  # technique label (used in JailbreakResult.technique)
            r"regex",     # regex string
            Severity.HIGH,
            "Description",
        )
    ],
)
```

---

### PIIDetector

```python
from guardrails import PIIDetector

detector = PIIDetector(
    entities=["EMAIL", "PHONE_US", "SSN"],  # None = all 11 types
    validate_credit_cards=True,             # Luhn check (default True)
)

result = detector.scan(text, redact=True)   # redact=False skips redaction
```

**Supported entity types:**
`EMAIL`, `PHONE_US`, `SSN`, `CREDIT_CARD`, `IP_V4`, `IP_V6`, `DATE_OF_BIRTH`, `PASSPORT`, `DRIVERS_LICENSE`, `US_ADDRESS`, `IBAN`

---

### PolicyEnforcer

```python
from guardrails import Policy, PolicyEnforcer, PolicyRule, RuleType, Severity

policy = Policy(
    name="my_policy",
    block_on_violation=True,   # False = warn-only (record violations, still allow)
    rules=[
        PolicyRule(
            rule_type=RuleType.BLOCKED_KEYWORDS,
            parameters={"keywords": ["harmful phrase"]},
            severity=Severity.CRITICAL,
            description="Human-readable description",
        ),
        PolicyRule(
            rule_type=RuleType.MAX_LENGTH,
            parameters={"max_chars": 4096},
            severity=Severity.LOW,
            description="Reject oversized inputs",
        ),
    ],
)

enforcer = PolicyEnforcer(policy=policy)
result = enforcer.check(text)
```

#### Rule types and their parameters

| `RuleType`          | Required parameter keys              | Description |
|---------------------|--------------------------------------|-------------|
| `BLOCKED_KEYWORDS`  | `keywords: list[str]`                | Block if any keyword is found (case-insensitive) |
| `ALLOWED_TOPICS`    | `topics: list[str]`                  | Block if *none* of the topics appear |
| `BLOCKED_TOPICS`    | `topics: list[str]`                  | Block if *any* topic appears |
| `MAX_LENGTH`        | `max_chars: int`                     | Block if `len(text) > max_chars` |
| `MIN_LENGTH`        | `min_chars: int`                     | Block if `len(text) < min_chars` |
| `REGEX_BLOCKLIST`   | `patterns: list[str]`                | Block if any regex matches |
| `CUSTOM`            | *(none)*, requires `custom_fn`       | Block if `custom_fn(text)` returns `True` |

---

## Microservice environment variables

Set these before starting `uvicorn`:

| Variable              | Default    | Description |
|-----------------------|------------|-------------|
| `INJECTION_THRESHOLD` | `medium`   | Severity threshold for injection detection |
| `JAILBREAK_THRESHOLD` | `medium`   | Severity threshold for jailbreak detection |
| `PII_ENTITIES`        | *(all)*    | Comma-separated entity types, e.g. `EMAIL,SSN` |

Example:

```bash
INJECTION_THRESHOLD=high \
JAILBREAK_THRESHOLD=high \
PII_ENTITIES=EMAIL,SSN,CREDIT_CARD \
uvicorn api.app:app --host 0.0.0.0 --port 8000
```

---

## POST /scan request body

All fields except `text` are optional and default to `true` / sensible values.

```jsonc
{
  "text": "string (required, min length 1)",
  "check_injection": true,
  "check_jailbreak": true,
  "check_pii": true,
  "check_policy": true,
  "injection_threshold": "medium",   // low | medium | high | critical
  "jailbreak_threshold": "medium",
  "redact_pii": true,
  "pii_entities": null               // null = all, or ["EMAIL", "SSN", ...]
}
```

Interactive OpenAPI docs are available at `http://localhost:8000/docs` when the server is running.
