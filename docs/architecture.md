# Architecture

## Overview

LLM Guardrails is a pure-Python safety middleware library with an optional FastAPI HTTP wrapper. It processes text through a pipeline of independently configurable detectors before that text reaches (or leaves) an LLM.

```
User / Application
        │
        ▼
┌───────────────────────────────────────────┐
│              Guardrails Pipeline           │
│                                           │
│  ┌─────────────────────────────────────┐  │
│  │  1. InjectionDetector               │  │
│  │     regex pattern matching           │  │
│  │     configurable severity threshold  │  │
│  └─────────────────────────────────────┘  │
│                   │                       │
│  ┌─────────────────────────────────────┐  │
│  │  2. JailbreakDetector               │  │
│  │     multi-technique pattern library  │  │
│  │     configurable severity threshold  │  │
│  └─────────────────────────────────────┘  │
│                   │                       │
│  ┌─────────────────────────────────────┐  │
│  │  3. PIIDetector                     │  │
│  │     11 entity-type regexes           │  │
│  │     Luhn card validation             │  │
│  │     optional in-place redaction      │  │
│  └─────────────────────────────────────┘  │
│                   │                       │
│  ┌─────────────────────────────────────┐  │
│  │  4. PolicyEnforcer                  │  │
│  │     keyword / topic / length rules   │  │
│  │     regex blocklist                  │  │
│  │     custom callable rules            │  │
│  └─────────────────────────────────────┘  │
│                   │                       │
└───────────────────┼───────────────────────┘
                    │
                    ▼
              ScanResult
        (blocked=True/False, …)
                    │
           ┌────────┴────────┐
           │                 │
      block request     forward to LLM
```

## Component Descriptions

### `guardrails/models.py`
Shared dataclasses and the `Severity` enum. All detector results are instances of these types, so callers depend only on a single schema.

### `guardrails/injection_detector.py`
Implements `InjectionDetector` with an internal library of 11 compiled regex patterns covering:
- Direct instruction overrides
- Role / persona hijacking
- System prompt exfiltration
- Delimiter injection (`</system>`, `[INST]`, `<|im_start|>`, …)
- Indirect / document-embedded injection
- Command-execution triggers
- Hidden Unicode steganography
- Encoding / obfuscation tricks
- Many-shot / context stuffing

### `guardrails/jailbreak_detector.py`
Implements `JailbreakDetector` with 12 patterns across families:
`DAN`, `HypotheticalFraming`, `TokenSmuggling`, `PersonaPlay`, `CompletionExploit`, `PromptWrapping`, `TranslationBypass`, `AuthorityExploit`, `AcknowledgementBait`, `ManyShotJailbreak`.

### `guardrails/pii_detector.py`
Implements `PIIDetector` with regex patterns for 11 entity types. Credit-card numbers are additionally validated with the Luhn algorithm to reduce false positives. Overlapping matches are resolved by keeping the longest span.

### `guardrails/policy_enforcer.py`
Implements `PolicyEnforcer` with a `Policy` / `PolicyRule` dataclass hierarchy. Seven built-in rule types: `BLOCKED_KEYWORDS`, `ALLOWED_TOPICS`, `BLOCKED_TOPICS`, `MAX_LENGTH`, `MIN_LENGTH`, `REGEX_BLOCKLIST`, `CUSTOM`.

### `api/app.py`
FastAPI application created via `create_app()`. Detector instances are constructed once during the `lifespan` context and stored on `app.state`.

### `api/routes/`
- `GET /health` — liveness probe
- `POST /scan` — full pipeline scan, returns `ScanResponse`

## Data Flow (HTTP)

```
POST /scan  { text, check_injection, check_jailbreak, … }
        │
        ├─► InjectionDetector.scan(text)   → InjectionResult
        ├─► JailbreakDetector.scan(text)   → JailbreakResult
        ├─► PIIDetector.scan(text, redact) → PIIResult
        └─► PolicyEnforcer.check(text)     → PolicyResult
                    │
                    ▼
            ScanResponse  {
              text, blocked, block_reasons, is_safe,
              injection, jailbreak, pii, policy
            }
```

Each step is independent — disabling one does not affect the others. The `blocked` flag is set if any of injection, jailbreak, or policy checks trigger. PII detection never blocks on its own; it only populates `redacted_text`.
