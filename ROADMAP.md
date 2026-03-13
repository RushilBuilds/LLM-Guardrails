# LLM-Guardrails — Project Roadmap

## Milestone 1: Project Scaffold
**Goal:** Establish the repository layout, dependency manifest, and packaging config so the project is installable from the start.

Files:
- `requirements.txt` — runtime and dev dependencies
- `pyproject.toml` — PEP 517 build metadata and tool config
- `guardrails/` — package directory (empty `__init__.py`)
- `api/` — FastAPI app directory (empty `__init__.py`)
- `tests/` — test directory (`conftest.py`)
- `examples/` — usage scripts directory
- `docs/` — documentation directory
- `.gitignore` additions for Python artefacts

Commit message: `feat: project scaffold — directories, requirements, pyproject`

---

## Milestone 2: Core Data Models
**Goal:** Define all shared result types and enums in `guardrails/models.py` so every subsequent module builds on a stable contract.

Files:
- `guardrails/models.py` — `Severity`, `InjectionResult`, `JailbreakResult`, `PIIEntity`, `PIIResult`, `PolicyViolation`, `PolicyResult`, `ScanResult`

Commit message: `feat: core data models (Severity, ScanResult, and result types)`

---

## Milestone 3: Detection Modules
**Goal:** Implement the three detection modules with real pattern-matching logic (no placeholders).

Files:
- `guardrails/injection_detector.py` — regex-based prompt injection detection
- `guardrails/jailbreak_detector.py` — jailbreak technique pattern library
- `guardrails/pii_detector.py` — PII regex scanning with Luhn card validation and redaction
- `guardrails/__init__.py` — expose public API

Commit message: `feat: injection, jailbreak, and PII detection modules`

---

## Milestone 4: Policy Enforcer
**Goal:** Add a configurable policy layer that evaluates text against user-defined topic blocklists, length limits, allowed/denied keyword lists, and custom rule functions.

Files:
- `guardrails/policy_enforcer.py` — `Policy`, `PolicyEnforcer`

Commit message: `feat: policy enforcer with configurable rules and custom validators`

---

## Milestone 5: FastAPI Microservice
**Goal:** Wrap the library in a deployable HTTP service with request/response schemas, health endpoint, and OpenAPI docs.

Files:
- `api/__init__.py`
- `api/app.py` — FastAPI application, lifespan, routers
- `api/schemas.py` — Pydantic request/response models
- `api/routes/scan.py` — `/scan` endpoint (full pipeline)
- `api/routes/health.py` — `/health` endpoint

Commit message: `feat: FastAPI microservice with /scan and /health endpoints`

---

## Milestone 6: Test Suite
**Goal:** Achieve meaningful coverage of all modules with both positive (attack detected) and negative (clean input) cases.

Files:
- `tests/conftest.py` — shared fixtures
- `tests/test_injection_detector.py`
- `tests/test_jailbreak_detector.py`
- `tests/test_pii_detector.py`
- `tests/test_policy_enforcer.py`
- `tests/test_api.py` — FastAPI integration tests via `TestClient`

Commit message: `test: pytest suite for all modules and API endpoints`

---

## Milestone 7: Examples & Docs
**Goal:** Provide runnable example scripts and concise reference documentation.

Files:
- `examples/basic_scan.py` — minimal library usage
- `examples/api_client.py` — HTTP client calling the microservice
- `examples/custom_policy.py` — defining and using a custom policy
- `docs/architecture.md` — component diagram and data-flow description
- `docs/configuration.md` — all knobs, env vars, and customisation points

Commit message: `docs: examples and reference documentation`

---

## Milestone 8: README Update
**Goal:** Replace the stub README with a complete project overview, install instructions, quick-start, API reference summary, and badge placeholders.

Files:
- `README.md`

Commit message: `docs: complete README with overview, install, and usage examples`
