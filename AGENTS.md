# AGENTS.md

Guardrails for coding/auditing agents (Claude Code, OpenAI Codex, and similar). Self-contained and normative.

**Project**: A command-line tool for analyzing HAR (HTTP Archive) files to extract performance metrics, detect issues, and generate actionable insights for backend/API and network troubleshooting.

## Overview

HAR Analyze is a Python package that parses HAR 1.2 files captured from browser developer tools or network proxies and produces comprehensive reports that help identify performance bottlenecks, service failures, and network issues.

### Key Capabilities

- **Performance Metrics**: Timing percentiles (p50, p95, p99) for overall requests and broken down by phase (DNS, connect, SSL, TTFB, receive)
- **Infrastructure Details**: HTTP version distribution, server software identification, server IP addresses by domain, connection reuse efficiency
- **Issue Detection**: Automatic identification of network errors, HTTP 4xx/5xx responses, slow endpoints, large payloads, redirect chains, and connection blocking
- **Domain Health Analysis**: Per-domain breakdown with error rates and health status (healthy, degraded, critical)
- **Service Failure Tracking**: Backend/API service health grouped by domain, method, and path
- **Time Gap Analysis**: Detection of significant gaps (>1 second) between consecutive requests indicating client-side processing delays
- **Large Request Bodies**: Identification of large POST/PUT payloads (>100KB) that may cause upload slowness
- **Cache Analysis**: Cache hit/miss ratios and detection of repeatedly downloaded resources

---

## Core Rules

- **Plan first**: Draft a short plan (bullets) and emit it before any code changes.
- **Docs first**: Use Context7 MCP (or equivalent) to resolve library IDs and retrieve docs before generating code that uses external libraries.
- **Minimal edits**: Prefer minimal, reversible changes. Do not change public APIs or file layout unless explicitly requested.
- **Determinism**: All code and tests must be deterministic (no network, no nondeterministic time unless frozen).
- **Escalate**: Stop and escalate (open an issue or produce a note) if a task conflicts with these rules, requires API/layout changes without permission, or if required tools/docs are unavailable.
- **Current time**: Execute `date` command when asked about date/time or before web searches; SessionStart timestamps are static, not live.

---

## Design Principles

- **YAGNI**: Don't build it until you need it.
- **DRY**: Extract patterns after second duplication, not before.
- **Fail Fast**: Explicit errors beat silent failures.
- **Simple First**: Write the obvious solution, optimize only if needed.
- **Delete Aggressively**: Less code = fewer bugs.
- **Semantic Naming**: Always name variables, parameters, and API endpoints with verbose, self-documenting names that optimize for comprehension by both humans and LLMs, not brevity (e.g., `wait_until_obs_is_saved=true` vs `wait=true`).

---

## Toolchain

- **Python**: 3.11-3.13
- **Formatter/Linter**: `ruff format` and `ruff check --fix`
- **Type checker**: `basedpyright` (strict)
- **Tests**: `pytest` with branch coverage >= 90%; optional `hypothesis`
- **Packaging**: `pyproject.toml` as single source of truth; `uv` exclusively (no pip/poetry/conda)
- **Bash tools**: `rg`, `fd`, `bat`, `jq` only (no grep/find)

---

## Verification

Run in sequence; **all must pass** before committing:

```bash
uv sync --frozen
ruff format --check
ruff check
basedpyright
pytest -q --cov=src/<package> --cov-branch --cov-fail-under=90
pip-audit  # or osv-scanner; fail on critical vulnerabilities
```

Environment: `TZ=UTC`, `PYTHONUTF8=1`, `LC_ALL=C.UTF-8`, `PYTHONWARNINGS=error`

Matrix across Python 3.11-3.13. Cache `uv` environments. Commit `uv.lock`.

---

## Project Structure

```
src/<package_name>/    # All package code
tests/                 # All tests (outside src/)
pyproject.toml         # Single config file (all tool settings live here)
uv.lock                # Committed lockfile
```

- Prefer relative imports within a package; do not mutate `sys.path`.
- Define `__all__` for public exports.
- No `setup.py`.

---

## Code Standards

### Typing
- Complete type hints on all code; `from __future__ import annotations`.
- No implicit `Any`. No `# type: ignore` without justification.
- Prefer `Protocol` for behavioral contracts; use `Self`, `ParamSpec`, `TypeVarTuple` as appropriate.
- PEP 695 syntax when minimum version is >= 3.12; otherwise `TypeVar`/`ParamSpec`.

### I/O & HTTP
- Use `pathlib.Path` for filesystem work.
- Use `httpx` (not `requests`) with pooled clients, HTTP/2, explicit timeouts (never `None`), and retries only for idempotent methods with exponential backoff.
- Atomic writes: temp file + `Path.replace()`; `fsync` for critical paths.
- Access package data via `importlib.resources`.

### Data
- Prefer `pydantic>=2` or `msgspec` for validation/serialization.
- Parameterized SQL only; never format/concatenate SQL with variables.
- Config via `pydantic-settings` (env + optional .env); env overrides file.

### CLI & Concurrency
- Prefer `typer` for CLI; if using Click, enforce typed callbacks and `main()` entrypoint.
- `asyncio`/`anyio` for I/O-bound; `concurrent.futures` for CPU-bound. No busy-waits.
- `tenacity` for retries with exponential backoff and jitter.

### Logging
- Use stdlib `logging` at module level: `logger = logging.getLogger(__name__)`.
- No `print()` in library code (CLI output only).
- Use `contextvars` for correlation IDs.

---

## Security

- Never commit secrets; use `pydantic-settings` for config.
- `yaml.safe_load` only; no untrusted pickle.
- Validate archive contents (tar/zip) for path traversal; block absolute and `..` paths.
- `subprocess.run([...], check=True, shell=False)` with explicit arg lists if shell needed.
- Explicit max sizes for file uploads/downloads.

---

## Testing

- Hermetic and network-free by default.
- Mock HTTP with `respx` or `httpx` mocking.
- Freeze time (`time-machine`/`freezegun`), seed randomness, enforce per-test timeouts.
- Branch coverage >= 90%.
- Test deprecation warnings with `warnings.warn(..., DeprecationWarning, stacklevel=2)`.

---

## Versioning

- Semantic versioning; expose `__version__` and CLI `--version` flag.
- Deprecation policy documented; deprecations tested.
