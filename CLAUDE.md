# CLAUDE.md

A command-line tool for analyzing HAR (HTTP Archive) files to extract performance metrics, detect issues, and generate actionable insights for backend/API and network troubleshooting.

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

## Toolchain

- **Package manager**: `uv` exclusively (no pip/poetry/conda)
- **Formatter/Linter**: `ruff format` / `ruff check --fix`
- **Type checker**: `basedpyright` (strict mode)
- **Tests**: `pytest` with branch coverage >= 90%
- **Python**: 3.11-3.13

---

## Verification

Run before committing; all must pass:

```bash
ruff format --check && ruff check && basedpyright && pytest -q --cov=src/<package> --cov-branch --cov-fail-under=90
```

---

## Project Structure

```
src/<package_name>/    # All package code
tests/                 # All tests (outside src/)
pyproject.toml         # Single config file (all tool settings)
uv.lock                # Committed lockfile
```

- `pyproject.toml` is the single source of truth for all tool configuration.
- Relative imports within packages. Define `__all__` for public exports.
- No `setup.py`.

---

## Key Conventions

- Complete type hints on all code; `from __future__ import annotations`.
- `httpx` over `requests`. `pathlib.Path` for filesystem. `pydantic>=2` for validation.
- `typer` for CLI. `asyncio`/`anyio` for I/O-bound concurrency.
- Hermetic, network-free tests. Mock HTTP with `respx`.
- Never commit secrets; `pydantic-settings` for config.

See `.claude/skills/python/` for detailed Python conventions.

---

## Also See

- `AGENTS.md` — comprehensive standalone guide for all coding agents (Codex, etc.)
