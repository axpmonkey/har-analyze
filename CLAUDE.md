# CLAUDE.md

Python package template and agent configuration files for consistent, high-quality Python development.

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
