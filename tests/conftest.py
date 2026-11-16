"""Shared helpers for har-analyze tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from har_analyze.cli import AnalyzerSettings, ConfigFact, Har, HarAnalysisReport, HarAnalyzer
from har_analyze.cli import load_har as load_har_document

FIXTURES = Path(__file__).parent / "fixtures"
T0 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)


def load_har(name: str) -> Har:
    """Parse a fixture HAR file."""
    return load_har_document(json.loads((FIXTURES / name).read_text(encoding="utf-8")))


def analyze_fixture(
    name: str,
    settings: AnalyzerSettings | None = None,
    config_facts: list[ConfigFact] | None = None,
) -> HarAnalysisReport:
    """Analyze a fixture with optional settings."""
    return HarAnalyzer(settings, config_facts=config_facts).analyze(load_har(name))


def make_entry(  # noqa: PLR0913
    offset_ms: float,
    url: str,
    status: int = 200,
    time_ms: float = 100,
    *,
    method: str = "GET",
    timings: dict[str, float] | None = None,
    response_headers: list[tuple[str, str]] | None = None,
    request_headers: list[tuple[str, str]] | None = None,
    extra: dict[str, Any] | None = None,
    response_extra: dict[str, Any] | None = None,
    request_extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one raw HAR entry dict relative to T0."""
    start = T0 + timedelta(milliseconds=offset_ms)
    entry: dict[str, Any] = {
        "startedDateTime": start.isoformat().replace("+00:00", "Z"),
        "time": time_ms,
        "request": {
            "method": method,
            "url": url,
            "httpVersion": "HTTP/1.1",
            "headers": [{"name": n, "value": v} for n, v in (request_headers or [])],
            "bodySize": 0,
            **(request_extra or {}),
        },
        "response": {
            "status": status,
            "statusText": "",
            "headers": [{"name": n, "value": v} for n, v in (response_headers or [])],
            "redirectURL": "",
            "bodySize": 0,
            **(response_extra or {}),
        },
        "timings": timings
        or {
            "blocked": 0,
            "dns": -1,
            "connect": -1,
            "ssl": -1,
            "send": 0,
            "wait": time_ms - 10,
            "receive": 10,
        },
        **(extra or {}),
    }
    return entry


def make_har(entries: list[dict[str, Any]]) -> Har:
    """Wrap raw entries into a Har model."""
    return load_har_document({"log": {"entries": entries}})


def write_har(path: Path, entries: list[dict[str, Any]]) -> Path:
    """Write raw entries as a HAR file."""
    path.write_text(json.dumps({"log": {"entries": entries}}), encoding="utf-8")
    return path


@pytest.fixture
def fixtures_dir() -> Path:
    """Directory holding golden fixtures."""
    return FIXTURES
