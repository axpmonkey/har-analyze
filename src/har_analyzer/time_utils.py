"""Time-related helpers for deterministic reporting."""

from __future__ import annotations

from datetime import datetime

from .models.analysis import HarAnalysisReport


def capture_window(report: HarAnalysisReport) -> tuple[datetime | None, datetime | None]:
    """Return the earliest and latest timestamps observed in the HAR-derived report.

    This is derived from HAR entry timestamps (issues, service first/last seen) and is intended
    to be stable and deterministic across runs.
    """
    timestamps: list[datetime] = []
    for service in report.service_failures:
        timestamps.append(service.first_seen)
        timestamps.append(service.last_seen)
    timestamps.extend([issue.timestamp for issue in report.issues])

    if not timestamps:
        return None, None

    aware = [ts for ts in timestamps if ts.tzinfo is not None]
    chosen = aware if aware else timestamps
    return min(chosen), max(chosen)
