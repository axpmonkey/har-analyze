"""Issue detection models."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel


class IssueSeverity(str, Enum):
    """Issue severity levels."""

    CRITICAL = "critical"  # Timeouts, total failures
    HIGH = "high"  # Server errors, major perf issues
    MEDIUM = "medium"  # Large payloads, slow endpoints
    LOW = "low"  # Minor issues


class IssueType(str, Enum):
    """Types of detected issues."""

    NETWORK_ERROR = "network_error"  # status=0 or explicit error field
    DURATION_EXCEEDED = (
        "duration_exceeded"  # Request exceeded threshold (not necessarily a true timeout)
    )
    SERVER_ERROR = "server_error"  # 5xx status
    CLIENT_ERROR = "client_error"  # 4xx status
    LARGE_PAYLOAD = "large_payload"  # Response >1MB
    SLOW_ENDPOINT = "slow_endpoint"  # p95 >10s
    BLOCKING = "blocking"  # Client-side blocked >5s
    REDIRECT_CHAIN = "redirect_chain"  # Multiple 302/303


class DetectedIssue(BaseModel):
    """A detected performance or error issue."""

    issue_type: IssueType
    severity: IssueSeverity
    url: str
    message: str  # Human-readable description
    details: dict[str, Any]  # Additional context
    timestamp: datetime  # When request occurred
    duration_ms: float | None = None  # Request duration
    size_bytes: int | None = None  # Response size
    domain: str = ""  # Extracted hostname for grouping
