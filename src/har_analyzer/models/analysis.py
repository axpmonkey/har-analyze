"""Analysis result models."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from .issues import DetectedIssue, IssueSeverity


class DomainHealth(str, Enum):
    """Health status for a domain."""

    CRITICAL = "critical"  # >50% error rate or has critical issues
    DEGRADED = "degraded"  # 10-50% error rate or has high issues
    HEALTHY = "healthy"  # <10% error rate and no major issues


class DomainAnalysis(BaseModel):
    """Per-domain analysis summary."""

    domain: str  # hostname
    total_requests: int
    failed_requests: int  # 4xx + 5xx + timeouts
    error_rate: float  # percentage
    timing_stats: TimingStatistics
    status_codes: dict[int, int]
    issue_count: int
    health: DomainHealth
    is_first_party: bool  # True if same domain as first request


class TimingStatistics(BaseModel):
    """Statistical timing analysis."""

    count: int
    p50: float  # Median
    p95: float  # 95th percentile
    p99: float  # 99th percentile
    max: float  # Maximum
    mean: float  # Average
    total_duration_ms: float


class EndpointStats(BaseModel):
    """Aggregated statistics for an endpoint."""

    url_pattern: str  # Simplified URL (no query params)
    count: int  # Number of requests
    timings: TimingStatistics
    blocked_timings: TimingStatistics
    dns_timings: TimingStatistics
    connect_timings: TimingStatistics
    ssl_timings: TimingStatistics
    send_timings: TimingStatistics
    ttfb_timings: TimingStatistics
    receive_timings: TimingStatistics
    client_total_timings: TimingStatistics
    network_total_timings: TimingStatistics
    status_codes: dict[int, int]  # Status code distribution
    total_bytes: int  # Total bytes transferred


class ServiceFailureStats(BaseModel):
    """Backend/API service health and failure breakdown."""

    domain: str
    method: str
    path: str  # Path without query string
    request_count: int
    success_count: int  # 2xx + 3xx
    status_4xx_count: int
    status_5xx_count: int
    network_error_count: int  # status=0 or explicit error field
    duration_exceeded_count: int  # Request duration exceeded threshold
    status_codes: dict[int, int]
    timings: TimingStatistics
    ttfb_timings: TimingStatistics
    network_total_timings: TimingStatistics
    first_seen: datetime
    last_seen: datetime


class SlowRequest(BaseModel):
    """Details of a slow request."""

    url: str
    method: str
    duration_ms: float
    status: int
    size_bytes: int
    timings: dict[str, float]  # Breakdown by phase


class LargePayload(BaseModel):
    """Details of a large payload."""

    url: str
    size_mb: float
    content_type: str
    cached: bool


class RepeatedResource(BaseModel):
    """Resource downloaded multiple times (cache issue)."""

    url: str
    count: int  # Number of downloads
    total_bytes: int  # Total bytes across all downloads
    size_bytes: int  # Size per download


class HarAnalysisReport(BaseModel):
    """Complete analysis report."""

    # Overall metrics
    total_requests: int
    total_duration_ms: float
    total_bytes_transferred: int
    total_bytes_downloaded: int

    # Timing breakdowns
    overall_timings: TimingStatistics
    blocked_timings: TimingStatistics
    dns_timings: TimingStatistics
    connect_timings: TimingStatistics
    ssl_timings: TimingStatistics
    send_timings: TimingStatistics
    ttfb_timings: TimingStatistics  # wait time (server processing)
    receive_timings: TimingStatistics

    # Status code distribution
    status_codes: dict[int, int]

    # Top problematic requests
    slowest_requests: list[SlowRequest]  # Top 20
    largest_payloads: list[LargePayload]  # Top 20

    # Endpoint analysis
    endpoints: list[EndpointStats]  # Aggregated by URL pattern

    # Issues detected
    issues: list[DetectedIssue]
    issues_by_severity: dict[IssueSeverity, int]

    # Cache analysis
    cache_hits: int
    cache_misses: int
    repeated_resources: list[RepeatedResource]  # Top 20

    # Domain analysis (grouped by host)
    domains: list[DomainAnalysis] = []

    # Backend/API service health (grouped by domain+method+path)
    service_failures: list[ServiceFailureStats] = []

    # Referer hostnames observed in request headers
    referer_hostnames: dict[str, int] = Field(default_factory=dict)
