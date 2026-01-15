#!/usr/bin/env python3
"""HAR file analyzer - single-file version.

Analyze HAR files with deterministic performance insights.
"""

from __future__ import annotations

__version__ = "0.1.0"

import json
import logging
import statistics
from collections import defaultdict
from datetime import UTC, datetime, tzinfo
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import typer
from pydantic import BaseModel, Field
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

logger = logging.getLogger(__name__)
console = Console()


# =============================================================================
# Enums
# =============================================================================


class IssueSeverity(str, Enum):
    """Issue severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IssueType(str, Enum):
    """Types of detected issues."""

    NETWORK_ERROR = "network_error"
    DURATION_EXCEEDED = "duration_exceeded"
    SERVER_ERROR = "server_error"
    CLIENT_ERROR = "client_error"
    LARGE_PAYLOAD = "large_payload"
    SLOW_ENDPOINT = "slow_endpoint"
    BLOCKING = "blocking"
    REDIRECT_CHAIN = "redirect_chain"


class DomainHealth(str, Enum):
    """Health status for a domain."""

    CRITICAL = "critical"
    DEGRADED = "degraded"
    HEALTHY = "healthy"


# =============================================================================
# HAR Models (HTTP Archive 1.2 spec)
# =============================================================================


class HarHeader(BaseModel):
    """HTTP header name-value pair."""

    name: str
    value: str


class HarQueryParam(BaseModel):
    """Query string parameter."""

    name: str
    value: str


class HarCookie(BaseModel):
    """HTTP cookie."""

    name: str
    value: str
    path: str | None = None
    domain: str | None = None
    expires: datetime | None = None
    http_only: bool | None = Field(None, alias="httpOnly")
    secure: bool | None = None


class HarPostData(BaseModel):
    """POST request data."""

    mime_type: str = Field(alias="mimeType")
    params: list[dict[str, str]] = Field(default_factory=list)
    text: str | None = None


class HarRequest(BaseModel):
    """HTTP request."""

    method: str
    url: str
    http_version: str = Field(alias="httpVersion")
    headers: list[HarHeader]
    query_string: list[HarQueryParam] = Field(alias="queryString")
    cookies: list[HarCookie]
    headers_size: int = Field(alias="headersSize")
    body_size: int = Field(alias="bodySize")
    post_data: HarPostData | None = Field(None, alias="postData")


class HarContent(BaseModel):
    """Response content."""

    size: int
    compression: int | None = None
    mime_type: str = Field(alias="mimeType")
    text: str | None = None
    encoding: str | None = None


class HarResponse(BaseModel):
    """HTTP response."""

    status: int
    status_text: str = Field(alias="statusText")
    http_version: str = Field(alias="httpVersion")
    headers: list[HarHeader]
    cookies: list[HarCookie]
    content: HarContent
    redirect_url: str = Field("", alias="redirectURL")
    headers_size: int = Field(alias="headersSize")
    body_size: int = Field(alias="bodySize")
    transfer_size: int | None = Field(None, alias="_transferSize")
    error: str | None = Field(None, alias="_error")


class HarCache(BaseModel):
    """Cache information."""

    before_request: dict[str, Any] | None = Field(None, alias="beforeRequest")
    after_request: dict[str, Any] | None = Field(None, alias="afterRequest")


class HarTimings(BaseModel):
    """Request/response timings (all in milliseconds)."""

    blocked: float = -1.0
    dns: float = -1.0
    ssl: float = -1.0
    connect: float = -1.0
    send: float
    wait: float
    receive: float


class HarEntry(BaseModel):
    """Single HTTP transaction."""

    started_date_time: datetime = Field(alias="startedDateTime")
    time: float
    request: HarRequest
    response: HarResponse
    cache: HarCache | None = None
    timings: HarTimings
    server_ip_address: str | None = Field(None, alias="serverIPAddress")
    connection: str | None = None
    comment: str | None = None


class HarPage(BaseModel):
    """Page timing information (optional)."""

    started_date_time: datetime = Field(alias="startedDateTime")
    id: str
    title: str
    page_timings: dict[str, float] = Field(alias="pageTimings")


class HarCreator(BaseModel):
    """Tool that created the HAR."""

    name: str
    version: str


class HarLog(BaseModel):
    """HAR log container."""

    version: str
    creator: HarCreator
    browser: HarCreator | None = None
    pages: list[HarPage] = Field(default_factory=list)
    entries: list[HarEntry]
    comment: str | None = None


class Har(BaseModel):
    """Root HAR object."""

    log: HarLog


# =============================================================================
# Analysis Models
# =============================================================================


class DetectedIssue(BaseModel):
    """A detected performance or error issue."""

    issue_type: IssueType
    severity: IssueSeverity
    url: str
    message: str
    details: dict[str, Any]
    timestamp: datetime
    duration_ms: float | None = None
    size_bytes: int | None = None
    domain: str = ""


class TimingStatistics(BaseModel):
    """Statistical timing analysis."""

    count: int
    p50: float
    p95: float
    p99: float
    max: float
    mean: float
    total_duration_ms: float


class DomainAnalysis(BaseModel):
    """Per-domain analysis summary."""

    domain: str
    total_requests: int
    failed_requests: int
    error_rate: float
    timing_stats: TimingStatistics
    status_codes: dict[int, int]
    issue_count: int
    health: DomainHealth
    is_first_party: bool


class EndpointStats(BaseModel):
    """Aggregated statistics for an endpoint."""

    url_pattern: str
    count: int
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
    status_codes: dict[int, int]
    total_bytes: int


class ServiceFailureStats(BaseModel):
    """Backend/API service health and failure breakdown."""

    domain: str
    method: str
    path: str
    request_count: int
    success_count: int
    status_4xx_count: int
    status_5xx_count: int
    network_error_count: int
    duration_exceeded_count: int
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
    timings: dict[str, float]


class LargePayload(BaseModel):
    """Details of a large payload."""

    url: str
    size_mb: float
    content_type: str
    cached: bool


class RepeatedResource(BaseModel):
    """Resource downloaded multiple times (cache issue)."""

    url: str
    count: int
    total_bytes: int
    size_bytes: int


class HarAnalysisReport(BaseModel):
    """Complete analysis report."""

    total_requests: int
    total_duration_ms: float
    total_bytes_transferred: int
    total_bytes_downloaded: int
    overall_timings: TimingStatistics
    blocked_timings: TimingStatistics
    dns_timings: TimingStatistics
    connect_timings: TimingStatistics
    ssl_timings: TimingStatistics
    send_timings: TimingStatistics
    ttfb_timings: TimingStatistics
    receive_timings: TimingStatistics
    status_codes: dict[int, int]
    slowest_requests: list[SlowRequest]
    largest_payloads: list[LargePayload]
    endpoints: list[EndpointStats]
    issues: list[DetectedIssue]
    issues_by_severity: dict[IssueSeverity, int]
    cache_hits: int
    cache_misses: int
    repeated_resources: list[RepeatedResource]
    domains: list[DomainAnalysis] = []
    service_failures: list[ServiceFailureStats] = []
    referer_hostnames: dict[str, int] = Field(default_factory=dict)


# =============================================================================
# Time Utils
# =============================================================================


def capture_window(report: HarAnalysisReport) -> tuple[datetime | None, datetime | None]:
    """Return the earliest and latest timestamps observed in the report."""
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


# =============================================================================
# HAR Analyzer
# =============================================================================


class HarAnalyzer:
    """Extract metrics and detect issues from HAR data."""

    HTTP_STATUS_SUCCESS_MIN = 200
    HTTP_STATUS_REDIRECT_MAX = 400
    HTTP_STATUS_CLIENT_ERROR_MIN = 400
    HTTP_STATUS_SERVER_ERROR_MIN = 500
    HTTP_STATUS_ERROR_MAX = 600

    DURATION_EXCEEDED_THRESHOLD_MS = 30_000
    SLOW_REQUEST_THRESHOLD_MS = 10_000
    LARGE_PAYLOAD_THRESHOLD_BYTES = 1_048_576
    BLOCKING_THRESHOLD_MS = 5_000

    DOMAIN_ERROR_RATE_CRITICAL_PCT = 50.0
    DOMAIN_ERROR_RATE_DEGRADED_PCT = 10.0

    def analyze(self, har: Har) -> HarAnalysisReport:
        """Perform comprehensive analysis of HAR data."""
        entries = har.log.entries
        logger.info(f"Analyzing {len(entries)} entries")

        total_duration = sum(e.time for e in entries)

        def _known_positive_bytes(value: int | None) -> int:
            if value is None:
                return 0
            return value if value > 0 else 0

        total_transferred = sum(
            _known_positive_bytes(e.response.transfer_size)
            or _known_positive_bytes(e.response.body_size)
            for e in entries
        )
        total_downloaded = sum(_known_positive_bytes(e.response.body_size) for e in entries)

        overall_timings = self._compute_timing_stats([e.time for e in entries])
        blocked_timings = self._compute_timing_stats(
            [e.timings.blocked for e in entries if e.timings.blocked >= 0]
        )
        dns_timings = self._compute_timing_stats(
            [e.timings.dns for e in entries if e.timings.dns >= 0]
        )
        connect_timings = self._compute_timing_stats(
            [e.timings.connect for e in entries if e.timings.connect >= 0]
        )
        ssl_timings = self._compute_timing_stats(
            [e.timings.ssl for e in entries if e.timings.ssl >= 0]
        )
        send_timings = self._compute_timing_stats(
            [e.timings.send for e in entries if e.timings.send >= 0]
        )
        ttfb_timings = self._compute_timing_stats([e.timings.wait for e in entries])
        receive_timings = self._compute_timing_stats(
            [e.timings.receive for e in entries if e.timings.receive >= 0]
        )

        status_codes: dict[int, int] = defaultdict(int)
        for entry in entries:
            status_codes[entry.response.status] += 1

        endpoints = self._aggregate_by_endpoint(entries)
        cache_hits, cache_misses = self._compute_cache_stats(entries)
        repeated = self._find_repeated_resources(entries)
        issues = self._detect_issues(entries, endpoints)
        issues_by_sev = self._count_by_severity(issues)
        slowest = self._get_slowest_requests(entries, 20)
        largest = self._get_largest_payloads(entries, 20)
        domains = self._analyze_by_domain(entries, issues)
        service_failures = self._compute_service_failures(entries)
        referer_hostnames = self._compute_referer_hostnames(entries)

        return HarAnalysisReport(
            total_requests=len(entries),
            total_duration_ms=total_duration,
            total_bytes_transferred=total_transferred,
            total_bytes_downloaded=total_downloaded,
            overall_timings=overall_timings,
            blocked_timings=blocked_timings,
            dns_timings=dns_timings,
            connect_timings=connect_timings,
            ssl_timings=ssl_timings,
            send_timings=send_timings,
            ttfb_timings=ttfb_timings,
            receive_timings=receive_timings,
            status_codes=dict(status_codes),
            endpoints=endpoints,
            issues=issues,
            issues_by_severity=issues_by_sev,
            cache_hits=cache_hits,
            cache_misses=cache_misses,
            repeated_resources=repeated,
            slowest_requests=slowest,
            largest_payloads=largest,
            domains=domains,
            service_failures=service_failures,
            referer_hostnames=referer_hostnames,
        )

    def _analyze_by_domain(
        self, entries: list[HarEntry], issues: list[DetectedIssue]
    ) -> list[DomainAnalysis]:
        """Analyze metrics grouped by domain."""
        first_party_domain = ""
        if entries:
            first_party_domain = urlparse(entries[0].request.url).netloc

        by_domain: dict[str, list[HarEntry]] = defaultdict(list)
        for entry in entries:
            domain = urlparse(entry.request.url).netloc
            by_domain[domain].append(entry)

        issues_by_domain: dict[str, list[DetectedIssue]] = defaultdict(list)
        for issue in issues:
            issues_by_domain[issue.domain].append(issue)

        domain_analyses: list[DomainAnalysis] = []
        for domain, domain_entries in by_domain.items():
            failed = sum(
                1
                for e in domain_entries
                if e.response.status == 0
                or e.response.error is not None
                or e.response.status >= self.HTTP_STATUS_CLIENT_ERROR_MIN
            )
            total = len(domain_entries)
            error_rate = (failed / total * 100) if total > 0 else 0.0

            status_dist: dict[int, int] = defaultdict(int)
            for e in domain_entries:
                status_dist[e.response.status] += 1

            timings = self._compute_timing_stats([e.time for e in domain_entries])

            domain_issues = issues_by_domain.get(domain, [])
            has_critical = any(i.issue_type == IssueType.NETWORK_ERROR for i in domain_issues)
            has_high = any(
                i.issue_type in (IssueType.SERVER_ERROR, IssueType.CLIENT_ERROR)
                for i in domain_issues
            )

            if error_rate >= self.DOMAIN_ERROR_RATE_CRITICAL_PCT or has_critical:
                health = DomainHealth.CRITICAL
            elif error_rate >= self.DOMAIN_ERROR_RATE_DEGRADED_PCT or has_high:
                health = DomainHealth.DEGRADED
            else:
                health = DomainHealth.HEALTHY

            domain_analyses.append(
                DomainAnalysis(
                    domain=domain,
                    total_requests=total,
                    failed_requests=failed,
                    error_rate=error_rate,
                    timing_stats=timings,
                    status_codes=dict(status_dist),
                    issue_count=len(domain_issues),
                    health=health,
                    is_first_party=(domain == first_party_domain),
                )
            )

        health_order = {
            DomainHealth.CRITICAL: 0,
            DomainHealth.DEGRADED: 1,
            DomainHealth.HEALTHY: 2,
        }
        return sorted(
            domain_analyses,
            key=lambda d: (health_order[d.health], -d.error_rate),
        )

    def _compute_timing_stats(self, values: list[float]) -> TimingStatistics:
        """Compute percentile statistics."""
        if not values:
            return TimingStatistics(
                count=0, p50=0, p95=0, p99=0, max=0, mean=0, total_duration_ms=0
            )

        sorted_values = sorted(values)
        count = len(sorted_values)

        return TimingStatistics(
            count=count,
            p50=self._percentile(sorted_values, 50),
            p95=self._percentile(sorted_values, 95),
            p99=self._percentile(sorted_values, 99),
            max=sorted_values[-1],
            mean=statistics.mean(values),
            total_duration_ms=sum(values),
        )

    def _percentile(self, sorted_values: list[float], percentile: int) -> float:
        """Calculate percentile from sorted values."""
        if not sorted_values:
            return 0.0
        index = int((percentile / 100) * len(sorted_values))
        return sorted_values[min(index, len(sorted_values) - 1)]

    def _aggregate_by_endpoint(self, entries: list[HarEntry]) -> list[EndpointStats]:
        """Group requests by URL pattern (strip query params)."""
        by_pattern: dict[str, list[HarEntry]] = defaultdict(list)

        for entry in entries:
            pattern = self._simplify_url(entry.request.url)
            by_pattern[pattern].append(entry)

        endpoints: list[EndpointStats] = []
        for pattern, reqs in by_pattern.items():
            status_dist: dict[int, int] = defaultdict(int)
            for req in reqs:
                status_dist[req.response.status] += 1

            endpoints.append(
                EndpointStats(
                    url_pattern=pattern,
                    count=len(reqs),
                    timings=self._compute_timing_stats([r.time for r in reqs]),
                    blocked_timings=self._compute_timing_stats(
                        [r.timings.blocked for r in reqs if r.timings.blocked >= 0]
                    ),
                    dns_timings=self._compute_timing_stats(
                        [r.timings.dns for r in reqs if r.timings.dns >= 0]
                    ),
                    connect_timings=self._compute_timing_stats(
                        [r.timings.connect for r in reqs if r.timings.connect >= 0]
                    ),
                    ssl_timings=self._compute_timing_stats(
                        [r.timings.ssl for r in reqs if r.timings.ssl >= 0]
                    ),
                    send_timings=self._compute_timing_stats(
                        [r.timings.send for r in reqs if r.timings.send >= 0]
                    ),
                    ttfb_timings=self._compute_timing_stats(
                        [r.timings.wait for r in reqs if r.timings.wait >= 0]
                    ),
                    receive_timings=self._compute_timing_stats(
                        [r.timings.receive for r in reqs if r.timings.receive >= 0]
                    ),
                    client_total_timings=self._compute_timing_stats(
                        [
                            (r.timings.blocked if r.timings.blocked >= 0 else 0.0)
                            + (r.timings.send if r.timings.send >= 0 else 0.0)
                            for r in reqs
                            if (r.timings.blocked >= 0 or r.timings.send >= 0)
                        ]
                    ),
                    network_total_timings=self._compute_timing_stats(
                        [
                            (r.timings.dns if r.timings.dns >= 0 else 0.0)
                            + (r.timings.connect if r.timings.connect >= 0 else 0.0)
                            + (r.timings.ssl if r.timings.ssl >= 0 else 0.0)
                            + (r.timings.receive if r.timings.receive >= 0 else 0.0)
                            for r in reqs
                            if (
                                r.timings.dns >= 0
                                or r.timings.connect >= 0
                                or r.timings.ssl >= 0
                                or r.timings.receive >= 0
                            )
                        ]
                    ),
                    status_codes=dict(status_dist),
                    total_bytes=sum(r.response.body_size for r in reqs if r.response.body_size > 0),
                )
            )

        return sorted(endpoints, key=lambda e: e.timings.p95, reverse=True)

    def _simplify_url(self, url: str) -> str:
        """Remove query parameters and fragments from URL."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def _detect_issues(
        self, entries: list[HarEntry], endpoints: list[EndpointStats]
    ) -> list[DetectedIssue]:
        """Run deterministic issue detection based on HAR contents."""
        issues: list[DetectedIssue] = []
        issues.extend(self._detect_network_errors(entries))
        issues.extend(self._detect_duration_exceeded(entries))
        issues.extend(self._detect_http_errors(entries))
        issues.extend(self._detect_large_payloads(entries))
        issues.extend(self._detect_slow_endpoints(entries, endpoints))
        issues.extend(self._detect_blocking(entries))
        issues.extend(self._detect_redirects(entries))

        severity_order = {sev: idx for idx, sev in enumerate(IssueSeverity)}
        return sorted(issues, key=lambda i: (severity_order[i.severity], i.timestamp))

    def _detect_network_errors(self, entries: list[HarEntry]) -> list[DetectedIssue]:
        """Detect network-level failures (status=0 or explicit error field)."""
        issues: list[DetectedIssue] = []
        for entry in entries:
            if entry.response.status == 0 or entry.response.error is not None:
                domain = urlparse(entry.request.url).netloc
                issues.append(
                    DetectedIssue(
                        issue_type=IssueType.NETWORK_ERROR,
                        severity=IssueSeverity.CRITICAL,
                        url=entry.request.url,
                        message=f"Network error: {entry.response.error or 'request failed'}",
                        duration_ms=entry.time,
                        timestamp=entry.started_date_time,
                        details={
                            "method": entry.request.method,
                            "status": entry.response.status,
                            "error": entry.response.error,
                        },
                        domain=domain,
                    )
                )
                self._maybe_add_referer_hostname(issues[-1].details, entry)
        return issues

    def _detect_duration_exceeded(self, entries: list[HarEntry]) -> list[DetectedIssue]:
        """Detect requests that exceed the duration threshold."""
        issues: list[DetectedIssue] = []
        for entry in entries:
            if entry.time > self.DURATION_EXCEEDED_THRESHOLD_MS:
                domain = urlparse(entry.request.url).netloc
                threshold_seconds = self.DURATION_EXCEEDED_THRESHOLD_MS / 1000
                issues.append(
                    DetectedIssue(
                        issue_type=IssueType.DURATION_EXCEEDED,
                        severity=IssueSeverity.CRITICAL,
                        url=entry.request.url,
                        message=(
                            f"Request exceeded {threshold_seconds:.0f}s threshold "
                            f"({entry.time / 1000:.1f}s)"
                        ),
                        duration_ms=entry.time,
                        timestamp=entry.started_date_time,
                        details={
                            "method": entry.request.method,
                            "status": entry.response.status,
                            "wait_time_ms": entry.timings.wait,
                            "threshold_ms": self.DURATION_EXCEEDED_THRESHOLD_MS,
                        },
                        domain=domain,
                    )
                )
                self._maybe_add_referer_hostname(issues[-1].details, entry)
        return issues

    def _detect_http_errors(self, entries: list[HarEntry]) -> list[DetectedIssue]:
        """Detect HTTP 4xx/5xx responses."""
        issues: list[DetectedIssue] = []
        for entry in entries:
            status = entry.response.status
            if self.HTTP_STATUS_SERVER_ERROR_MIN <= status < self.HTTP_STATUS_ERROR_MAX:
                domain = urlparse(entry.request.url).netloc
                issues.append(
                    DetectedIssue(
                        issue_type=IssueType.SERVER_ERROR,
                        severity=IssueSeverity.HIGH,
                        url=entry.request.url,
                        message=f"Server error: {status} {entry.response.status_text}",
                        timestamp=entry.started_date_time,
                        duration_ms=entry.time,
                        details={"status": status, "method": entry.request.method},
                        domain=domain,
                    )
                )
                self._maybe_add_referer_hostname(issues[-1].details, entry)
            elif self.HTTP_STATUS_CLIENT_ERROR_MIN <= status < self.HTTP_STATUS_SERVER_ERROR_MIN:
                domain = urlparse(entry.request.url).netloc
                severity = IssueSeverity.HIGH if status in (401, 403) else IssueSeverity.MEDIUM
                issues.append(
                    DetectedIssue(
                        issue_type=IssueType.CLIENT_ERROR,
                        severity=severity,
                        url=entry.request.url,
                        message=f"Client error: {status} {entry.response.status_text}",
                        timestamp=entry.started_date_time,
                        details={"status": status, "method": entry.request.method},
                        domain=domain,
                    )
                )
                self._maybe_add_referer_hostname(issues[-1].details, entry)
        return issues

    def _detect_large_payloads(self, entries: list[HarEntry]) -> list[DetectedIssue]:
        """Detect large payload responses."""
        issues: list[DetectedIssue] = []
        for entry in entries:
            if entry.response.body_size > self.LARGE_PAYLOAD_THRESHOLD_BYTES:
                domain = urlparse(entry.request.url).netloc
                content_type = self._get_content_type(entry)
                issues.append(
                    DetectedIssue(
                        issue_type=IssueType.LARGE_PAYLOAD,
                        severity=IssueSeverity.MEDIUM,
                        url=entry.request.url,
                        message=f"Large payload: {entry.response.body_size / 1024 / 1024:.1f} MB",
                        size_bytes=entry.response.body_size,
                        timestamp=entry.started_date_time,
                        details={"content_type": content_type, "cached": entry.cache is not None},
                        domain=domain,
                    )
                )
                self._maybe_add_referer_hostname(issues[-1].details, entry)
        return issues

    def _detect_slow_endpoints(
        self, entries: list[HarEntry], endpoints: list[EndpointStats]
    ) -> list[DetectedIssue]:
        """Detect endpoints with high p95 latency."""
        issues: list[DetectedIssue] = []
        for endpoint in endpoints:
            if endpoint.timings.p95 <= self.SLOW_REQUEST_THRESHOLD_MS:
                continue
            domain = urlparse(endpoint.url_pattern).netloc
            endpoint_entries = [
                e for e in entries if self._simplify_url(e.request.url) == endpoint.url_pattern
            ]
            first_seen = min(e.started_date_time for e in endpoint_entries)
            last_seen = max(e.started_date_time for e in endpoint_entries)
            issues.append(
                DetectedIssue(
                    issue_type=IssueType.SLOW_ENDPOINT,
                    severity=IssueSeverity.HIGH,
                    url=endpoint.url_pattern,
                    message=(
                        f"Slow endpoint: p95={endpoint.timings.p95:.0f}ms, "
                        f"p99={endpoint.timings.p99:.0f}ms"
                    ),
                    duration_ms=endpoint.timings.p95,
                    timestamp=last_seen,
                    details={
                        "count": endpoint.count,
                        "p50": endpoint.timings.p50,
                        "p95": endpoint.timings.p95,
                        "p99": endpoint.timings.p99,
                        "first_seen": first_seen.isoformat(),
                        "last_seen": last_seen.isoformat(),
                    },
                    domain=domain,
                )
            )
        return issues

    def _detect_blocking(self, entries: list[HarEntry]) -> list[DetectedIssue]:
        """Detect client-side connection blocking."""
        issues: list[DetectedIssue] = []
        for entry in entries:
            if entry.timings.blocked <= self.BLOCKING_THRESHOLD_MS:
                continue
            domain = urlparse(entry.request.url).netloc
            issues.append(
                DetectedIssue(
                    issue_type=IssueType.BLOCKING,
                    severity=IssueSeverity.MEDIUM,
                    url=entry.request.url,
                    message=f"Client-side blocking: {entry.timings.blocked / 1000:.1f}s",
                    duration_ms=entry.timings.blocked,
                    timestamp=entry.started_date_time,
                    details={"phase": "blocked", "method": entry.request.method},
                    domain=domain,
                )
            )
            self._maybe_add_referer_hostname(issues[-1].details, entry)
        return issues

    def _detect_redirects(self, entries: list[HarEntry]) -> list[DetectedIssue]:
        """Detect redirects (302/303 with redirect target)."""
        issues: list[DetectedIssue] = []
        redirect_statuses = {302, 303}
        for entry in entries:
            if entry.response.status not in redirect_statuses or not entry.response.redirect_url:
                continue
            domain = urlparse(entry.request.url).netloc
            issues.append(
                DetectedIssue(
                    issue_type=IssueType.REDIRECT_CHAIN,
                    severity=IssueSeverity.LOW,
                    url=entry.request.url,
                    message=f"Redirect to {entry.response.redirect_url}",
                    timestamp=entry.started_date_time,
                    details={
                        "status": entry.response.status,
                        "redirect_to": entry.response.redirect_url,
                        "method": entry.request.method,
                    },
                    domain=domain,
                )
            )
            self._maybe_add_referer_hostname(issues[-1].details, entry)
        return issues

    def _maybe_add_referer_hostname(self, details: dict[str, object], entry: HarEntry) -> None:
        """Add referer hostname to issue details when present."""
        referer_hostname = self._extract_referer_hostname(entry)
        if referer_hostname:
            details["referer_hostname"] = referer_hostname

    def _extract_referer_hostname(self, entry: HarEntry) -> str:
        """Extract referer hostname from request headers."""
        for header in entry.request.headers:
            if header.name.lower() == "referer":
                parsed = urlparse(header.value)
                return parsed.netloc
        return ""

    def _compute_referer_hostnames(self, entries: list[HarEntry]) -> dict[str, int]:
        """Compute counts of referer hostnames from request headers."""
        counts: dict[str, int] = defaultdict(int)
        for entry in entries:
            hostname = self._extract_referer_hostname(entry)
            if hostname:
                counts[hostname] += 1
        return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))

    def _get_content_type(self, entry: HarEntry) -> str:
        """Extract content-type header."""
        for header in entry.response.headers:
            if header.name.lower() == "content-type":
                return header.value
        return "unknown"

    def _find_repeated_resources(self, entries: list[HarEntry]) -> list[RepeatedResource]:
        """Find resources downloaded multiple times."""
        url_entries: dict[str, list[HarEntry]] = defaultdict(list)

        for entry in entries:
            url_entries[entry.request.url].append(entry)

        repeated: list[RepeatedResource] = []
        for url, reqs in url_entries.items():
            if len(reqs) > 1:
                total_bytes = sum(r.response.body_size for r in reqs)
                repeated.append(
                    RepeatedResource(
                        url=url,
                        count=len(reqs),
                        total_bytes=total_bytes,
                        size_bytes=reqs[0].response.body_size,
                    )
                )

        return sorted(repeated, key=lambda r: r.total_bytes, reverse=True)[:20]

    def _compute_cache_stats(self, entries: list[HarEntry]) -> tuple[int, int]:
        """Count cache hits vs misses."""
        hits = sum(1 for e in entries if e.cache and e.cache.before_request)
        misses = len(entries) - hits
        return hits, misses

    def _get_slowest_requests(self, entries: list[HarEntry], limit: int) -> list[SlowRequest]:
        """Get top N slowest requests."""
        sorted_entries = sorted(entries, key=lambda e: e.time, reverse=True)[:limit]

        return [
            SlowRequest(
                url=e.request.url,
                method=e.request.method,
                duration_ms=e.time,
                status=e.response.status,
                size_bytes=e.response.body_size,
                timings={
                    "blocked": e.timings.blocked,
                    "dns": e.timings.dns,
                    "connect": e.timings.connect,
                    "ssl": e.timings.ssl,
                    "send": e.timings.send,
                    "wait": e.timings.wait,
                    "receive": e.timings.receive,
                },
            )
            for e in sorted_entries
        ]

    def _get_largest_payloads(self, entries: list[HarEntry], limit: int) -> list[LargePayload]:
        """Get top N largest payloads."""
        sorted_entries = sorted(entries, key=lambda e: e.response.body_size, reverse=True)[:limit]

        return [
            LargePayload(
                url=e.request.url,
                size_mb=e.response.body_size / 1024 / 1024,
                content_type=self._get_content_type(e),
                cached=e.cache is not None and e.cache.before_request is not None,
            )
            for e in sorted_entries
        ]

    def _count_by_severity(self, issues: list[DetectedIssue]) -> dict[IssueSeverity, int]:
        """Count issues by severity."""
        counts: dict[IssueSeverity, int] = defaultdict(int)
        for issue in issues:
            counts[issue.severity] += 1
        return dict(counts)

    def _compute_service_failures(self, entries: list[HarEntry]) -> list[ServiceFailureStats]:
        """Compute backend/API service health grouped by (domain, method, path)."""
        by_service: dict[tuple[str, str, str], list[HarEntry]] = defaultdict(list)

        for entry in entries:
            parsed = urlparse(entry.request.url)
            domain = parsed.netloc
            path = parsed.path or "/"
            by_service[(domain, entry.request.method, path)].append(entry)

        results: list[ServiceFailureStats] = []
        for (domain, method, path), reqs in by_service.items():
            status_codes: dict[int, int] = defaultdict(int)
            for r in reqs:
                status_codes[r.response.status] += 1

            success_count = sum(
                v
                for k, v in status_codes.items()
                if self.HTTP_STATUS_SUCCESS_MIN <= k < self.HTTP_STATUS_REDIRECT_MAX
            )
            status_4xx_count = sum(
                v
                for k, v in status_codes.items()
                if self.HTTP_STATUS_CLIENT_ERROR_MIN <= k < self.HTTP_STATUS_SERVER_ERROR_MIN
            )
            status_5xx_count = sum(
                v
                for k, v in status_codes.items()
                if self.HTTP_STATUS_SERVER_ERROR_MIN <= k < self.HTTP_STATUS_ERROR_MAX
            )
            network_error_count = sum(1 for r in reqs if r.response.status == 0 or r.response.error)
            duration_exceeded_count = sum(
                1 for r in reqs if r.time > self.DURATION_EXCEEDED_THRESHOLD_MS
            )

            network_total_values = [
                (r.timings.dns if r.timings.dns >= 0 else 0.0)
                + (r.timings.connect if r.timings.connect >= 0 else 0.0)
                + (r.timings.ssl if r.timings.ssl >= 0 else 0.0)
                + (r.timings.receive if r.timings.receive >= 0 else 0.0)
                for r in reqs
                if (
                    r.timings.dns >= 0
                    or r.timings.connect >= 0
                    or r.timings.ssl >= 0
                    or r.timings.receive >= 0
                )
            ]

            results.append(
                ServiceFailureStats(
                    domain=domain,
                    method=method,
                    path=path,
                    request_count=len(reqs),
                    success_count=success_count,
                    status_4xx_count=status_4xx_count,
                    status_5xx_count=status_5xx_count,
                    network_error_count=network_error_count,
                    duration_exceeded_count=duration_exceeded_count,
                    status_codes=dict(status_codes),
                    timings=self._compute_timing_stats([r.time for r in reqs]),
                    ttfb_timings=self._compute_timing_stats([r.timings.wait for r in reqs]),
                    network_total_timings=self._compute_timing_stats(network_total_values),
                    first_seen=min(r.started_date_time for r in reqs),
                    last_seen=max(r.started_date_time for r in reqs),
                )
            )

        def sort_key(s: ServiceFailureStats) -> tuple[int, float, int]:
            error_count = s.network_error_count + s.status_5xx_count + s.status_4xx_count
            problem_count = error_count + s.duration_exceeded_count
            problem_rate = problem_count / s.request_count if s.request_count else 0.0
            is_down = 1 if s.success_count == 0 and error_count > 0 else 0
            return (-is_down, -problem_rate, -s.request_count)

        return sorted(results, key=sort_key)


# =============================================================================
# Output Formatter
# =============================================================================

DOMAIN_ERROR_RATE_CRITICAL_PCT = 50.0
DOMAIN_ERROR_RATE_DEGRADED_PCT = 10.0
DOMAIN_TABLE_MAX_ROWS = 20
OUTAGE_TABLE_MAX_ROWS = 25
SERVICE_TABLE_MAX_ROWS = 25
ISSUES_BY_DOMAIN_MAX_DOMAINS = 15
ISSUES_BY_DOMAIN_MAX_ISSUES = 8
MARKDOWN_MAX_ISSUES_PER_SEVERITY = 50
MARKDOWN_TOP_ENDPOINTS = 10


class OutputFormatter:
    """Format analysis results for terminal output and markdown exports."""

    def __init__(
        self,
        *,
        timestamp_timezone: tzinfo | None = None,
        timestamp_timezone_label: str | None = None,
    ) -> None:
        """Create a formatter with optional timestamp timezone conversion."""
        self._timestamp_timezone = timestamp_timezone
        self._timestamp_timezone_label = timestamp_timezone_label

    def print_report(self, report: HarAnalysisReport) -> None:
        """Print a backend/network-focused report to the terminal."""
        self._print_summary(report)
        console.print()

        if report.domains:
            self._print_domain_health(report)
            console.print()

        if report.referer_hostnames:
            self._print_referer_hostnames(report)
            console.print()

        if report.service_failures:
            self._print_outages(report.service_failures, max_rows=OUTAGE_TABLE_MAX_ROWS)
            console.print()
            self._print_service_failures(report.service_failures, max_rows=SERVICE_TABLE_MAX_ROWS)
            console.print()

        backend_error_issues = self._filter_backend_error_issues(report.issues)
        if backend_error_issues:
            self._print_issues_by_domain(backend_error_issues, title="Backend/API Errors by Domain")
            console.print()

        backend_perf_issues = self._filter_backend_perf_issues(report.issues)
        if backend_perf_issues:
            self._print_issues_by_domain(
                backend_perf_issues, title="Backend/API Performance Issues by Domain"
            )
            console.print()

        self._print_top_endpoints(report)

    def generate_markdown_report(self, report: HarAnalysisReport, har_filename: str) -> str:
        """Generate a factual markdown report."""
        lines: list[str] = []
        lines.extend(self._md_header(har_filename))
        lines.extend(self._md_hostnames(report))
        lines.extend(self._md_summary(report))
        lines.extend(self._md_domain_health(report))
        lines.extend(self._md_service_health(report))
        lines.extend(self._md_outages(report))
        lines.extend(
            self._md_issue_group(
                title="Detected Backend/API Error Issues",
                issues=self._filter_backend_error_issues(report.issues),
            )
        )
        lines.extend(
            self._md_issue_group(
                title="Detected Backend/API Performance Issues",
                issues=self._filter_backend_perf_issues(report.issues),
            )
        )
        lines.extend(self._md_top_endpoints(report))
        return "\n".join(lines)

    def _md_header(self, har_filename: str) -> list[str]:
        lines = [f"# HAR Analysis Report: {har_filename}", ""]
        if self._timestamp_timezone_label:
            lines.extend([f"**Timestamp Timezone:** {self._timestamp_timezone_label}", ""])
        lines.extend(["---", ""])
        return lines

    def _md_hostnames(self, report: HarAnalysisReport) -> list[str]:
        hostnames = self._extract_hostnames(report)
        lines = ["## Hostnames", ""]
        lines.extend([f"- {hostname}" for hostname in hostnames])
        lines.append("")
        return lines

    def _md_summary(self, report: HarAnalysisReport) -> list[str]:
        total_status = sum(report.status_codes.values()) or 1
        capture_start, capture_end = capture_window(report)

        lines = ["## Summary", ""]
        lines.append(f"- **Total Requests:** {report.total_requests:,}")
        lines.append(f"- **Total Duration:** {report.total_duration_ms / 1000:.1f}s")
        if capture_start and capture_end:
            lines.append(
                "- **Capture Window:** "
                f"{self._format_timestamp(capture_start)} → {self._format_timestamp(capture_end)}"
            )
        lines.append(
            "- **Total Transferred (best-effort):** "
            f"{report.total_bytes_transferred / 1024 / 1024:.1f} MB"
        )
        lines.extend(
            [
                "",
                "### Timing Percentiles (p50 / p95 / p99)",
                "",
                (
                    f"- **Overall:** {report.overall_timings.p50:.0f}ms / "
                    f"{report.overall_timings.p95:.0f}ms / {report.overall_timings.p99:.0f}ms"
                ),
                (
                    f"- **Blocked (client):** {report.blocked_timings.p50:.0f}ms / "
                    f"{report.blocked_timings.p95:.0f}ms / {report.blocked_timings.p99:.0f}ms"
                ),
                (
                    f"- **DNS (network):** {report.dns_timings.p50:.0f}ms / "
                    f"{report.dns_timings.p95:.0f}ms / {report.dns_timings.p99:.0f}ms"
                ),
                (
                    f"- **Connect (network):** {report.connect_timings.p50:.0f}ms / "
                    f"{report.connect_timings.p95:.0f}ms / {report.connect_timings.p99:.0f}ms"
                ),
                (
                    f"- **SSL (network):** {report.ssl_timings.p50:.0f}ms / "
                    f"{report.ssl_timings.p95:.0f}ms / {report.ssl_timings.p99:.0f}ms"
                ),
                (
                    f"- **Send (client):** {report.send_timings.p50:.0f}ms / "
                    f"{report.send_timings.p95:.0f}ms / {report.send_timings.p99:.0f}ms"
                ),
                (
                    f"- **TTFB (server):** {report.ttfb_timings.p50:.0f}ms / "
                    f"{report.ttfb_timings.p95:.0f}ms / {report.ttfb_timings.p99:.0f}ms"
                ),
                (
                    f"- **Receive (network):** {report.receive_timings.p50:.0f}ms / "
                    f"{report.receive_timings.p95:.0f}ms / {report.receive_timings.p99:.0f}ms"
                ),
                "",
                "### Status Codes",
                "",
            ]
        )
        lines.extend(
            [
                f"- **{code}:** {count:,} ({100 * count / total_status:.1f}%)"
                for code, count in sorted(report.status_codes.items())
            ]
        )
        lines.append("")
        if report.referer_hostnames:
            lines.extend(self._md_referer_hostnames(report))
        return lines

    def _md_referer_hostnames(self, report: HarAnalysisReport) -> list[str]:
        lines = ["### Referer Hostnames (from request headers)", ""]
        for hostname, count in list(report.referer_hostnames.items())[:10]:
            lines.append(f"- `{hostname}`: {count:,}")
        lines.append("")
        return lines

    def _md_domain_health(self, report: HarAnalysisReport) -> list[str]:
        if not report.domains:
            return []
        status_text = {
            DomainHealth.CRITICAL: "CRITICAL",
            DomainHealth.DEGRADED: "DEGRADED",
            DomainHealth.HEALTHY: "HEALTHY",
        }
        lines = [
            "## Domain Health Overview",
            "",
            "| Domain | Requests | Errors | Error Rate | p95 | Status |",
            "|--------|----------|--------|------------|-----|--------|",
        ]
        lines.extend(
            [
                (
                    f"| `{domain.domain}` | {domain.total_requests} | {domain.failed_requests} | "
                    f"{domain.error_rate:.1f}% | {domain.timing_stats.p95:.0f}ms | "
                    f"**{status_text[domain.health]}** |"
                )
                for domain in report.domains
            ]
        )
        lines.append("")
        return lines

    def _md_service_health(self, report: HarAnalysisReport) -> list[str]:
        failing = self._failing_services(report.service_failures)
        if not failing:
            return []
        lines = ["## Backend/API Service Health (Factual)", ""]
        lines.append(
            "| Domain | Method | Path | Req | OK | NetErr | 5xx | 4xx | >30s | "
            "ProblemRate | p95 total | p95 TTFB | p95 net |"
        )
        lines.append(
            "|--------|--------|------|-----|----|--------|-----|-----|------|"
            "------------|----------|----------|--------|"
        )
        lines.extend([self._md_service_row(s) for s in failing])
        lines.append("")
        return lines

    def _md_outages(self, report: HarAnalysisReport) -> list[str]:
        outages = self._outages(report.service_failures)
        if not outages:
            return []
        lines = ["## Outages (100% Error Rate)", ""]
        lines.append(
            "| Domain | Method | Path | Req | NetErr | 5xx | 4xx | First Seen | Last Seen |"
        )
        lines.append("|--------|--------|------|-----|--------|-----|-----|-----------|----------|")
        lines.extend(
            [
                (
                    f"| `{s.domain}` | `{s.method}` | `{s.path}` | {s.request_count} | "
                    f"{s.network_error_count} | {s.status_5xx_count} | {s.status_4xx_count} | "
                    f"`{self._format_timestamp(s.first_seen)}` | "
                    f"`{self._format_timestamp(s.last_seen)}` |"
                )
                for s in outages
            ]
        )
        lines.append("")
        return lines

    def _md_issue_group(self, title: str, issues: list[DetectedIssue]) -> list[str]:
        if not issues:
            return []
        lines = [f"## {title}", ""]
        for severity in (
            IssueSeverity.CRITICAL,
            IssueSeverity.HIGH,
            IssueSeverity.MEDIUM,
            IssueSeverity.LOW,
        ):
            severity_issues = [i for i in issues if i.severity == severity]
            if not severity_issues:
                continue
            lines.append(f"### {severity.value.upper()} ({len(severity_issues)})")
            lines.append("")
            for issue in severity_issues[:MARKDOWN_MAX_ISSUES_PER_SEVERITY]:
                lines.extend(self._md_issue_detail(issue))
            if len(severity_issues) > MARKDOWN_MAX_ISSUES_PER_SEVERITY:
                remaining = len(severity_issues) - MARKDOWN_MAX_ISSUES_PER_SEVERITY
                lines.append(f"*... and {remaining} more in this severity*")
                lines.append("")
        return lines

    def _md_issue_detail(self, issue: DetectedIssue) -> list[str]:
        path = self._extract_path(issue.url)
        method = issue.details.get("method")
        method_str = f"{method} " if method else ""
        referer = issue.details.get("referer_hostname")
        lines = [
            f"- **{issue.message}**",
            f"  - Request: `{method_str}{path}`",
            f"  - Domain: `{issue.domain}`",
            f"  - Timestamp: `{self._format_timestamp(issue.timestamp)}`",
        ]
        if referer:
            lines.append(f"  - Referer Hostname: `{referer}`")
        if issue.duration_ms is not None:
            lines.append(f"  - Duration: {issue.duration_ms:.0f}ms")
        for key, value in issue.details.items():
            if key in ("method", "referer_hostname"):
                continue
            lines.append(f"  - {key}: {value}")
        lines.append("")
        return lines

    def _md_top_endpoints(self, report: HarAnalysisReport) -> list[str]:
        filtered_endpoints = [
            e for e in report.endpoints if not self._is_static_asset(e.url_pattern)
        ]
        if not filtered_endpoints:
            return []
        lines = ["## Top 10 Slowest Endpoints (Attribution)", ""]
        lines.append("| Endpoint Path | Count | p95 total | p95 TTFB | p95 net | Dominant |")
        lines.append("|---------------|-------|----------|----------|--------|----------|")
        for endpoint in filtered_endpoints[:MARKDOWN_TOP_ENDPOINTS]:
            path = self._extract_path(endpoint.url_pattern)
            p95_net = (
                endpoint.network_total_timings.p95 if endpoint.network_total_timings.count else None
            )
            p95_ttfb = endpoint.ttfb_timings.p95
            dominant = "server" if (p95_net is None or p95_ttfb >= p95_net) else "network"
            p95_net_str = f"{p95_net:.0f}ms" if p95_net is not None else "-"
            lines.append(
                f"| `{path}` | {endpoint.count} | {endpoint.timings.p95:.0f}ms | "
                f"{p95_ttfb:.0f}ms | {p95_net_str} | **{dominant}** |"
            )
        lines.append("")
        return lines

    def _extract_hostnames(self, report: HarAnalysisReport) -> list[str]:
        hostnames: set[str] = set()
        for endpoint in report.endpoints:
            parsed = urlparse(endpoint.url_pattern)
            if parsed.netloc:
                hostnames.add(f"{parsed.scheme}://{parsed.netloc}")
        return sorted(hostnames)

    def _extract_path(self, url: str) -> str:
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        return path

    def _print_summary(self, report: HarAnalysisReport) -> None:
        hostnames = self._extract_hostnames(report)
        hostname_lines = ["**Hostnames:**", *[f"- {h}" for h in hostnames], ""]
        total_transferred_mb = report.total_bytes_transferred / 1024 / 1024
        capture_start, capture_end = capture_window(report)

        summary_lines: list[str] = [*hostname_lines]
        summary_lines.append(f"**Total Requests:** {report.total_requests:,}")
        summary_lines.append(f"**Total Duration:** {report.total_duration_ms / 1000:.1f}s")
        if capture_start and capture_end:
            summary_lines.append(
                "**Capture Window:** "
                f"{self._format_timestamp(capture_start)} → {self._format_timestamp(capture_end)}"
            )
        if self._timestamp_timezone_label:
            summary_lines.append(f"**Timestamp Timezone:** {self._timestamp_timezone_label}")
        summary_lines.append(f"**Total Transferred (best-effort):** {total_transferred_mb:.1f} MB")
        summary_lines.extend(
            [
                "**Focus:** Backend/API & network diagnostics",
                "",
                "**Timing Percentiles (p50 / p95 / p99):**",
                self._format_timing_line("Overall", report.overall_timings),
                self._format_timing_line("Blocked (client)", report.blocked_timings),
                self._format_timing_line("DNS (network)", report.dns_timings),
                self._format_timing_line("Connect (network)", report.connect_timings),
                self._format_timing_line("SSL (network)", report.ssl_timings),
                self._format_timing_line("Send (client)", report.send_timings),
                self._format_timing_line("TTFB (server)", report.ttfb_timings),
                self._format_timing_line("Receive (network)", report.receive_timings),
                "",
                "**Status Codes:**",
                self._format_status_codes(report.status_codes),
            ]
        )

        console.print(
            Panel(
                Markdown("\n".join(summary_lines)),
                title="[bold green]HAR Analysis Summary[/bold green]",
                border_style="green",
            )
        )

    def _format_timestamp(self, ts: datetime, *, timespec: str = "seconds") -> str:
        if self._timestamp_timezone is None:
            return ts.isoformat(timespec=timespec)
        if ts.tzinfo is None:
            return ts.isoformat(timespec=timespec)
        return ts.astimezone(self._timestamp_timezone).isoformat(timespec=timespec)

    def _format_timing_line(self, label: str, timing: TimingStatistics) -> str:
        return f"- {label}: {timing.p50:.0f}ms / {timing.p95:.0f}ms / {timing.p99:.0f}ms"

    def _format_status_codes(self, status_codes: dict[int, int]) -> str:
        total = sum(status_codes.values()) or 1
        lines: list[str] = []
        for code, count in sorted(status_codes.items()):
            pct = 100 * count / total
            lines.append(f"- {code}: {count:,} ({pct:.1f}%)")
        return "\n".join(lines)

    def _print_domain_health(self, report: HarAnalysisReport) -> None:
        table = Table(title="Domain Health Overview")

        table.add_column("Domain", style="cyan", no_wrap=False)
        table.add_column("Requests", justify="right")
        table.add_column("Errors", justify="right")
        table.add_column("Error Rate", justify="right")
        table.add_column("p95 total", justify="right")
        table.add_column("Status", justify="center")

        health_styles = {
            DomainHealth.CRITICAL: ("bold red", "CRITICAL"),
            DomainHealth.DEGRADED: ("yellow", "DEGRADED"),
            DomainHealth.HEALTHY: ("green", "HEALTHY"),
        }

        for domain in report.domains[:DOMAIN_TABLE_MAX_ROWS]:
            style, status_text = health_styles[domain.health]
            if domain.error_rate >= DOMAIN_ERROR_RATE_CRITICAL_PCT:
                error_rate_style = "red"
            elif domain.error_rate >= DOMAIN_ERROR_RATE_DEGRADED_PCT:
                error_rate_style = "yellow"
            else:
                error_rate_style = ""

            table.add_row(
                domain.domain,
                str(domain.total_requests),
                str(domain.failed_requests),
                f"[{error_rate_style}]{domain.error_rate:.1f}%[/{error_rate_style}]"
                if error_rate_style
                else f"{domain.error_rate:.1f}%",
                f"{domain.timing_stats.p95:.0f}ms",
                f"[{style}]{status_text}[/{style}]",
            )

        console.print(table)

    def _outages(self, services: list[ServiceFailureStats]) -> list[ServiceFailureStats]:
        return [
            s
            for s in services
            if s.success_count == 0
            and (s.network_error_count + s.status_5xx_count + s.status_4xx_count) > 0
            and not self._is_static_path(s.path)
        ]

    def _failing_services(self, services: list[ServiceFailureStats]) -> list[ServiceFailureStats]:
        return [
            s
            for s in services
            if (
                s.network_error_count
                + s.status_5xx_count
                + s.status_4xx_count
                + s.duration_exceeded_count
            )
            > 0
            and not self._is_static_path(s.path)
        ]

    def _print_outages(self, services: list[ServiceFailureStats], max_rows: int) -> None:
        outages = self._outages(services)
        if not outages:
            return

        table = Table(title="Outages (100% Error Rate)")
        table.add_column("Domain", style="cyan", no_wrap=False)
        table.add_column("Method", style="cyan", no_wrap=True)
        table.add_column("Path", style="cyan", no_wrap=False)
        table.add_column("Req", justify="right")
        table.add_column("NetErr", justify="right", style="red")
        table.add_column("5xx", justify="right", style="red")
        table.add_column("4xx", justify="right", style="yellow")
        table.add_column("First Seen", justify="right")
        table.add_column("Last Seen", justify="right")

        for s in outages[:max_rows]:
            table.add_row(
                s.domain,
                s.method,
                s.path,
                str(s.request_count),
                str(s.network_error_count) if s.network_error_count else "-",
                str(s.status_5xx_count) if s.status_5xx_count else "-",
                str(s.status_4xx_count) if s.status_4xx_count else "-",
                self._format_timestamp(s.first_seen, timespec="seconds"),
                self._format_timestamp(s.last_seen, timespec="seconds"),
            )

        console.print(table)

    def _print_service_failures(self, services: list[ServiceFailureStats], max_rows: int) -> None:
        failing = self._failing_services(services)
        if not failing:
            return

        table = Table(title="Backend/API Service Health (Factual)")
        table.add_column("Domain", style="cyan", no_wrap=False)
        table.add_column("Method", style="cyan", no_wrap=True)
        table.add_column("Path", style="cyan", no_wrap=False)
        table.add_column("Req", justify="right")
        table.add_column("OK", justify="right", style="green")
        table.add_column("NetErr", justify="right", style="red")
        table.add_column("5xx", justify="right", style="red")
        table.add_column("4xx", justify="right", style="yellow")
        table.add_column(">30s", justify="right", style="red")
        table.add_column("ProblemRate", justify="right", style="bold")
        table.add_column("p95 total", justify="right")
        table.add_column("p95 TTFB", justify="right")
        table.add_column("p95 net", justify="right")

        for s in failing[:max_rows]:
            problem_count = (
                s.network_error_count
                + s.status_5xx_count
                + s.status_4xx_count
                + s.duration_exceeded_count
            )
            problem_rate = 100.0 * problem_count / s.request_count if s.request_count else 0.0
            p95_net = s.network_total_timings.p95 if s.network_total_timings.count else None
            table.add_row(
                s.domain,
                s.method,
                s.path,
                str(s.request_count),
                str(s.success_count) if s.success_count else "-",
                str(s.network_error_count) if s.network_error_count else "-",
                str(s.status_5xx_count) if s.status_5xx_count else "-",
                str(s.status_4xx_count) if s.status_4xx_count else "-",
                str(s.duration_exceeded_count) if s.duration_exceeded_count else "-",
                f"{problem_rate:.1f}%",
                f"{s.timings.p95:.0f}ms",
                f"{s.ttfb_timings.p95:.0f}ms",
                f"{p95_net:.0f}ms" if p95_net is not None else "-",
            )

        console.print(table)
        if len(failing) > max_rows:
            console.print(f"[dim]... and {len(failing) - max_rows} more failing services[/dim]")

    def _print_issues_by_domain(self, issues: list[DetectedIssue], title: str) -> None:
        issues_by_domain: dict[str, list[DetectedIssue]] = defaultdict(list)
        for issue in issues:
            issues_by_domain[issue.domain].append(issue)

        def domain_sort_key(domain_issues: tuple[str, list[DetectedIssue]]) -> tuple[int, int]:
            _, domain_issue_list = domain_issues
            worst = min(
                (i.severity for i in domain_issue_list),
                key=lambda s: list(IssueSeverity).index(s),
            )
            return (list(IssueSeverity).index(worst), -len(domain_issue_list))

        sorted_domains = sorted(issues_by_domain.items(), key=domain_sort_key)

        tree = Tree(f"[bold]{title}[/bold]")
        severity_colors = {
            IssueSeverity.CRITICAL: "red",
            IssueSeverity.HIGH: "orange1",
            IssueSeverity.MEDIUM: "yellow",
            IssueSeverity.LOW: "blue",
        }

        for domain, domain_issues in sorted_domains[:ISSUES_BY_DOMAIN_MAX_DOMAINS]:
            worst = min(domain_issues, key=lambda i: list(IssueSeverity).index(i.severity)).severity
            domain_color = severity_colors[worst]

            type_counts: dict[IssueType, int] = defaultdict(int)
            for issue in domain_issues:
                type_counts[issue.issue_type] += 1
            type_summary = ", ".join(
                f"{count} {issue_type.value}"
                for issue_type, count in sorted(type_counts.items(), key=lambda x: x[0].value)
            )

            domain_branch = tree.add(
                f"[{domain_color}]{domain}[/{domain_color}] "
                f"({len(domain_issues)} issues: {type_summary})"
            )

            for issue in domain_issues[:ISSUES_BY_DOMAIN_MAX_ISSUES]:
                color = severity_colors[issue.severity]
                path = self._extract_path(issue.url)
                method = issue.details.get("method")
                method_str = f"{method} " if method else ""
                ts = self._format_timestamp(issue.timestamp, timespec="seconds")
                referer = issue.details.get("referer_hostname")
                referer_str = f" referer={referer}" if referer else ""
                domain_branch.add(
                    f"[{color}]{issue.message}[/{color}]: {method_str}{path} "
                    f"[bold magenta]@ {ts}[/bold magenta][dim]{referer_str}[/dim]"
                )

            if len(domain_issues) > ISSUES_BY_DOMAIN_MAX_ISSUES:
                more = len(domain_issues) - ISSUES_BY_DOMAIN_MAX_ISSUES
                domain_branch.add(f"[dim]... and {more} more[/dim]")

        if len(sorted_domains) > ISSUES_BY_DOMAIN_MAX_DOMAINS:
            remaining_domains = len(sorted_domains) - ISSUES_BY_DOMAIN_MAX_DOMAINS
            tree.add(f"[dim]... and {remaining_domains} more domains[/dim]")

        console.print(tree)

    def _print_top_endpoints(self, report: HarAnalysisReport) -> None:
        filtered = [e for e in report.endpoints if not self._is_static_asset(e.url_pattern)]
        if not filtered:
            return

        table = Table(title="Top 10 Slowest Endpoints (Attribution)")
        table.add_column("Endpoint Path", style="cyan", no_wrap=False)
        table.add_column("Count", justify="right")
        table.add_column("p95 total", justify="right", style="yellow")
        table.add_column("p95 TTFB", justify="right", style="red")
        table.add_column("p95 net", justify="right")
        table.add_column("Dominant", justify="center")

        for endpoint in filtered[:MARKDOWN_TOP_ENDPOINTS]:
            path = self._extract_path(endpoint.url_pattern)
            p95_net = (
                endpoint.network_total_timings.p95 if endpoint.network_total_timings.count else None
            )
            p95_ttfb = endpoint.ttfb_timings.p95
            dominant = "server" if (p95_net is None or p95_ttfb >= p95_net) else "network"
            table.add_row(
                path,
                str(endpoint.count),
                f"{endpoint.timings.p95:.0f}ms",
                f"{p95_ttfb:.0f}ms",
                f"{p95_net:.0f}ms" if p95_net is not None else "-",
                dominant,
            )

        console.print(table)

    def _print_referer_hostnames(self, report: HarAnalysisReport) -> None:
        table = Table(title="Referer Hostnames (from request headers)")
        table.add_column("Referer Hostname", style="cyan", no_wrap=False)
        table.add_column("Requests", justify="right")

        for hostname, count in list(report.referer_hostnames.items())[:10]:
            table.add_row(hostname, str(count))

        console.print(table)

    def _md_service_row(self, s: ServiceFailureStats) -> str:
        problem_count = (
            s.network_error_count
            + s.status_5xx_count
            + s.status_4xx_count
            + s.duration_exceeded_count
        )
        problem_rate = 100.0 * problem_count / s.request_count if s.request_count else 0.0
        p95_net = s.network_total_timings.p95 if s.network_total_timings.count else None
        p95_net_str = f"{p95_net:.0f}ms" if p95_net is not None else "-"
        return (
            f"| `{s.domain}` | `{s.method}` | `{s.path}` | {s.request_count} | "
            f"{s.success_count} | {s.network_error_count} | {s.status_5xx_count} | "
            f"{s.status_4xx_count} | {s.duration_exceeded_count} | {problem_rate:.1f}% | "
            f"{s.timings.p95:.0f}ms | {s.ttfb_timings.p95:.0f}ms | {p95_net_str} |"
        )

    def _filter_backend_error_issues(self, issues: list[DetectedIssue]) -> list[DetectedIssue]:
        error_types = {
            IssueType.NETWORK_ERROR,
            IssueType.SERVER_ERROR,
            IssueType.CLIENT_ERROR,
        }
        return [
            i for i in issues if i.issue_type in error_types and not self._is_static_asset(i.url)
        ]

    def _filter_backend_perf_issues(self, issues: list[DetectedIssue]) -> list[DetectedIssue]:
        perf_types = {IssueType.DURATION_EXCEEDED, IssueType.SLOW_ENDPOINT, IssueType.BLOCKING}
        return [
            i for i in issues if i.issue_type in perf_types and not self._is_static_asset(i.url)
        ]

    def _is_static_asset(self, url: str) -> bool:
        parsed = urlparse(url)
        path = (parsed.path or "").lower()
        static_suffixes = (
            ".css",
            ".js",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".svg",
            ".ico",
            ".woff",
            ".woff2",
            ".ttf",
            ".otf",
            ".eot",
            ".map",
        )
        if path.endswith(static_suffixes):
            return True
        static_prefixes = ("/images/", "/styles/", "/static/", "/assets/", "/fonts/")
        return path.startswith(static_prefixes)

    def _is_static_path(self, path: str) -> bool:
        """Heuristic for service paths to exclude static assets."""
        path_lower = (path or "").lower()
        static_suffixes = (
            ".css",
            ".js",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".svg",
            ".ico",
            ".woff",
            ".woff2",
            ".ttf",
            ".otf",
            ".eot",
            ".map",
        )
        if path_lower.endswith(static_suffixes):
            return True
        static_prefixes = ("/images/", "/styles/", "/static/", "/assets/", "/fonts/")
        return path_lower.startswith(static_prefixes)


# =============================================================================
# CLI
# =============================================================================

app = typer.Typer(
    name="har-analyzer",
    help="Analyze HAR files with deterministic performance insights",
    add_completion=False,
)


@app.callback()
def callback() -> None:
    """HAR file analyzer with deterministic performance insights."""
    pass


@app.command()
def version() -> None:
    """Show version information."""
    typer.echo(f"har-analyzer version {__version__}")


def setup_logging(verbose: bool) -> None:
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _resolve_timestamp_timezone(
    timezone_value: str | None,
    local_time: bool,
) -> tuple[tzinfo | None, str | None]:
    if local_time and timezone_value is not None:
        raise typer.BadParameter("--local-time cannot be used with --timezone")

    if local_time:
        local_tz = datetime.now().astimezone().tzinfo
        return local_tz or UTC, "local"

    if timezone_value is None:
        return None, None

    normalized = timezone_value.strip()
    lowered = normalized.lower()
    if lowered == "utc":
        return UTC, "UTC"
    if lowered == "local":
        local_tz = datetime.now().astimezone().tzinfo
        return local_tz or UTC, "local"

    try:
        return ZoneInfo(normalized), normalized
    except ZoneInfoNotFoundError as exc:
        raise typer.BadParameter(f"Unknown timezone: {normalized}") from exc


@app.command()
def analyze(
    har_file: Path = typer.Argument(  # noqa: B008
        ..., exists=True, file_okay=True, dir_okay=False, readable=True, help="Path to HAR file"
    ),
    export: Path | None = typer.Option(  # noqa: B008
        None, "--export", "-e", help="Export analysis to Markdown file"
    ),
    timezone: str | None = typer.Option(
        None,
        "--timezone",
        "-t",
        help="Convert displayed timestamps to timezone (e.g. UTC, local, America/New_York)",
    ),
    local_time: bool = typer.Option(
        False,
        "--local-time",
        help="Convert displayed timestamps to your local timezone",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging"),
) -> None:
    """Analyze a HAR file and generate performance insights."""
    setup_logging(verbose)

    timestamp_timezone, timestamp_timezone_label = _resolve_timestamp_timezone(timezone, local_time)

    try:
        # Parse HAR file
        logger.info(f"Parsing HAR file: {har_file}")
        with har_file.open("r", encoding="utf-8") as f:
            raw_data = json.load(f)
        har = Har.model_validate(raw_data)
        logger.info(f"Parsed {len(har.log.entries)} entries")

        # Analyze
        analyzer = HarAnalyzer()
        report = analyzer.analyze(har)
        logger.info(f"Detected {len(report.issues)} issues")

        # Format output
        formatter = OutputFormatter(
            timestamp_timezone=timestamp_timezone,
            timestamp_timezone_label=timestamp_timezone_label,
        )

        if export:
            markdown_content = formatter.generate_markdown_report(report, har_file.name)
            export.write_text(markdown_content, encoding="utf-8")
            typer.echo(f"Markdown report exported to: {export}")
        else:
            formatter.print_report(report)

    except KeyboardInterrupt:
        typer.echo("\n\nInterrupted by user", err=True)
        raise typer.Exit(130) from None
    except Exception as e:
        typer.echo(f"\nError: {e}", err=True)
        raise typer.Exit(1) from e


def main() -> None:
    """CLI entry point."""
    app()


if __name__ == "__main__":
    main()
