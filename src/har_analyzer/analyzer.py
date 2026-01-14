"""Core analysis logic with metrics extraction and issue detection."""

from __future__ import annotations

import logging
import statistics
from collections import defaultdict
from urllib.parse import urlparse

from .models.analysis import (
    DomainAnalysis,
    DomainHealth,
    EndpointStats,
    HarAnalysisReport,
    LargePayload,
    RepeatedResource,
    ServiceFailureStats,
    SlowRequest,
    TimingStatistics,
)
from .models.har import Har, HarEntry
from .models.issues import DetectedIssue, IssueSeverity, IssueType

logger = logging.getLogger(__name__)


class HarAnalyzer:
    """Extract metrics and detect issues from HAR data."""

    # HTTP status helpers
    HTTP_STATUS_SUCCESS_MIN = 200
    HTTP_STATUS_REDIRECT_MAX = 400
    HTTP_STATUS_CLIENT_ERROR_MIN = 400
    HTTP_STATUS_SERVER_ERROR_MIN = 500
    HTTP_STATUS_ERROR_MAX = 600

    # Configurable thresholds
    DURATION_EXCEEDED_THRESHOLD_MS = 30_000  # 30s (threshold, not necessarily a true timeout)
    SLOW_REQUEST_THRESHOLD_MS = 10_000  # 10s
    LARGE_PAYLOAD_THRESHOLD_BYTES = 1_048_576  # 1MB
    BLOCKING_THRESHOLD_MS = 5_000  # 5s

    DOMAIN_ERROR_RATE_CRITICAL_PCT = 50.0
    DOMAIN_ERROR_RATE_DEGRADED_PCT = 10.0

    def analyze(self, har: Har) -> HarAnalysisReport:
        """Perform comprehensive analysis of HAR data.

        Args:
            har: Parsed HAR object

        Returns:
            Complete analysis report
        """
        entries = har.log.entries
        logger.info(f"Analyzing {len(entries)} entries")

        # Aggregate metrics (bytes are best-effort; HAR frequently uses -1 for unknown sizes)
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

        # Timing statistics
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

        # Status code distribution
        status_codes: dict[int, int] = defaultdict(int)
        for entry in entries:
            status_codes[entry.response.status] += 1

        # Endpoint aggregation
        endpoints = self._aggregate_by_endpoint(entries)

        # Cache analysis
        cache_hits, cache_misses = self._compute_cache_stats(entries)
        repeated = self._find_repeated_resources(entries)

        # Issue detection
        issues = self._detect_issues(entries, endpoints)
        issues_by_sev = self._count_by_severity(issues)

        # Top problematic requests
        slowest = self._get_slowest_requests(entries, 20)
        largest = self._get_largest_payloads(entries, 20)

        # Domain analysis
        domains = self._analyze_by_domain(entries, issues)

        # Backend/API service health
        service_failures = self._compute_service_failures(entries)
        referer_hostnames = self._compute_referer_hostnames(entries)

        # Create report
        report = HarAnalysisReport(
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

        return report

    def _analyze_by_domain(
        self, entries: list[HarEntry], issues: list[DetectedIssue]
    ) -> list[DomainAnalysis]:
        """Analyze metrics grouped by domain.

        Args:
            entries: HAR entries
            issues: Detected issues

        Returns:
            List of per-domain analysis
        """
        # Determine first-party domain (from first request)
        first_party_domain = ""
        if entries:
            first_party_domain = urlparse(entries[0].request.url).netloc

        # Group entries by domain
        by_domain: dict[str, list[HarEntry]] = defaultdict(list)
        for entry in entries:
            domain = urlparse(entry.request.url).netloc
            by_domain[domain].append(entry)

        # Group issues by domain
        issues_by_domain: dict[str, list[DetectedIssue]] = defaultdict(list)
        for issue in issues:
            issues_by_domain[issue.domain].append(issue)

        domain_analyses: list[DomainAnalysis] = []
        for domain, domain_entries in by_domain.items():
            # Count errors
            failed = sum(
                1
                for e in domain_entries
                if e.response.status == 0
                or e.response.error is not None
                or e.response.status >= self.HTTP_STATUS_CLIENT_ERROR_MIN
            )
            total = len(domain_entries)
            error_rate = (failed / total * 100) if total > 0 else 0.0

            # Status codes
            status_dist: dict[int, int] = defaultdict(int)
            for e in domain_entries:
                status_dist[e.response.status] += 1

            # Timing stats
            timings = self._compute_timing_stats([e.time for e in domain_entries])

            # Issue count (domain health considers only error-class issues)
            domain_issues = issues_by_domain.get(domain, [])
            has_critical = any(i.issue_type == IssueType.NETWORK_ERROR for i in domain_issues)
            has_high = any(
                i.issue_type in (IssueType.SERVER_ERROR, IssueType.CLIENT_ERROR)
                for i in domain_issues
            )

            # Determine health status
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

        # Sort by health (critical first), then by error rate
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

        # Sort by p95 descending (slowest first)
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
                issue_type = IssueType.NETWORK_ERROR
                issues.append(
                    DetectedIssue(
                        issue_type=issue_type,
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
                issue_type = IssueType.DURATION_EXCEEDED
                threshold_seconds = self.DURATION_EXCEEDED_THRESHOLD_MS / 1000
                issues.append(
                    DetectedIssue(
                        issue_type=issue_type,
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
                issue_type = IssueType.SERVER_ERROR
                issues.append(
                    DetectedIssue(
                        issue_type=issue_type,
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
                issue_type = IssueType.CLIENT_ERROR
                severity = IssueSeverity.HIGH if status in (401, 403) else IssueSeverity.MEDIUM
                issues.append(
                    DetectedIssue(
                        issue_type=issue_type,
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
                issue_type = IssueType.LARGE_PAYLOAD
                content_type = self._get_content_type(entry)
                issues.append(
                    DetectedIssue(
                        issue_type=issue_type,
                        severity=IssueSeverity.MEDIUM,
                        url=entry.request.url,
                        message=(f"Large payload: {entry.response.body_size / 1024 / 1024:.1f} MB"),
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
            issue_type = IssueType.SLOW_ENDPOINT
            endpoint_entries = [
                e for e in entries if self._simplify_url(e.request.url) == endpoint.url_pattern
            ]
            first_seen = min(e.started_date_time for e in endpoint_entries)
            last_seen = max(e.started_date_time for e in endpoint_entries)
            issues.append(
                DetectedIssue(
                    issue_type=issue_type,
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
            issue_type = IssueType.BLOCKING
            issues.append(
                DetectedIssue(
                    issue_type=issue_type,
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
            issue_type = IssueType.REDIRECT_CHAIN
            issues.append(
                DetectedIssue(
                    issue_type=issue_type,
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

        # Sort by total bytes descending
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
        """Compute backend/API service health grouped by (domain, method, path without query)."""
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
