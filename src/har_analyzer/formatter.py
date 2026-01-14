"""Terminal and markdown output formatting.

Output is intentionally factual: it reports only what can be derived from the HAR file and
deterministic analysis.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, tzinfo
from urllib.parse import urlparse

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from .models.analysis import DomainHealth, HarAnalysisReport, ServiceFailureStats, TimingStatistics
from .models.issues import DetectedIssue, IssueSeverity, IssueType
from .time_utils import capture_window

console = Console()

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
        lines.extend(
            [
                "*Note: This report contains only deterministic findings derived from the HAR.*",
                "",
                "---",
                "",
            ]
        )
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
            if key == "method":
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
        """Heuristic for service paths (no scheme/host) to exclude static assets."""
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
