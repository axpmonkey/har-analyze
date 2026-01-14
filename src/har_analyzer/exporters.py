"""Export analysis results to JSON and CSV formats."""

from __future__ import annotations

import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from .models.analysis import HarAnalysisReport
from .time_utils import capture_window

logger = logging.getLogger(__name__)

HTTP_STATUS_SUCCESS_MIN = 200
HTTP_STATUS_REDIRECT_MIN = 300
HTTP_STATUS_CLIENT_ERROR_MIN = 400
HTTP_STATUS_SERVER_ERROR_MIN = 500
HTTP_STATUS_MAX = 600


class JSONExporter:
    """Export analysis report to JSON format."""

    def export(
        self,
        report: HarAnalysisReport,
        output_path: Path,
        har_filename: str = "",
    ) -> None:
        """Export report to JSON file.

        Args:
            report: Analysis report to export
            output_path: Path to write JSON file
            har_filename: Name of the analyzed HAR file
        """
        data = self._build_export_dict(report, har_filename)

        with output_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=self._json_serializer)

        logger.info(f"Exported JSON report to {output_path}")

    def export_string(
        self,
        report: HarAnalysisReport,
        har_filename: str = "",
    ) -> str:
        """Export report to JSON string.

        Args:
            report: Analysis report to export
            har_filename: Name of the analyzed HAR file

        Returns:
            JSON string
        """
        data = self._build_export_dict(report, har_filename)
        return json.dumps(data, indent=2, default=self._json_serializer)

    def _build_export_dict(
        self,
        report: HarAnalysisReport,
        har_filename: str,
    ) -> dict[str, Any]:
        """Build export dictionary from report.

        Args:
            report: Analysis report
            har_filename: HAR filename

        Returns:
            Dictionary for JSON export
        """
        capture_start, capture_end = capture_window(report)
        return {
            "metadata": {
                "har_filename": har_filename,
                "version": "1.0",
                "capture_start": capture_start.isoformat() if capture_start else None,
                "capture_end": capture_end.isoformat() if capture_end else None,
            },
            "summary": {
                "total_requests": report.total_requests,
                "total_duration_ms": report.total_duration_ms,
                "total_bytes_transferred": report.total_bytes_transferred,
                "total_bytes_downloaded": report.total_bytes_downloaded,
                "cache_hits": report.cache_hits,
                "cache_misses": report.cache_misses,
                "cache_hit_rate": (
                    report.cache_hits / (report.cache_hits + report.cache_misses) * 100
                    if (report.cache_hits + report.cache_misses) > 0
                    else 0
                ),
            },
            "timing_stats": {
                "overall": report.overall_timings.model_dump(),
                "blocked": report.blocked_timings.model_dump(),
                "dns": report.dns_timings.model_dump(),
                "connect": report.connect_timings.model_dump(),
                "ssl": report.ssl_timings.model_dump(),
                "send": report.send_timings.model_dump(),
                "ttfb": report.ttfb_timings.model_dump(),
                "receive": report.receive_timings.model_dump(),
            },
            "status_codes": report.status_codes,
            "domains": [d.model_dump() for d in report.domains],
            "issues": [
                {
                    **i.model_dump(),
                    "timestamp": i.timestamp.isoformat(),
                }
                for i in report.issues
            ],
            "issues_by_severity": {k.value: v for k, v in report.issues_by_severity.items()},
            "endpoints": [e.model_dump() for e in report.endpoints],
            "service_failures": [s.model_dump() for s in report.service_failures],
            "referer_hostnames": report.referer_hostnames,
            "slowest_requests": [r.model_dump() for r in report.slowest_requests],
            "largest_payloads": [p.model_dump() for p in report.largest_payloads],
            "repeated_resources": [r.model_dump() for r in report.repeated_resources],
        }

    def _json_serializer(self, obj: Any) -> Any:
        """Custom JSON serializer for non-serializable objects.

        Args:
            obj: Object to serialize

        Returns:
            Serializable representation
        """
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, "value"):  # Enum
            return obj.value
        if hasattr(obj, "model_dump"):  # Pydantic model
            return obj.model_dump()
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


class CSVExporter:
    """Export analysis report to CSV format."""

    def export(
        self,
        report: HarAnalysisReport,
        output_path: Path,
        har_filename: str = "",
    ) -> dict[str, Path]:
        """Export report to multiple CSV files.

        Args:
            report: Analysis report to export
            output_path: Base path for CSV files (extension will be replaced)
            har_filename: Name of the analyzed HAR file

        Returns:
            Dictionary mapping export type to file path
        """
        base_path = output_path.with_suffix("")
        exported_files: dict[str, Path] = {}

        # Export issues
        issues_path = Path(f"{base_path}_issues.csv")
        self._export_issues(report, issues_path)
        exported_files["issues"] = issues_path

        # Export endpoints
        endpoints_path = Path(f"{base_path}_endpoints.csv")
        self._export_endpoints(report, endpoints_path)
        exported_files["endpoints"] = endpoints_path

        # Export domains
        domains_path = Path(f"{base_path}_domains.csv")
        self._export_domains(report, domains_path)
        exported_files["domains"] = domains_path

        # Export backend/API service failures
        services_path = Path(f"{base_path}_services.csv")
        self._export_services(report, services_path)
        exported_files["services"] = services_path

        # Export summary
        summary_path = Path(f"{base_path}_summary.csv")
        self._export_summary(report, summary_path, har_filename)
        exported_files["summary"] = summary_path

        logger.info(f"Exported CSV reports to {base_path}_*.csv")
        return exported_files

    def _export_issues(self, report: HarAnalysisReport, path: Path) -> None:
        """Export issues to CSV."""
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "timestamp",
                    "severity",
                    "issue_type",
                    "domain",
                    "url",
                    "message",
                    "duration_ms",
                    "size_bytes",
                    "status_code",
                ]
            )

            for issue in report.issues:
                writer.writerow(
                    [
                        issue.timestamp.isoformat(),
                        issue.severity.value,
                        issue.issue_type.value,
                        issue.domain,
                        issue.url,
                        issue.message,
                        issue.duration_ms or "",
                        issue.size_bytes or "",
                        issue.details.get("status", ""),
                    ]
                )

    def _export_endpoints(self, report: HarAnalysisReport, path: Path) -> None:
        """Export endpoints to CSV."""
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "url_pattern",
                    "count",
                    "p50_ms",
                    "p95_ms",
                    "p99_ms",
                    "p95_ttfb_ms",
                    "p95_network_ms",
                    "max_ms",
                    "mean_ms",
                    "total_bytes",
                    "status_2xx",
                    "status_3xx",
                    "status_4xx",
                    "status_5xx",
                ]
            )

            for endpoint in report.endpoints:
                status_2xx = sum(
                    v
                    for k, v in endpoint.status_codes.items()
                    if HTTP_STATUS_SUCCESS_MIN <= k < HTTP_STATUS_REDIRECT_MIN
                )
                status_3xx = sum(
                    v
                    for k, v in endpoint.status_codes.items()
                    if HTTP_STATUS_REDIRECT_MIN <= k < HTTP_STATUS_CLIENT_ERROR_MIN
                )
                status_4xx = sum(
                    v
                    for k, v in endpoint.status_codes.items()
                    if HTTP_STATUS_CLIENT_ERROR_MIN <= k < HTTP_STATUS_SERVER_ERROR_MIN
                )
                status_5xx = sum(
                    v
                    for k, v in endpoint.status_codes.items()
                    if HTTP_STATUS_SERVER_ERROR_MIN <= k < HTTP_STATUS_MAX
                )

                p95_network = (
                    endpoint.network_total_timings.p95
                    if endpoint.network_total_timings.count
                    else ""
                )
                writer.writerow(
                    [
                        endpoint.url_pattern,
                        endpoint.count,
                        f"{endpoint.timings.p50:.0f}",
                        f"{endpoint.timings.p95:.0f}",
                        f"{endpoint.timings.p99:.0f}",
                        f"{endpoint.ttfb_timings.p95:.0f}",
                        f"{p95_network:.0f}" if p95_network != "" else "",
                        f"{endpoint.timings.max:.0f}",
                        f"{endpoint.timings.mean:.0f}",
                        endpoint.total_bytes,
                        status_2xx,
                        status_3xx,
                        status_4xx,
                        status_5xx,
                    ]
                )

    def _export_domains(self, report: HarAnalysisReport, path: Path) -> None:
        """Export domain analysis to CSV."""
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "domain",
                    "total_requests",
                    "failed_requests",
                    "error_rate_pct",
                    "p50_ms",
                    "p95_ms",
                    "p99_ms",
                    "health",
                    "is_first_party",
                    "issue_count",
                ]
            )

            for domain in report.domains:
                writer.writerow(
                    [
                        domain.domain,
                        domain.total_requests,
                        domain.failed_requests,
                        f"{domain.error_rate:.1f}",
                        f"{domain.timing_stats.p50:.0f}",
                        f"{domain.timing_stats.p95:.0f}",
                        f"{domain.timing_stats.p99:.0f}",
                        domain.health.value,
                        domain.is_first_party,
                        domain.issue_count,
                    ]
                )

    def _export_services(self, report: HarAnalysisReport, path: Path) -> None:
        """Export backend/API service health to CSV."""
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "domain",
                    "method",
                    "path",
                    "request_count",
                    "success_count",
                    "network_error_count",
                    "status_5xx_count",
                    "status_4xx_count",
                    "duration_exceeded_count",
                    "error_rate_pct",
                    "problem_rate_pct",
                    "p95_total_ms",
                    "p95_ttfb_ms",
                    "p95_network_ms",
                    "first_seen",
                    "last_seen",
                ]
            )

            for s in report.service_failures:
                error_count = s.network_error_count + s.status_5xx_count + s.status_4xx_count
                problem_count = error_count + s.duration_exceeded_count
                error_rate = 100.0 * error_count / s.request_count if s.request_count else 0.0
                problem_rate = 100.0 * problem_count / s.request_count if s.request_count else 0.0
                p95_net = s.network_total_timings.p95 if s.network_total_timings.count else ""
                writer.writerow(
                    [
                        s.domain,
                        s.method,
                        s.path,
                        s.request_count,
                        s.success_count,
                        s.network_error_count,
                        s.status_5xx_count,
                        s.status_4xx_count,
                        s.duration_exceeded_count,
                        f"{error_rate:.1f}",
                        f"{problem_rate:.1f}",
                        f"{s.timings.p95:.0f}",
                        f"{s.ttfb_timings.p95:.0f}",
                        f"{p95_net:.0f}" if p95_net != "" else "",
                        s.first_seen.isoformat(),
                        s.last_seen.isoformat(),
                    ]
                )

    def _export_summary(self, report: HarAnalysisReport, path: Path, har_filename: str) -> None:
        """Export summary metrics to CSV."""
        cache_total = report.cache_hits + report.cache_misses
        cache_rate = report.cache_hits / cache_total * 100 if cache_total > 0 else 0
        capture_start, capture_end = capture_window(report)

        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["metric", "value"])
            writer.writerow(["har_filename", har_filename])
            writer.writerow(["capture_start", capture_start.isoformat() if capture_start else ""])
            writer.writerow(["capture_end", capture_end.isoformat() if capture_end else ""])
            writer.writerow(["total_requests", report.total_requests])
            writer.writerow(["total_duration_ms", f"{report.total_duration_ms:.0f}"])
            writer.writerow(["total_bytes_transferred", report.total_bytes_transferred])
            writer.writerow(["total_bytes_downloaded", report.total_bytes_downloaded])
            writer.writerow(["cache_hits", report.cache_hits])
            writer.writerow(["cache_misses", report.cache_misses])
            writer.writerow(["cache_hit_rate_pct", f"{cache_rate:.1f}"])
            writer.writerow(["overall_p50_ms", f"{report.overall_timings.p50:.0f}"])
            writer.writerow(["overall_p95_ms", f"{report.overall_timings.p95:.0f}"])
            writer.writerow(["overall_p99_ms", f"{report.overall_timings.p99:.0f}"])
            writer.writerow(["blocked_p95_ms", f"{report.blocked_timings.p95:.0f}"])
            writer.writerow(["dns_p95_ms", f"{report.dns_timings.p95:.0f}"])
            writer.writerow(["connect_p95_ms", f"{report.connect_timings.p95:.0f}"])
            writer.writerow(["ssl_p95_ms", f"{report.ssl_timings.p95:.0f}"])
            writer.writerow(["ttfb_p95_ms", f"{report.ttfb_timings.p95:.0f}"])
            writer.writerow(["receive_p95_ms", f"{report.receive_timings.p95:.0f}"])
            writer.writerow(["total_issues", len(report.issues)])
            writer.writerow(["total_domains", len(report.domains)])

            # Issues by severity
            for severity, count in report.issues_by_severity.items():
                writer.writerow([f"issues_{severity.value}", count])
