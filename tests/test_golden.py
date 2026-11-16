"""Golden fixtures: hand-computed expected values (see 11-har-analyze-improvements.md).

Every number asserted here was worked out by hand from the fixture; the comment next to
it shows the arithmetic. If one of these fails, the analyzer's output changed.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from har_analyze.cli import (
    AnalyzerSettings,
    DomainHealth,
    IssueSeverity,
    IssueType,
    OutputFormatter,
    load_config_facts,
)

from .conftest import FIXTURES, analyze_fixture

# -----------------------------------------------------------------------------
# timing_semantics.har — P0.1-P0.5
#   #1 /SASLogon/login  t=1000 connect=300 (ssl=200 inside) wait=600 receive=100
#   #2 /SASStoredProcess/do   t=8000 start=+1.0s wait=7900 receive=100
#   #3 /SASStoredProcess/next t=100  start=+9.1s wait=-1 receive=100
# -----------------------------------------------------------------------------


def test_timing_semantics_ssl_not_double_counted() -> None:  # P0.1
    report = analyze_fixture("timing_semantics.har")
    assert report.connect_timings.count == 1
    assert report.connect_timings.total_duration_ms == 100  # 300 connect - 200 ssl
    assert report.ssl_timings.total_duration_ms == 200
    phases = {p.phase_name: p.total_ms for p in report.phase_breakdown}
    assert phases == {
        "Queued in browser": 0,
        "DNS": 0,
        "Connect (excl. TLS)": 100,
        "TLS": 200,
        "Send": 0,
        "Wait / TTFB": 8500,  # 600 + 7900
        "Receive": 300,  # 3 x 100
    }
    ttfb_share = next(p for p in report.phase_breakdown if p.phase_name == "Wait / TTFB")
    assert ttfb_share.percentage_of_total == pytest.approx(8500 / 9100 * 100)
    # network total = dns 0 + connect-excl-TLS 100 + ssl 200 + receive 100 = 400 (was 600)
    endpoint_net = {
        e.url_pattern.split(".com")[1]: e.network_total_timings.total_duration_ms
        for e in report.endpoints
    }
    assert endpoint_net == {
        "/SASLogon/login": 400,
        "/SASStoredProcess/do": 100,
        "/SASStoredProcess/next": 100,
    }
    service_net = {
        s.path: s.network_total_timings.total_duration_ms for s in report.service_failures
    }
    assert service_net["/SASLogon/login"] == 400


def test_timing_semantics_no_false_idle_gap() -> None:  # P0.2
    # #2 ends at 1.0 + 8.0 = 9.0s; #3 starts at 9.1s -> 100 ms idle, under 1 s
    assert analyze_fixture("timing_semantics.har").time_gaps == []


def test_timing_semantics_no_connection_reuse_without_ids() -> None:  # P0.3
    report = analyze_fixture("timing_semantics.har")
    assert report.connection_reuse_stats is None
    assert all(f.category != "connection_reuse" for f in report.key_findings)


def test_timing_semantics_ttfb_excludes_negative_wait() -> None:  # P0.4
    ttfb = analyze_fixture("timing_semantics.har").ttfb_timings
    assert ttfb.count == 2
    assert ttfb.total_duration_ms == 8500
    assert ttfb.mean == 4250
    assert ttfb.p50 == 4250  # interpolated: 600 + 0.5 * (7900 - 600)  (P1.8)
    assert ttfb.max == 7900


def test_timing_semantics_capture_window_uses_last_end() -> None:  # P0.5
    report = analyze_fixture("timing_semantics.har")
    assert report.capture_start == datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
    # max(start + time): #3 9.1 + 0.1 = 9.2 s (the #2 ends at 9.0 s)
    assert report.capture_end == datetime(2026, 1, 1, 10, 0, 9, 200_000, tzinfo=UTC)
    assert report.request_rate_stats is not None
    assert report.request_rate_stats.overall_requests_per_second == pytest.approx(3 / 9.2)


def test_timing_semantics_overall_percentiles() -> None:  # P1.8
    overall = analyze_fixture("timing_semantics.har").overall_timings
    assert (overall.count, overall.p50, overall.max) == (3, 1000, 8000)


# -----------------------------------------------------------------------------
# sas_logon_flow.har — P1.1 / P1.3
#   #1 GET  /SASPortal/        302 -> /SASLogon/login?service=...
#   #2 GET  /SASLogon/login    401 (Negotiate)          ends +0.140s
#   #3 POST /SASLogon/login    302 -> ...?ticket=ST-1-abcdef-secret   starts +5.0s
#   #4 GET  ...?ticket=...     302 -> /SASPortal/ (relative)
#   #5 GET  /SASPortal/        200
#   #6 GET  /favicon.ico       404
# -----------------------------------------------------------------------------


def test_sas_logon_flow_is_quiet_with_default_rules() -> None:
    report = analyze_fixture("sas_logon_flow.har")
    assert report.issues == []
    assert report.expected_response_count == 3  # #2 401, #3 302 on /SASLogon, #6 404 favicon
    (domain,) = report.domains
    assert (domain.health, domain.failed_requests, domain.expected_count) == (
        DomainHealth.HEALTHY,
        0,
        3,
    )
    assert all(
        f.severity not in (IssueSeverity.CRITICAL, IssueSeverity.HIGH) for f in report.key_findings
    )


def test_sas_logon_flow_real_idle_gap_while_user_types() -> None:
    (gap,) = analyze_fixture("sas_logon_flow.har").time_gaps
    assert gap.gap_duration_ms == 4860  # #3 at 5.000 s - #2 end at 0.100 + 0.040
    assert gap.after_url.startswith("https://sas.example.com/SASLogon/login")


def test_sas_logon_flow_one_chain_when_threshold_lowered() -> None:
    report = analyze_fixture("sas_logon_flow.har", AnalyzerSettings(redirect_chain_min_hops=2))
    (chain,) = report.issues
    assert chain.issue_type == IssueType.REDIRECT_CHAIN
    assert chain.details["hops"] == 2  # #3 -> #4 -> #5
    assert [hop.split(" ")[0] for hop in chain.details["chain"]] == ["302", "302", "200"]


def test_sas_logon_flow_two_chains_at_one_hop() -> None:
    report = analyze_fixture("sas_logon_flow.har", AnalyzerSettings(redirect_chain_min_hops=1))
    assert [i.details["hops"] for i in report.issues] == [1, 2]  # #1->#2, #3->#4->#5


def test_sas_logon_flow_without_expected_rules_flags_auth() -> None:
    report = analyze_fixture("sas_logon_flow.har", AnalyzerSettings(expected_rules=[]))
    found = sorted((i.details["status"], i.severity) for i in report.issues)
    assert found == [(401, IssueSeverity.HIGH), (404, IssueSeverity.MEDIUM)]


def test_sas_logon_flow_markdown_redacts_ticket() -> None:
    report = analyze_fixture("sas_logon_flow.har", AnalyzerSettings(redirect_chain_min_hops=2))
    markdown = OutputFormatter().generate_markdown_report(report, "sas_logon_flow.har")
    assert "ST-1-abcdef-secret" not in markdown
    assert "ticket=<redacted>" in markdown
    shown = OutputFormatter(show_query=True).generate_markdown_report(report, "x.har")
    assert "ticket=ST-1-abcdef-secret" in shown


# -----------------------------------------------------------------------------
# aborted_requests.har — P1.2
#   200, net::ERR_ABORTED (/reports/poll), net::ERR_CONNECTION_RESET (/reports/data), 200
# -----------------------------------------------------------------------------


def test_aborted_requests_only_reset_is_an_error() -> None:
    report = analyze_fixture("aborted_requests.har")
    assert report.network_errors_by_category == {"connection_reset": 1}
    assert report.aborted_request_count == 1
    by_type = {i.issue_type: i for i in report.issues}
    assert set(by_type) == {IssueType.NETWORK_ERROR, IssueType.REQUEST_ABORTED}
    assert by_type[IssueType.NETWORK_ERROR].url.endswith("/reports/data")
    # one failed connection is HIGH; CRITICAL needs the host to fail repeatedly
    assert by_type[IssueType.NETWORK_ERROR].severity == IssueSeverity.HIGH
    assert by_type[IssueType.REQUEST_ABORTED].url.endswith("/reports/poll")
    assert by_type[IssueType.REQUEST_ABORTED].severity == IssueSeverity.LOW


def test_aborted_requests_domain_health_counts_only_real_failures() -> None:
    (domain,) = analyze_fixture("aborted_requests.har").domains
    assert domain.failed_requests == 1
    assert domain.aborted_count == 1
    assert domain.error_rate == 25.0  # 1 of 4
    assert domain.health == DomainHealth.DEGRADED  # 25% >= 10%, but 1 problem < 2 for CRITICAL


def test_aborted_requests_outage_is_the_reset_endpoint_only() -> None:
    # One failed request is a failure, not an outage (B1): it is reported as a
    # network error and in the service table, and the aborted poll is in neither.
    report = analyze_fixture("aborted_requests.har")
    assert all(f.category != "outage" for f in report.key_findings)
    network = next(f for f in report.key_findings if f.category == "network_errors")
    assert network.summary == "1 network error(s): connection_reset (1)"
    failing = [s for s in report.service_failures if s.problem_count]
    assert [(s.method, s.path, s.problem_rate) for s in failing] == [("GET", "/reports/data", 1.0)]


# -----------------------------------------------------------------------------
# timeout_cluster.har — P1.4
#   8 x POST /SASStoredProcess/do 502 at 60000..60400 ms (every 2 s from 10:00:00)
#   1 x GET /SASStoredProcess/other 504 at 15000 ms (+20 s)
#   4 x GET /SASStoredProcess/do 200 (800..1100 ms)
# -----------------------------------------------------------------------------


def test_timeout_cluster_found_once() -> None:
    (cluster,) = analyze_fixture("timeout_cluster.har").timeout_clusters
    assert cluster.request_count == 8
    # R37: measured on wait for the first byte (total minus the 10 ms receive phase)
    assert cluster.basis == "wait"
    assert (cluster.min_ms, cluster.max_ms) == (59990, 60390)
    assert cluster.median_ms == 60165  # (60140 + 60190) / 2
    assert cluster.round_value_s == 60.165
    assert cluster.status_codes == {502: 8}
    assert cluster.endpoints == {"POST https://sas.example.com/SASStoredProcess/do": 8}
    assert cluster.matching_settings == []


def test_timeout_cluster_names_matching_config_setting() -> None:
    facts = load_config_facts(FIXTURES / "timeout_cluster.config_facts.json")
    report = analyze_fixture("timeout_cluster.har", config_facts=facts)
    (cluster,) = report.timeout_clusters
    # ProxyTimeout=60 s matches; timeout=300 s, connectionTimeout=20000 ms (20 s),
    # statement_timeout=0 and maxThreads do not.
    assert cluster.matching_settings == ["httpd ProxyTimeout=60 (web-01, conf/httpd.conf:120)"]
    finding = next(f for f in report.key_findings if f.category == "timeout_cluster")
    assert "ProxyTimeout=60" in finding.recommendation


def test_timeout_cluster_findings_lead_with_backend_signals() -> None:
    report = analyze_fixture("timeout_cluster.har")
    categories = [f.category for f in report.key_findings if not f.frontend]
    assert categories[0] == "outage"
    # R41: a domain whose failures are already named as an outage is not reported again
    assert "domain_health" not in categories
    assert "timeout_cluster" in categories
    assert "server_errors" in categories


def test_timeout_cluster_error_burst_chains_consecutive_errors() -> None:
    (burst,) = analyze_fixture("timeout_cluster.har").error_bursts
    # 502s at 0,2,...,14 s chain (gaps 2 s <= 5 s); the 504 at 20 s is 6 s later
    assert burst.error_count == 8


def test_timeout_cluster_domain_is_critical() -> None:
    (domain,) = analyze_fixture("timeout_cluster.har").domains
    assert domain.failed_requests == 9
    assert domain.health == DomainHealth.CRITICAL  # 9/13 = 69% >= 50% with >= 2 problems


# -----------------------------------------------------------------------------
# uuid_paths.har — P1.5 / P1.8
#   30 x GET /reports/reports/<uuid>/content; 25 x 3000 ms, 5 x 12000 ms
# -----------------------------------------------------------------------------


def test_uuid_paths_single_slow_endpoint_template() -> None:
    report = analyze_fixture("uuid_paths.har")
    (endpoint,) = report.endpoints
    assert endpoint.url_pattern == "https://sas.example.com/reports/reports/{uuid}/content"
    assert endpoint.count == 30
    assert endpoint.timings.p50 == 3000  # rank 14.5 between two 3000s
    assert endpoint.timings.p95 == 12000  # rank 27.55 between sorted[27]=sorted[28]=12000
    assert len(endpoint.examples) == 3
    (issue,) = report.issues
    assert issue.issue_type == IssueType.SLOW_ENDPOINT
    assert issue.url == endpoint.url_pattern
    assert "p95=12000ms" in issue.message


# -----------------------------------------------------------------------------
# no_connection_ids.har — P0.3 (2 of 5 entries have a connection ID: 40% < 80%)
# -----------------------------------------------------------------------------


def test_no_connection_ids_no_finding() -> None:
    report = analyze_fixture("no_connection_ids.har")
    assert report.connection_reuse_stats is None
    assert all(f.category != "connection_reuse" for f in report.key_findings)
    markdown = OutputFormatter().generate_markdown_report(report, "x.har")
    assert "Not available: HAR has no connection IDs" in markdown
