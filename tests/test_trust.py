"""Output-trust tests: numbers reconcile and labels claim no more than the capture shows.

The letter-number prefixes in test names (a1, b3, d5 ...) are the original review's
defect IDs, kept so related tests sort together.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from har_analyze.cli import (
    OUTAGE_MIN_FAILURES,
    AnalyzerSettings,
    ConfigFact,
    DomainHealth,
    HarAnalysisReport,
    HarAnalyzer,
    IssueSeverity,
    IssueType,
    OutputFormatter,
    app,
    build_events,
    classify_network_error,
    format_percentiles,
    generate_brief_report,
    load_har,
    md_table,
    timeout_fact_seconds,
)

from .conftest import FIXTURES, analyze_fixture, make_entry, make_har, write_har

HOST = "https://app.example.com"
DOMAIN = "app.example.com"
runner = CliRunner()

NEW_CONNECTION = {
    "blocked": 0,
    "dns": 5,
    "connect": 40,
    "ssl": 20,
    "send": 0,
    "wait": 50,
    "receive": 5,
}


def analyze(entries: list[dict[str, Any]], **settings: Any) -> HarAnalysisReport:
    return HarAnalyzer(AnalyzerSettings(**settings)).analyze(make_har(entries))


def findings(report: HarAnalysisReport, category: str) -> list[Any]:
    return [f for f in report.key_findings if f.category == category]


def failed(offset_ms: float, path: str, error: str, time_ms: float = 20) -> dict[str, Any]:
    return make_entry(offset_ms, f"{HOST}{path}", 0, time_ms, response_extra={"_error": error})


# --- A. wrong numbers ---------------------------------------------------------


def test_a1_problem_rate_counts_each_request_once() -> None:
    report = analyze_fixture("timeout_cluster.har")
    service = next(s for s in report.service_failures if s.method == "POST")
    # 8 requests, all 502 and all over 30 s: 8 problems, not 16
    assert (service.request_count, service.status_5xx_count, service.problem_count) == (8, 8, 8)
    assert service.duration_exceeded_count == 8
    assert service.problem_rate == 1.0


def test_a2_timeout_cluster_ignores_browser_queueing() -> None:
    entries = [
        make_entry(
            i * 1000,
            f"{HOST}/api/report",
            504,
            60_000 + blocked,
            timings={"blocked": blocked, "send": 0, "wait": 60_000, "receive": 0},
        )
        for i, blocked in enumerate((0, 4_000, 9_000, 15_000))
    ]
    (cluster,) = analyze(entries).timeout_clusters
    assert cluster.request_count == 4
    assert cluster.kind == "gateway"
    assert (cluster.min_ms, cluster.max_ms, cluster.round_value_s) == (60_000, 60_000, 60.0)
    assert cluster.max_queued_ms == 15_000


def test_a3_a4_cache_ratio_and_repeated_downloads() -> None:
    entries = [make_entry(i * 100, f"{HOST}/static/app{i}.js", 200) for i in range(20)]
    entries.append(make_entry(3000, f"{HOST}/static/logo.png", 304))
    entries += [make_entry(4000 + i * 100, f"{HOST}/api/items?page={i}", 200) for i in range(3)]
    entries += [
        make_entry(5000 + i * 100, f"{HOST}/api/save", 200, method="POST") for i in range(3)
    ]
    entries += [make_entry(6000 + i * 100, f"{HOST}/api/poll?x=1", 200) for i in range(2)]
    entries += [
        make_entry(
            7000 + i * 100,
            f"{HOST}/api/secret",
            200,
            response_headers=[("Cache-Control", "no-store")],
        )
        for i in range(2)
    ]
    cache = analyze(entries).cache_analysis
    assert cache is not None
    # GETs: 20 + 3 + 2 + 2 network 200s, one 304. POSTs are not cacheable.
    assert cache.network_download_count == 27
    assert cache.cacheable_get_count == 28
    assert cache.served_without_download_ratio == pytest.approx(1 / 28)
    # Different query strings are different resources; no-store is not a repeat.
    assert [(r["url"], r["count"]) for r in cache.repeated_downloads] == [
        (f"{HOST}/api/poll?x=1", 2)
    ]
    assert cache.repeated_download_request_count == 2


@pytest.mark.parametrize(
    "fixture",
    ["timeout_cluster.har", "aborted_requests.har", "sas_logon_flow.har", "uuid_paths.har"],
)
def test_a5_invariants_hold_for_every_fixture(fixture: str) -> None:
    report = analyze_fixture(fixture)
    for service in report.service_failures:
        buckets = (
            service.success_count
            + service.expected_count
            + service.aborted_count
            + service.network_error_count
            + service.status_4xx_count
            + service.status_5xx_count
        )
        assert buckets == service.request_count
        assert 0.0 <= service.problem_rate <= 1.0
    assert sum(e.count for e in report.endpoints) == report.total_requests
    assert sum(d.total_requests for d in report.domains) == report.total_requests
    population = report.latency_population
    assert population is not None
    assert (
        population.measured_count
        + population.browser_cache_hit_count
        + population.aborted_count
        + population.network_error_count
        == report.total_requests
    )
    for stats in (report.overall_timings, *(e.timings for e in report.endpoints)):
        assert stats.p50 <= stats.p95 <= stats.p99 <= stats.max


def test_a5_informational_status_is_counted_as_success() -> None:
    report = analyze([make_entry(0, f"{HOST}/api/continue", 100)])
    (service,) = report.service_failures
    assert (service.request_count, service.success_count, service.problem_count) == (1, 1, 0)


def test_a6_large_payload_and_compression_use_uncompressed_size() -> None:
    entries = [
        make_entry(
            0,
            f"{HOST}/api/big",
            200,
            response_headers=[("Content-Encoding", "gzip")],
            response_extra={
                "bodySize": 800_000,
                "content": {"size": 5_000_000, "mimeType": "application/json"},
            },
        ),
        make_entry(
            200,
            f"{HOST}/api/plain",
            200,
            response_extra={
                "bodySize": -1,
                "content": {"size": 50_000, "mimeType": "application/json"},
            },
        ),
    ]
    report = analyze(entries)
    (large,) = [i for i in report.issues if i.issue_type == IssueType.LARGE_PAYLOAD]
    assert large.size_bytes == 5_000_000
    assert large.details["bytes_on_wire"] == 800_000
    assert large.details["content_type"] == "application/json"
    compression = report.compression_analysis
    assert compression is not None
    assert compression.encoding_distribution == {"gzip": 1, "none": 1}
    assert compression.compressible_uncompressed_bytes == 50_000


@pytest.mark.parametrize(
    ("fact", "seconds"),
    [
        (ConfigFact(component="nginx", key="proxy_read_timeout", value="60"), 60.0),
        (ConfigFact(component="nginx", key="proxy_read_timeout", value="2m"), 120.0),
        (ConfigFact(component="mod_jk", key="socket_timeout", value="60"), 60.0),
        (ConfigFact(component="mod_jk", key="worker.node1.reply_timeout", value="60000"), 60.0),
        (ConfigFact(component="tomcat", key="session-timeout", value="30"), 1800.0),
        (ConfigFact(component="tomcat", key="Connector.keepAliveTimeout", value="20000"), 20.0),
        (ConfigFact(component="haproxy", key="timeout server", value="60000"), 60.0),
        (ConfigFact(component="haproxy", key="timeout server", value="1m"), 60.0),
        (ConfigFact(component="httpd", key="ProxyPass.timeout", value="1h"), 3600.0),
        # Unit not known for this product/key: no value rather than a guess
        (ConfigFact(component="mystery", key="read_timeout", value="60"), None),
        (ConfigFact(component="tomcat", key="someOtherTimeout", value="60"), None),
    ],
)
def test_a7_timeout_units_by_product(fact: ConfigFact, seconds: float | None) -> None:
    assert timeout_fact_seconds(fact) == seconds


def test_a9_a10_dominant_side_uses_summed_time_and_admits_no_data() -> None:
    entries = [
        failed(0, "/api/dead", "net::ERR_CONNECTION_REFUSED"),
        make_entry(
            100,
            f"{HOST}/api/stream",
            200,
            5_050,
            timings={"blocked": 0, "send": 0, "wait": 50, "receive": 5_000},
        ),
        make_entry(200, f"{HOST}/api/slow", 200, 2_010),
    ]
    report = analyze(entries)
    sides = {
        e.url_pattern.removeprefix(HOST): OutputFormatter._dominant_side(e)
        for e in report.endpoints
    }
    assert sides == {"/api/dead": "-", "/api/stream": "receive", "/api/slow": "wait"}


# --- B. labels that overstated ------------------------------------------------


def test_b1_one_404_is_not_an_outage() -> None:
    report = analyze([make_entry(0, f"{HOST}/api/a"), make_entry(100, f"{HOST}/api/missing", 404)])
    assert not findings(report, "outage")
    assert not findings(report, "always_rejected")


def test_b1_outage_needs_repeated_server_failures() -> None:
    down = [make_entry(i * 100, f"{HOST}/api/down", 503) for i in range(OUTAGE_MIN_FAILURES)]
    denied = [make_entry(1000 + i * 100, f"{HOST}/api/denied", 403) for i in range(3)]
    report = analyze([*down, *denied, *down[:0]])
    (outage,) = findings(report, "outage")
    assert outage.severity == IssueSeverity.CRITICAL
    assert "GET /api/down (3)" in outage.summary
    assert "/api/denied" not in outage.summary
    (rejected,) = findings(report, "always_rejected")
    assert rejected.severity == IssueSeverity.MEDIUM
    assert "GET /api/denied (3)" in rejected.summary
    # two failures are not enough
    assert not findings(analyze(down[:2]), "outage")


def test_b2_long_lived_connections_are_not_slow_requests() -> None:
    entries = [
        make_entry(0, f"{HOST}/api/a"),
        make_entry(100, "wss://app.example.com/ws/events", 101, 600_000),
        make_entry(
            200,
            f"{HOST}/api/stream",
            200,
            300_000,
            response_headers=[("Content-Type", "text/event-stream; charset=utf-8")],
        ),
        # A WebSocket handshake that failed is an ordinary failed request.
        make_entry(300, f"{HOST}/ws/broken", 502, extra={"_resourceType": "websocket"}),
    ]
    har = make_har(entries)
    report = HarAnalyzer().analyze(har)
    assert report.total_requests == 2
    assert [(c.kind, c.duration_ms) for c in report.long_lived_connections] == [
        ("websocket", 600_000),
        ("event-stream", 300_000),
    ]
    assert {i.issue_type for i in report.issues} == {IssueType.SERVER_ERROR}
    assert report.overall_timings.max == 100
    assert all("/ws/events" not in f.summary for f in report.key_findings)
    markdown = OutputFormatter().generate_markdown_report(report, "x.har")
    assert "Long-lived Connections" in markdown
    assert "2 long-lived connection(s)" in markdown
    levels = {
        e["attrs"]["path_template"]: e["level"] for e in build_events(har, HarAnalyzer(), "x")
    }
    assert levels["/ws/events"] == "INFO"


def test_b3_browser_cancels_are_not_called_a_gateway_timeout() -> None:
    entries = [failed(i * 1000, "/api/poll", "net::ERR_ABORTED", 30_000) for i in range(4)]
    report = analyze(entries)
    (cluster,) = report.timeout_clusters
    assert cluster.kind == "client_cancel"
    (finding,) = findings(report, "timeout_cluster")
    assert finding.severity == IssueSeverity.MEDIUM
    assert "browser cancellations" in finding.summary
    assert "gateway" not in finding.summary


def test_b3_gateway_and_network_timeouts_are_named() -> None:
    gateway = analyze_fixture("timeout_cluster.har")
    assert "no setting or error page in the capture confirms it" in (
        findings(gateway, "timeout_cluster")[0].summary
    )
    network = analyze([failed(i * 1000, "/api/x", "net::ERR_TIMED_OUT", 30_000) for i in range(3)])
    (finding,) = findings(network, "timeout_cluster")
    assert finding.severity == IssueSeverity.HIGH
    assert "consistent with a network timeout" in finding.summary


def test_b4_any_server_error_degrades_a_domain() -> None:
    entries = [make_entry(i, f"{HOST}/api/a") for i in range(920)]
    entries += [make_entry(1000 + i, f"{HOST}/api/a", 503) for i in range(80)]
    (domain,) = analyze(entries).domains
    assert domain.health == DomainHealth.DEGRADED
    assert (domain.server_error_count, domain.error_rate) == (80, 8.0)
    # A stray 404 among many successes does not.
    quiet = [make_entry(i, f"{HOST}/api/a") for i in range(19)]
    quiet.append(make_entry(100, f"{HOST}/api/gone", 404))
    assert analyze(quiet).domains[0].health == DomainHealth.HEALTHY


def test_b5_wait_is_not_labelled_server_time() -> None:
    report = analyze(
        [make_entry(i * 100, f"{HOST}/api/a", timings=NEW_CONNECTION) for i in range(3)]
    )
    markdown = OutputFormatter().generate_markdown_report(report, "x.har")
    assert "Wait / TTFB (network round trip + proxies + application)" in markdown
    assert "TTFB (server)" not in markdown
    (domain,) = report.domains
    # connect 40 - ssl 20 = 20 ms TCP connect on each of three new connections
    assert (domain.round_trip_estimate_ms, domain.round_trip_sample_count) == (20.0, 3)
    assert "20ms (n=3)" in markdown


@pytest.mark.parametrize(
    ("error", "status", "category"),
    [
        ("net::ERR_BLOCKED_BY_RESPONSE", 0, "blocked_by_response_policy"),  # B7
        ("net::ERR_BLOCKED_BY_CLIENT", 0, "blocked_by_client"),
        ("net::ERR_HTTP2_PROTOCOL_ERROR", 200, "truncated_response"),  # B8
        ("net::ERR_INCOMPLETE_CHUNKED_ENCODING", 200, "truncated_response"),
        ("net::ERR_CONTENT_LENGTH_MISMATCH", 200, "truncated_response"),
        ("net::ERR_TUNNEL_CONNECTION_FAILED", 0, "proxy_tunnel"),
        ("net::ERR_NETWORK_CHANGED", 0, "client_network_changed"),
        ("net::ERR_TOO_MANY_REDIRECTS", 0, "too_many_redirects"),
        ("net::ERR_FAILED", 0, "generic_failure"),
        ("net::ERR_NAME_RESOLUTION_FAILED", 0, "dns"),
        ("", 200, None),  # B9: an empty error string is no error
        ("", 0, "no_response"),
    ],
)
def test_b7_b8_b9_network_error_categories(error: str, status: int, category: str | None) -> None:
    har = make_har([make_entry(0, f"{HOST}/a", status, response_extra={"_error": error})])
    assert classify_network_error(har.log.entries[0]) == category


def test_b8_truncated_response_is_critical_with_a_hint() -> None:
    report = analyze(
        [
            make_entry(0, f"{HOST}/api/a"),
            failed(100, "/api/export", "net::ERR_INCOMPLETE_CHUNKED_ENCODING"),
        ]
    )
    (issue,) = [i for i in report.issues if i.issue_type == IssueType.NETWORK_ERROR]
    # A single failed connection is HIGH: one-offs must not read as an outage.
    assert issue.severity == IssueSeverity.HIGH
    (finding,) = findings(report, "network_errors")
    assert "cut off mid-stream" in finding.recommendation
    repeated = analyze(
        [failed(i * 100, "/api/export", "net::ERR_INCOMPLETE_CHUNKED_ENCODING") for i in range(3)]
    )
    assert {i.severity for i in repeated.issues} == {IssueSeverity.CRITICAL}
    assert findings(repeated, "network_errors")[0].severity == IssueSeverity.CRITICAL


def test_b10_error_with_status_is_one_issue() -> None:
    entry = make_entry(
        0, f"{HOST}/api/a", 502, response_extra={"_error": "net::ERR_CONNECTION_RESET"}
    )
    report = analyze([entry])
    (issue,) = report.issues
    assert issue.issue_type == IssueType.NETWORK_ERROR
    assert issue.details["status"] == 502
    (service,) = report.service_failures
    assert (service.network_error_count, service.status_5xx_count) == (1, 0)


def test_b11_no_response_at_capture_end_may_be_in_flight() -> None:
    entries = [
        make_entry(0, f"{HOST}/api/early", 0, 50),
        make_entry(10_000, f"{HOST}/api/a"),
        make_entry(10_050, f"{HOST}/api/late", 0, 50),
    ]
    by_path = {i.url.removeprefix(HOST): i for i in analyze(entries).issues}
    assert by_path["/api/early"].severity == IssueSeverity.HIGH
    assert by_path["/api/early"].message.startswith("Network error [no_response]")
    assert by_path["/api/late"].severity == IssueSeverity.MEDIUM
    assert "may have been in flight" in by_path["/api/late"].message


def test_b12_duration_severity_follows_the_dominant_phase() -> None:
    entries = [
        make_entry(0, f"{HOST}/api/slow", 200, 40_000),
        make_entry(
            100,
            f"{HOST}/files/big.zip",
            200,
            40_000,
            timings={"blocked": 0, "send": 0, "wait": 200, "receive": 39_800},
        ),
        make_entry(200, f"{HOST}/api/unknown", 200, 40_000, timings={"blocked": -1}),
    ]
    by_path = {
        i.url.removeprefix(HOST): i
        for i in analyze(entries).issues
        if i.issue_type == IssueType.DURATION_EXCEEDED
    }
    assert by_path["/api/slow"].severity == IssueSeverity.CRITICAL
    assert "mostly waiting for the first response byte: 40.0s" in by_path["/api/slow"].message
    assert by_path["/files/big.zip"].severity == IssueSeverity.HIGH
    assert "mostly receiving the response body: 39.8s" in by_path["/files/big.zip"].message
    assert by_path["/api/unknown"].severity == IssueSeverity.CRITICAL
    assert "phase split not recorded" in by_path["/api/unknown"].message


def test_b13_brief_states_the_real_redaction_state() -> None:
    report = analyze_fixture("sas_logon_flow.har")
    shown = generate_brief_report(report, OutputFormatter(show_query=True), "x.har")
    assert "query values shown (--show-query)" in shown
    assert "redacted" not in shown
    hidden = generate_brief_report(report, OutputFormatter(), "x.har")
    assert "query values redacted" in hidden
    assert "ticket=ST-" not in hidden


def test_b14_p99_needs_a_hundred_samples() -> None:
    analyzer = HarAnalyzer()
    fifty = analyzer._compute_timing_stats([float(v) for v in range(1, 51)])
    assert "p99" not in format_percentiles(fifty).split("(")[0]
    assert "max 50ms" in format_percentiles(fifty)
    hundred = analyzer._compute_timing_stats([float(v) for v in range(1, 101)])
    assert format_percentiles(hundred) == "p50 50ms / p95 95ms / p99 99ms (n=100)"


def test_b15_percentiles_cover_network_answered_requests_only() -> None:
    entries = [make_entry(i * 100, f"{HOST}/api/a", 200, 100) for i in range(3)]
    entries.append(make_entry(1000, f"{HOST}/static/a.js", 200, 1, extra={"_fromCache": "disk"}))
    entries.append(
        make_entry(1100, f"{HOST}/static/b.js", 200, 1, extra={"cache": {"beforeRequest": {}}})
    )
    entries.append(failed(1200, "/api/poll", "net::ERR_ABORTED", 9_000))
    entries.append(failed(1300, "/api/x", "net::ERR_TIMED_OUT", 60_000))
    report = analyze(entries)
    assert (report.overall_timings.count, report.overall_timings.max) == (4, 100)
    population = report.latency_population
    assert population is not None
    assert population.model_dump() == {
        "measured_count": 4,
        "browser_cache_hit_count": 1,
        "aborted_count": 1,
        "network_error_count": 1,
        "timing_unavailable_count": 0,
        "cache_source_unknown_count": 0,
    }
    markdown = OutputFormatter().generate_markdown_report(report, "x.har")
    assert "excluded: 1 browser-cache hit(s), 1 aborted, 1 network error(s)" in markdown


def test_b16_connection_churn_is_per_host() -> None:
    churn = [make_entry(i * 100, f"{HOST}/api/a", timings=NEW_CONNECTION) for i in range(12)]
    for raw in churn[:5]:
        raw["response"]["headers"].append({"name": "Connection", "value": "close"})
    report = analyze(churn)
    (host,) = report.host_connection_stats
    assert (host.network_request_count, host.new_connection_count) == (12, 12)
    (finding,) = findings(report, "connection_churn")
    assert "12 of 12 requests to app.example.com opened a new connection" in finding.summary
    assert "5 response(s) carried Connection: close" in finding.summary
    # Six parallel HTTP/1.1 connections reused for 12 requests is normal.
    normal = [
        make_entry(i * 100, f"{HOST}/api/a", timings=NEW_CONNECTION if i < 6 else None)
        for i in range(12)
    ]
    assert not findings(analyze(normal), "connection_churn")


# --- C. input handling --------------------------------------------------------


def test_c1_byte_order_mark_is_accepted(tmp_path: Path) -> None:
    har_path = tmp_path / "bom.har"
    har_path.write_bytes(b"\xef\xbb\xbf" + (FIXTURES / "timing_semantics.har").read_bytes())
    result = runner.invoke(app, ["analyze", str(har_path), "--brief"])
    assert result.exit_code == 0, result.output
    assert "# HAR brief: bom.har" in result.stdout


def test_c2_null_and_missing_optional_fields_are_not_recorded() -> None:
    raw = make_entry(0, f"{HOST}/api/a")
    raw["timings"] = {"ssl": None, "wait": 80, "receive": 20}
    raw["time"] = None
    raw["response"]["bodySize"] = None
    del raw["response"]["statusText"]
    del raw["request"]["httpVersion"]
    raw["request"]["headers"] = [{"name": "X-Request-Id", "value": None}]
    har = load_har({"log": {"entries": [raw]}})
    (entry,) = har.log.entries
    assert entry.time == -1  # missing send makes this a partial sum, not a total
    assert entry.duration_source == "unavailable"
    assert (entry.timings.ssl, entry.timings.send, entry.response.body_size) == (-1, -1, -1)
    assert har.load_notes.skipped_entry_count == 0
    assert HarAnalyzer().analyze(har).total_requests == 1


def test_c2_unusable_entries_are_skipped_and_reported(tmp_path: Path) -> None:
    good = make_entry(0, f"{HOST}/api/a")
    no_url = make_entry(100, f"{HOST}/api/b")
    del no_url["request"]["url"]
    no_status = make_entry(200, f"{HOST}/api/c")
    del no_status["response"]["status"]
    har = load_har({"log": {"entries": [good, no_url, "not an object", no_status]}})
    assert [e.entry_index for e in har.log.entries] == [1]
    assert har.load_notes.skipped_entry_count == 3
    assert har.load_notes.skipped_entry_reasons[0].startswith("entry 2: request.url:")
    har_path = write_har(tmp_path / "bad.har", [good, no_url])
    md_path = tmp_path / "r.md"
    result = runner.invoke(app, ["analyze", str(har_path), "-o", str(md_path)])
    assert result.exit_code == 0, result.output
    assert "WARNING: 1 malformed entry was skipped" in md_path.read_text()
    brief = runner.invoke(app, ["analyze", str(har_path), "--brief"])
    assert "WARNING: 1 malformed entry was skipped" in brief.stdout


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ([], "no top-level 'log' object"),
        ({"log": {"entries": {}}}, "'log.entries' is not a list"),
        ({"log": {"entries": [{"request": {}}]}}, "No usable entries in HAR (1 present)"),
        ({"log": {"entries": [{}, "x"]}}, "No usable entries"),
    ],
)
def test_c2_not_a_har_fails_with_a_clear_message(
    tmp_path: Path, document: object, message: str
) -> None:
    with pytest.raises(ValueError, match="HAR") as excinfo:
        load_har(document)
    assert message in str(excinfo.value)
    har_path = tmp_path / "x.har"
    har_path.write_text(json.dumps(document), encoding="utf-8")
    result = runner.invoke(app, ["analyze", str(har_path)])
    assert result.exit_code == 1


def test_c3_timestamps_without_offset_are_read_as_utc() -> None:
    aware = make_entry(0, f"{HOST}/api/a")
    naive = make_entry(1000, f"{HOST}/api/b")
    naive["startedDateTime"] = naive["startedDateTime"].removesuffix("Z")
    har = make_har([aware, naive])
    report = HarAnalyzer().analyze(har)
    assert report.assumed_utc_timestamp_count == 1
    assert report.capture_end is not None
    assert report.capture_start is not None
    assert (report.capture_end - report.capture_start).total_seconds() == 1.1
    markdown = OutputFormatter().generate_markdown_report(report, "x.har")
    assert "1 timestamp(s) had no UTC offset and were read as UTC" in markdown
    sources = [e["tz_source"] for e in build_events(har, HarAnalyzer(), "x")]
    assert sources == ["in-line", "assumed:UTC"]


def test_c4_non_network_entries_are_left_out() -> None:
    har = load_har(
        {
            "log": {
                "entries": [
                    make_entry(0, f"{HOST}/api/a"),
                    make_entry(10, "data:image/png;base64,AAAA"),
                    make_entry(20, "chrome-extension://abcdef/content.js"),
                    make_entry(30, f"{HOST}/api/b"),
                ]
            }
        }
    )
    report = HarAnalyzer().analyze(har)
    assert [d.domain for d in report.domains] == [DOMAIN]
    assert har.load_notes.non_http_entry_count == 2
    # entry_index keeps the position in the file, so events still point at the HAR
    events = build_events(har, HarAnalyzer(), "x")
    assert [e["attrs"]["entry_index"] for e in events] == [1, 4]
    markdown = OutputFormatter().generate_markdown_report(report, "x.har")
    assert "2 non-network entries" in markdown


def test_c5_capture_tool_is_reported() -> None:
    har = load_har(
        {
            "log": {
                "creator": {"name": "WebInspector", "version": "537.36"},
                "browser": {"name": "Firefox", "version": None},
                "entries": [make_entry(0, f"{HOST}/api/a")],
            }
        }
    )
    report = HarAnalyzer().analyze(har)
    assert report.capture_tool == "WebInspector 537.36, Firefox"
    assert "**Captured with:** WebInspector 537.36, Firefox" in (
        OutputFormatter().generate_markdown_report(report, "x.har")
    )


def test_c6_peak_request_rate() -> None:
    # starts at 0, 400, 800, 1000 ms then 5000 ms: four starts fall within one second
    offsets = (0, 400, 800, 1000, 5000)
    report = analyze([make_entry(offset, f"{HOST}/api/a", 200, 10) for offset in offsets])
    rate = report.request_rate_stats
    assert rate is not None
    assert rate.peak_requests_per_second == 4.0
    assert rate.overall_requests_per_second == pytest.approx(5 / 5.01)


# --- D. new evidence ----------------------------------------------------------


def _mixed_tier_entries() -> list[dict[str, Any]]:
    ok = [
        make_entry(
            i * 100,
            f"{HOST}/api/a",
            200,
            response_headers=[("Server", "Apache"), ("Content-Type", "application/json")],
        )
        for i in range(5)
    ]
    bad = [
        make_entry(
            1000 + i * 100,
            f"{HOST}/api/a",
            502,
            30,
            response_headers=[
                ("Server", "awselb/2.0"),
                ("Content-Type", "text/html"),
                ("X-Request-Id", f"req-{i}"),
            ],
        )
        for i in range(3)
    ]
    return [*ok, *bad]


def test_d1_d2_error_origin_compares_headers_and_explains_the_status() -> None:
    report = analyze(_mixed_tier_entries())
    (origin,) = report.error_origins
    assert (origin.domain, origin.status, origin.count) == (DOMAIN, 502, 3)
    assert origin.error_servers == {"awselb/2.0": 3}
    assert origin.success_servers == {"Apache": 5}
    assert origin.error_content_types == {"text/html": 3}
    assert "consistent with the errors being produced by a different tier" in origin.reading
    assert "headers point at: AWS load balancer (Server: awselb/2.0) (3)" in origin.reading
    assert "a proxy got no valid answer from the backend" in origin.status_hint
    assert "did not wait on the application" not in origin.status_hint
    markdown = OutputFormatter().generate_markdown_report(report, "x.har")
    assert "## 5xx Error Origin" in markdown
    assert "- 502 is consistent with:" in markdown


def test_d1_same_server_header_does_not_separate_tiers() -> None:
    entries = [
        make_entry(0, f"{HOST}/api/a", 200, response_headers=[("Server", "Apache")]),
        make_entry(100, f"{HOST}/api/a", 500, response_headers=[("Server", "Apache")]),
        make_entry(200, "https://other.example.com/x", 504, 60_000),
    ]
    same, alone = analyze(entries).error_origins
    assert "does not separate the tiers" in same.reading
    assert alone.reading == "no successful responses from this host to compare with"
    assert "answered fast" not in alone.status_hint


def test_d3_clock_offset_from_date_headers() -> None:
    # Browser clock: T0 = 10:00:00Z. Server Date says 10:00:40, headers arrive at +0.09 s.
    skewed = [
        make_entry(
            i * 1000,
            f"{HOST}/api/a",
            200,
            100,
            response_headers=[("Date", f"Thu, 01 Jan 2026 10:00:{40 + i:02d} GMT")],
        )
        for i in range(3)
    ]
    cached = make_entry(
        5000,
        f"{HOST}/api/a",
        200,
        response_headers=[("Date", "Thu, 01 Jan 2026 09:00:00 GMT"), ("Age", "3600")],
    )
    garbled = make_entry(6000, f"{HOST}/api/a", 200, response_headers=[("Date", "yesterday")])
    report = analyze([*skewed, cached, garbled])
    (offset,) = report.clock_offsets
    assert offset.sample_count == 3
    assert offset.median_seconds == pytest.approx(40 - 0.09)
    (finding,) = findings(report, "clock_offset")
    assert "Uncertain Date-header difference" in finding.summary
    assert "Keep browser timestamps unchanged" in finding.recommendation
    assert "Date Header Differences" in OutputFormatter().generate_markdown_report(report, "x.har")


def test_d3_clock_offset_absent_is_stated() -> None:
    report = analyze([make_entry(0, f"{HOST}/api/a")])
    assert report.clock_offsets == []
    markdown = OutputFormatter().generate_markdown_report(report, "x.har")
    assert "Clock offset: not available" in markdown
    assert "Backend node: not available" in markdown


def test_d4_slowest_requests_are_in_the_full_reports(tmp_path: Path) -> None:
    har_path = write_har(tmp_path / "a.har", _mixed_tier_entries())
    terminal = runner.invoke(app, ["analyze", str(har_path)], env={"COLUMNS": "250"})
    assert "Slowest Individual Requests" in terminal.stdout
    markdown = OutputFormatter().generate_markdown_report(
        HarAnalyzer().analyze(load_har(json.loads(har_path.read_text()))), "a.har"
    )
    assert "## Slowest Individual Requests" in markdown
    assert (
        "| 2026-01-01T10:00:00.000+00:00 | #1 GET app.example.com/api/a | 200 | 100 |"
    ) in markdown


def _two_node_entries() -> list[dict[str, Any]]:
    session = "0123456789ABCDEF0123456789ABCDEF"
    entries = [
        make_entry(
            i * 100,
            f"{HOST}/api/a",
            200,
            request_headers=[("Cookie", f"x=1; JSESSIONID={session}.node1")],
        )
        for i in range(4)
    ]
    entries += [
        make_entry(
            1000 + i * 100,
            f"{HOST}/api/a",
            500,
            response_headers=[("Set-Cookie", f"JSESSIONID={session}.node2; Path=/; HttpOnly")],
        )
        for i in range(3)
    ]
    return entries


def test_d5_backend_node_from_session_route() -> None:
    report = analyze(_two_node_entries())
    assert [(n.node, n.request_count, n.server_error_count) for n in report.backend_nodes] == [
        ("node1", 4, 0),
        ("node2", 3, 3),
    ]
    (finding,) = findings(report, "backend_node")
    assert "3 failures were associated with node2" in finding.summary
    markdown = OutputFormatter().generate_markdown_report(report, "x.har")
    assert "## Backend Nodes" in markdown
    assert "0123456789ABCDEF" not in markdown  # the session ID itself is never printed


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ([("Set-Cookie", "ROUTEID=.tc2; path=/")], ("tc2", "ROUTEID (Set-Cookie)")),
        ([("X-Served-By", "cache-lhr-1")], ("cache-lhr-1", "X-Served-By")),
        ([("Set-Cookie", "JSESSIONID=ABCDEF; Path=/")], None),  # no route suffix
        ([], None),
    ],
)
def test_d5_backend_node_sources(headers: list[tuple[str, str]], expected: object) -> None:
    har = make_har([make_entry(0, f"{HOST}/a", response_headers=headers)])
    assert HarAnalyzer.backend_node(har.log.entries[0]) == expected


def test_d6_browser_queueing_names_what_held_the_connections() -> None:
    entries = [
        make_entry(0, f"{HOST}/api/report/123", 200, 20_000),
        make_entry(
            1000,
            f"{HOST}/api/menu",
            200,
            8_100,
            timings={"blocked": 8_000, "send": 0, "wait": 90, "receive": 10},
        ),
    ]
    report = analyze(entries)
    (issue,) = [i for i in report.issues if i.issue_type == IssueType.BLOCKING]
    assert issue.details["in_flight_meanwhile"] == "GET /api/report/{n} (20.0s)"
    (finding,) = findings(report, "browser_queueing")
    assert "1 request(s) to app.example.com queued in the browser" in finding.summary
    assert "not proven connection holders" in finding.recommendation
    assert "GET /api/report/{n} (20.0s)" in finding.recommendation


def test_d7_correlation_ids_are_on_issues() -> None:
    report = analyze(_mixed_tier_entries())
    errors = [i for i in report.issues if i.issue_type == IssueType.SERVER_ERROR]
    assert [i.details["correlation"] for i in errors] == [f"x-request-id=req-{i}" for i in range(3)]
    markdown = OutputFormatter().generate_markdown_report(report, "x.har")
    assert "Correlation IDs: x-request-id=req-0" in markdown


# --- output consistency -------------------------------------------------------


def test_markdown_table_cells_escape_pipes() -> None:
    assert md_table(("A", "B"), [("x|y", "line\nbreak")]) == [
        "| A | B |",
        "|---|---|",
        "| x\\|y | line break |",
    ]
    report = analyze([make_entry(i * 10, f"{HOST}/api/a|b", 503) for i in range(3)])
    markdown = OutputFormatter().generate_markdown_report(report, "x.har")
    assert "`/api/a\\|b`" in markdown
    assert "`/api/a|b`" not in markdown


def test_reports_are_written_atomically(tmp_path: Path) -> None:
    har_path = write_har(tmp_path / "a.har", [make_entry(0, f"{HOST}/api/a")])
    for extra in ([], ["--brief"]):
        out = tmp_path / "report.md"
        result = runner.invoke(app, ["analyze", str(har_path), "-o", str(out), *extra])
        assert result.exit_code == 0, result.output
        assert out.read_text().startswith("# HAR")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.har", "report.md"]


def test_table_titles_follow_the_settings(tmp_path: Path) -> None:
    body = make_entry(0, f"{HOST}/api/upload", method="POST", request_extra={"bodySize": 60_000})
    report = analyze([body], large_request_body_bytes=51_200)
    markdown = OutputFormatter().generate_markdown_report(report, "x.har")
    assert "### Large Request Bodies (>50.0 KB)" in markdown
