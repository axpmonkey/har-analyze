"""Unit tests for P1/P2 features and end-to-end CLI rendering."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from har_analyze.cli import (
    BRIEF_MAX_BYTES,
    AnalyzerSettings,
    ConfigFact,
    DomainHealth,
    ExpectedRule,
    HarAnalyzer,
    HarHeader,
    IssueSeverity,
    IssueType,
    OutputFormatter,
    PathTemplateRule,
    app,
    build_events,
    classify_network_error,
    format_percentiles,
    generate_brief_report,
    load_config_facts,
    parse_server_timings,
    percentile_sorted,
    redact_url,
    template_path,
    timeout_fact_seconds,
)

from .conftest import FIXTURES, load_har, make_entry, make_har, write_har

HOST = "https://sas.example.com"
runner = CliRunner()


# --- P1.1 redaction -----------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (f"{HOST}/SASLogon/login?ticket=ST-1-x", "/SASLogon/login?ticket=<redacted>"),
        (f"{HOST}/cb?code=abc&state=xyz", "/cb?code=<redacted>&state=<redacted>"),
        (f"{HOST}/app#access_token=tok", "/app#<redacted>"),
        (f"{HOST}/plain", "/plain"),
        (f"{HOST}", "/"),
        ("/relative?x=1", "/relative?x=<redacted>"),
        (f"{HOST}/p?&", "/p?<redacted>"),
    ],
)
def test_redact_url(url: str, expected: str) -> None:
    assert redact_url(url) == expected


def test_redact_url_show_query() -> None:
    assert redact_url(f"{HOST}/a?code=1#frag", show_query=True) == "/a?code=1#frag"


# --- P1.2 network error classification ----------------------------------------


@pytest.mark.parametrize(
    ("error", "status", "category"),
    [
        ("net::ERR_ABORTED", 0, "aborted"),
        ("NS_BINDING_ABORTED", 0, "aborted"),
        ("net::ERR_BLOCKED_BY_CLIENT", 0, "blocked_by_client"),
        ("net::ERR_CONNECTION_RESET", 0, "connection_reset"),
        ("net::ERR_CONNECTION_ABORTED", 0, "connection_reset"),
        ("NS_ERROR_NET_RESET", 0, "connection_reset"),
        ("net::ERR_CONNECTION_REFUSED", 0, "connection_refused"),
        ("net::ERR_CONNECTION_TIMED_OUT", 0, "timed_out"),
        ("net::ERR_NAME_NOT_RESOLVED", 0, "dns"),
        ("net::ERR_CERT_AUTHORITY_INVALID", 0, "tls"),
        ("net::ERR_EMPTY_RESPONSE", 0, "empty_response"),
        ("something new", 0, "other"),
        (None, 0, "no_response"),
        (None, 200, None),
    ],
)
def test_classify_network_error(error: str | None, status: int, category: str | None) -> None:
    extra = {"_error": error} if error is not None else {}
    har = make_har([make_entry(0, f"{HOST}/x", status, response_extra=extra)])
    assert classify_network_error(har.log.entries[0]) == category


# --- P1.3 expected rules / domain health / redirect loops ---------------------


def test_expected_rule_parse_and_match() -> None:
    rule = ExpectedRule.parse("4xx:*/favicon.ico")
    assert rule.matches(404, "/favicon.ico")
    assert rule.matches(410, "/app/favicon.ico")
    assert not rule.matches(500, "/favicon.ico")
    assert not rule.matches(404, "/favicon.png")
    assert str(ExpectedRule.parse(" 401:/SASLogon/* ")) == "401:/SASLogon/*"


@pytest.mark.parametrize("text", ["401", "abc:/x", "401:", "600:/x", "4x:/x"])
def test_expected_rule_rejects_malformed(text: str) -> None:
    with pytest.raises(ValueError, match="Invalid expected rule"):
        ExpectedRule.parse(text)


def test_domain_health_needs_two_problems_for_critical() -> None:
    one = HarAnalyzer().analyze(make_har([make_entry(0, f"{HOST}/a", 500)]))
    assert one.domains[0].health == DomainHealth.DEGRADED
    two = HarAnalyzer().analyze(
        make_har([make_entry(0, f"{HOST}/a", 500), make_entry(200, f"{HOST}/b", 502)])
    )
    assert two.domains[0].health == DomainHealth.CRITICAL
    sporadic = HarAnalyzer().analyze(
        make_har(
            [make_entry(i * 200, f"{HOST}/ok", 200) for i in range(19)]
            + [make_entry(4000, f"{HOST}/a", 500)]
        )
    )
    # 1/20 = 5% < 10%, but any 5xx makes a domain at least DEGRADED (plan.md B4)
    assert sporadic.domains[0].health == DomainHealth.DEGRADED


def test_redirect_loop_detected() -> None:
    a, b = f"{HOST}/a", f"{HOST}/b"
    entries = [
        make_entry(0, a, 302, 10, response_extra={"redirectURL": b}),
        make_entry(20, b, 302, 10, response_extra={"redirectURL": "/a"}),
        make_entry(40, a, 302, 10, response_extra={"redirectURL": b}),
    ]
    report = HarAnalyzer().analyze(make_har(entries))
    (loop,) = [i for i in report.issues if i.issue_type == IssueType.REDIRECT_LOOP]
    assert loop.severity == IssueSeverity.HIGH
    assert len(loop.details["chain"]) == 3
    assert any(f.category == "redirect_loop" for f in report.key_findings)


# --- P1.4 timeout facts -------------------------------------------------------


@pytest.mark.parametrize(
    ("fact", "seconds"),
    [
        (ConfigFact(component="httpd", key="ProxyTimeout", value="60"), 60.0),
        (ConfigFact(component="httpd", key="Timeout", value="300"), 300.0),
        (ConfigFact(component="tomcat", key="connectionTimeout", value="20000"), 20.0),
        (ConfigFact(component="lb", key="idle_timeout", value="5", unit="min"), 300.0),
        (ConfigFact(component="postgres", key="statement_timeout", value="30s"), 30.0),
        (ConfigFact(component="jdbc", key="maxWaitMillis", value_num=10000), 10.0),
        (ConfigFact(component="tomcat", key="maxThreads", value="300"), None),
        (ConfigFact(component="x", key="timeout", value="abc"), None),
        (ConfigFact(component="x", key="timeout", value="5", unit="fortnights"), None),
    ],
)
def test_timeout_fact_seconds(fact: ConfigFact, seconds: float | None) -> None:
    assert timeout_fact_seconds(fact) == seconds


def test_load_config_facts_formats(tmp_path: Path) -> None:
    fact = {"component": "httpd", "key": "Timeout", "value": "60"}
    as_list = tmp_path / "list.json"
    as_list.write_text(json.dumps([fact]))
    wrapped = tmp_path / "wrapped.json"
    wrapped.write_text(json.dumps({"facts": [fact, fact]}))
    jsonl = tmp_path / "facts.jsonl"
    jsonl.write_text(json.dumps(fact) + "\n" + json.dumps(fact) + "\n\n" + json.dumps(fact))
    single = tmp_path / "single.json"
    single.write_text(json.dumps(fact))
    assert [len(load_config_facts(p)) for p in (as_list, wrapped, jsonl, single)] == [1, 2, 3, 1]


def test_failure_duration_cluster_does_not_require_round_value() -> None:
    # Similar failures are observed even when not near a guessed timeout setting.
    entries = [make_entry(i * 1000, f"{HOST}/x", 502, 37000 + i * 50) for i in range(5)]
    (cluster,) = HarAnalyzer().analyze(make_har(entries)).timeout_clusters
    assert cluster.kind == "failure"
    assert cluster.median_ms == 37100


# --- P1.5 path templating -----------------------------------------------------


def test_template_path() -> None:
    uuid = "0f8fad5b-d9cb-469f-a165-70867728950e"
    assert template_path(f"/reports/{uuid}/content") == "/reports/{uuid}/content"
    assert template_path("/api/items/12345") == "/api/items/{n}"
    assert template_path("/blob/0123456789abcdef0123") == "/blob/{hex}"
    assert template_path("/cafe/deadbeef") == "/cafe/deadbeef"  # short hex left alone
    assert template_path("") == "/"
    rule = PathTemplateRule.parse(r"RPT\d+=report")
    assert template_path("/x/RPT42/y", (rule,)) == "/x/{report}/y"


@pytest.mark.parametrize("text", ["noequals", "=name", "abc=", "(=x"])
def test_path_rule_rejects_malformed(text: str) -> None:
    with pytest.raises(ValueError, match="path rule"):
        PathTemplateRule.parse(text)


# --- P1.8 percentiles ---------------------------------------------------------


def test_percentile_interpolates_like_gc_analyze() -> None:
    values = [10.0, 20.0, 30.0, 40.0]
    assert percentile_sorted(values, 50) == 25.0
    assert percentile_sorted(values, 95) == pytest.approx(38.5)
    assert percentile_sorted([7.0], 99) == 7.0
    assert percentile_sorted([], 50) == 0.0


def test_format_percentiles_suppresses_tail_under_20() -> None:
    analyzer = HarAnalyzer()
    small = analyzer._compute_timing_stats([float(v) for v in range(1, 6)])
    assert format_percentiles(small) == "p50 3ms / max 5ms (n=5; p95/p99 need n≥20)"
    large = analyzer._compute_timing_stats([float(v) for v in range(1, 21)])
    # p99 is only printed from n >= 100 (plan.md B14)
    assert format_percentiles(large).endswith("max 20ms (n=20; p99 needs n≥100)")
    assert "p95 19ms" in format_percentiles(large)  # 19 * 0.95 = 18.05 -> 19 + 0.05*1


# --- P1.9 browser cache -------------------------------------------------------


def test_browser_cache_hits_are_not_repeated_downloads() -> None:
    css = f"{HOST}/app.css"
    api = f"{HOST}/api/data"
    entries = [
        make_entry(0, css, 200, response_extra={"bodySize": 5000, "_transferSize": 5300}),
        make_entry(
            100,
            css,
            200,
            extra={"_fromCache": "memory"},
            response_extra={"bodySize": 5000, "_transferSize": 0},
        ),
        make_entry(200, css, 200, response_extra={"bodySize": 5000, "_transferSize": 0}),
        make_entry(300, api, 200, response_extra={"bodySize": 800, "_transferSize": 1000}),
        make_entry(400, api, 200, response_extra={"bodySize": 800, "_transferSize": 1000}),
    ]
    report = HarAnalyzer().analyze(make_har(entries))
    cache = report.cache_analysis
    assert cache is not None
    assert cache.browser_cache_hit_count == 2
    assert cache.repeated_downloads == [{"url": api, "count": 2, "total_bytes": 2000}]
    assert report.total_bytes_transferred == 5300 + 1000 + 1000  # cache hits add 0


# --- P2.3 server timing -------------------------------------------------------


def test_parse_server_timings() -> None:
    headers = [
        HarHeader(name="Server-Timing", value='app;dur=120.5, db;desc="q";dur=30, miss'),
        HarHeader(name="X-Response-Time", value="45ms"),
        HarHeader(name="X-Runtime", value="0.25"),
        HarHeader(name="X-Response-Time", value="garbage"),
    ]
    assert parse_server_timings(headers) == {
        "app": 120.5,
        "db": 30.0,
        "X-Response-Time": 45.0,
        "X-Runtime": 250.0,
    }


def test_server_timing_per_endpoint() -> None:
    entries = [
        make_entry(
            i * 100,
            f"{HOST}/api/{i}",
            200,
            500,
            response_headers=[("Server-Timing", f"app;dur={100 + i}")],
        )
        for i in range(3)
    ]
    report = HarAnalyzer().analyze(make_har(entries))
    (endpoint,) = report.endpoints
    assert endpoint.server_timings["app"].count == 3
    assert endpoint.server_timings["app"].p50 == 101
    markdown = OutputFormatter().generate_markdown_report(report, "x.har")
    assert "## Server-Reported Timing vs TTFB" in markdown


# --- P2.1 events --------------------------------------------------------------


def test_events_follow_shared_format() -> None:
    har = load_har("timeout_cluster.har")
    events = build_events(har, HarAnalyzer(), "timeout_cluster.har")
    assert len(events) == 13
    assert [e["level"] for e in events].count("ERROR") == 9
    assert [e["level"] for e in events].count("INFO") == 4
    first = events[0]
    assert first["ts"] == "2026-01-01T10:00:00.000Z"
    assert first["ts_raw"] == "2026-01-01T10:00:00.000Z"
    assert first["tz_source"] == "in-line"
    assert first["source"] == "har"
    assert first["message"] == "POST /SASStoredProcess/do -> 502"
    assert first["duration_ms"] == 60000
    assert first["signature"].startswith("har:ERROR:")
    assert len(first["signature"].split(":")[2]) == 12
    assert "?" not in json.dumps(events)  # no query strings at all
    post_502 = {e["signature"] for e in events if e["message"].startswith("POST")}
    assert len(post_502) == 1  # same endpoint + status -> same signature


def test_events_attrs_and_levels() -> None:
    entries = [
        make_entry(
            0,
            f"{HOST}/items/{n}",
            200,
            12000,
            request_headers=[("X-Request-ID", "r-1")],
            response_headers=[("Server-Timing", "app;dur=5"), ("Authorization", "secret")],
            extra={"serverIPAddress": "10.0.0.5", "_fromCache": "disk"},
        )
        for n in (1,)
    ] + [
        make_entry(100, f"{HOST}/gone", 0, 10, response_extra={"_error": "net::ERR_ABORTED"}),
        {**make_entry(200, f"{HOST}/naive", 200), "startedDateTime": "2026-01-01T10:00:00.300"},
    ]
    events = build_events(make_har(entries), HarAnalyzer(), "x.har")
    by_path = {e["attrs"]["path_template"]: e for e in events}
    slow = by_path["/items/{n}"]
    assert slow["level"] == "WARN"  # 12 s > 10 s slow threshold
    assert slow["template"] == "GET /items/<*> -> 200"
    assert slow["attrs"]["correlation"] == {"x-request-id": "r-1"}
    assert slow["attrs"]["server_timing_ms"] == {"app": 5.0}
    assert slow["attrs"]["server_ip"] == "10.0.0.5"
    assert "secret" not in json.dumps(events)
    aborted = by_path["/gone"]
    assert aborted["level"] == "INFO"
    assert aborted["attrs"]["error_category"] == "aborted"
    assert by_path["/naive"]["tz_source"] == "assumed:UTC"


# --- P2.2 brief ---------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "timing_semantics.har",
        "sas_logon_flow.har",
        "aborted_requests.har",
        "timeout_cluster.har",
        "uuid_paths.har",
        "no_connection_ids.har",
    ],
)
def test_brief_fits_and_redacts(name: str) -> None:
    report = HarAnalyzer().analyze(load_har(name))
    brief = generate_brief_report(report, OutputFormatter(), name)
    assert len(brief.encode("utf-8")) <= BRIEF_MAX_BYTES
    assert "secret" not in brief
    assert "Informational" not in brief  # no front-end advice in the brief


def test_brief_shrinks_large_reports() -> None:
    long_segment = "x" * 120
    entries = [
        make_entry(i * 10, f"{HOST}/svc{i}/{long_segment}?token=abc", 500 + (i % 4), 1000 + i)
        for i in range(300)
    ]
    report = HarAnalyzer().analyze(make_har(entries))
    brief = generate_brief_report(report, OutputFormatter(), "big.har")
    assert len(brief.encode("utf-8")) <= BRIEF_MAX_BYTES
    assert "token=abc" not in brief


def test_brief_hard_truncates_when_rows_cannot_shrink_enough() -> None:
    settings = AnalyzerSettings(expected_rules=[f"404:/{'p' * 80}{i}/*" for i in range(80)])
    report = HarAnalyzer(settings).analyze(make_har([make_entry(0, f"{HOST}/a")]))
    brief = generate_brief_report(report, OutputFormatter(), "x.har")
    assert len(brief.encode("utf-8")) <= BRIEF_MAX_BYTES
    assert brief.endswith(f"(truncated to {BRIEF_MAX_BYTES} bytes)\n")


# --- connection reuse wording -------------------------------------------------


def test_connection_reuse_http2_wording() -> None:
    entries = [{**make_entry(i * 10, f"{HOST}/a"), "connection": str(i)} for i in range(4)]
    for raw in entries:
        raw["request"]["httpVersion"] = "h2"
    report = HarAnalyzer().analyze(make_har(entries))
    # The capture-wide "reuse efficiency" finding was replaced by per-host connection
    # churn (plan.md B16); connection IDs are still summarised.
    assert all(f.category != "connection_reuse" for f in report.key_findings)
    stats = report.connection_reuse_stats
    assert stats is not None
    assert (stats.total_requests, stats.unique_connections, stats.reuse_ratio) == (4, 4, 1.0)


# --- CLI end to end -----------------------------------------------------------


def _kitchen_sink(tmp_path: Path) -> Path:
    """One HAR touching every report section."""
    big = 2_000_000
    entries = [
        make_entry(
            0,
            f"{HOST}/upload?sig=secret-sig",
            200,
            40000,
            method="POST",
            request_headers=[("Referer", "https://portal.example.com/page")],
            response_headers=[("Server", "Apache"), ("Content-Type", "text/html")],
            request_extra={"bodySize": 200_000, "postData": {"mimeType": "application/json"}},
            response_extra={"bodySize": big},
            extra={"serverIPAddress": "10.0.0.1", "connection": "1"},
        ),
        make_entry(
            50_000,
            f"{HOST}/static/app.js",
            200,
            100,
            response_extra={"bodySize": 5000},
            extra={"connection": "2"},
        ),
        make_entry(
            50_200,
            f"{HOST}/static/app.js",
            200,
            100,
            response_extra={"bodySize": 5000},
            extra={"connection": "3"},
        ),
        make_entry(50_400, f"{HOST}/static/logo.png", 304, 20, extra={"connection": "4"}),
        make_entry(50_600, f"{HOST}/api/limited", 429, 20, extra={"connection": "5"}),
        make_entry(50_700, f"{HOST}/api/fail", 500, 20, extra={"connection": "6"}),
        make_entry(50_800, f"{HOST}/api/fail", 503, 20, extra={"connection": "7"}),
        make_entry(
            50_900,
            f"{HOST}/api/fail",
            0,
            20,
            extra={"connection": "8"},
            response_extra={"_error": "net::ERR_NAME_NOT_RESOLVED"},
        ),
        make_entry(
            51_000,
            f"{HOST}/api/slowdns",
            200,
            2000,
            extra={"connection": "9"},
            timings={
                "blocked": 6000,
                "dns": 900,
                "connect": 50,
                "ssl": -1,
                "send": 0,
                "wait": 40,
                "receive": 10,
            },
        ),
        make_entry(
            60_000,
            f"{HOST}/r/1",
            302,
            10,
            extra={"connection": "10"},
            response_extra={"redirectURL": f"{HOST}/r/2?code=oauth-secret"},
        ),
        make_entry(
            60_020,
            f"{HOST}/r/2?code=oauth-secret",
            302,
            10,
            extra={"connection": "11"},
            response_extra={"redirectURL": f"{HOST}/r/3"},
        ),
        make_entry(
            60_040,
            f"{HOST}/r/3",
            302,
            10,
            extra={"connection": "12"},
            response_extra={"redirectURL": f"{HOST}/r/4"},
        ),
        make_entry(
            60_060,
            f"{HOST}/r/4",
            200,
            10,
            extra={"connection": "13"},
            response_headers=[("Server-Timing", "app;dur=3")],
        ),
        make_entry(
            60_100,
            f"{HOST}/poll",
            0,
            10,
            extra={"connection": "14"},
            response_extra={"_error": "net::ERR_ABORTED"},
        ),
    ]
    return write_har(tmp_path / "sink.har", entries)


def test_cli_terminal_report_all_sections(tmp_path: Path) -> None:
    har_path = _kitchen_sink(tmp_path)
    result = runner.invoke(app, ["analyze", str(har_path), "-t", "UTC"], env={"COLUMNS": "200"})
    assert result.exit_code == 0, result.output
    out = result.stdout
    for title in (
        "Key Findings",
        "Timing Percentiles",
        "Thresholds used",
        "Server IP Addresses by Domain",
        "Idle Periods",
        "Large Request Bodies",
        "Referer Hostnames",
        "Domain Health Overview",
        "Outages",
        "Backend/API Service Health",
        "Backend/API Errors by Domain",
        "Informational (redirects, aborts)",
        "Server-Reported Timing vs TTFB",
        "Error Runs",
        "Slowest Individual Requests",
        "Connections per Host",
        "Informational (front-end)",
        "Compression Analysis",
        "Cache Analysis",
    ):
        assert title in out, title
    assert "secret" not in out


def test_cli_markdown_and_show_query(tmp_path: Path) -> None:
    har_path = _kitchen_sink(tmp_path)
    md_path = tmp_path / "report.md"
    result = runner.invoke(app, ["analyze", str(har_path), "-o", str(md_path)])
    assert result.exit_code == 0, result.output
    markdown = md_path.read_text()
    assert "secret" not in markdown
    assert "## Informational (front-end)" in markdown
    assert markdown.index("## Key Findings") < markdown.index("## Informational (front-end)")
    shown_path = tmp_path / "shown.md"
    result = runner.invoke(
        app,
        [
            "analyze",
            str(har_path),
            "-o",
            str(shown_path),
            "--show-query",
            "--redirect-chain-min-hops",
            "2",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "code=oauth-secret" in shown_path.read_text()


def test_cli_brief_events_and_facts(tmp_path: Path) -> None:
    events_path = tmp_path / "out.events.jsonl"
    result = runner.invoke(
        app,
        [
            "analyze",
            str(FIXTURES / "timeout_cluster.har"),
            "--brief",
            "--export-events",
            str(events_path),
            "--config-facts",
            str(FIXTURES / "timeout_cluster.config_facts.json"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "duration-compatible, scope unverified: httpd ProxyTimeout=60" in result.stdout
    lines = events_path.read_text().splitlines()
    assert len(lines) == 13
    assert all(json.loads(line)["source"] == "har" for line in lines)

    brief_path = tmp_path / "brief.md"
    result = runner.invoke(
        app, ["analyze", str(FIXTURES / "sas_logon_flow.har"), "--brief", "-o", str(brief_path)]
    )
    assert result.exit_code == 0
    assert brief_path.read_text().startswith("# HAR brief: sas_logon_flow.har")


def test_cli_rules_and_thresholds(tmp_path: Path) -> None:
    md_path = tmp_path / "r.md"
    result = runner.invoke(
        app,
        [
            "analyze",
            str(FIXTURES / "sas_logon_flow.har"),
            "-o",
            str(md_path),
            "--no-default-expect",
            "--expect",
            "401:/SASLogon/*",
            "--path-rule",
            r"SAS\w+=app",
            "--slow-ms",
            "5000",
        ],
    )
    assert result.exit_code == 0, result.output
    markdown = md_path.read_text()
    assert "slow endpoint > 5000ms" in markdown
    # favicon 404 now a failure (static, so not in the backend error list); only the
    # 401 matches a rule (the default 3xx:/SASLogon/* was dropped): 1/6 = 16.7%
    # columns: requests, failures, rate, 5xx, network errors, expected, aborted
    assert "| sas.example.com | 6 | 1 | 16.7% | 0 | 0 | 1 | 0 |" in markdown
    assert "Client error: 401" not in markdown
    assert "`/{app}/login`" in markdown or "/{app}/" in markdown


def test_cli_rejects_bad_rule() -> None:
    result = runner.invoke(
        app, ["analyze", str(FIXTURES / "sas_logon_flow.har"), "--expect", "nonsense"]
    )
    assert result.exit_code == 2
    assert "Invalid expected rule" in result.output


def test_cli_local_time_and_bad_timezone() -> None:
    har = str(FIXTURES / "timing_semantics.har")
    assert runner.invoke(app, ["analyze", har, "--local-time"]).exit_code == 0
    assert runner.invoke(app, ["analyze", har, "-t", "Not/AZone"]).exit_code == 2
    assert runner.invoke(app, ["analyze", har, "-t", "UTC", "--local-time"]).exit_code == 2
    assert runner.invoke(app, ["analyze", har, "-t", "America/New_York"]).exit_code == 0


def test_cli_invalid_har(tmp_path: Path) -> None:
    bad = tmp_path / "bad.har"
    bad.write_text("{not json")
    result = runner.invoke(app, ["analyze", str(bad)])
    assert result.exit_code == 1
    assert "Error:" in result.output


def test_cli_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "har-analyze version" in result.stdout
