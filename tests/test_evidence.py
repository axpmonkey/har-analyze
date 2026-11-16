"""Evidence tests: incidents, error-page fingerprints, sessions, stalls, log correlation.

The rNN prefixes in test names are review item numbers, kept so related tests sort
together. The facts about httpd, nginx, mod_jk, HAProxy and Tomcat that these tests encode
were checked against the products' documentation or source.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from har_analyze.cli import (
    AnalyzerSettings,
    ConfigFact,
    HarAnalysisReport,
    HarAnalyzer,
    IssueSeverity,
    IssueType,
    OutputFormatter,
    RequestOutcome,
    app,
    build_events,
    error_fingerprint,
    generate_brief_report,
    generate_json_report,
    load_har,
    request_header_size,
    timeout_fact_applies_to_response_wait,
    timeout_fact_seconds,
)

from .conftest import analyze_fixture, make_entry, write_har

HOST = "https://app.example.com"
DOMAIN = "app.example.com"
runner = CliRunner()
EN_DASH = "\N{EN DASH}"  # Tomcat's error page title uses one

TOMCAT_500 = (
    f'<!doctype html><html lang="en"><head><title>HTTP Status 500 {EN_DASH} Internal Server '
    f"Error</title></head><body><h1>HTTP Status 500 {EN_DASH} Internal Server Error</h1>"
    "<p><b>Type</b> Exception Report</p><p><b>Message</b> order 12345 for jane@example.org"
    "</p><pre>javax.servlet.ServletException: wrapper\n"
    "\tat com.example.web.OrderServlet.doGet(OrderServlet.java:42)\n"
    "Caused by: java.lang.OutOfMemoryError: Java heap space\n"
    "\tat com.example.Cache.load(Cache.java:10)</pre>"
    '<hr class="line" /><h3>Apache Tomcat/9.0.85</h3></body></html>'
)
HTTPD_502 = (
    '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n'
    "<title>502 Proxy Error</title>\n</head><body>\n<h1>Proxy Error</h1>\n"
    "<p>The proxy server received an invalid\nresponse from an upstream server.<br />\n"
    "The proxy server could not handle the request<p>Reason: "
    "<strong>Error reading from remote server</strong></p></p>\n"
    "<hr>\n<address>Apache/2.4.58 (Unix) Server at app.example.com Port 443</address>\n"
    "</body></html>"
)
NGINX_504 = (
    "<html>\r\n<head><title>504 Gateway Time-out</title></head>\r\n<body>\r\n"
    "<center><h1>504 Gateway Time-out</h1></center>\r\n<hr><center>nginx/1.24.0</center>\r\n"
    "</body>\r\n</html>"
)


def body(text: str, mime: str = "text/html") -> dict[str, Any]:
    return {"content": {"size": len(text), "mimeType": mime, "text": text}}


def analyze(
    entries: list[dict[str, Any]],
    config_facts: list[ConfigFact] | None = None,
    **settings: Any,
) -> HarAnalysisReport:
    har = load_har({"log": {"entries": entries}})
    return HarAnalyzer(AnalyzerSettings(**settings), config_facts=config_facts).analyze(har)


def first_entry(entry: dict[str, Any]) -> Any:
    return load_har({"log": {"entries": [entry]}}).log.entries[0]


def findings(report: HarAnalysisReport, category: str) -> list[Any]:
    return [f for f in report.key_findings if f.category == category]


def timings(**overrides: float) -> dict[str, float]:
    base = {"blocked": 0, "dns": -1, "connect": -1, "ssl": -1, "send": 0, "wait": 90, "receive": 10}
    return {**base, **overrides}


# --- R27: slow endpoints are judged on wait, not on browser queueing -----------------


def test_r27_browser_queueing_does_not_make_an_endpoint_slow() -> None:
    entries = [
        make_entry(
            i * 1000, f"{HOST}/api/x", 200, 15_110, timings=timings(blocked=15_000, wait=100)
        )
        for i in range(3)
    ]
    report = analyze(entries)
    assert not [i for i in report.issues if i.issue_type == IssueType.SLOW_ENDPOINT]
    assert findings(report, "browser_queueing")
    har = load_har({"log": {"entries": entries}})
    assert {event["level"] for event in build_events(har, HarAnalyzer(), "x.har")} == {"INFO"}


def test_r27_slow_wait_is_still_reported_with_both_figures() -> None:
    entries = [make_entry(i * 1000, f"{HOST}/api/x", 200, 12_010) for i in range(3)]
    (issue,) = [i for i in analyze(entries).issues if i.issue_type == IssueType.SLOW_ENDPOINT]
    assert issue.message.startswith("Slow endpoint: wait max=12000ms")
    assert "total incl. browser queueing max=12010ms" in issue.message


def test_r17_failed_requests_are_reported_once_as_failures() -> None:
    report = analyze_fixture("timeout_cluster.har")
    types = [i.issue_type for i in report.issues]
    # Eight 60 s 502s used to be listed again as "duration exceeded" and "slow endpoint".
    assert IssueType.DURATION_EXCEEDED not in types
    assert IssueType.SLOW_ENDPOINT not in types
    assert types.count(IssueType.SERVER_ERROR) == 9


# --- R12: error runs use the time the requests failed ---------------------------------


def test_r12_error_runs_are_grouped_by_failure_time() -> None:
    entries = [
        make_entry(0, f"{HOST}/x", 504, 60_000),
        make_entry(55_000, f"{HOST}/y", 504, 5_000),
        make_entry(59_000, f"{HOST}/z", 500, 1_000),
    ]
    (run,) = analyze(entries).error_bursts
    assert run.error_count == 3
    assert run.endpoint_count == 3
    assert run.start_time == run.end_time  # all three failed at 10:01:00


def test_r12_errors_starting_together_but_failing_apart_are_not_a_run() -> None:
    entries = [make_entry(0, f"{HOST}/x", 504, 10_000 * (i + 1)) for i in range(3)]
    assert analyze(entries).error_bursts == []


def test_r41_single_endpoint_run_is_not_a_separate_finding() -> None:
    report = analyze_fixture("timeout_cluster.har")
    assert report.error_bursts
    assert findings(report, "error_burst") == []
    entries = [make_entry(i * 100, f"{HOST}/api/{name}", 500, 50) for i, name in enumerate("abc")]
    (finding,) = findings(analyze(entries), "error_burst")
    assert "several endpoints failed together" in finding.summary


# --- R10 / R11: backend node from session cookies -------------------------------------


@pytest.mark.parametrize(
    ("request_cookie", "set_cookie", "expected"),
    [
        ("JSESSIONID=ABC123.node1", None, ("node1", "session pinned to (request JSESSIONID)")),
        # R11: everything after the first dot is the route
        (
            "JSESSIONID=ABC123.node1.dc2",
            None,
            ("node1.dc2", "session pinned to (request JSESSIONID)"),
        ),
        # R10: the route the response sets wins over where the session was pinned
        (
            "JSESSIONID=ABC123.node1",
            "JSESSIONID=DEF456.node2; Path=/app; HttpOnly",
            ("node2", "JSESSIONID route (Set-Cookie)"),
        ),
        # one session cookie per application path: no single node can be named
        ("JSESSIONID=AAA.SASServer1_1; JSESSIONID=BBB.SASServer1_2", None, None),
        (
            "JSESSIONID=AAA.n1; JSESSIONID=BBB.n1",
            None,
            ("n1", "session pinned to (request JSESSIONID)"),
        ),
        ("other=1; ROUTEID=.tc3", None, ("tc3", "session pinned to (request ROUTEID)")),
    ],
)
def test_r10_r11_backend_node(
    request_cookie: str, set_cookie: str | None, expected: tuple[str, str] | None
) -> None:
    entry = first_entry(
        make_entry(
            0,
            f"{HOST}/app/a",
            request_headers=[("Cookie", request_cookie)],
            response_headers=[("Set-Cookie", set_cookie)] if set_cookie else [],
        )
    )
    assert HarAnalyzer.backend_node(entry) == expected


def test_r11_ambiguous_routes_are_counted_and_disclosed() -> None:
    cookie = "JSESSIONID=AAA.SASServer1_1; JSESSIONID=BBB.SASServer1_2"
    report = analyze([make_entry(0, f"{HOST}/a", request_headers=[("Cookie", cookie)])])
    assert report.backend_ambiguous_request_count == 1
    assert report.backend_nodes == []
    markdown = OutputFormatter().generate_markdown_report(report, "x.har")
    assert "naming several different routes" in markdown
    assert "AAA" not in markdown  # session IDs are never printed
    assert "BBB" not in markdown


def test_r10_one_node_row_even_when_evidence_comes_from_both_directions() -> None:
    entries = [
        make_entry(
            0, f"{HOST}/app/a", response_headers=[("Set-Cookie", "JSESSIONID=A1.n1; Path=/app")]
        ),
        make_entry(100, f"{HOST}/app/b", request_headers=[("Cookie", "JSESSIONID=A1.n1")]),
    ]
    (node,) = analyze(entries).backend_nodes
    assert (node.node, node.request_count) == ("n1", 2)
    assert "Set-Cookie" in node.source
    assert "session pinned to" in node.source


# --- R28 / R29: idle periods ----------------------------------------------------------


def test_r28_unknown_duration_only_blocks_the_gap_it_could_cover() -> None:
    unknown = make_entry(40_000, f"{HOST}/c", 200, 100)
    unknown["time"] = None
    unknown["timings"]["wait"] = -1
    entries = [
        make_entry(0, f"{HOST}/a"),
        make_entry(30_000, f"{HOST}/b"),  # judged: 29.9 s idle before it
        unknown,  # judged (9.9 s after /b ended), but it may still be running...
        make_entry(70_000, f"{HOST}/d"),  # ...so this gap is not judged
        make_entry(71_000, f"{HOST}/e", 200, 500),
        make_entry(90_000, f"{HOST}/f"),  # judged again: /e has a known end
    ]
    report = analyze(entries)
    assert [round(gap.gap_duration_ms) for gap in report.time_gaps] == [29_900, 18_500, 9_900]
    assert report.idle_gap_unknown_count == 1
    markdown = OutputFormatter().generate_markdown_report(report, "x.har")
    assert "1 possible idle period(s) were not judged" in markdown


def test_r29_idle_table_labels_match_in_terminal_and_markdown(tmp_path: Path) -> None:
    har_path = write_har(
        tmp_path / "x.har", [make_entry(0, f"{HOST}/a"), make_entry(30_000, f"{HOST}/b")]
    )
    terminal = runner.invoke(app, ["analyze", str(har_path)], env={"COLUMNS": "200"}).output
    markdown_path = tmp_path / "x.md"
    runner.invoke(app, ["analyze", str(har_path), "-o", str(markdown_path)])
    markdown = markdown_path.read_text(encoding="utf-8")
    for label in ("Idle from", "Next request", "Next request started"):
        assert label in terminal, label
        assert label in markdown, label
    assert "After Request" not in terminal


# --- R30 / R40: the error page names the tier that wrote it ---------------------------


def test_r30_tomcat_error_page_gives_tier_exception_and_frame_but_no_message() -> None:
    fingerprint = error_fingerprint(
        first_entry(make_entry(0, f"{HOST}/app/x", 500, response_extra=body(TOMCAT_500)))
    )
    assert fingerprint is not None
    assert fingerprint.responder == "Tomcat default error page (Apache Tomcat/9.0.85)"
    assert fingerprint.source == "body"
    assert fingerprint.exception == "javax.servlet.ServletException"
    assert fingerprint.root_cause == "java.lang.OutOfMemoryError"
    assert fingerprint.first_frame == "com.example.web.OrderServlet.doGet(OrderServlet.java:42)"
    # exception messages can hold user data and are never copied
    assert "jane@example.org" not in fingerprint.describe()
    assert "12345" not in fingerprint.describe()


def test_r30_httpd_proxy_error_page_gives_the_reason() -> None:
    fingerprint = error_fingerprint(
        first_entry(make_entry(0, f"{HOST}/app/x", 502, response_extra=body(HTTPD_502)))
    )
    assert fingerprint is not None
    assert fingerprint.responder == "Apache httpd error document (Apache/2.4.58)"
    assert fingerprint.proxy_reason == "Error reading from remote server"


def test_r30_nginx_spring_boot_and_base64_bodies() -> None:
    nginx = error_fingerprint(
        first_entry(make_entry(0, f"{HOST}/x", 504, response_extra=body(NGINX_504)))
    )
    assert nginx is not None
    assert nginx.responder == "nginx error page (nginx/1.24.0)"

    spring = json.dumps(
        {
            "timestamp": "2026-01-01T10:00:00Z",
            "status": 500,
            "error": "Internal Server Error",
            "exception": "java.lang.IllegalStateException",
            "path": "/api/x",
        }
    )
    spring_fp = error_fingerprint(
        first_entry(
            make_entry(0, f"{HOST}/api/x", 500, response_extra=body(spring, "application/json"))
        )
    )
    assert spring_fp is not None
    assert spring_fp.responder == "Spring Boot default error JSON (application tier)"
    assert spring_fp.exception == "java.lang.IllegalStateException"

    encoded = {
        "content": {
            "size": len(TOMCAT_500),
            "mimeType": "text/html",
            "text": base64.b64encode(TOMCAT_500.encode()).decode(),
            "encoding": "base64",
        }
    }
    decoded = error_fingerprint(
        first_entry(make_entry(0, f"{HOST}/x", 500, response_extra=encoded))
    )
    assert decoded is not None
    assert decoded.responder.startswith("Tomcat default error page")


def test_r30_no_evidence_and_non_errors_give_no_fingerprint() -> None:
    assert error_fingerprint(first_entry(make_entry(0, f"{HOST}/x", 500))) is None
    ok_with_stack = make_entry(0, f"{HOST}/x", 200, response_extra=body(TOMCAT_500))
    assert error_fingerprint(first_entry(ok_with_stack)) is None
    bad_base64 = {"content": {"size": 4, "text": "!!!", "encoding": "base64"}}
    assert (
        error_fingerprint(first_entry(make_entry(0, f"{HOST}/x", 500, response_extra=bad_base64)))
        is None
    )
    not_spring = body('{"message": "no"}', "application/json")
    assert (
        error_fingerprint(first_entry(make_entry(0, f"{HOST}/x", 500, response_extra=not_spring)))
        is None
    )
    json_list = body("[1, 2]", "application/json")
    assert (
        error_fingerprint(first_entry(make_entry(0, f"{HOST}/x", 500, response_extra=json_list)))
        is None
    )
    broken_json = body("{not json", "application/json")
    assert (
        error_fingerprint(first_entry(make_entry(0, f"{HOST}/x", 500, response_extra=broken_json)))
        is None
    )


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ([("Server", "awselb/2.0")], "AWS load balancer (Server: awselb/2.0)"),
        ([("Server", "Apache-Coyote/1.1")], "Tomcat connector (Server: Apache-Coyote/1.1)"),
        (
            [("Content-Type", "text/html; charset=iso-8859-1")],
            "Content-Type matches httpd's built-in error documents (weak clue)",
        ),
        (
            [("Content-Type", "text/html;charset=utf-8"), ("Content-Language", "en")],
            "headers match Tomcat's default error page (weak clue)",
        ),
    ],
)
def test_r40_header_only_clues_are_labelled_as_headers(
    headers: list[tuple[str, str]], expected: str
) -> None:
    fingerprint = error_fingerprint(
        first_entry(make_entry(0, f"{HOST}/x", 502, response_headers=headers))
    )
    assert fingerprint is not None
    assert (fingerprint.responder, fingerprint.source) == (expected, "headers")


def test_r30_error_origin_and_incident_use_the_error_page() -> None:
    entries = [
        make_entry(0, f"{HOST}/app/x", 200),
        make_entry(1000, f"{HOST}/app/x", 500, response_extra=body(TOMCAT_500)),
    ]
    report = analyze(entries)
    (origin,) = report.error_origins
    assert origin.reading == (
        "the error page's own text identifies the responder: "
        "Tomcat default error page (Apache Tomcat/9.0.85) (1)"
    )
    assert origin.exceptions == {"java.lang.OutOfMemoryError": 1}
    (incident,) = report.incidents
    assert "exception: java.lang.OutOfMemoryError (1)" in incident.evidence[1]
    assert incident.where_to_look[0].startswith(
        "Search the application log and catalina.out for java.lang.OutOfMemoryError"
    )
    assert "the request reached Tomcat" in incident.where_to_look[1]
    (issue,) = [i for i in report.issues if i.issue_type == IssueType.SERVER_ERROR]
    assert issue.details["responder"].startswith("Tomcat default error page")
    har = load_har({"log": {"entries": entries}})
    event = build_events(har, HarAnalyzer(), "x.har")[1]
    assert event["exception"] == "java.lang.OutOfMemoryError"
    assert event["stack_signature"] == (
        "java.lang.OutOfMemoryError@com.example.web.OrderServlet.doGet(OrderServlet.java:42)"
    )
    assert event["attrs"]["responder"].startswith("Tomcat default error page")
    for text in (
        OutputFormatter().generate_markdown_report(report, "x.har"),
        generate_json_report(report, "x.har", show_query=False),
        json.dumps(event),
    ):
        assert "jane@example.org" not in text


def test_r30_missing_error_bodies_are_disclosed() -> None:
    report = analyze([make_entry(0, f"{HOST}/x", 500)])
    assert (report.error_response_count, report.error_body_count) == (1, 0)
    markdown = OutputFormatter().generate_markdown_report(report, "x.har")
    assert "Error page text: not available" in markdown


# --- R8: error origin compares with the same endpoint first ---------------------------


def test_r8_error_origin_prefers_successes_on_the_same_endpoint() -> None:
    static = [
        make_entry(i * 10, f"{HOST}/static/app.js?v={i}", response_headers=[("Server", "Apache")])
        for i in range(5)
    ]
    api_ok = [make_entry(1000 + i * 10, f"{HOST}/api/orders") for i in range(3)]
    api_bad = [
        make_entry(
            2000 + i * 10, f"{HOST}/api/orders", 503, response_headers=[("Server", "Apache")]
        )
        for i in range(3)
    ]
    (origin,) = analyze([*static, *api_ok, *api_bad]).error_origins
    # Host-wide, "Apache" is also on successes (the static files) and would read "same".
    assert origin.comparison_scope == "successes on the same endpoint(s)"
    assert origin.success_servers == {"(none)": 3}
    assert "different tier" in origin.reading

    (fallback,) = analyze([*static, *api_bad]).error_origins
    assert fallback.comparison_scope.startswith("host-wide successes")
    assert fallback.success_servers == {"Apache": 5}


# --- R9: the Date header belongs to whichever tier set it -----------------------------


def test_r9_clock_offset_names_the_tier_that_set_date() -> None:
    headers = [("Date", "Thu, 01 Jan 2026 10:05:00 GMT"), ("Server", "nginx")]
    entries = [make_entry(i * 1000, f"{HOST}/a{i}", response_headers=headers) for i in range(3)]
    report = analyze(entries)
    (offset,) = report.clock_offsets
    assert offset.date_servers == {"nginx": 3}
    markdown = OutputFormatter().generate_markdown_report(report, "x.har")
    assert "nginx replaces the backend's Date by default" in markdown
    assert "Server header on sampled responses" in markdown
    assert "widen the search window" not in markdown  # no failed/slow request to correlate


# --- R31: session continuity ----------------------------------------------------------


def _session_lost_entries() -> list[dict[str, Any]]:
    login = f"{HOST}/SASLogon/login"
    return [
        make_entry(0, f"{HOST}/app/api/data"),
        make_entry(
            2_000_000,
            f"{HOST}/app/api/save",
            302,
            method="POST",
            response_headers=[("Location", login)],
            response_extra={"redirectURL": login},
        ),
    ]


def test_r31_api_call_redirected_to_login_mid_capture() -> None:
    report = analyze(_session_lost_entries())
    (event,) = report.session_events
    assert (event.kind, event.request, event.entry_index) == (
        "login_redirect",
        "POST /app/api/save",
        2,
    )
    assert event.idle_seconds == pytest.approx(1999.9)
    (finding,) = findings(report, "session")
    assert finding.severity == IssueSeverity.HIGH  # a POST lost its data
    assert "1 were not GET" in finding.summary
    markdown = OutputFormatter().generate_markdown_report(report, "x.har")
    assert "## Session Events" in markdown
    assert "redirected to login" in markdown
    # no cookies in the capture: say so, but the redirect is still detected
    assert "Session cookie evidence (session re-issue, route change): not available" in markdown


@pytest.mark.parametrize(
    ("minutes", "expected"),
    [
        ("30", "so an ordinary session timeout fits"),
        ("60", "a session timeout does not explain it"),
    ],
)
def test_r31_idle_time_is_compared_with_session_timeout(minutes: str, expected: str) -> None:
    fact = ConfigFact(component="tomcat", key="session-config/session-timeout", value=minutes)
    (finding,) = findings(analyze(_session_lost_entries(), config_facts=[fact]), "session")
    assert expected in finding.recommendation
    assert f"({minutes} min)" in finding.recommendation


def test_r31_first_visit_redirect_to_login_is_not_a_session_loss() -> None:
    login = f"{HOST}/SASLogon/login"
    entries = [
        make_entry(0, f"{HOST}/app/", 302, response_extra={"redirectURL": login}),
        make_entry(100, login),
        make_entry(200, f"{HOST}/app/static/app.js"),
    ]
    assert analyze(entries).session_events == []


def test_r31_route_change_and_repeated_session_issue() -> None:
    def set_cookie(route: str, session: str) -> list[tuple[str, str]]:
        return [("Set-Cookie", f"JSESSIONID={session}.{route}; Path=/app; HttpOnly")]

    entries = [
        make_entry(0, f"{HOST}/app/a", response_headers=set_cookie("node1", "S1")),
        make_entry(1000, f"{HOST}/app/b", request_headers=[("Cookie", "JSESSIONID=S1.node1")]),
        make_entry(2000, f"{HOST}/app/c", response_headers=set_cookie("node2", "S2")),
        make_entry(3000, f"{HOST}/app/d", response_headers=set_cookie("node2", "S3")),
        # a cleared cookie is not a new session
        make_entry(
            4000,
            f"{HOST}/app/logout",
            response_headers=[("Set-Cookie", "JSESSIONID=; Path=/app; Max-Age=0")],
        ),
    ]
    report = analyze(entries)
    kinds = [event.kind for event in report.session_events]
    assert kinds == ["reissued", "route_changed", "reissued"]
    route_change = report.session_events[1]
    assert "route for /app changed from node1 to node2" in route_change.detail
    summaries = [f.summary for f in findings(report, "session")]
    assert any("The session route changed 1 time(s)" in s for s in summaries)
    assert any("session cookie for path /app on app.example.com (3 times)" in s for s in summaries)
    assert report.cookie_header_request_count == 5
    text = OutputFormatter().generate_markdown_report(report, "x.har")
    for session_id in ("S1.", "S2.", "S3."):
        assert f"JSESSIONID={session_id}" not in text


def test_r31_one_reissue_at_login_is_not_a_finding() -> None:
    entries = [
        make_entry(
            0, f"{HOST}/app/a", response_headers=[("Set-Cookie", "JSESSIONID=S1; Path=/app")]
        ),
        make_entry(
            1000, f"{HOST}/app/b", response_headers=[("Set-Cookie", "JSESSIONID=S2; Path=/app")]
        ),
    ]
    report = analyze(entries)
    assert [event.kind for event in report.session_events] == ["reissued"]
    assert findings(report, "session") == []


# --- R32: request header size ---------------------------------------------------------


def test_r32_400_with_oversized_cookie_names_the_header_limits() -> None:
    cookie = "a=" + "x" * 9000
    report = analyze([make_entry(0, f"{HOST}/app/x", 400, request_headers=[("Cookie", cookie)])])
    (issue,) = report.issues
    assert issue.severity == IssueSeverity.HIGH
    assert (
        issue.message == "Client error: 400 with request headers at or over the common 8 KB limit"
    )
    assert "largest field Cookie 8.8 KB" in issue.details["request_headers"]
    (finding,) = findings(report, "header_size")
    assert finding.severity == IssueSeverity.HIGH
    assert "Tomcat maxHttpHeaderSize 8192 bytes" in finding.recommendation
    (incident,) = report.incidents
    assert incident.severity == IssueSeverity.HIGH
    assert any("request headers 8.8 KB" in item for item in incident.evidence)
    assert any("find which cookies are large" in tip for tip in incident.where_to_look)


def test_r32_recorded_headers_size_is_used_and_small_400_is_unchanged() -> None:
    entry = make_entry(0, f"{HOST}/x", 400, request_extra={"headersSize": 512})
    size = request_header_size(first_entry(entry))
    assert size is not None
    assert (size.total_bytes, size.computed) == (512, False)
    assert size.describe() == "0.5 KB"
    report = analyze([entry])
    assert report.issues[0].severity == IssueSeverity.MEDIUM
    assert findings(report, "header_size") == []
    assert request_header_size(first_entry(make_entry(0, f"{HOST}/x"))) is None


def test_r32_headers_near_the_limit_are_a_low_finding() -> None:
    cookie = "a=" + "x" * 7000
    report = analyze([make_entry(0, f"{HOST}/x", request_headers=[("Cookie", cookie)])])
    (finding,) = findings(report, "header_size")
    assert finding.severity == IssueSeverity.LOW
    assert "Largest request headers in the capture: 6.9 KB" in finding.summary


# --- R33: host-wide stall -------------------------------------------------------------


def _stall_entries() -> list[dict[str, Any]]:
    baseline = [make_entry(20_000 + i * 1000, f"{HOST}/api/a", 200, 60) for i in range(5)]
    stalled = [
        make_entry(i * 500, f"{HOST}/api/{name}", 200, 8010 - i * 500)
        for i, name in enumerate(("a", "b", "c", "d"))
    ]
    return [*stalled, *baseline]


def test_r33_requests_sent_apart_and_answered_together() -> None:
    report = analyze(_stall_entries())
    (stall,) = report.stall_events
    assert (stall.request_count, stall.endpoint_count) == (4, 4)
    assert stall.entry_indexes == [1, 2, 3, 4]
    assert (stall.min_wait_ms, stall.max_wait_ms) == (6500, 8000)
    assert stall.release_spread_ms == 0
    assert stall.host_median_wait_ms == 50
    (finding,) = findings(report, "jvm_stall")
    assert finding.severity == IssueSeverity.HIGH
    assert "garbage collection" in finding.recommendation
    assert "cannot tell these apart" in finding.recommendation
    markdown = OutputFormatter().generate_markdown_report(report, "x.har")
    assert "## Host-wide Stalls" in markdown


def test_r33_one_connection_is_called_out() -> None:
    entries = _stall_entries()
    for entry in entries:
        entry["connection"] = "42"
    report = analyze(entries)
    assert report.stall_events[0].connection_count == 1
    assert "on one connection" in findings(report, "jvm_stall")[0].recommendation


def test_r33_requests_that_started_together_are_not_a_stall() -> None:
    baseline = [make_entry(20_000 + i * 1000, f"{HOST}/api/a", 200, 60) for i in range(5)]
    together = [make_entry(0, f"{HOST}/api/{name}", 200, 8010) for name in "abcd"]
    assert analyze([*together, *baseline]).stall_events == []
    # too few requests on the host to know what is normal
    assert analyze(_stall_entries()[:4]).stall_events == []


# --- R34: timeline --------------------------------------------------------------------


def test_r34_timeline_buckets_reconcile_with_the_request_count() -> None:
    entries = [
        make_entry(i * 3000, f"{HOST}/api/a", 500 if i == 7 else 200, 200) for i in range(12)
    ]
    entries.append(
        make_entry(
            36_000, f"{HOST}/api/b", 0, 50, response_extra={"_error": "net::ERR_CONNECTION_RESET"}
        )
    )
    report = analyze(entries)
    assert report.timeline_bucket_seconds == 5
    assert sum(b.request_count for b in report.timeline) == 13
    assert sum(b.server_error_count for b in report.timeline) == 1
    assert sum(b.network_error_count for b in report.timeline) == 1
    assert report.timeline[0].wait_p50_ms == 190
    markdown = OutputFormatter().generate_markdown_report(report, "x.har")
    assert "## Timeline (5 s buckets, by request start)" in markdown


def test_r34_small_hosts_have_no_timeline() -> None:
    assert analyze([make_entry(0, f"{HOST}/a")]).timeline == []


# --- R35: times to search for in server logs ------------------------------------------


def test_r35_log_correlation_gives_the_time_the_request_was_sent() -> None:
    phases = {
        "blocked": 4000,
        "dns": 10,
        "connect": 90,
        "ssl": 40,
        "send": 100,
        "wait": 800,
        "receive": 0,
    }
    entries = [make_entry(0, f"{HOST}/api/a?id=7", 500, 5000, timings=phases)]
    report = analyze(entries)
    (row,) = report.log_correlation
    assert row.sent_at is not None
    assert row.headers_at is not None
    assert row.sent_at.isoformat() == "2026-01-01T10:00:04.200000+00:00"  # ssl is inside connect
    assert row.headers_at.isoformat() == "2026-01-01T10:00:05+00:00"
    markdown = OutputFormatter().generate_markdown_report(report, "x.har")
    assert "## Log Correlation" in markdown
    assert "2026-01-01T10:00:04.200+00:00" in markdown
    assert "Tomcat %D is milliseconds up to Tomcat 9 and microseconds from Tomcat 10" in markdown
    har = load_har({"log": {"entries": entries}})
    assert (
        build_events(har, HarAnalyzer(), "x.har")[0]["attrs"]["sent_ts"]
        == "2026-01-01T10:00:04.200Z"
    )


def test_r35_log_correlation_is_capped_and_includes_slow_successes() -> None:
    failures = [make_entry(i * 100, f"{HOST}/api/a", 500, 50) for i in range(30)]
    slow = make_entry(10_000, f"{HOST}/api/slow", 200, 20_000)
    report = analyze([*failures, slow])
    assert len(report.log_correlation) == HarAnalyzer.LOG_CORRELATION_LIMIT
    few = analyze([*failures[:2], slow])
    assert [row.status for row in few.log_correlation] == [500, 500, 200]


def test_r35_clock_difference_is_carried_into_the_log_note() -> None:
    headers = [("Date", "Thu, 01 Jan 2026 10:05:00 GMT")]
    entries = [make_entry(i * 100, f"{HOST}/a", 500, response_headers=headers) for i in range(3)]
    markdown = OutputFormatter().generate_markdown_report(analyze(entries), "x.har")
    assert "widen the search window by that much" in markdown


# --- R36: request body limits ---------------------------------------------------------


def test_r36_oversized_form_post_and_413() -> None:
    form = {"bodySize": 3_000_000, "postData": {"mimeType": "application/x-www-form-urlencoded"}}
    upload = {"bodySize": 5_000_000, "postData": {"mimeType": "multipart/form-data; boundary=x"}}
    entries = [
        make_entry(0, f"{HOST}/app/save", 500, method="POST", request_extra=form),
        make_entry(1000, f"{HOST}/app/upload", 413, method="POST", request_extra=upload),
        make_entry(2000, f"{HOST}/app/ok", 200, method="POST", request_extra=upload),
    ]
    report = analyze(entries)
    notes = {body.url.rsplit("/", 1)[-1]: body.note for body in report.large_request_bodies}
    assert notes["save"].startswith("form body over Tomcat's default maxPostSize (2 MiB)")
    assert notes["upload"].startswith("rejected with 413")
    assert notes["ok"] == ""
    summaries = [f.summary for f in findings(report, "body_limit")]
    assert summaries == [
        "1 upload(s) were rejected with 413 (bodies up to 4.8 MB)",
        "1 form post(s) over 2 MiB were answered with an error",
    ]
    incident = next(i for i in report.incidents if i.signature == "413")
    assert "largest request body 4.8 MB" in incident.evidence
    markdown = OutputFormatter().generate_markdown_report(report, "x.har")
    assert "| Size | Method | Path | Content-Type | Status | Note |" in markdown


# --- R37 / R38: timeout clusters ------------------------------------------------------


def test_r37_clusters_use_wait_so_connection_setup_does_not_split_them() -> None:
    def phases(connect: float) -> dict[str, float]:
        return {
            "blocked": 0,
            "dns": -1,
            "connect": connect,
            "ssl": -1,
            "send": 0,
            "wait": 5000,
            "receive": 5,
        }

    entries = [
        make_entry(i * 1000, f"{HOST}/api/x", 504, 5005 + connect, timings=phases(connect))
        for i, connect in enumerate((0, 400, 900))
    ]
    (cluster,) = analyze(entries).timeout_clusters
    assert (cluster.basis, cluster.kind, cluster.request_count) == ("wait", "gateway", 3)
    assert cluster.min_ms == cluster.max_ms == 5000


def test_r37_requests_with_no_response_are_measured_without_queueing() -> None:
    entries = [
        make_entry(
            i * 1000,
            f"{HOST}/api/x",
            0,
            30_000 + queue,
            timings={
                "blocked": queue,
                "dns": -1,
                "connect": -1,
                "ssl": -1,
                "send": 0,
                "wait": -1,
                "receive": -1,
            },
            response_extra={"_error": "net::ERR_TIMED_OUT"},
        )
        for i, queue in enumerate((0, 4000, 9000))
    ]
    (cluster,) = analyze(entries).timeout_clusters
    assert (cluster.basis, cluster.kind) == ("total minus queue", "network")
    assert cluster.median_ms == 30_000


def test_r38_502_cluster_with_httpd_error_page_is_a_read_timeout_signature() -> None:
    entries = [
        make_entry(i * 2000, f"{HOST}/app/run", 502, 60_010, response_extra=body(HTTPD_502))
        for i in range(3)
    ]
    report = analyze(entries)
    (cluster,) = report.timeout_clusters
    assert cluster.kind == "proxy_502"
    assert cluster.proxy_reasons == {"Error reading from remote server": 3}
    (finding,) = findings(report, "timeout_cluster")
    assert finding.severity == IssueSeverity.HIGH
    assert "consistent with a proxy read timeout" in finding.summary
    assert 'error pages say "Error reading from remote server" (3)' in finding.summary
    (incident,) = report.incidents
    assert any("AH01102" in tip for tip in incident.where_to_look)
    assert any("Take thread dumps" in tip for tip in incident.where_to_look)
    # the restart / keep-alive advice is for fast 502s only
    assert not any("keepAliveTimeout" in tip for tip in incident.where_to_look)


def test_r38_502_cluster_without_evidence_stays_a_hypothesis() -> None:
    report = analyze_fixture("timeout_cluster.har")
    (finding,) = findings(report, "timeout_cluster")
    assert finding.severity == IssueSeverity.MEDIUM
    assert "may be a proxy read timeout" in finding.summary
    assert "No configuration facts were loaded" in finding.recommendation


def test_r38_fast_502_gets_the_keep_alive_advice() -> None:
    entries = [make_entry(0, f"{HOST}/app/run", 200), make_entry(1000, f"{HOST}/app/run", 502, 15)]
    (incident,) = analyze(entries).incidents
    assert any("keepAliveTimeout" in tip for tip in incident.where_to_look)
    slow = [make_entry(0, f"{HOST}/app/run", 502, 45_000)]
    (slow_incident,) = analyze(slow).incidents
    assert any("For a 502 after a long wait" in tip for tip in slow_incident.where_to_look)


def test_r14_r37_timeout_units_and_response_wait_candidates() -> None:
    # HAProxy bare numbers are milliseconds; session-timeout is minutes; mod_jk
    # socket_timeout is seconds and is a response-wait timer.
    assert (
        timeout_fact_seconds(ConfigFact(component="haproxy", key="timeout server", value="30000"))
        == 30
    )
    assert (
        timeout_fact_seconds(ConfigFact(component="haproxy", key="timeout server", value="30s"))
        == 30
    )
    assert (
        timeout_fact_seconds(ConfigFact(component="tomcat", key="session-timeout", value="30"))
        == 1800
    )
    socket_timeout = ConfigFact(component="mod_jk", key="worker.node1.socket_timeout", value="60")
    assert timeout_fact_seconds(socket_timeout) == 60
    assert timeout_fact_applies_to_response_wait(socket_timeout)
    connect = ConfigFact(component="mod_jk", key="worker.node1.connect_timeout", value="10000")
    assert not timeout_fact_applies_to_response_wait(connect)


def test_r7_short_timeouts_are_clustered() -> None:
    entries = [make_entry(i * 500, f"{HOST}/api/x", 504, 1010) for i in range(3)]
    (cluster,) = analyze(entries).timeout_clusters
    assert cluster.median_ms == 1000


# --- R39: status readings -------------------------------------------------------------


def test_r39_status_hints_state_verified_proxy_and_tomcat_behaviour() -> None:
    hints = HarAnalyzer.STATUS_HINTS
    assert 'httpd mod_proxy answers 502 "Error reading from remote server", not 504' in hints[502]
    assert "worker is in error state (retry, default 60 s)" in hints[503]
    assert "queues connections instead of answering 503" in hints[503]
    assert "time without data from the backend" in hints[504]


# --- R41 / R42: incidents -------------------------------------------------------------


def test_r41_every_failed_request_is_in_exactly_one_incident() -> None:
    entries = [
        *[make_entry(i * 100, f"{HOST}/api/a/{i}", 500, 50) for i in range(4)],
        *[make_entry(1000 + i * 100, f"{HOST}/api/a/{i}", 503, 50) for i in range(2)],
        make_entry(2000, f"{HOST}/api/a/9", 200),
        make_entry(3000, f"{HOST}/api/b", 404),
        make_entry(
            4000, f"{HOST}/api/c", 0, 20, response_extra={"_error": "net::ERR_CONNECTION_REFUSED"}
        ),
        make_entry(5000, f"{HOST}/api/d", 0, 20, response_extra={"_error": "net::ERR_ABORTED"}),
        make_entry(6000, f"{HOST}/SASLogon/x", 401),  # expected
    ]
    report = analyze(entries)
    assert sum(i.failure_count for i in report.incidents) == 8
    assert sum(d.failed_requests for d in report.domains) == 8
    by_signature = {(i.endpoint, i.signature): i for i in report.incidents}
    assert set(by_signature) == {
        ("/api/a/{n}", "500"),
        ("/api/a/{n}", "503"),
        ("/api/b", "404"),
        ("/api/c", "connection_refused"),
    }
    five_hundred = by_signature["/api/a/{n}", "500"]
    assert (five_hundred.failure_count, five_hundred.endpoint_request_count) == (4, 7)
    assert five_hundred.endpoint_success_count == 1
    assert five_hundred.severity == IssueSeverity.HIGH  # the endpoint also succeeded
    assert five_hundred.outcome == RequestOutcome.SERVER_ERROR
    assert five_hundred.entry_indexes == [1, 2, 3, 4]
    refused = by_signature["/api/c", "connection_refused"]
    assert refused.where_to_look == [
        "Nothing accepted the connection: check that the listener (load balancer, web "
        "server or Tomcat connector) was running and the port open at these times"
    ]
    assert by_signature["/api/b", "404"].severity == IssueSeverity.MEDIUM
    # incidents are ordered worst first
    assert [i.severity for i in report.incidents] == sorted(
        (i.severity for i in report.incidents), key=list(IssueSeverity).index
    )


def test_r41_r42_incident_section_in_every_output(tmp_path: Path) -> None:
    report = analyze_fixture("timeout_cluster.har")
    first, second = report.incidents
    assert (first.severity, first.failure_count, first.signature) == (
        IssueSeverity.CRITICAL,
        8,
        "502",
    )
    assert (second.severity, second.signature) == (IssueSeverity.HIGH, "504")
    assert first.first_sent.isoformat() == "2026-01-01T10:00:00+00:00"
    assert first.last_failure.isoformat() == "2026-01-01T10:01:14.400000+00:00"
    markdown = OutputFormatter().generate_markdown_report(report, "x.har")
    assert "## Incidents (failed requests grouped by endpoint and signature)" in markdown
    assert "**Incident 1: POST sas.example.com/SASStoredProcess/do → 502**" in markdown
    assert (
        "Search server logs from 2026-01-01T10:00:00.000+00:00 to 2026-01-01T10:01:14.400+00:00 "
        "(browser clock) for POST /SASStoredProcess/do with status 502; HAR entries "
        "1, 2, 3, 4, 5 (+3 more)"
    ) in markdown
    assert "Next: The capture does not show which tier wrote this response" in markdown
    brief = generate_brief_report(report, OutputFormatter(), "x.har")
    assert "## Incidents (failed requests by endpoint and signature)" in brief
    assert "[CRITICAL] 8 of 8 POST sas.example.com/SASStoredProcess/do → 502" in brief
    terminal = runner.invoke(
        app,
        ["analyze", str(Path(__file__).parent / "fixtures" / "timeout_cluster.har")],
        env={"COLUMNS": "200"},
    ).output
    assert "Incident 1: POST sas.example.com/SASStoredProcess/do → 502" in terminal
    assert "Times in tables are on 2026-01-01 (UTC offset +00:00)" in terminal


def test_r41_hidden_incidents_are_counted() -> None:
    entries = [make_entry(i * 10, f"{HOST}/api/e{i}/x", 500, 5) for i in range(18)]
    markdown = OutputFormatter().generate_markdown_report(analyze(entries), "x.har")
    assert "... and 3 more incident(s) covering 3 failed request(s)" in markdown


@pytest.mark.parametrize(
    ("status", "page", "expected"),
    [
        (504, NGINX_504, "The error page was written by nginx"),
        (502, HTTPD_502, "The error page was written by Apache httpd"),
        (503, "", "For 503: check balancer member state"),
        (500, "", "For 500: the stack trace is normally in the application log"),
        (401, "", "For 401: check the authentication service's log"),
        (403, "", "For 403: check the authorization rules"),
        (404, "", "For 404: check that the web application (context) is deployed"),
        (429, "", "For 429: find which tier applies the rate limit"),
        (400, "", 'logs "Error parsing HTTP request header" in catalina.out'),
    ],
)
def test_r42_where_to_look_follows_the_evidence(status: int, page: str, expected: str) -> None:
    extra = body(page) if page else None
    (incident,) = analyze(
        [make_entry(0, f"{HOST}/app/x", status, 20, response_extra=extra)]
    ).incidents
    assert any(expected in tip for tip in incident.where_to_look), incident.where_to_look


def test_r42_load_balancer_and_network_errors() -> None:
    lb = make_entry(0, f"{HOST}/x", 502, 20, response_headers=[("Server", "awselb/2.0")])
    (incident,) = analyze([lb]).incidents
    assert any("AWS load balancer" in tip for tip in incident.where_to_look)
    for error, expected in (
        ("net::ERR_CONNECTION_RESET", "The connection was dropped"),
        ("net::ERR_EMPTY_RESPONSE", "AH01102"),
        ("net::ERR_TIMED_OUT", "acceptCount / maxConnections"),
        ("net::ERR_SOMETHING_NEW", "See the browser console"),
    ):
        entry = make_entry(0, f"{HOST}/x", 0, 20, response_extra={"_error": error})
        (network_incident,) = analyze([entry]).incidents
        assert expected in network_incident.where_to_look[0], error


# --- R16 / R19: grouped issues with labelled details ----------------------------------


def test_r16_identical_issues_are_one_block_and_counts_reconcile() -> None:
    report = analyze_fixture("timeout_cluster.har")
    formatter = OutputFormatter()
    errors = [i for i in report.issues if i.issue_type == IssueType.SERVER_ERROR]
    groups = formatter._issue_groups(errors)
    assert sorted(len(group) for group in groups) == [1, 8]
    assert sum(len(group) for group in groups) == len(errors)
    markdown = formatter.generate_markdown_report(report, "x.har")
    assert markdown.count("Server error: 502 Bad Gateway**") == 1
    assert "- **8x Server error: 502 Bad Gateway**" in markdown
    assert "### HIGH (9 in 2 group(s))" in markdown
    assert "  - Duration: 60000-60400ms" in markdown
    assert "  - HAR entries: 1, 2, 3, 4, 5, 6, 7, 8" in markdown
    assert "  - Over the duration threshold: yes" in markdown


def test_r19_issue_details_are_labelled_not_raw_field_names() -> None:
    entries = [
        make_entry(0, f"{HOST}/api/slow?token=abc", 200, 40_000),
        make_entry(
            100,
            f"{HOST}/api/x",
            0,
            20,
            response_extra={"_error": "net::ERR_CONNECTION_RESET"},
            extra={"serverIPAddress": "10.0.0.7"},
        ),
    ]
    markdown = OutputFormatter().generate_markdown_report(analyze(entries), "x.har")
    for raw in (
        "wait_time_ms",
        "threshold_ms",
        "entry_index",
        "duration_source",
        "error_category:",
    ):
        assert raw not in markdown, raw
    assert "  - Browser error: net::ERR_CONNECTION_RESET" in markdown
    assert "  - Server IP: 10.0.0.7" in markdown
    assert "  - Sent (≈ server receipt): 2026-01-01T10:00:00.000+00:00" in markdown
    assert "token=abc" not in markdown


def test_r26_hidden_issue_groups_are_counted(tmp_path: Path) -> None:
    entries = [make_entry(i * 10, f"{HOST}/api/e{i}/x", 404, 5) for i in range(60)]
    markdown = OutputFormatter().generate_markdown_report(analyze(entries), "x.har")
    assert "*... and 10 more group(s) covering 10 issue(s) in this severity*" in markdown
    har_path = write_har(tmp_path / "many.har", entries)
    terminal = runner.invoke(app, ["analyze", str(har_path)], env={"COLUMNS": "200"}).output
    assert "... and 52 more group(s) covering 52 issue(s)" in terminal
    assert "... and 45 more incident(s) covering 45 failed request(s)" in terminal


# --- R18 / R20 / R21 ------------------------------------------------------------------


def test_r18_polling_an_api_is_not_a_caching_finding() -> None:
    polled = [make_entry(i * 1000, f"{HOST}/api/status") for i in range(5)]
    report = analyze(polled)
    assert report.cache_analysis is not None
    assert report.cache_analysis.repeated_downloads  # still listed in the cache table
    assert findings(report, "caching") == []
    static = [make_entry(i * 1000, f"{HOST}/static/app.js") for i in range(3)]
    (finding,) = findings(analyze([*polled, *static]), "caching")
    assert finding.summary.startswith("1 static URL(s) fetched repeatedly")


def test_r20_wait_is_labelled_the_same_everywhere() -> None:
    report = analyze_fixture("timeout_cluster.har")
    markdown = OutputFormatter().generate_markdown_report(report, "x.har")
    assert "- **Wait / TTFB:** 100%" in markdown
    assert "Tail wait (TTFB)" in markdown
    assert "Tail TTFB" not in markdown
    assert "- **TTFB:**" not in markdown


def test_r21_terminal_tables_fit_100_columns_without_cutting_text(tmp_path: Path) -> None:
    fixture = Path(__file__).parent / "fixtures" / "timeout_cluster.har"
    output = runner.invoke(app, ["analyze", str(fixture)], env={"COLUMNS": "100"}).output
    assert "…" not in output  # nothing is cut short with an ellipsis
    assert max(len(line) for line in output.splitlines()) <= 100
    assert "10:01:14.400" in output
    flowed = " ".join(output.split())
    assert "Not recorded for any row: Server IP / node, Correlation IDs" in flowed
    assert "Expected, Aborted and TCP connect median are in the Markdown report" in flowed


def test_compression_advice_states_tomcat_defaults() -> None:
    text = "x" * 5000
    entry = make_entry(
        0, f"{HOST}/api/a", response_extra=body(text, "application/json") | {"bodySize": 5000}
    )
    (finding,) = findings(analyze([entry]), "compression")
    assert "compression is off by default" in finding.recommendation
    assert "static files over 48 KiB are sent uncompressed" in finding.recommendation


# --- R23: JSON output -----------------------------------------------------------------


def test_r23_json_report_is_redacted_like_the_other_outputs(tmp_path: Path) -> None:
    entries = [
        make_entry(0, f"{HOST}/app/a;jsessionid=SECRETSESSION?ticket=ST-12345#frag", 500, 50),
        make_entry(
            100,
            f"{HOST}/app/b?code=OAUTHCODE",
            302,
            response_extra={"redirectURL": f"{HOST}/app/c?state=STATE99"},
        ),
        make_entry(200, f"{HOST}/app/c?state=STATE99", 200),
    ]
    har_path = write_har(tmp_path / "x.har", entries)
    json_path = tmp_path / "report.json"
    result = runner.invoke(app, ["analyze", str(har_path), "--json", str(json_path), "--brief"])
    assert result.exit_code == 0
    text = json_path.read_text(encoding="utf-8")
    payload = json.loads(text)
    assert payload["schema_version"] == 1
    assert payload["query_strings"] == "redacted"
    assert payload["report"]["total_requests"] == 3
    assert payload["report"]["incidents"][0]["signature"] == "500"
    for secret in ("ST-12345", "OAUTHCODE", "STATE99", "SECRETSESSION", "frag"):
        assert secret not in text, secret
    assert (
        "https://app.example.com/app/a;jsessionid=<redacted>?ticket=<redacted>#<redacted>" in text
    )

    shown = generate_json_report(analyze(entries), "x.har", show_query=True)
    assert "ticket=ST-12345" in shown
    assert "SECRETSESSION" not in shown  # session IDs are never printed
    assert json.loads(shown)["query_strings"] == "shown"
    assert generate_json_report(
        analyze(entries), "x.har", show_query=False
    ) == generate_json_report(analyze(entries), "x.har", show_query=False)


# --- invariants -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture",
    ["timeout_cluster.har", "sas_logon_flow.har", "aborted_requests.har", "uuid_paths.har"],
)
def test_incidents_timeline_and_groups_reconcile_on_every_fixture(fixture: str) -> None:
    report = analyze_fixture(fixture)
    failed_total = sum(d.failed_requests for d in report.domains)
    assert sum(i.failure_count for i in report.incidents) == failed_total
    for incident in report.incidents:
        assert incident.failure_count <= incident.endpoint_request_count
        assert incident.first_failure <= incident.last_failure
        assert incident.min_wait_ms <= incident.max_wait_ms
    timeline_hosts = {b.domain for b in report.timeline}
    for host in timeline_hosts:
        domain = next(d for d in report.domains if d.domain == host)
        assert (
            sum(b.request_count for b in report.timeline if b.domain == host)
            == domain.total_requests
        )
    formatter = OutputFormatter()
    assert sum(len(g) for g in formatter._issue_groups(report.issues)) == len(report.issues)


# --- R26: "... and N more" branches ---------------------------------------------------


def test_r26_long_lists_say_how_many_rows_are_hidden(tmp_path: Path) -> None:
    entries = [
        make_entry(
            i * 10,
            f"https://host{i:02d}.example.com/api/x",
            500,
            5,
            response_headers=[("Server", "Apache")],
            extra={"serverIPAddress": f"10.0.0.{i}"},
        )
        for i in range(25)
    ]
    har_path = write_har(tmp_path / "many-hosts.har", entries)
    output = runner.invoke(app, ["analyze", str(har_path)], env={"COLUMNS": "200"}).output
    flowed = " ".join(output.split())
    assert "... and 5 more domains" in flowed  # domain health (20 shown)
    assert "... and 10 more domains" in flowed  # issue tree (15 shown)
    assert "... and 15 more domains" in flowed  # server software (10 shown)
    assert "... and 10 more" in flowed  # server IPs (15 shown)
    assert "... and 10 more incident(s) covering 10 failed request(s)" in flowed


def test_cluster_evidence_blocks_and_event_attributes() -> None:
    entries = [
        make_entry(i * 2000, f"{HOST}/app/run", 502, 60_010, response_extra=body(HTTPD_502))
        for i in range(3)
    ]
    unrelated = ConfigFact(component="nginx", key="proxy_read_timeout", value="300")
    markdown = OutputFormatter().generate_markdown_report(
        analyze(entries, config_facts=[unrelated]), "x.har"
    )
    assert "- No loaded configuration setting has this length" in markdown
    assert '- Error pages say: "Error reading from remote server" (3)' in markdown
    matching = ConfigFact(component="httpd", key="ProxyTimeout", value="60")
    report = analyze(entries, config_facts=[matching])
    assert "Settings of the same length" in OutputFormatter().generate_markdown_report(report, "x")
    assert "no loaded config setting matches" in generate_brief_report(
        analyze(entries, config_facts=[unrelated]), OutputFormatter(), "x.har"
    )
    har = load_har({"log": {"entries": entries}})
    event = build_events(har, HarAnalyzer(), "x.har")[0]
    assert event["attrs"]["proxy_reason"] == "Error reading from remote server"
    assert event["exception"] is None


def test_stack_trace_in_an_unrecognised_error_page_still_names_the_java_tier() -> None:
    page = (
        "<pre>java.sql.SQLTransientConnectionException: pool timeout\n\tat a.b.C.d(C.java:1)</pre>"
    )
    fingerprint = error_fingerprint(
        first_entry(make_entry(0, f"{HOST}/x", 500, response_extra=body(page)))
    )
    assert fingerprint is not None
    assert fingerprint.responder == "Java application (stack trace in the response body)"
    assert fingerprint.exception == "java.sql.SQLTransientConnectionException"
    assert "pool timeout" not in fingerprint.describe()
