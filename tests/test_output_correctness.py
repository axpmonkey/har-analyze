"""Independent regression cases from the second output-correctness review."""

from __future__ import annotations

import pytest

from har_analyze.cli import (
    AnalyzerSettings,
    ConfigFact,
    HarAnalyzer,
    HarHeader,
    IssueType,
    OutputFormatter,
    build_events,
    generate_brief_report,
    load_har,
    parse_server_timings,
)

from .conftest import make_entry

HOST = "https://app.example"


def test_missing_timing_is_not_a_zero_ms_measurement() -> None:
    entry = make_entry(0, f"{HOST}/api")
    entry.pop("time")
    entry.pop("timings")
    report = HarAnalyzer().analyze(load_har({"log": {"entries": [entry]}}))
    assert report.total_requests == 1
    assert report.overall_timings.count == 0
    assert any("timing" in note.lower() for note in OutputFormatter().capture_note_lines(report))


@pytest.mark.parametrize("duration", [-50, float("nan"), float("inf"), 1e100])
def test_invalid_duration_preserves_http_failure_without_poisoning_stats(duration: float) -> None:
    entry = make_entry(0, f"{HOST}/api", 500, duration)
    report = HarAnalyzer().analyze(load_har({"log": {"entries": [entry]}}))
    assert report.total_requests == 1
    assert report.status_codes == {500: 1}
    assert report.overall_timings.count == 0
    assert report.total_duration_ms >= 0


def test_bad_url_does_not_discard_good_entries() -> None:
    har = load_har(
        {
            "log": {
                "entries": [
                    make_entry(0, "https://[broken/api"),
                    make_entry(100, f"{HOST}/api"),
                ]
            }
        }
    )
    assert len(har.log.entries) == 1
    assert har.load_notes.skipped_entry_count == 1


def test_cache_metadata_does_not_prove_local_hit_or_double_count_304() -> None:
    entries = [
        make_entry(0, f"{HOST}/asset.js", 304, extra={"cache": {"beforeRequest": {"eTag": "abc"}}})
    ]
    report = HarAnalyzer().analyze(load_har({"log": {"entries": entries}}))
    assert report.cache_analysis is not None
    assert report.cache_analysis.cacheable_get_count == 1
    assert report.cache_analysis.browser_cache_hit_count == 0
    assert report.latency_population is not None
    assert report.latency_population.measured_count == 1


def test_latency_endpoints_separate_methods() -> None:
    entries = [
        make_entry(0, f"{HOST}/api", method="GET"),
        make_entry(1000, f"{HOST}/api", time_ms=20000, method="POST"),
    ]
    report = HarAnalyzer().analyze(load_har({"log": {"entries": entries}}))
    assert len(report.endpoints) == 2
    assert sorted(endpoint.count for endpoint in report.endpoints) == [1, 1]


def test_application_errors_are_not_gateway_timeout_evidence() -> None:
    entries = [make_entry(index * 1000, f"{HOST}/api", 500, 60000) for index in range(3)]
    report = HarAnalyzer().analyze(load_har({"log": {"entries": entries}}))
    assert len(report.timeout_clusters) == 1
    assert report.timeout_clusters[0].kind == "failure"
    finding = next(item for item in report.key_findings if item.category == "timeout_cluster")
    assert "gateway/proxy timeout" not in finding.summary
    assert "connectionTimeout" not in finding.recommendation


def test_short_timeout_cluster_is_detected() -> None:
    entries = [make_entry(index * 1000, f"{HOST}/api", 504, 2000) for index in range(3)]
    report = HarAnalyzer().analyze(load_har({"log": {"entries": entries}}))
    assert len(report.timeout_clusters) == 1
    assert report.timeout_clusters[0].median_ms == 1990  # wait = total - 10 ms receive


def test_timeout_match_requires_relevant_semantics() -> None:
    facts = [
        ConfigFact(component="tomcat", key="connectionTimeout", value="60000"),
        ConfigFact(component="httpd", key="ProxyTimeout", value="60"),
    ]
    entries = [make_entry(index * 1000, f"{HOST}/api", 504, 60000) for index in range(3)]
    report = HarAnalyzer(config_facts=facts).analyze(load_har({"log": {"entries": entries}}))
    assert len(report.timeout_clusters[0].matching_settings) == 1
    assert "ProxyTimeout" in report.timeout_clusters[0].matching_settings[0]


def test_node_findings_disclose_unknown_failures_and_cookie_uncertainty() -> None:
    entries = [
        make_entry(
            index * 1000,
            f"{HOST}/api",
            500,
            request_headers=[("Cookie", "JSESSIONID=secret.node1")],
        )
        for index in range(3)
    ]
    entries += [
        make_entry(4000, f"{HOST}/api", request_headers=[("Cookie", "JSESSIONID=secret.node2")]),
        make_entry(5000, f"{HOST}/api", 500),
    ]
    report = HarAnalyzer().analyze(load_har({"log": {"entries": entries}}))
    for finding in report.key_findings:
        if finding.category == "backend_node":
            assert "All" not in finding.summary
            assert "unknown" in finding.summary.lower()
            assert "routing" in finding.recommendation.lower()


def test_date_difference_is_not_a_log_clock_correction() -> None:
    entries = [
        make_entry(
            index * 20000,
            f"{HOST}/api",
            time_ms=10000,
            response_headers=[("Date", f"Thu, 01 Jan 2026 10:00:{index * 20:02d} GMT")],
        )
        for index in range(3)
    ]
    report = HarAnalyzer().analyze(load_har({"log": {"entries": entries}}))
    finding = next(item for item in report.key_findings if item.category == "clock_offset")
    assert "add " not in finding.recommendation.lower()
    assert "uncertain" in finding.summary.lower()


def test_equal_timestamp_redirect_loop_is_reported() -> None:
    entries = [
        make_entry(0, f"{HOST}/a", 302, response_extra={"redirectURL": "/b"}),
        make_entry(0, f"{HOST}/b", 302, response_extra={"redirectURL": "/a"}),
    ]
    report = HarAnalyzer().analyze(load_har({"log": {"entries": entries}}))
    assert any(issue.issue_type == IssueType.REDIRECT_LOOP for issue in report.issues)


def test_static_errors_remain_visible_and_events_respect_expected_outcomes() -> None:
    analyzer = HarAnalyzer(AnalyzerSettings(expected_rules=["500:/expected"]))
    har = load_har(
        {
            "log": {
                "entries": [
                    make_entry(0, f"{HOST}/assets/app.js", 500),
                    make_entry(1000, f"{HOST}/expected", 500),
                ]
            }
        }
    )
    report = analyzer.analyze(har)
    assert len(OutputFormatter()._filter_backend_error_issues(report.issues)) == 1
    assert [event["level"] for event in build_events(har, analyzer, "synthetic.har")] == [
        "ERROR",
        "INFO",
    ]


@pytest.mark.parametrize("value", [-1, float("nan"), float("inf")])
def test_invalid_thresholds_fail_validation(value: float) -> None:
    with pytest.raises(ValueError):
        AnalyzerSettings(slow_endpoint_ms=value)


def test_percentiles_match_hand_calculated_interpolation() -> None:
    statistics = HarAnalyzer()._compute_timing_stats([40, 10, 30, 20])
    assert statistics.count == 4
    assert statistics.mean == statistics.p50 == 25
    assert statistics.p95 == pytest.approx(38.5)
    assert statistics.p99 == pytest.approx(39.7)
    assert statistics.total_duration_ms == 100


def test_inconsistent_phases_are_visible_and_tls_is_not_clamped_to_zero() -> None:
    entry = make_entry(
        0,
        f"{HOST}/api",
        time_ms=100,
        timings={"connect": 10, "ssl": 20, "send": 0, "wait": 50, "receive": 0},
    )
    report = HarAnalyzer().analyze(load_har({"log": {"entries": [entry]}}))
    assert report.connect_timings.count == 0
    assert report.timing_warning_count == 1
    assert "TLS exceeds connect" in ";".join(report.timing_warning_examples)
    assert "differs from recorded phase sum" in ";".join(report.timing_warning_examples)


def test_total_is_derived_only_from_complete_mandatory_phases() -> None:
    entry = make_entry(
        0,
        f"{HOST}/api",
        timings={
            "blocked": 5,
            "dns": 10,
            "connect": 30,
            "ssl": 20,
            "send": 5,
            "wait": 100,
            "receive": 50,
        },
    )
    entry.pop("time")
    report = HarAnalyzer().analyze(load_har({"log": {"entries": [entry]}}))
    assert report.overall_timings.max == 200  # SSL is inside connect
    assert report.derived_duration_count == 1
    assert sum(phase.total_ms for phase in report.phase_breakdown) == 200


def test_cache_and_latency_populations_reconcile_with_unknown_source() -> None:
    entry = make_entry(
        0, f"{HOST}/empty", time_ms=0, timings={"send": -1, "wait": -1, "receive": -1}
    )
    report = HarAnalyzer().analyze(load_har({"log": {"entries": [entry]}}))
    cache = report.cache_analysis
    assert cache is not None
    assert cache.unknown_cache_count == 1
    assert cache.cacheable_get_count == (
        cache.browser_cache_hit_count
        + cache.not_modified_count
        + cache.network_download_count
        + cache.unknown_cache_count
    )


def test_clusters_do_not_mix_hosts_or_expected_failures() -> None:
    entries = [
        make_entry(index * 1000, f"https://host{index}.example/api", 504, 2000)
        for index in range(3)
    ]
    analyzer = HarAnalyzer(AnalyzerSettings(expected_rules=["504:/expected"]))
    entries += [make_entry(index * 1000, f"{HOST}/expected", 504, 2000) for index in range(3)]
    report = analyzer.analyze(load_har({"log": {"entries": entries}}))
    assert report.timeout_clusters == []


def test_server_timing_ignores_delimiters_and_fake_durations_inside_descriptions() -> None:
    headers = [
        HarHeader(
            name="Server-Timing",
            value=('app;desc="nested;dur=999, fake;dur=888";dur=12.5, db;dur=5, app;dur=90'),
        )
    ]
    assert parse_server_timings(headers) == {"app": 12.5, "db": 5}


def test_session_path_is_redacted_even_when_show_query_is_enabled() -> None:
    analyzer = HarAnalyzer()
    har = load_har(
        {
            "log": {
                "entries": [
                    make_entry(
                        0,
                        f"{HOST}/api;jsessionid=SECRET.node1?code=QUERYSECRET",
                        500,
                        response_headers=[("X-Request-Id", "synthetic-request-1")],
                    )
                ]
            }
        }
    )
    report = analyzer.analyze(har)
    formatter = OutputFormatter(show_query=True)
    markdown = formatter.generate_markdown_report(report, "synthetic.har")
    brief = generate_brief_report(report, formatter, "synthetic.har")
    events = str(build_events(har, analyzer, "synthetic.har"))
    assert "SECRET.node1" not in markdown + brief + events
    assert "QUERYSECRET" in markdown
    assert "QUERYSECRET" not in events


def test_unknown_duration_does_not_create_false_idle_gap() -> None:
    entry = make_entry(0, f"{HOST}/pending", 0)
    entry.pop("time")
    entry.pop("timings")
    report = HarAnalyzer().analyze(
        load_har(
            {
                "log": {
                    "entries": [
                        entry,
                        make_entry(10000, f"{HOST}/api"),
                    ]
                }
            }
        )
    )
    assert report.time_gaps == []


@pytest.mark.parametrize("status", [-1, 1, 99, 600])
def test_invalid_status_is_counted_as_skipped(status: int) -> None:
    har = load_har(
        {
            "log": {
                "entries": [make_entry(0, f"{HOST}/bad", status), make_entry(100, f"{HOST}/good")]
            }
        }
    )
    assert har.load_notes.skipped_entry_count == 1
    assert len(har.log.entries) == 1
