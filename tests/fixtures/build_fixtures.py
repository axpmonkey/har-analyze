"""Regenerate the golden HAR fixtures (except timing_semantics.har, written by hand).

Run: ``uv run python tests/fixtures/build_fixtures.py``. The .har files are the source
of truth; expected values in tests/test_golden.py are computed by hand from them.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

FIXTURES = Path(__file__).parent
HOST = "https://sas.example.com"
T0 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)


def iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def entry(  # noqa: PLR0913
    start: datetime,
    url: str,
    status: int,
    time_ms: float,
    *,
    method: str = "GET",
    redirect: str = "",
    error: str | None = None,
    wait: float | None = None,
    receive: float = 10,
    connection: str | None = None,
    status_text: str = "",
) -> dict[str, Any]:
    response: dict[str, Any] = {
        "status": status,
        "statusText": status_text,
        "httpVersion": "HTTP/1.1",
        "headers": [],
        "cookies": [],
        "content": {"size": 0, "mimeType": "text/html"},
        "redirectURL": redirect,
        "headersSize": -1,
        "bodySize": 0,
    }
    if error is not None:
        response["_error"] = error
    record: dict[str, Any] = {
        "startedDateTime": iso(start),
        "time": time_ms,
        "request": {
            "method": method,
            "url": url,
            "httpVersion": "HTTP/1.1",
            "headers": [],
            "queryString": [],
            "cookies": [],
            "headersSize": -1,
            "bodySize": 0,
        },
        "response": response,
        "cache": {},
        "timings": {
            "blocked": 0,
            "dns": -1,
            "connect": -1,
            "ssl": -1,
            "send": 0,
            "wait": time_ms - receive if wait is None else wait,
            "receive": receive,
        },
    }
    if connection is not None:
        record["connection"] = connection
    return record


def write(name: str, entries: list[dict[str, Any]]) -> None:
    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "fixture", "version": "1"},
            "entries": entries,
        }
    }
    (FIXTURES / name).write_text(json.dumps(har, indent=2) + "\n", encoding="utf-8")


def ms(value: float) -> timedelta:
    return timedelta(milliseconds=value)


def sas_logon_flow() -> None:
    """302 -> 401 (Negotiate), user logs in, POST 302 -> ticket 302 -> 200, favicon 404."""
    service = "https%3A%2F%2Fsas.example.com%2FSASPortal%2Fj_spring_cas_security_check"
    login = f"{HOST}/SASLogon/login?service={service}"
    ticket_url = f"{HOST}/SASPortal/j_spring_cas_security_check?ticket=ST-1-abcdef-secret"
    write(
        "sas_logon_flow.har",
        [
            entry(T0, f"{HOST}/SASPortal/", 302, 50, redirect=login),
            entry(T0 + ms(100), login, 401, 40),
            entry(T0 + ms(5000), login, 302, 120, method="POST", redirect=ticket_url),
            entry(T0 + ms(5200), ticket_url, 302, 60, redirect="/SASPortal/"),
            entry(T0 + ms(5300), f"{HOST}/SASPortal/", 200, 300),
            entry(T0 + ms(5700), f"{HOST}/favicon.ico", 404, 20),
        ],
    )


def aborted_requests() -> None:
    write(
        "aborted_requests.har",
        [
            entry(T0, f"{HOST}/SASVisualAnalytics/", 200, 100),
            entry(
                T0 + ms(200),
                f"{HOST}/reports/poll",
                0,
                50,
                error="net::ERR_ABORTED",
                wait=-1,
                receive=-1,
            ),
            entry(
                T0 + ms(300),
                f"{HOST}/reports/data",
                0,
                2000,
                error="net::ERR_CONNECTION_RESET",
                wait=-1,
                receive=-1,
            ),
            entry(T0 + ms(2400), f"{HOST}/SASVisualAnalytics/app.js", 200, 100),
        ],
    )


def timeout_cluster() -> None:
    url = f"{HOST}/SASStoredProcess/do?_program=%2FReports%2Fbig"
    durations = [60000, 60050, 60100, 60150, 60200, 60250, 60300, 60400]
    entries = [
        entry(T0 + timedelta(seconds=2 * i), url, 502, d, method="POST", status_text="Bad Gateway")
        for i, d in enumerate(durations)
    ]
    entries.append(entry(T0 + timedelta(seconds=20), f"{HOST}/SASStoredProcess/other", 504, 15000))
    later = T0 + timedelta(minutes=3)
    entries.extend(
        entry(later + timedelta(seconds=2 * i), url, 200, d)
        for i, d in enumerate([800, 900, 1000, 1100])
    )
    write("timeout_cluster.har", entries)
    facts = [
        {
            "component": "httpd",
            "instance": "web-01",
            "file": "conf/httpd.conf",
            "line": 120,
            "key": "ProxyTimeout",
            "value": "60",
        },
        {
            "component": "httpd",
            "instance": "web-01",
            "file": "conf/httpd.conf",
            "line": 130,
            "key": "timeout",
            "value": "300",
        },
        {
            "component": "tomcat",
            "instance": "SASServer1_1",
            "file": "conf/server.xml",
            "line": 88,
            "key": "connectionTimeout",
            "value": "20000",
            "value_num": 20000,
        },
        {"component": "postgres", "instance": "db", "key": "statement_timeout", "value": "0"},
        {"component": "tomcat", "instance": "SASServer1_1", "key": "maxThreads", "value": "300"},
    ]
    (FIXTURES / "timeout_cluster.config_facts.json").write_text(
        json.dumps(facts, indent=2) + "\n", encoding="utf-8"
    )


def uuid_paths() -> None:
    """30 requests, one endpoint template; 25 x 3 s and 5 x 12 s -> p95 = 12 s."""
    entries: list[dict[str, Any]] = []
    start = T0
    for i in range(30):
        duration = 12000 if i >= 25 else 3000
        uuid = f"{i + 1:08x}-0000-4000-8000-{i + 1:012x}"
        entries.append(entry(start, f"{HOST}/reports/reports/{uuid}/content", 200, duration))
        start += ms(duration + 100)
    write("uuid_paths.har", entries)


def no_connection_ids() -> None:
    """5 requests, only 2 carry a connection ID (40% < 80% coverage)."""
    write(
        "no_connection_ids.har",
        [
            entry(
                T0 + ms(100 * i),
                f"{HOST}/api/item/{i}",
                200,
                50,
                connection="101" if i < 2 else None,
            )
            for i in range(5)
        ],
    )


if __name__ == "__main__":
    sas_logon_flow()
    aborted_requests()
    timeout_cluster()
    uuid_paths()
    no_connection_ids()
