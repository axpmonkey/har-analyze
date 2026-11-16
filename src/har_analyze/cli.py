#!/usr/bin/env python3
"""HAR Analyze CLI.

Analyze HAR files with deterministic performance insights.
"""

from __future__ import annotations

__version__ = "0.1.0"

import hashlib
import json
import logging
import re
import statistics
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, tzinfo
from email.utils import parsedate_to_datetime
from enum import StrEnum
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Self, cast
from urllib.parse import parse_qsl, urljoin, urlparse, urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import typer
from pydantic import BaseModel, Field, ValidationError, model_validator
from rich.console import Console
from rich.markdown import Markdown
from rich.markup import escape as rich_escape
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

logger = logging.getLogger(__name__)
console = Console()


# =============================================================================
# Enums
# =============================================================================


class IssueSeverity(StrEnum):
    """Issue severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IssueType(StrEnum):
    """Types of detected issues."""

    NETWORK_ERROR = "network_error"
    DURATION_EXCEEDED = "duration_exceeded"
    SERVER_ERROR = "server_error"
    CLIENT_ERROR = "client_error"
    RATE_LIMITED = "rate_limited"
    LARGE_PAYLOAD = "large_payload"
    SLOW_ENDPOINT = "slow_endpoint"
    BLOCKING = "blocking"
    REDIRECT_CHAIN = "redirect_chain"
    REDIRECT_LOOP = "redirect_loop"
    REQUEST_ABORTED = "request_aborted"


class RequestOutcome(StrEnum):
    """The single bucket each request falls into (buckets always sum to the total)."""

    SUCCESS = "success"  # 1xx-3xx
    EXPECTED = "expected"  # matched an expected rule
    ABORTED = "aborted"  # cancelled / blocked by the client (informational)
    NETWORK_ERROR = "network_error"
    CLIENT_ERROR = "client_error"  # 4xx
    SERVER_ERROR = "server_error"  # 5xx


PROBLEM_OUTCOMES = frozenset(
    {RequestOutcome.NETWORK_ERROR, RequestOutcome.CLIENT_ERROR, RequestOutcome.SERVER_ERROR}
)


class DomainHealth(StrEnum):
    """Health status for a domain."""

    CRITICAL = "critical"
    DEGRADED = "degraded"
    HEALTHY = "healthy"


# =============================================================================
# HAR Models (HTTP Archive 1.2 spec)
# =============================================================================


class LenientHarModel(BaseModel):
    """Base for HAR models: a JSON ``null`` means "not recorded" and takes the default.

    Real exporters (Firefox, Safari, proxies) write ``null`` or omit optional fields; one
    such field must not make the whole capture unreadable.
    """

    @model_validator(mode="before")
    @classmethod
    def _drop_nulls(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        raw = cast("dict[str, Any]", data)
        return {key: value for key, value in raw.items() if value is not None}


class HarHeader(LenientHarModel):
    """HTTP header name-value pair."""

    name: str
    value: str = ""


class HarPostData(LenientHarModel):
    """POST request data."""

    mime_type: str = Field("", alias="mimeType")


class HarRequest(LenientHarModel):
    """HTTP request."""

    method: str
    url: str
    http_version: str = Field("", alias="httpVersion")
    headers: list[HarHeader] = Field(default_factory=list[HarHeader])
    body_size: int = Field(-1, alias="bodySize")
    post_data: HarPostData | None = Field(None, alias="postData")


class HarContent(LenientHarModel):
    """Response body details (``size`` is the uncompressed length)."""

    size: int = -1
    mime_type: str = Field("", alias="mimeType")


class HarResponse(LenientHarModel):
    """HTTP response."""

    status: int
    status_text: str = Field("", alias="statusText")
    headers: list[HarHeader] = Field(default_factory=list[HarHeader])
    redirect_url: str = Field("", alias="redirectURL")
    body_size: int = Field(-1, alias="bodySize")  # bytes on the wire (compressed)
    content: HarContent | None = None
    transfer_size: int | None = Field(None, alias="_transferSize")
    error: str | None = Field(None, alias="_error")


class HarCache(LenientHarModel):
    """Cache information (``beforeRequest`` is set when a cache entry was used)."""

    before_request: dict[str, Any] | None = Field(None, alias="beforeRequest")


class HarTimings(LenientHarModel):
    """Request/response timings (all in milliseconds; -1 = not recorded)."""

    blocked: float = -1.0
    dns: float = -1.0
    ssl: float = -1.0
    connect: float = -1.0
    send: float = -1.0
    wait: float = -1.0
    receive: float = -1.0

    @property
    def connect_excluding_ssl(self) -> float:
        """TCP connect time without TLS, or -1 if unknown.

        Per HAR 1.2, ``ssl`` is included in ``connect`` when both are >= 0, so summing
        ``connect + ssl`` would count the TLS handshake twice.
        """
        if self.connect < 0:
            return -1.0
        if self.ssl >= 0:
            return max(self.connect - self.ssl, 0.0)
        return self.connect

    @property
    def before_response_headers_ms(self) -> float:
        """Blocked + DNS + connect + send + wait (recorded phases only)."""
        phases = (self.blocked, self.dns, self.connect, self.send, self.wait)
        return sum(phase for phase in phases if phase >= 0)


class HarEntry(LenientHarModel):
    """Single HTTP transaction."""

    started_date_time: datetime = Field(alias="startedDateTime")
    time: float
    request: HarRequest
    response: HarResponse
    cache: HarCache | None = None
    timings: HarTimings = Field(default_factory=HarTimings)
    server_ip_address: str | None = Field(None, alias="serverIPAddress")
    connection: str | None = None
    from_cache: str | None = Field(None, alias="_fromCache")
    resource_type: str | None = Field(None, alias="_resourceType")
    started_date_time_raw: str = ""  # startedDateTime exactly as written in the HAR
    timestamp_assumed_utc: bool = False  # startedDateTime had no UTC offset
    entry_index: int = 0  # 1-based position in the HAR file (0 = not loaded via load_har)

    @model_validator(mode="before")
    @classmethod
    def _keep_raw_start_and_derive_time(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        raw = dict(cast("dict[str, Any]", data))
        if "startedDateTime" in raw and "started_date_time_raw" not in raw:
            raw["started_date_time_raw"] = str(raw["startedDateTime"])
        if raw.get("time") is None:
            # No total recorded: use the sum of the recorded phases (ssl is inside connect).
            timings = raw.get("timings")
            phases: dict[str, Any] = (
                cast("dict[str, Any]", timings) if isinstance(timings, dict) else {}
            )
            raw["time"] = sum(
                float(value)
                for name in ("blocked", "dns", "connect", "send", "wait", "receive")
                if isinstance(value := phases.get(name), int | float) and value >= 0
            )
        return raw

    @model_validator(mode="after")
    def _assume_utc_without_offset(self) -> Self:
        if self.started_date_time.tzinfo is None:
            self.started_date_time = self.started_date_time.replace(tzinfo=UTC)
            self.timestamp_assumed_utc = True
        return self


class HarCreator(LenientHarModel):
    """Tool that produced the HAR (``log.creator`` / ``log.browser``)."""

    name: str = ""
    version: str = ""


class HarLoadNotes(BaseModel):
    """What ``load_har`` left out or adjusted, so reports can say so."""

    skipped_entry_count: int = 0
    skipped_entry_reasons: list[str] = Field(default_factory=list[str])  # first few only
    non_http_entry_count: int = 0  # data:, blob:, chrome-extension:, about: ...


class HarLog(LenientHarModel):
    """HAR log container."""

    entries: list[HarEntry]
    creator: HarCreator | None = None
    browser: HarCreator | None = None


class Har(LenientHarModel):
    """Root HAR object."""

    log: HarLog
    load_notes: HarLoadNotes = Field(default_factory=HarLoadNotes)


NETWORK_URL_SCHEMES = frozenset({"http", "https", "ws", "wss"})
SKIPPED_ENTRY_REASON_LIMIT = 5


def load_har(raw_data: object) -> Har:
    """Build a ``Har`` from parsed JSON, entry by entry.

    An entry that cannot be used (no URL, start time or status) is skipped and counted
    instead of rejecting the capture; entries that never touched the network (``data:``,
    ``blob:``, browser-extension URLs) are dropped and counted. Raises ValueError when the
    document is not a HAR or no entry is usable.
    """
    log_data = cast("dict[str, Any]", raw_data).get("log") if isinstance(raw_data, dict) else None
    if not isinstance(log_data, dict):
        raise ValueError("Not a HAR file: no top-level 'log' object")
    log_fields = cast("dict[str, Any]", log_data)
    raw_entries = log_fields.get("entries")
    if not isinstance(raw_entries, list):
        raise ValueError("Not a HAR file: 'log.entries' is not a list")

    raw_entry_list = cast("list[object]", raw_entries)
    notes = HarLoadNotes()
    entries: list[HarEntry] = []
    for entry_index, raw_entry in enumerate(raw_entry_list, start=1):
        try:
            entry = HarEntry.model_validate(raw_entry)
        except ValidationError as exc:
            notes.skipped_entry_count += 1
            if len(notes.skipped_entry_reasons) < SKIPPED_ENTRY_REASON_LIMIT:
                first_error = exc.errors()[0]
                field_path = ".".join(str(part) for part in first_error["loc"]) or "entry"
                notes.skipped_entry_reasons.append(
                    f"entry {entry_index}: {field_path}: {first_error['msg']}"
                )
            continue
        if urlsplit(entry.request.url).scheme.lower() not in NETWORK_URL_SCHEMES:
            notes.non_http_entry_count += 1
            continue
        entry.entry_index = entry_index
        entries.append(entry)

    if raw_entry_list and not entries:
        reasons = "; ".join(notes.skipped_entry_reasons) or "no http(s) entries"
        raise ValueError(f"No usable entries in HAR ({len(raw_entry_list)} present): {reasons}")

    def creator(value: object) -> HarCreator | None:
        try:
            return HarCreator.model_validate(value) if isinstance(value, dict) else None
        except ValidationError:
            return None

    return Har(
        log=HarLog(
            entries=entries,
            creator=creator(log_fields.get("creator")),
            browser=creator(log_fields.get("browser")),
        ),
        load_notes=notes,
    )


# =============================================================================
# Settings, Rules and Shared Helpers
# =============================================================================

DEFAULT_EXPECTED_RULES: tuple[str, ...] = (
    "401:/SASLogon/*",
    "3xx:/SASLogon/*",
    "404:*/favicon.ico",
)


class AnalyzerSettings(BaseModel):
    """User-tunable thresholds and rules (printed in every report)."""

    slow_endpoint_ms: float = 10_000
    duration_exceeded_ms: float = 30_000
    large_payload_bytes: int = 1_048_576
    blocking_ms: float = 5_000
    idle_gap_ms: float = 1_000
    large_request_body_bytes: int = 102_400
    redirect_chain_min_hops: int = 3
    timeout_cluster_min_requests: int = 3
    timeout_cluster_tolerance_pct: float = 2.0
    expected_rules: list[str] = Field(default_factory=lambda: list(DEFAULT_EXPECTED_RULES))
    path_rules: list[str] = Field(default_factory=list)


_STATUS_PATTERN_RE = re.compile(r"^[1-5](?:[0-9]{2}|xx)$")


@dataclass(frozen=True)
class ExpectedRule:
    """A response that is normal for the application (counted, never escalated).

    Text form is ``STATUS:PATH_GLOB``, e.g. ``401:/SASLogon/*`` or ``4xx:*/favicon.ico``.
    """

    status_pattern: str
    path_glob: str

    @classmethod
    def parse(cls, text: str) -> ExpectedRule:
        """Parse ``STATUS:PATH_GLOB``; raise ValueError when malformed."""
        status_part, separator, path_glob = text.strip().partition(":")
        status_pattern = status_part.strip().lower()
        if not separator or not path_glob or not _STATUS_PATTERN_RE.match(status_pattern):
            raise ValueError(
                f"Invalid expected rule {text!r}; use STATUS:PATH_GLOB, e.g. 401:/SASLogon/*"
            )
        return cls(status_pattern=status_pattern, path_glob=path_glob.strip())

    def matches(self, status: int, path: str) -> bool:
        """Return True when the status and URL path match this rule."""
        status_text = str(status)
        if self.status_pattern.endswith("xx"):
            status_ok = status_text[:1] == self.status_pattern[0] and len(status_text) == 3  # noqa: PLR2004
        else:
            status_ok = status_text == self.status_pattern
        return status_ok and fnmatchcase(path, self.path_glob)

    def __str__(self) -> str:
        """Return the rule in its ``STATUS:PATH_GLOB`` text form."""
        return f"{self.status_pattern}:{self.path_glob}"


@dataclass(frozen=True)
class PathTemplateRule:
    """User rule replacing a whole path segment matching ``pattern`` with ``{name}``."""

    pattern: re.Pattern[str]
    name: str

    @classmethod
    def parse(cls, text: str) -> PathTemplateRule:
        """Parse ``REGEX=NAME``; raise ValueError when malformed."""
        regex, separator, name = text.rpartition("=")
        if not separator or not regex or not name.strip():
            raise ValueError(f"Invalid path rule {text!r}; use REGEX=NAME, e.g. [A-Z]{{3}}\\d+=id")
        try:
            pattern = re.compile(regex)
        except re.error as exc:
            raise ValueError(f"Invalid regex in path rule {text!r}: {exc}") from exc
        return cls(pattern=pattern, name=name.strip())


_UUID_SEGMENT_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_DIGITS_SEGMENT_RE = re.compile(r"^\d+$")
_LONG_HEX_SEGMENT_RE = re.compile(r"^[0-9a-fA-F]{16,}$")


def template_path(path: str, rules: tuple[PathTemplateRule, ...] = ()) -> str:
    """Replace ID-like path segments so one endpoint is not split into many.

    User rules are tried first, then UUID -> ``{uuid}``, all digits -> ``{n}``,
    hex of 16+ chars -> ``{hex}``.
    """
    templated: list[str] = []
    for segment in (path or "/").split("/"):
        replacement = segment
        if segment:
            for rule in rules:
                if rule.pattern.fullmatch(segment):
                    replacement = f"{{{rule.name}}}"
                    break
            else:
                if _UUID_SEGMENT_RE.match(segment):
                    replacement = "{uuid}"
                elif _DIGITS_SEGMENT_RE.match(segment):
                    replacement = "{n}"
                elif _LONG_HEX_SEGMENT_RE.match(segment):
                    replacement = "{hex}"
        templated.append(replacement)
    return "/".join(templated) or "/"


REDACTED = "<redacted>"


def redact_url(url: str, *, show_query: bool = False) -> str:
    """Return the URL's path with query values and fragment redacted.

    SAS Logon / OAuth flows carry ``ticket=``, ``code=``, ``state=`` and
    ``access_token=`` in the query or fragment, so values are hidden by default.
    """
    parts = urlsplit(url)
    path = parts.path or "/"
    if show_query:
        query = f"?{parts.query}" if parts.query else ""
        fragment = f"#{parts.fragment}" if parts.fragment else ""
        return f"{path}{query}{fragment}"
    query = ""
    if parts.query:
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        if pairs:
            query = "?" + "&".join(f"{name}={REDACTED}" for name, _ in pairs)
        else:
            query = f"?{REDACTED}"
    fragment = f"#{REDACTED}" if parts.fragment else ""
    return f"{path}{query}{fragment}"


# Network error classification. Chrome records ``_error: "net::ERR_*"``; Firefox uses
# ``NS_*`` names. Order matters: the first matching category wins.
INFORMATIONAL_ERROR_CATEGORIES = frozenset({"aborted", "blocked_by_client"})
_NETWORK_ERROR_CATEGORIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("aborted", ("ERR_ABORTED", "ERR_CANCELED", "ERR_CANCELLED", "NS_BINDING_ABORTED")),
    ("blocked_by_client", ("ERR_BLOCKED_BY_CLIENT",)),
    # The server's own headers (CORP/COEP/X-Frame-Options, opaque-response blocking)
    # made the browser discard the response: a server-side configuration matter.
    ("blocked_by_response_policy", ("ERR_BLOCKED_BY_RESPONSE", "ERR_BLOCKED_BY_ORB")),
    (
        "connection_reset",
        (
            "ERR_CONNECTION_RESET",
            "ERR_CONNECTION_CLOSED",
            "ERR_CONNECTION_ABORTED",
            "NS_ERROR_NET_RESET",
            "NS_ERROR_NET_INTERRUPT",
        ),
    ),
    ("connection_refused", ("ERR_CONNECTION_REFUSED", "NS_ERROR_CONNECTION_REFUSED")),
    ("timed_out", ("ERR_TIMED_OUT", "ERR_CONNECTION_TIMED_OUT", "NS_ERROR_NET_TIMEOUT")),
    (
        "dns",
        ("ERR_NAME_NOT_RESOLVED", "ERR_NAME_RESOLUTION_FAILED", "NS_ERROR_UNKNOWN_HOST"),
    ),
    ("tls", ("ERR_SSL_", "ERR_CERT_", "SSL_ERROR_", "SEC_ERROR_")),
    ("empty_response", ("ERR_EMPTY_RESPONSE",)),
    # The response started and was cut off, or the stream was reset part-way.
    (
        "truncated_response",
        (
            "ERR_INCOMPLETE_CHUNKED_ENCODING",
            "ERR_INVALID_CHUNKED_ENCODING",
            "ERR_CONTENT_LENGTH_MISMATCH",
            "ERR_HTTP2_PROTOCOL_ERROR",
            "ERR_SPDY_PROTOCOL_ERROR",
            "ERR_QUIC_PROTOCOL_ERROR",
            "ERR_RESPONSE_HEADERS_TRUNCATED",
            "NS_ERROR_NET_PARTIAL_TRANSFER",
        ),
    ),
    (
        "proxy_tunnel",
        (
            "ERR_TUNNEL_CONNECTION_FAILED",
            "ERR_PROXY_CONNECTION_FAILED",
            "NS_ERROR_PROXY_CONNECTION_REFUSED",
        ),
    ),
    (
        "client_network_changed",
        (
            "ERR_NETWORK_CHANGED",
            "ERR_INTERNET_DISCONNECTED",
            "ERR_ADDRESS_UNREACHABLE",
            "NS_ERROR_OFFLINE",
        ),
    ),
    ("too_many_redirects", ("ERR_TOO_MANY_REDIRECTS", "NS_ERROR_REDIRECT_LOOP")),
    # Chrome reports net::ERR_FAILED for CORS rejections and other unspecific failures.
    ("generic_failure", ("ERR_FAILED",)),
)

# What each category is consistent with (shown only for categories that occurred).
NETWORK_ERROR_HINTS: dict[str, str] = {
    "connection_reset": "a proxy or server closed the connection",
    "connection_refused": "nothing was listening on the address (service down or blocked)",
    "timed_out": "no answer at the network level (firewall drop, host down, overload)",
    "dns": "the hostname did not resolve on the client",
    "tls": "certificate or TLS protocol setup",
    "empty_response": "the connection was closed before any response bytes",
    "truncated_response": (
        "the response was cut off mid-stream (proxy timeout during a streamed response, "
        "backend abort, or an HTTP/2 stream reset)"
    ),
    "proxy_tunnel": "the client-side forward proxy could not reach the site",
    "client_network_changed": "the client machine's own network changed or dropped",
    "too_many_redirects": "a redirect loop the browser gave up on",
    "blocked_by_response_policy": (
        "the server's response headers (CORP/COEP/X-Frame-Options) made the browser discard it"
    ),
    "generic_failure": "unspecific browser failure (often a CORS rejection; see the console)",
    "no_response": "no status and no error text were recorded",
    "other": "an error this tool does not classify",
}


def classify_network_error(entry: HarEntry) -> str | None:
    """Return a network error category, or None when the request got a response.

    ``aborted`` / ``blocked_by_client`` are informational (user navigated away, app
    cancelled polling, ad blocker); every other category is a real failure. An empty
    error string is the same as no error.
    """
    error = entry.response.error
    if not error:
        return "no_response" if entry.response.status == 0 else None
    error_upper = error.upper()
    for category, markers in _NETWORK_ERROR_CATEGORIES:
        if any(marker in error_upper for marker in markers):
            return category
    return "other"


def is_real_network_error(entry: HarEntry) -> bool:
    """Return True for network failures that are not informational (e.g. aborted)."""
    category = classify_network_error(entry)
    return category is not None and category not in INFORMATIONAL_ERROR_CATEGORIES


_SERVER_TIMING_DUR_RE = re.compile(r"(?:^|;)\s*dur\s*=\s*\"?([0-9]+(?:\.[0-9]+)?)", re.IGNORECASE)
_DURATION_WITH_UNIT_RE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*(ms|s|sec|seconds)?\s*$", re.I)


def parse_server_timings(headers: list[HarHeader]) -> dict[str, float]:
    """Extract server-reported timings (ms) from ``Server-Timing`` and custom headers.

    Supports ``Server-Timing: app;dur=123.4, db;dur=5``, ``X-Response-Time: 123ms``
    (bare number = ms) and ``X-Runtime: 0.123`` (seconds, Rails/Rack convention).
    """
    timings: dict[str, float] = {}
    for header in headers:
        name = header.name.lower()
        if name == "server-timing":
            for metric in header.value.split(","):
                metric_name = metric.split(";", 1)[0].strip()
                match = _SERVER_TIMING_DUR_RE.search(metric)
                if metric_name and match:
                    timings[metric_name] = float(match.group(1))
        elif name in ("x-response-time", "x-runtime"):
            match = _DURATION_WITH_UNIT_RE.match(header.value)
            if not match:
                continue
            value = float(match.group(1))
            unit = (match.group(2) or ("s" if name == "x-runtime" else "ms")).lower()
            timings[header.name] = value if unit == "ms" else value * 1000
    return timings


_JSESSIONID_ROUTE_RE = re.compile(
    r"JSESSIONID=[^;,\s.]+\.([A-Za-z0-9_-]{1,64})(?=[;,\s]|$)", re.IGNORECASE
)
_ROUTEID_RE = re.compile(r"ROUTEID=\.?([A-Za-z0-9_-]{1,64})(?=[;,\s]|$)", re.IGNORECASE)

_CORRELATION_HEADER_RE = re.compile(
    r"^(x-[a-z0-9-]*(request|correlation|trace)-?id|traceparent|request-id|x-amzn-trace-id)$"
)


def correlation_headers(entry: HarEntry) -> dict[str, str]:
    """Return allowlisted correlation-ID headers from the request and response."""
    found: dict[str, str] = {}
    for header in [*entry.request.headers, *entry.response.headers]:
        if _CORRELATION_HEADER_RE.match(header.name.lower()):
            found[header.name.lower()] = header.value
    return found


def entry_end_time(entry: HarEntry) -> datetime:
    """Return when the request finished (start + total time)."""
    return entry.started_date_time + timedelta(milliseconds=max(entry.time, 0.0))


def percentile_sorted(sorted_values: list[float], pct: float) -> float:
    """Linear-interpolated percentile of a pre-sorted list (same method as gc-analyze)."""
    if not sorted_values:
        return 0.0
    rank = (len(sorted_values) - 1) * (pct / 100)
    lower_index = int(rank)
    fraction = rank - lower_index
    if lower_index + 1 < len(sorted_values):
        lower = sorted_values[lower_index]
        return lower + fraction * (sorted_values[lower_index + 1] - lower)
    return sorted_values[lower_index]


MIN_SAMPLES_FOR_TAIL_PERCENTILES = 20
MIN_SAMPLES_FOR_P99 = 100
OUTAGE_MIN_FAILURES = 3  # fewer failures than this is a one-off, not an outage

HTTP_STATUS_SWITCHING_PROTOCOLS = 101
HTTP_STATUS_OK = 200
LONG_LIVED_RESOURCE_TYPES = frozenset({"websocket", "eventsource"})


def response_header(entry: HarEntry, name: str) -> str | None:
    """Return the first response header called ``name`` (case-insensitive), or None."""
    name_lower = name.lower()
    for header in entry.response.headers:
        if header.name.lower() == name_lower:
            return header.value
    return None


def response_content_type(entry: HarEntry) -> str:
    """Content-Type header, else ``content.mimeType``, lower-cased ("" when unknown)."""
    value = response_header(entry, "content-type")
    if not value and entry.response.content:
        value = entry.response.content.mime_type
    return (value or "").lower().strip()


def long_lived_kind(entry: HarEntry) -> str | None:
    """Return ``websocket`` / ``event-stream`` for connections that stay open by design.

    Their duration is the lifetime of the connection, not a response time, so they are
    kept out of latency statistics and duration rules. A failed handshake (any other
    status) is an ordinary request.
    """
    resource_type = (entry.resource_type or "").lower()
    status = entry.response.status
    is_websocket = (
        resource_type == "websocket"
        or urlsplit(entry.request.url).scheme.lower() in ("ws", "wss")
        or status == HTTP_STATUS_SWITCHING_PROTOCOLS
    )
    if is_websocket and status == HTTP_STATUS_SWITCHING_PROTOCOLS:
        return "websocket"
    is_event_stream = resource_type == "eventsource" or response_content_type(entry).startswith(
        "text/event-stream"
    )
    if is_event_stream and status == HTTP_STATUS_OK:
        return "event-stream"
    return None


def request_active_ms(entry: HarEntry) -> float:
    """Total time minus time queued in the browser before the request was sent.

    A proxy or server timeout runs from when the request reaches it, so queueing
    (``blocked``) must be removed before comparing durations with timeout settings.
    """
    return max(entry.time - max(entry.timings.blocked, 0.0), 0.0)


def response_uncompressed_bytes(entry: HarEntry) -> int:
    """Body size after decoding (``content.size``), falling back to the wire size."""
    content = entry.response.content
    if content and content.size > 0:
        return content.size
    return max(entry.response.body_size, 0)


def tail_label(stats: TimingStatistics) -> str:
    """``p95`` when there are enough samples, otherwise ``max``."""
    return "p95" if stats.count >= MIN_SAMPLES_FOR_TAIL_PERCENTILES else "max"


def tail_value(stats: TimingStatistics) -> float:
    """p95 when n >= 20; with fewer samples p95 is meaningless, so use max."""
    return stats.p95 if stats.count >= MIN_SAMPLES_FOR_TAIL_PERCENTILES else stats.max


# =============================================================================
# Config Facts (from ``sas-casefile config``)
# =============================================================================


class ConfigFact(BaseModel):
    """One configuration setting as written by ``sas-casefile config extract``."""

    component: str = ""
    instance: str | None = None
    file: str | None = None
    line: int | None = None
    path: str | None = None
    key: str
    value: str | None = None
    value_num: float | None = None
    unit: str | None = None


# Unit of a bare number, by component and key (checked against each product's
# documentation). A timeout whose unit is not known here is never matched: a guessed
# unit would name the wrong setting.
_UNIT_TO_SECONDS = {
    "ms": 0.001,
    "msec": 0.001,
    "milliseconds": 0.001,
    "s": 1.0,
    "sec": 1.0,
    "seconds": 1.0,
    "m": 60.0,
    "min": 60.0,
    "minutes": 60.0,
    "h": 3600.0,
    "hours": 3600.0,
}
_HTTPD_SECONDS_KEYS = frozenset(
    {"timeout", "proxytimeout", "keepalivetimeout", "connectiontimeout", "ttl", "retry"}
)
_MOD_JK_SECONDS_KEYS = frozenset({"socket_timeout", "connection_pool_timeout"})
_MOD_JK_MILLISECOND_KEYS = frozenset(
    {
        "reply_timeout",
        "connect_timeout",
        "prepost_timeout",
        "ping_timeout",
        "socket_connect_timeout",
    }
)
_TOMCAT_MILLISECOND_KEYS = frozenset(
    {"connectiontimeout", "keepalivetimeout", "asynctimeout", "connectionuploadtimeout"}
)
_TOMCAT_MINUTES_KEYS = frozenset({"session-timeout"})
_VALUE_WITH_UNIT_RE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([a-zA-Z]*)\s*$")


def _default_timeout_unit(component: str, key: str) -> str | None:  # noqa: PLR0911
    """Unit of a bare timeout number for ``component``/``key``; None when not known."""
    key_name = re.split(r"[./\s]", key)[-1] if component != "haproxy" else key
    if key_name.endswith("millis"):
        return "ms"
    if component in ("httpd", "apache"):
        return "s" if key_name in _HTTPD_SECONDS_KEYS else None
    if component == "nginx":
        return "s" if key_name.endswith("_timeout") else None
    if component in ("mod_jk", "jk"):
        if key_name in _MOD_JK_SECONDS_KEYS:
            return "s"
        return "ms" if key_name in _MOD_JK_MILLISECOND_KEYS else None
    if component == "tomcat":
        if key_name in _TOMCAT_MINUTES_KEYS:
            return "min"
        return "ms" if key_name in _TOMCAT_MILLISECOND_KEYS else None
    if component == "haproxy":
        return "ms" if key_name.startswith("timeout") else None
    return None


def timeout_fact_seconds(fact: ConfigFact) -> float | None:
    """Return the fact's timeout in seconds, or None if it is not a usable timeout.

    The unit comes from the fact (``unit`` or a suffix on the value), else from the
    per-product table. Unknown units give None rather than a guess.
    """
    key_lower = fact.key.lower()
    if "timeout" not in key_lower and not key_lower.endswith("millis"):
        return None
    number = fact.value_num
    unit = (fact.unit or "").lower()
    if fact.value is not None:
        match = _VALUE_WITH_UNIT_RE.match(fact.value)
        if match:
            number = float(match.group(1)) if number is None else number
            unit = unit or match.group(2).lower()
    if number is None:
        return None
    if not unit:
        unit = _default_timeout_unit(fact.component.lower(), key_lower) or ""
    factor = _UNIT_TO_SECONDS.get(unit)
    return number * factor if factor is not None else None


def describe_fact(fact: ConfigFact) -> str:
    """Return ``component key=value (instance, file:line)`` for display."""
    location_parts = [part for part in (fact.instance, fact.file) if part]
    location = ", ".join(location_parts)
    if fact.line is not None and fact.file:
        location += f":{fact.line}"
    suffix = f" ({location})" if location else ""
    return f"{fact.component} {fact.key}={fact.value}{suffix}".strip()


def load_config_facts(path: Path) -> list[ConfigFact]:
    """Load facts from a JSON list, ``{"facts": [...]}``, or JSON Lines file."""
    text = path.read_text(encoding="utf-8")
    raw_facts: list[Any]
    try:
        loaded: Any = json.loads(text)
    except json.JSONDecodeError:
        raw_facts = [json.loads(line) for line in text.splitlines() if line.strip()]
    else:
        if isinstance(loaded, list):
            raw_facts = list(loaded)  # pyright: ignore[reportUnknownArgumentType]
        elif isinstance(loaded, dict) and "facts" in loaded:
            raw_facts = list(loaded["facts"])  # pyright: ignore[reportUnknownArgumentType]
        else:
            raw_facts = [loaded]
    return [ConfigFact.model_validate(raw) for raw in raw_facts]


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
    dominant_bottleneck: str = ""  # "wait", "network", "client", or "" when no timings
    expected_count: int = 0  # responses matching expected rules (not counted as failures)
    aborted_count: int = 0  # informational network errors (aborted / blocked by client)
    server_error_count: int = 0  # 5xx responses not matching an expected rule
    network_error_count: int = 0  # real network failures
    # Median TCP connect time for new connections: about one network round trip.
    round_trip_estimate_ms: float | None = None
    round_trip_sample_count: int = 0


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
    first_seen: datetime
    last_seen: datetime
    examples: list[str] = Field(default_factory=list)  # concrete URLs behind the template
    server_timings: dict[str, TimingStatistics] = Field(default_factory=dict)


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
    aborted_count: int = 0
    expected_count: int = 0
    # Requests with an error outcome or over the duration threshold, each counted once.
    problem_count: int = 0

    @property
    def problem_rate(self) -> float:
        """Fraction of requests that had any problem (0.0 to 1.0)."""
        if self.request_count == 0:
            return 0.0
        return self.problem_count / self.request_count

    @property
    def is_outage(self) -> bool:
        """No success and enough 5xx / network failures to rule out a one-off."""
        failures = self.network_error_count + self.status_5xx_count
        return self.success_count == 0 and failures >= OUTAGE_MIN_FAILURES

    @property
    def is_always_rejected(self) -> bool:
        """Every answer was a 4xx (and there were several): a request the server refuses."""
        return (
            self.success_count == 0
            and self.network_error_count + self.status_5xx_count == 0
            and self.status_4xx_count >= OUTAGE_MIN_FAILURES
        )


class LargeRequestBody(BaseModel):
    """Large POST/PUT request payload (>100KB)."""

    url: str
    method: str
    body_size_bytes: int
    content_type: str
    timestamp: datetime


class TimeGap(BaseModel):
    """Idle period with no request in flight, longer than the idle-gap threshold."""

    gap_duration_ms: float
    before_url: str
    after_url: str
    before_timestamp: datetime
    after_timestamp: datetime


class ConnectionReuseStats(BaseModel):
    """Connection ID statistics across the capture."""

    total_requests: int
    unique_connections: int
    reuse_ratio: float  # requests per connection (higher = better)


class HostConnectionStats(BaseModel):
    """How many requests to one host had to open a new connection."""

    domain: str
    network_request_count: int  # requests answered over the network with timings
    new_connection_count: int  # of those, requests that spent time connecting
    connection_close_count: int  # responses carrying ``Connection: close``

    @property
    def new_connection_ratio(self) -> float:
        """Fraction of requests that opened a new connection (0.0 to 1.0)."""
        if self.network_request_count == 0:
            return 0.0
        return self.new_connection_count / self.network_request_count


class PhaseBreakdown(BaseModel):
    """Time breakdown by request phase."""

    phase_name: str
    total_ms: float
    percentage_of_total: float


class CompressionAnalysis(BaseModel):
    """Compression analysis results."""

    encoding_distribution: dict[str, int]  # e.g. {"gzip": 50, "br": 20, "none": 30}
    compressible_uncompressed_count: int
    compressible_uncompressed_bytes: int
    total_responses_analyzed: int


class CacheAnalysis(BaseModel):
    """Cache analysis over GET requests answered 200 or 304."""

    cacheable_get_count: int  # browser cache hits + 304s + network 200s
    not_modified_count: int = 0  # 304 responses
    browser_cache_hit_count: int = 0  # served from memory/disk cache
    network_download_count: int = 0  # 200 responses fetched over the network
    repeated_download_request_count: int = 0  # network 200s for a URL fetched 2+ times
    repeated_downloads: list[dict[str, Any]]  # [{url, count, total_bytes}]
    missing_cache_control_count: int
    served_without_download_ratio: float  # (cache hits + 304s) / cacheable GETs


class ErrorBurst(BaseModel):
    """A run of errors, each starting within the window of the previous one."""

    start_time: datetime
    end_time: datetime
    error_count: int
    affected_domains: list[str]


class RequestRateStats(BaseModel):
    """Request rate statistics."""

    overall_requests_per_second: float
    peak_requests_per_second: float


class KeyFinding(BaseModel):
    """A synthesized key finding from the analysis."""

    category: str  # "outage", "bottleneck", "protocol", "dns", "compression", etc.
    severity: IssueSeverity
    summary: str
    recommendation: str
    frontend: bool = False  # generic front-end advice, shown in an informational section


class RequestSummary(BaseModel):
    """One request with its phase split (for the slowest-requests list)."""

    url: str
    method: str
    status: int
    started: datetime
    total_ms: float
    blocked_ms: float
    dns_ms: float
    connect_excl_tls_ms: float
    tls_ms: float
    send_ms: float
    wait_ms: float
    receive_ms: float
    error_category: str | None = None
    correlation: dict[str, str] = Field(default_factory=dict)


class TimeoutCluster(BaseModel):
    """Failed requests whose durations bunch up at a round value (likely a timeout).

    Durations are measured from when the request was sent (total minus browser
    queueing), which is what a proxy or server timeout sees.
    """

    kind: str  # "gateway" (5xx), "network" (no response), "client_cancel" (all aborted)
    max_queued_ms: float = 0.0  # longest browser queueing among the members
    request_count: int
    min_ms: float
    max_ms: float
    median_ms: float
    round_value_s: float
    status_codes: dict[int, int]
    endpoints: dict[str, int]  # endpoint template -> count
    first_seen: datetime
    last_seen: datetime
    matching_settings: list[str] = Field(default_factory=list)


class LongLivedConnection(BaseModel):
    """A WebSocket or event stream: open by design, so not a slow request."""

    kind: str  # "websocket" or "event-stream"
    url: str
    status: int
    started: datetime
    duration_ms: float


class LatencyPopulation(BaseModel):
    """Which requests the latency percentiles cover, and what was left out."""

    measured_count: int  # answered over the network
    browser_cache_hit_count: int
    aborted_count: int
    network_error_count: int


class ErrorOrigin(BaseModel):
    """Headers on one host's 5xx responses next to its successful responses."""

    domain: str
    status: int
    count: int
    median_active_ms: float  # median time since the request was sent
    error_servers: dict[str, int]  # Server header value ("(none)" when absent) -> count
    success_servers: dict[str, int]
    error_content_types: dict[str, int]
    via_count: int  # error responses carrying a Via header
    reading: str  # what the header comparison is consistent with
    status_hint: str  # what this status at this duration is consistent with


class HostClockOffset(BaseModel):
    """Server ``Date`` header minus the browser's clock, per host."""

    domain: str
    median_seconds: float
    sample_count: int


class BackendNodeStats(BaseModel):
    """Requests per backend node (jvmRoute / ROUTEID / X-Served-By)."""

    domain: str
    node: str
    source: str  # where the node name came from
    request_count: int
    server_error_count: int
    network_error_count: int
    timings: TimingStatistics


class HarAnalysisReport(BaseModel):
    """Complete analysis report."""

    total_requests: int
    total_duration_ms: float
    total_bytes_transferred: int
    overall_timings: TimingStatistics
    blocked_timings: TimingStatistics
    dns_timings: TimingStatistics
    connect_timings: TimingStatistics
    ssl_timings: TimingStatistics
    send_timings: TimingStatistics
    ttfb_timings: TimingStatistics
    receive_timings: TimingStatistics
    status_codes: dict[int, int]
    endpoints: list[EndpointStats]
    issues: list[DetectedIssue]
    domains: list[DomainAnalysis] = []
    service_failures: list[ServiceFailureStats] = []
    referer_hostnames: dict[str, int] = Field(default_factory=dict)
    # Infrastructure diagnostic fields
    server_ips_by_domain: dict[str, list[str]] = Field(default_factory=dict)
    http_version_distribution: dict[str, int] = Field(default_factory=dict)
    large_request_bodies: list[LargeRequestBody] = Field(default_factory=list)
    connection_reuse_stats: ConnectionReuseStats | None = None
    time_gaps: list[TimeGap] = Field(default_factory=list)
    server_software_by_domain: dict[str, dict[str, int]] = Field(default_factory=dict)
    capture_start: datetime | None = None
    capture_end: datetime | None = None
    phase_breakdown: list[PhaseBreakdown] = Field(default_factory=list)
    compression_analysis: CompressionAnalysis | None = None
    cache_analysis: CacheAnalysis | None = None
    error_bursts: list[ErrorBurst] = Field(default_factory=list)
    request_rate_stats: RequestRateStats | None = None
    key_findings: list[KeyFinding] = Field(default_factory=list)
    settings: AnalyzerSettings = Field(default_factory=AnalyzerSettings)
    timeout_clusters: list[TimeoutCluster] = Field(default_factory=list)
    network_errors_by_category: dict[str, int] = Field(default_factory=dict)
    aborted_request_count: int = 0  # informational network errors
    expected_response_count: int = 0
    config_facts_loaded: int = 0
    slowest_requests: list[RequestSummary] = Field(default_factory=list)
    capture_tool: str = ""  # log.creator / log.browser
    load_notes: HarLoadNotes = Field(default_factory=HarLoadNotes)
    assumed_utc_timestamp_count: int = 0
    long_lived_connections: list[LongLivedConnection] = Field(default_factory=list)
    latency_population: LatencyPopulation | None = None
    host_connection_stats: list[HostConnectionStats] = Field(default_factory=list)
    error_origins: list[ErrorOrigin] = Field(default_factory=list)
    clock_offsets: list[HostClockOffset] = Field(default_factory=list)
    backend_nodes: list[BackendNodeStats] = Field(default_factory=list)


# =============================================================================
# HAR Analyzer
# =============================================================================


class HarAnalyzer:
    """Extract metrics and detect issues from HAR data."""

    HTTP_STATUS_CLIENT_ERROR_MIN = 400
    HTTP_STATUS_UNAUTHORIZED = 401
    HTTP_STATUS_FORBIDDEN = 403
    HTTP_STATUS_RATE_LIMITED = 429
    HTTP_STATUS_SERVER_ERROR_MIN = 500
    HTTP_STATUS_ERROR_MAX = 600
    REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

    DOMAIN_ERROR_RATE_CRITICAL_PCT = 50.0
    DOMAIN_ERROR_RATE_DEGRADED_PCT = 10.0
    DOMAIN_CRITICAL_MIN_PROBLEMS = 2  # one failed request never makes a domain CRITICAL

    MIN_ENTRIES_FOR_GAP_ANALYSIS = 2
    CONNECTION_ID_MIN_COVERAGE = 0.8  # fraction of entries that must have a connection ID
    ENDPOINT_EXAMPLE_LIMIT = 3

    # Network error categories that are well understood (CRITICAL); "no_response" and
    # "other" are real but ambiguous (HIGH).
    WELL_KNOWN_NETWORK_ERRORS = frozenset(
        {
            "connection_reset",
            "connection_refused",
            "timed_out",
            "dns",
            "tls",
            "empty_response",
            "truncated_response",
            "proxy_tunnel",
        }
    )

    def __init__(
        self,
        settings: AnalyzerSettings | None = None,
        config_facts: list[ConfigFact] | None = None,
    ) -> None:
        """Create an analyzer; raises ValueError for malformed rules in ``settings``."""
        self.settings = settings or AnalyzerSettings()
        self.expected_rules = tuple(ExpectedRule.parse(r) for r in self.settings.expected_rules)
        self.path_rules = tuple(PathTemplateRule.parse(r) for r in self.settings.path_rules)
        self.config_facts = list(config_facts or [])

    # -------------------------------------------------------------------------
    # Per-entry classification
    # -------------------------------------------------------------------------

    def is_expected(self, entry: HarEntry) -> bool:
        """Return True when the response matches an expected rule (e.g. SAS Logon 401)."""
        path = urlparse(entry.request.url).path or "/"
        return any(rule.matches(entry.response.status, path) for rule in self.expected_rules)

    def outcome(self, entry: HarEntry) -> RequestOutcome:
        """Classify a request into exactly one outcome; a network error wins over status."""
        category = classify_network_error(entry)
        if category in INFORMATIONAL_ERROR_CATEGORIES:
            return RequestOutcome.ABORTED
        if category is not None:
            return RequestOutcome.NETWORK_ERROR
        if self.is_expected(entry):
            return RequestOutcome.EXPECTED
        status = entry.response.status
        if status < self.HTTP_STATUS_CLIENT_ERROR_MIN:
            return RequestOutcome.SUCCESS
        if status < self.HTTP_STATUS_SERVER_ERROR_MIN:
            return RequestOutcome.CLIENT_ERROR
        return RequestOutcome.SERVER_ERROR

    def is_problem(self, entry: HarEntry) -> bool:
        """Return True for real failures: network errors, non-expected 4xx/5xx."""
        return self.outcome(entry) in PROBLEM_OUTCOMES

    def is_latency_sample(self, entry: HarEntry) -> bool:
        """Return True when the request was answered over the network.

        Browser-cache hits (about 0 ms) and requests that never got a response would
        distort latency percentiles, so those are counted separately.
        """
        return classify_network_error(entry) is None and not self.is_browser_cache_hit(entry)

    def path_template(self, url: str) -> str:
        """Return the URL path with ID-like segments templated."""
        return template_path(urlparse(url).path or "/", self.path_rules)

    def endpoint_key(self, url: str) -> str:
        """Return ``scheme://host/templated/path`` used to group requests."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{self.path_template(url)}"

    @staticmethod
    def transferred_bytes(entry: HarEntry) -> int:
        """Bytes that crossed the network (0 for browser-cache hits)."""
        if entry.from_cache:
            return 0
        transfer_size = entry.response.transfer_size
        if transfer_size is not None and transfer_size >= 0:
            return transfer_size
        return max(entry.response.body_size, 0)

    @staticmethod
    def is_browser_cache_hit(entry: HarEntry) -> bool:
        """Return True when the browser served the response from memory/disk cache.

        Signals: Chrome's ``_fromCache``, the standard ``cache.beforeRequest`` (Firefox),
        or a 200 with ``_transferSize`` 0.
        """
        if entry.from_cache:
            return True
        if entry.cache is not None and entry.cache.before_request is not None:
            return True
        return (
            entry.response.status == HTTP_STATUS_OK
            and entry.response.transfer_size == 0
            and not entry.response.error
        )

    # -------------------------------------------------------------------------
    # Main analysis
    # -------------------------------------------------------------------------

    def analyze(self, har: Har) -> HarAnalysisReport:
        """Perform comprehensive analysis of HAR data.

        WebSocket / event-stream connections are listed separately and excluded from
        every count and statistic below. Latency statistics cover requests answered
        over the network (see ``is_latency_sample``).
        """
        entries = [e for e in har.log.entries if long_lived_kind(e) is None]
        measured = [e for e in entries if self.is_latency_sample(e)]
        logger.info(f"Analyzing {len(entries)} entries")

        phase_stats = self._phase_stats(measured)
        status_codes: dict[int, int] = defaultdict(int)
        network_errors_by_category: dict[str, int] = defaultdict(int)
        aborted_request_count = 0
        for entry in entries:
            status_codes[entry.response.status] += 1
            category = classify_network_error(entry)
            if category in INFORMATIONAL_ERROR_CATEGORIES:
                aborted_request_count += 1
            elif category is not None:
                network_errors_by_category[category] += 1

        # Capture window: first request start to last request end (start + time)
        capture_start = min((e.started_date_time for e in entries), default=None)
        capture_end = max((entry_end_time(e) for e in entries), default=None)

        endpoints = self._aggregate_by_endpoint(entries)
        issues = self._detect_issues(entries, endpoints, capture_end)
        creators = [c for c in (har.log.creator, har.log.browser) if c and c.name]

        report = HarAnalysisReport(
            total_requests=len(entries),
            total_duration_ms=sum(e.time for e in entries),
            total_bytes_transferred=sum(self.transferred_bytes(e) for e in entries),
            overall_timings=self._compute_timing_stats([e.time for e in measured]),
            blocked_timings=phase_stats["Blocked"],
            dns_timings=phase_stats["DNS"],
            connect_timings=phase_stats["Connect (excl. TLS)"],
            ssl_timings=phase_stats["SSL"],
            send_timings=phase_stats["Send"],
            ttfb_timings=phase_stats["TTFB"],
            receive_timings=phase_stats["Receive"],
            status_codes=dict(status_codes),
            endpoints=endpoints,
            issues=issues,
            domains=self._analyze_by_domain(entries, issues),
            service_failures=self._compute_service_failures(entries),
            referer_hostnames=self._compute_referer_hostnames(entries),
            server_ips_by_domain=self._compute_server_ips_by_domain(entries),
            http_version_distribution=self._compute_http_version_distribution(entries),
            large_request_bodies=self._compute_large_request_bodies(entries),
            connection_reuse_stats=self._compute_connection_reuse_stats(entries),
            time_gaps=self._compute_time_gaps(entries),
            server_software_by_domain=self._extract_server_software_by_domain(entries),
            capture_start=capture_start,
            capture_end=capture_end,
            phase_breakdown=self._compute_phase_breakdown(phase_stats),
            compression_analysis=self._analyze_compression(entries),
            cache_analysis=self._analyze_caching(entries),
            error_bursts=self._detect_error_bursts(issues),
            request_rate_stats=self._compute_request_rate(entries, capture_start, capture_end),
            settings=self.settings,
            timeout_clusters=self._detect_timeout_clusters(entries),
            network_errors_by_category=dict(
                sorted(network_errors_by_category.items(), key=lambda kv: (-kv[1], kv[0]))
            ),
            aborted_request_count=aborted_request_count,
            expected_response_count=sum(
                1 for e in entries if self.outcome(e) == RequestOutcome.EXPECTED
            ),
            config_facts_loaded=len(self.config_facts),
            slowest_requests=self._slowest_requests(entries),
            capture_tool=", ".join(f"{c.name} {c.version}".strip() for c in creators),
            load_notes=har.load_notes,
            assumed_utc_timestamp_count=sum(1 for e in entries if e.timestamp_assumed_utc),
            long_lived_connections=self._long_lived_connections(har.log.entries),
            latency_population=LatencyPopulation(
                measured_count=len(measured),
                browser_cache_hit_count=sum(
                    1
                    for e in entries
                    if classify_network_error(e) is None and self.is_browser_cache_hit(e)
                ),
                aborted_count=aborted_request_count,
                network_error_count=sum(network_errors_by_category.values()),
            ),
            host_connection_stats=self._host_connection_stats(measured),
            error_origins=self._error_origins(entries),
            clock_offsets=self._clock_offsets(measured),
            backend_nodes=self._backend_nodes(entries),
        )
        report.key_findings = self._generate_key_findings(report)
        return report

    def _phase_stats(self, measured: list[HarEntry]) -> dict[str, TimingStatistics]:
        """Per-phase statistics over recorded (>= 0) values of network-answered requests."""

        def stats(values: list[float]) -> TimingStatistics:
            return self._compute_timing_stats([value for value in values if value >= 0])

        return {
            "Blocked": stats([e.timings.blocked for e in measured]),
            "DNS": stats([e.timings.dns for e in measured]),
            "Connect (excl. TLS)": stats([e.timings.connect_excluding_ssl for e in measured]),
            "SSL": stats([e.timings.ssl for e in measured]),
            "Send": stats([e.timings.send for e in measured]),
            "TTFB": stats([e.timings.wait for e in measured]),
            "Receive": stats([e.timings.receive for e in measured]),
        }

    @staticmethod
    def _long_lived_connections(entries: list[HarEntry]) -> list[LongLivedConnection]:
        """WebSocket and event-stream connections, longest first."""
        connections = [
            LongLivedConnection(
                kind=kind,
                url=e.request.url,
                status=e.response.status,
                started=e.started_date_time,
                duration_ms=e.time,
            )
            for e in entries
            if (kind := long_lived_kind(e)) is not None
        ]
        return sorted(connections, key=lambda c: (-c.duration_ms, c.started))

    SLOWEST_REQUESTS_LIMIT = 10

    def _slowest_requests(self, entries: list[HarEntry]) -> list[RequestSummary]:
        """The slowest individual requests with their phase split (-1 = not recorded)."""
        slowest = sorted(entries, key=lambda e: (-e.time, e.started_date_time))
        return [
            RequestSummary(
                url=e.request.url,
                method=e.request.method,
                status=e.response.status,
                started=e.started_date_time,
                total_ms=e.time,
                blocked_ms=e.timings.blocked,
                dns_ms=e.timings.dns,
                connect_excl_tls_ms=e.timings.connect_excluding_ssl,
                tls_ms=e.timings.ssl,
                send_ms=e.timings.send,
                wait_ms=e.timings.wait,
                receive_ms=e.timings.receive,
                error_category=classify_network_error(e),
                correlation=correlation_headers(e),
            )
            for e in slowest[: self.SLOWEST_REQUESTS_LIMIT]
        ]

    @staticmethod
    def _compute_phase_breakdown(
        phase_stats: dict[str, TimingStatistics],
    ) -> list[PhaseBreakdown]:
        """Share of summed phase time per phase (connect excludes TLS, so no double count)."""
        phase_totals = {name: stats.total_duration_ms for name, stats in phase_stats.items()}
        grand_total = sum(phase_totals.values())
        breakdown = [
            PhaseBreakdown(
                phase_name=name,
                total_ms=total_ms,
                percentage_of_total=(total_ms / grand_total * 100) if grand_total else 0,
            )
            for name, total_ms in phase_totals.items()
        ]
        breakdown.sort(key=lambda p: -p.percentage_of_total)
        return breakdown

    def _analyze_by_domain(
        self, entries: list[HarEntry], issues: list[DetectedIssue]
    ) -> list[DomainAnalysis]:
        """Analyze metrics grouped by domain.

        Health uses real problems only (network errors that are not aborts, and 4xx/5xx
        that do not match an expected rule). Any 5xx or network failure makes a domain at
        least DEGRADED, whatever the rate.
        """
        by_domain: dict[str, list[HarEntry]] = defaultdict(list)
        for entry in entries:
            by_domain[urlparse(entry.request.url).netloc].append(entry)

        issue_counts: dict[str, int] = defaultdict(int)
        for issue in issues:
            issue_counts[issue.domain] += 1

        domain_analyses: list[DomainAnalysis] = []
        for domain, domain_entries in by_domain.items():
            outcomes: dict[RequestOutcome, int] = defaultdict(int)
            status_dist: dict[int, int] = defaultdict(int)
            for e in domain_entries:
                outcomes[self.outcome(e)] += 1
                status_dist[e.response.status] += 1
            problems = sum(outcomes[outcome] for outcome in PROBLEM_OUTCOMES)
            total = len(domain_entries)
            error_rate = problems / total * 100
            server_errors = outcomes[RequestOutcome.SERVER_ERROR]
            network_errors = outcomes[RequestOutcome.NETWORK_ERROR]

            if (
                error_rate >= self.DOMAIN_ERROR_RATE_CRITICAL_PCT
                and problems >= self.DOMAIN_CRITICAL_MIN_PROBLEMS
            ):
                health = DomainHealth.CRITICAL
            elif (
                server_errors
                or network_errors
                or (problems and error_rate >= self.DOMAIN_ERROR_RATE_DEGRADED_PCT)
            ):
                health = DomainHealth.DEGRADED
            else:
                health = DomainHealth.HEALTHY

            measured = [e for e in domain_entries if self.is_latency_sample(e)]
            new_connection_times = sorted(
                e.timings.connect_excluding_ssl
                for e in measured
                if e.timings.connect_excluding_ssl > 0
            )
            domain_analyses.append(
                DomainAnalysis(
                    domain=domain,
                    total_requests=total,
                    failed_requests=problems,
                    error_rate=error_rate,
                    timing_stats=self._compute_timing_stats([e.time for e in measured]),
                    status_codes=dict(status_dist),
                    issue_count=issue_counts.get(domain, 0),
                    health=health,
                    dominant_bottleneck=self._dominant_bottleneck(measured),
                    expected_count=outcomes[RequestOutcome.EXPECTED],
                    aborted_count=outcomes[RequestOutcome.ABORTED],
                    server_error_count=server_errors,
                    network_error_count=network_errors,
                    round_trip_estimate_ms=(
                        percentile_sorted(new_connection_times, 50)
                        if new_connection_times
                        else None
                    ),
                    round_trip_sample_count=len(new_connection_times),
                )
            )

        health_order = {
            DomainHealth.CRITICAL: 0,
            DomainHealth.DEGRADED: 1,
            DomainHealth.HEALTHY: 2,
        }
        return sorted(
            domain_analyses,
            key=lambda d: (health_order[d.health], -d.error_rate, d.domain),
        )

    @staticmethod
    def _dominant_bottleneck(measured: list[HarEntry]) -> str:
        """Where a host's summed request time went: ``wait``, ``network`` or ``client``.

        ``wait`` is time to first byte: network round trip + every proxy hop + the
        application. Returns "" when no phase time was recorded.
        """

        def recorded(value: float) -> float:
            return max(value, 0.0)

        totals = {
            "wait": sum(recorded(e.timings.wait) for e in measured),
            "network": sum(
                recorded(e.timings.dns)
                + recorded(e.timings.connect_excluding_ssl)
                + recorded(e.timings.ssl)
                + recorded(e.timings.receive)
                for e in measured
            ),
            "client": sum(recorded(e.timings.blocked) + recorded(e.timings.send) for e in measured),
        }
        dominant = max(totals, key=lambda name: totals[name])
        return dominant if totals[dominant] > 0 else ""

    def _compute_timing_stats(self, values: list[float]) -> TimingStatistics:
        """Compute interpolated percentile statistics."""
        if not values:
            return TimingStatistics(
                count=0, p50=0, p95=0, p99=0, max=0, mean=0, total_duration_ms=0
            )

        sorted_values = sorted(values)
        return TimingStatistics(
            count=len(sorted_values),
            p50=percentile_sorted(sorted_values, 50),
            p95=percentile_sorted(sorted_values, 95),
            p99=percentile_sorted(sorted_values, 99),
            max=sorted_values[-1],
            mean=statistics.mean(values),
            total_duration_ms=sum(values),
        )

    @staticmethod
    def _network_total(entry: HarEntry) -> float | None:
        """DNS + connect (excl. TLS) + TLS + receive, or None when no phase is known."""
        timings = entry.timings
        parts = (timings.dns, timings.connect_excluding_ssl, timings.ssl, timings.receive)
        if all(part < 0 for part in parts):
            return None
        return sum(part for part in parts if part >= 0)

    def _aggregate_by_endpoint(self, entries: list[HarEntry]) -> list[EndpointStats]:
        """Group requests by endpoint template (host + path with IDs templated).

        ``count`` and ``status_codes`` cover every request; timing statistics cover the
        requests answered over the network.
        """
        by_pattern: dict[str, list[HarEntry]] = defaultdict(list)
        for entry in entries:
            by_pattern[self.endpoint_key(entry.request.url)].append(entry)

        def stats(values: list[float]) -> TimingStatistics:
            return self._compute_timing_stats([value for value in values if value >= 0])

        endpoints: list[EndpointStats] = []
        for pattern, reqs in by_pattern.items():
            status_dist: dict[int, int] = defaultdict(int)
            for req in reqs:
                status_dist[req.response.status] += 1

            examples: list[str] = []
            for req in reqs:
                if req.request.url not in examples:
                    examples.append(req.request.url)
                if len(examples) >= self.ENDPOINT_EXAMPLE_LIMIT:
                    break

            measured = [r for r in reqs if self.is_latency_sample(r)]
            server_timing_values: dict[str, list[float]] = defaultdict(list)
            for req in measured:
                for metric, value_ms in parse_server_timings(req.response.headers).items():
                    server_timing_values[metric].append(value_ms)

            endpoints.append(
                EndpointStats(
                    url_pattern=pattern,
                    count=len(reqs),
                    timings=self._compute_timing_stats([r.time for r in measured]),
                    blocked_timings=stats([r.timings.blocked for r in measured]),
                    dns_timings=stats([r.timings.dns for r in measured]),
                    connect_timings=stats([r.timings.connect_excluding_ssl for r in measured]),
                    ssl_timings=stats([r.timings.ssl for r in measured]),
                    send_timings=stats([r.timings.send for r in measured]),
                    ttfb_timings=stats([r.timings.wait for r in measured]),
                    receive_timings=stats([r.timings.receive for r in measured]),
                    client_total_timings=self._compute_timing_stats(
                        [
                            max(r.timings.blocked, 0.0) + max(r.timings.send, 0.0)
                            for r in measured
                            if (r.timings.blocked >= 0 or r.timings.send >= 0)
                        ]
                    ),
                    network_total_timings=self._compute_timing_stats(
                        [
                            total
                            for total in (self._network_total(r) for r in measured)
                            if total is not None
                        ]
                    ),
                    status_codes=dict(status_dist),
                    first_seen=min(r.started_date_time for r in reqs),
                    last_seen=max(r.started_date_time for r in reqs),
                    examples=examples,
                    server_timings={
                        metric: self._compute_timing_stats(values)
                        for metric, values in sorted(server_timing_values.items())
                    },
                )
            )

        return sorted(endpoints, key=lambda e: (-tail_value(e.timings), e.url_pattern))

    # -------------------------------------------------------------------------
    # Issue detection
    # -------------------------------------------------------------------------

    def _detect_issues(
        self,
        entries: list[HarEntry],
        endpoints: list[EndpointStats],
        capture_end: datetime | None,
    ) -> list[DetectedIssue]:
        """Run deterministic issue detection based on HAR contents."""
        issues: list[DetectedIssue] = []
        issues.extend(self._detect_network_errors(entries, capture_end))
        issues.extend(self._detect_duration_exceeded(entries))
        issues.extend(self._detect_http_errors(entries))
        issues.extend(self._detect_large_payloads(entries))
        issues.extend(self._detect_slow_endpoints(endpoints))
        issues.extend(self._detect_blocking(entries))
        issues.extend(self._detect_redirects(entries))

        severity_order = {sev: idx for idx, sev in enumerate(IssueSeverity)}
        return sorted(issues, key=lambda i: (severity_order[i.severity], i.timestamp))

    # A request with no status and no error that ends this close to the end of the
    # capture may simply have been in flight when the HAR was saved.
    IN_FLIGHT_AT_CAPTURE_END_MS = 1_000

    def _detect_network_errors(
        self, entries: list[HarEntry], capture_end: datetime | None
    ) -> list[DetectedIssue]:
        """Classify network-level failures; aborted/cancelled requests are informational.

        One issue per request: when a request has both an error and an HTTP status,
        the network error is reported and carries the status.
        """
        issues: list[DetectedIssue] = []
        for entry in entries:
            category = classify_network_error(entry)
            if category is None:
                continue
            raw_error = entry.response.error or "no response (status 0, no error recorded)"
            details: dict[str, object] = {
                "method": entry.request.method,
                "status": entry.response.status,
                "error": entry.response.error,
                "error_category": category,
            }
            may_be_in_flight = (
                category == "no_response"
                and capture_end is not None
                and (capture_end - entry_end_time(entry)).total_seconds() * 1000
                <= self.IN_FLIGHT_AT_CAPTURE_END_MS
            )
            if category in INFORMATIONAL_ERROR_CATEGORIES:
                issue_type = IssueType.REQUEST_ABORTED
                severity = IssueSeverity.LOW
                message = f"Request {category.replace('_', ' ')} (informational): {raw_error}"
            elif may_be_in_flight:
                issue_type = IssueType.NETWORK_ERROR
                severity = IssueSeverity.MEDIUM
                message = (
                    "No response recorded (the request may have been in flight when the "
                    "capture was saved)"
                )
                details["may_be_in_flight_at_capture_end"] = True
            else:
                issue_type = IssueType.NETWORK_ERROR
                severity = (
                    IssueSeverity.CRITICAL
                    if category in self.WELL_KNOWN_NETWORK_ERRORS
                    else IssueSeverity.HIGH
                )
                message = f"Network error [{category}]: {raw_error}"
            issue = DetectedIssue(
                issue_type=issue_type,
                severity=severity,
                url=entry.request.url,
                message=message,
                duration_ms=entry.time,
                timestamp=entry.started_date_time,
                details=details,
                domain=urlparse(entry.request.url).netloc,
            )
            self._add_request_context(issue.details, entry)
            issues.append(issue)
        return issues

    _PHASE_DESCRIPTIONS: tuple[tuple[str, str], ...] = (
        ("blocked", "queued in the browser"),
        ("dns", "DNS lookup"),
        ("connect", "connecting"),
        ("send", "sending the request body"),
        ("wait", "waiting for the first response byte"),
        ("receive", "receiving the response body"),
    )

    def _dominant_phase(self, entry: HarEntry) -> tuple[str, float] | None:
        """Return (phase, ms) for the longest recorded phase, or None if none recorded."""
        recorded = [
            (name, value)
            for name, _ in self._PHASE_DESCRIPTIONS
            if (value := float(getattr(entry.timings, name))) >= 0
        ]
        if not recorded:
            return None
        return max(recorded, key=lambda item: item[1])

    def _detect_duration_exceeded(self, entries: list[HarEntry]) -> list[DetectedIssue]:
        """Detect requests that exceed the duration threshold.

        CRITICAL when the time went into waiting for the response (or the phase split is
        unknown); HIGH when it went into another phase, which is named.
        """
        threshold_ms = self.settings.duration_exceeded_ms
        descriptions = dict(self._PHASE_DESCRIPTIONS)
        issues: list[DetectedIssue] = []
        for entry in entries:
            if entry.time <= threshold_ms:
                continue
            dominant = self._dominant_phase(entry)
            if dominant is None:
                severity = IssueSeverity.CRITICAL
                where = "phase split not recorded"
            else:
                phase_name, phase_ms = dominant
                severity = IssueSeverity.CRITICAL if phase_name == "wait" else IssueSeverity.HIGH
                where = f"mostly {descriptions[phase_name]}: {phase_ms / 1000:.1f}s"
            issues.append(
                DetectedIssue(
                    issue_type=IssueType.DURATION_EXCEEDED,
                    severity=severity,
                    url=entry.request.url,
                    message=(
                        f"Request exceeded {threshold_ms / 1000:g}s threshold "
                        f"({entry.time / 1000:.1f}s; {where})"
                    ),
                    duration_ms=entry.time,
                    timestamp=entry.started_date_time,
                    details={
                        "method": entry.request.method,
                        "status": entry.response.status,
                        "wait_time_ms": entry.timings.wait,
                        "dominant_phase": dominant[0] if dominant else "unknown",
                        "threshold_ms": threshold_ms,
                    },
                    domain=urlparse(entry.request.url).netloc,
                )
            )
            self._add_request_context(issues[-1].details, entry)
        return issues

    def _detect_http_errors(self, entries: list[HarEntry]) -> list[DetectedIssue]:
        """Detect HTTP 4xx/5xx responses that do not match an expected rule.

        Requests that also carry a network error are reported there, not here.
        """
        issues: list[DetectedIssue] = []
        for entry in entries:
            outcome = self.outcome(entry)
            status = entry.response.status
            details: dict[str, Any] = {"status": status, "method": entry.request.method}
            if outcome == RequestOutcome.SERVER_ERROR:
                issue_type = IssueType.SERVER_ERROR
                severity = IssueSeverity.HIGH
                message = f"Server error: {status} {entry.response.status_text}".rstrip()
            elif outcome != RequestOutcome.CLIENT_ERROR:
                continue
            elif status == self.HTTP_STATUS_RATE_LIMITED:
                issue_type = IssueType.RATE_LIMITED
                severity = IssueSeverity.HIGH
                message = "Rate limited (429) — client is being throttled"
            else:
                issue_type = IssueType.CLIENT_ERROR
                severity = (
                    IssueSeverity.HIGH
                    if status in (self.HTTP_STATUS_UNAUTHORIZED, self.HTTP_STATUS_FORBIDDEN)
                    else IssueSeverity.MEDIUM
                )
                message = f"Client error: {status} {entry.response.status_text}".rstrip()
            issues.append(
                DetectedIssue(
                    issue_type=issue_type,
                    severity=severity,
                    url=entry.request.url,
                    message=message,
                    timestamp=entry.started_date_time,
                    duration_ms=entry.time,
                    details=details,
                    domain=urlparse(entry.request.url).netloc,
                )
            )
            self._add_request_context(issues[-1].details, entry)
        return issues

    def _detect_large_payloads(self, entries: list[HarEntry]) -> list[DetectedIssue]:
        """Detect large responses by uncompressed size (``content.size``, else wire size)."""
        issues: list[DetectedIssue] = []
        for entry in entries:
            uncompressed_bytes = response_uncompressed_bytes(entry)
            if uncompressed_bytes <= self.settings.large_payload_bytes:
                continue
            wire_bytes = self.transferred_bytes(entry)
            issues.append(
                DetectedIssue(
                    issue_type=IssueType.LARGE_PAYLOAD,
                    severity=IssueSeverity.MEDIUM,
                    url=entry.request.url,
                    message=f"Large payload: {uncompressed_bytes / ONE_MEGABYTE:.1f} MB",
                    size_bytes=uncompressed_bytes,
                    timestamp=entry.started_date_time,
                    details={
                        "content_type": self._get_content_type(entry),
                        "bytes_on_wire": wire_bytes,
                        "browser_cache_hit": self.is_browser_cache_hit(entry),
                    },
                    domain=urlparse(entry.request.url).netloc,
                )
            )
            self._add_request_context(issues[-1].details, entry)
        return issues

    def _detect_slow_endpoints(self, endpoints: list[EndpointStats]) -> list[DetectedIssue]:
        """Detect endpoint templates whose p95 (max when n < 20) exceeds the threshold."""
        issues: list[DetectedIssue] = []
        for endpoint in endpoints:
            value = tail_value(endpoint.timings)
            if value <= self.settings.slow_endpoint_ms:
                continue
            label = tail_label(endpoint.timings)
            issues.append(
                DetectedIssue(
                    issue_type=IssueType.SLOW_ENDPOINT,
                    severity=IssueSeverity.HIGH,
                    url=endpoint.url_pattern,
                    message=(
                        f"Slow endpoint: {label}={value:.0f}ms "
                        f"(p50={endpoint.timings.p50:.0f}ms, n={endpoint.timings.count})"
                    ),
                    duration_ms=value,
                    timestamp=endpoint.last_seen,
                    details={
                        "count": endpoint.timings.count,
                        "p50": endpoint.timings.p50,
                        label: value,
                        "first_seen": endpoint.first_seen.isoformat(),
                        "last_seen": endpoint.last_seen.isoformat(),
                    },
                    domain=urlparse(endpoint.url_pattern).netloc,
                )
            )
        return issues

    QUEUE_HOLDER_LIMIT = 3

    def _queue_holders(self, blocked_entry: HarEntry, same_host: list[HarEntry]) -> str:
        """Longest same-host requests in flight while ``blocked_entry`` was queued."""
        window_start = blocked_entry.started_date_time
        window_end = window_start + timedelta(milliseconds=blocked_entry.timings.blocked)
        holders = sorted(
            (
                e
                for e in same_host
                if e is not blocked_entry
                and e.started_date_time < window_end
                and entry_end_time(e) > window_start
            ),
            key=lambda e: (-e.time, e.started_date_time),
        )
        return "; ".join(
            f"{e.request.method} {self.path_template(e.request.url)} ({e.time / 1000:.1f}s)"
            for e in holders[: self.QUEUE_HOLDER_LIMIT]
        )

    def _detect_blocking(self, entries: list[HarEntry]) -> list[DetectedIssue]:
        """Detect requests queued in the browser, naming what was in flight meanwhile."""
        by_domain: dict[str, list[HarEntry]] = defaultdict(list)
        for entry in entries:
            by_domain[urlparse(entry.request.url).netloc].append(entry)

        issues: list[DetectedIssue] = []
        for entry in entries:
            if entry.timings.blocked <= self.settings.blocking_ms:
                continue
            domain = urlparse(entry.request.url).netloc
            details: dict[str, object] = {
                "phase": "blocked",
                "method": entry.request.method,
                "http_version": entry.request.http_version or "unknown",
            }
            holders = self._queue_holders(entry, by_domain[domain])
            if holders:
                details["in_flight_meanwhile"] = holders
            issues.append(
                DetectedIssue(
                    issue_type=IssueType.BLOCKING,
                    severity=IssueSeverity.MEDIUM,
                    url=entry.request.url,
                    message=f"Queued in the browser: {entry.timings.blocked / 1000:.1f}s",
                    duration_ms=entry.timings.blocked,
                    timestamp=entry.started_date_time,
                    details=details,
                    domain=domain,
                )
            )
            self._add_request_context(issues[-1].details, entry)
        return issues

    def _link_redirects(self, sorted_entries: list[HarEntry]) -> dict[int, HarEntry]:
        """Map each redirect entry (by id) to the request that followed its redirectURL."""
        by_url: dict[str, list[HarEntry]] = defaultdict(list)
        for entry in sorted_entries:
            by_url[entry.request.url.split("#", 1)[0]].append(entry)

        next_of: dict[int, HarEntry] = {}
        targeted: set[int] = set()
        for entry in sorted_entries:
            if (
                entry.response.status not in self.REDIRECT_STATUSES
                or not entry.response.redirect_url
            ):
                continue
            target_url = urljoin(entry.request.url, entry.response.redirect_url).split("#", 1)[0]
            for candidate in by_url.get(target_url, []):
                if (
                    candidate is not entry
                    and id(candidate) not in targeted
                    and candidate.started_date_time >= entry.started_date_time
                ):
                    next_of[id(entry)] = candidate
                    targeted.add(id(candidate))
                    break
        return next_of

    def _detect_redirects(self, entries: list[HarEntry]) -> list[DetectedIssue]:
        """Detect redirect chains (>= N hops) and loops by following ``redirectURL``.

        A single redirect is normal; only chains at or above the configured hop count
        (unless every hop matches an expected rule) and loops (a URL revisited within
        one chain) are reported.
        """
        sorted_entries = sorted(entries, key=lambda e: e.started_date_time)
        next_of = self._link_redirects(sorted_entries)
        targeted_ids = {id(target) for target in next_of.values()}

        issues: list[DetectedIssue] = []
        for start in sorted_entries:
            if id(start) not in next_of or id(start) in targeted_ids:
                continue
            chain = [start]
            seen_urls = {start.request.url}
            is_loop = False
            current = start
            while id(current) in next_of:
                current = next_of[id(current)]
                chain.append(current)
                if current.request.url in seen_urls:
                    is_loop = True
                    break
                seen_urls.add(current.request.url)

            redirect_hops = [e for e in chain if e.response.status in self.REDIRECT_STATUSES]
            all_hops_expected = all(self.is_expected(e) for e in redirect_hops)
            if not is_loop and (
                len(redirect_hops) < self.settings.redirect_chain_min_hops or all_hops_expected
            ):
                continue

            chain_ms = (entry_end_time(chain[-1]) - start.started_date_time).total_seconds() * 1000
            issue_type = IssueType.REDIRECT_LOOP if is_loop else IssueType.REDIRECT_CHAIN
            kind = "Redirect loop" if is_loop else "Redirect chain"
            issues.append(
                DetectedIssue(
                    issue_type=issue_type,
                    severity=IssueSeverity.HIGH if is_loop else IssueSeverity.LOW,
                    url=start.request.url,
                    message=f"{kind}: {len(redirect_hops)} hop(s) over {chain_ms:.0f}ms",
                    duration_ms=chain_ms,
                    timestamp=start.started_date_time,
                    details={
                        "method": start.request.method,
                        "hops": len(redirect_hops),
                        "chain": [f"{e.response.status} {e.request.url}" for e in chain],
                    },
                    domain=urlparse(start.request.url).netloc,
                )
            )
            self._add_request_context(issues[-1].details, start)
        return issues

    # -------------------------------------------------------------------------
    # Timeout clusters
    # -------------------------------------------------------------------------

    TIMEOUT_ROUND_STEP_S = 5.0  # timeouts are configured in round values (30s, 60s, 300s)

    def _detect_timeout_clusters(self, entries: list[HarEntry]) -> list[TimeoutCluster]:
        """Find failed requests whose durations bunch at a round value (timeouts).

        Only 5xx and status-0 requests are considered. Durations are measured from when
        the request was sent (total minus browser queueing). A cluster is a run of
        sorted durations where max <= min * (1 + tolerance) with at least the configured
        count, whose median sits within the tolerance of a multiple of 5 seconds.
        """
        tolerance = self.settings.timeout_cluster_tolerance_pct / 100
        min_requests = self.settings.timeout_cluster_min_requests
        failed = sorted(
            (
                e
                for e in entries
                if e.response.status == 0
                or self.HTTP_STATUS_SERVER_ERROR_MIN
                <= e.response.status
                < self.HTTP_STATUS_ERROR_MAX
            ),
            key=request_active_ms,
        )

        clusters: list[TimeoutCluster] = []
        start_index = 0
        while start_index < len(failed):
            end_index = start_index
            limit = request_active_ms(failed[start_index]) * (1 + tolerance)
            while end_index + 1 < len(failed) and request_active_ms(failed[end_index + 1]) <= limit:
                end_index += 1
            members = failed[start_index : end_index + 1]
            cluster = self._build_timeout_cluster(members, tolerance, min_requests)
            if cluster:
                clusters.append(cluster)
                start_index = end_index + 1
            else:
                start_index += 1
        return sorted(clusters, key=lambda c: (-c.request_count, c.median_ms))

    def _timeout_cluster_kind(self, members: list[HarEntry]) -> str:
        """``gateway`` when any member is a 5xx, ``client_cancel`` when all were aborted."""
        if any(m.response.status >= self.HTTP_STATUS_SERVER_ERROR_MIN for m in members):
            return "gateway"
        if all(classify_network_error(m) in INFORMATIONAL_ERROR_CATEGORIES for m in members):
            return "client_cancel"
        return "network"

    def _build_timeout_cluster(
        self, members: list[HarEntry], tolerance: float, min_requests: int
    ) -> TimeoutCluster | None:
        """Return a cluster when members are numerous enough and near a round value."""
        if len(members) < min_requests:
            return None
        durations = [request_active_ms(m) for m in members]
        median_ms = statistics.median(durations)
        median_s = median_ms / 1000
        round_value_s = round(median_s / self.TIMEOUT_ROUND_STEP_S) * self.TIMEOUT_ROUND_STEP_S
        if round_value_s <= 0 or abs(median_s - round_value_s) > round_value_s * tolerance:
            return None

        status_codes: dict[int, int] = defaultdict(int)
        endpoint_counts: dict[str, int] = defaultdict(int)
        for member in members:
            status_codes[member.response.status] += 1
            endpoint_counts[self.endpoint_key(member.request.url)] += 1

        matching_settings = [
            describe_fact(fact)
            for fact in self.config_facts
            if (fact_seconds := timeout_fact_seconds(fact)) is not None
            and abs(fact_seconds - median_s) <= fact_seconds * tolerance
        ]
        return TimeoutCluster(
            kind=self._timeout_cluster_kind(members),
            max_queued_ms=max(max(m.timings.blocked, 0.0) for m in members),
            request_count=len(members),
            min_ms=min(durations),
            max_ms=max(durations),
            median_ms=median_ms,
            round_value_s=round_value_s,
            status_codes=dict(sorted(status_codes.items())),
            endpoints=dict(sorted(endpoint_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
            first_seen=min(m.started_date_time for m in members),
            last_seen=max(m.started_date_time for m in members),
            matching_settings=matching_settings,
        )

    def _add_request_context(self, details: dict[str, object], entry: HarEntry) -> None:
        """Add the referer hostname and correlation IDs (log lookup keys) when present."""
        referer_hostname = self._extract_referer_hostname(entry)
        if referer_hostname:
            details["referer_hostname"] = referer_hostname
        correlation = correlation_headers(entry)
        if correlation:
            details["correlation"] = ", ".join(
                f"{name}={value}" for name, value in sorted(correlation.items())
            )

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
        """Content type from the header, else ``content.mimeType``, else ``unknown``."""
        return response_content_type(entry) or "unknown"

    def _compute_service_failures(self, entries: list[HarEntry]) -> list[ServiceFailureStats]:
        """Compute backend/API service health grouped by (domain, method, path template).

        Expected responses (e.g. SAS Logon 401) and aborted requests are counted
        separately and never as failures.
        """
        by_service: dict[tuple[str, str, str], list[HarEntry]] = defaultdict(list)

        for entry in entries:
            domain = urlparse(entry.request.url).netloc
            path = self.path_template(entry.request.url)
            by_service[(domain, entry.request.method, path)].append(entry)

        results: list[ServiceFailureStats] = []
        for (domain, method, path), reqs in by_service.items():
            status_codes: dict[int, int] = defaultdict(int)
            outcomes: dict[RequestOutcome, int] = defaultdict(int)
            duration_exceeded_count = 0
            problem_count = 0
            for r in reqs:
                status_codes[r.response.status] += 1
                outcome = self.outcome(r)
                outcomes[outcome] += 1
                over_duration = r.time > self.settings.duration_exceeded_ms
                duration_exceeded_count += over_duration
                problem_count += outcome in PROBLEM_OUTCOMES or over_duration

            measured = [r for r in reqs if self.is_latency_sample(r)]
            results.append(
                ServiceFailureStats(
                    domain=domain,
                    method=method,
                    path=path,
                    request_count=len(reqs),
                    success_count=outcomes[RequestOutcome.SUCCESS],
                    status_4xx_count=outcomes[RequestOutcome.CLIENT_ERROR],
                    status_5xx_count=outcomes[RequestOutcome.SERVER_ERROR],
                    network_error_count=outcomes[RequestOutcome.NETWORK_ERROR],
                    duration_exceeded_count=duration_exceeded_count,
                    status_codes=dict(status_codes),
                    timings=self._compute_timing_stats([r.time for r in measured]),
                    ttfb_timings=self._compute_timing_stats(
                        [r.timings.wait for r in measured if r.timings.wait >= 0]
                    ),
                    network_total_timings=self._compute_timing_stats(
                        [
                            total
                            for total in (self._network_total(r) for r in measured)
                            if total is not None
                        ]
                    ),
                    first_seen=min(r.started_date_time for r in reqs),
                    last_seen=max(r.started_date_time for r in reqs),
                    aborted_count=outcomes[RequestOutcome.ABORTED],
                    expected_count=outcomes[RequestOutcome.EXPECTED],
                    problem_count=problem_count,
                )
            )

        def sort_key(s: ServiceFailureStats) -> tuple[int, float, int, str, str]:
            return (-int(s.is_outage), -s.problem_rate, -s.request_count, s.path, s.method)

        return sorted(results, key=sort_key)

    # -------------------------------------------------------------------------
    # Infrastructure Diagnostic Methods
    # -------------------------------------------------------------------------

    def _compute_server_ips_by_domain(self, entries: list[HarEntry]) -> dict[str, list[str]]:
        """Group unique server IP addresses by domain."""
        by_domain: dict[str, set[str]] = defaultdict(set)
        for entry in entries:
            if entry.server_ip_address:
                domain = urlparse(entry.request.url).netloc
                by_domain[domain].add(entry.server_ip_address)
        return {domain: sorted(ips) for domain, ips in sorted(by_domain.items())}

    def _compute_http_version_distribution(self, entries: list[HarEntry]) -> dict[str, int]:
        """Count HTTP version distribution across all requests."""
        distribution: dict[str, int] = defaultdict(int)
        for entry in entries:
            version = entry.request.http_version or "unknown"
            distribution[version] += 1
        # Sort by count descending, then alphabetically
        return dict(sorted(distribution.items(), key=lambda kv: (-kv[1], kv[0])))

    def _compute_large_request_bodies(
        self, entries: list[HarEntry], limit: int = 20
    ) -> list[LargeRequestBody]:
        """Find requests with large body sizes (POST/PUT payloads >100KB)."""
        large_bodies: list[LargeRequestBody] = []

        for entry in entries:
            if entry.request.body_size > self.settings.large_request_body_bytes:
                content_type = "unknown"
                if entry.request.post_data:
                    content_type = entry.request.post_data.mime_type

                large_bodies.append(
                    LargeRequestBody(
                        url=entry.request.url,
                        method=entry.request.method,
                        body_size_bytes=entry.request.body_size,
                        content_type=content_type,
                        timestamp=entry.started_date_time,
                    )
                )

        return sorted(large_bodies, key=lambda x: -x.body_size_bytes)[:limit]

    def _compute_connection_reuse_stats(
        self, entries: list[HarEntry]
    ) -> ConnectionReuseStats | None:
        """Analyze connection ID reuse efficiency.

        Returns None when too few entries carry a ``connection`` ID to judge reuse.
        """
        if not entries:
            return None

        entries_with_connection_id = [e for e in entries if e.connection]
        connection_id_coverage = len(entries_with_connection_id) / len(entries)
        if connection_id_coverage < self.CONNECTION_ID_MIN_COVERAGE:
            return None

        total_requests = len(entries_with_connection_id)
        unique_connections = len({e.connection for e in entries_with_connection_id})
        return ConnectionReuseStats(
            total_requests=total_requests,
            unique_connections=unique_connections,
            reuse_ratio=total_requests / unique_connections,
        )

    @staticmethod
    def _host_connection_stats(measured: list[HarEntry]) -> list[HostConnectionStats]:
        """Per host: how many network-answered requests had to open a new connection.

        A request that spent time in ``connect`` opened a connection; reused connections
        record no connect time. Only requests with recorded timings are counted.
        """
        by_domain: dict[str, list[HarEntry]] = defaultdict(list)
        for entry in measured:
            if entry.timings.wait >= 0:
                by_domain[urlparse(entry.request.url).netloc].append(entry)
        stats = [
            HostConnectionStats(
                domain=domain,
                network_request_count=len(domain_entries),
                new_connection_count=sum(1 for e in domain_entries if e.timings.connect > 0),
                connection_close_count=sum(
                    1
                    for e in domain_entries
                    if "close" in (response_header(e, "connection") or "").lower()
                ),
            )
            for domain, domain_entries in by_domain.items()
        ]
        return sorted(stats, key=lambda h: (-h.new_connection_ratio, h.domain))

    # -------------------------------------------------------------------------
    # Error origin, clock offset, backend node
    # -------------------------------------------------------------------------

    NO_HEADER = "(none)"
    FAST_ERROR_MS = 1_000
    STATUS_HINTS: dict[int, str] = {  # noqa: RUF012 - read-only lookup table
        500: (
            "the application failed while handling the request; look for a stack trace "
            "at this time in the application log"
        ),
        502: (
            "a proxy got no valid answer from the backend: the backend restarted or "
            "crashed, closed an idle keep-alive connection the proxy then reused, or "
            "(when the 502 comes after a long wait) the proxy gave up reading the response"
        ),
        503: (
            "no backend took the request: the proxy could not get a backend connection "
            "(backend down or its connection limits full) or the backend reported itself "
            "unavailable"
        ),
        504: (
            "a proxy stopped waiting for the backend; compare the duration with the "
            "proxy's read timeout"
        ),
    }

    def _origin_reading(
        self, error_servers: dict[str, int], success_servers: dict[str, int]
    ) -> str:
        """Say what the Server headers on errors vs successes are consistent with."""
        if not success_servers:
            return "no successful responses from this host to compare with"
        error_names, success_names = set(error_servers), set(success_servers)
        if error_names == {self.NO_HEADER} and success_names == {self.NO_HEADER}:
            return "no Server header on errors or successes; headers do not show the tier"
        if error_names <= success_names:
            return "same Server header as successful responses; it does not separate the tiers"
        if error_names.isdisjoint(success_names):
            return (
                "Server header differs from successful responses; consistent with the "
                "errors being produced by a different tier (proxy or load balancer) "
                "than the one answering successes"
            )
        return (
            "some errors carry a Server header not seen on successes; more than one "
            "tier may be producing them"
        )

    def _error_origins(self, entries: list[HarEntry]) -> list[ErrorOrigin]:
        """For each host and 5xx status, compare response headers with the successes."""
        errors: dict[tuple[str, int], list[HarEntry]] = defaultdict(list)
        success_servers: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for entry in entries:
            domain = urlparse(entry.request.url).netloc
            outcome = self.outcome(entry)
            if outcome == RequestOutcome.SERVER_ERROR:
                errors[(domain, entry.response.status)].append(entry)
            elif outcome == RequestOutcome.SUCCESS and not self.is_browser_cache_hit(entry):
                server = response_header(entry, "server") or self.NO_HEADER
                success_servers[domain][server] += 1

        origins: list[ErrorOrigin] = []
        for (domain, status), members in sorted(errors.items()):
            error_servers: dict[str, int] = defaultdict(int)
            content_types: dict[str, int] = defaultdict(int)
            for member in members:
                error_servers[response_header(member, "server") or self.NO_HEADER] += 1
                content_type = response_content_type(member).split(";", 1)[0] or self.NO_HEADER
                content_types[content_type] += 1
            median_active_ms = statistics.median(request_active_ms(m) for m in members)
            hint = self.STATUS_HINTS.get(status, "")
            if status in (502, 503) and median_active_ms < self.FAST_ERROR_MS:
                hint += "; answered fast, so the request did not wait on the application"
            origins.append(
                ErrorOrigin(
                    domain=domain,
                    status=status,
                    count=len(members),
                    median_active_ms=median_active_ms,
                    error_servers=dict(sorted(error_servers.items())),
                    success_servers=dict(sorted(success_servers[domain].items())),
                    error_content_types=dict(sorted(content_types.items())),
                    via_count=sum(1 for m in members if response_header(m, "via")),
                    reading=self._origin_reading(error_servers, success_servers[domain]),
                    status_hint=hint,
                )
            )
        return origins

    CLOCK_OFFSET_MIN_SAMPLES = 3
    DATE_HEADER_HALF_RESOLUTION_S = 0.5  # Date has 1 s resolution, truncated

    def _clock_offsets(self, measured: list[HarEntry]) -> list[HostClockOffset]:
        """Server clock minus browser clock per host, from ``Date`` response headers.

        Each sample is the Date header minus the moment the response headers arrived
        (start + blocked + dns + connect + send + wait). Responses carrying ``Age`` were
        served by an intermediary cache with an old Date and are skipped.
        """
        samples: dict[str, list[float]] = defaultdict(list)
        for entry in measured:
            date_value = response_header(entry, "date")
            if not date_value or response_header(entry, "age"):
                continue
            try:
                server_time = parsedate_to_datetime(date_value)
            except (TypeError, ValueError):
                continue
            if server_time.tzinfo is None:
                server_time = server_time.replace(tzinfo=UTC)
            headers_arrived = entry.started_date_time + timedelta(
                milliseconds=entry.timings.before_response_headers_ms
            )
            samples[urlparse(entry.request.url).netloc].append(
                (server_time - headers_arrived).total_seconds() + self.DATE_HEADER_HALF_RESOLUTION_S
            )
        return [
            HostClockOffset(
                domain=domain,
                median_seconds=statistics.median(values),
                sample_count=len(values),
            )
            for domain, values in sorted(samples.items())
            if len(values) >= self.CLOCK_OFFSET_MIN_SAMPLES
        ]

    @staticmethod
    def backend_node(entry: HarEntry) -> tuple[str, str] | None:
        """Return (node, source) naming the backend that handled the request, if visible.

        Sources, in order: the jvmRoute suffix of ``JSESSIONID`` (``<id>.<route>``), a
        ``ROUTEID`` cookie (mod_proxy_balancer), the ``X-Served-By`` header. Only the
        route name is returned, never the session ID. Chrome leaves cookies out of HAR
        files unless exported "with sensitive data".
        """
        cookie_headers = [
            header.value
            for header in (*entry.response.headers, *entry.request.headers)
            if header.name.lower() in ("set-cookie", "cookie")
        ]
        for pattern, source in (
            (_JSESSIONID_ROUTE_RE, "JSESSIONID jvmRoute"),
            (_ROUTEID_RE, "ROUTEID cookie"),
        ):
            for value in cookie_headers:
                match = pattern.search(value)
                if match:
                    return match.group(1), source
        served_by = response_header(entry, "x-served-by")
        if served_by:
            return served_by.strip(), "X-Served-By"
        return None

    def _backend_nodes(self, entries: list[HarEntry]) -> list[BackendNodeStats]:
        """Requests, failures and latency per backend node, when nodes are visible."""
        by_node: dict[tuple[str, str, str], list[HarEntry]] = defaultdict(list)
        for entry in entries:
            node = self.backend_node(entry)
            if node:
                domain = urlparse(entry.request.url).netloc
                by_node[(domain, node[0], node[1])].append(entry)
        nodes: list[BackendNodeStats] = []
        for (domain, node_name, source), members in sorted(by_node.items()):
            outcomes = [self.outcome(m) for m in members]
            nodes.append(
                BackendNodeStats(
                    domain=domain,
                    node=node_name,
                    source=source,
                    request_count=len(members),
                    server_error_count=outcomes.count(RequestOutcome.SERVER_ERROR),
                    network_error_count=outcomes.count(RequestOutcome.NETWORK_ERROR),
                    timings=self._compute_timing_stats(
                        [m.time for m in members if self.is_latency_sample(m)]
                    ),
                )
            )
        return nodes

    def _compute_time_gaps(self, entries: list[HarEntry], limit: int = 20) -> list[TimeGap]:
        """Find idle periods (>1 second) where no request was in flight.

        The gap before a request is measured from the latest end time (start + time) of all
        earlier requests, so time spent waiting on a long request is not reported as idle.
        """
        if len(entries) < self.MIN_ENTRIES_FOR_GAP_ANALYSIS:
            return []

        sorted_entries = sorted(entries, key=lambda e: e.started_date_time)

        gaps: list[TimeGap] = []
        latest_finishing_entry = sorted_entries[0]
        latest_end = entry_end_time(latest_finishing_entry)
        for curr_entry in sorted_entries[1:]:
            gap_ms = (curr_entry.started_date_time - latest_end).total_seconds() * 1000

            if gap_ms > self.settings.idle_gap_ms:
                gaps.append(
                    TimeGap(
                        gap_duration_ms=gap_ms,
                        before_url=latest_finishing_entry.request.url,
                        after_url=curr_entry.request.url,
                        before_timestamp=latest_end,
                        after_timestamp=curr_entry.started_date_time,
                    )
                )

            curr_end = entry_end_time(curr_entry)
            if curr_end > latest_end:
                latest_end = curr_end
                latest_finishing_entry = curr_entry

        return sorted(gaps, key=lambda x: -x.gap_duration_ms)[:limit]

    def _extract_server_software_by_domain(
        self, entries: list[HarEntry]
    ) -> dict[str, dict[str, int]]:
        """Extract Server header values grouped by domain."""
        by_domain: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

        for entry in entries:
            domain = urlparse(entry.request.url).netloc
            for header in entry.response.headers:
                if header.name.lower() == "server":
                    by_domain[domain][header.value] += 1
                    break

        # Convert defaultdicts to regular dicts, sorted
        return {
            domain: dict(sorted(servers.items(), key=lambda kv: (-kv[1], kv[0])))
            for domain, servers in sorted(by_domain.items())
        }

    # -------------------------------------------------------------------------
    # Compression Analysis
    # -------------------------------------------------------------------------

    COMPRESSION_MIN_BODY_BYTES = 1024  # 1KB

    COMPRESSIBLE_CONTENT_TYPES = (
        "text/",
        "application/json",
        "application/javascript",
        "application/xml",
        "application/xhtml+xml",
        "application/ld+json",
        "application/manifest+json",
        "image/svg+xml",
    )

    def _analyze_compression(self, entries: list[HarEntry]) -> CompressionAnalysis | None:
        """Analyze compression of response bodies that crossed the network.

        Sizes are the uncompressed body (``content.size``), falling back to the wire
        size. Browser-cache hits are left out: nothing was transferred.
        """
        encoding_counts: dict[str, int] = defaultdict(int)
        compressible_uncompressed_count = 0
        compressible_uncompressed_bytes = 0
        total_analyzed = 0

        for entry in entries:
            body_size = response_uncompressed_bytes(entry)
            if body_size <= 0 or self.is_browser_cache_hit(entry):
                continue
            total_analyzed += 1
            content_encoding = (response_header(entry, "content-encoding") or "").lower().strip()
            if content_encoding and content_encoding != "identity":
                encoding_counts[content_encoding] += 1
                continue
            encoding_counts["none"] += 1
            content_type = response_content_type(entry)
            if body_size > self.COMPRESSION_MIN_BODY_BYTES and any(
                content_type.startswith(ct) for ct in self.COMPRESSIBLE_CONTENT_TYPES
            ):
                compressible_uncompressed_count += 1
                compressible_uncompressed_bytes += body_size

        if total_analyzed == 0:
            return None

        return CompressionAnalysis(
            encoding_distribution=dict(
                sorted(encoding_counts.items(), key=lambda kv: (-kv[1], kv[0]))
            ),
            compressible_uncompressed_count=compressible_uncompressed_count,
            compressible_uncompressed_bytes=compressible_uncompressed_bytes,
            total_responses_analyzed=total_analyzed,
        )

    # -------------------------------------------------------------------------
    # Cache Analysis
    # -------------------------------------------------------------------------

    HTTP_STATUS_NOT_MODIFIED = 304

    def _analyze_caching(self, entries: list[HarEntry]) -> CacheAnalysis | None:
        """Analyze caching of GET requests answered 200 or 304.

        A request was served without a download when the browser used its own cache or
        the server answered 304. A repeated download is the same full URL (query string
        included) fetched over the network more than once with no cache hit or 304 and
        without ``Cache-Control: no-store``.
        """
        by_url: dict[str, list[HarEntry]] = defaultdict(list)
        for entry in entries:
            if entry.request.method.upper() == "GET" and classify_network_error(entry) is None:
                by_url[entry.request.url.split("#", 1)[0]].append(entry)

        not_modified_count = 0
        browser_cache_hit_count = 0
        network_download_count = 0
        missing_cache_control_count = 0
        repeated_downloads: list[dict[str, Any]] = []

        for url, url_entries in by_url.items():
            browser_hits = [e for e in url_entries if self.is_browser_cache_hit(e)]
            network_200s = [
                e
                for e in url_entries
                if e.response.status == HTTP_STATUS_OK and not self.is_browser_cache_hit(e)
            ]
            status_304_count = sum(
                1 for e in url_entries if e.response.status == self.HTTP_STATUS_NOT_MODIFIED
            )
            not_modified_count += status_304_count
            browser_cache_hit_count += len(browser_hits)
            network_download_count += len(network_200s)

            cache_controls = [
                (response_header(e, "cache-control") or "").lower() for e in network_200s
            ]
            forbids_storing = any("no-store" in value for value in cache_controls)
            if (
                len(network_200s) > 1
                and status_304_count == 0
                and not browser_hits
                and not forbids_storing
            ):
                repeated_downloads.append(
                    {
                        "url": url,
                        "count": len(network_200s),
                        "total_bytes": sum(self.transferred_bytes(e) for e in network_200s),
                    }
                )
            if network_200s and _is_static_url(url) and not all(cache_controls):
                missing_cache_control_count += 1  # once per URL

        if not by_url:
            return None
        repeated_downloads.sort(key=lambda x: (-x["total_bytes"], x["url"]))
        served_without_download = not_modified_count + browser_cache_hit_count
        cacheable_get_count = served_without_download + network_download_count
        return CacheAnalysis(
            cacheable_get_count=cacheable_get_count,
            not_modified_count=not_modified_count,
            browser_cache_hit_count=browser_cache_hit_count,
            network_download_count=network_download_count,
            repeated_download_request_count=sum(r["count"] for r in repeated_downloads),
            repeated_downloads=repeated_downloads[:20],
            missing_cache_control_count=missing_cache_control_count,
            served_without_download_ratio=(
                served_without_download / cacheable_get_count if cacheable_get_count else 0.0
            ),
        )

    # -------------------------------------------------------------------------
    # Error Burst Detection
    # -------------------------------------------------------------------------

    ERROR_BURST_WINDOW_MS = 5_000  # 5 seconds
    ERROR_BURST_MIN_ERRORS = 3

    def _detect_error_bursts(self, issues: list[DetectedIssue]) -> list[ErrorBurst]:
        """Detect clusters of errors within short time windows."""
        error_issues = [
            i
            for i in issues
            if i.issue_type
            in (
                IssueType.NETWORK_ERROR,
                IssueType.SERVER_ERROR,
                IssueType.CLIENT_ERROR,
                IssueType.RATE_LIMITED,
            )
        ]
        if len(error_issues) < self.ERROR_BURST_MIN_ERRORS:
            return []

        sorted_errors = sorted(error_issues, key=lambda i: i.timestamp)
        window = timedelta(milliseconds=self.ERROR_BURST_WINDOW_MS)

        # Chain errors whose consecutive gap is <= the window; keep chains of 3+.
        groups: list[list[DetectedIssue]] = [[sorted_errors[0]]]
        for issue in sorted_errors[1:]:
            if issue.timestamp - groups[-1][-1].timestamp <= window:
                groups[-1].append(issue)
            else:
                groups.append([issue])

        return [
            ErrorBurst(
                start_time=group[0].timestamp,
                end_time=group[-1].timestamp,
                error_count=len(group),
                affected_domains=sorted({i.domain for i in group}),
            )
            for group in groups
            if len(group) >= self.ERROR_BURST_MIN_ERRORS
        ]

    # -------------------------------------------------------------------------
    # Request Rate
    # -------------------------------------------------------------------------

    def _compute_request_rate(
        self, entries: list[HarEntry], capture_start: datetime | None, capture_end: datetime | None
    ) -> RequestRateStats | None:
        """Compute overall and peak request rates."""
        if not entries or not capture_start or not capture_end:
            return None

        duration_seconds = (capture_end - capture_start).total_seconds()
        if duration_seconds <= 0:
            return None

        overall_rps = len(entries) / duration_seconds

        # Peak: most request starts in any 1-second window (two-pointer sweep)
        starts = sorted(e.started_date_time for e in entries)
        one_second = timedelta(seconds=1)
        peak_count = 0
        window_start_index = 0
        for window_end_index, start in enumerate(starts):
            while start - starts[window_start_index] > one_second:
                window_start_index += 1
            peak_count = max(peak_count, window_end_index - window_start_index + 1)
        peak_rps = float(peak_count)

        return RequestRateStats(
            overall_requests_per_second=overall_rps,
            peak_requests_per_second=peak_rps,
        )

    # -------------------------------------------------------------------------
    # Key Findings Generation
    # -------------------------------------------------------------------------

    DNS_P95_THRESHOLD_MS = 200.0
    HTTP11_DOMINANCE_PCT = 50.0
    BOTTLENECK_DOMINANCE_PCT = 50.0
    FINDING_LIST_LIMIT = 3
    CONNECTION_CHURN_MIN_REQUESTS = 10
    CONNECTION_CHURN_MIN_RATIO = 0.8
    CLOCK_OFFSET_REPORT_S = 2.0

    # Backend categories lead the findings, in this order within a severity.
    FINDING_CATEGORY_PRIORITY = (
        "outage",
        "timeout_cluster",
        "server_errors",
        "network_errors",
        "backend_node",
        "domain_health",
        "slowest_server_time",
        "redirect_loop",
        "rate_limiting",
        "error_burst",
        "always_rejected",
        "bottleneck",
        "browser_queueing",
        "connection_churn",
        "clock_offset",
    )

    def _connection_churn_findings(self, report: HarAnalysisReport) -> list[KeyFinding]:
        """Flag hosts where nearly every request had to open a new connection."""
        findings: list[KeyFinding] = []
        for host in report.host_connection_stats:
            if (
                host.network_request_count < self.CONNECTION_CHURN_MIN_REQUESTS
                or host.new_connection_ratio < self.CONNECTION_CHURN_MIN_RATIO
            ):
                continue
            close_note = (
                f"; {host.connection_close_count} response(s) carried Connection: close"
                if host.connection_close_count
                else ""
            )
            findings.append(
                KeyFinding(
                    category="connection_churn",
                    severity=IssueSeverity.MEDIUM,
                    summary=(
                        f"{host.new_connection_count} of {host.network_request_count} "
                        f"requests to {host.domain} opened a new connection{close_note}"
                    ),
                    recommendation=(
                        "Connections are not being kept alive; check KeepAlive on the web "
                        "server, keep-alive timeouts and request limits on each proxy hop"
                    ),
                )
            )
        return findings

    def _outage_findings(self, report: HarAnalysisReport) -> list[KeyFinding]:
        def listed(services: list[ServiceFailureStats]) -> str:
            text = ", ".join(
                f"{s.method} {s.path} ({s.request_count})"
                for s in services[: self.FINDING_LIST_LIMIT]
            )
            more = len(services) - self.FINDING_LIST_LIMIT
            return text + (f" (+{more} more)" if more > 0 else "")

        services = [s for s in report.service_failures if not _is_static_path(s.path)]
        findings: list[KeyFinding] = []
        outages = [s for s in services if s.is_outage]
        if outages:
            findings.append(
                KeyFinding(
                    category="outage",
                    severity=IssueSeverity.CRITICAL,
                    summary=(
                        f"{len(outages)} endpoint(s) never succeeded "
                        f"({OUTAGE_MIN_FAILURES}+ 5xx/network failures each): {listed(outages)}"
                    ),
                    recommendation=(
                        "Check the backend behind these endpoints first; see the error "
                        "origin table for which tier answered"
                    ),
                )
            )
        rejected = [s for s in services if s.is_always_rejected]
        if rejected:
            findings.append(
                KeyFinding(
                    category="always_rejected",
                    severity=IssueSeverity.MEDIUM,
                    summary=f"{len(rejected)} endpoint(s) answered only 4xx: {listed(rejected)}",
                    recommendation=(
                        "The server is refusing these requests (authorisation, missing "
                        "resource or bad input), not failing; check the status codes"
                    ),
                )
            )
        return findings

    def _timeout_cluster_findings(self, report: HarAnalysisReport) -> list[KeyFinding]:
        findings: list[KeyFinding] = []
        for cluster in report.timeout_clusters[: self.FINDING_LIST_LIMIT]:
            statuses = ", ".join(f"{code} x{count}" for code, count in cluster.status_codes.items())
            span = (
                f"~{cluster.round_value_s:.1f}s after being sent "
                f"({cluster.min_ms / 1000:.1f}-{cluster.max_ms / 1000:.1f}s; {statuses})"
            )
            if cluster.kind == "client_cancel":
                findings.append(
                    KeyFinding(
                        category="timeout_cluster",
                        severity=IssueSeverity.MEDIUM,
                        summary=(
                            f"{cluster.request_count} requests were cancelled by the "
                            f"browser {span} — consistent with a client-side timeout or "
                            f"a polling cancel"
                        ),
                        recommendation=(
                            "The page gave up, not a proxy; check the application's "
                            "JavaScript request timeout and why no answer came sooner"
                        ),
                    )
                )
                continue
            if cluster.matching_settings:
                recommendation = "Matches configured timeout: " + "; ".join(
                    cluster.matching_settings
                )
            elif report.config_facts_loaded:
                recommendation = (
                    "No loaded config setting matches; check load balancer / firewall idle "
                    "timeouts outside the bundle"
                )
            else:
                recommendation = (
                    "Compare with httpd ProxyTimeout / BalancerMember timeout=, Tomcat "
                    "connectionTimeout, load balancer idle timeout (--config-facts matches "
                    "automatically)"
                )
            signature = (
                "a gateway/proxy timeout" if cluster.kind == "gateway" else "a network timeout"
            )
            findings.append(
                KeyFinding(
                    category="timeout_cluster",
                    severity=IssueSeverity.CRITICAL,
                    summary=(
                        f"{cluster.request_count} failed requests ended {span} — "
                        f"consistent with {signature}"
                    ),
                    recommendation=recommendation,
                )
            )
        return findings

    def _server_error_findings(self, report: HarAnalysisReport) -> list[KeyFinding]:
        by_endpoint: dict[str, int] = defaultdict(int)
        for issue in report.issues:
            if issue.issue_type == IssueType.SERVER_ERROR:
                method = issue.details.get("method", "")
                by_endpoint[f"{method} {self.path_template(issue.url)}".strip()] += 1
        if not by_endpoint:
            return []
        ranked = sorted(by_endpoint.items(), key=lambda kv: (-kv[1], kv[0]))
        listed = ", ".join(f"{name} ({count})" for name, count in ranked[: self.FINDING_LIST_LIMIT])
        more = len(ranked) - self.FINDING_LIST_LIMIT
        listed += f" (+{more} more)" if more > 0 else ""
        by_status: dict[int, int] = defaultdict(int)
        for origin in report.error_origins:
            by_status[origin.status] += origin.count
        statuses = ", ".join(f"{status} x{count}" for status, count in sorted(by_status.items()))
        return [
            KeyFinding(
                category="server_errors",
                severity=IssueSeverity.HIGH,
                summary=(
                    f"{sum(by_endpoint.values())} 5xx response(s) ({statuses}) on "
                    f"{len(ranked)} endpoint(s): {listed}"
                ),
                recommendation=(
                    "See the 5xx error origin table for which tier answered; match the "
                    "timestamps against server logs (--export-events)"
                ),
            )
        ]

    def _network_error_findings(self, report: HarAnalysisReport) -> list[KeyFinding]:
        if not report.network_errors_by_category:
            return []
        total = sum(report.network_errors_by_category.values())
        by_type = ", ".join(
            f"{category} ({count})" for category, count in report.network_errors_by_category.items()
        )
        severity_order = {sev: idx for idx, sev in enumerate(IssueSeverity)}
        severity = min(
            (i.severity for i in report.issues if i.issue_type == IssueType.NETWORK_ERROR),
            key=lambda sev: severity_order[sev],
        )
        hints = "; ".join(
            f"{category}: {NETWORK_ERROR_HINTS[category]}"
            for category in list(report.network_errors_by_category)[: self.FINDING_LIST_LIMIT]
        )
        return [
            KeyFinding(
                category="network_errors",
                severity=severity,
                summary=f"{total} network error(s): {by_type}",
                recommendation=f"Consistent with — {hints}",
            )
        ]

    def _backend_node_findings(self, report: HarAnalysisReport) -> list[KeyFinding]:
        """Flag a host where every failure came from one of several backend nodes."""
        by_domain: dict[str, list[BackendNodeStats]] = defaultdict(list)
        for node in report.backend_nodes:
            by_domain[node.domain].append(node)
        findings: list[KeyFinding] = []
        for domain, nodes in sorted(by_domain.items()):
            failing = [n for n in nodes if n.server_error_count + n.network_error_count]
            if len(nodes) < 2 or len(failing) != 1:  # noqa: PLR2004
                continue
            bad = failing[0]
            failures = bad.server_error_count + bad.network_error_count
            if failures < OUTAGE_MIN_FAILURES:
                continue
            other_requests = sum(n.request_count for n in nodes if n is not bad)
            findings.append(
                KeyFinding(
                    category="backend_node",
                    severity=IssueSeverity.HIGH,
                    summary=(
                        f"All {failures} failures on {domain} came from backend node "
                        f"{bad.node} ({bad.request_count} requests); the other "
                        f"{len(nodes) - 1} node(s) served {other_requests} requests "
                        f"without one"
                    ),
                    recommendation=f"Start with node {bad.node} (named by {bad.source})",
                )
            )
        return findings

    def _clock_offset_findings(self, report: HarAnalysisReport) -> list[KeyFinding]:
        findings: list[KeyFinding] = []
        for offset in report.clock_offsets:
            if abs(offset.median_seconds) <= self.CLOCK_OFFSET_REPORT_S:
                continue
            direction = "ahead of" if offset.median_seconds > 0 else "behind"
            findings.append(
                KeyFinding(
                    category="clock_offset",
                    severity=IssueSeverity.MEDIUM,
                    summary=(
                        f"Server clock for {offset.domain} is about "
                        f"{abs(offset.median_seconds):.0f}s {direction} the browser clock "
                        f"(Date headers, n={offset.sample_count})"
                    ),
                    recommendation=(
                        f"Timestamps in this report are browser time; add "
                        f"{offset.median_seconds:+.0f}s to find the same moment in that "
                        f"server's logs"
                    ),
                )
            )
        return findings

    def _queueing_findings(self, report: HarAnalysisReport) -> list[KeyFinding]:
        """Explain browser queueing as a consequence of what was holding the connections."""
        by_domain: dict[str, list[DetectedIssue]] = defaultdict(list)
        for issue in report.issues:
            if issue.issue_type == IssueType.BLOCKING:
                by_domain[issue.domain].append(issue)
        findings: list[KeyFinding] = []
        for domain, issues in sorted(by_domain.items()):
            worst = max(issues, key=lambda i: i.duration_ms or 0.0)
            is_http1 = str(worst.details.get("http_version", "")).lower().startswith("http/1")
            holders = worst.details.get("in_flight_meanwhile")
            cause = (
                "HTTP/1.1 allows about six connections per host, so requests queue behind "
                "slow responses"
                if is_http1
                else "Requests queued in the browser before being sent"
            )
            findings.append(
                KeyFinding(
                    category="browser_queueing",
                    severity=IssueSeverity.MEDIUM,
                    summary=(
                        f"{len(issues)} request(s) to {domain} queued in the browser for "
                        f"over {self.settings.blocking_ms:g}ms "
                        f"(longest {(worst.duration_ms or 0.0) / 1000:.1f}s)"
                    ),
                    recommendation=(
                        f"{cause}; in flight during the longest queue: {holders}"
                        if holders
                        else cause
                    ),
                )
            )
        return findings

    def _slowest_server_time_findings(self, report: HarAnalysisReport) -> list[KeyFinding]:
        candidates = [
            e
            for e in report.endpoints
            if e.ttfb_timings.count and not _is_static_url(e.url_pattern)
        ]
        if not candidates:
            return []
        slowest = max(candidates, key=lambda e: tail_value(e.ttfb_timings))
        value = tail_value(slowest.ttfb_timings)
        is_slow = value > self.settings.slow_endpoint_ms
        return [
            KeyFinding(
                category="slowest_server_time",
                severity=IssueSeverity.HIGH if is_slow else IssueSeverity.LOW,
                summary=(
                    f"Slowest wait for first byte (TTFB): {urlparse(slowest.url_pattern).path} "
                    f"{tail_label(slowest.ttfb_timings)} {value:.0f}ms "
                    f"(n={slowest.ttfb_timings.count})"
                ),
                recommendation=(
                    "TTFB covers network round trip, proxies and the application; compare "
                    "with the host's round-trip estimate, then profile the endpoint"
                    if is_slow
                    else f"Below the {self.settings.slow_endpoint_ms:g}ms slow threshold"
                ),
            )
        ]

    def _frontend_findings(self, report: HarAnalysisReport) -> list[KeyFinding]:
        """Generic web-performance advice; reported in an informational section."""
        findings: list[KeyFinding] = []
        if (
            report.dns_timings.count > 0
            and tail_value(report.dns_timings) > self.DNS_P95_THRESHOLD_MS
        ):
            findings.append(
                KeyFinding(
                    category="dns",
                    severity=IssueSeverity.MEDIUM,
                    summary=(
                        f"DNS resolution {tail_label(report.dns_timings)} "
                        f"{tail_value(report.dns_timings):.0f}ms (n={report.dns_timings.count})"
                    ),
                    recommendation="Consider DNS prefetching or preconnect hints",
                    frontend=True,
                )
            )

        if report.http_version_distribution and report.total_requests > 0:
            http11_count = sum(
                count
                for version, count in report.http_version_distribution.items()
                if "1.1" in version
            )
            http11_pct = http11_count / report.total_requests * 100
            if http11_pct > self.HTTP11_DOMINANCE_PCT:
                findings.append(
                    KeyFinding(
                        category="protocol",
                        severity=IssueSeverity.MEDIUM,
                        summary=f"{http11_pct:.0f}% of requests use HTTP/1.1",
                        recommendation=(
                            "HTTP/2 would improve multiplexing and reduce connection overhead"
                        ),
                        frontend=True,
                    )
                )

        comp = report.compression_analysis
        if comp and comp.compressible_uncompressed_count > 0:
            size_mb = comp.compressible_uncompressed_bytes / ONE_MEGABYTE
            findings.append(
                KeyFinding(
                    category="compression",
                    severity=IssueSeverity.MEDIUM,
                    summary=(
                        f"{comp.compressible_uncompressed_count} response(s) "
                        f"({size_mb:.1f} MB) could benefit from compression"
                    ),
                    recommendation="Enable gzip or Brotli compression on the server",
                    frontend=True,
                )
            )

        cache = report.cache_analysis
        if cache and cache.repeated_downloads:
            wasted_mb = sum(r["total_bytes"] for r in cache.repeated_downloads) / ONE_MEGABYTE
            findings.append(
                KeyFinding(
                    category="caching",
                    severity=IssueSeverity.MEDIUM,
                    summary=(
                        f"{len(cache.repeated_downloads)} URL(s) fetched repeatedly over "
                        f"the network with no cache hit or 304 ({wasted_mb:.1f} MB)"
                    ),
                    recommendation=(
                        "For static resources add Cache-Control; repeated API polling of "
                        "the same URL is expected and needs no change"
                    ),
                    frontend=True,
                )
            )
        return findings

    def _generate_key_findings(self, report: HarAnalysisReport) -> list[KeyFinding]:
        """Synthesize findings: backend signals first, front-end advice flagged separately."""
        findings: list[KeyFinding] = [
            *self._outage_findings(report),
            *self._timeout_cluster_findings(report),
            *self._server_error_findings(report),
            *self._network_error_findings(report),
            *self._backend_node_findings(report),
            *self._slowest_server_time_findings(report),
        ]

        critical_domains = [d.domain for d in report.domains if d.health == DomainHealth.CRITICAL]
        if critical_domains:
            findings.append(
                KeyFinding(
                    category="domain_health",
                    severity=IssueSeverity.CRITICAL,
                    summary=(
                        f"{len(critical_domains)} domain(s) in critical state: "
                        f"{', '.join(critical_domains)}"
                    ),
                    recommendation="Investigate error rates and backend health for these domains",
                )
            )

        loops = [i for i in report.issues if i.issue_type == IssueType.REDIRECT_LOOP]
        if loops:
            findings.append(
                KeyFinding(
                    category="redirect_loop",
                    severity=IssueSeverity.HIGH,
                    summary=f"{len(loops)} redirect loop(s) detected",
                    recommendation="Check SAS Logon service URLs, cookies and proxy rewrites",
                )
            )

        rate_limited = [i for i in report.issues if i.issue_type == IssueType.RATE_LIMITED]
        if rate_limited:
            findings.append(
                KeyFinding(
                    category="rate_limiting",
                    severity=IssueSeverity.HIGH,
                    summary=(
                        f"{len(rate_limited)} request(s) throttled (429) "
                        f"on {', '.join(sorted({i.domain for i in rate_limited}))}"
                    ),
                    recommendation="Reduce request frequency or implement backoff/retry logic",
                )
            )

        if report.error_bursts:
            total_burst_errors = sum(b.error_count for b in report.error_bursts)
            all_domains = sorted({d for b in report.error_bursts for d in b.affected_domains})
            findings.append(
                KeyFinding(
                    category="error_burst",
                    severity=IssueSeverity.HIGH,
                    summary=(
                        f"{total_burst_errors} errors came in "
                        f"{len(report.error_bursts)} run(s) (each within "
                        f"{self.ERROR_BURST_WINDOW_MS / 1000:g}s of the previous) "
                        f"affecting {', '.join(all_domains)}"
                    ),
                    recommendation="Investigate cascading failures or upstream outages",
                )
            )

        findings.extend(self._bottleneck_findings(report))
        findings.extend(self._queueing_findings(report))
        findings.extend(self._connection_churn_findings(report))
        findings.extend(self._clock_offset_findings(report))
        findings.extend(self._frontend_findings(report))

        severity_order = {sev: idx for idx, sev in enumerate(IssueSeverity)}
        priority = {cat: idx for idx, cat in enumerate(self.FINDING_CATEGORY_PRIORITY)}
        return sorted(
            findings,
            key=lambda f: (
                f.frontend,
                severity_order[f.severity],
                priority.get(f.category, len(priority)),
            ),
        )

    def _bottleneck_findings(self, report: HarAnalysisReport) -> list[KeyFinding]:
        phase_totals = {
            "DNS": report.dns_timings.total_duration_ms,
            "Connect (excl. TLS)": report.connect_timings.total_duration_ms,
            "SSL": report.ssl_timings.total_duration_ms,
            "TTFB": report.ttfb_timings.total_duration_ms,
            "Receive": report.receive_timings.total_duration_ms,
        }
        grand_total = sum(phase_totals.values())
        if grand_total <= 0:
            return []
        dominant_phase = max(phase_totals, key=lambda k: phase_totals[k])
        dominant_pct = phase_totals[dominant_phase] / grand_total * 100
        if dominant_pct < self.BOTTLENECK_DOMINANCE_PCT:
            return []
        phase_recommendations = {
            "DNS": "Consider DNS prefetching or switching DNS providers",
            "Connect (excl. TLS)": "Check for connection pooling issues or high network latency",
            "SSL": "Investigate TLS handshake overhead; consider session resumption",
            "TTFB": (
                "Waiting for the first byte dominates (normal for API traffic); it covers "
                "network round trip, proxies and the application — see slowest endpoints"
            ),
            "Receive": (
                "Time went into receiving bodies: large or uncompressed responses, a slow "
                "link, or responses the server streams as it produces them"
            ),
        }
        # Waiting on the server side dominating is the normal state for API traffic; a
        # network phase dominating is not.
        return [
            KeyFinding(
                category="bottleneck",
                severity=IssueSeverity.LOW if dominant_phase == "TTFB" else IssueSeverity.HIGH,
                summary=(
                    f"{'Wait (TTFB)' if dominant_phase == 'TTFB' else dominant_phase} accounts "
                    f"for {dominant_pct:.0f}% of summed phase time"
                ),
                recommendation=phase_recommendations[dominant_phase],
            )
        ]


# =============================================================================
# Output Formatter
# =============================================================================


_STATIC_SUFFIXES = (
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
_STATIC_PREFIXES = ("/images/", "/styles/", "/static/", "/assets/", "/fonts/")


def _is_static_path(path: str) -> bool:
    """Heuristic for service paths to exclude static assets."""
    path_lower = (path or "").lower()
    if path_lower.endswith(_STATIC_SUFFIXES):
        return True
    return path_lower.startswith(_STATIC_PREFIXES)


def _is_static_url(url: str) -> bool:
    """Check if a URL points to a static asset."""
    return _is_static_path(urlparse(url).path)


_SECONDS_PER_MINUTE = 60


def _format_duration(td: timedelta) -> str:
    """Format a timedelta as human-readable duration (e.g. '2m 34s', '1h 5m 12s')."""
    total_seconds = td.total_seconds()
    if total_seconds < _SECONDS_PER_MINUTE:
        return f"{total_seconds:.1f}s"
    minutes, seconds = divmod(int(total_seconds), _SECONDS_PER_MINUTE)
    hours, minutes = divmod(minutes, _SECONDS_PER_MINUTE)
    if hours:
        return f"{hours}h {minutes}m {seconds}s"
    return f"{minutes}m {seconds}s"


DOMAIN_TABLE_MAX_ROWS = 20
OUTAGE_TABLE_MAX_ROWS = 25
SERVICE_TABLE_MAX_ROWS = 25
ISSUES_BY_DOMAIN_MAX_DOMAINS = 15
ISSUES_BY_DOMAIN_MAX_ISSUES = 8
MARKDOWN_MAX_ISSUES_PER_SEVERITY = 50
MARKDOWN_TOP_ENDPOINTS = 10

# Infrastructure diagnostics display limits
SERVER_IPS_TABLE_MAX_ROWS = 15
TIME_GAP_TABLE_MAX_ROWS = 10
LARGE_REQUEST_BODY_TABLE_MAX_ROWS = 10
SERVER_SOFTWARE_MAX_DOMAINS = 10

# Path truncation limits for display
PATH_TRUNCATE_LONG = 80
PATH_TRUNCATE_MEDIUM = 60
PATH_TRUNCATE_SHORT = 50
PATH_TRUNCATE_TINY = 40

# Byte size thresholds
ONE_MEGABYTE = 1_048_576

CONNECTION_REUSE_UNAVAILABLE_MSG = "Not available: HAR has no connection IDs"


def format_percentiles(stats: TimingStatistics) -> str:
    """Percentiles the sample size supports: p95 needs n >= 20, p99 needs n >= 100."""
    if stats.count == 0:
        return "no data (n=0)"
    if stats.count < MIN_SAMPLES_FOR_TAIL_PERCENTILES:
        return (
            f"p50 {stats.p50:.0f}ms / max {stats.max:.0f}ms "
            f"(n={stats.count}; p95/p99 need n≥{MIN_SAMPLES_FOR_TAIL_PERCENTILES})"
        )
    if stats.count < MIN_SAMPLES_FOR_P99:
        return (
            f"p50 {stats.p50:.0f}ms / p95 {stats.p95:.0f}ms / max {stats.max:.0f}ms "
            f"(n={stats.count}; p99 needs n≥{MIN_SAMPLES_FOR_P99})"
        )
    return (
        f"p50 {stats.p50:.0f}ms / p95 {stats.p95:.0f}ms / p99 {stats.p99:.0f}ms (n={stats.count})"
    )


def md_cell(text: str) -> str:
    """Escape a value for use inside a Markdown table cell."""
    return text.replace("|", "\\|").replace("\n", " ")


def md_table(headers: tuple[str, ...], rows: list[tuple[str, ...]]) -> list[str]:
    """Render a Markdown table; every cell is escaped."""
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    lines.extend("| " + " | ".join(md_cell(cell) for cell in row) + " |" for row in rows)
    return lines


def format_bytes(size_bytes: float) -> str:
    """``1.5 MB`` / ``200.0 KB``."""
    if size_bytes >= ONE_MEGABYTE:
        return f"{size_bytes / ONE_MEGABYTE:.1f} MB"
    return f"{size_bytes / 1024:.1f} KB"


def write_text_atomic(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` via a temp file and replace, so no partial file is left."""
    temp_path = path.with_name(f".{path.name}.tmp")
    temp_path.write_text(text, encoding="utf-8")
    temp_path.replace(path)


@dataclass(frozen=True)
class ReportSection:
    """A titled table shared by the terminal and Markdown reports."""

    title: str
    note: str
    headers: tuple[str, ...]
    rows: list[tuple[str, ...]]
    footnotes: tuple[str, ...] = ()


def format_tail(stats: TimingStatistics) -> str:
    """Table cell for a tail latency: ``1234ms (p95, n=40)`` or ``900ms (max, n=3)``."""
    if stats.count == 0:
        return "-"
    return f"{tail_value(stats):.0f}ms ({tail_label(stats)}, n={stats.count})"


def describe_thresholds(settings: AnalyzerSettings) -> list[str]:
    """Human-readable list of the thresholds and rules a report was produced with."""
    expected = ", ".join(f"`{rule}`" for rule in settings.expected_rules) or "none"
    lines = [
        f"slow endpoint > {settings.slow_endpoint_ms:g}ms (p95; max when n<20)",
        f"request duration > {settings.duration_exceeded_ms:g}ms",
        f"idle gap > {settings.idle_gap_ms:g}ms with nothing in flight",
        f"client blocking > {settings.blocking_ms:g}ms",
        f"large response > {settings.large_payload_bytes:,} bytes",
        f"large request body > {settings.large_request_body_bytes:,} bytes",
        f"redirect chain ≥ {settings.redirect_chain_min_hops} hops",
        (
            f"timeout cluster ≥ {settings.timeout_cluster_min_requests} failed requests "
            f"within ±{settings.timeout_cluster_tolerance_pct:g}%"
        ),
        f"expected responses: {expected}",
    ]
    if settings.path_rules:
        lines.append(f"path rules: {', '.join(f'`{rule}`' for rule in settings.path_rules)}")
    return lines


def status_class_counts(status_codes: dict[int, int]) -> dict[str, int]:
    """Counts by ``2xx``..``5xx``; status 0 is reported as ``0 (no response)``."""
    counts: dict[str, int] = defaultdict(int)
    for code, count in status_codes.items():
        key = "0 (no response)" if code == 0 else f"{str(code)[0]}xx"
        counts[key] += count
    return dict(sorted(counts.items()))


class OutputFormatter:
    """Format analysis results for terminal output and markdown exports."""

    def __init__(
        self,
        *,
        timestamp_timezone: tzinfo | None = None,
        timestamp_timezone_label: str | None = None,
        show_query: bool = False,
    ) -> None:
        """Create a formatter; query values are redacted unless ``show_query``."""
        self._timestamp_timezone = timestamp_timezone
        self._timestamp_timezone_label = timestamp_timezone_label
        self._show_query = show_query

    def print_report(self, report: HarAnalysisReport) -> None:
        """Print a backend/network-focused report to the terminal."""
        backend_findings = [f for f in report.key_findings if not f.frontend]
        if backend_findings:
            self._print_findings_panel(backend_findings, "Key Findings", "yellow")
            console.print()

        # SECTION 1: METADATA & INFRASTRUCTURE
        self._print_summary(report)
        console.print()

        self._print_infrastructure_details(report)
        console.print()

        if report.server_ips_by_domain:
            self._print_server_ips_table(report)
            console.print()

        for section in self._infrastructure_sections(report):
            self._print_section(section)
            console.print()

        if report.time_gaps:
            self._print_time_gaps_table(report)
            console.print()

        if report.large_request_bodies:
            self._print_large_request_bodies_table(report)
            console.print()

        if report.referer_hostnames:
            self._print_referer_hostnames(report)
            console.print()

        self._print_problem_sections(report)
        self._print_frontend_section(report)

    def _print_section(self, section: ReportSection) -> None:
        table = Table(title=section.title, caption=section.note or None)
        for header in section.headers:
            table.add_column(header, no_wrap=False)
        for row in section.rows:
            table.add_row(*(rich_escape(cell) for cell in row))
        console.print(table)
        for footnote in section.footnotes:
            console.print(f"[dim]{rich_escape(footnote)}[/dim]")

    @staticmethod
    def _md_section(section: ReportSection, heading: str = "##") -> list[str]:
        lines = [f"{heading} {section.title}", ""]
        if section.note:
            lines.extend([section.note, ""])
        lines.extend(md_table(section.headers, section.rows))
        lines.append("")
        if section.footnotes:
            lines.extend(f"- {footnote}" for footnote in section.footnotes)
            lines.append("")
        return lines

    def _print_problem_sections(self, report: HarAnalysisReport) -> None:
        """SECTION 2: problem analysis (backend first)."""
        if report.timeout_clusters:
            self._print_timeout_clusters(report)
            console.print()

        if report.domains:
            self._print_domain_health(report)
            console.print()

        if report.service_failures:
            self._print_outages(report.service_failures, max_rows=OUTAGE_TABLE_MAX_ROWS)
            console.print()
            self._print_service_failures(report, max_rows=SERVICE_TABLE_MAX_ROWS)
            console.print()

        for section in self._error_evidence_sections(report):
            self._print_section(section)
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

        info_issues = self._filter_informational_issues(report.issues)
        if info_issues:
            self._print_issues_by_domain(info_issues, title="Informational (redirects, aborts)")
            console.print()

        self._print_top_endpoints(report)

        slowest = self._slowest_requests_section(report)
        if slowest:
            console.print()
            self._print_section(slowest)

        if self._has_server_timings(report):
            console.print()
            self._print_server_timings(report)

        if report.error_bursts:
            console.print()
            self._print_error_bursts(report)

    # -------------------------------------------------------------------------
    # Evidence sections shared by terminal and Markdown
    # -------------------------------------------------------------------------

    def _slowest_requests_section(self, report: HarAnalysisReport) -> ReportSection | None:
        if not report.slowest_requests:
            return None
        rows = [
            (
                self._format_timestamp(req.started, timespec="milliseconds"),
                f"{req.method} {self._extract_path(req.url)}",
                f"{req.status}" + (f" {req.error_category}" if req.error_category else ""),
                f"{req.total_ms:.0f}",
                _ms_or_dash(req.blocked_ms),
                _ms_or_dash(req.dns_ms),
                _ms_or_dash(req.connect_excl_tls_ms),
                _ms_or_dash(req.tls_ms),
                _ms_or_dash(req.send_ms),
                _ms_or_dash(req.wait_ms),
                _ms_or_dash(req.receive_ms),
                ", ".join(f"{name}={value}" for name, value in sorted(req.correlation.items()))
                or "-",
            )
            for req in report.slowest_requests
        ]
        return ReportSection(
            title="Slowest Individual Requests",
            note="Milliseconds; - = not recorded. Timestamps are the browser's clock.",
            headers=(
                "Start",
                "Request",
                "Status",
                "Total",
                "Queued",
                "DNS",
                "Connect",
                "TLS",
                "Send",
                "Wait",
                "Receive",
                "Correlation IDs",
            ),
            rows=rows,
        )

    @staticmethod
    def _counts_text(counts: dict[str, int]) -> str:
        return ", ".join(f"{name} ({count})" for name, count in counts.items()) or "-"

    def _error_evidence_sections(self, report: HarAnalysisReport) -> list[ReportSection]:
        """5xx error origin and per-backend-node tables (only when there is data)."""
        sections: list[ReportSection] = []
        if report.error_origins:
            hints = {o.status: o.status_hint for o in report.error_origins if o.status_hint}
            sections.append(
                ReportSection(
                    title="5xx Error Origin (response headers on errors vs successes)",
                    note=(
                        "Which tier answered: compare the Server header on error responses "
                        "with the same host's successful responses."
                    ),
                    headers=(
                        "Host",
                        "Status",
                        "Count",
                        "Median since sent",
                        "Server on errors",
                        "Server on successes",
                        "Content-Type on errors",
                        "With Via",
                        "Reading",
                    ),
                    rows=[
                        (
                            o.domain,
                            str(o.status),
                            str(o.count),
                            f"{o.median_active_ms / 1000:.2f}s",
                            self._counts_text(o.error_servers),
                            self._counts_text(o.success_servers),
                            self._counts_text(o.error_content_types),
                            str(o.via_count),
                            o.reading,
                        )
                        for o in report.error_origins
                    ],
                    footnotes=tuple(
                        f"{status} is consistent with: {hint}"
                        for status, hint in sorted(hints.items())
                    ),
                )
            )
        if report.backend_nodes:
            sections.append(
                ReportSection(
                    title="Backend Nodes",
                    note="Node names come from the session route cookie or X-Served-By header.",
                    headers=("Host", "Node", "Source", "Requests", "5xx", "NetErr", "Tail total"),
                    rows=[
                        (
                            n.domain,
                            n.node,
                            n.source,
                            str(n.request_count),
                            str(n.server_error_count),
                            str(n.network_error_count),
                            format_tail(n.timings),
                        )
                        for n in report.backend_nodes
                    ],
                )
            )
        return sections

    def _infrastructure_sections(self, report: HarAnalysisReport) -> list[ReportSection]:
        """Clock offset, per-host connections and long-lived connections."""
        sections: list[ReportSection] = []
        if report.clock_offsets:
            sections.append(
                ReportSection(
                    title="Clock Offset (server Date header minus browser clock)",
                    note=(
                        "Report timestamps are browser time. Add the offset to find the same "
                        "moment in that server's logs (accuracy about ±1s)."
                    ),
                    headers=("Host", "Offset", "Samples"),
                    rows=[
                        (o.domain, f"{o.median_seconds:+.1f}s", str(o.sample_count))
                        for o in report.clock_offsets
                    ],
                )
            )
        if report.host_connection_stats:
            sections.append(
                ReportSection(
                    title="Connections per Host",
                    note=(
                        "New connection = the request spent time connecting. HTTP/1.1 "
                        "browsers open up to about six per host; HTTP/2 needs one."
                    ),
                    headers=(
                        "Host",
                        "Network requests",
                        "Opened a new connection",
                        "Connection: close responses",
                    ),
                    rows=[
                        (
                            h.domain,
                            str(h.network_request_count),
                            f"{h.new_connection_count} ({h.new_connection_ratio * 100:.0f}%)",
                            str(h.connection_close_count),
                        )
                        for h in report.host_connection_stats[:DOMAIN_TABLE_MAX_ROWS]
                    ],
                )
            )
        if report.long_lived_connections:
            sections.append(
                ReportSection(
                    title="Long-lived Connections (WebSocket / event stream)",
                    note=(
                        "Open by design: their duration is the connection lifetime, so they "
                        "are excluded from every count, latency statistic and duration rule."
                    ),
                    headers=("Kind", "Request", "Status", "Started", "Open for"),
                    rows=[
                        (
                            c.kind,
                            self._extract_path(c.url),
                            str(c.status),
                            self._format_timestamp(c.started),
                            _format_duration(timedelta(milliseconds=c.duration_ms)),
                        )
                        for c in report.long_lived_connections[:DOMAIN_TABLE_MAX_ROWS]
                    ],
                )
            )
        return sections

    @staticmethod
    def _availability_lines(report: HarAnalysisReport) -> list[str]:
        """State plainly which evidence the capture does not contain."""
        lines: list[str] = []
        if not report.backend_nodes:
            lines.append(
                "Backend node: not available (no JSESSIONID route, ROUTEID cookie or "
                "X-Served-By header in the capture; Chrome omits cookies unless the HAR is "
                "exported with sensitive data)"
            )
        if not report.clock_offsets:
            lines.append(
                "Clock offset: not available (fewer than "
                f"{HarAnalyzer.CLOCK_OFFSET_MIN_SAMPLES} usable Date response headers per host)"
            )
        return lines

    def _capture_note_lines(self, report: HarAnalysisReport) -> list[str]:
        """What was left out of or assumed about the capture (empty when nothing)."""
        notes = report.load_notes
        lines: list[str] = []
        if notes.skipped_entry_count:
            reasons = "; ".join(notes.skipped_entry_reasons)
            lines.append(
                f"WARNING: {notes.skipped_entry_count} malformed entr"
                f"{'y was' if notes.skipped_entry_count == 1 else 'ies were'} skipped and "
                f"are not in any figure below ({reasons})"
            )
        if notes.non_http_entry_count:
            lines.append(
                f"{notes.non_http_entry_count} non-network entries (data:, blob:, "
                f"browser-extension URLs) were left out"
            )
        if report.assumed_utc_timestamp_count:
            lines.append(
                f"{report.assumed_utc_timestamp_count} timestamp(s) had no UTC offset and "
                f"were read as UTC"
            )
        if report.long_lived_connections:
            lines.append(
                f"{len(report.long_lived_connections)} long-lived connection(s) (WebSocket / "
                f"event stream) are listed separately and excluded from all figures"
            )
        return lines

    @staticmethod
    def _latency_population_line(report: HarAnalysisReport) -> str:
        population = report.latency_population
        if population is None:
            return ""
        return (
            f"Percentiles cover the {population.measured_count:,} request(s) answered over "
            f"the network; excluded: {population.browser_cache_hit_count:,} browser-cache "
            f"hit(s), {population.aborted_count:,} aborted, "
            f"{population.network_error_count:,} network error(s)"
        )

    def _print_frontend_section(self, report: HarAnalysisReport) -> None:
        """SECTION 3: generic front-end advice, kept apart from backend findings."""
        frontend_findings = [f for f in report.key_findings if f.frontend]
        if frontend_findings or report.compression_analysis or report.cache_analysis:
            console.print()
            console.rule("[bold]Informational (front-end)[/bold]")
        if frontend_findings:
            self._print_findings_panel(frontend_findings, "Front-end Suggestions", "blue")

        if report.compression_analysis:
            console.print()
            self._print_compression_analysis(report)

        if report.cache_analysis:
            console.print()
            self._print_cache_analysis(report)

    def _print_findings_panel(self, findings: list[KeyFinding], title: str, border: str) -> None:
        """Print a panel of findings."""
        severity_colors = {
            IssueSeverity.CRITICAL: "red",
            IssueSeverity.HIGH: "orange1",
            IssueSeverity.MEDIUM: "yellow",
            IssueSeverity.LOW: "blue",
        }
        lines: list[str] = []
        for finding in findings:
            color = severity_colors[finding.severity]
            label = finding.severity.value.upper()
            lines.append(
                f"[{color}][bold]\\[{label}][/bold] {rich_escape(finding.summary)}[/{color}]"
            )
            lines.append(f"  [dim]{rich_escape(finding.recommendation)}[/dim]")
        console.print(
            Panel(
                "\n".join(lines),
                title=f"[bold {border}]{title}[/bold {border}]",
                border_style=border,
            )
        )

    def generate_markdown_report(self, report: HarAnalysisReport, har_filename: str) -> str:
        """Generate a factual markdown report."""
        lines: list[str] = []
        # SECTION 1: METADATA & INFRASTRUCTURE
        lines.extend(self._md_header(har_filename, report))
        lines.extend(self._md_key_findings([f for f in report.key_findings if not f.frontend]))
        lines.extend(self._md_hostnames(report))
        lines.extend(self._md_summary(report))
        lines.extend(self._md_infrastructure_details(report))
        # SECTION 2: PROBLEM ANALYSIS
        lines.extend(self._md_timeout_clusters(report))
        lines.extend(self._md_domain_health(report))
        lines.extend(self._md_outages(report))
        lines.extend(self._md_service_health(report))
        for section in self._error_evidence_sections(report):
            lines.extend(self._md_section(section))
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
        lines.extend(
            self._md_issue_group(
                title="Informational (redirects, aborted requests)",
                issues=self._filter_informational_issues(report.issues),
            )
        )
        lines.extend(self._md_top_endpoints(report))
        slowest = self._slowest_requests_section(report)
        if slowest:
            lines.extend(self._md_section(slowest))
        lines.extend(self._md_server_timings(report))
        lines.extend(self._md_error_bursts(report))
        # SECTION 3: INFORMATIONAL (FRONT-END)
        frontend_findings = [f for f in report.key_findings if f.frontend]
        frontend_lines = [
            *self._md_findings_list(frontend_findings),
            *self._md_compression_analysis(report),
            *self._md_cache_analysis(report),
        ]
        if frontend_lines:
            lines.extend(["## Informational (front-end)", "", *frontend_lines])
        return "\n".join(lines)

    def _md_header(self, har_filename: str, report: HarAnalysisReport) -> list[str]:
        lines = [f"# HAR Analysis Report: {har_filename}", ""]
        # Add report creation timestamp (always in local time)
        now = datetime.now().astimezone()
        lines.append(f"**Report Generated:** {now.isoformat(timespec='seconds')}")
        if self._timestamp_timezone_label:
            lines.append(f"**Timestamp Timezone:** {self._timestamp_timezone_label}")
        query_note = "shown (--show-query)" if self._show_query else "values redacted"
        lines.append(f"**Query strings:** {query_note}")
        if report.capture_tool:
            lines.append(f"**Captured with:** {report.capture_tool}")
        capture_notes = self._capture_note_lines(report)
        if capture_notes:
            lines.extend(["", "**Capture notes:**", ""])
            lines.extend(f"- {note}" for note in capture_notes)
        lines.extend(["", "**Thresholds used:**", ""])
        lines.extend(f"- {line}" for line in describe_thresholds(report.settings))
        lines.extend(["", "---", ""])
        return lines

    def _md_findings_list(self, findings: list[KeyFinding]) -> list[str]:
        lines: list[str] = []
        for finding in findings:
            severity_label = finding.severity.value.upper()
            lines.append(f"- **[{severity_label}]** {finding.summary} — *{finding.recommendation}*")
        if lines:
            lines.append("")
        return lines

    def _md_key_findings(self, findings: list[KeyFinding]) -> list[str]:
        if not findings:
            return []
        return ["## Key Findings", "", *self._md_findings_list(findings)]

    def _md_hostnames(self, report: HarAnalysisReport) -> list[str]:
        hostnames = self._extract_hostnames(report)
        lines = ["## Hostnames", ""]
        lines.extend([f"- {hostname}" for hostname in hostnames])
        lines.append("")
        return lines

    def _timing_rows(self, report: HarAnalysisReport) -> list[tuple[str, TimingStatistics]]:
        return [
            ("Overall", report.overall_timings),
            ("Queued in browser (client)", report.blocked_timings),
            ("DNS (network)", report.dns_timings),
            ("Connect excl. TLS (network)", report.connect_timings),
            ("SSL/TLS (network)", report.ssl_timings),
            ("Send (client)", report.send_timings),
            (self._ttfb_label(report), report.ttfb_timings),
            ("Receive (network)", report.receive_timings),
        ]

    def _response_class_lines(self, report: HarAnalysisReport) -> list[str]:
        """Status-class counts plus expected / aborted / network error breakdown."""
        lines = [
            f"{status_class}: {count:,}"
            for status_class, count in status_class_counts(report.status_codes).items()
        ]
        if report.expected_response_count:
            lines.append(
                f"expected (matched rules, not failures): {report.expected_response_count:,}"
            )
        if report.aborted_request_count:
            lines.append(
                f"aborted/cancelled by browser (informational): {report.aborted_request_count:,}"
            )
        if report.network_errors_by_category:
            by_type = ", ".join(
                f"{category} {count}"
                for category, count in report.network_errors_by_category.items()
            )
            lines.append(f"network errors by type: {by_type}")
        return lines

    def _md_summary(self, report: HarAnalysisReport) -> list[str]:
        total_status = sum(report.status_codes.values()) or 1

        lines = ["## Summary", ""]
        lines.append(f"- **Total Requests:** {report.total_requests:,}")
        lines.append(
            f"- **Total Duration (sum of request times):** {report.total_duration_ms / 1000:.1f}s"
        )
        if report.capture_start and report.capture_end:
            lines.append(
                "- **Capture Window:** "
                f"{self._format_timestamp(report.capture_start, timespec='milliseconds')} → "
                f"{self._format_timestamp(report.capture_end, timespec='milliseconds')}"
            )
            lines.append(
                f"- **Capture Duration:** "
                f"{_format_duration(report.capture_end - report.capture_start)}"
            )
        lines.append(
            "- **Total Transferred (best-effort):** "
            f"{report.total_bytes_transferred / 1024 / 1024:.1f} MB"
        )
        lines.extend(["", "### Timing Percentiles", "", self._latency_population_line(report), ""])
        lines.extend(
            f"- **{label}:** {format_percentiles(stats)}"
            for label, stats in self._timing_rows(report)
        )
        lines.extend(["", "### Responses", ""])
        lines.extend(f"- {line}" for line in self._response_class_lines(report))
        lines.extend(["", "### Status Codes", ""])
        lines.extend(
            [
                f"- **{code}:** {count:,} ({100 * count / total_status:.1f}%)"
                for code, count in sorted(report.status_codes.items())
            ]
        )
        lines.append("")
        if report.request_rate_stats:
            rr = report.request_rate_stats
            lines.append(
                f"- **Request Rate:** {rr.overall_requests_per_second:.2f} req/s "
                f"(peak: {rr.peak_requests_per_second:.0f} req/s)"
            )
            lines.append("")
        if report.phase_breakdown:
            lines.append("### Phase Breakdown (share of summed phase time)")
            lines.append("")
            lines.extend(
                f"- **{phase.phase_name}:** {phase.percentage_of_total:.0f}% "
                f"({phase.total_ms:.0f}ms)"
                for phase in report.phase_breakdown
                if phase.percentage_of_total >= 1.0
            )
            lines.append("")
        if report.referer_hostnames:
            lines.extend(self._md_referer_hostnames(report))
        return lines

    def _md_referer_hostnames(self, report: HarAnalysisReport) -> list[str]:
        lines = ["### Referer Hostnames", ""]
        for hostname, count in list(report.referer_hostnames.items())[:10]:
            lines.append(f"- `{hostname}`: {count:,}")
        lines.append("")
        return lines

    DOMAIN_HEALTH_HEADERS = (
        "Domain",
        "Requests",
        "Failures",
        "Failure Rate",
        "5xx",
        "NetErr",
        "Expected",
        "Aborted",
        "Tail total",
        "Round trip est.",
        "Most time in",
        "Status",
    )
    DOMAIN_HEALTH_NOTE = (
        "Round trip est. = median TCP connect time of new connections. Most time in: "
        "wait = time to first byte (round trip + proxies + application), network = DNS + "
        "connect + TLS + receive, client = browser queueing + send."
    )

    @staticmethod
    def _domain_health_cells(domain: DomainAnalysis) -> tuple[str, ...]:
        round_trip = (
            f"{domain.round_trip_estimate_ms:.0f}ms (n={domain.round_trip_sample_count})"
            if domain.round_trip_estimate_ms is not None
            else "-"
        )
        return (
            domain.domain,
            str(domain.total_requests),
            str(domain.failed_requests),
            f"{domain.error_rate:.1f}%",
            str(domain.server_error_count),
            str(domain.network_error_count),
            str(domain.expected_count),
            str(domain.aborted_count),
            format_tail(domain.timing_stats),
            round_trip,
            domain.dominant_bottleneck or "-",
            domain.health.value.upper(),
        )

    def _md_domain_health(self, report: HarAnalysisReport) -> list[str]:
        if not report.domains:
            return []
        return self._md_section(
            ReportSection(
                title="Domain Health Overview",
                note=self.DOMAIN_HEALTH_NOTE,
                headers=self.DOMAIN_HEALTH_HEADERS,
                rows=[self._domain_health_cells(domain) for domain in report.domains],
            )
        )

    def _md_service_health(self, report: HarAnalysisReport) -> list[str]:
        failing = self._failing_services(report.service_failures)
        if not failing:
            return []
        over_label = f">{report.settings.duration_exceeded_ms / 1000:g}s"
        lines = ["## Backend/API Service Health", ""]
        lines.append(
            f"| Domain | Method | Path | Req | OK | Expected | Aborted | NetErr | 5xx | 4xx | "
            f"{over_label} | ProblemRate | Tail total | Tail TTFB | Tail net |"
        )
        lines.append(
            "|--------|--------|------|-----|----|----------|---------|--------|-----|-----|------|"
            "------------|------------|-----------|----------|"
        )
        lines.extend([self._md_service_row(s) for s in failing])
        lines.append("")
        return lines

    def _md_outages(self, report: HarAnalysisReport) -> list[str]:
        outages = self._outages(report.service_failures)
        if not outages:
            return []
        lines = [f"## {self.OUTAGE_TITLE}", ""]
        lines.append(
            "| Domain | Method | Path | Req | NetErr | 5xx | 4xx | First Seen | Last Seen |"
        )
        lines.append("|--------|--------|------|-----|--------|-----|-----|-----------|----------|")
        lines.extend(
            [
                (
                    f"| `{s.domain}` | `{s.method}` | `{md_cell(s.path)}` | {s.request_count} | "
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
            lines.append(f"  - {key}: {self._display_detail(value)}")
        lines.append("")
        return lines

    def _md_top_endpoints(self, report: HarAnalysisReport) -> list[str]:
        filtered_endpoints = [
            e for e in report.endpoints if not self._is_static_asset(e.url_pattern)
        ]
        if not filtered_endpoints:
            return []
        lines = ["## Top 10 Slowest Endpoints (path templates)", ""]
        lines.append(
            "Tail = p95 when n ≥ 20, otherwise max. IDs in paths are templated "
            "(`{uuid}`, `{n}`, `{hex}`). " + self.DOMINANT_SIDE_NOTE
        )
        lines.append("")
        lines.append(
            "| Endpoint Template | Count | Tail total | Tail TTFB | Tail net | Most time in |"
        )
        lines.append("|-------------------|-------|------------|-----------|----------|----------|")
        for endpoint in filtered_endpoints[:MARKDOWN_TOP_ENDPOINTS]:
            path = urlparse(endpoint.url_pattern).path
            lines.append(
                f"| `{md_cell(path)}` | {endpoint.count} | {format_tail(endpoint.timings)} | "
                f"{format_tail(endpoint.ttfb_timings)} | "
                f"{format_tail(endpoint.network_total_timings)} | "
                f"**{self._dominant_side(endpoint)}** |"
            )
            if self._is_templated(endpoint):
                examples = ", ".join(
                    f"`{md_cell(self._extract_path(u))}`" for u in endpoint.examples
                )
                lines.append(f"| ↳ e.g. {examples} | | | | | |")
        lines.append("")
        return lines

    @staticmethod
    def _is_templated(endpoint: EndpointStats) -> bool:
        """True when the template differs from the concrete example paths."""
        template = urlparse(endpoint.url_pattern).path
        return any(urlparse(url).path != template for url in endpoint.examples)

    DOMINANT_SIDE_NOTE = (
        "Most time in: wait = time to first byte (network round trip + proxies + "
        "application); receive = body transfer or a response streamed as it is produced; "
        "network = DNS + connect + TLS. Compared on summed time for the endpoint."
    )

    @staticmethod
    def _dominant_side(endpoint: EndpointStats) -> str:
        """Where the endpoint's summed time went: ``wait``, ``receive``, ``network``, ``-``."""
        wait_total = endpoint.ttfb_timings.total_duration_ms
        network_total = endpoint.network_total_timings.total_duration_ms
        if wait_total <= 0 and network_total <= 0:
            return "-"
        if wait_total >= network_total:
            return "wait"
        if endpoint.receive_timings.total_duration_ms * 2 >= network_total:
            return "receive"
        return "network"

    def _extract_hostnames(self, report: HarAnalysisReport) -> list[str]:
        hostnames: set[str] = set()
        for endpoint in report.endpoints:
            parsed = urlparse(endpoint.url_pattern)
            if parsed.netloc:
                hostnames.add(f"{parsed.scheme}://{parsed.netloc}")
        return sorted(hostnames)

    def _extract_path(self, url: str) -> str:
        """Path plus query with values redacted (unless --show-query)."""
        return redact_url(url, show_query=self._show_query)

    def _display_detail(self, value: object) -> str:
        """Render an issue detail value, redacting any URLs it contains."""
        if isinstance(value, list):
            items = [self._display_detail(item) for item in cast("list[object]", value)]
            return " → ".join(items)
        text = str(value)
        status, _, maybe_url = text.partition(" ")
        if maybe_url and status.isdigit() and ("://" in maybe_url or maybe_url.startswith("/")):
            return f"{status} {self._extract_path(maybe_url)}"
        if "://" in text or (text.startswith("/") and ("?" in text or "#" in text)):
            return self._extract_path(text)
        return text

    def _print_summary(self, report: HarAnalysisReport) -> None:
        hostnames = self._extract_hostnames(report)
        total_transferred_mb = report.total_bytes_transferred / 1024 / 1024

        summary_lines: list[str] = ["**Hostnames:**", *[f"- {h}" for h in hostnames], ""]
        if report.capture_tool:
            summary_lines.extend([f"**Captured with:** {report.capture_tool}", ""])
        capture_notes = self._capture_note_lines(report)
        if capture_notes:
            summary_lines.append("**Capture notes:**")
            summary_lines.extend(f"- {note}" for note in capture_notes)
            summary_lines.append("")
        summary_lines.append(f"**Total Requests:** {report.total_requests:,}")
        summary_lines.append("")
        summary_lines.append(
            f"**Total Duration (sum of request times):** {report.total_duration_ms / 1000:.1f}s"
        )
        summary_lines.append("")
        if report.capture_start and report.capture_end:
            summary_lines.append(
                "**Capture Window:** "
                f"{self._format_timestamp(report.capture_start, timespec='milliseconds')} → "
                f"{self._format_timestamp(report.capture_end, timespec='milliseconds')}"
            )
            summary_lines.append("")
            summary_lines.append(
                f"**Capture Duration:** "
                f"{_format_duration(report.capture_end - report.capture_start)}"
            )
            summary_lines.append("")
        if self._timestamp_timezone_label:
            summary_lines.append(f"**Timestamp Timezone:** {self._timestamp_timezone_label}")
            summary_lines.append("")
        summary_lines.append(f"**Total Transferred (best-effort):** {total_transferred_mb:.1f} MB")
        summary_lines.extend(
            ["", "**Timing Percentiles:**", "", self._latency_population_line(report), ""]
        )
        summary_lines.extend(
            self._format_timing_line(label, stats) for label, stats in self._timing_rows(report)
        )
        summary_lines.extend(["", "**Responses:**"])
        summary_lines.extend(f"- {line}" for line in self._response_class_lines(report))
        summary_lines.extend(
            ["", "**Status Codes:**", self._format_status_codes(report.status_codes)]
        )

        if report.request_rate_stats:
            summary_lines.append("")
            rr = report.request_rate_stats
            summary_lines.append(
                f"**Request Rate:** {rr.overall_requests_per_second:.2f} req/s "
                f"(peak: {rr.peak_requests_per_second:.0f} req/s)"
            )

        if report.phase_breakdown:
            summary_lines.append("")
            summary_lines.append("**Phase Breakdown (share of summed phase time):**")
            summary_lines.extend(
                f"- {phase.phase_name}: {phase.percentage_of_total:.0f}% ({phase.total_ms:.0f}ms)"
                for phase in report.phase_breakdown
                if phase.percentage_of_total >= 1.0
            )

        query_note = "shown (--show-query)" if self._show_query else "values redacted"
        summary_lines.extend(["", f"**Query strings:** {query_note}", "", "**Thresholds used:**"])
        summary_lines.extend(f"- {line}" for line in describe_thresholds(report.settings))

        console.print(
            Panel(
                Markdown("\n".join(summary_lines)),
                title="[bold green]HAR Analysis Summary[/bold green]",
                border_style="green",
            )
        )

    @property
    def show_query(self) -> bool:
        """True when query strings are printed unredacted."""
        return self._show_query

    def capture_note_lines(self, report: HarAnalysisReport) -> list[str]:
        """What was left out of or assumed about the capture."""
        return self._capture_note_lines(report)

    def format_timestamp(self, ts: datetime, *, timespec: str = "seconds") -> str:
        """Format a timestamp in the configured display timezone."""
        return self._format_timestamp(ts, timespec=timespec)

    def extract_path(self, url: str) -> str:
        """Path with query values redacted (unless --show-query)."""
        return self._extract_path(url)

    def response_class_lines(self, report: HarAnalysisReport) -> list[str]:
        """Status-class counts plus expected / aborted / network error breakdown."""
        return self._response_class_lines(report)

    def _format_timestamp(self, ts: datetime, *, timespec: str = "seconds") -> str:
        if self._timestamp_timezone is None:
            return ts.isoformat(timespec=timespec)
        return ts.astimezone(self._timestamp_timezone).isoformat(timespec=timespec)

    def _ttfb_label(self, report: HarAnalysisReport) -> str:
        """Label wait time honestly: it is not server time alone."""
        measured = report.latency_population.measured_count if report.latency_population else 0
        missing_ttfb_count = measured - report.ttfb_timings.count
        if missing_ttfb_count > 0:
            return (
                "Wait / TTFB (network round trip + proxies + application; "
                f"{missing_ttfb_count} of {measured} had none recorded)"
            )
        return "Wait / TTFB (network round trip + proxies + application)"

    def _format_timing_line(self, label: str, timing: TimingStatistics) -> str:
        return f"- {label}: {format_percentiles(timing)}"

    def _format_status_codes(self, status_codes: dict[int, int]) -> str:
        total = sum(status_codes.values()) or 1
        lines: list[str] = []
        for code, count in sorted(status_codes.items()):
            pct = 100 * count / total
            lines.append(f"- {code}: {count:,} ({pct:.1f}%)")
        return "\n".join(lines)

    def _print_domain_health(self, report: HarAnalysisReport) -> None:
        caption = self.DOMAIN_HEALTH_NOTE
        if len(report.domains) > DOMAIN_TABLE_MAX_ROWS:
            caption += f" ... and {len(report.domains) - DOMAIN_TABLE_MAX_ROWS} more domains"
        table = Table(title="Domain Health Overview", caption=caption)
        for header in self.DOMAIN_HEALTH_HEADERS:
            table.add_column(header, justify="left" if header == "Domain" else "right")
        health_styles = {
            DomainHealth.CRITICAL: "bold red",
            DomainHealth.DEGRADED: "yellow",
            DomainHealth.HEALTHY: "green",
        }
        for domain in report.domains[:DOMAIN_TABLE_MAX_ROWS]:
            *cells, status_text = self._domain_health_cells(domain)
            style = health_styles[domain.health]
            table.add_row(
                *(rich_escape(cell) for cell in cells), f"[{style}]{status_text}[/{style}]"
            )
        console.print(table)

    OUTAGE_TITLE = f"Outages (no success, {OUTAGE_MIN_FAILURES}+ 5xx/network failures)"

    def _outages(self, services: list[ServiceFailureStats]) -> list[ServiceFailureStats]:
        return [s for s in services if s.is_outage and not self._is_static_path(s.path)]

    def _failing_services(self, services: list[ServiceFailureStats]) -> list[ServiceFailureStats]:
        return [s for s in services if s.problem_count > 0 and not self._is_static_path(s.path)]

    def _print_outages(self, services: list[ServiceFailureStats], max_rows: int) -> None:
        outages = self._outages(services)
        if not outages:
            return

        table = Table(title=self.OUTAGE_TITLE)
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

    def _print_service_failures(self, report: HarAnalysisReport, max_rows: int) -> None:
        failing = self._failing_services(report.service_failures)
        if not failing:
            return

        table = Table(title="Backend/API Service Health")
        table.add_column("Domain", style="cyan", no_wrap=False)
        table.add_column("Method", style="cyan", no_wrap=True)
        table.add_column("Path", style="cyan", no_wrap=False)
        table.add_column("Req", justify="right")
        table.add_column("OK", justify="right", style="green")
        table.add_column("Exp", justify="right", style="dim")
        table.add_column("Abrt", justify="right", style="dim")
        table.add_column("NetErr", justify="right", style="red")
        table.add_column("5xx", justify="right", style="red")
        table.add_column("4xx", justify="right", style="yellow")
        table.add_column(
            f">{report.settings.duration_exceeded_ms / 1000:g}s", justify="right", style="red"
        )
        table.add_column("ProblemRate", justify="right", style="bold")
        table.add_column("Tail total", justify="right")
        table.add_column("Tail TTFB", justify="right")
        table.add_column("Tail net", justify="right")

        for s in failing[:max_rows]:
            table.add_row(
                s.domain,
                s.method,
                s.path,
                str(s.request_count),
                str(s.success_count) if s.success_count else "-",
                str(s.expected_count) if s.expected_count else "-",
                str(s.aborted_count) if s.aborted_count else "-",
                str(s.network_error_count) if s.network_error_count else "-",
                str(s.status_5xx_count) if s.status_5xx_count else "-",
                str(s.status_4xx_count) if s.status_4xx_count else "-",
                str(s.duration_exceeded_count) if s.duration_exceeded_count else "-",
                f"{s.problem_rate * 100:.1f}%",
                format_tail(s.timings),
                format_tail(s.ttfb_timings),
                format_tail(s.network_total_timings),
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
                    f"[{color}]{rich_escape(issue.message)}[/{color}]: "
                    f"{rich_escape(method_str + path)} "
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

        table = Table(
            title="Top 10 Slowest Endpoints (path templates)",
            caption=f"Tail = p95 when n ≥ 20, otherwise max. {self.DOMINANT_SIDE_NOTE}",
        )
        table.add_column("Endpoint Template", style="cyan", no_wrap=False)
        table.add_column("Count", justify="right")
        table.add_column("Tail total", justify="right", style="yellow")
        table.add_column("Tail TTFB", justify="right", style="red")
        table.add_column("Tail net", justify="right")
        table.add_column("Most time in", justify="center")

        for endpoint in filtered[:MARKDOWN_TOP_ENDPOINTS]:
            table.add_row(
                urlparse(endpoint.url_pattern).path,
                str(endpoint.count),
                format_tail(endpoint.timings),
                format_tail(endpoint.ttfb_timings),
                format_tail(endpoint.network_total_timings),
                self._dominant_side(endpoint),
            )

        console.print(table)

    def _print_referer_hostnames(self, report: HarAnalysisReport) -> None:
        table = Table(title="Referer Hostnames")
        table.add_column("Referer Hostname", style="cyan", no_wrap=False)
        table.add_column("Requests", justify="right")

        for hostname, count in list(report.referer_hostnames.items())[:10]:
            table.add_row(hostname, str(count))

        console.print(table)

    def _md_service_row(self, s: ServiceFailureStats) -> str:
        return (
            f"| `{s.domain}` | `{s.method}` | `{md_cell(s.path)}` | {s.request_count} | "
            f"{s.success_count} | {s.expected_count} | {s.aborted_count} | "
            f"{s.network_error_count} | {s.status_5xx_count} | "
            f"{s.status_4xx_count} | {s.duration_exceeded_count} | {s.problem_rate * 100:.1f}% | "
            f"{format_tail(s.timings)} | {format_tail(s.ttfb_timings)} | "
            f"{format_tail(s.network_total_timings)} |"
        )

    def _filter_backend_error_issues(self, issues: list[DetectedIssue]) -> list[DetectedIssue]:
        error_types = {
            IssueType.NETWORK_ERROR,
            IssueType.SERVER_ERROR,
            IssueType.CLIENT_ERROR,
            IssueType.RATE_LIMITED,
        }
        return [
            i for i in issues if i.issue_type in error_types and not self._is_static_asset(i.url)
        ]

    def _filter_backend_perf_issues(self, issues: list[DetectedIssue]) -> list[DetectedIssue]:
        perf_types = {
            IssueType.DURATION_EXCEEDED,
            IssueType.SLOW_ENDPOINT,
            IssueType.BLOCKING,
            IssueType.LARGE_PAYLOAD,
            IssueType.REDIRECT_LOOP,
        }
        return [
            i for i in issues if i.issue_type in perf_types and not self._is_static_asset(i.url)
        ]

    def _filter_informational_issues(self, issues: list[DetectedIssue]) -> list[DetectedIssue]:
        info_types = {IssueType.REQUEST_ABORTED, IssueType.REDIRECT_CHAIN}
        return [i for i in issues if i.issue_type in info_types]

    @staticmethod
    def _is_static_asset(url: str) -> bool:
        """Check if a URL points to a static asset."""
        return _is_static_url(url)

    @staticmethod
    def _is_static_path(path: str) -> bool:
        """Heuristic for service paths to exclude static assets."""
        return _is_static_path(path)

    # -------------------------------------------------------------------------
    # Compression Analysis (Terminal)
    # -------------------------------------------------------------------------

    def _print_compression_analysis(self, report: HarAnalysisReport) -> None:
        """Print compression analysis panel."""
        comp = report.compression_analysis
        if not comp:
            return

        lines: list[str] = ["**Encoding Distribution:**"]
        for encoding, count in comp.encoding_distribution.items():
            pct = (
                count / comp.total_responses_analyzed * 100 if comp.total_responses_analyzed else 0
            )
            lines.append(f"- {encoding}: {count:,} ({pct:.1f}%)")
        lines.append("")

        if comp.compressible_uncompressed_count > 0:
            size_mb = comp.compressible_uncompressed_bytes / ONE_MEGABYTE
            lines.append(
                f"**Compression Opportunities:** {comp.compressible_uncompressed_count} "
                f"compressible response(s) sent without compression ({size_mb:.1f} MB)"
            )
        else:
            lines.append("**Compression Opportunities:** None detected")

        console.print(
            Panel(
                Markdown("\n".join(lines)),
                title="[bold magenta]Compression Analysis[/bold magenta]",
                border_style="magenta",
            )
        )

    # -------------------------------------------------------------------------
    # Cache Analysis (Terminal)
    # -------------------------------------------------------------------------

    @staticmethod
    def _cache_summary_lines(cache: CacheAnalysis) -> list[str]:
        return [
            f"**Served without a download:** {cache.served_without_download_ratio * 100:.1f}% "
            f"of {cache.cacheable_get_count:,} GET responses (200 or 304)",
            f"**Browser Cache Hits (memory/disk):** {cache.browser_cache_hit_count:,}",
            f"**304 Not Modified:** {cache.not_modified_count:,}",
            f"**Downloaded over the network (200):** {cache.network_download_count:,}",
            f"**Repeated Network Downloads:** {cache.repeated_download_request_count:,} "
            f"requests across {len(cache.repeated_downloads)} URL(s) fetched more than once "
            f"with no cache hit or 304",
        ]

    def _print_cache_analysis(self, report: HarAnalysisReport) -> None:
        """Print cache analysis panel."""
        cache = report.cache_analysis
        if not cache:
            return

        lines: list[str] = [f"- {line}" for line in self._cache_summary_lines(cache)]
        if cache.missing_cache_control_count > 0:
            lines.append(
                f"- **Missing Cache-Control:** {cache.missing_cache_control_count} "
                f"static asset URL(s) without Cache-Control header"
            )
        lines.append("")

        if cache.repeated_downloads:
            lines.append("**Top Repeated Downloads:**")
            for item in cache.repeated_downloads[:10]:
                path = self._extract_path(str(item["url"]))
                total_kb = int(item["total_bytes"]) / 1024
                lines.append(f"- `{path}` x{item['count']} ({total_kb:.0f} KB)")

        console.print(
            Panel(
                Markdown("\n".join(lines)),
                title="[bold blue]Cache Analysis[/bold blue]",
                border_style="blue",
            )
        )

    # -------------------------------------------------------------------------
    # Timeout Clusters and Server Timing
    # -------------------------------------------------------------------------

    TIMEOUT_CLUSTER_HEADERS = (
        "Ends at (since sent)",
        "Kind",
        "Requests",
        "Range",
        "Queued first (max)",
        "Statuses",
        "Endpoints",
        "Config match",
    )
    TIMEOUT_CLUSTER_KINDS = {  # noqa: RUF012 - read-only lookup table
        "gateway": "gateway/proxy (5xx)",
        "network": "network (no response)",
        "client_cancel": "cancelled by browser",
    }
    TIMEOUT_CLUSTER_NOTE = (
        "Failed (5xx / status 0) requests whose durations bunch at a round value. "
        "Durations run from when the request was sent, so browser queueing is excluded. "
        "5xx at a round value is consistent with a gateway, proxy or load-balancer "
        "timeout; requests cancelled by the browser point at a client-side timeout."
    )

    def _timeout_cluster_rows(self, report: HarAnalysisReport) -> list[tuple[str, ...]]:
        rows: list[tuple[str, ...]] = []
        for cluster in report.timeout_clusters:
            statuses = ", ".join(f"{code} x{count}" for code, count in cluster.status_codes.items())
            endpoints = ", ".join(
                f"{urlparse(url).path} ({count})" for url, count in cluster.endpoints.items()
            )
            rows.append(
                (
                    f"~{cluster.round_value_s:.1f}s",
                    self.TIMEOUT_CLUSTER_KINDS[cluster.kind],
                    str(cluster.request_count),
                    f"{cluster.min_ms / 1000:.2f}-{cluster.max_ms / 1000:.2f}s",
                    f"{cluster.max_queued_ms / 1000:.1f}s",
                    statuses,
                    endpoints,
                    "; ".join(cluster.matching_settings) or "-",
                )
            )
        return rows

    def _timeout_cluster_section(self, report: HarAnalysisReport) -> ReportSection:
        return ReportSection(
            title="Timeout Clusters",
            note=self.TIMEOUT_CLUSTER_NOTE,
            headers=self.TIMEOUT_CLUSTER_HEADERS,
            rows=self._timeout_cluster_rows(report),
        )

    def _print_timeout_clusters(self, report: HarAnalysisReport) -> None:
        self._print_section(self._timeout_cluster_section(report))

    def _md_timeout_clusters(self, report: HarAnalysisReport) -> list[str]:
        if not report.timeout_clusters:
            return []
        return self._md_section(self._timeout_cluster_section(report))

    @staticmethod
    def _has_server_timings(report: HarAnalysisReport) -> bool:
        return any(e.server_timings for e in report.endpoints)

    def _server_timing_rows(self, report: HarAnalysisReport) -> list[tuple[str, ...]]:
        rows: list[tuple[str, ...]] = []
        for endpoint in report.endpoints:
            for metric, stats in endpoint.server_timings.items():
                rows.append(
                    (
                        urlparse(endpoint.url_pattern).path,
                        metric,
                        format_tail(stats),
                        f"{stats.p50:.0f}ms",
                        format_tail(endpoint.ttfb_timings),
                    )
                )
        return rows

    def _server_timing_section(self, report: HarAnalysisReport) -> ReportSection:
        return ReportSection(
            title="Server-Reported Timing vs TTFB",
            note=(
                "From Server-Timing, X-Response-Time and X-Runtime response headers. TTFB "
                "much larger than the application's own time points at the proxy/network path."
            ),
            headers=("Endpoint Template", "Metric", "Tail", "p50", "Tail TTFB"),
            rows=self._server_timing_rows(report),
        )

    def _print_server_timings(self, report: HarAnalysisReport) -> None:
        self._print_section(self._server_timing_section(report))

    def _md_server_timings(self, report: HarAnalysisReport) -> list[str]:
        if not self._has_server_timings(report):
            return []
        return self._md_section(self._server_timing_section(report))

    # -------------------------------------------------------------------------
    # Error Bursts (Terminal)
    # -------------------------------------------------------------------------

    ERROR_RUN_TITLE = (
        f"Error Runs ({HarAnalyzer.ERROR_BURST_MIN_ERRORS}+ errors, each starting within "
        f"{HarAnalyzer.ERROR_BURST_WINDOW_MS / 1000:g}s of the previous)"
    )

    def _print_error_bursts(self, report: HarAnalysisReport) -> None:
        """Print error burst detection results."""
        if not report.error_bursts:
            return

        table = Table(title=self.ERROR_RUN_TITLE)
        table.add_column("Start", style="dim")
        table.add_column("End", style="dim")
        table.add_column("Errors", justify="right", style="red")
        table.add_column("Affected Domains", style="cyan", no_wrap=False)

        for burst in report.error_bursts[:10]:
            table.add_row(
                self._format_timestamp(burst.start_time, timespec="seconds"),
                self._format_timestamp(burst.end_time, timespec="seconds"),
                str(burst.error_count),
                ", ".join(burst.affected_domains),
            )

        console.print(table)

    # -------------------------------------------------------------------------
    # Infrastructure Details (Terminal)
    # -------------------------------------------------------------------------

    def _print_infrastructure_details(self, report: HarAnalysisReport) -> None:
        """Print infrastructure and metadata details panel."""
        lines: list[str] = []

        # HTTP Version Distribution
        if report.http_version_distribution:
            lines.append("**HTTP Versions:**")
            for version, count in report.http_version_distribution.items():
                pct = 100 * count / report.total_requests if report.total_requests else 0
                lines.append(f"- {version}: {count:,} ({pct:.1f}%)")
            lines.append("")

        # Server Software (condensed)
        if report.server_software_by_domain:
            lines.append("**Server Software:**")
            for domain, servers in list(report.server_software_by_domain.items())[
                :SERVER_SOFTWARE_MAX_DOMAINS
            ]:
                server_str = ", ".join(f"{s} ({c})" for s, c in servers.items())
                lines.append(f"- `{domain}`: {server_str}")
            if len(report.server_software_by_domain) > SERVER_SOFTWARE_MAX_DOMAINS:
                remaining = len(report.server_software_by_domain) - SERVER_SOFTWARE_MAX_DOMAINS
                lines.append(f"- *... and {remaining} more domains*")
            lines.append("")

        # Connection Reuse
        if report.connection_reuse_stats:
            stats = report.connection_reuse_stats
            lines.append("**Connection Reuse:**")
            lines.append(f"- Unique connections: {stats.unique_connections:,}")
            lines.append(f"- Requests per connection: {stats.reuse_ratio:.1f}")
            lines.append("")
        elif report.total_requests:
            lines.append("**Connection Reuse:**")
            lines.append(f"- {CONNECTION_REUSE_UNAVAILABLE_MSG}")
            lines.append("")

        availability = self._availability_lines(report)
        if availability:
            lines.append("**Not available in this capture:**")
            lines.extend(f"- {line}" for line in availability)
            lines.append("")

        if lines:
            console.print(
                Panel(
                    Markdown("\n".join(lines)),
                    title="[bold cyan]Infrastructure Details[/bold cyan]",
                    border_style="cyan",
                )
            )

    def _print_server_ips_table(self, report: HarAnalysisReport) -> None:
        """Print server IPs by domain as a table."""
        if not report.server_ips_by_domain:
            return

        table = Table(title="Server IP Addresses by Domain")
        table.add_column("Domain", style="cyan", no_wrap=False)
        table.add_column("Server IPs", style="green", no_wrap=False)

        for domain, ips in list(report.server_ips_by_domain.items())[:SERVER_IPS_TABLE_MAX_ROWS]:
            table.add_row(domain, ", ".join(ips))

        if len(report.server_ips_by_domain) > SERVER_IPS_TABLE_MAX_ROWS:
            remaining = len(report.server_ips_by_domain) - SERVER_IPS_TABLE_MAX_ROWS
            table.add_row(f"... and {remaining} more", "", style="dim")

        console.print(table)

    def _print_time_gaps_table(self, report: HarAnalysisReport) -> None:
        """Print significant time gaps between requests."""
        if not report.time_gaps:
            return

        table = Table(
            title=f"Idle Periods (>{report.settings.idle_gap_ms:g}ms with no request in flight)"
        )
        table.add_column("Idle", style="yellow", justify="right")
        table.add_column("After Request", style="cyan", no_wrap=False)
        table.add_column("Timestamp", style="dim")

        for gap in report.time_gaps[:TIME_GAP_TABLE_MAX_ROWS]:
            path = self._extract_path(gap.after_url)
            gap_seconds = gap.gap_duration_ms / 1000
            table.add_row(
                f"{gap_seconds:.1f}s",
                path[:PATH_TRUNCATE_LONG] if len(path) > PATH_TRUNCATE_LONG else path,
                self._format_timestamp(gap.after_timestamp, timespec="seconds"),
            )

        if len(report.time_gaps) > TIME_GAP_TABLE_MAX_ROWS:
            remaining = len(report.time_gaps) - TIME_GAP_TABLE_MAX_ROWS
            table.add_row(f"... and {remaining} more", "", "", style="dim")

        console.print(table)

    @staticmethod
    def _large_request_bodies_title(report: HarAnalysisReport) -> str:
        return f"Large Request Bodies (>{format_bytes(report.settings.large_request_body_bytes)})"

    def _print_large_request_bodies_table(self, report: HarAnalysisReport) -> None:
        """Print large request bodies (POST/PUT payloads)."""
        if not report.large_request_bodies:
            return

        table = Table(title=self._large_request_bodies_title(report))
        table.add_column("Size", style="yellow", justify="right")
        table.add_column("Method", style="cyan")
        table.add_column("URL Path", style="cyan", no_wrap=False)
        table.add_column("Content-Type", style="dim")

        for body in report.large_request_bodies[:LARGE_REQUEST_BODY_TABLE_MAX_ROWS]:
            path = self._extract_path(body.url)
            size_str = format_bytes(body.body_size_bytes)
            table.add_row(
                size_str,
                body.method,
                path[:PATH_TRUNCATE_MEDIUM] if len(path) > PATH_TRUNCATE_MEDIUM else path,
                body.content_type[:30] if body.content_type else "-",
            )

        if len(report.large_request_bodies) > LARGE_REQUEST_BODY_TABLE_MAX_ROWS:
            remaining = len(report.large_request_bodies) - LARGE_REQUEST_BODY_TABLE_MAX_ROWS
            table.add_row(f"... and {remaining} more", "", "", "", style="dim")

        console.print(table)

    # -------------------------------------------------------------------------
    # Infrastructure Details (Markdown)
    # -------------------------------------------------------------------------

    def _md_infrastructure_details(self, report: HarAnalysisReport) -> list[str]:
        """Generate markdown for infrastructure details section."""
        lines: list[str] = ["## Infrastructure Details", ""]

        # HTTP Version Distribution
        if report.http_version_distribution:
            lines.append("### HTTP Versions")
            lines.append("")
            for version, count in report.http_version_distribution.items():
                pct = 100 * count / report.total_requests if report.total_requests else 0
                lines.append(f"- **{version}:** {count:,} ({pct:.1f}%)")
            lines.append("")

        # Server Software by Domain
        if report.server_software_by_domain:
            lines.append("### Server Software by Domain")
            lines.append("")
            lines.append("| Domain | Server Software |")
            lines.append("|--------|-----------------|")
            for domain, servers in list(report.server_software_by_domain.items())[
                :SERVER_SOFTWARE_MAX_DOMAINS
            ]:
                server_str = ", ".join(f"{s} ({c})" for s, c in servers.items())
                lines.append(f"| `{domain}` | {server_str} |")
            lines.append("")

        # Server IPs by Domain
        if report.server_ips_by_domain:
            lines.append("### Server IP Addresses by Domain")
            lines.append("")
            lines.append("| Domain | IPs |")
            lines.append("|--------|-----|")
            for domain, ips in list(report.server_ips_by_domain.items())[
                :SERVER_IPS_TABLE_MAX_ROWS
            ]:
                lines.append(f"| `{domain}` | {', '.join(ips)} |")
            lines.append("")

        # Connection Reuse Stats
        if report.connection_reuse_stats:
            stats = report.connection_reuse_stats
            lines.append("### Connection Reuse")
            lines.append("")
            lines.append(f"- **Unique connections:** {stats.unique_connections:,}")
            lines.append(f"- **Requests per connection:** {stats.reuse_ratio:.1f}")
            lines.append("")
        elif report.total_requests:
            lines.append("### Connection Reuse")
            lines.append("")
            lines.append(f"- {CONNECTION_REUSE_UNAVAILABLE_MSG}")
            lines.append("")

        availability = self._availability_lines(report)
        if availability:
            lines.extend(["### Not available in this capture", ""])
            lines.extend(f"- {line}" for line in availability)
            lines.append("")

        for section in self._infrastructure_sections(report):
            lines.extend(self._md_section(section, heading="###"))

        lines.extend(self._md_time_gaps(report))

        # Large Request Bodies
        lines.extend(self._md_large_request_bodies(report))

        return lines

    def _md_time_gaps(self, report: HarAnalysisReport) -> list[str]:
        """Generate markdown for idle periods."""
        if not report.time_gaps:
            return []
        lines: list[str] = []
        lines.append(
            f"### Idle Periods (>{report.settings.idle_gap_ms:g}ms with no request in flight)"
        )
        lines.append("")
        lines.append("| Idle | Next Request | Timestamp |")
        lines.append("|-----|---------------|-----------|")
        for gap in report.time_gaps[:TIME_GAP_TABLE_MAX_ROWS]:
            path = self._extract_path(gap.after_url)
            gap_seconds = gap.gap_duration_ms / 1000
            ts = self._format_timestamp(gap.after_timestamp, timespec="seconds")
            truncated_path = path[:PATH_TRUNCATE_SHORT] if len(path) > PATH_TRUNCATE_SHORT else path
            lines.append(f"| {gap_seconds:.1f}s | `{md_cell(truncated_path)}` | `{ts}` |")
        lines.append("")
        return lines

    def _md_large_request_bodies(self, report: HarAnalysisReport) -> list[str]:
        """Generate markdown for large request bodies section."""
        if not report.large_request_bodies:
            return []

        lines: list[str] = [
            f"### {self._large_request_bodies_title(report)}",
            "",
            "| Size | Method | Path | Content-Type |",
            "|------|--------|------|--------------|",
        ]
        for body in report.large_request_bodies[:LARGE_REQUEST_BODY_TABLE_MAX_ROWS]:
            path = self._extract_path(body.url)
            size_str = format_bytes(body.body_size_bytes)
            truncated_path = path[:PATH_TRUNCATE_TINY] if len(path) > PATH_TRUNCATE_TINY else path
            content_type = body.content_type[:25] if body.content_type else "-"
            lines.append(
                f"| {size_str} | `{body.method}` | `{md_cell(truncated_path)}` | "
                f"{md_cell(content_type)} |"
            )
        lines.append("")
        return lines

    # -------------------------------------------------------------------------
    # Advanced Analysis (Markdown)
    # -------------------------------------------------------------------------

    def _md_compression_analysis(self, report: HarAnalysisReport) -> list[str]:
        """Generate markdown for compression analysis."""
        comp = report.compression_analysis
        if not comp:
            return []

        lines: list[str] = ["## Compression Analysis", ""]
        lines.append("### Encoding Distribution")
        lines.append("")
        for encoding, count in comp.encoding_distribution.items():
            pct = (
                count / comp.total_responses_analyzed * 100 if comp.total_responses_analyzed else 0
            )
            lines.append(f"- **{encoding}:** {count:,} ({pct:.1f}%)")
        lines.append("")

        if comp.compressible_uncompressed_count > 0:
            size_mb = comp.compressible_uncompressed_bytes / ONE_MEGABYTE
            lines.append(
                f"**Compression Opportunities:** {comp.compressible_uncompressed_count} "
                f"compressible response(s) sent without compression ({size_mb:.1f} MB)"
            )
            lines.append("")

        return lines

    def _md_cache_analysis(self, report: HarAnalysisReport) -> list[str]:
        """Generate markdown for cache analysis."""
        cache = report.cache_analysis
        if not cache:
            return []

        lines: list[str] = ["## Cache Analysis", ""]
        lines.extend(f"- {line}" for line in self._cache_summary_lines(cache))
        if cache.missing_cache_control_count > 0:
            lines.append(
                f"- **Missing Cache-Control:** {cache.missing_cache_control_count} "
                f"static asset URL(s)"
            )
        lines.append("")

        if cache.repeated_downloads:
            lines.append("### Repeated Network Downloads")
            lines.append("")
            lines.append("| URL | Downloads | Total Size |")
            lines.append("|-----|-----------|------------|")
            for item in cache.repeated_downloads[:20]:
                path = self._extract_path(str(item["url"]))
                truncated = (
                    path[:PATH_TRUNCATE_MEDIUM] if len(path) > PATH_TRUNCATE_MEDIUM else path
                )
                total_kb = int(item["total_bytes"]) / 1024
                lines.append(f"| `{md_cell(truncated)}` | {item['count']} | {total_kb:.0f} KB |")
            lines.append("")

        return lines

    def _md_error_bursts(self, report: HarAnalysisReport) -> list[str]:
        """Generate markdown for error burst detection."""
        if not report.error_bursts:
            return []

        lines: list[str] = [f"## {self.ERROR_RUN_TITLE}", ""]
        lines.append("| Start | End | Errors | Affected Domains |")
        lines.append("|-------|-----|--------|------------------|")
        for burst in report.error_bursts[:10]:
            start = self._format_timestamp(burst.start_time, timespec="seconds")
            end = self._format_timestamp(burst.end_time, timespec="seconds")
            domains = ", ".join(burst.affected_domains)
            lines.append(f"| `{start}` | `{end}` | {burst.error_count} | {domains} |")
        lines.append("")
        return lines


# =============================================================================
# Event Export (shared events.jsonl format, see sas-casefile 00-architecture.md)
# =============================================================================

_TEMPLATE_PLACEHOLDER_RE = re.compile(r"\{[^/{}]+\}")


def _utc_millis(entry: HarEntry) -> tuple[str, str]:
    """Return (UTC ISO-8601 with ms and ``Z``, tz_source) for an entry start time."""
    utc_ts = entry.started_date_time.astimezone(UTC)
    tz_source = "assumed:UTC" if entry.timestamp_assumed_utc else "in-line"
    return utc_ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc_ts.microsecond // 1000:03d}Z", tz_source


def _template_hash(template: str) -> str:
    """First 12 hex chars of sha1(template), as in the shared signature format."""
    return hashlib.sha1(template.encode("utf-8"), usedforsecurity=False).hexdigest()[:12]


def build_events(har: Har, analyzer: HarAnalyzer, source_file: str) -> list[dict[str, Any]]:
    """One event per request, in the shared ``events.jsonl`` format.

    ``level`` is ERROR for 5xx and real network errors, WARN when the request took longer
    than the slow-endpoint threshold (WebSocket / event-stream connections excepted),
    otherwise INFO (expected and aborted included).
    Paths are templated and carry no query string; only allowlisted correlation headers
    are included.
    """
    events: list[dict[str, Any]] = []
    for position, entry in enumerate(har.log.entries, start=1):
        entry_index = entry.entry_index or position
        status = entry.response.status
        category = classify_network_error(entry)
        real_network_error = category is not None and category not in (
            INFORMATIONAL_ERROR_CATEGORIES
        )
        if real_network_error or (
            HarAnalyzer.HTTP_STATUS_SERVER_ERROR_MIN <= status < HarAnalyzer.HTTP_STATUS_ERROR_MAX
        ):
            level = "ERROR"
        elif entry.time > analyzer.settings.slow_endpoint_ms and long_lived_kind(entry) is None:
            level = "WARN"
        else:
            level = "INFO"

        path_template_value = analyzer.path_template(entry.request.url)
        suffix = f" [{category}]" if category else ""
        message = f"{entry.request.method} {path_template_value} -> {status}{suffix}"
        template = _TEMPLATE_PLACEHOLDER_RE.sub("<*>", message)
        ts, tz_source = _utc_millis(entry)

        attrs: dict[str, Any] = {
            "entry_index": entry_index,
            "method": entry.request.method,
            "path_template": path_template_value,
            "status": status,
            "ttfb_ms": entry.timings.wait if entry.timings.wait >= 0 else None,
            "expected": analyzer.is_expected(entry),
        }
        if category:
            attrs["error"] = entry.response.error
            attrs["error_category"] = category
        if entry.server_ip_address:
            attrs["server_ip"] = entry.server_ip_address
        if entry.from_cache:
            attrs["from_cache"] = entry.from_cache
        server_timings = parse_server_timings(entry.response.headers)
        if server_timings:
            attrs["server_timing_ms"] = server_timings
        correlation = correlation_headers(entry)
        if correlation:
            attrs["correlation"] = correlation

        events.append(
            {
                "ts": ts,
                "ts_raw": entry.started_date_time_raw
                or entry.started_date_time.isoformat(timespec="milliseconds"),
                "tz_source": tz_source,
                "source": "har",
                "host": urlparse(entry.request.url).netloc,
                "file": source_file,
                "line": None,
                "level": level,
                "thread": None,
                "logger": None,
                "message": message,
                "exception": None,
                "stack_signature": None,
                "template": template,
                "signature": f"har:{level}:{_template_hash(template)}",
                "duration_ms": entry.time,
                "attrs": attrs,
            }
        )
    return sorted(events, key=lambda ev: (ev["ts"], ev["attrs"]["entry_index"]))


def write_events(events: list[dict[str, Any]], path: Path) -> None:
    """Write events as JSON Lines atomically (temp file + replace)."""
    temp_path = path.with_name(f".{path.name}.tmp")
    with temp_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
    temp_path.replace(path)


# =============================================================================
# Brief Markdown (for M365 Copilot; <= ~5 KB)
# =============================================================================

BRIEF_MAX_BYTES = 5_120
_MS = "milliseconds"
BRIEF_PATH_MAX_CHARS = 60


def _ms_or_dash(value: float) -> str:
    return f"{value:.0f}" if value >= 0 else "-"


def _brief_lines(
    report: HarAnalysisReport,
    formatter: OutputFormatter,
    har_filename: str,
    row_limit: int,
) -> list[str]:
    def short(path: str) -> str:
        if len(path) <= BRIEF_PATH_MAX_CHARS:
            return path
        return path[: BRIEF_PATH_MAX_CHARS - 1] + "…"

    lines = [f"# HAR brief: {har_filename}", ""]
    if report.capture_start and report.capture_end:
        lines.append(
            f"- Capture: {formatter.format_timestamp(report.capture_start, timespec=_MS)}"
            f" → {formatter.format_timestamp(report.capture_end, timespec=_MS)} "
            f"({_format_duration(report.capture_end - report.capture_start)}), "
            f"{report.total_requests:,} requests; query values "
            f"{'shown (--show-query)' if formatter.show_query else 'redacted'}"
        )
    lines.extend(f"- {note}" for note in formatter.capture_note_lines(report))
    lines.append("- " + "; ".join(formatter.response_class_lines(report)))
    lines.append("")

    backend_findings = [f for f in report.key_findings if not f.frontend]
    if backend_findings:
        lines.append("## Findings")
        lines.extend(
            f"- [{f.severity.value.upper()}] {f.summary}" for f in backend_findings[:row_limit]
        )
        lines.append("")

    if report.timeout_clusters:
        lines.append("## Timeout clusters")
        for cluster in report.timeout_clusters[:row_limit]:
            statuses = ", ".join(f"{code}x{count}" for code, count in cluster.status_codes.items())
            if cluster.matching_settings:
                match = "matches " + "; ".join(cluster.matching_settings)
            elif report.config_facts_loaded:
                match = "no loaded config setting matches"
            else:
                match = "no config facts loaded"
            kind = OutputFormatter.TIMEOUT_CLUSTER_KINDS[cluster.kind]
            lines.append(
                f"- {cluster.request_count} req at ~{cluster.round_value_s:.0f}s after send "
                f"({cluster.min_ms / 1000:.1f}-{cluster.max_ms / 1000:.1f}s, {statuses}; "
                f"{kind}): {match}"
            )
        lines.append("")

    ranked = sorted(
        (e for e in report.endpoints if e.ttfb_timings.count),
        key=lambda e: -tail_value(e.ttfb_timings),
    )
    if ranked:
        lines.append("## Endpoints by wait for first byte (TTFB; tail = p95, or max when n<20)")
        lines.append("| Endpoint | n | TTFB tail | TTFB p50 | Total tail |")
        lines.append("|---|---|---|---|---|")
        lines.extend(
            f"| {short(urlparse(e.url_pattern).path)} | {e.ttfb_timings.count} | "
            f"{tail_value(e.ttfb_timings):.0f} ({tail_label(e.ttfb_timings)}) | "
            f"{e.ttfb_timings.p50:.0f} | {tail_value(e.timings):.0f} |"
            for e in ranked[:row_limit]
        )
        lines.append("")

    if report.slowest_requests:
        lines.append("## Slowest requests (ms; - = not recorded)")
        lines.append(
            "| Start | Request | Status | Total | Block | DNS | Conn | TLS | Send | Wait | Recv |"
        )
        lines.append("|---|---|---|---|---|---|---|---|---|---|---|")
        for req in report.slowest_requests[:row_limit]:
            status = f"{req.status}" + (f" {req.error_category}" if req.error_category else "")
            lines.append(
                f"| {formatter.format_timestamp(req.started)} | {req.method} "
                f"{short(formatter.extract_path(req.url))} | {status} | {req.total_ms:.0f} | "
                f"{_ms_or_dash(req.blocked_ms)} | {_ms_or_dash(req.dns_ms)} | "
                f"{_ms_or_dash(req.connect_excl_tls_ms)} | {_ms_or_dash(req.tls_ms)} | "
                f"{_ms_or_dash(req.send_ms)} | {_ms_or_dash(req.wait_ms)} | "
                f"{_ms_or_dash(req.receive_ms)} |"
            )
        lines.append("")

    settings = report.settings
    lines.append(
        f"Thresholds: slow>{settings.slow_endpoint_ms:g}ms, idle gap>{settings.idle_gap_ms:g}ms, "
        f"timeout cluster≥{settings.timeout_cluster_min_requests}@±"
        f"{settings.timeout_cluster_tolerance_pct:g}%, expected: "
        f"{', '.join(settings.expected_rules) or 'none'}"
    )
    return lines


def generate_brief_report(
    report: HarAnalysisReport, formatter: OutputFormatter, har_filename: str
) -> str:
    """Compact Markdown for Copilot; rows are reduced until it fits BRIEF_MAX_BYTES."""
    row_limit = 10
    text = ""
    while row_limit >= 1:
        text = "\n".join(_brief_lines(report, formatter, har_filename, row_limit)) + "\n"
        if len(text.encode("utf-8")) <= BRIEF_MAX_BYTES:
            return text
        row_limit -= 1
    note = f"\n(truncated to {BRIEF_MAX_BYTES} bytes)\n"
    encoded = text.encode("utf-8")[: BRIEF_MAX_BYTES - len(note.encode("utf-8"))]
    return encoded.decode("utf-8", errors="ignore") + note


# =============================================================================
# CLI
# =============================================================================

app = typer.Typer(
    name="har-analyze",
    help="Analyze HAR files with deterministic performance insights",
    add_completion=False,
)


@app.callback()
def callback() -> None:
    """HAR file analyzer with deterministic performance insights."""


@app.command()
def version() -> None:
    """Show version information."""
    typer.echo(f"har-analyze version {__version__}")


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


_DEFAULT_SETTINGS = AnalyzerSettings()


@app.command()
def analyze(  # noqa: PLR0913 - one parameter per CLI option is how typer works
    har_file: Path = typer.Argument(  # noqa: B008
        ..., exists=True, file_okay=True, dir_okay=False, readable=True, help="Path to HAR file"
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None, "--output", "-o", help="Export analysis to Markdown file"
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
    brief: bool = typer.Option(
        False, "--brief", help="Compact Markdown (<= ~5 KB) for Copilot; no front-end advice"
    ),
    show_query: bool = typer.Option(
        False, "--show-query", help="Print query strings and fragments unredacted"
    ),
    export_events: Path | None = typer.Option(  # noqa: B008
        None, "--export-events", help="Write one event per request to FILE.events.jsonl"
    ),
    config_facts: Path | None = typer.Option(  # noqa: B008
        None,
        "--config-facts",
        exists=True,
        dir_okay=False,
        help="config_facts.json from `sas-casefile config` to name matching timeout settings",
    ),
    expect: list[str] | None = typer.Option(  # noqa: B008
        None,
        "--expect",
        help="Expected response rule STATUS:PATH_GLOB (repeatable), e.g. 401:/SASLogon/*",
    ),
    no_default_expect: bool = typer.Option(
        False,
        "--no-default-expect",
        help=f"Drop the default expected rules ({', '.join(DEFAULT_EXPECTED_RULES)})",
    ),
    path_rule: list[str] | None = typer.Option(  # noqa: B008
        None,
        "--path-rule",
        help="Template path segments fully matching REGEX as {NAME}: REGEX=NAME (repeatable)",
    ),
    slow_ms: float = typer.Option(
        _DEFAULT_SETTINGS.slow_endpoint_ms,
        "--slow-ms",
        help="Slow endpoint threshold on p95 (max when n<20)",
    ),
    duration_exceeded_ms: float = typer.Option(
        _DEFAULT_SETTINGS.duration_exceeded_ms,
        "--duration-exceeded-ms",
        help="Flag individual requests longer than this",
    ),
    gap_ms: float = typer.Option(
        _DEFAULT_SETTINGS.idle_gap_ms, "--gap-ms", help="Report idle periods longer than this"
    ),
    blocking_ms: float = typer.Option(
        _DEFAULT_SETTINGS.blocking_ms, "--blocking-ms", help="Client-side blocking threshold"
    ),
    large_payload_bytes: int = typer.Option(
        _DEFAULT_SETTINGS.large_payload_bytes,
        "--large-payload-bytes",
        help="Large response threshold",
    ),
    large_request_body_bytes: int = typer.Option(
        _DEFAULT_SETTINGS.large_request_body_bytes,
        "--large-request-body-bytes",
        help="Large POST/PUT body threshold",
    ),
    redirect_chain_min_hops: int = typer.Option(
        _DEFAULT_SETTINGS.redirect_chain_min_hops,
        "--redirect-chain-min-hops",
        min=1,
        help="Report redirect chains with at least this many hops",
    ),
    timeout_cluster_min: int = typer.Option(
        _DEFAULT_SETTINGS.timeout_cluster_min_requests,
        "--timeout-cluster-min",
        min=2,
        help="Minimum failed requests to form a timeout cluster",
    ),
    timeout_tolerance_pct: float = typer.Option(
        _DEFAULT_SETTINGS.timeout_cluster_tolerance_pct,
        "--timeout-tolerance-pct",
        min=0.1,
        help="Timeout cluster width (±%)",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging"),
) -> None:
    """Analyze a HAR file and generate performance insights."""
    setup_logging(verbose)

    timestamp_timezone, timestamp_timezone_label = _resolve_timestamp_timezone(timezone, local_time)

    expected_rules = [] if no_default_expect else list(DEFAULT_EXPECTED_RULES)
    expected_rules.extend(expect or [])
    settings = AnalyzerSettings(
        slow_endpoint_ms=slow_ms,
        duration_exceeded_ms=duration_exceeded_ms,
        large_payload_bytes=large_payload_bytes,
        blocking_ms=blocking_ms,
        idle_gap_ms=gap_ms,
        large_request_body_bytes=large_request_body_bytes,
        redirect_chain_min_hops=redirect_chain_min_hops,
        timeout_cluster_min_requests=timeout_cluster_min,
        timeout_cluster_tolerance_pct=timeout_tolerance_pct,
        expected_rules=expected_rules,
        path_rules=list(path_rule or []),
    )
    try:
        analyzer = HarAnalyzer(
            settings,
            config_facts=load_config_facts(config_facts) if config_facts else None,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    try:
        # Parse HAR file
        logger.info(f"Parsing HAR file: {har_file}")
        # utf-8-sig: Windows tools write a byte-order mark that plain utf-8 rejects
        with har_file.open("r", encoding="utf-8-sig") as f:
            raw_data = json.load(f)
        har = load_har(raw_data)
        logger.info(f"Parsed {len(har.log.entries)} entries")
        if har.load_notes.skipped_entry_count:
            typer.echo(
                f"Warning: skipped {har.load_notes.skipped_entry_count} malformed entries: "
                f"{'; '.join(har.load_notes.skipped_entry_reasons)}",
                err=True,
            )

        report = analyzer.analyze(har)
        logger.info(f"Detected {len(report.issues)} issues")

        if export_events:
            events = build_events(har, analyzer, har_file.name)
            write_events(events, export_events)
            logger.info(f"Wrote {len(events)} events to {export_events}")

        formatter = OutputFormatter(
            timestamp_timezone=timestamp_timezone,
            timestamp_timezone_label=timestamp_timezone_label,
            show_query=show_query,
        )

        if brief:
            brief_content = generate_brief_report(report, formatter, har_file.name)
            if output:
                write_text_atomic(output, brief_content)
                typer.echo(f"Brief report exported to: {output}")
            else:
                typer.echo(brief_content, nl=False)
        elif output:
            markdown_content = formatter.generate_markdown_report(report, har_file.name)
            write_text_atomic(output, markdown_content)
            typer.echo(f"Markdown report exported to: {output}")
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
