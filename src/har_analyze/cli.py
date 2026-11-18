#!/usr/bin/env python3
"""HAR Analyze CLI.

Analyze HAR files with deterministic performance insights.
"""

from __future__ import annotations

__version__ = "0.1.0"

import base64
import binascii
import hashlib
import json
import logging
import math
import re
import statistics
from collections import defaultdict
from collections.abc import Callable
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
from pydantic import (
    BaseModel,
    Field,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)
from rich.console import Console
from rich.markdown import Markdown
from rich.markup import escape as rich_escape
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from ._jsonstream import JSONStreamError, ObjectBuilder, iter_json_events

HTTP_STATUS_MIN = 100
HTTP_STATUS_BAD_REQUEST = 400
HTTP_STATUS_NOT_MODIFIED = 304
HTTP_STATUS_BAD_GATEWAY = 502
HTTP_STATUS_GATEWAY_TIMEOUT = 504

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
# HAR Models (HTTP Archive 1.2 spec, plus the producer extensions seen in practice)
# =============================================================================
#
# What each producer writes was established against a ground-truth server (see the
# README, "How accuracy is verified"). The normalisation below turns those
# conventions into one model:
#
# * Chrome DevTools: failed requests have ``status`` 0 and ``_error``; ``bodySize`` is
#   negative (``-headersSize``) when nothing was transferred, and -1 on HTTP/2;
#   ``connection`` holds the server port while ``_connectionId`` is the socket; cache
#   hits carry ``_fromCache``; service-worker answers carry ``_fetchedViaServiceWorker``;
#   uploads are recorded with ``bodySize`` 0 and no ``postData``.
# * Playwright (Chromium, Firefox, WebKit): failed requests have ``status`` -1, ``time``
#   -1 and ``_failureText``; ``ssl`` is a made-up value on plain HTTP and ``time``
#   counts the TLS handshake twice on HTTPS (``connect`` already contains it).
# * mitmproxy: no pages, no ``blocked``/``dns``; ``content.size`` is the encoded size
#   and ``content.compression`` the bytes saved; errors are free text in ``_error``.

HTTP_STATUS_MAX = 999
# One name per timing phase, used by every output.
PHASE_DISPLAY_NAMES = {
    "Blocked": "Queued",
    "DNS": "DNS",
    "Connect (excl. TLS)": "TCP connect",
    "SSL": "TLS",
    "Send": "Send",
    "TTFB": "Wait (TTFB)",
    "Receive": "Receive",
}
CHROME_DEVTOOLS_PRODUCER = "WebInspector"  # log.creator.name of Chrome/Edge DevTools exports
ERROR_BODY_MAX_CHARS = 65_536


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


def _size_or_unknown(value: object) -> object:
    """A size below zero (or not a number) means "not recorded" (-1)."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return -1
    return int(value) if value >= 0 else -1


class HarHeader(LenientHarModel):
    """HTTP header name-value pair."""

    name: str
    value: str = ""


class HarPostData(LenientHarModel):
    """POST request data (only the length of the text is kept)."""

    mime_type: str = Field("", alias="mimeType")
    text_length: int = 0

    @model_validator(mode="before")
    @classmethod
    def _keep_length_only(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        raw = dict(cast("dict[str, Any]", data))
        text = raw.pop("text", None)
        if isinstance(text, str) and "text_length" not in raw:
            raw["text_length"] = len(text.encode("utf-8", errors="surrogatepass"))
        return raw


class HarRequest(LenientHarModel):
    """HTTP request."""

    method: str
    url: str
    http_version: str = Field("", alias="httpVersion")
    headers: list[HarHeader] = Field(default_factory=list[HarHeader])
    headers_size: int = Field(-1, alias="headersSize")
    body_size: int = Field(-1, alias="bodySize")
    post_data: HarPostData | None = Field(None, alias="postData")

    @field_validator("headers_size", "body_size", mode="before")
    @classmethod
    def _sizes(cls, value: object) -> object:
        return _size_or_unknown(value)

    @field_validator("url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme.lower() in NETWORK_URL_SCHEMES:
            if not parsed.hostname or parsed.username or parsed.password:
                raise ValueError("network URL requires a host and must not contain credentials")
            _ = parsed.port  # validates malformed and out-of-range ports
        return value

    @property
    def body_bytes(self) -> int:
        """Request body bytes: the largest of ``bodySize``, the posted text and Content-Length.

        Chrome records uploads with ``bodySize`` 0 and no ``postData``; Playwright's
        WebKit counts only the text parts of a multipart body. ``Content-Length`` is what
        was actually announced to the server. -1 when nothing was recorded.
        """
        candidates = [self.body_size]
        if self.post_data is not None:
            candidates.append(self.post_data.text_length)
        candidates.extend(
            int(header.value.strip())
            for header in self.headers
            if header.name.lower() == "content-length" and header.value.strip().isdigit()
        )
        return max(candidates)


class HarContent(LenientHarModel):
    """Response body details. ``text`` is kept only for 4xx/5xx responses (capped)."""

    size: int = Field(default=-1)
    compression: int = -1  # bytes saved by Content-Encoding (-1 = not recorded)
    mime_type: str = Field("", alias="mimeType")
    text: str = ""  # body as recorded by the exporter (often absent)
    encoding: str = ""  # "base64" when ``text`` is base64-encoded

    @field_validator("size", "compression", mode="before")
    @classmethod
    def _sizes(cls, value: object) -> object:
        return _size_or_unknown(value)


class HarResponse(LenientHarModel):
    """HTTP response. ``status`` 0 means no response was received."""

    status: int = Field(ge=0, le=HTTP_STATUS_MAX)
    status_text: str = Field("", alias="statusText")
    http_version: str = Field("", alias="httpVersion")
    headers: list[HarHeader] = Field(default_factory=list[HarHeader])
    redirect_url: str = Field("", alias="redirectURL")
    headers_size: int = Field(-1, alias="headersSize")
    body_size: int = Field(-1, alias="bodySize")  # encoded body bytes on the wire
    content: HarContent | None = None
    transfer_size: int | None = Field(None, alias="_transferSize")  # headers + body
    error: str | None = Field(None, alias="_error")
    error_recorded_empty: bool = False  # ``_error`` present but empty (Chrome: blocked)
    fetched_via_service_worker: bool = Field(False, alias="_fetchedViaServiceWorker")
    service_worker_source: str = Field("", alias="_serviceWorkerResponseSource")

    @model_validator(mode="before")
    @classmethod
    def _producer_conventions(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        raw = dict(cast("dict[str, Any]", data))
        # Playwright: status -1 = no response, reason in ``_failureText``.
        if raw.get("status") == -1:
            raw["status"] = 0
        failure_text = raw.pop("_failureText", None)
        if isinstance(failure_text, str) and failure_text and not raw.get("_error"):
            raw["_error"] = failure_text
        if raw.get("_error") == "":
            raw["error_recorded_empty"] = True
            raw["_error"] = None
        transfer = raw.get("_transferSize")
        if transfer is not None and (not isinstance(transfer, int | float) or transfer < 0):
            raw["_transferSize"] = None
        return raw

    @field_validator("headers_size", "body_size", mode="before")
    @classmethod
    def _sizes(cls, value: object) -> object:
        return _size_or_unknown(value)

    @field_validator("status")
    @classmethod
    def _validate_status(cls, value: int) -> int:
        if 0 < value < HTTP_STATUS_MIN:
            raise ValueError("status must be 0 (no response) or 100 through 999")
        return value


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
            return self.connect - self.ssl if self.ssl <= self.connect else -1.0
        return self.connect

    @property
    def before_response_headers_ms(self) -> float:
        """Blocked + DNS + connect + send + wait (recorded phases only)."""
        phases = (self.blocked, self.dns, self.connect, self.send, self.wait)
        return sum(phase for phase in phases if phase >= 0)


_TIMING_PHASES = ("blocked", "dns", "connect", "ssl", "send", "wait", "receive")
_TOTAL_PHASES = ("blocked", "dns", "connect", "send", "wait", "receive")  # ssl is in connect
_PLAIN_SCHEMES = frozenset({"http", "ws"})
WEBSOCKET_MESSAGES_FIELD = "_webSocketMessages"


def normalize_http_version(value: str) -> str:
    """``HTTP/1.0``, ``HTTP/1.1``, ``HTTP/2``, ``HTTP/3``, or "" when not recorded.

    Producers write ``h2``, ``http/2.0``, ``HTTP/2.0``, ``h3``, ``h3-29``, ``http/1.1`` ...
    """
    text = value.strip().lower()
    if not text:
        return ""
    if text.startswith(("h3", "http/3", "http/2+quic")) or "quic" in text:
        return "HTTP/3"
    if text in ("h2", "h2c") or text.startswith("http/2"):
        return "HTTP/2"
    if text.startswith("http/1.0"):
        return "HTTP/1.0"
    if text.startswith(("http/1.1", "http/1")):
        return "HTTP/1.1"
    return value.strip()


class HarEntry(LenientHarModel):
    """Single HTTP transaction."""

    started_date_time: datetime = Field(alias="startedDateTime")
    time: float
    request: HarRequest
    response: HarResponse
    cache: HarCache | None = None
    timings: HarTimings = Field(default_factory=HarTimings)
    server_ip_address: str | None = Field(None, alias="serverIPAddress")
    connection: str | None = None  # connection ID (never a port)
    from_cache: str | None = Field(None, alias="_fromCache")
    resource_type: str | None = Field(None, alias="_resourceType")
    pageref: str | None = None
    websocket_message_count: int = 0
    started_date_time_raw: str = ""  # startedDateTime exactly as written in the HAR
    timestamp_assumed_utc: bool = False  # startedDateTime had no UTC offset
    entry_index: int = 0  # 1-based position in the HAR file (0 = not loaded via load_har)
    producer: str = ""  # log.creator.name of the capture (set by the loader)
    duration_source: str = "recorded"
    timing_warnings: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _keep_raw_start_and_derive_time(  # noqa: PLR0912, PLR0915
        cls, data: Any, info: ValidationInfo
    ) -> Any:
        if not isinstance(data, dict):
            return data
        raw = dict(cast("dict[str, Any]", data))
        if "startedDateTime" in raw and "started_date_time_raw" not in raw:
            raw["started_date_time_raw"] = str(raw["startedDateTime"])
        messages = raw.pop(WEBSOCKET_MESSAGES_FIELD, None)
        if isinstance(messages, list):
            raw["websocket_message_count"] = len(cast("list[object]", messages))
        request = raw.get("request")
        url = cast("dict[str, Any]", request).get("url", "") if isinstance(request, dict) else ""
        parts = urlsplit(url) if isinstance(url, str) else urlsplit("")
        # Chrome writes the server port in ``connection`` and the socket in
        # ``_connectionId``; a value equal to the port is not a connection ID.
        connection_id = raw.pop("_connectionId", None)
        if connection_id not in (None, ""):
            raw["connection"] = str(connection_id)
        elif raw.get("connection") is not None:
            try:
                port = parts.port or {"https": 443, "wss": 443}.get(parts.scheme.lower(), 80)
            except ValueError:
                port = None
            if str(raw["connection"]).strip() in ("", str(port)):
                raw["connection"] = None
            else:
                raw["connection"] = str(raw["connection"])
        warnings = list(cast("list[str]", raw.get("timing_warnings", [])))
        raw_timings: object = raw.get("timings")
        if raw_timings is None:
            raw_timings = {}
        if not isinstance(raw_timings, dict):
            raise ValueError("timings must be an object")
        phases = {
            key: value
            for key, value in cast("dict[str, Any]", raw_timings).items()
            if key in _TIMING_PHASES
        }
        for name in _TIMING_PHASES:
            value = phases.get(name)
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, int | float)
                or not math.isfinite(value)
                or (value < 0 and value != -1)
            ):
                phases[name] = -1
                warnings.append(f"invalid {name} timing excluded")
        recorded = {
            name: float(value)
            for name, value in phases.items()
            if isinstance(value, int | float) and value >= 0
        }
        total = raw.get("time")
        total_is_number = (
            isinstance(total, int | float) and not isinstance(total, bool) and math.isfinite(total)
        )
        context = cast("dict[str, object]", info.context or {})
        producer = str(context.get("producer", "")).lower()
        ssl = recorded.get("ssl", 0.0)
        connect = recorded.get("connect", -1.0)
        phase_sum = sum(recorded.get(name, 0.0) for name in _TOTAL_PHASES)
        total_value = float(cast("float", total)) if total_is_number else -1.0
        total_counts_ssl_again = (
            ssl > 0
            and math.isclose(total_value, phase_sum + ssl, rel_tol=0.001, abs_tol=0.05)
            and not math.isclose(total_value, phase_sum, rel_tol=0.001, abs_tol=0.05)
        )
        if parts.scheme.lower() in _PLAIN_SCHEMES and "ssl" in recorded:
            # No TLS on a plain connection: Playwright writes connectEnd + 1 here and
            # adds it to ``time``.
            phases["ssl"] = -1
            del recorded["ssl"]
            if total_counts_ssl_again:
                raw["time"] = total = phase_sum
                raw["duration_source"] = "corrected"
        elif total_counts_ssl_again and (ssl > connect or producer == "mitmproxy"):
            # ``connect`` without TLS (mitmproxy): make it include TLS as HAR 1.2 says.
            phases["connect"] = connect + ssl if connect >= 0 else ssl
            recorded["connect"] = float(phases["connect"])
        elif total_counts_ssl_again:
            # Playwright adds ``ssl`` to a ``connect`` that already contains it.
            raw["time"] = total = phase_sum
            raw["duration_source"] = "corrected"
        raw["timings"] = phases
        if total is None:
            # Derive only when all mandatory phases are recorded. A partial sum is
            # a lower bound, not a measured request duration.
            if all(name in recorded for name in ("send", "wait", "receive")):
                raw["time"] = sum(recorded.get(name, 0.0) for name in _TOTAL_PHASES)
                raw["duration_source"] = "derived"
            else:
                raw["time"] = -1
                raw["duration_source"] = "unavailable"
                warnings.append("total timing unavailable")
        elif (
            isinstance(total, bool)
            or not isinstance(total, int | float)
            or not math.isfinite(total)
            or total < 0
        ):
            raw["time"] = -1
            raw["duration_source"] = "unavailable"
            if total != -1:
                warnings.append("invalid total timing excluded")
        raw["timing_warnings"] = warnings
        return raw

    @model_validator(mode="after")
    def _assume_utc_without_offset(self) -> Self:
        if self.started_date_time.tzinfo is None:
            self.started_date_time = self.started_date_time.replace(tzinfo=UTC)
            self.timestamp_assumed_utc = True
        try:
            _ = self.started_date_time + timedelta(milliseconds=max(self.time, 0))
            _ = self.started_date_time + timedelta(
                milliseconds=self.timings.before_response_headers_ms
            )
        except OverflowError, ValueError:
            self.time = -1
            self.duration_source = "unavailable"
            self.timings = HarTimings()
            self.timing_warnings.append("timing outside representable timestamp range excluded")
        if self.timings.ssl > self.timings.connect >= 0:
            self.timing_warnings.append("TLS exceeds connect; exclusive connect timing unavailable")
        phases = [getattr(self.timings, name) for name in _TOTAL_PHASES]
        if self.time >= 0 and all(value >= 0 for value in phases[3:]):
            phase_sum = sum(value for value in phases if value >= 0)
            if not math.isclose(self.time, phase_sum, rel_tol=0.01, abs_tol=1):
                self.timing_warnings.append("total timing differs from recorded phase sum")
        return self

    @property
    def http_version(self) -> str:
        """Normalised protocol (response first, as the request may be a placeholder)."""
        return normalize_http_version(self.response.http_version) or normalize_http_version(
            self.request.http_version
        )


class HarCreator(LenientHarModel):
    """Tool that produced the HAR (``log.creator`` / ``log.browser``)."""

    name: str = ""
    version: str = ""


class HarPageTimings(LenientHarModel):
    """Page load milestones, in ms after the page's ``startedDateTime`` (-1 = unknown)."""

    on_content_load: float = Field(-1.0, alias="onContentLoad")
    on_load: float = Field(-1.0, alias="onLoad")

    @field_validator("on_content_load", "on_load", mode="before")
    @classmethod
    def _milliseconds(cls, value: object) -> object:
        if isinstance(value, bool) or not isinstance(value, int | float):
            return -1.0
        return float(value) if value >= 0 and math.isfinite(value) else -1.0


class HarPage(LenientHarModel):
    """One page (navigation) of the capture."""

    id: str = ""
    started_date_time: datetime | None = Field(None, alias="startedDateTime")
    title: str = ""
    page_timings: HarPageTimings = Field(
        default_factory=lambda: HarPageTimings.model_validate({}), alias="pageTimings"
    )

    @model_validator(mode="after")
    def _assume_utc(self) -> Self:
        if self.started_date_time is not None and self.started_date_time.tzinfo is None:
            self.started_date_time = self.started_date_time.replace(tzinfo=UTC)
        return self


class HarLoadNotes(BaseModel):
    """What ``load_har`` left out or adjusted, so reports can say so."""

    skipped_entry_count: int = 0
    skipped_entry_reasons: list[str] = Field(default_factory=list[str])  # first few only
    non_http_entry_count: int = 0  # data:, blob:, chrome-extension:, about: ...
    corrected_duration_count: int = 0  # totals that double-counted TLS (Playwright)


class HarLog(LenientHarModel):
    """HAR log container."""

    version: str = ""
    entries: list[HarEntry]
    pages: list[HarPage] = Field(default_factory=list[HarPage])
    creator: HarCreator | None = None
    browser: HarCreator | None = None


class Har(LenientHarModel):
    """Root HAR object."""

    log: HarLog
    load_notes: HarLoadNotes = Field(default_factory=HarLoadNotes)


NETWORK_URL_SCHEMES = frozenset({"http", "https", "ws", "wss"})
SKIPPED_ENTRY_REASON_LIMIT = 5


class HarFormatError(ValueError):
    """The input is not a usable HAR document (exit code 3)."""


def _slim_entry(raw_entry: object) -> object:
    """Drop what the analysis never reads before validation (keeps memory bounded).

    Response text is kept only for 4xx/5xx responses (error-page fingerprints), capped.
    """
    if not isinstance(raw_entry, dict):
        return raw_entry
    entry = cast("dict[str, Any]", raw_entry)
    response = entry.get("response")
    if isinstance(response, dict):
        response_fields = cast("dict[str, Any]", response)
        content = response_fields.get("content")
        if isinstance(content, dict):
            content_fields = cast("dict[str, Any]", content)
            status = response_fields.get("status")
            text = content_fields.get("text")
            if isinstance(text, str):
                if isinstance(status, int) and status >= HTTP_STATUS_BAD_REQUEST:
                    content_fields["text"] = text[: ERROR_BODY_MAX_CHARS * 2]
                else:
                    content_fields.pop("text", None)
    return entry


class _HarAccumulator:
    """Collects entries one at a time so a file never has to be held whole."""

    def __init__(self, producer: str = "") -> None:
        self.producer = producer
        self.notes = HarLoadNotes()
        self.entries: list[HarEntry] = []
        self.raw_entry_count = 0

    def add(self, raw_entry: object) -> None:
        self.raw_entry_count += 1
        entry_index = self.raw_entry_count
        try:
            entry = HarEntry.model_validate(
                _slim_entry(raw_entry), context={"producer": self.producer}
            )
        except ValidationError as exc:
            self.notes.skipped_entry_count += 1
            if len(self.notes.skipped_entry_reasons) < SKIPPED_ENTRY_REASON_LIMIT:
                first_error = exc.errors()[0]
                field_path = ".".join(str(part) for part in first_error["loc"]) or "entry"
                self.notes.skipped_entry_reasons.append(
                    f"entry {entry_index}: {field_path}: {first_error['msg']}"
                )
            return
        if urlsplit(entry.request.url).scheme.lower() not in NETWORK_URL_SCHEMES:
            self.notes.non_http_entry_count += 1
            return
        entry.entry_index = entry_index
        entry.producer = self.producer
        self.notes.corrected_duration_count += entry.duration_source == "corrected"
        self.entries.append(entry)

    def build(self, log_fields: dict[str, Any]) -> Har:
        if self.raw_entry_count and not self.entries:
            reasons = "; ".join(self.notes.skipped_entry_reasons) or "no http(s) entries"
            raise HarFormatError(
                f"No usable entries in HAR ({self.raw_entry_count} present): {reasons}"
            )

        def creator(value: object) -> HarCreator | None:
            try:
                return HarCreator.model_validate(value) if isinstance(value, dict) else None
            except ValidationError:
                return None

        pages: list[HarPage] = []
        raw_pages = log_fields.get("pages")
        if isinstance(raw_pages, list):
            for raw_page in cast("list[object]", raw_pages):
                try:
                    pages.append(HarPage.model_validate(raw_page))
                except ValidationError:
                    continue
        version = log_fields.get("version")
        # Entries are already validated: construct the containers without re-running
        # entry validators (which would repeat their warnings).
        return Har.model_construct(
            log=HarLog.model_construct(
                version=version if isinstance(version, str) else "",
                entries=self.entries,
                pages=pages,
                creator=creator(log_fields.get("creator")),
                browser=creator(log_fields.get("browser")),
            ),
            load_notes=self.notes,
        )


def load_har(raw_data: object) -> Har:
    """Build a ``Har`` from already-parsed JSON, entry by entry.

    An entry that cannot be used (no URL, start time or status) is skipped and counted
    instead of rejecting the capture; entries that never touched the network (``data:``,
    ``blob:``, browser-extension URLs) are dropped and counted. Raises HarFormatError
    when the document is not a HAR or no entry is usable.
    """
    log_data = cast("dict[str, Any]", raw_data).get("log") if isinstance(raw_data, dict) else None
    if not isinstance(log_data, dict):
        raise HarFormatError("Not a HAR file: no top-level 'log' object")
    log_fields = cast("dict[str, Any]", log_data)
    raw_entries = log_fields.get("entries")
    if not isinstance(raw_entries, list):
        raise HarFormatError("Not a HAR file: 'log.entries' is not a list")
    creator_fields = log_fields.get("creator")
    producer = (
        str(cast("dict[str, Any]", creator_fields).get("name", ""))
        if isinstance(creator_fields, dict)
        else ""
    )
    accumulator = _HarAccumulator(producer)
    for raw_entry in cast("list[object]", raw_entries):
        accumulator.add(raw_entry)
    return accumulator.build(log_fields)


_UTF8_BOM = b"\xef\xbb\xbf"
_CREATOR_NAME_RE = re.compile(rb'"creator"\s*:\s*\{[^{}]*?"name"\s*:\s*"([^"\\]{1,100})"')
CREATOR_SCAN_BYTES = 65_536
_ENTRY_PREFIX = "log.entries.item"
_LOG_SCALARS = ("log.version", "log.creator", "log.browser", "log.pages")


class _HarEventCollector:
    """Turns ijson events into log fields and entries (one entry built at a time)."""

    def __init__(self, accumulator: _HarAccumulator) -> None:
        self.accumulator = accumulator
        self.log_fields: dict[str, Any] = {}
        self.saw_log = False
        self.saw_entries = False
        self._builder: ObjectBuilder | None = None
        self._builder_prefix = ""

    def feed(self, prefix: str, event: str, value: object) -> None:
        if self._builder is not None:
            self._builder.event(event, value)
            if prefix == self._builder_prefix and event in ("end_map", "end_array"):
                self._finish(self._builder.value)
            return
        if prefix == "log" and event == "start_map":
            self.saw_log = True
        elif prefix == "log.entries" and event == "start_array":
            self.saw_entries = True
        elif prefix == _ENTRY_PREFIX or prefix in _LOG_SCALARS:
            if event in ("start_map", "start_array"):
                self._builder = ObjectBuilder()
                self._builder.event(event, value)
                self._builder_prefix = prefix
            else:  # a scalar where an object was expected
                self._builder_prefix = prefix
                self._finish(value)

    def _finish(self, value: object) -> None:
        if self._builder_prefix == _ENTRY_PREFIX:
            self.accumulator.add(value)
        else:
            self.log_fields[self._builder_prefix.removeprefix("log.")] = value
        self._builder = None


def load_har_file(path: Path) -> Har:
    """Stream a HAR file from disk: one entry is in memory as raw JSON at a time.

    Response bodies of non-error responses are discarded as each entry is read, so
    memory use grows with the number of entries, not with the size of the bodies.
    Raises HarFormatError for files that are not JSON or not a HAR.
    """
    with path.open("rb") as handle:
        head = handle.read(CREATOR_SCAN_BYTES)
    creator_match = _CREATOR_NAME_RE.search(head)
    collector = _HarEventCollector(
        _HarAccumulator(creator_match.group(1).decode() if creator_match else "")
    )
    with path.open("rb") as handle:
        if handle.read(len(_UTF8_BOM)) != _UTF8_BOM:  # Windows tools write a BOM
            handle.seek(0)
        try:
            for prefix, event, value in iter_json_events(handle):
                collector.feed(prefix, event, value)
        except JSONStreamError as exc:
            raise HarFormatError(f"Not valid JSON: {exc}") from exc
    if not collector.saw_log:
        raise HarFormatError("Not a HAR file: no top-level 'log' object")
    if not collector.saw_entries:
        raise HarFormatError("Not a HAR file: 'log.entries' is not a list")
    return collector.accumulator.build(collector.log_fields)


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

    slow_endpoint_ms: float = Field(default=10_000, ge=0, allow_inf_nan=False)
    duration_exceeded_ms: float = Field(default=30_000, ge=0, allow_inf_nan=False)
    large_payload_bytes: int = Field(default=1_048_576, ge=0)
    blocking_ms: float = Field(default=5_000, ge=0, allow_inf_nan=False)
    idle_gap_ms: float = Field(default=1_000, ge=0, allow_inf_nan=False)
    large_request_body_bytes: int = Field(default=102_400, ge=0)
    redirect_chain_min_hops: int = Field(default=3, ge=1)
    timeout_cluster_min_requests: int = Field(default=3, ge=2)
    timeout_cluster_tolerance_pct: float = Field(default=2.0, gt=0, le=100, allow_inf_nan=False)
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
    path = re.sub(r"(?i);jsessionid=[^/;?#]*", ";jsessionid=<redacted>", path)
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
    path = re.sub(r"(?i);jsessionid=[^/;?#]*", ";jsessionid=<redacted>", parts.path or "/")
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
# ``NS_*`` names; WebKit (via Playwright) and mitmproxy write free text. Matching is
# case-insensitive on substrings; the first matching category wins, so specific
# markers come before general ones.
INFORMATIONAL_ERROR_CATEGORIES = frozenset(
    {"aborted", "blocked_by_client", "blocked_by_page_policy", "not_sent"}
)
_NETWORK_ERROR_CATEGORIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "aborted",
        (
            "ERR_ABORTED",
            "ERR_CANCELED",
            "ERR_CANCELLED",
            "NS_BINDING_ABORTED",
            "LOAD REQUEST CANCELLED",  # WebKit
            "CLIENT DISCONNECTED",  # mitmproxy: the browser went away
        ),
    ),
    ("blocked_by_client", ("ERR_BLOCKED_BY_CLIENT", "NS_ERROR_TRACKING_URI")),
    # The page's own policy stopped the request before it was sent (Playwright writes
    # the reason: "csp", "mixed-content", "inspector", ...).
    (
        "blocked_by_page_policy",
        ("ERR_BLOCKED_BY_CSP", "MIXED-CONTENT", "MIXED_CONTENT", "NS_ERROR_CONTENT_BLOCKED"),
    ),
    # The server's own headers (CORP/COEP/X-Frame-Options, opaque-response blocking)
    # made the browser discard the response: a server-side configuration matter.
    ("blocked_by_response_policy", ("ERR_BLOCKED_BY_RESPONSE", "ERR_BLOCKED_BY_ORB")),
    ("cors_rejected", ("NOT ALLOWED BY ACCESS-CONTROL-ALLOW-ORIGIN", "CORS")),
    (
        "connection_refused",
        (
            "ERR_CONNECTION_REFUSED",
            "NS_ERROR_CONNECTION_REFUSED",
            "CONNECTION REFUSED",
            "CONNECT CALL FAILED",
        ),
    ),
    (
        "timed_out",
        ("ERR_TIMED_OUT", "ERR_CONNECTION_TIMED_OUT", "NS_ERROR_NET_TIMEOUT", "TIMED OUT"),
    ),
    (
        "dns",
        (
            "ERR_NAME_NOT_RESOLVED",
            "ERR_NAME_RESOLUTION_FAILED",
            "NS_ERROR_UNKNOWN_HOST",
            "NAME OR SERVICE NOT KNOWN",
            "ERROR RESOLVING",
            "NODENAME NOR SERVNAME",
            "COULD NOT RESOLVE",
        ),
    ),
    (
        "tls",
        ("ERR_SSL_", "ERR_CERT_", "SSL_ERROR_", "SEC_ERROR_", "ERR_QUIC_HANDSHAKE", "CERTIFICATE"),
    ),
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
    ("empty_response", ("ERR_EMPTY_RESPONSE",)),
    (
        "connection_reset",
        (
            "ERR_CONNECTION_RESET",
            "ERR_CONNECTION_CLOSED",
            "ERR_CONNECTION_ABORTED",
            "NS_ERROR_NET_RESET",
            "NS_ERROR_NET_INTERRUPT",
            "CONNECTION RESET",
            "CONNECTION TERMINATED UNEXPECTEDLY",  # WebKit
            "SERVER CLOSED CONNECTION",  # mitmproxy
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
    (
        "too_many_redirects",
        ("ERR_TOO_MANY_REDIRECTS", "NS_ERROR_REDIRECT_LOOP", "CANNOT FOLLOW MORE THAN"),
    ),
    # Chrome reports net::ERR_FAILED for CORS rejections and other unspecific failures.
    ("generic_failure", ("ERR_FAILED",)),
)
# How informational categories are named to the reader.
INFORMATIONAL_LABELS: dict[str, str] = {
    "aborted": "cancelled by the browser",
    "blocked_by_client": "blocked by a browser extension",
    "blocked_by_page_policy": "blocked by the page's own policy (CSP, mixed content)",
    "not_sent": "not sent by the browser (no reason recorded; often CSP)",
}

# What each category is consistent with (shown only for categories that occurred).
NETWORK_ERROR_HINTS: dict[str, str] = {
    "connection_reset": "a proxy or server closed or reset the connection",
    "connection_refused": "nothing was listening on the address (service down or blocked)",
    "timed_out": "no answer at the network level (firewall drop, host down, overload)",
    "dns": "the hostname did not resolve on the client",
    "tls": "certificate or TLS protocol setup",
    "empty_response": (
        "the connection was closed before any response bytes (an httpd reverse proxy does "
        "this on purpose when its backend read fails on a kept-alive client connection)"
    ),
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
    "cors_rejected": (
        "the browser received a response but refused it, most often because it lacked the "
        "CORS headers the page's origin needs"
    ),
    "generic_failure": "unspecific browser failure (often a CORS rejection; see the console)",
    "no_response": "no HTTP response or error reason was recorded; cause unknown",
    "other": "an error this tool does not classify",
}


def classify_network_error(entry: HarEntry) -> str | None:
    """Return a network error category, or None when the request got a response.

    ``aborted``, ``blocked_by_client``, ``blocked_by_page_policy`` and ``not_sent`` are
    informational (user navigated away, app cancelled polling, ad blocker, the page's
    Content-Security-Policy); every other category is a real failure.
    """
    error = entry.response.error
    if not error:
        return _classify_without_error_text(entry)
    error_upper = error.upper()
    category = next(
        (
            name
            for name, markers in _NETWORK_ERROR_CATEGORIES
            if any(marker in error_upper for marker in markers)
        ),
        None,
    )
    if category is None:
        return "blocked_by_page_policy" if error_upper.strip() in _POLICY_REASONS else "other"
    if entry.response.status > 0:
        # A status line arrived first: a later abort does not undo it (the browser
        # stopped reading), a close means the body was cut off, and a generic failure
        # on a received response is the browser refusing it (Chrome reports CORS
        # rejections this way).
        return _AFTER_STATUS_CATEGORY.get(category, category)
    return category


_POLICY_REASONS = frozenset({"CSP", "INSPECTOR", "SUBRESOURCE-FILTER", "DEVTOOLS"})
_AFTER_STATUS_CATEGORY: dict[str, str | None] = {
    "aborted": None,
    "connection_reset": "truncated_response",
    "empty_response": "truncated_response",
    "generic_failure": "cors_rejected",
}


def _classify_without_error_text(entry: HarEntry) -> str | None:
    """No error text: a response was received, never sent, or not recorded at all."""
    if entry.response.status != 0:
        return None
    timings = entry.timings
    nothing_sent = all(
        value <= 0 for value in (timings.dns, timings.connect, timings.send, timings.wait)
    )
    # Chrome writes ``_error: ""`` for requests its own policy stopped (CSP, mixed
    # content); they never reached the network.
    if entry.response.error_recorded_empty and nothing_sent:
        return "not_sent"
    return "no_response"


def is_real_network_error(entry: HarEntry) -> bool:
    """Return True for network failures that are not informational (e.g. aborted)."""
    category = classify_network_error(entry)
    return category is not None and category not in INFORMATIONAL_ERROR_CATEGORIES


_SERVER_TIMING_DUR_RE = re.compile(r'\s*dur\s*=\s*"?([0-9]+(?:\.[0-9]+)?)"?\s*', re.I)
_DURATION_WITH_UNIT_RE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*(ms|s|sec|seconds)?\s*$", re.I)


def _split_header_fields(value: str, delimiter: str) -> list[str]:
    """Split HTTP list/parameter fields without interpreting quoted delimiters."""
    fields: list[str] = []
    start = 0
    quoted = False
    escaped = False
    for position, character in enumerate(value):
        if escaped:
            escaped = False
        elif quoted and character == "\\":
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif character == delimiter and not quoted:
            fields.append(value[start:position])
            start = position + 1
    fields.append(value[start:])
    return fields


def parse_server_timings(headers: list[HarHeader]) -> dict[str, float]:
    """Extract server-reported timings (ms) from ``Server-Timing`` and custom headers.

    Supports ``Server-Timing: app;dur=123.4, db;dur=5``, ``X-Response-Time: 123ms``
    (bare number = ms) and ``X-Runtime: 0.123`` (seconds, Rails/Rack convention).
    """
    timings: dict[str, float] = {}
    for header in headers:
        name = header.name.lower()
        if name == "server-timing":
            for metric in _split_header_fields(header.value, ","):
                metric_name, *parameters = _split_header_fields(metric, ";")
                metric_name = metric_name.strip()
                for parameter in parameters:
                    match = _SERVER_TIMING_DUR_RE.fullmatch(parameter)
                    if metric_name and match:
                        duration = float(match.group(1))
                        if math.isfinite(duration):
                            timings.setdefault(metric_name, duration)
                        break
        elif name in ("x-response-time", "x-runtime"):
            match = _DURATION_WITH_UNIT_RE.match(header.value)
            if not match:
                continue
            value = float(match.group(1))
            unit = (match.group(2) or ("s" if name == "x-runtime" else "ms")).lower()
            duration = value if unit == "ms" else value * 1000
            if math.isfinite(duration):
                timings.setdefault(header.name, duration)
    return timings


_JSESSIONID_ROUTE_RE = re.compile(
    r"(?:^|[;,\s])JSESSIONID=[^;,\s.]+\.([A-Za-z0-9_.-]{1,64})(?=[;,\s]|$)"
)
_ROUTEID_RE = re.compile(r"(?:^|[;,\s])ROUTEID=\.?([A-Za-z0-9_.-]{1,64})(?=[;,\s]|$)")
_JSESSIONID_SET_RE = re.compile(r"(?:^|\n)\s*JSESSIONID=([^;,\s]*)([^\n]*)")
_SESSION_ROUTE_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")

_CORRELATION_HEADER_RE = re.compile(
    r"^(x-[a-z0-9-]*(request|correlation|trace)-?id|traceparent|request-id|x-amzn-trace-id)$"
)


def correlation_headers(entry: HarEntry) -> dict[str, str]:
    """Return allowlisted correlation-ID headers from the request and response."""
    request_ids = {
        header.name.lower(): header.value
        for header in entry.request.headers
        if _CORRELATION_HEADER_RE.match(header.name.lower())
    }
    response_ids = {
        header.name.lower(): header.value
        for header in entry.response.headers
        if _CORRELATION_HEADER_RE.match(header.name.lower())
    }
    return (
        request_ids
        | response_ids
        | {
            f"request:{name}": value
            for name, value in request_ids.items()
            if name in response_ids and response_ids[name] != value
        }
    )


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
OUTAGE_MIN_FAILURES = 3  # capture-level threshold for repeated endpoint problems

HTTP_STATUS_SWITCHING_PROTOCOLS = 101
HTTP_STATUS_OK = 200
HTTP_STATUS_MULTIPLE_CHOICES = 300
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
    is_websocket = resource_type == "websocket" or urlsplit(entry.request.url).scheme.lower() in (
        "ws",
        "wss",
    )
    # HTTP/1.1 upgrades answer 101; WebSockets over HTTP/2 (RFC 8441) and HTTP/3 answer 200.
    if status == HTTP_STATUS_SWITCHING_PROTOCOLS or (is_websocket and status == HTTP_STATUS_OK):
        return "websocket"
    is_event_stream = resource_type == "eventsource" or response_content_type(entry).startswith(
        "text/event-stream"
    )
    if is_event_stream and status == HTTP_STATUS_OK:
        return "event-stream"
    return None


def request_active_ms(entry: HarEntry) -> float:
    """Total minus recorded queueing; still includes setup, upload and download.

    This is not the duration seen by a proxy or application execution timer.
    """
    return max(entry.time - max(entry.timings.blocked, 0.0), 0.0)


def content_encoding(entry: HarEntry) -> str:
    """Response ``Content-Encoding`` lower-cased ("identity" when absent)."""
    value = (response_header(entry, "content-encoding") or "").strip().lower()
    return value or "identity"


def decoded_body_bytes(entry: HarEntry) -> int:
    """Size of the response body after decoding, or -1 when the capture does not say.

    0 for 304 and HEAD (no body crossed). Producers disagree on ``content.size``:
    mitmproxy writes the encoded size there, so ``bodySize + compression`` is used
    when it is larger.
    """
    if entry.response.status == HTTP_STATUS_NOT_MODIFIED or entry.request.method == "HEAD":
        return 0
    content = entry.response.content
    size = content.size if content else -1
    body = entry.response.body_size
    if content and content.compression > 0 and body >= 0:
        size = max(size, body + content.compression)
    if content_encoding(entry) != "identity":
        return size
    declared = response_header(entry, "content-length") or ""
    # Unencoded: Content-Length is the body size. Chrome writes content.size 0 when a
    # service worker consumed the body, and its bodySize is one byte high on HTTP/1.1.
    if declared.strip().isdigit() and (size < 0 or (size == 0 and body > 0)):
        return int(declared.strip())
    if size >= 0:
        return size
    return body


def request_sent_time(entry: HarEntry) -> datetime | None:
    """Estimate browser send completion from available phases and a recorded send."""
    timings = entry.timings
    if (
        timings.send < 0
        or classify_network_error(entry) in PRE_SEND_ERROR_CATEGORIES
        or HarAnalyzer.is_served_locally(entry)
    ):
        return None
    phases = (timings.blocked, timings.dns, timings.connect, timings.send)
    elapsed_ms = sum(phase for phase in phases if phase >= 0)
    if entry.time >= 0 and elapsed_ms > entry.time:
        return None
    return entry.started_date_time + timedelta(milliseconds=elapsed_ms)


def response_headers_time(entry: HarEntry) -> datetime | None:
    """Estimate first byte arrival for requests with an HTTP status and recorded wait."""
    sent_at = request_sent_time(entry)
    if sent_at is None or entry.response.status == 0 or entry.timings.wait < 0:
        return None
    return sent_at + timedelta(milliseconds=entry.timings.wait)


PRE_SEND_ERROR_CATEGORIES = frozenset(
    {
        "dns",
        "tls",
        "connection_refused",
        "proxy_tunnel",
        "blocked_by_client",
        "blocked_by_page_policy",
        "not_sent",
    }
)


# -----------------------------------------------------------------------------
# Request header size
# -----------------------------------------------------------------------------

# Default request-header limits (checked against each product's documentation):
# Tomcat maxHttpHeaderSize 8192 bytes for the request line plus all headers; httpd
# LimitRequestFieldSize 8190 bytes per header field; nginx large_client_header_buffers
# 4 x 8k, one field per buffer.
REQUEST_HEADER_BLOCK_LIMIT_BYTES = 8_192
REQUEST_HEADER_FIELD_LIMIT_BYTES = 8_190
REQUEST_HEADER_NEAR_LIMIT_BYTES = 6_144
REQUEST_HEADER_LIMIT_NOTE = (
    "compare with Tomcat maxHttpRequestHeaderSize (8192 bytes by default for the request "
    "line and headers), httpd LimitRequestFieldSize (8190 bytes per field by default), "
    "or nginx large_client_header_buffers (one buffer per field)"
)
HEADER_SIZE_STATUSES = frozenset({400, 431})


@dataclass(frozen=True)
class RequestHeaderSize:
    """Size of a request's header block and of its largest field."""

    total_bytes: int
    largest_field: str
    largest_field_bytes: int
    computed: bool  # summed from the recorded headers (``headersSize`` was absent)

    @property
    def near_default_limit(self) -> bool:
        """Whether the block or its largest field reaches a common default limit."""
        return (
            self.total_bytes >= REQUEST_HEADER_BLOCK_LIMIT_BYTES
            or self.largest_field_bytes >= REQUEST_HEADER_FIELD_LIMIT_BYTES
        )

    def describe(self) -> str:
        """``9.1 KiB (largest field Cookie 9.0 KiB; estimated from the captured request)``."""
        text = format_bytes(self.total_bytes)
        parts: list[str] = []
        if self.largest_field:
            parts.append(
                f"largest field {self.largest_field} {format_bytes(self.largest_field_bytes)}"
            )
        if self.computed:
            parts.append("estimated from the captured request; headers may be omitted")
        return f"{text} ({'; '.join(parts)})" if parts else text


def request_header_size(entry: HarEntry) -> RequestHeaderSize | None:
    """Request header bytes: ``headersSize`` when recorded, else summed from the headers."""
    headers = entry.request.headers
    largest_name, largest_bytes, summed = "", 0, 0
    for header in headers:
        field_bytes = len(header.name.encode()) + len(header.value.encode()) + 4  # ": " + CRLF
        summed += field_bytes
        if field_bytes > largest_bytes:
            largest_name, largest_bytes = header.name, field_bytes
    if entry.request.headers_size > 0:
        return RequestHeaderSize(entry.request.headers_size, largest_name, largest_bytes, False)
    if not headers:
        return None
    parts = urlsplit(entry.request.url)
    target = parts.path or "/"
    if parts.query:
        target += "?" + parts.query
    version = entry.request.http_version or "HTTP/1.1"
    request_line = f"{entry.request.method} {target} {version}\r\n\r\n"
    return RequestHeaderSize(summed + len(request_line.encode()), largest_name, largest_bytes, True)


# -----------------------------------------------------------------------------
# Error response fingerprint (which tier wrote the error page)
# -----------------------------------------------------------------------------

FORM_URLENCODED = "application/x-www-form-urlencoded"
# Tomcat maxPostSize: default 2 MiB of form body is parsed into request parameters.
TOMCAT_MAX_POST_SIZE_BYTES = 2_097_152
HTTP_STATUS_PAYLOAD_TOO_LARGE = 413

_TOMCAT_VERSION_RE = re.compile(r"Apache Tomcat/([0-9][0-9A-Za-z.\-]{0,20})")
_TOMCAT_STATUS_TITLE_RE = re.compile(r"HTTP Status \d{3}\s+[\u2013-]")
_HTTPD_SIGNATURE_RE = re.compile(r"<address>Apache(?:/([0-9][0-9.]{0,12}))?")
_HTTPD_REASON_RE = re.compile(r"Reason:\s*(?:<strong>)?\s*([A-Za-z][A-Za-z0-9 .:'_-]{2,80})")
_NGINX_BODY_RE = re.compile(r"<center>nginx(?:/([0-9][0-9.]{0,12}))?</center>")
_JAVA_EXCEPTION_RE = re.compile(
    r"\b((?:[a-z_][A-Za-z0-9_$]*\.)+[A-Z][A-Za-z0-9_$]*(?:Exception|Error|Throwable))\b"
)
_JAVA_CAUSED_BY_RE = re.compile(r"Caused by:\s*((?:[a-z_][A-Za-z0-9_$]*\.)+[A-Z][A-Za-z0-9_$]*)")
_JAVA_FRAME_RE = re.compile(
    r"\bat\s+((?:[A-Za-z_$][A-Za-z0-9_$]*\.)+[A-Za-z_$<][A-Za-z0-9_$<>]*)"
    r"\(([A-Za-z0-9_$.]{1,60}(?::\d+)?)\)"
)
_SPRING_BOOT_ERROR_KEYS = frozenset({"timestamp", "status", "error", "path"})


@dataclass(frozen=True)
class ErrorFingerprint:
    """What an error response says about the tier that produced it.

    Only product names, versions, a fixed proxy reason phrase and Java class / frame
    names are kept; exception messages and other body text are never copied.
    """

    responder: str = ""  # e.g. "Tomcat default error page (Apache Tomcat/9.0.85)"
    source: str = ""  # "body" or "headers"
    proxy_reason: str = ""  # httpd "Reason:" phrase, e.g. "Error reading from remote server"
    exception: str = ""  # first Java exception class in the body
    root_cause: str = ""  # last "Caused by:" class
    first_frame: str = ""  # first "at pkg.Class.method(File.java:NN)" frame

    def describe(self) -> str:
        """One-line evidence text ("" when there is none)."""
        parts: list[str] = []
        if self.responder:
            parts.append(f"{self.responder} [{self.source}]")
        if self.proxy_reason:
            parts.append(f'reason "{self.proxy_reason}"')
        if self.exception:
            exception = self.exception
            if self.root_cause and self.root_cause != self.exception:
                exception += f" (root cause {self.root_cause})"
            parts.append(exception)
        if self.first_frame:
            parts.append(f"at {self.first_frame}")
        return "; ".join(parts)


def response_body_text(entry: HarEntry) -> str:
    """Recorded response body as text, capped; "" when the exporter kept none."""
    content = entry.response.content
    if content is None or not content.text:
        return ""
    text = content.text[: ERROR_BODY_MAX_CHARS * 2]
    if content.encoding.lower() == "base64":
        try:
            text = base64.b64decode(text[: len(text) - len(text) % 4], validate=False).decode(
                "utf-8", errors="replace"
            )
        except binascii.Error, ValueError:
            return ""
    return text[:ERROR_BODY_MAX_CHARS]


def _spring_boot_error(body: str) -> tuple[bool, str]:
    """(is Spring Boot's default error JSON, exception class if it names one)."""
    if not body.lstrip().startswith("{"):
        return False, ""
    try:
        loaded: object = json.loads(body)
    except ValueError:
        return False, ""
    if not isinstance(loaded, dict):
        return False, ""
    fields = cast("dict[str, object]", loaded)
    if not fields.keys() >= _SPRING_BOOT_ERROR_KEYS:
        return False, ""
    exception = fields.get("exception")
    return True, exception if isinstance(exception, str) else ""


def _header_responder(entry: HarEntry) -> str:
    """Responder named by headers alone; weaker than a body fingerprint."""
    server = (response_header(entry, "server") or "").strip()
    server_lower = server.lower()
    if server_lower.startswith("awselb"):
        return f"AWS load balancer (Server: {server})"
    if server_lower.startswith("apache-coyote"):
        return f"Tomcat connector (Server: {server})"
    content_type = (response_header(entry, "content-type") or "").lower().replace(" ", "")
    if content_type == "text/html;charset=iso-8859-1":
        # httpd's built-in error documents are sent with exactly this type.
        return "Content-Type matches httpd's built-in error documents (weak clue)"
    if content_type == "text/html;charset=utf-8" and response_header(entry, "content-language"):
        # Tomcat's ErrorReportValve sets text/html, utf-8 and the response locale.
        return "headers match Tomcat's default error page (weak clue)"
    return ""


def error_fingerprint(entry: HarEntry) -> ErrorFingerprint | None:
    """Fingerprint a 4xx/5xx response from its body and headers; None for no evidence."""
    if entry.response.status < HTTP_STATUS_BAD_REQUEST:
        return None
    body = response_body_text(entry)
    responder = ""
    proxy_reason = ""
    exception = ""
    if body:
        tomcat_version = _TOMCAT_VERSION_RE.search(body)
        httpd_signature = _HTTPD_SIGNATURE_RE.search(body)
        nginx_body = _NGINX_BODY_RE.search(body)
        is_spring_boot, spring_exception = _spring_boot_error(body)
        if tomcat_version or _TOMCAT_STATUS_TITLE_RE.search(body):
            version = f" (Apache Tomcat/{tomcat_version.group(1)})" if tomcat_version else ""
            responder = f"Tomcat default error page{version}"
        elif "-//IETF//DTD HTML 2.0//EN" in body or httpd_signature:
            version = (
                f" (Apache/{httpd_signature.group(1)})"
                if httpd_signature and httpd_signature.group(1)
                else ""
            )
            responder = f"Apache httpd error document{version}"
            reason = _HTTPD_REASON_RE.search(body)
            if reason:
                proxy_reason = reason.group(1).strip()
        elif nginx_body:
            version = f" (nginx/{nginx_body.group(1)})" if nginx_body.group(1) else ""
            responder = f"nginx error page{version}"
        elif is_spring_boot:
            responder = "Spring Boot default error JSON (application tier)"
            exception = spring_exception
    exception_match = _JAVA_EXCEPTION_RE.search(body) if body else None
    if exception_match and not exception:
        exception = exception_match.group(1)
    causes = _JAVA_CAUSED_BY_RE.findall(body) if body else []
    frame = _JAVA_FRAME_RE.search(body) if body else None
    if exception and not responder:
        responder = "Java application (stack trace in the response body)"
    source = "body" if responder else ""
    if not responder:
        responder = _header_responder(entry)
        source = "headers" if responder else ""
    if not responder and not exception:
        return None
    return ErrorFingerprint(
        responder=responder,
        source=source,
        proxy_reason=proxy_reason,
        exception=exception,
        root_cause=causes[-1] if causes else "",
        first_frame=f"{frame.group(1)}({frame.group(2)})" if frame else "",
    )


# -----------------------------------------------------------------------------
# Session cookies (route names only; session IDs are never kept)
# -----------------------------------------------------------------------------


def _routes_in(pattern: re.Pattern[str], header_values: list[str]) -> list[str]:
    """Distinct route names matched in the header values, in first-seen order."""
    routes: list[str] = []
    for value in header_values:
        for match in pattern.finditer(value):
            if match.group(1) not in routes:
                routes.append(match.group(1))
    return routes


def _header_values(headers: list[HarHeader], name: str) -> list[str]:
    return [header.value for header in headers if header.name.lower() == name]


def has_cookie_headers(entry: HarEntry) -> bool:
    """True when the capture kept this request's Cookie or Set-Cookie headers."""
    return bool(
        _header_values(entry.request.headers, "cookie")
        or _header_values(entry.response.headers, "set-cookie")
    )


def _session_cookie_updates(entry: HarEntry) -> list[tuple[str, str, str]]:
    """Cookie domain, path and value for each JSESSIONID update, for in-memory comparison."""
    parts = urlsplit(entry.request.url)
    hostname = parts.hostname or ""
    default_path = parts.path.rpartition("/")[0] or "/"
    updates: list[tuple[str, str, str]] = []
    for value in _header_values(entry.response.headers, "set-cookie"):
        for match in _JSESSIONID_SET_RE.finditer(value):
            session_id, raw_attributes = match.groups()
            attributes: dict[str, str] = {}
            for raw_attribute in raw_attributes.split(";"):
                name, _, attribute_value = raw_attribute.strip().partition("=")
                attributes[name.strip().lower()] = attribute_value.strip()
            domain = attributes.get("domain", "").lower().removeprefix(".") or hostname
            if domain != hostname and not hostname.endswith("." + domain):
                continue
            path = attributes.get("path", "")
            if not path.startswith("/"):
                path = default_path
            max_age = attributes.get("max-age", "")
            if re.fullmatch(r"-?[0-9]+", max_age):
                if max_age.startswith("-") or not max_age.strip("0"):
                    session_id = ""
            elif expires := attributes.get("expires"):
                try:
                    expires_at = parsedate_to_datetime(expires)
                except ValueError, TypeError, OverflowError:
                    pass
                else:
                    if expires_at.tzinfo is None:
                        expires_at = expires_at.replace(tzinfo=UTC)
                    if expires_at <= entry.started_date_time:
                        session_id = ""
            updates.append((domain, path, session_id))
    return updates


def tail_label(stats: TimingStatistics) -> str:
    """``p95`` when there are enough samples, otherwise ``max``."""
    return "p95" if stats.count >= MIN_SAMPLES_FOR_TAIL_PERCENTILES else "max"


def tail_value(stats: TimingStatistics) -> float:
    """p95 when n >= 20; with fewer samples p95 is meaningless, so use max."""
    return known_ms(stats.p95 if stats.count >= MIN_SAMPLES_FOR_TAIL_PERCENTILES else stats.max)


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
    if number is None or not math.isfinite(number) or number <= 0:
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


def timeout_fact_applies_to_response_wait(fact: ConfigFact) -> bool:
    """Allow only known response-wait timers as duration-comparison candidates.

    These timers have different start/reset conditions. A duration match never
    establishes that the setting applied to the captured request or caused it to fail.
    """
    key = re.split(r"[./\s]", fact.key.lower())[-1]
    component = fact.component.lower()
    return (
        (component in ("httpd", "apache") and key in ("proxytimeout", "timeout"))
        or (component == "nginx" and key == "proxy_read_timeout")
        or (component in ("mod_jk", "jk") and key in ("reply_timeout", "socket_timeout"))
        or (component == "haproxy" and fact.key.lower() in ("timeout server", "timeout tunnel"))
        or (component == "tomcat" and key == "asynctimeout")
    )


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
    """Timing statistics in milliseconds; every figure is None when ``count`` is 0."""

    count: int = 0
    p50: float | None = None
    p95: float | None = None
    p99: float | None = None
    max: float | None = None
    mean: float | None = None
    total_duration_ms: float = 0.0


def known_ms(value: float | None) -> float:
    """A statistic for display: -1 (shown as "-") when there were no samples."""
    return -1.0 if value is None else value


class DomainAnalysis(BaseModel):
    """Per-domain analysis summary."""

    domain: str
    total_requests: int
    failed_requests: int
    failure_rate_pct: float  # failed requests as a percentage of the host's requests
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
    method: str = ""
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
    # Wait for the first byte (total minus queueing when wait is not recorded) of the
    # responses that were not 5xx: what "slow endpoint" is judged on.
    served_wait_timings: TimingStatistics = Field(default_factory=TimingStatistics)


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
    """Request body above the large-request-body threshold."""

    url: str
    method: str
    body_size_bytes: int
    content_type: str
    timestamp: datetime
    status: int = 0
    note: str = ""  # what a body of this size is known to run into


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
    network_download_count: int = 0  # 200 responses with evidence of network activity
    unknown_cache_count: int = 0  # 200 responses lacking sufficient evidence
    repeated_download_request_count: int = 0  # network 200s for a URL fetched 2+ times
    repeated_downloads: list[dict[str, Any]]  # [{url, count, total_bytes}]
    missing_cache_control_count: int
    served_without_download_ratio: float  # (cache hits + 304s) / cacheable GETs


class ErrorBurst(BaseModel):
    """A run of errors, each failing within the window of the previous one.

    Times are when the requests failed (start + duration), not when they started.
    """

    start_time: datetime
    end_time: datetime
    error_count: int
    affected_domains: list[str]
    endpoint_count: int = 0


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
    entry_index: int = 0
    sent_at: datetime | None = None  # estimated browser send completion
    headers_at: datetime | None = None  # first response byte arrived
    ended_at: datetime | None = None
    server_ip: str = ""
    node: str = ""


class TimeoutCluster(BaseModel):
    """Similar failure durations; causes remain hypotheses.

    ``basis`` is either recorded browser ``wait`` on a 5xx or browser
    ``total minus queue`` for the other measurements.
    """

    kind: str  # "gateway" (504), "proxy_502", "network", "client_cancel", "failure"
    basis: str = "wait"
    proxy_reasons: dict[str, int] = Field(default_factory=dict)  # from error bodies
    max_queued_ms: float = 0.0  # longest browser queueing among the members
    request_count: int
    min_ms: float
    max_ms: float
    median_ms: float
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
    timing_unavailable_count: int = 0
    cache_source_unknown_count: int = 0
    service_worker_count: int = 0


class ErrorOrigin(BaseModel):
    """Headers on one host's 5xx responses next to its successful responses."""

    domain: str
    status: int
    count: int
    median_active_ms: float  # median recorded wait, or -1 if unavailable
    error_servers: dict[str, int]  # Server header value ("(none)" when absent) -> count
    success_servers: dict[str, int]
    error_content_types: dict[str, int]
    via_count: int  # error responses carrying a Via header
    reading: str  # what the header comparison is consistent with
    status_hint: str  # what this status at this duration is consistent with
    comparison_scope: str = ""  # which successes the errors were compared with
    fingerprints: dict[str, int] = Field(default_factory=dict)  # responder -> count
    exceptions: dict[str, int] = Field(default_factory=dict)  # Java exception -> count


class HostClockOffset(BaseModel):
    """``Date`` response header minus the browser's clock, per host.

    ``Date`` is stamped by whichever tier generated or rewrote it (nginx replaces the
    backend's Date by default), so ``date_servers`` lists the Server headers seen on
    the sampled responses.
    """

    domain: str
    median_seconds: float
    sample_count: int
    date_servers: dict[str, int] = Field(default_factory=dict)


class SessionEvent(BaseModel):
    """Browser-visible login redirects and session cookie updates."""

    kind: str  # "login_redirect", "route_changed", "reissued", "cookie_refreshed"
    domain: str
    timestamp: datetime
    entry_index: int
    request: str  # "METHOD /templated/path"
    detail: str
    idle_seconds: float | None = None  # since the previous request to the host ended


class StallEvent(BaseModel):
    """Requests sent at different times whose first bytes all arrived together."""

    domain: str
    stall_start: datetime  # earliest moment one of the requests was sent
    release_time: datetime  # when the first of the delayed responses arrived
    release_spread_ms: float
    request_count: int
    endpoint_count: int
    min_wait_ms: float
    max_wait_ms: float
    host_median_wait_ms: float
    entry_indexes: list[int]
    connection_count: int | None = None  # distinct connection IDs, when recorded
    http_versions: list[str] = Field(default_factory=list)


class TimelineBucket(BaseModel):
    """Requests of one host that started inside one time bucket."""

    domain: str
    start: datetime
    request_count: int
    server_error_count: int
    network_error_count: int
    client_error_count: int
    wait_sample_count: int
    wait_p50_ms: float | None = None
    wait_max_ms: float | None = None


class Incident(BaseModel):
    """Failed requests of one endpoint with one signature, with their evidence."""

    severity: IssueSeverity
    domain: str
    method: str
    endpoint: str  # path template
    signature: str  # HTTP status or network error category
    outcome: RequestOutcome
    failure_count: int
    endpoint_request_count: int
    endpoint_success_count: int
    first_failure: datetime  # when the first of them failed (start + duration)
    last_failure: datetime
    first_sent: datetime | None  # earliest available browser send estimate
    min_wait_ms: float
    max_wait_ms: float
    evidence: list[str] = Field(default_factory=list)
    entry_indexes: list[int] = Field(default_factory=list)  # first few
    correlation_ids: list[str] = Field(default_factory=list)  # first few
    server_ips: list[str] = Field(default_factory=list)
    nodes: dict[str, int] = Field(default_factory=dict)
    where_to_look: list[str] = Field(default_factory=list)


class PageSummary(BaseModel):
    """One page (navigation) of the capture, with its load milestones.

    Milestones are milliseconds after the page started (-1 when not recorded); the
    requests are those whose ``pageref`` names the page.
    """

    page_id: str
    title: str  # usually the page URL
    started: datetime | None
    dom_content_loaded_ms: float = -1.0
    load_ms: float = -1.0
    request_count: int = 0
    failed_count: int = 0
    last_response_end_ms: float = -1.0  # last request of the page finished, after start


class BackendNodeStats(BaseModel):
    """Responses grouped by the X-Served-By value reported in the capture."""

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
    aborted_request_count: int = 0  # informational: cancelled, blocked or never sent
    informational_by_category: dict[str, int] = Field(default_factory=dict)
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
    timing_warning_count: int = 0
    timing_warning_examples: list[str] = Field(default_factory=list)
    derived_duration_count: int = 0
    unavailable_duration_count: int = 0
    transfer_unknown_count: int = 0
    transfer_body_only_count: int = 0
    backend_unknown_request_count: int = 0
    backend_unknown_failure_count: int = 0
    backend_ambiguous_request_count: int = 0  # several different routes in one cookie header
    idle_gap_unknown_count: int = 0  # gaps not judged: a request of unknown length came first
    session_events: list[SessionEvent] = Field(default_factory=list)
    cookie_header_request_count: int = 0  # requests whose Cookie/Set-Cookie headers were kept
    stall_events: list[StallEvent] = Field(default_factory=list)
    timeline: list[TimelineBucket] = Field(default_factory=list)
    timeline_bucket_seconds: int = 0
    incidents: list[Incident] = Field(default_factory=list)
    log_correlation: list[RequestSummary] = Field(default_factory=list)
    max_request_header_bytes: int = 0
    max_request_header_note: str = ""
    pages: list[PageSummary] = Field(default_factory=list)
    error_body_count: int = 0  # 4xx/5xx responses whose body text the capture kept
    error_response_count: int = 0  # 4xx/5xx responses in all


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
        return (
            entry.time >= 0
            and classify_network_error(entry) is None
            and not self.is_served_locally(entry)
            and not self.is_cache_source_unknown(entry)
        )

    @staticmethod
    def is_cache_source_unknown(entry: HarEntry) -> bool:
        """A 200 without local-cache or positive network evidence has unknown source."""
        return (
            entry.response.status == HTTP_STATUS_OK
            and not HarAnalyzer.is_served_locally(entry)
            and HarAnalyzer.wire_bytes(entry) <= 0
            and not any(
                value > 0
                for value in (
                    entry.timings.dns,
                    entry.timings.connect,
                    entry.timings.send,
                    entry.timings.wait,
                    entry.timings.receive,
                )
            )
        )

    def path_template(self, url: str) -> str:
        """Return the URL path with ID-like segments templated."""
        return template_path(urlsplit(url).path or "/", self.path_rules)

    def endpoint_key(self, url: str) -> str:
        """Return ``scheme://host/templated/path`` used to group requests."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{self.path_template(url)}"

    @staticmethod
    def wire_bytes(entry: HarEntry) -> int:
        """Response bytes that crossed the network (headers + body); -1 when unknown.

        0 for responses served by the browser cache or a service worker. Uses
        ``_transferSize`` when recorded, else ``headersSize + bodySize``, else
        ``bodySize`` alone (a lower bound; counted as "body bytes only").
        """
        if HarAnalyzer.is_served_locally(entry):
            return 0
        response = entry.response
        if response.transfer_size is not None and response.transfer_size >= 0:
            return response.transfer_size
        if response.status == 0:
            return 0  # no response arrived
        if response.headers_size >= 0 and response.body_size >= 0:
            return response.headers_size + response.body_size
        return response.body_size

    @staticmethod
    def is_service_worker_response(entry: HarEntry) -> bool:
        """True when a service worker answered (Chrome ``_fetchedViaServiceWorker``).

        If the worker fetched from the network, that fetch is its own entry in the
        capture, so this one is not counted as network traffic a second time.
        """
        return entry.response.fetched_via_service_worker

    @staticmethod
    def is_browser_cache_hit(entry: HarEntry) -> bool:
        """Return True when the browser served the response from memory/disk cache.

        Chrome DevTools marks every hit with ``_fromCache`` (memory or disk), so for its
        captures that marker alone decides. Other producers (Playwright) write no marker:
        a 200 with ``_transferSize`` 0, no error and no DNS or connection setup is a hit.
        (A response the browser blocked, such as ORB, also has ``_transferSize`` 0, but it
        was fetched over a connection.) ``cache.beforeRequest`` is not proof of a hit.
        """
        if (
            entry.response.status == HTTP_STATUS_NOT_MODIFIED
            or entry.response.fetched_via_service_worker
        ):
            return False
        if entry.from_cache in ("memory", "disk", "memory-cache", "disk-cache"):
            return True
        if entry.producer == CHROME_DEVTOOLS_PRODUCER:
            return False
        return (
            entry.response.status == HTTP_STATUS_OK
            and entry.response.transfer_size == 0
            and not entry.response.error
            and entry.timings.dns <= 0
            and entry.timings.connect <= 0
        )

    @staticmethod
    def is_served_locally(entry: HarEntry) -> bool:
        """Answered without the network: browser cache or service worker."""
        return HarAnalyzer.is_browser_cache_hit(entry) or HarAnalyzer.is_service_worker_response(
            entry
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
        informational_by_category: dict[str, int] = defaultdict(int)
        for entry in entries:
            status_codes[entry.response.status] += 1
            category = classify_network_error(entry)
            if category in INFORMATIONAL_ERROR_CATEGORIES:
                informational_by_category[category] += 1
            elif category is not None:
                network_errors_by_category[category] += 1
        aborted_request_count = sum(informational_by_category.values())

        # Capture window: first request start to last request end (start + time)
        capture_start = min((e.started_date_time for e in entries), default=None)
        capture_end = max((entry_end_time(e) for e in entries), default=None)

        endpoints = self._aggregate_by_endpoint(entries)
        issues = self._detect_issues(entries, endpoints, capture_end)
        creators = [c for c in (har.log.creator, har.log.browser) if c and c.name]
        time_gaps, idle_gap_unknown_count = self._compute_time_gaps(entries)
        timeout_clusters = self._detect_timeout_clusters(entries)
        timeline, timeline_bucket_seconds = self._timeline(entries, capture_start, capture_end)
        header_sizes = [size for e in entries if (size := request_header_size(e)) is not None]
        largest_headers = max(header_sizes, key=lambda size: size.total_bytes, default=None)
        error_responses = [e for e in entries if e.response.status >= HTTP_STATUS_BAD_REQUEST]

        report = HarAnalysisReport(
            total_requests=len(entries),
            total_duration_ms=sum(e.time for e in entries if e.time >= 0),
            total_bytes_transferred=sum(max(self.wire_bytes(e), 0) for e in entries),
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
            time_gaps=time_gaps,
            idle_gap_unknown_count=idle_gap_unknown_count,
            server_software_by_domain=self._extract_server_software_by_domain(entries),
            capture_start=capture_start,
            capture_end=capture_end,
            phase_breakdown=self._compute_phase_breakdown(phase_stats),
            compression_analysis=self._analyze_compression(entries),
            cache_analysis=self._analyze_caching(entries),
            error_bursts=self._detect_error_bursts(issues),
            request_rate_stats=self._compute_request_rate(entries, capture_start, capture_end),
            settings=self.settings,
            timeout_clusters=timeout_clusters,
            network_errors_by_category=dict(
                sorted(network_errors_by_category.items(), key=lambda kv: (-kv[1], kv[0]))
            ),
            aborted_request_count=aborted_request_count,
            informational_by_category=dict(sorted(informational_by_category.items())),
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
                service_worker_count=sum(
                    1
                    for e in entries
                    if classify_network_error(e) is None and self.is_service_worker_response(e)
                ),
                aborted_count=aborted_request_count,
                network_error_count=sum(network_errors_by_category.values()),
                timing_unavailable_count=sum(
                    1
                    for e in entries
                    if e.time < 0
                    and classify_network_error(e) is None
                    and not self.is_served_locally(e)
                ),
                cache_source_unknown_count=sum(
                    e.time >= 0
                    and classify_network_error(e) is None
                    and self.is_cache_source_unknown(e)
                    for e in entries
                ),
            ),
            host_connection_stats=self._host_connection_stats(measured),
            error_origins=self._error_origins(entries),
            clock_offsets=self._clock_offsets(measured),
            backend_nodes=self._backend_nodes(entries),
            timing_warning_count=sum(bool(e.timing_warnings) for e in entries),
            timing_warning_examples=[
                f"entry {e.entry_index}: {'; '.join(e.timing_warnings)}"
                for e in entries
                if e.timing_warnings
            ][:5],
            derived_duration_count=sum(e.duration_source == "derived" for e in entries),
            unavailable_duration_count=sum(e.time < 0 for e in entries),
            transfer_unknown_count=sum(self.wire_bytes(e) < 0 for e in entries),
            transfer_body_only_count=sum(
                not self.is_served_locally(e)
                and e.response.status != 0
                and e.response.transfer_size is None
                and e.response.headers_size < 0
                and e.response.body_size >= 0
                for e in entries
            ),
            backend_unknown_request_count=sum(self.backend_node(e) is None for e in entries),
            backend_ambiguous_request_count=sum(self.backend_node_is_ambiguous(e) for e in entries),
            session_events=self._session_events(entries),
            cookie_header_request_count=sum(has_cookie_headers(e) for e in entries),
            stall_events=self._stall_events(measured),
            timeline=timeline,
            timeline_bucket_seconds=timeline_bucket_seconds,
            incidents=self._incidents(entries, timeout_clusters),
            log_correlation=self._log_correlation(entries),
            pages=self._page_summaries(har.log.pages, entries),
            max_request_header_bytes=largest_headers.total_bytes if largest_headers else 0,
            max_request_header_note=largest_headers.describe() if largest_headers else "",
            error_body_count=sum(bool(response_body_text(e)) for e in error_responses),
            error_response_count=len(error_responses),
            backend_unknown_failure_count=sum(
                self.backend_node(e) is None
                and self.outcome(e) in (RequestOutcome.SERVER_ERROR, RequestOutcome.NETWORK_ERROR)
                for e in entries
            ),
        )
        report.key_findings = self._generate_key_findings(report)
        return report

    def _page_summaries(self, pages: list[HarPage], entries: list[HarEntry]) -> list[PageSummary]:
        """Each page's milestones plus the requests that belong to it (by ``pageref``)."""
        by_page: dict[str, list[HarEntry]] = defaultdict(list)
        for entry in entries:
            if entry.pageref:
                by_page[entry.pageref].append(entry)
        summaries: list[PageSummary] = []
        for page in pages:
            members = by_page.get(page.id, [])
            last_end = -1.0
            if page.started_date_time is not None:
                ends = [
                    (entry_end_time(e) - page.started_date_time).total_seconds() * 1000
                    for e in members
                    if e.time >= 0
                ]
                last_end = max(ends, default=-1.0)
            summaries.append(
                PageSummary(
                    page_id=page.id,
                    title=page.title,
                    started=page.started_date_time,
                    dom_content_loaded_ms=page.page_timings.on_content_load,
                    load_ms=page.page_timings.on_load,
                    request_count=len(members),
                    failed_count=sum(self.is_problem(e) for e in members),
                    last_response_end_ms=last_end,
                )
            )
        return summaries

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
        return [self._request_summary(e) for e in slowest[: self.SLOWEST_REQUESTS_LIMIT]]

    def _request_summary(self, e: HarEntry) -> RequestSummary:
        node = self.backend_node(e)
        return RequestSummary(
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
            wait_ms=e.timings.wait if e.response.status else -1.0,
            receive_ms=e.timings.receive,
            error_category=classify_network_error(e),
            correlation=correlation_headers(e),
            entry_index=e.entry_index,
            sent_at=request_sent_time(e),
            headers_at=response_headers_time(e),
            ended_at=entry_end_time(e) if e.time >= 0 else None,
            server_ip=e.server_ip_address or "",
            node=node[0] if node else "",
        )

    LOG_CORRELATION_LIMIT = 25

    def _log_correlation(self, entries: list[HarEntry]) -> list[RequestSummary]:
        """Requests worth finding in server logs: failures first (oldest first), then slowest.

        Each carries the browser send estimate when available.
        """
        failed = sorted(
            (e for e in entries if self.is_problem(e)),
            key=lambda e: (e.started_date_time, e.entry_index),
        )
        chosen = failed[: self.LOG_CORRELATION_LIMIT]
        chosen_ids = {id(e) for e in chosen}
        slowest = sorted(
            (e for e in entries if e.time > self.settings.slow_endpoint_ms),
            key=lambda e: (-e.time, e.started_date_time),
        )
        for entry in slowest:
            if len(chosen) >= self.LOG_CORRELATION_LIMIT:
                break
            if id(entry) not in chosen_ids:
                chosen.append(entry)
                chosen_ids.add(id(entry))
        chosen.sort(key=lambda e: (e.started_date_time, e.entry_index))
        return [self._request_summary(e) for e in chosen]

    @staticmethod
    def _compute_phase_breakdown(
        phase_stats: dict[str, TimingStatistics],
    ) -> list[PhaseBreakdown]:
        """Share of summed phase time per phase (connect excludes TLS, so no double count)."""
        display_names = PHASE_DISPLAY_NAMES
        phase_totals = {
            display_names.get(name, name): stats.total_duration_ms
            for name, stats in phase_stats.items()
        }
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

            confirmed_problems = problems - sum(
                classify_network_error(entry) == "no_response" for entry in domain_entries
            )
            if (
                confirmed_problems / total * 100 >= self.DOMAIN_ERROR_RATE_CRITICAL_PCT
                and confirmed_problems >= self.DOMAIN_CRITICAL_MIN_PROBLEMS
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
                    failure_rate_pct=error_rate,
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
            key=lambda d: (health_order[d.health], -d.failure_rate_pct, d.domain),
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
            return TimingStatistics()

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
        by_pattern: dict[tuple[str, str], list[HarEntry]] = defaultdict(list)
        for entry in entries:
            by_pattern[(entry.request.method.upper(), self.endpoint_key(entry.request.url))].append(
                entry
            )

        def stats(values: list[float]) -> TimingStatistics:
            return self._compute_timing_stats([value for value in values if value >= 0])

        endpoints: list[EndpointStats] = []
        for (method, pattern), reqs in by_pattern.items():
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
                    method=method,
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
                    served_wait_timings=self._compute_timing_stats(
                        [
                            r.timings.wait
                            for r in measured
                            if r.timings.wait >= 0
                            and r.response.status < self.HTTP_STATUS_SERVER_ERROR_MIN
                        ]
                    ),
                )
            )

        # Ranked by tail wait (TTFB) of non-5xx responses: the measure the slow-endpoint
        # rule uses. Queueing in the browser is not the server's time, and failures are
        # reported as failures.
        return sorted(
            endpoints,
            key=lambda e: (-tail_value(e.served_wait_timings), e.url_pattern, e.method),
        )

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
        well_known_by_host: dict[str, int] = defaultdict(int)
        for entry in entries:
            if classify_network_error(entry) in self.WELL_KNOWN_NETWORK_ERRORS:
                well_known_by_host[urlparse(entry.request.url).netloc] += 1
        for entry in entries:
            category = classify_network_error(entry)
            if category is None:
                continue
            raw_error = entry.response.error or NETWORK_ERROR_HINTS["no_response"]
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
            elif category == "no_response":
                issue_type = IssueType.NETWORK_ERROR
                severity = IssueSeverity.MEDIUM
                message = "No HTTP response recorded (status 0; cause unknown)"
            else:
                issue_type = IssueType.NETWORK_ERROR
                host_failures = well_known_by_host[urlparse(entry.request.url).netloc]
                # One failed connection is a failure worth a look (HIGH); the same host
                # failing repeatedly is CRITICAL. A one-off must not read as an outage.
                severity = (
                    IssueSeverity.CRITICAL
                    if category in self.WELL_KNOWN_NETWORK_ERRORS
                    and host_failures >= OUTAGE_MIN_FAILURES
                    else IssueSeverity.HIGH
                )
                message = f"Network error [{category}]: {raw_error}"
            issue = DetectedIssue(
                issue_type=issue_type,
                severity=severity,
                url=entry.request.url,
                message=message,
                duration_ms=entry.time if entry.time >= 0 else None,
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

        Name the largest recorded phase when a phase breakdown is available.
        """
        threshold_ms = self.settings.duration_exceeded_ms
        descriptions = dict(self._PHASE_DESCRIPTIONS)
        issues: list[DetectedIssue] = []
        for entry in entries:
            if entry.time <= threshold_ms:
                continue
            if self.outcome(entry) in (RequestOutcome.SERVER_ERROR, RequestOutcome.NETWORK_ERROR):
                continue  # reported once, as the failure, with its duration
            dominant = self._dominant_phase(entry)
            if dominant is None:
                where = "phase split unavailable"
            else:
                phase_name, phase_ms = dominant
                where = (
                    f"largest recorded phase: {descriptions[phase_name]} "
                    f"{format_duration_ms(phase_ms)}"
                )
            issues.append(
                DetectedIssue(
                    issue_type=IssueType.DURATION_EXCEEDED,
                    severity=IssueSeverity.HIGH,
                    url=entry.request.url,
                    message=(
                        f"Request exceeded {format_duration_ms(threshold_ms)} threshold "
                        f"({format_duration_ms(entry.time)}; {where})"
                    ),
                    duration_ms=entry.time if entry.time >= 0 else None,
                    timestamp=entry.started_date_time,
                    details={
                        "method": entry.request.method,
                        "status": entry.response.status,
                        "wait_time_ms": entry.timings.wait,
                        "dominant_phase": dominant[0] if dominant else "unknown",
                        "threshold_ms": threshold_ms,
                        "group_label": (
                            f"Request exceeded {format_duration_ms(threshold_ms)} threshold "
                            f"({where.split(':', 1)[0]})"
                        ),
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
            fingerprint = error_fingerprint(entry)
            if fingerprint:
                details["responder"] = fingerprint.describe()
            header_size = request_header_size(entry)
            if status in HEADER_SIZE_STATUSES and header_size and header_size.near_default_limit:
                severity = IssueSeverity.HIGH
                message += " with captured header size near or above a common default limit"
                details["request_headers"] = header_size.describe()
                details["request_headers_over_limit"] = True
            rejected_body_size = (
                entry.request.body_bytes
                if status == HTTP_STATUS_PAYLOAD_TOO_LARGE and entry.request.body_bytes > 0
                else None
            )
            if rejected_body_size is not None:
                details["request_body"] = format_bytes(rejected_body_size)
            if entry.time > self.settings.duration_exceeded_ms:
                details["over_duration_threshold"] = True
            issues.append(
                DetectedIssue(
                    issue_type=issue_type,
                    severity=severity,
                    url=entry.request.url,
                    message=message,
                    timestamp=entry.started_date_time,
                    duration_ms=entry.time if entry.time >= 0 else None,
                    size_bytes=rejected_body_size,
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
            uncompressed_bytes = decoded_body_bytes(entry)
            if uncompressed_bytes <= self.settings.large_payload_bytes:
                continue
            wire_bytes = self.wire_bytes(entry)
            issues.append(
                DetectedIssue(
                    issue_type=IssueType.LARGE_PAYLOAD,
                    severity=IssueSeverity.MEDIUM,
                    url=entry.request.url,
                    message=f"Large payload: {format_bytes(uncompressed_bytes)}",
                    size_bytes=uncompressed_bytes,
                    timestamp=entry.started_date_time,
                    details={
                        "content_type": self._get_content_type(entry),
                        "bytes_on_wire": wire_bytes,
                        "served_locally": self.is_served_locally(entry),
                    },
                    domain=urlparse(entry.request.url).netloc,
                )
            )
            self._add_request_context(issues[-1].details, entry)
        return issues

    def _detect_slow_endpoints(self, endpoints: list[EndpointStats]) -> list[DetectedIssue]:
        """Detect endpoint templates whose wait for the first byte exceeds the threshold.

        Judged on the p95 (max when n < 20) of wait time over responses that were not
        5xx. Time queued in the browser is not the server's, and failed requests are
        reported as failures, so neither makes an endpoint "slow".
        """
        issues: list[DetectedIssue] = []
        for endpoint in endpoints:
            waits = endpoint.served_wait_timings
            value = tail_value(waits)
            if waits.count == 0 or value <= self.settings.slow_endpoint_ms:
                continue
            label = tail_label(waits)
            issues.append(
                DetectedIssue(
                    issue_type=IssueType.SLOW_ENDPOINT,
                    severity=IssueSeverity.HIGH,
                    url=endpoint.url_pattern,
                    message=(
                        f"Slow endpoint: wait {label}={format_duration_ms(value)} "
                        f"(wait p50={format_duration_ms(known_ms(waits.p50))}, n={waits.count} "
                        "non-5xx responses; "
                        f"total incl. browser queueing {tail_label(endpoint.timings)}="
                        f"{format_duration_ms(tail_value(endpoint.timings))})"
                    ),
                    duration_ms=value,
                    timestamp=endpoint.last_seen,
                    details={
                        "method": endpoint.method,
                        "endpoint": urlparse(endpoint.url_pattern).path,
                        "count": waits.count,
                        "p50": waits.p50,
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
            f"{e.request.method} {self.path_template(e.request.url)} ({format_duration_ms(e.time)})"
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
                "http_version": entry.http_version or "unknown",
            }
            holders = self._queue_holders(entry, by_domain[domain])
            if holders:
                details["in_flight_meanwhile"] = holders
            issues.append(
                DetectedIssue(
                    issue_type=IssueType.BLOCKING,
                    severity=IssueSeverity.MEDIUM,
                    url=entry.request.url,
                    message=f"Queued in the browser: {format_duration_ms(entry.timings.blocked)}",
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
        positions = {id(entry): position for position, entry in enumerate(sorted_entries)}
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
                    and positions[id(candidate)] > positions[id(entry)]
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
            if current.response.status in self.REDIRECT_STATUSES and current.response.redirect_url:
                target = urljoin(current.request.url, current.response.redirect_url).split("#", 1)[
                    0
                ]
                is_loop = is_loop or target in seen_urls

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
                    message=(
                        f"{kind}: {len(redirect_hops)} hop(s) over {format_duration_ms(chain_ms)}"
                    ),
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

    def _detect_timeout_clusters(self, entries: list[HarEntry]) -> list[TimeoutCluster]:
        """Find similar failure durations per host and evidence category.

        Prefer recorded browser wait on a 5xx. Otherwise compare total minus recorded
        queueing, which can include DNS, connection setup, upload and download.
        """
        populations: dict[tuple[str, str, str], list[HarEntry]] = defaultdict(list)
        for entry in entries:
            if self._cluster_duration_ms(entry) <= 0 or self.is_expected(entry):
                continue
            if (
                entry.response.status != 0
                and entry.response.status < self.HTTP_STATUS_SERVER_ERROR_MIN
            ):
                continue
            kind = self._timeout_cluster_kind([entry])
            basis = self._cluster_basis(entry)
            populations[(urlsplit(entry.request.url).netloc, kind, basis)].append(entry)
        tolerance = self.settings.timeout_cluster_tolerance_pct / 100
        clusters: list[TimeoutCluster] = []
        for population in populations.values():
            failed = sorted(population, key=self._cluster_duration_ms)
            start_index = 0
            while start_index < len(failed):
                end_index = start_index
                limit = self._cluster_duration_ms(failed[start_index]) * (1 + tolerance)
                while (
                    end_index + 1 < len(failed)
                    and self._cluster_duration_ms(failed[end_index + 1]) <= limit
                ):
                    end_index += 1
                members = failed[start_index : end_index + 1]
                cluster = self._build_timeout_cluster(
                    members, tolerance, self.settings.timeout_cluster_min_requests
                )
                if cluster:
                    clusters.append(cluster)
                    start_index = end_index + 1
                else:
                    start_index += 1
        return sorted(
            clusters,
            key=lambda cluster: (
                -cluster.request_count,
                cluster.median_ms,
                tuple(cluster.endpoints),
            ),
        )

    CLUSTER_BASIS_WAIT = "wait"
    CLUSTER_BASIS_ACTIVE = "total minus queue"

    def _cluster_basis(self, entry: HarEntry) -> str:
        has_wait = entry.response.status >= self.HTTP_STATUS_SERVER_ERROR_MIN and (
            entry.timings.wait >= 0
        )
        return self.CLUSTER_BASIS_WAIT if has_wait else self.CLUSTER_BASIS_ACTIVE

    def _cluster_duration_ms(self, entry: HarEntry) -> float:
        if self._cluster_basis(entry) == self.CLUSTER_BASIS_WAIT:
            return entry.timings.wait
        return request_active_ms(entry) if entry.time >= 0 else -1.0

    def _timeout_cluster_kind(self, members: list[HarEntry]) -> str:
        """Name the observed evidence, without inferring a timeout from any 5xx."""
        if all(member.response.status == HTTP_STATUS_GATEWAY_TIMEOUT for member in members):
            return "gateway"
        if all(member.response.status == HTTP_STATUS_BAD_GATEWAY for member in members):
            return "proxy_502"
        if all(
            classify_network_error(member) in INFORMATIONAL_ERROR_CATEGORIES for member in members
        ):
            return "client_cancel"
        if all(classify_network_error(member) == "timed_out" for member in members):
            return "network"
        return "failure"

    def _build_timeout_cluster(
        self, members: list[HarEntry], tolerance: float, min_requests: int
    ) -> TimeoutCluster | None:
        """Return a cluster when members are numerous enough and have positive durations."""
        if len(members) < min_requests:
            return None
        durations = [self._cluster_duration_ms(m) for m in members]
        median_ms = statistics.median(durations)
        median_s = median_ms / 1000
        if median_ms <= 0:
            return None

        status_codes: dict[int, int] = defaultdict(int)
        endpoint_counts: dict[str, int] = defaultdict(int)
        for member in members:
            status_codes[member.response.status] += 1
            endpoint_counts[f"{member.request.method} {self.endpoint_key(member.request.url)}"] += 1

        matching_settings = [
            describe_fact(fact)
            for fact in self.config_facts
            if timeout_fact_applies_to_response_wait(fact)
            and (fact_seconds := timeout_fact_seconds(fact)) is not None
            and abs(fact_seconds - median_s) <= fact_seconds * tolerance
        ]
        proxy_reasons: dict[str, int] = defaultdict(int)
        for member in members:
            fingerprint = error_fingerprint(member)
            if fingerprint and fingerprint.proxy_reason:
                proxy_reasons[fingerprint.proxy_reason] += 1
        return TimeoutCluster(
            kind=self._timeout_cluster_kind(members),
            basis=self._cluster_basis(members[0]),
            proxy_reasons=dict(sorted(proxy_reasons.items())),
            max_queued_ms=max(max(m.timings.blocked, 0.0) for m in members),
            request_count=len(members),
            min_ms=min(durations),
            max_ms=max(durations),
            median_ms=median_ms,
            status_codes=dict(sorted(status_codes.items())),
            endpoints=dict(sorted(endpoint_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
            first_seen=min(m.started_date_time for m in members),
            last_seen=max(m.started_date_time for m in members),
            matching_settings=matching_settings,
        )

    def _add_request_context(self, details: dict[str, object], entry: HarEntry) -> None:
        """Add the referer hostname and correlation IDs (log lookup keys) when present."""
        details["entry_index"] = entry.entry_index
        details["endpoint"] = self.path_template(entry.request.url)
        if (sent_at := request_sent_time(entry)) is not None:
            details["sent_at"] = sent_at
        if entry.server_ip_address:
            details["server_ip"] = entry.server_ip_address
        details["duration_source"] = entry.duration_source
        if entry.timing_warnings:
            details["timing_warnings"] = "; ".join(entry.timing_warnings)
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
                try:
                    return urlparse(header.value).hostname or ""
                except ValueError:
                    return ""
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
            if entry.http_version:
                version = entry.http_version
            elif entry.response.status == 0:
                version = "none (no response)"
            else:
                version = "not recorded"
            distribution[version] += 1
        # Sort by count descending, then alphabetically
        return dict(sorted(distribution.items(), key=lambda kv: (-kv[1], kv[0])))

    def _compute_large_request_bodies(
        self, entries: list[HarEntry], limit: int = 20
    ) -> list[LargeRequestBody]:
        """Requests whose body exceeds the large-request-body threshold, largest first."""
        large_bodies: list[LargeRequestBody] = []

        for entry in entries:
            body_bytes = entry.request.body_bytes
            if body_bytes > self.settings.large_request_body_bytes:
                content_type = next(
                    (h.value for h in entry.request.headers if h.name.lower() == "content-type"),
                    "unknown",
                )
                if entry.request.post_data:
                    content_type = entry.request.post_data.mime_type or content_type

                note = ""
                if (
                    content_type.lower().startswith(FORM_URLENCODED)
                    and body_bytes > TOMCAT_MAX_POST_SIZE_BYTES
                ):
                    note = (
                        "form body over Tomcat's default maxPostSize (2 MiB), which "
                        "applies when the connector parses the body into parameters"
                    )
                elif entry.response.status == HTTP_STATUS_PAYLOAD_TOO_LARGE:
                    note = (
                        "rejected with 413: compare with nginx client_max_body_size "
                        "(default 1m) or httpd LimitRequestBody"
                    )
                large_bodies.append(
                    LargeRequestBody(
                        url=entry.request.url,
                        method=entry.request.method,
                        body_size_bytes=body_bytes,
                        content_type=content_type,
                        timestamp=entry.started_date_time,
                        status=entry.response.status,
                        note=note,
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
            "the responding server encountered an unexpected condition; correlate proxy "
            "and application logs before identifying the failing tier"
        ),
        502: (
            "a gateway reports an invalid or missing upstream response. In httpd "
            "mod_proxy_http, an upstream status-line read failure can produce 502, "
            "including on timeout. Check the proxy error log for the actual failure."
        ),
        503: (
            "the responding server was temporarily unable to handle the request. Check "
            "Retry-After, proxy worker state, and application logs. If Tomcat saturation "
            "is suspected, check executor utilization and connector connection counts."
        ),
        504: (
            "a proxy stopped waiting for the backend; compare the wait with the proxy's "
            "read timeout (nginx proxy_read_timeout, load balancer idle timeout). These "
            "timers measure time without data from the backend, not total request time"
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
        host_successes: dict[str, list[HarEntry]] = defaultdict(list)
        endpoint_successes: dict[tuple[str, str, str], list[HarEntry]] = defaultdict(list)
        for entry in entries:
            domain = urlparse(entry.request.url).netloc
            outcome = self.outcome(entry)
            if outcome == RequestOutcome.SERVER_ERROR:
                errors[(domain, entry.response.status)].append(entry)
            elif outcome == RequestOutcome.SUCCESS and not self.is_served_locally(entry):
                host_successes[domain].append(entry)
                endpoint_successes[
                    domain, entry.request.method.upper(), self.path_template(entry.request.url)
                ].append(entry)

        origins: list[ErrorOrigin] = []
        for (domain, status), members in sorted(errors.items()):
            error_servers: dict[str, int] = defaultdict(int)
            content_types: dict[str, int] = defaultdict(int)
            fingerprints: dict[str, int] = defaultdict(int)
            exceptions: dict[str, int] = defaultdict(int)
            body_fingerprint_count = 0
            for member in members:
                error_servers[response_header(member, "server") or self.NO_HEADER] += 1
                content_type = response_content_type(member).split(";", 1)[0] or self.NO_HEADER
                content_types[content_type] += 1
                fingerprint = error_fingerprint(member)
                if fingerprint and fingerprint.responder:
                    responder = fingerprint.responder
                    if fingerprint.proxy_reason:
                        responder += f': "{fingerprint.proxy_reason}"'
                    fingerprints[responder] += 1
                    body_fingerprint_count += fingerprint.source == "body"
                if fingerprint and fingerprint.exception:
                    exceptions[fingerprint.root_cause or fingerprint.exception] += 1
            # Compare with successes on the failing endpoints first: static files and
            # API calls of one host are often answered by different tiers.
            same_endpoint = [
                success
                for method, path in sorted(
                    {(m.request.method.upper(), self.path_template(m.request.url)) for m in members}
                )
                for success in endpoint_successes.get((domain, method, path), [])
            ]
            compared = same_endpoint or host_successes[domain]
            comparison_scope = (
                "successes on the same endpoint(s)"
                if same_endpoint
                else "host-wide successes (the failing endpoint(s) had none)"
            )
            success_servers: dict[str, int] = defaultdict(int)
            for success in compared:
                success_servers[response_header(success, "server") or self.NO_HEADER] += 1
            reading = self._origin_reading(error_servers, success_servers)
            named = ", ".join(f"{name} ({count})" for name, count in sorted(fingerprints.items()))
            if body_fingerprint_count:
                reading = f"error-page text or headers suggest these responders: {named}"
            elif fingerprints:
                reading += f"; headers point at: {named}"
            waits = [m.timings.wait for m in members if m.timings.wait >= 0]
            median_active_ms = statistics.median(waits) if waits else -1.0
            hint = self.STATUS_HINTS.get(status, "")
            origins.append(
                ErrorOrigin(
                    domain=domain,
                    status=status,
                    count=len(members),
                    median_active_ms=median_active_ms,
                    error_servers=dict(sorted(error_servers.items())),
                    success_servers=dict(sorted(success_servers.items())),
                    error_content_types=dict(sorted(content_types.items())),
                    via_count=sum(1 for m in members if response_header(m, "via")),
                    reading=reading,
                    status_hint=hint,
                    comparison_scope=comparison_scope,
                    fingerprints=dict(sorted(fingerprints.items())),
                    exceptions=dict(sorted(exceptions.items())),
                )
            )
        return origins

    CLOCK_OFFSET_MIN_SAMPLES = 3

    def _clock_offsets(self, measured: list[HarEntry]) -> list[HostClockOffset]:
        """Server clock minus browser clock per host, from ``Date`` response headers.

        Each sample is the Date header minus the moment the response headers arrived
        (start + blocked + dns + connect + send + wait). Responses carrying ``Age`` were
        served by an intermediary cache with an old Date and are skipped.
        """
        samples: dict[str, list[float]] = defaultdict(list)
        date_servers: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for entry in measured:
            date_value = response_header(entry, "date")
            if not date_value or response_header(entry, "age"):
                continue
            try:
                server_time = parsedate_to_datetime(date_value)
            except TypeError, ValueError:
                continue
            if server_time.tzinfo is None:
                server_time = server_time.replace(tzinfo=UTC)
            if (headers_arrived := response_headers_time(entry)) is None:
                continue
            domain = urlparse(entry.request.url).netloc
            samples[domain].append((server_time - headers_arrived).total_seconds())
            date_servers[domain][response_header(entry, "server") or self.NO_HEADER] += 1
        return [
            HostClockOffset(
                domain=domain,
                median_seconds=statistics.median(values),
                sample_count=len(values),
                date_servers=dict(sorted(date_servers[domain].items())),
            )
            for domain, values in sorted(samples.items())
            if len(values) >= self.CLOCK_OFFSET_MIN_SAMPLES
        ]

    @staticmethod
    def backend_node(entry: HarEntry) -> tuple[str, str] | None:
        """Return (value, source) for a routing or responder hint, if visible.

        Evidence from the response comes first: the route in a ``JSESSIONID`` or
        ``ROUTEID`` the response sets, then ``X-Served-By``. A route in the request's
        ``Cookie`` only says where the session is pinned (after a failover the node that
        answered differs), so it is used last and labelled as such. The route is
        everything after the first dot of the session ID; the ID itself is never
        returned. A header naming several different routes (one session cookie per
        application path) is ambiguous and is not used.
        """
        set_cookies = _header_values(entry.response.headers, "set-cookie")
        for pattern, source in (
            (_JSESSIONID_ROUTE_RE, "JSESSIONID route (Set-Cookie)"),
            (_ROUTEID_RE, "ROUTEID (Set-Cookie)"),
        ):
            routes = _routes_in(pattern, set_cookies)
            if len(routes) == 1:
                return routes[0], source
        served_by = response_header(entry, "x-served-by")
        if served_by:
            return served_by.strip(), "X-Served-By"
        request_cookies = _header_values(entry.request.headers, "cookie")
        for pattern, source in (
            (_JSESSIONID_ROUTE_RE, "session pinned to (request JSESSIONID)"),
            (_ROUTEID_RE, "session pinned to (request ROUTEID)"),
        ):
            routes = _routes_in(pattern, request_cookies)
            if len(routes) == 1:
                return routes[0], source
        return None

    @staticmethod
    def backend_node_is_ambiguous(entry: HarEntry) -> bool:
        """True when the only routing evidence names several different routes."""
        if HarAnalyzer.backend_node(entry) is not None:
            return False
        cookies = [
            *_header_values(entry.response.headers, "set-cookie"),
            *_header_values(entry.request.headers, "cookie"),
        ]
        return any(
            len(_routes_in(pattern, cookies)) > 1 for pattern in (_JSESSIONID_ROUTE_RE, _ROUTEID_RE)
        )

    def _responder_hint(self, entry: HarEntry) -> str:
        """Read a captured response hint only when there is network-response evidence."""
        if (
            entry.response.status == 0
            or self.is_served_locally(entry)
            or self.is_cache_source_unknown(entry)
        ):
            return ""
        return (response_header(entry, "x-served-by") or "").strip()

    def _backend_nodes(self, entries: list[HarEntry]) -> list[BackendNodeStats]:
        """Count observed response header values without treating them as Tomcat nodes."""
        by_node: dict[tuple[str, str], list[HarEntry]] = defaultdict(list)
        for entry in entries:
            responder = self._responder_hint(entry)
            if responder:
                by_node[urlsplit(entry.request.url).netloc, responder].append(entry)
        nodes: list[BackendNodeStats] = []
        for (domain, node_name), members in sorted(by_node.items()):
            outcomes = [self.outcome(m) for m in members]
            nodes.append(
                BackendNodeStats(
                    domain=domain,
                    node=node_name,
                    source="X-Served-By",
                    request_count=len(members),
                    server_error_count=outcomes.count(RequestOutcome.SERVER_ERROR),
                    network_error_count=outcomes.count(RequestOutcome.NETWORK_ERROR),
                    timings=self._compute_timing_stats(
                        [m.time for m in members if self.is_latency_sample(m)]
                    ),
                )
            )
        return nodes

    def _compute_time_gaps(
        self, entries: list[HarEntry], limit: int = 20
    ) -> tuple[list[TimeGap], int]:
        """Find idle periods where no request was in flight; return (gaps, not judged).

        The gap before a request is measured from the latest end time (start + time) of
        all earlier requests, so time spent waiting on a long request is not reported as
        idle. A request of unknown duration may still have been running, so a gap that
        follows one is not judged (and is counted) until a later request with a known
        end time overtakes it.
        """
        if len(entries) < self.MIN_ENTRIES_FOR_GAP_ANALYSIS:
            return [], 0

        sorted_entries = sorted(entries, key=lambda e: e.started_date_time)

        gaps: list[TimeGap] = []
        unknown_count = 0
        latest_finishing_entry = sorted_entries[0]
        latest_end = entry_end_time(latest_finishing_entry)
        end_is_unknown = latest_finishing_entry.time < 0
        for curr_entry in sorted_entries[1:]:
            gap_ms = (curr_entry.started_date_time - latest_end).total_seconds() * 1000

            if gap_ms > self.settings.idle_gap_ms:
                if end_is_unknown:
                    unknown_count += 1
                else:
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
            if curr_entry.time < 0:
                end_is_unknown = True
            if curr_end > latest_end:
                latest_end = curr_end
                latest_finishing_entry = curr_entry
                end_is_unknown = curr_entry.time < 0

        return sorted(gaps, key=lambda x: -x.gap_duration_ms)[:limit], unknown_count

    # -------------------------------------------------------------------------
    # Session continuity
    # -------------------------------------------------------------------------

    LOGIN_PATH_MARKERS = (
        "/saslogon",
        "/login",
        "/signin",
        "/sso",
        "/oauth/authorize",
        "/oauth2/authorize",
        "/saml",
        "/cas/",
    )

    @classmethod
    def _is_login_path(cls, path: str) -> bool:
        path_lower = path.lower()
        return any(marker in path_lower for marker in cls.LOGIN_PATH_MARKERS)

    def _session_event(
        self,
        kind: str,
        entry: HarEntry,
        detail: str,
        timestamp: datetime,
        idle_seconds: float | None = None,
    ) -> SessionEvent:
        """Build an event with its browser timestamp and any measured host gap."""
        return SessionEvent(
            kind=kind,
            domain=urlsplit(entry.request.url).netloc,
            timestamp=timestamp,
            entry_index=entry.entry_index,
            request=f"{entry.request.method} {self.path_template(entry.request.url)}",
            detail=detail,
            idle_seconds=idle_seconds,
        )

    def _session_events(self, entries: list[HarEntry]) -> list[SessionEvent]:
        """Detect login redirects and compare observed updates within each cookie scope."""
        events: list[SessionEvent] = []
        first_app_response: dict[str, datetime] = {}
        last_end: dict[str, datetime] = {}
        for entry in sorted(entries, key=lambda e: (e.started_date_time, e.entry_index)):
            parts = urlsplit(entry.request.url)
            domain, path = parts.netloc, parts.path or "/"

            target = entry.response.redirect_url or response_header(entry, "location") or ""
            if (
                entry.response.status in self.REDIRECT_STATUSES
                and target
                and not self._is_login_path(path)
                and self._is_login_path(urlsplit(urljoin(entry.request.url, target)).path)
                and domain in first_app_response
                and first_app_response[domain] <= entry.started_date_time
                and not self.is_served_locally(entry)
            ):
                gap_seconds = (
                    max((entry.started_date_time - last_end[domain]).total_seconds(), 0.0)
                    if domain in last_end
                    else None
                )
                events.append(
                    self._session_event(
                        "login_redirect",
                        entry,
                        f"answered {entry.response.status} to the login page",
                        entry.started_date_time,
                        gap_seconds,
                    )
                )

            if (
                self.outcome(entry) == RequestOutcome.SUCCESS
                and HTTP_STATUS_OK <= entry.response.status < HTTP_STATUS_MULTIPLE_CHOICES
                and not self._is_login_path(path)
                and not _is_static_path(path)
                and not self.is_served_locally(entry)
                and not self.is_cache_source_unknown(entry)
            ):
                first_byte_at = response_headers_time(entry)
                if first_byte_at is not None or entry.time >= 0:
                    observed_at = first_byte_at or entry_end_time(entry)
                    first_app_response[domain] = min(
                        observed_at, first_app_response.get(domain, observed_at)
                    )
            end = entry_end_time(entry)
            if domain not in last_end or end > last_end[domain]:
                last_end[domain] = end
        events.extend(self._session_cookie_events(entries))
        return sorted(events, key=lambda event: (event.timestamp, event.entry_index))

    def _session_cookie_events(self, entries: list[HarEntry]) -> list[SessionEvent]:
        """Compare cookie observations in response order because requests can overlap."""
        observations = [
            (response_headers_time(entry) or entry_end_time(entry), entry, updates)
            for entry in entries
            if entry.response.status
            and not self.is_served_locally(entry)
            and (updates := _session_cookie_updates(entry))
        ]
        events: list[SessionEvent] = []
        session_values: dict[tuple[str, str], str] = {}
        for timestamp, entry, updates in sorted(
            observations, key=lambda sample: (sample[0], sample[1].entry_index)
        ):
            for cookie_domain, cookie_path, session_value in updates:
                scope = (cookie_domain, cookie_path)
                previous = session_values.get(scope)
                if not session_value:
                    session_values.pop(scope, None)
                    continue
                session_values[scope] = session_value
                if previous is None:
                    continue
                cookie_label = f"session cookie for path {cookie_path}"
                previous_id, _, previous_route = previous.partition(".")
                session_id, _, route = session_value.partition(".")
                if session_id != previous_id:
                    events.append(
                        self._session_event(
                            "reissued", entry, f"{cookie_label} value changed", timestamp
                        )
                    )
                elif session_value == previous:
                    events.append(
                        self._session_event(
                            "cookie_refreshed", entry, f"{cookie_label} was set again", timestamp
                        )
                    )
                if (
                    previous_route != route
                    and _SESSION_ROUTE_RE.fullmatch(previous_route)
                    and _SESSION_ROUTE_RE.fullmatch(route)
                ):
                    events.append(
                        self._session_event(
                            "route_changed",
                            entry,
                            f"{cookie_label} route changed from {previous_route} to {route}",
                            timestamp,
                        )
                    )
        return events

    # -------------------------------------------------------------------------
    # Host-wide stalls
    # -------------------------------------------------------------------------

    STALL_MIN_WAIT_MS = 2_000.0
    STALL_WAIT_RATIO = 5.0  # times the host's median wait
    STALL_RELEASE_WINDOW_MS = 250.0
    STALL_MIN_REQUESTS = 3
    STALL_MIN_ENDPOINTS = 2
    STALL_MIN_SENT_SPREAD_MS = 500.0
    STALL_MIN_HOST_SAMPLES = 5

    def _stall_events(self, measured: list[HarEntry]) -> list[StallEvent]:
        """Find requests sent at different times whose first bytes arrived together.

        Delayed requests across multiple endpoints whose responses arrive close together
        are candidates for investigating a shared delay.
        """
        by_domain: dict[str, list[tuple[datetime, datetime, HarEntry]]] = defaultdict(list)
        for entry in measured:
            sent_at = request_sent_time(entry)
            if sent_at is not None and entry.timings.wait >= 0:
                headers_at = sent_at + timedelta(milliseconds=entry.timings.wait)
                by_domain[urlsplit(entry.request.url).netloc].append((headers_at, sent_at, entry))

        events: list[StallEvent] = []
        window = timedelta(milliseconds=self.STALL_RELEASE_WINDOW_MS)
        for domain, host_entries in sorted(by_domain.items()):
            if len(host_entries) < self.STALL_MIN_HOST_SAMPLES:
                continue
            median_wait = statistics.median(e.timings.wait for _, _, e in host_entries)
            threshold = max(self.STALL_MIN_WAIT_MS, self.STALL_WAIT_RATIO * median_wait)
            delayed = sorted(
                (sample for sample in host_entries if sample[2].timings.wait >= threshold),
                key=lambda sample: (sample[0], sample[2].entry_index),
            )
            start_index = 0
            while start_index < len(delayed):
                end_index = start_index
                release = delayed[start_index][0]
                while (
                    end_index + 1 < len(delayed) and delayed[end_index + 1][0] - release <= window
                ):
                    end_index += 1
                samples = delayed[start_index : end_index + 1]
                members = [entry for _, _, entry in samples]
                sent_times = [sent_at for _, sent_at, _ in samples]
                sent_spread_ms = (max(sent_times) - min(sent_times)).total_seconds() * 1000
                endpoints = {(m.request.method, self.path_template(m.request.url)) for m in members}
                if (
                    len(members) >= self.STALL_MIN_REQUESTS
                    and len(endpoints) >= self.STALL_MIN_ENDPOINTS
                    and sent_spread_ms >= self.STALL_MIN_SENT_SPREAD_MS
                ):
                    connections = {m.connection for m in members if m.connection}
                    events.append(
                        StallEvent(
                            domain=domain,
                            stall_start=min(sent_times),
                            release_time=release,
                            release_spread_ms=(samples[-1][0] - release).total_seconds() * 1000,
                            request_count=len(members),
                            endpoint_count=len(endpoints),
                            min_wait_ms=min(m.timings.wait for m in members),
                            max_wait_ms=max(m.timings.wait for m in members),
                            host_median_wait_ms=median_wait,
                            entry_indexes=sorted(m.entry_index for m in members),
                            connection_count=(
                                len(connections) if all(m.connection for m in members) else None
                            ),
                            http_versions=sorted({m.http_version or "unknown" for m in members}),
                        )
                    )
                    start_index = end_index + 1
                else:
                    start_index += 1
        return events

    # -------------------------------------------------------------------------
    # Timeline
    # -------------------------------------------------------------------------

    TIMELINE_BUCKET_CHOICES_SECONDS = (1, 5, 10, 30, 60, 300, 600, 1800, 3600, 21600, 86400)
    TIMELINE_MAX_BUCKETS = 30
    TIMELINE_MAX_HOSTS = 3
    TIMELINE_MIN_REQUESTS = 10

    def _timeline(
        self, entries: list[HarEntry], capture_start: datetime | None, capture_end: datetime | None
    ) -> tuple[list[TimelineBucket], int]:
        """Per-host activity in equal time buckets (by request start); (buckets, seconds)."""
        if not entries or capture_start is None or capture_end is None:
            return [], 0
        duration_seconds = (capture_end - capture_start).total_seconds()
        bucket_seconds = next(
            (
                choice
                for choice in self.TIMELINE_BUCKET_CHOICES_SECONDS
                if duration_seconds / choice <= self.TIMELINE_MAX_BUCKETS
            ),
            self.TIMELINE_BUCKET_CHOICES_SECONDS[-1],
        )
        by_domain: dict[str, list[HarEntry]] = defaultdict(list)
        for entry in entries:
            by_domain[urlsplit(entry.request.url).netloc].append(entry)
        busiest = sorted(
            (item for item in by_domain.items() if len(item[1]) >= self.TIMELINE_MIN_REQUESTS),
            key=lambda item: (-len(item[1]), item[0]),
        )[: self.TIMELINE_MAX_HOSTS]

        buckets: list[TimelineBucket] = []
        for domain, host_entries in busiest:
            grouped: dict[int, list[HarEntry]] = defaultdict(list)
            for entry in host_entries:
                offset = (entry.started_date_time - capture_start).total_seconds()
                grouped[int(offset // bucket_seconds)].append(entry)
            for index, members in sorted(grouped.items()):
                outcomes = [self.outcome(m) for m in members]
                waits = sorted(
                    m.timings.wait
                    for m in members
                    if m.timings.wait >= 0 and self.is_latency_sample(m)
                )
                buckets.append(
                    TimelineBucket(
                        domain=domain,
                        start=capture_start + timedelta(seconds=index * bucket_seconds),
                        request_count=len(members),
                        server_error_count=outcomes.count(RequestOutcome.SERVER_ERROR),
                        network_error_count=outcomes.count(RequestOutcome.NETWORK_ERROR),
                        client_error_count=outcomes.count(RequestOutcome.CLIENT_ERROR),
                        wait_sample_count=len(waits),
                        wait_p50_ms=percentile_sorted(waits, 50) if waits else None,
                        wait_max_ms=waits[-1] if waits else None,
                    )
                )
        return buckets, bucket_seconds

    # -------------------------------------------------------------------------
    # Incidents: failures grouped by endpoint and signature, with their evidence
    # -------------------------------------------------------------------------

    INCIDENT_SAMPLE_LIMIT = 5
    INCIDENT_CORRELATION_LIMIT = 3

    def _incidents(self, entries: list[HarEntry], clusters: list[TimeoutCluster]) -> list[Incident]:
        """One incident per (host, method, endpoint template, status or error category).

        Every failed request (network error, unexpected 4xx/5xx) is in exactly one
        incident, so the failure counts add up to the totals elsewhere in the report.
        """
        by_endpoint: dict[tuple[str, str, str], list[HarEntry]] = defaultdict(list)
        for entry in entries:
            key = (
                urlsplit(entry.request.url).netloc,
                entry.request.method.upper(),
                self.path_template(entry.request.url),
            )
            by_endpoint[key].append(entry)

        incidents: list[Incident] = []
        for (domain, method, endpoint), requests in by_endpoint.items():
            outcomes = [self.outcome(r) for r in requests]
            success_count = outcomes.count(RequestOutcome.SUCCESS)
            hard_failures = sum(
                outcome == RequestOutcome.SERVER_ERROR
                or (
                    outcome == RequestOutcome.NETWORK_ERROR
                    and classify_network_error(request) != "no_response"
                )
                for request, outcome in zip(requests, outcomes, strict=True)
            )
            is_outage = success_count == 0 and hard_failures >= OUTAGE_MIN_FAILURES
            by_signature: dict[str, list[HarEntry]] = defaultdict(list)
            for request, outcome in zip(requests, outcomes, strict=True):
                if outcome == RequestOutcome.NETWORK_ERROR:
                    by_signature[classify_network_error(request) or "no_response"].append(request)
                elif outcome in PROBLEM_OUTCOMES:
                    by_signature[str(request.response.status)].append(request)
            incidents.extend(
                self._build_incident(
                    domain,
                    method,
                    endpoint,
                    signature,
                    members,
                    endpoint_requests=requests,
                    clusters=clusters,
                    is_outage=is_outage,
                    success_count=success_count,
                )
                for signature, members in by_signature.items()
            )
        severity_order = {sev: idx for idx, sev in enumerate(IssueSeverity)}
        outcome_order = {
            RequestOutcome.SERVER_ERROR: 0,
            RequestOutcome.NETWORK_ERROR: 1,
            RequestOutcome.CLIENT_ERROR: 2,
        }
        return sorted(
            incidents,
            key=lambda i: (
                severity_order[i.severity],
                outcome_order.get(i.outcome, 3),
                -i.failure_count,
                i.first_failure,
                i.domain,
                i.endpoint,
                i.method,
                i.signature,
            ),
        )

    @staticmethod
    def _incident_fingerprints(
        members: list[HarEntry],
    ) -> tuple[dict[str, int], set[str], dict[str, int], str]:
        """Summarize fingerprints and keep body evidence separate for log guidance."""
        responders: dict[str, int] = defaultdict(int)
        body_responders: set[str] = set()
        exceptions: dict[str, int] = defaultdict(int)
        first_frame = ""
        for member in members:
            fingerprint = error_fingerprint(member)
            if not fingerprint:
                continue
            if fingerprint.responder:
                responder = fingerprint.responder
                if fingerprint.proxy_reason:
                    responder += f': "{fingerprint.proxy_reason}"'
                responders[f"{responder} [{fingerprint.source}]"] += 1
                if fingerprint.source == "body":
                    body_responders.add(fingerprint.responder)
            if fingerprint.exception:
                exceptions[fingerprint.root_cause or fingerprint.exception] += 1
                first_frame = first_frame or fingerprint.first_frame
        return responders, body_responders, exceptions, first_frame

    def _incident_cluster_evidence(
        self, members: list[HarEntry], clusters: list[TimeoutCluster]
    ) -> list[str]:
        """Evidence lines for duration clusters that cover this incident's requests."""
        first = members[0]
        cluster_key = f"{first.request.method.upper()} {self.endpoint_key(first.request.url)}"
        evidence: list[str] = []
        for cluster in clusters:
            if cluster_key not in cluster.endpoints:
                continue
            if first.response.status not in cluster.status_codes:
                continue
            text = (
                f"{cluster.endpoints[cluster_key]} of them took "
                f"~{format_duration_ms(cluster.median_ms)} ({cluster.basis}; range "
                f"{format_duration_ms(cluster.min_ms)} to {format_duration_ms(cluster.max_ms)})"
            )
            if cluster.matching_settings:
                text += (
                    "; the same length as "
                    + "; ".join(cluster.matching_settings)
                    + " (whether that setting applies to these requests is not verified)"
                )
            evidence.append(text)
        return evidence

    @staticmethod
    def _largest_headers_over_limit(members: list[HarEntry]) -> RequestHeaderSize | None:
        """The largest request header block when a size-related 4xx met the 8 KiB limits."""
        if members[0].response.status not in HEADER_SIZE_STATUSES:
            return None
        sizes = [size for m in members if (size := request_header_size(m)) is not None]
        return max(
            (size for size in sizes if size.near_default_limit),
            key=lambda size: size.total_bytes,
            default=None,
        )

    def _incident_severity(
        self, outcome: RequestOutcome, status: int, *, is_outage: bool, headers_over_limit: bool
    ) -> IssueSeverity:
        if outcome != RequestOutcome.CLIENT_ERROR:
            return IssueSeverity.CRITICAL if is_outage else IssueSeverity.HIGH
        notable = status in (
            self.HTTP_STATUS_UNAUTHORIZED,
            self.HTTP_STATUS_FORBIDDEN,
            self.HTTP_STATUS_RATE_LIMITED,
        )
        return IssueSeverity.HIGH if headers_over_limit or notable else IssueSeverity.MEDIUM

    def _build_incident(  # noqa: PLR0913 - one evidence roll-up per incident
        self,
        domain: str,
        method: str,
        endpoint: str,
        signature: str,
        members: list[HarEntry],
        *,
        endpoint_requests: list[HarEntry],
        clusters: list[TimeoutCluster],
        is_outage: bool,
        success_count: int,
    ) -> Incident:
        members = sorted(members, key=lambda m: (entry_end_time(m), m.entry_index))
        outcome = self.outcome(members[0])
        status = members[0].response.status
        responders, body_responders, exceptions, first_frame = self._incident_fingerprints(members)

        evidence: list[str] = []
        if responders:
            evidence.append(
                "responder: " + ", ".join(f"{name} ({n})" for name, n in responders.items())
            )
        if exceptions:
            text = ", ".join(f"{name} ({n})" for name, n in exceptions.items())
            evidence.append(f"exception: {text}" + (f" at {first_frame}" if first_frame else ""))
        if outcome == RequestOutcome.NETWORK_ERROR:
            evidence.append(f"consistent with: {NETWORK_ERROR_HINTS.get(signature, signature)}")
        cluster_evidence = self._incident_cluster_evidence(members, clusters)
        evidence.extend(cluster_evidence)
        largest_headers = (
            self._largest_headers_over_limit(members)
            if outcome == RequestOutcome.CLIENT_ERROR
            else None
        )
        if largest_headers:
            evidence.append(
                f"request headers {largest_headers.describe()}; {REQUEST_HEADER_LIMIT_NOTE}"
            )
        largest_body = max(m.request.body_bytes for m in members)
        if status == HTTP_STATUS_PAYLOAD_TOO_LARGE and largest_body > 0:
            evidence.append(f"largest request body {format_bytes(largest_body)}")

        nodes: dict[str, int] = defaultdict(int)
        correlation_ids: list[str] = []
        for member in members:
            node = self.backend_node(member)
            if node:
                nodes[node[0]] += 1
            for name, value in sorted(correlation_headers(member).items()):
                if f"{name}={value}" not in correlation_ids:
                    correlation_ids.append(f"{name}={value}")

        waits = [m.timings.wait for m in members if m.response.status and m.timings.wait >= 0]
        return Incident(
            severity=(
                IssueSeverity.MEDIUM
                if signature == "no_response"
                else self._incident_severity(
                    outcome, status, is_outage=is_outage, headers_over_limit=bool(largest_headers)
                )
            ),
            domain=domain,
            method=method,
            endpoint=endpoint,
            signature=signature,
            outcome=outcome,
            failure_count=len(members),
            endpoint_request_count=len(endpoint_requests),
            endpoint_success_count=success_count,
            first_failure=entry_end_time(members[0]),
            last_failure=entry_end_time(members[-1]),
            first_sent=min(
                (sent_at for m in members if (sent_at := request_sent_time(m)) is not None),
                default=None,
            ),
            min_wait_ms=min(waits, default=-1.0),
            max_wait_ms=max(waits, default=-1.0),
            evidence=evidence,
            entry_indexes=sorted(m.entry_index for m in members)[: self.INCIDENT_SAMPLE_LIMIT],
            correlation_ids=correlation_ids[: self.INCIDENT_CORRELATION_LIMIT],
            server_ips=sorted({m.server_ip_address for m in members if m.server_ip_address}),
            nodes=dict(sorted(nodes.items())),
            where_to_look=self._where_to_look(
                outcome,
                signature,
                body_responders=" ".join(sorted(body_responders)).lower(),
                exception=next(iter(exceptions), ""),
                first_frame=first_frame,
                headers_over_limit=bool(largest_headers),
                has_cluster=bool(cluster_evidence),
                slow_failure=min(waits, default=-1.0) >= self.FAST_ERROR_MS,
            ),
        )

    _NETWORK_WHERE_TO_LOOK: dict[str, str] = {  # noqa: RUF012 - read-only lookup table
        "no_response": (
            "The exporter recorded no HTTP response or error reason. Check whether the "
            "request was pending when the capture ended and review the browser Network panel."
        ),
        "connection_refused": (
            "Nothing accepted the connection: check that the listener (load balancer, web "
            "server or Tomcat connector) was running and the port open at these times"
        ),
        "connection_reset": (
            "The connection was dropped: read the proxy's error log at these times, check "
            "whether the JVM restarted or crashed (hs_err_pid*.log, OutOfMemoryError in "
            "catalina.out) and any idle timeout on the load balancer"
        ),
        "empty_response": (
            "The connection closed with no response: read the proxy's error log at these "
            "times (httpd logs AH01102 when its backend read fails) and check whether the "
            "JVM restarted or crashed"
        ),
        "truncated_response": (
            "The response was cut off part-way: read the proxy's error log at these times "
            "and catalina.out for an exception thrown while the response was being written"
        ),
        "timed_out": (
            "The browser reported a timeout. Use the recorded phases and browser-facing "
            "logs to distinguish connection setup from waiting for a response."
        ),
        "tls": (
            "Check the certificate chain, host name and TLS protocol settings on the tier "
            "that terminates TLS"
        ),
        "dns": "The client could not resolve the host name: check DNS from the client's network",
        "proxy_tunnel": "The client's forward proxy could not reach the site: check that proxy",
        "client_network_changed": "The client machine's own network dropped: not a server fault",
        "too_many_redirects": (
            "Follow the redirect chain in the capture: a loop between the application and "
            "the login service usually means the session cookie is not being kept"
        ),
        "blocked_by_response_policy": (
            "Compare the CORP / COEP / X-Frame-Options response headers with what the page "
            "embedding this resource requires"
        ),
    }
    _STATUS_WHERE_TO_LOOK: dict[int, str] = {  # noqa: RUF012 - read-only lookup table
        400: (
            "For 400: check which tier rejected the request. If Tomcat rejected it at "
            'the connector, look for "Error parsing HTTP request header" in its logs.'
        ),
        401: (
            "For 401: check the authentication service's log for this user and time, and "
            "whether the session or token had expired"
        ),
        403: (
            "For 403: check the authorization rules for this path; on POST/PUT/DELETE also "
            "check CSRF token handling after a session change"
        ),
        404: (
            "For 404: check that the web application (context) is deployed and started on "
            "every node, and the proxy's path mapping to it"
        ),
        413: (
            "For 413: identify the tier that rejected the body, then compare the request "
            "with its effective upload limit."
        ),
        429: "For 429: find which tier applies the rate limit and what it is keyed on",
        500: (
            "For 500: correlate the proxy and application logs for the request. If the "
            "application produced the error, look for an exception at that time."
        ),
        502: (
            "For 502: check whether the backend JVM restarted or was unreachable at these "
            "times, and compare the backend's keep-alive timeout (Tomcat keepAliveTimeout, "
            "which defaults to connectionTimeout) with how long the proxy reuses idle "
            "backend connections (httpd ProxyPass ttl)"
        ),
        503: (
            "For 503: check balancer member state at these times (a worker in error state "
            "is skipped for its retry interval) and whether the application was deployed "
            "and started"
        ),
        504: (
            "For 504: check which gateway timed out and whether it connected to its upstream. "
            "Correlate the gateway's error and timing with the next tier."
        ),
    }

    def _where_to_look(  # noqa: PLR0913 - evidence flags decide which advice applies
        self,
        outcome: RequestOutcome,
        signature: str,
        *,
        body_responders: str,
        exception: str,
        first_frame: str,
        headers_over_limit: bool,
        has_cluster: bool,
        slow_failure: bool = False,
    ) -> list[str]:
        """Which logs to open for an incident, from the evidence the capture holds."""
        tips: list[str] = []
        if exception:
            where = f" at {first_frame}" if first_frame else ""
            tips.append(
                f"Search the application log and catalina.out for {exception}{where} in the "
                "window above"
            )
        if any(name in body_responders for name in ("tomcat", "spring boot", "java application")):
            tips.append(
                "The captured body resembles a Java-tier error page. Confirm the responder "
                "by matching the request in the proxy and application access logs."
            )
        if "httpd" in body_responders:
            tips.append(
                "The body resembles an Apache httpd error page. Check httpd's error log "
                "for an upstream failure, then check the Tomcat access log for the request."
            )
        if "nginx" in body_responders:
            tips.append(
                "The body resembles an nginx error page. Check the nginx error log "
                "and upstream status, then correlate with the application access log."
            )
        if outcome == RequestOutcome.NETWORK_ERROR:
            tips.append(
                self._NETWORK_WHERE_TO_LOOK.get(
                    signature,
                    "See the browser console for this request; the capture records no more "
                    "than the error name",
                )
            )
            return tips
        if outcome == RequestOutcome.SERVER_ERROR and not body_responders:
            tips.append(
                "Start at the browser-facing load balancer or proxy. Compare the status "
                "it sent to the browser with its upstream status, then follow the request inward."
            )
        if headers_over_limit:
            tips.append(
                "Compare the captured header size with the effective limit and protocol "
                "at the tier that returned the response. Forwarded headers can differ."
            )
        status_tip = self._STATUS_WHERE_TO_LOOK.get(int(signature)) if signature.isdigit() else None
        if signature == "502" and slow_failure:
            # The restart / keep-alive advice is for fast 502s; this one waited.
            status_tip = (
                None
                if has_cluster
                else "For a delayed 502, check the proxy log for the upstream read error "
                "and assess which timer, if any, applied to the request."
            )
        if status_tip and not (exception and signature == "500"):
            tips.append(status_tip)
        if has_cluster and signature in ("502", "504"):
            tips.append(
                "Compare the duration cluster with upstream timing in the proxy log. "
                "Confirm the timer, failure reason and affected hop before investigating Tomcat."
            )
        return tips

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
            body_size = decoded_body_bytes(entry)
            if body_size <= 0 or self.is_served_locally(entry):
                continue
            total_analyzed += 1
            encoding = content_encoding(entry)
            if encoding != "identity":
                encoding_counts[encoding] += 1
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
        unknown_cache_count = 0
        missing_cache_control_count = 0
        repeated_downloads: list[dict[str, Any]] = []

        for url, url_entries in by_url.items():
            browser_hits = [
                e
                for e in url_entries
                if e.response.status == HTTP_STATUS_OK and self.is_browser_cache_hit(e)
            ]
            network_200s = [
                e
                for e in url_entries
                if e.response.status == HTTP_STATUS_OK
                and not self.is_served_locally(e)
                and not self.is_cache_source_unknown(e)
            ]
            unknown_cache_count += sum(self.is_cache_source_unknown(e) for e in url_entries)
            status_304_count = sum(
                1 for e in url_entries if e.response.status == HTTP_STATUS_NOT_MODIFIED
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
                        "total_bytes": sum(max(self.wire_bytes(e), 0) for e in network_200s),
                    }
                )
            if network_200s and _is_static_url(url) and not all(cache_controls):
                missing_cache_control_count += 1  # once per URL

        if not by_url:
            return None
        repeated_downloads.sort(key=lambda x: (-x["total_bytes"], x["url"]))
        served_without_download = not_modified_count + browser_cache_hit_count
        cacheable_get_count = served_without_download + network_download_count + unknown_cache_count
        return CacheAnalysis(
            cacheable_get_count=cacheable_get_count,
            not_modified_count=not_modified_count,
            browser_cache_hit_count=browser_cache_hit_count,
            network_download_count=network_download_count,
            unknown_cache_count=unknown_cache_count,
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

        def failed_at(issue: DetectedIssue) -> datetime:
            # An error is observed when the request fails, not when it starts: three
            # 60 s timeouts started a minute apart can all fail in the same second.
            return issue.timestamp + timedelta(milliseconds=max(issue.duration_ms or 0.0, 0.0))

        sorted_errors = sorted(error_issues, key=failed_at)
        window = timedelta(milliseconds=self.ERROR_BURST_WINDOW_MS)

        # Chain errors whose consecutive gap is <= the window; keep chains of 3+.
        groups: list[list[DetectedIssue]] = [[sorted_errors[0]]]
        for issue in sorted_errors[1:]:
            if failed_at(issue) - failed_at(groups[-1][-1]) <= window:
                groups[-1].append(issue)
            else:
                groups.append([issue])

        return [
            ErrorBurst(
                start_time=failed_at(group[0]),
                end_time=failed_at(group[-1]),
                error_count=len(group),
                affected_domains=sorted({i.domain for i in group}),
                endpoint_count=len(
                    {(i.domain, i.details.get("method"), i.details.get("endpoint")) for i in group}
                ),
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
        "jvm_stall",
        "session",
        "header_size",
        "body_limit",
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
                    severity=(
                        IssueSeverity.HIGH
                        if any(s.status_5xx_count for s in outages)
                        else IssueSeverity.MEDIUM
                    ),
                    summary=(
                        f"{len(outages)} endpoint(s) had repeated problems in this capture "
                        f"with no non-exempt 1xx-3xx outcome: {listed(outages)}"
                    ),
                    recommendation=(
                        "See the Incidents section for the evidence on each and which logs to open"
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
            has_upstream_read_clue = bool(cluster.proxy_reasons)
            evidence = {
                "gateway": "504 responses are consistent with a gateway/proxy timeout",
                "proxy_502": (
                    "502 responses can reflect an upstream read failure, including a timeout"
                ),
                "network": "the browser reported timeouts; the phase and tier may be unknown",
                "client_cancel": (
                    "browser cancellations may reflect a client-side timeout or cancellation"
                ),
                "failure": (
                    "similar failure durations alone do not establish a timeout or failing tier"
                ),
            }[cluster.kind]
            if cluster.proxy_reasons:
                evidence += "; error pages say " + ", ".join(
                    f'"{reason}" ({count})' for reason, count in cluster.proxy_reasons.items()
                )
            comparison = (
                "Settings of the same length (whether they apply to these requests is not "
                "verified): " + "; ".join(cluster.matching_settings) + "."
                if cluster.matching_settings
                else "No loaded configuration setting has this length."
                if report.config_facts_loaded
                else "No configuration facts were loaded to compare with (--config-facts)."
            )
            is_strong = cluster.kind in ("gateway", "network") or (
                cluster.kind == "proxy_502" and has_upstream_read_clue
            )
            findings.append(
                KeyFinding(
                    category="timeout_cluster",
                    severity=IssueSeverity.HIGH if is_strong else IssueSeverity.MEDIUM,
                    summary=(
                        f"{cluster.request_count} requests had similar durations "
                        f"({cluster.basis}): {format_duration_ms(cluster.min_ms)} to "
                        f"{format_duration_ms(cluster.max_ms)} ({statuses}); {evidence}"
                    ),
                    recommendation=(
                        comparison + " Check upstream timing and error logs. Browser wait and "
                        "elapsed duration have different boundaries from a proxy read timer "
                        "or a Tomcat Servlet async timeout."
                    ),
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
                    "See Incidents for the evidence per endpoint and Log Correlation for the "
                    "times to search in server logs (--export-events writes them as events)"
                ),
            )
        ]

    def _network_error_findings(self, report: HarAnalysisReport) -> list[KeyFinding]:
        if not report.network_errors_by_category:
            return []
        missing = report.network_errors_by_category.get("no_response", 0)
        total = sum(report.network_errors_by_category.values()) - missing
        by_type = ", ".join(
            f"{category} ({count})"
            for category, count in report.network_errors_by_category.items()
            if category != "no_response"
        )
        summary = f"{total} network error(s): {by_type}" if total else ""
        if missing:
            summary += ("; " if summary else "") + (
                f"{missing} request(s) with no HTTP response or recorded error reason"
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
                summary=summary,
                recommendation=f"Consistent with — {hints}",
            )
        ]

    def _stall_findings(self, report: HarAnalysisReport) -> list[KeyFinding]:
        findings: list[KeyFinding] = []
        for stall in report.stall_events[: self.FINDING_LIST_LIMIT]:
            one_connection = (
                " All of them were on one connection, so a stalled connection or proxy "
                "explains it equally well."
                if stall.connection_count == 1
                else ""
            )
            findings.append(
                KeyFinding(
                    category="jvm_stall",
                    severity=IssueSeverity.HIGH,
                    summary=(
                        f"{stall.request_count} requests to {stall.domain} on "
                        f"{stall.endpoint_count} endpoints, sent at different times, all got "
                        "their first byte within "
                        f"{format_duration_ms(stall.release_spread_ms)} of each other "
                        f"after waiting {format_duration_ms(stall.min_wait_ms)} to "
                        f"{format_duration_ms(stall.max_wait_ms)} (host median wait "
                        f"{format_duration_ms(stall.host_median_wait_ms)})"
                    ),
                    recommendation=(
                        "Responses arriving together suggest a shared delay. Possible causes "
                        "include a JVM-wide pause "
                        "(garbage collection or another safepoint), a shared lock or "
                        "exhausted pool that released, or a stalled proxy. Check the GC log "
                        "and thread dumps for the window in the Host-wide Stalls table; the "
                        "capture cannot tell these apart." + one_connection
                    ),
                )
            )
        return findings

    def _session_timeout_facts(self) -> list[tuple[float, str]]:
        """(seconds, description) for each session-timeout setting in the config facts."""
        facts: list[tuple[float, str]] = []
        for fact in self.config_facts:
            if re.split(r"[./\s]", fact.key.lower())[-1] == "session-timeout":
                seconds = timeout_fact_seconds(fact)
                if seconds is not None:
                    facts.append((seconds, describe_fact(fact)))
        return facts

    def _session_findings(self, report: HarAnalysisReport) -> list[KeyFinding]:
        findings: list[KeyFinding] = []
        by_kind: dict[str, list[SessionEvent]] = defaultdict(list)
        for event in report.session_events:
            by_kind[event.kind].append(event)

        redirects = by_kind["login_redirect"]
        if redirects:
            first = redirects[0]
            idle = (
                f" after a {first.idle_seconds:.0f}s gap between captured host requests"
                if first.idle_seconds is not None
                else ""
            )
            timeout_note = ""
            for seconds, description in self._session_timeout_facts():
                if first.idle_seconds is not None:
                    relation = "longer" if first.idle_seconds >= seconds else "shorter"
                    timeout_note = (
                        f" The idle time is {relation} than {description} "
                        f"({seconds / 60:g} min)"
                        + ". Verify that this setting applies and check the session's "
                        "actual last activity in server logs."
                    )
                    break
            writes = sum(
                e.request.split(" ", 1)[0].upper() in {"POST", "PUT", "PATCH", "DELETE"}
                for e in redirects
            )
            findings.append(
                KeyFinding(
                    category="session",
                    severity=IssueSeverity.HIGH if writes else IssueSeverity.MEDIUM,
                    summary=(
                        f"{len(redirects)} request(s) were redirected to the login page after "
                        f"the application had been answering (first: {first.request} on "
                        f"{first.domain}, entry {first.entry_index}{idle})"
                        + (
                            f"; {writes} possible write(s) with operation outcome unknown"
                            if writes
                            else ""
                        )
                    ),
                    recommendation=(
                        (
                            "Verify application logs or transaction state before retrying. "
                            if writes
                            else ""
                        )
                        + "Check the authentication decision and cookie scope. Session expiry "
                        "or failover are possible explanations." + timeout_note
                    ),
                )
            )

        route_changes = by_kind["route_changed"]
        if route_changes:
            first = route_changes[0]
            findings.append(
                KeyFinding(
                    category="session",
                    severity=IssueSeverity.HIGH,
                    summary=(
                        f"The session route changed {len(route_changes)} time(s) (first: "
                        f"{first.detail} on {first.domain}, entry {first.entry_index})"
                    ),
                    recommendation=(
                        "Check balancer routing and session continuity in server logs. "
                        "A changed route can accompany failover, reassignment, or a new session."
                    ),
                )
            )

        reissued_paths: dict[tuple[str, str], int] = defaultdict(int)
        for event in by_kind["reissued"]:
            reissued_paths[event.domain, event.detail.removesuffix(" value changed")] += 1
        repeated = {key: count for key, count in reissued_paths.items() if count >= 2}  # noqa: PLR2004
        if repeated:
            listed = ", ".join(
                f"{detail} on {domain} ({count} changes)"
                for (domain, detail), count in sorted(repeated.items())
            )
            findings.append(
                KeyFinding(
                    category="session",
                    severity=IssueSeverity.MEDIUM,
                    summary=f"A session cookie ID changed repeatedly: {listed}",
                    recommendation=(
                        "Compare the cookie changes with login, logout, and session "
                        "events in server logs. Authentication can legitimately rotate IDs."
                    ),
                )
            )
        return findings

    def _request_limit_findings(self, report: HarAnalysisReport) -> list[KeyFinding]:
        """Request headers or bodies running into size limits."""
        findings: list[KeyFinding] = []
        over_limit = [i for i in report.issues if i.details.get("request_headers_over_limit")]
        if over_limit:
            statuses = sorted({str(i.details.get("status")) for i in over_limit})
            findings.append(
                KeyFinding(
                    category="header_size",
                    severity=IssueSeverity.HIGH,
                    summary=(
                        f"{len(over_limit)} request(s) answered {'/'.join(statuses)} carried "
                        "headers near or above a common default limit"
                    ),
                    recommendation=(
                        f"Check the tier that returned the error and its logs, then "
                        f"{REQUEST_HEADER_LIMIT_NOTE}."
                    ),
                )
            )
        elif report.max_request_header_bytes >= REQUEST_HEADER_NEAR_LIMIT_BYTES:
            findings.append(
                KeyFinding(
                    category="header_size",
                    severity=IssueSeverity.LOW,
                    summary=(
                        f"Largest request headers in the capture: {report.max_request_header_note}"
                    ),
                    recommendation=(
                        f"If request headers are being rejected, {REQUEST_HEADER_LIMIT_NOTE}."
                    ),
                )
            )

        rejected = [
            issue
            for issue in report.issues
            if issue.details.get("status") == HTTP_STATUS_PAYLOAD_TOO_LARGE
            and issue.issue_type == IssueType.CLIENT_ERROR
        ]
        if rejected:
            largest = max((issue.size_bytes or 0 for issue in rejected), default=0)
            size_note = (
                f"bodies up to {format_bytes(largest)}" if largest else "body size unavailable"
            )
            findings.append(
                KeyFinding(
                    category="body_limit",
                    severity=IssueSeverity.HIGH,
                    summary=(f"{len(rejected)} upload(s) were rejected with 413 ({size_note})"),
                    recommendation=(
                        "Identify the tier that returned 413, then check its configured body "
                        "limit. A proxy, container or application can reject an upload."
                    ),
                )
            )
        oversized_forms = [
            b
            for b in report.large_request_bodies
            if b.note.startswith("form body over") and b.status >= HTTP_STATUS_BAD_REQUEST
        ]
        if oversized_forms:
            findings.append(
                KeyFinding(
                    category="body_limit",
                    severity=IssueSeverity.MEDIUM,
                    summary=(
                        f"{len(oversized_forms)} of the listed large request bodies were "
                        "forms over 2 MiB that received an error"
                    ),
                    recommendation=(
                        "If Tomcat parsed the form into request parameters, check the effective "
                        "Connector maxPostSize and the application logs. The HTTP error alone "
                        "does not identify a parameter parsing failure."
                    ),
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
                        f"Uncertain Date-header difference for {offset.domain}: "
                        f"{abs(offset.median_seconds):.0f}s {direction} "
                        "browser header-arrival time "
                        f"(n={offset.sample_count}); this is not a clock correction"
                    ),
                    recommendation=(
                        "Keep browser timestamps unchanged. Date can precede response completion "
                        "or be generated by an intermediary. Verify clock synchronization and "
                        "correlation IDs before aligning server logs."
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
                "Browser connection limits can cause HTTP/1.1 queueing; concurrent requests "
                "are candidates to investigate, not proven connection holders"
                if is_http1
                else "Requests queued in the browser before being sent"
            )
            findings.append(
                KeyFinding(
                    category="browser_queueing",
                    severity=IssueSeverity.MEDIUM,
                    summary=(
                        f"{len(issues)} request(s) to {domain} queued in the browser for "
                        f"over {format_duration_ms(self.settings.blocking_ms)} "
                        f"(longest {format_duration_ms(worst.duration_ms or 0.0)})"
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
            if e.served_wait_timings.count and not _is_static_url(e.url_pattern)
        ]
        if not candidates:
            return []
        slowest = max(
            candidates, key=lambda e: (tail_value(e.served_wait_timings), e.url_pattern, e.method)
        )
        value = tail_value(slowest.served_wait_timings)
        is_slow = value > self.settings.slow_endpoint_ms
        return [
            KeyFinding(
                category="slowest_server_time",
                severity=IssueSeverity.HIGH if is_slow else IssueSeverity.LOW,
                summary=(
                    "Slowest wait (TTFB) among non-5xx responses: "
                    f"{slowest.method} {urlparse(slowest.url_pattern).path} "
                    f"{tail_label(slowest.served_wait_timings)} {format_duration_ms(value)} "
                    f"(n={slowest.served_wait_timings.count})"
                ),
                recommendation=(
                    "TTFB covers network round trip, proxies and the application; compare "
                    "with TCP connect observations, then correlate proxy and "
                    "Tomcat access timings; "
                    ""
                    "inspect thread/dependency pools and JVM evidence "
                    "if server latency is confirmed"
                    if is_slow
                    else (
                        "Below the "
                        f"{format_duration_ms(self.settings.slow_endpoint_ms)} slow threshold"
                    )
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
                        f"{format_duration_ms(tail_value(report.dns_timings))} "
                        f"(n={report.dns_timings.count})"
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
            findings.append(
                KeyFinding(
                    category="compression",
                    severity=IssueSeverity.MEDIUM,
                    summary=(
                        f"{comp.compressible_uncompressed_count} response(s) "
                        f"({format_bytes(comp.compressible_uncompressed_bytes)}) could "
                        "benefit from compression"
                    ),
                    recommendation=(
                        "Enable compression on the tier that serves these responses. On a "
                        "Tomcat connector compression is off by default, and where sendfile "
                        "is in use (NIO) static files over 48 KiB are sent uncompressed "
                        "even with it on"
                    ),
                    frontend=True,
                )
            )

        cache = report.cache_analysis
        repeated_static = [
            r for r in (cache.repeated_downloads if cache else []) if _is_static_url(str(r["url"]))
        ]
        if repeated_static:
            wasted_bytes = sum(r["total_bytes"] for r in repeated_static)
            findings.append(
                KeyFinding(
                    category="caching",
                    severity=IssueSeverity.MEDIUM,
                    summary=(
                        f"{len(repeated_static)} static URL(s) fetched repeatedly over "
                        f"the network with no cache hit or 304 ({format_bytes(wasted_bytes)})"
                    ),
                    recommendation=(
                        "Add Cache-Control (and validators) on the tier that serves these "
                        "static resources"
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
            *self._stall_findings(report),
            *self._session_findings(report),
            *self._request_limit_findings(report),
            *self._slowest_server_time_findings(report),
        ]

        # A domain whose failures are already named as an outage is not reported again.
        outage_domains = {
            s.domain for s in report.service_failures if s.is_outage and not _is_static_path(s.path)
        }
        critical_domains = [
            d.domain
            for d in report.domains
            if d.health == DomainHealth.CRITICAL and d.domain not in outage_domains
        ]
        if critical_domains:
            findings.append(
                KeyFinding(
                    category="domain_health",
                    severity=IssueSeverity.CRITICAL,
                    summary=(
                        f"{len(critical_domains)} host(s) had a critical failure rate "
                        "in this capture: "
                        f"{', '.join(critical_domains)}"
                    ),
                    recommendation="Review the response and network error counts for these hosts",
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

        # A run on one endpoint is that endpoint's incident; a run across several
        # endpoints is its own signal (something they share failed).
        shared_runs = [b for b in report.error_bursts if b.endpoint_count > 1]
        if shared_runs:
            total_burst_errors = sum(b.error_count for b in shared_runs)
            all_domains = sorted({d for b in shared_runs for d in b.affected_domains})
            findings.append(
                KeyFinding(
                    category="error_burst",
                    severity=IssueSeverity.HIGH,
                    summary=(
                        f"{total_burst_errors} errors on several endpoints failed together in "
                        f"{len(shared_runs)} run(s) (each failing within "
                        f"{format_duration_ms(self.ERROR_BURST_WINDOW_MS)} of the previous) "
                        f"affecting {', '.join(all_domains)}"
                    ),
                    recommendation=(
                        "Different endpoints failing at the same moment points at something "
                        "they share (a backend node, a proxy, a database); see the Error "
                        "Runs table for the times"
                    ),
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
            "Blocked": report.blocked_timings.total_duration_ms,
            "Send": report.send_timings.total_duration_ms,
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
            "Blocked": (
                "Inspect browser queueing and concurrent requests; HAR cannot prove its cause"
            ),
            "Send": "Inspect upload size, link speed and server request-body consumption",
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
        phase_labels = PHASE_DISPLAY_NAMES
        return [
            KeyFinding(
                category="bottleneck",
                severity=IssueSeverity.LOW,
                summary=(
                    f"{phase_labels.get(dominant_phase, dominant_phase)} accounts "
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


def _format_bucket(seconds: int) -> str:
    """``10 s`` / ``5 min`` / ``6 h`` for a timeline bucket length."""
    if seconds < _SECONDS_PER_MINUTE:
        return f"{seconds} s"
    if seconds < _SECONDS_PER_MINUTE * _SECONDS_PER_MINUTE:
        return f"{seconds // _SECONDS_PER_MINUTE} min"
    return f"{seconds // (_SECONDS_PER_MINUTE * _SECONDS_PER_MINUTE)} h"


def _format_duration(td: timedelta) -> str:
    """A timedelta in the one duration style (see ``format_duration_ms``)."""
    return format_duration_ms(td.total_seconds() * 1000)


DOMAIN_TABLE_MAX_ROWS = 20
OUTAGE_TABLE_MAX_ROWS = 25
SERVICE_TABLE_MAX_ROWS = 25
ISSUES_BY_DOMAIN_MAX_DOMAINS = 15
ISSUES_BY_DOMAIN_MAX_ISSUES = 8
MARKDOWN_MAX_ISSUES_PER_SEVERITY = 50
INCIDENT_TABLE_MAX_ROWS = 15
SESSION_EVENT_TABLE_MAX_ROWS = 20
ISSUE_GROUP_VALUE_LIMIT = 3
TERMINAL_SHORT_CELL_CHARS = 16
ISSUE_GROUP_ENTRY_LIMIT = 8
MARKDOWN_TOP_ENDPOINTS = 10

# Infrastructure diagnostics display limits
SERVER_IPS_TABLE_MAX_ROWS = 15
TIME_GAP_TABLE_MAX_ROWS = 10
LARGE_REQUEST_BODY_TABLE_MAX_ROWS = 10
SERVER_SOFTWARE_MAX_DOMAINS = 10

# Path truncation limits for display
PATH_TRUNCATE_LONG = 80
PATH_TRUNCATE_MEDIUM = 60


CONNECTION_REUSE_UNAVAILABLE_MSG = "Not available: HAR has no connection IDs"


def format_percentiles(stats: TimingStatistics) -> str:
    """Percentiles the sample size supports: p95 needs n >= 20, p99 needs n >= 100."""
    if stats.count == 0:
        return "no data (n=0)"
    parts = [f"p50 {format_duration_ms(known_ms(stats.p50))}"]
    if stats.count >= MIN_SAMPLES_FOR_TAIL_PERCENTILES:
        parts.append(f"p95 {format_duration_ms(known_ms(stats.p95))}")
    if stats.count >= MIN_SAMPLES_FOR_P99:
        parts.append(f"p99 {format_duration_ms(known_ms(stats.p99))}")
        return f"{' / '.join(parts)} (n={stats.count})"
    parts.append(f"max {format_duration_ms(known_ms(stats.max))}")
    needs = (
        f"p95/p99 need n≥{MIN_SAMPLES_FOR_TAIL_PERCENTILES}"
        if stats.count < MIN_SAMPLES_FOR_TAIL_PERCENTILES
        else f"p99 needs n≥{MIN_SAMPLES_FOR_P99}"
    )
    return f"{' / '.join(parts)} (n={stats.count}; {needs})"


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


_BINARY_UNITS = ("KiB", "MiB", "GiB", "TiB")
_MS_PER_SECOND = 1000.0
_MS_PER_MINUTE = 60_000.0
_MINUTES_PER_HOUR = 60


def format_bytes(size_bytes: float) -> str:
    """``512 B``, ``1.5 KiB``, ``200.0 MiB`` (1024-based); ``unknown`` when negative.

    A non-zero size never prints as zero: anything below 1 KiB is shown in bytes.
    """
    if size_bytes < 0:
        return "unknown"
    if size_bytes < 1024:  # noqa: PLR2004 - one KiB
        return f"{size_bytes:,.0f} B"
    value = float(size_bytes) / 1024
    unit_index = 0
    while value >= 1024 and unit_index < len(_BINARY_UNITS) - 1:  # noqa: PLR2004 - next unit
        value /= 1024
        unit_index += 1
    return f"{value:,.1f} {_BINARY_UNITS[unit_index]}"


def format_duration_ms(milliseconds: float) -> str:
    """One duration style everywhere: ``<1 ms``, ``250 ms``, ``1.51 s``, ``2 min 5 s``.

    Precision is 1 ms below one second and 10 ms up to a minute (trailing zeros
    dropped); a non-zero duration never prints as zero. ``-`` when not recorded.
    """
    if milliseconds < 0:
        return "-"
    if milliseconds == 0:
        return "0 ms"
    if milliseconds < 1:
        return "<1 ms"
    if round(milliseconds) < _MS_PER_SECOND:
        return f"{milliseconds:.0f} ms"
    if round(milliseconds, -1) < _MS_PER_MINUTE:
        seconds = f"{milliseconds / _MS_PER_SECOND:.2f}".rstrip("0").rstrip(".")
        return f"{seconds} s"
    return _format_minutes(milliseconds)


def _format_minutes(milliseconds: float) -> str:
    """``1 min 0.4 s`` (10 ms precision) below an hour, ``2 h 5 min`` above."""
    minutes, rest_ms = divmod(round(milliseconds, -1), _MS_PER_MINUTE)
    if minutes < _MINUTES_PER_HOUR:
        seconds = f"{rest_ms / _MS_PER_SECOND:.2f}".rstrip("0").rstrip(".")
        return f"{minutes:.0f} min {seconds} s"
    hours, minutes = divmod(minutes, _MINUTES_PER_HOUR)
    return f"{hours:.0f} h {minutes:.0f} min"


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
    # (heading, lines) printed in full under the table: evidence too long for a cell.
    blocks: tuple[tuple[str, tuple[str, ...]], ...] = ()


def format_tail(stats: TimingStatistics) -> str:
    """Table cell for a tail latency: ``1234ms (p95, n=40)`` or ``900ms (max, n=3)``."""
    if stats.count == 0:
        return "-"
    return f"{format_duration_ms(tail_value(stats))} ({tail_label(stats)}, n={stats.count})"


def describe_thresholds(settings: AnalyzerSettings) -> list[str]:
    """Human-readable list of the thresholds and rules a report was produced with."""
    expected = ", ".join(f"`{rule}`" for rule in settings.expected_rules) or "none"
    lines = [
        (
            f"slow endpoint: wait for first byte > {format_duration_ms(settings.slow_endpoint_ms)} "
            "(p95; max when n<20; non-5xx responses)"
        ),
        f"request duration > {format_duration_ms(settings.duration_exceeded_ms)}",
        f"idle gap > {format_duration_ms(settings.idle_gap_ms)} with nothing in flight",
        f"client blocking > {format_duration_ms(settings.blocking_ms)}",
        f"large response > {format_bytes(settings.large_payload_bytes)} (decoded body)",
        f"large request body > {format_bytes(settings.large_request_body_bytes)}",
        f"redirect chain ≥ {settings.redirect_chain_min_hops} hops",
        (
            f"timeout cluster ≥ {settings.timeout_cluster_min_requests} requests with "
            f"durations within {settings.timeout_cluster_tolerance_pct:g}% of the shortest"
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
        # Set while printing to a terminal when the whole capture falls on one date:
        # table cells then show the time only, and the date is stated once.
        self._table_date: str | None = None

    @staticmethod
    def _print_table(table: Table) -> None:
        """Print a table without cutting cell text short: long values wrap instead."""
        for column in table.columns:
            column.overflow = "fold"
        console.print(table)

    def _table_time(self, ts: datetime, *, timespec: str = "milliseconds") -> str:
        """Timestamp for a table cell: time only when the date is stated once elsewhere."""
        full = self._format_timestamp(ts, timespec=timespec)
        date_text, _, time_text = full.partition("T")
        if self._table_date is None or date_text != self._table_date:
            return full
        return re.sub(r"(Z|[+-]\d{2}:\d{2})$", "", time_text)

    def _single_capture_date(self, report: HarAnalysisReport) -> tuple[str, str] | None:
        """(date, UTC offset) when the capture starts and ends on one date and offset."""
        if not report.capture_start or not report.capture_end:
            return None
        start = self._format_timestamp(report.capture_start)
        end = self._format_timestamp(report.capture_end)
        offset = re.search(r"(Z|[+-]\d{2}:\d{2})$", start)
        end_offset = re.search(r"(Z|[+-]\d{2}:\d{2})$", end)
        if start[:10] != end[:10] or not offset or not end_offset:
            return None
        if offset.group(1) != end_offset.group(1):
            return None
        return start[:10], offset.group(1)

    def print_report(self, report: HarAnalysisReport) -> None:
        """Print a backend/network-focused report to the terminal."""
        single_date = self._single_capture_date(report)
        self._table_date = single_date[0] if single_date else None
        try:
            self._print_report_sections(report)
        finally:
            self._table_date = None

    def _print_report_sections(self, report: HarAnalysisReport) -> None:
        single_date = self._single_capture_date(report)
        if single_date:
            console.print(
                f"[dim]Times in tables are on {single_date[0]} (UTC offset {single_date[1]}), "
                "browser clock.[/dim]"
            )
        backend_findings = [f for f in report.key_findings if not f.frontend]
        if backend_findings:
            self._print_findings_panel(backend_findings, "Key Findings", "yellow")
            console.print()

        incidents = self._incident_section(report)
        if incidents:
            self._print_section(incidents)
            console.print()

        # SECTION 1: METADATA & INFRASTRUCTURE
        self._print_summary(report)
        console.print()

        self._print_infrastructure_details(report)
        console.print()

        if report.server_ips_by_domain:
            self._print_server_ips_table(report)
            console.print()

        for section in (
            self._pages_section(report),
            *self._infrastructure_sections(report),
            self._time_gap_section(report),
            self._large_request_body_section(report),
        ):
            if section:
                self._print_section(section)
                console.print()

        if report.referer_hostnames:
            self._print_referer_hostnames(report)
            console.print()

        self._print_problem_sections(report)
        self._print_frontend_section(report)

    def _print_section(self, section: ReportSection) -> None:
        # Columns with nothing recorded in any row are named once instead of printed,
        # and short columns keep their natural width so long ones get the space.
        empty = [
            index
            for index in range(len(section.headers))
            if section.rows and all(row[index] == "-" for row in section.rows)
        ]
        table = Table(title=section.title, caption=section.note or None)
        for index, header in enumerate(section.headers):
            if index in empty:
                continue
            widest = max((len(row[index]) for row in section.rows), default=0)
            table.add_column(header, no_wrap=max(widest, len(header)) <= TERMINAL_SHORT_CELL_CHARS)
        for row in section.rows:
            table.add_row(
                *(rich_escape(cell) for index, cell in enumerate(row) if index not in empty)
            )
        self._print_table(table)
        if empty:
            names = ", ".join(section.headers[index] for index in empty)
            console.print(f"[dim]Not recorded for any row: {rich_escape(names)}[/dim]")
        for footnote in section.footnotes:
            console.print(f"[dim]{rich_escape(footnote)}[/dim]")
        for heading, block_lines in section.blocks:
            console.print(f"[bold]{rich_escape(heading)}[/bold]")
            for line in block_lines:
                console.print(f"  • {rich_escape(line)}", soft_wrap=False)

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
        for block_heading, block_lines in section.blocks:
            lines.extend([f"**{block_heading}**", ""])
            lines.extend(f"- {line}" for line in block_lines)
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

        for section in (
            *self._error_evidence_sections(report),
            *self._runtime_evidence_sections(report),
        ):
            self._print_section(section)
            console.print()

        backend_error_issues = self._filter_backend_error_issues(report.issues)
        if backend_error_issues:
            self._print_issues_by_domain(backend_error_issues, title="Backend/API Errors by Host")
            console.print()

        backend_perf_issues = self._filter_backend_perf_issues(report.issues)
        if backend_perf_issues:
            self._print_issues_by_domain(
                backend_perf_issues, title="Backend/API Performance Issues by Host"
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
                self._table_time(req.started),
                f"#{req.entry_index} {req.method} "
                f"{urlsplit(req.url).netloc}{self._extract_path(req.url)}",
                f"{req.status}" + (f" {req.error_category}" if req.error_category else ""),
                _ms_or_dash(req.total_ms),
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
                "TCP connect",
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

    # -------------------------------------------------------------------------
    # Incidents, log correlation, sessions, stalls, timeline
    # -------------------------------------------------------------------------

    def _time_range(self, first: datetime, last: datetime) -> str:
        first_text = self._table_time(first)
        if first == last:
            return first_text
        return f"{first_text} → {self._table_time(last)}"

    @staticmethod
    def seconds_range(low_ms: float, high_ms: float) -> str:
        """``1.51 s to 2 s``, or one value when both display the same."""
        if low_ms < 0 or high_ms < 0:
            return "-"
        low, high = format_duration_ms(low_ms), format_duration_ms(high_ms)
        return high if low == high else f"{low} to {high}"

    def _incident_section(self, report: HarAnalysisReport) -> ReportSection | None:
        """Failures grouped by endpoint and signature, each with evidence and next steps."""
        if not report.incidents:
            return None
        shown = report.incidents[:INCIDENT_TABLE_MAX_ROWS]
        rows: list[tuple[str, ...]] = []
        blocks: list[tuple[str, tuple[str, ...]]] = []
        for number, incident in enumerate(shown, start=1):
            failed = f"{incident.failure_count} of {incident.endpoint_request_count}"
            request = f"{incident.method} {incident.domain}{incident.endpoint}"
            rows.append(
                (
                    str(number),
                    incident.severity.value.upper(),
                    failed,
                    request,
                    incident.signature,
                    self._time_range(incident.first_failure, incident.last_failure),
                    self.seconds_range(incident.min_wait_ms, incident.max_wait_ms),
                )
            )
            search = "Correlate by request/trace ID when available. "
            search += (
                "Browser clock window "
                f"{self._format_timestamp(incident.first_sent, timespec='milliseconds')}"
                f" to {self._format_timestamp(incident.last_failure, timespec='milliseconds')}"
                if incident.first_sent is not None
                else "Browser send time unavailable; use the observed window above"
            )
            search += f" for {incident.method} {incident.endpoint}"
            if incident.signature.isdigit():
                search += f" (browser received {incident.signature})"
            keys: list[str] = []
            if incident.correlation_ids:
                keys.append("correlation " + ", ".join(incident.correlation_ids))
            if incident.server_ips:
                keys.append(f"browser peer IP {', '.join(incident.server_ips)}")
            if incident.nodes:
                keys.append(
                    "routing/responder hints "
                    + ", ".join(f"{name} ({count})" for name, count in incident.nodes.items())
                )
            more = incident.failure_count - len(incident.entry_indexes)
            keys.append(
                "HAR entries "
                + ", ".join(str(index) for index in incident.entry_indexes)
                + (f" (+{more} more)" if more > 0 else "")
            )
            lines = [
                *(f"Evidence: {item}" for item in incident.evidence),
                f"{search}; {'; '.join(keys)}",
                *(f"Next: {tip}" for tip in incident.where_to_look),
            ]
            blocks.append((f"Incident {number}: {request} → {incident.signature}", tuple(lines)))
        hidden = report.incidents[INCIDENT_TABLE_MAX_ROWS:]
        footnotes = (
            (
                f"... and {len(hidden)} more incident(s) covering "
                f"{sum(i.failure_count for i in hidden)} failed request(s)",
            )
            if hidden
            else ()
        )
        return ReportSection(
            title="Incidents (failed requests grouped by endpoint and signature)",
            note=(
                "Every failed request is in exactly one row. Signature = HTTP status or "
                "browser error category. Observed window uses request ends when recorded. "
                "Wait = recorded browser wait for the first byte; - = unavailable."
            ),
            headers=(
                "#",
                "Severity",
                "Failed",
                "Request",
                "Signature",
                "Observed window",
                "Wait",
            ),
            rows=rows,
            footnotes=footnotes,
            blocks=tuple(blocks),
        )

    def _log_correlation_section(self, report: HarAnalysisReport) -> ReportSection | None:
        if not report.log_correlation:
            return None
        rows: list[tuple[str, ...]] = []
        for req in report.log_correlation:
            server = ", ".join(part for part in (req.server_ip, req.node) if part) or "-"
            rows.append(
                (
                    str(req.entry_index),
                    self._table_time(req.sent_at) if req.sent_at else "-",
                    self._table_time(req.headers_at) if req.headers_at else "-",
                    f"{req.method} {urlsplit(req.url).netloc}{self._extract_path(req.url)}",
                    f"{req.status}" + (f" {req.error_category}" if req.error_category else ""),
                    _ms_or_dash(req.wait_ms),
                    _ms_or_dash(req.total_ms),
                    server,
                    ", ".join(f"{name}={value}" for name, value in sorted(req.correlation.items()))
                    or "-",
                )
            )
        offsets = [
            f"{o.domain} {o.median_seconds:+.0f}s"
            for o in report.clock_offsets
            if abs(o.median_seconds) > HarAnalyzer.CLOCK_OFFSET_REPORT_S
        ]
        offset_note = (
            " Date headers differ from the browser clock by "
            + ", ".join(offsets)
            + ": widen the search window by that much."
            if offsets
            else ""
        )
        return ReportSection(
            title="Log Correlation (failed and slowest requests, in time order)",
            note=(
                "Use correlation IDs first. Times are browser-side estimates based on "
                "recorded phases. The browser-facing status can differ from the upstream "
                "status. Wait and Total in ms. Tomcat can log request begin/end and %F "
                "for response commit. httpd %D is in microseconds; Tomcat %D is in "
                "milliseconds through Tomcat 9 and microseconds from Tomcat 10." + offset_note
            ),
            headers=(
                "Entry",
                "Browser send estimate",
                "First byte",
                "Request",
                "Status",
                "Wait",
                "Total",
                "Peer IP / routing hint",
                "Correlation IDs",
            ),
            rows=rows,
        )

    def _runtime_evidence_sections(self, report: HarAnalysisReport) -> list[ReportSection]:
        """Host-wide stalls, session events, the timeline and log-correlation times."""
        sections: list[ReportSection] = []
        if report.stall_events:
            sections.append(
                ReportSection(
                    title="Host-wide Stalls (requests sent apart, answered together)",
                    note=(
                        "Window = first of the requests sent → first delayed response "
                        "(browser clock): the period to look at in GC logs and thread dumps. "
                        "The capture cannot say what held the requests."
                    ),
                    headers=(
                        "Host",
                        "Window",
                        "Requests",
                        "Endpoints",
                        "Waited",
                        "Answered within",
                        "Connections",
                        "HAR entries",
                    ),
                    rows=[
                        (
                            s.domain,
                            self._time_range(s.stall_start, s.release_time),
                            str(s.request_count),
                            str(s.endpoint_count),
                            self.seconds_range(s.min_wait_ms, s.max_wait_ms),
                            f"{format_duration_ms(s.release_spread_ms)}",
                            str(s.connection_count) if s.connection_count else "not recorded",
                            ", ".join(str(index) for index in s.entry_indexes),
                        )
                        for s in report.stall_events[:DOMAIN_TABLE_MAX_ROWS]
                    ],
                )
            )
        if report.session_events:
            kinds = {
                "login_redirect": "redirected to login",
                "route_changed": "session route changed",
                "reissued": "session cookie ID changed",
                "cookie_refreshed": "same session cookie set again",
            }
            hidden = len(report.session_events) - SESSION_EVENT_TABLE_MAX_ROWS
            sections.append(
                ReportSection(
                    title="Session Events",
                    note=(
                        "Browser-visible login redirects and session cookie updates. "
                        "Cookie updates are ordered by estimated response time. Host gap "
                        "measures time since the previous captured request ended."
                    ),
                    headers=("Time", "Entry", "Host", "Request", "Event", "Detail", "Host gap"),
                    rows=[
                        (
                            self._table_time(e.timestamp),
                            str(e.entry_index),
                            e.domain,
                            e.request,
                            kinds.get(e.kind, e.kind),
                            e.detail,
                            f"{e.idle_seconds:.0f}s" if e.idle_seconds is not None else "-",
                        )
                        for e in report.session_events[:SESSION_EVENT_TABLE_MAX_ROWS]
                    ],
                    footnotes=(f"... and {hidden} more session event(s)",) if hidden > 0 else (),
                )
            )
        if report.timeline:
            sections.append(
                ReportSection(
                    title=(
                        f"Timeline ({_format_bucket(report.timeline_bucket_seconds)} buckets, "
                        "by request start)"
                    ),
                    note=(
                        "Busiest hosts only; buckets without requests are left out. Wait = "
                        "time to first byte of requests answered over the network."
                    ),
                    headers=(
                        "Host",
                        "From",
                        "Requests",
                        "5xx",
                        "Net errors",
                        "4xx",
                        "Wait p50",
                        "Wait max",
                    ),
                    rows=[
                        (
                            b.domain,
                            self._table_time(b.start, timespec="milliseconds"),
                            str(b.request_count),
                            str(b.server_error_count) if b.server_error_count else "-",
                            str(b.network_error_count) if b.network_error_count else "-",
                            str(b.client_error_count) if b.client_error_count else "-",
                            f"{format_duration_ms(b.wait_p50_ms)}"
                            if b.wait_p50_ms is not None
                            else "-",
                            f"{format_duration_ms(b.wait_max_ms)}"
                            if b.wait_max_ms is not None
                            else "-",
                        )
                        for b in report.timeline
                    ],
                )
            )
        log_correlation = self._log_correlation_section(report)
        if log_correlation:
            sections.append(log_correlation)
        return sections

    def _pages_section(self, report: HarAnalysisReport) -> ReportSection | None:
        if not report.pages:
            return None
        rows = [
            (
                self._table_time(page.started) if page.started else "-",
                self._display_detail(page.title) if page.title else page.page_id,
                format_duration_ms(page.dom_content_loaded_ms),
                format_duration_ms(page.load_ms),
                str(page.request_count),
                str(page.failed_count) if page.failed_count else "-",
                format_duration_ms(page.last_response_end_ms),
            )
            for page in report.pages[:DOMAIN_TABLE_MAX_ROWS]
        ]
        hidden = len(report.pages) - DOMAIN_TABLE_MAX_ROWS
        return ReportSection(
            title="Pages",
            note=(
                "Milestones are measured from each page's start (browser clock). Requests "
                "are those the capture assigned to the page. Some producers (Playwright) "
                "record one page for a whole session."
            ),
            headers=(
                "Started",
                "Page",
                "DOMContentLoaded",
                "Load",
                "Requests",
                "Failed",
                "Last request done",
            ),
            rows=rows,
            footnotes=(f"... and {hidden} more pages",) if hidden > 0 else (),
        )

    def _time_gap_section(self, report: HarAnalysisReport) -> ReportSection | None:
        if not report.time_gaps and not report.idle_gap_unknown_count:
            return None
        hidden = len(report.time_gaps) - TIME_GAP_TABLE_MAX_ROWS
        footnotes: list[str] = []
        if hidden > 0:
            footnotes.append(f"... and {hidden} more")
        if report.idle_gap_unknown_count:
            footnotes.append(
                f"{report.idle_gap_unknown_count} possible idle period(s) were not judged: a "
                "request of unknown duration started before them and may still have been "
                "running"
            )
        return ReportSection(
            title=(
                f"Idle Periods (>{format_duration_ms(report.settings.idle_gap_ms)} "
                "with no request in flight)"
            ),
            note="Idle from = when the last running request ended; the next request ended the gap.",
            headers=("Idle", "Idle from", "Next request", "Next request started"),
            rows=[
                (
                    f"{format_duration_ms(gap.gap_duration_ms)}",
                    self._table_time(gap.before_timestamp, timespec="milliseconds"),
                    self._extract_path(gap.after_url)[:PATH_TRUNCATE_LONG],
                    self._table_time(gap.after_timestamp, timespec="milliseconds"),
                )
                for gap in report.time_gaps[:TIME_GAP_TABLE_MAX_ROWS]
            ],
            footnotes=tuple(footnotes),
        )

    def _large_request_body_section(self, report: HarAnalysisReport) -> ReportSection | None:
        if not report.large_request_bodies:
            return None
        hidden = len(report.large_request_bodies) - LARGE_REQUEST_BODY_TABLE_MAX_ROWS
        return ReportSection(
            title=(
                f"Large Request Bodies (>{format_bytes(report.settings.large_request_body_bytes)})"
            ),
            note="",
            headers=("Size", "Method", "Path", "Content-Type", "Status", "Note"),
            rows=[
                (
                    format_bytes(body.body_size_bytes),
                    body.method,
                    self._extract_path(body.url)[:PATH_TRUNCATE_MEDIUM],
                    body.content_type[:40] if body.content_type else "-",
                    str(body.status),
                    body.note or "-",
                )
                for body in report.large_request_bodies[:LARGE_REQUEST_BODY_TABLE_MAX_ROWS]
            ],
            footnotes=(f"... and {hidden} more",) if hidden > 0 else (),
        )

    def _error_evidence_sections(self, report: HarAnalysisReport) -> list[ReportSection]:
        """5xx error origin and per-backend-node tables (only when there is data)."""
        sections: list[ReportSection] = []
        if report.error_origins:
            hints = {o.status: o.status_hint for o in report.error_origins if o.status_hint}
            readings = tuple(
                (
                    f"{o.domain} {o.status}",
                    (
                        f"Reading: {o.reading}",
                        f"Compared with: {o.comparison_scope}",
                        *(
                            (f"Java exception: {self._counts_text(o.exceptions)}",)
                            if o.exceptions
                            else ()
                        ),
                    ),
                )
                for o in report.error_origins
            )
            sections.append(
                ReportSection(
                    title="5xx Error Origin Clues",
                    note=(
                        "Page fingerprints and headers suggest possible responders. "
                        "Median wait uses recorded browser wait values."
                    ),
                    headers=(
                        "Host",
                        "Status",
                        "Count",
                        "Median wait",
                        "Error page / headers say",
                        "Server on errors",
                        "Server on successes",
                        "Content-Type on errors",
                        "With Via",
                    ),
                    rows=[
                        (
                            o.domain,
                            str(o.status),
                            str(o.count),
                            f"{format_duration_ms(o.median_active_ms)}"
                            if o.median_active_ms >= 0
                            else "-",
                            self._counts_text(o.fingerprints),
                            self._counts_text(o.error_servers),
                            self._counts_text(o.success_servers),
                            self._counts_text(o.error_content_types),
                            str(o.via_count),
                        )
                        for o in report.error_origins
                    ],
                    footnotes=tuple(
                        f"{status} is consistent with: {hint}"
                        for status, hint in sorted(hints.items())
                    ),
                    blocks=readings,
                )
            )
        if report.backend_nodes:
            sections.append(
                ReportSection(
                    title="Response Responder Hints",
                    note=(
                        "Counts group responses by X-Served-By. A proxy or cache can set this "
                        "header. Confirm the serving backend in deployment logs."
                    ),
                    headers=(
                        "Host",
                        "Hint",
                        "Source",
                        "Responses",
                        "5xx",
                        "Net errors",
                        "Tail total",
                    ),
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
                    title="Date Header Differences (uncertain; not clock corrections)",
                    note=(
                        "Date minus browser header-arrival time. This is the clock of "
                        "whichever tier set the Date header, not necessarily the application "
                        "server: nginx replaces the backend's Date by default. Do not use it "
                        "to correct log timestamps."
                    ),
                    headers=("Host", "Offset", "Samples", "Server header on sampled responses"),
                    rows=[
                        (
                            o.domain,
                            f"{o.median_seconds:+.1f}s",
                            str(o.sample_count),
                            self._counts_text(o.date_servers),
                        )
                        for o in report.clock_offsets
                    ],
                )
            )
        if report.host_connection_stats:
            sections.append(
                ReportSection(
                    title="Connections per Host",
                    note=(
                        "Positive connect time is evidence of connection setup. Browser limits and "
                        "multiplexing vary; missing connect timing does not prove reuse."
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
                "Responder hints: no usable X-Served-By response header in the capture. "
                "Cookie routes, when available, indicate affinity."
            )
        if not report.clock_offsets:
            lines.append(
                "Clock offset: not available (fewer than "
                f"{HarAnalyzer.CLOCK_OFFSET_MIN_SAMPLES} usable Date response headers per host)"
            )
        if report.cookie_header_request_count == 0:
            lines.append(
                "Session cookie evidence (session re-issue, route change): not available "
                "(no Cookie or Set-Cookie headers in the capture; a sanitized export removes "
                "them). Redirects to a login page are still detected."
            )
        if report.error_response_count and report.error_body_count == 0:
            lines.append(
                "Error page text: not available (the capture kept no body for any of the "
                f"{report.error_response_count} 4xx/5xx responses), so the tier that wrote an "
                "error can only be inferred from headers"
            )
        return lines

    def _capture_note_lines(self, report: HarAnalysisReport) -> list[str]:
        """What was left out of or assumed about the capture (empty when nothing)."""
        notes = report.load_notes
        lines: list[str] = [
            "Scope: observations from this browser capture, not service-wide health or throughput. "
            "HAR alone cannot establish GC pauses, thread exhaustion or database contention."
        ]
        lines.append(self._latency_population_line(report))
        if report.timing_warning_count:
            lines.append(
                f"WARNING: timing quality warnings on {report.timing_warning_count} request(s): "
                + "; ".join(report.timing_warning_examples)
            )
        if report.derived_duration_count or report.unavailable_duration_count:
            lines.append(
                f"Total timing: {report.derived_duration_count} derived from phases; "
                f"{report.unavailable_duration_count} unavailable "
                "and excluded from duration statistics. "
                "Capture duration and request rate may be incomplete; "
                "an idle period that follows a request of unknown duration is not judged."
            )
        lines.append(
            f"Transfer evidence: {report.transfer_unknown_count} request(s) with unknown bytes; "
            f"{report.transfer_body_only_count} with body bytes only (headers excluded). "
            "Best-effort transfer totals are a lower bound when evidence is incomplete."
        )
        if report.backend_unknown_request_count:
            failures = report.backend_unknown_failure_count
            lines.append(
                "Routing evidence unavailable for "
                f"{report.backend_unknown_request_count} request(s)"
                + (f", including {failures} 5xx/network failure(s)." if failures else ".")
            )
        if report.backend_ambiguous_request_count:
            lines.append(
                f"{report.backend_ambiguous_request_count} request(s) carried session cookies "
                "naming several different routes (one cookie per application path); no routing "
                "hint was assigned to them."
            )
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
        excluded = [
            f"{count:,} {label}"
            for count, label in (
                (population.browser_cache_hit_count, "served by the browser cache"),
                (population.service_worker_count, "served by a service worker"),
                (population.aborted_count, "cancelled, blocked or not sent"),
                (population.network_error_count, "network error(s)"),
                (population.timing_unavailable_count, "without a recorded total time"),
                (population.cache_source_unknown_count, "cache or network source unknown"),
            )
            if count
        ]
        return f"Percentiles cover the {population.measured_count:,} request(s) answered over " + (
            f"the network; not included: {'; '.join(excluded)}" if excluded else "the network"
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
        incidents = self._incident_section(report)
        if incidents:
            lines.extend(self._md_section(incidents))
        lines.extend(self._md_hostnames(report))
        lines.extend(self._md_summary(report))
        lines.extend(self._md_infrastructure_details(report))
        # SECTION 2: PROBLEM ANALYSIS
        lines.extend(self._md_timeout_clusters(report))
        lines.extend(self._md_domain_health(report))
        lines.extend(self._md_outages(report))
        lines.extend(self._md_service_health(report))
        for section in (
            *self._error_evidence_sections(report),
            *self._runtime_evidence_sections(report),
        ):
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
            ("Queued (in the browser)", report.blocked_timings),
            ("DNS", report.dns_timings),
            ("TCP connect", report.connect_timings),
            ("TLS", report.ssl_timings),
            ("Send", report.send_timings),
            (self._ttfb_label(report), report.ttfb_timings),
            ("Receive", report.receive_timings),
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
        lines.extend(
            f"{INFORMATIONAL_LABELS.get(category, category)} (informational): {count:,}"
            for category, count in report.informational_by_category.items()
        )
        if report.network_errors_by_category:
            by_type = ", ".join(
                f"{category} {count}"
                for category, count in report.network_errors_by_category.items()
            )
            lines.append(f"network errors: {by_type}")
        return lines

    def _md_summary(self, report: HarAnalysisReport) -> list[str]:
        total_status = sum(report.status_codes.values()) or 1

        lines = ["## Summary", ""]
        lines.append(f"- **Total Requests:** {report.total_requests:,}")
        lines.append(
            "- **Total Duration (sum of request times):** "
            f"{format_duration_ms(report.total_duration_ms)}"
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
            f"- **Total transferred (best effort):** {format_bytes(report.total_bytes_transferred)}"
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
                f"({format_duration_ms(phase.total_ms)})"
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
        "Host",
        "Requests",
        "Failures",
        "Failure rate",
        "5xx",
        "Net errors",
        "Expected",
        "Cancelled/blocked",
        "Tail total",
        "TCP connect median",
        "Most time in",
        "Status",
    )
    DOMAIN_HEALTH_TERMINAL_HIDDEN = frozenset(
        {"Expected", "Cancelled/blocked", "TCP connect median"}
    )
    DOMAIN_HEALTH_NOTE = (
        "Status describes the captured requests. Net errors include entries without an HTTP "
        "response or recorded cause. TCP connect median is observed setup time. "
        "Most time in: "
        "wait = time to first byte (round trip + proxies + application), network = DNS + "
        "connect + TLS + receive, client = browser queueing + send."
    )

    @staticmethod
    def _domain_health_cells(domain: DomainAnalysis) -> tuple[str, ...]:
        round_trip = (
            f"{format_duration_ms(domain.round_trip_estimate_ms)} "
            f"(n={domain.round_trip_sample_count})"
            if domain.round_trip_estimate_ms is not None
            else "-"
        )
        return (
            domain.domain,
            str(domain.total_requests),
            str(domain.failed_requests),
            f"{domain.failure_rate_pct:.1f}%",
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
                title="Host Health",
                note=self.DOMAIN_HEALTH_NOTE,
                headers=self.DOMAIN_HEALTH_HEADERS,
                rows=[self._domain_health_cells(domain) for domain in report.domains],
            )
        )

    def _md_service_health(self, report: HarAnalysisReport) -> list[str]:
        failing = self._failing_services(report.service_failures)
        if not failing:
            return []
        over_label = f">{format_duration_ms(report.settings.duration_exceeded_ms)}"
        lines = ["## Backend/API Service Health", ""]
        lines.append(
            "| Host | Method | Path | Req | 1xx-3xx | Expected | Cancelled/blocked | Net errors "
            f"| 5xx | 4xx | {over_label} | Problem rate | Tail total | Tail wait (TTFB) "
            "| Tail net |"
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
            "| Host | Method | Path | Req | Net errors | 5xx | 4xx | First Seen | Last Seen |"
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

    # Issue details shown to the reader, with the label each is printed under. Anything
    # not listed is internal (already in the headline, or a grouping key).
    DETAIL_LABELS: dict[str, str] = {  # noqa: RUF012 - read-only lookup table
        "error": "Browser error",
        "responder": "Responder",
        "request_headers": "Request headers",
        "request_body": "Request body",
        "server_ip": "Server IP",
        "correlation": "Correlation IDs",
        "referer_hostname": "Referer host",
        "http_version": "HTTP version",
        "in_flight_meanwhile": "In flight meanwhile",
        "chain": "Chain",
        "content_type": "Content type",
        "bytes_on_wire": "Bytes on wire",
        "served_locally": "Served by the browser cache or a service worker",
        "may_be_in_flight_at_capture_end": "May have been in flight when the capture was saved",
        "over_duration_threshold": "Over the duration threshold",
        "timing_warnings": "Timing warnings",
        "duration_source": "Duration source",
    }

    def _issue_groups(self, issues: list[DetectedIssue]) -> list[list[DetectedIssue]]:
        """Group issues that say the same thing about the same endpoint (order kept).

        The groups partition ``issues``: their sizes add up to ``len(issues)``.
        """
        groups: dict[tuple[object, ...], list[DetectedIssue]] = {}
        for issue in issues:
            key = (
                issue.issue_type,
                issue.severity,
                issue.domain,
                issue.details.get("method"),
                issue.details.get("endpoint") or issue.url,
                issue.details.get("group_label") or issue.message,
            )
            groups.setdefault(key, []).append(issue)
        return list(groups.values())

    def _group_headline(self, group: list[DetectedIssue]) -> tuple[str, str]:
        """(what happened, which request) for a group of identical issues."""
        first = group[0]
        method = first.details.get("method")
        method_text = f"{method} " if method else ""
        if len(group) == 1:
            return first.message, f"{method_text}{self._extract_path(first.url)}"
        label = str(first.details.get("group_label") or first.message)
        endpoint = str(first.details.get("endpoint") or self._extract_path(first.url))
        return f"{len(group)}x {label}", f"{method_text}{endpoint}"

    def _group_when(self, group: list[DetectedIssue]) -> str:
        timestamps = [issue.timestamp for issue in group]
        return self._time_range(min(timestamps), max(timestamps))

    @staticmethod
    def _group_entries(group: list[DetectedIssue]) -> str:
        indexes = sorted(
            int(index) for issue in group if (index := issue.details.get("entry_index"))
        )
        if not indexes:
            return ""
        shown = ", ".join(str(index) for index in indexes[:ISSUE_GROUP_ENTRY_LIMIT])
        more = len(indexes) - ISSUE_GROUP_ENTRY_LIMIT
        return shown + (f" (+{more} more)" if more > 0 else "")

    def _group_detail_lines(self, group: list[DetectedIssue]) -> list[str]:
        """Labelled details; values that differ within the group are listed (first few)."""
        lines: list[str] = []
        durations = [issue.duration_ms for issue in group if issue.duration_ms is not None]
        if durations:
            low, high = min(durations), max(durations)
            lines.append(f"Duration: {self.seconds_range(low, high)}")
        entries = self._group_entries(group)
        if entries:
            lines.append(f"HAR entries: {entries}")
        sent = [issue.details["sent_at"] for issue in group if "sent_at" in issue.details]
        if sent:
            lines.append("Browser send estimate: " + self._time_range(min(sent), max(sent)))
        for key, label in self.DETAIL_LABELS.items():
            values: list[str] = []
            for issue in group:
                value = issue.details.get(key)
                if value in (None, "", False) or (key == "duration_source" and value == "recorded"):
                    continue
                text = "yes" if value is True else self._display_detail(value)
                if text not in values:
                    values.append(text)
            if not values:
                continue
            more = len(values) - ISSUE_GROUP_VALUE_LIMIT
            shown = "; ".join(values[:ISSUE_GROUP_VALUE_LIMIT])
            lines.append(f"{label}: {shown}" + (f" (+{more} more)" if more > 0 else ""))
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
            groups = self._issue_groups(severity_issues)
            lines.append(
                f"### {severity.value.upper()} ({len(severity_issues)} in {len(groups)} group(s))"
            )
            lines.append("")
            for group in groups[:MARKDOWN_MAX_ISSUES_PER_SEVERITY]:
                lines.extend(self._md_issue_detail(group))
            if len(groups) > MARKDOWN_MAX_ISSUES_PER_SEVERITY:
                hidden = groups[MARKDOWN_MAX_ISSUES_PER_SEVERITY:]
                lines.append(
                    f"*... and {len(hidden)} more group(s) covering "
                    f"{sum(len(g) for g in hidden)} issue(s) in this severity*"
                )
                lines.append("")
        return lines

    def _md_issue_detail(self, group: list[DetectedIssue]) -> list[str]:
        what, request = self._group_headline(group)
        lines = [
            f"- **{what}**",
            f"  - Request: `{request}`",
            f"  - Host: `{group[0].domain}`",
            f"  - When (request start): `{self._group_when(group)}`",
        ]
        lines.extend(f"  - {line}" for line in self._group_detail_lines(group))
        lines.append("")
        return lines

    def _md_top_endpoints(self, report: HarAnalysisReport) -> list[str]:
        filtered_endpoints = report.endpoints
        if not filtered_endpoints:
            return []
        lines = [f"## {self.SLOWEST_ENDPOINTS_TITLE}", ""]
        lines.append(
            "Tail = p95 when n ≥ 20, otherwise max. IDs in paths are templated "
            "(`{uuid}`, `{n}`, `{hex}`). " + self.DOMINANT_SIDE_NOTE
        )
        lines.append("")
        lines.append(
            "| Endpoint Template | Count | Tail total | Tail wait (TTFB) | Tail net "
            "| Most time in |"
        )
        lines.append(
            "|-------------------|-------|------------|------------------|----------|----------|"
        )
        for endpoint in filtered_endpoints[:MARKDOWN_TOP_ENDPOINTS]:
            path = urlparse(endpoint.url_pattern).path
            identity = f"{endpoint.method} {urlsplit(endpoint.url_pattern).netloc}{path}"
            lines.append(
                f"| `{md_cell(identity)}` | {endpoint.count} | {format_tail(endpoint.timings)} | "
                f"{format_tail(endpoint.served_wait_timings)} | "
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

    SLOWEST_ENDPOINTS_TITLE = "Slowest Endpoints by Wait (TTFB, non-5xx responses)"
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
        if isinstance(value, datetime):
            return self._format_timestamp(value, timespec="milliseconds")
        if isinstance(value, float):
            return f"{value:.0f}"
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
            "**Total Duration (sum of request times):** "
            f"{format_duration_ms(report.total_duration_ms)}"
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
        summary_lines.append(
            f"**Total transferred (best effort):** {format_bytes(report.total_bytes_transferred)}"
        )
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
                f"**Observed browser request rate:** {rr.overall_requests_per_second:.2f} req/s "
                f"(peak: {rr.peak_requests_per_second:.0f} req/s)"
            )

        if report.phase_breakdown:
            summary_lines.append("")
            summary_lines.append("**Phase Breakdown (share of summed phase time):**")
            summary_lines.extend(
                f"- {phase.phase_name}: {phase.percentage_of_total:.0f}% "
                f"({format_duration_ms(phase.total_ms)})"
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

    def format_timestamp(self, ts: datetime, *, timespec: str = "milliseconds") -> str:
        """Format a timestamp in the configured display timezone."""
        return self._format_timestamp(ts, timespec=timespec)

    def extract_path(self, url: str) -> str:
        """Path with query values redacted (unless --show-query)."""
        return self._extract_path(url)

    def response_class_lines(self, report: HarAnalysisReport) -> list[str]:
        """Status-class counts plus expected / aborted / network error breakdown."""
        return self._response_class_lines(report)

    def _format_timestamp(self, ts: datetime, *, timespec: str = "milliseconds") -> str:
        if self._timestamp_timezone is None:
            return ts.isoformat(timespec=timespec)
        return ts.astimezone(self._timestamp_timezone).isoformat(timespec=timespec)

    def _ttfb_label(self, report: HarAnalysisReport) -> str:
        """Label wait time honestly: it is not server time alone."""
        measured = report.latency_population.measured_count if report.latency_population else 0
        missing_ttfb_count = measured - report.ttfb_timings.count
        if missing_ttfb_count > 0:
            return (
                "Wait (TTFB: network round trip + proxies + application; "
                f"{missing_ttfb_count} of {measured} had none recorded)"
            )
        return "Wait (TTFB: network round trip + proxies + application)"

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
            caption += f" ... and {len(report.domains) - DOMAIN_TABLE_MAX_ROWS} more hosts"
        # The terminal leaves out the columns that are zero in most captures and the
        # connect median; the Markdown report has all of them.
        hidden = [
            index
            for index, header in enumerate(self.DOMAIN_HEALTH_HEADERS)
            if header in self.DOMAIN_HEALTH_TERMINAL_HIDDEN
        ]
        caption += (
            " Expected, Cancelled/blocked and TCP connect median are in the Markdown report (-o)."
        )
        table = Table(title="Host Health", caption=caption)
        for index, header in enumerate(self.DOMAIN_HEALTH_HEADERS):
            if index not in hidden:
                table.add_column(header, justify="left" if header == "Host" else "right")
        health_styles = {
            DomainHealth.CRITICAL: "bold red",
            DomainHealth.DEGRADED: "yellow",
            DomainHealth.HEALTHY: "green",
        }
        for domain in report.domains[:DOMAIN_TABLE_MAX_ROWS]:
            *cells, status_text = self._domain_health_cells(domain)
            style = health_styles[domain.health]
            table.add_row(
                *(rich_escape(cell) for index, cell in enumerate(cells) if index not in hidden),
                f"[{style}]{status_text}[/{style}]",
            )
        self._print_table(table)

    OUTAGE_TITLE = (
        f"Repeated Endpoint Problems in This Capture "
        f"(no non-exempt 1xx-3xx, {OUTAGE_MIN_FAILURES}+ 5xx or browser problems)"
    )

    def _outages(self, services: list[ServiceFailureStats]) -> list[ServiceFailureStats]:
        return [s for s in services if s.is_outage]

    def _failing_services(self, services: list[ServiceFailureStats]) -> list[ServiceFailureStats]:
        return [s for s in services if s.problem_count > 0]

    def _print_outages(self, services: list[ServiceFailureStats], max_rows: int) -> None:
        outages = self._outages(services)
        if not outages:
            return

        table = Table(title=self.OUTAGE_TITLE)
        table.add_column("Host", style="cyan", no_wrap=False)
        table.add_column("Method", style="cyan", no_wrap=True)
        table.add_column("Path", style="cyan", no_wrap=False)
        table.add_column("Req", justify="right")
        table.add_column("Net errors", justify="right", style="red")
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
                self._format_timestamp(s.first_seen, timespec="milliseconds"),
                self._format_timestamp(s.last_seen, timespec="milliseconds"),
            )

        self._print_table(table)

    def _print_service_failures(self, report: HarAnalysisReport, max_rows: int) -> None:
        failing = self._failing_services(report.service_failures)
        if not failing:
            return

        # One Endpoint column and the counts that decide where to look; Expected,
        # Aborted, total and network tails are in the Markdown report.
        table = Table(
            title="Backend/API Service Health",
            caption=(
                "Expected, Cancelled/blocked, Tail total and Tail net are in the Markdown "
                "report (-o)."
            ),
        )
        table.add_column("Endpoint", style="cyan", no_wrap=False)
        table.add_column("Req", justify="right")
        table.add_column("1xx-3xx", justify="right", style="green")
        table.add_column("Net errors", justify="right", style="red")
        table.add_column("5xx", justify="right", style="red")
        table.add_column("4xx", justify="right", style="yellow")
        table.add_column(
            f">{format_duration_ms(report.settings.duration_exceeded_ms)}",
            justify="right",
            style="red",
        )
        table.add_column("Problem rate", justify="right", style="bold")
        table.add_column("Tail wait (TTFB)", justify="right")

        for s in failing[:max_rows]:
            table.add_row(
                f"{s.method} {s.domain}{s.path}",
                str(s.request_count),
                str(s.success_count) if s.success_count else "-",
                str(s.network_error_count) if s.network_error_count else "-",
                str(s.status_5xx_count) if s.status_5xx_count else "-",
                str(s.status_4xx_count) if s.status_4xx_count else "-",
                str(s.duration_exceeded_count) if s.duration_exceeded_count else "-",
                f"{s.problem_rate * 100:.1f}%",
                format_tail(s.ttfb_timings),
            )

        self._print_table(table)
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

            groups = self._issue_groups(domain_issues)
            for group in groups[:ISSUES_BY_DOMAIN_MAX_ISSUES]:
                color = severity_colors[group[0].severity]
                what, request = self._group_headline(group)
                branch = domain_branch.add(
                    f"[{color}]{rich_escape(what)}[/{color}]: {rich_escape(request)} "
                    f"[bold magenta]@ {self._group_when(group)}[/bold magenta]"
                )
                for line in self._group_detail_lines(group):
                    branch.add(f"[dim]{rich_escape(line)}[/dim]")

            if len(groups) > ISSUES_BY_DOMAIN_MAX_ISSUES:
                hidden = groups[ISSUES_BY_DOMAIN_MAX_ISSUES:]
                domain_branch.add(
                    f"[dim]... and {len(hidden)} more group(s) covering "
                    f"{sum(len(g) for g in hidden)} issue(s)[/dim]"
                )

        if len(sorted_domains) > ISSUES_BY_DOMAIN_MAX_DOMAINS:
            remaining_domains = len(sorted_domains) - ISSUES_BY_DOMAIN_MAX_DOMAINS
            tree.add(f"[dim]... and {remaining_domains} more hosts[/dim]")

        console.print(tree)

    def _print_top_endpoints(self, report: HarAnalysisReport) -> None:
        filtered = report.endpoints
        if not filtered:
            return

        table = Table(
            title=self.SLOWEST_ENDPOINTS_TITLE,
            caption=f"Tail = p95 when n ≥ 20, otherwise max. {self.DOMINANT_SIDE_NOTE}",
        )
        table.add_column("Endpoint Template", style="cyan", no_wrap=False)
        table.add_column("Count", justify="right")
        table.add_column("Tail total", justify="right", style="yellow")
        table.add_column("Tail wait (TTFB)", justify="right", style="red")
        table.add_column("Tail net", justify="right")
        table.add_column("Most time in", justify="center")

        for endpoint in filtered[:MARKDOWN_TOP_ENDPOINTS]:
            table.add_row(
                f"{endpoint.method} {urlsplit(endpoint.url_pattern).netloc}"
                f"{urlparse(endpoint.url_pattern).path}",
                str(endpoint.count),
                format_tail(endpoint.timings),
                format_tail(endpoint.served_wait_timings),
                format_tail(endpoint.network_total_timings),
                self._dominant_side(endpoint),
            )

        self._print_table(table)

    def _print_referer_hostnames(self, report: HarAnalysisReport) -> None:
        table = Table(title="Referer Hostnames")
        table.add_column("Referer Hostname", style="cyan", no_wrap=False)
        table.add_column("Requests", justify="right")

        for hostname, count in list(report.referer_hostnames.items())[:10]:
            table.add_row(hostname, str(count))

        self._print_table(table)

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
        return [i for i in issues if i.issue_type in error_types]

    def _filter_backend_perf_issues(self, issues: list[DetectedIssue]) -> list[DetectedIssue]:
        perf_types = {
            IssueType.DURATION_EXCEEDED,
            IssueType.SLOW_ENDPOINT,
            IssueType.BLOCKING,
            IssueType.LARGE_PAYLOAD,
            IssueType.REDIRECT_LOOP,
        }
        return [i for i in issues if i.issue_type in perf_types]

    def _filter_informational_issues(self, issues: list[DetectedIssue]) -> list[DetectedIssue]:
        info_types = {IssueType.REQUEST_ABORTED, IssueType.REDIRECT_CHAIN}
        return [i for i in issues if i.issue_type in info_types]

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
            lines.append(
                f"**Compression Opportunities:** {comp.compressible_uncompressed_count} "
                "compressible response(s) sent without compression "
                f"({format_bytes(comp.compressible_uncompressed_bytes)})"
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
            f"**Served without a body download:** {cache.served_without_download_ratio * 100:.1f}% "
            f"of {cache.cacheable_get_count:,} GET responses (200 or 304); "
            "this is an observed fraction, not a cache eligibility rate",
            f"**Browser Cache Hits (memory/disk):** {cache.browser_cache_hit_count:,}",
            f"**304 Not Modified:** {cache.not_modified_count:,}",
            f"**Downloaded over the network (200):** {cache.network_download_count:,}",
            f"**Cache/network source unknown (200):** {cache.unknown_cache_count:,}",
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
                total = format_bytes(int(item["total_bytes"]))
                lines.append(f"- `{path}` x{item['count']} ({total})")

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
        "Duration",
        "Measured as",
        "Kind",
        "Requests",
        "Range",
        "Queued first (max)",
        "Statuses",
        "Endpoints",
    )
    TIMEOUT_CLUSTER_KINDS = {  # noqa: RUF012 - read-only lookup table
        "gateway": "504 gateway timeout evidence",
        "proxy_502": "502 with similar durations",
        "failure": "failure duration cluster (cause unknown)",
        "network": "browser timeout error",
        "client_cancel": "cancelled by browser",
    }
    TIMEOUT_CLUSTER_NOTE = (
        "Similar durations grouped by host, evidence kind and timing basis. Wait is the "
        "recorded browser wait for a 5xx response. Total minus recorded queueing can still "
        "include setup, upload and download. Confirm any timeout with the applicable tier's logs."
    )

    def _timeout_cluster_rows(self, report: HarAnalysisReport) -> list[tuple[str, ...]]:
        rows: list[tuple[str, ...]] = []
        for cluster in report.timeout_clusters:
            statuses = ", ".join(f"{code} x{count}" for code, count in cluster.status_codes.items())
            endpoints = ", ".join(f"{url} ({count})" for url, count in cluster.endpoints.items())
            rows.append(
                (
                    f"~{format_duration_ms(cluster.median_ms)}",
                    cluster.basis,
                    self.TIMEOUT_CLUSTER_KINDS[cluster.kind],
                    str(cluster.request_count),
                    f"{format_duration_ms(cluster.min_ms)} to {format_duration_ms(cluster.max_ms)}",
                    f"{format_duration_ms(cluster.max_queued_ms)}",
                    statuses,
                    endpoints,
                )
            )
        return rows

    def _timeout_cluster_blocks(
        self, report: HarAnalysisReport
    ) -> tuple[tuple[str, tuple[str, ...]], ...]:
        blocks: list[tuple[str, tuple[str, ...]]] = []
        for cluster in report.timeout_clusters:
            lines: list[str] = []
            if cluster.matching_settings:
                lines.append(
                    "Settings of the same length (whether they apply to these requests is "
                    "not verified): " + "; ".join(cluster.matching_settings)
                )
            elif report.config_facts_loaded:
                lines.append("No loaded configuration setting has this length")
            if cluster.proxy_reasons:
                lines.append(
                    "Error pages say: "
                    + ", ".join(f'"{r}" ({c})' for r, c in cluster.proxy_reasons.items())
                )
            if lines:
                blocks.append((f"~{format_duration_ms(cluster.median_ms)} cluster", tuple(lines)))
        return tuple(blocks)

    def _timeout_cluster_section(self, report: HarAnalysisReport) -> ReportSection:
        return ReportSection(
            title="Timeout Clusters",
            note=self.TIMEOUT_CLUSTER_NOTE,
            headers=self.TIMEOUT_CLUSTER_HEADERS,
            rows=self._timeout_cluster_rows(report),
            blocks=self._timeout_cluster_blocks(report),
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
                        f"{format_duration_ms(known_ms(stats.p50))}",
                        format_tail(endpoint.ttfb_timings),
                    )
                )
        return rows

    def _server_timing_section(self, report: HarAnalysisReport) -> ReportSection:
        return ReportSection(
            title="Server-Reported Timing vs Wait (TTFB)",
            note=(
                "From Server-Timing, X-Response-Time and X-Runtime response headers. The "
                "metric scope depends on its producer. Compare individual requests and "
                "verify the measurement boundaries before attributing a difference to any tier."
            ),
            headers=("Endpoint Template", "Metric", "Tail", "p50", "Tail wait (TTFB)"),
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
        f"Error Runs ({HarAnalyzer.ERROR_BURST_MIN_ERRORS}+ errors, each failing within "
        f"{format_duration_ms(HarAnalyzer.ERROR_BURST_WINDOW_MS)} of the previous)"
    )

    def _print_error_bursts(self, report: HarAnalysisReport) -> None:
        """Print error burst detection results."""
        if not report.error_bursts:
            return

        table = Table(title=self.ERROR_RUN_TITLE)
        table.add_column("First failure", style="dim")
        table.add_column("Last failure", style="dim")
        table.add_column("Errors", justify="right", style="red")
        table.add_column("Endpoints", justify="right")
        table.add_column("Affected hosts", style="cyan", no_wrap=False)

        for burst in report.error_bursts[:10]:
            table.add_row(
                self._format_timestamp(burst.start_time, timespec="milliseconds"),
                self._format_timestamp(burst.end_time, timespec="milliseconds"),
                str(burst.error_count),
                str(burst.endpoint_count),
                ", ".join(burst.affected_domains),
            )

        self._print_table(table)

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
                lines.append(f"- *... and {remaining} more hosts*")
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

        table = Table(title="Server IP Addresses by Host")
        table.add_column("Host", style="cyan", no_wrap=False)
        table.add_column("Server IPs", style="green", no_wrap=False)

        for domain, ips in list(report.server_ips_by_domain.items())[:SERVER_IPS_TABLE_MAX_ROWS]:
            table.add_row(domain, ", ".join(ips))

        if len(report.server_ips_by_domain) > SERVER_IPS_TABLE_MAX_ROWS:
            remaining = len(report.server_ips_by_domain) - SERVER_IPS_TABLE_MAX_ROWS
            table.add_row(f"... and {remaining} more", "", style="dim")

        self._print_table(table)

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
            lines.append("### Server Software by Host")
            lines.append("")
            lines.append("| Host | Server Software |")
            lines.append("|--------|-----------------|")
            for domain, servers in list(report.server_software_by_domain.items())[
                :SERVER_SOFTWARE_MAX_DOMAINS
            ]:
                server_str = ", ".join(f"{s} ({c})" for s, c in servers.items())
                lines.append(f"| `{domain}` | {server_str} |")
            lines.append("")

        # Server IPs by Domain
        if report.server_ips_by_domain:
            lines.append("### Server IP Addresses by Host")
            lines.append("")
            lines.append("| Host | IPs |")
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

        for section in (
            self._pages_section(report),
            self._time_gap_section(report),
            self._large_request_body_section(report),
        ):
            if section:
                lines.extend(self._md_section(section, heading="###"))

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
            lines.append(
                f"**Compression Opportunities:** {comp.compressible_uncompressed_count} "
                "compressible response(s) sent without compression "
                f"({format_bytes(comp.compressible_uncompressed_bytes)})"
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
                total = format_bytes(int(item["total_bytes"]))
                lines.append(f"| `{md_cell(truncated)}` | {item['count']} | {total} |")
            lines.append("")

        return lines

    def _md_error_bursts(self, report: HarAnalysisReport) -> list[str]:
        """Generate markdown for error burst detection."""
        if not report.error_bursts:
            return []

        lines: list[str] = [f"## {self.ERROR_RUN_TITLE}", ""]
        lines.append("| First failure | Last failure | Errors | Endpoints | Affected hosts |")
        lines.append("|-------|-----|--------|-----------|------------------|")
        for burst in report.error_bursts[:10]:
            start = self._format_timestamp(burst.start_time, timespec="milliseconds")
            end = self._format_timestamp(burst.end_time, timespec="milliseconds")
            domains = ", ".join(burst.affected_domains)
            lines.append(
                f"| `{start}` | `{end}` | {burst.error_count} | {burst.endpoint_count} | "
                f"{domains} |"
            )
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


def _request_event_level(
    entry: HarEntry, outcome: RequestOutcome, category: str | None, slow_threshold_ms: float
) -> str:
    if category == "no_response" or outcome == RequestOutcome.CLIENT_ERROR:
        return "WARN"
    if outcome in PROBLEM_OUTCOMES:
        return "ERROR"
    if (
        outcome == RequestOutcome.SUCCESS
        and entry.timings.wait > slow_threshold_ms
        and long_lived_kind(entry) is None
    ):
        return "WARN"
    return "INFO"


def build_events(har: Har, analyzer: HarAnalyzer, source_file: str) -> list[dict[str, Any]]:
    """One event per request, in the shared ``events.jsonl`` format.

    ``level`` is ERROR for unexpected 5xx/network errors and WARN for unexpected 4xx
    or slow successful requests (long-lived connections excepted). Expected responses
    and browser cancellations are INFO, matching report classification.
    Paths are templated and carry no query string; only allowlisted correlation headers
    are included.
    """
    events: list[dict[str, Any]] = []
    for position, entry in enumerate(har.log.entries, start=1):
        entry_index = entry.entry_index or position
        status = entry.response.status
        category = classify_network_error(entry)
        outcome = analyzer.outcome(entry)
        level = _request_event_level(entry, outcome, category, analyzer.settings.slow_endpoint_ms)

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
            "ttfb_ms": entry.timings.wait
            if entry.response.status and entry.timings.wait >= 0
            else None,
            "expected": analyzer.is_expected(entry),
            "duration_source": entry.duration_source,
            "timing_warnings": entry.timing_warnings,
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
        if (sent_at := request_sent_time(entry)) is not None:
            attrs["sent_ts"] = (
                sent_at.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            )
        fingerprint = error_fingerprint(entry)
        if fingerprint and fingerprint.responder:
            attrs["responder"] = fingerprint.responder
        if fingerprint and fingerprint.proxy_reason:
            attrs["proxy_reason"] = fingerprint.proxy_reason
        exception = (fingerprint.root_cause or fingerprint.exception) if fingerprint else ""
        stack_signature = (
            f"{exception}@{fingerprint.first_frame}"
            if fingerprint and exception and fingerprint.first_frame
            else None
        )

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
                "exception": exception or None,
                "stack_signature": stack_signature,
                "template": template,
                "signature": f"har:{level}:{_template_hash(template)}",
                "duration_ms": entry.time if entry.time >= 0 else None,
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
    """Millisecond table cell: ``-`` when not recorded, ``<1`` below one millisecond."""
    if value < 0:
        return "-"
    return "<1" if 0 < value < 1 else f"{value:,.0f}"


def _brief_incident_lines(
    report: HarAnalysisReport,
    formatter: OutputFormatter,
    row_limit: int,
    short: Callable[[str], str],
) -> list[str]:
    if not report.incidents:
        return []
    lines = ["## Incidents (failed requests by endpoint and signature)"]
    for incident in report.incidents[:row_limit]:
        window = formatter.format_timestamp(incident.first_failure, timespec=_MS)
        if incident.last_failure != incident.first_failure:
            window += " → " + formatter.format_timestamp(incident.last_failure, timespec=_MS)
        evidence = "; ".join(incident.evidence[:2])
        lines.append(
            f"- [{incident.severity.value.upper()}] {incident.failure_count} of "
            f"{incident.endpoint_request_count} {incident.method} "
            f"{incident.domain}{short(incident.endpoint)} → {incident.signature}; failed "
            f"{window}; wait "
            f"{OutputFormatter.seconds_range(incident.min_wait_ms, incident.max_wait_ms)}"
            + (f"; {evidence}" if evidence else "")
        )
    lines.append(
        f"Shown {min(row_limit, len(report.incidents))} of {len(report.incidents)} incidents."
    )
    lines.append("")
    return lines


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
            f"{report.total_requests:,} request(s); query values "
            f"{'shown (--show-query)' if formatter.show_query else 'redacted'}"
        )
    lines.extend(f"- {note}" for note in formatter.capture_note_lines(report))
    lines.append("- " + "; ".join(formatter.response_class_lines(report)))
    lines.append("")

    backend_findings = [f for f in report.key_findings if not f.frontend]
    if backend_findings:
        lines.append("## Findings")
        lines.extend(
            f"- [{f.severity.value.upper()}] {f.summary} {f.recommendation}"
            for f in backend_findings[:row_limit]
        )
        lines.append(
            f"Shown {min(row_limit, len(backend_findings))} of {len(backend_findings)} findings."
        )
        lines.append("")

    lines.extend(_brief_incident_lines(report, formatter, row_limit, short))

    if report.timeout_clusters:
        lines.append("## Timeout clusters")
        for cluster in report.timeout_clusters[:row_limit]:
            statuses = ", ".join(f"{code}x{count}" for code, count in cluster.status_codes.items())
            if cluster.matching_settings:
                match = "duration-compatible, scope unverified: " + "; ".join(
                    cluster.matching_settings
                )
            elif report.config_facts_loaded:
                match = "no loaded config setting matches"
            else:
                match = "no config facts loaded"
            kind = OutputFormatter.TIMEOUT_CLUSTER_KINDS[cluster.kind]
            lines.append(
                f"- {cluster.request_count} req at ~{format_duration_ms(cluster.median_ms)} "
                f"({cluster.basis}) "
                f"({format_duration_ms(cluster.min_ms)} to "
                f"{format_duration_ms(cluster.max_ms)}, {statuses}; "
                f"{kind}): {match}"
            )
        lines.append("")

    ranked = [e for e in report.endpoints if e.served_wait_timings.count]  # already ranked
    if ranked:
        lines.append(
            "## Slowest endpoints by wait (TTFB, non-5xx responses; ms; tail = p95, or max "
            "when n<20)"
        )
        lines.append("| Endpoint | n | Wait tail | Wait p50 | Total tail |")
        lines.append("|---|---|---|---|---|")
        lines.extend(
            f"| {md_cell(e.method + ' ' + urlsplit(e.url_pattern).netloc)}"
            f"{md_cell(short(urlparse(e.url_pattern).path))} | {e.served_wait_timings.count} | "
            f"{_ms_or_dash(tail_value(e.served_wait_timings))} "
            f"({tail_label(e.served_wait_timings)}) | "
            f"{_ms_or_dash(known_ms(e.served_wait_timings.p50))} | "
            f"{_ms_or_dash(tail_value(e.timings))} |"
            for e in ranked[:row_limit]
        )
        lines.append("")

    if report.slowest_requests:
        lines.append("## Slowest requests (ms; - = not recorded)")
        lines.append(
            "| Start | Request | Status | Total | Queued | DNS | TCP connect | TLS | Send | Wait "
            "| Receive |"
        )
        lines.append("|---|---|---|---|---|---|---|---|---|---|---|")
        for req in report.slowest_requests[:row_limit]:
            status = f"{req.status}" + (f" {req.error_category}" if req.error_category else "")
            lines.append(
                f"| {formatter.format_timestamp(req.started, timespec=_MS)} | "
                f"#{req.entry_index} {req.method} "
                f"{md_cell(urlsplit(req.url).netloc + short(formatter.extract_path(req.url)))} | "
                f"{status} | {_ms_or_dash(req.total_ms)} | "
                f"{_ms_or_dash(req.blocked_ms)} | {_ms_or_dash(req.dns_ms)} | "
                f"{_ms_or_dash(req.connect_excl_tls_ms)} | {_ms_or_dash(req.tls_ms)} | "
                f"{_ms_or_dash(req.send_ms)} | {_ms_or_dash(req.wait_ms)} | "
                f"{_ms_or_dash(req.receive_ms)} |"
            )
        lines.append("")

    settings = report.settings
    lines.append(
        f"Thresholds: slow wait>{format_duration_ms(settings.slow_endpoint_ms)}, "
        f"idle gap>{format_duration_ms(settings.idle_gap_ms)}, "
        f"timeout cluster≥{settings.timeout_cluster_min_requests}, width "
        f"{settings.timeout_cluster_tolerance_pct:g}% of shortest, expected: "
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
# JSON report
# =============================================================================

JSON_SCHEMA_VERSION = 1
# A URL runs to the next whitespace (";" is part of a path parameter such as
# ";jsessionid="); trailing list punctuation is left outside the match.
_URL_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s]*[^\s,;)]")


def _redact_url_token(match: re.Match[str], *, show_query: bool) -> str:
    try:
        parts = urlsplit(match.group(0))
    except ValueError:
        return REDACTED
    return f"{parts.scheme}://{parts.netloc}{redact_url(match.group(0), show_query=show_query)}"


def _redact_json_value(value: object, *, show_query: bool) -> object:
    """Redact every URL inside a JSON-compatible value (dict keys included)."""
    if isinstance(value, str):
        return _URL_TOKEN_RE.sub(lambda m: _redact_url_token(m, show_query=show_query), value)
    if isinstance(value, list):
        return [
            _redact_json_value(item, show_query=show_query) for item in cast("list[object]", value)
        ]
    if isinstance(value, dict):
        return {
            str(_redact_json_value(key, show_query=show_query)): _redact_json_value(
                item, show_query=show_query
            )
            for key, item in cast("dict[object, object]", value).items()
        }
    return value


def generate_json_report(report: HarAnalysisReport, har_filename: str, *, show_query: bool) -> str:
    """The whole report model as JSON, redacted the same way as the other outputs.

    Query-string values and fragments are redacted unless ``show_query``; session IDs
    in paths are always redacted; cookie values are never part of the model.
    """
    payload = {
        "schema_version": JSON_SCHEMA_VERSION,
        "tool": "har-analyze",
        "tool_version": __version__,
        "source_file": har_filename,
        "query_strings": "shown" if show_query else "redacted",
        "report": _redact_json_value(report.model_dump(mode="json"), show_query=show_query),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


# =============================================================================
# CLI
# =============================================================================

app = typer.Typer(
    name="har-analyze",
    help="Analyze HAR files with deterministic performance insights",
    add_completion=False,
)


# Exit codes: each failure kind has its own code so scripts can tell them apart.
EXIT_OK = 0  # analysis completed (whatever the report found)
EXIT_INTERNAL_ERROR = 1  # a bug in har-analyze
EXIT_USAGE = 2  # invalid command-line arguments (reported by the CLI framework)
EXIT_INPUT_UNUSABLE = 3  # the input could not be read or is not a usable HAR
EXIT_OUTPUT_FAILED = 4  # a report or export could not be written
EXIT_INTERRUPTED = 130  # Ctrl+C


def _print_version(value: bool) -> None:
    if value:
        typer.echo(f"har-analyze {__version__}")
        raise typer.Exit(EXIT_OK)


@app.callback()
def callback(
    show_version: bool = typer.Option(
        False,
        "--version",
        callback=_print_version,
        is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """HAR file analyzer with deterministic performance insights."""


def setup_logging(verbose: bool) -> None:
    """Warnings only by default; ``--verbose`` adds progress messages."""
    level = logging.INFO if verbose else logging.WARNING
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
def analyze(  # noqa: PLR0913, PLR0917 - Typer requires one parameter per CLI option
    har_file: Path = typer.Argument(  # noqa: B008
        ..., help="HAR file to analyze (missing or unreadable files exit with code 3)"
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None,
        "--output",
        "-o",
        help="Write the report as Markdown to this file instead of the terminal",
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
        False, "--brief", help="Compact Markdown summary (at most 5 KiB); no front-end advice"
    ),
    show_query: bool = typer.Option(
        False, "--show-query", help="Print query strings and fragments unredacted"
    ),
    export_events: Path | None = typer.Option(  # noqa: B008
        None,
        "--export-events",
        help="Also write one JSON event per request to this file (JSON Lines)",
    ),
    json_output: Path | None = typer.Option(  # noqa: B008
        None,
        "--json",
        help="Also write the full report as JSON to this file (URLs redacted as in the report)",
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
        help="Slow endpoint: tail wait (TTFB) above this many ms (p95; max when n<20)",
    ),
    duration_exceeded_ms: float = typer.Option(
        _DEFAULT_SETTINGS.duration_exceeded_ms,
        "--duration-exceeded-ms",
        help="Flag individual requests longer than this many ms",
    ),
    gap_ms: float = typer.Option(
        _DEFAULT_SETTINGS.idle_gap_ms,
        "--gap-ms",
        help="Report idle periods longer than this many ms",
    ),
    blocking_ms: float = typer.Option(
        _DEFAULT_SETTINGS.blocking_ms,
        "--blocking-ms",
        help="Flag requests queued in the browser longer than this many ms",
    ),
    large_payload_bytes: int = typer.Option(
        _DEFAULT_SETTINGS.large_payload_bytes,
        "--large-payload-bytes",
        help="Flag responses whose decoded body exceeds this many bytes",
    ),
    large_request_body_bytes: int = typer.Option(
        _DEFAULT_SETTINGS.large_request_body_bytes,
        "--large-request-body-bytes",
        help="List request bodies larger than this many bytes",
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
        help="Maximum cluster width as a percentage of the shortest duration",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show progress messages on stderr"),
) -> None:
    """Analyze a HAR file and generate performance insights."""
    setup_logging(verbose)

    timestamp_timezone, timestamp_timezone_label = _resolve_timestamp_timezone(timezone, local_time)

    expected_rules = [] if no_default_expect else list(DEFAULT_EXPECTED_RULES)
    expected_rules.extend(expect or [])
    try:
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
        analyzer = HarAnalyzer(
            settings,
            config_facts=load_config_facts(config_facts) if config_facts else None,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    try:
        _run_analysis(
            har_file,
            analyzer,
            OutputFormatter(
                timestamp_timezone=timestamp_timezone,
                timestamp_timezone_label=timestamp_timezone_label,
                show_query=show_query,
            ),
            output=output,
            brief=brief,
            export_events=export_events,
            json_output=json_output,
        )
    except KeyboardInterrupt:
        typer.echo("\nInterrupted", err=True)
        raise typer.Exit(EXIT_INTERRUPTED) from None
    except HarFormatError as exc:
        typer.echo(f"Error: {har_file}: {exc}", err=True)
        raise typer.Exit(EXIT_INPUT_UNUSABLE) from exc
    except _OutputError as exc:
        typer.echo(f"Error: cannot write {exc.path}: {exc.reason}", err=True)
        raise typer.Exit(EXIT_OUTPUT_FAILED) from exc
    except OSError as exc:
        typer.echo(f"Error: cannot read {har_file}: {exc.strerror or exc}", err=True)
        raise typer.Exit(EXIT_INPUT_UNUSABLE) from exc
    except Exception as exc:
        logger.exception("Internal error")
        typer.echo(f"Internal error (a bug in har-analyze): {exc!r}", err=True)
        raise typer.Exit(EXIT_INTERNAL_ERROR) from exc


class _OutputError(Exception):
    """Writing a report or export failed (exit code 4)."""

    def __init__(self, path: Path, reason: str) -> None:
        super().__init__(f"{path}: {reason}")
        self.path = path
        self.reason = reason


def _write_output(path: Path, write: Callable[[Path], None]) -> None:
    try:
        write(path)
    except OSError as exc:
        raise _OutputError(path, exc.strerror or str(exc)) from exc


def _run_analysis(  # noqa: PLR0913 - one argument per output option
    har_file: Path,
    analyzer: HarAnalyzer,
    formatter: OutputFormatter,
    *,
    output: Path | None,
    brief: bool,
    export_events: Path | None,
    json_output: Path | None,
) -> None:
    logger.info("Reading %s", har_file)
    har = load_har_file(har_file)
    logger.info("Read %d entries", len(har.log.entries))
    if har.load_notes.skipped_entry_count:
        typer.echo(
            f"Warning: skipped {har.load_notes.skipped_entry_count} unusable entries: "
            f"{'; '.join(har.load_notes.skipped_entry_reasons)}",
            err=True,
        )
    report = analyzer.analyze(har)
    if export_events:
        events = build_events(har, analyzer, har_file.name)
        _write_output(export_events, lambda path: write_events(events, path))
        logger.info("Wrote %d events to %s", len(events), export_events)
    if json_output:
        json_text = generate_json_report(report, har_file.name, show_query=formatter.show_query)
        _write_output(json_output, lambda path: write_text_atomic(path, json_text))
        logger.info("Wrote the JSON report to %s", json_output)
    if brief:
        brief_content = generate_brief_report(report, formatter, har_file.name)
        if output:
            _write_output(output, lambda path: write_text_atomic(path, brief_content))
            typer.echo(f"Brief report written to {output}")
        else:
            typer.echo(brief_content, nl=False)
    elif output:
        markdown_content = formatter.generate_markdown_report(report, har_file.name)
        _write_output(output, lambda path: write_text_atomic(path, markdown_content))
        typer.echo(f"Markdown report written to {output}")
    else:
        formatter.print_report(report)


def main() -> None:
    """CLI entry point."""
    app()


if __name__ == "__main__":
    main()
