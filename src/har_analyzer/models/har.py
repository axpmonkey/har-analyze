"""Pydantic models for HAR (HTTP Archive) 1.2 specification."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class HarHeader(BaseModel):
    """HTTP header name-value pair."""

    name: str
    value: str


class HarQueryParam(BaseModel):
    """Query string parameter."""

    name: str
    value: str


class HarCookie(BaseModel):
    """HTTP cookie."""

    name: str
    value: str
    path: str | None = None
    domain: str | None = None
    expires: datetime | None = None
    http_only: bool | None = Field(None, alias="httpOnly")
    secure: bool | None = None


class HarPostData(BaseModel):
    """POST request data."""

    mime_type: str = Field(alias="mimeType")
    params: list[dict[str, str]] = Field(default_factory=list)
    text: str | None = None


class HarRequest(BaseModel):
    """HTTP request."""

    method: str
    url: str
    http_version: str = Field(alias="httpVersion")
    headers: list[HarHeader]
    query_string: list[HarQueryParam] = Field(alias="queryString")
    cookies: list[HarCookie]
    headers_size: int = Field(alias="headersSize")
    body_size: int = Field(alias="bodySize")
    post_data: HarPostData | None = Field(None, alias="postData")


class HarContent(BaseModel):
    """Response content."""

    size: int
    compression: int | None = None
    mime_type: str = Field(alias="mimeType")
    text: str | None = None
    encoding: str | None = None


class HarResponse(BaseModel):
    """HTTP response."""

    status: int
    status_text: str = Field(alias="statusText")
    http_version: str = Field(alias="httpVersion")
    headers: list[HarHeader]
    cookies: list[HarCookie]
    content: HarContent
    redirect_url: str = Field("", alias="redirectURL")
    headers_size: int = Field(alias="headersSize")
    body_size: int = Field(alias="bodySize")
    transfer_size: int | None = Field(None, alias="_transferSize")
    error: str | None = Field(None, alias="_error")


class HarCache(BaseModel):
    """Cache information."""

    before_request: dict[str, Any] | None = Field(None, alias="beforeRequest")
    after_request: dict[str, Any] | None = Field(None, alias="afterRequest")


class HarTimings(BaseModel):
    """Request/response timings (all in milliseconds).

    Timing phases:
    - blocked: Time waiting in queue before request can be made
    - dns: DNS resolution time
    - ssl: SSL/TLS negotiation time
    - connect: TCP connection time
    - send: Time to send HTTP request
    - wait: Time to first byte (TTFB) - server processing
    - receive: Time to download response

    -1 indicates timing not applicable or not measured.
    """

    blocked: float = -1.0
    dns: float = -1.0
    ssl: float = -1.0
    connect: float = -1.0
    send: float
    wait: float  # TTFB
    receive: float


class HarEntry(BaseModel):
    """Single HTTP transaction."""

    started_date_time: datetime = Field(alias="startedDateTime")
    time: float  # Total duration in milliseconds
    request: HarRequest
    response: HarResponse
    cache: HarCache | None = None
    timings: HarTimings
    server_ip_address: str | None = Field(None, alias="serverIPAddress")
    connection: str | None = None
    comment: str | None = None


class HarPage(BaseModel):
    """Page timing information (optional)."""

    started_date_time: datetime = Field(alias="startedDateTime")
    id: str
    title: str
    page_timings: dict[str, float] = Field(alias="pageTimings")


class HarCreator(BaseModel):
    """Tool that created the HAR."""

    name: str
    version: str


class HarLog(BaseModel):
    """HAR log container."""

    version: str
    creator: HarCreator
    browser: HarCreator | None = None
    pages: list[HarPage] = Field(default_factory=list)
    entries: list[HarEntry]
    comment: str | None = None


class Har(BaseModel):
    """Root HAR object."""

    log: HarLog
