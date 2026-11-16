# HAR Analyze

A command-line tool for analyzing HAR (HTTP Archive) files to extract performance metrics, detect issues, and generate actionable insights for backend/API and network troubleshooting.

Requires **Python 3.15 only**. Use the **latest compatible dependencies and development tools**,
installed with `uv sync --upgrade --extra dev --python 3.15`.

## Overview

HAR Analyze is a Python package that parses HAR 1.2 files captured from browser developer tools or network proxies and produces reports that help identify performance bottlenecks, service failures, and network issues. The report is written for people who troubleshoot the server side (load balancer, web server, application server): it shows the evidence behind each finding and says "not available" when the capture does not contain something.

### Key Capabilities

- **Performance Metrics**: Timing percentiles (p50, p95, p99) overall and by phase (queueing, DNS, connect, TLS, send, wait, receive). p95 is shown from 20 samples and p99 from 100; below that the maximum is shown instead.
- **Key Findings**: A short list of what matters most (observed failures, duration clusters, 5xx, network errors, host-wide stalls, lost sessions, size limits, routing hints, uncertain Date-header differences). One cause is reported once: a failing endpoint is not repeated as a slow endpoint, a critical domain and an error run.
- **Incidents**: Every failed request, grouped by endpoint and signature (HTTP status or network error category). Each incident lists its evidence, the time window and keys to search for in server logs, and which logs to open first.
- **Timeout Clusters**: Failed requests that took the same time, grouped by host and evidence type, including short and non-round values. A 5xx is measured by its wait for the first byte. Applicable response-wait settings from `--config-facts` are duration comparisons, not proof of a cause.
- **5xx Error Origin**: Which tier wrote the error. When the capture kept the error body, its own text is used: Tomcat's default error page (with version), Java exception class and first stack frame, httpd error documents (with the proxy's reason), nginx error pages, Spring Boot error JSON. Exception messages and other body text are never copied into a report. Without a body, response headers on errors are compared with successes on the same endpoint (host-wide when the endpoint has none); those are clues, not proof.
- **Host-wide Stalls**: Requests to different endpoints, sent at different times, whose first bytes all arrived together. Consistent with a JVM-wide pause (garbage collection), a shared lock or pool, or a stalled proxy; the report gives the time window to check in GC logs and thread dumps and does not claim to tell these apart.
- **Session Events**: A request redirected to the login page after the application had been answering, a session route that changes, a session cookie issued again. Idle time is compared with `session-timeout` from `--config-facts`. Session IDs are never shown.
- **Request size limits**: 400/413/414/431 responses whose request headers are at the common 8 KB limits, uploads rejected with 413, and form posts over Tomcat's default `maxPostSize`.
- **Timeline**: Requests, 5xx, network errors, 4xx and wait p50/max per time bucket for the busiest hosts.
- **Log Correlation**: For failed and slowest requests, the time the request was sent (the closest a capture gets to the time in a server access log), when the first byte arrived, server IP, node and correlation IDs.
- **Backend Nodes**: Errors and latency grouped by routing hints (`JSESSIONID` route, `ROUTEID`, `X-Served-By`). A route set by the response names the node that answered; a route in the request cookie is labelled "session pinned to". Everything after the first dot of the session ID is the route. Requests whose cookies name several different routes are counted and not assigned.
- **Date Header Differences**: Uncertain differences between HTTP `Date` and browser header-arrival time. These must not be used as automatic clock corrections.
- **Domain Health**: Per-host failures, 5xx and network error counts, observed TCP connect median, and capture health status.
- **Service Health**: Per method and path template; every request falls into exactly one outcome column.
- **Slowest Requests**: Individual requests with host, method, original HAR entry number, phase split, millisecond timestamps and correlation IDs.
- **Infrastructure Details**: HTTP versions, server software, server IPs, connections per host, idle periods, large request bodies (with what a body of that size is known to run into).
- **Front-end information**: Compression and cache analysis, kept in a separate section.

### How to read the numbers

- **Timestamps are the browser's clock.** Correlate request IDs and verify clock synchronization before aligning logs. HTTP `Date` can be generated earlier or by an intermediary.
- **Wait / TTFB is not server time alone.** It is network round trip + every proxy hop + the application. TCP connect time is an observation of connection setup, not a reliable number to subtract to obtain application execution time.
- **Latency percentiles cover requests answered over the network.** Browser-cache hits, aborted requests, network errors, unavailable totals and unknown cache/network sources are excluded and counted separately.
- **WebSocket and event-stream connections are listed separately.** Their duration is the connection lifetime, so they are excluded from every count and rule.
- **Failure clusters are measured on wait for the first byte** when the request got a 5xx, because that is what a proxy's read timer sees; a request with no response is measured by total minus browser queueing. Proxy read timers (`ProxyTimeout`, `proxy_read_timeout`, mod_jk `reply_timeout`) measure time without data from the backend, not total request time. httpd answers **502**, not 504, when `ProxyTimeout` expires before the response headers arrive, so a cluster of 502s is named as a possible read timeout; it is HIGH only when a loaded setting has the same length or the error page says "Error reading from remote server".
- **"Slow endpoint" is judged on wait for the first byte of non-5xx responses.** Time queued in the browser is not the server's, and failed requests are reported as failures.
- **Error runs use the time requests failed**, not when they started.
- **In the terminal, tables show the time only** when the whole capture is on one date; the date and UTC offset are printed once at the top. Columns with nothing recorded in any row are named below the table instead of printed. The Markdown and JSON reports always carry full timestamps and every column.
- **Capture notes** at the top list anything left out: malformed entries (skipped and counted), non-network entries (`data:`, `blob:`, extension URLs), and timestamps read as UTC because they had no offset. Invalid/nonfinite timings are excluded, incomplete totals remain unknown, and complete derived totals are labeled. Totals that disagree with recorded phases produce warnings.

### Detected Issue Types

| Issue Type | Severity | Description |
|------------|----------|-------------|
| Network Error | Critical / High / Medium | Critical when a host has three or more understood failures (reset, refused, timed out, DNS, TLS, empty or truncated response, proxy tunnel); High for one-offs and other categories; Medium when a request with no status ends at the end of the capture and may have been in flight |
| Duration Exceeded | Critical / High | A request that was answered (not a 5xx or network failure, which are reported as failures with their duration) over the duration threshold (default 30 s). Critical when the time went into waiting for the response; High when it went into another phase, which is named |
| Server Error | High | HTTP 5xx responses |
| Rate Limited | High | HTTP 429 responses |
| Client Error | Medium / High | HTTP 4xx responses (401/403 are High; so is a 400/413/414/431 whose request headers are at the 8 KB limits) |
| Slow Endpoint | High | Endpoint template whose wait for the first byte, p95 (max when n < 20) over non-5xx responses, exceeds the threshold (default 10 s) |
| Redirect Loop | High | A URL revisited within one redirect chain |
| Large Payload | Medium | Response larger than 1 MB uncompressed |
| Blocking | Medium | Request queued in the browser over the threshold (default 5 s), with the requests that were in flight meanwhile |
| Redirect Chain | Low | Three or more redirect hops |
| Request Aborted | Low | Cancelled or blocked by the client (informational) |

Identical issues on one endpoint are printed as one block with the count, time range, duration range and HAR entry numbers.

An endpoint is reported as an **outage in the capture** only when it never succeeded and had at least three 5xx or network failures. This does not establish service-wide availability. Endpoints that answered only 4xx are listed as "always rejected". A host with any 5xx or network failure is at least DEGRADED.

## Installation

### Install uv

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://astral.sh/uv/install.ps1 | iex
```

### Setup

```bash
# Clone the repository
git clone <repository-url>
cd har-analyze

# Install the latest dependencies and tools for Python 3.15
uv sync --upgrade --extra dev --python 3.15
```

## Run the analyzer

```bash
uv run har-analyze analyze <har-file>
```

## CLI Reference

### `analyze` Command

```
uv run har-analyze analyze <HAR_FILE> [OPTIONS]
```

**Output options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--output PATH` | `-o` | Export the analysis to a Markdown file |
| `--brief` | | Compact Markdown (about 5 KB) with findings, incidents, timeout clusters, endpoints and slowest requests |
| `--export-events PATH` | | Write one event per request as JSON Lines, for merging with server logs |
| `--json PATH` | | Write the full report model as JSON. URLs are redacted exactly as in the other outputs (`--show-query` applies; session IDs in paths are always redacted) |
| `--timezone ZONE` | `-t` | Convert displayed timestamps (e.g. `UTC`, `local`, `America/New_York`) |
| `--local-time` | | Convert displayed timestamps to your local timezone |
| `--show-query` | | Print query strings and fragments unredacted (values are redacted by default) |
| `--verbose` | `-v` | Enable verbose logging |

**Rules:**

| Option | Description |
|--------|-------------|
| `--config-facts PATH` | `config_facts.json` from `sas-casefile config`; lists duration-compatible response-wait settings (request scope remains unverified) and compares idle time with `session-timeout` |
| `--expect STATUS:PATH_GLOB` | A response that is normal for the application, e.g. `401:/SASLogon/*` (repeatable) |
| `--no-default-expect` | Drop the default expected rules |
| `--path-rule REGEX=NAME` | Template path segments matching `REGEX` as `{NAME}` (repeatable) |

**Thresholds:**

| Option | Default | Description |
|--------|---------|-------------|
| `--slow-ms` | 10000 | Slow endpoint threshold on wait for the first byte, p95 (max when n < 20) |
| `--duration-exceeded-ms` | 30000 | Flag individual requests longer than this |
| `--gap-ms` | 1000 | Report idle periods longer than this |
| `--blocking-ms` | 5000 | Browser queueing threshold |
| `--large-payload-bytes` | 1048576 | Large response threshold (uncompressed) |
| `--large-request-body-bytes` | 102400 | Large request body threshold |
| `--redirect-chain-min-hops` | 3 | Report redirect chains with at least this many hops |
| `--timeout-cluster-min` | 3 | Minimum failed requests to form a timeout cluster |
| `--timeout-tolerance-pct` | 2 | Timeout cluster width (±%) |

Timeout settings in `--config-facts` are compared only when their response-wait semantics and units are known: from the fact itself (a `unit` field or a suffix such as `60s`, `2m`), or from the product's documented default for httpd, nginx, mod_jk, Tomcat and HAProxy keys. A bare number for any other product is not matched. Response-wait candidates are httpd `ProxyTimeout`/`Timeout`/`timeout=`, nginx `proxy_read_timeout`, mod_jk `reply_timeout` and `socket_timeout`, HAProxy `timeout server`/`timeout tunnel` and Tomcat `asyncTimeout`. Connection setup, keep-alive, upload and session-expiry settings are not response-wait matches. Tomcat `connectionTimeout` is not a servlet execution timeout. Even relevant response-wait settings can reset on activity or apply only to particular routes; verify their actual scope in the server configuration.

## Examples

```bash
# Terminal report
uv run har-analyze analyze network-capture.har

# Markdown report
uv run har-analyze analyze network-capture.har -o analysis-report.md

# Timestamps in a specific timezone
uv run har-analyze analyze network-capture.har --timezone America/Los_Angeles

# Match timeout clusters against extracted configuration
uv run har-analyze analyze network-capture.har --config-facts config_facts.json

# Machine-readable report, for diffing between versions or feeding other tools
uv run har-analyze analyze network-capture.har --json report.json
```

## Capturing a useful HAR

- Chrome leaves cookies out of HAR files unless you choose "Export HAR (with sensitive data)". Without cookies, backend node, session re-issue and route-change evidence is absent (the report says so); redirects to a login page and response routing headers are still used. A HAR with sensitive data contains session IDs; the report prints only the route name, but treat the file itself as a secret.
- Keep the network panel open from before the problem starts, with "Preserve log" on.
- Error response bodies are the best evidence of which tier failed. Browsers record them only for responses whose content they loaded; when the capture has none, the report says "Error page text: not available".


## Trust and incident workflow

- Treat each finding as an observation from one browser capture. It is not a server load test,
  an application trace, or evidence of a JVM root cause.
- Use the HAR entry number, host, method, millisecond timestamp and correlation ID to locate
  the request in proxy upstream logs and Tomcat access logs. Compare durations measured by
  each tier before changing configuration.
- When server-side delay is confirmed, inspect Tomcat worker/thread metrics, dependency
  connection pools and application traces. GC pauses, thread exhaustion and database
  contention require JVM or server evidence beyond the HAR.
- Cache metadata (`cache.beforeRequest`) does not prove a local hit. Each GET 200/304 appears
  once in local-hit, revalidation, network-download or unknown-source counts. The reported
  fraction is not a determination that every response was eligible for caching.
- Transfer totals distinguish unknown bytes and body-only measurements. They are lower
  bounds when sizes or headers are missing. A 304 still uses network headers.
- An idle period that follows a request of unknown duration is not judged, because that
  request could span the apparent gap; such periods are counted. Long-lived streams are
  analyzed separately.
- Static-resource failures remain visible: a failed JavaScript or stylesheet response can
  explain a broken application even when API requests succeed.
- Endpoint latency separates HTTP methods. Percentiles use linear interpolation over valid
  samples; phase sample counts can differ when exporters omit fields.
- URL path session IDs are redacted even with `--show-query`. Events contain templated paths
  without queries. Event severity follows report outcomes: expected responses and browser
  cancellations are INFO, unexpected 4xx are WARN, and unexpected 5xx/network failures are
  ERROR. Unavailable event durations are null; `duration_source` and timing warnings explain
  the measurement. Consumers must allow an unavailable duration. A successful request is
  WARN only when its wait for the first byte is over the slow threshold. Events also carry
  `attrs.sent_ts` (when the request was sent, UTC), `attrs.responder` / `attrs.proxy_reason`
  from an error page, and `exception` / `stack_signature` when an error body holds a Java
  stack trace (class and frame names only).
- Server-Timing values are server-reported measurements, not independent proof of execution
  time. Quoted description delimiters are respected; when a metric name repeats, the first
  duration in a response is used. Overlapping metrics must not be added as disjoint phases.

## Verification

Use Python 3.15 only and current dependencies:

```bash
uv sync --upgrade --extra dev --python 3.15
uv run --no-sync ruff format --check
uv run --no-sync ruff check
uv run --no-sync basedpyright
TZ=UTC PYTHONUTF8=1 LC_ALL=C.UTF-8 PYTHONWARNINGS=error uv run --no-sync pytest -q --cov=src/har_analyze --cov-branch --cov-fail-under=90
uv run --no-sync pip-audit
```

Tests and synthetic fixtures are versioned; private browser captures remain ignored.
Tests are network-free and each test has a 30-second hang timeout.
The regression suite checks hand-calculated percentile values, TLS accounting, cache
population reconciliation, invalid and missing timings, short and non-round failure
clusters, routing uncertainty, clock wording, redirect loops, report consistency and
redaction; that incidents, timeline buckets and grouped issues add up to the totals; error
page fingerprints; session events; host-wide stalls; and that terminal tables fit 100
columns without cutting text.

## Known gaps

The report's statements about servers are verified (next section). What browsers write into
a HAR is not: every test fixture is synthetic, and no real capture was available.

- **Real captures.** Run the tool on Chrome, Firefox and Edge captures of known faults and
  read the report against DevTools and the server logs before treating the output as proven
  on real exporters. Useful faults to stage against a Tomcat stack: stop Tomcat; make a
  request sleep past the proxy's read timeout; throw an exception; send a 9 KB cookie; fail
  over between two `jvmRoute` nodes; `kill -STOP` the JVM for ten seconds (a stand-in for a
  long GC pause).
- **Firefox reused connections.** If Firefox writes `0` instead of `-1` for DNS/connect/TLS
  on a reused connection, those phase percentiles are pulled toward zero. Not checked.
- **Firefox cache hits.** Cache hits are recognised from Chrome's `_fromCache` and
  `_transferSize`. Whether Firefox captures need another signal is not checked.
- **Requests in flight when the capture was saved.** A request with no status that ends
  within one second of the end of the capture is labelled "may have been in flight". What
  browsers actually write for a pending request is not checked.
- **Error bodies in sanitized exports.** Whether a sanitized Chrome export keeps error
  response bodies is not checked; the report says when it found none.

## Verified product behaviour

Each statement the report makes about a server product was checked against that product's
documentation or source:

| Statement | Source |
|-----------|--------|
| httpd answers 502 "Error reading from remote server" (logged as AH01102), not 504, when a backend read fails or times out before the response headers; on a kept-alive client connection it may close the connection with no response instead | httpd 2.4 `mod_proxy_http.c` |
| httpd answers 503 without contacting the backend while a worker is in error state (`retry`, default 60 s) | httpd 2.4 `proxy_util.c`, mod_proxy docs |
| `ProxyTimeout`, `timeout=`, `ttl`, `retry` are seconds; `LimitRequestFieldSize` defaults to 8190 bytes per field; `LimitRequestBody` defaults to 1 GiB since 2.4.54 | httpd 2.4 docs |
| httpd's built-in error documents are sent as `text/html; charset=iso-8859-1` with the `-//IETF//DTD HTML 2.0//EN` doctype | httpd 2.4 `http_protocol.c` |
| nginx `proxy_read_timeout` (default 60 s) is the time between two reads, not for the whole response; nginx does not pass the backend's `Date` and `Server` headers; `client_max_body_size` defaults to 1m and answers 413; `large_client_header_buffers` defaults to 4 × 8k and answers 400 for a field that does not fit | nginx docs |
| mod_jk `reply_timeout` is milliseconds between two packets; `socket_timeout` is seconds | Tomcat Connectors docs |
| HAProxy bare timeout values are milliseconds | HAProxy docs |
| Tomcat `maxHttpHeaderSize` defaults to 8192 bytes; `maxPostSize` (default 2 MiB) limits the form body parsed into parameters; `keepAliveTimeout` defaults to `connectionTimeout`; compression is off by default and sendfile takes precedence over it for static files over 48 KiB | Tomcat 9 HTTP connector docs |
| When Tomcat's request threads are all busy, connections queue (`maxConnections`, `acceptCount`) and may then be refused or time out; it does not answer 503 | Tomcat 9 HTTP connector docs |
| Tomcat's default error page is `text/html`, UTF-8, with the server info (`Apache Tomcat/x.y.z`) in an `<h3>` | Tomcat `ErrorReportValve.java` |
| Tomcat access log `%D` is milliseconds up to Tomcat 9 and microseconds from Tomcat 10 | Tomcat 9 and 11 valve docs |

## Reference semantics

- [HAR 1.2](https://github.com/ahmadnassri/har-spec/blob/master/versions/1.2.md):
  timing inclusion, missing-value conventions, cache metadata and body sizes.
- [HTTP semantics](https://www.rfc-editor.org/rfc/rfc9110.html): Date and status meanings.
- [Tomcat HTTP connector](https://tomcat.apache.org/tomcat-9.0-doc/config/http.html):
  connection, upload and asynchronous timeout semantics; `maxHttpHeaderSize`, `maxPostSize`,
  `maxThreads` / `maxConnections` / `acceptCount` queueing, compression and sendfile.
- [Tomcat access log valve](https://tomcat.apache.org/tomcat-9.0-doc/config/valve.html):
  `%D` is milliseconds up to Tomcat 9 and microseconds from Tomcat 10.
- [httpd mod_proxy_http source](https://github.com/apache/httpd/blob/2.4.x/modules/proxy/mod_proxy_http.c):
  502 "Error reading from remote server" (AH01102) on a backend read failure or timeout.
- [Apache proxy timeout](https://httpd.apache.org/docs/2.4/mod/mod_proxy.html#proxytimeout),
  [nginx proxy read timeout](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_read_timeout),
  [mod_jk worker settings](https://tomcat.apache.org/connectors-doc/reference/workers.html),
  [HAProxy configuration](https://docs.haproxy.org/3.2/configuration.html):
  candidate response-wait timer behavior.
- [Server Timing](https://www.w3.org/TR/server-timing/): metric syntax and interpretation.
