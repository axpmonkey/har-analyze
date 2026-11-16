# HAR Analyze

A command-line tool for analyzing HAR (HTTP Archive) files to extract performance metrics, detect issues, and generate actionable insights for backend/API and network troubleshooting.

Requires **Python 3.15 only**. Use the **latest compatible dependencies and development tools**,
installed with `uv sync --upgrade --extra dev --python 3.15`.

## Overview

HAR Analyze is a Python package that parses HAR 1.2 files captured from browser developer tools or network proxies and produces reports that help identify performance bottlenecks, service failures, and network issues. The report is written for people who troubleshoot the server side (load balancer, web server, application server): it shows the evidence behind each finding and says "not available" when the capture does not contain something.

### Key Capabilities

- **Performance Metrics**: Timing percentiles (p50, p95, p99) overall and by phase (queueing, DNS, connect, TLS, send, wait, receive). p95 is shown from 20 samples and p99 from 100; below that the maximum is shown instead.
- **Key Findings**: A short list of what matters most (observed failures, duration clusters, 5xx, network errors, routing hints, uncertain Date-header differences).
- **Timeout Clusters**: Similar failure durations grouped by host and evidence type, including short and non-round values. Applicable response-wait settings from `--config-facts` are duration comparisons, not proof of a cause.
- **5xx Error Origin**: Response headers on errors next to the same host's successes. These are clues to investigate in proxy and application logs, not proof of which tier failed.
- **Backend Nodes**: Errors and latency grouped by routing hints (`JSESSIONID` jvmRoute, `ROUTEID`, `X-Served-By`). Request affinity does not establish which node served a request; unknown routing coverage is reported.
- **Date Header Differences**: Uncertain differences between HTTP `Date` and browser header-arrival time. These must not be used as automatic clock corrections.
- **Domain Health**: Per-host failures, 5xx and network error counts, observed TCP connect median, and capture health status.
- **Service Health**: Per method and path template; every request falls into exactly one outcome column.
- **Slowest Requests**: Individual requests with host, method, original HAR entry number, phase split, millisecond timestamps and correlation IDs.
- **Infrastructure Details**: HTTP versions, server software, server IPs, connections per host, idle periods, large request bodies.
- **Front-end information**: Compression and cache analysis, kept in a separate section.

### How to read the numbers

- **Timestamps are the browser's clock.** Correlate request IDs and verify clock synchronization before aligning logs. HTTP `Date` can be generated earlier or by an intermediary.
- **Wait / TTFB is not server time alone.** It is network round trip + every proxy hop + the application. TCP connect time is an observation of connection setup, not a reliable number to subtract to obtain application execution time.
- **Latency percentiles cover requests answered over the network.** Browser-cache hits, aborted requests, network errors, unavailable totals and unknown cache/network sources are excluded and counted separately.
- **WebSocket and event-stream connections are listed separately.** Their duration is the connection lifetime, so they are excluded from every count and rule.
- **Failure-cluster durations exclude recorded browser queueing.** They still include DNS, connection setup, upload and download. A cluster of 500/502/503 responses does not establish a gateway timeout; 504 and explicit browser timeout errors provide stronger evidence.
- **Capture notes** at the top list anything left out: malformed entries (skipped and counted), non-network entries (`data:`, `blob:`, extension URLs), and timestamps read as UTC because they had no offset. Invalid/nonfinite timings are excluded, incomplete totals remain unknown, and complete derived totals are labeled. Totals that disagree with recorded phases produce warnings.

### Detected Issue Types

| Issue Type | Severity | Description |
|------------|----------|-------------|
| Network Error | Critical / High / Medium | Critical for understood failures (reset, refused, timed out, DNS, TLS, empty or truncated response, proxy tunnel); High for others; Medium when a request with no status ends at the end of the capture and may have been in flight |
| Duration Exceeded | Critical / High | Request over the duration threshold (default 30 s). Critical when the time went into waiting for the response; High when it went into another phase, which is named |
| Server Error | High | HTTP 5xx responses |
| Rate Limited | High | HTTP 429 responses |
| Client Error | Medium / High | HTTP 4xx responses (401/403 are High) |
| Slow Endpoint | High | Endpoint template whose p95 (max when n < 20) exceeds the threshold (default 10 s) |
| Redirect Loop | High | A URL revisited within one redirect chain |
| Large Payload | Medium | Response larger than 1 MB uncompressed |
| Blocking | Medium | Request queued in the browser over the threshold (default 5 s), with the requests that were in flight meanwhile |
| Redirect Chain | Low | Three or more redirect hops |
| Request Aborted | Low | Cancelled or blocked by the client (informational) |

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
| `--brief` | | Compact Markdown (about 5 KB) with findings, timeout clusters, endpoints and slowest requests |
| `--export-events PATH` | | Write one event per request as JSON Lines, for merging with server logs |
| `--timezone ZONE` | `-t` | Convert displayed timestamps (e.g. `UTC`, `local`, `America/New_York`) |
| `--local-time` | | Convert displayed timestamps to your local timezone |
| `--show-query` | | Print query strings and fragments unredacted (values are redacted by default) |
| `--verbose` | `-v` | Enable verbose logging |

**Rules:**

| Option | Description |
|--------|-------------|
| `--config-facts PATH` | `config_facts.json` from `sas-casefile config`; lists duration-compatible response-wait settings; request scope remains unverified |
| `--expect STATUS:PATH_GLOB` | A response that is normal for the application, e.g. `401:/SASLogon/*` (repeatable) |
| `--no-default-expect` | Drop the default expected rules |
| `--path-rule REGEX=NAME` | Template path segments matching `REGEX` as `{NAME}` (repeatable) |

**Thresholds:**

| Option | Default | Description |
|--------|---------|-------------|
| `--slow-ms` | 10000 | Slow endpoint threshold on p95 (max when n < 20) |
| `--duration-exceeded-ms` | 30000 | Flag individual requests longer than this |
| `--gap-ms` | 1000 | Report idle periods longer than this |
| `--blocking-ms` | 5000 | Browser queueing threshold |
| `--large-payload-bytes` | 1048576 | Large response threshold (uncompressed) |
| `--large-request-body-bytes` | 102400 | Large request body threshold |
| `--redirect-chain-min-hops` | 3 | Report redirect chains with at least this many hops |
| `--timeout-cluster-min` | 3 | Minimum failed requests to form a timeout cluster |
| `--timeout-tolerance-pct` | 2 | Timeout cluster width (±%) |

Timeout settings in `--config-facts` are compared only when their response-wait semantics and units are known: from the fact itself (a `unit` field or a suffix such as `60s`, `2m`), or from the product's documented default for httpd, nginx, mod_jk, Tomcat and HAProxy keys. A bare number for any other product is not matched. Connection setup, keep-alive, upload and session-expiry settings are not response-wait matches. Tomcat `connectionTimeout` is not a servlet execution timeout. Even relevant response-wait settings can reset on activity or apply only to particular routes; verify their actual scope in the server configuration.

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
```

## Capturing a useful HAR

- Chrome leaves cookies out of HAR files unless you choose "Export HAR (with sensitive data)". Without cookies, session routing evidence may be absent; response routing headers can still provide hints. A HAR with sensitive data contains session IDs; the report prints only the route name, but treat the file itself as a secret.
- Keep the network panel open from before the problem starts, with "Preserve log" on.


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
- Missing durations disable idle-gap inference because an unfinished request could span
  the apparent gap. Long-lived streams are analyzed separately.
- Static-resource failures remain visible: a failed JavaScript or stylesheet response can
  explain a broken application even when API requests succeed.
- Endpoint latency separates HTTP methods. Percentiles use linear interpolation over valid
  samples; phase sample counts can differ when exporters omit fields.
- URL path session IDs are redacted even with `--show-query`. Events contain templated paths
  without queries. Event severity follows report outcomes: expected responses and browser
  cancellations are INFO, unexpected 4xx are WARN, and unexpected 5xx/network failures are
  ERROR. Unavailable event durations are null; `duration_source` and timing warnings explain
  the measurement. Consumers must allow an unavailable duration.
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
redaction.

**Remaining validation:** real Chrome, Firefox and Edge captures with known Tomcat/proxy
faults must be checked against DevTools and corresponding server logs before claiming
real-world exporter compatibility. No real captures were available for this review.

## Reference semantics

- [HAR 1.2](https://github.com/ahmadnassri/har-spec/blob/master/versions/1.2.md):
  timing inclusion, missing-value conventions, cache metadata and body sizes.
- [HTTP semantics](https://www.rfc-editor.org/rfc/rfc9110.html): Date and status meanings.
- [Tomcat HTTP connector](https://tomcat.apache.org/tomcat-10.1-doc/config/http.html):
  connection, upload and asynchronous timeout semantics.
- [Apache proxy timeout](https://httpd.apache.org/docs/2.4/mod/mod_proxy.html#proxytimeout),
  [nginx proxy read timeout](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_read_timeout),
  [mod_jk worker settings](https://tomcat.apache.org/connectors-doc/reference/workers.html),
  [HAProxy configuration](https://docs.haproxy.org/3.2/configuration.html):
  candidate response-wait timer behavior.
- [Server Timing](https://www.w3.org/TR/server-timing/): metric syntax and interpretation.
