# HAR Analyze

A command-line tool for analyzing HAR (HTTP Archive) files to extract performance metrics, detect issues, and generate actionable insights for backend/API and network troubleshooting.

## Overview

HAR Analyze is a Python package that parses HAR 1.2 files captured from browser developer tools or network proxies and produces reports that help identify performance bottlenecks, service failures, and network issues. The report is written for people who troubleshoot the server side (load balancer, web server, application server): it shows the evidence behind each finding and says "not available" when the capture does not contain something.

### Key Capabilities

- **Performance Metrics**: Timing percentiles (p50, p95, p99) overall and by phase (queueing, DNS, connect, TLS, send, wait, receive). p95 is shown from 20 samples and p99 from 100; below that the maximum is shown instead.
- **Key Findings**: A short list of what matters most (outages, timeouts, 5xx, network errors, one bad backend node, clock offset).
- **Timeout Clusters**: Failed requests whose durations bunch at a round value, matched against timeout settings from `--config-facts`.
- **5xx Error Origin**: Response headers on errors next to the same host's successes, to show which tier answered, with what each of 500/502/503/504 is consistent with.
- **Backend Nodes**: Errors and latency per node when the session route (`JSESSIONID` jvmRoute, `ROUTEID`) or `X-Served-By` is in the capture.
- **Clock Offset**: Server `Date` headers compared with the browser clock, so report timestamps can be matched to server logs.
- **Domain Health**: Per-host failures, 5xx and network error counts, round-trip estimate, and health status.
- **Service Health**: Per method and path template; every request falls into exactly one outcome column.
- **Slowest Requests**: Individual requests with their phase split, timestamps and correlation IDs.
- **Infrastructure Details**: HTTP versions, server software, server IPs, connections per host, idle periods, large request bodies.
- **Front-end information**: Compression and cache analysis, kept in a separate section.

### How to read the numbers

- **Timestamps are the browser's clock.** Use the Clock Offset table before searching server logs.
- **Wait / TTFB is not server time alone.** It is network round trip + every proxy hop + the application. The round-trip estimate per host (median TCP connect time) shows how much of it is network.
- **Latency percentiles cover requests answered over the network.** Browser-cache hits, aborted requests and network errors are counted separately, and the summary states how many.
- **WebSocket and event-stream connections are listed separately.** Their duration is the connection lifetime, so they are excluded from every count and rule.
- **Timeout cluster durations run from when the request was sent**, so time queued in the browser does not hide a timeout.
- **Capture notes** at the top list anything left out: malformed entries (skipped and counted), non-network entries (`data:`, `blob:`, extension URLs), and timestamps read as UTC because they had no offset.

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

An endpoint is reported as an **outage** only when it never succeeded and had at least three 5xx or network failures. Endpoints that answered only 4xx are listed as "always rejected". A host with any 5xx or network failure is at least DEGRADED.

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

# Install dependencies
uv sync
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
| `--config-facts PATH` | `config_facts.json` from `sas-casefile config`; names the timeout setting a cluster matches |
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

Timeout settings in `--config-facts` are matched only when their unit is known: from the fact itself (a `unit` field or a suffix such as `60s`, `2m`), or from the product's documented default for httpd, nginx, mod_jk, Tomcat and HAProxy keys. A bare number for any other product is not matched.

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

- Chrome leaves cookies out of HAR files unless you choose "Export HAR (with sensitive data)". Without cookies the backend node cannot be identified. A HAR with sensitive data contains session IDs; the report prints only the route name, but treat the file itself as a secret.
- Keep the network panel open from before the problem starts, with "Preserve log" on.
