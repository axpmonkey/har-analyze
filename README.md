# HAR Analyze

HAR Analyze turns an HTTP Archive (HAR) capture into a report of failed requests,
slow endpoints, and network timing. Use it to investigate a browser session and
identify the requests and time windows to check in server logs.

The application reads local HAR files and produces terminal, Markdown, JSON, or
JSON Lines output. Analysis runs locally without contacting the captured servers.
Additional diagnostics help investigate proxy, Apache HTTP Server, Tomcat, and
Java application failures when the capture contains the necessary evidence.

## Install and verify

You need [Git](https://git-scm.com/downloads), [uv](https://docs.astral.sh/uv/getting-started/installation/),
and Python **3.14 or 3.15**.

If uv is not installed, use the command for your operating system from its
[installation guide](https://docs.astral.sh/uv/getting-started/installation/):

**macOS or Linux**

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

**Windows PowerShell**

```powershell
irm https://astral.sh/uv/install.ps1 | iex
```

Open a new terminal after installation, then download and install HAR Analyze:

```bash
git clone https://github.com/axpmonkey/har-analyze.git
cd har-analyze
uv sync --python 3.14
uv run har-analyze version
```

Use `uv sync --python 3.15` to install with Python 3.15.

uv creates a `.venv` environment and installs the application and its dependencies.
It can [download Python when needed](https://docs.astral.sh/uv/concepts/python-versions/#installing-a-python-version).
Installation requires internet access; analysis of a local file does not.
You do not need to activate the environment when using `uv run`.

Run all commands below from the `har-analyze` directory.

## Capture a browser session

1. Open your browser's developer tools and select the **Network** panel.
2. Enable **Preserve log** to retain requests across page navigation.
3. Clear existing requests, then reproduce the problem.
4. Export the network log as a HAR file, for example `capture.har`.

Keep the capture focused on the problem, including the steps immediately before
and after it. Preserve response content if you need error-page analysis.

HAR files can contain credentials, cookies, tokens, and request or response data.
Use a sanitized export for routine analysis. If you need session or backend routing
diagnostics, the export must retain cookie headers; a sanitized file may omit them.
Protect captures containing sensitive data and review reports before sharing them.

## Analyze a capture

Display a report in the terminal:

```bash
uv run har-analyze analyze capture.har
```

Replace `capture.har` with the path to your file. Quote paths containing spaces:

```bash
uv run har-analyze analyze "captures/login failure.har"
```

### Save a report

Write a Markdown report that you can open in a Markdown viewer or attach to a
support case:

```bash
uv run har-analyze analyze capture.har -o report.md
```

For a compact Markdown summary of up to approximately 5 KB, use `--brief`:

```bash
uv run har-analyze analyze capture.har --brief -o summary.md
```

Create the destination directory before exporting. An existing output file is
replaced.

### Match the timezone used in server logs

```bash
uv run har-analyze analyze capture.har --timezone America/New_York -o report.md
```

Use `--timezone UTC` for UTC or `--local-time` for your computer's timezone.
Without either option, displayed capture timestamps retain their recorded offsets.
Do not combine `--timezone` with `--local-time`.

Timezone conversion changes how timestamps are displayed. It does not correct
differences between browser and server clocks. HTTP Date header differences, when
reported, are uncertain evidence rather than clock corrections.

### Export structured data

Write the full report as JSON for further processing:

```bash
uv run har-analyze analyze capture.har --json report.json -o report.md
```

The JSON document contains report metadata, including `schema_version` and
`tool_version`, followed by the analysis in `report`. It includes data beyond the
row limits used in the readable reports. Missing incident send estimates are
`null`, and missing wait values in incident ranges and error-origin summaries
are `-1`. The `backend_nodes` field groups observed `X-Served-By` response
header values. These values are responder hints and can name an intermediary.

Export one event per accepted request as JSON Lines for correlation with other logs:

```bash
uv run har-analyze analyze capture.har --export-events capture.events.jsonl
```

Events are sorted by request start time. Each includes a UTC timestamp (`ts`),
host, severity (`level`), request summary (`message`), duration, and request details
in `attrs`. Paths are grouped into templates and query strings are omitted.
`attrs.sent_ts` is a browser-side send estimate included when the recorded
phases support it. When an ID header has different request and response values,
the correlation map also includes the request value under `request:<header>`.
Display timezone options do not change event timestamps.

`--json` and `--export-events` add exports; the usual terminal or Markdown report
is still produced.

## Understand the report

Start with **Key Findings**, then use **Incidents** to find the failed requests,
supporting evidence, and suggested server logs. Sections appear when applicable;
their contents depend on what the HAR file recorded.

| Section | How to use it |
| --- | --- |
| Key Findings | Review the highest-priority observations and investigation steps. |
| Incidents | Find failures grouped by endpoint and signature, with log-search time windows. |
| Summary and Timing Percentiles | Check capture size, duration, response counts, and timing distributions. |
| Domain Health Overview and Backend/API Service Health | Locate hosts and endpoints with failures or high latency. These describe the captured session. |
| Timeout Clusters | Find failed requests with similar waits or durations; compare them with configured timeout values. A cluster alone does not prove a timeout. |
| 5xx Error Origin Clues | Review page fingerprints and headers for clues about the responder. |
| Response Responder Hints | Compare captured `X-Served-By` values. Verify which backend handled each request in deployment logs. |
| Host-wide Stalls and Session Events | Investigate groups of responses arriving together, login redirects, and observed session cookie updates. |
| Timeline and Log Correlation | Search by request or trace ID first, then by browser time, method, and path. The upstream status and timestamp can differ from those in the capture. |
| Slowest Individual Requests and Slowest Endpoints | Compare total duration with browser queueing, network phases, and wait time. |
| Infrastructure and Cache Analysis | Review recorded protocols, connections, server details, and cache behavior. |

### Timing and status definitions

| Term | Meaning |
| --- | --- |
| Total Duration | Sum of individual request durations. Concurrent requests overlap, so this can exceed the elapsed capture duration. |
| Capture Duration | Elapsed time from the first request's start to the last request's end. |
| Queued / blocked | Time waiting in the browser before the request can proceed. |
| DNS / Connect / TLS | Name lookup, TCP connection setup excluding TLS, and TLS negotiation. |
| Wait / TTFB | The recorded browser wait for the first response byte. It can include network transit, proxies, and application processing. Missing wait stays unavailable. |
| Total minus queue | Browser elapsed duration minus recorded blocking time. This can still include DNS, connection setup, upload, and download. |
| Receive | Time receiving the response, including any time spent waiting for streamed content. |
| p50 / p95 / p99 | Median, 95th-percentile, and 99th-percentile timing. `n` is the sample count. |
| Tail | p95 when there are at least 20 samples; otherwise the maximum. |
| Failures / ProblemRate | Capture-level outcomes include unexpected 4xx and 5xx responses, browser errors, and entries without an HTTP response. The endpoint problem rate also includes requests that exceeded the duration threshold. Expected responses and browser cancellations have separate outcome counts. |

Timings are in milliseconds unless another unit is shown. Readable reports show
p95 with at least 20 samples and p99 with at least 100. Latency statistics exclude
browser-cache hits, network failures, and requests with unavailable timing or
unknown cache/network source. Capture notes explain these exclusions.

Domain health is **CRITICAL** when at least two requests have unexpected HTTP
errors or recorded browser errors and these account for at least 50% of captured
requests. Entries without a response or recorded error reason can make a domain
**DEGRADED**, as can a single 5xx, a browser error, or an overall problem rate
of at least 10%. Other domains are **HEALTHY** in the capture.

Repeated 502 responses around 60 seconds suggest checking upstream timing and
failure reasons in the proxy log. A same-length configuration value is a clue
whose applicability depends on the timer and the tier. If a write was redirected
to login, check application logs or transaction state before retrying.

### Missing evidence and redaction

`Not available`, `no data`, or `-` indicates missing evidence in the relevant table.
Missing cookies, connection IDs, response bodies, or timing phases limit the
corresponding analysis. Malformed entries can be skipped with a warning; review
capture notes before relying on totals.

Readable reports and JSON reports hide query values and URL fragments by default.
Use `--show-query` only when those values are needed and the report will be handled
appropriately. It exposes query strings and fragments in those reports; event
exports continue to omit query strings. Session IDs in URL path parameters remain
redacted. Redaction is not a guarantee that all sensitive data has been removed.

## Adjust the analysis

### Recognize expected responses

Use `--expect STATUS:PATH_GLOB` when a response is normal for your application.
Quote the rule so the shell does not expand `*`:

```bash
uv run har-analyze analyze capture.har --expect "401:/api/session"
```

Rules match the URL path and accept an exact status such as `401` or a class such
as `3xx`. Repeat `--expect` to add rules. Matching responses remain in request
counts but are not escalated as failures.

The built-in rules are `401:/SASLogon/*`, `3xx:/SASLogon/*`, and
`404:*/favicon.ico`. Use `--no-default-expect` to remove them before applying
your own rules.

### Change detection thresholds

For example, flag endpoints whose tail wait exceeds two seconds and individual
requests lasting more than ten seconds:

```bash
uv run har-analyze analyze capture.har --slow-ms 2000 --duration-exceeded-ms 10000
```

| Option | Default | Detection |
| --- | --- | --- |
| `--slow-ms` | `10000` | Endpoint tail wait above this value, using non-5xx responses. |
| `--duration-exceeded-ms` | `30000` | Individual request duration above this value. |
| `--blocking-ms` | `5000` | Browser queueing above this value. |
| `--gap-ms` | `1000` | Idle period above this value with no request in flight. |
| `--large-payload-bytes` | `1048576` | Response size above this value (1 MiB). |
| `--large-request-body-bytes` | `102400` | Request body size above this value (100 KiB). |
| `--redirect-chain-min-hops` | `3` | Redirect chain with at least this many hops. |
| `--timeout-cluster-min` | `3` | Minimum failed requests in a timeout cluster. |
| `--timeout-tolerance-pct` | `2` | Maximum cluster width as a percentage of the shortest duration, also used for config duration comparisons. |

For custom endpoint grouping, use the repeatable `--path-rule "REGEX=NAME"`
option to replace fully matching path segments with `{NAME}`. Numeric IDs, UUIDs,
and long hexadecimal IDs are grouped automatically.

If you already have configuration facts from `sas-casefile config`, pass
`--config-facts config_facts.json` to compare timeout clusters and session idle
periods with recorded settings. A matching duration does not verify that a setting
applies to the affected request.

## Troubleshooting

| Problem | What to check |
| --- | --- |
| `uv` or `git` is not found | Install the missing tool, then open a new terminal so PATH changes take effect. |
| Python cannot be resolved | Run `uv sync --python 3.14` or `uv sync --python 3.15`. Check network access if uv needs to download the interpreter. |
| HAR file cannot be opened | Check the path and permissions. Relative paths are resolved from your current directory. |
| Invalid JSON or HAR structure | Export the Network log again as HAR. Renaming another file to `.har` does not convert it. |
| A report cannot be written | Check that the destination directory exists and is writable. |
| Unknown timezone | Use `UTC`, `local`, or an IANA timezone name available on your system. |

Use `--verbose` for diagnostic logging. For the complete command reference and
installed version, run:

```bash
uv run har-analyze --help
uv run har-analyze analyze --help
uv run har-analyze version
```

Successful analysis exits with code `0`, including when the report finds failures.
Processing errors exit with `1`, invalid command arguments with `2`, and an
interrupted analysis with `130`.
