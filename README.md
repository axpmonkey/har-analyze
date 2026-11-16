# HAR Analyze

A command-line tool that reads a browser HAR capture and reports what went wrong between the
browser and a Java application server stack (load balancer, web server, Tomcat): which
requests failed, which tier answered, and which server logs to open, with the times to
search for.

## Requirements

- Python 3.15
- [uv](https://docs.astral.sh/uv/)

## Install

```bash
# Install uv (macOS / Linux)
curl -LsSf https://astral.sh/uv/install.sh | sh
```

```powershell
# Install uv (Windows PowerShell)
irm https://astral.sh/uv/install.ps1 | iex
```

```bash
git clone git@github.com:axpmonkey/har-analyze.git
cd har-analyze
uv sync --python 3.15
```

## Capture a HAR file

1. Open the browser's developer tools and select the **Network** tab.
2. Turn on **Preserve log** before reproducing the problem.
3. Reproduce the problem.
4. Export the capture as a HAR file.

In Chrome, the default export removes cookies. Choose **Export HAR (with sensitive data)**
if you need the report to show backend nodes and session changes. That file contains session
IDs, so treat it as a secret.

## Run

```bash
# Report in the terminal
uv run har-analyze analyze capture.har

# Report as a Markdown file
uv run har-analyze analyze capture.har -o report.md

# Short summary (about 5 KB of Markdown)
uv run har-analyze analyze capture.har --brief

# Show times in the servers' timezone, to match their logs
uv run har-analyze analyze capture.har --timezone America/New_York
```

Run `uv run har-analyze analyze --help` for every option, and `uv run har-analyze version`
for the installed version.

## Read the report

Start at the top and stop when you have what you need.

| Section | What it tells you |
|---------|-------------------|
| **Key Findings** | The few things that matter most, worst first. |
| **Incidents** | Every failed request, grouped by endpoint and status. Each incident lists its evidence, the time window to search for in server logs, and which logs to open first. |
| **Timeout Clusters** | Failed requests that all took the same time, which points at a timeout setting. |
| **5xx Error Origin** | Which tier wrote the error, read from the error page when the capture kept it. |
| **Host-wide Stalls** | Requests sent at different times that were all answered together, with the window to check in GC logs and thread dumps. |
| **Session Events** | Requests sent back to the login page, session routes that changed, sessions issued again. |
| **Timeline** | Requests, errors and wait time per time bucket. |
| **Log Correlation** | When each failed or slow request was sent, to find it in an access log. |
| **Backend/API Service Health** | Counts and wait times per endpoint. |
| **Slowest Requests / Endpoints** | Where the time went, by phase. |

Keep these in mind when reading the numbers:

- **All times are the browser's clock.** A server's clock may differ; the report shows the
  difference when it can measure one.
- **Wait (TTFB) is not server time alone.** It is the network round trip, every proxy and
  the application together.
- **Findings say "consistent with", not "caused by".** A capture shows what the browser saw.
  Confirm the cause in the server logs the report points to.
- **"Not available" means the capture did not contain the evidence**, for example cookies in
  a sanitized export.
- **Query string values are hidden** unless you pass `--show-query`. Session IDs are never
  printed.

## Options

### Output

| Option | Description |
|--------|-------------|
| `-o`, `--output PATH` | Write the report as Markdown. |
| `--brief` | Write a compact Markdown summary. |
| `--json PATH` | Write the full report as JSON, with the same redaction as the other outputs. |
| `--export-events PATH` | Write one JSON line per request, for merging with server logs. |
| `-t`, `--timezone ZONE` | Show times in a timezone, for example `UTC`, `local` or `America/New_York`. |
| `--local-time` | Show times in your local timezone. |
| `--show-query` | Show query strings and fragments unredacted. |
| `-v`, `--verbose` | Verbose logging. |

### Rules

| Option | Description |
|--------|-------------|
| `--expect STATUS:PATH_GLOB` | Treat a response as normal for the application, for example `401:/SASLogon/*`. Repeatable. |
| `--no-default-expect` | Drop the built-in rules (`401:/SASLogon/*`, `3xx:/SASLogon/*`, `404:*/favicon.ico`). |
| `--path-rule REGEX=NAME` | Group path segments that match `REGEX` under `{NAME}`. Repeatable. IDs that are numbers, UUIDs or long hex strings are grouped automatically. |
| `--config-facts PATH` | A `config_facts.json` from `sas-casefile config`. The report then names timeout settings whose length matches a timeout cluster, and compares idle time with the session timeout. |

### Thresholds

| Option | Default | Flags |
|--------|---------|-------|
| `--slow-ms` | 10000 | Endpoints whose wait for the first byte is longer. |
| `--duration-exceeded-ms` | 30000 | Individual requests that took longer. |
| `--blocking-ms` | 5000 | Requests queued in the browser for longer. |
| `--gap-ms` | 1000 | Periods longer than this with no request in flight. |
| `--large-payload-bytes` | 1048576 | Responses larger than this. |
| `--large-request-body-bytes` | 102400 | Request bodies larger than this. |
| `--redirect-chain-min-hops` | 3 | Redirect chains at least this long. |
| `--timeout-cluster-min` | 3 | Minimum failed requests that form a timeout cluster. |
| `--timeout-tolerance-pct` | 2 | How close the durations in a cluster must be (±%). |

## Limitations

- The tool has been tested on synthetic captures only. It has not yet been checked against
  real Chrome, Firefox or Edge exports, so read the first few reports against the capture in
  the browser's developer tools.
- A capture is one browser's view. It cannot show garbage collection, thread pools or
  database contention directly; the report tells you when and where to look for them.

## Development

```bash
uv sync --upgrade --extra dev --python 3.15
uv run --no-sync ruff format --check
uv run --no-sync ruff check
uv run --no-sync basedpyright
TZ=UTC uv run --no-sync pytest -q --cov=src/har_analyze --cov-branch --cov-fail-under=90
uv run --no-sync pip-audit
```

Contributor rules are in `AGENTS.md`.
