# HAR Analyze

HAR Analyze reads an HTTP Archive (HAR) file exported from a browser or proxy and reports
the failed requests, slow endpoints and network timing in it, with the time windows and
request details you need to find the same requests in server logs. It runs locally and
never contacts the servers in the capture.

## What it reads

**Format:** HAR 1.2. Files that declare HAR 1.1 also load (the fields used are the same).
Files of any size are streamed: one entry is held as raw JSON at a time.

**Supported browsers:**

| Browser | Minimum version |
| --- | --- |
| Chrome | 158 |
| Microsoft Edge | 158 |
| Firefox | 141 |
| Safari (WebKit) | 26 |

Each producer records some things differently, and some things not at all. HAR Analyze
normalises what it can (below) and lists the rest under [Limits](#limits).

| Producer behaviour | How HAR Analyze handles it |
| --- | --- |
| Playwright records a failed request with status `-1` and `_failureText` | read as "no response" with that error |
| Chrome writes a negative `bodySize` when nothing was transferred | read as "not recorded" |
| Chrome records uploads with `bodySize: 0` and no `postData` | size taken from the request's `Content-Length` |
| Chrome puts the server port in `connection` | the socket ID in `_connectionId` is used instead |
| Playwright writes a made-up `ssl` time on plain HTTP and counts TLS twice in `time` on HTTPS | `ssl` ignored on HTTP, total recomputed (shown as a corrected duration) |
| mitmproxy records `connect` without TLS | TLS added back, so `connect` includes TLS as HAR 1.2 specifies |
| mitmproxy writes the compressed size in `content.size` | decoded size is `bodySize + content.compression` |
| Producers name the protocol `h2`, `http/2.0`, `HTTP/2.0`, `h3` … | shown as `HTTP/1.1`, `HTTP/2` or `HTTP/3` |
| Error texts differ: `net::ERR_*` (Chromium), `NS_*` (Firefox), English sentences (WebKit, mitmproxy) | mapped to one set of categories |

## Install

You need [uv](https://docs.astral.sh/uv/getting-started/installation/). uv provides
Python 3.14 or 3.15 if it is not already installed.

```bash
git clone https://github.com/axpmonkey/har-analyze.git
cd har-analyze
uv tool install .
har-analyze --version
```

`uv tool install` puts `har-analyze` on your PATH. To run it from the clone without
installing, use `uv run har-analyze …` instead. Installing needs internet access;
analysing a file does not.

## Quick start

1. In Chrome, open DevTools (**Cmd+Option+I** on macOS, **Ctrl+Shift+I** elsewhere),
   select **Network**, and tick **Preserve log**.
2. Reproduce the problem.
3. Click the download arrow (**Export HAR…**) and save the file, for example `capture.har`.
4. Run:

```bash
har-analyze analyze capture.har            # report in the terminal
har-analyze analyze capture.har -o report.md   # full report as Markdown
har-analyze analyze capture.har --brief    # compact Markdown summary (at most 5 KiB)
```

This is the beginning of `--brief` for a sample capture (shortened):

```text
# HAR brief: capture.har

- Capture: 2026-11-18T11:49:20.651+00:00 → 2026-11-18T11:49:42.481+00:00 (21.83 s), 68 request(s); query values redacted
- Percentiles cover the 59 request(s) answered over the network; not included: 2 cancelled, blocked or not sent; 7 network error(s)
- 0 (no response): 7; 2xx: 28; 3xx: 25; 4xx: 4; 5xx: 4; cancelled by the browser (informational): 1; …

## Findings
- [CRITICAL] 7 network error(s): empty_response (2), connection_refused (1), cors_rejected (1), dns (1), too_many_redirects (1), truncated_response (1) …
- [HIGH] 4 5xx response(s) (500 x1, 502 x1, 503 x1, 504 x1) on 1 endpoint(s): GET /api/delay (4) …
- [HIGH] 1 upload(s) were rejected with 413 (bodies up to 200.0 KiB) …

## Incidents (failed requests by endpoint and signature)
- [HIGH] 1 of 16 GET localhost:18080/api/delay → 504; failed 2026-11-18T11:49:31.942+00:00; wait 2.01 s
- [HIGH] 1 of 1 GET localhost:18099/nothing → connection_refused; failed 2026-11-18T11:49:31.947+00:00; wait -; …

## Slowest endpoints by wait (TTFB, non-5xx responses; ms; tail = p95, or max when n<20)
| Endpoint | n | Wait tail | Wait p50 | Total tail |
|---|---|---|---|---|
| GET localhost:18080/api/delay | 11 | 1,509 (max) | 7 | 2,010 |
```

Start with **Key Findings** and **Incidents**: every failed request is in exactly one
incident, with the browser-clock window to search in server logs and which logs to open.

## Before you share a HAR file

> **A HAR file can contain passwords, session cookies, bearer tokens, API keys, form
> data and whole response bodies.** Treat it like a credential. Do not attach an
> unsanitised HAR to a ticket, chat or email.

HAR Analyze's own reports hide query-string values and URL fragments, keep cookies and
session IDs out of the report, and copy only product names and versions, a proxy's
reason phrase, and Java class and frame names out of error pages. The **HAR file itself** is the risk.

Chrome DevTools offers two exports, *Export HAR (sanitized)* and *Export HAR (with
sensitive data)*; prefer the sanitised one. To strip a HAR yourself, this
[jq](https://jqlang.org/) program removes cookies, authorisation and API-key headers,
query strings, posted data and response bodies, and keeps everything the timing and
failure analysis needs:

```bash
cat > sanitize.jq <<'EOF'
def scrub_headers: map(select(.name | ascii_downcase
  | IN("cookie", "set-cookie", "authorization", "proxy-authorization", "x-api-key",
       "x-auth-token", "x-csrf-token") | not));
.log.entries |= map(
  .request.headers |= scrub_headers
  | .response.headers |= scrub_headers
  | .request.cookies = [] | .response.cookies = []
  | .request.url |= sub("\\?.*$"; "")
  | .request.queryString = []
  | del(.request.postData.text, .request.postData.params)
  | del(.response.content.text)
)
| .log.pages |= ((. // []) | map(.title |= sub("\\?.*$"; "")))
EOF
jq -f sanitize.jq capture.har > capture-clean.har
```

Check the result before sharing (for example `grep -i -e cookie -e token capture-clean.har`).
Other headers your application uses for credentials must be added to the list. What a
sanitised file can no longer show: session-cookie and backend-route evidence (needs
`Cookie`/`Set-Cookie`), and which tier wrote an error page (needs the response body).

## Options

```text
har-analyze --version
har-analyze analyze [OPTIONS] HAR_FILE
```

| Option | Default | What it does |
| --- | --- | --- |
| `-o, --output FILE` | terminal | Write the report as Markdown to FILE. With `--brief`, writes the brief. |
| `--brief` | off | Compact Markdown summary, at most 5 KiB; leaves out front-end advice. |
| `--json FILE` | – | Also write the full report as JSON (schema version 1). URLs are redacted as in the report. |
| `--export-events FILE` | – | Also write one JSON event per request (JSON Lines), with UTC timestamps, path templates and no query strings. |
| `-t, --timezone ZONE` | as recorded | Show timestamps in `UTC`, `local` or an IANA zone such as `America/New_York`. |
| `--local-time` | off | Same as `--timezone local`. Cannot be combined with `--timezone`. |
| `--show-query` | off | Show query strings and fragments unredacted in the report and JSON (events still omit them). |
| `--expect STATUS:PATH_GLOB` | see below | Treat a response as normal, e.g. `--expect "401:/api/session"`; repeatable. `STATUS` is a code or a class like `3xx`. |
| `--no-default-expect` | off | Drop the built-in rules `401:/SASLogon/*`, `3xx:/SASLogon/*`, `404:*/favicon.ico`. |
| `--path-rule REGEX=NAME` | – | Group path segments that fully match REGEX as `{NAME}`; repeatable. UUIDs, numbers and long hex IDs are grouped automatically. |
| `--slow-ms MS` | 10000 | Slow endpoint: tail wait (TTFB) of non-5xx responses above this (p95; max when fewer than 20). |
| `--duration-exceeded-ms MS` | 30000 | Flag individual requests longer than this. |
| `--blocking-ms MS` | 5000 | Flag requests queued in the browser longer than this. |
| `--gap-ms MS` | 1000 | Report idle periods (nothing in flight) longer than this. |
| `--large-payload-bytes N` | 1048576 | Flag responses whose decoded body exceeds this. |
| `--large-request-body-bytes N` | 102400 | List request bodies larger than this. |
| `--redirect-chain-min-hops N` | 3 | Report redirect chains of at least this many hops (loops are always reported). |
| `--timeout-cluster-min N` | 3 | Minimum failed requests with similar durations to form a timeout cluster. |
| `--timeout-tolerance-pct P` | 2 | Maximum width of a timeout cluster, as a percentage of its shortest duration. |
| `--config-facts FILE` | – | `config_facts.json` from `sas-casefile config`, to name timeout settings with the same length as a cluster. |
| `-v, --verbose` | off | Show progress messages on stderr. |

Quote rules that contain `*` so the shell does not expand them.

## Reading the report

| Term | Meaning |
| --- | --- |
| Queued | Time in the browser before the request could be sent (`blocked`). |
| DNS, TCP connect, TLS | Name lookup, TCP connection setup, and TLS handshake. TLS is reported separately and is not counted twice. |
| Wait (TTFB) | Time to the first response byte. It covers the network round trip, every proxy and the application; it is not server time alone. |
| Receive | Time receiving the body, including a server that streams as it produces. |
| Tail | p95 when there are at least 20 samples, otherwise the maximum. p99 is shown from 100 samples. |
| Failed | A network error, or a 4xx/5xx response that no `--expect` rule matches. |
| Cancelled, blocked or not sent | Requests the browser itself cancelled or never sent (navigation, CSP, an extension). Informational, never failures. |
| Served locally | Answered by the browser cache or a service worker; excluded from latency figures and transfer totals. |
| Total duration | Sum of request durations. Concurrent requests overlap, so it can exceed the capture duration. |

Durations are shown in one style: `<1 ms`, `250 ms`, `1.51 s`, `1 min 0.4 s`. Sizes use
1024-based units: `512 B`, `1.5 KiB`, `5.0 MiB`. A `-` means the capture did not record
the value; nothing is ever shown as `0` when it was not measured as zero. In the JSON
report, statistics with no samples are `null`.

Network error categories: `connection_refused`, `connection_reset`, `empty_response`,
`truncated_response`, `timed_out`, `dns`, `tls`, `cors_rejected`,
`blocked_by_response_policy`, `proxy_tunnel`, `client_network_changed`,
`too_many_redirects`, `generic_failure`, `no_response` (status 0 with no reason
recorded) and `other`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Analysis completed, whatever the report found. |
| 1 | Internal error (a bug in HAR Analyze); the message says so. |
| 2 | Invalid command-line arguments. |
| 3 | The input could not be read, is not valid JSON, or is not a usable HAR. |
| 4 | A report or export could not be written. |
| 130 | Interrupted (Ctrl+C). |

## Limits

- **Size and memory.** Files are streamed. A 950 MB capture with 6,900 entries was
  analysed in 2.9 s using 214 MB of memory (the previous whole-file loader needed 2.5 GB).
  Memory grows with the number of entries, not with the size of response bodies.
- **What is kept.** Response bodies are kept only for 4xx/5xx responses, up to 64 KiB
  each, to recognise error pages. Entries without a URL, start time or status (status
  must be 0 or 100–999) are skipped and counted in the capture notes.
- **What HAR files do not show:**
  - No producer records opaque-response blocking (ORB); the response appears as a normal 200.
  - Firefox (through Playwright) does not mark CORS rejections, and records a WebSocket over HTTP/2 as a plain `https` request.
  - Playwright does not mark responses made by a service worker, and its Chromium records a revalidated `304` as the cached `200`.
  - WebKit records redirect responses over HTTP/2 as `HTTP/1.1`.
  - A proxy such as mitmproxy cannot see a browser's CORS refusal and recorded a truncated body as a complete 200.
  - Chrome's HTTP/1.1 `bodySize` is one byte higher than the body sent; HAR Analyze uses `content.size`, `Content-Length` and `_transferSize` instead.
- **What a browser capture cannot tell you.** It shows the browser's view: it cannot
  establish GC pauses, thread exhaustion or database contention, and the status a proxy
  sent to the browser can differ from what the backend returned.
- **Display limits.** Tables show the first rows (for example 15 incidents and 20 hosts)
  and say how many were left out; `--json` contains everything.

## How accuracy is checked

We built a test website that keeps its own record of everything it sends, then visited
it with each supported browser, saved the browser's recording, and compared HAR
Analyze's report with the website's record. They matched on every request. The few
things a browser's recording leaves out are listed under [Limits](#limits).
