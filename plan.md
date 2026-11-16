# har-analyze: output trust and usefulness plan

Current environment policy: **Python 3.15 only, latest compatible dependencies and tools.**
Use `uv sync --upgrade --extra dev --python 3.15`; do not require historical dependency versions
or a lockfile. This policy supersedes historical environment instructions below.

## Current implementation status

The five-phase correctness review has been implemented in the existing module: invalid and
missing timing handling; cache/population and method grouping fixes; evidence-based timeout,
routing and Date-header wording; report/event consistency and traceability; regression tests
and current-tool verification. Python 3.15 only and latest compatible dependencies apply.

Verified: 196 passing tests, 96% branch-aware coverage, formatter/linter clean, strict type
checker clean, and no known vulnerabilities in installed third-party dependencies. The local
har-analyze package is not published on PyPI and is excluded by pip-audit.

Real Chrome/Firefox/Edge captures and controlled Tomcat/proxy captures were unavailable.
Real-exporter and incident validation remains outstanding; passing synthetic tests does not
prove compatibility with those captures. No browser-specific assumptions were added without
capture evidence. The historical review below is background, not a claim that every R item
was completed by this five-phase change.

Existing test expectations changed intentionally: non-round clusters are now observed;
502 clusters have unknown cause rather than a gateway diagnosis; clusters report their actual
median and include methods in endpoint identity; ambiguous cluster severity is lower; cache
metadata alone no longer excludes a response from latency; incomplete phase sums stay unknown;
Date differences no longer add 0.5s or recommend log corrections; routing findings disclose
uncertainty; request tables include host/entry identity; and queueing advice does not claim a
fixed protocol connection limit. README documents the user-visible behavior and event changes.

## Historical review (superseded where current status differs)

Reviewed 2026-11-15 at commit `d2c30a3`, from the point of view of someone using the report to
troubleshoot a Java application server stack (browser → load balancer → httpd/nginx → Tomcat).

Scope: `src/har_analyze/cli.py` (4,510 lines, the whole program), the tests and fixtures.
Baseline: 92 tests pass, 94% branch coverage.

## Status (2026-11-16)

Implemented on branch `output-trust-fixes` (uncommitted), using the recommended option for all
four decisions. Tests for each defect ID are in `tests/test_trust.py`.

- **Fixed:** A1–A10, B1–B16, C1–C7, D1–D7, and the housekeeping list.
- **Not done:** D8 (`--json`). The report model holds unredacted URLs, so a JSON dump needs its
  own redaction pass first.
- **Also fixed while there:** three `ruff` errors that were already failing on `main`
  (`str, Enum` → `StrEnum`); non-deterministic ordering of ties in several sorted tables.
- **Timeout units:** httpd, nginx, mod_jk and Tomcat connector units were checked against the
  product documentation. HAProxy (bare numbers are milliseconds) and Tomcat `session-timeout`
  (minutes) were not re-checked. The 502/503/504 readings are from experience, not from
  documentation, and are worded as "consistent with".
- **Still needed:** a run against real Chrome, Firefox and Edge captures. All fixtures are
  synthetic.

## Remaining work

Nothing below has been started. IDs continue from the original review (R = remaining).

### 1. Prove it on real captures (blocks calling the output "correct")

| ID | Work | Why |
|----|------|-----|
| R1 | Run the tool on real captures from Chrome, Firefox and Edge against a Tomcat-backed application, including at least one with a known fault. Read every finding and table against the capture in DevTools. Put the captures in `test-har/` (ignored by git). | Every fixture is synthetic and encodes my understanding of what browsers write. This is the only step that tests that understanding. **Needs captures from you.** |
| R2 | Turn each surprise from R1 into a fixture in `build_fixtures.py` and a test. | Keeps real-world behaviour from regressing. |
| R3 | Run the verification suite on Python 3.15 only, using the latest compatible dependencies and tools. | This is the only supported Python version. |
| R4 | Run `uv run --no-sync pip-audit`. | Audit the latest installed dependencies. |

### 2. Behaviour I believe is wrong or unverified on real data

| ID | Problem | Fix |
|----|---------|-----|
| R5 | **Firefox reused connections.** Firefox is believed to write `0`, not `-1`, for `dns`/`connect`/`ssl` on a reused connection. If so, those phase percentiles are pulled toward zero and their sample counts are inflated. Not verified. | Confirm on a Firefox capture. If true, treat `0` in those three phases as "not applicable" when the capture tool is Firefox. |
| R6 | **Firefox cache hits.** Cache hits are detected from Chrome's `_fromCache`, `_transferSize` 0, or `cache.beforeRequest`. Whether Firefox fills `cache.beforeRequest` was not verified. | Confirm on a Firefox capture; adjust the signal if needed. |
| R7 | **Short timeouts are missed.** Timeout clusters are only recognised near multiples of 5 s, so 1 s, 2 s and 3 s timeouts are never flagged. | Recognise whole seconds below 5 s as round values, with a higher minimum request count to avoid false positives on fast failures. |
| R8 | **Error origin compares host-wide.** A host's 5xx responses are compared with all of its successes. If static files are answered by the web server and API calls by Tomcat, the comparison can read "same Server header" when the tiers are in fact separable per endpoint. | Compare with successes on the same endpoint first; fall back to the host when the endpoint has none. Say which was used. |
| R9 | **Clock offset names the wrong clock.** The `Date` header is stamped by whichever tier generated or rewrote it (often the proxy, not Tomcat). The report calls it "server clock". | Reword to "the clock of the tier that set the Date header" and show the `Server` value beside it. |
| R10 | **Backend node from the request cookie can be stale.** The route in a request `Cookie` is where the session was pinned, not proof of which node answered (after failover they differ). | Prefer the route from the response; label a request-cookie route as "session pinned to". |
| R11 | **Routes containing a dot are not recognised** (`JSESSIONID=<id>.node1.dc2`). The node silently shows as not available. | Take everything after the first dot of the session ID as the route. |
| R12 | **Error runs use request start times.** Errors from long timeouts are grouped by when they began, not when they failed. | Group on end time (start + duration). |
| R13 | **"In flight at capture end" is a guess.** A status-0 request ending within 1 s of the capture end is downgraded to MEDIUM. A real failure in the last second gets the softer label. | Verify on a real capture what Chrome writes for a pending request; key on that instead of timing if it is distinguishable. |
| R14 | **HAProxy and Tomcat `session-timeout` units were not checked** against documentation. | Check; correct or remove the rows. |
| R15 | **502/503/504 readings are from experience.** | Check each against httpd `mod_proxy`, nginx and AWS ALB documentation; narrow or drop any that do not hold across them. |

### 3. Usefulness: output that is true but hard to use

| ID | Problem | Fix |
|----|---------|-----|
| R16 | **Identical issues are listed one by one.** Eight 502s on one endpoint print eight near-identical blocks, then eight more under "duration exceeded". Up to 50 per severity. | Group issues by type, endpoint template and status: one block with the count, first and last time, duration range and up to three correlation IDs. |
| R17 | **The same request is reported twice.** A slow request appears as "duration exceeded" and again under "slow endpoint". | When every slow request of an endpoint is already listed individually, fold the endpoint line into that group. |
| R18 | **Repeated API polling is a MEDIUM front-end finding.** The same URL polled many times reads as a caching problem. | Raise the finding only for static resources; list polled API URLs in the cache table without a finding. |
| R19 | **Raw field names in issue details** (`wait_time_ms: 59990.0`, `threshold_ms: 30000.0`). | Print labelled, rounded values; drop details that repeat the headline. |
| R20 | **Phase breakdown still says "TTFB"** where the rest of the report says "Wait / TTFB". | Use the same label everywhere. |
| R21 | **Wide tables in the terminal.** Domain health has 12 columns and service health 15; not checked at 80–120 columns. | Check at 100 columns; move the least-used columns to the Markdown report only if they wrap badly. |
| R22 | **4xx events are INFO** in `--export-events`. A 403 or 404 that is not an expected response is easy to miss when merged with server logs. | Emit WARN for 4xx that do not match an expected rule. Confirm this does not break the consumer of `events.jsonl` first. |
| R23 | **`--json` (D8).** | Add after a redaction pass over every URL-bearing field of the report model. |

### 4. Housekeeping

| ID | Work |
|----|------|
| R24 | Commit the work on `output-trust-fixes` (one commit, or split by phase) and open a pull request. Not done because no commit was asked for. |
| R25 | Decide whether to split the module. It is now about 5,800 lines in one file; `AGENTS.md` forbids layout changes without your say-so. |
| R26 | Cover the display-truncation branches ("... and N more") that the tests do not reach. Coverage is 96%, above the 90% floor. |

### Order

R1 first: it will confirm or remove R5, R6 and R13, and will probably add items. Then R7–R15
(correctness), then R16–R23 (usefulness). R3 and R4 can run at any time.

The prompt to carry this out is the last section of this file.

The sections below are the original review, kept as the record of what was wrong.

## Verdict

The core arithmetic is sound. The report is not yet safe to hand to someone as evidence, for
three reasons:

1. **Some numbers are wrong.** Problem rates can read 200%, the cache hit ratio uses the wrong
   denominator, and timeout detection misses queued requests.
2. **Some labels claim more than the data supports.** One 404 is reported as a CRITICAL outage,
   a WebSocket is reported as a CRITICAL 600-second request, browser-side aborts are reported as
   a gateway timeout, and a host returning 80 × 503 is labelled HEALTHY.
3. **Real HAR files are rejected outright.** A byte-order mark, or one entry with a null field,
   fails the whole file.

It also leaves out the evidence a middleware engineer most wants: which tier produced an error,
which backend node served it, and how far the browser clock is from the server clock.

Every defect below marked **confirmed** was reproduced by running the current code.

## What is already correct (do not rework)

- Percentiles use linear interpolation and are replaced by `max` when n < 20.
- TLS time is not double-counted inside connect time (`connect_excluding_ssl`).
- Idle gaps are measured against the latest end time of all earlier requests, so a long request
  is not reported as idle time.
- Phase statistics exclude `-1` (not applicable) values.
- Expected-response rules, path templating and query-value redaction work as designed.
- Aborted requests are kept out of failure counts.

## Defects

Line numbers refer to `src/har_analyze/cli.py`.

### A. Wrong numbers

| ID | Defect | Evidence | Fix |
|----|--------|----------|-----|
| A1 | `problem_rate` adds the over-duration count to the error counts, so a 504 that took 60 s is counted twice (line 649). | Confirmed: `timeout_cluster.har` gives `POST /SASStoredProcess/do` 8 requests, 200%. | Count each request once: a request is a problem if it has any of the conditions. |
| A2 | Timeout clusters use `entry.time`, which includes time queued in the browser (line 1616). Queueing spreads identical timeouts apart. | Confirmed: four 504s with `wait` = 60 s and `blocked` = 0, 4, 9, 15 s produce no cluster. | Cluster on time since the request was sent: `time − blocked` (ignore `blocked` < 0). Report both values. |
| A3 | Cache hit ratio is hits ÷ (hits + repeated downloads) (line 2044). Single downloads are left out of the denominator. | Confirmed: 1 hit and 25 network downloads reports 14% from "6 misses". | Denominator is all cacheable GET responses (200 from network, 200 from cache, 304). Rename the field to say what it measures. |
| A4 | Repeated downloads group by URL without the query string and include every method (line 1997). | Confirmed: `GET /api/items?page=0..2` and three `POST /api/save` are both reported as one resource downloaded three times. | Key on the full URL, GET only, and skip responses marked `no-store`. |
| A5 | Service rows do not add up: 1xx responses (WebSocket 101) fall through every branch (line 1735). | Confirmed: `/ws/events` shows 1 request, 0 OK, 0 errors, 100% problem rate. | Give every request exactly one outcome bucket and assert the buckets sum to the request count. |
| A6 | Large-response and compression checks use `bodySize`, the size on the wire. `response.content.size` (the uncompressed size) is not parsed at all. | By inspection: a 5 MB JSON body compressed to 800 KB is not flagged; `bodySize` of `-1` is skipped silently. | Parse `content.size` and `content.mimeType`. Use the uncompressed size for "large response", the wire size for "transferred". |
| A7 | Timeout units are guessed as milliseconds unless the component is httpd (line 494). | Confirmed: nginx `proxy_read_timeout=60` → 0.06 s; mod_jk `socket_timeout=60` → 0.06 s; Tomcat `session-timeout=30` → 0.03 s; HAProxy `1m` → no value. | Per-component unit table (see "Timeout units" below). An unknown unit means no match, never a guess. |
| A8 | The error-burst rule chains errors while each is within 5 s of the previous one, so a steady error every 4 s for ten minutes is one "burst" (line 2086). The table title says "3+ errors within 5s". | By inspection. | Either a true sliding window, or keep the chaining and retitle it "error run" with its duration and rate. |
| A9 | `_dominant_side` returns "server" when an endpoint has no timing data at all (line 3114). | Confirmed with a refused connection. | Return "-" when there is nothing to compare. |
| A10 | The dominant-side comparison sets the tail of TTFB against the tail of network time. Those can come from different requests. | By inspection. | Compare summed TTFB with summed network time for the endpoint, as the domain table already does. |

### B. Labels that overstate

| ID | Defect | Evidence | Fix |
|----|--------|----------|-----|
| B1 | An endpoint with one request and one 404 is a CRITICAL "outage: failed every request — investigate backend health immediately" (line 2194). | Confirmed. | An outage needs at least 3 failed requests and no success, and must be 5xx or network errors. All-4xx endpoints go in a separate "always rejected" list at MEDIUM. |
| B2 | WebSocket, server-sent events and long-poll requests are flagged CRITICAL for duration, HIGH as a slow endpoint, and become the "slowest server time" finding. | Confirmed with a 101 response lasting 600 s. | Recognise them (`_resourceType` websocket/eventsource, status 101, `Content-Type: text/event-stream`) and exclude them from latency statistics and duration rules. List them in their own table. |
| B3 | Requests the browser aborted at a round duration are reported as CRITICAL "matches a gateway/proxy timeout" (line 1611 takes every status 0). | Confirmed: four `ERR_ABORTED` at 30 s. | Split by evidence: 502/503/504 → gateway timeout; `timed_out` → network timeout; aborted → "client-side timeout or cancel", not CRITICAL. |
| B4 | Domain health is rate-only: under 10% is HEALTHY regardless of what failed (line 1111). | Confirmed: 80 × 503 in 1,000 requests is HEALTHY. | Any 5xx or real network error makes a host at least DEGRADED. Show counts beside the label. |
| B5 | "TTFB (server)" is used throughout. `wait` is network round trip plus every proxy hop plus the application. | By inspection. | Label it "Wait (TTFB: network + proxies + app)". Print the per-host round-trip estimate (median TCP connect time) next to it so the reader can subtract it. |
| B6 | Receive time is always counted as "network". For streamed or chunked responses it is the server producing the body. | By inspection. | When receive dominates, say "receive (transfer or streamed generation)" and show the response size beside it. |
| B7 | `ERR_BLOCKED_BY_RESPONSE` is classed as informational "blocked by client" (line 353). It is caused by the server's own headers. | Confirmed. | Move to a real category, `blocked_by_response_policy`. |
| B8 | Truncated-response errors land in "other" with no guidance: `ERR_HTTP2_PROTOCOL_ERROR`, `ERR_INCOMPLETE_CHUNKED_ENCODING`, `ERR_CONTENT_LENGTH_MISMATCH`. These are the usual signature of a proxy or Tomcat dropping a response mid-stream. | Confirmed. | Add a `truncated_response` category (CRITICAL). Add `proxy_tunnel`, `network_changed`, `too_many_redirects`, `cors_or_generic_failure`. |
| B9 | An empty `_error` string on a 200 response is classed as `no_response` (line 384). | Confirmed. | Treat empty the same as absent. |
| B10 | A request with both `_error` and a 4xx/5xx status produces two issues, and counts twice in error bursts and issue counts. | By inspection. | One issue per request; the network error wins and carries the status. |
| B11 | Status 0 with no error text is reported as a network failure. Requests still running when the HAR was saved look the same. | By inspection. | When such a request ends at the capture end, word it "no response recorded (may have been in flight when the capture was saved)". |
| B12 | Any request over 30 s is CRITICAL, including large uploads and downloads where the time is in send or receive. | By inspection. | CRITICAL only when wait dominates; otherwise HIGH with the dominant phase named. |
| B13 | `--brief` always prints "query values redacted", including with `--show-query` (line 4184). | Confirmed: the brief says redacted and contains `ticket=ST-…`. | Print the real state. |
| B14 | p99 is printed from n = 20, where it is the maximum under another name. | By inspection. | Print p99 only when n ≥ 100. |
| B15 | Overall percentiles mix cache hits (about 0 ms), aborted requests and failed requests with completed ones. | By inspection. | Compute latency percentiles over requests that received a response from the network. State how many were excluded and why. |
| B16 | Connection reuse is one figure across all hosts. With HTTP/1.1 a browser opens six connections per host, so 12 requests to one host reads as 50% "low" (line 2164). | By inspection. | Report per host: requests, new connections (entries with `connect` ≥ 0), and whether responses carry `Connection: close`. Flag only "nearly every request opened a new connection". |

### C. Input handling

| ID | Defect | Evidence | Fix |
|----|--------|----------|-----|
| C1 | A UTF-8 byte-order mark fails the file (line 4463). Windows tools write one. | Confirmed: `JSONDecodeError: Unexpected UTF-8 BOM`. | Read as `utf-8-sig`. |
| C2 | One entry with a null or missing field rejects the whole file. | Confirmed for `timings.ssl` null, `timings.send` missing, `statusText` missing, `bodySize` null, `time` null, `httpVersion` missing. | Validate entry by entry. Null and missing optional numbers become "not recorded". Skip an entry only when it has no usable URL, start time or status; print the skipped count and the first reasons at the top of every output. |
| C3 | Mixing timestamps with and without a UTC offset crashes with `TypeError` (line 1867). | Confirmed. | Normalise once at load: timestamps without an offset are treated as UTC and the report says so. |
| C4 | `data:`, `blob:`, `chrome-extension:` and similar entries are analysed as hosts. | Confirmed: domains come out as `''` and `abcdef`. | Drop non-http(s) entries at load and report the count. |
| C5 | `log.creator`, `log.browser` and `log.pages` are ignored. Chrome and Firefox record timings differently, and the reader is not told which produced the file. | By inspection. | Print the capturing tool and version in the summary. Use it to pick the Chrome or Firefox reading where they differ. |
| C6 | Peak request rate is quadratic (line 2125). | Confirmed: 6,000 entries take 2.7 s; 30,000 would take over a minute. | Two-pointer sliding window. Same for the per-endpoint rescan at line 1459. |
| C7 | Dead code: `HarCookie`, `HarQueryParam`, `HarCache.before_request`, `EndpointStats.total_bytes`, `DomainAnalysis.is_first_party`, duplicate `DOMAIN_ERROR_RATE_*` constants. | `rg` shows no readers. | Delete, except `cache.beforeRequest`, which becomes the standard cache-hit signal for Firefox files. |

### D. Missing evidence a middleware engineer needs

Listed in order of value. Each is derived only from data in the HAR.

| ID | Addition | Why it matters |
|----|----------|----------------|
| D1 | **Error origin.** For each 5xx group, compare `Server`, `Via`, `Content-Type` and body size with the same endpoint's successful responses. Report "5xx responses carry `Server: awselb/2.0`; successes carry none". | Tells the reader whether the load balancer, the web server or Tomcat produced the error. That decides whose logs to open. |
| D2 | **Status-specific reading of 502, 503 and 504, with duration.** Fast 502 → backend refused or closed the connection (restart, or keep-alive mismatch between proxy and Tomcat). Fast 503 → no backend available, or Tomcat `maxThreads` plus `acceptCount` exhausted. 504 at a round duration → proxy read timeout. | Replaces "investigate backend health immediately" with a testable hypothesis. Word each as "consistent with", never as a diagnosis. |
| D3 | **Clock offset.** Median of (response `Date` header − the moment the response headers arrived), skipping cache hits. Print when it exceeds 2 s, with n. | The HAR uses the browser clock. Without the offset, matching against access logs and `catalina.out` fails or points at the wrong lines. |
| D4 | **Slowest requests table in the terminal and Markdown reports.** It already exists in `--brief` only (line 4229). | Individual requests with their phase split and timestamps are what get searched for in access logs. |
| D5 | **Backend node, when visible.** The `jvmRoute` suffix of `JSESSIONID` (for example `.node2`), a `ROUTEID` cookie, `X-Served-By`, or the server IP. Show errors and tail latency per node. | One bad node behind a balancer is a common cause and invisible in per-host totals. Chrome removes cookies from HAR files unless the user opts in, so report "not available" when absent. Print only the route name, never the session ID. |
| D6 | **Browser queueing as a symptom.** When `blocked` is high on an HTTP/1.1 host, say that requests were waiting for one of six connections, and name the slow requests that were holding them. | Stops queueing being read as a client problem when the cause is slow responses. |
| D7 | **Correlation IDs on issues.** The export already collects them (line 433); show them on each error in the reports. | Direct lookup key into server logs. |
| D8 | **JSON output** (`--json`) of the full report model. | Lets the numbers be diffed between versions and consumed by other tools. Optional; do last. |

### Timeout units (for A7)

Bare numbers, by component and key:

| Component | Seconds | Milliseconds | Minutes |
|-----------|---------|--------------|---------|
| httpd | `Timeout`, `ProxyTimeout`, `KeepAliveTimeout`, `timeout=`, `connectiontimeout=`, `ttl=`, `retry=` | | |
| nginx | all `*_timeout` directives | | |
| mod_jk | `socket_timeout`, `connection_pool_timeout` | `reply_timeout`, `connect_timeout`, `prepost_timeout`, `socket_connect_timeout` | |
| Tomcat connector | | `connectionTimeout`, `keepAliveTimeout`, `asyncTimeout`, `connectionUploadTimeout` | |
| Tomcat `web.xml` | | | `session-timeout` |
| HAProxy | | bare `timeout *` values | |

Suffixes to accept everywhere: `ms`, `s`, `m`/`min`, `h`. Confirm each row against the product
documentation before coding it; the table is from memory.

## Order of work

Each phase leaves the verification suite green and is one commit.

1. **Input handling** — C1, C2, C3, C4, C5. Nothing else can be trusted on real files until
   this is done.
2. **Wrong numbers** — A1 to A10.
3. **Overstated labels** — B1 to B16. This changes severities, so the golden tests will need
   deliberate updates; review each changed expectation.
4. **New evidence** — D1 to D7, in that order.
5. **Consistency** — C6, C7, D8, and the housekeeping below.

Housekeeping for phase 5:

- Terminal, Markdown and brief reports show the same sections in the same order.
- Table titles take their thresholds from settings ("Large Request Bodies (>100KB)" is
  hard-coded at lines 3832 and 3944).
- Pipe characters in paths are escaped in Markdown tables.
- Report files are written atomically (lines 4485 and 4491), as `AGENTS.md` requires.
- `README.md` matches the code: it still describes redirect chains as "HTTP 302/303" and omits
  `--brief`, `--export-events`, `--config-facts`, `--expect` and the threshold options.

## Testing

- Every defect ID gets a test that fails before the fix. Name the ID in the test.
- New fixtures go through `tests/fixtures/build_fixtures.py`: a WebSocket and SSE capture, a
  Firefox-shaped capture, a capture with malformed entries, a multi-node capture with
  `jvmRoute` cookies, and a capture with a clock offset.
- Add invariant tests that hold for any input: outcome buckets sum to the request count; no rate
  exceeds 100%; every request appears in exactly one endpoint; percentiles are ordered
  p50 ≤ p95 ≤ p99 ≤ max.
- The fixtures are synthetic. Before calling the work finished, run the tool on real captures
  from Chrome, Firefox and Edge against a Tomcat-backed application and read the output for
  claims the data does not support. **This needs captures from you**; the ignored `test-har/`
  directory is empty on this machine.

## Decisions for you

These change what the report says about severity. The plan uses the recommended value unless
you say otherwise.

1. **Malformed entries.** Recommended: skip the entry, continue, and print the count
   prominently. `AGENTS.md` says "fail fast"; the alternative is to keep rejecting the file and
   only improve the message.
2. **Outage rule.** Recommended: at least 3 failures, no successes, 5xx or network errors only.
3. **Health rule.** Recommended: any 5xx or real network error means at least DEGRADED.
4. **One file or several.** The program is one 4,510-line module. `AGENTS.md` forbids layout
   changes without your say-so, so the plan keeps it. Splitting it into parse / analyse / render
   modules would make this work easier to review; say so if you want that first.

## Out of scope

- Anything that needs data outside the HAR (server logs, thread dumps, GC logs).
- Front-end performance advice beyond what exists.
- Changing CLI option names or the `events.jsonl` format.

---

## Prompt: finish everything in this plan

Paste the block below into a new session started in the repository root. It covers all
remaining work (R1 to R26). The original review items (A, B, C, D) are already implemented,
apart from D8, which is R23.

```text
You are working in the har-analyze repository: a Python command-line tool that reads a browser
HAR capture and produces a report used to troubleshoot Java application server stacks (browser →
load balancer → httpd/nginx → Tomcat). The readers are middleware engineers. They use the report
as evidence when deciding which tier is at fault and which server logs to open, so a wrong
number or an overstated label sends them to the wrong team. The goal is that every figure and
every label in the report can be trusted, and that the report is quick to act on.

Start by reading plan.md and AGENTS.md in full. plan.md has three parts: a "Status" section
saying what is already done, a "Remaining work" section with items R1 to R26, and the original
review below that, kept as background. Your job is the "Remaining work" section, all of it. The
whole program is src/har_analyze/cli.py; the tests for the first round are in
tests/test_trust.py and show the style to follow.

Before changing anything, establish the starting point:
- Check out the branch output-trust-fixes. If the first round of work is still uncommitted
  there, commit it as it stands as one commit, so your own changes can be reviewed separately.
- Run the verification commands below and confirm they pass. If they do not, stop and report;
  do not build on a failing base.

Then work in this order:

1. Real captures (R1, R2). Look in test-har/. If it holds HAR files, run the tool on each one
   and read the whole report against the capture: check totals, a sample of per-request
   figures, every finding, and every "not available" line. Anything wrong or misleading is
   higher priority than the listed items; fix it, and add a synthetic fixture and test that
   reproduce it. Use what the captures show to settle R5, R6 and R13. If test-har/ is empty,
   say so plainly, skip R1 and R2, and leave R5, R6 and R13 unimplemented, because they cannot
   be settled without a real capture.
2. Environment checks (R3, R4): the verification suite on Python 3.15 only with the latest
   compatible dependencies and tools, and pip-audit.
3. Correctness (R7 to R15).
4. Usefulness (R16 to R23).
5. Housekeeping (R26).

Leave R25 (splitting the module) alone: it is the user's decision and AGENTS.md forbids layout
changes without it. Commit on the branch after each of the five groups; do not push and do not
open a pull request (that part of R24 is for the user).

How to work:

- For each item, write a test that fails on the current code and names the R number, then make
  the fix. If you cannot make an item reproduce, do not change the code for it; record what you
  tried.
- Several items rest on claims about how Chrome, Firefox, httpd, nginx, HAProxy, AWS load
  balancers and Tomcat behave. plan.md marks which were written from memory. Check each claim
  against the product's documentation or a real capture before encoding it. If you cannot
  confirm one, leave it out and list it in your report with what you checked. A confident
  wrong statement in the report is worse than a missing one.
- Keep the wording rule the existing code follows. When the data supports a hypothesis but not
  a diagnosis, say "consistent with" and print the evidence beside it (counts, durations,
  header values). When something cannot be computed from the capture, print "not available"
  and the reason. Never print a zero that means "unknown".
- Every count shown to the user must reconcile: categories sum to their total, no rate exceeds
  100%, and when requests are left out of a statistic the report says how many and why. R16 and
  R17 group and fold issues; after them the grouped counts must still add up to the number of
  underlying issues.
- The terminal, Markdown and brief reports must stay consistent with each other: the same
  figure must not differ between them.
- Changing an existing test expectation is allowed only when plan.md intends the new value.
  List every one you change, with the old and new value.
- R22 changes event levels in --export-events. Find out what consumes events.jsonl before
  changing it (the code comments point at sas-casefile). If you cannot tell whether a level
  change is safe for the consumer, skip R22 and say so.
- R23 (--json) must not leak what the other outputs redact: query-string values and fragments
  are redacted unless --show-query is given, and session IDs are never printed.
- Keep the single-module layout, the existing CLI option names and the events.jsonl field
  names. Do not add abstractions the fixes do not need.

Repository specifics that are easy to get wrong:

- Sanitized tests and synthetic fixtures are included in version control. Real captures in
  test-har/ remain ignored. A lockfile is not required for this work.
- Never copy hostnames, URLs, tokens, cookies or session IDs from test-har/ into a fixture, a
  test, a commit message or your report. Describe what you found in general terms and
  reproduce it with invented values in tests/fixtures/build_fixtures.py.
- Use uv only, with the dev extra: uv sync --upgrade --extra dev --python 3.15
- Verification, with TZ=UTC PYTHONUTF8=1 set; all must pass before each commit:
  uv run --extra dev ruff format --check --no-respect-gitignore
  uv run --extra dev ruff check --no-respect-gitignore
  uv run --extra dev basedpyright
  uv run --extra dev pytest -q --cov=src/har_analyze --cov-branch --cov-fail-under=90
  (ruff skips the ignored tests/ directory without --no-respect-gitignore.)
- Output must be deterministic apart from the "Report Generated" timestamp.

When you finish, or if you have to stop early:

1. Update the "Status" and "Remaining work" sections of plan.md so they are true: move
   finished items into Status, leave unfinished ones where they are with a note, and add any
   new problems you found as new R items.
2. Update README.md for any change a user of the tool would notice.
3. Report, leading with whether the output can now be trusted on real captures and what that
   rests on. Then, for each R number: fixed, not reproduced, could not confirm, or skipped,
   with one line of reason. Then every test expectation you changed, every domain claim you
   could not confirm, and the final output of the verification commands.

If test-har/ was empty, say in the first line of the report that the tool is still unproven on
real captures, however many tests pass.
```
