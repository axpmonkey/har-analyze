# HAR Analyzer

A single-file command-line tool for analyzing HAR (HTTP Archive) files to extract performance metrics, detect issues, and generate actionable insights for backend/API and network troubleshooting.

## Overview

HAR Analyzer is a self-contained Python script (`har-analyzer.py`) that parses HAR 1.2 files captured from browser developer tools or network proxies and produces comprehensive reports that help identify performance bottlenecks, service failures, and network issues.

### Key Capabilities

- **Performance Metrics**: Timing percentiles (p50, p95, p99) for overall requests and broken down by phase (DNS, connect, SSL, TTFB, receive)
- **Infrastructure Details**: HTTP version distribution, server software identification, server IP addresses by domain, connection reuse efficiency
- **Issue Detection**: Automatic identification of network errors, HTTP 4xx/5xx responses, slow endpoints, large payloads, redirect chains, and connection blocking
- **Domain Health Analysis**: Per-domain breakdown with error rates and health status (healthy, degraded, critical)
- **Service Failure Tracking**: Backend/API service health grouped by domain, method, and path
- **Time Gap Analysis**: Detection of significant gaps (>1 second) between consecutive requests indicating client-side processing delays
- **Large Request Bodies**: Identification of large POST/PUT payloads (>100KB) that may cause upload slowness
- **Cache Analysis**: Cache hit/miss ratios and detection of repeatedly downloaded resources

### Detected Issue Types

HAR Analyzer automatically detects and categorizes the following issues:

| Issue Type | Severity | Description |
|------------|----------|-------------|
| Network Error | Critical | Connection failures (status=0 or explicit error) |
| Duration Exceeded | Critical | Requests exceeding 30-second threshold |
| Server Error | High | HTTP 5xx responses |
| Client Error | Medium/High | HTTP 4xx responses (401/403 are High severity) |
| Slow Endpoint | High | Endpoints with p95 latency > 10 seconds |
| Large Payload | Medium | Responses exceeding 1 MB |
| Blocking | Medium | Client-side connection blocking > 5 seconds |
| Redirect Chain | Low | HTTP 302/303 redirects |

Each detected issue includes:
- Timestamp of when the request occurred
- Full URL and HTTP method
- Duration and response size (where applicable)
- Root cause hints with actionable troubleshooting suggestions

## Installation

### Prerequisites

- Python 3.11 or later
- [uv](https://docs.astral.sh/uv/) package manager

### Setup

```bash
# Clone the repository
git clone <repository-url>
cd har-analyzer

# Install dependencies
uv sync
```

## Usage

### Basic Command

```bash
uv run har-analyzer.py analyze <har-file>
```

### Show Version

```bash
uv run har-analyzer.py version
```

## CLI Reference

### `analyze` Command

Analyze a HAR file and generate performance insights.

```
uv run har-analyzer.py analyze <HAR_FILE> [OPTIONS]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `HAR_FILE` | Path to the HAR file to analyze (required) |

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--output PATH` | `-o` | Export analysis to Markdown file |
| `--timezone ZONE` | `-t` | Convert displayed timestamps to specified timezone (e.g., `UTC`, `local`, `America/New_York`) |
| `--local-time` | | Convert displayed timestamps to your local timezone |
| `--verbose` | `-v` | Enable verbose logging for debugging |

## Output

By default, results are displayed in the terminal with rich, colorized tables and panels.

Use `--output` to export the analysis as a Markdown file:

```bash
uv run har-analyzer.py analyze capture.har --output report.md
```

## Examples

### Analyze a HAR File with Terminal Output

```bash
uv run har-analyzer.py analyze network-capture.har
```

### Export to Markdown

```bash
uv run har-analyzer.py analyze network-capture.har -o analysis-report.md
```

### Display Timestamps in Local Time

```bash
uv run har-analyzer.py analyze network-capture.har --local-time
```

### Display Timestamps in a Specific Timezone

```bash
uv run har-analyzer.py analyze network-capture.har --timezone America/Los_Angeles
```

### Enable Verbose Logging

```bash
uv run har-analyzer.py analyze network-capture.har --verbose
```

## Timestamp Display

All issue timestamps reflect when the request was initiated (from the HAR entry's `startedDateTime` field). Use `--timezone` or `--local-time` to convert timestamps from UTC to your preferred timezone for terminal and Markdown output.
