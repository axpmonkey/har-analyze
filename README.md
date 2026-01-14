# HAR Analyzer

A command-line tool for analyzing HAR (HTTP Archive) files to extract performance metrics, detect issues, and generate actionable insights for backend/API and network troubleshooting.

## Overview

HAR Analyzer parses HAR 1.2 files captured from browser developer tools or network proxies and produces comprehensive reports that help identify performance bottlenecks, service failures, and network issues.

### Key Capabilities

- **Performance Metrics**: Timing percentiles (p50, p95, p99) for overall requests and broken down by phase (DNS, connect, SSL, TTFB, receive)
- **Issue Detection**: Automatic identification of network errors, HTTP 4xx/5xx responses, slow endpoints, large payloads, redirect chains, and connection blocking
- **Domain Health Analysis**: Per-domain breakdown with error rates and health status (healthy, degraded, critical)
- **Service Failure Tracking**: Backend/API service health grouped by domain, method, and path
- **Cache Analysis**: Cache hit/miss ratios and detection of repeatedly downloaded resources
- **Root Cause Hints**: Actionable troubleshooting suggestions for each detected issue

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
uv run har-analyzer analyze <har-file>
```

## CLI Reference

### `analyze` Command

Analyze a HAR file and generate performance insights.

```
uv run har-analyzer analyze <HAR_FILE> [OPTIONS]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `HAR_FILE` | Path to the HAR file to analyze (required) |

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--output PATH` | `-o` | Export analysis to file (required for non-terminal formats) |
| `--format FORMAT` | `-f` | Output format: `terminal`, `markdown`, `json`, or `csv` (default: `terminal`) |
| `--timezone ZONE` | `-t` | Convert displayed timestamps to specified timezone (e.g., `UTC`, `local`, `America/New_York`) |
| `--local-time` | | Convert displayed timestamps to your local timezone |
| `--verbose` | `-v` | Enable verbose logging for debugging |

### `version` Command

Display version information.

```bash
uv run har-analyzer version
```

## Output Formats

### Terminal (Default)

Rich, colorized tables and panels displayed directly in the terminal. Ideal for interactive analysis.

```bash
uv run har-analyzer analyze capture.har
```

### Markdown

Single Markdown report file suitable for documentation, sharing, or integration with wikis and issue trackers.

```bash
uv run har-analyzer analyze capture.har --format markdown --output report.md
```

### JSON

Structured JSON output containing the complete analysis report with all metrics and issues. Suitable for programmatic processing and integration with other tools.

```bash
uv run har-analyzer analyze capture.har --format json --output report.json
```

### CSV

Multiple CSV files generated from a base filename, each containing a specific aspect of the analysis:

| File | Contents |
|------|----------|
| `*_summary.csv` | Overall metrics and statistics |
| `*_issues.csv` | All detected issues with details |
| `*_endpoints.csv` | Per-endpoint timing statistics |
| `*_domains.csv` | Per-domain health analysis |
| `*_services.csv` | Backend service failure breakdown |

```bash
uv run har-analyzer analyze capture.har --format csv --output report.csv
# Creates: report_summary.csv, report_issues.csv, report_endpoints.csv, etc.
```

## Examples

### Analyze a HAR File with Terminal Output

```bash
uv run har-analyzer analyze network-capture.har
```

### Export to Markdown for Documentation

```bash
uv run har-analyzer analyze network-capture.har -f markdown -o analysis-report.md
```

### Export to JSON for Processing

```bash
uv run har-analyzer analyze network-capture.har -f json -o analysis.json
```

### Export to CSV for Spreadsheet Analysis

```bash
uv run har-analyzer analyze network-capture.har -f csv -o metrics.csv
```

### Display Timestamps in Local Time

```bash
uv run har-analyzer analyze network-capture.har --local-time
```

### Display Timestamps in a Specific Timezone

```bash
uv run har-analyzer analyze network-capture.har --timezone America/Los_Angeles
```

### Enable Verbose Logging

```bash
uv run har-analyzer analyze network-capture.har --verbose
```

## Detected Issue Types

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

## Timestamp Display

All issue timestamps reflect when the request was initiated (from the HAR entry's `startedDateTime` field). Use `--timezone` or `--local-time` to convert timestamps from UTC to your preferred timezone for terminal and Markdown output.
