"""Command-line interface."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, tzinfo
from enum import Enum
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import typer

from . import __version__
from .coordinator import AnalysisCoordinator
from .exporters import CSVExporter, JSONExporter
from .formatter import OutputFormatter


class OutputFormat(str, Enum):
    """Output format options."""

    TERMINAL = "terminal"
    MARKDOWN = "markdown"
    JSON = "json"
    CSV = "csv"


app = typer.Typer(
    name="har-analyzer",
    help="Analyze HAR files with deterministic performance insights",
    add_completion=False,
)


def setup_logging(verbose: bool) -> None:
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


@app.command()
def analyze(  # noqa: PLR0913
    har_file: Path = typer.Argument(  # noqa: B008
        ..., exists=True, file_okay=True, dir_okay=False, readable=True, help="Path to HAR file"
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None, "--output", "-o", help="Export analysis to file"
    ),
    output_format: OutputFormat = typer.Option(  # noqa: B008
        OutputFormat.TERMINAL,
        "--format",
        "-f",
        help="Output format (terminal, markdown, json, csv)",
    ),
    timezone: str | None = typer.Option(
        None,
        "--timezone",
        "-t",
        help="Convert displayed timestamps to timezone (e.g. UTC, local, America/New_York)",
    ),
    local_time: bool = typer.Option(
        False,
        "--local-time",
        help="Convert displayed timestamps to your local timezone (equivalent to --timezone local)",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging"),
) -> None:
    """Analyze a HAR file and generate performance insights.

    Examples:
      # Basic analysis (terminal output)
      har-analyzer analyze myfile.har

      # Export to markdown
      har-analyzer analyze myfile.har -f markdown -o report.md

      # Export to JSON
      har-analyzer analyze myfile.har -f json -o report.json

      # Export to CSV (creates multiple files: *_issues.csv, *_endpoints.csv, etc.)
      har-analyzer analyze myfile.har -f csv -o report.csv

      # With verbose logging
      har-analyzer analyze myfile.har -v
    """
    setup_logging(verbose)

    timestamp_timezone, timestamp_timezone_label = _resolve_timestamp_timezone(timezone, local_time)

    # Validate output file requirement for non-terminal formats
    if output_format != OutputFormat.TERMINAL and output is None:
        typer.echo(
            f"Error: --output/-o is required for {output_format.value} format",
            err=True,
        )
        raise typer.Exit(1)

    # Run analysis
    try:
        _run_analysis(
            har_file,
            output,
            output_format,
            timestamp_timezone=timestamp_timezone,
            timestamp_timezone_label=timestamp_timezone_label,
        )
    except KeyboardInterrupt:
        typer.echo("\n\nInterrupted by user", err=True)
        raise typer.Exit(130) from None
    except Exception as e:
        typer.echo(f"\nError: {e}", err=True)
        raise typer.Exit(1) from e


def _run_analysis(
    har_file: Path,
    output_file: Path | None = None,
    output_format: OutputFormat = OutputFormat.TERMINAL,
    *,
    timestamp_timezone: tzinfo | None,
    timestamp_timezone_label: str | None,
) -> None:
    """Run analysis pipeline."""
    coordinator = AnalysisCoordinator()
    formatter = OutputFormatter(
        timestamp_timezone=timestamp_timezone,
        timestamp_timezone_label=timestamp_timezone_label,
    )

    # Analyze HAR file
    report = coordinator.analyze_har_file(har_file)

    # Handle output based on format
    if output_format == OutputFormat.JSON and output_file:
        exporter = JSONExporter()
        exporter.export(report, output_file, har_file.name)
        typer.echo(f"\n✓ JSON report exported to: {output_file}")

    elif output_format == OutputFormat.CSV and output_file:
        exporter = CSVExporter()
        exported_files = exporter.export(report, output_file, har_file.name)
        typer.echo("\n✓ CSV reports exported:")
        for export_type, path in exported_files.items():
            typer.echo(f"  - {export_type}: {path}")

    elif output_format == OutputFormat.MARKDOWN and output_file:
        markdown_content = formatter.generate_markdown_report(report, har_file.name)
        output_file.write_text(markdown_content, encoding="utf-8")
        typer.echo(f"\n✓ Markdown report exported to: {output_file}")

    # Always display results to terminal (unless only exporting to file)
    if output_format == OutputFormat.TERMINAL or output_file is None:
        formatter.print_report(report)


@app.command()
def version() -> None:
    """Show version information."""
    typer.echo(f"har-analyzer version {__version__}")


def main() -> None:
    """CLI entry point."""
    app()


def _resolve_timestamp_timezone(
    timezone_value: str | None,
    local_time: bool,
) -> tuple[tzinfo | None, str | None]:
    if local_time and timezone_value is not None:
        raise typer.BadParameter("--local-time cannot be used with --timezone")

    if local_time:
        local_tz = datetime.now().astimezone().tzinfo
        return local_tz or UTC, "local"

    if timezone_value is None:
        return None, None

    normalized = timezone_value.strip()
    lowered = normalized.lower()
    if lowered == "utc":
        return UTC, "UTC"
    if lowered == "local":
        local_tz = datetime.now().astimezone().tzinfo
        return local_tz or UTC, "local"

    try:
        return ZoneInfo(normalized), normalized
    except ZoneInfoNotFoundError as exc:
        raise typer.BadParameter(f"Unknown timezone: {normalized}") from exc


if __name__ == "__main__":
    main()
