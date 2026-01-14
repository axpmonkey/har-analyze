"""Command-line interface."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, tzinfo
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import typer

from . import __version__
from .coordinator import AnalysisCoordinator
from .formatter import OutputFormatter

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
def analyze(
    har_file: Path = typer.Argument(  # noqa: B008
        ..., exists=True, file_okay=True, dir_okay=False, readable=True, help="Path to HAR file"
    ),
    export: Path | None = typer.Option(  # noqa: B008
        None, "--export", "-e", help="Export analysis to Markdown file"
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
      har-analyzer analyze myfile.har -e report.md

      # With verbose logging
      har-analyzer analyze myfile.har -v
    """
    setup_logging(verbose)

    timestamp_timezone, timestamp_timezone_label = _resolve_timestamp_timezone(timezone, local_time)

    # Run analysis
    try:
        _run_analysis(
            har_file,
            export,
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
    export_file: Path | None = None,
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

    # Export to markdown file or display to terminal
    if export_file:
        markdown_content = formatter.generate_markdown_report(report, har_file.name)
        export_file.write_text(markdown_content, encoding="utf-8")
        typer.echo(f"Markdown report exported to: {export_file}")
    else:
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
