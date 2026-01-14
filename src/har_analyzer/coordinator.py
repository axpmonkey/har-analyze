"""Pipeline orchestration."""

from __future__ import annotations

import logging
from pathlib import Path

from .analyzer import HarAnalyzer
from .models.analysis import HarAnalysisReport
from .parser import HarParser

logger = logging.getLogger(__name__)


class AnalysisCoordinator:
    """Orchestrates the full HAR analysis pipeline."""

    def __init__(self) -> None:
        """Initialize coordinator with configuration.

        Args:
            None
        """
        self.parser = HarParser()
        self.analyzer = HarAnalyzer()

    def analyze_har_file(self, har_path: Path) -> HarAnalysisReport:
        """Run full analysis pipeline.

        Args:
            har_path: Path to HAR file

        Returns:
            analysis_report
        """
        # Step 1: Parse HAR
        logger.info("Step 1/2: Parsing HAR file")
        har = self.parser.parse_file(har_path)

        # Step 2: Analyze metrics and detect issues
        logger.info("Step 2/2: Analyzing metrics and detecting issues")
        report = self.analyzer.analyze(har)

        logger.info(f"Detected {len(report.issues)} issues across {len(har.log.entries)} requests")

        return report
