"""HAR file parsing."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from .models.har import Har

logger = logging.getLogger(__name__)


class HarParser:
    """Parse HAR files with validation."""

    def parse_file(self, har_path: Path) -> Har:
        """Parse complete HAR file into memory.

        Args:
            har_path: Path to HAR file

        Returns:
            Validated Har object

        Raises:
            FileNotFoundError: If file doesn't exist
            json.JSONDecodeError: If invalid JSON
            pydantic.ValidationError: If doesn't match HAR spec
        """
        if not har_path.exists():
            raise FileNotFoundError(f"HAR file not found: {har_path}")

        logger.info(
            f"Parsing HAR file: {har_path} ({har_path.stat().st_size / 1024 / 1024:.1f} MB)"
        )

        with har_path.open("r", encoding="utf-8") as f:
            raw_data = json.load(f)

        # Pydantic validation happens here
        har = Har.model_validate(raw_data)

        logger.info(f"Parsed {len(har.log.entries)} entries")
        return har
