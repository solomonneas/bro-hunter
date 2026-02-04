"""
Suricata eve.json parser with streaming support for large files.
Routes events by event_type (alert, flow, dns, http, tls, fileinfo).
"""
import json
import logging
from pathlib import Path
from typing import Iterator, Union, Any
from datetime import datetime

from api.models.suricata import (
    SuricataAlert,
    SuricataFlow,
    SuricataDns,
    SuricataHttp,
    SuricataTls,
)

logger = logging.getLogger(__name__)


class SuricataParser:
    """
    Parser for Suricata eve.json logs with streaming support.
    Routes events based on event_type field.
    """

    # Map event types to Pydantic models
    EVENT_TYPE_MODELS = {
        "alert": SuricataAlert,
        "flow": SuricataFlow,
        "dns": SuricataDns,
        "http": SuricataHttp,
        "tls": SuricataTls,
        # fileinfo is typically embedded in alerts/http, not standalone
    }

    @staticmethod
    def parse_timestamp(timestamp_str: str) -> datetime:
        """
        Convert Suricata ISO 8601 timestamp to datetime object.

        Args:
            timestamp_str: ISO 8601 timestamp string

        Returns:
            datetime object in UTC
        """
        # Handle various ISO formats
        formats = [
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%SZ",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue

        # Fallback: try dateutil parser if available
        try:
            from dateutil import parser as dateutil_parser
            return dateutil_parser.parse(timestamp_str)
        except Exception:
            logger.warning(f"Failed to parse timestamp: {timestamp_str}")
            return datetime.utcnow()

    @staticmethod
    def parse_file(
        file_path: Union[str, Path],
        event_types: list[str] = None,
        max_errors: int = 100
    ) -> Iterator[Union[SuricataAlert, SuricataFlow, SuricataDns, SuricataHttp, SuricataTls]]:
        """
        Parse a Suricata eve.json file line-by-line (streaming).

        This method reads the file incrementally to handle large files (>100MB)
        without loading the entire file into memory.

        Args:
            file_path: Path to the eve.json file
            event_types: List of event types to parse (None = all types)
            max_errors: Maximum number of parsing errors before stopping

        Yields:
            Parsed Suricata events as Pydantic models

        Raises:
            FileNotFoundError: If file does not exist
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")

        # If event_types filter not provided, accept all known types
        if event_types is None:
            event_types = list(SuricataParser.EVENT_TYPE_MODELS.keys())

        error_count = 0
        line_num = 0
        parsed_count = 0

        logger.info(f"Parsing Suricata eve.json: {file_path}")

        # Stream file line-by-line to handle large files
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line_num += 1
                line = line.strip()

                # Skip empty lines
                if not line:
                    continue

                try:
                    # Parse JSON line
                    data = json.loads(line)

                    # Get event type
                    event_type = data.get("event_type")

                    if not event_type:
                        logger.warning(f"Missing event_type at line {line_num}")
                        continue

                    # Skip if not in requested event types
                    if event_type not in event_types:
                        continue

                    # Get model for this event type
                    model_class = SuricataParser.EVENT_TYPE_MODELS.get(event_type)

                    if model_class is None:
                        # Unknown event type - log but continue
                        logger.debug(f"Unsupported event_type '{event_type}' at line {line_num}")
                        continue

                    # Validate and create model instance
                    entry = model_class(**data)
                    parsed_count += 1
                    yield entry

                except json.JSONDecodeError as e:
                    error_count += 1
                    logger.warning(
                        f"JSON decode error at {file_path}:{line_num}: {e}"
                    )
                    if error_count >= max_errors:
                        logger.error(f"Too many errors ({max_errors}), stopping parse")
                        break
                    continue

                except Exception as e:
                    error_count += 1
                    logger.warning(
                        f"Validation error at {file_path}:{line_num}: {e}"
                    )
                    if error_count >= max_errors:
                        logger.error(f"Too many errors ({max_errors}), stopping parse")
                        break
                    continue

        logger.info(
            f"Completed parsing {file_path}: {line_num} lines, {parsed_count} parsed, {error_count} errors"
        )

    @staticmethod
    def parse_line(line: str) -> Union[SuricataAlert, SuricataFlow, SuricataDns, SuricataHttp, SuricataTls, None]:
        """
        Parse a single JSON line from a Suricata eve.json log.

        Args:
            line: JSON string containing a single log entry

        Returns:
            Parsed Suricata event or None if parsing fails
        """
        try:
            data = json.loads(line)
            event_type = data.get("event_type")

            if not event_type:
                logger.warning("Missing event_type in log entry")
                return None

            model_class = SuricataParser.EVENT_TYPE_MODELS.get(event_type)

            if model_class is None:
                logger.debug(f"Unsupported event_type: {event_type}")
                return None

            return model_class(**data)

        except Exception as e:
            logger.warning(f"Failed to parse line: {e}")
            return None

    @staticmethod
    def validate_log_entry(data: dict) -> bool:
        """
        Validate a Suricata log entry against its schema.

        Args:
            data: Dictionary containing log entry data

        Returns:
            True if valid, False otherwise
        """
        try:
            event_type = data.get("event_type")

            if not event_type:
                return False

            model_class = SuricataParser.EVENT_TYPE_MODELS.get(event_type)

            if model_class is None:
                return False

            model_class(**data)
            return True

        except Exception:
            return False

    @staticmethod
    def extract_alerts(
        file_path: Union[str, Path],
        max_errors: int = 100
    ) -> Iterator[SuricataAlert]:
        """
        Extract only alert events from eve.json.

        Args:
            file_path: Path to the eve.json file
            max_errors: Maximum number of parsing errors before stopping

        Yields:
            Parsed alert events
        """
        return SuricataParser.parse_file(
            file_path,
            event_types=["alert"],
            max_errors=max_errors
        )

    @staticmethod
    def extract_flows(
        file_path: Union[str, Path],
        max_errors: int = 100
    ) -> Iterator[SuricataFlow]:
        """
        Extract only flow events from eve.json.

        Args:
            file_path: Path to the eve.json file
            max_errors: Maximum number of parsing errors before stopping

        Yields:
            Parsed flow events
        """
        return SuricataParser.parse_file(
            file_path,
            event_types=["flow"],
            max_errors=max_errors
        )
