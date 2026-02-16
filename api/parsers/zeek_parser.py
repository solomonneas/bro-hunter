"""
Zeek JSON log parser with streaming support for large files.
Handles all major Zeek log types with proper error handling.
"""
import json
import logging
from pathlib import Path
from typing import Iterator, Union, Any
from datetime import datetime, timezone

from api.models.zeek import (
    ConnLog,
    DnsLog,
    HttpLog,
    SslLog,
    X509Log,
    FilesLog,
    NoticeLog,
    WeirdLog,
    DpdLog,
    SmtpLog,
)

logger = logging.getLogger(__name__)


class ZeekParser:
    """
    Parser for Zeek JSON logs with streaming support.
    Handles large files efficiently by processing line-by-line.
    """

    # Map log type identifiers to Pydantic models
    LOG_TYPE_MODELS = {
        "conn": ConnLog,
        "dns": DnsLog,
        "http": HttpLog,
        "ssl": SslLog,
        "x509": X509Log,
        "files": FilesLog,
        "notice": NoticeLog,
        "weird": WeirdLog,
        "dpd": DpdLog,
        "smtp": SmtpLog,
    }

    @staticmethod
    def parse_timestamp(ts: float) -> datetime:
        """
        Convert Zeek epoch timestamp to UTC-aware datetime object.

        Args:
            ts: Zeek timestamp (float epoch seconds with microsecond precision)

        Returns:
            UTC-aware datetime object

        Raises:
            ValueError: If timestamp is invalid
        """
        if ts is None:
            raise ValueError("Timestamp cannot be None")
        if not isinstance(ts, (int, float)):
            raise ValueError(f"Timestamp must be numeric, got {type(ts)}")
        # Sanity check: timestamps should be reasonable (after 2000, before 2100)
        if ts < 946684800 or ts > 4102444800:
            raise ValueError(f"Timestamp {ts} out of valid range")
        return datetime.fromtimestamp(ts, tz=timezone.utc)

    @staticmethod
    def detect_log_type(filename: str) -> str:
        """
        Detect Zeek log type from filename.

        Args:
            filename: Name of the log file (e.g., 'conn.log.json', 'http.log')

        Returns:
            Log type identifier (e.g., 'conn', 'http')

        Raises:
            ValueError: If log type cannot be determined
        """
        # Strip common suffixes
        name = filename.replace(".json", "").replace(".log", "")

        # Extract base log type
        for log_type in ZeekParser.LOG_TYPE_MODELS.keys():
            if log_type in name:
                return log_type

        raise ValueError(f"Unable to determine log type from filename: {filename}")

    @staticmethod
    def parse_file(
        file_path: Union[str, Path],
        log_type: str = None,
        max_errors: int = 100
    ) -> Iterator[Union[ConnLog, DnsLog, HttpLog, SslLog, X509Log, FilesLog, NoticeLog, WeirdLog, DpdLog, SmtpLog]]:
        """
        Parse a Zeek JSON log file line-by-line (streaming).

        This method reads the file incrementally to handle large files (>100MB)
        without loading the entire file into memory.

        Args:
            file_path: Path to the Zeek JSON log file
            log_type: Log type identifier (auto-detected if None)
            max_errors: Maximum number of parsing errors before stopping

        Yields:
            Parsed Zeek log entries as Pydantic models

        Raises:
            FileNotFoundError: If file does not exist
            ValueError: If log type is invalid
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")

        # Auto-detect log type from filename if not provided
        if log_type is None:
            log_type = ZeekParser.detect_log_type(file_path.name)

        # Get the appropriate model for this log type
        if log_type not in ZeekParser.LOG_TYPE_MODELS:
            raise ValueError(f"Unsupported log type: {log_type}")

        model_class = ZeekParser.LOG_TYPE_MODELS[log_type]

        error_count = 0
        line_num = 0

        logger.info(f"Parsing Zeek {log_type} log: {file_path}")

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

                    # Normalize Zeek dot-notation keys (e.g. id.orig_h -> id_orig_h)
                    data = {k.replace(".", "_"): v for k, v in data.items()}

                    # Validate and create model instance
                    entry = model_class(**data)
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
            f"Completed parsing {file_path}: {line_num} lines, {error_count} errors"
        )

    @staticmethod
    def parse_line(line: str, log_type: str) -> Union[ConnLog, DnsLog, HttpLog, SslLog, X509Log, FilesLog, NoticeLog, WeirdLog, DpdLog, SmtpLog, None]:
        """
        Parse a single JSON line from a Zeek log.

        Args:
            line: JSON string containing a single log entry
            log_type: Type of log entry (conn, dns, http, etc.)

        Returns:
            Parsed Zeek log entry or None if parsing fails
        """
        if log_type not in ZeekParser.LOG_TYPE_MODELS:
            logger.error(f"Unsupported log type: {log_type}")
            return None

        model_class = ZeekParser.LOG_TYPE_MODELS[log_type]

        try:
            data = json.loads(line)
            data = {k.replace(".", "_"): v for k, v in data.items()}
            return model_class(**data)
        except Exception as e:
            logger.warning(f"Failed to parse line: {e}")
            return None

    @staticmethod
    def validate_log_entry(data: dict, log_type: str) -> bool:
        """
        Validate a Zeek log entry against its schema.

        Args:
            data: Dictionary containing log entry data
            log_type: Type of log entry

        Returns:
            True if valid, False otherwise
        """
        if log_type not in ZeekParser.LOG_TYPE_MODELS:
            return False

        model_class = ZeekParser.LOG_TYPE_MODELS[log_type]

        try:
            normalized = {k.replace(".", "_"): v for k, v in data.items()}
            model_class(**normalized)
            return True
        except Exception:
            return False
