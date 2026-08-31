"""
SIH26145 - Zeek Log Tailer Module
Provides real-time non-blocking streaming ingestion of Zeek JSON logs (conn.log, dns.log, ssl.log)
with automatic schema normalization into Pydantic models.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, Union

from .models import (
    ConnTelemetryEvent,
    DnsTelemetryEvent,
    SslTelemetryEvent,
)

logger = logging.getLogger("zeek_log_tailer")


def normalize_zeek_record(
    log_type: str,
    raw_record: Dict[str, Any],
) -> Union[ConnTelemetryEvent, DnsTelemetryEvent, SslTelemetryEvent, Dict[str, Any]]:
    """
    Transforms raw Zeek JSON dict to its corresponding validated Pydantic model.
    """
    clean_type = log_type.lower().strip()
    if clean_type in ("conn", "conn.log"):
        return ConnTelemetryEvent.from_zeek_dict(raw_record)
    elif clean_type in ("dns", "dns.log"):
        return DnsTelemetryEvent.from_zeek_dict(raw_record)
    elif clean_type in ("ssl", "ssl.log"):
        return SslTelemetryEvent.from_zeek_dict(raw_record)
    return raw_record


class ZeekLogTailer:
    """
    High-performance real-time tailer for Zeek structured JSON logs.
    Supports non-blocking line reading, file rollover detection, and batch streaming.
    """

    def __init__(
        self,
        log_file_path: Union[str, Path],
        from_beginning: bool = True,
        poll_interval: float = 0.05,
        log_type: Optional[str] = None,
    ):
        """
        :param log_file_path: Path to the Zeek log file (e.g. conn.log, dns.log, ssl.log)
        :param from_beginning: If True, read all existing lines before tailing; if False, seek to EOF
        :param poll_interval: Sleep interval in seconds when no new lines are available
        :param log_type: Optional explicit log type ('conn', 'dns', 'ssl')
        """
        self.log_file_path = Path(log_file_path)
        self.from_beginning = from_beginning
        self.poll_interval = poll_interval
        self._stop_requested = False
        self._current_file = None
        self._current_inode = None
        self._last_position = 0

        # Infer log type if not provided
        if log_type:
            self.log_type = log_type.lower()
        else:
            name = self.log_file_path.stem.lower()
            if "conn" in name:
                self.log_type = "conn"
            elif "dns" in name:
                self.log_type = "dns"
            elif "ssl" in name:
                self.log_type = "ssl"
            else:
                self.log_type = "generic"

    def stop(self) -> None:
        """Signal the tailer loop to terminate."""
        self._stop_requested = True
        if self._current_file and not self._current_file.closed:
            try:
                self._current_file.close()
            except Exception:
                pass

    def _open_file(self) -> bool:
        """Open or reopen the target log file, tracking file descriptor and inode."""
        if not self.log_file_path.exists():
            return False

        try:
            stat_info = self.log_file_path.stat()
            self._current_file = open(self.log_file_path, "r", encoding="utf-8", errors="replace")
            self._current_inode = stat_info.st_ino

            if not self.from_beginning:
                self._current_file.seek(0, os.SEEK_END)
                self._last_position = self._current_file.tell()
            else:
                self._last_position = 0
            return True
        except Exception as e:
            logger.warning(f"Failed to open log file {self.log_file_path}: {e}")
            return False

    def _check_rotation_or_truncation(self) -> None:
        """Detect if the file has been rotated or truncated."""
        if not self.log_file_path.exists():
            return

        try:
            stat_info = self.log_file_path.stat()
            # If inode changed or file size is smaller than current pointer, file was rotated/truncated
            if (stat_info.st_ino != self._current_inode) or (stat_info.st_size < self._last_position):
                logger.info(f"Log rotation detected on {self.log_file_path}. Reopening file.")
                if self._current_file and not self._current_file.closed:
                    self._current_file.close()
                self._current_file = open(self.log_file_path, "r", encoding="utf-8", errors="replace")
                self._current_inode = stat_info.st_ino
                self._last_position = 0
        except Exception as e:
            logger.warning(f"Error checking file stat for {self.log_file_path}: {e}")

    def tail(
        self,
        normalize: bool = False,
    ) -> Generator[Union[Dict[str, Any], ConnTelemetryEvent, DnsTelemetryEvent, SslTelemetryEvent], None, None]:
        """
        Generator yielding parsed JSON dictionaries (or normalized Pydantic models) from the log stream.
        """
        while not self._stop_requested and self._current_file is None:
            if not self._open_file():
                time.sleep(self.poll_interval)

        while not self._stop_requested:
            if self._current_file is None:
                if not self._open_file():
                    time.sleep(self.poll_interval)
                    continue

            self._check_rotation_or_truncation()

            line = self._current_file.readline()
            if line:
                self._last_position = self._current_file.tell()
                line_str = line.strip()
                if not line_str or line_str.startswith("#"):
                    continue

                try:
                    record = json.loads(line_str)
                    record["_tail_ts"] = time.time()
                    if normalize and self.log_type in ("conn", "dns", "ssl"):
                        yield normalize_zeek_record(self.log_type, record)
                    else:
                        yield record
                except json.JSONDecodeError as err:
                    logger.debug(f"Malformed JSON line skipped: {line_str[:100]} ({err})")
                    continue
            else:
                # No new line available, sleep briefly
                time.sleep(self.poll_interval)

    def read_all_available(self, max_batch: int = 1000) -> List[Dict[str, Any]]:
        """
        Read all currently available lines in batch up to max_batch records as raw dictionaries.
        """
        if self._current_file is None:
            if not self._open_file():
                return []

        self._check_rotation_or_truncation()

        records = []
        for _ in range(max_batch):
            line = self._current_file.readline()
            if not line:
                break
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue
            try:
                rec = json.loads(line_str)
                rec["_tail_ts"] = time.time()
                records.append(rec)
            except json.JSONDecodeError:
                continue

        self._last_position = self._current_file.tell()
        return records

    def read_normalized_batch(
        self,
        max_batch: int = 1000,
    ) -> List[Union[ConnTelemetryEvent, DnsTelemetryEvent, SslTelemetryEvent, Dict[str, Any]]]:
        """
        Read all currently available lines and return normalized Pydantic model instances.
        """
        raw_records = self.read_all_available(max_batch=max_batch)
        return [normalize_zeek_record(self.log_type, r) for r in raw_records]


class MultiZeekLogTailer:
    """
    Orchestrates simultaneous tailing of conn.log, dns.log, and ssl.log from a directory.
    """

    def __init__(self, log_dir: Union[str, Path], from_beginning: bool = True):
        self.log_dir = Path(log_dir)
        self.from_beginning = from_beginning
        self.tailers: Dict[str, ZeekLogTailer] = {
            "conn": ZeekLogTailer(str(self.log_dir / "conn.log"), from_beginning=from_beginning, log_type="conn"),
            "dns": ZeekLogTailer(str(self.log_dir / "dns.log"), from_beginning=from_beginning, log_type="dns"),
            "ssl": ZeekLogTailer(str(self.log_dir / "ssl.log"), from_beginning=from_beginning, log_type="ssl"),
        }

    def stop_all(self) -> None:
        """Stop all active tailers."""
        for tailer in self.tailers.values():
            tailer.stop()

    def get_tailer(self, log_type: str) -> Optional[ZeekLogTailer]:
        """Retrieve tailer instance for specific log type."""
        return self.tailers.get(log_type)

    def read_all_available(self, max_batch: int = 1000) -> Dict[str, List[Dict[str, Any]]]:
        """Read available raw records from all tailers."""
        results = {}
        for ltype, tailer in self.tailers.items():
            results[ltype] = tailer.read_all_available(max_batch=max_batch)
        return results

    def read_normalized_all(
        self,
        max_batch: int = 1000,
    ) -> Dict[str, List[Union[ConnTelemetryEvent, DnsTelemetryEvent, SslTelemetryEvent, Dict[str, Any]]]]:
        """Read and normalize available records across all tailers."""
        results = {}
        for ltype, tailer in self.tailers.items():
            results[ltype] = tailer.read_normalized_batch(max_batch=max_batch)
        return results
