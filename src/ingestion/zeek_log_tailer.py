"""
SIH26145 - Zeek Log Tailer Module
Provides real-time non-blocking streaming ingestion of Zeek JSON logs (conn.log, dns.log, ssl.log).
"""

import os
import time
import json
import logging
from typing import Generator, Dict, Any, Optional, List, Callable
from pathlib import Path

logger = logging.getLogger("zeek_log_tailer")


class ZeekLogTailer:
    """
    High-performance real-time tailer for Zeek structured JSON logs.
    Supports non-blocking line reading, file rollover detection, and batch streaming.
    """

    def __init__(
        self,
        log_file_path: str,
        from_beginning: bool = True,
        poll_interval: float = 0.05,
    ):
        """
        :param log_file_path: Path to the Zeek log file (e.g. conn.log, dns.log, ssl.log)
        :param from_beginning: If True, read all existing lines before tailing; if False, seek to EOF
        :param poll_interval: Sleep interval in seconds when no new lines are available
        """
        self.log_file_path = Path(log_file_path)
        self.from_beginning = from_beginning
        self.poll_interval = poll_interval
        self._stop_requested = False
        self._current_file = None
        self._current_inode = None
        self._last_position = 0

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

    def tail(self) -> Generator[Dict[str, Any], None, None]:
        """
        Generator yielding parsed JSON dictionaries from the log stream in real time.
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
                    # Enrich record with local tail ingestion timestamp
                    record["_tail_ts"] = time.time()
                    yield record
                except json.JSONDecodeError as err:
                    logger.debug(f"Malformed JSON line skipped: {line_str[:100]} ({err})")
                    continue
            else:
                # No new line available, sleep briefly
                time.sleep(self.poll_interval)

    def read_all_available(self, max_batch: int = 1000) -> List[Dict[str, Any]]:
        """
        Read all currently available lines in batch up to max_batch records.
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


class MultiZeekLogTailer:
    """
    Orchestrates simultaneous tailing of conn.log, dns.log, and ssl.log from a directory.
    """

    def __init__(self, log_dir: str, from_beginning: bool = True):
        self.log_dir = Path(log_dir)
        self.from_beginning = from_beginning
        self.tailers: Dict[str, ZeekLogTailer] = {
            "conn": ZeekLogTailer(str(self.log_dir / "conn.log"), from_beginning=from_beginning),
            "dns": ZeekLogTailer(str(self.log_dir / "dns.log"), from_beginning=from_beginning),
            "ssl": ZeekLogTailer(str(self.log_dir / "ssl.log"), from_beginning=from_beginning),
        }

    def stop_all(self) -> None:
        """Stop all active tailers."""
        for tailer in self.tailers.values():
            tailer.stop()

    def get_tailer(self, log_type: str) -> Optional[ZeekLogTailer]:
        """Retrieve tailer instance for specific log type."""
        return self.tailers.get(log_type)
