"""Universal log ingester and directory watcher for SHUGO Log Analysis Agent.

Supports ingesting logs from any organization device or system:
- Linux servers (auth.log, syslog, audit.log, secure)
- Windows servers & domain controllers (EVTX-JSON)
- Web servers (Nginx, Apache, IIS)
- Firewalls & network appliances (Cisco, pfSense, Fortinet)
- Application and container JSON logs
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.db.models import EventModel
from core.db.session import DatabaseManager
from core.schemas import Event
from shugo_agents.log_analysis.ingest.parsers import (
    auto_parse_log_line,
    parse_auth_syslog_line,
    parse_web_log_line,
    parse_windows_event_json,
)

logger = logging.getLogger(__name__)

SUPPORTED_EXTENSIONS = {".log", ".txt", ".json", ".syslog", ".out"}


class LogTailer:
    """Tails real log files and directories, tracks byte offsets, and ingests into database."""

    def __init__(
        self,
        db_manager: DatabaseManager,
        watched_files: Optional[Dict[str, str]] = None,
        watched_directories: Optional[List[str]] = None,
        state_file_path: str = "tailer_state.json",
        batch_size: int = 200,
    ):
        self.db_manager = db_manager
        self.watched_files: Dict[str, str] = watched_files or {}
        self.watched_directories: List[str] = watched_directories or []
        self.state_file_path = Path(state_file_path)
        self.batch_size = batch_size
        self.offsets: Dict[str, Dict[str, Any]] = self._load_offsets()

    def _load_offsets(self) -> Dict[str, Dict[str, Any]]:
        if self.state_file_path.is_file():
            try:
                with open(self.state_file_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Could not load tailer state: {e}")
        return {}

    def _save_offsets(self) -> None:
        try:
            with open(self.state_file_path, "w", encoding="utf-8") as f:
                json.dump(self.offsets, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save tailer state: {e}")

    def tail_step(self) -> int:
        """Process new lines across all configured files and watched directories."""
        total_ingested = 0

        # 1. Discover any new log files in watched directories
        for dir_str in self.watched_directories:
            p = Path(dir_str)
            if not p.is_dir():
                try:
                    p.mkdir(parents=True, exist_ok=True)
                except Exception:
                    continue

            for file_path in p.rglob("*"):
                if file_path.is_file() and file_path.suffix.lower() in SUPPORTED_EXTENSIONS:
                    file_key = str(file_path.resolve())
                    if file_key not in self.watched_files:
                        self.watched_files[file_key] = "auto"

        # 2. Tail each discovered / configured file
        for file_path_str, parser_type in list(self.watched_files.items()):
            path = Path(file_path_str)
            if not path.is_file():
                continue

            try:
                # Derive default host name from file or directory name
                host_hint = path.stem.replace("_sample", "").replace("sample_", "")
                if host_hint in ("auth", "syslog"):
                    host_hint = path.parent.name if path.parent.name not in ("log", "samples") else "server-01"

                ingested = self._tail_file(path, parser_type, default_host=host_hint)
                total_ingested += ingested
            except Exception as e:
                logger.error(f"Error tailing file {file_path_str}: {e}", exc_info=True)

        if total_ingested > 0:
            self._save_offsets()

        return total_ingested

    def _tail_file(self, path: Path, parser_type: str, default_host: str = "generic-host") -> int:
        file_key = str(path.resolve())
        stat = path.stat()
        file_size = stat.st_size
        file_inode = getattr(stat, "st_ino", 0)

        file_state = self.offsets.get(file_key, {"offset": 0, "inode": file_inode})
        offset = file_state.get("offset", 0)
        last_inode = file_state.get("inode", file_inode)

        # Detect log rotation (inode changed or file truncated)
        if file_inode != last_inode or file_size < offset:
            logger.info(f"Log rotation detected for {path.name}. Resetting offset from {offset} to 0.")
            offset = 0

        if file_size == offset:
            return 0

        events_to_insert: List[Event] = []

        try:
            with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
                f.seek(offset)
                lines_read = 0

                while lines_read < self.batch_size:
                    line = f.readline()
                    if not line:
                        break

                    event = self._parse_line(line, parser_type, default_host=default_host, source_name=path.name)
                    if event:
                        events_to_insert.append(event)
                    lines_read += 1

                new_offset = f.tell()

            if events_to_insert:
                self._insert_events(events_to_insert)

            self.offsets[file_key] = {"offset": new_offset, "inode": file_inode}
            return len(events_to_insert)

        except Exception as e:
            logger.error(f"Failed while reading {path}: {e}", exc_info=True)
            return 0

    def _parse_line(self, line: str, parser_type: str, default_host: str, source_name: str) -> Optional[Event]:
        try:
            if parser_type == "auth_syslog":
                return parse_auth_syslog_line(line, default_host=default_host)
            elif parser_type == "web_access":
                return parse_web_log_line(line, default_host=default_host)
            elif parser_type == "windows_json":
                return parse_windows_event_json(line, default_host=default_host)
            else:
                return auto_parse_log_line(line, default_host=default_host, source_hint=source_name)
        except Exception as e:
            logger.warning(f"Failed to parse line: {line[:100]}... Error: {e}")
            return None

    def _insert_events(self, events: List[Event]) -> None:
        with self.db_manager.session() as session:
            for ev in events:
                model = EventModel(
                    id=ev.id,
                    source=ev.source,
                    host=ev.host,
                    timestamp=ev.timestamp,
                    event_type=ev.event_type,
                    raw=ev.raw,
                    normalized=ev.normalized,
                    processed_by=ev.processed_by,
                    created_at=ev.created_at,
                )
                session.add(model)

    def ingest_file(self, file_path: Path, parser_type: str = "auto") -> int:
        """Immediately ingest an entire log file from start to finish."""
        if not file_path.is_file():
            return 0

        host_hint = file_path.stem
        events_to_insert = []
        with open(file_path, "r", encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                if line.strip():
                    ev = self._parse_line(line, parser_type, default_host=host_hint, source_name=file_path.name)
                    if ev:
                        events_to_insert.append(ev)

        if events_to_insert:
            self._insert_events(events_to_insert)

        # Mark offset as at EOF
        self.offsets[str(file_path.resolve())] = {
            "offset": file_path.stat().st_size,
            "inode": getattr(file_path.stat(), "st_ino", 0),
        }
        self._save_offsets()
        return len(events_to_insert)
