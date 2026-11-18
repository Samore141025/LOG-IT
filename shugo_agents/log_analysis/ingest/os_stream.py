"""Live Operating System Event Stream Ingestion.

Directly collects live Windows Security/System events and Linux journald/syslog
streams in real time.
"""
from __future__ import annotations

import json
import logging
import platform
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional

from core.schemas import Event
from shugo_agents.log_analysis.ingest.parsers import auto_parse_log_line, parse_windows_event_json

logger = logging.getLogger(__name__)


class LiveOSStreamCollector:
    """Collects real-time security events directly from Windows or Linux operating systems."""

    def __init__(self, max_batch: int = 50):
        self.os_type = platform.system().lower()
        self.max_batch = max_batch
        self.last_win_record_id: Optional[int] = None
        self.last_linux_ts: Optional[str] = None

    def poll_new_events(self) -> List[Event]:
        """Poll the host OS for newly generated security events."""
        if self.os_type == "windows":
            return self._poll_windows_security_events()
        elif self.os_type == "linux":
            return self._poll_linux_journal()
        return []

    def _poll_windows_security_events(self) -> List[Event]:
        """Query recent Windows Security events (4624, 4625, 4688, 4720, 1102)."""
        events: List[Event] = []
        try:
            # Query recent security events in JSON format via PowerShell
            ps_script = (
                f"$events = Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4624,4625,4688,4720,1102}} "
                f"-MaxEvents {self.max_batch} -ErrorAction SilentlyContinue; "
                f"if ($events) {{ "
                f"  $events | ForEach-Object {{ "
                f"    @{{ "
                f"      Id = $_.Id; "
                f"      RecordId = $_.RecordId; "
                f"      TimeCreated = $_.TimeCreated.ToString('o'); "
                f"      Message = $_.Message; "
                f"      MachineName = $_.MachineName "
                f"    }} "
                f"  }} | ConvertTo-Json -Compress "
                f"}}"
            )
            cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=8.0, check=False)
            if res.returncode == 0 and res.stdout.strip():
                raw_json = res.stdout.strip()
                parsed = json.loads(raw_json)
                items = parsed if isinstance(parsed, list) else [parsed]
                
                for item in items:
                    rec_id = item.get("RecordId")
                    if self.last_win_record_id and rec_id and rec_id <= self.last_win_record_id:
                        continue
                    
                    ev = parse_windows_event_json(item, default_host=item.get("MachineName", platform.node()))
                    if ev:
                        events.append(ev)
                
                if items and items[0].get("RecordId"):
                    self.last_win_record_id = max([i.get("RecordId", 0) for i in items])
        except Exception as e:
            logger.debug(f"Windows Event polling skipped or unavailable: {e}")

        return events

    def _poll_linux_journal(self) -> List[Event]:
        """Query recent entries from systemd-journald."""
        events: List[Event] = []
        try:
            cmd = ["journalctl", "-u", "ssh", "-u", "sshd", "-n", str(self.max_batch), "--output=json", "--no-pager"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5.0, check=False)
            if res.returncode == 0 and res.stdout.strip():
                for line in res.stdout.strip().split("\n"):
                    if not line.strip():
                        continue
                    try:
                        entry = json.loads(line)
                        msg = entry.get("MESSAGE", "")
                        host = entry.get("_HOSTNAME", platform.node())
                        ev = auto_parse_log_line(msg, default_host=host, source_hint="journald")
                        if ev:
                            events.append(ev)
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f"Linux journalctl polling skipped: {e}")

        return events
