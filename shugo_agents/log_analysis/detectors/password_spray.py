from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Set

from core.schemas import Event, Finding, SeverityEnum, VerdictEnum
from shugo_agents.log_analysis.detectors.base_detector import BaseDetector

logger = logging.getLogger(__name__)


class PasswordSprayDetector(BaseDetector):
    """Detects password spraying: single IP failing authentication against many distinct usernames."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("password_spray", config)
        self.distinct_user_threshold: int = config.get("distinct_user_threshold", 4)
        self.window_seconds: int = config.get("window_seconds", 600)

    def analyze(self, events: List[Event], baseline: Any = None) -> List[Finding]:
        if not self.enabled:
            return []

        findings: List[Finding] = []

        failed_logins = [
            e for e in events
            if e.event_type in ("ssh_failed_login", "windows_failed_login")
        ]

        if not failed_logins:
            return []

        failed_logins.sort(key=lambda x: x.timestamp)

        # Group by Source IP
        ip_groups: Dict[str, List[Event]] = defaultdict(list)
        for ev in failed_logins:
            ip = ev.normalized.get("source_ip")
            if ip and ip not in ("-", "127.0.0.1", "::1"):
                ip_groups[ip].append(ev)

        for ip, ev_list in ip_groups.items():
            window_events: List[Event] = []
            distinct_users: Set[str] = set()

            for ev in ev_list:
                # Slide window
                window_events = [
                    e for e in window_events
                    if (ev.timestamp - e.timestamp).total_seconds() <= self.window_seconds
                ]
                window_events.append(ev)

                # Count distinct usernames in current window
                current_users: set[str] = {
                    str(e.normalized.get("user"))
                    for e in window_events
                    if e.normalized.get("user")
                }

                if len(current_users) >= self.distinct_user_threshold:
                    time_bucket = window_events[0].timestamp.strftime("%Y%m%d%H")
                    dedupe_key = self.make_dedupe_key(
                        "password_spray",
                        f"ip:{ip}",
                        time_bucket,
                        extra=f"users:{len(current_users)}"
                    )

                    users_str = ", ".join(sorted(list(current_users))[:8])
                    finding = self.build_finding(
                        rule="T1110.003 - password_spray_detected",
                        reasoning=(
                            f"Password spraying detected from IP {ip}: attempted logins against "
                            f"{len(current_users)} distinct users ({users_str}) within {self.window_seconds}s."
                        ),
                        verdict=VerdictEnum.SUSPICIOUS,
                        severity=SeverityEnum.HIGH,
                        confidence=0.90,
                        evidence_events=window_events,
                        dedupe_key=dedupe_key,
                        mitre_technique="T1110.003",
                        ips=[ip],
                        users=list(current_users),
                    )
                    findings.append(finding)
                    break  # One finding per window for this IP

        return findings
