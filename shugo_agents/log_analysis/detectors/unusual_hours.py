from __future__ import annotations

import logging
from typing import Any, Dict, List, Set

from core.schemas import Event, Finding, SeverityEnum, VerdictEnum
from shugo_agents.log_analysis.detectors.base_detector import BaseDetector

logger = logging.getLogger(__name__)


class UnusualHoursDetector(BaseDetector):
    """Detects user logins occurring outside the user's learned baseline active hours."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("unusual_hours", config)

    def analyze(self, events: List[Event], baseline: Any = None) -> List[Finding]:
        if not self.enabled or baseline is None:
            return []

        findings: List[Finding] = []

        success_logins = [
            e for e in events
            if e.event_type in ("ssh_success_login", "windows_success_login")
        ]

        for ev in success_logins:
            user = ev.normalized.get("user")
            if not user or user in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
                continue

            # Check if user baseline has matured
            if not baseline.is_user_baseline_mature(user):
                continue

            active_hours = baseline.get_user_active_hours(user)
            if not active_hours:
                continue

            event_hour = ev.timestamp.hour
            if event_hour not in active_hours:
                time_bucket = ev.timestamp.strftime("%Y%m%d%H")
                dedupe_key = self.make_dedupe_key(
                    "unusual_login_hours",
                    f"user:{user}",
                    time_bucket,
                    extra=f"hour:{event_hour}"
                )

                sorted_hours = sorted(list(active_hours))
                hours_str = ", ".join(f"{h:02d}:00" for h in sorted_hours)
                reasoning = (
                    f"User '{user}' logged in at an unusual hour ({event_hour:02d}:00 UTC). "
                    f"Learned baseline active hours for this user are: [{hours_str}]."
                )

                finding = self.build_finding(
                    rule="T1078 - unusual_login_hours",
                    reasoning=reasoning,
                    verdict=VerdictEnum.SUSPICIOUS,
                    severity=SeverityEnum.MEDIUM,
                    confidence=0.75,
                    evidence_events=[ev],
                    dedupe_key=dedupe_key,
                    mitre_technique="T1078",
                    users=[user],
                )
                findings.append(finding)

        return findings
