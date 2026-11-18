from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from core.schemas import Event, Finding, SeverityEnum, VerdictEnum
from shugo_agents.log_analysis.detectors.base_detector import BaseDetector

logger = logging.getLogger(__name__)


class BruteForceDetector(BaseDetector):
    """Detects brute force login attempts from IP or targeting specific users."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("brute_force", config)
        self.failure_threshold: int = config.get("failure_threshold", 5)
        self.window_seconds: int = config.get("window_seconds", 300)
        self.escalate_on_success: bool = config.get("escalate_on_success", True)

    def analyze(self, events: List[Event], baseline: Any = None) -> List[Finding]:
        if not self.enabled:
            return []

        findings: List[Finding] = []

        # Filter for login events
        login_events = [
            e for e in events
            if e.event_type in ("ssh_failed_login", "ssh_success_login", "windows_failed_login", "windows_success_login")
        ]

        if not login_events:
            return []

        # Sort chronologically
        login_events.sort(key=lambda x: x.timestamp)

        # Group by IP
        ip_events: Dict[str, List[Event]] = defaultdict(list)
        # Group by User
        user_events: Dict[str, List[Event]] = defaultdict(list)

        for ev in login_events:
            ip = ev.normalized.get("source_ip")
            if ip and ip != "-" and ip != "127.0.0.1" and ip != "::1":
                ip_events[ip].append(ev)
            user = ev.normalized.get("user")
            if user:
                user_events[user].append(ev)

        # 1. Analyze by IP
        for ip, ev_list in ip_events.items():
            failed_in_window: List[Event] = []
            success_after_failure: List[Event] = []

            for ev in ev_list:
                is_failed = ev.event_type in ("ssh_failed_login", "windows_failed_login")
                is_success = ev.event_type in ("ssh_success_login", "windows_success_login")

                if is_failed:
                    # Clean out events older than sliding window
                    failed_in_window = [
                        e for e in failed_in_window
                        if (ev.timestamp - e.timestamp).total_seconds() <= self.window_seconds
                    ]
                    failed_in_window.append(ev)
                elif is_success:
                    if len(failed_in_window) >= self.failure_threshold:
                        # Success occurred after threshold failures in window
                        time_since_last_fail = (ev.timestamp - failed_in_window[-1].timestamp).total_seconds()
                        if 0 <= time_since_last_fail <= self.window_seconds:
                            success_after_failure.append(ev)

            if len(failed_in_window) >= self.failure_threshold:
                # Determine time bucket for deduplication (1-hour bucket)
                time_bucket = failed_in_window[0].timestamp.strftime("%Y%m%d%H")
                has_compromise = len(success_after_failure) > 0 and self.escalate_on_success

                if has_compromise:
                    severity = SeverityEnum.CRITICAL
                    verdict = VerdictEnum.MALICIOUS
                    confidence = 0.95
                    all_evidence = failed_in_window + success_after_failure
                    success_user = success_after_failure[0].normalized.get("user")
                    reasoning = (
                        f"Brute force compromise detected from IP {ip}: {len(failed_in_window)} failed logins "
                        f"within {self.window_seconds}s followed by successful login as user '{success_user}'."
                    )
                    rule_name = "brute_force_compromise"
                else:
                    severity = SeverityEnum.HIGH if len(failed_in_window) >= self.failure_threshold * 2 else SeverityEnum.MEDIUM
                    verdict = VerdictEnum.SUSPICIOUS
                    confidence = 0.85
                    all_evidence = failed_in_window
                    reasoning = (
                        f"Brute force login attempts detected from IP {ip}: {len(failed_in_window)} failed logins "
                        f"within {self.window_seconds}s."
                    )
                    rule_name = "brute_force_ip"

                dedupe_key = self.make_dedupe_key(rule_name, f"ip:{ip}", time_bucket)
                findings.append(
                    self.build_finding(
                        rule=f"T1110.001 - {rule_name}",
                        reasoning=reasoning,
                        verdict=verdict,
                        severity=severity,
                        confidence=confidence,
                        evidence_events=all_evidence,
                        dedupe_key=dedupe_key,
                        mitre_technique="T1110.001",
                        ips=[ip],
                    )
                )

        # 2. Analyze by User (Targeted Brute Force against single user account)
        for user, ev_list in user_events.items():
            failed_in_window = []
            for ev in ev_list:
                if ev.event_type in ("ssh_failed_login", "windows_failed_login"):
                    failed_in_window = [
                        e for e in failed_in_window
                        if (ev.timestamp - e.timestamp).total_seconds() <= self.window_seconds
                    ]
                    failed_in_window.append(ev)

            if len(failed_in_window) >= self.failure_threshold:
                time_bucket = failed_in_window[0].timestamp.strftime("%Y%m%d%H")
                dedupe_key = self.make_dedupe_key("brute_force_user", f"user:{user}", time_bucket)
                # Avoid duplicate if already covered by single IP with same evidence
                ips_involved = {e.normalized.get("source_ip") for e in failed_in_window if e.normalized.get("source_ip")}
                if len(ips_involved) > 1:  # Distributed against one account
                    findings.append(
                        self.build_finding(
                            rule="T1110.001 - targeted_account_brute_force",
                            reasoning=(
                                f"Targeted brute force against user '{user}': {len(failed_in_window)} failed logins "
                                f"within {self.window_seconds}s from {len(ips_involved)} distinct IPs."
                            ),
                            verdict=VerdictEnum.SUSPICIOUS,
                            severity=SeverityEnum.HIGH,
                            confidence=0.88,
                            evidence_events=failed_in_window,
                            dedupe_key=dedupe_key,
                            mitre_technique="T1110.001",
                            users=[user],
                        )
                    )

        return findings
