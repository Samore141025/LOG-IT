from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, List, Set

from core.schemas import Event, Finding, SeverityEnum, VerdictEnum
from shugo_agents.log_analysis.detectors.base_detector import BaseDetector

logger = logging.getLogger(__name__)

CRITICAL_LOGGING_SERVICES: Set[str] = {
    "auditd",
    "rsyslog",
    "rsyslogd",
    "syslog",
    "syslogd",
    "system logging service",
    "eventlog",
    "windows event log",
    "security log",
}


class LogTamperingDetector(BaseDetector):
    """Detects anti-forensics activity: cleared logs, stopped logging daemons, and unexpected log stream gaps."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("log_tampering", config)
        self.max_silent_gap_minutes: float = config.get("max_silent_gap_minutes", 60.0)

    def analyze(self, events: List[Event], baseline: Any = None) -> List[Finding]:
        if not self.enabled:
            return []

        findings: List[Finding] = []

        host_events: Dict[str, List[Event]] = defaultdict(list)

        for ev in events:
            host_events[ev.host].append(ev)

            # 1. Direct Log Cleared Event
            if ev.event_type == "log_cleared":
                time_bucket = ev.timestamp.strftime("%Y%m%d%H")
                dedupe_key = self.make_dedupe_key("log_cleared", f"host:{ev.host}", time_bucket)
                findings.append(
                    self.build_finding(
                        rule="T1070.001 - security_audit_log_cleared",
                        reasoning=(
                            f"Audit or event log cleared on host '{ev.host}'. "
                            f"Raw indicator: {ev.raw[:120]}"
                        ),
                        verdict=VerdictEnum.MALICIOUS,
                        severity=SeverityEnum.CRITICAL,
                        confidence=0.98,
                        evidence_events=[ev],
                        dedupe_key=dedupe_key,
                        mitre_technique="T1070.001",
                        hosts=[ev.host],
                    )
                )

            # 2. Critical Security Logging Service Stopped
            elif ev.event_type == "service_stopped":
                svc = (ev.normalized.get("service") or "").lower().strip()
                if any(target in svc for target in CRITICAL_LOGGING_SERVICES):
                    time_bucket = ev.timestamp.strftime("%Y%m%d%H")
                    dedupe_key = self.make_dedupe_key(
                        "logging_service_stopped",
                        f"host:{ev.host}:service:{svc}",
                        time_bucket
                    )
                    findings.append(
                        self.build_finding(
                            rule="T1562.001 - logging_service_disabled",
                            reasoning=f"Critical logging daemon or service '{svc}' was stopped on host '{ev.host}'.",
                            verdict=VerdictEnum.SUSPICIOUS,
                            severity=SeverityEnum.HIGH,
                            confidence=0.92,
                            evidence_events=[ev],
                            dedupe_key=dedupe_key,
                            mitre_technique="T1562.001",
                            hosts=[ev.host],
                        )
                    )

        # 3. Detect Unexpected Silent Gaps in Host Log Stream
        for host, ev_list in host_events.items():
            if len(ev_list) < 2:
                continue

            ev_list.sort(key=lambda x: x.timestamp)
            for i in range(len(ev_list) - 1):
                gap_minutes = (ev_list[i + 1].timestamp - ev_list[i].timestamp).total_seconds() / 60.0
                if gap_minutes >= self.max_silent_gap_minutes:
                    # Check with baseline if host is expected to be continuous
                    if baseline and not baseline.is_host_continuous(host):
                        continue

                    time_bucket = ev_list[i].timestamp.strftime("%Y%m%d")
                    dedupe_key = self.make_dedupe_key(
                        "unexpected_silent_gap",
                        f"host:{host}",
                        time_bucket,
                        extra=f"gap:{int(gap_minutes)}"
                    )
                    findings.append(
                        self.build_finding(
                            rule="T1070 - unexpected_log_stream_gap",
                            reasoning=(
                                f"Unexpected silent gap of {gap_minutes:.1f} minutes detected in log stream for host '{host}' "
                                f"between {ev_list[i].timestamp.isoformat()} and {ev_list[i + 1].timestamp.isoformat()}."
                            ),
                            verdict=VerdictEnum.SUSPICIOUS,
                            severity=SeverityEnum.MEDIUM,
                            confidence=0.80,
                            evidence_events=[ev_list[i], ev_list[i + 1]],
                            dedupe_key=dedupe_key,
                            mitre_technique="T1070",
                            hosts=[host],
                        )
                    )

        return findings
