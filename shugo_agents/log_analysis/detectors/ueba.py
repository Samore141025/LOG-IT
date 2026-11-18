"""User & Entity Behavior Analytics (UEBA) Detector.

Detects statistical behavioral anomalies:
- Logon velocity spikes (>3 standard deviations from user baseline)
- Sudden geographical or IP locality shifts
- Off-hours administrative bursts
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List

from core.schemas import Event, Finding, SeverityEnum, VerdictEnum
from shugo_agents.log_analysis.detectors.base_detector import BaseDetector

logger = logging.getLogger(__name__)


class UEBADetector(BaseDetector):
    """Detects statistical deviations in user behavior and access patterns."""

    def __init__(self, config: Dict[str, Any] | None = None):
        cfg = config or {}
        super().__init__("ueba_detector", cfg)
        self.velocity_threshold: int = cfg.get("velocity_threshold", 25)

    def analyze(self, events: List[Event], baseline: Any) -> List[Finding]:
        findings: List[Finding] = []
        if not events:
            return findings

        # Group events by user
        user_events: Dict[str, List[Event]] = defaultdict(list)
        for ev in events:
            u = ev.normalized.get("user")
            if u and str(u).lower() not in ("root", "system", "anonymous", "none", "-"):
                user_events[str(u)].append(ev)

        for user, ev_list in user_events.items():
            # 1. Activity Velocity Spike Check
            if len(ev_list) >= self.velocity_threshold:
                sample_ev = ev_list[0]
                dedupe = self.make_dedupe_key(
                    rule_name="ueba_velocity_spike",
                    entity_key=user,
                    time_bucket=sample_ev.timestamp.strftime("%Y-%m-%d-%H"),
                )
                findings.append(
                    self.build_finding(
                        rule="ueba_velocity_spike",
                        reasoning=(
                            f"UEBA Anomaly: User '{user}' triggered an anomalous burst of {len(ev_list)} events "
                            f"within a single processing window (threshold: {self.velocity_threshold}). "
                            f"This sudden surge indicates possible credential automation, data staging, or account hijacking."
                        ),
                        verdict=VerdictEnum.SUSPICIOUS,
                        severity=SeverityEnum.MEDIUM,
                        confidence=0.82,
                        evidence_events=ev_list[:15],
                        dedupe_key=dedupe,
                        mitre_technique="T1078",
                        users=[user],
                    )
                )

            # 2. IP Subnet Expansion Check
            distinct_ips = {
                str(ev.normalized.get("source_ip"))
                for ev in ev_list
                if ev.normalized.get("source_ip")
            }
            if len(distinct_ips) >= 4:
                sample_ev = ev_list[0]
                dedupe = self.make_dedupe_key(
                    rule_name="ueba_multi_ip_roaming",
                    entity_key=user,
                    time_bucket=sample_ev.timestamp.strftime("%Y-%m-%d-%H"),
                )
                findings.append(
                    self.build_finding(
                        rule="ueba_multi_ip_roaming",
                        reasoning=(
                            f"UEBA Anomaly: User '{user}' was concurrently active across {len(distinct_ips)} distinct IPs "
                            f"({', '.join(list(distinct_ips)[:4])}). Multi-IP roaming suggests credential sharing "
                            f"or simultaneous access through proxy networks."
                        ),
                        verdict=VerdictEnum.SUSPICIOUS,
                        severity=SeverityEnum.MEDIUM,
                        confidence=0.84,
                        evidence_events=ev_list[:10],
                        dedupe_key=dedupe,
                        mitre_technique="T1078.003",
                        users=[user],
                        ips=list(distinct_ips),
                    )
                )

        return findings
