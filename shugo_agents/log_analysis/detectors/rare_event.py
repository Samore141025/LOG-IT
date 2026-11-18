from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, List

from core.schemas import Event, Finding, SeverityEnum, VerdictEnum
from shugo_agents.log_analysis.detectors.base_detector import BaseDetector

logger = logging.getLogger(__name__)


class RareEventDetector(BaseDetector):
    """Detects statistical anomalies versus learned baseline: event volume spikes and novel event types."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("rare_event", config)
        self.z_score_threshold: float = config.get("z_score_threshold", 3.0)
        self.mad_threshold: float = config.get("mad_threshold", 3.5)

    def analyze(self, events: List[Event], baseline: Any = None) -> List[Finding]:
        if not self.enabled or baseline is None:
            return []

        findings: List[Finding] = []

        # 1. Check for novel event types per entity
        for ev in events:
            user = ev.normalized.get("user")
            host = ev.host
            event_type = ev.event_type

            # Check novel event types for user
            if user and baseline.is_user_baseline_mature(user):
                known_types = baseline.get_user_known_event_types(user)
                if known_types and event_type not in known_types:
                    time_bucket = ev.timestamp.strftime("%Y%m%d%H")
                    dedupe_key = self.make_dedupe_key(
                        "novel_event_type_user",
                        f"user:{user}:type:{event_type}",
                        time_bucket
                    )
                    findings.append(
                        self.build_finding(
                            rule="T1087 - novel_event_type_for_user",
                            reasoning=(
                                f"User '{user}' produced event type '{event_type}' which was never observed "
                                f"during the baseline learning period."
                            ),
                            verdict=VerdictEnum.SUSPICIOUS,
                            severity=SeverityEnum.LOW,
                            confidence=0.70,
                            evidence_events=[ev],
                            dedupe_key=dedupe_key,
                            mitre_technique="T1087",
                            users=[user],
                        )
                    )

        # 2. Check for volume spikes (event rate anomaly) per host
        host_event_counts: Dict[str, List[Event]] = defaultdict(list)
        for ev in events:
            host_event_counts[ev.host].append(ev)

        for host, ev_list in host_event_counts.items():
            if not baseline.is_host_baseline_mature(host):
                continue

            current_count = len(ev_list)
            stats = baseline.get_host_event_rate_stats(host)
            if not stats:
                continue

            mean = stats.get("mean", 0.0)
            std = stats.get("std", 1.0)
            median = stats.get("median", mean)
            mad = stats.get("mad", std)

            # Robust MAD Score: |x - median| / (1.4826 * MAD)
            mad_denom = 1.4826 * mad if mad > 0 else 1.0
            robust_score = abs(current_count - median) / mad_denom

            # Z-Score: (x - mean) / std
            z_score = (current_count - mean) / (std if std > 0 else 1.0)

            if robust_score >= self.mad_threshold or z_score >= self.z_score_threshold:
                time_bucket = ev_list[0].timestamp.strftime("%Y%m%d%H")
                dedupe_key = self.make_dedupe_key(
                    "event_volume_spike",
                    f"host:{host}",
                    time_bucket
                )
                findings.append(
                    self.build_finding(
                        rule="T1499 - anomalous_event_volume_spike",
                        reasoning=(
                            f"Statistical anomaly in event volume on host '{host}': current batch volume is "
                            f"{current_count} events (baseline median={median:.1f}, MAD={mad:.1f}, "
                            f"robust score={robust_score:.2f}, z-score={z_score:.2f})."
                        ),
                        verdict=VerdictEnum.SUSPICIOUS,
                        severity=SeverityEnum.MEDIUM,
                        confidence=0.82,
                        evidence_events=ev_list[:10],  # Link first 10 events as evidence sample
                        dedupe_key=dedupe_key,
                        mitre_technique="T1499",
                        hosts=[host],
                    )
                )

        return findings
