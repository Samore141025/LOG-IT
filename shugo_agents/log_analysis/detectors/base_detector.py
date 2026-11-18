from __future__ import annotations

import hashlib
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from core.schemas import Event, Finding, FindingEntities, SeverityEnum, VerdictEnum
from shugo_agents.log_analysis.playbooks import get_remediation_playbook

logger = logging.getLogger(__name__)


class BaseDetector(ABC):
    """Abstract base class for all log analysis detectors."""

    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.enabled: bool = config.get("enabled", True)

    @abstractmethod
    def analyze(self, events: List[Event], baseline: Any) -> List[Finding]:
        """Analyze a collection of events and return detected findings."""
        pass

    def make_dedupe_key(
        self,
        rule_name: str,
        entity_key: str,
        time_bucket: Optional[str] = None,
        extra: Optional[str] = None,
    ) -> str:
        """Create a deterministic hash string for deduplicating identical findings."""
        raw = f"{self.name}:{rule_name}:{entity_key}:{time_bucket or 'global'}:{extra or ''}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def build_finding(
        self,
        rule: str,
        reasoning: str,
        verdict: VerdictEnum,
        severity: SeverityEnum,
        confidence: float,
        evidence_events: List[Event],
        dedupe_key: str,
        mitre_technique: Optional[str] = None,
        users: Optional[List[str]] = None,
        ips: Optional[List[str]] = None,
        hosts: Optional[List[str]] = None,
    ) -> Finding:
        """Construct a validated Finding object."""
        extracted_users = set(users or [])
        extracted_ips = set(ips or [])
        extracted_hosts = set(hosts or [])

        for ev in evidence_events:
            extracted_hosts.add(ev.host)
            u = ev.normalized.get("user")
            if u:
                extracted_users.add(str(u))
            ip = ev.normalized.get("source_ip")
            if ip:
                extracted_ips.add(str(ip))

        entities_dict = {
            "users": sorted(list(extracted_users)),
            "ips": sorted(list(extracted_ips)),
            "hosts": sorted(list(extracted_hosts)),
        }

        playbook = get_remediation_playbook(
            rule_name=rule,
            mitre_technique=mitre_technique,
            entities=entities_dict,
        )

        # Append actionable solutions to reasoning
        playbook_text = "\n".join(playbook)
        enhanced_reasoning = f"{reasoning}\n\n🛡️ Actionable Solutions & Remediation Playbook:\n{playbook_text}"

        return Finding(
            agent="log_analysis",
            verdict=verdict,
            severity=severity,
            confidence=max(0.0, min(1.0, confidence)),
            rule=rule,
            reasoning=enhanced_reasoning,
            evidence_event_ids=[ev.id for ev in evidence_events],
            mitre_technique=mitre_technique,
            entities=FindingEntities(
                users=entities_dict["users"],
                ips=entities_dict["ips"],
                hosts=entities_dict["hosts"],
            ),
            remediation=playbook,
            dedupe_key=dedupe_key,
            created_at=datetime.now(timezone.utc),
        )
