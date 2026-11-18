"""Sigma-compatible Detection-as-Code engine.

Loads standard YAML detection rules from rules/sigma/ and evaluates
them against log event streams.
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from core.schemas import Event, Finding, SeverityEnum, VerdictEnum
from shugo_agents.log_analysis.detectors.base_detector import BaseDetector

logger = logging.getLogger(__name__)


class SigmaRule:
    """Represents a parsed Sigma detection rule."""

    def __init__(self, rule_path: Path, raw_dict: Dict[str, Any]):
        self.path = rule_path
        self.title: str = raw_dict.get("title", rule_path.stem)
        self.id: str = raw_dict.get("id", rule_path.stem)
        self.status: str = raw_dict.get("status", "experimental")
        self.description: str = raw_dict.get("description", "")
        self.level: str = raw_dict.get("level", "medium").lower()
        
        # Tags for MITRE techniques
        self.tags: List[str] = raw_dict.get("tags", [])
        self.mitre_technique: Optional[str] = None
        for tag in self.tags:
            if tag.lower().startswith("attack.t"):
                self.mitre_technique = tag.split(".", 1)[1].upper()
                break

        # Detection logic
        self.detection: Dict[str, Any] = raw_dict.get("detection", {})
        self.condition: str = str(self.detection.get("condition", "selection"))

    def matches(self, event: Event) -> bool:
        """Evaluate if an event satisfies the Sigma selection criteria."""
        norm = event.normalized or {}
        raw_text = event.raw or ""

        # Check selection dictionaries
        for sel_key, sel_val in self.detection.items():
            if sel_key == "condition":
                continue

            if isinstance(sel_val, dict):
                # Field-specific matching
                for field_name, criteria in sel_val.items():
                    val = str(norm.get(field_name, "")).lower()
                    if field_name == "command" and not val:
                        val = str(norm.get("process", "")).lower()

                    if isinstance(criteria, list):
                        # Any match
                        if not any(str(c).lower() in val or str(c).lower() in raw_text.lower() for c in criteria):
                            return False
                    elif isinstance(criteria, str):
                        if criteria.lower() not in val and criteria.lower() not in raw_text.lower():
                            return False
            elif isinstance(sel_val, list):
                # Keyword matching across raw text
                if not any(str(k).lower() in raw_text.lower() for k in sel_val):
                    return False

        return True


class SigmaEngineDetector(BaseDetector):
    """Executes community and organization Sigma rules against log streams."""

    def __init__(self, config: Dict[str, Any] | None = None):
        cfg = config or {}
        super().__init__("sigma_engine", cfg)
        self.rules_dir = Path(cfg.get("rules_dir", "rules/sigma"))
        self.rules: List[SigmaRule] = []
        self._load_rules()

    def _load_rules(self) -> None:
        self.rules.clear()
        if not self.rules_dir.is_dir():
            self.rules_dir.mkdir(parents=True, exist_ok=True)
            return

        for p in self.rules_dir.glob("*.yml"):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if isinstance(data, dict):
                        self.rules.append(SigmaRule(p, data))
            except Exception as e:
                logger.warning(f"Failed to load Sigma rule {p.name}: {e}")

        logger.info(f"Loaded {len(self.rules)} Sigma detection rules from {self.rules_dir}")

    def analyze(self, events: List[Event], baseline: Any) -> List[Finding]:
        findings: List[Finding] = []
        if not self.rules or not events:
            return findings

        for rule in self.rules:
            matched_events: List[Event] = []
            for ev in events:
                if rule.matches(ev):
                    matched_events.append(ev)

            if matched_events:
                # Map level to SeverityEnum
                sev_map = {
                    "critical": SeverityEnum.CRITICAL,
                    "high": SeverityEnum.HIGH,
                    "medium": SeverityEnum.MEDIUM,
                    "low": SeverityEnum.LOW,
                }
                sev = sev_map.get(rule.level, SeverityEnum.MEDIUM)
                verdict = VerdictEnum.MALICIOUS if sev in (SeverityEnum.HIGH, SeverityEnum.CRITICAL) else VerdictEnum.SUSPICIOUS

                dedupe = self.make_dedupe_key(
                    rule_name=f"sigma_{rule.id}",
                    entity_key=matched_events[0].host,
                    time_bucket=matched_events[0].timestamp.strftime("%Y-%m-%d-%H"),
                )

                finding = self.build_finding(
                    rule=f"sigma_{rule.id}",
                    reasoning=(
                        f"Sigma Rule Detected: '{rule.title}'. {rule.description}. "
                        f"Triggered by {len(matched_events)} matching security event(s)."
                    ),
                    verdict=verdict,
                    severity=sev,
                    confidence=0.88,
                    evidence_events=matched_events[:10],
                    dedupe_key=dedupe,
                    mitre_technique=rule.mitre_technique,
                )
                findings.append(finding)

        return findings
