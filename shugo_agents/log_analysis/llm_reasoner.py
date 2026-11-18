from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from uuid import UUID

from core.config import GeminiConfig, RedactionConfig
from core.llm import GeminiClient
from core.schemas import Event, Finding, LLMTriageOutput, SeverityEnum, VerdictEnum

logger = logging.getLogger(__name__)

PASSWORD_RE = re.compile(r"(?:password|passwd|pwd|token|api[_-]?key|secret|cookie)\s*[:=]\s*([^\s,;&\"']+)", re.IGNORECASE)
BEARER_RE = re.compile(r"Bearer\s+([A-Za-z0-9\-\._~\+\/]+=*)", re.IGNORECASE)


class Redactor:
    """Masks or hashes sensitive fields before sending log lines to external LLM APIs."""

    def __init__(self, config: RedactionConfig):
        self.config = config

    def redact_text(self, text: str) -> str:
        if not text:
            return ""

        redacted = text
        if self.config.mask_tokens:
            redacted = re.sub(
                r"(?:token\s*[:=]\s*)?Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*",
                "token: Bearer [REDACTED_TOKEN]",
                redacted,
                flags=re.IGNORECASE,
            )
            redacted = BEARER_RE.sub("Bearer [REDACTED_TOKEN]", redacted)

        if self.config.mask_passwords:
            redacted = re.sub(
                r"((?:password|passwd|pwd|api[_-]?key|secret|cookie)\s*[:=]\s*)([^\s,;&\"']+)",
                r"\1[REDACTED]",
                redacted,
                flags=re.IGNORECASE,
            )

        if self.config.hash_internal_ips:
            for prefix in self.config.internal_ip_prefixes:
                # Hash private IPs matching prefix
                ip_pattern = re.compile(rf"\b({re.escape(prefix)}\d{{1,3}}\.\d{{1,3}})\b")
                redacted = ip_pattern.sub(
                    lambda m: f"ip_hash_{hashlib.sha256(m.group(1).encode()).hexdigest()[:8]}",
                    redacted,
                )

        return redacted


class RateLimiter:
    """Sliding-window rate limiter for LLM requests (enforces RPM and RPD)."""

    def __init__(self, rpm: int = 15, rpd: int = 1500):
        self.rpm = rpm
        self.rpd = rpd
        self._minute_timestamps: deque[float] = deque()
        self._day_timestamps: deque[float] = deque()

    def allow(self) -> bool:
        now = time.time()

        # Clean timestamps older than 60 seconds
        while self._minute_timestamps and now - self._minute_timestamps[0] > 60.0:
            self._minute_timestamps.popleft()

        # Clean timestamps older than 86400 seconds (24 hours)
        while self._day_timestamps and now - self._day_timestamps[0] > 86400.0:
            self._day_timestamps.popleft()

        if len(self._minute_timestamps) >= self.rpm:
            logger.warning(f"LLM reasoner hit RPM limit ({self.rpm}/min). Skipping LLM triage.")
            return False

        if len(self._day_timestamps) >= self.rpd:
            logger.warning(f"LLM reasoner hit RPD limit ({self.rpd}/day). Skipping LLM triage.")
            return False

        self._minute_timestamps.append(now)
        self._day_timestamps.append(now)
        return True


class LLMReasoner:
    """Triage and summary reasoning layer powered by Google Gemini with strict guardrails."""

    def __init__(
        self,
        gemini_config: GeminiConfig,
        redaction_config: RedactionConfig,
        prompt_path: Optional[str | Path] = None,
    ):
        self.client = GeminiClient(gemini_config)
        self.redactor = Redactor(redaction_config)
        self.rate_limiter = RateLimiter(
            rpm=gemini_config.rate_limit_rpm,
            rpd=gemini_config.rate_limit_rpd,
        )
        self._prompt_template = self._load_prompt(prompt_path)
        self._cache: Dict[str, Finding] = {}

    def _load_prompt(self, prompt_path: Optional[str | Path]) -> str:
        p = Path(prompt_path) if prompt_path else Path(__file__).parent / "prompts" / "triage.md"
        if p.is_file():
            return p.read_text(encoding="utf-8")
        logger.warning(f"Prompt file not found at {p}. Using fallback triage prompt.")
        return (
            "Evaluate evidence for rule '{rule_name}'. Initial verdict: {initial_severity}.\n"
            "<evidence_log_data>\n{evidence_block}\n</evidence_log_data>"
        )

    def should_triage(self, finding: Finding) -> bool:
        """Determine if a finding qualifies for LLM evaluation."""
        if not self.client.is_available():
            return False

        # Triage ambiguous clusters (confidence between 0.60 and 0.85) or high/critical findings
        is_ambiguous = 0.60 <= finding.confidence <= 0.85
        is_high_or_critical = finding.severity in (SeverityEnum.HIGH, SeverityEnum.CRITICAL)

        return is_ambiguous or is_high_or_critical

    def triage_finding(self, finding: Finding, evidence_events: List[Event]) -> Finding:
        """Run LLM triage on finding with fallback to rule-based finding on failure."""
        if not self.should_triage(finding):
            return finding

        # Check in-memory cache
        if finding.dedupe_key in self._cache:
            return self._cache[finding.dedupe_key]

        if not self.rate_limiter.allow():
            return finding

        valid_ids: Set[str] = {str(ev.id) for ev in evidence_events}
        evidence_lines = []
        for ev in evidence_events:
            redacted_raw = self.redactor.redact_text(ev.raw)
            evidence_lines.append(
                f"[EventID: {ev.id}] Timestamp: {ev.timestamp.isoformat()} Host: {ev.host} "
                f"Type: {ev.event_type} | Raw: {redacted_raw}"
            )
        evidence_block = "\n".join(evidence_lines)

        prompt = self._prompt_template.format(
            rule_name=finding.rule,
            initial_severity=finding.severity.value,
            initial_confidence=finding.confidence,
            rule_summary=finding.reasoning,
            evidence_block=evidence_block,
        )

        try:
            triage_result = self.client.generate_json(prompt, schema=LLMTriageOutput)
            if not triage_result:
                # Fallback to original finding
                return finding

            # Validate that referenced evidence IDs actually exist
            grounded_ids = [
                UUID(eid) for eid in triage_result.validated_evidence_ids
                if eid in valid_ids
            ]
            if not grounded_ids:
                # Retain original evidence IDs if model omitted or fabricated
                grounded_ids = finding.evidence_event_ids

            # Guardrail: The LLM cannot upgrade a verdict that rules did not support without evidence
            new_verdict = triage_result.verdict
            if finding.verdict == VerdictEnum.BENIGN and new_verdict == VerdictEnum.MALICIOUS:
                new_verdict = VerdictEnum.SUSPICIOUS

            # Adjust confidence
            adjusted_confidence = min(triage_result.confidence, finding.confidence + 0.1)

            # Append Gemini's recommended actions to remediation list
            updated_remediation = list(finding.remediation or [])
            if triage_result.recommended_actions:
                for action in triage_result.recommended_actions:
                    if action not in updated_remediation:
                        updated_remediation.append(f"[AI Recommendation] {action}")

            actions_block = ""
            if triage_result.recommended_actions:
                actions_block = "\n[AI Tailored Containment Actions]:\n" + "\n".join(
                    f"  • {action}" for action in triage_result.recommended_actions
                )

            updated_reasoning = (
                f"{finding.reasoning}\n\n[LLM Triage Reasoning]: {triage_result.reasoning}\n"
                f"[Benign/FP Hypothesis]: {triage_result.false_positive_hypothesis}"
                f"{actions_block}"
            )

            updated_finding = finding.model_copy(
                update={
                    "verdict": new_verdict,
                    "confidence": adjusted_confidence,
                    "reasoning": updated_reasoning,
                    "evidence_event_ids": grounded_ids,
                    "remediation": updated_remediation,
                }
            )

            self._cache[finding.dedupe_key] = updated_finding
            return updated_finding

        except Exception as e:
            logger.warning(f"LLM triage execution failed: {e}. Falling back to rule-based finding.")
            return finding
