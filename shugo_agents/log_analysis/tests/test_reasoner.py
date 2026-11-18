from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock
import pytest

from core.config import GeminiConfig, RedactionConfig
from core.schemas import Event, Finding, FindingEntities, LLMTriageOutput, SeverityEnum, VerdictEnum
from shugo_agents.log_analysis.llm_reasoner import LLMReasoner, RateLimiter, Redactor


def test_redactor_masks_passwords_and_tokens():
    cfg = RedactionConfig(mask_passwords=True, mask_tokens=True, hash_internal_ips=True)
    redactor = Redactor(cfg)

    sample = "User login failed: password=SuperSecret123! token: Bearer eyJhbGciOiJIUz... host: 192.168.1.50"
    redacted = redactor.redact_text(sample)

    assert "SuperSecret123!" not in redacted
    assert "password=[REDACTED]" in redacted
    assert "eyJhbGciOiJIUz" not in redacted
    assert "Bearer [REDACTED_TOKEN]" in redacted
    assert "192.168.1.50" not in redacted
    assert "ip_hash_" in redacted


def test_rate_limiter_enforcement():
    limiter = RateLimiter(rpm=2, rpd=10)
    assert limiter.allow() is True
    assert limiter.allow() is True
    # Third request in same minute should be rejected
    assert limiter.allow() is False


def test_llm_reasoner_validation_and_grounding():
    gemini_cfg = GeminiConfig(api_key="mock_key")
    redaction_cfg = RedactionConfig()
    reasoner = LLMReasoner(gemini_cfg, redaction_cfg)

    ev_id = uuid.uuid4()
    ev = Event(
        id=ev_id,
        source="auth",
        host="web01",
        timestamp=datetime.now(timezone.utc),
        event_type="ssh_failed_login",
        raw="Failed password for root from 1.2.3.4",
        normalized={"source_ip": "1.2.3.4"},
    )

    initial_finding = Finding(
        agent="log_analysis",
        verdict=VerdictEnum.SUSPICIOUS,
        severity=SeverityEnum.MEDIUM,
        confidence=0.75,
        rule="T1110 - brute_force",
        reasoning="Multiple failed attempts",
        evidence_event_ids=[ev_id],
        dedupe_key="dedupe-key-123",
        entities=FindingEntities(ips=["1.2.3.4"]),
    )

    # Mock Gemini Client returning hallucinated ID alongside real ID
    fake_id = str(uuid.uuid4())
    mock_triage_output = LLMTriageOutput(
        verdict=VerdictEnum.SUSPICIOUS,
        confidence=0.80,
        reasoning="Consistent with external automated scan.",
        false_positive_hypothesis="Security scan by external vendor.",
        validated_evidence_ids=[str(ev_id), fake_id],  # Includes hallucinated fake_id
    )

    reasoner.client.is_available = MagicMock(return_value=True)
    reasoner.client.generate_json = MagicMock(return_value=mock_triage_output)

    triaged = reasoner.triage_finding(initial_finding, [ev])

    # Verified: hallucinated fake_id was stripped, only valid ev_id retained
    assert ev_id in triaged.evidence_event_ids
    assert uuid.UUID(fake_id) not in triaged.evidence_event_ids
    assert "LLM Triage Reasoning" in triaged.reasoning
    assert triaged.confidence == 0.80
