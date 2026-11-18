from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Tuple

from core.schemas import Event, Finding, SeverityEnum, VerdictEnum
from shugo_agents.log_analysis.detectors.base_detector import BaseDetector

logger = logging.getLogger(__name__)

# Precompiled detection regex patterns: (pattern, subrule, description, mitre, severity)
SUSPICIOUS_COMMAND_PATTERNS: List[Tuple[re.Pattern, str, str, str, SeverityEnum]] = [
    # Reverse shells
    (
        re.compile(r"bash\s+-i\s+>&?\s*/dev/tcp/\d+", re.IGNORECASE),
        "reverse_shell_bash_tcp",
        "Interactive bash reverse shell redirection via /dev/tcp",
        "T1059.004",
        SeverityEnum.CRITICAL,
    ),
    (
        re.compile(r"(?:nc|ncat|netcat)(?:\.traditional)?\s+.*-e\s+(?:/bin/(?:ba)?sh|cmd\.exe|powershell)", re.IGNORECASE),
        "reverse_shell_netcat",
        "Netcat reverse shell with executable invocation (-e)",
        "T1059.004",
        SeverityEnum.CRITICAL,
    ),
    (
        re.compile(r"mkfifo\s+[^\s;]+\s*;\s*nc\s+", re.IGNORECASE),
        "reverse_shell_fifo",
        "Named pipe (mkfifo) FIFO reverse shell via netcat",
        "T1059.004",
        SeverityEnum.CRITICAL,
    ),
    (
        re.compile(r"socat\s+exec:.*pty", re.IGNORECASE),
        "reverse_shell_socat",
        "Socat pseudo-terminal reverse shell",
        "T1059.004",
        SeverityEnum.CRITICAL,
    ),
    # Download and pipe to shell (curl|sh, wget|sh)
    (
        re.compile(r"(?:curl|wget|fetch)\s+[^\n|;]+\|\s*(?:ba)?sh", re.IGNORECASE),
        "download_pipe_shell",
        "Arbitrary script download directly piped to shell execution (curl|sh or wget|sh)",
        "T1059.004",
        SeverityEnum.HIGH,
    ),
    # Base64 decode and execute
    (
        re.compile(r"base64\s+(?:-d|--decode)\s*\|\s*(?:ba)?sh", re.IGNORECASE),
        "base64_decode_exec",
        "Base64-decoded string piped directly to shell interpreter",
        "T1059.004",
        SeverityEnum.HIGH,
    ),
    (
        re.compile(r"certutil(?:\.exe)?\s+.*-(?:f|split)?\s*-decode\s+", re.IGNORECASE),
        "certutil_decode_payload",
        "Windows CertUtil used to decode obfuscated binary payload",
        "T1140",
        SeverityEnum.HIGH,
    ),
    (
        re.compile(r"powershell(?:\.exe)?\s+.*(?:-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{15,}", re.IGNORECASE),
        "powershell_encoded_command",
        "PowerShell executed with encoded base64 command payload",
        "T1059.001",
        SeverityEnum.HIGH,
    ),
    # Credential Dumping
    (
        re.compile(r"\b(?:mimikatz|secretsdump|samdump2|pwdump)\b", re.IGNORECASE),
        "credential_dumping_tool",
        "Execution of known credential dumping utility",
        "T1003",
        SeverityEnum.CRITICAL,
    ),
    (
        re.compile(r"(?:cat|head|tail|grep|awk|strings)\s+[^\n;]*/etc/shadow\b", re.IGNORECASE),
        "shadow_file_access",
        "Direct attempt to read system password hash file (/etc/shadow)",
        "T1003.008",
        SeverityEnum.HIGH,
    ),
    (
        re.compile(r"rundll32(?:\.exe)?\s+.*comsvcs.*minidump", re.IGNORECASE),
        "comsvcs_lsass_dump",
        "LSASS process memory minidump via rundll32 and comsvcs.dll",
        "T1003.001",
        SeverityEnum.CRITICAL,
    ),
    (
        re.compile(r"procdump(?:\.exe)?\s+.*-ma\s+lsass", re.IGNORECASE),
        "procdump_lsass_dump",
        "LSASS memory dump using Sysinternals ProcDump",
        "T1003.001",
        SeverityEnum.CRITICAL,
    ),
]


class SuspiciousCommandsDetector(BaseDetector):
    """Detects dangerous commands including reverse shells, curl|sh, base64 exec, and credential dumping."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("suspicious_commands", config)

    def analyze(self, events: List[Event], baseline: Any = None) -> List[Finding]:
        if not self.enabled:
            return []

        findings: List[Finding] = []

        for ev in events:
            # Check command field from normalized or raw string
            cmd = ev.normalized.get("command") or ""
            raw = ev.raw or ""
            target_text = f"{cmd} {raw}"

            for pattern, subrule, description, mitre, severity in SUSPICIOUS_COMMAND_PATTERNS:
                match = pattern.search(target_text)
                if match:
                    user = ev.normalized.get("user")
                    matched_snippet = match.group(0)[:100]
                    time_bucket = ev.timestamp.strftime("%Y%m%d%H")
                    dedupe_key = self.make_dedupe_key(
                        subrule,
                        f"host:{ev.host}:user:{user}",
                        time_bucket,
                        extra=matched_snippet
                    )

                    reasoning = (
                        f"Suspicious command execution detected: {description}. "
                        f"Matched pattern: '{matched_snippet}'. Host: {ev.host}, User: '{user or 'unknown'}'."
                    )

                    verdict = VerdictEnum.MALICIOUS if severity == SeverityEnum.CRITICAL else VerdictEnum.SUSPICIOUS

                    findings.append(
                        self.build_finding(
                            rule=f"{mitre} - {subrule}",
                            reasoning=reasoning,
                            verdict=verdict,
                            severity=severity,
                            confidence=0.95,
                            evidence_events=[ev],
                            dedupe_key=dedupe_key,
                            mitre_technique=mitre,
                            users=[user] if user else [],
                            hosts=[ev.host],
                        )
                    )
                    break  # One pattern match per event is sufficient

        return findings
