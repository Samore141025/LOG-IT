from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import Any, Dict, List, Tuple
from urllib.parse import unquote

from core.schemas import Event, Finding, SeverityEnum, VerdictEnum
from shugo_agents.log_analysis.detectors.base_detector import BaseDetector

logger = logging.getLogger(__name__)

# Attack regex signatures
SQLI_PATTERNS = [
    re.compile(r"(\%27)|(\')|(\-\-)|(\%23)|(#)", re.IGNORECASE),
    re.compile(r"\b(?:union\s+(?:all\s+)?select|select\s+.*\s+from|insert\s+into|waitfor\s+delay|sleep\(\d+\)|benchmark\(\d+,)\b", re.IGNORECASE),
    re.compile(r"(?:\bor\b|\band\b)\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+", re.IGNORECASE),
]

XSS_PATTERNS = [
    re.compile(r"<script.*?>.*?</script>", re.IGNORECASE),
    re.compile(r"javascript:\s*[^\s]+", re.IGNORECASE),
    re.compile(r"<\s*(?:img|svg|body|iframe|input)\s+[^>]*onerror\s*=", re.IGNORECASE),
    re.compile(r"<\s*(?:img|svg|body|iframe|input)\s+[^>]*onload\s*=", re.IGNORECASE),
]

PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f)", re.IGNORECASE),
    re.compile(r"(?:/etc/passwd|/etc/shadow|c:\\boot\.ini|windows[/\\]system32|win\.ini)", re.IGNORECASE),
]

SCANNER_UA_PATTERN = re.compile(
    r"\b(?:sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|acunetix|nuclei|nessus|arachni|zgrab)\b",
    re.IGNORECASE,
)


class WebAttacksDetector(BaseDetector):
    """Detects web application attacks: SQLi, XSS, Path Traversal, Scanner UAs, and HTTP error bursts."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("web_attacks", config)
        self.error_burst_threshold: int = config.get("error_burst_threshold", 15)
        self.error_burst_window_seconds: int = config.get("error_burst_window_seconds", 60)

    def analyze(self, events: List[Event], baseline: Any = None) -> List[Finding]:
        if not self.enabled:
            return []

        findings: List[Finding] = []

        web_events = [e for e in events if e.event_type == "http_request"]
        if not web_events:
            return []

        # Sort chronologically
        web_events.sort(key=lambda x: x.timestamp)

        ip_error_events: Dict[str, List[Event]] = defaultdict(list)

        for ev in web_events:
            ip = ev.normalized.get("source_ip") or "unknown"
            uri = ev.normalized.get("http_uri") or ""
            ua = ev.normalized.get("user_agent") or ""
            status = ev.normalized.get("http_status") or 200

            # Decode URI twice to catch double URL encoding
            decoded_uri = unquote(unquote(uri))
            full_req_str = f"{decoded_uri} {ua}"

            # 1. Scanner User-Agent Check
            if ua and SCANNER_UA_PATTERN.search(ua):
                time_bucket = ev.timestamp.strftime("%Y%m%d%H")
                dedupe_key = self.make_dedupe_key("scanner_ua", f"ip:{ip}", time_bucket)
                findings.append(
                    self.build_finding(
                        rule="T1595.002 - vulnerability_scanner_user_agent",
                        reasoning=f"Automated vulnerability scanner User-Agent detected from IP {ip}: '{ua}'.",
                        verdict=VerdictEnum.SUSPICIOUS,
                        severity=SeverityEnum.MEDIUM,
                        confidence=0.90,
                        evidence_events=[ev],
                        dedupe_key=dedupe_key,
                        mitre_technique="T1595.002",
                        ips=[ip],
                    )
                )

            # 2. SQL Injection Check
            sqli_matched = any(p.search(decoded_uri) for p in SQLI_PATTERNS[1:])
            if sqli_matched:
                time_bucket = ev.timestamp.strftime("%Y%m%d%H")
                dedupe_key = self.make_dedupe_key("sqli_payload", f"ip:{ip}", time_bucket, extra=decoded_uri[:60])
                findings.append(
                    self.build_finding(
                        rule="T1190 - sql_injection_attempt",
                        reasoning=f"SQL Injection payload pattern detected in HTTP request from {ip}: '{decoded_uri[:150]}'.",
                        verdict=VerdictEnum.MALICIOUS,
                        severity=SeverityEnum.HIGH,
                        confidence=0.92,
                        evidence_events=[ev],
                        dedupe_key=dedupe_key,
                        mitre_technique="T1190",
                        ips=[ip],
                    )
                )

            # 3. Cross-Site Scripting (XSS) Check
            if any(p.search(decoded_uri) for p in XSS_PATTERNS):
                time_bucket = ev.timestamp.strftime("%Y%m%d%H")
                dedupe_key = self.make_dedupe_key("xss_payload", f"ip:{ip}", time_bucket, extra=decoded_uri[:60])
                findings.append(
                    self.build_finding(
                        rule="T1190 - cross_site_scripting_attempt",
                        reasoning=f"Cross-Site Scripting (XSS) payload detected in HTTP request from {ip}: '{decoded_uri[:150]}'.",
                        verdict=VerdictEnum.SUSPICIOUS,
                        severity=SeverityEnum.MEDIUM,
                        confidence=0.88,
                        evidence_events=[ev],
                        dedupe_key=dedupe_key,
                        mitre_technique="T1190",
                        ips=[ip],
                    )
                )

            # 4. Path Traversal Check
            if any(p.search(decoded_uri) for p in PATH_TRAVERSAL_PATTERNS):
                time_bucket = ev.timestamp.strftime("%Y%m%d%H")
                dedupe_key = self.make_dedupe_key("path_traversal", f"ip:{ip}", time_bucket, extra=decoded_uri[:60])
                findings.append(
                    self.build_finding(
                        rule="T1190 - path_traversal_lfi_attempt",
                        reasoning=f"Directory traversal / LFI attempt detected in HTTP request from {ip}: '{decoded_uri[:150]}'.",
                        verdict=VerdictEnum.SUSPICIOUS,
                        severity=SeverityEnum.HIGH,
                        confidence=0.91,
                        evidence_events=[ev],
                        dedupe_key=dedupe_key,
                        mitre_technique="T1190",
                        ips=[ip],
                    )
                )

            # Track HTTP errors (403, 404, 500) for burst scanning detection
            if status in (400, 401, 403, 404, 500):
                ip_error_events[ip].append(ev)

        # 5. Analyze Error Bursts
        for ip, err_list in ip_error_events.items():
            if ip in ("unknown", "127.0.0.1", "::1"):
                continue

            window_errs: List[Event] = []
            for ev in err_list:
                window_errs = [
                    e for e in window_errs
                    if (ev.timestamp - e.timestamp).total_seconds() <= self.error_burst_window_seconds
                ]
                window_errs.append(ev)

                if len(window_errs) >= self.error_burst_threshold:
                    time_bucket = window_errs[0].timestamp.strftime("%Y%m%d%H")
                    dedupe_key = self.make_dedupe_key("http_error_burst", f"ip:{ip}", time_bucket)
                    findings.append(
                        self.build_finding(
                            rule="T1595 - http_error_burst_scanning",
                            reasoning=(
                                f"Anomalous burst of HTTP error responses ({len(window_errs)} errors) "
                                f"elicited by IP {ip} within {self.error_burst_window_seconds}s (indicates web brute-force/directory fuzzing)."
                            ),
                            verdict=VerdictEnum.SUSPICIOUS,
                            severity=SeverityEnum.MEDIUM,
                            confidence=0.85,
                            evidence_events=window_errs,
                            dedupe_key=dedupe_key,
                            mitre_technique="T1595",
                            ips=[ip],
                        )
                    )
                    break

        return findings
