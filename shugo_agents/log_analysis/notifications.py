"""SOC Notifications dispatcher module.

Dispatches real-time incident alert cards to Slack, Microsoft Teams, Discord,
and generic SIEM/SOAR webhooks.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SOCNotifier:
    """Multi-channel incident notification dispatcher for SOC and IT teams."""

    def __init__(
        self,
        slack_webhook: Optional[str] = None,
        discord_webhook: Optional[str] = None,
        teams_webhook: Optional[str] = None,
        generic_webhook: Optional[str] = None,
    ):
        self.slack_webhook = slack_webhook or os.getenv("SLACK_WEBHOOK_URL")
        self.discord_webhook = discord_webhook or os.getenv("DISCORD_WEBHOOK_URL")
        self.teams_webhook = teams_webhook or os.getenv("TEAMS_WEBHOOK_URL")
        self.generic_webhook = generic_webhook or os.getenv("GENERIC_WEBHOOK_URL")

    def is_configured(self) -> bool:
        """Return True if at least one webhook endpoint is configured."""
        return bool(
            self.slack_webhook
            or self.discord_webhook
            or self.teams_webhook
            or self.generic_webhook
        )

    def dispatch_alert(self, finding_data: Dict[str, Any]) -> None:
        """Asynchronously dispatch an alert across all active channels."""
        if not self.is_configured():
            return

        thread = threading.Thread(
            target=self._send_all,
            args=(finding_data,),
            daemon=True,
        )
        thread.start()

    def _send_all(self, finding: Dict[str, Any]) -> None:
        rule = finding.get("rule", "Unknown Rule")
        severity = str(finding.get("severity", "MEDIUM")).upper()
        verdict = str(finding.get("verdict", "SUSPICIOUS")).upper()
        mitre = finding.get("mitre_technique", "N/A")
        reasoning = finding.get("reasoning", "")[:300]
        entities = finding.get("entities", {})
        ips = ", ".join(entities.get("ips", [])) or "None identified"
        users = ", ".join(entities.get("users", [])) or "None identified"
        hosts = ", ".join(entities.get("hosts", [])) or "Host System"

        # 1. Slack Webhook
        if self.slack_webhook:
            payload = {
                "text": f"🚨 *[LOG-IT ALERT] {severity} Threat Detected: {rule}*",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*🚨 THREAT DETECTED: {rule}*\n*Severity:* `{severity}` | *Verdict:* `{verdict}` | *MITRE:* `{mitre}`",
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Target Hosts:*\n{hosts}"},
                            {"type": "mrkdwn", "text": f"*Attacker IPs:*\n{ips}"},
                            {"type": "mrkdwn", "text": f"*Target Users:*\n{users}"},
                        ],
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"*Analysis:*\n{reasoning}..."},
                    },
                ],
            }
            self._post_json(self.slack_webhook, payload)

        # 2. Discord Webhook
        if self.discord_webhook:
            color = 0xEF4444 if severity == "CRITICAL" else 0xF97316 if severity == "HIGH" else 0xEAB308
            payload = {
                "username": "LOG-IT Sentinel",
                "embeds": [
                    {
                        "title": f"🚨 Threat Detected: {rule}",
                        "color": color,
                        "description": f"**Verdict:** {verdict} | **Severity:** {severity}\n**MITRE ATT&CK:** {mitre}\n\n{reasoning}...",
                        "fields": [
                            {"name": "Attacker IPs", "value": ips, "inline": True},
                            {"name": "Target Accounts", "value": users, "inline": True},
                            {"name": "Hosts", "value": hosts, "inline": True},
                        ],
                        "footer": {"text": "LOG-IT Autonomous Incident Response"},
                    }
                ],
            }
            self._post_json(self.discord_webhook, payload)

        # 3. Teams Webhook
        if self.teams_webhook:
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": "EF4444" if severity == "CRITICAL" else "F97316",
                "summary": f"Security Alert: {rule}",
                "sections": [
                    {
                        "activityTitle": f"🚨 [LOG-IT] {severity} Alert: {rule}",
                        "activitySubtitle": f"MITRE Technique: {mitre}",
                        "facts": [
                            {"name": "Attacker IP", "value": ips},
                            {"name": "User", "value": users},
                            {"name": "Host", "value": hosts},
                        ],
                        "text": reasoning,
                    }
                ],
            }
            self._post_json(self.teams_webhook, payload)

        # 4. Generic Webhook
        if self.generic_webhook:
            self._post_json(self.generic_webhook, finding)

    def _post_json(self, url: str, data: Dict[str, Any]) -> bool:
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(data).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "LOG-IT-Notifier/1.0"},
            )
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                return resp.status in (200, 201, 204)
        except Exception as e:
            logger.debug(f"Webhook dispatch failed: {e}")
            return False

    def test_alert(self) -> Dict[str, Any]:
        """Send a test security notification to verify webhook configuration."""
        test_finding = {
            "rule": "LOGIT_TEST_ALERT",
            "severity": "HIGH",
            "verdict": "SUSPICIOUS",
            "mitre_technique": "T1110.001",
            "reasoning": "This is a test notification generated by LOG-IT to verify webhook connectivity.",
            "entities": {
                "ips": ["198.51.100.23"],
                "users": ["test_admin"],
                "hosts": ["soc-sentinel-01"],
            },
        }
        self.dispatch_alert(test_finding)
        return {
            "status": "DISPATCHED",
            "channels_configured": {
                "slack": bool(self.slack_webhook),
                "discord": bool(self.discord_webhook),
                "teams": bool(self.teams_webhook),
                "generic": bool(self.generic_webhook),
            },
        }
