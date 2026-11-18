from __future__ import annotations

import logging
from typing import Any, Dict, List, Set

from core.schemas import Event, Finding, SeverityEnum, VerdictEnum
from shugo_agents.log_analysis.detectors.base_detector import BaseDetector

logger = logging.getLogger(__name__)

DEFAULT_SENSITIVE_GROUPS = {"sudo", "admin", "wheel", "root", "Administrators", "Domain Admins"}


class PrivilegeEscalationDetector(BaseDetector):
    """Detects unauthorized privilege escalation attempts, group changes, and UID 0 accounts."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("privilege_escalation", config)
        self.sensitive_groups: Set[str] = set(
            config.get("sensitive_groups", list(DEFAULT_SENSITIVE_GROUPS))
        )

    def analyze(self, events: List[Event], baseline: Any = None) -> List[Finding]:
        if not self.enabled:
            return []

        findings: List[Finding] = []

        for ev in events:
            # 1. New UID 0 Account Creation
            if ev.event_type == "user_created":
                uid = ev.normalized.get("uid")
                user = ev.normalized.get("user")
                if uid == 0:
                    time_bucket = ev.timestamp.strftime("%Y%m%d%H")
                    dedupe_key = self.make_dedupe_key("new_uid_0_user", f"user:{user}", time_bucket)
                    findings.append(
                        self.build_finding(
                            rule="T1136.001 - new_root_uid_user_created",
                            reasoning=f"New user account '{user}' was created with root privileges (UID 0).",
                            verdict=VerdictEnum.MALICIOUS,
                            severity=SeverityEnum.CRITICAL,
                            confidence=0.98,
                            evidence_events=[ev],
                            dedupe_key=dedupe_key,
                            mitre_technique="T1136.001",
                            users=[user] if user else [],
                        )
                    )

            # 2. User added to administrative / sudo group
            elif ev.event_type == "user_group_added":
                group = ev.normalized.get("group")
                user = ev.normalized.get("user")
                if group and group in self.sensitive_groups:
                    time_bucket = ev.timestamp.strftime("%Y%m%d%H")
                    dedupe_key = self.make_dedupe_key(
                        "admin_group_addition",
                        f"user:{user}:group:{group}",
                        time_bucket
                    )
                    findings.append(
                        self.build_finding(
                            rule="T1098 - user_added_to_privileged_group",
                            reasoning=f"User '{user}' was added to privileged security group '{group}'.",
                            verdict=VerdictEnum.SUSPICIOUS,
                            severity=SeverityEnum.HIGH,
                            confidence=0.90,
                            evidence_events=[ev],
                            dedupe_key=dedupe_key,
                            mitre_technique="T1098",
                            users=[user] if user else [],
                        )
                    )

            # 3. Sudo / su usage by user who never used it
            elif ev.event_type == "sudo_command":
                user = ev.normalized.get("user")
                cmd = ev.normalized.get("command")
                if user and baseline and baseline.is_user_baseline_mature(user):
                    known_sudo_users = baseline.get_known_sudo_users()
                    if known_sudo_users and user not in known_sudo_users:
                        time_bucket = ev.timestamp.strftime("%Y%m%d%H")
                        dedupe_key = self.make_dedupe_key(
                            "first_time_sudo",
                            f"user:{user}",
                            time_bucket
                        )
                        findings.append(
                            self.build_finding(
                                rule="T1548.003 - anomalous_sudo_execution",
                                reasoning=(
                                    f"User '{user}' executed a sudo command ('{cmd}') for the first time. "
                                    f"User has no prior history of sudo usage in the baseline."
                                ),
                                verdict=VerdictEnum.SUSPICIOUS,
                                severity=SeverityEnum.MEDIUM,
                                confidence=0.82,
                                evidence_events=[ev],
                                dedupe_key=dedupe_key,
                                mitre_technique="T1548.003",
                                users=[user],
                            )
                        )

        return findings
