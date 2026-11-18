"""Active Defense & Security Orchestration, Automation, and Response (SOAR) module.

Provides:
- execute_containment: Blocks malicious IP addresses on the local host firewall.
- rollback_containment: Removes firewall rules and unbans IP addresses.
- list_active_bans: Lists all currently active containment rules.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def is_safe_to_block(ip_str: str) -> bool:
    """Verify that the target is a valid external IP and not localhost or loopback."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        if ip.is_loopback or ip.is_reserved or ip.is_multicast:
            return False
        # Do not block standard RFC 1918 gateway/local addresses by default
        if ip_str.strip() in ("127.0.0.1", "::1", "0.0.0.0"):
            return False
        return True
    except ValueError:
        return False


class ActiveDefenseSOAR:
    """Automated security response engine for immediate attacker containment."""

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.active_bans: Dict[str, Dict[str, Any]] = {}

    def execute_containment(
        self,
        target_ip: str,
        reason: str = "Automated threat response",
        duration_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Execute host firewall containment against an attacker IP."""
        ip = target_ip.strip()
        if not is_safe_to_block(ip):
            return {
                "success": False,
                "ip": ip,
                "message": f"Containment rejected: {ip} is protected (localhost/reserved IP).",
            }

        rule_name = f"LOGIT-Block-{ip}"
        success = False
        command_used = ""
        error_msg = ""

        if self.dry_run:
            logger.info(f"[SOAR DRY-RUN] Would block {ip} at firewall.")
            success = True
            command_used = f"[DRY-RUN] Block {ip}"
        else:
            try:
                if sys.platform == "win32":
                    cmd = [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}",
                        "dir=in",
                        "action=block",
                        f"remoteip={ip}",
                    ]
                    command_used = " ".join(cmd)
                    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
                    if res.returncode == 0 or "Ok." in res.stdout:
                        success = True
                    else:
                        error_msg = res.stderr or res.stdout
                else:
                    cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                    command_used = " ".join(cmd)
                    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
                    if res.returncode == 0:
                        success = True
                    else:
                        error_msg = res.stderr or res.stdout
            except Exception as e:
                error_msg = str(e)

        ban_record = {
            "ip": ip,
            "rule_name": rule_name,
            "reason": reason,
            "blocked_at": time.time(),
            "expires_at": time.time() + duration_seconds if duration_seconds else None,
            "success": success,
            "command": command_used,
            "error": error_msg,
        }
        if success:
            self.active_bans[ip] = ban_record
            logger.info(f"[SOAR] Containment active: Blocked {ip} ({command_used})")

        return ban_record

    def rollback_containment(self, target_ip: str) -> Dict[str, Any]:
        """Remove containment rule and restore traffic for an IP."""
        ip = target_ip.strip()
        rule_name = f"LOGIT-Block-{ip}"
        success = False
        command_used = ""
        error_msg = ""

        if self.dry_run:
            success = True
            command_used = f"[DRY-RUN] Unblock {ip}"
        else:
            try:
                if sys.platform == "win32":
                    cmd = [
                        "netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={rule_name}",
                    ]
                    command_used = " ".join(cmd)
                    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
                    if res.returncode == 0 or "Deleted" in res.stdout or "Ok." in res.stdout:
                        success = True
                    else:
                        error_msg = res.stderr or res.stdout
                else:
                    cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
                    command_used = " ".join(cmd)
                    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
                    if res.returncode == 0:
                        success = True
                    else:
                        error_msg = res.stderr or res.stdout
            except Exception as e:
                error_msg = str(e)

        if ip in self.active_bans:
            del self.active_bans[ip]

        return {
            "success": success,
            "ip": ip,
            "command": command_used,
            "error": error_msg,
        }

    def list_active_bans(self) -> List[Dict[str, Any]]:
        """Return list of active firewall containment rules."""
        return list(self.active_bans.values())
