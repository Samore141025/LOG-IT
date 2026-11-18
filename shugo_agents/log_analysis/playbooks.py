"""Automated Incident Response & Remediation Playbooks for SHUGO.

Provides actionable, copy-pasteable containment, remediation, and hardening commands
for every MITRE ATT&CK technique and detection rule in the Log Analysis Agent.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


def get_remediation_playbook(
    rule_name: str,
    mitre_technique: Optional[str] = None,
    entities: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """Generate exact step-by-step remediation commands and recommendations."""
    entities = entities or {}
    ips: List[str] = entities.get("ips", [])
    users: List[str] = entities.get("users", [])
    hosts: List[str] = entities.get("hosts", [])

    primary_ip = ips[0] if ips else "<ATTACKER_IP>"
    primary_user = users[0] if users else "<TARGET_USER>"
    primary_host = hosts[0] if hosts else "<AFFECTED_HOST>"

    playbook: List[str] = []

    # 1. BRUTE FORCE / PASSWORD SPRAY (T1110)
    if "brute_force" in rule_name or "T1110" in (mitre_technique or "") or "spray" in rule_name:
        playbook.extend([
            f"[IMMEDIATE CONTAINMENT] Block attacker IP {primary_ip} at network and host firewall:",
            f"  • Linux iptables: sudo iptables -A INPUT -s {primary_ip} -j DROP",
            f"  • Linux ufw: sudo ufw deny from {primary_ip}",
            f"  • Windows Firewall: netsh advfirewall firewall add rule name=\"Block-{primary_ip}\" dir=in action=block remoteip={primary_ip}",
            f"[ACCOUNT REMEDIATION] Terminate active sessions and force password reset for user '{primary_user}':",
            f"  • Linux session kill: sudo pkill -u {primary_user} -9",
            f"  • Linux password reset: sudo passwd -l {primary_user} (lock) or sudo passwd {primary_user} (reset)",
            f"  • Windows lock: Disable-LocalUser -Name '{primary_user}' or Set-ADUser '{primary_user}' -Enabled $false",
            f"[SYSTEM HARDENING] Long-term protection against credential attacks:",
            "  • Disable SSH password authentication: set 'PasswordAuthentication no' in /etc/ssh/sshd_config",
            "  • Enforce Multi-Factor Authentication (MFA / Duo / Google Authenticator) for all remote logins",
            "  • Install and configure automated IP banning: sudo apt install fail2ban",
        ])

    # 2. SUSPICIOUS COMMANDS / REVERSE SHELLS (T1059.004)
    elif "reverse_shell" in rule_name or "T1059" in (mitre_technique or "") or "suspicious_command" in rule_name:
        playbook.extend([
            f"[CRITICAL CONTAINMENT] Immediately isolate host '{primary_host}' from the network:",
            "  • Linux disable network: sudo ip link set dev eth0 down",
            "  • Windows disable network: Disable-NetAdapter -Name 'Ethernet*' -Confirm:$false",
            f"[PROCESS TERMINATION] Identify and kill rogue command and reverse shell processes:",
            "  • Linux: ps aux | grep -E 'nc|bash|sh|python|socat' | grep -v grep",
            "  • Kill rogue PID: sudo kill -9 <PID>",
            "  • Windows: Get-Process | Where-Object {$_.CommandLine -match 'powershell|cmd|certutil'}",
            "[PERSISTENCE AUDITING] Inspect scheduled tasks and startup locations for backdoors:",
            "  • Linux crontabs: sudo crontab -l; sudo ls -la /etc/cron.* /var/spool/cron/crontabs",
            "  • Linux systemd services: sudo systemctl list-unit-files --state=enabled",
            "  • Check writable staging dirs: sudo ls -lat /tmp /dev/shm /var/tmp",
            "  • Windows persistence: Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'}",
            "[CREDENTIAL REVOCATION] Rotate all service account tokens and SSH authorized_keys present on this host.",
        ])

    # 3. WEB APPLICATION ATTACKS - SQLi / XSS / TRAVERSAL (T1190)
    elif "sql_injection" in rule_name or "xss" in rule_name or "path_traversal" in rule_name or "T1190" in (mitre_technique or ""):
        playbook.extend([
            f"[PERIMETER MITIGATION] Block source IP {primary_ip} on your Web Application Firewall (WAF) or Reverse Proxy:",
            f"  • Nginx block: add 'deny {primary_ip};' to /etc/nginx/conf.d/blocklist.conf and run 'nginx -s reload'",
            f"  • Apache block: Require not ip {primary_ip}",
            f"  • Cloudflare WAF: Add IP Access Rule to block {primary_ip}",
            "[CODE-LEVEL REMEDIATION] Patch vulnerable web application endpoints:",
            "  • SQL Injection: Replace raw SQL string concatenation with Parameterized Queries (Prepared Statements)",
            "  • XSS: Enforce Context-Aware Output HTML Encoding and configure Content-Security-Policy (CSP) headers",
            "  • Path Traversal: Canonicalize filenames with os.path.realpath() and disallow '..' path segments",
            "[DATABASE SECURITY] Enforce principle of least privilege for web application database accounts:",
            "  • Revoke administrative/SUPERUSER rights from web application DB users",
            "  • Disable database command execution functions (e.g. xp_cmdshell in MSSQL)",
        ])

    # 4. PRIVILEGE ESCALATION / BACKDOOR ROOT ACCOUNTS (T1136, T1098, T1548)
    elif "privilege_escalation" in rule_name or "uid_0" in rule_name or "group_added" in rule_name or "T1098" in (mitre_technique or ""):
        playbook.extend([
            f"[IMMEDIATE ACTION] Remove unauthorized user '{primary_user}' and revoke privileged access:",
            f"  • Linux remove user: sudo userdel -r {primary_user}",
            f"  • Linux remove from sudo group: sudo gpasswd -d {primary_user} sudo",
            f"  • Windows remove admin: Remove-LocalGroupMember -Group 'Administrators' -Member '{primary_user}'",
            "[SUDOERS AUDIT] Review and clean unauthorized sudo privileges:",
            "  • Inspect sudo configuration: sudo visudo -c",
            "  • Check files in /etc/sudoers.d/ for unauthorized 'NOPASSWD' rules",
            "[ACCOUNT AUDITING] Verify all accounts with UID 0 (root equivalent):",
            "  • Linux: awk -F: '($3 == 0) {print $1}' /etc/passwd (should ONLY be root)",
        ])

    # 5. CREDENTIAL DUMPING (T1003)
    elif "credential" in rule_name or "shadow" in rule_name or "T1003" in (mitre_technique or "") or "lsass" in rule_name:
        playbook.extend([
            "[CRITICAL ACTION] Assume ALL domain or system credentials on this host have been captured:",
            "  • Immediately initiate password reset for all administrator accounts and domain accounts logged into this host",
            "  • If Active Directory environment: perform a double reset of the Kerberos KRBTGT account password",
            "[LSASS & MEMORY HARDENING]:",
            "  • Windows: Enable LSA Protection by creating registry key: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL' = 1",
            "  • Windows: Enable Windows Defender Credential Guard via Group Policy",
            "  • Linux: Restrict /etc/shadow permissions: sudo chmod 640 /etc/shadow && sudo chown root:shadow /etc/shadow",
        ])

    # 6. LOG TAMPERING & ANTI-FORENSICS (T1070, T1562)
    elif "log_tampering" in rule_name or "log_cleared" in rule_name or "T1070" in (mitre_technique or ""):
        playbook.extend([
            f"[SERVICE RESTORATION] Restart and verify logging services on host '{primary_host}':",
            "  • Linux: sudo systemctl restart rsyslog auditd && sudo systemctl status rsyslog",
            "  • Windows: Start-Service -Name 'EventLog' -PassThru",
            "[INCIDENT RESPONSE PRESERVATION]:",
            "  • Do NOT reboot the host yet; capture a live volatile RAM memory dump for digital forensics",
            "  • Inspect bash history / PowerShell command history: history; cat ~/.bash_history",
            "[IMMUTABLE LOGGING ARCHITECTURE]:",
            "  • Forward all logs to an external, write-once SIEM or remote syslog server (e.g. rsyslog remote TLS forwarding)",
            "  • Configure file integrity monitoring (AIDE / Wazuh / Tripwire) on /var/log directories",
        ])

    # 7. DEFAULT GENERIC SECURITY PLAYBOOK
    else:
        playbook.extend([
            f"[CONTAINMENT] Verify connectivity and activity from source IP '{primary_ip}' and user '{primary_user}'.",
            f"[INVESTIGATION] Review all process and network connections around the incident timestamp on host '{primary_host}'.",
            "[MITIGATION] Block suspicious network traffic, isolate untrusted hosts, and enforce least-privilege access.",
        ])

    return playbook
