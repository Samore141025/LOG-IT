# LOG-IT Sentinel: Enterprise Autonomous Log Analysis & Incident Response Engine

**LOG-IT** is an enterprise-grade, autonomous security operations and log analysis agent. It combines deterministic pattern detection, community Sigma rules, User & Entity Behavior Analytics (UEBA), and Google Gemini neural reasoning to analyze system and network logs in real time, block malicious actors, and produce compliance-ready forensic reports.

---

## 🚀 Key Highlights & Enterprise Architecture

1. **Native OS Event Streaming**: Collects live Windows Security/System events and Linux journald/syslog in real time.
2. **Active Defense SOAR**: Automated 1-click and policy-driven firewall containment (`netsh advfirewall`, `iptables`, `ufw`).
3. **Detection-as-Code (Sigma)**: Loads and evaluates standard YAML Sigma rules from `rules/sigma/`.
4. **Multi-Channel Alert Dispatch**: Real-time rich alert cards to Slack, Discord, Microsoft Teams, and generic webhooks.
5. **Threat Intelligence Enrichment**: Automated IP reputation scoring, bogon/private filtering, and AbuseIPDB integration.
6. **Network Syslog Server**: Built-in UDP/TCP listener on port 5140 accepting remote router, firewall, and server streams.
7. **Live Web SOC Dashboard**: Built-in browser-based operations portal at `http://localhost:8080` with 1-click ban actions.
8. **UEBA & Behavioral Baselines**: Detects access velocity spikes and multi-IP roaming across user accounts.
9. **Cryptographic Chain-of-Custody**: SHA-256 Merkle chain ledger ensuring audit trail tamper-evidence.
10. **MITRE ATT&CK & Compliance**: Continuous mapping to 14 ATT&CK tactics, PCI-DSS v4.0, SOC 2 Type II, ISO 27001, and HIPAA.

---

## 🛠️ Quick Installation & Setup

### 1. Prerequisites
- Python 3.10, 3.11, or 3.12
- Windows 10/11 / Windows Server or Linux (Ubuntu, Debian, RHEL)

### 2. Install Dependencies
```bash
git clone https://github.com/samore141025/log-it.git
cd "Log Analysis Agent"
pip install -r requirements.txt
```

### 3. Configure Environment Variables
Copy `.env.example` to `.env` and set your API keys:
```bash
cp .env.example .env
```

Edit `.env`:
```env
# Google Gemini API Key (for neural reasoning and false-positive suppression)
GEMINI_API_KEY=your_gemini_api_key_here

# Optional: Threat Intelligence & Webhooks
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/...
```

---

## 📖 Complete CLI Command Reference

### 1. Autonomous 24/7 Live Monitoring
Monitors `logs_to_analyze/`, live host OS telemetry, and database queues continuously:
```powershell
python run.py
```

### 2. Reset Database & Start from 0 Events
Wipes previous SQLite database files and tailer cursor states to begin completely clean:
```powershell
python run.py --clean
```

### 3. Ingest and Analyze a Specific Log File
Directly parses and audits any server, device, or web log:
```powershell
python run.py --file "C:\path\to\auth.log"
```

### 4. Recursively Analyze an Entire Directory of Logs
Scans a folder and ingests all matching `.log`, `.txt`, and `.json` files:
```powershell
python run.py --dir "C:\path\to\organization_logs"
```

### 5. Inject Authentic Cyber Attack Scenarios (Demo Mode)
Queues real-world attack patterns (SSH brute force, reverse shells, SQL injection, privilege escalation):
```powershell
python run.py --demo
```

### 6. Generate Executive Security & Compliance Reports
Generates `findings_report.html`, `findings_report.md`, and `findings_report.json` with copyable remediation commands, MITRE ATT&CK heatmap, and compliance controls:
```powershell
python run.py --report
```

### 7. Launch Live Web SOC Dashboard
Starts a real-time web portal with live attack streams, metrics, and 1-click ban buttons:
```powershell
python run.py --web --web-port 8080
```
Open `http://localhost:8080` in your web browser.

### 8. Run Embedded Network Syslog Server
Listens on UDP for incoming syslog datagrams from routers, switches, and remote hosts:
```powershell
python run.py --syslog --syslog-port 5140
```

### 9. Active Defense SOAR (Automated Host Firewall Containment)
Runs the agent with automated firewall enforcement enabled:
```powershell
python run.py --auto-remediate
```

### 10. Unban an IP Address (Containment Rollback)
Removes active firewall block rules for a remediated IP:
```powershell
python run.py --unban 104.192.3.34
```

### 11. Verify Cryptographic Forensic Ledger Integrity
Audits the SHA-256 Merkle chain to confirm zero tampering of log and finding batches:
```powershell
python run.py --verify-ledger
```

### 12. Test Multi-Channel Webhook Notifications
Dispatches a test incident card to all configured Slack, Discord, and Teams webhooks:
```powershell
python run.py --test-webhook
```

### 13. Inspect Agent Telemetry & Recent Findings
Shows active agent PID, database engine, Gemini status, and recent threat events:
```powershell
python run.py --status
```

### 14. Stop Background Agent Process
Safely terminates the running background sentinel process:
```powershell
python run.py --stop
```

### 15. Single-Pass Execution
Runs one processing cycle over queued events and exits:
```powershell
python run.py --once
```

---

## 🛡️ Enterprise Modules Overview

| Module | Location | Purpose |
| :--- | :--- | :--- |
| **Sigma Engine** | `shugo_agents/log_analysis/detectors/sigma_engine.py` | Evaluates community YAML detection rules from `rules/sigma/`. |
| **UEBA Detector** | `shugo_agents/log_analysis/detectors/ueba.py` | Flags anomalous access velocity spikes and multi-IP roaming. |
| **SOAR Active Defense** | `shugo_agents/log_analysis/soar.py` | Executes and rolls back OS firewall containment rules. |
| **Threat Intelligence** | `shugo_agents/log_analysis/threat_intel.py` | Enriches attacker IPs with reputation, country, and risk tags. |
| **Forensics & Merkle Ledger** | `shugo_agents/log_analysis/forensics.py` | PII redaction and SHA-256 tamper-proof audit chaining. |
| **Compliance & MITRE** | `shugo_agents/log_analysis/compliance.py` | Maps findings to ATT&CK tactics, PCI-DSS, SOC 2, and ISO 27001. |
| **Web SOC Dashboard** | `shugo_agents/log_analysis/web_dashboard.py` | Real-time web console with REST API endpoints. |
| **Syslog Listener** | `shugo_agents/log_analysis/ingest/syslog_server.py` | UDP/TCP daemon for network log ingestion. |
| **OS Stream Collector** | `shugo_agents/log_analysis/ingest/os_stream.py` | Collects live Windows Event Logs and Linux journald entries. |
| **SOC Notifier** | `shugo_agents/log_analysis/notifications.py` | Multi-channel webhook incident dispatcher. |

---

## 🧪 Running the Verification Test Suite

Run the full automated test suite covering all integration, detector, parser, and enterprise modules:
```powershell
pytest
```

---

## 📄 License
This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.  
Copyright (c) 2026 samore141025.
