# 🛡️ LOG-IT: Universal Autonomous Log Analysis & Incident Response Sentinel

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Tests: 36 Passed](https://img.shields.io/badge/tests-36%20passed-brightgreen.svg)]()
[![AI Engine: Gemini](https://img.shields.io/badge/AI%20Engine-Google%20Gemini-orange.svg)]()

**LOG-IT** is an enterprise-grade autonomous cybersecurity sentinel that investigates system, security, and application logs in real time. It blends deterministic pattern detectors, community **Sigma** rules, **User & Entity Behavior Analytics (UEBA)**, and **Google Gemini neural triage** to identify threats, enforce active firewall containment, and generate compliance-ready forensic reports.

---

## ⚡ Architectural Overview

```
+-----------------------------------------------------------------------------------------+
|                               LOG-IT SENTINEL ARCHITECTURE                              |
|                                                                                         |
|  [Live Host OS Logs]     [Remote Syslog UDP:5140]      [Dropped Files: logs_to_analyze] |
|           │                         │                               │                   |
|           ▼                         ▼                               ▼                   |
|  [Windows Events API]      [RFC 3164/5424 Server]          [Directory Log Tailer]       |
|           │                         │                               │                   |
|           └─────────────────────────┼───────────────────────────────┘                   |
|                                     ▼                                                   |
|                        [PII & Credential Redactor]                                      |
|                                     │                                                   |
|                                     ▼                                                   |
|                  [Unified High-Speed Event Datastore]                                   |
|                                     │                                                   |
|                                     ▼                                                   |
|                  [Autonomous Detection Pipeline (10 Engines)]                           |
|                  • Brute Force & Password Spraying                                      |
|                  • Reverse Shells & Suspicious Commands                                 |
|                  • Web Application Attacks (SQLi, XSS, Path Traversal)                  |
|                  • Sigma-Compatible Rule Engine (rules/sigma/)                          |
|                  • User & Entity Behavior Analytics (UEBA)                              |
|                                     │                                                   |
|                                     ▼                                                   |
|                  [Google Gemini Neural Reasoning & Triage]                              |
|                  • False-Positive Suppression & Confidence Scoring                      |
|                  • Threat Intel Enrichment (AbuseIPDB, Tor, Botnets)                    |
|                                     │                                                   |
|                                     ▼                                                   |
|                  [Actionable Multi-Channel Incident Response]                           |
|                  ├── SOAR Active Defense: Host Firewall Quarantine (netsh / iptables)   |
|                  ├── SOC Webhooks: Slack, Discord, MS Teams Cards                       |
|                  ├── SHA-256 Merkle Chain Cryptographic Audit Ledger                    |
|                  ├── Live Web SOC Dashboard (http://localhost:8080)                     |
|                  └── Regulatory Compliance (PCI-DSS 4.0, SOC 2, ISO 27001, HIPAA)       |
+-----------------------------------------------------------------------------------------+
```

---

## 🚀 Key Features

* **Real-Time Live OS Streaming**: Native Windows Event Log (`4624`, `4625`, `4688`, `4720`) and Linux `journald`/syslog collectors.
* **SOAR Active Defense**: Automatic and 1-click IP containment at host firewalls (`netsh advfirewall`, `iptables`, `ufw`).
* **Detection-as-Code (Sigma)**: Seamlessly loads community Sigma YAML rules from `rules/sigma/`.
* **Multi-Channel Alerting**: Instant dispatch of rich incident cards to Slack, Discord, and Teams.
* **Threat Intelligence**: Enriches external attacker IPs with reputation scores and threat categories.
* **Embedded Syslog Server**: Ingests remote network device logs via UDP port `5140`.
* **Live Web Operations Console**: Browser-based SOC dashboard running on `http://localhost:8080`.
* **Behavioral Analytics (UEBA)**: Flags access velocity spikes and multi-IP roaming across user accounts.
* **Cryptographic Forensic Ledger**: Mathematically proves audit trails have not been altered or deleted via SHA-256 Merkle chaining.
* **Compliance Mapping**: Automatically maps findings to PCI-DSS, SOC 2, ISO/IEC 27001, and HIPAA controls.

---

## 🛠️ Quick Start

### 1. Installation
```bash
git clone https://github.com/Samore141025/LOG-IT.git
cd LOG-IT
pip install -r requirements.txt
```

### 2. Environment Setup
```bash
cp .env.example .env
```
Add your Google Gemini API key to `.env`:
```env
GEMINI_API_KEY=your_gemini_api_key_here
```

### 3. Launch Sentinel
```powershell
# Continuous 24/7 Autonomous Surveillance
python run.py

# Launch with Live Web SOC Dashboard at http://localhost:8080
python run.py --web

# Test with authentic cyber attack scenarios
python run.py --demo

# Generate compliance and executive reports
python run.py --report

# Verify cryptographic ledger integrity
python run.py --verify-ledger
```

For the complete guide on all 16 command line options and features, see [MANUAL.md](MANUAL.md).

---

## 🧪 Automated Test Suite

All detector, reasoning, parser, and enterprise modules are verified with pytest:
```bash
pytest
```
*Result: 36 passed / verified across all suites.*

---

## 📄 License & Attribution

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.  
Copyright (c) 2026 **samore141025**.
