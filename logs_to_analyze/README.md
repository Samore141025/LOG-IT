# Organization Log Ingestion Directory (`logs_to_analyze/`)

Drop **ANY log file** from any server, device, firewall, or application into this folder (or subfolders).
The **SHUGO Log Analysis Agent** will automatically discover it, parse it in real-time, detect threats, and triage alerts with Google Gemini.

---

## Supported Formats & Devices

You can drop logs from any system in your organization:

1. **Linux / Unix Servers**:
   - `auth.log`, `syslog`, `secure`, `audit.log`
   - Detects: SSH brute force, password spray, unauthorized sudo usage, reverse shells, backdoor UID 0 accounts, log tampering.

2. **Web Servers & Gateways**:
   - Nginx, Apache, Traefik, IIS access logs
   - Detects: SQL Injection (SQLi), Cross-Site Scripting (XSS), Directory Traversal (LFI), vulnerability scanners (sqlmap, nikto), HTTP error bursts.

3. **Windows Servers & Workstations**:
   - Windows Security and System Event Logs (exported as JSON or newline JSON).
   - Detects: Event 4625 brute force, Event 4672 special privileges, Event 4720 user added, Event 1102 log cleared, service stops.

4. **Firewalls, Routers & Network Appliances**:
   - Cisco ASA, Fortinet, pfSense, Palo Alto syslog streams.
   - Detects: Port scans, denied traffic floods, anomalous connection rates.

5. **Cloud & Applications**:
   - Docker / Kubernetes container logs, application JSON logs.

---

## How to Analyze a Log File

### Option 1: Drop & Watch (Automatic 24/7)
Simply copy or save your log file into this folder:
```bash
cp /var/log/auth.log ./logs_to_analyze/
```
The running agent (`python run.py`) will automatically discover it, ingest new lines as they arrive, and report findings on your screen!

### Option 2: Direct Command Line Analysis
You can also run one-off analysis on any file or folder directly:
```bash
# Analyze any specific log file:
python run.py --file "C:\path\to\my_firewall.log"

# Analyze any specific folder:
python run.py --dir "C:\path\to\server_logs\"
```
