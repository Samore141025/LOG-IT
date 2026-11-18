# Real Log Samples Directory

According to the SHUGO security rules:
- **No fake, mock, or randomly generated data is allowed anywhere**, including tests.
- Tests will strictly use real log samples saved in this directory (`tests/samples/`).
- If any sample file is not present on your testing machine, tests will cleanly skip that sample without failing.

## How to capture real logs from your machine

### 1. Linux Auth & Syslog (`auth.log` / `syslog`)
Run on your Linux server:
```bash
# Copy real auth log
sudo cp /var/log/auth.log ./tests/samples/auth_sample.log

# Or on systems using systemd-journald:
sudo journalctl -u ssh -n 200 --no-pager > ./tests/samples/auth_sample.log
sudo journalctl -n 200 --no-pager > ./tests/samples/syslog_sample.log
```

### 2. Nginx / Apache Access Logs
Run on your web server:
```bash
# Nginx
sudo tail -n 200 /var/log/nginx/access.log > ./tests/samples/nginx_sample.log

# Apache
sudo tail -n 200 /var/log/apache2/access.log > ./tests/samples/nginx_sample.log
```

### 3. Windows Security & System Events (JSON)
Run in PowerShell (as Administrator for Security log):
```powershell
# Export real Security events:
Get-WinEvent -LogName Security -MaxEvents 100 | Select-Object Id, TimeCreated, MachineName, Message | ConvertTo-Json | Out-File -Encoding utf8 ./tests/samples/winevent_security.json

# Export real System events:
Get-WinEvent -LogName System -MaxEvents 50 | Select-Object Id, TimeCreated, MachineName, Message | ConvertTo-Json | Out-File -Encoding utf8 ./tests/samples/winevent_sample.json
```
