"""Embedded Live Web SOC Dashboard & REST API.

Provides:
- Lightweight HTTP server on port 8080 (or custom port).
- Dark-mode responsive Web UI with real-time stats and findings.
- REST endpoints for metrics, alerts, and 1-click SOAR remediation.
"""
from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger(__name__)

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LOG-IT // Live SOC Operations Center</title>
    <style>
        :root {
            --bg: #090d16;
            --card-bg: #111827;
            --border: #1f2937;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --cyan: #06b6d4;
            --green: #10b981;
            --red: #ef4444;
            --orange: #f97316;
            --yellow: #eab308;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            padding: 24px;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }
        .brand {
            font-size: 24px;
            font-weight: 800;
            letter-spacing: 1px;
            color: var(--cyan);
        }
        .live-badge {
            background: rgba(16, 185, 129, 0.2);
            color: var(--green);
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 13px;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        .pulse {
            width: 8px;
            height: 8px;
            background: var(--green);
            border-radius: 50%;
            animation: pulse-anim 1.5s infinite;
        }
        @keyframes pulse-anim {
            0% { transform: scale(0.95); opacity: 0.8; }
            50% { transform: scale(1.4); opacity: 1; }
            100% { transform: scale(0.95); opacity: 0.8; }
        }
        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .kpi-card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
        }
        .kpi-val { font-size: 32px; font-weight: 800; margin-bottom: 4px; }
        .kpi-label { font-size: 12px; color: var(--text-muted); text-transform: uppercase; }
        .card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 24px;
        }
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }
        .card-title { font-size: 16px; font-weight: 700; }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        th { color: var(--text-muted); font-size: 12px; text-transform: uppercase; }
        .badge {
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }
        .badge-critical { background: rgba(239, 68, 68, 0.2); color: var(--red); }
        .badge-high { background: rgba(249, 115, 22, 0.2); color: var(--orange); }
        .badge-medium { background: rgba(234, 179, 8, 0.2); color: var(--yellow); }
        .badge-low { background: rgba(6, 182, 212, 0.2); color: var(--cyan); }
        .btn-ban {
            background: #dc2626;
            color: #fff;
            border: none;
            padding: 4px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 600;
        }
        .btn-ban:hover { background: #b91c1c; }
    </style>
</head>
<body>
    <div class="header">
        <div class="brand">🛡️ LOG-IT // SOC DASHBOARD</div>
        <div class="live-badge"><div class="pulse"></div> LIVE SURVEILLANCE ACTIVE</div>
    </div>

    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-val" id="val-events" style="color: var(--cyan);">0</div>
            <div class="kpi-label">Events Analyzed</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-val" id="val-critical" style="color: var(--red);">0</div>
            <div class="kpi-label">Critical Incidents</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-val" id="val-high" style="color: var(--orange);">0</div>
            <div class="kpi-label">High Threats</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-val" id="val-med-low" style="color: var(--yellow);">0</div>
            <div class="kpi-label">Medium & Low</div>
        </div>
    </div>

    <div class="card">
        <div class="card-header">
            <div class="card-title">🚨 Recent Security Findings & Incident Stream</div>
            <div style="font-size: 13px; color: var(--text-muted);" id="refresh-time">Auto-refreshes every 3s</div>
        </div>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Detection Rule</th>
                    <th>MITRE ATT&CK</th>
                    <th>Attacker IP</th>
                    <th>Target Account</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody id="findings-body">
                <tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 24px;">Listening for threat telemetry...</td></tr>
            </tbody>
        </table>
    </div>

    <script>
        async function fetchSOCData() {
            try {
                const res = await fetch('/api/stats');
                if (!res.ok) return;
                const data = await res.json();
                
                document.getElementById('val-events').innerText = data.total_events || 0;
                document.getElementById('val-critical').innerText = data.critical_count || 0;
                document.getElementById('val-high').innerText = data.high_count || 0;
                document.getElementById('val-med-low').innerText = (data.medium_count || 0) + (data.low_count || 0);

                const tbody = document.getElementById('findings-body');
                if (data.findings && data.findings.length > 0) {
                    tbody.innerHTML = '';
                    data.findings.slice(0, 15).forEach(f => {
                        const sev = (f.severity || 'medium').toLowerCase();
                        const badgeClass = 'badge-' + (sev === 'critical' ? 'critical' : sev === 'high' ? 'high' : sev === 'low' ? 'low' : 'medium');
                        const ips = (f.entities && f.entities.ips && f.entities.ips.length) ? f.entities.ips.join(', ') : 'None';
                        const users = (f.entities && f.entities.users && f.entities.users.length) ? f.entities.users.join(', ') : 'Host System';
                        
                        const tr = document.createElement('tr');
                        tr.innerHTML = `
                            <td><span class="badge ${badgeClass}">${f.severity}</span></td>
                            <td style="font-weight: 600;">${f.rule}</td>
                            <td><code>${f.mitre_technique || 'N/A'}</code></td>
                            <td><code>${ips}</code></td>
                            <td>${users}</td>
                            <td>
                                ${ips !== 'None' ? `<button class="btn-ban" onclick="remediateIP('${f.entities.ips[0]}')">Block IP</button>` : '<span style="color:var(--text-muted)">-</span>'}
                            </td>
                        `;
                        tbody.appendChild(tr);
                    });
                }
                document.getElementById('refresh-time').innerText = 'Last updated: ' + new Date().toLocaleTimeString();
            } catch (e) {
                console.error('Fetch error:', e);
            }
        }

        async function remediateIP(ip) {
            if (!confirm('Execute immediate firewall containment against IP ' + ip + '?')) return;
            try {
                const res = await fetch('/api/remediate?ip=' + encodeURIComponent(ip), { method: 'POST' });
                const r = await res.json();
                alert(r.message || (r.success ? 'IP blocked successfully!' : 'Block failed.'));
                fetchSOCData();
            } catch (e) {
                alert('Containment failed: ' + e);
            }
        }

        fetchSOCData();
        setInterval(fetchSOCData, 3000);
    </script>
</body>
</html>
"""


class DashboardHTTPHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests for the live SOC dashboard."""

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/" or parsed.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode("utf-8"))
        elif parsed.path == "/api/stats":
            server: WebSOCDashboardServer = self.server.custom_dashboard_server  # type: ignore
            stats_data = server.data_provider() if server.data_provider else {}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(stats_data).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/remediate":
            query = parse_qs(parsed.query)
            ip = query.get("ip", [""])[0]
            server: WebSOCDashboardServer = self.server.custom_dashboard_server  # type: ignore
            if server.remediate_handler and ip:
                res = server.remediate_handler(ip)
            else:
                res = {"success": False, "message": "No remediation handler or IP provided."}

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(res).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress standard HTTP request logging to avoid terminal clutter
        pass


class WebSOCDashboardServer:
    """Standalone HTTP server for the live Web SOC Dashboard."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        data_provider: Optional[Callable[[], Dict[str, Any]]] = None,
        remediate_handler: Optional[Callable[[str], Dict[str, Any]]] = None,
    ):
        self.host = host
        self.port = port
        self.data_provider = data_provider
        self.remediate_handler = remediate_handler
        self.httpd: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.is_running = False

    def start(self) -> None:
        """Start the web server in a background thread."""
        try:
            self.httpd = HTTPServer((self.host, self.port), DashboardHTTPHandler)
            self.httpd.custom_dashboard_server = self  # type: ignore
            self.is_running = True
            self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
            self._thread.start()
            logger.info(f"[WEB DASHBOARD] Live SOC Dashboard running at http://{self.host}:{self.port}")
        except Exception as e:
            logger.warning(f"Could not bind Web Dashboard to {self.host}:{self.port}: {e}")
            self.is_running = False

    def stop(self) -> None:
        """Stop the background web server."""
        if self.httpd and self.is_running:
            self.is_running = False
            self.httpd.shutdown()
            self.httpd.server_close()
            logger.info("[WEB DASHBOARD] Stopped successfully.")
