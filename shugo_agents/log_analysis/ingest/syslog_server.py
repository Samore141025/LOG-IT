"""Embedded Network Syslog Server (UDP & TCP Ingestion).

Accepts incoming syslog streams from external routers, firewalls, and servers
on UDP/TCP port 5140 (or standard 514).
"""
from __future__ import annotations

import logging
import socket
import socketserver
import threading
from typing import Callable, Optional

from core.schemas import Event
from shugo_agents.log_analysis.ingest.parsers import auto_parse_log_line

logger = logging.getLogger(__name__)


class SyslogUDPHandler(socketserver.BaseRequestHandler):
    """Handles raw UDP syslog datagrams."""

    def handle(self) -> None:
        data = self.request[0].strip()
        client_ip = self.client_address[0]
        try:
            line = data.decode("utf-8", errors="replace")
            server: SyslogServer = self.server.custom_syslog_server  # type: ignore
            if server.event_callback:
                ev = auto_parse_log_line(line, default_host=client_ip, source_hint="remote_syslog")
                if ev:
                    server.event_callback(ev)
        except Exception as e:
            logger.debug(f"Syslog UDP processing error: {e}")


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True


class SyslogServer:
    """Network syslog listener accepting remote device and server logs."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 5140,
        event_callback: Optional[Callable[[Event], None]] = None,
    ):
        self.host = host
        self.port = port
        self.event_callback = event_callback
        self.udp_server: Optional[ThreadedUDPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.is_running = False

    def start(self) -> None:
        """Start the syslog listener in a background thread."""
        try:
            self.udp_server = ThreadedUDPServer((self.host, self.port), SyslogUDPHandler)
            self.udp_server.custom_syslog_server = self  # type: ignore
            self.is_running = True
            self._thread = threading.Thread(target=self.udp_server.serve_forever, daemon=True)
            self._thread.start()
            logger.info(f"[SYSLOG SERVER] Listening for remote logs on udp://{self.host}:{self.port}")
        except Exception as e:
            logger.warning(f"Could not bind Syslog Server to {self.host}:{self.port}: {e}")
            self.is_running = False

    def stop(self) -> None:
        """Stop the background syslog listener."""
        if self.udp_server and self.is_running:
            self.is_running = False
            self.udp_server.shutdown()
            self.udp_server.server_close()
            logger.info("[SYSLOG SERVER] Stopped successfully.")
