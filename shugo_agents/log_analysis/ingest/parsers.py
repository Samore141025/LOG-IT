from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import unquote

from core.schemas import Event

logger = logging.getLogger(__name__)

# RFC 3164 Syslog / auth.log format: "Oct 11 04:02:18 server01 sshd[1234]: Failed password for root from 192.168.1.10 port 22 ssh2"
SYSLOG_LINE_RE = re.compile(
    r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[^\s]+)\s+(?P<process>[A-Za-z0-9_\-\.]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)

# ISO 8601 Syslog format: "2026-11-18T10:00:00.123456+00:00 host process[123]: message"
ISO_SYSLOG_LINE_RE = re.compile(
    r"^(?P<iso_time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+"
    r"(?P<host>[^\s]+)\s+(?P<process>[A-Za-z0-9_\-\.]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)

# Specific auth.log regex patterns
SSH_FAILED_RE = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>[^\s]+) from (?P<ip>[^\s]+) port (?P<port>\d+) ssh2"
)
SSH_SUCCESS_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>[^\s]+) from (?P<ip>[^\s]+) port (?P<port>\d+) ssh2"
)
SSH_INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>[^\s]+) from (?P<ip>[^\s]+) port (?P<port>\d+)"
)
SUDO_COMMAND_RE = re.compile(
    r"(?P<user>[^\s]+)\s+:\s+TTY=(?P<tty>[^\s]*)\s+;\s+PWD=(?P<pwd>[^\s]*)\s+;\s+USER=(?P<target_user>[^\s]*)\s+;\s+COMMAND=(?P<command>.*)$"
)
USER_ADD_RE = re.compile(
    r"new user: name=(?P<user>[^,]+),\s+UID=(?P<uid>\d+),\s+GID=(?P<gid>\d+)"
)
GROUP_ADD_RE = re.compile(
    r"(?:add\s+'(?P<user>[^']+)'\s+to\s+group\s+'(?P<group>[^']+)'|added\s+to\s+group\s+(?P<group2>[^\s]+)\s+by\s+(?P<user2>[^\s]+))"
)
SERVICE_STOPPED_RE = re.compile(
    r"(?:Stopped\s+(?P<service>[^\.]+)\.|Stopping\s+(?P<service2>[^\.]+)\.|(?P<service3>auditd|rsyslogd|syslogd)\s+stopped)"
)
LOG_CLEARED_RE = re.compile(
    r"(?:Log file cleared|Audit log cleared|logrotate|truncate.*log|rm\s+-rf\s+/var/log)"
)

# Nginx / Apache Combined Log Format
COMBINED_LOG_RE = re.compile(
    r'^(?P<ip>[^\s]+)\s+(?P<ident>[^\s]+)\s+(?P<user>[^\s]+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>[^\s]*)\s*(?P<proto>[^"]*)?"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>[^\s]+)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
)


def _parse_syslog_timestamp(month: str, day: str, time_str: str) -> datetime:
    """Parse standard syslog date (e.g. Oct 11 04:02:18), resolving year to current or previous."""
    now = datetime.now(timezone.utc)
    date_str = f"{month} {day.zfill(2)} {time_str} {now.year}"
    try:
        dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
        # If timestamp is in future by more than 1 day, assume previous year
        if dt > now and (dt - now).days > 1:
            dt = dt.replace(year=now.year - 1)
        return dt
    except ValueError:
        return now


def _parse_clf_timestamp(time_str: str) -> datetime:
    """Parse Common Log Format timestamp: '10/Oct/2026:13:55:36 +0000'."""
    try:
        return datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return datetime.now(timezone.utc)


def parse_auth_syslog_line(raw_line: str, default_host: str = "unknown") -> Optional[Event]:
    line = raw_line.strip()
    if not line:
        return None

    # Check ISO format first
    iso_match = ISO_SYSLOG_LINE_RE.match(line)
    if iso_match:
        try:
            ts_str = iso_match.group("iso_time")
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if not dt.tzinfo:
                dt = dt.replace(tzinfo=timezone.utc)
        except Exception:
            dt = datetime.now(timezone.utc)
        host = iso_match.group("host")
        process = iso_match.group("process")
        message = iso_match.group("message")
    else:
        sys_match = SYSLOG_LINE_RE.match(line)
        if sys_match:
            dt = _parse_syslog_timestamp(
                sys_match.group("month"),
                sys_match.group("day"),
                sys_match.group("time")
            )
            host = sys_match.group("host")
            process = sys_match.group("process")
            message = sys_match.group("message")
        else:
            # Fallback raw line
            dt = datetime.now(timezone.utc)
            host = default_host
            process = "unknown"
            message = line

    normalized: Dict[str, Any] = {
        "timestamp": dt.isoformat(),
        "host": host,
        "process": process,
        "raw_message": message,
    }

    event_type = "syslog_event"

    # Analyze message semantics
    ssh_failed = SSH_FAILED_RE.search(message) or SSH_INVALID_USER_RE.search(message)
    if ssh_failed:
        event_type = "ssh_failed_login"
        normalized["user"] = ssh_failed.group("user")
        normalized["source_ip"] = ssh_failed.group("ip")
        if "port" in ssh_failed.groupdict():
            normalized["port"] = int(ssh_failed.group("port"))
        normalized["status"] = "failure"

    ssh_success = SSH_SUCCESS_RE.search(message)
    if ssh_success:
        event_type = "ssh_success_login"
        normalized["user"] = ssh_success.group("user")
        normalized["source_ip"] = ssh_success.group("ip")
        normalized["port"] = int(ssh_success.group("port"))
        normalized["status"] = "success"

    sudo_match = SUDO_COMMAND_RE.search(message)
    if sudo_match:
        event_type = "sudo_command"
        normalized["user"] = sudo_match.group("user")
        normalized["target_user"] = sudo_match.group("target_user")
        normalized["command"] = sudo_match.group("command")
        normalized["pwd"] = sudo_match.group("pwd")

    user_add = USER_ADD_RE.search(message)
    if user_add:
        event_type = "user_created"
        normalized["user"] = user_add.group("user")
        normalized["uid"] = int(user_add.group("uid"))
        normalized["gid"] = int(user_add.group("gid"))

    group_add = GROUP_ADD_RE.search(message)
    if group_add:
        event_type = "user_group_added"
        user = group_add.group("user") or group_add.group("user2")
        group = group_add.group("group") or group_add.group("group2")
        normalized["user"] = user
        normalized["group"] = group

    service_stop = SERVICE_STOPPED_RE.search(message)
    if service_stop:
        event_type = "service_stopped"
        service = (
            service_stop.group("service")
            or service_stop.group("service2")
            or service_stop.group("service3")
        )
        normalized["service"] = service

    if LOG_CLEARED_RE.search(message):
        event_type = "log_cleared"

    normalized["event_type"] = event_type

    return Event(
        source="auth_syslog",
        host=host,
        timestamp=dt,
        event_type=event_type,
        raw=line,
        normalized=normalized,
        processed_by=[],
    )


def parse_web_log_line(raw_line: str, default_host: str = "webserver") -> Optional[Event]:
    line = raw_line.strip()
    if not line:
        return None

    match = COMBINED_LOG_RE.match(line)
    if not match:
        return None

    ip = match.group("ip")
    user = match.group("user") if match.group("user") != "-" else None
    dt = _parse_clf_timestamp(match.group("time"))
    method = match.group("method")
    raw_uri = match.group("uri")
    uri = unquote(raw_uri)
    status_code = int(match.group("status"))
    bytes_sent = match.group("bytes")
    user_agent = match.group("user_agent")
    referer = match.group("referer")

    normalized = {
        "timestamp": dt.isoformat(),
        "host": default_host,
        "source_ip": ip,
        "user": user,
        "http_method": method,
        "http_uri": uri,
        "raw_uri": raw_uri,
        "http_status": status_code,
        "bytes_sent": bytes_sent,
        "user_agent": user_agent,
        "referer": referer,
        "event_type": "http_request",
    }

    return Event(
        source="web_access",
        host=default_host,
        timestamp=dt,
        event_type="http_request",
        raw=line,
        normalized=normalized,
        processed_by=[],
    )


def parse_windows_event_json(json_data: str | Dict[str, Any], default_host: str = "windows-host") -> Optional[Event]:
    if isinstance(json_data, str):
        try:
            cleaned_str = json_data.strip().lstrip("\ufeff")
            if not cleaned_str:
                return None
            data = json.loads(cleaned_str)
        except json.JSONDecodeError:
            return None
    elif isinstance(json_data, dict):
        data = json_data
    else:
        return None

    # Handle standard Windows Event Object (from Get-WinEvent, evtx_dump, or Winlogbeat)
    event_id = data.get("Id") or data.get("EventID") or data.get("id") or 0
    if isinstance(event_id, dict):
        event_id = event_id.get("#text") or event_id.get("value") or 0
    try:
        event_id = int(event_id)
    except (ValueError, TypeError):
        event_id = 0

    # Timestamp extraction
    time_created = (
        data.get("TimeCreated")
        or data.get("SystemTime")
        or data.get("time_created")
        or data.get("@timestamp")
    )
    if isinstance(time_created, dict):
        time_created = time_created.get("SystemTime") or time_created.get("#text")
    if isinstance(time_created, str):
        # Handle PowerShell JSON \/Date(1794992386489)\/ format
        date_ms_match = re.search(r"/Date\((\d+)\)/", time_created)
        if date_ms_match:
            try:
                ms = int(date_ms_match.group(1))
                dt = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
            except Exception:
                dt = datetime.now(timezone.utc)
        else:
            try:
                dt = datetime.fromisoformat(time_created.replace("Z", "+00:00"))
                if not dt.tzinfo:
                    dt = dt.replace(tzinfo=timezone.utc)
            except Exception:
                dt = datetime.now(timezone.utc)
    else:
        dt = datetime.now(timezone.utc)

    host = (
        data.get("MachineName")
        or data.get("Computer")
        or data.get("ComputerName")
        or default_host
    )
    if isinstance(host, dict):
        host = host.get("#text") or default_host

    message = data.get("Message") or json.dumps(data)
    properties = data.get("Properties") or data.get("EventData") or {}

    normalized: Dict[str, Any] = {
        "timestamp": dt.isoformat(),
        "host": str(host),
        "windows_event_id": event_id,
        "raw_message": message if isinstance(message, str) else str(message),
        "properties": properties if isinstance(properties, (dict, list)) else {},
    }

    event_type = f"win_event_{event_id}"

    # Extract user and IP from properties if available
    user = None
    ip = None
    command = None

    if isinstance(properties, dict):
        user = (
            properties.get("TargetUserName")
            or properties.get("SubjectUserName")
            or properties.get("AccountName")
        )
        ip = properties.get("IpAddress") or properties.get("WorkstationName")
        command = properties.get("CommandLine") or properties.get("ProcessCommandLine")
    elif isinstance(properties, list):
        for p in properties:
            if isinstance(p, dict):
                val = p.get("Value")
                if val:
                    val_str = str(val)
                    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val_str):
                        ip = val_str

    # Map Windows Event IDs to normalized types
    if event_id == 4625:
        event_type = "windows_failed_login"
        normalized["status"] = "failure"
    elif event_id == 4624:
        event_type = "windows_success_login"
        normalized["status"] = "success"
    elif event_id == 4672:
        event_type = "windows_special_privilege"
    elif event_id == 4720:
        event_type = "user_created"
    elif event_id in (4728, 4732, 4756):
        event_type = "user_group_added"
    elif event_id == 4688:
        event_type = "windows_process_creation"
    elif event_id in (1102, 104):
        event_type = "log_cleared"
    elif event_id == 7036:
        event_type = "service_stopped"

    normalized["user"] = user
    normalized["source_ip"] = ip
    normalized["command"] = command
    normalized["event_type"] = event_type

    raw_text = json.dumps(data) if isinstance(data, dict) else str(data)

    return Event(
        source="windows_evtx",
        host=str(host),
        timestamp=dt,
        event_type=event_type,
        raw=raw_text,
        normalized=normalized,
        processed_by=[],
    )


def auto_parse_log_line(raw_line: str, default_host: str = "generic-device", source_hint: str = "device_log") -> Optional[Event]:
    """Universal parser for any enterprise device: Linux, Windows, web servers, firewalls, network appliances."""
    line = raw_line.strip()
    if not line:
        return None

    # 1. JSON (Windows EVTX-JSON, Suricata, Zeek, CloudTrail, App logs)
    if line.startswith("{") and line.endswith("}"):
        try:
            data = json.loads(line)
            if any(k in data for k in ("Id", "EventID", "MachineName", "Task")):
                return parse_windows_event_json(data, default_host=default_host)

            ts_str = data.get("timestamp") or data.get("time") or data.get("@timestamp")
            dt = datetime.now(timezone.utc)
            if ts_str:
                try:
                    dt = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
                    if not dt.tzinfo:
                        dt = dt.replace(tzinfo=timezone.utc)
                except Exception:
                    pass

            host = data.get("host") or data.get("hostname") or data.get("device") or default_host
            ev_type = data.get("event_type") or data.get("action") or "json_event"
            user = data.get("user") or data.get("username")
            src_ip = data.get("source_ip") or data.get("src_ip") or data.get("client_ip")
            cmd = data.get("command") or data.get("cmd")

            normalized = dict(data)
            normalized["host"] = str(host)
            normalized["timestamp"] = dt.isoformat()
            if user:
                normalized["user"] = str(user)
            if src_ip:
                normalized["source_ip"] = str(src_ip)
            if cmd:
                normalized["command"] = str(cmd)
            normalized["event_type"] = str(ev_type)

            return Event(
                source=source_hint,
                host=str(host),
                timestamp=dt,
                event_type=str(ev_type),
                raw=line,
                normalized=normalized,
                processed_by=[],
            )
        except Exception:
            pass

    # 2. Web Access Log (Nginx, Apache, IIS)
    if COMBINED_LOG_RE.match(line):
        ev = parse_web_log_line(line, default_host=default_host)
        if ev:
            return ev

    # 3. Syslog / Auth / Audit log (Linux servers, SSH, Sudo)
    ev = parse_auth_syslog_line(line, default_host=default_host)
    if ev and ev.event_type != "syslog_event":
        return ev

    # 4. Universal Fallback (Firewalls, Routers, Network Switches, pfSense, Cisco ASA)
    ip_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", line)
    ip = ip_match.group(1) if ip_match else None

    user_match = re.search(r"(?:user|username|account)[=:\s]+['\"]?([A-Za-z0-9_\-\.]+)['\"]?", line, re.IGNORECASE)
    user = user_match.group(1) if user_match else None

    line_lower = line.lower()
    ev_type = "device_event"
    if any(w in line_lower for w in ("failed", "failure", "invalid user", "authentication failure", "bad password")):
        ev_type = "ssh_failed_login" if ("ssh" in line_lower or "port 22" in line_lower) else "auth_failed"
    elif any(w in line_lower for w in ("accepted", "success", "session opened", "logon")):
        ev_type = "ssh_success_login" if ("ssh" in line_lower or "port 22" in line_lower) else "auth_success"
    elif any(w in line_lower for w in ("blocked", "denied", "drop", "reject")):
        ev_type = "network_denied"

    dt = datetime.now(timezone.utc)
    if ev and ev.timestamp:
        dt = ev.timestamp

    normalized = {
        "timestamp": dt.isoformat(),
        "host": default_host,
        "source_ip": ip,
        "user": user,
        "raw_message": line,
        "event_type": ev_type,
    }

    return Event(
        source=source_hint,
        host=default_host,
        timestamp=dt,
        event_type=ev_type,
        raw=line,
        normalized=normalized,
        processed_by=[],
    )
