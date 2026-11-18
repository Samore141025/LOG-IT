from __future__ import annotations

import json
from pathlib import Path
import pytest

from shugo_agents.log_analysis.ingest.parsers import (
    parse_auth_syslog_line,
    parse_web_log_line,
    parse_windows_event_json,
)

SAMPLES_DIR = Path(__file__).parent / "samples"


def test_windows_evtx_json_parser_with_real_sample():
    sample_path = SAMPLES_DIR / "winevent_sample.json"
    if not sample_path.is_file():
        pytest.skip("winevent_sample.json is not present on this machine")

    with open(sample_path, "r", encoding="utf-8-sig") as f:
        events_data = json.load(f)

    assert isinstance(events_data, list)
    parsed_count = 0
    for record in events_data:
        event = parse_windows_event_json(record)
        assert event is not None
        assert event.source == "windows_evtx"
        assert event.host != ""
        assert event.timestamp is not None
        parsed_count += 1

    assert parsed_count > 0


def test_auth_log_parser_with_sample_if_present():
    sample_path = SAMPLES_DIR / "auth_sample.log"
    if not sample_path.is_file():
        pytest.skip("auth_sample.log is not present in tests/samples/ (skipping cleanly)")

    with open(sample_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                event = parse_auth_syslog_line(line)
                if event:
                    assert event.source == "auth_syslog"
                    assert event.timestamp is not None


def test_web_log_parser_with_sample_if_present():
    sample_path = SAMPLES_DIR / "nginx_sample.log"
    if not sample_path.is_file():
        pytest.skip("nginx_sample.log is not present in tests/samples/ (skipping cleanly)")

    with open(sample_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                event = parse_web_log_line(line)
                if event:
                    assert event.source == "web_access"
                    assert event.event_type == "http_request"


def test_parser_edge_cases():
    # Empty or whitespace line returns None
    assert parse_auth_syslog_line("") is None
    assert parse_auth_syslog_line("   \n") is None
    assert parse_web_log_line("") is None
    assert parse_windows_event_json("not valid json") is None
