from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import pytest

from core.config import DatabaseConfig
from core.db.session import DatabaseManager
from core.schemas import Event
from shugo_agents.log_analysis.baseline import (
    BaselineStore,
    compute_mean_and_std,
    compute_median_and_mad,
)


def test_statistical_helpers():
    data = [10.0, 12.0, 11.0, 15.0, 12.0]
    mean, std = compute_mean_and_std(data)
    assert round(mean, 2) == 12.0
    assert std > 0.0

    median, mad = compute_median_and_mad(data)
    assert median == 12.0
    assert mad >= 0.0


def test_baseline_learning_and_persistence(tmp_path: Path):
    db_file = tmp_path / "test_baseline.db"
    db_config = DatabaseConfig(url=f"sqlite:///{db_file}")
    db_manager = DatabaseManager(db_config)
    db_manager.init_tables()

    baseline = BaselineStore(
        db_manager=db_manager,
        min_events_threshold=5,
        min_learning_period_hours=1.0,
    )

    now = datetime.now(timezone.utc)
    benign_events = [
        Event(
            source="auth_syslog",
            host="app-server",
            timestamp=now,
            event_type="ssh_success_login",
            raw="Accepted publickey for alice",
            normalized={"user": "alice", "source_ip": "10.0.0.5"},
        ),
        Event(
            source="auth_syslog",
            host="app-server",
            timestamp=now,
            event_type="sudo_command",
            raw="alice : sudo ls",
            normalized={"user": "alice", "command": "ls"},
        ),
    ]

    baseline.learn_from_benign_events(benign_events)

    # Active hours
    hours = baseline.get_user_active_hours("alice")
    assert now.hour in hours

    # Sudo users
    sudo_users = baseline.get_known_sudo_users()
    assert "alice" in sudo_users

    # Known event types
    event_types = baseline.get_user_known_event_types("alice")
    assert "ssh_success_login" in event_types
    assert "sudo_command" in event_types

    # Event rate update
    baseline.record_host_batch_count("app-server", 25)
    stats = baseline.get_host_event_rate_stats("app-server")
    assert stats is not None
    assert stats["median"] == 25.0

    # Reload fresh baseline from DB to verify persistence
    reloaded_baseline = BaselineStore(
        db_manager=db_manager,
        min_events_threshold=5,
        min_learning_period_hours=1.0,
    )
    assert "alice" in reloaded_baseline.get_known_sudo_users()
    assert now.hour in reloaded_baseline.get_user_active_hours("alice")
