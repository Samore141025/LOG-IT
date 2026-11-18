from __future__ import annotations

import json
from pathlib import Path
import pytest
from sqlalchemy import select

from core.config import DatabaseConfig
from core.db.models import EventModel
from core.db.session import DatabaseManager
from shugo_agents.log_analysis.ingest.tailer import LogTailer

SAMPLES_DIR = Path(__file__).parent / "samples"


def test_tailer_reads_and_tracks_offsets(tmp_path: Path):
    sample_winevent = SAMPLES_DIR / "winevent_sample.json"
    if not sample_winevent.is_file():
        pytest.skip("winevent_sample.json not present")

    # Set up in-memory or temp SQLite DB for test
    db_file = tmp_path / "test_tailer.db"
    db_config = DatabaseConfig(url=f"sqlite:///{db_file}")
    db_manager = DatabaseManager(db_config)
    db_manager.init_tables()

    # Create a real log file in tmp_path
    log_file = tmp_path / "test_events.json"
    with open(sample_winevent, "r", encoding="utf-8-sig") as f:
        records = json.load(f)

    # Write first 3 records as newline delimited json
    with open(log_file, "w", encoding="utf-8") as f:
        for r in records[:3]:
            f.write(json.dumps(r) + "\n")

    state_file = tmp_path / "tailer_state.json"
    tailer = LogTailer(
        db_manager=db_manager,
        watched_files={str(log_file): "windows_json"},
        state_file_path=str(state_file),
        batch_size=50,
    )

    # First tail step
    ingested = tailer.tail_step()
    assert ingested == 3

    # Check database rows
    with db_manager.session() as session:
        count = session.query(EventModel).count()
        assert count == 3

    # Second tail step with no new lines
    ingested_2 = tailer.tail_step()
    assert ingested_2 == 0

    # Append 2 more records
    with open(log_file, "a", encoding="utf-8") as f:
        for r in records[3:5]:
            f.write(json.dumps(r) + "\n")

    # Third tail step
    ingested_3 = tailer.tail_step()
    assert ingested_3 == 2

    with db_manager.session() as session:
        count = session.query(EventModel).count()
        assert count == 5


def test_tailer_handles_log_rotation_or_truncation(tmp_path: Path):
    sample_winevent = SAMPLES_DIR / "winevent_sample.json"
    if not sample_winevent.is_file():
        pytest.skip("winevent_sample.json not present")

    db_file = tmp_path / "test_rotation.db"
    db_config = DatabaseConfig(url=f"sqlite:///{db_file}")
    db_manager = DatabaseManager(db_config)
    db_manager.init_tables()

    log_file = tmp_path / "rotated.log"
    with open(sample_winevent, "r", encoding="utf-8-sig") as f:
        records = json.load(f)

    # Write initial lines
    with open(log_file, "w", encoding="utf-8") as f:
        for r in records[:5]:
            f.write(json.dumps(r) + "\n")

    state_file = tmp_path / "tailer_state.json"
    tailer = LogTailer(
        db_manager=db_manager,
        watched_files={str(log_file): "windows_json"},
        state_file_path=str(state_file),
    )

    ingested = tailer.tail_step()
    assert ingested == 5

    # Truncate file (log rotation simulated)
    with open(log_file, "w", encoding="utf-8") as f:
        for r in records[:2]:
            f.write(json.dumps(r) + "\n")

    # Tailer should detect smaller size and reset offset to read from beginning
    ingested_rotated = tailer.tail_step()
    assert ingested_rotated == 2
