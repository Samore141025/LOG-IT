from __future__ import annotations

import logging
import signal
import sys
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.db.models import AgentStateModel, AuditLogModel
from core.db.session import DatabaseManager
from core.schemas import AgentState, AuditLog

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Abstract base class for all autonomous SHUGO agents."""

    def __init__(self, agent_name: str, db_manager: DatabaseManager):
        self.agent_name = agent_name
        self.db_manager = db_manager
        self.running: bool = False
        self.cursor: Optional[Dict[str, Any]] = None
        self.stats: Dict[str, Any] = {
            "processed_events_total": 0,
            "findings_generated_total": 0,
            "errors_total": 0,
            "batches_total": 0,
        }
        self.status: str = "initialized"
        self._last_heartbeat_time: float = 0.0

    def register_signal_handlers(self) -> None:
        """Register graceful shutdown handlers."""
        def _handle_shutdown(signum, frame):
            sig_name = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
            logger.info(f"Received signal {sig_name}. Initiating graceful shutdown...")
            self.stop()

        try:
            signal.signal(signal.SIGINT, _handle_shutdown)
            signal.signal(signal.SIGTERM, _handle_shutdown)
        except (ValueError, AttributeError):
            # Not in main thread or platform specific
            pass

    def load_state(self) -> None:
        """Load cursor and statistics from the database."""
        try:
            with self.db_manager.session() as session:
                state_record = session.execute(
                    select(AgentStateModel).where(AgentStateModel.agent == self.agent_name)
                ).scalar_one_or_none()

                if state_record:
                    self.cursor = state_record.cursor
                    if isinstance(state_record.stats, dict):
                        self.stats.update(state_record.stats)
                    logger.info(f"Loaded agent state: cursor={self.cursor}, stats={self.stats}")
                else:
                    new_state = AgentStateModel(
                        agent=self.agent_name,
                        cursor=None,
                        last_heartbeat=datetime.now(timezone.utc),
                        status="initialized",
                        stats=self.stats,
                    )
                    session.add(new_state)
                    logger.info(f"Initialized new state record for agent {self.agent_name}")
        except Exception as e:
            logger.error(f"Error loading state for {self.agent_name}: {e}", exc_info=True)

    def save_state(self, status: Optional[str] = None) -> None:
        """Persist cursor, status, and stats to the database."""
        if status:
            self.status = status
        try:
            with self.db_manager.session() as session:
                state_record = session.execute(
                    select(AgentStateModel).where(AgentStateModel.agent == self.agent_name)
                ).scalar_one_or_none()

                now = datetime.now(timezone.utc)
                if state_record:
                    state_record.cursor = self.cursor
                    state_record.last_heartbeat = now
                    state_record.status = self.status
                    state_record.stats = self.stats
                else:
                    session.add(
                        AgentStateModel(
                            agent=self.agent_name,
                            cursor=self.cursor,
                            last_heartbeat=now,
                            status=self.status,
                            stats=self.stats,
                        )
                    )
                self._last_heartbeat_time = time.time()
        except Exception as e:
            logger.error(f"Error saving state for {self.agent_name}: {e}", exc_info=True)

    def record_audit(self, action: str, details: Dict[str, Any]) -> None:
        """Record an action in the audit_logs table."""
        try:
            with self.db_manager.session() as session:
                session.add(
                    AuditLogModel(
                        agent=self.agent_name,
                        action=action,
                        details=details,
                        created_at=datetime.now(timezone.utc),
                    )
                )
        except Exception as e:
            logger.error(f"Failed to record audit log for action '{action}': {e}", exc_info=True)

    def heartbeat_if_needed(self, interval_seconds: float = 15.0) -> None:
        now = time.time()
        if now - self._last_heartbeat_time >= interval_seconds:
            self.save_state()

    def start(self) -> None:
        """Start the agent."""
        self.running = True
        self.status = "running"
        self.register_signal_handlers()
        self.load_state()
        self.record_audit("agent_started", {"timestamp": datetime.now(timezone.utc).isoformat()})
        logger.info(f"Agent '{self.agent_name}' started successfully.")

    def stop(self) -> None:
        """Gracefully stop the agent."""
        self.running = False
        self.status = "stopped"
        self.save_state(status="stopped")
        self.record_audit("agent_stopped", {"timestamp": datetime.now(timezone.utc).isoformat()})
        logger.info(f"Agent '{self.agent_name}' stopped gracefully.")

    @abstractmethod
    def step(self) -> int:
        """Execute one unit/batch of processing. Returns count of processed events."""
        pass

    def run_loop(
        self,
        once: bool = False,
        idle_sleep_seconds: float = 5.0,
        busy_sleep_seconds: float = 0.5,
        heartbeat_interval_seconds: float = 15.0,
    ) -> None:
        """Autonomous main execution loop with adaptive sleep and error recovery."""
        self.start()
        try:
            while self.running:
                try:
                    self.heartbeat_if_needed(heartbeat_interval_seconds)
                    count = self.step()
                    self.stats["batches_total"] += 1

                    if once:
                        logger.info("Single-step mode completed (--once flag set).")
                        break

                    # Adaptive sleep: if backlog was processed, sleep shorter; if idle, sleep longer
                    if count > 0:
                        time.sleep(busy_sleep_seconds)
                    else:
                        time.sleep(idle_sleep_seconds)

                except Exception as e:
                    self.stats["errors_total"] += 1
                    logger.critical(f"Unhandled error in agent loop: {e}", exc_info=True)
                    self.record_audit("loop_error", {"error": str(e), "type": type(e).__name__})
                    time.sleep(min(idle_sleep_seconds, 5.0))
        finally:
            if self.running:
                self.stop()
