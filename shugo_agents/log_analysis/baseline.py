from __future__ import annotations

import logging
import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.db.models import BaselineModel
from core.db.session import DatabaseManager
from core.schemas import Event

logger = logging.getLogger(__name__)


def compute_median_and_mad(data: List[float]) -> tuple[float, float]:
    """Compute median and median absolute deviation (MAD)."""
    if not data:
        return 0.0, 0.0
    sorted_data = sorted(data)
    n = len(sorted_data)
    mid = n // 2
    if n % 2 == 1:
        median = sorted_data[mid]
    else:
        median = (sorted_data[mid - 1] + sorted_data[mid]) / 2.0

    deviations = sorted([abs(x - median) for x in data])
    if n % 2 == 1:
        mad = deviations[mid]
    else:
        mad = (deviations[mid - 1] + deviations[mid]) / 2.0

    return median, mad


def compute_mean_and_std(data: List[float]) -> tuple[float, float]:
    """Compute mean and sample standard deviation."""
    if not data:
        return 0.0, 0.0
    n = len(data)
    mean = sum(data) / n
    if n < 2:
        return mean, 0.0
    variance = sum((x - mean) ** 2 for x in data) / (n - 1)
    return mean, math.sqrt(variance)


class BaselineStore:
    """Manages continuous behavioral baselines for users and hosts with database persistence."""

    def __init__(
        self,
        db_manager: DatabaseManager,
        min_events_threshold: int = 20,
        min_learning_period_hours: float = 24.0,
    ):
        self.db_manager = db_manager
        self.min_events_threshold = min_events_threshold
        self.min_learning_period_hours = min_learning_period_hours

        # In-memory caches for fast evaluation
        # entity_type -> entity_id -> metric -> dict
        self._cache: Dict[str, Dict[str, Dict[str, Any]]] = {
            "user": {},
            "host": {},
        }
        self.load_all_baselines()

    def load_all_baselines(self) -> None:
        """Load baseline records from database into memory cache."""
        try:
            with self.db_manager.session() as session:
                records = session.execute(select(BaselineModel)).scalars().all()
                for rec in records:
                    if rec.entity_type not in self._cache:
                        self._cache[rec.entity_type] = {}
                    if rec.entity_id not in self._cache[rec.entity_type]:
                        self._cache[rec.entity_type][rec.entity_id] = {}
                    self._cache[rec.entity_type][rec.entity_id][rec.metric] = rec.value
            logger.info(f"Loaded baselines from DB: {len(records)} metric records.")
        except Exception as e:
            logger.warning(f"Failed to load baselines from database: {e}")

    def save_metric(self, entity_type: str, entity_id: str, metric: str, value: Dict[str, Any]) -> None:
        """Persist or update metric in DB and update cache."""
        now = datetime.now(timezone.utc)
        if entity_type not in self._cache:
            self._cache[entity_type] = {}
        if entity_id not in self._cache[entity_type]:
            self._cache[entity_type][entity_id] = {}
        self._cache[entity_type][entity_id][metric] = value

        try:
            with self.db_manager.session() as session:
                rec = session.execute(
                    select(BaselineModel).where(
                        BaselineModel.entity_type == entity_type,
                        BaselineModel.entity_id == entity_id,
                        BaselineModel.metric == metric,
                    )
                ).scalar_one_or_none()

                if rec:
                    rec.value = value
                    rec.updated_at = now
                else:
                    session.add(
                        BaselineModel(
                            entity_type=entity_type,
                            entity_id=entity_id,
                            metric=metric,
                            value=value,
                            updated_at=now,
                        )
                    )
        except Exception as e:
            logger.error(f"Failed saving baseline metric {entity_type}:{entity_id}:{metric}: {e}")

    def learn_from_benign_events(self, events: List[Event]) -> None:
        """Update baselines using events that have been verified as benign."""
        for ev in events:
            now = datetime.now(timezone.utc)

            # Update User Baselines
            user = ev.normalized.get("user")
            if user and user not in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
                self._update_user_baseline(user, ev, now)

            # Update Host Baselines
            host = ev.host
            if host:
                self._update_host_baseline(host, ev, now)

    def _update_user_baseline(self, user: str, ev: Event, now: datetime) -> None:
        # 1. Profile / Observation count
        prof = self._cache.get("user", {}).get(user, {}).get("profile", {})
        count = prof.get("event_count", 0) + 1
        first_seen_str = prof.get("first_seen")
        first_seen = datetime.fromisoformat(first_seen_str) if first_seen_str else now
        prof_val = {
            "event_count": count,
            "first_seen": first_seen.isoformat(),
            "last_seen": now.isoformat(),
        }
        self.save_metric("user", user, "profile", prof_val)

        # 2. Active Hours
        hours_metric = self._cache.get("user", {}).get(user, {}).get("active_hours", {})
        active_hours = set(hours_metric.get("hours", []))
        active_hours.add(ev.timestamp.hour)
        self.save_metric("user", user, "active_hours", {"hours": sorted(list(active_hours))})

        # 3. Known Event Types
        types_metric = self._cache.get("user", {}).get(user, {}).get("known_event_types", {})
        known_types = set(types_metric.get("types", []))
        known_types.add(ev.event_type)
        self.save_metric("user", user, "known_event_types", {"types": sorted(list(known_types))})

        # 4. Known sudo usage
        if ev.event_type == "sudo_command":
            sudo_metric = self._cache.get("user", {}).get(user, {}).get("sudo_usage", {})
            has_used = True
            self.save_metric("user", user, "sudo_usage", {"has_used_sudo": has_used})

    def _update_host_baseline(self, host: str, ev: Event, now: datetime) -> None:
        # Profile
        prof = self._cache.get("host", {}).get(host, {}).get("profile", {})
        count = prof.get("event_count", 0) + 1
        first_seen_str = prof.get("first_seen")
        first_seen = datetime.fromisoformat(first_seen_str) if first_seen_str else now
        prof_val = {
            "event_count": count,
            "first_seen": first_seen.isoformat(),
            "last_seen": now.isoformat(),
        }
        self.save_metric("host", host, "profile", prof_val)

        # Known event types for host
        types_metric = self._cache.get("host", {}).get(host, {}).get("known_event_types", {})
        known_types = set(types_metric.get("types", []))
        known_types.add(ev.event_type)
        self.save_metric("host", host, "known_event_types", {"types": sorted(list(known_types))})

    def record_host_batch_count(self, host: str, batch_size: int) -> None:
        """Update rolling event volume statistics for a host."""
        rate_metric = self._cache.get("host", {}).get(host, {}).get("event_rate", {})
        history = rate_metric.get("history", [])
        history.append(float(batch_size))
        if len(history) > 100:
            history = history[-100:]

        mean, std = compute_mean_and_std(history)
        median, mad = compute_median_and_mad(history)
        val = {
            "history": history,
            "mean": mean,
            "std": std,
            "median": median,
            "mad": mad,
            "samples": len(history),
        }
        self.save_metric("host", host, "event_rate", val)

    def is_user_baseline_mature(self, user: str) -> bool:
        prof = self._cache.get("user", {}).get(user, {}).get("profile", {})
        count = prof.get("event_count", 0)
        first_seen_str = prof.get("first_seen")
        if not first_seen_str or count < self.min_events_threshold:
            return False

        try:
            first_seen = datetime.fromisoformat(first_seen_str)
            hours_elapsed = (datetime.now(timezone.utc) - first_seen).total_seconds() / 3600.0
            return hours_elapsed >= self.min_learning_period_hours or count >= self.min_events_threshold * 2
        except Exception:
            return False

    def is_host_baseline_mature(self, host: str) -> bool:
        rate = self._cache.get("host", {}).get(host, {}).get("event_rate", {})
        samples = rate.get("samples", 0)
        return samples >= 10

    def get_user_active_hours(self, user: str) -> Set[int]:
        hours_metric = self._cache.get("user", {}).get(user, {}).get("active_hours", {})
        return set(hours_metric.get("hours", []))

    def get_user_known_event_types(self, user: str) -> Set[str]:
        types_metric = self._cache.get("user", {}).get(user, {}).get("known_event_types", {})
        return set(types_metric.get("types", []))

    def get_known_sudo_users(self) -> Set[str]:
        sudo_users: Set[str] = set()
        user_cache = self._cache.get("user", {})
        for user, metrics in user_cache.items():
            if metrics.get("sudo_usage", {}).get("has_used_sudo", False):
                sudo_users.add(user)
        return sudo_users

    def get_host_event_rate_stats(self, host: str) -> Optional[Dict[str, float]]:
        return self._cache.get("host", {}).get(host, {}).get("event_rate")

    def is_host_continuous(self, host: str) -> bool:
        return self.is_host_baseline_mature(host)
