from __future__ import annotations

import logging
import math
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.schemas import Event, Finding, SeverityEnum, VerdictEnum
from shugo_agents.log_analysis.detectors.base_detector import BaseDetector

logger = logging.getLogger(__name__)

# Earth radius in kilometers
EARTH_RADIUS_KM = 6371.0


def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Compute great-circle distance between two geographic coordinates in kilometers."""
    d_lat = math.radians(lat2 - lat1)
    d_lon = math.radians(lon2 - lon1)
    a = (
        math.sin(d_lat / 2.0) ** 2
        + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(d_lon / 2.0) ** 2
    )
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return EARTH_RADIUS_KM * c


class ImpossibleLoginDetector(BaseDetector):
    """Detects physically impossible travel between logins for the same user account."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("impossible_login", config)
        self.db_path: Optional[str] = config.get("geolite_city_db_path")
        self.max_speed_kmh: float = config.get("max_speed_kmh", 800.0)
        self.min_distance_km: float = config.get("min_distance_km", 200.0)
        self._reader: Any = None
        self._init_reader()

    def _init_reader(self) -> None:
        if not self.db_path:
            logger.info("ImpossibleLoginDetector: geolite_city_db_path not set. Skipping detector gracefully.")
            self.enabled = False
            return

        p = Path(self.db_path)
        if not p.is_file():
            logger.info(f"ImpossibleLoginDetector: Database file {self.db_path} not found. Skipping detector gracefully.")
            self.enabled = False
            return

        try:
            import geoip2.database
            self._reader = geoip2.database.Reader(str(p))
            logger.info(f"ImpossibleLoginDetector initialized with GeoLite2 database at {p}")
        except Exception as e:
            logger.warning(f"ImpossibleLoginDetector: Failed to load geoip2 reader: {e}. Skipping detector.")
            self.enabled = False

    def _lookup_ip_coords(self, ip: str) -> Optional[Tuple[float, float, str]]:
        """Return (lat, lon, location_summary) or None."""
        if not self._reader:
            return None
        try:
            resp = self._reader.city(ip)
            if resp.location and resp.location.latitude and resp.location.longitude:
                city = resp.city.name or "UnknownCity"
                country = resp.country.name or "UnknownCountry"
                return (resp.location.latitude, resp.location.longitude, f"{city}, {country}")
        except Exception:
            return None
        return None

    def analyze(self, events: List[Event], baseline: Any = None) -> List[Finding]:
        if not self.enabled or not self._reader:
            return []

        findings: List[Finding] = []

        success_logins = [
            e for e in events
            if e.event_type in ("ssh_success_login", "windows_success_login")
        ]

        if not success_logins:
            return []

        success_logins.sort(key=lambda x: x.timestamp)

        # Group by User
        user_logins: Dict[str, List[Event]] = defaultdict(list)
        for ev in success_logins:
            user = ev.normalized.get("user")
            ip = ev.normalized.get("source_ip")
            if user and ip and ip not in ("-", "127.0.0.1", "::1"):
                user_logins[user].append(ev)

        for user, ev_list in user_logins.items():
            if len(ev_list) < 2:
                continue

            for i in range(len(ev_list) - 1):
                ev1 = ev_list[i]
                ev2 = ev_list[i + 1]

                ip1 = ev1.normalized.get("source_ip")
                ip2 = ev2.normalized.get("source_ip")

                if not ip1 or not ip2 or ip1 == ip2:
                    continue

                coords1 = self._lookup_ip_coords(ip1)
                coords2 = self._lookup_ip_coords(ip2)

                if not coords1 or not coords2:
                    continue

                lat1, lon1, loc1 = coords1
                lat2, lon2, loc2 = coords2

                distance_km = haversine_distance_km(lat1, lon1, lat2, lon2)
                if distance_km < self.min_distance_km:
                    continue

                elapsed_seconds = abs((ev2.timestamp - ev1.timestamp).total_seconds())
                if elapsed_seconds <= 0:
                    speed_kmh = float("inf")
                else:
                    speed_kmh = (distance_km / elapsed_seconds) * 3600.0

                if speed_kmh > self.max_speed_kmh:
                    time_bucket = ev1.timestamp.strftime("%Y%m%d")
                    dedupe_key = self.make_dedupe_key(
                        "impossible_travel",
                        f"user:{user}",
                        time_bucket,
                        extra=f"{ip1}:{ip2}"
                    )

                    reasoning = (
                        f"Impossible travel detected for user '{user}': logged in from {ip1} ({loc1}) at "
                        f"{ev1.timestamp.isoformat()} and from {ip2} ({loc2}) at {ev2.timestamp.isoformat()}. "
                        f"Distance: {distance_km:.1f} km, Time elapsed: {elapsed_seconds / 60:.1f} min, "
                        f"Implied speed: {speed_kmh:.1f} km/h (threshold: {self.max_speed_kmh:.1f} km/h)."
                    )

                    finding = self.build_finding(
                        rule="T1078 - impossible_login_travel",
                        reasoning=reasoning,
                        verdict=VerdictEnum.SUSPICIOUS,
                        severity=SeverityEnum.HIGH,
                        confidence=0.92,
                        evidence_events=[ev1, ev2],
                        dedupe_key=dedupe_key,
                        mitre_technique="T1078",
                        users=[user],
                        ips=[ip1, ip2],
                    )
                    findings.append(finding)

        return findings
