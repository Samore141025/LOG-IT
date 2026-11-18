from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set
from uuid import UUID

from sqlalchemy import String, and_, or_, select

from core.config import Config
from core.db.models import AgentFindingModel, AgentStateModel, EventModel
from core.db.session import DatabaseManager
from core.schemas import Event, Finding, SeverityEnum
from shugo_agents.base.base_agent import BaseAgent
from shugo_agents.log_analysis.baseline import BaselineStore
from shugo_agents.log_analysis.detectors import (
    BaseDetector,
    BruteForceDetector,
    ImpossibleLoginDetector,
    LogTamperingDetector,
    PasswordSprayDetector,
    PrivilegeEscalationDetector,
    RareEventDetector,
    SigmaEngineDetector,
    SuspiciousCommandsDetector,
    UEBADetector,
    UnusualHoursDetector,
    WebAttacksDetector,
)
from shugo_agents.log_analysis.forensics import ForensicLedger, mask_sensitive_data
from shugo_agents.log_analysis.ingest.os_stream import LiveOSStreamCollector
from shugo_agents.log_analysis.ingest.tailer import LogTailer
from shugo_agents.log_analysis.llm_reasoner import LLMReasoner
from shugo_agents.log_analysis.notifications import SOCNotifier
from shugo_agents.log_analysis.soar import ActiveDefenseSOAR
from shugo_agents.log_analysis.threat_intel import ThreatIntelEnricher

logger = logging.getLogger(__name__)


class LogAnalysisAgent(BaseAgent):
    """Autonomous Log Analysis Agent (Agent #4) for SHUGO cybersecurity system."""

    def __init__(self, config_path: Optional[str | Path] = None):
        # 1. Load config
        if not config_path:
            config_path = Path(__file__).parent / "config.yaml"
        self.app_config = Config.load(config_path)
        self.raw_config = self.app_config.raw_yaml

        # 2. Database manager with retry & backoff
        db_manager = DatabaseManager(self.app_config.database)
        db_manager.check_connection_with_retry(max_retries=2, base_delay=0.1)
        db_manager.init_tables()

        super().__init__(agent_name=self.app_config.runtime.agent_name, db_manager=db_manager)

        # 3. Baseline store
        base_cfg = self.raw_config.get("baseline", {})
        self.baseline_store = BaselineStore(
            db_manager=self.db_manager,
            min_events_threshold=base_cfg.get("min_events_threshold", 20),
            min_learning_period_hours=base_cfg.get("min_learning_period_hours", 24.0),
        )

        # 4. LLM reasoner
        self.reasoner = LLMReasoner(
            gemini_config=self.app_config.gemini,
            redaction_config=self.app_config.redaction,
        )

        # 5. Initialize detectors
        self.detectors: List[BaseDetector] = self._init_detectors()

        # 6. Temporary Log Tailer (if enabled)
        self.tailer: Optional[LogTailer] = None
        ingest_cfg = self.raw_config.get("ingest", {})
        if ingest_cfg.get("enabled", False):
            watched = ingest_cfg.get("watched_files", {})
            watched_dirs = ingest_cfg.get("watched_directories", ["logs_to_analyze"])
            state_file = ingest_cfg.get("state_file_path", "tailer_state.json")
            self.tailer = LogTailer(
                db_manager=self.db_manager,
                watched_files=watched,
                watched_directories=watched_dirs,
                state_file_path=state_file,
                batch_size=ingest_cfg.get("batch_size", 200),
            )
            logger.info(f"Temporary LogTailer active for files: {list(watched.keys())}")

        # 7. Enterprise SOC modules (SOAR, Threat Intel, Forensics, Notifications, OS Collector)
        self.threat_intel = ThreatIntelEnricher()
        self.soar = ActiveDefenseSOAR(dry_run=not self.raw_config.get("soar", {}).get("auto_remediate", False))
        self.notifier = SOCNotifier()
        self.forensic_ledger = ForensicLedger()
        self.os_collector = LiveOSStreamCollector()

    def _init_detectors(self) -> List[BaseDetector]:
        det_cfg = self.raw_config.get("detectors", {})
        detectors: List[BaseDetector] = [
            BruteForceDetector(det_cfg.get("brute_force", {})),
            PasswordSprayDetector(det_cfg.get("password_spray", {})),
            ImpossibleLoginDetector(det_cfg.get("impossible_login", {})),
            UnusualHoursDetector(det_cfg.get("unusual_hours", {})),
            PrivilegeEscalationDetector(det_cfg.get("privilege_escalation", {})),
            SuspiciousCommandsDetector(det_cfg.get("suspicious_commands", {})),
            WebAttacksDetector(det_cfg.get("web_attacks", {})),
            LogTamperingDetector(det_cfg.get("log_tampering", {})),
            RareEventDetector(det_cfg.get("rare_event", {})),
            SigmaEngineDetector(det_cfg.get("sigma_engine", {})),
            UEBADetector(det_cfg.get("ueba", {})),
        ]
        active = [d.name for d in detectors if d.enabled]
        logger.info(f"Initialized {len(active)} active detectors: {active}")
        return detectors

    def step(self) -> int:
        """Executes one autonomous processing cycle: ingest -> fetch -> detect -> triage -> persist."""
        # 1. Ingest newly available lines if temporary tailer is active
        if self.tailer:
            try:
                self.tailer.tail_step()
            except Exception as e:
                logger.error(f"Tailer step error: {e}", exc_info=True)

        # 1b. Ingest live OS kernel events if available
        try:
            live_events = self.os_collector.poll_new_events()
            if live_events:
                with self.db_manager.session() as session:
                    for ev in live_events:
                        ev.raw = mask_sensitive_data(ev.raw)
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
                            )
                        )
        except Exception as e:
            logger.debug(f"Live OS stream collection note: {e}")

        # 2. Fetch batch of unprocessed events from events table
        events = self._fetch_unprocessed_batch()
        if not events:
            return 0

        logger.info(f"Fetched {len(events)} unprocessed events for analysis.")

        # 3. Analyze events across all enabled detectors (fail-safe per detector)
        all_findings: List[Finding] = []
        findings_to_evidence: Dict[str, List[Event]] = {}

        for detector in self.detectors:
            if not detector.enabled:
                continue
            try:
                det_findings = detector.analyze(events, baseline=self.baseline_store)
                for f in det_findings:
                    all_findings.append(f)
                    # Map finding dedupe_key to relevant evidence events for LLM triage
                    evidence = [e for e in events if e.id in f.evidence_event_ids]
                    findings_to_evidence[f.dedupe_key] = evidence
            except Exception as e:
                logger.error(
                    f"Detector '{detector.name}' failed while analyzing batch: {e}. Skipping.",
                    exc_info=True,
                )
                self.record_audit("detector_error", {"detector": detector.name, "error": str(e)})

        # 4. Optional LLM reasoning / triage for ambiguous or critical findings
        triaged_findings: List[Finding] = []
        for finding in all_findings:
            evidence = findings_to_evidence.get(finding.dedupe_key, [])
            try:
                triaged = self.reasoner.triage_finding(finding, evidence)
                triaged_findings.append(triaged)
            except Exception as e:
                logger.warning(f"Reasoner triage error for finding {finding.rule}: {e}. Retaining rule finding.")
                triaged_findings.append(finding)

        # 4b. Threat intelligence enrichment
        for f in triaged_findings:
            if f.entities and f.entities.ips:
                for ip in f.entities.ips:
                    intel = self.threat_intel.enrich_ip(ip)
                    if intel.get("threat_level") == "MALICIOUS":
                        f.confidence = min(1.0, f.confidence + 0.08)

        # 5. Persist findings, update baselines, and advance cursor atomically
        newly_created_findings = self._persist_batch_atomic(events, triaged_findings)

        # 5b. Record batch in cryptographic tamper-proof ledger
        self.forensic_ledger.record_batch([ev.id for ev in events], newly_created_findings)

        # 5c. Dispatch real-time SOC incident notifications & SOAR containment
        if newly_created_findings > 0:
            for f in triaged_findings:
                if f.severity in (SeverityEnum.MEDIUM, SeverityEnum.HIGH, SeverityEnum.CRITICAL):
                    self.notifier.dispatch_alert({
                        "rule": f.rule,
                        "severity": f.severity.value,
                        "verdict": f.verdict.value,
                        "mitre_technique": f.mitre_technique,
                        "reasoning": f.reasoning,
                        "entities": {
                            "ips": f.entities.ips if f.entities else [],
                            "users": f.entities.users if f.entities else [],
                            "hosts": f.entities.hosts if f.entities else [],
                        },
                    })
                    # SOAR auto-remediation if configured
                    if self.raw_config.get("soar", {}).get("auto_remediate", False) and f.entities and f.entities.ips:
                        for ip in f.entities.ips:
                            self.soar.execute_containment(ip, reason=f"Auto-Remediated: {f.rule}")

        # 6. Update agent metrics
        self.stats["processed_events_total"] += len(events)
        self.stats["findings_generated_total"] += newly_created_findings

        if newly_created_findings > 0:
            self.record_audit(
                "batch_findings_created",
                {"count": newly_created_findings, "processed_events": len(events)},
            )

        return len(events)

    def _fetch_unprocessed_batch(self) -> List[Event]:
        """Fetch next batch of events where 'log_analysis' is not in processed_by."""
        batch_size = self.app_config.runtime.batch_size
        events: List[Event] = []

        try:
            with self.db_manager.session() as session:
                base_query = select(EventModel).where(
                    ~EventModel.processed_by.cast(String).contains(self.agent_name)
                )

                records: Sequence[EventModel] = []
                # Resume from cursor if available
                if self.cursor and "last_timestamp" in self.cursor and "last_id" in self.cursor:
                    try:
                        cursor_ts = datetime.fromisoformat(self.cursor["last_timestamp"])
                        cursor_id = UUID(self.cursor["last_id"])
                        cursor_query = base_query.where(
                            or_(
                                EventModel.timestamp > cursor_ts,
                                and_(EventModel.timestamp == cursor_ts, EventModel.id > cursor_id),
                            )
                        ).order_by(EventModel.timestamp.asc(), EventModel.id.asc()).limit(batch_size)
                        records = session.execute(cursor_query).scalars().all()
                    except Exception as e:
                        logger.warning(f"Malformed cursor {self.cursor}: {e}. Querying without cursor.")

                # If no events found past cursor, fetch any unprocessed events (e.g. historical log files)
                if not records:
                    records = session.execute(
                        base_query.order_by(EventModel.timestamp.asc(), EventModel.id.asc()).limit(batch_size)
                    ).scalars().all()

                for r in records:
                    processed_list = r.processed_by if isinstance(r.processed_by, list) else []
                    # Filter out already processed or quarantined events
                    if self.agent_name in processed_list or any("quarantine" in p for p in processed_list):
                        continue

                    try:
                        ev = Event(
                            id=r.id,
                            source=r.source,
                            host=r.host,
                            timestamp=r.timestamp,
                            event_type=r.event_type,
                            raw=r.raw,
                            normalized=r.normalized if isinstance(r.normalized, dict) else {},
                            processed_by=processed_list,
                            created_at=r.created_at,
                        )
                        events.append(ev)
                    except Exception as e:
                        # Poison event: mark quarantined in database immediately
                        logger.error(f"Poison event detected (ID={r.id}): {e}. Quarantining.")
                        self._quarantine_poison_event(r.id, str(e))

        except Exception as e:
            logger.error(f"Error fetching unprocessed events batch: {e}", exc_info=True)

        return events

    def _quarantine_poison_event(self, event_id: UUID, reason: str) -> None:
        """Mark poison event as quarantined to prevent infinite retry loops."""
        try:
            with self.db_manager.session() as session:
                model = session.get(EventModel, event_id)
                if model:
                    current = list(model.processed_by or [])
                    current.append(f"quarantine:{reason[:50]}")
                    model.processed_by = current
        except Exception as e:
            logger.error(f"Failed to quarantine poison event {event_id}: {e}")

    def _persist_batch_atomic(self, events: List[Event], findings: List[Finding]) -> int:
        """Atomically insert findings, update event processed status, and advance cursor."""
        if not events:
            return 0

        last_ev = events[-1]
        new_cursor = {
            "last_timestamp": last_ev.timestamp.isoformat(),
            "last_id": str(last_ev.id),
        }

        # Identify which events are part of findings
        flagged_event_ids: Set[UUID] = set()
        for f in findings:
            flagged_event_ids.update(f.evidence_event_ids)

        # Benign events are those not involved in any suspicious or malicious finding
        benign_events = [e for e in events if e.id not in flagged_event_ids]
        self.baseline_store.learn_from_benign_events(benign_events)

        newly_inserted_findings_count = 0

        with self.db_manager.session() as session:
            # 1. Deduplicate and insert findings
            for f in findings:
                existing = session.execute(
                    select(AgentFindingModel).where(AgentFindingModel.dedupe_key == f.dedupe_key)
                ).scalar_one_or_none()

                entities_payload = f.entities.model_dump()
                if f.remediation:
                    entities_payload["remediation"] = f.remediation

                if not existing:
                    finding_model = AgentFindingModel(
                        id=f.id,
                        agent=self.agent_name,
                        incident_id=f.incident_id,
                        verdict=f.verdict.value,
                        severity=f.severity.value,
                        confidence=f.confidence,
                        rule=f.rule,
                        reasoning=f.reasoning,
                        evidence_event_ids=f.evidence_event_ids,
                        mitre_technique=f.mitre_technique,
                        entities=entities_payload,
                        dedupe_key=f.dedupe_key,
                        created_at=f.created_at,
                    )
                    session.add(finding_model)
                    newly_inserted_findings_count += 1
                else:
                    # Idempotent: Update verdict or confidence if escalated
                    if f.severity == SeverityEnum.CRITICAL and existing.severity != SeverityEnum.CRITICAL.value:
                        existing.severity = f.severity.value
                        existing.verdict = f.verdict.value
                        existing.reasoning = f.reasoning
                        existing.entities = entities_payload

            # 2. Mark all events in this batch as processed by log_analysis
            event_ids = [e.id for e in events]
            db_events = session.execute(
                select(EventModel).where(EventModel.id.in_(event_ids))
            ).scalars().all()

            for db_ev in db_events:
                curr_list = list(db_ev.processed_by or [])
                if self.agent_name not in curr_list:
                    curr_list.append(self.agent_name)
                    db_ev.processed_by = curr_list

            # 3. Advance cursor in agent_state table
            state_record = session.execute(
                select(AgentStateModel).where(AgentStateModel.agent == self.agent_name)
            ).scalar_one_or_none()

            now = datetime.now(timezone.utc)
            if state_record:
                state_record.cursor = new_cursor
                state_record.last_heartbeat = now
                state_record.stats = self.stats
            else:
                session.add(
                    AgentStateModel(
                        agent=self.agent_name,
                        cursor=new_cursor,
                        last_heartbeat=now,
                        status="running",
                        stats=self.stats,
                    )
                )

        self.cursor = new_cursor
        return newly_inserted_findings_count
