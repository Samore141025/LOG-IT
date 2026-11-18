from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY as PG_ARRAY, JSONB as PG_JSONB, UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import JSON, TypeDecorator, Uuid


class Base(DeclarativeBase):
    pass


# Dialect-portable JSON and ARRAY types
PortableJSON = PG_JSONB().with_variant(JSON(), "sqlite")
PortableUUID = PG_UUID(as_uuid=True).with_variant(Uuid(as_uuid=True), "sqlite")


class PortableUUIDArray(TypeDecorator):
    """PostgreSQL ARRAY of UUIDs with JSON serialization fallback for SQLite."""
    impl = PG_ARRAY(PG_UUID(as_uuid=True))
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_ARRAY(PG_UUID(as_uuid=True)))
        return dialect.type_descriptor(JSON())

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if dialect.name == "postgresql":
            return [str(v) if isinstance(v, uuid.UUID) else v for v in value]
        # In SQLite fallback, store as list of strings
        return [str(v) if isinstance(v, uuid.UUID) else v for v in value]

    def process_result_value(self, value, dialect):
        if value is None:
            return []
        out = []
        for v in value:
            if isinstance(v, uuid.UUID):
                out.append(v)
            elif isinstance(v, str):
                try:
                    out.append(uuid.UUID(v))
                except ValueError:
                    continue
        return out


class EventModel(Base):
    __tablename__ = "events"

    id: Mapped[uuid.UUID] = mapped_column(PortableUUID, primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    host: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    raw: Mapped[str] = mapped_column(Text, nullable=False)
    normalized: Mapped[Dict[str, Any]] = mapped_column(PortableJSON, nullable=False, default=dict)
    processed_by: Mapped[List[str]] = mapped_column(PortableJSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        Index("ix_events_unprocessed", "timestamp", "id"),
    )


class AgentFindingModel(Base):
    __tablename__ = "agent_findings"

    id: Mapped[uuid.UUID] = mapped_column(PortableUUID, primary_key=True, default=uuid.uuid4)
    agent: Mapped[str] = mapped_column(String(100), nullable=False, default="log_analysis", index=True)
    incident_id: Mapped[Optional[uuid.UUID]] = mapped_column(PortableUUID, nullable=True)
    verdict: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    rule: Mapped[str] = mapped_column(String(255), nullable=False)
    reasoning: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_event_ids: Mapped[List[uuid.UUID]] = mapped_column(PortableUUIDArray, nullable=False, default=list)
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    entities: Mapped[Dict[str, Any]] = mapped_column(PortableJSON, nullable=False, default=dict)
    dedupe_key: Mapped[str] = mapped_column(String(512), unique=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )


class AgentStateModel(Base):
    __tablename__ = "agent_state"

    agent: Mapped[str] = mapped_column(String(100), primary_key=True)
    cursor: Mapped[Optional[Dict[str, Any]]] = mapped_column(PortableJSON, nullable=True)
    last_heartbeat: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="idle")
    stats: Mapped[Dict[str, Any]] = mapped_column(PortableJSON, nullable=False, default=dict)


class AuditLogModel(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(PortableUUID, primary_key=True, default=uuid.uuid4)
    agent: Mapped[str] = mapped_column(String(100), nullable=False, default="log_analysis")
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    details: Mapped[Dict[str, Any]] = mapped_column(PortableJSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )


class BaselineModel(Base):
    __tablename__ = "baselines"

    entity_type: Mapped[str] = mapped_column(String(100), primary_key=True)
    entity_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    metric: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[Dict[str, Any]] = mapped_column(PortableJSON, nullable=False, default=dict)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
