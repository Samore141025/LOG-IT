from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class VerdictEnum(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class SeverityEnum(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventNormalized(BaseModel):
    timestamp: datetime
    host: str
    user: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    port: Optional[int] = None
    process: Optional[str] = None
    command: Optional[str] = None
    event_type: str
    status: Optional[str] = None
    http_method: Optional[str] = None
    http_uri: Optional[str] = None
    http_status: Optional[int] = None
    user_agent: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class Event(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    source: str
    host: str
    timestamp: datetime
    event_type: str
    raw: str
    normalized: Dict[str, Any] = Field(default_factory=dict)
    processed_by: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("timestamp", "created_at", mode="before")
    @classmethod
    def ensure_tz_aware(cls, v: Any) -> datetime:
        if isinstance(v, str):
            dt = datetime.fromisoformat(v)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        if isinstance(v, datetime):
            return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        return v


class FindingEntities(BaseModel):
    users: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    hosts: List[str] = Field(default_factory=list)


class Finding(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    agent: str = "log_analysis"
    incident_id: Optional[UUID] = None
    verdict: VerdictEnum
    severity: SeverityEnum
    confidence: float = Field(ge=0.0, le=1.0)
    rule: str
    reasoning: str
    evidence_event_ids: List[UUID] = Field(default_factory=list)
    mitre_technique: Optional[str] = None
    entities: FindingEntities = Field(default_factory=FindingEntities)
    remediation: List[str] = Field(default_factory=list)
    dedupe_key: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("created_at", mode="before")
    @classmethod
    def ensure_tz_aware(cls, v: Any) -> datetime:
        if isinstance(v, str):
            dt = datetime.fromisoformat(v)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        if isinstance(v, datetime):
            return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        return v


class LLMTriageOutput(BaseModel):
    verdict: VerdictEnum
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    false_positive_hypothesis: str
    validated_evidence_ids: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)


class AgentState(BaseModel):
    agent: str
    cursor: Optional[Dict[str, Any]] = None
    last_heartbeat: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "idle"
    stats: Dict[str, Any] = Field(default_factory=dict)


class AuditLog(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    agent: str = "log_analysis"
    action: str
    details: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class BaselineRecord(BaseModel):
    entity_type: str
    entity_id: str
    metric: str
    value: Dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
