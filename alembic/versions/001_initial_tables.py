"""Initial tables for SHUGO log analysis

Revision ID: 001_initial_tables
Revises: 
Create Date: 2026-11-18

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "001_initial_tables"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # events table
    op.create_table(
        "events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("source", sa.String(255), nullable=False),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("raw", sa.Text(), nullable=False),
        sa.Column("normalized", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("processed_by", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_events_source", "events", ["source"])
    op.create_index("ix_events_host", "events", ["host"])
    op.create_index("ix_events_timestamp", "events", ["timestamp"])
    op.create_index("ix_events_event_type", "events", ["event_type"])
    op.create_index("ix_events_unprocessed", "events", ["timestamp", "id"])

    # agent_findings table
    op.create_table(
        "agent_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("agent", sa.String(100), nullable=False),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("verdict", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(50), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("rule", sa.String(255), nullable=False),
        sa.Column("reasoning", sa.Text(), nullable=False),
        sa.Column("evidence_event_ids", postgresql.ARRAY(postgresql.UUID(as_uuid=True)), nullable=False),
        sa.Column("mitre_technique", sa.String(100), nullable=True),
        sa.Column("entities", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("dedupe_key", sa.String(512), unique=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_agent_findings_agent", "agent_findings", ["agent"])
    op.create_index("ix_agent_findings_verdict", "agent_findings", ["verdict"])
    op.create_index("ix_agent_findings_severity", "agent_findings", ["severity"])
    op.create_index("ix_agent_findings_dedupe_key", "agent_findings", ["dedupe_key"])

    # agent_state table
    op.create_table(
        "agent_state",
        sa.Column("agent", sa.String(100), primary_key=True),
        sa.Column("cursor", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("last_heartbeat", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(50), nullable=False),
        sa.Column("stats", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    )

    # audit_logs table
    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("agent", sa.String(100), nullable=False),
        sa.Column("action", sa.String(255), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # baselines table
    op.create_table(
        "baselines",
        sa.Column("entity_type", sa.String(100), primary_key=True),
        sa.Column("entity_id", sa.String(255), primary_key=True),
        sa.Column("metric", sa.String(100), primary_key=True),
        sa.Column("value", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("baselines")
    op.drop_table("audit_logs")
    op.drop_table("agent_state")
    op.drop_table("agent_findings")
    op.drop_table("events")
