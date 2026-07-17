from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, Column, Index, JSON
from sqlmodel import Field, SQLModel

from schema.threat.investigations import (
    AuditActorType,
    AuditEventKind,
    InvestigationTaskPriority,
    InvestigationTaskStatus,
)
from utils.sqlalchemy import enum_value_type


class InvestigationTask(SQLModel, table=True):
    __tablename__ = "investigation_tasks"
    __table_args__ = (
        Index("ix_investigation_tasks_incident_status", "incident_id", "status"),
        Index("ix_investigation_tasks_incident_assignee", "incident_id", "assignee_agent_code"),
    )

    id: int | None = Field(default=None, primary_key=True)
    incident_id: int = Field(foreign_key="threat_incidents.id", index=True, ondelete="CASCADE")
    title: str = Field(index=True)
    status: InvestigationTaskStatus = Field(
        sa_column=Column(enum_value_type(InvestigationTaskStatus, length=32), nullable=False, index=True)
    )
    priority: InvestigationTaskPriority = Field(
        sa_column=Column(enum_value_type(InvestigationTaskPriority, length=32), nullable=False, index=True)
    )
    assignee_agent_code: str = Field(index=True)
    objective: str = ""
    completion_criteria: str = ""
    result_summary: str = ""
    blocker_reason: str = ""
    created_by_agent_code: str = Field(default="", index=True)
    created_from_session_id: str = Field(default="", index=True)
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)


class InvestigationTaskDependency(SQLModel, table=True):
    __tablename__ = "investigation_task_dependencies"

    task_id: int = Field(foreign_key="investigation_tasks.id", primary_key=True, ondelete="CASCADE")
    depends_on_task_id: int = Field(
        foreign_key="investigation_tasks.id",
        primary_key=True,
        ondelete="CASCADE",
    )


class InvestigationEvidence(SQLModel, table=True):
    __tablename__ = "investigation_evidence"
    __table_args__ = (Index("ix_investigation_evidence_task_created", "task_id", "created_at"),)

    id: int | None = Field(default=None, primary_key=True)
    task_id: int = Field(foreign_key="investigation_tasks.id", index=True, ondelete="CASCADE")
    statement: str = Field(index=True)
    analysis: str = ""
    related_evidence_ids: list[int] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    created_by_agent_code: str = Field(default="", index=True)
    created_from_session_id: str = Field(default="", index=True)
    created_at: datetime = Field(default_factory=datetime.now)


class InvestigationTaskEvent(SQLModel, table=True):
    __tablename__ = "investigation_task_events"
    __table_args__ = (
        Index("ix_investigation_task_events_event", "event_id"),
        Index("ix_investigation_task_events_evidence", "evidence_id"),
    )

    task_id: int = Field(foreign_key="investigation_tasks.id", primary_key=True, ondelete="CASCADE")
    event_id: int = Field(foreign_key="behavior_events.id", primary_key=True, ondelete="CASCADE")
    evidence_id: int | None = Field(
        default=None,
        foreign_key="investigation_evidence.id",
        index=True,
        ondelete="RESTRICT",
    )
    assigned_at: datetime = Field(default_factory=datetime.now)
    covered_at: datetime | None = None


class AuditEvent(SQLModel, table=True):
    __tablename__ = "audit_events"
    __table_args__ = (
        CheckConstraint(
            "incident_id IS NOT NULL OR environment_id IS NOT NULL OR task_id IS NOT NULL OR detection_rule_id IS NOT NULL OR managed_host_id IS NOT NULL",
            name="ck_audit_event_context",
        ),
        Index("ix_audit_events_incident_created", "incident_id", "created_at"),
        Index("ix_audit_events_environment_created", "environment_id", "created_at"),
        Index("ix_audit_events_task_created", "task_id", "created_at"),
    )

    id: int | None = Field(default=None, primary_key=True)
    incident_id: int | None = Field(
        default=None,
        foreign_key="threat_incidents.id",
        index=True,
        ondelete="CASCADE",
    )
    environment_id: int | None = Field(
        default=None,
        foreign_key="deception_environments.id",
        index=True,
        ondelete="CASCADE",
    )
    task_id: int | None = Field(
        default=None,
        foreign_key="investigation_tasks.id",
        index=True,
        ondelete="SET NULL",
    )
    detection_rule_id: int | None = Field(
        default=None,
        foreign_key="detection_rules.id",
        index=True,
        ondelete="CASCADE",
    )
    managed_host_id: int | None = Field(
        default=None,
        foreign_key="managed_hosts.id",
        index=True,
        ondelete="CASCADE",
    )
    kind: AuditEventKind = Field(
        sa_column=Column(enum_value_type(AuditEventKind, length=64), nullable=False, index=True)
    )
    actor_type: AuditActorType = Field(
        sa_column=Column(enum_value_type(AuditActorType, length=32), nullable=False, index=True)
    )
    actor_code: str = Field(default="", index=True)
    session_id: str = Field(default="", index=True)
    object_type: str = Field(default="", max_length=64, index=True)
    object_id: str = Field(default="", max_length=128, index=True)
    summary: str = ""
    details: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
    created_at: datetime = Field(default_factory=datetime.now, index=True)
