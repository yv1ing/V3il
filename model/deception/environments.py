from datetime import datetime
from typing import Any

from sqlalchemy import Column, Index, JSON, UniqueConstraint
from sqlmodel import Field, SQLModel

from schema.deception.environments import (
    DeceptionArtifactKind,
    DeceptionContainerOwnership,
    DeceptionEvaluationStatus,
    DeceptionAdaptationMode,
    DeceptionEnvironmentStatus,
    DeceptionRevisionKind,
    DeceptionRevisionStatus,
    DeceptionRevisionStepStatus,
    DeceptionRiskLevel,
)
from schema.sandbox.containers import SandboxContainerEgressMode
from utils.sqlalchemy import enum_value_type, utc_datetime_column
from utils.time import utc_now


class DeceptionEnvironment(SQLModel, table=True):
    __tablename__ = "deception_environments"
    __table_args__ = (
        UniqueConstraint("sandbox_container_id", name="uq_deception_environment_container"),
        Index("ix_deception_environments_owner_status", "owner_id", "status"),
    )

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    description: str = ""
    persona: str = ""
    reference_urls: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    host_id: int = Field(foreign_key="managed_hosts.id", index=True, ondelete="RESTRICT")
    image_id: int = Field(foreign_key="sandbox_images.id", index=True, ondelete="RESTRICT")
    egress_mode: SandboxContainerEgressMode = Field(
        sa_column=Column(enum_value_type(SandboxContainerEgressMode, length=32), nullable=False, index=True)
    )
    egress_proxy_id: int | None = Field(
        default=None,
        foreign_key="egress_proxies.id",
        index=True,
        ondelete="RESTRICT",
    )
    sandbox_container_id: int | None = Field(
        default=None,
        foreign_key="sandbox_containers.id",
        index=True,
        ondelete="RESTRICT",
    )
    container_ownership: DeceptionContainerOwnership = Field(
        sa_column=Column(enum_value_type(DeceptionContainerOwnership, length=32), nullable=False, index=True)
    )
    services: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    status: DeceptionEnvironmentStatus = Field(
        default=DeceptionEnvironmentStatus.DRAFT,
        sa_column=Column(enum_value_type(DeceptionEnvironmentStatus, length=32), nullable=False, index=True),
    )
    applied_revision_id: int | None = Field(default=None, index=True)
    active_revision_id: int | None = Field(default=None, index=True)
    adaptation_mode: DeceptionAdaptationMode = Field(
        default=DeceptionAdaptationMode.POLICY_AUTO,
        sa_column=Column(enum_value_type(DeceptionAdaptationMode, length=32), nullable=False, index=True),
    )
    last_error: str = ""
    owner_id: int = Field(foreign_key="system_users.id", index=True, ondelete="RESTRICT")
    created_at: datetime = Field(default_factory=utc_now, sa_column=utc_datetime_column())
    updated_at: datetime = Field(default_factory=utc_now, sa_column=utc_datetime_column())

class DeceptionRevision(SQLModel, table=True):
    __tablename__ = "deception_revisions"
    __table_args__ = (
        UniqueConstraint("environment_id", "version", name="uq_deception_revision_version"),
        Index("ix_deception_revisions_environment_status", "environment_id", "status"),
    )

    id: int | None = Field(default=None, primary_key=True)
    environment_id: int = Field(foreign_key="deception_environments.id", index=True, ondelete="RESTRICT")
    version: int = Field(index=True)
    kind: DeceptionRevisionKind = Field(
        sa_column=Column(enum_value_type(DeceptionRevisionKind, length=32), nullable=False, index=True)
    )
    status: DeceptionRevisionStatus = Field(
        sa_column=Column(enum_value_type(DeceptionRevisionStatus, length=32), nullable=False, index=True)
    )
    rationale: str = ""
    target_persona: str = ""
    target_services: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    container_spec: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
    plan_snapshot: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
    plan_sha256: str = Field(default="", max_length=64, index=True)
    baseline_snapshot: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON, nullable=True))
    execution_checkpoint: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON, nullable=True))
    execution_container_id: int | None = Field(default=None, index=True)
    trigger_event_ids: list[int] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    trigger_signal_ids: list[int] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    engagement_goal: str = ""
    engagement_hypothesis: str = ""
    success_criteria: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    observation_window_seconds: int = Field(default=3600)
    observation_deadline: datetime | None = Field(
        default=None,
        sa_column=utc_datetime_column(nullable=True, index=True),
    )
    evaluation_status: DeceptionEvaluationStatus = Field(
        default=DeceptionEvaluationStatus.PENDING,
        sa_column=Column(enum_value_type(DeceptionEvaluationStatus, length=32), nullable=False, index=True),
    )
    evaluation_summary: str = ""
    source_incident_id: int | None = Field(default=None, foreign_key="threat_incidents.id", index=True, ondelete="RESTRICT")
    evaluation_task_id: int | None = Field(default=None, foreign_key="investigation_tasks.id", index=True, ondelete="RESTRICT")
    risk_level: DeceptionRiskLevel = Field(
        default=DeceptionRiskLevel.LOW,
        sa_column=Column(enum_value_type(DeceptionRiskLevel, length=32), nullable=False, index=True),
    )
    approval_reason: str = ""
    failure_reason: str = ""
    rollback_error: str = ""
    result: str = ""
    created_by_agent_code: str = Field(default="", index=True)
    created_from_session_id: str = Field(default="", index=True)
    created_at: datetime = Field(default_factory=utc_now, sa_column=utc_datetime_column())
    started_at: datetime | None = Field(default=None, sa_column=utc_datetime_column(nullable=True))
    resolved_at: datetime | None = Field(default=None, sa_column=utc_datetime_column(nullable=True))


class DeceptionRevisionStep(SQLModel, table=True):
    __tablename__ = "deception_revision_steps"
    __table_args__ = (
        UniqueConstraint("revision_id", "sequence", name="uq_deception_revision_step_sequence"),
        Index("ix_deception_revision_steps_revision_status", "revision_id", "status"),
    )

    id: int | None = Field(default=None, primary_key=True)
    revision_id: int = Field(foreign_key="deception_revisions.id", index=True, ondelete="RESTRICT")
    sequence: int = Field(index=True)
    kind: str = Field(index=True)
    target: str = ""
    parameters: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    expected_effect: str = ""
    apply_command: str = ""
    verify_command: str = ""
    rollback_command: str = ""
    timeout_seconds: int = Field(default=60)
    status: DeceptionRevisionStepStatus = Field(
        default=DeceptionRevisionStepStatus.PENDING,
        sa_column=Column(enum_value_type(DeceptionRevisionStepStatus, length=32), nullable=False, index=True),
    )
    apply_exit_code: int | None = None
    apply_output: str = ""
    verify_exit_code: int | None = None
    verify_output: str = ""
    rollback_exit_code: int | None = None
    rollback_output: str = ""
    before_state: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON, nullable=True))
    after_apply_state: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON, nullable=True))
    after_verify_state: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON, nullable=True))
    after_rollback_state: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON, nullable=True))
    error: str = ""
    started_at: datetime | None = Field(default=None, sa_column=utc_datetime_column(nullable=True))
    finished_at: datetime | None = Field(default=None, sa_column=utc_datetime_column(nullable=True))


class DeceptionArtifact(SQLModel, table=True):
    __tablename__ = "deception_artifacts"
    __table_args__ = (
        UniqueConstraint("revision_id", "fingerprint", name="uq_deception_artifact_revision_fingerprint"),
        Index("ix_deception_artifacts_environment_active", "environment_id", "active"),
    )

    id: int | None = Field(default=None, primary_key=True)
    environment_id: int = Field(foreign_key="deception_environments.id", index=True, ondelete="RESTRICT")
    revision_id: int = Field(foreign_key="deception_revisions.id", index=True, ondelete="RESTRICT")
    kind: DeceptionArtifactKind = Field(
        sa_column=Column(enum_value_type(DeceptionArtifactKind, length=32), nullable=False, index=True)
    )
    name: str = Field(max_length=255, index=True)
    locator: str = Field(max_length=4096)
    fingerprint: str = Field(max_length=512, index=True)
    description: str = ""
    active: bool = Field(default=True, index=True)
    created_by_agent_code: str = Field(default="", index=True)
    created_from_session_id: str = Field(default="", index=True)
    created_at: datetime = Field(default_factory=utc_now, sa_column=utc_datetime_column())
