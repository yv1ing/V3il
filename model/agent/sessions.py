from datetime import datetime

from sqlalchemy import BigInteger, Boolean, CheckConstraint, Column, DateTime, Index, JSON, Text, UniqueConstraint, text
from sqlmodel import Field, SQLModel

from schema.agent.types import (
    AgentAttemptStatus,
    AgentCancellationMode,
    AgentCode,
    AgentContextItemStatus,
    AgentContextKind,
    AgentRunWaitReason,
    AgentRunStatus,
    AgentSegmentKind,
    AgentSegmentStatus,
    AgentSessionStatus,
    AgentToolInvocationStatus,
    AgentTriggerKind,
    SessionType,
)
from schema.runtime import RuntimeContinuationDisposition
from utils.sqlalchemy import enum_value_type
from utils.time import utc_now


class AgentSession(SQLModel, table=True):
    __tablename__ = "agent_sessions"
    __table_args__ = (
        CheckConstraint(
            "(session_type = 'chat' AND incident_id IS NULL AND environment_id IS NULL) OR "
            "(session_type = 'incident' AND incident_id IS NOT NULL AND environment_id IS NULL) OR "
            "(session_type = 'environment' AND incident_id IS NULL AND environment_id IS NOT NULL)",
            name="ck_agent_session_scope",
        ),
        Index("uq_agent_session_incident", "incident_id", unique=True, postgresql_where=text("incident_id IS NOT NULL")),
        Index("uq_agent_session_environment", "environment_id", unique=True, postgresql_where=text("environment_id IS NOT NULL")),
        Index("ix_agent_sessions_owner_updated", "owner_id", "updated_at"),
        CheckConstraint(
            "(status = 'active' AND archived_at IS NULL) OR "
            "(status = 'archived' AND archived_at IS NOT NULL)",
            name="ck_agent_session_archive_state",
        ),
        CheckConstraint(
            "(selected_sandbox_container_id IS NULL AND selected_sandbox_generation = 0) OR "
            "(selected_sandbox_container_id IS NOT NULL AND selected_sandbox_generation > 0)",
            name="ck_agent_session_sandbox_binding",
        ),
        CheckConstraint("next_event_seq > 0", name="ck_agent_session_next_event_seq"),
    )

    id: str = Field(primary_key=True, max_length=36)
    session_type: SessionType = Field(
        sa_column=Column(enum_value_type(SessionType, length=24), nullable=False, index=True)
    )
    status: AgentSessionStatus = Field(
        default=AgentSessionStatus.ACTIVE,
        sa_column=Column(enum_value_type(AgentSessionStatus, length=24), nullable=False, index=True),
    )
    title: str = Field(default="", max_length=80)
    primary_agent_code: AgentCode = Field(
        default=AgentCode.CSO,
        sa_column=Column(enum_value_type(AgentCode, length=16), nullable=False, index=True),
    )
    owner_id: int = Field(foreign_key="system_users.id", index=True, ondelete="RESTRICT")
    incident_id: int | None = Field(default=None, foreign_key="threat_incidents.id", ondelete="RESTRICT")
    environment_id: int | None = Field(default=None, foreign_key="deception_environments.id", ondelete="RESTRICT")
    selected_sandbox_container_id: int | None = Field(
        default=None,
        foreign_key="sandbox_containers.id",
        ondelete="RESTRICT",
    )
    selected_sandbox_generation: int = Field(default=0, sa_column=Column(BigInteger, nullable=False))
    next_event_seq: int = Field(default=1, sa_column=Column(BigInteger, nullable=False))
    created_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))
    updated_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False, index=True))
    archived_at: datetime | None = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))


class AgentContext(SQLModel, table=True):
    __tablename__ = "agent_contexts"
    __table_args__ = (
        Index(
            "uq_agent_main_context",
            "session_id",
            "agent_code",
            unique=True,
            postgresql_where=text("kind = 'main'"),
        ),
        CheckConstraint(
            "(kind = 'main' AND parent_context_id IS NULL) OR "
            "(kind = 'delegation' AND parent_context_id IS NOT NULL)",
            name="ck_agent_context_parent",
        ),
        CheckConstraint("next_item_seq > 0", name="ck_agent_context_next_item_seq"),
    )

    id: str = Field(primary_key=True, max_length=36)
    session_id: str = Field(foreign_key="agent_sessions.id", index=True, ondelete="RESTRICT")
    agent_code: AgentCode = Field(sa_column=Column(enum_value_type(AgentCode, length=16), nullable=False, index=True))
    kind: AgentContextKind = Field(sa_column=Column(enum_value_type(AgentContextKind, length=24), nullable=False))
    parent_context_id: str | None = Field(default=None, foreign_key="agent_contexts.id", ondelete="RESTRICT")
    next_item_seq: int = Field(default=1, sa_column=Column(BigInteger, nullable=False))
    created_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))


class AgentRun(SQLModel, table=True):
    __tablename__ = "agent_runs"
    __table_args__ = (
        Index("ix_agent_runs_session_queue", "session_id", "status", "queued_at", "id"),
        Index(
            "uq_agent_run_source_key",
            "session_id",
            "source_key",
            unique=True,
            postgresql_where=text("source_key <> ''"),
        ),
        Index(
            "uq_agent_foreground_active",
            "session_id",
            unique=True,
            postgresql_where=text("is_foreground AND status IN ('running', 'waiting')"),
        ),
        CheckConstraint(
            "(status = 'waiting' AND wait_reason IS NOT NULL AND wait_reference_id IS NOT NULL "
            "AND wait_reference_id <> '') OR "
            "(status <> 'waiting' AND wait_reason IS NULL AND wait_reference_id IS NULL)",
            name="ck_agent_run_wait_state",
        ),
        CheckConstraint(
            "(status IN ('succeeded', 'failed', 'canceled') AND finished_at IS NOT NULL) OR "
            "(status NOT IN ('succeeded', 'failed', 'canceled') AND finished_at IS NULL)",
            name="ck_agent_run_terminal_state",
        ),
        CheckConstraint(
            "(continuation_disposition IS NULL AND continuation_resolved_at IS NULL) OR "
            "(continuation_disposition IS NOT NULL AND continuation_resolved_at IS NOT NULL)",
            name="ck_agent_run_continuation_state",
        ),
        CheckConstraint(
            "(parent_run_id IS NULL AND is_foreground) OR "
            "(parent_run_id IS NOT NULL AND NOT is_foreground)",
            name="ck_agent_run_role",
        ),
        CheckConstraint(
            "parent_run_id IS NOT NULL OR continuation_disposition IS NULL",
            name="ck_agent_run_child_continuation",
        ),
        CheckConstraint(
            "(sandbox_container_id IS NULL AND sandbox_generation = 0) OR "
            "(sandbox_container_id IS NOT NULL AND sandbox_generation > 0)",
            name="ck_agent_run_sandbox_binding",
        ),
        CheckConstraint("trigger_revision > 0", name="ck_agent_run_trigger_revision"),
        CheckConstraint(
            "(cancel_requested_at IS NULL AND cancel_requested_by = '' AND cancel_requested_mode IS NULL) OR "
            "(cancel_requested_at IS NOT NULL AND cancel_requested_by <> '' AND cancel_requested_mode IS NOT NULL)",
            name="ck_agent_run_cancel_request",
        ),
        CheckConstraint(
            "(status = 'canceled' AND canceled_at IS NOT NULL AND canceled_by <> '') OR "
            "(status <> 'canceled' AND canceled_at IS NULL AND canceled_by = '')",
            name="ck_agent_run_canceled_state",
        ),
    )

    id: str = Field(primary_key=True, max_length=36)
    session_id: str = Field(foreign_key="agent_sessions.id", index=True, ondelete="RESTRICT")
    context_id: str = Field(foreign_key="agent_contexts.id", index=True, ondelete="RESTRICT")
    parent_run_id: str | None = Field(default=None, foreign_key="agent_runs.id", index=True, ondelete="RESTRICT")
    agent_code: AgentCode = Field(sa_column=Column(enum_value_type(AgentCode, length=16), nullable=False, index=True))
    status: AgentRunStatus = Field(sa_column=Column(enum_value_type(AgentRunStatus, length=24), nullable=False, index=True))
    trigger_kind: AgentTriggerKind = Field(sa_column=Column(enum_value_type(AgentTriggerKind, length=32), nullable=False))
    trigger: dict = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
    trigger_revision: int = Field(default=1, ge=1, sa_column=Column(BigInteger, nullable=False))
    source_key: str = Field(default="", max_length=255)
    is_foreground: bool = Field(default=True, sa_column=Column(Boolean, nullable=False))
    investigation_task_id: int | None = Field(default=None, foreign_key="investigation_tasks.id", ondelete="RESTRICT")
    environment_revision_id: int | None = Field(default=None, foreign_key="deception_revisions.id", ondelete="RESTRICT")
    sandbox_container_id: int | None = Field(default=None, foreign_key="sandbox_containers.id", ondelete="RESTRICT")
    sandbox_generation: int = Field(default=0, sa_column=Column(BigInteger, nullable=False))
    wait_reason: AgentRunWaitReason | None = Field(
        default=None,
        sa_column=Column(enum_value_type(AgentRunWaitReason, length=32), nullable=True),
    )
    wait_reference_id: str | None = Field(default=None, max_length=64)
    error_code: str = Field(default="", max_length=96)
    error_message: str = ""
    result_summary: str = ""
    continuation_disposition: RuntimeContinuationDisposition | None = Field(
        default=None,
        sa_column=Column(enum_value_type(RuntimeContinuationDisposition, length=24), nullable=True),
    )
    continuation_resolved_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    queued_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))
    started_at: datetime | None = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))
    finished_at: datetime | None = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))
    cancel_requested_at: datetime | None = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))
    cancel_requested_by: str = Field(default="", max_length=128)
    cancel_requested_mode: AgentCancellationMode | None = Field(
        default=None,
        sa_column=Column(enum_value_type(AgentCancellationMode, length=24), nullable=True),
    )
    canceled_at: datetime | None = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))
    canceled_by: str = Field(default="", max_length=128)


class AgentRunAttempt(SQLModel, table=True):
    __tablename__ = "agent_run_attempts"
    __table_args__ = (
        UniqueConstraint("run_id", "ordinal", name="uq_agent_run_attempt_ordinal"),
        Index(
            "uq_agent_run_attempt_active",
            "run_id",
            unique=True,
            postgresql_where=text("status = 'running'"),
        ),
        CheckConstraint(
            "(status = 'running' AND finished_at IS NULL) OR "
            "(status <> 'running' AND finished_at IS NOT NULL)",
            name="ck_agent_attempt_terminal_state",
        ),
        CheckConstraint("ordinal > 0", name="ck_agent_attempt_ordinal"),
        CheckConstraint("lease_fencing_token > 0", name="ck_agent_attempt_fencing_token"),
        CheckConstraint("runtime_owner_id <> ''", name="ck_agent_attempt_runtime_owner"),
    )

    id: str = Field(primary_key=True, max_length=36)
    run_id: str = Field(foreign_key="agent_runs.id", index=True, ondelete="RESTRICT")
    ordinal: int = Field(ge=1)
    status: AgentAttemptStatus = Field(sa_column=Column(enum_value_type(AgentAttemptStatus, length=24), nullable=False, index=True))
    trigger: dict = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
    model_config_snapshot: dict = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
    usage: dict = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
    runtime_owner_id: str = Field(max_length=128)
    lease_fencing_token: int = Field(sa_column=Column(BigInteger, nullable=False))
    error_code: str = Field(default="", max_length=96)
    error_message: str = ""
    started_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))
    finished_at: datetime | None = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))


class AgentContextItem(SQLModel, table=True):
    __tablename__ = "agent_context_items"
    __table_args__ = (
        Index(
            "uq_agent_context_item_active_seq",
            "context_id",
            "seq",
            unique=True,
            postgresql_where=text("status = 'active'"),
        ),
        Index(
            "uq_agent_context_item_dedupe_key",
            "context_id",
            "dedupe_key",
            unique=True,
            postgresql_where=text("dedupe_key <> ''"),
        ),
        Index("ix_agent_context_items_visible", "context_id", "status", "seq"),
        CheckConstraint(
            "(status = 'active' AND retired_at IS NULL) OR "
            "(status <> 'active' AND retired_at IS NOT NULL)",
            name="ck_agent_context_item_retirement",
        ),
        CheckConstraint("seq > 0", name="ck_agent_context_item_seq"),
    )

    id: int | None = Field(default=None, primary_key=True, sa_type=BigInteger)
    context_id: str = Field(foreign_key="agent_contexts.id", index=True, ondelete="RESTRICT")
    seq: int = Field(sa_column=Column(BigInteger, nullable=False))
    status: AgentContextItemStatus = Field(
        default=AgentContextItemStatus.ACTIVE,
        sa_column=Column(enum_value_type(AgentContextItemStatus, length=24), nullable=False),
    )
    provenance_attempt_id: str | None = Field(
        default=None,
        foreign_key="agent_run_attempts.id",
        ondelete="RESTRICT",
    )
    dedupe_key: str = Field(default="", max_length=320)
    item: dict = Field(sa_column=Column(JSON, nullable=False))
    created_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))
    retired_at: datetime | None = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))


class AgentToolInvocation(SQLModel, table=True):
    __tablename__ = "agent_tool_invocations"
    __table_args__ = (
        UniqueConstraint("context_id", "call_id", name="uq_agent_tool_invocation_call"),
        Index("ix_agent_tool_invocations_recovery", "context_id", "status", "started_at"),
        CheckConstraint(
            "(status = 'running' AND finished_at IS NULL AND output IS NULL) OR "
            "(status = 'succeeded' AND finished_at IS NOT NULL AND output IS NOT NULL) OR "
            "(status IN ('recovery_required', 'not_applied') AND finished_at IS NOT NULL AND output IS NULL)",
            name="ck_agent_tool_invocation_result_state",
        ),
        CheckConstraint(
            "(resolved_at IS NULL AND resolved_by = '' AND resolution_note = '') OR "
            "(resolved_at IS NOT NULL AND resolved_by <> '' AND resolution_note <> '')",
            name="ck_agent_tool_invocation_resolution_state",
        ),
        CheckConstraint(
            "status <> 'not_applied' OR resolved_at IS NOT NULL",
            name="ck_agent_tool_invocation_not_applied_resolution",
        ),
        CheckConstraint(
            "status NOT IN ('running', 'recovery_required') OR resolved_at IS NULL",
            name="ck_agent_tool_invocation_pending_resolution",
        ),
    )

    id: str = Field(primary_key=True, max_length=36)
    context_id: str = Field(foreign_key="agent_contexts.id", index=True, ondelete="RESTRICT")
    run_id: str = Field(foreign_key="agent_runs.id", index=True, ondelete="RESTRICT")
    attempt_id: str = Field(foreign_key="agent_run_attempts.id", index=True, ondelete="RESTRICT")
    call_id: str = Field(max_length=255)
    tool_name: str = Field(max_length=160)
    arguments: str = Field(default="", sa_column=Column(Text, nullable=False))
    status: AgentToolInvocationStatus = Field(
        sa_column=Column(enum_value_type(AgentToolInvocationStatus, length=32), nullable=False, index=True)
    )
    output: str | None = Field(default=None, sa_column=Column(JSON, nullable=True))
    error_message: str = ""
    started_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))
    finished_at: datetime | None = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))
    resolved_at: datetime | None = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))
    resolved_by: str = Field(default="", max_length=128)
    resolution_note: str = Field(default="", sa_column=Column(Text, nullable=False))


class AgentSegment(SQLModel, table=True):
    __tablename__ = "agent_segments"
    __table_args__ = (
        UniqueConstraint("attempt_id", "segment_key", name="uq_agent_attempt_segment"),
        CheckConstraint("persisted_utf16_offset >= 0", name="ck_agent_segment_persisted_offset"),
    )

    id: str = Field(primary_key=True, max_length=36)
    attempt_id: str = Field(foreign_key="agent_run_attempts.id", index=True, ondelete="RESTRICT")
    segment_key: str = Field(max_length=160)
    kind: AgentSegmentKind = Field(sa_column=Column(enum_value_type(AgentSegmentKind, length=24), nullable=False))
    status: AgentSegmentStatus = Field(sa_column=Column(enum_value_type(AgentSegmentStatus, length=24), nullable=False))
    text: str = Field(default="", sa_column=Column(Text, nullable=False))
    persisted_utf16_offset: int = Field(default=0, sa_column=Column(BigInteger, nullable=False))
    created_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))
    updated_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))


class AgentEvent(SQLModel, table=True):
    __tablename__ = "agent_events"
    __table_args__ = (
        UniqueConstraint("session_id", "seq", name="uq_agent_event_session_seq"),
        Index("ix_agent_events_session_seq", "session_id", "seq"),
        CheckConstraint("seq > 0", name="ck_agent_event_seq"),
    )

    id: str = Field(primary_key=True, max_length=36)
    session_id: str = Field(foreign_key="agent_sessions.id", index=True, ondelete="RESTRICT")
    run_id: str | None = Field(default=None, foreign_key="agent_runs.id", index=True, ondelete="RESTRICT")
    attempt_id: str | None = Field(default=None, foreign_key="agent_run_attempts.id", ondelete="RESTRICT")
    seq: int = Field(sa_column=Column(BigInteger, nullable=False))
    event_type: str = Field(max_length=64, index=True)
    payload: dict = Field(sa_column=Column(JSON, nullable=False))
    occurred_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False, index=True))


class AgentCompaction(SQLModel, table=True):
    __tablename__ = "agent_compactions"
    __table_args__ = (
        UniqueConstraint("context_id", "through_seq", name="uq_agent_compaction_boundary"),
        CheckConstraint(
            "from_seq > 0 AND through_seq >= from_seq",
            name="ck_agent_compaction_range",
        ),
        CheckConstraint(
            "source_token_count >= 0 AND summary_token_count >= 0",
            name="ck_agent_compaction_token_counts",
        ),
    )

    id: str = Field(primary_key=True, max_length=36)
    context_id: str = Field(foreign_key="agent_contexts.id", index=True, ondelete="RESTRICT")
    attempt_id: str | None = Field(default=None, foreign_key="agent_run_attempts.id", ondelete="RESTRICT")
    from_seq: int = Field(sa_column=Column(BigInteger, nullable=False))
    through_seq: int = Field(sa_column=Column(BigInteger, nullable=False))
    summary_item: dict = Field(sa_column=Column(JSON, nullable=False))
    source_token_count: int = 0
    summary_token_count: int = 0
    created_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))
