from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, Column, DateTime, Index, Text
from sqlmodel import Field, SQLModel

from schema.sandbox.async_jobs import SandboxAsyncJobStatus
from schema.runtime import RuntimeContinuationDisposition
from utils.sqlalchemy import enum_value_type
from utils.time import utc_now


class SandboxAsyncJob(SQLModel, table=True):
    __tablename__ = "sandbox_async_jobs"
    __table_args__ = (
        Index("ix_sandbox_jobs_waiting_run_status", "waiting_run_id", "status"),
        Index("ix_sandbox_jobs_runtime_queue", "status", "created_at", "run_id"),
        CheckConstraint(
            "(status = 'queued' AND started_at IS NULL AND finished_at IS NULL) OR "
            "(status = 'running' AND started_at IS NOT NULL AND finished_at IS NULL) OR "
            "(status IN ('completed', 'failed', 'canceled', 'recovery_required') AND finished_at IS NOT NULL)",
            name="ck_sandbox_async_job_execution_state",
        ),
        CheckConstraint(
            "(continuation_disposition IS NULL AND continuation_resolved_at IS NULL) OR "
            "(continuation_disposition IS NOT NULL AND continuation_resolved_at IS NOT NULL)",
            name="ck_sandbox_async_job_continuation_state",
        ),
        CheckConstraint(
            "(recovery_resolved_at IS NULL AND recovery_resolved_by = '' AND recovery_resolution_note = '') OR "
            "(recovery_resolved_at IS NOT NULL AND recovery_resolved_by <> '' AND recovery_resolution_note <> '')",
            name="ck_sandbox_async_job_recovery_resolution",
        ),
        CheckConstraint(
            "status <> 'recovery_required' OR recovery_resolved_at IS NULL",
            name="ck_sandbox_async_job_pending_recovery",
        ),
        CheckConstraint(
            "recovery_resolved_at IS NULL OR status = 'failed'",
            name="ck_sandbox_async_job_resolved_status",
        ),
        CheckConstraint(
            "(started_at IS NULL AND runtime_owner_id = '' AND lease_fencing_token = 0) OR "
            "(started_at IS NOT NULL AND runtime_owner_id <> '' AND lease_fencing_token > 0)",
            name="ck_sandbox_async_job_runtime_owner",
        ),
        CheckConstraint(
            "(cancel_requested_at IS NULL AND cancel_requested_by = '') OR "
            "(cancel_requested_at IS NOT NULL AND cancel_requested_by <> '')",
            name="ck_sandbox_async_job_cancel_request",
        ),
        CheckConstraint("timeout_seconds > 0", name="ck_sandbox_async_job_timeout"),
        CheckConstraint(
            "sandbox_container_generation > 0",
            name="ck_sandbox_async_job_container_generation",
        ),
        CheckConstraint(
            "output_bytes >= 0 AND output_lines >= 0",
            name="ck_sandbox_async_job_output_counts",
        ),
    )

    run_id: str = Field(primary_key=True, max_length=64)
    waiting_run_id: str = Field(foreign_key="agent_runs.id", index=True, ondelete="RESTRICT")
    session_id: str = Field(foreign_key="agent_sessions.id", index=True, ondelete="RESTRICT")
    attempt_id: str = Field(foreign_key="agent_run_attempts.id", index=True, ondelete="RESTRICT")
    investigation_task_id: int | None = Field(
        default=None,
        foreign_key="investigation_tasks.id",
        index=True,
        ondelete="RESTRICT",
    )
    command: str = ""
    output_file: str = ""
    timeout_seconds: int = 300
    execution_marker: str = Field(max_length=160)
    status: SandboxAsyncJobStatus = Field(
        default=SandboxAsyncJobStatus.QUEUED,
        sa_column=Column(enum_value_type(SandboxAsyncJobStatus, length=32), index=True, nullable=False),
    )
    exit_code: int | None = Field(default=None, sa_column=Column(BigInteger, nullable=True))
    output_bytes: int = Field(default=0, sa_column=Column(BigInteger, nullable=False))
    output_lines: int = Field(default=0, sa_column=Column(BigInteger, nullable=False))
    error: str = ""
    sandbox_container_id: int = Field(foreign_key="sandbox_containers.id", index=True, ondelete="RESTRICT")
    sandbox_container_generation: int = Field(default=0, sa_column=Column(BigInteger, nullable=False))
    cancel_requested_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True, index=True),
    )
    cancel_requested_by: str = Field(default="", max_length=128)
    runtime_owner_id: str = Field(default="", max_length=128)
    lease_fencing_token: int = Field(default=0, sa_column=Column(BigInteger, nullable=False))
    created_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))
    updated_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))
    started_at: datetime | None = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))
    finished_at: datetime | None = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))
    continuation_disposition: RuntimeContinuationDisposition | None = Field(
        default=None,
        sa_column=Column(enum_value_type(RuntimeContinuationDisposition, length=24), nullable=True),
    )
    continuation_resolved_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True, index=True),
    )
    recovery_resolved_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    recovery_resolved_by: str = Field(default="", max_length=128)
    recovery_resolution_note: str = Field(default="", sa_column=Column(Text, nullable=False))
