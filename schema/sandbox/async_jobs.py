from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from schema.runtime import RuntimeContinuationDisposition


class SandboxAsyncJobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"
    RECOVERY_REQUIRED = "recovery_required"


class SandboxAsyncJobResolution(StrEnum):
    CONFIRM_TERMINATED = "confirm_terminated"


SANDBOX_ASYNC_JOB_STATUS_TRANSITIONS: dict[
    SandboxAsyncJobStatus,
    tuple[SandboxAsyncJobStatus, ...],
] = {
    SandboxAsyncJobStatus.QUEUED: (
        SandboxAsyncJobStatus.RUNNING,
        SandboxAsyncJobStatus.FAILED,
        SandboxAsyncJobStatus.CANCELED,
    ),
    SandboxAsyncJobStatus.RUNNING: (
        SandboxAsyncJobStatus.COMPLETED,
        SandboxAsyncJobStatus.FAILED,
        SandboxAsyncJobStatus.CANCELED,
        SandboxAsyncJobStatus.RECOVERY_REQUIRED,
    ),
    SandboxAsyncJobStatus.COMPLETED: (),
    SandboxAsyncJobStatus.FAILED: (),
    SandboxAsyncJobStatus.CANCELED: (),
    SandboxAsyncJobStatus.RECOVERY_REQUIRED: (SandboxAsyncJobStatus.FAILED,),
}


class ResolveSandboxAsyncJobRequest(BaseModel):
    resolution: SandboxAsyncJobResolution
    note: str = Field(min_length=1, max_length=1000)

    @field_validator("note", mode="before")
    @classmethod
    def normalize_note(cls, value):
        return value.strip() if isinstance(value, str) else value


class SandboxAsyncJobSnapshot(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    run_id: str
    waiting_run_id: str
    session_id: str
    attempt_id: str
    investigation_task_id: int | None = None
    command: str
    output_file: str
    timeout_seconds: int = Field(gt=0)
    execution_marker: str
    status: SandboxAsyncJobStatus
    exit_code: int | None = None
    output_bytes: int = Field(default=0, ge=0)
    output_lines: int = Field(default=0, ge=0)
    error: str = ""
    sandbox_container_id: int = Field(gt=0)
    sandbox_container_generation: int = Field(gt=0)
    cancel_requested_at: datetime | None = None
    cancel_requested_by: str = ""
    runtime_owner_id: str = ""
    lease_fencing_token: int = Field(default=0, ge=0)
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    continuation_disposition: RuntimeContinuationDisposition | None = None
    continuation_resolved_at: datetime | None = None
    recovery_resolved_at: datetime | None = None
    recovery_resolved_by: str = ""
    recovery_resolution_note: str = ""


class ListSandboxAsyncJobRecoveriesResponse(BaseModel):
    session_id: str
    items: list[SandboxAsyncJobSnapshot] = Field(default_factory=list)
