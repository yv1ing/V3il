from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from schema.agent.events import AgentDurableEvent, AgentInputPart, validate_agent_input_content
from schema.agent.types import (
    CANONICAL_AGENT_IDENTITIES,
    AgentAttemptStatus,
    AgentCancellationMode,
    AgentCode,
    AgentContextKind,
    AgentRunWaitReason,
    AgentRunStatus,
    AgentSegmentKind,
    AgentSegmentStatus,
    AgentSessionStatus,
    AgentToolInvocationResolution,
    AgentToolInvocationStatus,
    AgentTriggerKind,
    SessionType,
)
from schema.common.responses import PaginatedResponse
from schema.runtime import RuntimeContinuationDisposition


class AgentRunSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    session_id: str
    parent_run_id: str | None = None
    agent_code: AgentCode
    status: AgentRunStatus
    trigger_kind: AgentTriggerKind
    trigger_revision: int = Field(ge=1)
    is_foreground: bool
    investigation_task_id: int | None = None
    environment_revision_id: int | None = None
    wait_reason: AgentRunWaitReason | None = None
    wait_reference_id: str | None = Field(default=None, min_length=1, max_length=64)
    error_code: str = ""
    error_message: str = ""
    result_summary: str = ""
    continuation_disposition: RuntimeContinuationDisposition | None = None
    continuation_resolved_at: datetime | None = None
    queued_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    cancel_requested_at: datetime | None = None
    cancel_requested_by: str = ""
    cancel_requested_mode: AgentCancellationMode | None = None
    canceled_at: datetime | None = None
    canceled_by: str = ""


class AgentSessionCapabilitiesSchema(BaseModel):
    can_submit_turn: bool
    can_archive: bool
    can_select_sandbox_container: bool
    can_switch_agent: bool
    can_interrupt: bool
    can_cancel_all: bool
    can_resolve_tool_invocations: bool
    can_resolve_sandbox_jobs: bool
    turn_block_reason: str = ""


class AgentSessionSummarySchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    session_type: SessionType
    status: AgentSessionStatus
    title: str
    primary_agent_code: AgentCode
    owner_id: int
    incident_id: int | None = None
    environment_id: int | None = None
    selected_sandbox_container_id: int | None = None
    selected_sandbox_generation: int = Field(default=0, ge=0)
    active_run: AgentRunSchema | None = None
    queued_run_count: int = Field(default=0, ge=0)
    event_count: int = Field(default=0, ge=0)
    tool_recovery_count: int = Field(default=0, ge=0)
    sandbox_recovery_count: int = Field(default=0, ge=0)
    capabilities: AgentSessionCapabilitiesSchema
    created_at: datetime
    updated_at: datetime


class ListAgentSessionsResponse(PaginatedResponse[AgentSessionSummarySchema]):
    pass


class ListAgentEventsResponse(BaseModel):
    session_id: str
    items: list[AgentDurableEvent]
    has_more: bool = False
    next_before_seq: int | None = None


class AgentToolInvocationSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    context_id: str
    run_id: str
    attempt_id: str
    call_id: str
    tool_name: str
    arguments: str
    status: AgentToolInvocationStatus
    output: str | None = None
    error_message: str = ""
    started_at: datetime
    finished_at: datetime | None = None
    resolved_at: datetime | None = None
    resolved_by: str = ""
    resolution_note: str = ""


class ListAgentToolInvocationRecoveriesResponse(BaseModel):
    session_id: str
    items: list[AgentToolInvocationSchema] = Field(default_factory=list)


class ResolveAgentToolInvocationRequest(BaseModel):
    resolution: AgentToolInvocationResolution
    output: str | None = None
    note: str = Field(min_length=1, max_length=1000)

    @field_validator("note", mode="before")
    @classmethod
    def normalize_note(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value

    @model_validator(mode="after")
    def validate_resolution_output(self) -> "ResolveAgentToolInvocationRequest":
        has_output = self.output is not None
        if self.resolution == AgentToolInvocationResolution.CONFIRM_SUCCEEDED and not has_output:
            raise ValueError("output is required when confirming a successful tool invocation")
        if self.resolution == AgentToolInvocationResolution.CONFIRM_NOT_APPLIED and has_output:
            raise ValueError("output must be omitted when confirming that a tool invocation was not applied")
        return self


class AgentTurnRequestBase(BaseModel):
    content: list[AgentInputPart] = Field(min_length=1, max_length=8)
    agent_code: AgentCode | None = None

    @field_validator("content", mode="after")
    @classmethod
    def validate_content(cls, value: list[AgentInputPart]) -> list[AgentInputPart]:
        validate_agent_input_content(value)
        return value


class CreateAgentSessionTurnRequest(AgentTurnRequestBase):
    sandbox_container_id: int | None = Field(default=None, gt=0)


class SubmitAgentSessionTurnRequest(AgentTurnRequestBase):
    pass


class AgentTurnResponse(BaseModel):
    session: AgentSessionSummarySchema
    run: AgentRunSchema
    accepted_event: AgentDurableEvent


class AgentControlResponse(BaseModel):
    session: AgentSessionSummarySchema
    affected_run_ids: list[str] = Field(default_factory=list)


class UpdateAgentSessionTitleRequest(BaseModel):
    title: str = Field(min_length=1, max_length=80)

    @field_validator("title", mode="before")
    @classmethod
    def normalize_title(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class UpdateAgentSessionSandboxContainerRequest(BaseModel):
    sandbox_container_id: int | None = Field(default=None, gt=0)


class AgentInfoSchema(BaseModel):
    code: AgentCode
    name: str
    description: str = ""


class ListAgentsResponse(BaseModel):
    items: list[AgentInfoSchema]
    default_code: AgentCode
