import base64
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, JsonValue, field_validator, model_validator

from schema.agent.types import (
    AgentAttemptStatus,
    AgentCode,
    AgentRunStatus,
    AgentSegmentKind,
    AgentSegmentStatus,
    AgentToolInvocationStatus,
)
from schema.sandbox.async_jobs import SandboxAsyncJobStatus

class AgentInputPartType(StrEnum):
    TEXT = "text"
    IMAGE = "image"


class AgentImageDetail(StrEnum):
    AUTO = "auto"
    LOW = "low"
    HIGH = "high"


class AgentImageMediaType(StrEnum):
    PNG = "image/png"
    JPEG = "image/jpeg"
    WEBP = "image/webp"


MAX_AGENT_IMAGES = 4
MAX_AGENT_IMAGE_BYTES = 15 * 1024 * 1024 // 4
MAX_AGENT_TOTAL_IMAGE_BYTES = 6 * 1024 * 1024
MAX_AGENT_TEXT_INPUT_CHARS = 20_000


class AgentTextInputPart(BaseModel):
    type: Literal[AgentInputPartType.TEXT] = AgentInputPartType.TEXT
    text: str = Field(min_length=1, max_length=MAX_AGENT_TEXT_INPUT_CHARS)

    @field_validator("text", mode="before")
    @classmethod
    def normalize_text(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class AgentImageInputPart(BaseModel):
    type: Literal[AgentInputPartType.IMAGE] = AgentInputPartType.IMAGE
    media_type: AgentImageMediaType
    data: str = Field(min_length=1, max_length=((MAX_AGENT_IMAGE_BYTES + 2) // 3) * 4)
    detail: AgentImageDetail = AgentImageDetail.AUTO

    @field_validator("data")
    @classmethod
    def validate_base64_data(cls, value: str) -> str:
        compact = "".join(value.split())
        if compact.startswith("data:"):
            raise ValueError("image data must be raw base64 without a data URL prefix")
        try:
            base64.b64decode(compact, validate=True)
        except Exception as exc:
            raise ValueError("image data must be valid base64") from exc
        return compact


AgentInputPart = Annotated[AgentTextInputPart | AgentImageInputPart, Field(discriminator="type")]


class AgentDurableEventType(StrEnum):
    USER_MESSAGE = "user_message"
    RUN_TRANSITION = "run_transition"
    ATTEMPT_TRANSITION = "attempt_transition"
    SEGMENT_COMPLETED = "segment_completed"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    TOOL_RECOVERY = "tool_recovery"
    SANDBOX_RECOVERY = "sandbox_recovery"
    DELEGATION = "delegation"
    ERROR = "error"


class AgentEventBase(BaseModel):
    id: str
    session_id: str
    run_id: str | None = None
    attempt_id: str | None = None
    seq: int = Field(ge=1)
    occurred_at: datetime


class UserMessageEvent(AgentEventBase):
    type: Literal[AgentDurableEventType.USER_MESSAGE] = AgentDurableEventType.USER_MESSAGE
    agent_code: AgentCode
    content: list[AgentInputPart]
    display_text: str


class RunTransitionEvent(AgentEventBase):
    type: Literal[AgentDurableEventType.RUN_TRANSITION] = AgentDurableEventType.RUN_TRANSITION
    previous_status: AgentRunStatus | None = None
    status: AgentRunStatus
    reason: str = ""


class AttemptTransitionEvent(AgentEventBase):
    type: Literal[AgentDurableEventType.ATTEMPT_TRANSITION] = AgentDurableEventType.ATTEMPT_TRANSITION
    previous_status: AgentAttemptStatus | None = None
    status: AgentAttemptStatus
    reason: str = ""


class SegmentCompletedEvent(AgentEventBase):
    type: Literal[AgentDurableEventType.SEGMENT_COMPLETED] = AgentDurableEventType.SEGMENT_COMPLETED
    segment_id: str
    segment_kind: AgentSegmentKind
    status: AgentSegmentStatus
    agent_code: AgentCode
    text: str


class ToolCallEvent(AgentEventBase):
    type: Literal[AgentDurableEventType.TOOL_CALL] = AgentDurableEventType.TOOL_CALL
    call_id: str
    agent_code: AgentCode
    name: str
    arguments: dict[str, JsonValue] = Field(default_factory=dict)


class ToolResultEvent(AgentEventBase):
    type: Literal[AgentDurableEventType.TOOL_RESULT] = AgentDurableEventType.TOOL_RESULT
    call_id: str
    agent_code: AgentCode
    output: str = ""
    is_error: bool = False


class ToolRecoveryEvent(AgentEventBase):
    type: Literal[AgentDurableEventType.TOOL_RECOVERY] = AgentDurableEventType.TOOL_RECOVERY
    invocation_id: str
    call_id: str
    agent_code: AgentCode
    status: AgentToolInvocationStatus
    resolved_by: str
    resolution_note: str


class SandboxRecoveryEvent(AgentEventBase):
    type: Literal[AgentDurableEventType.SANDBOX_RECOVERY] = AgentDurableEventType.SANDBOX_RECOVERY
    sandbox_job_id: str
    status: SandboxAsyncJobStatus
    resolved_by: str
    resolution_note: str


class DelegationEvent(AgentEventBase):
    type: Literal[AgentDurableEventType.DELEGATION] = AgentDurableEventType.DELEGATION
    child_run_id: str
    parent_agent_code: AgentCode
    child_agent_code: AgentCode
    status: AgentRunStatus
    summary: str = ""


class AgentErrorEvent(AgentEventBase):
    type: Literal[AgentDurableEventType.ERROR] = AgentDurableEventType.ERROR
    code: str
    message: str


AgentDurableEvent = Annotated[
    UserMessageEvent
    | RunTransitionEvent
    | AttemptTransitionEvent
    | SegmentCompletedEvent
    | ToolCallEvent
    | ToolResultEvent
    | ToolRecoveryEvent
    | SandboxRecoveryEvent
    | DelegationEvent
    | AgentErrorEvent,
    Field(discriminator="type"),
]


class AgentSegmentSnapshot(BaseModel):
    segment_id: str
    run_id: str
    attempt_id: str
    segment_kind: AgentSegmentKind
    status: AgentSegmentStatus
    text: str
    persisted_utf16_offset: int = Field(
        ge=0,
        description="Persisted text length measured in UTF-16 code units.",
    )

    @model_validator(mode="after")
    def validate_persisted_utf16_offset(self) -> "AgentSegmentSnapshot":
        if self.persisted_utf16_offset != _utf16_length(self.text):
            raise ValueError("persisted UTF-16 offset must match the snapshot text")
        return self


class AgentServerFrameType(StrEnum):
    HELLO = "hello"
    REPLAY = "replay"
    EVENT = "event"
    DELTA = "delta"
    REBASE_REQUIRED = "rebase_required"
    HEARTBEAT = "heartbeat"
    ERROR = "error"


class AgentHelloFrame(BaseModel):
    type: Literal[AgentServerFrameType.HELLO] = AgentServerFrameType.HELLO
    session_id: str
    durable_head_seq: int = Field(ge=0)
    active_run_ids: list[str] = Field(default_factory=list)
    segments: list[AgentSegmentSnapshot] = Field(default_factory=list)


class AgentReplayFrame(BaseModel):
    type: Literal[AgentServerFrameType.REPLAY] = AgentServerFrameType.REPLAY
    events: list[AgentDurableEvent]
    durable_head_seq: int = Field(ge=0)


class AgentEventFrame(BaseModel):
    type: Literal[AgentServerFrameType.EVENT] = AgentServerFrameType.EVENT
    event: AgentDurableEvent


class AgentDeltaFrame(BaseModel):
    type: Literal[AgentServerFrameType.DELTA] = AgentServerFrameType.DELTA
    run_id: str
    attempt_id: str
    segment_id: str
    segment_kind: AgentSegmentKind
    start_utf16_offset: int = Field(
        ge=0,
        description="Delta start offset measured in UTF-16 code units.",
    )
    end_utf16_offset: int = Field(
        ge=0,
        description="Delta end offset measured in UTF-16 code units.",
    )
    delta: str

    @model_validator(mode="after")
    def validate_delta_offsets(self) -> "AgentDeltaFrame":
        if self.end_utf16_offset - self.start_utf16_offset != _utf16_length(self.delta):
            raise ValueError("delta UTF-16 offsets must match the delta text")
        return self


class AgentRebaseRequiredFrame(BaseModel):
    type: Literal[AgentServerFrameType.REBASE_REQUIRED] = AgentServerFrameType.REBASE_REQUIRED
    durable_head_seq: int = Field(ge=0)
    reason: str


class AgentHeartbeatFrame(BaseModel):
    type: Literal[AgentServerFrameType.HEARTBEAT] = AgentServerFrameType.HEARTBEAT
    sent_at: datetime


class AgentStreamErrorFrame(BaseModel):
    type: Literal[AgentServerFrameType.ERROR] = AgentServerFrameType.ERROR
    code: str
    message: str


AgentServerFrame = Annotated[
    AgentHelloFrame
    | AgentReplayFrame
    | AgentEventFrame
    | AgentDeltaFrame
    | AgentRebaseRequiredFrame
    | AgentHeartbeatFrame
    | AgentStreamErrorFrame,
    Field(discriminator="type"),
]


class AgentClientFrameType(StrEnum):
    ACK = "ack"
    PING = "ping"


class AgentAckFrame(BaseModel):
    type: Literal[AgentClientFrameType.ACK] = AgentClientFrameType.ACK
    durable_seq: int = Field(ge=0)


class AgentPingFrame(BaseModel):
    type: Literal[AgentClientFrameType.PING] = AgentClientFrameType.PING


AgentClientFrame = Annotated[AgentAckFrame | AgentPingFrame, Field(discriminator="type")]


def validate_agent_input_content(content: list[AgentInputPart]) -> None:
    images = [part for part in content if isinstance(part, AgentImageInputPart)]
    if len(images) > MAX_AGENT_IMAGES:
        raise ValueError(f"at most {MAX_AGENT_IMAGES} images are allowed in one message")
    decoded_bytes = sum(len(part.data) * 3 // 4 - (len(part.data) - len(part.data.rstrip("="))) for part in images)
    if decoded_bytes > MAX_AGENT_TOTAL_IMAGE_BYTES:
        raise ValueError("image payload is too large")


def _utf16_length(value: str) -> int:
    return len(value.encode("utf-16-le")) // 2
