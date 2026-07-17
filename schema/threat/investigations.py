from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from schema.common.responses import PaginatedResponse
from schema.agent.sessions import AgentCode


class InvestigationTaskStatus(StrEnum):
    QUEUED = "queued"
    ACTIVE = "active"
    BLOCKED = "blocked"
    REVIEW = "review"
    COMPLETED = "completed"
    CANCELED = "canceled"


class InvestigationTaskPriority(StrEnum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class InvestigationReviewDecision(StrEnum):
    ACCEPT = "accept"
    REQUEST_CHANGES = "request_changes"


class AuditActorType(StrEnum):
    SYSTEM = "system"
    USER = "user"
    AGENT = "agent"


class AuditEventKind(StrEnum):
    ENVIRONMENT = "environment"
    REVISION = "revision"
    CORRELATION = "correlation"
    INCIDENT_STATE = "incident_state"
    TASK_STATE = "task_state"
    DELEGATION = "delegation"
    EVIDENCE = "evidence"
    ANALYSIS = "analysis"
    REPORT = "report"
    KNOWLEDGE = "knowledge"
    DETECTION = "detection"


class InvestigationTaskSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int
    title: str
    status: InvestigationTaskStatus
    priority: InvestigationTaskPriority
    assignee_agent_code: AgentCode
    objective: str
    completion_criteria: str
    result_summary: str
    blocker_reason: str
    dependency_ids: list[int]
    behavior_event_ids: list[int]
    covered_event_ids: list[int]
    created_by_agent_code: str
    created_from_session_id: str
    created_at: datetime
    updated_at: datetime


class InvestigationEvidenceSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    task_id: int
    statement: str
    analysis: str
    behavior_event_ids: list[int]
    related_evidence_ids: list[int]
    created_by_agent_code: str
    created_from_session_id: str
    created_at: datetime


class AuditEventSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int | None
    environment_id: int | None
    task_id: int | None
    detection_rule_id: int | None
    managed_host_id: int | None
    kind: AuditEventKind
    actor_type: AuditActorType
    actor_code: str
    session_id: str
    object_type: str
    object_id: str
    summary: str
    details: dict[str, Any]
    created_at: datetime


class CreateInvestigationTaskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=255)
    priority: InvestigationTaskPriority = InvestigationTaskPriority.NORMAL
    assignee_agent_code: AgentCode
    objective: str = Field(min_length=1, max_length=4000)
    completion_criteria: str = Field(min_length=1, max_length=4000)
    dependency_ids: list[int] = Field(default_factory=list, max_length=100)
    behavior_event_ids: list[int] = Field(min_length=1, max_length=1000)

    @field_validator("title", "assignee_agent_code", "objective", "completion_criteria", mode="before")
    @classmethod
    def normalize_text(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value

    @field_validator("dependency_ids", "behavior_event_ids", mode="after")
    @classmethod
    def normalize_ids(cls, value: list[int]) -> list[int]:
        normalized = list(dict.fromkeys(value))
        if any(item <= 0 for item in normalized):
            raise ValueError("IDs must be positive")
        return normalized


class CreateInvestigationEvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    statement: str = Field(min_length=1, max_length=4000)
    analysis: str = Field(min_length=1, max_length=12000)
    behavior_event_ids: list[int] = Field(min_length=1, max_length=1000)
    related_evidence_ids: list[int] = Field(default_factory=list, max_length=100)

    @field_validator("statement", "analysis", mode="before")
    @classmethod
    def normalize_text(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value

    @field_validator("behavior_event_ids", "related_evidence_ids", mode="after")
    @classmethod
    def normalize_ids(cls, value: list[int]) -> list[int]:
        normalized = list(dict.fromkeys(value))
        if any(item <= 0 for item in normalized):
            raise ValueError("IDs must be positive")
        return normalized


class BlockInvestigationTaskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=1, max_length=4000)


class SubmitInvestigationTaskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    result_summary: str = Field(min_length=1, max_length=8000)


class ReviewInvestigationTaskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: InvestigationReviewDecision
    reason: str = Field(min_length=1, max_length=4000)


class QueryInvestigationTasksResponse(PaginatedResponse[InvestigationTaskSchema]):
    pass


class QueryInvestigationEvidenceResponse(PaginatedResponse[InvestigationEvidenceSchema]):
    pass


class QueryAuditEventsResponse(PaginatedResponse[AuditEventSchema]):
    pass
