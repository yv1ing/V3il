from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

from schema.common.responses import PaginatedResponse
from schema.agent.sessions import AgentCode


class InvestigationTaskStatus(StrEnum):
    QUEUED = "queued"
    ACTIVE = "active"
    BLOCKED = "blocked"
    REVIEW = "review"
    COMPLETED = "completed"
    CANCELED = "canceled"


INVESTIGATION_TASK_STATUS_TRANSITIONS: dict[
    InvestigationTaskStatus,
    tuple[InvestigationTaskStatus, ...],
] = {
    InvestigationTaskStatus.QUEUED: (
        InvestigationTaskStatus.ACTIVE,
        InvestigationTaskStatus.CANCELED,
    ),
    InvestigationTaskStatus.ACTIVE: (
        InvestigationTaskStatus.BLOCKED,
        InvestigationTaskStatus.REVIEW,
        InvestigationTaskStatus.CANCELED,
    ),
    InvestigationTaskStatus.BLOCKED: (
        InvestigationTaskStatus.ACTIVE,
        InvestigationTaskStatus.REVIEW,
        InvestigationTaskStatus.CANCELED,
    ),
    InvestigationTaskStatus.REVIEW: (
        InvestigationTaskStatus.ACTIVE,
        InvestigationTaskStatus.COMPLETED,
        InvestigationTaskStatus.CANCELED,
    ),
    InvestigationTaskStatus.COMPLETED: (),
    InvestigationTaskStatus.CANCELED: (),
}


class InvestigationTaskPriority(StrEnum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class InvestigationReviewDecision(StrEnum):
    ACCEPT = "accept"
    REQUEST_CHANGES = "request_changes"


class EvidenceRelationType(StrEnum):
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    RELATED = "related"


class CreateEvidenceBehaviorLinkRequest(BaseModel):
    event_id: int
    relation: EvidenceRelationType


class EvidenceBehaviorLinkSchema(BaseModel):
    evidence_id: int
    event_id: int
    relation: EvidenceRelationType
    linked_at: datetime


class CreateEvidenceRelationRequest(BaseModel):
    target_evidence_id: int
    relation: EvidenceRelationType


class EvidenceRelationSchema(BaseModel):
    source_evidence_id: int
    target_evidence_id: int
    relation: EvidenceRelationType
    linked_at: datetime


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
    behavior_links: list[EvidenceBehaviorLinkSchema]
    evidence_relations: list[EvidenceRelationSchema]
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
    details: dict[str, JsonValue]
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
    behavior_links: list[CreateEvidenceBehaviorLinkRequest] = Field(min_length=1, max_length=1000)
    evidence_relations: list[CreateEvidenceRelationRequest] = Field(default_factory=list, max_length=100)

    @field_validator("statement", "analysis", mode="before")
    @classmethod
    def normalize_text(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value

    @field_validator("behavior_links", mode="after")
    @classmethod
    def normalize_behavior_links(cls, value: list[CreateEvidenceBehaviorLinkRequest]):
        if any(item.event_id <= 0 for item in value):
            raise ValueError("event IDs must be positive")
        if len({item.event_id for item in value}) != len(value):
            raise ValueError("behavior event links must be unique")
        return value

    @field_validator("evidence_relations", mode="after")
    @classmethod
    def normalize_evidence_relations(cls, value: list[CreateEvidenceRelationRequest]):
        if any(item.target_evidence_id <= 0 for item in value):
            raise ValueError("evidence IDs must be positive")
        keys = {(item.target_evidence_id, item.relation) for item in value}
        if len(keys) != len(value):
            raise ValueError("evidence relations must be unique")
        return value


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
