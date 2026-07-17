from datetime import datetime
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from schema.agent.sessions import AgentSessionSummarySchema
from schema.common.responses import PaginatedResponse


class ThreatIncidentStatus(StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    ENGAGING = "engaging"
    FINALIZING = "finalizing"
    CLOSED = "closed"


THREAT_INCIDENT_STATUS_TRANSITIONS: dict[ThreatIncidentStatus, tuple[ThreatIncidentStatus, ...]] = {
    ThreatIncidentStatus.OPEN: (ThreatIncidentStatus.INVESTIGATING, ThreatIncidentStatus.FINALIZING),
    ThreatIncidentStatus.INVESTIGATING: (ThreatIncidentStatus.ENGAGING, ThreatIncidentStatus.FINALIZING),
    ThreatIncidentStatus.ENGAGING: (ThreatIncidentStatus.INVESTIGATING, ThreatIncidentStatus.FINALIZING),
    ThreatIncidentStatus.FINALIZING: (ThreatIncidentStatus.INVESTIGATING, ThreatIncidentStatus.CLOSED),
    ThreatIncidentStatus.CLOSED: (ThreatIncidentStatus.INVESTIGATING,),
}


class ThreatSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatConfidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class ThreatIncidentSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    status: ThreatIncidentStatus
    severity: ThreatSeverity
    confidence: ThreatConfidence
    risk_score: int = Field(ge=0, le=100)
    primary_fingerprint: str
    source_ips: list[str]
    summary: str
    first_observed_at: datetime
    last_observed_at: datetime
    idle_deadline: datetime | None
    owner_id: int
    created_at: datetime
    updated_at: datetime


class ThreatIncidentEnvironmentSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    incident_id: int
    environment_id: int
    first_observed_at: datetime
    last_observed_at: datetime
    correlation_method: str
    correlation_key: str
    linked_at: datetime


class UpdateThreatIncidentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=255)
    summary: str | None = Field(default=None, max_length=8000)

    @field_validator("title", "summary", mode="before")
    @classmethod
    def normalize_text(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value

    @model_validator(mode="after")
    def validate_updates(self) -> Self:
        if not self.model_fields_set:
            raise ValueError("at least one incident field must be provided")
        return self


class TransitionThreatIncidentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=4000)


class QueryThreatIncidentsResponse(PaginatedResponse[ThreatIncidentSchema]):
    pass


class CreateThreatIncidentSessionResponse(BaseModel):
    session_id: str


class ListThreatIncidentSessionsResponse(PaginatedResponse[AgentSessionSummarySchema]):
    pass
