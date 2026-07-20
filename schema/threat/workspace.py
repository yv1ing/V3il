from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, Field, model_validator

from schema.deception.environments import (
    DeceptionEnvironmentSchema,
    DeceptionRevisionSchema,
    DeceptionRevisionStatus,
)
from schema.threat.analysis import AttackerProfileSchema, IntentAssessmentSchema, RiskAssessmentSchema
from schema.threat.chains import AttackChainSchema
from schema.threat.incidents import ThreatIncidentSchema
from schema.threat.intelligence import IntelligenceReportSchema
from schema.threat.behaviors import BehaviorEventSchema
from schema.threat.investigations import (
    AuditEventSchema,
    InvestigationEvidenceSchema,
    InvestigationTaskSchema,
    InvestigationTaskStatus,
)


class ThreatTimelineItemKind(StrEnum):
    BEHAVIOR_EVENT = "behavior_event"
    AUDIT_EVENT = "audit_event"
    INVESTIGATION_TASK = "investigation_task"
    INVESTIGATION_EVIDENCE = "investigation_evidence"
    DECEPTION_REVISION = "deception_revision"


class ThreatTimelineCursor(BaseModel):
    occurred_at: datetime
    kind: ThreatTimelineItemKind
    object_id: int


class ThreatTimelineQuery(BaseModel):
    cursor_at: datetime | None = None
    cursor_kind: ThreatTimelineItemKind | None = None
    cursor_id: int | None = Field(default=None, gt=0)
    limit: int = Field(default=100, ge=1, le=500)

    @model_validator(mode="after")
    def validate_cursor(self):
        values = (self.cursor_at, self.cursor_kind, self.cursor_id)
        if any(value is not None for value in values) and not all(value is not None for value in values):
            raise ValueError("timeline cursor fields must be provided together")
        return self

    def to_cursor(self) -> ThreatTimelineCursor | None:
        if self.cursor_at is None or self.cursor_kind is None or self.cursor_id is None:
            return None
        return ThreatTimelineCursor(
            occurred_at=self.cursor_at,
            kind=self.cursor_kind,
            object_id=self.cursor_id,
        )


class ThreatTimelineItemBase(BaseModel):
    occurred_at: datetime
    object_id: int
    environment_id: int | None = None
    task_id: int | None = None


class BehaviorEventTimelineItem(ThreatTimelineItemBase):
    kind: Literal[ThreatTimelineItemKind.BEHAVIOR_EVENT] = ThreatTimelineItemKind.BEHAVIOR_EVENT
    payload: BehaviorEventSchema


class AuditEventTimelineItem(ThreatTimelineItemBase):
    kind: Literal[ThreatTimelineItemKind.AUDIT_EVENT] = ThreatTimelineItemKind.AUDIT_EVENT
    payload: AuditEventSchema


class InvestigationTaskTimelineItem(ThreatTimelineItemBase):
    kind: Literal[ThreatTimelineItemKind.INVESTIGATION_TASK] = ThreatTimelineItemKind.INVESTIGATION_TASK
    payload: InvestigationTaskSchema


class InvestigationEvidenceTimelineItem(ThreatTimelineItemBase):
    kind: Literal[ThreatTimelineItemKind.INVESTIGATION_EVIDENCE] = ThreatTimelineItemKind.INVESTIGATION_EVIDENCE
    payload: InvestigationEvidenceSchema


class DeceptionRevisionTimelineItem(ThreatTimelineItemBase):
    kind: Literal[ThreatTimelineItemKind.DECEPTION_REVISION] = ThreatTimelineItemKind.DECEPTION_REVISION
    payload: DeceptionRevisionSchema


ThreatTimelineItemSchema = Annotated[
    BehaviorEventTimelineItem
    | AuditEventTimelineItem
    | InvestigationTaskTimelineItem
    | InvestigationEvidenceTimelineItem
    | DeceptionRevisionTimelineItem,
    Field(discriminator="kind"),
]


class ThreatTimelineResponse(BaseModel):
    items: list[ThreatTimelineItemSchema]
    next_cursor: ThreatTimelineCursor | None = None
    has_more: bool = False


class ThreatWorkspaceCounts(BaseModel):
    tasks_by_status: dict[InvestigationTaskStatus, int] = Field(default_factory=dict)
    evidence_count: int = 0
    assigned_event_count: int = 0
    scoped_event_count: int = 0
    covered_event_count: int = 0
    indicators_count: int = 0
    revisions_by_status: dict[DeceptionRevisionStatus, int] = Field(default_factory=dict)


class ThreatSensorCoverageStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


class ThreatSensorCoverageSchema(BaseModel):
    environment_id: int
    sensor_id: str
    status: ThreatSensorCoverageStatus
    last_sequence: int
    verification_token: str
    last_observed_at: datetime | None = None
    updated_at: datetime
    last_transition_at: datetime | None = None
    summary: str = ""


class ThreatIncidentWorkspaceSchema(BaseModel):
    incident: ThreatIncidentSchema
    environments: list[DeceptionEnvironmentSchema]
    current_intent: IntentAssessmentSchema | None = None
    current_attack_chain: AttackChainSchema | None = None
    current_attacker_profile: AttackerProfileSchema | None = None
    current_risk_assessment: RiskAssessmentSchema | None = None
    current_report: IntelligenceReportSchema | None = None
    counts: ThreatWorkspaceCounts
    sensor_coverage: list[ThreatSensorCoverageSchema] = Field(default_factory=list)
    recent_audit_events: list[AuditEventSchema] = Field(default_factory=list)
