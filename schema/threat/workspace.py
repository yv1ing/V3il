from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from schema.deception.environments import DeceptionEnvironmentSchema
from schema.threat.analysis import AttackerProfileSchema, IntentAssessmentSchema, RiskAssessmentSchema
from schema.threat.chains import AttackChainSchema
from schema.threat.incidents import ThreatIncidentSchema
from schema.threat.intelligence import IntelligenceReportSchema
from schema.threat.investigations import AuditEventSchema


class ThreatTimelineItemKind(StrEnum):
    BEHAVIOR_EVENT = "behavior_event"
    AUDIT_EVENT = "audit_event"
    INVESTIGATION_TASK = "investigation_task"
    INVESTIGATION_EVIDENCE = "investigation_evidence"
    DECEPTION_REVISION = "deception_revision"


class ThreatTimelineItemSchema(BaseModel):
    kind: ThreatTimelineItemKind
    occurred_at: datetime
    object_id: str
    environment_id: int | None = None
    task_id: int | None = None
    payload: dict[str, Any]


class ThreatTimelineResponse(BaseModel):
    items: list[ThreatTimelineItemSchema]
    next_before: datetime | None = None
    has_more: bool = False


class ThreatWorkspaceCounts(BaseModel):
    tasks_by_status: dict[str, int] = Field(default_factory=dict)
    evidence_count: int = 0
    assigned_event_count: int = 0
    scoped_event_count: int = 0
    covered_event_count: int = 0
    indicators_count: int = 0
    revisions_by_status: dict[str, int] = Field(default_factory=dict)


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
