import re
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from schema.common.responses import PaginatedResponse
from schema.threat.incidents import ThreatConfidence, ThreatSeverity


class AnalysisKind(StrEnum):
    INTENT = "intent"
    ATTACK_CHAIN = "attack_chain"
    INDICATOR = "indicator"
    ATTACKER_PROFILE = "attacker_profile"
    RISK = "risk"


class AttackStage(StrEnum):
    UNKNOWN = "unknown"
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class IntentAssessmentStatus(StrEnum):
    HYPOTHESIS = "hypothesis"
    SUPPORTED = "supported"
    REFUTED = "refuted"


class AttackerProfileStatus(StrEnum):
    DRAFT = "draft"
    REVIEW = "review"
    ACCEPTED = "accepted"


class AnalysisReviewStatus(StrEnum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    CHANGES_REQUESTED = "changes_requested"


def normalize_attack_technique_ids(values: list[str]) -> list[str]:
    normalized = list(dict.fromkeys(value.strip().upper() for value in values if value.strip()))
    if any(not re.fullmatch(r"T\d{4}(?:\.\d{3})?", value) for value in normalized):
        raise ValueError("ATT&CK technique IDs must use the T1234 or T1234.001 form")
    return normalized


def normalize_positive_ids(values: list[int], label: str) -> list[int]:
    normalized = list(dict.fromkeys(values))
    if any(value <= 0 for value in normalized):
        raise ValueError(f"{label} IDs must be positive")
    return normalized


class AnalysisRecordSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int
    kind: AnalysisKind
    subject_key: str
    version: int
    is_current: bool
    investigation_task_id: int | None
    review_status: AnalysisReviewStatus
    evidence_ids: list[int]
    created_by_agent_code: str
    created_from_session_id: str
    created_at: datetime


class IntentAssessmentSchema(AnalysisRecordSchema):
    stage: AttackStage
    intent: str
    status: IntentAssessmentStatus
    confidence: ThreatConfidence
    rationale: str
    predicted_next_actions: list[str]
    technique_ids: list[str]


class CreateIntentAssessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stage: AttackStage
    intent: str = Field(min_length=1, max_length=4000)
    status: IntentAssessmentStatus
    confidence: ThreatConfidence
    rationale: str = Field(min_length=1, max_length=8000)
    predicted_next_actions: list[str] = Field(default_factory=list, max_length=100)
    technique_ids: list[str] = Field(default_factory=list, max_length=100)
    evidence_ids: list[int] = Field(min_length=1, max_length=1000)

    @field_validator("technique_ids", mode="after")
    @classmethod
    def normalize_techniques(cls, value: list[str]) -> list[str]:
        return normalize_attack_technique_ids(value)

    @field_validator("evidence_ids", mode="after")
    @classmethod
    def normalize_evidence(cls, value: list[int]) -> list[int]:
        return normalize_positive_ids(value, "evidence")


class AttackerProfileSchema(AnalysisRecordSchema):
    status: AttackerProfileStatus
    summary: str
    objectives: list[str]
    capabilities: list[str]
    skill_level: str
    operational_patterns: list[str]
    tools: list[str]
    infrastructure: list[str]
    identity_hypotheses: list[str]
    attribution_limits: list[str]
    confidence: ThreatConfidence


class CreateAttackerProfileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AttackerProfileStatus
    summary: str = Field(min_length=1, max_length=12000)
    objectives: list[str] = Field(default_factory=list, max_length=100)
    capabilities: list[str] = Field(default_factory=list, max_length=100)
    skill_level: str = Field(default="", max_length=255)
    operational_patterns: list[str] = Field(default_factory=list, max_length=100)
    tools: list[str] = Field(default_factory=list, max_length=100)
    infrastructure: list[str] = Field(default_factory=list, max_length=100)
    identity_hypotheses: list[str] = Field(default_factory=list, max_length=100)
    attribution_limits: list[str] = Field(min_length=1, max_length=100)
    confidence: ThreatConfidence
    evidence_ids: list[int] = Field(min_length=1, max_length=1000)


class RiskAssessmentSchema(AnalysisRecordSchema):
    severity: ThreatSeverity
    confidence: ThreatConfidence
    risk_score: int
    rationale: str
    stop_conditions: list[str]
    response_recommendations: list[str]
    defense_improvements: list[str]
    residual_risk: str


class CreateRiskAssessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: ThreatSeverity
    confidence: ThreatConfidence
    risk_score: int = Field(ge=0, le=100)
    rationale: str = Field(min_length=1, max_length=8000)
    stop_conditions: list[str] = Field(default_factory=list, max_length=100)
    response_recommendations: list[str] = Field(default_factory=list, max_length=100)
    defense_improvements: list[str] = Field(default_factory=list, max_length=100)
    residual_risk: str = Field(default="", max_length=8000)
    evidence_ids: list[int] = Field(min_length=1, max_length=1000)


class QueryIntentAssessmentsResponse(PaginatedResponse[IntentAssessmentSchema]):
    pass


class QueryAttackerProfilesResponse(PaginatedResponse[AttackerProfileSchema]):
    pass


class QueryRiskAssessmentsResponse(PaginatedResponse[RiskAssessmentSchema]):
    pass
