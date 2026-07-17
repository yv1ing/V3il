from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from schema.common.responses import PaginatedResponse
from schema.threat.analysis import AnalysisRecordSchema, AttackStage, normalize_attack_technique_ids, normalize_positive_ids
from schema.threat.incidents import ThreatConfidence


class AttackChainStatus(StrEnum):
    RECONSTRUCTING = "reconstructing"
    PARTIAL = "partial"
    COMPLETE = "complete"


class AttackChainStepSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sequence: int = Field(ge=1)
    stage: AttackStage
    description: str = Field(min_length=1, max_length=8000)
    source: str = Field(default="", max_length=2000)
    target: str = Field(default="", max_length=2000)
    confidence: ThreatConfidence
    technique_ids: list[str] = Field(default_factory=list, max_length=100)
    started_at: datetime
    ended_at: datetime
    evidence_ids: list[int] = Field(min_length=1, max_length=1000)

    @field_validator("technique_ids", mode="after")
    @classmethod
    def normalize_techniques(cls, value: list[str]) -> list[str]:
        return normalize_attack_technique_ids(value)

    @field_validator("evidence_ids", mode="after")
    @classmethod
    def normalize_evidence(cls, value: list[int]) -> list[int]:
        return normalize_positive_ids(value, "evidence")

    @model_validator(mode="after")
    def validate_time(self):
        if self.ended_at < self.started_at:
            raise ValueError("attack chain step end time cannot precede start time")
        return self


class AttackChainSchema(AnalysisRecordSchema):
    status: AttackChainStatus
    summary: str
    steps: list[AttackChainStepSchema]
    gaps: list[str]


class CreateAttackChainRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AttackChainStatus
    summary: str = Field(min_length=1, max_length=12000)
    steps: list[AttackChainStepSchema] = Field(min_length=1, max_length=200)
    gaps: list[str] = Field(default_factory=list, max_length=100)
    evidence_ids: list[int] = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def validate_chain(self):
        if [step.sequence for step in self.steps] != list(range(1, len(self.steps) + 1)):
            raise ValueError("attack chain step sequences must start at 1 and be continuous")
        if self.status == AttackChainStatus.PARTIAL and not self.gaps:
            raise ValueError("partial attack chains must describe evidence gaps")
        if self.status == AttackChainStatus.COMPLETE and self.gaps:
            raise ValueError("complete attack chains cannot contain unresolved gaps")
        linked = set(self.evidence_ids)
        if any(not set(step.evidence_ids).issubset(linked) for step in self.steps):
            raise ValueError("attack chain step evidence must be included in chain evidence_ids")
        return self


class QueryAttackChainsResponse(PaginatedResponse[AttackChainSchema]):
    pass
