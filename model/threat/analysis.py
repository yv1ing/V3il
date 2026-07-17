from datetime import datetime

from sqlalchemy import Boolean, Column, Index, JSON, text
from sqlmodel import Field, SQLModel

from schema.threat.analysis import (
    AnalysisReviewStatus,
    AnalysisKind,
    AttackStage,
    AttackerProfileStatus,
    IntentAssessmentStatus,
)
from schema.threat.incidents import ThreatConfidence, ThreatSeverity
from utils.sqlalchemy import enum_value_type


class AnalysisRecord(SQLModel, table=True):
    __tablename__ = "analysis_records"
    __table_args__ = (
        Index(
            "uq_analysis_records_current",
            "incident_id",
            "kind",
            "subject_key",
            unique=True,
            postgresql_where=text("is_current"),
        ),
        Index(
            "uq_analysis_records_version",
            "incident_id",
            "kind",
            "subject_key",
            "version",
            unique=True,
        ),
        Index("ix_analysis_records_incident_kind", "incident_id", "kind"),
    )

    id: int | None = Field(default=None, primary_key=True)
    incident_id: int = Field(foreign_key="threat_incidents.id", index=True, ondelete="CASCADE")
    kind: AnalysisKind = Field(
        sa_column=Column(enum_value_type(AnalysisKind, length=32), nullable=False, index=True)
    )
    subject_key: str = Field(default="default", max_length=1024, index=True)
    version: int = Field(index=True)
    is_current: bool = Field(default=True, sa_column=Column(Boolean, nullable=False, index=True))
    investigation_task_id: int | None = Field(
        default=None,
        foreign_key="investigation_tasks.id",
        index=True,
        ondelete="RESTRICT",
    )
    review_status: AnalysisReviewStatus = Field(
        default=AnalysisReviewStatus.ACCEPTED,
        sa_column=Column(enum_value_type(AnalysisReviewStatus, length=32), nullable=False, index=True),
    )
    created_by_agent_code: str = Field(default="", index=True)
    created_from_session_id: str = Field(default="", index=True)
    created_at: datetime = Field(default_factory=datetime.now)


class AnalysisEvidenceLink(SQLModel, table=True):
    __tablename__ = "analysis_evidence_links"

    analysis_id: int = Field(foreign_key="analysis_records.id", primary_key=True, ondelete="CASCADE")
    evidence_id: int = Field(
        foreign_key="investigation_evidence.id",
        primary_key=True,
        index=True,
        ondelete="RESTRICT",
    )


class IntentAssessment(SQLModel, table=True):
    __tablename__ = "intent_assessments"

    analysis_id: int = Field(foreign_key="analysis_records.id", primary_key=True, ondelete="CASCADE")
    stage: AttackStage = Field(
        sa_column=Column(enum_value_type(AttackStage, length=32), nullable=False, index=True)
    )
    intent: str = ""
    status: IntentAssessmentStatus = Field(
        sa_column=Column(enum_value_type(IntentAssessmentStatus, length=32), nullable=False, index=True)
    )
    confidence: ThreatConfidence = Field(
        sa_column=Column(enum_value_type(ThreatConfidence, length=32), nullable=False, index=True)
    )
    rationale: str = ""
    predicted_next_actions: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    technique_ids: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))


class AttackerProfile(SQLModel, table=True):
    __tablename__ = "attacker_profiles"

    analysis_id: int = Field(foreign_key="analysis_records.id", primary_key=True, ondelete="CASCADE")
    status: AttackerProfileStatus = Field(
        sa_column=Column(enum_value_type(AttackerProfileStatus, length=32), nullable=False, index=True)
    )
    summary: str = ""
    objectives: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    capabilities: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    skill_level: str = ""
    operational_patterns: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    tools: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    infrastructure: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    identity_hypotheses: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    attribution_limits: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    confidence: ThreatConfidence = Field(
        sa_column=Column(enum_value_type(ThreatConfidence, length=32), nullable=False, index=True)
    )


class RiskAssessment(SQLModel, table=True):
    __tablename__ = "risk_assessments"

    analysis_id: int = Field(foreign_key="analysis_records.id", primary_key=True, ondelete="CASCADE")
    severity: ThreatSeverity = Field(
        sa_column=Column(enum_value_type(ThreatSeverity, length=32), nullable=False, index=True)
    )
    confidence: ThreatConfidence = Field(
        sa_column=Column(enum_value_type(ThreatConfidence, length=32), nullable=False, index=True)
    )
    risk_score: int = Field(default=0)
    rationale: str = ""
    stop_conditions: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    response_recommendations: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    defense_improvements: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    residual_risk: str = ""
