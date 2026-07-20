from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, CheckConstraint, Column, DateTime, Index, JSON, LargeBinary, text
from sqlmodel import Field, SQLModel

from schema.threat.incidents import ThreatConfidence
from schema.threat.intelligence import (
    IntelligenceReportStatus,
    KnowledgePublicationStatus,
    ThreatIndicatorDisposition,
    ThreatIndicatorType,
)
from utils.sqlalchemy import enum_value_type, utc_datetime_column
from utils.time import utc_now


class ThreatIndicator(SQLModel, table=True):
    __tablename__ = "threat_indicators"

    analysis_id: int = Field(foreign_key="analysis_records.id", primary_key=True, ondelete="RESTRICT")
    type: ThreatIndicatorType = Field(
        sa_column=Column(enum_value_type(ThreatIndicatorType, length=32), nullable=False, index=True)
    )
    value: str = Field(index=True)
    disposition: ThreatIndicatorDisposition = Field(
        sa_column=Column(enum_value_type(ThreatIndicatorDisposition, length=32), nullable=False, index=True)
    )
    confidence: ThreatConfidence = Field(
        sa_column=Column(enum_value_type(ThreatConfidence, length=32), nullable=False, index=True)
    )
    context: str = ""
    first_observed_at: datetime = Field(sa_column=utc_datetime_column(index=True))
    last_observed_at: datetime = Field(sa_column=utc_datetime_column(index=True))


class IntelligenceReport(SQLModel, table=True):
    __tablename__ = "intelligence_reports"
    __table_args__ = (
        Index("uq_intelligence_reports_version", "incident_id", "version", unique=True),
        Index(
            "uq_intelligence_reports_current",
            "incident_id",
            unique=True,
            postgresql_where=text("is_current"),
        ),
        Index("ix_intelligence_reports_incident_status", "incident_id", "status"),
        CheckConstraint(
            "status <> 'final' OR (artifact_sha256 <> '' AND artifact_size > 0)",
            name="ck_intelligence_report_final_artifact",
        ),
    )

    id: int | None = Field(default=None, primary_key=True)
    incident_id: int = Field(foreign_key="threat_incidents.id", index=True, ondelete="RESTRICT")
    version: int = Field(index=True)
    is_current: bool = Field(default=True, sa_column=Column(Boolean, nullable=False, index=True))
    status: IntelligenceReportStatus = Field(
        sa_column=Column(enum_value_type(IntelligenceReportStatus, length=32), nullable=False, index=True)
    )
    title: str = Field(index=True)
    executive_summary: str = ""
    behavior_summary: str = ""
    deception_summary: str = ""
    conclusion: str = ""
    analysis_snapshot: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    evidence_manifest: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
    markdown: str = ""
    artifact_sha256: str = Field(default="", max_length=64, index=True)
    artifact_media_type: str = Field(default="", max_length=128)
    artifact_filename: str = Field(default="", max_length=255)
    artifact_size: int = 0
    knowledge_document_name: str = Field(default="", index=True)
    knowledge_status: KnowledgePublicationStatus = Field(
        default=KnowledgePublicationStatus.NOT_QUEUED,
        sa_column=Column(enum_value_type(KnowledgePublicationStatus, length=32), nullable=False, index=True),
    )
    knowledge_error: str = ""
    created_by_agent_code: str = Field(default="", index=True)
    created_from_session_id: str = Field(default="", index=True)
    created_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))


class IntelligenceReportArtifact(SQLModel, table=True):
    __tablename__ = "intelligence_report_artifacts"

    report_id: int = Field(
        foreign_key="intelligence_reports.id",
        primary_key=True,
        ondelete="RESTRICT",
    )
    sha256: str = Field(max_length=64, unique=True, index=True)
    media_type: str = Field(max_length=128)
    filename: str = Field(max_length=255)
    content: bytes = Field(sa_column=Column(LargeBinary, nullable=False))
    byte_size: int
    created_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))
