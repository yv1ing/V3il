from datetime import datetime

from sqlalchemy import Column, Index, JSON, UniqueConstraint
from sqlmodel import Field, SQLModel

from schema.threat.incidents import ThreatConfidence, ThreatIncidentStatus, ThreatSeverity
from utils.sqlalchemy import enum_value_type


class ThreatIncident(SQLModel, table=True):
    __tablename__ = "threat_incidents"
    __table_args__ = (
        Index("ix_threat_incidents_status_observed", "status", "last_observed_at"),
        Index("ix_threat_incidents_fingerprint_status", "primary_fingerprint", "status"),
    )

    id: int | None = Field(default=None, primary_key=True)
    title: str = Field(index=True)
    status: ThreatIncidentStatus = Field(
        default=ThreatIncidentStatus.OPEN,
        sa_column=Column(enum_value_type(ThreatIncidentStatus, length=32), nullable=False, index=True),
    )
    severity: ThreatSeverity = Field(
        default=ThreatSeverity.INFO,
        sa_column=Column(enum_value_type(ThreatSeverity, length=32), nullable=False, index=True),
    )
    confidence: ThreatConfidence = Field(
        default=ThreatConfidence.LOW,
        sa_column=Column(enum_value_type(ThreatConfidence, length=32), nullable=False, index=True),
    )
    risk_score: int = Field(default=0)
    primary_fingerprint: str = Field(default="", index=True)
    source_ips: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    summary: str = ""
    first_observed_at: datetime = Field(default_factory=datetime.now, index=True)
    last_observed_at: datetime = Field(default_factory=datetime.now, index=True)
    idle_deadline: datetime | None = Field(default=None, index=True)
    owner_id: int = Field(foreign_key="system_users.id", index=True, ondelete="RESTRICT")
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)


class ThreatIncidentEnvironment(SQLModel, table=True):
    __tablename__ = "threat_incident_environments"
    __table_args__ = (
        UniqueConstraint("incident_id", "environment_id", name="uq_threat_incident_environment"),
    )

    incident_id: int = Field(foreign_key="threat_incidents.id", primary_key=True, ondelete="CASCADE")
    environment_id: int = Field(
        foreign_key="deception_environments.id",
        primary_key=True,
        index=True,
        ondelete="CASCADE",
    )
    first_observed_at: datetime = Field(index=True)
    last_observed_at: datetime = Field(index=True)
    correlation_method: str = Field(default="", max_length=64, index=True)
    correlation_key: str = Field(default="", max_length=512)
    linked_at: datetime = Field(default_factory=datetime.now)
