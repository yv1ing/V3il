from datetime import datetime
from typing import Any

from sqlalchemy import Column, Index, JSON, UniqueConstraint
from sqlmodel import Field, SQLModel

from schema.threat.behaviors import (
    BehaviorDirection,
    BehaviorEventCategory,
    BehaviorEventSource,
    BehaviorOutcome,
)
from utils.sqlalchemy import enum_value_type, utc_datetime_column
from utils.time import utc_now


class BehaviorEvent(SQLModel, table=True):
    __tablename__ = "behavior_events"
    __table_args__ = (
        UniqueConstraint("environment_id", "sensor_id", "sequence", name="uq_behavior_event_sensor_sequence"),
        Index("ix_behavior_events_environment_observed", "environment_id", "observed_at"),
        Index("ix_behavior_events_environment_category", "environment_id", "category"),
    )

    id: int | None = Field(default=None, primary_key=True)
    environment_id: int = Field(foreign_key="deception_environments.id", index=True, ondelete="RESTRICT")
    sensor_id: str = Field(index=True)
    network_session_id: str = Field(default="", max_length=128, index=True)
    sensor_bundle_hash: str = Field(default="", max_length=64, index=True)
    deception_artifact_id: int | None = Field(
        default=None,
        foreign_key="deception_artifacts.id",
        index=True,
        ondelete="RESTRICT",
    )
    sequence: int = Field(index=True)
    observed_at: datetime = Field(sa_column=utc_datetime_column(index=True))
    category: BehaviorEventCategory = Field(
        sa_column=Column(enum_value_type(BehaviorEventCategory, length=32), nullable=False, index=True)
    )
    action: str = Field(index=True)
    source: BehaviorEventSource = Field(
        sa_column=Column(enum_value_type(BehaviorEventSource, length=32), nullable=False, index=True)
    )
    direction: BehaviorDirection = Field(
        sa_column=Column(enum_value_type(BehaviorDirection, length=32), nullable=False, index=True)
    )
    outcome: BehaviorOutcome = Field(
        sa_column=Column(enum_value_type(BehaviorOutcome, length=32), nullable=False, index=True)
    )
    source_ip: str = Field(default="", index=True)
    source_port: int | None = Field(default=None)
    destination_ip: str = Field(default="", index=True)
    destination_port: int | None = Field(default=None)
    protocol: str = Field(default="", index=True)
    process_id: int | None = Field(default=None)
    parent_process_id: int | None = Field(default=None)
    process_name: str = Field(default="", index=True)
    command_line: str = ""
    file_path: str = Field(default="", index=True)
    username: str = Field(default="", index=True)
    service_name: str = Field(default="", index=True)
    summary: str = ""
    raw_reference: str = ""
    attributes: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
    sensor_previous_hash: str = Field(default="", max_length=64, index=True)
    sensor_event_hash: str = Field(default="", max_length=64, index=True)
    previous_event_hash: str = Field(default="", max_length=64, index=True)
    event_hash: str = Field(max_length=64, index=True)
    ingested_at: datetime = Field(
        default_factory=utc_now,
        sa_column=utc_datetime_column(index=True),
    )


class BehaviorSensorCursor(SQLModel, table=True):
    __tablename__ = "behavior_sensor_cursors"

    environment_id: int = Field(
        foreign_key="deception_environments.id",
        primary_key=True,
        ondelete="RESTRICT",
    )
    sensor_id: str = Field(primary_key=True, max_length=128)
    last_sequence: int = Field(default=0)
    verification_token: str = Field(default="")
    last_sensor_hash: str = Field(default="", max_length=64)
    last_event_hash: str = Field(default="", max_length=64)
    last_observed_at: datetime | None = Field(default=None, sa_column=utc_datetime_column(nullable=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_column=utc_datetime_column())


class ThreatIncidentBehaviorEvent(SQLModel, table=True):
    __tablename__ = "threat_incident_behavior_events"

    event_id: int = Field(foreign_key="behavior_events.id", primary_key=True, ondelete="RESTRICT")
    incident_id: int = Field(foreign_key="threat_incidents.id", index=True, ondelete="RESTRICT")
    linked_by_agent_code: str = Field(default="", index=True)
    linked_from_session_id: str = Field(default="", index=True)
    correlation_method: str = Field(default="", max_length=64, index=True)
    correlation_key: str = Field(default="", max_length=512)
    is_material: bool = Field(default=True)
    materiality_reason: str = ""
    correlation_score: int = Field(default=0)
    linked_at: datetime = Field(default_factory=utc_now, sa_column=utc_datetime_column())
