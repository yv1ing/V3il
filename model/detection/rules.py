from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, CheckConstraint, Column, Index, JSON, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

from schema.detection.rules import (
    BehaviorClassification,
    BehaviorDecisionMode,
    BehaviorSignalStatus,
    DetectionRuleChangeAction,
    DetectionRuleChangeStatus,
    DetectionRuleDeploymentStatus,
    DetectionRuleOrigin,
    DetectionRuleScope,
    DetectionRuleType,
    DetectionRuleVersionStatus,
    ManagedHostSensorStatus,
)
from utils.sqlalchemy import enum_value_type, utc_datetime_column
from utils.time import utc_now


class ManagedHostSensor(SQLModel, table=True):
    __tablename__ = "managed_host_sensors"
    __table_args__ = (
        UniqueConstraint("host_id", name="uq_managed_host_sensor_host"),
        UniqueConstraint("sensor_id", name="uq_managed_host_sensor_id"),
    )

    id: int | None = Field(default=None, primary_key=True)
    host_id: int = Field(foreign_key="managed_hosts.id", index=True, ondelete="RESTRICT")
    sensor_id: str = Field(max_length=128, index=True)
    capture_interface: str = Field(max_length=128)
    excluded_ports: list[int] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    proxy_url: str = Field(max_length=2000)
    proxy_token: str = Field(default="", max_length=512)
    status: ManagedHostSensorStatus = Field(
        default=ManagedHostSensorStatus.UNCONFIGURED,
        sa_column=Column(enum_value_type(ManagedHostSensorStatus, length=32), nullable=False, index=True),
    )
    active_bundle_hash: str = Field(default="", max_length=64, index=True)
    desired_bundle_hash: str = Field(default="", max_length=64, index=True)
    last_sequence: int = Field(default=0)
    last_error: str = ""
    last_heartbeat_at: datetime | None = Field(
        default=None,
        sa_column=utc_datetime_column(nullable=True, index=True),
    )
    created_at: datetime = Field(default_factory=utc_now, sa_column=utc_datetime_column())
    updated_at: datetime = Field(default_factory=utc_now, sa_column=utc_datetime_column())


class DetectionRule(SQLModel, table=True):
    __tablename__ = "detection_rules"
    __table_args__ = (
        CheckConstraint(
            "(scope = 'global' AND host_id IS NULL AND environment_id IS NULL) OR "
            "(scope = 'host' AND host_id IS NOT NULL AND environment_id IS NULL) OR "
            "(scope = 'environment' AND host_id IS NULL AND environment_id IS NOT NULL)",
            name="ck_detection_rule_scope_target",
        ),
        Index("ix_detection_rules_scope_type", "scope", "type"),
    )

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(max_length=255, index=True)
    description: str = ""
    type: DetectionRuleType = Field(
        sa_column=Column(enum_value_type(DetectionRuleType, length=32), nullable=False, index=True)
    )
    origin: DetectionRuleOrigin = Field(
        sa_column=Column(enum_value_type(DetectionRuleOrigin, length=32), nullable=False, index=True)
    )
    scope: DetectionRuleScope = Field(
        sa_column=Column(enum_value_type(DetectionRuleScope, length=32), nullable=False, index=True)
    )
    host_id: int | None = Field(default=None, foreign_key="managed_hosts.id", index=True, ondelete="RESTRICT")
    environment_id: int | None = Field(default=None, foreign_key="deception_environments.id", index=True, ondelete="RESTRICT")
    active_version_id: int | None = Field(default=None, index=True)
    created_by_actor_type: str = Field(default="user", max_length=32, index=True)
    created_by_actor_code: str = Field(default="", max_length=128, index=True)
    created_at: datetime = Field(default_factory=utc_now, sa_column=utc_datetime_column())
    updated_at: datetime = Field(default_factory=utc_now, sa_column=utc_datetime_column())


class DetectionRuleVersion(SQLModel, table=True):
    __tablename__ = "detection_rule_versions"
    __table_args__ = (
        UniqueConstraint("rule_id", "version", name="uq_detection_rule_version"),
        Index("ix_detection_rule_versions_rule_status", "rule_id", "status"),
    )

    id: int | None = Field(default=None, primary_key=True)
    rule_id: int = Field(foreign_key="detection_rules.id", index=True, ondelete="RESTRICT")
    version: int = Field(index=True)
    parent_version_id: int | None = Field(default=None, foreign_key="detection_rule_versions.id", ondelete="RESTRICT")
    status: DetectionRuleVersionStatus = Field(
        sa_column=Column(enum_value_type(DetectionRuleVersionStatus, length=32), nullable=False, index=True)
    )
    content: str = Field(sa_column=Column(Text, nullable=False))
    content_sha256: str = Field(max_length=64, index=True)
    validation_result: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
    replay_result: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON, nullable=True))
    created_by_actor_type: str = Field(default="user", max_length=32, index=True)
    created_by_actor_code: str = Field(default="", max_length=128, index=True)
    created_from_session_id: str = Field(default="", index=True)
    created_at: datetime = Field(default_factory=utc_now, sa_column=utc_datetime_column())
    validated_at: datetime | None = Field(default=None, sa_column=utc_datetime_column(nullable=True))


class DetectionRuleChangeRequest(SQLModel, table=True):
    __tablename__ = "detection_rule_change_requests"
    __table_args__ = (Index("ix_detection_change_status_created", "status", "created_at"),)

    id: int | None = Field(default=None, primary_key=True)
    rule_id: int = Field(foreign_key="detection_rules.id", index=True, ondelete="RESTRICT")
    rule_version_id: int | None = Field(default=None, foreign_key="detection_rule_versions.id", index=True, ondelete="RESTRICT")
    action: DetectionRuleChangeAction = Field(
        sa_column=Column(enum_value_type(DetectionRuleChangeAction, length=32), nullable=False, index=True)
    )
    status: DetectionRuleChangeStatus = Field(
        sa_column=Column(enum_value_type(DetectionRuleChangeStatus, length=32), nullable=False, index=True)
    )
    content_sha256: str = Field(default="", max_length=64)
    scope: DetectionRuleScope = Field(
        sa_column=Column(enum_value_type(DetectionRuleScope, length=32), nullable=False, index=True)
    )
    target_sensor_ids: list[int] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    effective_bundle_hash: str = Field(max_length=64, index=True)
    reason: str = ""
    requested_by_actor_type: str = Field(default="user", max_length=32, index=True)
    requested_by_actor_code: str = Field(default="", max_length=128, index=True)
    requested_from_session_id: str = Field(default="", index=True)
    decided_by_user_id: int | None = Field(default=None, foreign_key="system_users.id", ondelete="RESTRICT")
    decision_reason: str = ""
    error: str = ""
    created_at: datetime = Field(default_factory=utc_now, sa_column=utc_datetime_column())
    decided_at: datetime | None = Field(default=None, sa_column=utc_datetime_column(nullable=True))
    resolved_at: datetime | None = Field(default=None, sa_column=utc_datetime_column(nullable=True))


class DetectionRuleDeployment(SQLModel, table=True):
    __tablename__ = "detection_rule_deployments"
    __table_args__ = (
        UniqueConstraint("change_request_id", "sensor_id", "attempt", name="uq_detection_deployment_attempt"),
        Index("ix_detection_deployments_change_status", "change_request_id", "status"),
        CheckConstraint(
            "status != 'active' OR (observed_bundle_hash = target_bundle_hash AND health_snapshot IS NOT NULL)",
            name="ck_detection_deployment_active_observation",
        ),
        CheckConstraint(
            "status != 'rolled_back' OR "
            "(rollback_observed_bundle_hash = previous_bundle_hash AND rollback_health_snapshot IS NOT NULL)",
            name="ck_detection_deployment_rollback_observation",
        ),
        CheckConstraint("attempt > 0", name="ck_detection_deployment_attempt"),
        CheckConstraint(
            "(started_at IS NULL AND runtime_owner_id = '' AND lease_fencing_token = 0) OR "
            "(started_at IS NOT NULL AND runtime_owner_id <> '' AND lease_fencing_token > 0)",
            name="ck_detection_deployment_runtime_owner",
        ),
    )

    id: int | None = Field(default=None, primary_key=True)
    change_request_id: int = Field(foreign_key="detection_rule_change_requests.id", index=True, ondelete="RESTRICT")
    sensor_id: int = Field(foreign_key="managed_host_sensors.id", index=True, ondelete="RESTRICT")
    status: DetectionRuleDeploymentStatus = Field(
        sa_column=Column(enum_value_type(DetectionRuleDeploymentStatus, length=32), nullable=False, index=True)
    )
    previous_bundle_hash: str = Field(default="", max_length=64)
    target_bundle_hash: str = Field(max_length=64, index=True)
    observed_bundle_hash: str = Field(default="", max_length=64)
    health_snapshot: dict | None = Field(default=None, sa_column=Column(JSON, nullable=True))
    rollback_observed_bundle_hash: str = Field(default="", max_length=64)
    rollback_health_snapshot: dict | None = Field(default=None, sa_column=Column(JSON, nullable=True))
    runtime_owner_id: str = Field(default="", max_length=128)
    lease_fencing_token: int = Field(default=0, sa_column=Column(BigInteger, nullable=False))
    attempt: int = Field(default=1)
    error: str = ""
    started_at: datetime | None = Field(default=None, sa_column=utc_datetime_column(nullable=True))
    health_checked_at: datetime | None = Field(default=None, sa_column=utc_datetime_column(nullable=True))
    resolved_at: datetime | None = Field(default=None, sa_column=utc_datetime_column(nullable=True))


class DetectionBundle(SQLModel, table=True):
    __tablename__ = "detection_bundles"

    bundle_hash: str = Field(primary_key=True, max_length=64)
    content: dict[str, Any] = Field(sa_column=Column(JSON, nullable=False))
    created_at: datetime = Field(default_factory=utc_now, sa_column=utc_datetime_column())


class BehaviorDecision(SQLModel, table=True):
    __tablename__ = "behavior_decisions"
    __table_args__ = (
        UniqueConstraint("event_id", "mode", "bundle_hash", name="uq_behavior_decision_evaluation"),
        Index("ix_behavior_decisions_classification_created", "classification", "created_at"),
    )

    id: int | None = Field(default=None, primary_key=True)
    event_id: int = Field(foreign_key="behavior_events.id", index=True, ondelete="RESTRICT")
    mode: BehaviorDecisionMode = Field(
        sa_column=Column(enum_value_type(BehaviorDecisionMode, length=16), nullable=False, index=True)
    )
    bundle_hash: str = Field(max_length=64, index=True)
    classification: BehaviorClassification = Field(
        sa_column=Column(enum_value_type(BehaviorClassification, length=32), nullable=False, index=True)
    )
    score: int = Field(default=0, ge=0, le=100, index=True)
    signal_kind: str = Field(default="", max_length=128, index=True)
    reason: str = ""
    matched_rule_versions: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    suppression_rule_versions: list[int] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    material: bool = Field(default=False, sa_column=Column(Boolean, nullable=False))
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=utc_datetime_column(index=True),
    )


class BehaviorSignal(SQLModel, table=True):
    __tablename__ = "behavior_signals"
    __table_args__ = (
        Index("ix_behavior_signals_environment_status", "environment_id", "status"),
        Index("ix_behavior_signals_aggregation_updated", "aggregation_key", "updated_at"),
    )

    id: int | None = Field(default=None, primary_key=True)
    environment_id: int = Field(foreign_key="deception_environments.id", index=True, ondelete="RESTRICT")
    incident_id: int | None = Field(default=None, foreign_key="threat_incidents.id", index=True, ondelete="RESTRICT")
    aggregation_key: str = Field(max_length=512, index=True)
    kind: str = Field(max_length=128, index=True)
    classification: BehaviorClassification = Field(
        sa_column=Column(enum_value_type(BehaviorClassification, length=32), nullable=False, index=True)
    )
    score: int = Field(ge=0, le=100, index=True)
    correlation_keys: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    event_count: int = Field(default=0)
    threshold_count: int = Field(default=0)
    distinct_keys: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    threshold: int = Field(default=1)
    status: BehaviorSignalStatus = Field(
        sa_column=Column(enum_value_type(BehaviorSignalStatus, length=32), nullable=False, index=True)
    )
    first_observed_at: datetime = Field(sa_column=utc_datetime_column(index=True))
    last_observed_at: datetime = Field(sa_column=utc_datetime_column(index=True))
    debounce_until: datetime | None = Field(
        default=None,
        sa_column=utc_datetime_column(nullable=True, index=True),
    )
    cooldown_until: datetime | None = Field(
        default=None,
        sa_column=utc_datetime_column(nullable=True, index=True),
    )
    notified_at: datetime | None = Field(default=None, sa_column=utc_datetime_column(nullable=True))
    created_at: datetime = Field(default_factory=utc_now, sa_column=utc_datetime_column())
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=utc_datetime_column(index=True),
    )


class BehaviorSignalEvent(SQLModel, table=True):
    __tablename__ = "behavior_signal_events"

    signal_id: int = Field(foreign_key="behavior_signals.id", primary_key=True, ondelete="RESTRICT")
    event_id: int = Field(foreign_key="behavior_events.id", primary_key=True, index=True, ondelete="RESTRICT")
    decision_id: int = Field(foreign_key="behavior_decisions.id", index=True, ondelete="RESTRICT")
    linked_at: datetime = Field(default_factory=utc_now, sa_column=utc_datetime_column())
