from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal
from urllib.parse import urlparse

import regex
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from schema.common.responses import PaginatedResponse


class ManagedHostSensorStatus(StrEnum):
    UNCONFIGURED = "unconfigured"
    OFFLINE = "offline"
    HEALTHY = "healthy"
    DEGRADED = "degraded"


class DetectionRuleType(StrEnum):
    ZEEK_SCRIPT = "zeek_script"
    ZEEK_SIGNATURE = "zeek_signature"
    CENTRAL_RULE = "central_rule"
    SUPPRESSION = "suppression"


class DetectionRuleOrigin(StrEnum):
    BUILTIN = "builtin"
    USER = "user"
    AGENT = "agent"


class DetectionRuleScope(StrEnum):
    GLOBAL = "global"
    HOST = "host"
    ENVIRONMENT = "environment"


class DetectionRuleVersionStatus(StrEnum):
    DRAFT = "draft"
    VALIDATION_FAILED = "validation_failed"
    VALIDATED = "validated"
    RETIRED = "retired"


class DetectionRuleChangeAction(StrEnum):
    ACTIVATE = "activate"
    REPLACE = "replace"
    DISABLE = "disable"
    ROLLBACK = "rollback"


class DetectionRuleChangeDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"
    REQUEST_CHANGES = "request_changes"


class DetectionRuleChangeStatus(StrEnum):
    PENDING_APPROVAL = "pending_approval"
    CHANGES_REQUESTED = "changes_requested"
    REJECTED = "rejected"
    DEPLOYING = "deploying"
    ROLLING_BACK = "rolling_back"
    ACTIVE = "active"
    FAILED = "failed"
    RECOVERY_REQUIRED = "recovery_required"
    SUPERSEDED = "superseded"


class DetectionRuleDeploymentStatus(StrEnum):
    PENDING = "pending"
    DEPLOYING = "deploying"
    HEALTH_CHECK = "health_check"
    ACTIVE = "active"
    ROLLING_BACK = "rolling_back"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"


DETECTION_RULE_VERSION_STATUS_TRANSITIONS: dict[
    DetectionRuleVersionStatus,
    tuple[DetectionRuleVersionStatus, ...],
] = {
    DetectionRuleVersionStatus.DRAFT: (
        DetectionRuleVersionStatus.VALIDATED,
        DetectionRuleVersionStatus.VALIDATION_FAILED,
    ),
    DetectionRuleVersionStatus.VALIDATION_FAILED: (
        DetectionRuleVersionStatus.VALIDATED,
        DetectionRuleVersionStatus.VALIDATION_FAILED,
    ),
    DetectionRuleVersionStatus.VALIDATED: (
        DetectionRuleVersionStatus.VALIDATED,
        DetectionRuleVersionStatus.VALIDATION_FAILED,
        DetectionRuleVersionStatus.RETIRED,
    ),
    DetectionRuleVersionStatus.RETIRED: (),
}


DETECTION_RULE_CHANGE_STATUS_TRANSITIONS: dict[
    DetectionRuleChangeStatus,
    tuple[DetectionRuleChangeStatus, ...],
] = {
    DetectionRuleChangeStatus.PENDING_APPROVAL: (
        DetectionRuleChangeStatus.CHANGES_REQUESTED,
        DetectionRuleChangeStatus.REJECTED,
        DetectionRuleChangeStatus.DEPLOYING,
    ),
    DetectionRuleChangeStatus.CHANGES_REQUESTED: (),
    DetectionRuleChangeStatus.REJECTED: (),
    DetectionRuleChangeStatus.DEPLOYING: (
        DetectionRuleChangeStatus.ACTIVE,
        DetectionRuleChangeStatus.ROLLING_BACK,
    ),
    DetectionRuleChangeStatus.ROLLING_BACK: (
        DetectionRuleChangeStatus.FAILED,
        DetectionRuleChangeStatus.RECOVERY_REQUIRED,
    ),
    DetectionRuleChangeStatus.ACTIVE: (DetectionRuleChangeStatus.SUPERSEDED,),
    DetectionRuleChangeStatus.FAILED: (),
    DetectionRuleChangeStatus.RECOVERY_REQUIRED: (),
    DetectionRuleChangeStatus.SUPERSEDED: (),
}


DETECTION_RULE_DEPLOYMENT_STATUS_TRANSITIONS: dict[
    DetectionRuleDeploymentStatus,
    tuple[DetectionRuleDeploymentStatus, ...],
] = {
    DetectionRuleDeploymentStatus.PENDING: (
        DetectionRuleDeploymentStatus.DEPLOYING,
        DetectionRuleDeploymentStatus.FAILED,
    ),
    DetectionRuleDeploymentStatus.DEPLOYING: (
        DetectionRuleDeploymentStatus.HEALTH_CHECK,
        DetectionRuleDeploymentStatus.ROLLING_BACK,
    ),
    DetectionRuleDeploymentStatus.HEALTH_CHECK: (
        DetectionRuleDeploymentStatus.ACTIVE,
        DetectionRuleDeploymentStatus.ROLLING_BACK,
    ),
    DetectionRuleDeploymentStatus.ACTIVE: (DetectionRuleDeploymentStatus.ROLLING_BACK,),
    DetectionRuleDeploymentStatus.ROLLING_BACK: (
        DetectionRuleDeploymentStatus.ROLLED_BACK,
        DetectionRuleDeploymentStatus.ROLLBACK_FAILED,
    ),
    DetectionRuleDeploymentStatus.ROLLBACK_FAILED: (DetectionRuleDeploymentStatus.ROLLING_BACK,),
    DetectionRuleDeploymentStatus.FAILED: (),
    DetectionRuleDeploymentStatus.ROLLED_BACK: (),
}


class DetectionSensorHealthStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"


class BehaviorClassification(StrEnum):
    EXPECTED = "expected"
    CONTEXTUAL = "contextual"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class BehaviorDecisionMode(StrEnum):
    LIVE = "live"
    REPLAY = "replay"


class BehaviorSignalStatus(StrEnum):
    OPEN = "open"
    NOTIFIED = "notified"
    CLOSED = "closed"


class CentralRuleOperator(StrEnum):
    EQUALS = "eq"
    NOT_EQUALS = "neq"
    CONTAINS = "contains"
    PREFIX = "prefix"
    SUFFIX = "suffix"
    IN = "in"
    REGEX = "regex"
    EXISTS = "exists"


JsonScalar = str | int | float | bool


class CentralRuleCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z_][A-Za-z0-9_.]*$")
    operator: CentralRuleOperator
    value: JsonScalar | list[JsonScalar] | None = None

    @model_validator(mode="after")
    def validate_operator_value(self) -> "CentralRuleCondition":
        if self.operator == "exists" and not isinstance(self.value, bool):
            raise ValueError("exists conditions require a boolean value")
        if self.operator == "in" and (
            not isinstance(self.value, list)
            or not self.value
            or len(self.value) > 256
        ):
            raise ValueError("in conditions require a non-empty list with at most 256 values")
        if self.operator == "regex":
            if not isinstance(self.value, str) or not self.value or len(self.value) > 1024:
                raise ValueError("regex conditions require a pattern between 1 and 1024 characters")
            try:
                regex.compile(self.value)
            except regex.error as exc:
                raise ValueError(f"invalid regular expression: {exc}") from exc
        return self


class CentralRuleDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    signal_kind: str = Field(min_length=1, max_length=128)
    classification: BehaviorClassification
    score: int = Field(ge=0, le=100)
    all: list[CentralRuleCondition] = Field(default_factory=list, max_length=32)
    any: list[CentralRuleCondition] = Field(default_factory=list, max_length=32)
    threshold: int = Field(default=1, ge=1, le=10000)
    window_seconds: int = Field(default=60, ge=1, le=86400)
    cooldown_seconds: int = Field(default=60, ge=0, le=86400)
    group_by: list[str] = Field(default_factory=lambda: ["source_ip"], max_length=8)
    distinct_by: list[str] = Field(default_factory=list, max_length=8)
    correlation_fields: list[str] = Field(default_factory=lambda: ["source_ip"], max_length=8)
    material: bool = True
    reason: str = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def validate_conditions(self) -> "CentralRuleDefinition":
        if not self.all and not self.any:
            raise ValueError("central rule requires at least one condition")
        if self.classification in {BehaviorClassification.EXPECTED, BehaviorClassification.CONTEXTUAL} and self.score >= 40:
            raise ValueError("expected and contextual rules must score below 40")
        if self.classification in {BehaviorClassification.SUSPICIOUS, BehaviorClassification.MALICIOUS} and self.score < 40:
            raise ValueError("suspicious and malicious rules must score at least 40")
        for name, fields in (
            ("group_by", self.group_by),
            ("distinct_by", self.distinct_by),
            ("correlation_fields", self.correlation_fields),
        ):
            if len(fields) != len(set(fields)):
                raise ValueError(f"{name} fields must be unique")
            if any(not regex.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", field) for field in fields):
                raise ValueError(f"{name} contains an invalid field path")
        return self


class SuppressionRuleDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_rule_ids: list[int] = Field(min_length=1, max_length=100)
    all: list[CentralRuleCondition] = Field(min_length=1, max_length=32)
    reason: str = Field(min_length=1, max_length=1000)


class DetectionSensorHealthSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sensor_id: str
    status: DetectionSensorHealthStatus
    active_bundle_hash: str
    desired_bundle_hash: str
    sequence: int = Field(ge=0)
    error: str
    observed_at: datetime


class DetectionRuleValidationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    valid: bool
    errors: list[str]
    normalized: CentralRuleDefinition | SuppressionRuleDefinition | None
    validator: Literal["v3il-static-detection-v1"] = "v3il-static-detection-v1"
    sensor_validation_required: bool


class DetectionReplayClassificationCount(BaseModel):
    model_config = ConfigDict(extra="forbid")

    classification: BehaviorClassification
    count: int = Field(ge=0)


class CentralDetectionRuleReplayResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["central"] = "central"
    evaluated: int = Field(ge=0)
    matched: int = Field(ge=0)
    classifications: list[DetectionReplayClassificationCount]


class SensorDetectionRuleReplayResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["sensor_validation_required"] = "sensor_validation_required"
    evaluated: Literal[0] = 0
    matched: Literal[0] = 0
    note: str


DetectionRuleReplayResult = Annotated[
    CentralDetectionRuleReplayResult | SensorDetectionRuleReplayResult,
    Field(discriminator="kind"),
]


class MatchedDetectionRuleVersion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: int
    version_id: int
    content_sha256: str
    score: int = Field(ge=0, le=100)
    classification: BehaviorClassification
    suppressed: bool


class ManagedHostSensorSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    host_id: int
    sensor_id: str
    capture_interface: str
    excluded_ports: list[int]
    proxy_url: str
    status: ManagedHostSensorStatus
    active_bundle_hash: str
    desired_bundle_hash: str
    last_sequence: int
    last_error: str
    last_heartbeat_at: datetime | None
    created_at: datetime
    updated_at: datetime


class DetectionRuleSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str
    type: DetectionRuleType
    origin: DetectionRuleOrigin
    scope: DetectionRuleScope
    host_id: int | None
    environment_id: int | None
    active_version_id: int | None
    created_by_actor_type: str
    created_by_actor_code: str
    created_at: datetime
    updated_at: datetime


class DetectionRuleVersionSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: int
    version: int
    parent_version_id: int | None
    status: DetectionRuleVersionStatus
    content: str
    content_sha256: str
    validation_result: DetectionRuleValidationResult
    replay_result: DetectionRuleReplayResult | None
    created_by_actor_type: str
    created_by_actor_code: str
    created_from_session_id: str
    created_at: datetime
    validated_at: datetime | None


class DetectionRuleChangeRequestSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: int
    rule_version_id: int | None
    action: DetectionRuleChangeAction
    status: DetectionRuleChangeStatus
    content_sha256: str
    scope: DetectionRuleScope
    target_sensor_ids: list[int]
    effective_bundle_hash: str
    reason: str
    requested_by_actor_type: str
    requested_by_actor_code: str
    requested_from_session_id: str
    decided_by_user_id: int | None
    decision_reason: str
    error: str
    created_at: datetime
    decided_at: datetime | None
    resolved_at: datetime | None


class DetectionRuleDeploymentSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    change_request_id: int
    sensor_id: int
    status: DetectionRuleDeploymentStatus
    previous_bundle_hash: str
    target_bundle_hash: str
    observed_bundle_hash: str
    health_snapshot: DetectionSensorHealthSnapshot | None
    rollback_observed_bundle_hash: str
    rollback_health_snapshot: DetectionSensorHealthSnapshot | None
    runtime_owner_id: str
    lease_fencing_token: int
    attempt: int
    error: str
    started_at: datetime | None
    health_checked_at: datetime | None
    resolved_at: datetime | None


class BehaviorDecisionSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    event_id: int
    mode: BehaviorDecisionMode
    bundle_hash: str
    classification: BehaviorClassification
    score: int
    signal_kind: str
    reason: str
    matched_rule_versions: list[MatchedDetectionRuleVersion]
    suppression_rule_versions: list[int]
    material: bool
    created_at: datetime


class BehaviorSignalSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    environment_id: int
    incident_id: int | None
    aggregation_key: str
    kind: str
    classification: BehaviorClassification
    score: int
    correlation_keys: list[str]
    event_count: int
    threshold_count: int
    threshold: int
    status: BehaviorSignalStatus
    first_observed_at: datetime
    last_observed_at: datetime
    debounce_until: datetime | None
    cooldown_until: datetime | None
    notified_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ConfigureManagedHostSensorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host_id: int = Field(gt=0)
    sensor_id: str = Field(min_length=1, max_length=128)
    capture_interface: str = Field(min_length=1, max_length=128)
    excluded_ports: list[int] = Field(default_factory=list, max_length=128)
    proxy_url: str = Field(min_length=1, max_length=2000)
    proxy_token: str = Field(min_length=16, max_length=512)

    @field_validator("excluded_ports", mode="after")
    @classmethod
    def validate_ports(cls, value: list[int]) -> list[int]:
        ports = list(dict.fromkeys(value))
        if any(port < 1 or port > 65535 for port in ports):
            raise ValueError("excluded ports must be between 1 and 65535")
        return sorted(ports)

    @field_validator("proxy_url", mode="after")
    @classmethod
    def validate_proxy_url(cls, value: str) -> str:
        normalized = value.strip().rstrip("/")
        parsed = urlparse(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("proxy URL must be an absolute HTTP or HTTPS URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("proxy URL cannot contain credentials, a query, or a fragment")
        return normalized


class CreateDetectionRuleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=4000)
    type: DetectionRuleType
    scope: DetectionRuleScope
    host_id: int | None = Field(default=None, gt=0)
    environment_id: int | None = Field(default=None, gt=0)
    content: str = Field(min_length=1, max_length=256000)


class CreateDetectionRuleVersionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    parent_version_id: int | None = Field(default=None, gt=0)
    content: str = Field(min_length=1, max_length=256000)


class ReplayDetectionRuleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_ids: list[int] = Field(min_length=1, max_length=5000)


class SubmitDetectionRuleChangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: DetectionRuleChangeAction
    rule_version_id: int | None = Field(default=None, gt=0)
    target_sensor_ids: list[int] = Field(min_length=1, max_length=1000)
    reason: str = Field(min_length=1, max_length=4000)


class DecideDetectionRuleChangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: DetectionRuleChangeDecision
    reason: str = Field(min_length=1, max_length=4000)


class QueryManagedHostSensorsResponse(PaginatedResponse[ManagedHostSensorSchema]):
    pass


class QueryDetectionRulesResponse(PaginatedResponse[DetectionRuleSchema]):
    pass


class QueryRuleVersionsResponse(PaginatedResponse[DetectionRuleVersionSchema]):
    pass


class QueryRuleChangesResponse(PaginatedResponse[DetectionRuleChangeRequestSchema]):
    pass


class QueryRuleDeploymentsResponse(PaginatedResponse[DetectionRuleDeploymentSchema]):
    pass


class QueryBehaviorDecisionsResponse(PaginatedResponse[BehaviorDecisionSchema]):
    pass


class QueryBehaviorSignalsResponse(PaginatedResponse[BehaviorSignalSchema]):
    pass


class CreateDetectionRuleResponse(BaseModel):
    rule: DetectionRuleSchema
    version: DetectionRuleVersionSchema
