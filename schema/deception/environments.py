from datetime import datetime
from enum import StrEnum
from typing import Any, Self
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from schema.common.responses import PaginatedResponse
from schema.sandbox.containers import SandboxContainerEgressMode, SandboxContainerPortMapping


MAX_DECEPTION_REFERENCE_URLS = 10
MAX_DECEPTION_REFERENCE_URL_LENGTH = 2000
MAX_DECEPTION_REFERENCE_FILES = 10
MAX_DECEPTION_REFERENCE_FILE_BYTES = 10 * 1024 * 1024
MAX_DECEPTION_REFERENCE_TOTAL_BYTES = 50 * 1024 * 1024


class DeceptionEnvironmentStatus(StrEnum):
    DRAFT = "draft"
    BUILDING = "building"
    ACTIVE = "active"
    ADAPTING = "adapting"
    PAUSED = "paused"
    RECOVERY_REQUIRED = "recovery_required"
    RETIRED = "retired"


class DeceptionAdaptationMode(StrEnum):
    POLICY_AUTO = "policy_auto"
    MANUAL_APPROVAL = "manual_approval"


class DeceptionServiceProtocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    DATABASE = "database"
    CUSTOM = "custom"


class DeceptionRevisionKind(StrEnum):
    INITIAL = "initial"
    ADAPTIVE = "adaptive"


class DeceptionContainerOwnership(StrEnum):
    PRESELECTED = "preselected"
    PLATFORM_MANAGED = "platform_managed"


class DeceptionRevisionStatus(StrEnum):
    PLANNED = "planned"
    PENDING_APPROVAL = "pending_approval"
    EXECUTING = "executing"
    APPLIED = "applied"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"
    RECOVERY_REQUIRED = "recovery_required"
    REJECTED = "rejected"


class DeceptionRevisionStepStatus(StrEnum):
    PENDING = "pending"
    APPLYING = "applying"
    APPLIED = "applied"
    VERIFYING = "verifying"
    VERIFIED = "verified"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"
    ROLLBACK_FAILED = "rollback_failed"


class DeceptionRiskLevel(StrEnum):
    LOW = "low"
    HIGH = "high"


class DeceptionEvaluationStatus(StrEnum):
    PENDING = "pending"
    EFFECTIVE = "effective"
    INEFFECTIVE = "ineffective"
    INCONCLUSIVE = "inconclusive"


class DeceptionArtifactKind(StrEnum):
    CREDENTIAL = "credential"
    TOKEN = "token"
    FILE = "file"
    URL = "url"
    SERVICE = "service"
    OTHER = "other"


class DeceptionReferenceFileState(StrEnum):
    STAGED = "staged"
    COPIED = "copied"


class DeceptionReferenceFileSchema(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    media_type: str = Field(min_length=1, max_length=255)
    size: int = Field(ge=1)
    sha256: str = Field(pattern="^[0-9a-f]{64}$")
    container_path: str = Field(min_length=1, max_length=4096)
    state: DeceptionReferenceFileState = DeceptionReferenceFileState.STAGED
    copied_container_id: int | None = Field(default=None, gt=0)
    copied_at: datetime | None = None

    @model_validator(mode="after")
    def validate_copy_state(self) -> Self:
        copied = self.copied_container_id is not None and self.copied_at is not None
        if self.state == DeceptionReferenceFileState.COPIED and not copied:
            raise ValueError("copied reference files require container and timestamp metadata")
        if self.state == DeceptionReferenceFileState.STAGED and (
            self.copied_container_id is not None or self.copied_at is not None
        ):
            raise ValueError("staged reference files cannot contain copied metadata")
        return self


class DeceptionReferenceBundleSchema(BaseModel):
    environment_id: int = Field(gt=0)
    reference_urls: list[str] = Field(
        default_factory=list,
        max_length=MAX_DECEPTION_REFERENCE_URLS,
    )
    files: list[DeceptionReferenceFileSchema] = Field(
        default_factory=list,
        max_length=MAX_DECEPTION_REFERENCE_FILES,
    )


class DeceptionServiceSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    protocol: DeceptionServiceProtocol
    port: int = Field(ge=1, le=65535)
    persona: str = Field(default="", max_length=2000)
    exposed: bool = True

    @field_validator("name", "persona", mode="before")
    @classmethod
    def normalize_text(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class DeceptionContainerPortRequirement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    container_port: int = Field(ge=1, le=65535)
    protocol: str = Field(default="tcp", pattern="^(tcp|udp)$")


class DeceptionContainerSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host_id: int = Field(gt=0)
    image_id: int = Field(gt=0)
    egress_mode: SandboxContainerEgressMode
    egress_proxy_id: int | None = Field(default=None, gt=0)
    port_requirements: list[DeceptionContainerPortRequirement] = Field(default_factory=list, max_length=32)
    port_mappings: list[SandboxContainerPortMapping] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def validate_egress(self) -> Self:
        if self.egress_mode == SandboxContainerEgressMode.PROXY and self.egress_proxy_id is None:
            raise ValueError("egress_proxy_id is required for proxy egress")
        if self.egress_mode != SandboxContainerEgressMode.PROXY and self.egress_proxy_id is not None:
            raise ValueError("egress_proxy_id is only valid for proxy egress")
        requirement_keys = [
            (item.container_port, item.protocol)
            for item in self.port_requirements
        ]
        mapping_container_keys = [
            (item.container_port, item.protocol)
            for item in self.port_mappings
        ]
        mapping_host_keys = [
            (item.host_port, item.protocol)
            for item in self.port_mappings
        ]
        if len(set(requirement_keys)) != len(requirement_keys):
            raise ValueError("container port requirements must be unique per protocol")
        if len(set(mapping_container_keys)) != len(mapping_container_keys):
            raise ValueError("container port mappings must be unique per protocol")
        if len(set(mapping_host_keys)) != len(mapping_host_keys):
            raise ValueError("host port mappings must be unique per protocol")
        return self


class DeceptionRevisionParameter(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    value_json: str = Field(max_length=16000)


class DeceptionRevisionStepPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str = Field(min_length=1, max_length=64)
    target: str = Field(min_length=1, max_length=1000)
    parameters: list[DeceptionRevisionParameter] = Field(default_factory=list, max_length=128)
    expected_effect: str = Field(min_length=1, max_length=4000)
    apply_command: str = Field(min_length=1, max_length=16000)
    verify_command: str = Field(min_length=1, max_length=16000)
    rollback_command: str = Field(min_length=1, max_length=16000)
    timeout_seconds: int = Field(default=60, ge=1, le=300)

    @field_validator(
        "kind",
        "target",
        "expected_effect",
        "apply_command",
        "verify_command",
        "rollback_command",
        mode="before",
    )
    @classmethod
    def normalize_text(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class DeceptionRevisionStepSchema(DeceptionRevisionStepPlan):
    model_config = ConfigDict(from_attributes=True)

    id: int
    revision_id: int
    sequence: int = Field(ge=1)
    status: DeceptionRevisionStepStatus
    apply_exit_code: int | None = None
    apply_output: str
    verify_exit_code: int | None = None
    verify_output: str
    rollback_exit_code: int | None = None
    rollback_output: str
    error: str
    started_at: datetime | None = None
    finished_at: datetime | None = None


class DeceptionEnvironmentSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str
    persona: str
    reference_urls: list[str]
    host_id: int
    image_id: int
    egress_mode: SandboxContainerEgressMode
    egress_proxy_id: int | None
    sandbox_container_id: int | None
    container_ownership: DeceptionContainerOwnership
    services: list[DeceptionServiceSpec]
    status: DeceptionEnvironmentStatus
    applied_revision_id: int | None
    active_revision_id: int | None
    adaptation_mode: DeceptionAdaptationMode
    last_error: str
    owner_id: int
    created_at: datetime
    updated_at: datetime


class DeceptionRevisionSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    environment_id: int
    version: int = Field(ge=1)
    kind: DeceptionRevisionKind
    status: DeceptionRevisionStatus
    rationale: str
    target_persona: str
    target_services: list[DeceptionServiceSpec]
    container_spec: DeceptionContainerSpec
    execution_container_id: int | None
    trigger_event_ids: list[int]
    trigger_signal_ids: list[int]
    engagement_goal: str
    engagement_hypothesis: str
    success_criteria: list[str]
    observation_window_seconds: int = Field(ge=60, le=604800)
    observation_deadline: datetime | None
    evaluation_status: DeceptionEvaluationStatus
    evaluation_summary: str
    source_incident_id: int | None
    evaluation_task_id: int | None
    risk_level: DeceptionRiskLevel
    approval_reason: str
    failure_reason: str
    rollback_error: str
    result: str
    created_by_agent_code: str
    created_from_session_id: str
    created_at: datetime
    started_at: datetime | None
    resolved_at: datetime | None
    steps: list[DeceptionRevisionStepSchema] = Field(default_factory=list)


class CreateDeceptionEnvironmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=4000)
    sandbox_container_id: int | None = Field(default=None, gt=0)
    host_id: int = Field(gt=0)
    image_id: int = Field(gt=0)
    egress_mode: SandboxContainerEgressMode
    egress_proxy_id: int | None = Field(default=None, gt=0)
    adaptation_mode: DeceptionAdaptationMode = DeceptionAdaptationMode.POLICY_AUTO
    reference_urls: list[str] = Field(
        default_factory=list,
        max_length=MAX_DECEPTION_REFERENCE_URLS,
    )

    @field_validator("name", "description", mode="before")
    @classmethod
    def normalize_text(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value

    @field_validator("reference_urls", mode="after")
    @classmethod
    def validate_reference_urls(cls, value: list[str]) -> list[str]:
        normalized: list[str] = []
        for item in value:
            url = item.strip()
            parsed = urlparse(url)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError("reference URLs must use http or https")
            if len(url) > MAX_DECEPTION_REFERENCE_URL_LENGTH:
                raise ValueError(
                    f"reference URL exceeds {MAX_DECEPTION_REFERENCE_URL_LENGTH} characters"
                )
            if url not in normalized:
                normalized.append(url)
        return normalized

    @model_validator(mode="after")
    def validate_egress(self) -> Self:
        if self.egress_mode == SandboxContainerEgressMode.PROXY and self.egress_proxy_id is None:
            raise ValueError("egress_proxy_id is required for proxy egress")
        if self.egress_mode != SandboxContainerEgressMode.PROXY and self.egress_proxy_id is not None:
            raise ValueError("egress_proxy_id is only valid for proxy egress")
        return self


class UpdateDeceptionEnvironmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4000)
    adaptation_mode: DeceptionAdaptationMode | None = None

    @field_validator("name", "description", mode="before")
    @classmethod
    def normalize_update_text(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value

    @model_validator(mode="after")
    def validate_updates(self) -> Self:
        if not self.model_fields_set:
            raise ValueError("at least one environment field must be provided")
        return self


class PlanDeceptionRevisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rationale: str = Field(min_length=1, max_length=8000)
    target_persona: str = Field(min_length=1, max_length=8000)
    target_services: list[DeceptionServiceSpec] = Field(min_length=1, max_length=64)
    container_spec: DeceptionContainerSpec
    trigger_event_ids: list[int] = Field(default_factory=list, max_length=1000)
    trigger_signal_ids: list[int] = Field(default_factory=list, max_length=1000)
    engagement_goal: str = Field(default="", max_length=4000)
    engagement_hypothesis: str = Field(default="", max_length=8000)
    success_criteria: list[str] = Field(default_factory=list, max_length=100)
    observation_window_seconds: int = Field(default=3600, ge=60, le=604800)
    risk_level: DeceptionRiskLevel = DeceptionRiskLevel.LOW
    approval_reason: str = Field(default="", max_length=4000)
    steps: list[DeceptionRevisionStepPlan] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def validate_service_ports(self) -> Self:
        exposed = [item for item in self.target_services if item.exposed]
        if not exposed:
            raise ValueError("a deception revision must expose at least one monitored service")
        service_keys = [
            (item.port, _service_transport(item.protocol))
            for item in exposed
        ]
        if len(set(service_keys)) != len(service_keys):
            raise ValueError("exposed deception services must use unique container ports")
        available = {
            (item.container_port, item.protocol)
            for item in self.container_spec.port_requirements
        } | {
            (item.container_port, item.protocol)
            for item in self.container_spec.port_mappings
        }
        missing = [
            f"{port}/{protocol}"
            for port, protocol in service_keys
            if (port, protocol) not in available
        ]
        if missing:
            raise ValueError(
                "exposed deception services require container port coverage: "
                + ", ".join(missing)
            )
        return self


def _service_transport(protocol: DeceptionServiceProtocol) -> str:
    return "udp" if protocol == DeceptionServiceProtocol.UDP else "tcp"


class DeceptionRevisionDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=4000)


class CreateDeceptionEnvironmentResponse(BaseModel):
    environment: DeceptionEnvironmentSchema
    session_id: str
    references: DeceptionReferenceBundleSchema


class QueryDeceptionEnvironmentsResponse(PaginatedResponse[DeceptionEnvironmentSchema]):
    pass


class QueryDeceptionRevisionsResponse(PaginatedResponse[DeceptionRevisionSchema]):
    pass


class DeceptionArtifactSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    environment_id: int
    revision_id: int
    kind: DeceptionArtifactKind
    name: str
    locator: str
    fingerprint: str
    description: str
    active: bool
    created_by_agent_code: str
    created_from_session_id: str
    created_at: datetime


class CreateDeceptionArtifactRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    revision_id: int = Field(gt=0)
    kind: DeceptionArtifactKind
    name: str = Field(min_length=1, max_length=255)
    locator: str = Field(min_length=1, max_length=4096)
    fingerprint: str = Field(min_length=1, max_length=512)
    description: str = Field(default="", max_length=4000)


class EvaluateDeceptionRevisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: DeceptionEvaluationStatus
    summary: str = Field(min_length=1, max_length=12000)

    @model_validator(mode="after")
    def require_terminal_status(self) -> Self:
        if self.status == DeceptionEvaluationStatus.PENDING:
            raise ValueError("evaluation result must be terminal")
        return self


class QueryDeceptionArtifactsResponse(PaginatedResponse[DeceptionArtifactSchema]):
    pass
