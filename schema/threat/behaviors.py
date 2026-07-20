import ipaddress
import json
import math
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from schema.common.responses import PaginatedResponse


MAX_BEHAVIOR_ATTRIBUTES_BYTES = 16 * 1024
MAX_BEHAVIOR_ATTRIBUTE_DEPTH = 8
MAX_BEHAVIOR_ATTRIBUTE_ITEMS = 256
MAX_BEHAVIOR_ATTRIBUTE_STRING_LENGTH = 4000
MAX_BEHAVIOR_BATCH_BYTES = 8 * 1024 * 1024


class BehaviorEventCategory(StrEnum):
    NETWORK = "network"
    PROCESS = "process"
    COMMAND = "command"
    FILE = "file"
    AUTHENTICATION = "authentication"
    SERVICE = "service"
    SYSTEM = "system"


class BehaviorEventSource(StrEnum):
    SENSOR = "sensor"
    SERVICE = "service"
    CONTROL_PROXY = "control_proxy"
    CONTROL_PLANE = "control_plane"
    AGENT = "agent"
    IMPORT = "import"


class BehaviorDirection(StrEnum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    INTERNAL = "internal"
    UNKNOWN = "unknown"


class BehaviorOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class BehaviorEventPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observed_at: datetime
    category: BehaviorEventCategory
    action: str = Field(min_length=1, max_length=128)
    direction: BehaviorDirection = BehaviorDirection.UNKNOWN
    outcome: BehaviorOutcome = BehaviorOutcome.UNKNOWN
    source_ip: str = Field(default="", max_length=64)
    source_port: int | None = Field(default=None, ge=1, le=65535)
    destination_ip: str = Field(default="", max_length=64)
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str = Field(default="", max_length=32)
    process_id: int | None = Field(default=None, ge=0)
    parent_process_id: int | None = Field(default=None, ge=0)
    process_name: str = Field(default="", max_length=255)
    command_line: str = Field(default="", max_length=16000)
    file_path: str = Field(default="", max_length=4096)
    username: str = Field(default="", max_length=255)
    service_name: str = Field(default="", max_length=255)
    network_session_id: str = Field(default="", max_length=128)
    sensor_bundle_hash: str = Field(default="", max_length=64)
    deception_artifact_id: int | None = Field(default=None, gt=0)
    summary: str = Field(default="", max_length=4000)
    attributes: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator(
        "action",
        "source_ip",
        "destination_ip",
        "protocol",
        "process_name",
        "command_line",
        "file_path",
        "username",
        "service_name",
        "summary",
        mode="before",
    )
    @classmethod
    def normalize_text(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value

    @field_validator("source_ip", "destination_ip", mode="after")
    @classmethod
    def validate_ip_address(cls, value: str) -> str:
        if not value:
            return value
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as error:
            raise ValueError("behavior event IP address is invalid") from error

    @field_validator("observed_at", mode="after")
    @classmethod
    def normalize_observed_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone offset")
        return value.astimezone(timezone.utc)

    @field_validator("attributes", mode="after")
    @classmethod
    def validate_attributes(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        validated = _validate_behavior_attribute_value(value, depth=0)
        encoded = json.dumps(
            validated,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > MAX_BEHAVIOR_ATTRIBUTES_BYTES:
            raise ValueError(
                f"behavior event attributes cannot exceed {MAX_BEHAVIOR_ATTRIBUTES_BYTES} bytes"
            )
        return validated

    @model_validator(mode="after")
    def validate_category_detail(self) -> "CapturedBehaviorEvent":
        required = {
            BehaviorEventCategory.COMMAND: bool(self.command_line),
            BehaviorEventCategory.FILE: bool(self.file_path),
            BehaviorEventCategory.NETWORK: bool(
                self.source_ip or self.destination_ip or self.source_port or self.destination_port or self.protocol
            ),
            BehaviorEventCategory.PROCESS: bool(self.process_name or self.process_id is not None),
            BehaviorEventCategory.AUTHENTICATION: bool(self.service_name),
            BehaviorEventCategory.SERVICE: bool(self.service_name),
        }
        if self.category in required and not required[self.category]:
            raise ValueError(f"{self.category.value} behavior event is missing category detail")
        return self


class ImportedBehaviorEvent(BehaviorEventPayload):
    sequence: int = Field(gt=0)


class CapturedBehaviorEvent(BehaviorEventPayload):
    sequence: int = Field(gt=0)
    source: BehaviorEventSource = BehaviorEventSource.SENSOR
    raw_reference: str = Field(default="", max_length=2000)
    sensor_previous_hash: str = Field(default="", max_length=64)
    sensor_event_hash: str = Field(default="", max_length=64)

    @field_validator("raw_reference", "sensor_previous_hash", "sensor_event_hash", mode="before")
    @classmethod
    def normalize_raw_reference(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class BehaviorEventSchema(CapturedBehaviorEvent):
    model_config = ConfigDict(from_attributes=True)

    id: int
    environment_id: int
    incident_id: int | None = None
    incident_link_method: str = ""
    incident_linked_at: datetime | None = None
    incident_material: bool = False
    materiality_reason: str = ""
    correlation_score: int = 0
    sensor_id: str
    previous_event_hash: str = Field(max_length=64)
    event_hash: str = Field(max_length=64)
    ingested_at: datetime


class BehaviorEventBatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sensor_id: str = Field(min_length=1, max_length=128)
    incident_id: int | None = Field(default=None, gt=0)

    @field_validator("sensor_id", mode="before")
    @classmethod
    def normalize_sensor_id(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value

    @model_validator(mode="after")
    def validate_batch(self) -> Self:
        events = getattr(self, "events", [])
        sequences = [event.sequence for event in events]
        if sequences != sorted(sequences):
            raise ValueError("behavior event sequences must be ordered")
        if len(sequences) != len(set(sequences)):
            raise ValueError("behavior event sequences must be unique within a batch")
        encoded = json.dumps(
            self.model_dump(mode="json"),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > MAX_BEHAVIOR_BATCH_BYTES:
            raise ValueError(f"behavior event batch cannot exceed {MAX_BEHAVIOR_BATCH_BYTES} bytes")
        return self


class ImportBehaviorEventBatchRequest(BehaviorEventBatchRequest):
    events: list[ImportedBehaviorEvent] = Field(min_length=1, max_length=1000)


class IngestBehaviorEventBatchRequest(BehaviorEventBatchRequest):
    events: list[CapturedBehaviorEvent] = Field(min_length=1, max_length=1000)


class IngestBehaviorEventBatchResponse(BaseModel):
    sensor_id: str
    accepted: int = Field(ge=0)
    duplicates: int = Field(ge=0)
    last_sequence: int = Field(ge=0)
    event_ids: list[int]


class AssignBehaviorEventsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_ids: list[int] = Field(min_length=1, max_length=1000)

    @field_validator("event_ids", mode="after")
    @classmethod
    def normalize_event_ids(cls, value: list[int]) -> list[int]:
        normalized = list(dict.fromkeys(value))
        if any(event_id <= 0 for event_id in normalized):
            raise ValueError("behavior event IDs must be positive")
        return normalized


class AssignBehaviorEventsResponse(BaseModel):
    incident_id: int
    assigned: int = Field(ge=0)
    existing: int = Field(ge=0)


class QueryBehaviorEventsResponse(PaginatedResponse[BehaviorEventSchema]):
    pass


def _validate_behavior_attribute_value(value: JsonValue, *, depth: int) -> JsonValue:
    if depth > MAX_BEHAVIOR_ATTRIBUTE_DEPTH:
        raise ValueError(
            f"behavior event attributes cannot exceed depth {MAX_BEHAVIOR_ATTRIBUTE_DEPTH}"
        )
    if isinstance(value, dict):
        if len(value) > MAX_BEHAVIOR_ATTRIBUTE_ITEMS:
            raise ValueError(
                f"behavior event attribute objects cannot exceed {MAX_BEHAVIOR_ATTRIBUTE_ITEMS} entries"
            )
        return {
            key: _validate_behavior_attribute_value(item, depth=depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, list):
        if len(value) > MAX_BEHAVIOR_ATTRIBUTE_ITEMS:
            raise ValueError(
                f"behavior event attribute arrays cannot exceed {MAX_BEHAVIOR_ATTRIBUTE_ITEMS} entries"
            )
        return [
            _validate_behavior_attribute_value(item, depth=depth + 1)
            for item in value
        ]
    if isinstance(value, str):
        if len(value) > MAX_BEHAVIOR_ATTRIBUTE_STRING_LENGTH:
            raise ValueError(
                "behavior event attribute strings cannot exceed "
                f"{MAX_BEHAVIOR_ATTRIBUTE_STRING_LENGTH} characters"
            )
        return value
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("behavior event attributes require finite numeric values")
        return value
    raise ValueError("behavior event attributes must contain JSON-compatible values")
