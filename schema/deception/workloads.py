from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ObservedWorkloadStatus(StrEnum):
    RUNNING = "running"
    STOPPED = "stopped"
    FAILED = "failed"


class ObservedWorkloadSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    name: str
    command: str
    working_directory: str
    process_id: int = Field(ge=1)
    status: ObservedWorkloadStatus
    exit_code: int | None = None
    error: str = ""
    started_at: datetime
    finished_at: datetime | None = None


class ObservedWorkloadEnvironmentVariable(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    value: str = Field(max_length=8000)

    @field_validator("name", mode="after")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if "=" in value or "\x00" in value:
            raise ValueError("workload environment contains an invalid variable name")
        return value

    @field_validator("value", mode="after")
    @classmethod
    def validate_value(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("workload environment contains an invalid variable value")
        return value


class CreateObservedWorkloadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    command: str = Field(min_length=1, max_length=16000)
    working_directory: str = Field(default="/opt/deception", min_length=1, max_length=4096)
    environment: list[ObservedWorkloadEnvironmentVariable] = Field(default_factory=list, max_length=128)

    @field_validator("name", "command", "working_directory", mode="before")
    @classmethod
    def normalize_text(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value

    @field_validator("environment", mode="after")
    @classmethod
    def validate_environment(
        cls,
        value: list[ObservedWorkloadEnvironmentVariable],
    ) -> list[ObservedWorkloadEnvironmentVariable]:
        names = [item.name for item in value]
        if len(names) != len(set(names)):
            raise ValueError("workload environment variable names must be unique")
        return value


class ListObservedWorkloadsResponse(BaseModel):
    items: list[ObservedWorkloadSchema]
