from pydantic import BaseModel, ConfigDict, Field


class ProblemViolation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    location: list[str | int] = Field(default_factory=list)
    message: str
    code: str


class ProblemDetails(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str = "about:blank"
    title: str
    status: int
    detail: str = ""
    instance: str = ""
    error_code: str = ""
    violations: list[ProblemViolation] = Field(default_factory=list)
