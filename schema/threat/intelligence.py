import ipaddress
import re
from datetime import datetime
from enum import StrEnum
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from schema.common.responses import PaginatedResponse
from schema.threat.analysis import AnalysisRecordSchema, AnalysisKind, normalize_positive_ids
from schema.threat.incidents import ThreatConfidence


class ThreatIndicatorType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    FILE_SHA256 = "file_sha256"
    USERNAME = "username"
    USER_AGENT = "user_agent"
    CERTIFICATE = "certificate"
    CUSTOM = "custom"


class ThreatIndicatorDisposition(StrEnum):
    UNKNOWN = "unknown"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    BENIGN = "benign"


class IntelligenceReportStatus(StrEnum):
    DRAFT = "draft"
    REVIEW = "review"
    FINAL = "final"


class KnowledgePublicationStatus(StrEnum):
    NOT_QUEUED = "not_queued"
    QUEUED = "queued"
    PUBLISHED = "published"
    FAILED = "failed"


class ThreatIndicatorSchema(AnalysisRecordSchema):
    type: ThreatIndicatorType
    value: str
    disposition: ThreatIndicatorDisposition
    confidence: ThreatConfidence
    context: str
    first_observed_at: datetime
    last_observed_at: datetime


class CreateThreatIndicatorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: ThreatIndicatorType
    value: str = Field(min_length=1, max_length=4000)
    disposition: ThreatIndicatorDisposition
    confidence: ThreatConfidence
    context: str = Field(default="", max_length=8000)
    first_observed_at: datetime
    last_observed_at: datetime
    evidence_ids: list[int] = Field(min_length=1, max_length=1000)

    @field_validator("value", mode="after")
    @classmethod
    def normalize_value(cls, value: str, info) -> str:
        return normalize_indicator_value(info.data.get("type"), value)

    @field_validator("evidence_ids", mode="after")
    @classmethod
    def normalize_evidence(cls, value: list[int]) -> list[int]:
        return normalize_positive_ids(value, "evidence")

    @model_validator(mode="after")
    def validate_time(self):
        if self.last_observed_at < self.first_observed_at:
            raise ValueError("indicator last_observed_at cannot precede first_observed_at")
        return self


class IntelligenceReportAnalysisSnapshot(BaseModel):
    analysis_id: int
    kind: AnalysisKind
    subject_key: str
    version: int


class IntelligenceReportEvidenceManifest(BaseModel):
    evidence_ids: list[int] = Field(default_factory=list)
    behavior_event_ids: list[int] = Field(default_factory=list)
    environment_ids: list[int] = Field(default_factory=list)
    sensor_chain_heads: dict[str, str] = Field(default_factory=dict)
    backend_chain_heads: dict[str, str] = Field(default_factory=dict)
    decision_ids: list[int] = Field(default_factory=list)
    signal_ids: list[int] = Field(default_factory=list)
    bundle_hashes: list[str] = Field(default_factory=list)
    rule_version_hashes: dict[str, str] = Field(default_factory=dict)
    material_event_count: int = Field(default=0, ge=0)
    covered_event_count: int = Field(default=0, ge=0)
    known_gaps: list[str] = Field(default_factory=list)


class IntelligenceReportSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int
    version: int
    is_current: bool
    status: IntelligenceReportStatus
    title: str
    executive_summary: str
    behavior_summary: str
    deception_summary: str
    conclusion: str
    analysis_snapshot: list[IntelligenceReportAnalysisSnapshot]
    evidence_manifest: IntelligenceReportEvidenceManifest
    markdown: str
    artifact_sha256: str
    artifact_media_type: str
    artifact_filename: str
    artifact_size: int
    knowledge_document_name: str
    knowledge_status: KnowledgePublicationStatus
    knowledge_error: str
    created_by_agent_code: str
    created_from_session_id: str
    created_at: datetime


class CreateIntelligenceReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: IntelligenceReportStatus
    title: str = Field(min_length=1, max_length=255)
    executive_summary: str = Field(min_length=1, max_length=16000)
    behavior_summary: str = Field(min_length=1, max_length=16000)
    deception_summary: str = Field(default="", max_length=16000)
    conclusion: str = Field(min_length=1, max_length=16000)
    analysis_ids: list[int] = Field(min_length=1, max_length=1000)
    markdown: str = Field(min_length=1, max_length=200000)

    @field_validator("analysis_ids", mode="after")
    @classmethod
    def normalize_analysis_ids(cls, value: list[int]) -> list[int]:
        return normalize_positive_ids(value, "analysis")


class QueryThreatIndicatorsResponse(PaginatedResponse[ThreatIndicatorSchema]):
    pass


class QueryIntelligenceReportsResponse(PaginatedResponse[IntelligenceReportSchema]):
    pass


def normalize_indicator_value(type: ThreatIndicatorType | None, value: str) -> str:
    value = value.strip()
    if type == ThreatIndicatorType.IPV4:
        candidate = str(ipaddress.ip_address(value))
        if ":" in candidate:
            raise ValueError("IPv4 indicator is invalid")
        return candidate
    if type == ThreatIndicatorType.IPV6:
        candidate = str(ipaddress.ip_address(value))
        if ":" not in candidate:
            raise ValueError("IPv6 indicator is invalid")
        return candidate
    if type == ThreatIndicatorType.DOMAIN:
        candidate = value.casefold().rstrip(".")
        if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,62}", candidate):
            raise ValueError("domain indicator is invalid")
        return candidate
    if type == ThreatIndicatorType.URL:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("URL indicator must be an absolute HTTP or HTTPS URL")
        return value
    if type == ThreatIndicatorType.EMAIL:
        candidate = value.casefold()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", candidate):
            raise ValueError("email indicator is invalid")
        return candidate
    if type == ThreatIndicatorType.FILE_SHA256:
        candidate = value.lower().removeprefix("sha256:")
        if not re.fullmatch(r"[0-9a-f]{64}", candidate):
            raise ValueError("file SHA-256 indicator must contain 64 hexadecimal characters")
        return candidate
    return value
