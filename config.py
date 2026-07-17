import json
import secrets
import tempfile
from pathlib import Path
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from schema.agent.sessions import AgentCode, CANONICAL_AGENT_IDENTITIES


ROOT_PATH = Path(__file__).resolve().parent
WORKSPACE = ROOT_PATH / ".v3il"
CONFIG_FILE = WORKSPACE / "config.json"


# strict type config base model
class StrictConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


# system config
class BootstrapAdminConfig(StrictConfigModel):
    enabled: bool = Field(default=False)
    username: str = Field(default="admin", min_length=1, max_length=64)
    email: str = Field(default="admin@v3il.local", min_length=1, max_length=255)
    password: str = Field(default="", max_length=128)

    @model_validator(mode="after")
    def validate_password_when_enabled(self):
        if self.enabled and not self.password:
            raise ValueError("bootstrap admin password is required when bootstrap admin is enabled")
        return self


class SystemConfig(StrictConfigModel):
    listen_addr: str = Field(default="127.0.0.1", min_length=1)
    listen_port: int = Field(default=8000, ge=1, le=65535)
    jwt_signing_key: str = Field(default_factory=lambda: secrets.token_urlsafe(32), min_length=32)
    bootstrap_admin: BootstrapAdminConfig = Field(default_factory=BootstrapAdminConfig)


# database config
class DatabaseConfig(StrictConfigModel):
    host: str = Field(default="127.0.0.1", min_length=1)
    port: int = Field(default=5432, ge=1, le=65535)
    database: str = Field(default="v3il", min_length=1)
    username: str = Field(default="root", min_length=1)
    password: str = Field(default="")
    pool_size: int = Field(default=32, ge=1)
    max_overflow: int = Field(default=32, ge=0)
    pool_timeout_seconds: int = Field(default=30, gt=0)
    pool_recycle_seconds: int = Field(default=1800, ge=0)
    pool_pre_ping: bool = Field(default=True)


# agent config
class AgentConfig(StrictConfigModel):
    code: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="")
    base_url: str = Field(min_length=1)
    api_key: str = Field(default="")
    model: str = Field(min_length=1)
    use_responses: bool = Field(default=False)
    context_window: int = Field(default=1000000, ge=0)


# per-process agent runtime pool tuning
class AgentPoolConfig(StrictConfigModel):
    max_size: int = Field(default=256, ge=1)
    ttl_seconds: int = Field(default=30 * 60, ge=0)
    sweep_interval_seconds: int = Field(default=60, ge=1)


# per-process agent run tuning
class AgentRuntimeConfig(StrictConfigModel):
    main_max_turns: int = Field(default=1000, ge=1)
    subordinate_max_turns: int = Field(default=1000, ge=1)
    model_stream_idle_timeout_seconds: int = Field(default=300, ge=30)
    report_retention_seconds: int = Field(default=3 * 24 * 60 * 60, ge=0)
    context_compression_trigger_ratio: float = Field(default=0.90, gt=0, lt=1)
    context_compression_hard_stop_ratio: float = Field(default=0.98, gt=0, lt=1)
    context_compression_target_ratio: float = Field(default=0.20, gt=0, lt=1)
    context_budget_model_call_ratio: float = Field(default=0.80, gt=0, lt=1)
    context_compression_preserve_recent_ratio: float = Field(default=0.25, gt=0, lt=1)
    context_compression_preserve_recent_items: int = Field(default=20, ge=1)
    context_compression_min_items: int = Field(default=12, ge=1)
    context_compression_summary_max_tokens: int = Field(default=8000, ge=512)

    @model_validator(mode="after")
    def validate_context_thresholds(self) -> Self:
        if not (
            self.context_compression_target_ratio
            < self.context_compression_trigger_ratio
            < self.context_compression_hard_stop_ratio
        ):
            raise ValueError(
                "context compression ratios must satisfy target < trigger < hard stop"
            )
        return self


class BehaviorCaptureConfig(StrictConfigModel):
    poll_interval_seconds: float = Field(default=1.0, ge=0.2, le=60)
    batch_size: int = Field(default=500, ge=1, le=1000)
    max_batches_per_poll: int = Field(default=8, ge=1, le=100)
    concurrency: int = Field(default=16, ge=1, le=64)


class ThreatAutomationConfig(StrictConfigModel):
    enabled: bool = True
    correlation_window_seconds: int = Field(default=30 * 60, ge=60, le=24 * 60 * 60)
    notification_event_limit: int = Field(default=200, ge=1, le=1000)


# LightRAG config
class LightRAGConfig(StrictConfigModel):
    embedding_api: str = Field(default="https://api.openai.com/v1", min_length=1)
    embedding_key: str = Field(default="")
    embedding_model: str = Field(default="text-embedding-3-small", min_length=1)
    embedding_dim: int = Field(default=1536, ge=1, le=16000)
    llm_api: str = Field(default="https://api.openai.com/v1", min_length=1)
    llm_key: str = Field(default="")
    llm_model: str = Field(default="gpt-5", min_length=1)
    graph_matches: int = Field(default=5, ge=1, le=50)
    chunk_matches: int = Field(default=10, ge=1, le=50)


# global config
class GlobalConfig(StrictConfigModel):
    system: SystemConfig = Field(default_factory=SystemConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    agents: dict[str, AgentConfig] = Field(default_factory=dict)
    agent_pool: AgentPoolConfig = Field(default_factory=AgentPoolConfig)
    agent_runtime: AgentRuntimeConfig = Field(default_factory=AgentRuntimeConfig)
    behavior_capture: BehaviorCaptureConfig = Field(default_factory=BehaviorCaptureConfig)
    threat_automation: ThreatAutomationConfig = Field(default_factory=ThreatAutomationConfig)
    lightrag: LightRAGConfig = Field(default_factory=LightRAGConfig)

    @model_validator(mode="after")
    def validate_agent_codes(self) -> Self:
        for code, agent in self.agents.items():
            if code != agent.code:
                raise ValueError(f"agent code mismatch: {code}")
        return self


###
# global config instance
###
_cfg: GlobalConfig = GlobalConfig()


def load_config() -> None:
    """Load validated configuration while preserving the shared object identity."""
    next_cfg = read_config_file()
    for field_name in type(_cfg).model_fields:
        setattr(_cfg, field_name, getattr(next_cfg, field_name))


def get_config() -> GlobalConfig:
    """Return the process-wide configuration object."""
    return _cfg


def read_config_file() -> GlobalConfig:
    """Read and validate config.json without mutating global state."""
    with CONFIG_FILE.open("r", encoding="utf-8") as f:
        data = json.load(f)
    config = GlobalConfig.model_validate(data)
    validate_runtime_agent_set(config.agents)
    return config


def validate_runtime_agent_set(agents: dict[str, AgentConfig]) -> None:
    expected = {code.value for code in AgentCode}
    configured = set(agents)
    if configured != expected:
        missing = sorted(expected - configured)
        extra = sorted(configured - expected)
        details = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if extra:
            details.append("unsupported: " + ", ".join(extra))
        raise ValueError(
            "agents must contain exactly cso, cth, cde, cie, and cir ("
            + "; ".join(details)
            + ")"
        )
    for code_value, agent in agents.items():
        code = AgentCode(code_value)
        expected_name, expected_role = CANONICAL_AGENT_IDENTITIES[code]
        if agent.name != expected_name or agent.description != expected_role:
            raise ValueError(
                f"agent {code_value} identity must remain {expected_name} / {expected_role}"
            )


def write_config_file(cfg: GlobalConfig) -> None:
    """Atomically write a validated config.json."""
    WORKSPACE.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = cfg.model_dump(mode="json")
    payload = json.dumps(data, ensure_ascii=False, indent=4)

    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=WORKSPACE,
            prefix=".config.",
            suffix=".json.tmp",
            delete=False,
        ) as f:
            temp_path = Path(f.name)
            f.write(payload)
            f.write("\n")
        temp_path.replace(CONFIG_FILE)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
