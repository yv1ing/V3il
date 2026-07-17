from pydantic import BaseModel, ConfigDict, Field, model_validator

from config import (
    AgentConfig,
    AgentPoolConfig,
    AgentRuntimeConfig,
    BehaviorCaptureConfig,
    LightRAGConfig,
    ThreatAutomationConfig,
    validate_runtime_agent_set,
)


class InstanceConfigSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)

    agents: dict[str, AgentConfig] = Field(default_factory=dict)
    agent_pool: AgentPoolConfig = Field(default_factory=AgentPoolConfig)
    agent_runtime: AgentRuntimeConfig = Field(default_factory=AgentRuntimeConfig)
    behavior_capture: BehaviorCaptureConfig = Field(default_factory=BehaviorCaptureConfig)
    threat_automation: ThreatAutomationConfig = Field(default_factory=ThreatAutomationConfig)
    lightrag: LightRAGConfig = Field(default_factory=LightRAGConfig)

    @model_validator(mode="after")
    def validate_agent_codes(self):
        validate_runtime_agent_set(self.agents)
        for code, agent in self.agents.items():
            if agent.code != code:
                raise ValueError(f"agent code mismatch: {code}")
        return self


class UpdateAgentConfigRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    base_url: str = Field(min_length=1)
    api_key: str
    model: str = Field(min_length=1)
    use_responses: bool
    context_window: int = Field(ge=0)


class UpdateInstanceConfigRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agents: dict[str, UpdateAgentConfigRequest]
    agent_pool: AgentPoolConfig
    agent_runtime: AgentRuntimeConfig
    behavior_capture: BehaviorCaptureConfig
    threat_automation: ThreatAutomationConfig
    lightrag: LightRAGConfig


class UpdateInstanceConfigResponse(BaseModel):
    config: InstanceConfigSchema
    restarted: bool
