import asyncio
from dataclasses import dataclass
from http import HTTPStatus

from fastapi import HTTPException

from config import (
    AgentConfig,
    AgentRuntimeConfig,
    BehaviorCaptureConfig,
    GlobalConfig,
    LightRAGConfig,
    ThreatAutomationConfig,
    get_config,
    read_config_file,
    write_config_file,
)
from core.lightrag.runtime import lightrag_client, restart_lightrag
from logger import get_logger
from schema.system_config.config import InstanceConfigSchema, UpdateInstanceConfigRequest
from schema.agent.sessions import AgentCode


logger = get_logger(__name__)

_config_lock = asyncio.Lock()


@dataclass(frozen=True)
class InstanceConfigApplyResult:
    config: InstanceConfigSchema
    restarted: bool


async def get_instance_config() -> InstanceConfigApplyResult:
    async with _config_lock:
        file_cfg = read_config_file()
        return await _apply_instance_config_from_file(file_cfg)


async def update_instance_config(request: UpdateInstanceConfigRequest) -> InstanceConfigApplyResult:
    async with _config_lock:
        current = read_config_file()
        if set(request.agents) != set(current.agents):
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST.value,
                detail="agent set cannot be changed",
            )

        agents = {}
        for code, agent in current.agents.items():
            patch = request.agents[code]
            agents[code] = agent.model_copy(update={
                "base_url": patch.base_url,
                "api_key": patch.api_key,
                "model": patch.model,
                "use_responses": patch.use_responses,
                "context_window": patch.context_window,
            })

        next_cfg = current.model_copy(update={
            "agents": agents,
            "agent_runtime": request.agent_runtime,
            "behavior_capture": request.behavior_capture,
            "threat_automation": request.threat_automation,
            "lightrag": request.lightrag,
        })
        write_config_file(next_cfg)
        try:
            return await _apply_instance_config_from_file(next_cfg)
        except BaseException as exc:
            try:
                write_config_file(current)
            except Exception as rollback_error:
                logger.exception("failed to roll back instance config file")
                exc.add_note(f"config file rollback also failed: {rollback_error}")
            raise


async def _apply_instance_config_from_file(file_cfg: GlobalConfig) -> InstanceConfigApplyResult:
    previous = _snapshot_instance_config(get_config())
    await _ensure_embedding_storage_compatible(previous.lightrag, file_cfg.lightrag)
    agent_runtime_changed, lightrag_runtime_changed = _apply_instance_config(file_cfg)
    if lightrag_runtime_changed:
        try:
            await restart_lightrag(file_cfg.lightrag, rollback_config=previous.lightrag)
        except BaseException:
            _restore_instance_config(previous)
            raise
        logger.info("LightRAG config applied and runtime rebuilt")
    if agent_runtime_changed:
        logger.info("Agent config applied; active Attempts retain their snapshots and new Attempts use the new config")
    return InstanceConfigApplyResult(
        config=_instance_config_from_global(get_config()),
        restarted=agent_runtime_changed or lightrag_runtime_changed,
    )


def _apply_instance_config(file_cfg: GlobalConfig) -> tuple[bool, bool]:
    current = get_config()
    agent_runtime_changed = _agent_runtime_config_changed(current, file_cfg)
    behavior_capture_changed = current.behavior_capture != file_cfg.behavior_capture
    threat_automation_changed = current.threat_automation != file_cfg.threat_automation
    lightrag_changed = current.lightrag != file_cfg.lightrag
    lightrag_runtime_changed = _lightrag_runtime_config_changed(current.lightrag, file_cfg.lightrag)
    if not agent_runtime_changed and not behavior_capture_changed and not threat_automation_changed and not lightrag_changed:
        return False, False

    current.agents = _copy_agents(file_cfg.agents)
    current.agent_runtime = _copy_agent_runtime(file_cfg.agent_runtime)
    current.behavior_capture = _copy_behavior_capture(file_cfg.behavior_capture)
    current.threat_automation = _copy_threat_automation(file_cfg.threat_automation)
    current.lightrag = _copy_lightrag(file_cfg.lightrag)
    return agent_runtime_changed, lightrag_runtime_changed


def _agent_runtime_config_changed(current: GlobalConfig, next_cfg: GlobalConfig) -> bool:
    return (
        current.agents != next_cfg.agents
        or current.agent_runtime != next_cfg.agent_runtime
    )


def _lightrag_runtime_config_changed(current: LightRAGConfig, next_cfg: LightRAGConfig) -> bool:
    retrieval_fields = {"graph_matches", "chunk_matches"}
    return current.model_dump(exclude=retrieval_fields) != next_cfg.model_dump(exclude=retrieval_fields)


async def _ensure_embedding_storage_compatible(current: LightRAGConfig, next_cfg: LightRAGConfig) -> None:
    embedding_changed = (
        current.embedding_api != next_cfg.embedding_api
        or current.embedding_model != next_cfg.embedding_model
        or current.embedding_dim != next_cfg.embedding_dim
    )
    if not embedding_changed:
        return

    async with lightrag_client() as rag:
        status_counts = await rag.get_processing_status()
    if any(int(count) > 0 for count in status_counts.values()):
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST.value,
            detail="embedding API, model, and dimension cannot change while LightRAG documents exist",
        )


def _copy_agents(agents: dict[AgentCode, AgentConfig]) -> dict[AgentCode, AgentConfig]:
    return {code: agent.model_copy(deep=True) for code, agent in agents.items()}


def _copy_agent_runtime(agent_runtime: AgentRuntimeConfig) -> AgentRuntimeConfig:
    return agent_runtime.model_copy(deep=True)


def _copy_behavior_capture(behavior_capture: BehaviorCaptureConfig) -> BehaviorCaptureConfig:
    return behavior_capture.model_copy(deep=True)


def _copy_threat_automation(threat_automation: ThreatAutomationConfig) -> ThreatAutomationConfig:
    return threat_automation.model_copy(deep=True)


def _copy_lightrag(lightrag: LightRAGConfig) -> LightRAGConfig:
    return lightrag.model_copy(deep=True)


def _snapshot_instance_config(cfg: GlobalConfig) -> InstanceConfigSchema:
    return _instance_config_from_global(cfg).model_copy(deep=True)


def _restore_instance_config(snapshot: InstanceConfigSchema) -> None:
    current = get_config()
    current.agents = _copy_agents(snapshot.agents)
    current.agent_runtime = _copy_agent_runtime(snapshot.agent_runtime)
    current.behavior_capture = _copy_behavior_capture(snapshot.behavior_capture)
    current.threat_automation = _copy_threat_automation(snapshot.threat_automation)
    current.lightrag = _copy_lightrag(snapshot.lightrag)


def _instance_config_from_global(cfg: GlobalConfig) -> InstanceConfigSchema:
    return InstanceConfigSchema(
        agents=cfg.agents,
        agent_runtime=cfg.agent_runtime,
        behavior_capture=cfg.behavior_capture,
        threat_automation=cfg.threat_automation,
        lightrag=cfg.lightrag,
    )
