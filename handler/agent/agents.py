from fastapi import Request

from config import get_config
from core.agent.constants import DEFAULT_AGENT_CODE
from schema.agent.sessions import AgentCode, AgentInfoSchema, ListAgentsResponse
from service.agent.supervisor import AgentRuntimeSupervisor


async def list_agents_handler(request: Request) -> ListAgentsResponse:
    runtime = getattr(request.app.state, "agent_runtime", None)
    if not isinstance(runtime, AgentRuntimeSupervisor):
        raise RuntimeError("agent runtime is unavailable")
    cfg = get_config()
    return ListAgentsResponse(
        items=[AgentInfoSchema(
            code=AgentCode(code),
            name=cfg.agents[code].name,
            description=cfg.agents[code].description,
        ) for code in runtime.registry.codes()],
        default_code=AgentCode(DEFAULT_AGENT_CODE),
    )
