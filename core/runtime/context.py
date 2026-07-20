from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from typing import Any

from schema.agent.types import AgentRunWaitReason
from schema.system_user.users import SystemUserRole


MAIN_AGENT_INSTANCE_PREFIX = "main:"
SUBAGENT_INSTANCE_PREFIX = "subagent:"


@dataclass(frozen=True)
class AgentUserContext:
    id: int
    username: str
    email: str
    role: SystemUserRole


@dataclass
class AgentRuntimeContext:
    session_id: str
    user: AgentUserContext
    run_id: str = ""
    attempt_id: str = ""
    context_id: str = ""
    agent_code: str = ""
    agent_instance_id: str = ""
    rag_context: str = ""
    investigation_context: str = ""
    deception_context: str = ""
    sandbox_container_id: int | None = None
    sandbox_container_generation: int = 0
    sandbox_skill_metadata: tuple[str, ...] = ()
    incident_id: int | None = None
    environment_id: int | None = None
    investigation_task_id: int | None = None
    wait_requested: bool = False
    wait_reason: AgentRunWaitReason | None = None
    wait_reference_id: str | None = None
    tool_invocation_runner: Callable[
        [str, str, str, Callable[[], Awaitable[Any]]],
        Awaitable[Any],
    ] | None = field(default=None, repr=False, compare=False)

    async def invoke_tool(
        self,
        tool_name: str,
        call_id: str,
        arguments: str,
        operation: Callable[[], Awaitable[Any]],
    ) -> Any:
        if self.tool_invocation_runner is None:
            raise RuntimeError("Agent tool invocation journal is unavailable")
        return await self.tool_invocation_runner(tool_name, call_id, arguments, operation)


def main_agent_instance_id(session_id: str, user_id: int, agent_code: str) -> str:
    return f"{MAIN_AGENT_INSTANCE_PREFIX}{session_id}:{user_id}:{agent_code}"


def subagent_instance_id(run_id: str) -> str:
    return f"{SUBAGENT_INSTANCE_PREFIX}{run_id}"
