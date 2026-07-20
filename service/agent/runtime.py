from core.agent.constants import DEFAULT_AGENT_CODE
from middleware.system_user import AuthUser
from schema.agent.events import AgentInputPart
from schema.agent.sessions import AgentCode, AgentControlResponse, AgentTurnResponse
from service.agent import repository
from service.agent.supervisor import AgentRuntimeSupervisor
from service.sandbox.status import resolve_sandbox_container_selection


class SessionNotRunnableError(PermissionError):
    pass


class SessionBusyError(RuntimeError):
    pass


class SandboxContainerUnavailableError(ValueError):
    pass


class AgentUnavailableError(ValueError):
    pass


async def submit_new_chat_turn(
    *,
    supervisor: AgentRuntimeSupervisor,
    content: list[AgentInputPart],
    user: AuthUser,
    sandbox_container_id: int | None,
    requested_agent_code: AgentCode | None,
) -> AgentTurnResponse:
    agent_code = requested_agent_code or AgentCode(DEFAULT_AGENT_CODE)
    _validate_agent(supervisor, agent_code)
    selected_id, generation = await _resolve_selection(sandbox_container_id, user)
    agent_session, run, event = await repository.create_chat_run(
        content=content,
        owner_id=user.id,
        agent_code=agent_code,
        sandbox_container_id=selected_id,
        sandbox_generation=generation,
    )
    supervisor.notify()
    summary = await repository.session_summary(agent_session.id, user.id, user.role)
    if summary is None:
        raise RuntimeError("created agent session is unavailable")
    return AgentTurnResponse(session=summary, run=run, accepted_event=event)


async def submit_user_turn(
    *,
    supervisor: AgentRuntimeSupervisor,
    session_id: str,
    content: list[AgentInputPart],
    user: AuthUser,
    requested_agent_code: AgentCode | None,
) -> AgentTurnResponse:
    if requested_agent_code is not None:
        _validate_agent(supervisor, requested_agent_code)
    try:
        agent_session, run, event = await repository.enqueue_chat_run(
            session_id=session_id,
            content=content,
            user_id=user.id,
            user_role=user.role,
            requested_agent_code=requested_agent_code,
        )
    except repository.AgentSessionNotRunnableError as exc:
        raise SessionNotRunnableError(str(exc)) from exc
    supervisor.notify()
    summary = await repository.session_summary(agent_session.id, user.id, user.role)
    if summary is None:
        raise PermissionError("agent session not found")
    return AgentTurnResponse(session=summary, run=run, accepted_event=event)


async def update_selected_sandbox_container(
    *,
    session_id: str,
    sandbox_container_id: int | None,
    user: AuthUser,
):
    selected_id, generation = await _resolve_selection(sandbox_container_id, user)
    try:
        summary = await repository.update_sandbox_selection(
            session_id,
            selected_id,
            generation,
            user.id,
            user.role,
        )
    except RuntimeError as exc:
        raise SessionBusyError(str(exc)) from exc
    if summary is None:
        raise PermissionError("agent session not found")
    return summary


async def interrupt_turn(
    *,
    supervisor: AgentRuntimeSupervisor,
    session_id: str,
    user: AuthUser,
) -> AgentControlResponse:
    affected = await repository.request_foreground_interrupt(
        session_id,
        user_id=user.id,
        user_role=user.role,
        actor=f"user:{user.id}",
    )
    if affected is None:
        raise PermissionError("agent session not found")
    supervisor.notify()
    refreshed = await repository.session_summary(session_id, user.id, user.role)
    if refreshed is None:
        raise PermissionError("agent session not found")
    return AgentControlResponse(session=refreshed, affected_run_ids=affected)


async def cancel_all_tasks(
    *,
    supervisor: AgentRuntimeSupervisor,
    session_id: str,
    user: AuthUser,
) -> AgentControlResponse:
    affected = await repository.request_all_run_cancellations(
        session_id,
        user_id=user.id,
        user_role=user.role,
        actor=f"user:{user.id}",
    )
    if affected is None:
        raise PermissionError("agent session not found")
    supervisor.notify()
    refreshed = await repository.session_summary(session_id, user.id, user.role)
    if refreshed is None:
        raise PermissionError("agent session not found")
    return AgentControlResponse(session=refreshed, affected_run_ids=affected)


def _validate_agent(supervisor: AgentRuntimeSupervisor, agent_code: AgentCode) -> None:
    if not supervisor.registry.has(str(agent_code)):
        raise AgentUnavailableError("agent is not available")


async def _resolve_selection(container_id: int | None, user: AuthUser) -> tuple[int | None, int]:
    if container_id is None:
        return None, 0
    selection = await resolve_sandbox_container_selection(
        id=container_id,
        user_id=user.id,
        user_role=user.role,
    )
    if selection is None:
        raise SandboxContainerUnavailableError("sandbox container is not available")
    return selection.id, selection.generation
