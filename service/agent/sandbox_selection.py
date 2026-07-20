from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from model.agent.sessions import AgentSession
from utils.time import utc_now


async def set_environment_session_sandbox_container(
    session: AsyncSession,
    *,
    environment_id: int,
    sandbox_container_id: int | None,
    sandbox_container_generation: int,
) -> None:
    agent_session = (await session.exec(
        select(AgentSession)
        .where(AgentSession.environment_id == environment_id)
        .with_for_update()
    )).one_or_none()
    if agent_session is None:
        return
    agent_session.selected_sandbox_container_id = sandbox_container_id
    agent_session.selected_sandbox_generation = sandbox_container_generation
    agent_session.updated_at = utc_now()
    session.add(agent_session)


async def refresh_session_sandbox_container_generation(
    session: AsyncSession,
    *,
    sandbox_container_id: int,
    sandbox_container_generation: int,
) -> None:
    rows = list((await session.exec(
        select(AgentSession)
        .where(AgentSession.selected_sandbox_container_id == sandbox_container_id)
        .order_by(AgentSession.id.asc())
        .with_for_update()
    )).all())
    for agent_session in rows:
        agent_session.selected_sandbox_generation = sandbox_container_generation
        agent_session.updated_at = utc_now()
        session.add(agent_session)


async def clear_session_sandbox_container_bindings(
    session: AsyncSession,
    *,
    sandbox_container_id: int,
) -> None:
    rows = list((await session.exec(
        select(AgentSession)
        .where(AgentSession.selected_sandbox_container_id == sandbox_container_id)
        .order_by(AgentSession.id.asc())
        .with_for_update()
    )).all())
    for agent_session in rows:
        agent_session.selected_sandbox_container_id = None
        agent_session.selected_sandbox_generation = 0
        agent_session.updated_at = utc_now()
        session.add(agent_session)
