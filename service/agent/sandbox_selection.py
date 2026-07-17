from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from model.agent.sessions import AgentSessionMeta


async def set_environment_session_sandbox_container(
    session: AsyncSession,
    *,
    environment_id: int,
    sandbox_container_id: int | None,
    sandbox_container_generation: int,
) -> None:
    metas = list((await session.exec(
        select(AgentSessionMeta)
        .where(AgentSessionMeta.environment_id == environment_id)
        .order_by(AgentSessionMeta.session_id.asc())
        .with_for_update()
    )).all())
    for meta in metas:
        meta.selected_sandbox_container_id = sandbox_container_id
        meta.selected_sandbox_container_generation = sandbox_container_generation
        session.add(meta)


async def refresh_session_sandbox_container_generation(
    session: AsyncSession,
    *,
    sandbox_container_id: int,
    sandbox_container_generation: int,
) -> None:
    metas = list((await session.exec(
        select(AgentSessionMeta)
        .where(AgentSessionMeta.selected_sandbox_container_id == sandbox_container_id)
        .order_by(AgentSessionMeta.session_id.asc())
        .with_for_update()
    )).all())
    for meta in metas:
        meta.selected_sandbox_container_generation = sandbox_container_generation
        session.add(meta)
