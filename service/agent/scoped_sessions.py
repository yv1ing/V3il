from uuid import uuid4

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from model.agent.sessions import AgentContext, AgentSession
from schema.agent.sessions import AgentCode, AgentContextKind, SessionType


async def ensure_scoped_session(
    db: AsyncSession,
    *,
    session_type: SessionType,
    owner_id: int,
    title: str,
    incident_id: int | None = None,
    environment_id: int | None = None,
    sandbox_container_id: int | None = None,
    sandbox_generation: int = 0,
) -> AgentSession:
    if session_type == SessionType.CHAT:
        raise ValueError("scoped session type is required")
    statement = select(AgentSession).where(
        AgentSession.incident_id == incident_id
        if session_type == SessionType.INCIDENT
        else AgentSession.environment_id == environment_id
    )
    existing = (await db.exec(statement.with_for_update())).one_or_none()
    if existing is not None:
        return existing
    session_id = str(uuid4())
    agent_session = AgentSession(
        id=session_id,
        session_type=session_type,
        title=title[:80],
        primary_agent_code=AgentCode.CSO,
        owner_id=owner_id,
        incident_id=incident_id,
        environment_id=environment_id,
        selected_sandbox_container_id=sandbox_container_id,
        selected_sandbox_generation=sandbox_generation,
    )
    db.add(agent_session)
    await db.flush()
    db.add(AgentContext(
        id=str(uuid4()),
        session_id=session_id,
        agent_code=AgentCode.CSO,
        kind=AgentContextKind.MAIN,
    ))
    await db.flush()
    return agent_session
