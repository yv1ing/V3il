from dataclasses import dataclass
from datetime import datetime

from sqlmodel import select

from database import get_async_session
from model.agent.notifications import AgentNotification
from model.agent.sessions import AgentSessionMeta
from model.system_user.users import SystemUser
from schema.agent.notifications import OUTSTANDING_NOTIFICATION_STATUSES
from schema.agent.sessions import SessionType
from service.agent import notifications as agent_notifications
from service.system_user.locking import lock_system_user_lifecycle


_OUTSTANDING_STATUS_VALUES = [status.value for status in OUTSTANDING_NOTIFICATION_STATUSES]


@dataclass(frozen=True)
class AgentSessionState:
    session_id: str
    session_type: SessionType
    title: str
    agent_code: str
    owner_id: int
    incident_id: int | None
    environment_id: int | None
    is_automated: bool
    selected_sandbox_container_id: int | None
    selected_sandbox_container_generation: int
    is_running: bool
    runtime_agent_code: str
    runtime_sandbox_container_id: int | None
    runtime_sandbox_container_generation: int
    run_started_at: datetime | None
    run_finished_at: datetime | None
    run_error: str
    created_at: datetime


def snapshot_session_meta(meta: AgentSessionMeta) -> AgentSessionState:
    return AgentSessionState(
        session_id=meta.session_id,
        session_type=meta.session_type,
        title=meta.title,
        agent_code=meta.agent_code,
        owner_id=meta.owner_id,
        incident_id=meta.incident_id,
        environment_id=meta.environment_id,
        is_automated=meta.is_automated,
        selected_sandbox_container_id=meta.selected_sandbox_container_id,
        selected_sandbox_container_generation=meta.selected_sandbox_container_generation,
        is_running=meta.is_running,
        runtime_agent_code=meta.runtime_agent_code,
        runtime_sandbox_container_id=meta.runtime_sandbox_container_id,
        runtime_sandbox_container_generation=meta.runtime_sandbox_container_generation,
        run_started_at=meta.run_started_at,
        run_finished_at=meta.run_finished_at,
        run_error=meta.run_error,
        created_at=meta.created_at,
    )


async def list_running_sessions() -> list[AgentSessionState]:
    async with get_async_session() as session:
        metas = list((await session.exec(
            select(AgentSessionMeta).where(AgentSessionMeta.is_running.is_(True))
        )).all())
        return [snapshot_session_meta(meta) for meta in metas]


async def mark_session_running(
    session_id: str,
    *,
    agent_code: str,
    user_id: int,
    sandbox_container_id: int | None,
    sandbox_container_generation: int,
) -> None:
    async with get_async_session() as session:
        await lock_system_user_lifecycle(session, user_id)
        if await session.get(SystemUser, user_id) is None:
            raise PermissionError("system user no longer exists")
        meta = await session.get(AgentSessionMeta, session_id)
        if meta is None:
            return
        meta.is_running = True
        meta.runtime_agent_code = agent_code
        meta.runtime_sandbox_container_id = sandbox_container_id
        meta.runtime_sandbox_container_generation = sandbox_container_generation
        meta.run_started_at = datetime.now()
        meta.run_finished_at = None
        meta.run_error = ""
        session.add(meta)
        await session.commit()


async def mark_session_stopped(session_id: str, *, error: str = "") -> None:
    async with get_async_session() as session, session.begin():
        meta = (await session.exec(
            select(AgentSessionMeta)
            .where(AgentSessionMeta.session_id == session_id)
            .with_for_update()
        )).one_or_none()
        if meta is None or await _session_has_outstanding_work(session, session_id):
            return
        _stop_session_meta(meta, error)
        session.add(meta)


async def mark_sessions_stopped(session_ids: list[str], *, error: str = "") -> None:
    if not session_ids:
        return
    normalized_ids = sorted(set(session_ids))
    async with get_async_session() as session, session.begin():
        metas = (await session.exec(
            select(AgentSessionMeta)
            .where(AgentSessionMeta.session_id.in_(normalized_ids))
            .order_by(AgentSessionMeta.session_id.asc())
            .with_for_update()
        )).all()
        active_session_ids = set((await session.exec(
            select(AgentNotification.session_id)
            .where(
                AgentNotification.session_id.in_(normalized_ids),
                AgentNotification.status.in_(_OUTSTANDING_STATUS_VALUES),
            )
            .distinct()
        )).all())
        for meta in metas:
            if meta.session_id in active_session_ids:
                continue
            _stop_session_meta(meta, error)
            session.add(meta)


async def force_mark_session_stopped(session_id: str, *, error: str = "") -> None:
    async with get_async_session() as session:
        meta = await session.get(AgentSessionMeta, session_id)
        if meta is None:
            return
        meta.is_running = False
        meta.run_finished_at = datetime.now()
        meta.run_error = _truncate_error(error)
        session.add(meta)
        await session.commit()


async def has_outstanding_session_work(session_id: str) -> bool:
    return await agent_notifications.has_active_session_notifications(session_id=session_id)


async def get_session_meta(session_id: str) -> AgentSessionState | None:
    async with get_async_session() as session:
        meta = await session.get(AgentSessionMeta, session_id)
        return snapshot_session_meta(meta) if meta is not None else None


def _truncate_error(value: str) -> str:
    value = value.strip().replace("\n", " ")
    return value if len(value) <= 500 else value[:499] + "..."


async def _session_has_outstanding_work(session, session_id: str) -> bool:
    notification_id = (await session.exec(
        select(AgentNotification.id)
        .where(
            AgentNotification.session_id == session_id,
            AgentNotification.status.in_(_OUTSTANDING_STATUS_VALUES),
        )
        .limit(1)
    )).first()
    return notification_id is not None


def _stop_session_meta(meta: AgentSessionMeta, error: str) -> None:
    meta.is_running = False
    meta.run_finished_at = datetime.now()
    meta.run_error = _truncate_error(error)
