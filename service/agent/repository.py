from collections.abc import Sequence
from datetime import datetime
from uuid import uuid4

from pydantic import TypeAdapter
from sqlalchemy import func, or_
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from core.agent.constants import DEFAULT_AGENT_CODE
from core.runtime.input_items import display_text_from_content
from database import get_async_session
from model.agent.sessions import AgentContext, AgentEvent, AgentRun, AgentSession
from model.sandbox.containers import SandboxContainer
from model.system_user.users import SystemUser
from schema.agent.events import AgentDurableEvent, AgentInputPart, RunTransitionEvent, UserMessageEvent
from schema.agent.sessions import (
    AgentCancellationMode,
    AgentCode,
    AgentContextKind,
    AgentRunSchema,
    AgentRunStatus,
    AgentSessionCapabilitiesSchema,
    AgentSessionStatus,
    AgentSessionSummarySchema,
    AgentTriggerKind,
    SessionType,
)
from schema.runtime import AgentRunCancelPayload, AgentRunReadyPayload, AgentSessionCancelPayload
from schema.sandbox.containers import SandboxContainerStatus
from schema.system_user.users import SystemUserRole
from service.agent.admission import (
    run_admission_block_reason,
    sandbox_job_recovery_count,
    tool_recovery_count,
)
from service.common.pagination import Page, page_offset
from service.agent.event_store import append_event
from service.runtime import enqueue_outbox_event
from service.sandbox.locking import lock_sandbox_container_mutation
from utils.time import utc_now


_event_adapter = TypeAdapter(AgentDurableEvent)
_TERMINAL_RUN_STATUSES = {
    AgentRunStatus.SUCCEEDED,
    AgentRunStatus.FAILED,
    AgentRunStatus.CANCELED,
}


class AgentSessionNotRunnableError(RuntimeError):
    pass


async def create_chat_run(
    *,
    content: list[AgentInputPart],
    owner_id: int,
    agent_code: AgentCode | None,
    sandbox_container_id: int | None,
    sandbox_generation: int,
) -> tuple[AgentSession, AgentRun, UserMessageEvent]:
    session_id = str(uuid4())
    selected_agent = agent_code or AgentCode(DEFAULT_AGENT_CODE)
    async with get_async_session() as db:
        if sandbox_container_id is not None:
            await lock_sandbox_container_mutation(db, sandbox_container_id)
            await _require_current_sandbox_binding(
                db,
                sandbox_container_id,
                sandbox_generation,
            )
        if await db.get(SystemUser, owner_id) is None:
            raise PermissionError("system user no longer exists")
        agent_session = AgentSession(
            id=session_id,
            session_type=SessionType.CHAT,
            title=_title(content),
            primary_agent_code=selected_agent,
            owner_id=owner_id,
            selected_sandbox_container_id=sandbox_container_id,
            selected_sandbox_generation=sandbox_generation,
        )
        db.add(agent_session)
        await db.flush()
        context = _new_context(session_id, selected_agent)
        db.add(context)
        await db.flush()
        run, event = await _enqueue_user_run(db, agent_session, context, content, selected_agent)
        await db.commit()
        await db.refresh(agent_session)
        await db.refresh(run)
        return agent_session, run, event


async def enqueue_chat_run(
    *,
    session_id: str,
    content: list[AgentInputPart],
    user_id: int,
    user_role: SystemUserRole,
    requested_agent_code: AgentCode | None,
) -> tuple[AgentSession, AgentRun, UserMessageEvent]:
    async with get_async_session() as db:
        candidate = (await db.exec(select(
            AgentSession.selected_sandbox_container_id,
            AgentSession.selected_sandbox_generation,
        ).where(AgentSession.id == session_id))).one_or_none()
        if candidate is None:
            raise PermissionError("agent session not found")
        candidate_container_id, candidate_generation = candidate
        if candidate_container_id is not None:
            await lock_sandbox_container_mutation(db, candidate_container_id)
        agent_session = await _lock_accessible_session(db, session_id, user_id, user_role)
        if agent_session is None:
            raise PermissionError("agent session not found")
        if (
            agent_session.selected_sandbox_container_id != candidate_container_id
            or agent_session.selected_sandbox_generation != candidate_generation
        ):
            raise AgentSessionNotRunnableError("sandbox selection changed while admitting the Agent Run")
        if candidate_container_id is not None:
            await _require_current_sandbox_binding(
                db,
                candidate_container_id,
                candidate_generation,
            )
        if block_reason := await run_admission_block_reason(db, agent_session):
            raise AgentSessionNotRunnableError(block_reason)
        agent_code = _resolve_agent_code(agent_session, requested_agent_code)
        context = await _main_context(db, agent_session.id, agent_code)
        run, event = await _enqueue_user_run(db, agent_session, context, content, agent_code)
        if agent_session.session_type == SessionType.CHAT and not agent_session.title:
            agent_session.title = _title(content)
        agent_session.updated_at = utc_now()
        db.add(agent_session)
        await db.commit()
        await db.refresh(run)
        return agent_session, run, event


async def _enqueue_user_run(
    db: AsyncSession,
    agent_session: AgentSession,
    context: AgentContext,
    content: list[AgentInputPart],
    agent_code: AgentCode,
) -> tuple[AgentRun, UserMessageEvent]:
    run_id = str(uuid4())
    run = AgentRun(
        id=run_id,
        session_id=agent_session.id,
        context_id=context.id,
        agent_code=agent_code,
        status=AgentRunStatus.QUEUED,
        trigger_kind=AgentTriggerKind.USER_MESSAGE,
        trigger={"content": [part.model_dump(mode="json") for part in content]},
        sandbox_container_id=agent_session.selected_sandbox_container_id,
        sandbox_generation=agent_session.selected_sandbox_generation,
    )
    db.add(run)
    await db.flush()
    event = await append_event(
        db,
        agent_session,
        UserMessageEvent(
            id=str(uuid4()),
            session_id=agent_session.id,
            run_id=run_id,
            seq=agent_session.next_event_seq,
            occurred_at=utc_now(),
            agent_code=agent_code,
            content=content,
            display_text=display_text_from_content(content),
        ),
    )
    queued_event = await append_event(db, agent_session, RunTransitionEvent(
        id=str(uuid4()),
        session_id=agent_session.id,
        run_id=run_id,
        seq=agent_session.next_event_seq,
        occurred_at=utc_now(),
        status=AgentRunStatus.QUEUED,
        reason="user_message",
    ))
    enqueue_outbox_event(
        db,
        AgentRunReadyPayload(run_id=run_id, event_id=queued_event.id),
        idempotency_key=run_id,
    )
    return run, event


async def get_accessible_session(
    session_id: str,
    user_id: int,
    user_role: SystemUserRole,
) -> AgentSession | None:
    async with get_async_session() as db:
        agent_session = await db.get(AgentSession, session_id)
        if (
            agent_session is None
            or agent_session.status != AgentSessionStatus.ACTIVE
            or not _can_access(agent_session, user_id, user_role)
        ):
            return None
        return agent_session


async def session_summary(
    session_id: str,
    user_id: int,
    user_role: SystemUserRole,
) -> AgentSessionSummarySchema | None:
    async with get_async_session() as db:
        agent_session = await db.get(AgentSession, session_id)
        if (
            agent_session is None
            or agent_session.status != AgentSessionStatus.ACTIVE
            or not _can_access(agent_session, user_id, user_role)
        ):
            return None
        return await _summary(db, agent_session)


async def list_sessions(
    *,
    page: int,
    size: int,
    user_id: int,
    user_role: SystemUserRole,
    include_scoped: bool,
) -> Page[AgentSessionSummarySchema]:
    statement = select(AgentSession).where(AgentSession.status == AgentSessionStatus.ACTIVE)
    if user_role != SystemUserRole.ADMIN:
        statement = statement.where(AgentSession.owner_id == user_id)
    if not include_scoped:
        statement = statement.where(AgentSession.session_type == SessionType.CHAT)
    statement = statement.order_by(AgentSession.updated_at.desc(), AgentSession.id.desc())
    async with get_async_session() as db:
        total = int((await db.exec(select(func.count()).select_from(statement.order_by(None).subquery()))).one())
        rows = list((await db.exec(statement.offset(page_offset(page, size)).limit(size))).all())
        items = [await _summary(db, row) for row in rows]
    return Page(page=page, size=size, total=total, items=items)


async def replay_events(
    *,
    session_id: str,
    user_id: int,
    user_role: SystemUserRole,
    before_seq: int | None,
    limit: int,
) -> tuple[list[AgentDurableEvent], bool, int | None] | None:
    async with get_async_session() as db:
        agent_session = await db.get(AgentSession, session_id)
        if (
            agent_session is None
            or agent_session.status != AgentSessionStatus.ACTIVE
            or not _can_access(agent_session, user_id, user_role)
        ):
            return None
        statement = select(AgentEvent).where(AgentEvent.session_id == session_id)
        if before_seq is not None:
            statement = statement.where(AgentEvent.seq < before_seq)
        rows = list((await db.exec(statement.order_by(AgentEvent.seq.desc()).limit(limit + 1))).all())
    has_more = len(rows) > limit
    selected = rows[:limit]
    selected.reverse()
    events = [_event_adapter.validate_python(row.payload) for row in selected]
    return events, has_more, selected[0].seq if has_more and selected else None


async def update_title(
    session_id: str,
    title: str,
    user_id: int,
    user_role: SystemUserRole,
) -> AgentSessionSummarySchema | None:
    async with get_async_session() as db:
        agent_session = await _lock_accessible_session(db, session_id, user_id, user_role)
        if agent_session is None:
            return None
        agent_session.title = title
        agent_session.updated_at = utc_now()
        db.add(agent_session)
        await db.commit()
    return await session_summary(session_id, user_id, user_role)


async def update_sandbox_selection(
    session_id: str,
    sandbox_container_id: int | None,
    sandbox_generation: int,
    user_id: int,
    user_role: SystemUserRole,
) -> AgentSessionSummarySchema | None:
    async with get_async_session() as db:
        if sandbox_container_id is not None:
            await lock_sandbox_container_mutation(db, sandbox_container_id)
            await _require_current_sandbox_binding(
                db,
                sandbox_container_id,
                sandbox_generation,
            )
        agent_session = await _lock_accessible_session(db, session_id, user_id, user_role)
        if agent_session is None:
            return None
        if agent_session.session_type != SessionType.CHAT:
            raise ValueError("scoped session sandbox selection is owned by its parent resource")
        if await _has_nonterminal_runs(db, session_id):
            raise RuntimeError("cancel active and queued runs before changing sandbox container")
        agent_session.selected_sandbox_container_id = sandbox_container_id
        agent_session.selected_sandbox_generation = sandbox_generation
        agent_session.updated_at = utc_now()
        db.add(agent_session)
        await db.commit()
    return await session_summary(session_id, user_id, user_role)


async def archive_agent_session(session_id: str, user_id: int, user_role: SystemUserRole) -> bool:
    async with get_async_session() as db:
        agent_session = await _lock_accessible_session(db, session_id, user_id, user_role)
        if agent_session is None or agent_session.session_type != SessionType.CHAT:
            return False
        if await _has_nonterminal_runs(db, session_id):
            raise RuntimeError("cancel active and queued runs before archiving the session")
        if await tool_recovery_count(db, session_id):
            raise RuntimeError("resolve ambiguous tool invocations before archiving the session")
        if await sandbox_job_recovery_count(db, session_id):
            raise RuntimeError("resolve ambiguous Sandbox commands before archiving the session")
        now = utc_now()
        agent_session.status = AgentSessionStatus.ARCHIVED
        agent_session.archived_at = now
        agent_session.updated_at = now
        db.add(agent_session)
        await db.commit()
        return True


async def _summary(db: AsyncSession, agent_session: AgentSession) -> AgentSessionSummarySchema:
    active = (await db.exec(select(AgentRun).where(
        AgentRun.session_id == agent_session.id,
        AgentRun.is_foreground.is_(True),
        AgentRun.status.in_([AgentRunStatus.RUNNING, AgentRunStatus.WAITING]),
    ).order_by(AgentRun.queued_at.asc()).limit(1))).one_or_none()
    queued = int((await db.exec(select(func.count()).select_from(AgentRun).where(
        AgentRun.session_id == agent_session.id,
        AgentRun.status == AgentRunStatus.QUEUED,
    ))).one())
    event_count = int((await db.exec(select(func.count()).select_from(AgentEvent).where(
        AgentEvent.session_id == agent_session.id
    ))).one())
    nonterminal_run_count = int((await db.exec(select(func.count()).select_from(AgentRun).where(
        AgentRun.session_id == agent_session.id,
        AgentRun.status.notin_(_TERMINAL_RUN_STATUSES),
    ))).one())
    unsafe_recovery_run = (await db.exec(select(AgentRun.id).where(
        AgentRun.session_id == agent_session.id,
        or_(
            AgentRun.status == AgentRunStatus.RUNNING,
            (
                (AgentRun.status == AgentRunStatus.QUEUED)
                & (AgentRun.trigger_kind != AgentTriggerKind.TOOL_RECOVERY)
            ),
        ),
    ).limit(1))).first()
    recovery_count = await tool_recovery_count(db, agent_session.id)
    sandbox_recoveries = await sandbox_job_recovery_count(db, agent_session.id)
    turn_block_reason = await run_admission_block_reason(
        db,
        agent_session,
        recovery_count=recovery_count,
        sandbox_recovery_count=sandbox_recoveries,
    )
    is_chat = agent_session.session_type == SessionType.CHAT
    is_idle = nonterminal_run_count == 0
    return AgentSessionSummarySchema(
        id=agent_session.id,
        session_type=agent_session.session_type,
        status=agent_session.status,
        title=agent_session.title,
        primary_agent_code=agent_session.primary_agent_code,
        owner_id=agent_session.owner_id,
        incident_id=agent_session.incident_id,
        environment_id=agent_session.environment_id,
        selected_sandbox_container_id=agent_session.selected_sandbox_container_id,
        selected_sandbox_generation=agent_session.selected_sandbox_generation,
        active_run=AgentRunSchema.model_validate(active) if active else None,
        queued_run_count=queued,
        event_count=event_count,
        tool_recovery_count=recovery_count,
        sandbox_recovery_count=sandbox_recoveries,
        capabilities=AgentSessionCapabilitiesSchema(
            can_submit_turn=not turn_block_reason,
            can_archive=is_chat and is_idle and recovery_count == 0 and sandbox_recoveries == 0,
            can_select_sandbox_container=is_chat and is_idle,
            can_switch_agent=is_chat and is_idle and recovery_count == 0 and sandbox_recoveries == 0,
            can_interrupt=active is not None and active.status == AgentRunStatus.RUNNING,
            can_cancel_all=nonterminal_run_count > 0,
            can_resolve_tool_invocations=recovery_count > 0 and unsafe_recovery_run is None,
            can_resolve_sandbox_jobs=sandbox_recoveries > 0 and unsafe_recovery_run is None,
            turn_block_reason=turn_block_reason,
        ),
        created_at=agent_session.created_at,
        updated_at=agent_session.updated_at,
    )


def _resolve_agent_code(agent_session: AgentSession, requested: AgentCode | None) -> AgentCode:
    if agent_session.session_type != SessionType.CHAT:
        if requested is not None and requested != AgentCode.CSO:
            raise ValueError("scoped sessions are coordinated by the CSO agent")
        return AgentCode.CSO
    return requested or agent_session.primary_agent_code


async def _main_context(db: AsyncSession, session_id: str, agent_code: AgentCode) -> AgentContext:
    context = (await db.exec(select(AgentContext).where(
        AgentContext.session_id == session_id,
        AgentContext.agent_code == agent_code,
        AgentContext.kind == AgentContextKind.MAIN,
    ))).one_or_none()
    if context is None:
        context = _new_context(session_id, agent_code)
        db.add(context)
        await db.flush()
    return context


def _new_context(session_id: str, agent_code: AgentCode) -> AgentContext:
    return AgentContext(
        id=str(uuid4()),
        session_id=session_id,
        agent_code=agent_code,
        kind=AgentContextKind.MAIN,
    )


async def _lock_accessible_session(
    db: AsyncSession,
    session_id: str,
    user_id: int,
    user_role: SystemUserRole,
) -> AgentSession | None:
    agent_session = (await db.exec(
        select(AgentSession).where(AgentSession.id == session_id).with_for_update()
    )).one_or_none()
    if (
        agent_session is None
        or agent_session.status != AgentSessionStatus.ACTIVE
        or not _can_access(agent_session, user_id, user_role)
    ):
        return None
    return agent_session


def _can_access(agent_session: AgentSession, user_id: int, user_role: SystemUserRole) -> bool:
    return user_role == SystemUserRole.ADMIN or agent_session.owner_id == user_id


async def _has_nonterminal_runs(db: AsyncSession, session_id: str) -> bool:
    return (await db.exec(select(AgentRun.id).where(
        AgentRun.session_id == session_id,
        AgentRun.status.not_in(_TERMINAL_RUN_STATUSES),
    ).limit(1))).first() is not None


async def _require_current_sandbox_binding(
    db: AsyncSession,
    container_id: int,
    generation: int,
) -> None:
    container = (await db.exec(select(SandboxContainer).where(
        SandboxContainer.id == container_id,
    ).with_for_update())).one_or_none()
    if (
        container is None
        or container.status != SandboxContainerStatus.RUNNING
        or container.generation != generation
    ):
        raise ValueError("sandbox container generation is no longer available")


def _title(content: Sequence[AgentInputPart]) -> str:
    return display_text_from_content(list(content))[:80]


async def request_session_cancellation(
    session_ids: Sequence[str],
    *,
    reason: str,
) -> None:
    async with get_async_session() as db:
        for session_id in sorted(set(session_ids)):
            runs = list((await db.exec(select(AgentRun).where(
                AgentRun.session_id == session_id,
                AgentRun.status.not_in(_TERMINAL_RUN_STATUSES),
                AgentRun.cancel_requested_at.is_(None),
            ).order_by(AgentRun.id.asc()).with_for_update())).all())
            if not runs:
                continue
            now = utc_now()
            for run in runs:
                _mark_cancellation_requested(run, AgentCancellationMode.CANCEL, reason, now)
                db.add(run)
            enqueue_outbox_event(
                db,
                AgentSessionCancelPayload(
                    session_id=session_id,
                    mode=AgentCancellationMode.CANCEL,
                    actor=reason,
                ),
                idempotency_key=f"cancel-session:{session_id}:{uuid4()}",
            )
        await db.commit()


async def request_foreground_interrupt(
    session_id: str,
    *,
    user_id: int,
    user_role: SystemUserRole,
    actor: str,
) -> list[str] | None:
    async with get_async_session() as db:
        agent_session = await db.get(AgentSession, session_id)
        if agent_session is None or not _can_access(agent_session, user_id, user_role):
            return None
        run = (await db.exec(select(AgentRun).where(
            AgentRun.session_id == session_id,
            AgentRun.is_foreground.is_(True),
            AgentRun.status == AgentRunStatus.RUNNING,
            AgentRun.cancel_requested_at.is_(None),
        ).order_by(AgentRun.started_at.asc(), AgentRun.id.asc()).limit(1).with_for_update())).one_or_none()
        if run is None:
            return []
        _mark_cancellation_requested(run, AgentCancellationMode.INTERRUPT, actor, utc_now())
        db.add(run)
        enqueue_outbox_event(
            db,
            AgentRunCancelPayload(
                run_id=run.id,
                mode=AgentCancellationMode.INTERRUPT,
                actor=actor,
            ),
            idempotency_key=f"interrupt-run:{run.id}",
        )
        await db.commit()
        return [run.id]


async def request_all_run_cancellations(
    session_id: str,
    *,
    user_id: int,
    user_role: SystemUserRole,
    actor: str,
) -> list[str] | None:
    async with get_async_session() as db:
        agent_session = await db.get(AgentSession, session_id)
        if agent_session is None or not _can_access(agent_session, user_id, user_role):
            return None
        runs = list((await db.exec(select(AgentRun).where(
            AgentRun.session_id == session_id,
            AgentRun.status.not_in(_TERMINAL_RUN_STATUSES),
            AgentRun.cancel_requested_at.is_(None),
        ).order_by(AgentRun.id.asc()).with_for_update())).all())
        if not runs:
            return []
        now = utc_now()
        for run in runs:
            _mark_cancellation_requested(run, AgentCancellationMode.CANCEL, actor, now)
            db.add(run)
        enqueue_outbox_event(
            db,
            AgentSessionCancelPayload(
                session_id=session_id,
                mode=AgentCancellationMode.CANCEL,
                actor=actor,
            ),
            idempotency_key=f"cancel-session:{session_id}:{uuid4()}",
        )
        await db.commit()
        return [run.id for run in runs]


def _mark_cancellation_requested(
    run: AgentRun,
    mode: AgentCancellationMode,
    actor: str,
    requested_at: datetime,
) -> None:
    run.cancel_requested_at = requested_at
    run.cancel_requested_by = actor
    run.cancel_requested_mode = mode


async def enqueue_system_run(
    db: AsyncSession,
    *,
    agent_session: AgentSession,
    content: str,
    source_key: str,
) -> AgentRun | None:
    if await run_admission_block_reason(
        db,
        agent_session,
        recovery_count=0,
        sandbox_recovery_count=0,
    ):
        return None
    existing = (await db.exec(select(AgentRun.id).where(
        AgentRun.session_id == agent_session.id,
        AgentRun.source_key == source_key,
    ).limit(1))).first()
    if existing is not None:
        return None
    context = await _main_context(db, agent_session.id, AgentCode.CSO)
    run = AgentRun(
        id=str(uuid4()),
        session_id=agent_session.id,
        context_id=context.id,
        agent_code=AgentCode.CSO,
        status=AgentRunStatus.QUEUED,
        trigger_kind=AgentTriggerKind.SYSTEM_EVENT,
        trigger={"content": [{"type": "text", "text": content[:20_000]}]},
        source_key=source_key,
        sandbox_container_id=agent_session.selected_sandbox_container_id,
        sandbox_generation=agent_session.selected_sandbox_generation,
    )
    db.add(run)
    await db.flush()
    queued_event = await append_event(db, agent_session, RunTransitionEvent(
        id=str(uuid4()),
        session_id=agent_session.id,
        run_id=run.id,
        seq=agent_session.next_event_seq,
        occurred_at=utc_now(),
        status=AgentRunStatus.QUEUED,
        reason="system_event",
    ))
    enqueue_outbox_event(
        db,
        AgentRunReadyPayload(run_id=run.id, event_id=queued_event.id),
        idempotency_key=run.id,
    )
    return run
