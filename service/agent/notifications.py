from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import or_
from sqlmodel import select, update

from core.runtime.context import MAIN_AGENT_INSTANCE_PREFIX
from database import get_async_session
from logger import get_logger
from model.agent.notifications import AgentNotification
from model.agent.sessions import AgentSessionMeta
from schema.agent.notifications import (
    AgentNotificationKind,
    AgentNotificationSnapshot,
    AgentNotificationStatus,
    OUTSTANDING_NOTIFICATION_STATUSES,
    USER_MESSAGE_PRIORITY,
)


logger = get_logger(__name__)
_TERMINAL_NOTIFICATION_STATUSES = {
    AgentNotificationStatus.COMPLETED,
    AgentNotificationStatus.FAILED,
    AgentNotificationStatus.CANCELED,
}
_OUTSTANDING_VALUES = [status.value for status in OUTSTANDING_NOTIFICATION_STATUSES]
_ACTIVE_CANCELABLE_VALUES = [
    AgentNotificationStatus.PENDING.value,
    AgentNotificationStatus.PROCESSING.value,
]

_MAIN_AGENT_TARGET = f"{MAIN_AGENT_INSTANCE_PREFIX}%"


def add_obligation_in_session(
    session: Any,
    *,
    meta: AgentSessionMeta,
    kind: AgentNotificationKind,
    target_agent_code: str,
    target_agent_instance_id: str,
    run_id: str,
    payload: dict[str, Any] | None = None,
    nested_for_agent_code: str = "",
    nested_call_id: str = "",
    sandbox_container_id: int | None = None,
    sandbox_container_generation: int = 0,
    sandbox_skill_metadata: tuple[str, ...] = (),
) -> AgentNotification:
    """Register an AWAITING obligation row on an already-open session.

    Created in the same transaction as the background task it tracks, so a
    parent driver can never observe "no running task and no notification" — the
    obligation is outstanding from the instant the task is born until its result
    is consumed. The caller is responsible for committing.
    """
    notification = AgentNotification(
        id=str(uuid4()),
        session_id=meta.session_id,
        target_agent_code=target_agent_code,
        target_agent_instance_id=target_agent_instance_id,
        nested_for_agent_code=nested_for_agent_code,
        nested_call_id=nested_call_id,
        sandbox_container_id=sandbox_container_id,
        sandbox_container_generation=sandbox_container_generation,
        sandbox_skill_metadata=list(sandbox_skill_metadata),
        kind=kind,
        status=AgentNotificationStatus.AWAITING,
        run_id=run_id,
        payload=payload or {},
    )
    _mark_notification_session_active(session, meta, target_agent_code, notification.created_at)
    session.add(notification)
    return notification


async def resolve_obligation_in_session(
    session: Any,
    *,
    kind: AgentNotificationKind,
    run_id: str,
    ready: bool,
    payload: dict[str, Any] | None = None,
    error: str = "",
) -> AgentNotification | None:
    """Resolve a registered obligation on an already-open session.

    ``ready=True`` flips AWAITING -> PENDING (result available, wakes the
    parent); ``ready=False`` flips AWAITING -> CANCELED (no wake). Idempotent:
    if the obligation is missing or already past AWAITING it is left untouched.
    The caller is responsible for committing.
    """
    now = datetime.now()
    notification = (await session.exec(
        select(AgentNotification).where(
            AgentNotification.kind == kind.value,
            AgentNotification.run_id == run_id,
        ).with_for_update()
    )).first()
    if notification is None or _coerce_status(notification.status) != AgentNotificationStatus.AWAITING:
        return notification
    notification.status = (
        AgentNotificationStatus.PENDING if ready else AgentNotificationStatus.CANCELED
    )
    if payload is not None:
        notification.payload = payload
    notification.error = error
    notification.updated_at = now
    if not ready:
        notification.finished_at = now
    session.add(notification)
    return notification


async def enqueue_user_message_notification(
    *,
    session_id: str,
    target_agent_code: str,
    target_agent_instance_id: str,
    user_content: list[dict[str, Any]],
    user_display_text: str = "",
    user_requested_agent_code: str = "",
    sandbox_container_id: int | None = None,
    sandbox_container_generation: int = 0,
    sandbox_skill_metadata: tuple[str, ...] = (),
) -> AgentNotificationSnapshot:
    """Queue a user message for the agent that is already running."""
    run_id = str(uuid4())
    payload: dict[str, Any] = {
        "content": user_content,
        "display_text": user_display_text,
        "requested_agent_code": user_requested_agent_code,
    }
    notification = AgentNotification(
        id=str(uuid4()),
        session_id=session_id,
        target_agent_code=target_agent_code,
        target_agent_instance_id=target_agent_instance_id,
        nested_for_agent_code="",
        nested_call_id="",
        sandbox_container_id=sandbox_container_id,
        sandbox_container_generation=sandbox_container_generation,
        sandbox_skill_metadata=list(sandbox_skill_metadata),
        kind=AgentNotificationKind.USER_MESSAGE,
        status=AgentNotificationStatus.PENDING,
        priority=USER_MESSAGE_PRIORITY,
        run_id=run_id,
        payload=payload,
    )
    async with get_async_session() as session:
        meta = (await session.exec(
            select(AgentSessionMeta)
            .where(AgentSessionMeta.session_id == session_id)
            .with_for_update()
        )).one_or_none()
        if meta is None:
            raise ValueError("Agent session is unavailable")
        _mark_notification_session_active(session, meta, target_agent_code, notification.created_at)
        session.add(notification)
        await session.commit()
        await session.refresh(notification)
        result = snapshot_from_notification(notification)
    logger.debug(
        "user message notification queued: %s session=%s target=%s",
        result.id,
        result.session_id,
        result.target_agent_code,
    )
    return result


async def enqueue_behavior_events_notification_in_session(
    session: Any,
    *,
    meta: AgentSessionMeta,
    target_agent_code: str,
    target_agent_instance_id: str,
    incident_id: int,
    environment_id: int,
    event_ids: list[int],
    event_limit: int,
    now: datetime | None = None,
) -> AgentNotification | None:
    unique_event_ids = list(dict.fromkeys(event_id for event_id in event_ids if event_id > 0))
    if not unique_event_ids or meta.incident_id != incident_id:
        return None
    bounded_event_limit = max(1, event_limit)
    timestamp = now or datetime.now()
    _mark_notification_session_active(session, meta, target_agent_code, timestamp)
    notification = (await session.exec(
        select(AgentNotification)
        .where(
            AgentNotification.session_id == meta.session_id,
            AgentNotification.target_agent_instance_id == target_agent_instance_id,
            AgentNotification.kind == AgentNotificationKind.BEHAVIOR_EVENTS_CAPTURED.value,
            AgentNotification.status == AgentNotificationStatus.PENDING.value,
        )
        .order_by(AgentNotification.created_at.desc())
        .limit(1)
    )).one_or_none()
    if notification is None:
        notification = AgentNotification(
            id=str(uuid4()),
            session_id=meta.session_id,
            target_agent_code=target_agent_code,
            target_agent_instance_id=target_agent_instance_id,
            kind=AgentNotificationKind.BEHAVIOR_EVENTS_CAPTURED,
            status=AgentNotificationStatus.PENDING,
            run_id=str(uuid4()),
            sandbox_container_id=meta.selected_sandbox_container_id,
            sandbox_container_generation=meta.selected_sandbox_container_generation,
            payload={
                "incident_id": incident_id,
                "environment_id": environment_id,
                "event_ids": unique_event_ids[-bounded_event_limit:],
                "event_count": len(unique_event_ids),
            },
            created_at=timestamp,
            updated_at=timestamp,
        )
    else:
        previous = _coerce_payload(notification.payload)
        previous_ids = previous.get("event_ids")
        combined = [
            event_id for event_id in (
                *(previous_ids if isinstance(previous_ids, list) else []),
                *unique_event_ids,
            )
            if isinstance(event_id, int) and event_id > 0
        ]
        notification.payload = {
            "incident_id": incident_id,
            "environment_id": environment_id,
            "event_ids": list(dict.fromkeys(combined))[-bounded_event_limit:],
            "event_count": int(previous.get("event_count") or 0) + len(unique_event_ids),
        }
        notification.updated_at = timestamp
    session.add(notification)
    await session.flush()
    return notification


async def enqueue_behavior_signals_notification_in_session(
    session: Any,
    *,
    meta: AgentSessionMeta,
    target_agent_code: str,
    target_agent_instance_id: str,
    incident_id: int,
    signal_ids: list[int],
    highest_score: int,
    signal_limit: int,
    now: datetime | None = None,
) -> AgentNotification | None:
    unique_signal_ids = list(dict.fromkeys(signal_id for signal_id in signal_ids if signal_id > 0))
    if not unique_signal_ids or meta.incident_id != incident_id:
        return None
    timestamp = now or datetime.now()
    priority = 90 if highest_score >= 90 else 70 if highest_score >= 70 else 40
    _mark_notification_session_active(session, meta, target_agent_code, timestamp)
    notification = (await session.exec(
        select(AgentNotification).where(
            AgentNotification.session_id == meta.session_id,
            AgentNotification.target_agent_instance_id == target_agent_instance_id,
            AgentNotification.kind == AgentNotificationKind.BEHAVIOR_SIGNALS_DETECTED.value,
            AgentNotification.status == AgentNotificationStatus.PENDING.value,
        ).order_by(AgentNotification.created_at.desc()).limit(1)
    )).one_or_none()
    if notification is None:
        notification = AgentNotification(
            id=str(uuid4()),
            session_id=meta.session_id,
            target_agent_code=target_agent_code,
            target_agent_instance_id=target_agent_instance_id,
            kind=AgentNotificationKind.BEHAVIOR_SIGNALS_DETECTED,
            status=AgentNotificationStatus.PENDING,
            priority=priority,
            run_id=str(uuid4()),
            sandbox_container_id=meta.selected_sandbox_container_id,
            sandbox_container_generation=meta.selected_sandbox_container_generation,
            payload={
                "incident_id": incident_id,
                "signal_ids": unique_signal_ids[-max(1, signal_limit):],
                "signal_count": len(unique_signal_ids),
                "highest_score": highest_score,
            },
            created_at=timestamp,
            updated_at=timestamp,
        )
    else:
        previous = _coerce_payload(notification.payload)
        previous_ids = previous.get("signal_ids")
        combined = [
            item for item in [
                *(previous_ids if isinstance(previous_ids, list) else []),
                *unique_signal_ids,
            ] if isinstance(item, int) and item > 0
        ]
        notification.priority = max(notification.priority, priority)
        notification.payload = {
            "incident_id": incident_id,
            "signal_ids": list(dict.fromkeys(combined))[-max(1, signal_limit):],
            "signal_count": int(previous.get("signal_count") or 0) + len(unique_signal_ids),
            "highest_score": max(int(previous.get("highest_score") or 0), highest_score),
        }
        notification.updated_at = timestamp
    session.add(notification)
    await session.flush()
    return notification


async def enqueue_deception_evaluation_notification_in_session(
    session: Any,
    *,
    meta: AgentSessionMeta,
    target_agent_code: str,
    target_agent_instance_id: str,
    incident_id: int,
    environment_id: int,
    revision_id: int,
    task_id: int,
) -> AgentNotification | None:
    if meta.incident_id != incident_id:
        return None
    notification = AgentNotification(
        id=str(uuid4()),
        session_id=meta.session_id,
        target_agent_code=target_agent_code,
        target_agent_instance_id=target_agent_instance_id,
        kind=AgentNotificationKind.DECEPTION_EVALUATION_DUE,
        status=AgentNotificationStatus.PENDING,
        priority=10,
        run_id=f"deception-evaluation:{revision_id}",
        sandbox_container_id=meta.selected_sandbox_container_id,
        sandbox_container_generation=meta.selected_sandbox_container_generation,
        payload={
            "incident_id": incident_id,
            "environment_id": environment_id,
            "revision_id": revision_id,
            "investigation_task_id": task_id,
        },
    )
    _mark_notification_session_active(session, meta, target_agent_code, notification.created_at)
    session.add(notification)
    await session.flush()
    return notification


async def claim_next_pending_notification(
    *,
    session_id: str,
    target_agent_code: str | None = None,
    target_agent_instance_id: str | None = None,
) -> AgentNotificationSnapshot | None:
    now = datetime.now()
    async with get_async_session() as session:
        statement = select(AgentNotification).where(
            AgentNotification.session_id == session_id,
            AgentNotification.status == AgentNotificationStatus.PENDING.value,
        )
        if target_agent_code is not None:
            statement = statement.where(AgentNotification.target_agent_code == target_agent_code)
        statement = _filter_notification_target(statement, target_agent_instance_id)
        notification = (await session.exec(
            statement
            .order_by(AgentNotification.priority.desc(), AgentNotification.created_at.asc())
            .limit(1)
            .with_for_update(skip_locked=True)
        )).first()
        if notification is None:
            return None
        notification_id = notification.id
        updated = await session.exec(
            update(AgentNotification)
            .where(
                AgentNotification.id == notification_id,
                AgentNotification.status == AgentNotificationStatus.PENDING.value,
            )
            .values(
                status=AgentNotificationStatus.PROCESSING,
                started_at=now,
                updated_at=now,
            )
        )
        if updated.rowcount != 1:
            await session.rollback()
            return None
        await session.commit()
        claimed = await session.get(AgentNotification, notification_id)
        return snapshot_from_notification(claimed) if claimed is not None else None


async def has_pending_notification(
    *,
    session_id: str,
    target_agent_code: str | None = None,
    target_agent_instance_id: str | None = None,
    minimum_priority_exclusive: int | None = None,
) -> bool:
    async with get_async_session() as session:
        statement = select(AgentNotification.id).where(
            AgentNotification.session_id == session_id,
            AgentNotification.status == AgentNotificationStatus.PENDING.value,
        )
        if target_agent_code is not None:
            statement = statement.where(AgentNotification.target_agent_code == target_agent_code)
        statement = _filter_notification_target(statement, target_agent_instance_id)
        if minimum_priority_exclusive is not None:
            statement = statement.where(AgentNotification.priority > minimum_priority_exclusive)
        notification_id = (await session.exec(
            statement
            .limit(1)
        )).first()
        return notification_id is not None


async def has_pending_main_agent_notification(*, session_id: str) -> bool:
    async with get_async_session() as session:
        notification_id = (await session.exec(
            select(AgentNotification.id)
            .where(
                AgentNotification.session_id == session_id,
                AgentNotification.status == AgentNotificationStatus.PENDING.value,
                AgentNotification.target_agent_instance_id.like(_MAIN_AGENT_TARGET),
            )
            .limit(1)
        )).first()
        return notification_id is not None


async def has_active_session_notifications(*, session_id: str) -> bool:
    """Session-wide liveness: any outstanding work anywhere in the session.

    Single source of truth for ``run_state`` — covers in-flight obligations
    (AWAITING), ready items (PENDING) and items being handled (PROCESSING).
    """
    async with get_async_session() as session:
        notification_id = (await session.exec(
            select(AgentNotification.id)
            .where(
                AgentNotification.session_id == session_id,
                AgentNotification.status.in_(_OUTSTANDING_VALUES),
            )
            .limit(1)
        )).first()
        return notification_id is not None


async def has_outstanding_target_notifications(
    *,
    session_id: str,
    target_agent_instance_id: str | None = None,
) -> bool:
    # Target-scoped liveness: outstanding obligations (sub-agents / async jobs)
    # owned by one instance; a driver goes dormant while this holds.
    async with get_async_session() as session:
        statement = select(AgentNotification.id).where(
            AgentNotification.session_id == session_id,
            AgentNotification.status.in_(_OUTSTANDING_VALUES),
        )
        statement = _filter_notification_target(statement, target_agent_instance_id)
        notification_id = (await session.exec(statement.limit(1))).first()
        return notification_id is not None


async def complete_notification(notification_id: str) -> AgentNotificationSnapshot | None:
    return await _finish_notification(notification_id, AgentNotificationStatus.COMPLETED)


async def fail_notification(notification_id: str, error: str) -> AgentNotificationSnapshot | None:
    return await _finish_notification(notification_id, AgentNotificationStatus.FAILED, error=error)


async def release_notification(notification_id: str) -> AgentNotificationSnapshot | None:
    now = datetime.now()
    async with get_async_session() as session:
        notification = await session.get(AgentNotification, notification_id)
        if notification is None:
            return None
        if _coerce_status(notification.status) != AgentNotificationStatus.PROCESSING:
            return snapshot_from_notification(notification)
        # ``started_at`` is intentionally preserved so that
        # ``cancel_main_agent_interrupted_notifications`` can distinguish a
        # USER_MESSAGE that was claimed and released by a user interrupt
        # (must be cancelled) from a fresh USER_MESSAGE that has never been
        # processed (must be honoured).
        updated = await session.exec(
            update(AgentNotification)
            .where(
                AgentNotification.id == notification_id,
                AgentNotification.status == AgentNotificationStatus.PROCESSING.value,
            )
            .values(
                status=AgentNotificationStatus.PENDING,
                error="",
                updated_at=now,
            )
        )
        if updated.rowcount != 1:
            await session.rollback()
            current = await session.get(AgentNotification, notification_id)
            return snapshot_from_notification(current) if current is not None else None
        await session.commit()
        current = await session.get(AgentNotification, notification_id)
        return snapshot_from_notification(current) if current is not None else None


async def cancel_session_notifications(
    session_id: str,
    error: str = "",
    *,
    target_agent_instance_id: str | None = None,
) -> list[AgentNotificationSnapshot]:
    return await _cancel_notifications(
        session_id=session_id,
        error=error,
        instance_equals=target_agent_instance_id,
        statuses=_OUTSTANDING_VALUES,
    )


async def cancel_main_agent_interrupted_notifications(
    session_id: str,
    error: str = "",
) -> list[AgentNotificationSnapshot]:
    """Cancel main-agent notifications that represent interrupted/abandoned work.

    Called on user interrupt.  The filter discards:

    * every SUBAGENT_FINISHED / SANDBOX_ASYNC_JOB_FINISHED notification
      targeted at the main agent (whether still queued or released back to
      PENDING by the executor's CancelledError handler), and
    * any USER_MESSAGE that was already claimed at least once
      (``started_at`` is set) — those represent work the user explicitly
      asked to abandon.

    Fresh USER_MESSAGE notifications enqueued by ``start_turn`` during the
    interrupt window keep ``started_at IS NULL`` and are deliberately
    preserved so that the next idle cycle (or the user's next ``start_turn``)
    can still honour them.
    """
    return await _cancel_notifications(
        session_id=session_id,
        error=error,
        instance_like=_MAIN_AGENT_TARGET,
        spare_unclaimed_user_messages=True,
    )


async def _cancel_notifications(
    *,
    session_id: str,
    error: str,
    instance_equals: str | None = None,
    instance_like: str | None = None,
    spare_unclaimed_user_messages: bool = False,
    statuses: list[str] | None = None,
) -> list[AgentNotificationSnapshot]:
    now = datetime.now()
    async with get_async_session() as session:
        statement = select(AgentNotification).where(
            AgentNotification.session_id == session_id,
            AgentNotification.status.in_(statuses or _ACTIVE_CANCELABLE_VALUES),
        )
        if instance_equals is not None:
            statement = statement.where(AgentNotification.target_agent_instance_id == instance_equals)
        if instance_like is not None:
            statement = statement.where(AgentNotification.target_agent_instance_id.like(instance_like))
        if spare_unclaimed_user_messages:
            statement = statement.where(or_(
                AgentNotification.kind != AgentNotificationKind.USER_MESSAGE.value,
                AgentNotification.started_at.is_not(None),
            ))
        rows = (await session.exec(statement.with_for_update())).all()
        if not rows:
            return []
        for notification in rows:
            notification.status = AgentNotificationStatus.CANCELED
            notification.error = error
            notification.updated_at = now
            notification.finished_at = now
            session.add(notification)
        await session.commit()
        for notification in rows:
            await session.refresh(notification)
        return [snapshot_from_notification(notification) for notification in rows]


async def reset_processing_notifications_all() -> int:
    now = datetime.now()
    async with get_async_session() as session:
        rows = (await session.exec(
            select(AgentNotification).where(
                AgentNotification.status == AgentNotificationStatus.PROCESSING.value,
            ).with_for_update()
        )).all()
        for notification in rows:
            notification.status = AgentNotificationStatus.PENDING
            notification.error = ""
            notification.started_at = None
            notification.updated_at = now
            session.add(notification)
        if rows:
            await session.commit()
            logger.info("processing agent notifications reset: %d", len(rows))
        return len(rows)


async def _finish_notification(
    notification_id: str,
    status: AgentNotificationStatus,
    *,
    error: str = "",
) -> AgentNotificationSnapshot | None:
    now = datetime.now()
    async with get_async_session() as session:
        notification = await session.get(AgentNotification, notification_id)
        if notification is None:
            return None
        if _coerce_status(notification.status) in _TERMINAL_NOTIFICATION_STATUSES:
            return snapshot_from_notification(notification)
        updated = await session.exec(
            update(AgentNotification)
            .where(
                AgentNotification.id == notification_id,
                AgentNotification.status == AgentNotificationStatus.PROCESSING.value,
            )
            .values(
                status=status,
                error=error,
                updated_at=now,
                finished_at=now,
            )
        )
        if updated.rowcount != 1:
            await session.rollback()
            current = await session.get(AgentNotification, notification_id)
            return snapshot_from_notification(current) if current is not None else None
        await session.commit()
        current = await session.get(AgentNotification, notification_id)
        return snapshot_from_notification(current) if current is not None else None


def snapshot_from_notification(notification: AgentNotification) -> AgentNotificationSnapshot:
    payload = _coerce_payload(notification.payload)
    kind = _coerce_kind(notification.kind)

    user_content: list[dict[str, Any]] | None = None
    user_display_text = ""
    user_requested_agent_code = ""
    if kind == AgentNotificationKind.USER_MESSAGE:
        raw_content = payload.get("content")
        user_content = raw_content if isinstance(raw_content, list) else None
        user_display_text = str(payload.get("display_text") or "")
        user_requested_agent_code = str(payload.get("requested_agent_code") or "")

    return AgentNotificationSnapshot(
        id=notification.id,
        session_id=notification.session_id,
        target_agent_code=notification.target_agent_code,
        target_agent_instance_id=notification.target_agent_instance_id,
        nested_for_agent_code=notification.nested_for_agent_code,
        nested_call_id=notification.nested_call_id,
        kind=kind,
        status=_coerce_status(notification.status),
        priority=notification.priority,
        run_id=notification.run_id,
        payload=payload,
        error=notification.error,
        sandbox_container_id=notification.sandbox_container_id,
        sandbox_container_generation=notification.sandbox_container_generation,
        sandbox_skill_metadata=_coerce_string_tuple(notification.sandbox_skill_metadata),
        created_at=notification.created_at,
        updated_at=notification.updated_at,
        started_at=notification.started_at,
        finished_at=notification.finished_at,
        user_content=user_content,
        user_display_text=user_display_text,
        user_requested_agent_code=user_requested_agent_code,
    )


def _coerce_kind(value: AgentNotificationKind | str) -> AgentNotificationKind:
    if isinstance(value, AgentNotificationKind):
        return value
    return AgentNotificationKind(str(value).lower())


def _coerce_status(value: AgentNotificationStatus | str) -> AgentNotificationStatus:
    if isinstance(value, AgentNotificationStatus):
        return value
    return AgentNotificationStatus(str(value).lower())


def _coerce_payload(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _coerce_string_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _filter_notification_target(statement: Any, target_agent_instance_id: str | None) -> Any:
    if target_agent_instance_id is not None:
        return statement.where(AgentNotification.target_agent_instance_id == target_agent_instance_id)
    return statement.where(AgentNotification.target_agent_instance_id.like(_MAIN_AGENT_TARGET))


def _mark_notification_session_active(
    session: Any,
    meta: AgentSessionMeta,
    target_agent_code: str,
    now: datetime,
) -> None:
    meta.is_running = True
    meta.runtime_agent_code = target_agent_code or meta.runtime_agent_code or meta.agent_code
    if meta.run_started_at is None:
        meta.run_started_at = now
    meta.run_finished_at = None
    meta.run_error = ""
    session.add(meta)
