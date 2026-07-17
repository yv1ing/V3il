from datetime import datetime
from uuid import uuid4

from sqlmodel import select, update

from database import get_async_session
from logger import get_logger
from model.agent.sessions import AgentSessionMeta
from model.agent.subordinates import AgentSubordinateTask
from model.threat.investigations import InvestigationTask, InvestigationTaskEvent
from schema.agent.notifications import AgentNotificationKind
from schema.agent.subordinates import (
    AgentSubordinateStatus,
    AgentSubordinateTaskSnapshot,
)
from schema.system_user.users import SystemUserRole
from schema.threat.investigations import AuditActorType, AuditEventKind, InvestigationTaskStatus
from service.threat.audit import add_audit_event
from service.agent import notifications as agent_notifications
from service.threat.evidence import require_incident_behavior_events


logger = get_logger(__name__)


TERMINAL_SUBAGENT_STATUSES = {
    AgentSubordinateStatus.COMPLETED,
    AgentSubordinateStatus.FAILED,
    AgentSubordinateStatus.CANCELED,
}

# Statuses whose result the parent must integrate (wakes the parent driver).
# CANCELED is resolved silently so an aborted child never wakes the parent.
_PARENT_WAKING_STATUSES = {
    AgentSubordinateStatus.COMPLETED,
    AgentSubordinateStatus.FAILED,
}


async def create_subagent_task(
    *,
    session_id: str,
    parent_agent_code: str,
    parent_agent_instance_id: str,
    agent_code: str,
    agent_name: str,
    brief: str,
    investigation_task_id: int | None,
    nested_call_id: str,
    owner_id: int,
    sandbox_container_id: int | None = None,
    sandbox_container_generation: int = 0,
    sandbox_skill_metadata: tuple[str, ...] = (),
) -> AgentSubordinateTaskSnapshot:
    now = datetime.now()
    run_id = str(uuid4())
    task = AgentSubordinateTask(
        run_id=run_id,
        session_id=session_id,
        parent_agent_code=parent_agent_code,
        parent_agent_instance_id=parent_agent_instance_id,
        agent_code=agent_code,
        agent_name=agent_name,
        status=AgentSubordinateStatus.RUNNING,
        brief=brief,
        investigation_task_id=investigation_task_id,
        nested_call_id=nested_call_id,
        owner_id=owner_id,
        created_at=now,
        updated_at=now,
        started_at=now,
    )
    async with get_async_session() as session:
        parent_session = (await session.exec(
            select(AgentSessionMeta)
            .where(AgentSessionMeta.session_id == session_id)
            .with_for_update()
        )).one_or_none()
        if parent_session is None or parent_session.owner_id != owner_id:
            raise ValueError("subagent parent session is unavailable")
        if investigation_task_id is not None:
            if parent_session.incident_id is None:
                raise ValueError("investigation delegation requires a threat incident session")
            investigation_task = (await session.exec(
                select(InvestigationTask)
                .where(InvestigationTask.id == investigation_task_id)
                .with_for_update()
            )).one_or_none()
            if investigation_task is None:
                raise ValueError("investigation task not found")
            if investigation_task.incident_id != parent_session.incident_id:
                raise ValueError("investigation task does not belong to the parent threat incident")
            if investigation_task.assignee_agent_code != agent_code:
                raise ValueError("investigation task assignee does not match the selected subagent")
            if investigation_task.status != InvestigationTaskStatus.ACTIVE:
                raise ValueError("investigation task must be active before delegation")
            behavior_event_ids = list((await session.exec(
                select(InvestigationTaskEvent.event_id).where(
                    InvestigationTaskEvent.task_id == investigation_task_id,
                )
            )).all())
            if not behavior_event_ids:
                raise ValueError("investigation task has no behavior event scope")
            await require_incident_behavior_events(
                session,
                investigation_task.incident_id,
                behavior_event_ids,
            )
            active_run = (await session.exec(
                select(AgentSubordinateTask.run_id).where(
                    AgentSubordinateTask.investigation_task_id == investigation_task_id,
                    AgentSubordinateTask.status == AgentSubordinateStatus.RUNNING.value,
                ).limit(1)
            )).first()
            if active_run is not None:
                raise ValueError("investigation task already has a running subagent")
        else:
            if parent_session.environment_id is None:
                raise ValueError("delegation without an investigation task requires an environment session")
            if agent_code != "cde":
                raise ValueError("environment sessions may delegate only to cde")
            active_run = (await session.exec(
                select(AgentSubordinateTask.run_id).where(
                    AgentSubordinateTask.session_id == session_id,
                    AgentSubordinateTask.agent_code == agent_code,
                    AgentSubordinateTask.status == AgentSubordinateStatus.RUNNING.value,
                ).limit(1)
            )).first()
            if active_run is not None:
                raise ValueError("environment session already has a running cde subagent")
        session.add(task)
        # Register the parent wake-up obligation in the same transaction so the
        # parent driver can never see the child as neither running nor pending.
        if parent_agent_code:
            agent_notifications.add_obligation_in_session(
                session,
                meta=parent_session,
                kind=AgentNotificationKind.SUBAGENT_FINISHED,
                target_agent_code=parent_agent_code,
                target_agent_instance_id=parent_agent_instance_id,
                run_id=run_id,
                payload={
                    "run_id": run_id,
                    "agent_code": agent_code,
                    "agent_name": agent_name,
                    "investigation_task_id": investigation_task_id,
                },
                sandbox_container_id=sandbox_container_id,
                sandbox_container_generation=sandbox_container_generation,
                sandbox_skill_metadata=sandbox_skill_metadata,
            )
        await _add_subagent_audit_log(
            session,
            task,
            (
                "Investigation task delegated to a specialist Agent."
                if investigation_task_id is not None
                else "Deception environment planning delegated to Ph4ntom."
            ),
            event="subagent_started",
        )
        await session.commit()
        await session.refresh(task)
        result = snapshot_from_task(task)
    logger.debug("subagent task created: %s", result.run_id)
    return result


async def get_subagent_task(
    *,
    run_id: str,
    session_id: str,
    user_id: int,
    user_role: SystemUserRole,
) -> AgentSubordinateTaskSnapshot | None:
    async with get_async_session() as session:
        task = await session.get(AgentSubordinateTask, run_id)
        if task is None or not _can_access_task(task, session_id, user_id, user_role):
            return None
        return snapshot_from_task(task)


async def list_subagent_tasks(
    *,
    session_id: str,
    user_id: int,
    user_role: SystemUserRole,
    limit: int = 20,
) -> list[AgentSubordinateTaskSnapshot]:
    async with get_async_session() as session:
        statement = (
            select(AgentSubordinateTask)
            .where(AgentSubordinateTask.session_id == session_id)
            .order_by(AgentSubordinateTask.created_at.desc())
            .limit(max(1, min(limit, 100)))
        )
        rows = (await session.exec(statement)).all()
        return [snapshot_from_task(task) for task in rows if _can_access_task(task, session_id, user_id, user_role)]


async def get_subagent_task_internal(run_id: str) -> AgentSubordinateTaskSnapshot | None:
    async with get_async_session() as session:
        task = await session.get(AgentSubordinateTask, run_id)
        return snapshot_from_task(task) if task is not None else None


async def update_subagent_progress(run_id: str, progress: str) -> AgentSubordinateTaskSnapshot | None:
    async with get_async_session() as session:
        updated = await session.exec(
            update(AgentSubordinateTask)
            .where(
                AgentSubordinateTask.run_id == run_id,
                AgentSubordinateTask.status == AgentSubordinateStatus.RUNNING.value,
            )
            .values(progress=progress, updated_at=datetime.now())
        )
        if updated.rowcount != 1:
            await session.rollback()
            return None
        await session.commit()
        current = await session.get(AgentSubordinateTask, run_id)
        return snapshot_from_task(current) if current is not None else None


async def complete_subagent_task(run_id: str, result: str) -> AgentSubordinateTaskSnapshot | None:
    return await _finish_subagent_task(run_id, AgentSubordinateStatus.COMPLETED, result=result)


async def fail_subagent_task(run_id: str, error: str) -> AgentSubordinateTaskSnapshot | None:
    return await _finish_subagent_task(run_id, AgentSubordinateStatus.FAILED, error=error)


async def cancel_subagent_task_record(run_id: str, error: str = "") -> AgentSubordinateTaskSnapshot | None:
    return await _finish_subagent_task(run_id, AgentSubordinateStatus.CANCELED, error=error)


async def cancel_running_subagent_tasks_for_session(
    session_id: str,
    error: str = "",
) -> list[AgentSubordinateTaskSnapshot]:
    return await _cancel_running_subagent_tasks(error=error, session_id=session_id)


async def cancel_running_child_subagent_tasks(
    *,
    session_id: str,
    parent_agent_instance_id: str,
    error: str = "",
) -> list[AgentSubordinateTaskSnapshot]:
    return await _cancel_running_subagent_tasks(
        error=error,
        session_id=session_id,
        parent_agent_instance_id=parent_agent_instance_id,
    )


async def cancel_running_subagent_tasks(error: str = "") -> list[AgentSubordinateTaskSnapshot]:
    return await _cancel_running_subagent_tasks(error=error)


async def _cancel_running_subagent_tasks(
    *,
    error: str = "",
    session_id: str | None = None,
    parent_agent_instance_id: str | None = None,
) -> list[AgentSubordinateTaskSnapshot]:
    now = datetime.now()
    async with get_async_session() as session:
        statement = select(AgentSubordinateTask).where(
            AgentSubordinateTask.status == AgentSubordinateStatus.RUNNING.value,
        )
        if session_id is not None:
            statement = statement.where(AgentSubordinateTask.session_id == session_id)
        if parent_agent_instance_id is not None:
            statement = statement.where(AgentSubordinateTask.parent_agent_instance_id == parent_agent_instance_id)
        rows = (await session.exec(statement.with_for_update())).all()
        for task in rows:
            task.status = AgentSubordinateStatus.CANCELED
            task.error = error
            task.progress = ""
            task.updated_at = now
            task.finished_at = now
            session.add(task)
            await agent_notifications.resolve_obligation_in_session(
                session,
                kind=AgentNotificationKind.SUBAGENT_FINISHED,
                run_id=task.run_id,
                ready=False,
                error=error,
            )
            await _add_subagent_audit_log(
                session,
                task,
                "Specialist Agent execution was canceled.",
                event="subagent_canceled",
                error=error,
            )
        if not rows:
            return []
        await session.commit()
        for task in rows:
            await session.refresh(task)
        return [snapshot_from_task(task) for task in rows]


async def mark_stale_running_subagent_tasks_failed() -> list[AgentSubordinateTaskSnapshot]:
    now = datetime.now()
    async with get_async_session() as session:
        rows = (await session.exec(
            select(AgentSubordinateTask)
            .where(AgentSubordinateTask.status == AgentSubordinateStatus.RUNNING.value)
            .with_for_update()
        )).all()
        restart_error = "Subagent task was interrupted by backend restart."
        for task in rows:
            task.status = AgentSubordinateStatus.FAILED
            task.error = restart_error
            task.updated_at = now
            task.finished_at = now
            session.add(task)
            # Surface the restart failure to the recovered parent so it can
            # finish its turn instead of waiting forever on a dead child.
            await agent_notifications.resolve_obligation_in_session(
                session,
                kind=AgentNotificationKind.SUBAGENT_FINISHED,
                run_id=task.run_id,
                ready=True,
                payload=_subagent_obligation_payload(task),
                error=restart_error,
            )
            await _add_subagent_audit_log(
                session,
                task,
                "Specialist Agent execution was interrupted by backend restart.",
                event="subagent_failed",
                error=restart_error,
            )
        if rows:
            await session.commit()
            for task in rows:
                await session.refresh(task)
        snapshots = [snapshot_from_task(task) for task in rows]
    if rows:
        logger.info("stale subagent tasks marked failed: %d", len(rows))
    return snapshots


async def _finish_subagent_task(
    run_id: str,
    status: AgentSubordinateStatus,
    *,
    result: str = "",
    error: str = "",
) -> AgentSubordinateTaskSnapshot | None:
    now = datetime.now()
    async with get_async_session() as session:
        task = await session.get(AgentSubordinateTask, run_id)
        if task is None:
            return None
        if _coerce_subagent_status(task.status) in TERMINAL_SUBAGENT_STATUSES:
            return snapshot_from_task(task)
        updated = await session.exec(
            update(AgentSubordinateTask)
            .where(
                AgentSubordinateTask.run_id == run_id,
                AgentSubordinateTask.status == AgentSubordinateStatus.RUNNING.value,
            )
            .values(
                status=status,
                result=result,
                error=error,
                progress="",
                updated_at=now,
                finished_at=now,
            )
        )
        if updated.rowcount != 1:
            await session.rollback()
            current = await session.get(AgentSubordinateTask, run_id)
            return snapshot_from_task(current) if current is not None else None
        # Flip the parent obligation in the same transaction: task-terminal and
        # parent-wakeup commit atomically, so there is no check-then-act window.
        await session.refresh(task)
        refreshed = task
        await agent_notifications.resolve_obligation_in_session(
            session,
            kind=AgentNotificationKind.SUBAGENT_FINISHED,
            run_id=run_id,
            ready=status in _PARENT_WAKING_STATUSES,
            payload=_subagent_obligation_payload(refreshed) if refreshed is not None else None,
            error=error,
        )
        if refreshed is not None:
            await _add_subagent_audit_log(
                session,
                refreshed,
                (
                    "Specialist Agent execution completed."
                    if status == AgentSubordinateStatus.COMPLETED
                    else "Specialist Agent execution failed."
                ),
                event=(
                    "subagent_completed"
                    if status == AgentSubordinateStatus.COMPLETED
                    else "subagent_failed"
                ),
                error=error,
            )
        await session.commit()
        current = await session.get(AgentSubordinateTask, run_id)
        return snapshot_from_task(current) if current is not None else None


def _subagent_obligation_payload(task: AgentSubordinateTask) -> dict[str, object]:
    # Metadata only: the body lives in the DB and is paged through read_subagent_task,
    # so the notification stays small and the parent agent has a single source of truth.
    return {
        "run_id": task.run_id,
        "agent_code": task.agent_code,
        "agent_name": task.agent_name,
        "status": _coerce_subagent_status(task.status).value,
        "investigation_task_id": task.investigation_task_id,
    }


async def _add_subagent_audit_log(
    session,
    task: AgentSubordinateTask,
    content: str,
    *,
    event: str,
    error: str = "",
) -> None:
    incident_id = None
    environment_id = None
    if task.investigation_task_id is not None:
        investigation_task = await session.get(InvestigationTask, task.investigation_task_id)
        if investigation_task is None:
            return
        incident_id = investigation_task.incident_id
    else:
        parent_session = await session.get(AgentSessionMeta, task.session_id)
        if parent_session is None or parent_session.environment_id is None:
            return
        environment_id = parent_session.environment_id
    await add_audit_event(
        session,
        incident_id=incident_id,
        environment_id=environment_id,
        task_id=task.investigation_task_id,
        kind=AuditEventKind.DELEGATION,
        actor_type=AuditActorType.AGENT,
        actor_code=task.agent_code,
        session_id=task.session_id,
        object_type="subagent_run",
        object_id=task.run_id,
        summary=content,
        details={
            "event": event,
            "run_id": task.run_id,
            "parent_agent_code": task.parent_agent_code,
            "parent_agent_instance_id": task.parent_agent_instance_id,
            "agent_code": task.agent_code,
            "status": _coerce_subagent_status(task.status).value,
            "error": error,
        },
    )


def snapshot_from_task(task: AgentSubordinateTask) -> AgentSubordinateTaskSnapshot:
    return AgentSubordinateTaskSnapshot(
        run_id=task.run_id,
        session_id=task.session_id,
        parent_agent_code=task.parent_agent_code,
        parent_agent_instance_id=task.parent_agent_instance_id,
        agent_code=task.agent_code,
        agent_name=task.agent_name,
        status=_coerce_subagent_status(task.status),
        brief=task.brief,
        result=task.result,
        error=task.error,
        progress=task.progress,
        investigation_task_id=task.investigation_task_id,
        nested_call_id=task.nested_call_id,
        created_at=task.created_at,
        updated_at=task.updated_at,
        started_at=task.started_at,
        finished_at=task.finished_at,
    )


def _coerce_subagent_status(status: AgentSubordinateStatus | str) -> AgentSubordinateStatus:
    if isinstance(status, AgentSubordinateStatus):
        return status
    return AgentSubordinateStatus(status.lower())


def _can_access_task(
    task: AgentSubordinateTask,
    session_id: str,
    user_id: int,
    user_role: SystemUserRole,
) -> bool:
    if task.session_id != session_id:
        return False
    return user_role == SystemUserRole.ADMIN or task.owner_id == user_id
