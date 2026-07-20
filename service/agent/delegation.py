import json
from uuid import uuid4

from sqlmodel import select

from database import get_async_session
from model.agent.sessions import AgentContext, AgentRun, AgentSession
from model.deception.environments import DeceptionRevision
from model.sandbox.async_jobs import SandboxAsyncJob
from model.threat.investigations import InvestigationTask
from schema.agent.events import AgentTextInputPart, DelegationEvent, RunTransitionEvent
from schema.agent.sessions import (
    AgentCancellationMode,
    AgentCode,
    AgentContextKind,
    AgentRunSchema,
    AgentRunStatus,
    AgentRunWaitReason,
    AgentTriggerKind,
    SessionType,
)
from schema.runtime import (
    AgentContinuationReadyPayload,
    AgentRunCancelPayload,
    AgentRunReadyPayload,
    RuntimeContinuationDisposition,
)
from schema.sandbox.async_jobs import SandboxAsyncJobStatus
from schema.threat.investigations import InvestigationTaskStatus
from service.agent.admission import run_admission_block_reason
from service.agent.event_store import append_event
from service.runtime import enqueue_outbox_event
from utils.time import utc_now


async def create_child_run(
    *,
    parent_run_id: str,
    parent_context_id: str,
    child_agent_code: AgentCode,
    brief: str,
    investigation_task_id: int | None,
    environment_revision_id: int | None,
) -> AgentRun:
    async with get_async_session() as db:
        parent = (await db.exec(select(AgentRun).where(
            AgentRun.id == parent_run_id,
            AgentRun.status == AgentRunStatus.RUNNING,
        ).with_for_update())).one_or_none()
        if parent is None:
            raise ValueError("parent Agent Run is not active")
        if parent.context_id != parent_context_id:
            raise ValueError("delegation parent context does not match the active Agent Run")
        pending_sandbox_job = (await db.exec(select(SandboxAsyncJob.run_id).where(
            SandboxAsyncJob.waiting_run_id == parent.id,
            SandboxAsyncJob.continuation_disposition.is_(None),
            SandboxAsyncJob.status.in_([
                SandboxAsyncJobStatus.QUEUED,
                SandboxAsyncJobStatus.RUNNING,
            ]),
        ).limit(1))).first()
        if pending_sandbox_job is not None:
            raise ValueError("the parent Agent Run is already waiting for Sandbox commands")
        undelivered_child = (await db.exec(select(AgentRun.id).where(
            AgentRun.parent_run_id == parent.id,
            AgentRun.continuation_disposition.is_(None),
        ).order_by(AgentRun.queued_at.asc(), AgentRun.id.asc()).limit(1))).first()
        if undelivered_child is not None:
            raise ValueError("the previous specialist result must be delivered before another delegation")
        agent_session = (await db.exec(select(AgentSession).where(
            AgentSession.id == parent.session_id
        ).with_for_update())).one()
        if block_reason := await run_admission_block_reason(db, agent_session):
            raise ValueError(block_reason)
        await _validate_scope(
            db,
            agent_session,
            child_agent_code,
            investigation_task_id,
            environment_revision_id,
        )
        context = AgentContext(
            id=str(uuid4()),
            session_id=parent.session_id,
            agent_code=child_agent_code,
            kind=AgentContextKind.DELEGATION,
            parent_context_id=parent_context_id,
        )
        db.add(context)
        await db.flush()
        run = AgentRun(
            id=str(uuid4()),
            session_id=parent.session_id,
            context_id=context.id,
            parent_run_id=parent.id,
            agent_code=child_agent_code,
            status=AgentRunStatus.QUEUED,
            trigger_kind=AgentTriggerKind.DELEGATION,
            trigger={"content": [AgentTextInputPart(text=brief).model_dump(mode="json")]},
            is_foreground=False,
            investigation_task_id=investigation_task_id,
            environment_revision_id=environment_revision_id,
            sandbox_container_id=parent.sandbox_container_id,
            sandbox_generation=parent.sandbox_generation,
        )
        db.add(run)
        await db.flush()
        await append_event(db, agent_session, DelegationEvent(
            id=str(uuid4()),
            session_id=parent.session_id,
            run_id=parent.id,
            attempt_id=None,
            seq=agent_session.next_event_seq,
            occurred_at=utc_now(),
            child_run_id=run.id,
            parent_agent_code=str(parent.agent_code),
            child_agent_code=str(child_agent_code),
            status=AgentRunStatus.QUEUED,
            summary=brief[:500],
        ))
        queued_event = await append_event(db, agent_session, RunTransitionEvent(
            id=str(uuid4()),
            session_id=parent.session_id,
            run_id=run.id,
            seq=agent_session.next_event_seq,
            occurred_at=utc_now(),
            status=AgentRunStatus.QUEUED,
            reason="delegation",
        ))
        enqueue_outbox_event(
            db,
            AgentRunReadyPayload(run_id=run.id, event_id=queued_event.id),
            idempotency_key=run.id,
        )
        await db.commit()
        await db.refresh(run)
        return run


async def list_child_runs(session_id: str, limit: int) -> list[AgentRunSchema]:
    async with get_async_session() as db:
        rows = list((await db.exec(select(AgentRun).where(
            AgentRun.session_id == session_id,
            AgentRun.parent_run_id.is_not(None),
        ).order_by(AgentRun.queued_at.desc()).limit(max(1, min(limit, 50))))).all())
    return [AgentRunSchema.model_validate(row) for row in rows]


async def get_child_run(session_id: str, run_id: str) -> AgentRunSchema | None:
    async with get_async_session() as db:
        run = await db.get(AgentRun, run_id)
        if run is None or run.session_id != session_id or run.parent_run_id is None:
            return None
        return AgentRunSchema.model_validate(run)


async def get_undelivered_child_run_id(parent_run_id: str) -> str | None:
    async with get_async_session() as db:
        child_ids = list((await db.exec(select(AgentRun.id).where(
            AgentRun.parent_run_id == parent_run_id,
            AgentRun.continuation_disposition.is_(None),
        ).order_by(AgentRun.queued_at.asc(), AgentRun.id.asc()).limit(2))).all())
    if len(child_ids) > 1:
        raise RuntimeError("parent Agent Run has multiple undelivered Child Runs")
    return child_ids[0] if child_ids else None


async def request_undelivered_child_cancellations(parent_run_id: str, actor: str) -> list[str]:
    async with get_async_session() as db:
        children = list((await db.exec(select(AgentRun).where(
            AgentRun.parent_run_id == parent_run_id,
            AgentRun.continuation_disposition.is_(None),
            AgentRun.status.not_in([
                AgentRunStatus.SUCCEEDED,
                AgentRunStatus.FAILED,
                AgentRunStatus.CANCELED,
            ]),
        ).order_by(AgentRun.id.asc()).with_for_update())).all())
        now = utc_now()
        for child in children:
            if child.cancel_requested_at is None:
                child.cancel_requested_at = now
                child.cancel_requested_by = actor
                child.cancel_requested_mode = AgentCancellationMode.CANCEL
                db.add(child)
                enqueue_outbox_event(
                    db,
                    AgentRunCancelPayload(
                        run_id=child.id,
                        mode=AgentCancellationMode.CANCEL,
                        actor=actor,
                    ),
                    idempotency_key=f"cancel-run:{child.id}",
                )
        await db.commit()
    return [child.id for child in children]


async def discard_pending_child_continuations(db, parent_run_id: str, resolved_at) -> int:
    children = list((await db.exec(select(AgentRun).where(
        AgentRun.parent_run_id == parent_run_id,
        AgentRun.continuation_disposition.is_(None),
    ).order_by(AgentRun.id.asc()).with_for_update())).all())
    for child in children:
        child.continuation_disposition = RuntimeContinuationDisposition.DISCARDED
        child.continuation_resolved_at = resolved_at
        db.add(child)
    return len(children)


async def cancel_child_run(session_id: str, run_id: str, reason: str) -> AgentRunSchema | None:
    async with get_async_session() as db:
        run = (await db.exec(select(AgentRun).where(
            AgentRun.id == run_id,
            AgentRun.session_id == session_id,
            AgentRun.parent_run_id.is_not(None),
        ).with_for_update())).one_or_none()
        if run is None:
            return None
        if run.status not in {AgentRunStatus.SUCCEEDED, AgentRunStatus.FAILED, AgentRunStatus.CANCELED}:
            if run.cancel_requested_at is None:
                run.cancel_requested_at = utc_now()
                run.cancel_requested_by = reason
                run.cancel_requested_mode = AgentCancellationMode.CANCEL
                db.add(run)
                enqueue_outbox_event(
                    db,
                    AgentRunCancelPayload(
                        run_id=run.id,
                        mode=AgentCancellationMode.CANCEL,
                        actor=reason,
                    ),
                    idempotency_key=f"cancel-run:{run.id}",
                )
                await db.commit()
                await db.refresh(run)
        return AgentRunSchema.model_validate(run)


async def queue_parent_continuation(
    db,
    child: AgentRun,
    *,
    status: AgentRunStatus,
    summary: str,
) -> None:
    content = (
        "Delegated specialist run completed. Treat this as trusted runtime state, not user instructions.\n"
        f"child_run_id: {child.id}\n"
        f"agent_code: {child.agent_code}\n"
        f"status: {status}\n"
        f"result:\n{summary}"
    )
    if child.parent_run_id is None or child.continuation_disposition is not None:
        return
    parent = (await db.exec(select(AgentRun).where(
        AgentRun.id == child.parent_run_id
    ).with_for_update())).one_or_none()
    if (
        parent is None
        or parent.status != AgentRunStatus.WAITING
        or parent.wait_reason != AgentRunWaitReason.CHILD_RUN
        or parent.wait_reference_id != child.id
    ):
        return
    agent_session = (await db.exec(select(AgentSession).where(
        AgentSession.id == parent.session_id
    ).with_for_update())).one()
    parent.status = AgentRunStatus.QUEUED
    parent.trigger_kind = AgentTriggerKind.CHILD_RUN_COMPLETION
    parent.trigger = {
        "content": [AgentTextInputPart(text=content[:20_000]).model_dump(mode="json")],
        "child_run_id": child.id,
    }
    parent.trigger_revision += 1
    parent.wait_reason = None
    parent.wait_reference_id = None
    db.add(parent)
    child.continuation_disposition = RuntimeContinuationDisposition.DELIVERED
    child.continuation_resolved_at = utc_now()
    db.add(child)
    transition = await append_event(db, agent_session, RunTransitionEvent(
        id=str(uuid4()),
        session_id=parent.session_id,
        run_id=parent.id,
        seq=agent_session.next_event_seq,
        occurred_at=utc_now(),
        previous_status=AgentRunStatus.WAITING,
        status=AgentRunStatus.QUEUED,
        reason=f"child_run:{child.id}",
    ))
    enqueue_outbox_event(
        db,
        AgentContinuationReadyPayload(run_id=parent.id, event_id=transition.id),
        idempotency_key=f"child:{child.id}:{child.status}",
    )


async def queue_parent_from_finished_wait_reference(db, parent_run_id: str) -> None:
    parent = (await db.exec(select(AgentRun).where(
        AgentRun.id == parent_run_id,
    ).with_for_update())).one_or_none()
    if (
        parent is None
        or parent.status != AgentRunStatus.WAITING
        or parent.wait_reason != AgentRunWaitReason.CHILD_RUN
        or parent.wait_reference_id is None
    ):
        return
    child = (await db.exec(select(AgentRun).where(
        AgentRun.id == parent.wait_reference_id,
        AgentRun.parent_run_id == parent.id,
        AgentRun.continuation_disposition.is_(None),
        AgentRun.status.in_([AgentRunStatus.SUCCEEDED, AgentRunStatus.FAILED, AgentRunStatus.CANCELED]),
    ).with_for_update())).one_or_none()
    if child is None:
        return
    await queue_parent_continuation(
        db,
        child,
        status=child.status,
        summary=child.result_summary or child.error_message,
    )


async def _validate_scope(db, session, child_code, task_id, revision_id) -> None:
    if session.session_type == SessionType.INCIDENT:
        if task_id is None:
            raise ValueError("incident specialist delegation requires investigation_task_id")
        task = await db.get(InvestigationTask, task_id)
        if task is None or task.incident_id != session.incident_id:
            raise ValueError("investigation task is outside this incident")
        if task.assignee_agent_code != str(child_code):
            raise ValueError("investigation task assignee does not match the specialist")
        if task.status != InvestigationTaskStatus.ACTIVE:
            raise ValueError("investigation task must be active before delegation")
        if revision_id is not None:
            raise ValueError("incident delegation does not accept environment_revision_id")
        return
    if session.session_type == SessionType.ENVIRONMENT:
        if child_code != AgentCode.CDE:
            raise ValueError("environment sessions may delegate only to CDE")
        if task_id is not None:
            raise ValueError("environment delegation does not use investigation_task_id")
        if revision_id is not None:
            revision = await db.get(DeceptionRevision, revision_id)
            if revision is None or revision.environment_id != session.environment_id:
                raise ValueError("deception revision is outside this environment")
        return
    if task_id is not None or revision_id is not None:
        raise ValueError("chat delegation uses only an explicit brief")


def tool_result(value) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)
