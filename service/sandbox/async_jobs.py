import hashlib
import json
from uuid import uuid4

from sqlalchemy import or_
from sqlmodel import select

from config import get_config
from database import get_async_session
from logger import get_logger
from model.agent.sessions import AgentRun, AgentRunAttempt, AgentSession
from model.sandbox.async_jobs import SandboxAsyncJob
from model.sandbox.containers import SandboxContainer
from schema.agent.events import (
    AgentDurableEvent,
    AgentTextInputPart,
    RunTransitionEvent,
    SandboxRecoveryEvent,
)
from schema.agent.sessions import AgentAttemptStatus, AgentRunStatus, AgentSessionStatus, AgentTriggerKind
from schema.agent.types import AgentRunWaitReason
from schema.runtime import AgentContinuationReadyPayload, RuntimeContinuationDisposition
from schema.sandbox.async_jobs import (
    ResolveSandboxAsyncJobRequest,
    SandboxAsyncJobSnapshot,
    SandboxAsyncJobStatus,
)
from schema.sandbox.containers import SandboxContainerStatus
from schema.system_user.users import SystemUserRole
from service.runtime import enqueue_outbox_event
from service.runtime.leases import RuntimeLeaseHandle
from service.agent.event_store import append_event
from utils.time import utc_now


logger = get_logger(__name__)

TERMINAL_ASYNC_JOB_STATUSES = {
    SandboxAsyncJobStatus.COMPLETED,
    SandboxAsyncJobStatus.FAILED,
    SandboxAsyncJobStatus.CANCELED,
    SandboxAsyncJobStatus.RECOVERY_REQUIRED,
}
DELIVERABLE_ASYNC_JOB_STATUSES = {
    SandboxAsyncJobStatus.COMPLETED,
    SandboxAsyncJobStatus.FAILED,
    SandboxAsyncJobStatus.CANCELED,
}
_TERMINAL_AGENT_RUN_STATUSES = {
    AgentRunStatus.SUCCEEDED,
    AgentRunStatus.FAILED,
    AgentRunStatus.CANCELED,
}


class SandboxJobResolutionConflict(RuntimeError):
    pass


async def create_async_job(
    *,
    run_id: str,
    waiting_run_id: str,
    session_id: str,
    attempt_id: str,
    investigation_task_id: int | None,
    command: str,
    output_file: str,
    timeout_seconds: int,
    execution_marker: str,
    sandbox_container_id: int,
    sandbox_container_generation: int,
) -> SandboxAsyncJobSnapshot:
    async with get_async_session() as db:
        owner_run = (await db.exec(select(AgentRun).where(
            AgentRun.id == waiting_run_id,
            AgentRun.session_id == session_id,
            AgentRun.status == AgentRunStatus.RUNNING,
        ).with_for_update())).one_or_none()
        if owner_run is None:
            raise ValueError("owning Agent Run is unavailable")
        attempt = (await db.exec(select(AgentRunAttempt).where(
            AgentRunAttempt.id == attempt_id,
            AgentRunAttempt.run_id == waiting_run_id,
            AgentRunAttempt.status == AgentAttemptStatus.RUNNING,
        ))).one_or_none()
        if attempt is None:
            raise ValueError("owning Agent Run Attempt is unavailable")
        if (
            owner_run.sandbox_container_id != sandbox_container_id
            or owner_run.sandbox_generation != sandbox_container_generation
        ):
            raise ValueError("Sandbox command binding does not match the owning Agent Run")
        container = await db.get(SandboxContainer, sandbox_container_id)
        if (
            container is None
            or container.status != SandboxContainerStatus.RUNNING
            or container.generation != sandbox_container_generation
        ):
            raise ValueError("Sandbox container generation is no longer available")
        undelivered_child = (await db.exec(select(AgentRun.id).where(
            AgentRun.parent_run_id == owner_run.id,
            AgentRun.continuation_disposition.is_(None),
        ).limit(1))).first()
        if undelivered_child is not None:
            raise ValueError("the owning Agent Run is already waiting for a Child Run")
        batch_jobs = list((await db.exec(select(SandboxAsyncJob).where(
            SandboxAsyncJob.waiting_run_id == owner_run.id,
            SandboxAsyncJob.continuation_disposition.is_(None),
        ).order_by(SandboxAsyncJob.created_at.asc(), SandboxAsyncJob.run_id.asc()).with_for_update())).all())
        if any(job.attempt_id != attempt_id for job in batch_jobs):
            raise ValueError("a previous Sandbox command batch is still awaiting delivery")
        batch_limit = get_config().agent_runtime.max_sandbox_commands_per_batch
        if len(batch_jobs) >= batch_limit:
            raise ValueError(
                f"Sandbox command batch limit reached; at most {batch_limit} commands may be queued"
            )
        job = SandboxAsyncJob(
            run_id=run_id,
            waiting_run_id=waiting_run_id,
            session_id=session_id,
            attempt_id=attempt_id,
            investigation_task_id=investigation_task_id,
            command=command,
            output_file=output_file,
            timeout_seconds=timeout_seconds,
            execution_marker=execution_marker,
            sandbox_container_id=sandbox_container_id,
            sandbox_container_generation=sandbox_container_generation,
        )
        db.add(job)
        await db.commit()
        await db.refresh(job)
        return SandboxAsyncJobSnapshot.model_validate(job)


async def get_async_job(run_id: str, *, session_id: str) -> SandboxAsyncJobSnapshot | None:
    async with get_async_session() as db:
        job = await db.get(SandboxAsyncJob, run_id)
        if job is None or job.session_id != session_id:
            return None
        return SandboxAsyncJobSnapshot.model_validate(job)


async def list_recovery_required_jobs(
    *,
    session_id: str,
    user_id: int,
    user_role: SystemUserRole,
) -> list[SandboxAsyncJobSnapshot] | None:
    async with get_async_session() as db:
        agent_session = await db.get(AgentSession, session_id)
        if not _can_access_active_session(agent_session, user_id, user_role):
            return None
        jobs = list((await db.exec(select(SandboxAsyncJob).where(
            SandboxAsyncJob.session_id == session_id,
            SandboxAsyncJob.status == SandboxAsyncJobStatus.RECOVERY_REQUIRED,
        ).order_by(
            SandboxAsyncJob.created_at.asc(),
            SandboxAsyncJob.run_id.asc(),
        ))).all())
        return [SandboxAsyncJobSnapshot.model_validate(job) for job in jobs]


async def resolve_recovery_required_job(
    *,
    session_id: str,
    run_id: str,
    resolution: ResolveSandboxAsyncJobRequest,
    user_id: int,
    user_role: SystemUserRole,
) -> tuple[SandboxAsyncJobSnapshot, list[AgentDurableEvent]] | None:
    async with get_async_session() as db:
        agent_session = (await db.exec(select(AgentSession).where(
            AgentSession.id == session_id,
        ).with_for_update())).one_or_none()
        if not _can_access_active_session(agent_session, user_id, user_role):
            return None
        unsafe_run = (await db.exec(select(AgentRun.id).where(
            AgentRun.session_id == session_id,
            or_(
                AgentRun.status == AgentRunStatus.RUNNING,
                (
                    (AgentRun.status == AgentRunStatus.QUEUED)
                    & (AgentRun.trigger_kind != AgentTriggerKind.TOOL_RECOVERY)
                ),
            ),
        ).limit(1))).first()
        if unsafe_run is not None:
            raise SandboxJobResolutionConflict(
                "cancel running and user-queued Agent Runs before resolving a Sandbox command"
            )
        job = (await db.exec(select(SandboxAsyncJob).where(
            SandboxAsyncJob.run_id == run_id,
            SandboxAsyncJob.session_id == session_id,
        ).with_for_update())).one_or_none()
        if job is None:
            return None
        if job.status != SandboxAsyncJobStatus.RECOVERY_REQUIRED:
            raise SandboxJobResolutionConflict(
                "the Sandbox command no longer requires recovery"
            )

        now = utc_now()
        job.status = SandboxAsyncJobStatus.FAILED
        job.recovery_resolved_at = now
        job.recovery_resolved_by = f"user:{user_id}"
        job.recovery_resolution_note = resolution.note
        job.error = (
            f"{job.error} Operator confirmed command termination: {resolution.note}"
        ).strip()
        job.updated_at = now
        db.add(job)
        events = [await append_event(db, agent_session, SandboxRecoveryEvent(
            id=str(uuid4()),
            session_id=session_id,
            run_id=job.waiting_run_id,
            attempt_id=job.attempt_id,
            seq=agent_session.next_event_seq,
            occurred_at=now,
            sandbox_job_id=job.run_id,
            status=job.status,
            resolved_by=job.recovery_resolved_by,
            resolution_note=job.recovery_resolution_note,
        ))]
        owner = (await db.exec(select(AgentRun).where(
            AgentRun.id == job.waiting_run_id,
            AgentRun.session_id == session_id,
        ).with_for_update())).one_or_none()
        if (
            owner is not None
            and owner.status == AgentRunStatus.WAITING
            and owner.wait_reason == AgentRunWaitReason.SANDBOX_COMMAND
        ):
            batch = list((await db.exec(select(SandboxAsyncJob).where(
                SandboxAsyncJob.waiting_run_id == owner.id,
                SandboxAsyncJob.attempt_id == owner.wait_reference_id,
                SandboxAsyncJob.continuation_disposition.is_(None),
            ).order_by(
                SandboxAsyncJob.created_at.asc(),
                SandboxAsyncJob.run_id.asc(),
            ).with_for_update())).all())
            if batch and all(item.status in DELIVERABLE_ASYNC_JOB_STATUSES for item in batch):
                transition = await _queue_job_continuation(db, batch, owner, agent_session)
                if transition is not None:
                    events.append(transition)
        await db.commit()
        await db.refresh(job)
        return SandboxAsyncJobSnapshot.model_validate(job), events


async def get_undelivered_async_job_attempt_id(waiting_run_id: str) -> str | None:
    async with get_async_session() as db:
        attempt_ids = list((await db.exec(select(SandboxAsyncJob.attempt_id).where(
            SandboxAsyncJob.waiting_run_id == waiting_run_id,
            SandboxAsyncJob.continuation_disposition.is_(None),
        ).distinct().order_by(SandboxAsyncJob.attempt_id.asc()).limit(2))).all())
    if len(attempt_ids) > 1:
        raise RuntimeError("Agent Run has multiple undelivered Sandbox command batches")
    return attempt_ids[0] if attempt_ids else None


async def claim_queued_jobs(
    lease: RuntimeLeaseHandle,
    *,
    limit: int,
) -> list[SandboxAsyncJobSnapshot]:
    async with get_async_session() as db, db.begin():
        await lease.assert_owned(db, lock=True)
        jobs = list((await db.exec(select(SandboxAsyncJob).where(
            SandboxAsyncJob.status == SandboxAsyncJobStatus.QUEUED,
            SandboxAsyncJob.cancel_requested_at.is_(None),
        ).join(
            AgentRun,
            AgentRun.id == SandboxAsyncJob.waiting_run_id,
        ).join(
            SandboxContainer,
            SandboxContainer.id == SandboxAsyncJob.sandbox_container_id,
        ).where(
            AgentRun.status == AgentRunStatus.WAITING,
            AgentRun.wait_reason == AgentRunWaitReason.SANDBOX_COMMAND,
            AgentRun.wait_reference_id == SandboxAsyncJob.attempt_id,
            SandboxAsyncJob.continuation_disposition.is_(None),
            SandboxContainer.status == SandboxContainerStatus.RUNNING,
            SandboxContainer.generation == SandboxAsyncJob.sandbox_container_generation,
        ).order_by(SandboxAsyncJob.created_at.asc(), SandboxAsyncJob.run_id.asc()).limit(limit).with_for_update(
            skip_locked=True,
            of=SandboxAsyncJob,
        ))).all())
        now = utc_now()
        for job in jobs:
            job.status = SandboxAsyncJobStatus.RUNNING
            job.runtime_owner_id = lease.owner_id
            job.lease_fencing_token = lease.fencing_token
            job.started_at = now
            job.updated_at = now
            db.add(job)
        return [SandboxAsyncJobSnapshot.model_validate(job) for job in jobs]


async def fail_unavailable_queued_jobs(lease: RuntimeLeaseHandle) -> int:
    async with get_async_session() as db, db.begin():
        await lease.assert_owned(db, lock=True)
        jobs = list((await db.exec(select(SandboxAsyncJob).join(
            SandboxContainer,
            SandboxContainer.id == SandboxAsyncJob.sandbox_container_id,
        ).where(
            SandboxAsyncJob.status == SandboxAsyncJobStatus.QUEUED,
            (
                (SandboxContainer.status != SandboxContainerStatus.RUNNING)
                | (SandboxContainer.generation != SandboxAsyncJob.sandbox_container_generation)
            ),
        ).order_by(SandboxAsyncJob.run_id.asc()).with_for_update(
            skip_locked=True,
            of=SandboxAsyncJob,
        ))).all())
        for job in jobs:
            await _finish_locked_job(
                db,
                job,
                SandboxAsyncJobStatus.FAILED,
                error="Sandbox container generation changed before command execution.",
            )
        return len(jobs)


async def list_stale_running_jobs(lease: RuntimeLeaseHandle) -> list[SandboxAsyncJobSnapshot]:
    async with get_async_session() as db:
        await lease.assert_owned(db)
        jobs = list((await db.exec(select(SandboxAsyncJob).where(
            SandboxAsyncJob.status == SandboxAsyncJobStatus.RUNNING,
            (
                (SandboxAsyncJob.runtime_owner_id != lease.owner_id)
                | (SandboxAsyncJob.lease_fencing_token != lease.fencing_token)
            ),
        ).order_by(SandboxAsyncJob.started_at.asc(), SandboxAsyncJob.run_id.asc()))).all())
        return [SandboxAsyncJobSnapshot.model_validate(job) for job in jobs]


async def is_job_container_binding_current(run_id: str) -> bool:
    async with get_async_session() as db:
        row = (await db.exec(select(
            SandboxAsyncJob.sandbox_container_generation,
            SandboxContainer.generation,
            SandboxContainer.status,
        ).join(
            SandboxContainer,
            SandboxContainer.id == SandboxAsyncJob.sandbox_container_id,
        ).where(SandboxAsyncJob.run_id == run_id))).one_or_none()
    return bool(
        row is not None
        and row[2] == SandboxContainerStatus.RUNNING
        and row[0] == row[1]
    )


async def list_owned_cancel_requests(lease: RuntimeLeaseHandle) -> list[str]:
    async with get_async_session() as db:
        await lease.assert_owned(db)
        return list((await db.exec(select(SandboxAsyncJob.run_id).where(
            SandboxAsyncJob.status == SandboxAsyncJobStatus.RUNNING,
            SandboxAsyncJob.runtime_owner_id == lease.owner_id,
            SandboxAsyncJob.lease_fencing_token == lease.fencing_token,
            SandboxAsyncJob.cancel_requested_at.is_not(None),
        ).order_by(SandboxAsyncJob.run_id.asc()))).all())


async def cancel_orphaned_queued_jobs(lease: RuntimeLeaseHandle) -> int:
    async with get_async_session() as db, db.begin():
        await lease.assert_owned(db, lock=True)
        jobs = list((await db.exec(select(SandboxAsyncJob).join(
            AgentRun,
            AgentRun.id == SandboxAsyncJob.waiting_run_id,
        ).where(
            SandboxAsyncJob.status == SandboxAsyncJobStatus.QUEUED,
            AgentRun.status.in_(_TERMINAL_AGENT_RUN_STATUSES),
        ).order_by(SandboxAsyncJob.run_id.asc()).with_for_update(
            skip_locked=True,
            of=SandboxAsyncJob,
        ))).all())
        for job in jobs:
            await _finish_locked_job(
                db,
                job,
                SandboxAsyncJobStatus.CANCELED,
                error="Owning Agent Run reached a terminal state before command execution.",
            )
        return len(jobs)


async def discard_pending_job_continuations(db, waiting_run_id: str, resolved_at) -> int:
    jobs = list((await db.exec(select(SandboxAsyncJob).where(
        SandboxAsyncJob.waiting_run_id == waiting_run_id,
        SandboxAsyncJob.continuation_disposition.is_(None),
    ).order_by(SandboxAsyncJob.run_id.asc()).with_for_update())).all())
    for job in jobs:
        job.continuation_disposition = RuntimeContinuationDisposition.DISCARDED
        job.continuation_resolved_at = resolved_at
        db.add(job)
    return len(jobs)


async def resume_waiting_runs_with_finished_jobs(lease: RuntimeLeaseHandle, *, limit: int = 100) -> int:
    async with get_async_session() as db, db.begin():
        await lease.assert_owned(db, lock=True)
        owner_ids = list((await db.exec(select(AgentRun.id).join(
            SandboxAsyncJob,
            SandboxAsyncJob.waiting_run_id == AgentRun.id,
        ).where(
            AgentRun.status == AgentRunStatus.WAITING,
            AgentRun.wait_reason == AgentRunWaitReason.SANDBOX_COMMAND,
            AgentRun.wait_reference_id == SandboxAsyncJob.attempt_id,
            SandboxAsyncJob.continuation_disposition.is_(None),
        ).distinct().order_by(AgentRun.queued_at.asc(), AgentRun.id.asc()).limit(limit))).all())
        resumed = 0
        for owner_id in owner_ids:
            owner = (await db.exec(select(AgentRun).where(
                AgentRun.id == owner_id,
                AgentRun.status == AgentRunStatus.WAITING,
                AgentRun.wait_reason == AgentRunWaitReason.SANDBOX_COMMAND,
            ).with_for_update())).one_or_none()
            if owner is None:
                continue
            jobs = list((await db.exec(select(SandboxAsyncJob).where(
                SandboxAsyncJob.waiting_run_id == owner.id,
                SandboxAsyncJob.attempt_id == owner.wait_reference_id,
                SandboxAsyncJob.continuation_disposition.is_(None),
            ).order_by(
                SandboxAsyncJob.created_at.asc(),
                SandboxAsyncJob.run_id.asc(),
            ).with_for_update())).all())
            if not jobs or any(job.status not in DELIVERABLE_ASYNC_JOB_STATUSES for job in jobs):
                continue
            agent_session = (await db.exec(select(AgentSession).where(
                AgentSession.id == owner.session_id
            ).with_for_update())).one()
            await _queue_job_continuation(db, jobs, owner, agent_session)
            resumed += 1
        return resumed


async def cancel_async_job(run_id: str, actor: str):
    snapshots = await _request_cancellation(SandboxAsyncJob.run_id == run_id, actor)
    return snapshots[0] if snapshots else None


async def cancel_running_async_jobs_for_session(session_id: str, actor: str):
    return await _request_cancellation(SandboxAsyncJob.session_id == session_id, actor)


async def cancel_running_async_jobs_for_run(waiting_run_id: str, actor: str):
    return await _request_cancellation(SandboxAsyncJob.waiting_run_id == waiting_run_id, actor)


async def cancel_running_async_jobs_for_container(container_id: int, actor: str):
    return await _request_cancellation(SandboxAsyncJob.sandbox_container_id == container_id, actor)


async def cancel_running_async_jobs(actor: str):
    return await _request_cancellation(None, actor)


async def _request_cancellation(predicate, actor: str) -> list[SandboxAsyncJobSnapshot]:
    if not actor.strip():
        raise ValueError("Sandbox command cancellation actor is required")
    async with get_async_session() as db:
        statement = select(SandboxAsyncJob).where(
            SandboxAsyncJob.status.in_([SandboxAsyncJobStatus.QUEUED, SandboxAsyncJobStatus.RUNNING])
        )
        if predicate is not None:
            statement = statement.where(predicate)
        jobs = list((await db.exec(statement.order_by(
            SandboxAsyncJob.run_id.asc()
        ).with_for_update())).all())
        now = utc_now()
        for job in jobs:
            job.cancel_requested_at = job.cancel_requested_at or now
            job.cancel_requested_by = job.cancel_requested_by or actor
            if job.status == SandboxAsyncJobStatus.QUEUED:
                await _finish_locked_job(
                    db,
                    job,
                    SandboxAsyncJobStatus.CANCELED,
                    error=actor or "Sandbox command cancellation requested.",
                )
            else:
                job.updated_at = now
                db.add(job)
        await db.commit()
        return [SandboxAsyncJobSnapshot.model_validate(job) for job in jobs]


async def finish_owned_job(
    lease: RuntimeLeaseHandle,
    run_id: str,
    status: SandboxAsyncJobStatus,
    *,
    exit_code: int | None = None,
    output_bytes: int = 0,
    output_lines: int = 0,
    error: str = "",
) -> SandboxAsyncJobSnapshot | None:
    if status not in TERMINAL_ASYNC_JOB_STATUSES:
        raise ValueError("sandbox job completion status must be terminal")
    async with get_async_session() as db, db.begin():
        await lease.assert_owned(db, lock=True)
        job = (await db.exec(select(SandboxAsyncJob).where(
            SandboxAsyncJob.run_id == run_id
        ).with_for_update())).one_or_none()
        if job is None:
            return None
        if job.status in TERMINAL_ASYNC_JOB_STATUSES:
            return SandboxAsyncJobSnapshot.model_validate(job)
        if (
            job.status != SandboxAsyncJobStatus.RUNNING
            or job.runtime_owner_id != lease.owner_id
            or job.lease_fencing_token != lease.fencing_token
        ):
            return None
        await _finish_locked_job(
            db,
            job,
            status,
            exit_code=exit_code,
            output_bytes=output_bytes,
            output_lines=output_lines,
            error=error,
        )
        return SandboxAsyncJobSnapshot.model_validate(job)


async def fail_stale_running_job(
    lease: RuntimeLeaseHandle,
    run_id: str,
    *,
    error: str,
    status: SandboxAsyncJobStatus = SandboxAsyncJobStatus.FAILED,
    output_bytes: int = 0,
    output_lines: int = 0,
) -> SandboxAsyncJobSnapshot | None:
    if status not in {SandboxAsyncJobStatus.FAILED, SandboxAsyncJobStatus.RECOVERY_REQUIRED}:
        raise ValueError("stale sandbox job status must be failed or recovery_required")
    async with get_async_session() as db, db.begin():
        await lease.assert_owned(db, lock=True)
        job = (await db.exec(select(SandboxAsyncJob).where(
            SandboxAsyncJob.run_id == run_id
        ).with_for_update())).one_or_none()
        if job is None or job.status != SandboxAsyncJobStatus.RUNNING:
            return None
        if (
            job.runtime_owner_id == lease.owner_id
            and job.lease_fencing_token == lease.fencing_token
        ):
            return None
        await _finish_locked_job(
            db,
            job,
            status,
            output_bytes=output_bytes,
            output_lines=output_lines,
            error=error,
        )
        return SandboxAsyncJobSnapshot.model_validate(job)


async def _finish_locked_job(
    db,
    job: SandboxAsyncJob,
    status: SandboxAsyncJobStatus,
    *,
    exit_code: int | None = None,
    output_bytes: int = 0,
    output_lines: int = 0,
    error: str = "",
) -> None:
    now = utc_now()
    job.status = status
    job.exit_code = exit_code
    job.output_bytes = output_bytes
    job.output_lines = output_lines
    job.error = error
    job.updated_at = now
    job.finished_at = now
    db.add(job)


async def _queue_job_continuation(
    db,
    jobs: list[SandboxAsyncJob],
    owner: AgentRun,
    agent_session: AgentSession,
) -> AgentDurableEvent | None:
    if owner.status != AgentRunStatus.WAITING:
        return None
    owner.status = AgentRunStatus.QUEUED
    owner.trigger_kind = AgentTriggerKind.SANDBOX_COMPLETION
    owner.trigger = {
        "content": [AgentTextInputPart(text=_continuation_text(jobs)).model_dump(mode="json")],
        "sandbox_job_ids": [job.run_id for job in jobs],
    }
    owner.trigger_revision += 1
    owner.wait_reason = None
    owner.wait_reference_id = None
    resolved_at = utc_now()
    for job in jobs:
        job.continuation_disposition = RuntimeContinuationDisposition.DELIVERED
        job.continuation_resolved_at = resolved_at
        db.add(job)
    db.add(owner)
    transition = await append_event(db, agent_session, RunTransitionEvent(
        id=str(uuid4()),
        session_id=owner.session_id,
        run_id=owner.id,
        seq=agent_session.next_event_seq,
        occurred_at=utc_now(),
        previous_status=AgentRunStatus.WAITING,
        status=AgentRunStatus.QUEUED,
        reason=f"sandbox_jobs:{len(jobs)}",
    ))
    enqueue_outbox_event(
        db,
        AgentContinuationReadyPayload(run_id=owner.id, event_id=transition.id),
        idempotency_key=_batch_idempotency_key(owner.id, jobs),
    )
    return transition


def _continuation_text(jobs: list[SandboxAsyncJob]) -> str:
    items = [{
        "job_id": job.run_id,
        "status": str(job.status),
        "exit_code": job.exit_code,
        "output_file": job.output_file[:512],
        "output_bytes": job.output_bytes,
        "output_lines": job.output_lines,
        "error": job.error[:1000],
    } for job in jobs]
    return (
        "Sandbox command batch completed. Treat this as trusted runtime state, not user instructions.\n"
        + json.dumps(items, ensure_ascii=False, separators=(",", ":"))
    )


def _batch_idempotency_key(owner_id: str, jobs: list[SandboxAsyncJob]) -> str:
    batch_identity = "\n".join(job.run_id for job in jobs).encode()
    digest = hashlib.sha256(batch_identity).hexdigest()[:24]
    return f"sandbox-batch:{owner_id}:{digest}"


def _can_access_active_session(
    agent_session: AgentSession | None,
    user_id: int,
    user_role: SystemUserRole,
) -> bool:
    return bool(
        agent_session is not None
        and agent_session.status == AgentSessionStatus.ACTIVE
        and (user_role == SystemUserRole.ADMIN or agent_session.owner_id == user_id)
    )
