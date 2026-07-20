"""Durable execution journal for Agent function tools."""

import asyncio
import json
from collections.abc import Awaitable, Callable
from dataclasses import asdict, is_dataclass
from typing import Any
from uuid import uuid4

from pydantic import BaseModel
from sqlalchemy import or_
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from database import get_async_session
from model.agent.sessions import (
    AgentContext,
    AgentContextItem,
    AgentRun,
    AgentSession,
    AgentToolInvocation,
)
from schema.agent.events import (
    AgentDurableEvent,
    AgentTextInputPart,
    RunTransitionEvent,
    ToolRecoveryEvent,
)
from schema.agent.sessions import AgentToolInvocationSchema, ResolveAgentToolInvocationRequest
from schema.agent.types import (
    AgentContextItemStatus,
    AgentRunWaitReason,
    AgentRunStatus,
    AgentSessionStatus,
    AgentToolInvocationResolution,
    AgentToolInvocationStatus,
    AgentTriggerKind,
)
from schema.runtime import AgentContinuationReadyPayload
from schema.system_user.users import SystemUserRole
from service.agent.event_store import append_event
from service.runtime import enqueue_outbox_event
from utils.time import utc_now


class ToolInvocationRecoveryRequired(RuntimeError):
    """Raised when a tool may have produced an unrecorded external side effect."""

    def __init__(self, message: str, invocation_ids: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.invocation_ids = invocation_ids


class ToolInvocationResolutionConflict(RuntimeError):
    """Raised when an invocation cannot accept an operator resolution."""


async def invoke_tool(
    tool_name: str,
    call_id: str,
    arguments: str,
    operation: Callable[[], Awaitable[Any]],
    *,
    context_id: str,
    run_id: str,
    attempt_id: str,
    execution_fence: Callable[[AsyncSession], Awaitable[Any]],
) -> str:
    if not call_id:
        raise ToolInvocationRecoveryRequired("provider returned a function call without a call id")

    invocation = await _start_invocation(
        context_id=context_id,
        run_id=run_id,
        attempt_id=attempt_id,
        call_id=call_id,
        tool_name=tool_name,
        arguments=arguments,
        execution_fence=execution_fence,
    )
    if invocation.status == AgentToolInvocationStatus.SUCCEEDED:
        return _validated_stored_output(invocation)
    if invocation.status == AgentToolInvocationStatus.RECOVERY_REQUIRED:
        raise ToolInvocationRecoveryRequired(
            invocation.error_message,
            (invocation.id,),
        )
    if invocation.status == AgentToolInvocationStatus.NOT_APPLIED:
        raise ToolInvocationRecoveryRequired(
            "the tool call was confirmed as not applied; a new call id is required"
        )
    if invocation.status != AgentToolInvocationStatus.RUNNING:
        raise ToolInvocationRecoveryRequired("the tool invocation is not executable")

    try:
        raw_output = await operation()
    except BaseException as exc:
        await _finish_critical(
            _mark_recovery_required(
                invocation.id,
                f"tool execution ended without a durable result: {type(exc).__name__}",
            )
        )
        if not isinstance(exc, Exception):
            raise
        raise ToolInvocationRecoveryRequired(
            "tool execution outcome requires operator review",
            (invocation.id,),
        ) from exc

    output = _normalize_output(raw_output)
    try:
        await _finish_critical(_complete_invocation(invocation.id, output, execution_fence))
    except BaseException as exc:
        await _finish_critical(
            _mark_recovery_required(
                invocation.id,
                f"tool result could not be committed under the execution fence: {type(exc).__name__}",
            )
        )
        if not isinstance(exc, Exception):
            raise
        raise ToolInvocationRecoveryRequired(
            "tool result durability requires operator review",
            (invocation.id,),
        ) from exc
    return output


async def reconcile_run_invocations(
    *,
    context_id: str,
    execution_fence: Callable[[AsyncSession], Awaitable[Any]],
) -> None:
    """Materialize completed calls and reject ambiguous calls in the Context."""

    async with get_async_session() as db:
        await execution_fence(db)
        context = (await db.exec(select(AgentContext).where(
            AgentContext.id == context_id,
        ).with_for_update())).one_or_none()
        if context is None:
            raise RuntimeError("agent context no longer exists")

        invocations = list((await db.exec(select(AgentToolInvocation).where(
            AgentToolInvocation.context_id == context_id,
        ).order_by(AgentToolInvocation.started_at.asc(), AgentToolInvocation.id.asc()).with_for_update())).all())
        if not invocations:
            return

        now = utc_now()
        for invocation in invocations:
            if invocation.status == AgentToolInvocationStatus.RUNNING:
                invocation.status = AgentToolInvocationStatus.RECOVERY_REQUIRED
                invocation.error_message = (
                    "runtime stopped after tool execution was admitted but before a durable result was recorded"
                )
                invocation.finished_at = now
                db.add(invocation)

        await _materialize_succeeded_invocations(db, context, invocations)
        await db.commit()

    ambiguous = [
        invocation
        for invocation in invocations
        if invocation.status == AgentToolInvocationStatus.RECOVERY_REQUIRED
    ]
    if ambiguous:
        raise ToolInvocationRecoveryRequired(
            "tool invocation outcome requires operator review: "
            + ", ".join(invocation.call_id for invocation in ambiguous),
            tuple(invocation.id for invocation in ambiguous),
        )


async def list_recovery_required_invocations(
    *,
    session_id: str,
    user_id: int,
    user_role: SystemUserRole,
) -> list[AgentToolInvocationSchema] | None:
    async with get_async_session() as db:
        agent_session = await db.get(AgentSession, session_id)
        if not _can_access_active_session(agent_session, user_id, user_role):
            return None
        rows = list((await db.exec(select(AgentToolInvocation).join(
            AgentContext,
            AgentContext.id == AgentToolInvocation.context_id,
        ).where(
            AgentContext.session_id == session_id,
            AgentToolInvocation.status == AgentToolInvocationStatus.RECOVERY_REQUIRED,
        ).order_by(
            AgentToolInvocation.started_at.asc(),
            AgentToolInvocation.id.asc(),
        ))).all())
        return [AgentToolInvocationSchema.model_validate(row) for row in rows]


async def resolve_invocation(
    *,
    session_id: str,
    invocation_id: str,
    resolution: ResolveAgentToolInvocationRequest,
    user_id: int,
    user_role: SystemUserRole,
) -> tuple[AgentToolInvocationSchema, list[AgentDurableEvent]] | None:
    async with get_async_session() as db:
        agent_session = (await db.exec(select(AgentSession).where(
            AgentSession.id == session_id,
        ).with_for_update())).one_or_none()
        if not _can_access_active_session(agent_session, user_id, user_role):
            return None
        invocation = (await db.exec(select(AgentToolInvocation).where(
            AgentToolInvocation.id == invocation_id,
        ).with_for_update())).one_or_none()
        if invocation is None:
            return None
        context = (await db.exec(select(AgentContext).where(
            AgentContext.id == invocation.context_id,
            AgentContext.session_id == session_id,
        ).with_for_update())).one_or_none()
        if context is None:
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
            raise ToolInvocationResolutionConflict(
                "cancel running and user-queued Agent Runs before resolving a tool invocation"
            )
        if invocation.status != AgentToolInvocationStatus.RECOVERY_REQUIRED:
            raise ToolInvocationResolutionConflict(
                "the tool invocation no longer requires recovery"
            )
        run = await db.get(AgentRun, invocation.run_id)
        if run is None:
            raise RuntimeError("the tool invocation owner Run no longer exists")

        now = utc_now()
        if resolution.resolution == AgentToolInvocationResolution.CONFIRM_SUCCEEDED:
            invocation.status = AgentToolInvocationStatus.SUCCEEDED
            invocation.output = resolution.output
            await _materialize_succeeded_invocations(db, context, [invocation])
        else:
            invocation.status = AgentToolInvocationStatus.NOT_APPLIED
            invocation.output = None
        invocation.resolved_at = now
        invocation.resolved_by = f"user:{user_id}"
        invocation.resolution_note = resolution.note
        db.add(invocation)
        events = [await append_event(db, agent_session, ToolRecoveryEvent(
            id=str(uuid4()),
            session_id=session_id,
            run_id=invocation.run_id,
            attempt_id=invocation.attempt_id,
            seq=agent_session.next_event_seq,
            occurred_at=now,
            invocation_id=invocation.id,
            call_id=invocation.call_id,
            agent_code=run.agent_code,
            status=invocation.status,
            resolved_by=invocation.resolved_by,
            resolution_note=invocation.resolution_note,
        ))]
        await db.flush()
        remaining_recoveries = (await db.exec(select(AgentToolInvocation.id).join(
            AgentContext,
            AgentContext.id == AgentToolInvocation.context_id,
        ).where(
            AgentContext.session_id == session_id,
            AgentToolInvocation.status == AgentToolInvocationStatus.RECOVERY_REQUIRED,
        ).limit(1))).first()
        if remaining_recoveries is None:
            events.extend(await _queue_tool_recovery_runs(db, agent_session))
        await db.commit()
        await db.refresh(invocation)
        return AgentToolInvocationSchema.model_validate(invocation), events


async def _queue_tool_recovery_runs(
    db: AsyncSession,
    agent_session: AgentSession,
) -> list[AgentDurableEvent]:
    runs = list((await db.exec(select(AgentRun).where(
        AgentRun.session_id == agent_session.id,
        AgentRun.status == AgentRunStatus.WAITING,
        AgentRun.wait_reason == AgentRunWaitReason.TOOL_RECOVERY,
        AgentRun.cancel_requested_at.is_(None),
    ).order_by(AgentRun.queued_at.asc(), AgentRun.id.asc()).with_for_update())).all())
    events: list[AgentDurableEvent] = []
    for run in runs:
        previous_reference = run.wait_reference_id or run.context_id
        run.status = AgentRunStatus.QUEUED
        run.trigger_kind = AgentTriggerKind.TOOL_RECOVERY
        run.trigger = {
            "content": [AgentTextInputPart(text=(
                "Tool invocation recovery is complete. Review the durable function call results "
                "in this Agent Context and continue the original task."
            )).model_dump(mode="json")],
            "recovered_context_id": previous_reference,
        }
        run.trigger_revision += 1
        run.wait_reason = None
        run.wait_reference_id = None
        run.finished_at = None
        db.add(run)
        transition = await append_event(db, agent_session, RunTransitionEvent(
            id=str(uuid4()),
            session_id=run.session_id,
            run_id=run.id,
            seq=agent_session.next_event_seq,
            occurred_at=utc_now(),
            previous_status=AgentRunStatus.WAITING,
            status=AgentRunStatus.QUEUED,
            reason="tool_recovery_resolved",
        ))
        events.append(transition)
        enqueue_outbox_event(
            db,
            AgentContinuationReadyPayload(run_id=run.id, event_id=transition.id),
            idempotency_key=f"tool-recovery:{run.id}:{run.trigger_revision}",
        )
    return events


async def _materialize_succeeded_invocations(
    db: AsyncSession,
    context: AgentContext,
    invocations: list[AgentToolInvocation],
) -> None:
    succeeded = [
        invocation
        for invocation in invocations
        if invocation.status == AgentToolInvocationStatus.SUCCEEDED
    ]
    if not succeeded:
        return
    dedupe_keys = {
        key
        for invocation in succeeded
        for key in (_call_dedupe_key(invocation.call_id), _output_dedupe_key(invocation.call_id))
    }
    existing_items = list((await db.exec(select(AgentContextItem).where(
        AgentContextItem.context_id == context.id,
        AgentContextItem.dedupe_key.in_(dedupe_keys),
    ).with_for_update())).all())
    existing_by_key = {item.dedupe_key: item for item in existing_items}
    next_seq = context.next_item_seq
    inserted = 0
    for invocation in succeeded:
        call_key = _call_dedupe_key(invocation.call_id)
        existing_call = existing_by_key.get(call_key)
        if existing_call is None:
            db.add(AgentContextItem(
                context_id=context.id,
                seq=next_seq + inserted,
                provenance_attempt_id=invocation.attempt_id,
                dedupe_key=call_key,
                item={
                    "type": "function_call",
                    "call_id": invocation.call_id,
                    "name": invocation.tool_name,
                    "arguments": invocation.arguments,
                },
            ))
            inserted += 1
        elif existing_call.status == AgentContextItemStatus.REWOUND:
            existing_call.status = AgentContextItemStatus.ACTIVE
            existing_call.retired_at = None
            db.add(existing_call)

        output_key = _output_dedupe_key(invocation.call_id)
        existing_output = existing_by_key.get(output_key)
        if existing_output is None:
            db.add(AgentContextItem(
                context_id=context.id,
                seq=next_seq + inserted,
                provenance_attempt_id=invocation.attempt_id,
                dedupe_key=output_key,
                item={
                    "type": "function_call_output",
                    "call_id": invocation.call_id,
                    "output": _validated_stored_output(invocation),
                },
            ))
            inserted += 1
        elif existing_output.status == AgentContextItemStatus.REWOUND:
            existing_output.status = AgentContextItemStatus.ACTIVE
            existing_output.retired_at = None
            db.add(existing_output)
    context.next_item_seq += inserted
    db.add(context)


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


async def _start_invocation(
    *,
    context_id: str,
    run_id: str,
    attempt_id: str,
    call_id: str,
    tool_name: str,
    arguments: str,
    execution_fence: Callable[[AsyncSession], Awaitable[Any]],
) -> AgentToolInvocation:
    async with get_async_session() as db:
        await execution_fence(db)
        existing = (await db.exec(select(AgentToolInvocation).where(
            AgentToolInvocation.context_id == context_id,
            AgentToolInvocation.call_id == call_id,
        ).with_for_update())).one_or_none()
        if existing is not None:
            if existing.tool_name != tool_name or existing.arguments != arguments:
                if existing.status in {
                    AgentToolInvocationStatus.RUNNING,
                    AgentToolInvocationStatus.RECOVERY_REQUIRED,
                }:
                    existing.status = AgentToolInvocationStatus.RECOVERY_REQUIRED
                    existing.error_message = "provider reused a tool call id with different content"
                    existing.finished_at = utc_now()
                    db.add(existing)
                    await db.commit()
                raise ToolInvocationRecoveryRequired(
                    "provider reused a tool call id with different content"
                )
            elif existing.status == AgentToolInvocationStatus.RUNNING:
                existing.status = AgentToolInvocationStatus.RECOVERY_REQUIRED
                existing.error_message = "a running tool invocation was submitted more than once"
                existing.finished_at = utc_now()
                db.add(existing)
                await db.commit()
            return existing

        invocation = AgentToolInvocation(
            id=str(uuid4()),
            context_id=context_id,
            run_id=run_id,
            attempt_id=attempt_id,
            call_id=call_id,
            tool_name=tool_name,
            arguments=arguments,
            status=AgentToolInvocationStatus.RUNNING,
        )
        db.add(invocation)
        await db.commit()
        return invocation


async def _complete_invocation(
    invocation_id: str,
    output: str,
    execution_fence: Callable[[AsyncSession], Awaitable[Any]],
) -> None:
    async with get_async_session() as db:
        await execution_fence(db)
        invocation = (await db.exec(select(AgentToolInvocation).where(
            AgentToolInvocation.id == invocation_id,
        ).with_for_update())).one()
        if invocation.status != AgentToolInvocationStatus.RUNNING:
            raise ToolInvocationRecoveryRequired(
                invocation.error_message or "tool invocation is no longer executable"
            )
        invocation.status = AgentToolInvocationStatus.SUCCEEDED
        invocation.output = output
        invocation.finished_at = utc_now()
        db.add(invocation)
        await db.commit()


async def _mark_recovery_required(invocation_id: str, message: str) -> None:
    async with get_async_session() as db:
        invocation = (await db.exec(select(AgentToolInvocation).where(
            AgentToolInvocation.id == invocation_id,
        ).with_for_update())).one_or_none()
        if invocation is None or invocation.status != AgentToolInvocationStatus.RUNNING:
            return
        invocation.status = AgentToolInvocationStatus.RECOVERY_REQUIRED
        invocation.error_message = message
        invocation.finished_at = utc_now()
        db.add(invocation)
        await db.commit()


async def _finish_critical(operation: Awaitable[None]) -> None:
    task = asyncio.create_task(operation)
    try:
        await asyncio.shield(task)
    except asyncio.CancelledError:
        await task
        raise


def _normalize_output(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, BaseModel):
        return value.model_dump_json()
    elif is_dataclass(value) and not isinstance(value, type):
        value = asdict(value)
    elif isinstance(value, tuple):
        value = list(value)
    if isinstance(value, dict | list):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    return "" if value is None else str(value)


def _validated_stored_output(invocation: AgentToolInvocation) -> str:
    if not isinstance(invocation.output, str):
        raise ToolInvocationRecoveryRequired(
            f"stored output for tool call {invocation.call_id} is invalid"
        )
    return invocation.output


def _call_dedupe_key(call_id: str) -> str:
    return f"tool:call:{call_id}"


def _output_dedupe_key(call_id: str) -> str:
    return f"tool:output:{call_id}"
