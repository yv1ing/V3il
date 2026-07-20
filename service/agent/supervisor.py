import asyncio
from collections import defaultdict
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import partial
from typing import Literal
from uuid import uuid4

from agents import Runner
from pydantic import TypeAdapter, ValidationError
from sqlalchemy import and_, func, or_
from sqlalchemy.dialects.postgresql import insert
from sqlmodel import select

from config import AgentConfig, get_config
from core.agent.registry import AgentRegistry
from core.agent.tool_snapshot import AgentToolSnapshot
from core.conversation.context_budget import build_context_run_config
from core.conversation.compaction import compact_context_if_needed
from core.conversation.retrieval import build_conversation_retrieval_query
from core.conversation.store import V3ilSession
from core.deception import activate_deception_context
from core.investigation import activate_investigation_context
from core.lightrag.runtime import activate_lightrag_context
from core.runtime.context import AgentRuntimeContext, AgentUserContext
from core.runtime.events import (
    StreamDelta,
    StreamError,
    StreamSegmentComplete,
    StreamToolCall,
    StreamToolResult,
)
from core.runtime.input_items import build_user_message_item, retrieval_text_from_content
from core.runtime.streaming import iter_normalized_stream_events
from database import get_async_session
from logger import get_logger
from model.agent.sessions import (
    AgentContextItem,
    AgentEvent,
    AgentRun,
    AgentRunAttempt,
    AgentSegment,
    AgentSession,
    AgentToolInvocation,
)
from model.runtime import RuntimeLease, RuntimeOutboxEvent
from model.system_user.users import SystemUser
from schema.agent.events import (
    AgentDeltaFrame,
    AgentDurableEvent,
    AgentErrorEvent,
    AgentEventFrame,
    AgentHelloFrame,
    AgentInputPart,
    AgentReplayFrame,
    AgentRebaseRequiredFrame,
    AgentSegmentSnapshot,
    AgentServerFrame,
    AttemptTransitionEvent,
    RunTransitionEvent,
    SegmentCompletedEvent,
    ToolCallEvent,
    ToolResultEvent,
)
from schema.agent.sessions import (
    AgentAttemptStatus,
    AgentCancellationMode,
    AgentCode,
    AgentRunStatus,
    AgentSegmentKind,
    AgentSegmentStatus,
)
from schema.agent.types import AgentContextItemStatus, AgentRunWaitReason, AgentToolInvocationStatus
from schema.runtime import (
    AgentContinuationReadyPayload,
    AgentRunCancelPayload,
    AgentRunReadyPayload,
    AgentSessionCancelPayload,
    OutboxPayload,
    OutboxTopic,
)
from service.agent import delegation as agent_delegation
from service.agent import tool_invocations as agent_tool_invocations
from service.agent.admission import run_admission_block_reason
from service.agent.event_store import append_event
from service.sandbox import async_jobs as sandbox_async_jobs
from service.runtime import enqueue_outbox_event
from utils.time import utc_now


logger = get_logger(__name__)

_content_adapter = TypeAdapter(list[AgentInputPart])
_event_adapter = TypeAdapter(AgentDurableEvent)
_outbox_adapter = TypeAdapter(OutboxPayload)
_TERMINAL_RUN_STATUSES = {
    AgentRunStatus.SUCCEEDED,
    AgentRunStatus.FAILED,
    AgentRunStatus.CANCELED,
}
_LEASE_NAME = "runtime-supervisor"
_LEASE_SECONDS = 15
_POLL_SECONDS = 0.5
_SUBSCRIBER_QUEUE_SIZE = 512
_REPLAY_EVENT_LIMIT = 200
_SEGMENT_CHECKPOINT_UTF16_UNITS = 2048


@dataclass(slots=True)
class _LiveSegment:
    id: str
    key: str
    kind: AgentSegmentKind
    text: str = ""
    persisted_utf16_offset: int = 0
    last_checkpoint_at: float = 0.0


@dataclass(eq=False, slots=True)
class AgentStreamSubscription:
    queue: asyncio.Queue[AgentServerFrame | None] = field(
        default_factory=lambda: asyncio.Queue(maxsize=_SUBSCRIBER_QUEUE_SIZE)
    )
    replaying: bool = True
    replay_head_seq: int | None = None
    segment_utf16_offsets: dict[str, int] = field(default_factory=dict)
    pending_frames: list[AgentServerFrame] = field(default_factory=list)
    closed: bool = False


@dataclass(frozen=True, slots=True)
class _TaskStop:
    kind: AgentCancellationMode | Literal["shutdown", "lease_lost"]
    actor: str = ""
    resume_parent: bool = True


class _ExecutionLeaseLost(RuntimeError):
    pass


class AgentRuntimeSupervisor:
    def __init__(self, registry: AgentRegistry | None = None) -> None:
        self.registry = registry or AgentRegistry()
        self.owner_id = str(uuid4())
        self._driver: asyncio.Task[None] | None = None
        self._active_tasks: dict[str, asyncio.Task[None]] = {}
        self._cancel_modes: dict[str, _TaskStop] = {}
        self._subscribers: dict[str, set[AgentStreamSubscription]] = defaultdict(set)
        self._durable_heads: dict[str, int] = {}
        self._wake = asyncio.Event()
        self._stopping = False
        self._fencing_token = 0
        self._recovered_fencing_token = 0

    async def start(self) -> None:
        if self._driver is not None:
            return
        self._stopping = False
        self._driver = asyncio.create_task(self._loop(), name="runtime-supervisor")
        self._wake.set()

    async def stop(self) -> None:
        self._stopping = True
        self._wake.set()
        driver, self._driver = self._driver, None
        if driver is not None:
            driver.cancel()
        tasks = list(self._active_tasks.values())
        for run_id, task in self._active_tasks.items():
            self._cancel_modes[run_id] = _TaskStop(kind="shutdown")
            task.cancel()
        await asyncio.gather(*(tasks + ([driver] if driver else [])), return_exceptions=True)
        self._active_tasks.clear()
        self._cancel_modes.clear()
        for queues in self._subscribers.values():
            for subscription in queues:
                subscription.closed = True
                _offer(subscription.queue, None)
        self._subscribers.clear()

    def notify(self) -> None:
        self._wake.set()

    def publish_durable_event(self, event: AgentDurableEvent) -> None:
        self._broadcast(event.session_id, AgentEventFrame(event=event))

    async def subscribe(self, session_id: str) -> AgentStreamSubscription:
        subscription = AgentStreamSubscription()
        self._subscribers[session_id].add(subscription)
        try:
            hello = await self._hello(session_id)
        except BaseException:
            self._subscribers[session_id].discard(subscription)
            raise
        subscription.replay_head_seq = hello.durable_head_seq
        subscription.segment_utf16_offsets = {
            segment.segment_id: segment.persisted_utf16_offset
            for segment in hello.segments
        }
        self._durable_heads[session_id] = max(
            self._durable_heads.get(session_id, 0),
            hello.durable_head_seq,
        )
        if not subscription.closed:
            _offer(subscription.queue, hello)
        return subscription

    def unsubscribe(self, session_id: str, subscription: AgentStreamSubscription) -> None:
        subscribers = self._subscribers.get(session_id)
        if subscribers is None:
            return
        subscription.closed = True
        subscription.segment_utf16_offsets.clear()
        subscription.pending_frames.clear()
        subscribers.discard(subscription)
        if not subscribers:
            self._subscribers.pop(session_id, None)

    async def replay_from(
        self,
        session_id: str,
        subscription: AgentStreamSubscription,
        after_seq: int,
    ) -> None:
        if subscription not in self._subscribers.get(session_id, ()) or subscription.closed:
            return
        replay_head_seq = subscription.replay_head_seq
        if replay_head_seq is None:
            raise RuntimeError("agent stream replay boundary is not initialized")
        async with get_async_session() as db:
            agent_session = await db.get(AgentSession, session_id)
            if agent_session is None:
                raise KeyError("agent session not found")
            if after_seq > replay_head_seq:
                self._finish_replay(session_id, subscription, AgentRebaseRequiredFrame(
                    durable_head_seq=replay_head_seq,
                    reason="client durable cursor is ahead of the WebSocket replay boundary",
                ))
                return
            if after_seq == replay_head_seq:
                self._finish_replay(session_id, subscription, None)
                return
            rows = list((await db.exec(select(AgentEvent).where(
                AgentEvent.session_id == session_id,
                AgentEvent.seq > after_seq,
                AgentEvent.seq <= replay_head_seq,
            ).order_by(AgentEvent.seq.asc()).limit(_REPLAY_EVENT_LIMIT + 1))).all())
        expected_count = replay_head_seq - after_seq
        if (
            expected_count > _REPLAY_EVENT_LIMIT
            or len(rows) != expected_count
            or any(row.seq != after_seq + index for index, row in enumerate(rows, start=1))
        ):
            self._finish_replay(session_id, subscription, AgentRebaseRequiredFrame(
                durable_head_seq=replay_head_seq,
                reason="client durable cursor is outside the WebSocket replay window",
            ))
            return
        self._finish_replay(session_id, subscription, AgentReplayFrame(
            events=[_event_adapter.validate_python(row.payload) for row in rows],
            durable_head_seq=replay_head_seq,
        ))

    def _finish_replay(
        self,
        session_id: str,
        subscription: AgentStreamSubscription,
        replay_frame: AgentServerFrame | None,
    ) -> None:
        if subscription.closed:
            return
        pending = subscription.pending_frames
        subscription.pending_frames = []
        subscription.replaying = False
        if isinstance(replay_frame, AgentRebaseRequiredFrame):
            self._close_after_rebase(session_id, subscription, replay_frame)
            return
        if replay_frame is not None:
            self._enqueue_frame(session_id, subscription, replay_frame)

        replay_head_seq = subscription.replay_head_seq or 0
        completed_segment_ids = {
            event.segment_id
            for event in (replay_frame.events if isinstance(replay_frame, AgentReplayFrame) else [])
            if isinstance(event, SegmentCompletedEvent)
        }
        completed_segment_ids.update(
            frame.event.segment_id
            for frame in pending
            if (
                isinstance(frame, AgentEventFrame)
                and frame.event.seq <= replay_head_seq
                and isinstance(frame.event, SegmentCompletedEvent)
            )
        )
        segment_offsets = dict(subscription.segment_utf16_offsets)
        for frame in pending:
            if isinstance(frame, AgentEventFrame):
                if frame.event.seq <= replay_head_seq:
                    continue
                self._enqueue_frame(session_id, subscription, frame)
                if isinstance(frame.event, SegmentCompletedEvent):
                    completed_segment_ids.add(frame.event.segment_id)
                    segment_offsets.pop(frame.event.segment_id, None)
                continue
            if isinstance(frame, AgentDeltaFrame):
                if frame.segment_id in completed_segment_ids:
                    continue
                expected_offset = segment_offsets.get(frame.segment_id, 0)
                if frame.start_utf16_offset > expected_offset:
                    self._close_after_rebase(session_id, subscription, AgentRebaseRequiredFrame(
                        durable_head_seq=self._durable_heads.get(session_id, replay_head_seq),
                        reason="live segment delta is outside the WebSocket snapshot boundary",
                    ))
                    return
                normalized = _trim_replayed_delta(frame, expected_offset)
                segment_offsets[frame.segment_id] = max(
                    expected_offset,
                    frame.end_utf16_offset,
                )
                if normalized is not None:
                    self._enqueue_frame(session_id, subscription, normalized)
                continue
            self._enqueue_frame(session_id, subscription, frame)
        subscription.segment_utf16_offsets = segment_offsets

    def _close_after_rebase(
        self,
        session_id: str,
        subscription: AgentStreamSubscription,
        frame: AgentRebaseRequiredFrame,
    ) -> None:
        self._enqueue_frame(session_id, subscription, frame)
        subscription.closed = True
        _offer(subscription.queue, None)

    async def _cancel_session_runs(
        self,
        session_id: str,
        *,
        mode: AgentCancellationMode,
        actor: str,
    ) -> list[str]:
        async with get_async_session() as db:
            await self._require_supervisor_lease(db)
            run_ids = list((await db.exec(select(AgentRun.id).where(
                AgentRun.session_id == session_id,
                AgentRun.status.not_in(_TERMINAL_RUN_STATUSES),
            ).order_by(AgentRun.id.asc()))).all())
        for run_id in run_ids:
            task = self._active_tasks.get(run_id)
            if task is not None and not task.done():
                self._cancel_modes[run_id] = _TaskStop(
                    kind=mode,
                    actor=actor,
                    resume_parent=False,
                )
                task.cancel()
        await asyncio.gather(
            *(self._active_tasks[run_id] for run_id in run_ids if run_id in self._active_tasks),
            return_exceptions=True,
        )
        for run_id in run_ids:
            await self._cancel_persisted_run(
                run_id,
                mode=mode,
                actor=actor,
                resume_parent=False,
            )
        return run_ids

    async def _cancel_single_run(
        self,
        run_id: str,
        *,
        mode: AgentCancellationMode,
        actor: str,
    ) -> bool:
        task = self._active_tasks.get(run_id)
        if task is not None and not task.done():
            self._cancel_modes[run_id] = _TaskStop(kind=mode, actor=actor)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        return await self._cancel_persisted_run(
            run_id,
            mode=mode,
            actor=actor,
            resume_parent=True,
        )

    async def _loop(self) -> None:
        while not self._stopping:
            try:
                if await self._renew_lease():
                    if self._recovered_fencing_token != self._fencing_token:
                        if self._recovered_fencing_token:
                            await self._yield_active_runs("runtime lease fencing token changed")
                        await self._recover_interrupted_attempts()
                        self._recovered_fencing_token = self._fencing_token
                    await self._dispatch_outbox()
                    await self._schedule_queued_runs()
                else:
                    await self._yield_active_runs("runtime lease ownership changed")
                self._wake.clear()
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=_POLL_SECONDS)
                except TimeoutError:
                    pass
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("runtime supervisor iteration failed")
                await asyncio.sleep(_POLL_SECONDS)

    async def _renew_lease(self) -> bool:
        now = utc_now()
        expires_at = now + timedelta(seconds=_LEASE_SECONDS)
        async with get_async_session() as db:
            await db.execute(
                insert(RuntimeLease)
                .values(
                    name=_LEASE_NAME,
                    owner_id=self.owner_id,
                    fencing_token=1,
                    acquired_at=now,
                    expires_at=expires_at,
                )
                .on_conflict_do_nothing(index_elements=["name"])
            )
            lease = (await db.exec(
                select(RuntimeLease).where(RuntimeLease.name == _LEASE_NAME).with_for_update()
            )).one()
            if lease.owner_id == self.owner_id and lease.expires_at > now:
                lease.expires_at = expires_at
                db.add(lease)
            elif lease.expires_at <= now:
                lease.owner_id = self.owner_id
                lease.fencing_token += 1
                lease.acquired_at = now
                lease.expires_at = expires_at
                db.add(lease)
            else:
                self._fencing_token = 0
                return False
            await db.commit()
            self._fencing_token = lease.fencing_token
            return True

    async def _dispatch_outbox(self) -> None:
        now = utc_now()
        run_cancel_commands: list[tuple[int, AgentRunCancelPayload]] = []
        session_cancel_commands: list[tuple[int, AgentSessionCancelPayload]] = []
        ready_runs: list[tuple[str, AgentDurableEvent]] = []
        owned_topics = {
            OutboxTopic.AGENT_RUN_READY,
            OutboxTopic.AGENT_CONTINUATION_READY,
            OutboxTopic.AGENT_RUN_CANCEL,
            OutboxTopic.AGENT_SESSION_CANCEL,
        }
        async with get_async_session() as db:
            rows = list((await db.exec(select(RuntimeOutboxEvent).where(
                RuntimeOutboxEvent.published_at.is_(None),
                RuntimeOutboxEvent.available_at <= now,
                RuntimeOutboxEvent.topic.in_(owned_topics),
            ).order_by(RuntimeOutboxEvent.id.asc()).limit(100).with_for_update(skip_locked=True))).all())
            for row in rows:
                try:
                    payload = _outbox_adapter.validate_python(row.payload)
                except ValidationError as exc:
                    self._defer_invalid_outbox(row, now, f"invalid payload: {exc.errors()[0]['msg']}")
                    db.add(row)
                    continue
                if str(payload.type) != row.topic:
                    self._defer_invalid_outbox(
                        row,
                        now,
                        f"topic {row.topic!r} does not match payload type {payload.type!s}",
                    )
                    db.add(row)
                    continue

                if isinstance(payload, AgentRunReadyPayload | AgentContinuationReadyPayload):
                    event_row = await db.get(AgentEvent, payload.event_id)
                    if event_row is None:
                        self._defer_invalid_outbox(row, now, "referenced Agent Event does not exist")
                        db.add(row)
                        continue
                    try:
                        event = _event_adapter.validate_python(event_row.payload)
                    except ValidationError as exc:
                        self._defer_invalid_outbox(
                            row,
                            now,
                            f"referenced Agent Event is invalid: {exc.errors()[0]['msg']}",
                        )
                        db.add(row)
                        continue
                    ready_runs.append((payload.run_id, event))
                    row.published_at = now
                    db.add(row)
                elif isinstance(payload, AgentSessionCancelPayload) and row.id is not None:
                    session_cancel_commands.append((row.id, payload))
                elif isinstance(payload, AgentRunCancelPayload) and row.id is not None:
                    run_cancel_commands.append((row.id, payload))
            await db.commit()
        for _, event in ready_runs:
            self._broadcast(event.session_id, AgentEventFrame(event=event))
        for event_id, payload in session_cancel_commands:
            await self._cancel_session_runs(
                payload.session_id,
                mode=payload.mode,
                actor=payload.actor,
            )
            await self._mark_outbox_published(event_id)
        for event_id, payload in run_cancel_commands:
            await self._cancel_single_run(
                payload.run_id,
                mode=payload.mode,
                actor=payload.actor,
            )
            await self._mark_outbox_published(event_id)

    @staticmethod
    def _defer_invalid_outbox(row: RuntimeOutboxEvent, now, message: str) -> None:
        row.attempt_count += 1
        row.last_error = message[:1000]
        row.available_at = now + timedelta(seconds=min(300, 2 ** min(row.attempt_count, 8)))

    async def _mark_outbox_published(self, event_id: int) -> None:
        async with get_async_session() as db:
            row = await db.get(RuntimeOutboxEvent, event_id)
            if row is not None and row.published_at is None:
                row.published_at = utc_now()
                db.add(row)
                await db.commit()

    async def _yield_active_runs(self, reason: str) -> None:
        tasks = list(self._active_tasks.items())
        for run_id, task in tasks:
            if not task.done():
                self._cancel_modes[run_id] = _TaskStop(kind="lease_lost")
                task.cancel()
        if tasks:
            await asyncio.gather(*(task for _, task in tasks), return_exceptions=True)
            logger.warning("yielded %d Agent Run(s): %s", len(tasks), reason)

    async def _schedule_queued_runs(self) -> None:
        capacity = get_config().agent_runtime.max_concurrent_runs - sum(
            not task.done() for task in self._active_tasks.values()
        )
        if capacity <= 0:
            return
        cursor: tuple[datetime, str] | None = None
        while capacity > 0:
            statement = select(AgentRun.id, AgentRun.queued_at).where(
                AgentRun.status == AgentRunStatus.QUEUED,
                AgentRun.cancel_requested_at.is_(None),
            )
            if cursor is not None:
                queued_at, run_id = cursor
                statement = statement.where(or_(
                    AgentRun.queued_at > queued_at,
                    and_(AgentRun.queued_at == queued_at, AgentRun.id > run_id),
                ))
            async with get_async_session() as db:
                candidates = list((await db.exec(
                    statement.order_by(AgentRun.queued_at.asc(), AgentRun.id.asc()).limit(64)
                )).all())
            if not candidates:
                return

            for run_id, queued_at in candidates:
                cursor = (queued_at, run_id)
                claimed = await self._claim(run_id)
                if claimed is None:
                    continue
                task = asyncio.create_task(
                    self._execute_claimed(*claimed),
                    name=f"agent-run-{run_id}",
                )
                self._active_tasks[run_id] = task
                task.add_done_callback(
                    lambda completed, key=run_id: self._task_finished(key, completed)
                )
                capacity -= 1
                if capacity == 0:
                    return

            if len(candidates) < 64:
                return

    def _task_finished(self, run_id: str, task: asyncio.Task[None]) -> None:
        if self._active_tasks.get(run_id) is task:
            self._active_tasks.pop(run_id, None)
        try:
            task.result()
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("agent run task escaped: %s", run_id)
        self._cancel_modes.pop(run_id, None)
        self._wake.set()

    async def _execute_claimed(
        self,
        run: AgentRun,
        attempt: AgentRunAttempt,
        start_events: list[AgentDurableEvent],
    ) -> None:
        for event in start_events:
            self._broadcast(run.session_id, AgentEventFrame(event=event))
        graph = None
        segments: dict[str, _LiveSegment] = {}
        try:
            context = await self._build_context(run, attempt)
            execution_fence = partial(self._assert_attempt_fence, run.id, attempt.id)
            await agent_tool_invocations.reconcile_run_invocations(
                context_id=run.context_id,
                execution_fence=execution_fence,
            )
            if context.wait_requested:
                await self._finish_run(
                    run.id,
                    attempt.id,
                    run.session_id,
                    waiting=True,
                    wait_reason=context.wait_reason,
                    wait_reference_id=context.wait_reference_id,
                    usage={},
                    result_summary="Recovered durable wait state.",
                )
                return
            graph = self.registry.bind(AgentToolSnapshot.from_context(context))
            agent = graph.get(str(run.agent_code))
            memory = V3ilSession(
                run.context_id,
                attempt_id=attempt.id,
                write_fence=execution_fence,
            )
            content = _content_adapter.validate_python(run.trigger.get("content", []))
            input_item = build_user_message_item(
                content,
                message_id=_run_input_item_id(run.id, run.trigger_revision),
            )
            cfg = AgentConfig.model_validate(attempt.model_config_snapshot)
            await compact_context_if_needed(
                context_id=run.context_id,
                attempt_id=attempt.id,
                agent_config=cfg,
                incoming_items=[input_item],
                write_fence=execution_fence,
            )
            await memory.add_items([input_item])
            query = await build_conversation_retrieval_query(memory, retrieval_text_from_content(content))
            async with AsyncExitStack() as stack:
                await stack.enter_async_context(activate_investigation_context(context))
                await stack.enter_async_context(activate_deception_context(context))
                await stack.enter_async_context(activate_lightrag_context(context, query))
                stream = Runner.run_streamed(
                    starting_agent=agent,
                    session=memory,
                    input=[],
                    context=context,
                    max_turns=(
                        get_config().agent_runtime.main_max_turns
                        if run.is_foreground
                        else get_config().agent_runtime.specialist_max_turns
                    ),
                    run_config=build_context_run_config(cfg),
                )
                async for event in iter_normalized_stream_events(stream, current_agent_name=agent.name):
                    await self._consume_stream_event(run, attempt, event, segments)
            await self._complete_open_segments(run, attempt, segments)
            usage = _usage_payload(stream.context_wrapper.usage)
            await self._finish_run(
                run.id,
                attempt.id,
                run.session_id,
                waiting=context.wait_requested,
                wait_reason=context.wait_reason,
                wait_reference_id=context.wait_reference_id,
                usage=usage,
                result_summary=_result_summary(segments),
            )
        except asyncio.CancelledError:
            directive = self._cancel_modes.pop(run.id, _TaskStop(kind="shutdown"))
            await self._checkpoint_live_segments_if_owned(run.id, attempt.id, segments)
            if isinstance(directive.kind, AgentCancellationMode):
                await self._cancel_persisted_run(
                    run.id,
                    mode=directive.kind,
                    actor=directive.actor,
                    resume_parent=directive.resume_parent,
                )
            else:
                await self._requeue_interrupted_run(run.id, attempt.id, reason=directive.kind)
            raise
        except _ExecutionLeaseLost:
            return
        except agent_tool_invocations.ToolInvocationRecoveryRequired as exc:
            if not exc.invocation_ids:
                await self._checkpoint_live_segments_if_owned(run.id, attempt.id, segments)
                await self._fail_run(run, attempt, exc)
            else:
                await self._checkpoint_live_segments_if_owned(run.id, attempt.id, segments)
                await self._wait_for_tool_recovery(run, attempt, str(exc))
        except Exception as exc:
            logger.exception("agent run failed: %s", run.id)
            await self._checkpoint_live_segments_if_owned(run.id, attempt.id, segments)
            await self._fail_run(run, attempt, exc)
        finally:
            if graph is not None:
                await graph.close()

    async def _wait_for_tool_recovery(
        self,
        run: AgentRun,
        attempt: AgentRunAttempt,
        reason: str,
    ) -> None:
        try:
            await sandbox_async_jobs.cancel_running_async_jobs_for_run(
                run.id,
                "Owning Agent Run requires tool recovery.",
            )
        except Exception:
            logger.exception(
                "failed to cancel Sandbox Jobs for tool recovery: %s",
                run.id,
            )
        try:
            await agent_delegation.request_undelivered_child_cancellations(
                run.id,
                "Owning Agent Run requires tool recovery.",
            )
        except Exception:
            logger.exception(
                "failed to cancel Child Runs for tool recovery: %s",
                run.id,
            )

        async with get_async_session() as db:
            current_run, current_attempt = await self._require_attempt_lease(
                db,
                run.id,
                attempt.id,
            )
            agent_session = (await db.exec(select(AgentSession).where(
                AgentSession.id == current_run.session_id,
            ).with_for_update())).one()
            now = utc_now()
            await agent_delegation.discard_pending_child_continuations(
                db,
                current_run.id,
                now,
            )
            await sandbox_async_jobs.discard_pending_job_continuations(
                db,
                current_run.id,
                now,
            )
            events = await self._interrupt_persisted_segments(
                db,
                agent_session,
                current_run,
                current_attempt,
                now,
            )
            await self._rewind_attempt_context_items(
                db,
                current_run,
                current_attempt,
                now,
            )
            current_attempt.status = AgentAttemptStatus.INTERRUPTED
            current_attempt.finished_at = now
            current_attempt.error_code = "tool_recovery_required"
            current_attempt.error_message = reason
            current_run.status = AgentRunStatus.WAITING
            current_run.wait_reason = AgentRunWaitReason.TOOL_RECOVERY
            current_run.wait_reference_id = current_run.context_id
            current_run.finished_at = None
            current_run.error_code = ""
            current_run.error_message = ""
            db.add(current_attempt)
            db.add(current_run)
            events.extend([
                await append_event(db, agent_session, AttemptTransitionEvent(
                    id=str(uuid4()),
                    session_id=current_run.session_id,
                    run_id=current_run.id,
                    attempt_id=current_attempt.id,
                    seq=agent_session.next_event_seq,
                    occurred_at=now,
                    previous_status=AgentAttemptStatus.RUNNING,
                    status=AgentAttemptStatus.INTERRUPTED,
                    reason=reason,
                )),
                await append_event(db, agent_session, RunTransitionEvent(
                    id=str(uuid4()),
                    session_id=current_run.session_id,
                    run_id=current_run.id,
                    seq=agent_session.next_event_seq,
                    occurred_at=now,
                    previous_status=AgentRunStatus.RUNNING,
                    status=AgentRunStatus.WAITING,
                    reason=AgentRunWaitReason.TOOL_RECOVERY,
                )),
            ])
            await db.commit()
        for event in events:
            self._broadcast(run.session_id, AgentEventFrame(event=event))

    async def _claim(self, run_id: str) -> tuple[AgentRun, AgentRunAttempt, list[AgentDurableEvent]] | None:
        async with get_async_session() as db:
            await self._require_supervisor_lease(db)
            run = (await db.exec(select(AgentRun).where(AgentRun.id == run_id).with_for_update())).one_or_none()
            if (
                run is None
                or run.status != AgentRunStatus.QUEUED
                or run.cancel_requested_at is not None
            ):
                return None
            agent_session = (await db.exec(
                select(AgentSession).where(AgentSession.id == run.session_id).with_for_update()
            )).one()
            if await run_admission_block_reason(db, agent_session):
                return None
            if run.is_foreground:
                blocker = (await db.exec(select(AgentRun.id).where(
                    AgentRun.session_id == run.session_id,
                    AgentRun.id != run.id,
                    AgentRun.is_foreground.is_(True),
                    AgentRun.status.in_([AgentRunStatus.RUNNING, AgentRunStatus.WAITING]),
                ).limit(1))).first()
                if blocker is not None:
                    return None
            now = utc_now()
            run.status = AgentRunStatus.RUNNING
            run.started_at = run.started_at or now
            run.wait_reason = None
            run.wait_reference_id = None
            db.add(run)
            ordinal = int((await db.exec(select(func.count()).select_from(AgentRunAttempt).where(
                AgentRunAttempt.run_id == run.id
            ))).one()) + 1
            attempt = AgentRunAttempt(
                id=str(uuid4()),
                run_id=run.id,
                ordinal=ordinal,
                status=AgentAttemptStatus.RUNNING,
                trigger=run.trigger,
                model_config_snapshot=get_config().agents[str(run.agent_code)].model_dump(mode="json"),
                runtime_owner_id=self.owner_id,
                lease_fencing_token=self._fencing_token,
            )
            db.add(attempt)
            await db.flush()
            events: list[AgentDurableEvent] = []
            events.append(await append_event(db, agent_session, RunTransitionEvent(
                id=str(uuid4()), session_id=run.session_id, run_id=run.id,
                seq=agent_session.next_event_seq, occurred_at=now,
                previous_status=AgentRunStatus.QUEUED, status=AgentRunStatus.RUNNING,
            )))
            events.append(await append_event(db, agent_session, AttemptTransitionEvent(
                id=str(uuid4()), session_id=run.session_id, run_id=run.id, attempt_id=attempt.id,
                seq=agent_session.next_event_seq, occurred_at=now,
                status=AgentAttemptStatus.RUNNING,
            )))
            await db.commit()
            return run, attempt, events

    async def _build_context(self, run: AgentRun, attempt: AgentRunAttempt) -> AgentRuntimeContext:
        async with get_async_session() as db:
            agent_session = await db.get(AgentSession, run.session_id)
            user = await db.get(SystemUser, agent_session.owner_id) if agent_session else None
        if agent_session is None or user is None:
            raise RuntimeError("agent session owner is unavailable")
        context = AgentRuntimeContext(
            session_id=run.session_id,
            run_id=run.id,
            attempt_id=attempt.id,
            context_id=run.context_id,
            user=AgentUserContext(id=user.id, username=user.username, email=user.email, role=user.role),
            agent_code=str(run.agent_code),
            agent_instance_id=f"run:{run.id}",
            sandbox_container_id=run.sandbox_container_id,
            sandbox_container_generation=run.sandbox_generation,
            incident_id=agent_session.incident_id,
            environment_id=agent_session.environment_id,
            investigation_task_id=run.investigation_task_id,
            tool_invocation_runner=partial(
                agent_tool_invocations.invoke_tool,
                context_id=run.context_id,
                run_id=run.id,
                attempt_id=attempt.id,
                execution_fence=partial(
                    self._assert_attempt_fence,
                    run.id,
                    attempt.id,
                ),
            ),
        )
        sandbox_attempt_id = await sandbox_async_jobs.get_undelivered_async_job_attempt_id(run.id)
        child_run_id = await agent_delegation.get_undelivered_child_run_id(run.id)
        if sandbox_attempt_id is not None and child_run_id is not None:
            raise RuntimeError("Agent Run has conflicting durable wait dependencies")
        if sandbox_attempt_id is not None:
            context.wait_requested = True
            context.wait_reason = AgentRunWaitReason.SANDBOX_COMMAND
            context.wait_reference_id = sandbox_attempt_id
        elif child_run_id is not None:
            context.wait_requested = True
            context.wait_reason = AgentRunWaitReason.CHILD_RUN
            context.wait_reference_id = child_run_id
        return context

    async def _assert_attempt_fence(self, run_id: str, attempt_id: str, db) -> None:
        await self._require_attempt_lease(db, run_id, attempt_id)

    async def _consume_stream_event(self, run, attempt, event, segments: dict[str, _LiveSegment]) -> None:
        if isinstance(event, StreamDelta):
            segment = segments.get(event.segment_key)
            if segment is None:
                segment = await self._create_segment(run.id, attempt.id, event)
                segments[event.segment_key] = segment
            start_utf16_offset = _utf16_length(segment.text)
            segment.text = event.text
            end_utf16_offset = _utf16_length(segment.text)
            checkpoint_due = (
                end_utf16_offset - segment.persisted_utf16_offset >= _SEGMENT_CHECKPOINT_UTF16_UNITS
                or asyncio.get_running_loop().time() - segment.last_checkpoint_at >= 2.0
            )
            if checkpoint_due:
                await self._checkpoint_segment(
                    run.id,
                    attempt.id,
                    segment,
                    AgentSegmentStatus.STREAMING,
                )
            self._broadcast(run.session_id, AgentDeltaFrame(
                run_id=run.id,
                attempt_id=attempt.id,
                segment_id=segment.id,
                segment_kind=segment.kind,
                start_utf16_offset=start_utf16_offset,
                end_utf16_offset=end_utf16_offset,
                delta=event.delta,
            ))
            return
        if isinstance(event, StreamSegmentComplete):
            segment = segments.get(event.segment_key)
            if segment is None:
                segment = await self._create_segment(run.id, attempt.id, event)
                segments[event.segment_key] = segment
            segment.text = event.text
            await self._persist_completed_segment(run, attempt, segment)
            return
        if isinstance(event, StreamToolCall):
            durable = await self._persist_event(run, attempt, ToolCallEvent(
                id=str(uuid4()), session_id=run.session_id, run_id=run.id, attempt_id=attempt.id,
                seq=1, occurred_at=utc_now(), call_id=event.call_id,
                agent_code=str(run.agent_code), name=event.name, arguments=event.arguments,
            ))
            self._broadcast(run.session_id, AgentEventFrame(event=durable))
            return
        if isinstance(event, StreamToolResult):
            durable = await self._persist_event(run, attempt, ToolResultEvent(
                id=str(uuid4()), session_id=run.session_id, run_id=run.id, attempt_id=attempt.id,
                seq=1, occurred_at=utc_now(), call_id=event.call_id,
                agent_code=str(run.agent_code), output=event.output, is_error=event.is_error,
            ))
            self._broadcast(run.session_id, AgentEventFrame(event=durable))
            return
        if isinstance(event, StreamError):
            durable = await self._persist_event(run, attempt, AgentErrorEvent(
                id=str(uuid4()), session_id=run.session_id, run_id=run.id, attempt_id=attempt.id,
                seq=1, occurred_at=utc_now(), code=event.code, message=event.message,
            ))
            self._broadcast(run.session_id, AgentEventFrame(event=durable))

    async def _create_segment(
        self,
        run_id: str,
        attempt_id: str,
        event: StreamDelta | StreamSegmentComplete,
    ) -> _LiveSegment:
        segment = _LiveSegment(
            id=str(uuid4()),
            key=event.segment_key,
            kind=AgentSegmentKind(event.kind),
            last_checkpoint_at=asyncio.get_running_loop().time(),
        )
        async with get_async_session() as db:
            await self._require_attempt_lease(db, run_id, attempt_id)
            db.add(AgentSegment(
                id=segment.id,
                attempt_id=attempt_id,
                segment_key=segment.key,
                kind=segment.kind,
                status=AgentSegmentStatus.STREAMING,
            ))
            await db.commit()
        return segment

    async def _checkpoint_segment(
        self,
        run_id: str,
        attempt_id: str,
        segment: _LiveSegment,
        status: AgentSegmentStatus,
    ) -> None:
        async with get_async_session() as db:
            await self._require_attempt_lease(db, run_id, attempt_id)
            row = await db.get(AgentSegment, segment.id)
            if row is None:
                return
            row.text = segment.text
            row.persisted_utf16_offset = _utf16_length(segment.text)
            row.status = status
            row.updated_at = utc_now()
            db.add(row)
            await db.commit()
        segment.persisted_utf16_offset = _utf16_length(segment.text)
        segment.last_checkpoint_at = asyncio.get_running_loop().time()

    async def _persist_completed_segment(self, run, attempt, segment: _LiveSegment) -> None:
        await self._checkpoint_segment(
            run.id,
            attempt.id,
            segment,
            AgentSegmentStatus.COMPLETED,
        )
        durable = await self._persist_event(run, attempt, SegmentCompletedEvent(
            id=str(uuid4()), session_id=run.session_id, run_id=run.id, attempt_id=attempt.id,
            seq=1, occurred_at=utc_now(), segment_id=segment.id,
            segment_kind=segment.kind, status=AgentSegmentStatus.COMPLETED,
            agent_code=str(run.agent_code), text=segment.text,
        ))
        self._broadcast(run.session_id, AgentEventFrame(event=durable))

    async def _complete_open_segments(self, run, attempt, segments: dict[str, _LiveSegment]) -> None:
        async with get_async_session() as db:
            completed = set((await db.exec(select(AgentSegment.id).where(
                AgentSegment.attempt_id == attempt.id,
                AgentSegment.status == AgentSegmentStatus.COMPLETED,
            ))).all())
        for segment in segments.values():
            if segment.id not in completed:
                await self._persist_completed_segment(run, attempt, segment)

    async def _checkpoint_live_segments_if_owned(
        self,
        run_id: str,
        attempt_id: str,
        segments: dict[str, _LiveSegment],
    ) -> None:
        for segment in segments.values():
            try:
                await self._checkpoint_segment(
                    run_id,
                    attempt_id,
                    segment,
                    AgentSegmentStatus.STREAMING,
                )
            except _ExecutionLeaseLost:
                return

    async def _persist_event(self, run, attempt, event: AgentDurableEvent) -> AgentDurableEvent:
        async with get_async_session() as db:
            await self._require_attempt_lease(db, run.id, attempt.id)
            agent_session = (await db.exec(
                select(AgentSession).where(AgentSession.id == run.session_id).with_for_update()
            )).one()
            durable = await append_event(db, agent_session, event)
            await db.commit()
            return durable

    async def _require_supervisor_lease(self, db) -> RuntimeLease:
        lease = (await db.exec(select(RuntimeLease).where(
            RuntimeLease.name == _LEASE_NAME,
        ).with_for_update())).one_or_none()
        if (
            lease is None
            or lease.owner_id != self.owner_id
            or lease.fencing_token != self._fencing_token
            or lease.expires_at <= utc_now()
        ):
            raise _ExecutionLeaseLost("Agent runtime supervisor lease is no longer current")
        return lease

    async def _require_attempt_lease(
        self,
        db,
        run_id: str,
        attempt_id: str,
    ) -> tuple[AgentRun, AgentRunAttempt]:
        lease = await self._require_supervisor_lease(db)
        run = (await db.exec(select(AgentRun).where(
            AgentRun.id == run_id,
        ).with_for_update())).one_or_none()
        attempt = (await db.exec(select(AgentRunAttempt).where(
            AgentRunAttempt.id == attempt_id,
            AgentRunAttempt.run_id == run_id,
        ).with_for_update())).one_or_none()
        if (
            run is None
            or attempt is None
            or run.status != AgentRunStatus.RUNNING
            or attempt.status != AgentAttemptStatus.RUNNING
            or lease.owner_id != attempt.runtime_owner_id
            or lease.fencing_token != attempt.lease_fencing_token
        ):
            raise _ExecutionLeaseLost("Agent Run execution lease is no longer current")
        return run, attempt

    async def _finish_run(
        self,
        run_id,
        attempt_id,
        session_id,
        *,
        waiting,
        wait_reason,
        wait_reference_id,
        usage,
        result_summary,
    ) -> None:
        has_wait_state = wait_reason is not None and bool(wait_reference_id)
        if waiting != has_wait_state:
            raise RuntimeError("Agent Run wait state is incomplete")
        async with get_async_session() as db:
            run, attempt = await self._require_attempt_lease(db, run_id, attempt_id)
            agent_session = (await db.exec(select(AgentSession).where(
                AgentSession.id == session_id
            ).with_for_update())).one()
            now = utc_now()
            if not waiting:
                await agent_delegation.discard_pending_child_continuations(db, run.id, now)
                await sandbox_async_jobs.discard_pending_job_continuations(db, run.id, now)
            attempt.status = AgentAttemptStatus.SUCCEEDED
            attempt.finished_at = now
            attempt.usage = usage
            run.status = AgentRunStatus.WAITING if waiting else AgentRunStatus.SUCCEEDED
            run.wait_reason = wait_reason if waiting else None
            run.wait_reference_id = wait_reference_id if waiting else None
            run.finished_at = None if waiting else now
            run.result_summary = result_summary
            db.add(attempt)
            db.add(run)
            events = [
                await append_event(db, agent_session, AttemptTransitionEvent(
                    id=str(uuid4()), session_id=session_id, run_id=run_id, attempt_id=attempt_id,
                    seq=agent_session.next_event_seq, occurred_at=now,
                    previous_status=AgentAttemptStatus.RUNNING, status=AgentAttemptStatus.SUCCEEDED,
                )),
                await append_event(db, agent_session, RunTransitionEvent(
                    id=str(uuid4()), session_id=session_id, run_id=run_id,
                    seq=agent_session.next_event_seq, occurred_at=now,
                    previous_status=AgentRunStatus.RUNNING,
                    status=run.status,
                    reason=str(run.wait_reason or ""),
                )),
            ]
            if waiting and wait_reason == AgentRunWaitReason.CHILD_RUN:
                await agent_delegation.queue_parent_from_finished_wait_reference(db, run_id)
            elif not waiting and run.parent_run_id is not None:
                await agent_delegation.queue_parent_continuation(
                    db,
                    run,
                    status=AgentRunStatus.SUCCEEDED,
                    summary=result_summary,
                )
            await db.commit()
        for event in events:
            self._broadcast(session_id, AgentEventFrame(event=event))

    async def _fail_run(self, run, attempt, exc: Exception) -> None:
        message = str(exc) or type(exc).__name__
        try:
            await sandbox_async_jobs.cancel_running_async_jobs_for_run(
                run.id,
                "Owning Agent Run failed.",
            )
        except Exception:
            logger.exception("failed to cancel Sandbox Jobs for failed Agent Run: %s", run.id)
        try:
            await agent_delegation.request_undelivered_child_cancellations(
                run.id,
                "Owning Agent Run failed.",
            )
        except Exception:
            logger.exception("failed to cancel Child Runs for failed Agent Run: %s", run.id)
        lease_lost = False
        async with get_async_session() as db:
            try:
                current_run, current_attempt = await self._require_attempt_lease(
                    db,
                    run.id,
                    attempt.id,
                )
            except _ExecutionLeaseLost:
                lease_lost = True
            if not lease_lost:
                agent_session = (await db.exec(select(AgentSession).where(
                    AgentSession.id == run.session_id
                ).with_for_update())).one()
                now = utc_now()
                await agent_delegation.discard_pending_child_continuations(
                    db,
                    current_run.id,
                    now,
                )
                await sandbox_async_jobs.discard_pending_job_continuations(
                    db,
                    current_run.id,
                    now,
                )
                segment_events = await self._interrupt_persisted_segments(
                    db,
                    agent_session,
                    current_run,
                    current_attempt,
                    now,
                )
                await self._rewind_attempt_context_items(db, current_run, current_attempt, now)
                current_attempt.status = AgentAttemptStatus.FAILED
                current_attempt.finished_at = now
                current_attempt.error_code = type(exc).__name__
                current_attempt.error_message = message
                current_run.status = AgentRunStatus.FAILED
                current_run.wait_reason = None
                current_run.wait_reference_id = None
                current_run.finished_at = now
                current_run.error_code = type(exc).__name__
                current_run.error_message = message
                db.add(current_attempt)
                db.add(current_run)
                attempt_event = await append_event(db, agent_session, AttemptTransitionEvent(
                    id=str(uuid4()), session_id=run.session_id, run_id=run.id, attempt_id=attempt.id,
                    seq=agent_session.next_event_seq, occurred_at=now,
                    previous_status=AgentAttemptStatus.RUNNING,
                    status=AgentAttemptStatus.FAILED,
                    reason=message,
                ))
                error_event = await append_event(db, agent_session, AgentErrorEvent(
                    id=str(uuid4()), session_id=run.session_id, run_id=run.id, attempt_id=attempt.id,
                    seq=agent_session.next_event_seq, occurred_at=now,
                    code=type(exc).__name__, message=message,
                ))
                run_event = await append_event(db, agent_session, RunTransitionEvent(
                    id=str(uuid4()), session_id=run.session_id, run_id=run.id,
                    seq=agent_session.next_event_seq, occurred_at=now,
                    previous_status=AgentRunStatus.RUNNING, status=AgentRunStatus.FAILED, reason=message,
                ))
                if current_run.parent_run_id is not None:
                    await agent_delegation.queue_parent_continuation(
                        db,
                        current_run,
                        status=AgentRunStatus.FAILED,
                        summary=message,
                    )
                await db.commit()
        if lease_lost:
            return
        for event in segment_events:
            self._broadcast(run.session_id, AgentEventFrame(event=event))
        self._broadcast(run.session_id, AgentEventFrame(event=attempt_event))
        self._broadcast(run.session_id, AgentEventFrame(event=error_event))
        self._broadcast(run.session_id, AgentEventFrame(event=run_event))

    async def _cancel_persisted_run(
        self,
        run_id: str,
        *,
        mode: AgentCancellationMode,
        actor: str,
        resume_parent: bool,
    ) -> bool:
        from core.sandbox.command_jobs import cancel_run_async_sandbox_commands

        async with get_async_session() as db:
            await self._require_supervisor_lease(db)
        await cancel_run_async_sandbox_commands(run_id)
        await agent_delegation.request_undelivered_child_cancellations(
            run_id,
            actor or "Owning Agent Run canceled.",
        )
        async with get_async_session() as db:
            await self._require_supervisor_lease(db)
            run = (await db.exec(select(AgentRun).where(AgentRun.id == run_id).with_for_update())).one_or_none()
            if run is None or run.status in _TERMINAL_RUN_STATUSES:
                return False
            attempt = (await db.exec(select(AgentRunAttempt).where(
                AgentRunAttempt.run_id == run_id,
                AgentRunAttempt.status == AgentAttemptStatus.RUNNING,
            ).order_by(AgentRunAttempt.ordinal.desc()).limit(1).with_for_update())).one_or_none()
            agent_session = (await db.exec(select(AgentSession).where(
                AgentSession.id == run.session_id
            ).with_for_update())).one()
            previous = run.status
            now = utc_now()
            await agent_delegation.discard_pending_child_continuations(db, run.id, now)
            await sandbox_async_jobs.discard_pending_job_continuations(db, run.id, now)
            run.cancel_requested_at = run.cancel_requested_at or now
            run.cancel_requested_by = run.cancel_requested_by or actor
            run.cancel_requested_mode = run.cancel_requested_mode or mode
            run.status = AgentRunStatus.CANCELED
            run.wait_reason = None
            run.wait_reference_id = None
            run.canceled_at = now
            run.finished_at = now
            run.canceled_by = actor
            db.add(run)
            events: list[AgentDurableEvent] = []
            if attempt is not None:
                events.extend(await self._interrupt_persisted_segments(
                    db,
                    agent_session,
                    run,
                    attempt,
                    now,
                ))
                await self._rewind_attempt_context_items(db, run, attempt, now)
                attempt.status = (
                    AgentAttemptStatus.INTERRUPTED
                    if mode == AgentCancellationMode.INTERRUPT
                    else AgentAttemptStatus.CANCELED
                )
                attempt.finished_at = now
                db.add(attempt)
                events.append(await append_event(db, agent_session, AttemptTransitionEvent(
                    id=str(uuid4()), session_id=run.session_id, run_id=run.id, attempt_id=attempt.id,
                    seq=agent_session.next_event_seq, occurred_at=now,
                    previous_status=AgentAttemptStatus.RUNNING, status=attempt.status, reason=actor,
                )))
            events.append(await append_event(db, agent_session, RunTransitionEvent(
                id=str(uuid4()), session_id=run.session_id, run_id=run.id,
                seq=agent_session.next_event_seq, occurred_at=now,
                previous_status=previous, status=AgentRunStatus.CANCELED, reason=actor,
            )))
            if resume_parent and run.parent_run_id is not None:
                await agent_delegation.queue_parent_continuation(
                    db,
                    run,
                    status=AgentRunStatus.CANCELED,
                    summary=f"Delegated run canceled: {actor}",
                )
            await db.commit()
        for event in events:
            self._broadcast(run.session_id, AgentEventFrame(event=event))
        return True

    async def _requeue_interrupted_run(self, run_id: str, attempt_id: str, *, reason: str) -> None:
        async with get_async_session() as db:
            await self._require_supervisor_lease(db)
            run = (await db.exec(select(AgentRun).where(
                AgentRun.id == run_id
            ).with_for_update())).one_or_none()
            attempt = (await db.exec(select(AgentRunAttempt).where(
                AgentRunAttempt.id == attempt_id,
                AgentRunAttempt.run_id == run_id,
            ).with_for_update())).one_or_none()
            if (
                run is None
                or attempt is None
                or run.status != AgentRunStatus.RUNNING
                or attempt.status != AgentAttemptStatus.RUNNING
            ):
                return
            agent_session = (await db.exec(select(AgentSession).where(
                AgentSession.id == run.session_id
            ).with_for_update())).one()
            now = utc_now()
            events: list[AgentDurableEvent] = []
            events.extend(await self._interrupt_persisted_segments(
                db,
                agent_session,
                run,
                attempt,
                now,
            ))
            await self._rewind_attempt_context_items(db, run, attempt, now)
            attempt.status = AgentAttemptStatus.INTERRUPTED
            attempt.finished_at = now
            attempt.error_code = "runtime_interrupted"
            attempt.error_message = reason
            db.add(attempt)
            events.append(await append_event(db, agent_session, AttemptTransitionEvent(
                id=str(uuid4()),
                session_id=run.session_id,
                run_id=run.id,
                attempt_id=attempt.id,
                seq=agent_session.next_event_seq,
                occurred_at=now,
                previous_status=AgentAttemptStatus.RUNNING,
                status=AgentAttemptStatus.INTERRUPTED,
                reason=reason,
            )))
            run.status = AgentRunStatus.QUEUED
            run.wait_reason = None
            run.wait_reference_id = None
            run.error_code = ""
            run.error_message = ""
            run.finished_at = None
            db.add(run)
            queued_event = await append_event(db, agent_session, RunTransitionEvent(
                id=str(uuid4()),
                session_id=run.session_id,
                run_id=run.id,
                seq=agent_session.next_event_seq,
                occurred_at=now,
                previous_status=AgentRunStatus.RUNNING,
                status=AgentRunStatus.QUEUED,
                reason=reason,
            ))
            events.append(queued_event)
            enqueue_outbox_event(
                db,
                AgentRunReadyPayload(run_id=run.id, event_id=queued_event.id),
                idempotency_key=f"recovery:{attempt.id}",
            )
            await db.commit()
        for event in events:
            self._broadcast(run.session_id, AgentEventFrame(event=event))

    async def _interrupt_persisted_segments(
        self,
        db,
        agent_session: AgentSession,
        run: AgentRun,
        attempt: AgentRunAttempt,
        now,
    ) -> list[AgentDurableEvent]:
        events: list[AgentDurableEvent] = []
        segments = list((await db.exec(select(AgentSegment).where(
            AgentSegment.attempt_id == attempt.id,
            AgentSegment.status == AgentSegmentStatus.STREAMING,
        ).with_for_update())).all())
        for segment in segments:
            segment.status = AgentSegmentStatus.INTERRUPTED
            segment.updated_at = now
            db.add(segment)
            events.append(await append_event(db, agent_session, SegmentCompletedEvent(
                id=str(uuid4()),
                session_id=run.session_id,
                run_id=run.id,
                attempt_id=attempt.id,
                seq=agent_session.next_event_seq,
                occurred_at=now,
                segment_id=segment.id,
                segment_kind=segment.kind,
                status=AgentSegmentStatus.INTERRUPTED,
                agent_code=str(run.agent_code),
                text=segment.text,
            )))
        return events

    async def _rewind_attempt_context_items(
        self,
        db,
        run: AgentRun,
        attempt: AgentRunAttempt,
        now,
    ) -> None:
        succeeded_call_ids = set((await db.exec(select(AgentToolInvocation.call_id).where(
            AgentToolInvocation.attempt_id == attempt.id,
            AgentToolInvocation.status == AgentToolInvocationStatus.SUCCEEDED,
        ))).all())
        preserved_dedupe_keys = {
            key
            for call_id in succeeded_call_ids
            for key in (f"tool:call:{call_id}", f"tool:output:{call_id}")
        }
        rows = list((await db.exec(select(AgentContextItem).where(
            AgentContextItem.context_id == run.context_id,
            AgentContextItem.provenance_attempt_id == attempt.id,
            AgentContextItem.status == AgentContextItemStatus.ACTIVE,
        ).with_for_update())).all())
        input_item_id = _run_input_item_id(run.id, run.trigger_revision)
        for row in rows:
            is_run_input = row.item.get("id") == input_item_id and row.item.get("role") == "user"
            if is_run_input or row.dedupe_key in preserved_dedupe_keys:
                continue
            row.status = AgentContextItemStatus.REWOUND
            row.retired_at = now
            db.add(row)

    async def _recover_interrupted_attempts(self) -> None:
        async with get_async_session() as db:
            await self._require_supervisor_lease(db)
            attempts = list((await db.exec(select(
                AgentRunAttempt.id,
                AgentRunAttempt.run_id,
            ).where(
                AgentRunAttempt.status == AgentAttemptStatus.RUNNING
            ))).all())
        for attempt_id, run_id in attempts:
            await self._requeue_interrupted_run(
                run_id,
                attempt_id,
                reason="runtime restarted during model invocation",
            )

    async def _hello(self, session_id: str) -> AgentHelloFrame:
        async with get_async_session() as db:
            agent_session = await db.get(AgentSession, session_id)
            if agent_session is None:
                raise KeyError("agent session not found")
            active_runs = list((await db.exec(select(AgentRun.id).where(
                AgentRun.session_id == session_id,
                AgentRun.status.in_([AgentRunStatus.RUNNING, AgentRunStatus.WAITING]),
            ))).all())
            rows = list((await db.exec(select(AgentSegment, AgentRunAttempt, AgentRun).join(
                AgentRunAttempt, AgentRunAttempt.id == AgentSegment.attempt_id
            ).join(AgentRun, AgentRun.id == AgentRunAttempt.run_id).where(
                AgentRun.session_id == session_id,
                AgentSegment.status == AgentSegmentStatus.STREAMING,
            ))).all())
        return AgentHelloFrame(
            session_id=session_id,
            durable_head_seq=max(0, agent_session.next_event_seq - 1),
            active_run_ids=active_runs,
            segments=[AgentSegmentSnapshot(
                segment_id=segment.id,
                run_id=run.id,
                attempt_id=attempt.id,
                segment_kind=segment.kind,
                status=segment.status,
                text=segment.text,
                persisted_utf16_offset=segment.persisted_utf16_offset,
            ) for segment, attempt, run in rows],
        )

    def _broadcast(self, session_id: str, frame: AgentServerFrame) -> None:
        if isinstance(frame, AgentEventFrame):
            self._durable_heads[session_id] = max(
                self._durable_heads.get(session_id, 0),
                frame.event.seq,
            )
        for subscription in tuple(self._subscribers.get(session_id, ())):
            if subscription.closed:
                continue
            if subscription.replaying:
                if len(subscription.pending_frames) >= _SUBSCRIBER_QUEUE_SIZE:
                    self._terminate_overflow(session_id, subscription)
                else:
                    subscription.pending_frames.append(frame)
                continue
            self._enqueue_frame(session_id, subscription, frame)

    def _enqueue_frame(
        self,
        session_id: str,
        subscription: AgentStreamSubscription,
        frame: AgentServerFrame,
    ) -> None:
        if subscription.closed:
            return
        if subscription.queue.full():
            self._terminate_overflow(session_id, subscription)
            return
        _offer(subscription.queue, frame)

    def _terminate_overflow(self, session_id: str, subscription: AgentStreamSubscription) -> None:
        subscription.closed = True
        subscription.pending_frames.clear()
        while not subscription.queue.empty():
            try:
                subscription.queue.get_nowait()
            except asyncio.QueueEmpty:
                break
        _offer(subscription.queue, AgentRebaseRequiredFrame(
            durable_head_seq=self._durable_heads.get(session_id, 0),
            reason="subscriber exceeded the recoverable live stream window",
        ))
        _offer(subscription.queue, None)


def _offer(queue: asyncio.Queue[AgentServerFrame | None], frame: AgentServerFrame | None) -> None:
    try:
        queue.put_nowait(frame)
    except asyncio.QueueFull:
        pass


def _trim_replayed_delta(frame: AgentDeltaFrame, expected_offset: int) -> AgentDeltaFrame | None:
    if frame.end_utf16_offset <= expected_offset:
        return None
    if frame.start_utf16_offset == expected_offset:
        return frame
    prefix_units = expected_offset - frame.start_utf16_offset
    delta_bytes = frame.delta.encode("utf-16-le")
    trimmed_delta = delta_bytes[prefix_units * 2:].decode("utf-16-le")
    return frame.model_copy(update={
        "start_utf16_offset": expected_offset,
        "delta": trimmed_delta,
    })


def _utf16_length(value: str) -> int:
    return len(value.encode("utf-16-le")) // 2


def _usage_payload(usage) -> dict[str, int]:
    return {
        "requests": int(usage.requests),
        "input_tokens": int(usage.input_tokens),
        "output_tokens": int(usage.output_tokens),
        "total_tokens": int(usage.total_tokens),
    }


def _result_summary(segments: dict[str, _LiveSegment]) -> str:
    texts = [segment.text for segment in segments.values() if segment.kind == AgentSegmentKind.TEXT and segment.text]
    return "\n\n".join(texts)[-20_000:]


def _run_input_item_id(run_id: str, trigger_revision: int) -> str:
    return f"v3il-run-{run_id}-trigger-{trigger_revision}"
