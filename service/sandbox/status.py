import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from sqlmodel import select

from database import get_async_session
from logger import get_logger
from model.deception.environments import DeceptionEnvironment
from model.host.hosts import ManagedHost
from model.sandbox.containers import SandboxContainer
from schema.sandbox.containers import SandboxContainerStatus
from schema.system_user.users import SystemUserRole
from service.agent.sandbox_selection import (
    clear_session_sandbox_container_bindings,
    refresh_session_sandbox_container_generation,
)
from service.host.state import ManagedHostConnection, snapshot_managed_host
from service.sandbox.docker_ops import (
    DockerContainerState,
    docker_status_to_sandbox_status,
    inspect_container_state_sync,
)
from service.sandbox.locking import try_sandbox_container_mutation_lock
from service.sandbox.records import load_sandbox_container_record
from service.sandbox.types import (
    SandboxContainerRecord,
    SandboxContainerSelection,
    SandboxContainerToolBinding,
)
from service.threat.control_plane import (
    ContainerRuntimeEvidence,
    record_container_runtime_state,
)
from utils.time import utc_now


logger = get_logger(__name__)

_STATUS_MONITOR_INTERVAL_SECONDS = 5
_STATUS_MONITOR_BATCH_SIZE = 32
_TOOL_BINDING_INSPECT_TTL_SECONDS = 3
_status_monitor_task: asyncio.Task[None] | None = None
_tool_invalidation_tasks: set[asyncio.Task[None]] = set()
_tool_binding_state_cache: dict[int, "DockerStateCacheEntry"] = {}
_AgentToolBindingInvalidator = Callable[[int | None], Awaitable[None]]
_agent_tool_binding_invalidator: _AgentToolBindingInvalidator | None = None
_StatusEventOrchestrator = Callable[[int, list[int]], Awaitable[object]]
_status_event_orchestrator: _StatusEventOrchestrator | None = None


@dataclass(frozen=True)
class ContainerStatusSnapshot:
    id: int
    host_id: int
    container_hash: str
    status: SandboxContainerStatus


@dataclass(frozen=True)
class DockerStateCacheEntry:
    host_id: int
    container_hash: str
    generation: int
    state: DockerContainerState
    expires_at: float


def set_agent_tool_binding_invalidator(callback: _AgentToolBindingInvalidator | None) -> None:
    global _agent_tool_binding_invalidator
    _agent_tool_binding_invalidator = callback


def set_sandbox_status_event_orchestrator(callback: _StatusEventOrchestrator | None) -> None:
    global _status_event_orchestrator
    _status_event_orchestrator = callback


async def save_sandbox_container_status(
    id: int,
    status: SandboxContainerStatus,
) -> SandboxContainerRecord | None:
    async with get_async_session() as session:
        sandbox_container = (await session.exec(
            select(SandboxContainer).where(SandboxContainer.id == id).with_for_update()
        )).one_or_none()
        if sandbox_container is None:
            return None

        previous_status = sandbox_container.status
        if (
            status == SandboxContainerStatus.RUNNING
            and previous_status not in {SandboxContainerStatus.RUNNING, SandboxContainerStatus.PAUSED}
        ):
            sandbox_container.generation += 1
        sandbox_container.status = status
        sandbox_container.updated_at = utc_now()
        session.add(sandbox_container)
        if status == SandboxContainerStatus.RUNNING:
            await refresh_session_sandbox_container_generation(
                session,
                sandbox_container_id=id,
                sandbox_container_generation=status_generation(sandbox_container),
            )
        else:
            await clear_session_sandbox_container_bindings(
                session,
                sandbox_container_id=id,
            )
        await session.commit()

    _schedule_agent_tool_invalidation(id)
    return await load_sandbox_container_record(id)


def status_generation(sandbox_container: SandboxContainer) -> int:
    return sandbox_container.generation


def _clear_tool_binding_state_cache(container_id: int | None = None) -> None:
    if container_id is None:
        _tool_binding_state_cache.clear()
        return
    _tool_binding_state_cache.pop(container_id, None)


async def inspect_container_state_cached(
    *,
    id: int,
    host_id: int,
    container_hash: str,
    generation: int,
) -> DockerContainerState:
    now = time.monotonic()
    cached = _tool_binding_state_cache.get(id)
    if (
        cached is not None
        and cached.host_id == host_id
        and cached.container_hash == container_hash
        and cached.generation == generation
        and cached.expires_at > now
    ):
        return cached.state

    host = await _load_host(host_id)
    if host is None:
        return DockerContainerState(exists=False)
    state = await asyncio.to_thread(inspect_container_state_sync, host, container_hash)
    _tool_binding_state_cache[id] = DockerStateCacheEntry(
        host_id=host_id,
        container_hash=container_hash,
        generation=generation,
        state=state,
        expires_at=now + _TOOL_BINDING_INSPECT_TTL_SECONDS,
    )
    return state


def _schedule_agent_tool_invalidation(container_id: int) -> None:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        logger.debug("no running loop for agent tool invalidation: %s", container_id)
        return

    task = loop.create_task(
        invalidate_agent_tool_bindings(container_id),
        name=f"agent-tool-invalidate-{container_id}",
    )
    _tool_invalidation_tasks.add(task)
    task.add_done_callback(_tool_invalidation_tasks.discard)


async def invalidate_agent_tool_bindings(container_id: int) -> None:
    _clear_tool_binding_state_cache(container_id)
    try:
        if _agent_tool_binding_invalidator is not None:
            await _agent_tool_binding_invalidator(container_id)
    except Exception:
        logger.exception("agent tool binding invalidation failed: %s", container_id)


async def _invalidate_all_agent_tool_bindings() -> None:
    _clear_tool_binding_state_cache()
    if _tool_invalidation_tasks:
        await asyncio.gather(*tuple(_tool_invalidation_tasks), return_exceptions=True)
    try:
        if _agent_tool_binding_invalidator is not None:
            await _agent_tool_binding_invalidator(None)
    except Exception:
        logger.exception("agent tool binding invalidation failed")


async def _load_container_status_snapshots() -> list[ContainerStatusSnapshot]:
    statement = (
        select(
            SandboxContainer.id,
            SandboxContainer.host_id,
            SandboxContainer.container_hash,
            SandboxContainer.status,
        )
        .where(SandboxContainer.container_hash != "")
    )
    async with get_async_session() as session:
        result = await session.exec(statement)
        return [
            ContainerStatusSnapshot(id=row[0], host_id=row[1], container_hash=row[2], status=row[3])
            for row in result.all()
        ]


async def sync_container_status(snapshot: ContainerStatusSnapshot) -> None:
    async with try_sandbox_container_mutation_lock(snapshot.id) as acquired:
        if not acquired:
            return
        await sync_container_status_unlocked(snapshot)


async def sync_container_status_unlocked(
    snapshot: ContainerStatusSnapshot,
    *,
    capture_unexpected: bool = True,
) -> None:
    host = await _load_host(snapshot.host_id)
    if host is None:
        await _save_observed_sandbox_container_status(
            snapshot,
            DockerContainerState(exists=False, status="managed_host_unavailable"),
            SandboxContainerStatus.ERROR,
            capture_unexpected=capture_unexpected,
        )
        return
    try:
        state = await asyncio.to_thread(inspect_container_state_sync, host, snapshot.container_hash)
    except Exception as exc:
        state = _docker_inspect_error_state(exc)
        await _save_observed_sandbox_container_status(
            snapshot,
            state,
            SandboxContainerStatus.ERROR,
            capture_unexpected=capture_unexpected,
        )
        logger.warning(
            "sandbox container inspect failed during status sync: %s",
            snapshot.id,
            exc_info=True,
        )
        return
    next_status = SandboxContainerStatus.ERROR if not state.exists else docker_status_to_sandbox_status(state.status)
    if next_status == snapshot.status:
        return

    await _save_observed_sandbox_container_status(
        snapshot,
        state,
        next_status,
        capture_unexpected=capture_unexpected,
    )
    logger.debug(
        "sandbox container status synced: %s %s -> %s",
        snapshot.id,
        snapshot.status,
        next_status,
    )


async def save_observed_sandbox_container_status(
    snapshot: ContainerStatusSnapshot,
    state: DockerContainerState,
) -> SandboxContainerRecord | None:
    next_status = (
        SandboxContainerStatus.ERROR
        if not state.exists
        else docker_status_to_sandbox_status(state.status)
    )
    async with try_sandbox_container_mutation_lock(snapshot.id) as acquired:
        if not acquired:
            return await load_sandbox_container_record(snapshot.id)
        current = await load_sandbox_container_record(snapshot.id)
        if current is None or current.container.status == next_status:
            return current
        current_snapshot = ContainerStatusSnapshot(
            id=snapshot.id,
            host_id=current.container.host_id,
            container_hash=current.container.container_hash,
            status=current.container.status,
        )
        return await _save_observed_sandbox_container_status(
            current_snapshot,
            state,
            next_status,
            capture_unexpected=True,
        )


async def _save_observed_sandbox_container_status(
    snapshot: ContainerStatusSnapshot,
    state: DockerContainerState,
    next_status: SandboxContainerStatus,
    *,
    capture_unexpected: bool,
) -> SandboxContainerRecord | None:
    evidence: ContainerRuntimeEvidence | None = None
    if capture_unexpected or next_status == SandboxContainerStatus.RUNNING:
        evidence = await record_container_runtime_state(
            snapshot.id,
            previous_status=snapshot.status,
            observed_status=next_status,
            docker_status=state.status,
            container_exists=(
                None
                if state.status == "managed_host_unavailable" or state.status.startswith("inspect_error:")
                else state.exists
            ),
        )
    record = await save_sandbox_container_status(snapshot.id, next_status)
    if evidence is not None:
        await _orchestrate_status_evidence(evidence)
    return record


async def _orchestrate_status_evidence(evidence: ContainerRuntimeEvidence) -> None:
    environment_id, event_ids = evidence
    if not event_ids or _status_event_orchestrator is None:
        return
    try:
        await _status_event_orchestrator(environment_id, list(event_ids))
    except Exception:
        logger.exception(
            "sandbox status evidence orchestration failed: environment=%s events=%s",
            environment_id,
            event_ids,
        )


def docker_inspect_error_state(error: Exception) -> DockerContainerState:
    return _docker_inspect_error_state(error)


def _docker_inspect_error_state(error: Exception) -> DockerContainerState:
    detail = f"inspect_error:{type(error).__name__}:{error}"
    return DockerContainerState(exists=False, status=detail[:4000])


async def sync_sandbox_container_statuses() -> None:
    snapshots = await _load_container_status_snapshots()
    for offset in range(0, len(snapshots), _STATUS_MONITOR_BATCH_SIZE):
        await asyncio.gather(*(
            _sync_container_status_safely(snapshot)
            for snapshot in snapshots[offset:offset + _STATUS_MONITOR_BATCH_SIZE]
        ))


async def _sync_container_status_safely(snapshot: ContainerStatusSnapshot) -> None:
    try:
        await sync_container_status(snapshot)
    except Exception:
        logger.exception("sandbox container status sync failed: %s", snapshot.id)


async def _status_monitor_loop() -> None:
    while True:
        try:
            await sync_sandbox_container_statuses()
            await asyncio.sleep(_STATUS_MONITOR_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("sandbox container status monitor iteration failed")
            await asyncio.sleep(_STATUS_MONITOR_INTERVAL_SECONDS)


async def start_sandbox_container_status_monitor() -> None:
    global _status_monitor_task
    if _status_monitor_task is not None and not _status_monitor_task.done():
        return
    _status_monitor_task = asyncio.create_task(
        _status_monitor_loop(),
        name="sandbox-container-status-monitor",
    )
    logger.info("sandbox container status monitor started")


async def stop_sandbox_container_status_monitor() -> None:
    global _status_monitor_task
    task, _status_monitor_task = _status_monitor_task, None
    if task is None or task.done():
        await _drain_tool_invalidation_tasks()
        return
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    await _drain_tool_invalidation_tasks()
    logger.info("sandbox container status monitor stopped")


async def invalidate_all_agent_tool_bindings() -> None:
    await _invalidate_all_agent_tool_bindings()


async def _drain_tool_invalidation_tasks() -> None:
    tasks = tuple(_tool_invalidation_tasks)
    if not tasks:
        return
    await asyncio.gather(*tasks, return_exceptions=True)


async def resolve_sandbox_container_tool_binding(
    id: int,
    user_id: int,
    user_role: SystemUserRole,
) -> SandboxContainerToolBinding | None:
    return await _resolve_sandbox_container_tool_binding(
        id=id,
        can_use=lambda container: (
            user_role == SystemUserRole.ADMIN
            or container.owner_id == user_id
        ),
        allow_deception_bound=False,
    )


async def resolve_sandbox_container_selection(
    id: int,
    user_id: int,
    user_role: SystemUserRole,
) -> SandboxContainerSelection | None:
    async with get_async_session() as session:
        sandbox_container = await session.get(SandboxContainer, id)
        if sandbox_container is None or sandbox_container.status != SandboxContainerStatus.RUNNING:
            return None
        if user_role != SystemUserRole.ADMIN and sandbox_container.owner_id != user_id:
            return None
        if await _sandbox_container_has_deception_binding(session, id):
            return None
        return SandboxContainerSelection(
            id=id,
            generation=status_generation(sandbox_container),
        )


async def resolve_bound_sandbox_container_tool_binding(
    id: int,
) -> SandboxContainerToolBinding | None:
    return await _resolve_sandbox_container_tool_binding(
        id=id,
        can_use=lambda _: True,
        allow_deception_bound=True,
    )


async def _resolve_sandbox_container_tool_binding(
    id: int,
    can_use: Callable[[SandboxContainer], bool],
    allow_deception_bound: bool,
) -> SandboxContainerToolBinding | None:
    async with get_async_session() as session:
        sandbox_container = await session.get(SandboxContainer, id)
        if sandbox_container is None:
            return None
        if sandbox_container.status != SandboxContainerStatus.RUNNING:
            return None
        if not can_use(sandbox_container):
            return None
        if not allow_deception_bound and await _sandbox_container_has_deception_binding(session, id):
            return None
        container_hash = sandbox_container.container_hash
        host_id = sandbox_container.host_id
        generation = status_generation(sandbox_container)

    try:
        state = await inspect_container_state_cached(
            id=id,
            host_id=host_id,
            container_hash=container_hash,
            generation=generation,
        )
    except Exception as exc:
        logger.exception("sandbox container inspect failed before tool binding: %s", id)
        await save_observed_sandbox_container_status(
            ContainerStatusSnapshot(
                id=id,
                host_id=host_id,
                container_hash=container_hash,
                status=SandboxContainerStatus.RUNNING,
            ),
            _docker_inspect_error_state(exc),
        )
        return None

    status = SandboxContainerStatus.ERROR if not state.exists else docker_status_to_sandbox_status(state.status)
    if status != SandboxContainerStatus.RUNNING:
        await save_observed_sandbox_container_status(
            ContainerStatusSnapshot(
                id=id,
                host_id=host_id,
                container_hash=container_hash,
                status=SandboxContainerStatus.RUNNING,
            ),
            state,
        )
        return None

    return SandboxContainerToolBinding(id=id, generation=generation)


async def _sandbox_container_has_deception_binding(session, id: int) -> bool:
    result = await session.exec(
        select(DeceptionEnvironment.id)
        .where(DeceptionEnvironment.sandbox_container_id == id)
        .limit(1)
    )
    return result.first() is not None


async def _load_host(host_id: int) -> ManagedHostConnection | None:
    async with get_async_session() as session:
        host = await session.get(ManagedHost, host_id)
        return snapshot_managed_host(host) if host is not None else None
