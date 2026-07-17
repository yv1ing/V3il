from dataclasses import dataclass

from sqlmodel import select

from database import get_async_session
from model.deception.environments import DeceptionEnvironment, DeceptionRevision
from schema.deception.environments import DeceptionEnvironmentStatus, DeceptionRevisionStatus
from schema.deception.workloads import (
    CreateObservedWorkloadRequest,
    ListObservedWorkloadsResponse,
    ObservedWorkloadSchema,
)
from schema.system_user.users import SystemUserRole
from service.sandbox.observer import (
    list_observed_workloads,
    start_observed_workload,
    stop_observed_workload,
)


@dataclass(frozen=True)
class ObservedWorkloadResult:
    workload: ObservedWorkloadSchema | None = None
    workloads: ListObservedWorkloadsResponse | None = None
    not_found: bool = False
    forbidden: bool = False
    conflict: bool = False
    message: str = ""


@dataclass(frozen=True)
class _ManageableEnvironment:
    status: DeceptionEnvironmentStatus
    sandbox_container_id: int | None
    active_revision_id: int | None
    active_revision_status: DeceptionRevisionStatus | None


async def start_deception_workload(
    environment_id: int,
    request: CreateObservedWorkloadRequest,
    *,
    user_id: int,
    user_role: SystemUserRole,
) -> ObservedWorkloadResult:
    environment, error = await _load_manageable_environment(environment_id, user_id, user_role)
    if error is not None:
        return error
    if environment is None:
        raise RuntimeError("manageable deception environment was not loaded")
    if environment.active_revision_status != DeceptionRevisionStatus.EXECUTING:
        return ObservedWorkloadResult(
            conflict=True,
            message="workloads can only start while the active revision is executing",
        )
    try:
        if environment.sandbox_container_id is None:
            return ObservedWorkloadResult(conflict=True, message="deception environment has no sandbox container")
        workload = await start_observed_workload(environment.sandbox_container_id, request)
    except FileNotFoundError:
        return ObservedWorkloadResult(not_found=True, message="sandbox container is not running")
    except ValueError as exc:
        return ObservedWorkloadResult(conflict=True, message=str(exc))
    return ObservedWorkloadResult(workload=workload)


async def list_deception_workloads(
    environment_id: int,
    *,
    user_id: int,
    user_role: SystemUserRole,
) -> ObservedWorkloadResult:
    environment, error = await _load_manageable_environment(environment_id, user_id, user_role)
    if error is not None:
        return error
    if environment is None:
        raise RuntimeError("manageable deception environment was not loaded")
    try:
        if environment.sandbox_container_id is None:
            return ObservedWorkloadResult(workloads=ListObservedWorkloadsResponse(items=[]))
        workloads = await list_observed_workloads(environment.sandbox_container_id)
    except FileNotFoundError:
        return ObservedWorkloadResult(workloads=ListObservedWorkloadsResponse(items=[]))
    return ObservedWorkloadResult(workloads=workloads)


async def stop_deception_workload(
    environment_id: int,
    run_id: str,
    *,
    user_id: int,
    user_role: SystemUserRole,
) -> ObservedWorkloadResult:
    environment, error = await _load_manageable_environment(environment_id, user_id, user_role)
    if error is not None:
        return error
    if environment is None:
        raise RuntimeError("manageable deception environment was not loaded")
    if (
        environment.status != DeceptionEnvironmentStatus.RETIRED
        and environment.active_revision_status != DeceptionRevisionStatus.EXECUTING
    ):
        return ObservedWorkloadResult(
            conflict=True,
            message="workloads can only stop while the active revision is executing or the environment is retired",
        )
    try:
        if environment.sandbox_container_id is None:
            return ObservedWorkloadResult(conflict=True, message="deception environment has no sandbox container")
        workload = await stop_observed_workload(environment.sandbox_container_id, run_id)
    except FileNotFoundError:
        return ObservedWorkloadResult(not_found=True, message="observed workload not found")
    return ObservedWorkloadResult(workload=workload)


async def _load_manageable_environment(
    environment_id: int,
    user_id: int,
    user_role: SystemUserRole,
) -> tuple[_ManageableEnvironment | None, ObservedWorkloadResult | None]:
    async with get_async_session() as session:
        row = (await session.exec(select(
            DeceptionEnvironment.owner_id,
            DeceptionEnvironment.status,
            DeceptionEnvironment.sandbox_container_id,
            DeceptionEnvironment.active_revision_id,
        ).where(DeceptionEnvironment.id == environment_id))).one_or_none()
        if row is None:
            return None, ObservedWorkloadResult(not_found=True, message="deception environment not found")
        owner_id, status, sandbox_container_id, active_revision_id = row
        if user_role != SystemUserRole.ADMIN and owner_id != user_id:
            return None, ObservedWorkloadResult(
                forbidden=True,
                message="deception environment is not manageable by user",
            )
        active_revision_status = None
        if active_revision_id is not None:
            active_revision_status = (await session.exec(select(DeceptionRevision.status).where(
                DeceptionRevision.id == active_revision_id,
                DeceptionRevision.environment_id == environment_id,
            ))).one_or_none()
        return _ManageableEnvironment(
            status=status,
            sandbox_container_id=sandbox_container_id,
            active_revision_id=active_revision_id,
            active_revision_status=active_revision_status,
        ), None
