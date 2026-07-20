import asyncio
import hashlib
import json
from dataclasses import dataclass, replace
from datetime import timedelta

from sqlmodel import select

from utils.time import utc_now

from database import get_async_session
from logger import get_logger
from model.deception.environments import DeceptionArtifact, DeceptionEnvironment, DeceptionRevision, DeceptionRevisionStep
from model.sandbox.containers import SandboxContainer
from schema.deception.environments import (
    DeceptionContainerOwnership,
    DeceptionContainerSpec,
    DeceptionEnvironmentSchema,
    DeceptionEnvironmentStatus,
    DeceptionRevisionKind,
    DeceptionRevisionBaselineSnapshot,
    DeceptionRevisionExecutionCheckpoint,
    DeceptionRevisionStatus,
    DeceptionRevisionStepStatus,
)
from schema.sandbox.containers import SandboxContainerPortMapping, SandboxContainerStatus
from schema.system_user.users import SystemUserRole
from schema.threat.investigations import AuditActorType, AuditEventKind
from service.deception.environments import (
    DeceptionRevisionMutationResult,
    serialize_deception_revision,
)
from service.agent.sandbox_selection import set_environment_session_sandbox_container
from service.deception.references import (
    copy_reference_bundle_to_container,
    finalize_reference_bundle,
)
from service.deception.lifecycle import (
    DeceptionLifecycle,
    DeceptionLifecycleError,
    apply_revision,
    begin_rollback_recovery,
    fail_unstarted_revision,
    finish_rollback,
    require_active_revision,
    restore_interrupted_claim,
)
from service.sandbox.commands import execute_sandbox_container_command
from service.sandbox.lifecycle import (
    create_sandbox_container,
    delete_revision_sandbox_container,
    start_sandbox_container,
)
from service.sandbox.status import status_generation
from service.runtime.leases import RuntimeLeaseUnavailable, runtime_lease
from service.threat.audit import add_audit_event


logger = get_logger(__name__)
_OUTPUT_LIMIT = 8000


@dataclass(frozen=True)
class _RevisionStepCommand:
    id: int
    sequence: int
    apply_command: str
    verify_command: str
    rollback_command: str
    timeout_seconds: int
    status: DeceptionRevisionStepStatus


@dataclass(frozen=True)
class _ClaimedRevision:
    environment_id: int
    revision_id: int
    container_id: int | None
    container_generation: int
    steps: tuple[_RevisionStepCommand, ...]
    initial: bool
    reference_urls: tuple[str, ...]
    owner_id: int
    container_spec: DeceptionContainerSpec | None


async def execute_deception_revision(environment_id: int, revision_id: int, *, user_id: int, user_role: SystemUserRole, agent_code: str = "", session_id: str = "", incident_id: int | None = None, investigation_task_id: int | None = None):
    try:
        async with runtime_lease(
            _revision_lease_name(revision_id),
            wait_timeout_seconds=0,
        ) as lease:
            return await _execute_claimed_revision(
                environment_id,
                revision_id,
                user_id=user_id,
                user_role=user_role,
                agent_code=agent_code,
                session_id=session_id,
                incident_id=incident_id,
                investigation_task_id=investigation_task_id,
                lease=lease,
            )
    except RuntimeLeaseUnavailable:
        return DeceptionRevisionMutationResult(
            revision=None,
            environment=None,
            conflict=True,
            message="deception revision is already executing",
        )


async def _execute_claimed_revision(
    environment_id: int,
    revision_id: int,
    *,
    user_id: int,
    user_role: SystemUserRole,
    agent_code: str,
    session_id: str,
    incident_id: int | None,
    investigation_task_id: int | None,
    lease,
):
    claimed, result = await _claim_revision(
        environment_id,
        revision_id,
        user_id=user_id,
        user_role=user_role,
        agent_code=agent_code,
        session_id=session_id,
        incident_id=incident_id,
        investigation_task_id=investigation_task_id,
    )
    if claimed is None:
        return result
    try:
        await lease.assert_owned()
        if claimed.initial and claimed.container_id is None:
            claimed, result = await _provision_initial_revision(claimed)
            if claimed is None:
                return result
            await lease.assert_owned()
        if claimed.container_id is None:
            raise RuntimeError("claimed deception revision has no execution container")
        if claimed.initial:
            await lease.assert_owned()
            await copy_reference_bundle_to_container(
                claimed.environment_id,
                list(claimed.reference_urls),
                claimed.container_id,
            )
            await lease.assert_owned()
        for step in claimed.steps:
            await _apply_and_verify(
                claimed.container_id,
                claimed.container_generation,
                step,
                lease,
            )
        await lease.assert_owned()
        return await _complete(claimed)
    except asyncio.CancelledError:
        await asyncio.shield(_rollback(claimed, "Revision execution was canceled.", lease=lease))
        raise
    except Exception as exc:
        logger.warning("deception revision failed: %s", revision_id, exc_info=True)
        return await _rollback(claimed, str(exc) or "Revision execution failed.", lease=lease)


async def recover_interrupted_deception_revisions():
    try:
        async with runtime_lease("deception-revision-recovery", wait_timeout_seconds=0):
            async with get_async_session() as session:
                revisions = list((await session.exec(select(
                    DeceptionRevision.id,
                    DeceptionRevision.environment_id,
                    DeceptionRevision.status,
                ).where(
                    DeceptionRevision.status.in_({DeceptionRevisionStatus.EXECUTING, DeceptionRevisionStatus.ROLLING_BACK})
                ))).all())
            for revision_id, environment_id, status in revisions:
                await _recover_interrupted_revision(revision_id, environment_id, status)
    except RuntimeLeaseUnavailable:
        return


async def _recover_interrupted_revision(revision_id, environment_id, status) -> None:
    try:
        async with runtime_lease(
            _revision_lease_name(revision_id),
            wait_timeout_seconds=20,
        ) as lease:
            claimed = await _load_claimed(environment_id, revision_id)
            if claimed is None:
                await _mark_interrupted_recovery_required(
                    environment_id,
                    revision_id,
                    "Interrupted revision is missing its execution journal.",
                )
                return
            if (
                status == DeceptionRevisionStatus.EXECUTING
                and all(step.status == DeceptionRevisionStepStatus.PENDING for step in claimed.steps)
                and await _restore_unstarted_revision(claimed)
            ):
                return
            await _rollback(claimed, "Recovered interrupted revision.", lease=lease)
    except RuntimeLeaseUnavailable:
        return
    except Exception:
        logger.exception(
            "interrupted deception revision recovery failed: revision=%s environment=%s",
            revision_id,
            environment_id,
        )
        await _mark_interrupted_recovery_required(
            environment_id,
            revision_id,
            "Interrupted revision could not be reconstructed safely.",
        )


async def recover_deception_revision_rollback(
    environment_id: int,
    revision_id: int,
    *,
    user_id: int,
    user_role: SystemUserRole,
    agent_code: str = "",
    session_id: str = "",
) -> DeceptionRevisionMutationResult:
    try:
        async with runtime_lease(
            _revision_lease_name(revision_id),
            wait_timeout_seconds=0,
        ) as lease:
            return await _recover_deception_revision_rollback_owned(
                environment_id,
                revision_id,
                user_id=user_id,
                user_role=user_role,
                agent_code=agent_code,
                session_id=session_id,
                lease=lease,
            )
    except RuntimeLeaseUnavailable:
        return DeceptionRevisionMutationResult(
            revision=None,
            environment=None,
            conflict=True,
            message="deception revision is already executing",
        )


async def _recover_deception_revision_rollback_owned(
    environment_id: int,
    revision_id: int,
    *,
    user_id: int,
    user_role: SystemUserRole,
    agent_code: str,
    session_id: str,
    lease,
) -> DeceptionRevisionMutationResult:
    claimed, result, previous_error = await _claim_rollback_recovery(
        environment_id,
        revision_id,
        user_id=user_id,
        user_role=user_role,
        agent_code=agent_code,
        session_id=session_id,
    )
    if claimed is None:
        return result
    return await _rollback(
        claimed,
        f"Rollback recovery requested after: {previous_error}",
        report_original_failure=False,
        lease=lease,
    )


async def _claim_revision(environment_id, revision_id, *, user_id, user_role, agent_code, session_id, incident_id, investigation_task_id):
    async with get_async_session() as session, session.begin():
        environment = (await session.exec(select(DeceptionEnvironment).where(DeceptionEnvironment.id == environment_id).with_for_update())).one_or_none()
        revision = (await session.exec(select(DeceptionRevision).where(
            DeceptionRevision.id == revision_id,
            DeceptionRevision.environment_id == environment_id,
        ).with_for_update())).one_or_none()
        if environment is None or revision is None:
            return None, DeceptionRevisionMutationResult(revision=None, environment=None, not_found=True)
        if user_role != SystemUserRole.ADMIN and environment.owner_id != user_id:
            return None, DeceptionRevisionMutationResult(revision=None, environment=None, forbidden=True)
        try:
            require_active_revision(
                DeceptionLifecycle.from_environment(environment),
                revision_id,
                revision.status,
                DeceptionRevisionStatus.PLANNED,
            )
        except DeceptionLifecycleError as exc:
            return None, DeceptionRevisionMutationResult(
                revision=None,
                environment=None,
                conflict=True,
                message=str(exc),
            )
        step_rows = tuple((await session.exec(select(DeceptionRevisionStep).where(
            DeceptionRevisionStep.revision_id == revision_id
        ).order_by(DeceptionRevisionStep.sequence.asc()).with_for_update())).all())
        if not step_rows:
            return None, DeceptionRevisionMutationResult(revision=None, environment=None, conflict=True, message="revision has no executable steps")
        if any(step.status != DeceptionRevisionStepStatus.PENDING for step in step_rows):
            return None, DeceptionRevisionMutationResult(
                revision=None,
                environment=None,
                conflict=True,
                message="a planned revision must contain only pending steps",
            )
        try:
            _validate_frozen_plan(revision, step_rows)
        except ValueError as exc:
            return None, DeceptionRevisionMutationResult(
                revision=None,
                environment=None,
                conflict=True,
                message=str(exc),
            )
        container_spec = None
        initial = revision.kind == DeceptionRevisionKind.INITIAL
        if initial != (environment.applied_revision_id is None):
            return None, DeceptionRevisionMutationResult(
                revision=None,
                environment=None,
                conflict=True,
                message="revision kind does not match the environment baseline",
            )
        if initial:
            container_spec = DeceptionContainerSpec.model_validate(revision.container_spec)
        try:
            container = await _resolve_execution_container(
                session,
                environment,
                revision,
                lock=True,
            )
        except RuntimeError as exc:
            return None, DeceptionRevisionMutationResult(
                revision=None,
                environment=None,
                conflict=True,
                message=str(exc),
            )
        container_id = container.id if container is not None else None
        if container is None:
            if revision.kind != DeceptionRevisionKind.INITIAL:
                return None, DeceptionRevisionMutationResult(revision=None, environment=None, conflict=True, message="environment has no sandbox container")
        else:
            if environment.sandbox_container_id is None:
                return None, DeceptionRevisionMutationResult(
                    revision=None,
                    environment=None,
                    conflict=True,
                    message="an unbound revision container requires rollback recovery",
                )
            if container.status != SandboxContainerStatus.RUNNING:
                return None, DeceptionRevisionMutationResult(
                    revision=None,
                    environment=None,
                    conflict=True,
                    message="environment sandbox container must be running before revision execution",
                )
            revision.execution_container_id = container_id
        baseline = DeceptionRevisionBaselineSnapshot(
            environment_status=environment.status,
            persona=environment.persona,
            services=environment.services,
            applied_revision_id=environment.applied_revision_id,
            container=_container_state(container),
            recorded_at=utc_now(),
        )
        revision.baseline_snapshot = baseline.model_dump(mode="json")
        revision.execution_checkpoint = DeceptionRevisionExecutionCheckpoint(
            phase="claimed",
            step_sequence=None,
            container=_container_state(container),
            recorded_at=utc_now(),
        ).model_dump(mode="json")
        claimed = _ClaimedRevision(
            environment_id=environment_id,
            revision_id=revision_id,
            container_id=container_id,
            container_generation=status_generation(container) if container is not None else 0,
            steps=tuple(_snapshot_step(step) for step in step_rows),
            initial=initial,
            reference_urls=tuple(environment.reference_urls),
            owner_id=environment.owner_id,
            container_spec=container_spec,
        )
        revision.status = DeceptionRevisionStatus.EXECUTING
        revision.started_at = utc_now()
        environment.status = DeceptionEnvironmentStatus.BUILDING if revision.kind == DeceptionRevisionKind.INITIAL else DeceptionEnvironmentStatus.ADAPTING
        environment.last_error = ""
        session.add(revision)
        session.add(environment)
        await add_audit_event(
            session,
            incident_id=incident_id,
            environment_id=environment_id,
            task_id=investigation_task_id,
            kind=AuditEventKind.REVISION,
            actor_type=AuditActorType.AGENT if agent_code else AuditActorType.USER,
            actor_code=agent_code or str(user_id),
            session_id=session_id,
            object_type="deception_revision",
            object_id=revision_id,
            summary="Deception revision execution started.",
        )
    return claimed, DeceptionRevisionMutationResult(revision=None, environment=None)


async def _claim_rollback_recovery(
    environment_id: int,
    revision_id: int,
    *,
    user_id: int,
    user_role: SystemUserRole,
    agent_code: str,
    session_id: str,
) -> tuple[_ClaimedRevision | None, DeceptionRevisionMutationResult, str]:
    async with get_async_session() as session, session.begin():
        environment = (await session.exec(select(DeceptionEnvironment).where(
            DeceptionEnvironment.id == environment_id,
        ).with_for_update())).one_or_none()
        revision = (await session.exec(select(DeceptionRevision).where(
            DeceptionRevision.id == revision_id,
            DeceptionRevision.environment_id == environment_id,
        ).with_for_update())).one_or_none()
        if environment is None or revision is None:
            return None, DeceptionRevisionMutationResult(
                revision=None,
                environment=None,
                not_found=True,
            ), ""
        if user_role != SystemUserRole.ADMIN and environment.owner_id != user_id:
            return None, DeceptionRevisionMutationResult(
                revision=None,
                environment=None,
                forbidden=True,
            ), ""
        try:
            next_environment_status = begin_rollback_recovery(
                DeceptionLifecycle.from_environment(environment),
                revision_id,
                revision.status,
            )
            container = await _resolve_execution_container(
                session,
                environment,
                revision,
                lock=True,
            )
        except (DeceptionLifecycleError, RuntimeError) as exc:
            return None, DeceptionRevisionMutationResult(
                revision=None,
                environment=None,
                conflict=True,
                message=str(exc),
            ), ""
        step_rows = tuple((await session.exec(select(DeceptionRevisionStep).where(
            DeceptionRevisionStep.revision_id == revision_id,
        ).order_by(DeceptionRevisionStep.sequence.asc()).with_for_update())).all())
        if not step_rows:
            return None, DeceptionRevisionMutationResult(
                revision=None,
                environment=None,
                conflict=True,
                message="rollback recovery requires the revision step journal",
            ), ""
        previous_error = (
            revision.failure_reason
            or revision.result
            or environment.last_error
            or "unknown revision failure"
        )
        revision.status = DeceptionRevisionStatus.ROLLING_BACK
        revision.resolved_at = None
        environment.status = next_environment_status
        environment.updated_at = utc_now()
        session.add(revision)
        session.add(environment)
        await add_audit_event(
            session,
            environment_id=environment_id,
            kind=AuditEventKind.REVISION,
            actor_type=AuditActorType.AGENT if agent_code else AuditActorType.USER,
            actor_code=agent_code or str(user_id),
            session_id=session_id,
            object_type="deception_revision",
            object_id=revision_id,
            summary="Deception revision rollback recovery started.",
        )
        claimed = _ClaimedRevision(
            environment_id=environment_id,
            revision_id=revision_id,
            container_id=container.id if container is not None else None,
            container_generation=status_generation(container) if container is not None else 0,
            steps=tuple(_snapshot_step(step) for step in step_rows),
            initial=revision.kind == DeceptionRevisionKind.INITIAL,
            reference_urls=tuple(environment.reference_urls),
            owner_id=environment.owner_id,
            container_spec=(
                DeceptionContainerSpec.model_validate(revision.container_spec)
                if revision.kind == DeceptionRevisionKind.INITIAL
                else None
            ),
        )
    return claimed, DeceptionRevisionMutationResult(revision=None, environment=None), previous_error


async def _provision_initial_revision(
    claimed: _ClaimedRevision,
) -> tuple[_ClaimedRevision | None, DeceptionRevisionMutationResult]:
    spec = claimed.container_spec
    if spec is None:
        return None, await _fail_claimed_revision(claimed, "Initial revision has no container specification.")
    created = await create_sandbox_container(
        spec.host_id,
        spec.image_id,
        spec.egress_mode,
        spec.egress_proxy_id,
        claimed.owner_id,
        [],
        port_requirements=[
            (requirement.container_port, requirement.protocol)
            for requirement in spec.port_requirements
        ],
        provisioned_for_revision_id=claimed.revision_id,
    )
    if not created.succeeded or created.record is None or created.record.container.id is None:
        return None, await _fail_claimed_revision(
            claimed,
            created.message or "Sandbox container provisioning failed.",
        )
    container_id = created.record.container.id
    resolved_spec = spec.model_copy(deep=True)
    resolved_spec.port_requirements = []
    resolved_spec.port_mappings = [
        SandboxContainerPortMapping.model_validate(item)
        for item in created.record.container.port_mappings
    ]
    try:
        await _bind_initial_container(claimed, container_id, resolved_spec)
    except Exception as exc:
        logger.exception("initial deception container binding failed: revision=%s", claimed.revision_id)
        return None, await _fail_claimed_revision(
            claimed,
            str(exc) or "Sandbox container could not be bound to the initial revision.",
            container_id=container_id,
        )
    started = await start_sandbox_container(container_id)
    if not started.succeeded or started.record is None:
        return None, await _fail_claimed_revision(
            claimed,
            started.message or "Sandbox container failed to start.",
            container_id=container_id,
        )
    try:
        await _bind_initial_session_container(claimed, container_id)
    except Exception as exc:
        logger.exception("initial deception session binding failed: revision=%s", claimed.revision_id)
        return None, await _fail_claimed_revision(
            claimed,
            str(exc) or "Sandbox container could not be bound to the environment session.",
            container_id=container_id,
        )
    return replace(
        claimed,
        container_id=container_id,
        container_generation=started.record.container.generation,
        container_spec=resolved_spec,
    ), DeceptionRevisionMutationResult(revision=None, environment=None)


async def _bind_initial_container(
    claimed: _ClaimedRevision,
    container_id: int,
    spec: DeceptionContainerSpec,
) -> None:
    async with get_async_session() as session, session.begin():
        environment = (await session.exec(select(DeceptionEnvironment).where(
            DeceptionEnvironment.id == claimed.environment_id,
        ).with_for_update())).one()
        revision = (await session.exec(select(DeceptionRevision).where(
            DeceptionRevision.id == claimed.revision_id,
        ).with_for_update())).one()
        container = (await session.exec(select(SandboxContainer).where(
            SandboxContainer.id == container_id,
        ).with_for_update())).one()
        if (
            revision.status != DeceptionRevisionStatus.EXECUTING
            or environment.active_revision_id != claimed.revision_id
            or environment.sandbox_container_id is not None
            or container.provisioned_for_revision_id != claimed.revision_id
        ):
            raise RuntimeError("initial revision claim is no longer current")
        environment.sandbox_container_id = container_id
        revision.execution_container_id = container_id
        revision.container_spec = spec.model_dump(mode="json")
        session.add(environment)
        session.add(revision)


async def _bind_initial_session_container(
    claimed: _ClaimedRevision,
    container_id: int,
) -> None:
    async with get_async_session() as session, session.begin():
        environment = (await session.exec(select(DeceptionEnvironment).where(
            DeceptionEnvironment.id == claimed.environment_id,
        ).with_for_update())).one()
        revision = (await session.exec(select(DeceptionRevision).where(
            DeceptionRevision.id == claimed.revision_id,
        ).with_for_update())).one()
        container = (await session.exec(select(SandboxContainer).where(
            SandboxContainer.id == container_id,
        ).with_for_update())).one()
        if (
            revision.status != DeceptionRevisionStatus.EXECUTING
            or environment.active_revision_id != claimed.revision_id
            or environment.sandbox_container_id != container_id
            or revision.execution_container_id != container_id
            or container.provisioned_for_revision_id != claimed.revision_id
            or container.status != SandboxContainerStatus.RUNNING
        ):
            raise RuntimeError("initial revision container binding is no longer current")
        await set_environment_session_sandbox_container(
            session,
            environment_id=claimed.environment_id,
            sandbox_container_id=container_id,
            sandbox_container_generation=status_generation(container),
        )


async def _fail_claimed_revision(
    claimed: _ClaimedRevision,
    message: str,
    *,
    container_id: int | None = None,
) -> DeceptionRevisionMutationResult:
    cleanup_succeeded = True
    if container_id is not None:
        cleanup_succeeded = await delete_revision_sandbox_container(
            container_id,
            environment_id=claimed.environment_id,
            revision_id=claimed.revision_id,
        )
    async with get_async_session() as session, session.begin():
        environment = (await session.exec(select(DeceptionEnvironment).where(
            DeceptionEnvironment.id == claimed.environment_id,
        ).with_for_update())).one_or_none()
        revision = (await session.exec(select(DeceptionRevision).where(
            DeceptionRevision.id == claimed.revision_id,
        ).with_for_update())).one_or_none()
        if environment is None or revision is None:
            return DeceptionRevisionMutationResult(revision=None, environment=None, not_found=True)
        if container_id is not None and not cleanup_succeeded:
            environment.sandbox_container_id = container_id
            revision.execution_container_id = container_id
        if cleanup_succeeded:
            terminal = fail_unstarted_revision(
                DeceptionLifecycle.from_environment(environment),
                claimed.revision_id,
            )
            revision.status = DeceptionRevisionStatus.FAILED
        else:
            terminal = finish_rollback(
                DeceptionLifecycle.from_environment(environment),
                claimed.revision_id,
                succeeded=False,
            )
            revision.status = DeceptionRevisionStatus.RECOVERY_REQUIRED
            revision.rollback_error = "platform container cleanup failed"
        revision.failure_reason = message
        final_message = (
            f"{message}; rollback failures: {revision.rollback_error}"
            if revision.rollback_error
            else message
        )
        revision.result = final_message
        revision.resolved_at = None if not cleanup_succeeded else utc_now()
        environment.status = terminal.environment_status
        environment.applied_revision_id = terminal.applied_revision_id
        environment.active_revision_id = terminal.active_revision_id
        environment.last_error = final_message
        session.add(revision)
        session.add(environment)
        return DeceptionRevisionMutationResult(
            revision=await serialize_deception_revision(session, revision),
            environment=DeceptionEnvironmentSchema.model_validate(environment),
            conflict=True,
            message=final_message,
        )


async def _mark_interrupted_recovery_required(
    environment_id: int,
    revision_id: int,
    message: str,
) -> None:
    async with get_async_session() as session, session.begin():
        environment = (await session.exec(select(DeceptionEnvironment).where(
            DeceptionEnvironment.id == environment_id,
        ).with_for_update())).one_or_none()
        revision = (await session.exec(select(DeceptionRevision).where(
            DeceptionRevision.id == revision_id,
        ).with_for_update())).one_or_none()
        if revision is None or environment is None:
            return
        if environment.active_revision_id != revision_id:
            logger.error(
                "interrupted revision is not active: revision=%s environment=%s active_revision=%s",
                revision_id,
                environment_id,
                environment.active_revision_id,
            )
            return
        revision.status = DeceptionRevisionStatus.RECOVERY_REQUIRED
        revision.failure_reason = revision.failure_reason or message
        revision.rollback_error = message
        revision.result = message
        revision.resolved_at = None
        session.add(revision)
        environment.status = DeceptionEnvironmentStatus.RECOVERY_REQUIRED
        environment.last_error = message
        environment.updated_at = utc_now()
        session.add(environment)


async def _restore_unstarted_revision(claimed: _ClaimedRevision) -> bool:
    async with get_async_session() as session, session.begin():
        environment = (await session.exec(select(DeceptionEnvironment).where(
            DeceptionEnvironment.id == claimed.environment_id,
        ).with_for_update())).one_or_none()
        revision = (await session.exec(select(DeceptionRevision).where(
            DeceptionRevision.id == claimed.revision_id,
        ).with_for_update())).one_or_none()
        if (
            environment is None
            or revision is None
            or revision.status != DeceptionRevisionStatus.EXECUTING
            or environment.active_revision_id != claimed.revision_id
            or (
                claimed.container_id is not None
                and environment.sandbox_container_id != claimed.container_id
            )
        ):
            return False
        if claimed.container_id is not None:
            container = (await session.exec(select(SandboxContainer).where(
                SandboxContainer.id == claimed.container_id,
            ).with_for_update())).one_or_none()
            if container is None or container.status != SandboxContainerStatus.RUNNING:
                return False
        non_pending_step_id = (await session.exec(select(DeceptionRevisionStep.id).where(
            DeceptionRevisionStep.revision_id == claimed.revision_id,
            DeceptionRevisionStep.status != DeceptionRevisionStepStatus.PENDING,
        ).with_for_update().limit(1))).first()
        if non_pending_step_id is not None:
            return False
        revision.status = DeceptionRevisionStatus.PLANNED
        revision.started_at = None
        revision.resolved_at = None
        revision.result = ""
        environment.status = restore_interrupted_claim(
            DeceptionLifecycle.from_environment(environment),
            claimed.revision_id,
        )
        environment.last_error = ""
        environment.updated_at = utc_now()
        session.add(revision)
        session.add(environment)
        if claimed.container_id is not None:
            await set_environment_session_sandbox_container(
                session,
                environment_id=claimed.environment_id,
                sandbox_container_id=claimed.container_id,
                sandbox_container_generation=status_generation(container),
            )
        await add_audit_event(
            session,
            environment_id=claimed.environment_id,
            kind=AuditEventKind.REVISION,
            actor_type=AuditActorType.SYSTEM,
            object_type="deception_revision",
            object_id=claimed.revision_id,
            summary="Interrupted deception revision restored to planned before any step executed.",
        )
    return True


async def _apply_and_verify(
    container_id: int,
    container_generation: int,
    step: _RevisionStepCommand,
    lease,
):
    await _update_step(
        step.id,
        expected={DeceptionRevisionStepStatus.PENDING},
        status=DeceptionRevisionStepStatus.APPLYING,
        started_at=utc_now(),
        before_state=await _capture_container_state(container_id),
    )
    await lease.assert_owned()
    applied = await execute_sandbox_container_command(
        container_id,
        step.apply_command,
        step.timeout_seconds,
        expected_generation=container_generation,
    )
    await lease.assert_owned()
    if applied.exit_code != 0:
        await _update_step(step.id, expected={DeceptionRevisionStepStatus.APPLYING}, status=DeceptionRevisionStepStatus.FAILED, apply_exit_code=applied.exit_code, apply_output=applied.output[:_OUTPUT_LIMIT], error="apply command failed", finished_at=utc_now())
        raise RuntimeError(_step_failure_message(step.sequence, "apply", applied.exit_code, applied.output))
    await _update_step(
        step.id,
        expected={DeceptionRevisionStepStatus.APPLYING},
        status=DeceptionRevisionStepStatus.APPLIED,
        apply_exit_code=applied.exit_code,
        apply_output=applied.output[:_OUTPUT_LIMIT],
        after_apply_state=await _capture_container_state(container_id),
    )
    await _update_step(step.id, expected={DeceptionRevisionStepStatus.APPLIED}, status=DeceptionRevisionStepStatus.VERIFYING)
    await lease.assert_owned()
    verified = await execute_sandbox_container_command(
        container_id,
        step.verify_command,
        step.timeout_seconds,
        expected_generation=container_generation,
    )
    await lease.assert_owned()
    if verified.exit_code != 0:
        await _update_step(step.id, expected={DeceptionRevisionStepStatus.VERIFYING}, status=DeceptionRevisionStepStatus.FAILED, verify_exit_code=verified.exit_code, verify_output=verified.output[:_OUTPUT_LIMIT], error="verification command failed", finished_at=utc_now())
        raise RuntimeError(_step_failure_message(step.sequence, "verification", verified.exit_code, verified.output))
    await _update_step(
        step.id,
        expected={DeceptionRevisionStepStatus.VERIFYING},
        status=DeceptionRevisionStepStatus.VERIFIED,
        verify_exit_code=verified.exit_code,
        verify_output=verified.output[:_OUTPUT_LIMIT],
        after_verify_state=await _capture_container_state(container_id),
        finished_at=utc_now(),
    )


async def _rollback(
    claimed: _ClaimedRevision,
    reason: str,
    *,
    report_original_failure: bool = True,
    lease,
):
    await lease.assert_owned()
    async with get_async_session() as session, session.begin():
        revision = (await session.exec(select(DeceptionRevision).where(
            DeceptionRevision.id == claimed.revision_id,
        ).with_for_update())).one_or_none()
        environment = (await session.exec(select(DeceptionEnvironment).where(
            DeceptionEnvironment.id == claimed.environment_id,
        ).with_for_update())).one_or_none()
        if revision is None or environment is None:
            return DeceptionRevisionMutationResult(revision=None, environment=None, not_found=True)
        if environment.active_revision_id != claimed.revision_id or revision.status not in {
            DeceptionRevisionStatus.EXECUTING,
            DeceptionRevisionStatus.ROLLING_BACK,
            DeceptionRevisionStatus.RECOVERY_REQUIRED,
        }:
            return DeceptionRevisionMutationResult(
                revision=None,
                environment=None,
                conflict=True,
                message="revision is no longer eligible for rollback",
            )
        revision.status = DeceptionRevisionStatus.ROLLING_BACK
        revision.failure_reason = revision.failure_reason or reason
        revision.rollback_error = ""
        revision.result = revision.failure_reason
        session.add(revision)
        environment.status = (
            DeceptionEnvironmentStatus.BUILDING
            if environment.applied_revision_id is None
            else DeceptionEnvironmentStatus.ADAPTING
        )
        environment.last_error = reason
        session.add(environment)
    rollback_failures: list[str] = []
    for step in reversed(claimed.steps):
        async with get_async_session() as session:
            current_status = (await session.exec(select(DeceptionRevisionStep.status).where(
                DeceptionRevisionStep.id == step.id
            ))).one_or_none()
        if current_status in {
            None,
            DeceptionRevisionStepStatus.PENDING,
            DeceptionRevisionStepStatus.ROLLED_BACK,
        }:
            continue
        await _update_step(
            step.id,
            expected={current_status},
            status=DeceptionRevisionStepStatus.ROLLING_BACK,
        )
        try:
            if claimed.container_id is None:
                raise RuntimeError("revision rollback has no execution container")
            await lease.assert_owned()
            result = await execute_sandbox_container_command(
                claimed.container_id,
                step.rollback_command,
                step.timeout_seconds,
                expected_generation=claimed.container_generation,
            )
            await lease.assert_owned()
            step_failed = result.exit_code != 0
            if step_failed:
                rollback_failures.append(f"step {step.sequence} exited with {result.exit_code}")
            await _update_step(
                step.id,
                expected={DeceptionRevisionStepStatus.ROLLING_BACK},
                status=DeceptionRevisionStepStatus.ROLLBACK_FAILED if step_failed else DeceptionRevisionStepStatus.ROLLED_BACK,
                rollback_exit_code=result.exit_code,
                rollback_output=result.output[:_OUTPUT_LIMIT],
                after_rollback_state=(
                    await _capture_container_state(claimed.container_id)
                    if claimed.container_id is not None
                    else None
                ),
                error="rollback command failed" if step_failed else "",
                finished_at=utc_now(),
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            rollback_failures.append(f"step {step.sequence}: {str(exc) or 'rollback command failed'}")
            await _update_step(
                step.id,
                expected={DeceptionRevisionStepStatus.ROLLING_BACK},
                status=DeceptionRevisionStepStatus.ROLLBACK_FAILED,
                error=str(exc) or "rollback command failed",
                finished_at=utc_now(),
            )
    successful_terminal = None
    if not rollback_failures:
        async with get_async_session() as session:
            environment = await session.get(DeceptionEnvironment, claimed.environment_id)
            if environment is not None:
                successful_terminal = finish_rollback(
                    DeceptionLifecycle.from_environment(environment),
                    claimed.revision_id,
                    succeeded=True,
                )
        if (
            successful_terminal is not None
            and successful_terminal.release_platform_container
            and claimed.container_id is not None
        ):
            await lease.assert_owned()
            released = await delete_revision_sandbox_container(
                claimed.container_id,
                environment_id=claimed.environment_id,
                revision_id=claimed.revision_id,
            )
            await lease.assert_owned()
            if not released:
                rollback_failures.append("platform container cleanup failed")
    async with get_async_session() as session, session.begin():
        revision = (await session.exec(select(DeceptionRevision).where(
            DeceptionRevision.id == claimed.revision_id,
        ).with_for_update())).one_or_none()
        environment = (await session.exec(select(DeceptionEnvironment).where(
            DeceptionEnvironment.id == claimed.environment_id,
        ).with_for_update())).one_or_none()
        if revision is None or environment is None:
            return DeceptionRevisionMutationResult(revision=None, environment=None, not_found=True)
        failed = bool(rollback_failures)
        failure_reason = revision.failure_reason or reason
        rollback_error = "; ".join(rollback_failures)
        final_reason = (
            f"{failure_reason}; rollback failures: {rollback_error}"
            if rollback_error
            else failure_reason
        )
        terminal = (
            finish_rollback(
                DeceptionLifecycle.from_environment(environment),
                claimed.revision_id,
                succeeded=False,
            )
            if failed
            else successful_terminal
        )
        if terminal is None:
            raise RuntimeError("rollback terminal state could not be determined")
        revision.status = (
            DeceptionRevisionStatus.RECOVERY_REQUIRED
            if failed
            else DeceptionRevisionStatus.ROLLED_BACK
        )
        revision.result = final_reason
        revision.failure_reason = failure_reason
        revision.rollback_error = rollback_error
        revision.resolved_at = None if failed else utc_now()
        rollback_container = (
            await session.get(SandboxContainer, claimed.container_id)
            if claimed.container_id is not None
            else None
        )
        revision.execution_checkpoint = DeceptionRevisionExecutionCheckpoint(
            phase="recovery_required" if failed else "rolled_back",
            step_sequence=None,
            container=_container_state(rollback_container),
            recorded_at=utc_now(),
        ).model_dump(mode="json")
        session.add(revision)
        environment.status = terminal.environment_status
        environment.applied_revision_id = terminal.applied_revision_id
        environment.active_revision_id = terminal.active_revision_id
        environment.last_error = final_reason
        environment.updated_at = utc_now()
        session.add(environment)
        await add_audit_event(
            session,
            environment_id=claimed.environment_id,
            kind=AuditEventKind.REVISION,
            actor_type=AuditActorType.SYSTEM,
            object_type="deception_revision",
            object_id=claimed.revision_id,
            summary="Deception revision rollback failed." if failed else "Deception revision rolled back.",
            details={"reason": reason, "rollback_failures": rollback_failures},
        )
        return DeceptionRevisionMutationResult(
            revision=await serialize_deception_revision(session, revision),
            environment=DeceptionEnvironmentSchema.model_validate(environment),
            conflict=failed or report_original_failure,
            message=final_reason,
        )


async def _complete(claimed):
    async with get_async_session() as session, session.begin():
        revision = (await session.exec(select(DeceptionRevision).where(
            DeceptionRevision.id == claimed.revision_id,
        ).with_for_update())).one_or_none()
        environment = (await session.exec(select(DeceptionEnvironment).where(
            DeceptionEnvironment.id == claimed.environment_id,
        ).with_for_update())).one_or_none()
        if revision is None or environment is None:
            raise RuntimeError("claimed deception revision or environment no longer exists")
        require_active_revision(
            DeceptionLifecycle.from_environment(environment),
            claimed.revision_id,
            revision.status,
            DeceptionRevisionStatus.EXECUTING,
        )
        incomplete_step_id = (await session.exec(select(DeceptionRevisionStep.id).where(
            DeceptionRevisionStep.revision_id == claimed.revision_id,
            DeceptionRevisionStep.status != DeceptionRevisionStepStatus.VERIFIED,
        ).limit(1))).first()
        if incomplete_step_id is not None:
            raise RuntimeError("revision cannot complete before every step is verified")
        terminal = apply_revision(DeceptionLifecycle.from_environment(environment), claimed.revision_id)
        if (
            environment.sandbox_container_id != claimed.container_id
            or revision.execution_container_id != claimed.container_id
        ):
            raise RuntimeError("revision execution container no longer matches the environment binding")
        revision.status = DeceptionRevisionStatus.APPLIED
        revision.failure_reason = ""
        revision.rollback_error = ""
        revision.result = "Revision applied and verified."
        revision.resolved_at = utc_now()
        completed_container = await session.get(SandboxContainer, claimed.container_id)
        revision.execution_checkpoint = DeceptionRevisionExecutionCheckpoint(
            phase="completed",
            step_sequence=None,
            container=_container_state(completed_container),
            recorded_at=utc_now(),
        ).model_dump(mode="json")
        if revision.kind == DeceptionRevisionKind.ADAPTIVE:
            revision.observation_deadline = revision.resolved_at + timedelta(
                seconds=revision.observation_window_seconds
            )
        environment.persona = revision.target_persona
        environment.services = revision.target_services
        environment.applied_revision_id = terminal.applied_revision_id
        environment.active_revision_id = terminal.active_revision_id
        environment.status = terminal.environment_status
        environment.last_error = ""
        environment.updated_at = utc_now()
        artifacts = list((await session.exec(select(DeceptionArtifact).where(
            DeceptionArtifact.environment_id == claimed.environment_id,
        ).with_for_update())).all())
        for artifact in artifacts:
            artifact.active = artifact.revision_id == revision.id
            session.add(artifact)
        if claimed.initial and claimed.container_id is not None:
            container = await session.get(SandboxContainer, claimed.container_id)
            if container is not None:
                container.provisioned_for_revision_id = None
                session.add(container)
        session.add(revision)
        session.add(environment)
        await add_audit_event(
            session,
            environment_id=claimed.environment_id,
            kind=AuditEventKind.REVISION,
            actor_type=AuditActorType.SYSTEM,
            object_type="deception_revision",
            object_id=claimed.revision_id,
            summary="Deception revision applied and verified.",
            details={"version": revision.version},
        )
        result = DeceptionRevisionMutationResult(
            revision=await serialize_deception_revision(session, revision),
            environment=DeceptionEnvironmentSchema.model_validate(environment),
        )
        host_id = environment.host_id
    if claimed.initial:
        try:
            await finalize_reference_bundle(claimed.environment_id, claimed.container_id)
        except Exception:
            logger.warning(
                "could not clean up staged deception references: environment=%s",
                claimed.environment_id,
                exc_info=True,
            )
    from service.detection.sensor_bundles import schedule_sensor_bundle_refresh
    try:
        schedule_sensor_bundle_refresh(host_id)
    except Exception:
        logger.warning(
            "could not schedule deception sensor refresh: environment=%s host=%s",
            claimed.environment_id,
            host_id,
            exc_info=True,
        )
    return result


async def _load_claimed(environment_id, revision_id):
    async with get_async_session() as session:
        environment = await session.get(DeceptionEnvironment, environment_id)
        revision = await session.get(DeceptionRevision, revision_id)
        step_rows = tuple((await session.exec(select(DeceptionRevisionStep).where(
            DeceptionRevisionStep.revision_id == revision_id
        ).order_by(DeceptionRevisionStep.sequence.asc()))).all())
        if (
            environment is None
            or revision is None
            or revision.environment_id != environment_id
            or environment.active_revision_id != revision_id
            or not step_rows
        ):
            return None
        initial = revision.kind == DeceptionRevisionKind.INITIAL
        container = await _resolve_execution_container(session, environment, revision)
        return _ClaimedRevision(
            environment_id=environment_id,
            revision_id=revision_id,
            container_id=container.id if container is not None else None,
            container_generation=status_generation(container) if container is not None else 0,
            steps=tuple(_snapshot_step(step) for step in step_rows),
            initial=initial,
            reference_urls=tuple(environment.reference_urls),
            owner_id=environment.owner_id,
            container_spec=(
                DeceptionContainerSpec.model_validate(revision.container_spec)
                if initial
                else None
            ),
        )


async def _resolve_execution_container(
    session,
    environment: DeceptionEnvironment,
    revision: DeceptionRevision,
    *,
    lock: bool = False,
) -> SandboxContainer | None:
    provenance_statement = select(SandboxContainer).where(
        SandboxContainer.provisioned_for_revision_id == revision.id,
    )
    if lock:
        provenance_statement = provenance_statement.with_for_update()
    provisioned = list((await session.exec(provenance_statement)).all())
    if len(provisioned) > 1:
        raise RuntimeError("revision owns more than one platform-provisioned container")

    candidate_ids = {
        candidate_id
        for candidate_id in (
            revision.execution_container_id,
            environment.sandbox_container_id,
            provisioned[0].id if provisioned else None,
            _checkpoint_container_id(revision.execution_checkpoint),
        )
        if candidate_id is not None
    }
    if len(candidate_ids) > 1:
        raise RuntimeError("revision execution container conflicts with the environment binding")
    if not candidate_ids:
        return None

    container_id = next(iter(candidate_ids))
    container_statement = select(SandboxContainer).where(SandboxContainer.id == container_id)
    if lock:
        container_statement = container_statement.with_for_update()
    container = (await session.exec(container_statement)).one_or_none()
    if container is None:
        if (
            revision.kind == DeceptionRevisionKind.INITIAL
            and environment.container_ownership == DeceptionContainerOwnership.PLATFORM_MANAGED
            and environment.sandbox_container_id is None
            and not provisioned
        ):
            return None
        raise RuntimeError("revision execution container no longer exists")

    initial = revision.kind == DeceptionRevisionKind.INITIAL
    if initial and environment.container_ownership == DeceptionContainerOwnership.PLATFORM_MANAGED:
        if container.provisioned_for_revision_id != revision.id:
            raise RuntimeError("initial revision does not own its platform-provisioned container")
        if environment.sandbox_container_id not in {None, container.id}:
            raise RuntimeError("initial revision container conflicts with the environment binding")
    else:
        if environment.sandbox_container_id != container.id:
            raise RuntimeError("revision must use the environment's bound container")
        if revision.execution_container_id not in {None, container.id}:
            raise RuntimeError("revision execution container conflicts with the environment binding")
    return container


def _snapshot_step(step: DeceptionRevisionStep) -> _RevisionStepCommand:
    if step.id is None:
        raise RuntimeError("deception revision step id was not generated")
    return _RevisionStepCommand(
        id=step.id,
        sequence=step.sequence,
        apply_command=step.apply_command,
        verify_command=step.verify_command,
        rollback_command=step.rollback_command,
        timeout_seconds=step.timeout_seconds,
        status=step.status,
    )


async def _update_step(
    step_id: int,
    *,
    expected: set[DeceptionRevisionStepStatus],
    **updates,
):
    async with get_async_session() as session, session.begin():
        step = (await session.exec(select(DeceptionRevisionStep).where(DeceptionRevisionStep.id == step_id).with_for_update())).one()
        if step.status not in expected:
            raise RuntimeError(
                f"revision step {step.sequence} cannot transition from {step.status.value}"
            )
        for field, value in updates.items():
            setattr(step, field, value)
        session.add(step)
        revision = (await session.exec(select(DeceptionRevision).where(
            DeceptionRevision.id == step.revision_id
        ).with_for_update())).one()
        container = (
            await session.get(SandboxContainer, revision.execution_container_id)
            if revision.execution_container_id is not None
            else None
        )
        status = updates.get("status", step.status)
        revision.execution_checkpoint = DeceptionRevisionExecutionCheckpoint(
            phase=status.value if isinstance(status, DeceptionRevisionStepStatus) else str(status),
            step_sequence=step.sequence,
            container=_container_state(container),
            recorded_at=utc_now(),
        ).model_dump(mode="json")
        session.add(revision)


async def _capture_container_state(container_id: int):
    async with get_async_session() as session:
        state = _container_state(await session.get(SandboxContainer, container_id))
        return state.model_dump(mode="json") if state is not None else None


def _container_state(container: SandboxContainer | None):
    if container is None or container.id is None:
        return None
    from schema.deception.environments import DeceptionContainerExecutionState

    return DeceptionContainerExecutionState(
        container_id=container.id,
        status=container.status,
        container_hash=container.container_hash,
        status_generation=status_generation(container),
        recorded_at=utc_now(),
    )


def _validate_frozen_plan(
    revision: DeceptionRevision,
    steps: tuple[DeceptionRevisionStep, ...],
) -> None:
    canonical = json.dumps(
        revision.plan_snapshot,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if hashlib.sha256(canonical).hexdigest() != revision.plan_sha256:
        raise ValueError("deception revision plan snapshot integrity validation failed")
    snapshot_steps = revision.plan_snapshot.get("steps")
    if not isinstance(snapshot_steps, list) or len(snapshot_steps) != len(steps):
        raise ValueError("deception revision step journal does not match the frozen plan")
    for persisted, frozen in zip(steps, snapshot_steps, strict=True):
        current = {
            "kind": persisted.kind,
            "target": persisted.target,
            "parameters": persisted.parameters,
            "expected_effect": persisted.expected_effect,
            "apply_command": persisted.apply_command,
            "verify_command": persisted.verify_command,
            "rollback_command": persisted.rollback_command,
            "timeout_seconds": persisted.timeout_seconds,
        }
        if current != frozen:
            raise ValueError(
                f"deception revision step {persisted.sequence} differs from the frozen plan"
            )


def _checkpoint_container_id(checkpoint) -> int | None:
    if not isinstance(checkpoint, dict):
        return None
    container = checkpoint.get("container")
    value = container.get("container_id") if isinstance(container, dict) else None
    return value if isinstance(value, int) else None


def _step_failure_message(sequence: int, phase: str, exit_code: int, output: str) -> str:
    summary = " ".join(output.strip().split())
    if len(summary) > 1000:
        summary = "..." + summary[-997:]
    message = f"revision step {sequence} {phase} failed with exit code {exit_code}"
    return f"{message}: {summary}" if summary else message


def _revision_lease_name(revision_id: int) -> str:
    return f"deception-revision:{revision_id}"
