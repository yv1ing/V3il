from dataclasses import dataclass
from datetime import datetime
import hashlib
from uuid import uuid4

from fastapi import UploadFile
from sqlalchemy import func, or_
from sqlmodel import select

from database import get_async_session
from core.agent.constants import DEFAULT_AGENT_CODE
from logger import get_logger
from model.agent.sessions import AgentSessionMeta
from model.deception.environments import DeceptionArtifact, DeceptionEnvironment, DeceptionRevision, DeceptionRevisionStep
from model.detection.rules import BehaviorSignal
from model.egress_proxy.proxies import EgressProxy
from model.host.hosts import ManagedHost
from model.sandbox.containers import SandboxContainer
from model.sandbox.images import SandboxImage
from schema.deception.environments import (
    CreateDeceptionArtifactRequest,
    DeceptionArtifactSchema,
    DeceptionContainerOwnership,
    DeceptionEvaluationStatus,
    EvaluateDeceptionRevisionRequest,
    CreateDeceptionEnvironmentRequest,
    DeceptionEnvironmentSchema,
    DeceptionEnvironmentStatus,
    DeceptionReferenceBundleSchema,
    DeceptionRevisionKind,
    DeceptionRevisionSchema,
    DeceptionRevisionStatus,
    DeceptionRevisionStepSchema,
    PlanDeceptionRevisionRequest,
    UpdateDeceptionEnvironmentRequest,
)
from schema.sandbox.containers import (
    SandboxContainerEgressMode,
    SandboxContainerStatus,
)
from schema.system_user.users import SystemUserRole
from schema.agent.sessions import SessionType
from schema.threat.investigations import AuditActorType, AuditEventKind
from service.common.pagination import Page, RESOURCE_PAGE_SIZE, page_offset
from service.agent.sandbox_selection import set_environment_session_sandbox_container
from service.deception.references import (
    delete_reference_bundle,
    discard_staged_reference_bundle,
    load_reference_bundle,
    commit_staged_reference_bundle,
    stage_reference_uploads,
)
from service.threat.audit import add_audit_event
from service.sandbox.status import status_generation
from service.deception.lifecycle import (
    DeceptionLifecycle,
    DeceptionLifecycleError,
    plan_revision,
    reject_revision,
    require_active_revision,
    validate_container_spec,
)


logger = get_logger(__name__)
@dataclass(frozen=True)
class DeceptionMutationResult:
    environment: DeceptionEnvironmentSchema | None
    revision: DeceptionRevisionSchema | None = None
    session_id: str = ""
    references: DeceptionReferenceBundleSchema | None = None
    not_found: bool = False
    forbidden: bool = False
    conflict: bool = False
    message: str = ""


@dataclass(frozen=True)
class DeceptionRevisionMutationResult:
    revision: DeceptionRevisionSchema | None
    environment: DeceptionEnvironmentSchema | None
    not_found: bool = False
    forbidden: bool = False
    conflict: bool = False
    message: str = ""


async def create_deception_environment(
    request: CreateDeceptionEnvironmentRequest,
    uploads: list[UploadFile],
    *,
    user_id: int,
    user_role: SystemUserRole,
    agent_code: str = "",
    session_id: str = "",
):
    from service.agent.sessions import ensure_sdk_session_row

    planning_session_id = str(uuid4())
    staged = await stage_reference_uploads(uploads)
    environment_id: int | None = None
    try:
        async with get_async_session() as session, session.begin():
            host = await session.get(ManagedHost, request.host_id)
            image = await session.get(SandboxImage, request.image_id)
            if host is None or image is None:
                await discard_staged_reference_bundle(staged)
                return DeceptionMutationResult(environment=None, not_found=True, message="selected managed host or sandbox image does not exist")
            if request.egress_mode == SandboxContainerEgressMode.PROXY:
                proxy = await session.get(EgressProxy, request.egress_proxy_id)
                if proxy is None:
                    await discard_staged_reference_bundle(staged)
                    return DeceptionMutationResult(environment=None, not_found=True, message="selected egress proxy does not exist")
            selected_container = None
            if request.sandbox_container_id is not None:
                selected_container = (await session.exec(
                    select(SandboxContainer)
                    .where(SandboxContainer.id == request.sandbox_container_id)
                    .with_for_update()
                )).one_or_none()
                if selected_container is None:
                    await discard_staged_reference_bundle(staged)
                    return DeceptionMutationResult(
                        environment=None,
                        not_found=True,
                        message="selected sandbox container does not exist",
                    )
                if user_role != SystemUserRole.ADMIN and selected_container.owner_id != user_id:
                    await discard_staged_reference_bundle(staged)
                    return DeceptionMutationResult(
                        environment=None,
                        forbidden=True,
                        message="selected sandbox container is not manageable by user",
                    )
                if selected_container.status != SandboxContainerStatus.RUNNING:
                    await discard_staged_reference_bundle(staged)
                    return DeceptionMutationResult(
                        environment=None,
                        conflict=True,
                        message="selected sandbox container must be running",
                    )
                bound_environment_id = (await session.exec(
                    select(DeceptionEnvironment.id)
                    .where(DeceptionEnvironment.sandbox_container_id == request.sandbox_container_id)
                    .limit(1)
                )).first()
                if bound_environment_id is not None:
                    await discard_staged_reference_bundle(staged)
                    return DeceptionMutationResult(
                        environment=None,
                        conflict=True,
                        message="selected sandbox container is already bound to a deception environment",
                    )
                selected_configuration = (
                    selected_container.host_id,
                    selected_container.image_id,
                    selected_container.egress_mode,
                    selected_container.egress_proxy_id,
                )
                requested_configuration = (
                    request.host_id,
                    request.image_id,
                    request.egress_mode,
                    request.egress_proxy_id,
                )
                if selected_configuration != requested_configuration:
                    await discard_staged_reference_bundle(staged)
                    return DeceptionMutationResult(
                        environment=None,
                        conflict=True,
                        message="selected sandbox container does not match the submitted host, image, or egress configuration",
                    )
                if not selected_container.port_mappings:
                    await discard_staged_reference_bundle(staged)
                    return DeceptionMutationResult(
                        environment=None,
                        conflict=True,
                        message="selected sandbox container requires at least one service port mapping",
                    )
            now = datetime.now()
            environment = DeceptionEnvironment(
                name=request.name,
                description=request.description,
                reference_urls=request.reference_urls,
                host_id=request.host_id,
                image_id=request.image_id,
                egress_mode=request.egress_mode,
                egress_proxy_id=request.egress_proxy_id,
                sandbox_container_id=request.sandbox_container_id,
                container_ownership=(
                    DeceptionContainerOwnership.PRESELECTED
                    if selected_container is not None
                    else DeceptionContainerOwnership.PLATFORM_MANAGED
                ),
                status=DeceptionEnvironmentStatus.DRAFT,
                applied_revision_id=None,
                active_revision_id=None,
                adaptation_mode=request.adaptation_mode,
                owner_id=user_id,
                created_at=now,
                updated_at=now,
            )
            session.add(environment)
            await session.flush()
            if environment.id is None:
                raise RuntimeError("deception environment id was not generated")
            environment_id = environment.id
            await add_audit_event(
                session,
                environment_id=environment.id,
                kind=AuditEventKind.ENVIRONMENT,
                actor_type=AuditActorType.AGENT if agent_code else AuditActorType.USER,
                actor_code=agent_code or str(user_id),
                session_id=session_id,
                object_type="deception_environment",
                object_id=environment.id,
                summary="Deception environment context created; awaiting Console instructions.",
                details={
                    "host_id": request.host_id,
                    "image_id": request.image_id,
                    "egress_mode": request.egress_mode.value,
                    "sandbox_container_id": request.sandbox_container_id,
                    "reference_url_count": len(request.reference_urls),
                    "reference_file_count": len(staged.files),
                },
            )
            await ensure_sdk_session_row(session, planning_session_id)
            session.add(AgentSessionMeta(
                session_id=planning_session_id,
                session_type=SessionType.ENVIRONMENT,
                title=f"Build deception environment: {request.name}",
                agent_code=DEFAULT_AGENT_CODE,
                owner_id=user_id,
                environment_id=environment.id,
                is_automated=False,
                selected_sandbox_container_id=request.sandbox_container_id,
                selected_sandbox_container_generation=(
                    status_generation(selected_container)
                    if selected_container is not None
                    else 0
                ),
            ))
            env_schema = DeceptionEnvironmentSchema.model_validate(environment)
            references = await commit_staged_reference_bundle(
                staged,
                environment.id,
                request.reference_urls,
            )
    except BaseException:
        if environment_id is None:
            await discard_staged_reference_bundle(staged)
        else:
            await delete_reference_bundle(environment_id)
        raise
    return DeceptionMutationResult(
        environment=env_schema,
        session_id=planning_session_id,
        references=references,
    )


async def plan_deception_revision(environment_id: int, request: PlanDeceptionRevisionRequest, *, user_id: int, user_role: SystemUserRole, agent_code: str = "", session_id: str = "", incident_id: int | None = None, investigation_task_id: int | None = None):
    async with get_async_session() as session, session.begin():
        environment = (await session.exec(select(DeceptionEnvironment).where(DeceptionEnvironment.id == environment_id).with_for_update())).one_or_none()
        if environment is None:
            return DeceptionRevisionMutationResult(revision=None, environment=None, not_found=True)
        if user_role != SystemUserRole.ADMIN and environment.owner_id != user_id:
            return DeceptionRevisionMutationResult(revision=None, environment=None, forbidden=True)
        if request.container_spec.host_id != environment.host_id or request.container_spec.image_id != environment.image_id:
            return DeceptionRevisionMutationResult(revision=None, environment=None, conflict=True, message="revision cannot change the operator-selected host or image")
        if request.container_spec.egress_mode != environment.egress_mode or request.container_spec.egress_proxy_id != environment.egress_proxy_id:
            return DeceptionRevisionMutationResult(revision=None, environment=None, conflict=True, message="revision cannot change the operator-selected egress configuration")
        try:
            decision = plan_revision(DeceptionLifecycle.from_environment(environment))
        except DeceptionLifecycleError as exc:
            return DeceptionRevisionMutationResult(
                revision=None,
                environment=None,
                conflict=True,
                message=str(exc),
            )
        container = None
        current_mappings: list[dict[str, object]] = []
        if environment.sandbox_container_id is not None:
            container = (await session.exec(
                select(SandboxContainer)
                .where(SandboxContainer.id == environment.sandbox_container_id)
                .with_for_update()
            )).one_or_none()
            if container is None:
                return DeceptionRevisionMutationResult(
                    revision=None,
                    environment=None,
                    conflict=True,
                    message="environment sandbox container no longer exists",
                )
            if container.status != SandboxContainerStatus.RUNNING:
                return DeceptionRevisionMutationResult(
                    revision=None,
                    environment=None,
                    conflict=True,
                    message="environment sandbox container must be running before planning a revision",
                )
            current_mappings = list(container.port_mappings)
        try:
            validate_container_spec(decision, request.container_spec, current_mappings)
        except DeceptionLifecycleError as exc:
            return DeceptionRevisionMutationResult(
                revision=None,
                environment=None,
                conflict=True,
                message=str(exc),
            )
        if decision.kind == DeceptionRevisionKind.ADAPTIVE:
            unresolved_evaluation = (await session.exec(select(DeceptionRevision.id).where(
                DeceptionRevision.environment_id == environment_id,
                DeceptionRevision.kind == DeceptionRevisionKind.ADAPTIVE,
                DeceptionRevision.status == DeceptionRevisionStatus.APPLIED,
                DeceptionRevision.evaluation_status == DeceptionEvaluationStatus.PENDING,
                DeceptionRevision.observation_deadline <= datetime.now(),
            ).limit(1))).first()
            if unresolved_evaluation is not None:
                return DeceptionRevisionMutationResult(
                    revision=None,
                    environment=None,
                    conflict=True,
                    message="the previous adaptive revision must be evaluated before planning another revision",
                )
            if not request.engagement_goal.strip() or not request.engagement_hypothesis.strip() or not request.success_criteria:
                return DeceptionRevisionMutationResult(
                    revision=None,
                    environment=None,
                    conflict=True,
                    message="adaptive revisions require an engagement goal, hypothesis, and success criteria",
                )
            if not request.trigger_signal_ids:
                return DeceptionRevisionMutationResult(
                    revision=None,
                    environment=None,
                    conflict=True,
                    message="adaptive revisions require at least one triggering behavior signal",
                )
            if incident_id is None:
                return DeceptionRevisionMutationResult(
                    revision=None,
                    environment=None,
                    conflict=True,
                    message="adaptive revisions require a source threat incident",
                )
            signal_count = int((await session.exec(select(func.count()).select_from(BehaviorSignal).where(
                BehaviorSignal.id.in_(request.trigger_signal_ids),
                BehaviorSignal.environment_id == environment_id,
                BehaviorSignal.incident_id == incident_id,
            ))).one())
            if signal_count != len(set(request.trigger_signal_ids)):
                return DeceptionRevisionMutationResult(
                    revision=None,
                    environment=None,
                    conflict=True,
                    message="trigger signals must belong to the deception environment and source incident",
                )
        next_version = int((await session.exec(select(func.max(DeceptionRevision.version)).where(
            DeceptionRevision.environment_id == environment_id
        ))).one() or 0) + 1
        requires_approval = _requires_approval(
            request,
            decision.kind == DeceptionRevisionKind.INITIAL,
        )
        revision = DeceptionRevision(
            environment_id=environment_id,
            version=next_version,
            kind=decision.kind,
            status=(
                DeceptionRevisionStatus.PENDING_APPROVAL
                if requires_approval or (
                    decision.kind == DeceptionRevisionKind.ADAPTIVE
                    and environment.adaptation_mode.value == "manual_approval"
                )
                else DeceptionRevisionStatus.PLANNED
            ),
            rationale=request.rationale,
            target_persona=request.target_persona,
            target_services=[item.model_dump(mode="json") for item in request.target_services],
            container_spec=request.container_spec.model_dump(mode="json"),
            execution_container_id=(container.id if container is not None else None),
            trigger_event_ids=request.trigger_event_ids,
            trigger_signal_ids=list(dict.fromkeys(request.trigger_signal_ids)),
            engagement_goal=request.engagement_goal.strip(),
            engagement_hypothesis=request.engagement_hypothesis.strip(),
            success_criteria=request.success_criteria,
            observation_window_seconds=request.observation_window_seconds,
            evaluation_status=DeceptionEvaluationStatus.PENDING,
            source_incident_id=incident_id,
            risk_level=(type(request.risk_level).HIGH if requires_approval else request.risk_level),
            approval_reason=request.approval_reason,
            created_by_agent_code=agent_code,
            created_from_session_id=session_id,
            created_at=datetime.now(),
        )
        session.add(revision)
        await session.flush()
        if revision.id is None:
            raise RuntimeError("deception revision id was not generated")
        session.add_all([
            DeceptionRevisionStep(
                revision_id=revision.id,
                sequence=sequence,
                **step.model_dump(),
            )
            for sequence, step in enumerate(request.steps, start=1)
        ])
        environment.status = decision.environment_status
        environment.active_revision_id = revision.id
        environment.last_error = ""
        environment.updated_at = datetime.now()
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
            object_id=revision.id,
            summary="Deception revision planned.",
            details={"version": revision.version, "status": revision.status.value, "risk_level": revision.risk_level.value},
        )
        env_schema = DeceptionEnvironmentSchema.model_validate(environment)
        rev_schema = await serialize_deception_revision(session, revision)
    return DeceptionRevisionMutationResult(revision=rev_schema, environment=env_schema)


async def create_deception_artifact(
    environment_id: int,
    request: CreateDeceptionArtifactRequest,
    *,
    user_id: int,
    user_role: SystemUserRole,
    agent_code: str = "",
    session_id: str = "",
) -> DeceptionArtifactSchema:
    async with get_async_session() as session, session.begin():
        environment = await session.get(DeceptionEnvironment, environment_id)
        revision = await session.get(DeceptionRevision, request.revision_id)
        if environment is None or revision is None or revision.environment_id != environment_id:
            raise LookupError("deception environment or revision not found")
        if user_role != SystemUserRole.ADMIN and environment.owner_id != user_id:
            raise PermissionError("deception environment is not accessible by user")
        if agent_code and agent_code != "cde":
            raise ValueError("only cde can register deception artifacts")
        if revision.status not in {
            DeceptionRevisionStatus.PLANNED,
            DeceptionRevisionStatus.PENDING_APPROVAL,
            DeceptionRevisionStatus.EXECUTING,
            DeceptionRevisionStatus.APPLIED,
        }:
            raise ValueError("artifacts can only be registered for a live revision")
        if revision.status == DeceptionRevisionStatus.APPLIED:
            if environment.applied_revision_id != revision.id:
                raise ValueError("artifacts can only be registered for the applied baseline revision")
        elif environment.active_revision_id != revision.id:
            raise ValueError("artifacts can only be registered for the active revision attempt")
        existing = (await session.exec(select(DeceptionArtifact).where(
            DeceptionArtifact.revision_id == request.revision_id,
            DeceptionArtifact.fingerprint == request.fingerprint,
        ))).one_or_none()
        if existing is not None:
            raise ValueError("deception artifact fingerprint already exists in this revision")
        artifact = DeceptionArtifact(
            environment_id=environment_id,
            revision_id=request.revision_id,
            kind=request.kind,
            name=request.name.strip(),
            locator=request.locator.strip(),
            fingerprint=request.fingerprint,
            description=request.description.strip(),
            active=environment.applied_revision_id == revision.id,
            created_by_agent_code=agent_code,
            created_from_session_id=session_id,
        )
        session.add(artifact)
        await session.flush()
        await add_audit_event(
            session,
            incident_id=revision.source_incident_id,
            environment_id=environment_id,
            kind=AuditEventKind.REVISION,
            actor_type=AuditActorType.AGENT if agent_code else AuditActorType.USER,
            actor_code=agent_code or str(user_id),
            session_id=session_id,
            object_type="deception_artifact",
            object_id=artifact.id,
            summary="Deception artifact registered.",
            details={"revision_id": request.revision_id, "kind": request.kind.value, "fingerprint_sha256": hashlib.sha256(request.fingerprint.encode()).hexdigest()},
        )
        schema = DeceptionArtifactSchema.model_validate(artifact)
        host_id = environment.host_id
    if schema.active:
        from service.detection.sensor_bundles import schedule_sensor_bundle_refresh
        try:
            schedule_sensor_bundle_refresh(host_id)
        except Exception:
            logger.warning(
                "could not schedule deception artifact sensor refresh: environment=%s host=%s",
                environment_id,
                host_id,
                exc_info=True,
            )
    return schema


async def query_deception_artifacts_for_user(
    environment_id: int,
    *,
    page: int,
    size: int,
    user_id: int,
    user_role: SystemUserRole,
):
    async with get_async_session() as session:
        environment = await session.get(DeceptionEnvironment, environment_id)
        if environment is None or (user_role != SystemUserRole.ADMIN and environment.owner_id != user_id):
            return None
        statement = select(DeceptionArtifact).where(
            DeceptionArtifact.environment_id == environment_id,
        ).order_by(DeceptionArtifact.created_at.desc())
        total = int((await session.execute(select(func.count()).select_from(statement.order_by(None).subquery()))).scalar_one())
        rows = list((await session.exec(statement.offset(page_offset(page, size)).limit(size))).all())
        items = [DeceptionArtifactSchema.model_validate(item) for item in rows]
    return Page(page=page, size=size, total=total, items=items)


async def evaluate_deception_revision(
    environment_id: int,
    revision_id: int,
    request: EvaluateDeceptionRevisionRequest,
    *,
    user_id: int,
    user_role: SystemUserRole,
    agent_code: str = "",
    session_id: str = "",
    investigation_task_id: int | None = None,
):
    async with get_async_session() as session, session.begin():
        environment = await session.get(DeceptionEnvironment, environment_id)
        revision = (await session.exec(select(DeceptionRevision).where(
            DeceptionRevision.id == revision_id,
            DeceptionRevision.environment_id == environment_id,
        ).with_for_update())).one_or_none()
        if environment is None or revision is None:
            raise LookupError("deception environment or revision not found")
        if user_role != SystemUserRole.ADMIN and environment.owner_id != user_id:
            raise PermissionError("deception environment is not accessible by user")
        if agent_code and agent_code != "cde":
            raise ValueError("only cde can record deception engagement evaluations")
        if revision.status != DeceptionRevisionStatus.APPLIED:
            raise ValueError("only applied revisions can be evaluated")
        if revision.evaluation_status != DeceptionEvaluationStatus.PENDING:
            raise ValueError("deception revision evaluation is already final")
        if revision.evaluation_task_id is not None and revision.evaluation_task_id != investigation_task_id:
            raise ValueError("evaluation must be recorded from the assigned investigation task")
        revision.evaluation_status = request.status
        revision.evaluation_summary = request.summary.strip()
        session.add(revision)
        await add_audit_event(
            session,
            incident_id=revision.source_incident_id,
            environment_id=environment_id,
            task_id=investigation_task_id,
            kind=AuditEventKind.REVISION,
            actor_type=AuditActorType.AGENT if agent_code else AuditActorType.USER,
            actor_code=agent_code or str(user_id),
            session_id=session_id,
            object_type="deception_revision_evaluation",
            object_id=revision.id,
            summary="Deception engagement evaluation recorded.",
            details={"status": request.status.value, "success_criteria": revision.success_criteria},
        )
        return await serialize_deception_revision(session, revision)


async def decide_deception_revision(environment_id: int, revision_id: int, *, approve: bool, reason: str, user_id: int, user_role: SystemUserRole):
    async with get_async_session() as session, session.begin():
        environment = await session.get(DeceptionEnvironment, environment_id)
        revision = (await session.exec(select(DeceptionRevision).where(
            DeceptionRevision.id == revision_id,
            DeceptionRevision.environment_id == environment_id,
        ).with_for_update())).one_or_none()
        if environment is None or revision is None:
            return DeceptionRevisionMutationResult(revision=None, environment=None, not_found=True)
        if user_role != SystemUserRole.ADMIN and environment.owner_id != user_id:
            return DeceptionRevisionMutationResult(revision=None, environment=None, forbidden=True)
        try:
            require_active_revision(
                DeceptionLifecycle.from_environment(environment),
                revision_id,
                revision.status,
                DeceptionRevisionStatus.PENDING_APPROVAL,
            )
        except DeceptionLifecycleError as exc:
            return DeceptionRevisionMutationResult(
                revision=None,
                environment=None,
                conflict=True,
                message=str(exc),
            )
        revision.status = DeceptionRevisionStatus.PLANNED if approve else DeceptionRevisionStatus.REJECTED
        revision.approval_reason = reason
        revision.resolved_at = None if approve else datetime.now()
        session.add(revision)
        if not approve:
            terminal = reject_revision(DeceptionLifecycle.from_environment(environment), revision_id)
            environment.status = terminal.environment_status
            environment.active_revision_id = terminal.active_revision_id
            environment.last_error = "Revision rejected by operator."
            session.add(environment)
        await add_audit_event(
            session,
            environment_id=environment_id,
            kind=AuditEventKind.REVISION,
            actor_type=AuditActorType.USER,
            actor_code=str(user_id),
            object_type="deception_revision",
            object_id=revision_id,
            summary="Deception revision approved." if approve else "Deception revision rejected.",
            details={"reason": reason},
        )
        env_schema = DeceptionEnvironmentSchema.model_validate(environment)
        rev_schema = await serialize_deception_revision(session, revision)
    return DeceptionRevisionMutationResult(revision=rev_schema, environment=env_schema)


async def get_deception_environment_for_user(id: int, *, user_id: int, user_role: SystemUserRole):
    async with get_async_session() as session:
        environment = await session.get(DeceptionEnvironment, id)
        if environment is None or (user_role != SystemUserRole.ADMIN and environment.owner_id != user_id):
            return None
        return DeceptionEnvironmentSchema.model_validate(environment)


async def query_deception_environments_for_user(*, page=1, size=RESOURCE_PAGE_SIZE, keyword="", status=None, user_id: int, user_role: SystemUserRole):
    statement = select(DeceptionEnvironment)
    if user_role != SystemUserRole.ADMIN:
        statement = statement.where(DeceptionEnvironment.owner_id == user_id)
    if status is not None:
        statement = statement.where(DeceptionEnvironment.status == status)
    if keyword := keyword.strip():
        pattern = f"%{keyword}%"
        statement = statement.where(or_(
            DeceptionEnvironment.name.ilike(pattern),
            DeceptionEnvironment.description.ilike(pattern),
            DeceptionEnvironment.persona.ilike(pattern),
        ))
    statement = statement.order_by(DeceptionEnvironment.updated_at.desc(), DeceptionEnvironment.id.desc())
    async with get_async_session() as session:
        total = int((await session.execute(select(func.count()).select_from(statement.order_by(None).subquery()))).scalar_one())
        rows = list((await session.exec(statement.offset(page_offset(page, size)).limit(size))).all())
        items = [DeceptionEnvironmentSchema.model_validate(row) for row in rows]
    return Page(page=page, size=size, total=total, items=items)


async def update_deception_environment(id: int, request: UpdateDeceptionEnvironmentRequest, *, user_id: int, user_role: SystemUserRole):
    async with get_async_session() as session, session.begin():
        environment = (await session.exec(select(DeceptionEnvironment).where(DeceptionEnvironment.id == id).with_for_update())).one_or_none()
        if environment is None:
            return DeceptionMutationResult(environment=None, not_found=True)
        if user_role != SystemUserRole.ADMIN and environment.owner_id != user_id:
            return DeceptionMutationResult(environment=None, forbidden=True)
        for field, value in request.model_dump(exclude_unset=True).items():
            setattr(environment, field, value)
        environment.updated_at = datetime.now()
        session.add(environment)
        env_schema = DeceptionEnvironmentSchema.model_validate(environment)
    return DeceptionMutationResult(environment=env_schema)


async def get_deception_references_for_user(
    id: int,
    *,
    user_id: int,
    user_role: SystemUserRole,
) -> DeceptionReferenceBundleSchema | None:
    async with get_async_session() as session:
        environment = await session.get(DeceptionEnvironment, id)
        if environment is None or (
            user_role != SystemUserRole.ADMIN and environment.owner_id != user_id
        ):
            return None
        reference_urls = tuple(environment.reference_urls)
    return await load_reference_bundle(id, list(reference_urls))


async def set_deception_environment_status(id: int, status: DeceptionEnvironmentStatus, *, user_id: int, user_role: SystemUserRole):
    async with get_async_session() as session, session.begin():
        environment = (await session.exec(select(DeceptionEnvironment).where(DeceptionEnvironment.id == id).with_for_update())).one_or_none()
        if environment is None:
            return DeceptionMutationResult(environment=None, not_found=True)
        if user_role != SystemUserRole.ADMIN and environment.owner_id != user_id:
            return DeceptionMutationResult(environment=None, forbidden=True)
        allowed = {
            DeceptionEnvironmentStatus.DRAFT: {DeceptionEnvironmentStatus.RETIRED},
            DeceptionEnvironmentStatus.ACTIVE: {DeceptionEnvironmentStatus.PAUSED, DeceptionEnvironmentStatus.RETIRED},
            DeceptionEnvironmentStatus.PAUSED: {DeceptionEnvironmentStatus.ACTIVE, DeceptionEnvironmentStatus.RETIRED},
        }
        if status not in allowed.get(environment.status, set()):
            return DeceptionMutationResult(environment=None, conflict=True, message="environment cannot transition to the requested state")
        environment.status = status
        environment.updated_at = datetime.now()
        session.add(environment)
        await add_audit_event(
            session,
            environment_id=id,
            kind=AuditEventKind.ENVIRONMENT,
            actor_type=AuditActorType.USER,
            actor_code=str(user_id),
            object_type="deception_environment",
            object_id=id,
            summary=f"Deception environment transitioned to {status.value}.",
        )
        env_schema = DeceptionEnvironmentSchema.model_validate(environment)
    if status == DeceptionEnvironmentStatus.RETIRED:
        try:
            await delete_reference_bundle(id)
        except Exception:
            logger.warning(
                "could not delete retired deception reference bundle: environment=%s",
                id,
                exc_info=True,
            )
    return DeceptionMutationResult(environment=env_schema)


async def query_deception_revisions_for_user(environment_id: int, *, page=1, size=RESOURCE_PAGE_SIZE, user_id: int, user_role: SystemUserRole):
    async with get_async_session() as session:
        environment = await session.get(DeceptionEnvironment, environment_id)
        if environment is None or (user_role != SystemUserRole.ADMIN and environment.owner_id != user_id):
            return None
        statement = select(DeceptionRevision).where(DeceptionRevision.environment_id == environment_id).order_by(DeceptionRevision.version.desc())
        total = int((await session.execute(select(func.count()).select_from(statement.order_by(None).subquery()))).scalar_one())
        rows = list((await session.exec(statement.offset(page_offset(page, size)).limit(size))).all())
        items = [await serialize_deception_revision(session, row) for row in rows]
    return Page(page=page, size=size, total=total, items=items)


async def serialize_deception_revision(session, revision):
    steps = list((await session.exec(select(DeceptionRevisionStep).where(
        DeceptionRevisionStep.revision_id == revision.id
    ).order_by(DeceptionRevisionStep.sequence.asc()))).all())
    payload = revision.model_dump()
    payload["steps"] = [DeceptionRevisionStepSchema.model_validate(step) for step in steps]
    return DeceptionRevisionSchema.model_validate(payload)


def _requires_approval(request: PlanDeceptionRevisionRequest, initial: bool) -> bool:
    if initial:
        return False
    risky_kinds = {"network", "port_mapping", "mount", "capability", "control", "sensor", "privilege"}
    risky_fragments = (
        "docker ", "mount ", "umount ", "setcap ", "iptables ", "nft ",
        "/var/run/docker.sock", "SANDBOX_CONTROL_PROXY_TOKEN", "V3IL_SENSOR_ID",
        "/var/lib/v3il", "/run/v3il",
    )
    for step in request.steps:
        if step.kind.casefold() in risky_kinds:
            return True
        command_text = "\n".join((step.apply_command, step.verify_command, step.rollback_command))
        if any(fragment.casefold() in command_text.casefold() for fragment in risky_fragments):
            return True
    return request.risk_level.value == "high"
