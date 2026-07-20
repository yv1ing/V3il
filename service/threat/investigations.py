from dataclasses import dataclass

from sqlalchemy import func, or_
from sqlmodel import select

from utils.time import utc_now

from core.agent.constants import DEFAULT_AGENT_CODE, SPECIALIST_AGENT_CODES
from database import get_async_session
from model.agent.sessions import AgentRun
from model.threat.analysis import AnalysisRecord, RiskAssessment
from model.threat.incidents import ThreatIncident
from model.threat.investigations import (
    AuditEvent,
    EvidenceBehaviorLink,
    EvidenceRelation,
    InvestigationEvidence,
    InvestigationTask,
    InvestigationTaskDependency,
    InvestigationTaskEvent,
)
from schema.agent.sessions import AgentRunStatus
from schema.system_user.users import SystemUserRole
from schema.threat.incidents import ThreatIncidentStatus
from schema.threat.analysis import AnalysisKind, AnalysisReviewStatus
from schema.threat.investigations import (
    AuditActorType,
    AuditEventKind,
    AuditEventSchema,
    CreateInvestigationEvidenceRequest,
    CreateInvestigationTaskRequest,
    InvestigationEvidenceSchema,
    InvestigationReviewDecision,
    InvestigationTaskSchema,
    InvestigationTaskStatus,
)
from service.common.pagination import Page, RESOURCE_PAGE_SIZE, page_offset
from service.threat.audit import add_audit_event
from service.threat.evidence import require_incident_behavior_events


@dataclass(frozen=True)
class InvestigationTaskMutationResult:
    task: InvestigationTaskSchema | None
    not_found: bool = False
    forbidden: bool = False
    conflict: bool = False
    message: str = ""


@dataclass(frozen=True)
class InvestigationEvidenceMutationResult:
    evidence: InvestigationEvidenceSchema | None
    not_found: bool = False
    forbidden: bool = False
    conflict: bool = False
    message: str = ""


async def create_investigation_task(
    incident_id: int,
    request: CreateInvestigationTaskRequest,
    *,
    user_id: int,
    user_role: SystemUserRole,
    agent_code: str = "",
    session_id: str = "",
) -> InvestigationTaskMutationResult:
    async with get_async_session() as session, session.begin():
        return await create_investigation_task_in_session(
            session,
            incident_id,
            request,
            user_id=user_id,
            user_role=user_role,
            agent_code=agent_code,
            session_id=session_id,
        )


async def create_investigation_task_in_session(
    session,
    incident_id: int,
    request: CreateInvestigationTaskRequest,
    *,
    user_id: int,
    user_role: SystemUserRole,
    agent_code: str = "",
    session_id: str = "",
) -> InvestigationTaskMutationResult:
    if request.assignee_agent_code not in SPECIALIST_AGENT_CODES:
        return InvestigationTaskMutationResult(
            task=None,
            conflict=True,
            message="investigation task assignee must be a configured specialist Agent",
        )
    incident, error = await _lock_incident(session, incident_id, user_id, user_role)
    if error is not None:
        return InvestigationTaskMutationResult(task=None, **error)
    try:
        await require_incident_behavior_events(session, incident_id, request.behavior_event_ids)
    except ValueError as exc:
        return InvestigationTaskMutationResult(task=None, conflict=True, message=str(exc))
    dependencies = list((await session.exec(
        select(InvestigationTask).where(InvestigationTask.id.in_(request.dependency_ids))
    )).all()) if request.dependency_ids else []
    if len(dependencies) != len(request.dependency_ids) or any(
        dependency.incident_id != incident_id for dependency in dependencies
    ):
        return InvestigationTaskMutationResult(
            task=None,
            conflict=True,
            message="investigation task dependencies must belong to the same incident",
        )
    now = utc_now()
    task = InvestigationTask(
        incident_id=incident_id,
        title=request.title,
        status=(
            InvestigationTaskStatus.ACTIVE
            if not dependencies
            else InvestigationTaskStatus.QUEUED
        ),
        priority=request.priority,
        assignee_agent_code=request.assignee_agent_code,
        objective=request.objective,
        completion_criteria=request.completion_criteria,
        created_by_agent_code=agent_code,
        created_from_session_id=session_id,
        created_at=now,
        updated_at=now,
    )
    session.add(task)
    await session.flush()
    if task.id is None:
        raise RuntimeError("investigation task id was not generated")
    session.add_all([
        InvestigationTaskDependency(task_id=task.id, depends_on_task_id=dependency_id)
        for dependency_id in request.dependency_ids
    ])
    session.add_all([
        InvestigationTaskEvent(task_id=task.id, event_id=event_id, assigned_at=now)
        for event_id in request.behavior_event_ids
    ])
    await add_audit_event(
        session,
        incident_id=incident_id,
        task_id=task.id,
        kind=AuditEventKind.TASK_STATE,
        actor_type=_actor_type(agent_code),
        actor_code=agent_code or str(user_id),
        session_id=session_id,
        object_type="investigation_task",
        object_id=task.id,
        summary="Investigation task created.",
        details={
            "assignee_agent_code": request.assignee_agent_code,
            "dependency_ids": request.dependency_ids,
            "behavior_event_ids": request.behavior_event_ids,
        },
    )
    schema = await serialize_investigation_task(session, task)
    return InvestigationTaskMutationResult(task=schema)


async def activate_investigation_task(
    incident_id: int,
    task_id: int,
    *,
    user_id: int,
    user_role: SystemUserRole,
    agent_code: str = "",
    session_id: str = "",
) -> InvestigationTaskMutationResult:
    async with get_async_session() as session, session.begin():
        task, error = await _lock_manageable_task(
            session, incident_id, task_id, user_id, user_role, agent_code
        )
        if error is not None:
            return error
        if task.status not in {InvestigationTaskStatus.QUEUED, InvestigationTaskStatus.BLOCKED}:
            return InvestigationTaskMutationResult(task=None, conflict=True, message="task cannot be activated from its current state")
        dependency_ids = await _task_dependency_ids(session, task_id)
        if dependency_ids:
            completed = set((await session.exec(
                select(InvestigationTask.id).where(
                    InvestigationTask.id.in_(dependency_ids),
                    InvestigationTask.status == InvestigationTaskStatus.COMPLETED,
                )
            )).all())
            missing = [item for item in dependency_ids if item not in completed]
            if missing:
                return InvestigationTaskMutationResult(
                    task=None,
                    conflict=True,
                    message="task dependencies are not completed: " + ", ".join(map(str, missing)),
                )
        task.status = InvestigationTaskStatus.ACTIVE
        task.blocker_reason = ""
        task.updated_at = utc_now()
        session.add(task)
        await _audit_task_state(session, task, "Investigation task activated.", agent_code, session_id, user_id)
        schema = await serialize_investigation_task(session, task)
    return InvestigationTaskMutationResult(task=schema)


async def block_investigation_task(
    incident_id: int,
    task_id: int,
    reason: str,
    *,
    user_id: int,
    user_role: SystemUserRole,
    agent_code: str = "",
    session_id: str = "",
) -> InvestigationTaskMutationResult:
    async with get_async_session() as session, session.begin():
        task, error = await _lock_manageable_task(session, incident_id, task_id, user_id, user_role, agent_code)
        if error is not None:
            return error
        if task.status != InvestigationTaskStatus.ACTIVE:
            return InvestigationTaskMutationResult(task=None, conflict=True, message="only active tasks can be blocked")
        task.status = InvestigationTaskStatus.BLOCKED
        task.blocker_reason = reason.strip()
        task.updated_at = utc_now()
        session.add(task)
        await _audit_task_state(session, task, "Investigation task blocked.", agent_code, session_id, user_id, {"reason": task.blocker_reason})
        schema = await serialize_investigation_task(session, task)
    return InvestigationTaskMutationResult(task=schema)


async def submit_investigation_task(
    incident_id: int,
    task_id: int,
    result_summary: str,
    *,
    user_id: int,
    user_role: SystemUserRole,
    agent_code: str = "",
    session_id: str = "",
) -> InvestigationTaskMutationResult:
    async with get_async_session() as session, session.begin():
        task, error = await _lock_manageable_task(session, incident_id, task_id, user_id, user_role, agent_code)
        if error is not None:
            return error
        if task.status not in {InvestigationTaskStatus.ACTIVE, InvestigationTaskStatus.BLOCKED}:
            return InvestigationTaskMutationResult(task=None, conflict=True, message="task is not ready for submission")
        uncovered = await _uncovered_event_ids(session, task_id)
        if uncovered:
            return InvestigationTaskMutationResult(
                task=None,
                conflict=True,
                message="task cannot be submitted with uncovered events: " + ", ".join(map(str, uncovered[:20])),
            )
        active_run = (await session.exec(
            select(AgentRun.id).where(
                AgentRun.investigation_task_id == task_id,
                AgentRun.parent_run_id.is_not(None),
                AgentRun.status.in_({
                    AgentRunStatus.QUEUED,
                    AgentRunStatus.RUNNING,
                    AgentRunStatus.WAITING,
                }),
            ).limit(1)
        )).first()
        if active_run is not None:
            return InvestigationTaskMutationResult(task=None, conflict=True, message="task still has an active specialist run")
        task.status = InvestigationTaskStatus.REVIEW
        task.result_summary = result_summary.strip()
        task.blocker_reason = ""
        task.updated_at = utc_now()
        session.add(task)
        await _audit_task_state(session, task, "Investigation task submitted for review.", agent_code, session_id, user_id)
        schema = await serialize_investigation_task(session, task)
    return InvestigationTaskMutationResult(task=schema)


async def review_investigation_task(
    incident_id: int,
    task_id: int,
    decision: InvestigationReviewDecision,
    reason: str,
    *,
    user_id: int,
    user_role: SystemUserRole,
    agent_code: str = "",
    session_id: str = "",
) -> InvestigationTaskMutationResult:
    if agent_code and agent_code != DEFAULT_AGENT_CODE:
        return InvestigationTaskMutationResult(task=None, conflict=True, message="only cso can review investigation tasks")
    async with get_async_session() as session, session.begin():
        task, error = await _lock_manageable_task(session, incident_id, task_id, user_id, user_role, DEFAULT_AGENT_CODE)
        if error is not None:
            return error
        if task.status != InvestigationTaskStatus.REVIEW:
            return InvestigationTaskMutationResult(task=None, conflict=True, message="only submitted tasks can be reviewed")
        if await _uncovered_event_ids(session, task_id):
            return InvestigationTaskMutationResult(task=None, conflict=True, message="task evidence coverage changed during review")
        task.status = (
            InvestigationTaskStatus.COMPLETED
            if decision == InvestigationReviewDecision.ACCEPT
            else InvestigationTaskStatus.ACTIVE
        )
        task.blocker_reason = "" if decision == InvestigationReviewDecision.ACCEPT else reason.strip()
        task.updated_at = utc_now()
        session.add(task)
        await _audit_task_state(
            session,
            task,
            "Investigation task accepted." if decision == InvestigationReviewDecision.ACCEPT else "Investigation task returned for changes.",
            agent_code,
            session_id,
            user_id,
            {"decision": decision.value, "reason": reason.strip()},
        )
        if decision == InvestigationReviewDecision.ACCEPT:
            await _promote_task_analyses(session, task)
            await _activate_ready_dependents(session, task_id)
        else:
            proposals = list((await session.exec(select(AnalysisRecord).where(
                AnalysisRecord.investigation_task_id == task_id,
                AnalysisRecord.review_status == AnalysisReviewStatus.PENDING,
            ).with_for_update())).all())
            for proposal in proposals:
                proposal.review_status = AnalysisReviewStatus.CHANGES_REQUESTED
                proposal.is_current = False
                session.add(proposal)
        schema = await serialize_investigation_task(session, task)
    return InvestigationTaskMutationResult(task=schema)


async def _promote_task_analyses(session, task: InvestigationTask) -> None:
    proposals = list((await session.exec(select(AnalysisRecord).where(
        AnalysisRecord.investigation_task_id == task.id,
        AnalysisRecord.review_status == AnalysisReviewStatus.PENDING,
    ).order_by(AnalysisRecord.version.desc()).with_for_update())).all())
    selected: dict[tuple[AnalysisKind, str], AnalysisRecord] = {}
    for proposal in proposals:
        key = (proposal.kind, proposal.subject_key)
        if key in selected:
            proposal.review_status = AnalysisReviewStatus.CHANGES_REQUESTED
            proposal.is_current = False
            session.add(proposal)
            continue
        selected[key] = proposal
    for (kind, subject_key), proposal in selected.items():
        current_rows = list((await session.exec(select(AnalysisRecord).where(
            AnalysisRecord.incident_id == task.incident_id,
            AnalysisRecord.kind == kind,
            AnalysisRecord.subject_key == subject_key,
            AnalysisRecord.is_current.is_(True),
        ).with_for_update())).all())
        for current in current_rows:
            current.is_current = False
            session.add(current)
        proposal.review_status = AnalysisReviewStatus.ACCEPTED
        proposal.is_current = True
        session.add(proposal)
        if kind == AnalysisKind.RISK:
            risk = await session.get(RiskAssessment, proposal.id)
            incident = await session.get(ThreatIncident, task.incident_id)
            if risk is not None and incident is not None:
                incident.severity = risk.severity
                incident.confidence = risk.confidence
                incident.risk_score = risk.risk_score
                session.add(incident)


async def create_investigation_evidence(
    incident_id: int,
    task_id: int,
    request: CreateInvestigationEvidenceRequest,
    *,
    user_id: int,
    user_role: SystemUserRole,
    agent_code: str = "",
    session_id: str = "",
) -> InvestigationEvidenceMutationResult:
    async with get_async_session() as session, session.begin():
        task, task_error = await _lock_manageable_task(session, incident_id, task_id, user_id, user_role, agent_code)
        if task_error is not None:
            return InvestigationEvidenceMutationResult(
                evidence=None,
                not_found=task_error.not_found,
                forbidden=task_error.forbidden,
                conflict=task_error.conflict,
                message=task_error.message,
            )
        if task.status not in {InvestigationTaskStatus.ACTIVE, InvestigationTaskStatus.BLOCKED}:
            return InvestigationEvidenceMutationResult(evidence=None, conflict=True, message="evidence can only be added to active or blocked tasks")
        event_ids = [item.event_id for item in request.behavior_links]
        rows = list((await session.exec(
            select(InvestigationTaskEvent)
            .where(
                InvestigationTaskEvent.task_id == task_id,
                InvestigationTaskEvent.event_id.in_(event_ids),
            )
            .with_for_update()
        )).all())
        if len(rows) != len(event_ids):
            return InvestigationEvidenceMutationResult(evidence=None, conflict=True, message="evidence event IDs must belong to the task scope")
        try:
            await require_incident_behavior_events(session, incident_id, event_ids)
        except ValueError as exc:
            return InvestigationEvidenceMutationResult(evidence=None, conflict=True, message=str(exc))
        if request.evidence_relations:
            related_ids = list({item.target_evidence_id for item in request.evidence_relations})
            related = list((await session.exec(
                select(InvestigationEvidence, InvestigationTask)
                .join(InvestigationTask, InvestigationTask.id == InvestigationEvidence.task_id)
                .where(InvestigationEvidence.id.in_(related_ids))
            )).all())
            if len(related) != len(related_ids) or any(
                related_task.incident_id != incident_id for _, related_task in related
            ):
                return InvestigationEvidenceMutationResult(evidence=None, conflict=True, message="related evidence must belong to the same incident")
        evidence = InvestigationEvidence(
            task_id=task_id,
            statement=request.statement,
            analysis=request.analysis,
            created_by_agent_code=agent_code,
            created_from_session_id=session_id,
        )
        session.add(evidence)
        await session.flush()
        if evidence.id is None:
            raise RuntimeError("investigation evidence id was not generated")
        session.add_all([
            EvidenceBehaviorLink(
                evidence_id=evidence.id,
                event_id=item.event_id,
                relation=item.relation,
            )
            for item in request.behavior_links
        ])
        session.add_all([
            EvidenceRelation(
                source_evidence_id=evidence.id,
                target_evidence_id=item.target_evidence_id,
                relation=item.relation,
            )
            for item in request.evidence_relations
        ])
        await add_audit_event(
            session,
            incident_id=incident_id,
            task_id=task_id,
            kind=AuditEventKind.EVIDENCE,
            actor_type=_actor_type(agent_code),
            actor_code=agent_code or str(user_id),
            session_id=session_id,
            object_type="investigation_evidence",
            object_id=evidence.id,
            summary="Investigation evidence recorded.",
            details={
                "behavior_links": [item.model_dump(mode="json") for item in request.behavior_links],
                "evidence_relations": [item.model_dump(mode="json") for item in request.evidence_relations],
            },
        )
        schema = await serialize_investigation_evidence(session, evidence)
    return InvestigationEvidenceMutationResult(evidence=schema)


async def query_investigation_tasks_for_user(
    incident_id: int,
    *,
    page: int = 1,
    size: int = RESOURCE_PAGE_SIZE,
    status: InvestigationTaskStatus | None = None,
    keyword: str = "",
    user_id: int,
    user_role: SystemUserRole,
) -> Page[InvestigationTaskSchema] | None:
    async with get_async_session() as session:
        if not await _can_access_incident(session, incident_id, user_id, user_role):
            return None
        statement = select(InvestigationTask).where(InvestigationTask.incident_id == incident_id)
        if status is not None:
            statement = statement.where(InvestigationTask.status == status)
        if keyword := keyword.strip():
            pattern = f"%{keyword}%"
            statement = statement.where(or_(
                InvestigationTask.title.ilike(pattern),
                InvestigationTask.objective.ilike(pattern),
                InvestigationTask.assignee_agent_code.ilike(pattern),
            ))
        statement = statement.order_by(InvestigationTask.updated_at.desc(), InvestigationTask.id.desc())
        total = int((await session.execute(select(func.count()).select_from(statement.order_by(None).subquery()))).scalar_one())
        tasks = list((await session.exec(statement.offset(page_offset(page, size)).limit(size))).all())
        items = [await serialize_investigation_task(session, task) for task in tasks]
    return Page(page=page, size=size, total=total, items=items)


async def query_investigation_evidence_for_user(
    incident_id: int,
    *,
    page: int,
    size: int,
    task_id: int | None,
    user_id: int,
    user_role: SystemUserRole,
) -> Page[InvestigationEvidenceSchema] | None:
    async with get_async_session() as session:
        if not await _can_access_incident(session, incident_id, user_id, user_role):
            return None
        statement = (
            select(InvestigationEvidence)
            .join(InvestigationTask, InvestigationTask.id == InvestigationEvidence.task_id)
            .where(InvestigationTask.incident_id == incident_id)
        )
        if task_id is not None:
            statement = statement.where(InvestigationEvidence.task_id == task_id)
        statement = statement.order_by(InvestigationEvidence.created_at.desc(), InvestigationEvidence.id.desc())
        total = int((await session.execute(select(func.count()).select_from(statement.order_by(None).subquery()))).scalar_one())
        evidence = list((await session.exec(statement.offset(page_offset(page, size)).limit(size))).all())
        items = [await serialize_investigation_evidence(session, item) for item in evidence]
    return Page(page=page, size=size, total=total, items=items)


async def query_audit_events_for_user(
    incident_id: int,
    *,
    page: int,
    size: int,
    task_id: int | None,
    user_id: int,
    user_role: SystemUserRole,
) -> Page[AuditEventSchema] | None:
    async with get_async_session() as session:
        if not await _can_access_incident(session, incident_id, user_id, user_role):
            return None
        statement = select(AuditEvent).where(AuditEvent.incident_id == incident_id)
        if task_id is not None:
            statement = statement.where(AuditEvent.task_id == task_id)
        statement = statement.order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        total = int((await session.execute(select(func.count()).select_from(statement.order_by(None).subquery()))).scalar_one())
        rows = list((await session.exec(statement.offset(page_offset(page, size)).limit(size))).all())
        items = [AuditEventSchema.model_validate(row) for row in rows]
    return Page(page=page, size=size, total=total, items=items)


async def _lock_incident(session, incident_id: int, user_id: int, user_role: SystemUserRole):
    incident = (await session.exec(
        select(ThreatIncident).where(ThreatIncident.id == incident_id).with_for_update()
    )).one_or_none()
    if incident is None:
        return None, {"not_found": True}
    if user_role != SystemUserRole.ADMIN and incident.owner_id != user_id:
        return None, {"forbidden": True}
    if incident.status == ThreatIncidentStatus.CLOSED:
        return None, {"conflict": True, "message": "closed threat incidents are immutable"}
    return incident, None


async def _lock_manageable_task(session, incident_id, task_id, user_id, user_role, agent_code=""):
    _, incident_error = await _lock_incident(session, incident_id, user_id, user_role)
    if incident_error is not None:
        return None, InvestigationTaskMutationResult(task=None, **incident_error)
    task = (await session.exec(
        select(InvestigationTask)
        .where(InvestigationTask.id == task_id, InvestigationTask.incident_id == incident_id)
        .with_for_update()
    )).one_or_none()
    if task is None:
        return None, InvestigationTaskMutationResult(task=None, not_found=True)
    if agent_code and agent_code != DEFAULT_AGENT_CODE and task.assignee_agent_code != agent_code:
        return None, InvestigationTaskMutationResult(task=None, conflict=True, message="task is assigned to another Agent")
    return task, None


async def _can_access_incident(session, incident_id, user_id, user_role):
    incident = await session.get(ThreatIncident, incident_id)
    return incident is not None and (user_role == SystemUserRole.ADMIN or incident.owner_id == user_id)


async def _task_dependency_ids(session, task_id):
    return list((await session.exec(
        select(InvestigationTaskDependency.depends_on_task_id)
        .where(InvestigationTaskDependency.task_id == task_id)
        .order_by(InvestigationTaskDependency.depends_on_task_id.asc())
    )).all())


async def _uncovered_event_ids(session, task_id):
    covered_event_ids = (
        select(EvidenceBehaviorLink.event_id)
        .join(
            InvestigationEvidence,
            InvestigationEvidence.id == EvidenceBehaviorLink.evidence_id,
        )
        .where(InvestigationEvidence.task_id == task_id)
    )
    return list((await session.exec(
        select(InvestigationTaskEvent.event_id)
        .where(
            InvestigationTaskEvent.task_id == task_id,
            InvestigationTaskEvent.event_id.notin_(covered_event_ids),
        )
        .order_by(InvestigationTaskEvent.event_id.asc())
    )).all())


async def serialize_investigation_task(session, task):
    rows = list((await session.exec(
        select(InvestigationTaskEvent).where(InvestigationTaskEvent.task_id == task.id)
    )).all())
    covered_event_ids = set((await session.exec(
        select(EvidenceBehaviorLink.event_id)
        .join(
            InvestigationEvidence,
            InvestigationEvidence.id == EvidenceBehaviorLink.evidence_id,
        )
        .where(InvestigationEvidence.task_id == task.id)
    )).all())
    payload = task.model_dump()
    payload.update({
        "dependency_ids": await _task_dependency_ids(session, task.id),
        "behavior_event_ids": sorted(row.event_id for row in rows),
        "covered_event_ids": sorted(covered_event_ids),
    })
    return InvestigationTaskSchema.model_validate(payload)


async def serialize_investigation_evidence(session, evidence):
    behavior_links = list((await session.exec(
        select(EvidenceBehaviorLink)
        .where(EvidenceBehaviorLink.evidence_id == evidence.id)
        .order_by(EvidenceBehaviorLink.event_id.asc(), EvidenceBehaviorLink.relation.asc())
    )).all())
    evidence_relations = list((await session.exec(
        select(EvidenceRelation)
        .where(EvidenceRelation.source_evidence_id == evidence.id)
        .order_by(EvidenceRelation.target_evidence_id.asc(), EvidenceRelation.relation.asc())
    )).all())
    payload = evidence.model_dump()
    payload["behavior_links"] = [item.model_dump() for item in behavior_links]
    payload["evidence_relations"] = [item.model_dump() for item in evidence_relations]
    return InvestigationEvidenceSchema.model_validate(payload)


async def _activate_ready_dependents(session, completed_task_id):
    dependent_ids = list((await session.exec(
        select(InvestigationTaskDependency.task_id)
        .where(InvestigationTaskDependency.depends_on_task_id == completed_task_id)
    )).all())
    for dependent_id in dependent_ids:
        task = await session.get(InvestigationTask, dependent_id)
        if task is None or task.status != InvestigationTaskStatus.QUEUED:
            continue
        dependencies = await _task_dependency_ids(session, dependent_id)
        completed = set((await session.exec(
            select(InvestigationTask.id).where(
                InvestigationTask.id.in_(dependencies),
                InvestigationTask.status == InvestigationTaskStatus.COMPLETED,
            )
        )).all())
        if len(completed) == len(dependencies):
            task.status = InvestigationTaskStatus.ACTIVE
            task.updated_at = utc_now()
            session.add(task)
            await _audit_task_state(session, task, "Investigation task activated after dependencies completed.", "system", "", 0)


async def _audit_task_state(session, task, summary, agent_code, session_id, user_id, details=None):
    await add_audit_event(
        session,
        incident_id=task.incident_id,
        task_id=task.id,
        kind=AuditEventKind.TASK_STATE,
        actor_type=_actor_type(agent_code),
        actor_code=agent_code or str(user_id),
        session_id=session_id,
        object_type="investigation_task",
        object_id=task.id,
        summary=summary,
        details=details,
    )


def _actor_type(agent_code: str) -> AuditActorType:
    if agent_code == "system":
        return AuditActorType.SYSTEM
    return AuditActorType.AGENT if agent_code else AuditActorType.USER
