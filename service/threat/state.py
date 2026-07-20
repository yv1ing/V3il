from datetime import timedelta

from sqlalchemy import func
from sqlmodel import select

from utils.time import utc_now

from config import get_config
from database import get_async_session
from model.agent.sessions import AgentRun, AgentSession
from model.deception.environments import DeceptionRevision
from model.threat.analysis import AnalysisRecord, RiskAssessment
from model.threat.behaviors import ThreatIncidentBehaviorEvent
from model.threat.incidents import ThreatIncident, ThreatIncidentEnvironment
from model.threat.intelligence import IntelligenceReport
from model.threat.investigations import (
    EvidenceBehaviorLink,
    InvestigationEvidence,
    InvestigationTask,
    InvestigationTaskEvent,
)
from schema.agent.sessions import AgentRunStatus
from schema.deception.environments import DeceptionRevisionStatus
from schema.system_user.users import SystemUserRole
from schema.threat.analysis import AnalysisKind
from schema.threat.incidents import (
    THREAT_INCIDENT_STATUS_TRANSITIONS,
    ThreatIncidentSchema,
    ThreatIncidentStatus,
    UpdateThreatIncidentRequest,
)
from schema.threat.intelligence import (
    IntelligenceReportEvidenceManifest,
    IntelligenceReportStatus,
    KnowledgePublicationStatus,
)
from schema.threat.investigations import AuditActorType, AuditEventKind, InvestigationTaskStatus
from service.threat.audit import add_audit_event
from service.agent.repository import request_session_cancellation
from service.threat.intelligence import build_intelligence_report_evidence_manifest
from service.threat.report_readiness import final_report_analysis_error
from service.threat.types import ThreatIncidentMutationResult


async def update_threat_incident(id: int, request: UpdateThreatIncidentRequest, *, user_id: int, user_role: SystemUserRole):
    async with get_async_session() as session, session.begin():
        incident = (await session.exec(select(ThreatIncident).where(ThreatIncident.id == id).with_for_update())).one_or_none()
        if incident is None:
            return ThreatIncidentMutationResult(incident=None, not_found=True)
        if user_role != SystemUserRole.ADMIN and incident.owner_id != user_id:
            return ThreatIncidentMutationResult(incident=None, forbidden=True)
        if incident.status == ThreatIncidentStatus.CLOSED:
            return ThreatIncidentMutationResult(incident=None, conflict=True, message="closed threat incidents are immutable")
        for field, value in request.model_dump(exclude_unset=True).items():
            setattr(incident, field, value)
        incident.updated_at = utc_now()
        session.add(incident)
        await add_audit_event(
            session,
            incident_id=id,
            kind=AuditEventKind.INCIDENT_STATE,
            actor_type=AuditActorType.USER,
            actor_code=str(user_id),
            object_type="threat_incident",
            object_id=id,
            summary="Threat incident metadata updated.",
            details=request.model_dump(exclude_unset=True, mode="json"),
        )
        schema = ThreatIncidentSchema.model_validate(incident)
    return ThreatIncidentMutationResult(incident=schema)


async def transition_threat_incident(
    id: int,
    next_status: ThreatIncidentStatus,
    reason: str,
    *,
    user_id: int,
    user_role: SystemUserRole,
    agent_code: str = "",
    session_id: str = "",
    preserve_session_id: str = "",
    audit_actor_type: AuditActorType | None = None,
    audit_actor_code: str = "",
):
    closed = False
    async with get_async_session() as session, session.begin():
        incident = (await session.exec(select(ThreatIncident).where(ThreatIncident.id == id).with_for_update())).one_or_none()
        if incident is None:
            return ThreatIncidentMutationResult(incident=None, not_found=True)
        if user_role != SystemUserRole.ADMIN and incident.owner_id != user_id:
            return ThreatIncidentMutationResult(incident=None, forbidden=True)
        if next_status not in THREAT_INCIDENT_STATUS_TRANSITIONS[incident.status]:
            return ThreatIncidentMutationResult(incident=None, conflict=True, message=f"incident cannot transition from {incident.status.value} to {next_status.value}")
        if next_status == ThreatIncidentStatus.FINALIZING:
            error = await _finalizing_error(session, id)
            if error:
                return ThreatIncidentMutationResult(incident=None, conflict=True, message=error)
        if next_status == ThreatIncidentStatus.CLOSED:
            error = await _closure_error(session, id)
            if error:
                return ThreatIncidentMutationResult(incident=None, conflict=True, message=error)
            closed = True
        previous = incident.status
        incident.status = next_status
        now = utc_now()
        incident.updated_at = now
        if next_status in {
            ThreatIncidentStatus.OPEN,
            ThreatIncidentStatus.INVESTIGATING,
            ThreatIncidentStatus.ENGAGING,
        }:
            incident.idle_deadline = now + timedelta(
                seconds=get_config().threat_automation.correlation_window_seconds
            )
        else:
            incident.idle_deadline = None
        session.add(incident)
        await add_audit_event(
            session,
            incident_id=id,
            kind=AuditEventKind.INCIDENT_STATE,
            actor_type=audit_actor_type or (
                AuditActorType.AGENT if agent_code else AuditActorType.USER
            ),
            actor_code=audit_actor_code or agent_code or str(user_id),
            session_id=session_id,
            object_type="threat_incident",
            object_id=id,
            summary=f"Threat incident transitioned to {next_status.value}.",
            details={"previous_status": previous.value, "next_status": next_status.value, "reason": reason},
        )
        schema = ThreatIncidentSchema.model_validate(incident)
    if closed:
        async with get_async_session() as session:
            session_ids = list((await session.exec(select(AgentSession.id).where(AgentSession.incident_id == id))).all())
        await request_session_cancellation(
            [item for item in session_ids if item != preserve_session_id],
            reason="Threat incident was closed.",
        )
    return ThreatIncidentMutationResult(incident=schema)


async def _finalizing_error(session, incident_id: int):
    running_revisions = int((await session.exec(
        select(func.count()).select_from(DeceptionRevision).where(
            DeceptionRevision.status.in_({
                DeceptionRevisionStatus.EXECUTING,
                DeceptionRevisionStatus.ROLLING_BACK,
                DeceptionRevisionStatus.RECOVERY_REQUIRED,
            }),
            DeceptionRevision.environment_id.in_(
                select(ThreatIncidentEnvironment.environment_id).where(
                    ThreatIncidentEnvironment.incident_id == incident_id
                )
            ),
        )
    )).one())
    if running_revisions:
        return "incident cannot finalize while a deception revision is running or requires recovery"
    active_specialists = int((await session.exec(
        select(func.count()).select_from(AgentRun).join(
            InvestigationTask,
            InvestigationTask.id == AgentRun.investigation_task_id,
        ).where(
            InvestigationTask.incident_id == incident_id,
            AgentRun.parent_run_id.is_not(None),
            AgentRun.status.in_([AgentRunStatus.QUEUED, AgentRunStatus.RUNNING, AgentRunStatus.WAITING]),
        )
    )).one())
    if active_specialists:
        return f"incident cannot finalize with {active_specialists} active specialist run(s)"
    active_tasks = int((await session.exec(
        select(func.count()).select_from(InvestigationTask).where(
            InvestigationTask.incident_id == incident_id,
            InvestigationTask.status.in_({InvestigationTaskStatus.ACTIVE, InvestigationTaskStatus.BLOCKED, InvestigationTaskStatus.REVIEW}),
        )
    )).one())
    if active_tasks:
        return f"incident cannot finalize with {active_tasks} unresolved investigation task(s)"
    assigned_event_ids = set((await session.exec(
        select(ThreatIncidentBehaviorEvent.event_id).where(
            ThreatIncidentBehaviorEvent.incident_id == incident_id,
            ThreatIncidentBehaviorEvent.is_material.is_(True),
        )
    )).all())
    scoped_event_ids = set((await session.exec(
        select(InvestigationTaskEvent.event_id)
        .join(InvestigationTask, InvestigationTask.id == InvestigationTaskEvent.task_id)
        .where(
            InvestigationTask.incident_id == incident_id,
            InvestigationTask.status != InvestigationTaskStatus.CANCELED,
        )
    )).all())
    unscoped = assigned_event_ids - scoped_event_ids
    if unscoped:
        return f"incident has {len(unscoped)} material behavior event(s) outside investigation scope"
    risk = await _current_analysis_payload(session, incident_id, AnalysisKind.RISK, RiskAssessment)
    if risk is None:
        return "incident cannot finalize without a current risk assessment"
    return ""


async def _closure_error(session, incident_id: int):
    if error := await _finalizing_error(session, incident_id):
        return error
    open_tasks = int((await session.exec(select(func.count()).select_from(InvestigationTask).where(
        InvestigationTask.incident_id == incident_id,
        InvestigationTask.status.notin_({InvestigationTaskStatus.COMPLETED, InvestigationTaskStatus.CANCELED}),
    ))).one())
    if open_tasks:
        return f"incident has {open_tasks} unresolved task(s)"
    covered_event_ids = (
        select(EvidenceBehaviorLink.event_id)
        .join(
            InvestigationEvidence,
            InvestigationEvidence.id == EvidenceBehaviorLink.evidence_id,
        )
        .where(InvestigationEvidence.task_id == InvestigationTaskEvent.task_id)
    )
    uncovered = int((await session.exec(
        select(func.count()).select_from(InvestigationTaskEvent)
        .join(InvestigationTask, InvestigationTask.id == InvestigationTaskEvent.task_id)
        .where(
            InvestigationTask.incident_id == incident_id,
            InvestigationTaskEvent.event_id.notin_(covered_event_ids),
        )
    )).one())
    if uncovered:
        return f"incident has {uncovered} task event(s) without evidence"
    if error := await final_report_analysis_error(session, incident_id):
        return error
    report = (await session.exec(select(IntelligenceReport).where(
        IntelligenceReport.incident_id == incident_id,
        IntelligenceReport.is_current.is_(True),
        IntelligenceReport.status == IntelligenceReportStatus.FINAL,
    ))).one_or_none()
    if report is None:
        return "incident requires a current final intelligence report"
    if report.knowledge_status != KnowledgePublicationStatus.PUBLISHED:
        return "incident final report must be published to LightRAG before closure"
    current_analysis_ids = set((await session.exec(select(AnalysisRecord.id).where(
        AnalysisRecord.incident_id == incident_id,
        AnalysisRecord.is_current.is_(True),
    ))).all())
    try:
        snapshot_ids = {int(item["analysis_id"]) for item in report.analysis_snapshot}
    except (KeyError, TypeError, ValueError):
        return "incident final report contains an invalid analysis snapshot"
    if snapshot_ids != current_analysis_ids:
        return "incident final report does not snapshot every current analysis"
    try:
        expected_manifest = await build_intelligence_report_evidence_manifest(
            session,
            incident_id,
            sorted(snapshot_ids),
        )
    except ValueError as exc:
        return "incident evidence integrity validation failed: " + str(exc)
    try:
        persisted_manifest = IntelligenceReportEvidenceManifest.model_validate(
            report.evidence_manifest
        )
    except ValueError:
        return "incident final report contains an invalid evidence manifest"
    if persisted_manifest != expected_manifest:
        return "incident final report evidence manifest is stale"
    if (
        persisted_manifest.covered_event_count
        != persisted_manifest.material_event_count
    ):
        return "incident final report does not cover every material behavior event"
    return ""


async def _current_analysis_payload(session, incident_id, kind, model):
    row = (await session.exec(
        select(model)
        .join(AnalysisRecord, AnalysisRecord.id == model.analysis_id)
        .where(
            AnalysisRecord.incident_id == incident_id,
            AnalysisRecord.kind == kind,
            AnalysisRecord.is_current.is_(True),
        )
    )).one_or_none()
    return row
