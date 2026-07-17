from dataclasses import dataclass

from sqlalchemy import func
from sqlmodel import select

from database import get_async_session
from model.threat.analysis import (
    AnalysisRecord,
    AttackerProfile,
    IntentAssessment,
    RiskAssessment,
)
from model.threat.incidents import ThreatIncident
from schema.system_user.users import SystemUserRole
from schema.threat.analysis import (
    AnalysisKind,
    AttackerProfileSchema,
    CreateAttackerProfileRequest,
    CreateIntentAssessmentRequest,
    CreateRiskAssessmentRequest,
    IntentAssessmentSchema,
    RiskAssessmentSchema,
)
from schema.threat.incidents import ThreatIncidentStatus
from service.common.pagination import Page, RESOURCE_PAGE_SIZE, page_offset
from service.threat.analysis_records import analysis_evidence_ids, create_analysis_record
from service.threat.audit import add_audit_event
from schema.threat.investigations import AuditActorType, AuditEventKind


@dataclass(frozen=True)
class AnalysisMutationResult:
    item: IntentAssessmentSchema | AttackerProfileSchema | RiskAssessmentSchema | None
    not_found: bool = False
    forbidden: bool = False
    conflict: bool = False
    message: str = ""

    @property
    def assessment(self):
        return self.item

    @property
    def profile(self):
        return self.item

    @property
    def risk(self):
        return self.item


IntentAssessmentMutationResult = AnalysisMutationResult
AttackerProfileMutationResult = AnalysisMutationResult
RiskAssessmentMutationResult = AnalysisMutationResult


async def create_intent_assessment(
    incident_id: int,
    request: CreateIntentAssessmentRequest,
    *,
    user_id: int,
    user_role: SystemUserRole,
    agent_code: str = "",
    session_id: str = "",
    investigation_task_id: int | None = None,
) -> AnalysisMutationResult:
    async with get_async_session() as session, session.begin():
        incident, error = await _lock_incident(session, incident_id, user_id, user_role)
        if error:
            return AnalysisMutationResult(item=None, **error)
        try:
            record = await create_analysis_record(
                session,
                incident_id=incident_id,
                kind=AnalysisKind.INTENT,
                subject_key="default",
                evidence_ids=request.evidence_ids,
                agent_code=agent_code,
                source_session_id=session_id,
                investigation_task_id=investigation_task_id,
            )
        except ValueError as exc:
            return AnalysisMutationResult(item=None, conflict=True, message=str(exc))
        row = IntentAssessment(analysis_id=record.id, **request.model_dump(exclude={"evidence_ids"}))
        session.add(row)
        await session.flush()
        await _audit_analysis(session, incident_id, record, "Intent assessment version created.", agent_code, session_id, user_id)
        schema = await serialize_intent_assessment(session, record, row)
    return AnalysisMutationResult(item=schema)


async def create_attacker_profile(
    incident_id: int,
    request: CreateAttackerProfileRequest,
    *,
    user_id: int,
    user_role: SystemUserRole,
    agent_code: str = "",
    session_id: str = "",
    investigation_task_id: int | None = None,
) -> AnalysisMutationResult:
    async with get_async_session() as session, session.begin():
        _, error = await _lock_incident(session, incident_id, user_id, user_role)
        if error:
            return AnalysisMutationResult(item=None, **error)
        try:
            record = await create_analysis_record(
                session,
                incident_id=incident_id,
                kind=AnalysisKind.ATTACKER_PROFILE,
                subject_key="default",
                evidence_ids=request.evidence_ids,
                agent_code=agent_code,
                source_session_id=session_id,
                investigation_task_id=investigation_task_id,
            )
        except ValueError as exc:
            return AnalysisMutationResult(item=None, conflict=True, message=str(exc))
        row = AttackerProfile(analysis_id=record.id, **request.model_dump(exclude={"evidence_ids"}))
        session.add(row)
        await session.flush()
        await _audit_analysis(session, incident_id, record, "Attacker profile version created.", agent_code, session_id, user_id)
        schema = await serialize_attacker_profile(session, record, row)
    return AnalysisMutationResult(item=schema)


async def create_risk_assessment(
    incident_id: int,
    request: CreateRiskAssessmentRequest,
    *,
    user_id: int,
    user_role: SystemUserRole,
    agent_code: str = "",
    session_id: str = "",
    investigation_task_id: int | None = None,
) -> AnalysisMutationResult:
    async with get_async_session() as session, session.begin():
        incident, error = await _lock_incident(session, incident_id, user_id, user_role)
        if error:
            return AnalysisMutationResult(item=None, **error)
        try:
            record = await create_analysis_record(
                session,
                incident_id=incident_id,
                kind=AnalysisKind.RISK,
                subject_key="default",
                evidence_ids=request.evidence_ids,
                agent_code=agent_code,
                source_session_id=session_id,
                investigation_task_id=investigation_task_id,
            )
        except ValueError as exc:
            return AnalysisMutationResult(item=None, conflict=True, message=str(exc))
        row = RiskAssessment(analysis_id=record.id, **request.model_dump(exclude={"evidence_ids"}))
        session.add(row)
        if record.is_current:
            incident.severity = request.severity
            incident.confidence = request.confidence
            incident.risk_score = request.risk_score
            session.add(incident)
        await session.flush()
        await _audit_analysis(session, incident_id, record, "Risk assessment version created.", agent_code, session_id, user_id)
        schema = await serialize_risk_assessment(session, record, row)
    return AnalysisMutationResult(item=schema)


async def query_intent_assessments_for_user(incident_id: int, *, page=1, size=RESOURCE_PAGE_SIZE, user_id: int, user_role: SystemUserRole):
    return await _query_analysis(incident_id, AnalysisKind.INTENT, IntentAssessment, serialize_intent_assessment, page, size, user_id, user_role)


async def query_attacker_profiles_for_user(incident_id: int, *, page=1, size=RESOURCE_PAGE_SIZE, user_id: int, user_role: SystemUserRole):
    return await _query_analysis(incident_id, AnalysisKind.ATTACKER_PROFILE, AttackerProfile, serialize_attacker_profile, page, size, user_id, user_role)


async def query_risk_assessments_for_user(incident_id: int, *, page=1, size=RESOURCE_PAGE_SIZE, user_id: int, user_role: SystemUserRole):
    return await _query_analysis(incident_id, AnalysisKind.RISK, RiskAssessment, serialize_risk_assessment, page, size, user_id, user_role)


async def _query_analysis(incident_id, kind, model, serializer, page, size, user_id, user_role):
    async with get_async_session() as session:
        incident = await session.get(ThreatIncident, incident_id)
        if incident is None or (user_role != SystemUserRole.ADMIN and incident.owner_id != user_id):
            return None
        statement = (
            select(AnalysisRecord, model)
            .join(model, model.analysis_id == AnalysisRecord.id)
            .where(AnalysisRecord.incident_id == incident_id, AnalysisRecord.kind == kind)
            .order_by(AnalysisRecord.version.desc())
        )
        total = int((await session.execute(select(func.count()).select_from(statement.order_by(None).subquery()))).scalar_one())
        rows = list((await session.exec(statement.offset(page_offset(page, size)).limit(size))).all())
        items = [await serializer(session, record, payload) for record, payload in rows]
    return Page(page=page, size=size, total=total, items=items)


async def _lock_incident(session, incident_id, user_id, user_role):
    incident = (await session.exec(select(ThreatIncident).where(ThreatIncident.id == incident_id).with_for_update())).one_or_none()
    if incident is None:
        return None, {"not_found": True}
    if user_role != SystemUserRole.ADMIN and incident.owner_id != user_id:
        return None, {"forbidden": True}
    if incident.status == ThreatIncidentStatus.CLOSED:
        return None, {"conflict": True, "message": "closed threat incidents are immutable"}
    return incident, None


async def _base_payload(session, record):
    payload = record.model_dump()
    payload["evidence_ids"] = await analysis_evidence_ids(session, record.id)
    return payload


async def serialize_intent_assessment(session, record, row):
    return IntentAssessmentSchema.model_validate({**await _base_payload(session, record), **row.model_dump(exclude={"analysis_id"})})


async def serialize_attacker_profile(session, record, row):
    return AttackerProfileSchema.model_validate({**await _base_payload(session, record), **row.model_dump(exclude={"analysis_id"})})


async def serialize_risk_assessment(session, record, row):
    return RiskAssessmentSchema.model_validate({**await _base_payload(session, record), **row.model_dump(exclude={"analysis_id"})})


async def _audit_analysis(session, incident_id, record, summary, agent_code, source_session_id, user_id):
    await add_audit_event(
        session,
        incident_id=incident_id,
        kind=AuditEventKind.ANALYSIS,
        actor_type=AuditActorType.AGENT if agent_code else AuditActorType.USER,
        actor_code=agent_code or str(user_id),
        session_id=source_session_id,
        object_type=record.kind.value,
        object_id=record.id,
        summary=summary,
        details={"version": record.version, "subject_key": record.subject_key},
    )
