from dataclasses import dataclass

from sqlalchemy import func
from sqlmodel import select

from database import get_async_session
from model.threat.analysis import AnalysisRecord
from model.threat.chains import AttackChain
from model.threat.incidents import ThreatIncident
from schema.system_user.users import SystemUserRole
from schema.threat.analysis import AnalysisKind
from schema.threat.chains import AttackChainSchema, CreateAttackChainRequest
from schema.threat.incidents import ThreatIncidentStatus
from schema.threat.investigations import AuditActorType, AuditEventKind
from service.common.pagination import Page, RESOURCE_PAGE_SIZE, page_offset
from service.threat.analysis_records import analysis_evidence_ids, create_analysis_record
from service.threat.audit import add_audit_event


@dataclass(frozen=True)
class AttackChainMutationResult:
    chain: AttackChainSchema | None
    not_found: bool = False
    forbidden: bool = False
    conflict: bool = False
    message: str = ""


async def create_attack_chain(incident_id: int, request: CreateAttackChainRequest, *, user_id: int, user_role: SystemUserRole, agent_code: str = "", session_id: str = "", investigation_task_id: int | None = None) -> AttackChainMutationResult:
    async with get_async_session() as session, session.begin():
        incident = (await session.exec(select(ThreatIncident).where(ThreatIncident.id == incident_id).with_for_update())).one_or_none()
        if incident is None:
            return AttackChainMutationResult(chain=None, not_found=True)
        if user_role != SystemUserRole.ADMIN and incident.owner_id != user_id:
            return AttackChainMutationResult(chain=None, forbidden=True)
        if incident.status == ThreatIncidentStatus.CLOSED:
            return AttackChainMutationResult(chain=None, conflict=True, message="closed threat incidents are immutable")
        try:
            record = await create_analysis_record(
                session,
                incident_id=incident_id,
                kind=AnalysisKind.ATTACK_CHAIN,
                subject_key="default",
                evidence_ids=request.evidence_ids,
                agent_code=agent_code,
                source_session_id=session_id,
                investigation_task_id=investigation_task_id,
            )
        except ValueError as exc:
            return AttackChainMutationResult(chain=None, conflict=True, message=str(exc))
        chain = AttackChain(
            analysis_id=record.id,
            status=request.status,
            summary=request.summary,
            steps=[step.model_dump(mode="json") for step in request.steps],
            gaps=request.gaps,
        )
        session.add(chain)
        await session.flush()
        await add_audit_event(
            session,
            incident_id=incident_id,
            kind=AuditEventKind.ANALYSIS,
            actor_type=AuditActorType.AGENT if agent_code else AuditActorType.USER,
            actor_code=agent_code or str(user_id),
            session_id=session_id,
            object_type="attack_chain",
            object_id=record.id,
            summary="Attack chain version created.",
            details={"version": record.version, "status": request.status.value},
        )
        schema = await serialize_attack_chain(session, record, chain)
    return AttackChainMutationResult(chain=schema)


async def query_attack_chains_for_user(incident_id: int, *, page=1, size=RESOURCE_PAGE_SIZE, user_id: int, user_role: SystemUserRole):
    async with get_async_session() as session:
        incident = await session.get(ThreatIncident, incident_id)
        if incident is None or (user_role != SystemUserRole.ADMIN and incident.owner_id != user_id):
            return None
        statement = (
            select(AnalysisRecord, AttackChain)
            .join(AttackChain, AttackChain.analysis_id == AnalysisRecord.id)
            .where(AnalysisRecord.incident_id == incident_id, AnalysisRecord.kind == AnalysisKind.ATTACK_CHAIN)
            .order_by(AnalysisRecord.version.desc())
        )
        total = int((await session.execute(select(func.count()).select_from(statement.order_by(None).subquery()))).scalar_one())
        rows = list((await session.exec(statement.offset(page_offset(page, size)).limit(size))).all())
        items = [await serialize_attack_chain(session, record, chain) for record, chain in rows]
    return Page(page=page, size=size, total=total, items=items)


async def serialize_attack_chain(session, record, chain):
    return AttackChainSchema.model_validate({
        **record.model_dump(),
        "evidence_ids": await analysis_evidence_ids(session, record.id),
        **chain.model_dump(exclude={"analysis_id"}),
    })
