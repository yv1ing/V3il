from dataclasses import dataclass
from uuid import uuid4

from sqlalchemy import func, or_
from sqlmodel import select

from core.agent.constants import DEFAULT_AGENT_CODE
from database import get_async_session
from model.agent.sessions import AgentSessionMeta
from model.deception.environments import DeceptionEnvironment
from model.sandbox.containers import SandboxContainer
from model.threat.incidents import ThreatIncident, ThreatIncidentEnvironment
from schema.agent.sessions import SessionType
from schema.system_user.users import SystemUserRole
from schema.threat.incidents import ThreatIncidentSchema, ThreatIncidentStatus
from service.agent.sessions import delete_session, ensure_sdk_session_row, list_sessions
from service.common.pagination import Page, RESOURCE_PAGE_SIZE, page_offset
from service.sandbox.status import status_generation


@dataclass(frozen=True)
class ThreatIncidentSessionResult:
    session_id: str = ""
    not_found: bool = False
    forbidden: bool = False
    conflict: bool = False
    message: str = ""


def _can_access_incident(incident, user_id, user_role):
    return user_role == SystemUserRole.ADMIN or incident.owner_id == user_id


async def get_threat_incident_for_user(id: int, *, user_id: int, user_role: SystemUserRole):
    async with get_async_session() as session:
        incident = await session.get(ThreatIncident, id)
        if incident is None or not _can_access_incident(incident, user_id, user_role):
            return None
        return ThreatIncidentSchema.model_validate(incident)


async def query_threat_incidents_for_user(*, page=1, size=RESOURCE_PAGE_SIZE, keyword="", status=None, environment_id=None, user_id: int, user_role: SystemUserRole):
    statement = select(ThreatIncident)
    if user_role != SystemUserRole.ADMIN:
        statement = statement.where(ThreatIncident.owner_id == user_id)
    if status is not None:
        statement = statement.where(ThreatIncident.status == status)
    if environment_id is not None:
        statement = statement.join(
            ThreatIncidentEnvironment,
            ThreatIncidentEnvironment.incident_id == ThreatIncident.id,
        ).where(ThreatIncidentEnvironment.environment_id == environment_id)
    if keyword := keyword.strip():
        pattern = f"%{keyword}%"
        statement = statement.where(or_(
            ThreatIncident.title.ilike(pattern),
            ThreatIncident.summary.ilike(pattern),
            ThreatIncident.primary_fingerprint.ilike(pattern),
        ))
    statement = statement.order_by(ThreatIncident.last_observed_at.desc(), ThreatIncident.id.desc())
    async with get_async_session() as session:
        total = int((await session.execute(select(func.count()).select_from(statement.order_by(None).subquery()))).scalar_one())
        rows = list((await session.exec(statement.offset(page_offset(page, size)).limit(size))).all())
        items = [ThreatIncidentSchema.model_validate(row) for row in rows]
    return Page(page=page, size=size, total=total, items=items)


async def create_threat_incident_session(incident_id: int, *, user_id: int, user_role: SystemUserRole):
    async with get_async_session() as session, session.begin():
        incident = (await session.exec(select(ThreatIncident).where(ThreatIncident.id == incident_id).with_for_update())).one_or_none()
        if incident is None:
            return ThreatIncidentSessionResult(not_found=True)
        if not _can_access_incident(incident, user_id, user_role):
            return ThreatIncidentSessionResult(forbidden=True)
        if incident.status == ThreatIncidentStatus.CLOSED:
            return ThreatIncidentSessionResult(conflict=True, message="closed threat incidents cannot create investigation sessions")
        container = await _incident_container(session, incident_id)
        if container is None:
            return ThreatIncidentSessionResult(conflict=True, message="incident has no available deception container")
        session_id = str(uuid4())
        await ensure_sdk_session_row(session, session_id)
        session.add(AgentSessionMeta(
            session_id=session_id,
            session_type=SessionType.INCIDENT,
            title=incident.title,
            agent_code=DEFAULT_AGENT_CODE,
            owner_id=user_id,
            incident_id=incident_id,
            selected_sandbox_container_id=container.id,
            selected_sandbox_container_generation=status_generation(container),
        ))
    return ThreatIncidentSessionResult(session_id=session_id)


async def ensure_automated_threat_incident_session_in_session(session, incident):
    if incident.id is None:
        return ThreatIncidentSessionResult(conflict=True, message="threat incident is not persisted")
    if incident.status == ThreatIncidentStatus.CLOSED:
        return ThreatIncidentSessionResult(conflict=True, message="closed threat incidents cannot run autonomous investigation")
    existing = (await session.exec(select(AgentSessionMeta.session_id).where(
        AgentSessionMeta.incident_id == incident.id,
        AgentSessionMeta.is_automated.is_(True),
    ).limit(1))).first()
    if existing is not None:
        return ThreatIncidentSessionResult(session_id=existing)
    container = await _incident_container(session, incident.id)
    if container is None:
        return ThreatIncidentSessionResult(conflict=True, message="incident has no available deception container")
    session_id = str(uuid4())
    await ensure_sdk_session_row(session, session_id)
    session.add(AgentSessionMeta(
        session_id=session_id,
        session_type=SessionType.INCIDENT,
        title=f"Autonomous investigation: {incident.title}",
        agent_code=DEFAULT_AGENT_CODE,
        owner_id=incident.owner_id,
        incident_id=incident.id,
        is_automated=True,
        selected_sandbox_container_id=container.id,
        selected_sandbox_container_generation=status_generation(container),
    ))
    await session.flush()
    return ThreatIncidentSessionResult(session_id=session_id)


async def _incident_container(session, incident_id):
    row = (await session.exec(
        select(SandboxContainer)
        .join(DeceptionEnvironment, DeceptionEnvironment.sandbox_container_id == SandboxContainer.id)
        .join(ThreatIncidentEnvironment, ThreatIncidentEnvironment.environment_id == DeceptionEnvironment.id)
        .where(ThreatIncidentEnvironment.incident_id == incident_id)
        .order_by(ThreatIncidentEnvironment.last_observed_at.desc())
        .limit(1)
    )).first()
    return row


async def list_threat_incident_sessions(incident_id: int, *, page: int, size: int, user_id: int, user_role: SystemUserRole):
    async with get_async_session() as session:
        incident = await session.get(ThreatIncident, incident_id)
        if incident is None or not _can_access_incident(incident, user_id, user_role):
            return None
    return await list_sessions(page=page, size=size, user_id=user_id, user_role=user_role, incident_id=incident_id)


async def delete_threat_incident_session(incident_id: int, session_id: str, *, user_id: int, user_role: SystemUserRole):
    async with get_async_session() as session:
        incident = await session.get(ThreatIncident, incident_id)
        if incident is None or not _can_access_incident(incident, user_id, user_role):
            return None
        meta = await session.get(AgentSessionMeta, session_id)
        if meta is None or meta.incident_id != incident_id:
            return False
    return await delete_session(session_id, user_id=user_id, user_role=user_role, allow_incident_session=True)


async def can_run_threat_incident_session(session_id: str, user_id: int, user_role: SystemUserRole):
    async with get_async_session() as session:
        meta = await session.get(AgentSessionMeta, session_id)
        if meta is None:
            return False
        if meta.incident_id is None:
            return True
        incident = await session.get(ThreatIncident, meta.incident_id)
        return incident is not None and _can_access_incident(incident, user_id, user_role) and incident.status != ThreatIncidentStatus.CLOSED


async def sandbox_container_id_for_threat_incident(incident_id: int):
    async with get_async_session() as session:
        container = await _incident_container(session, incident_id)
        return container.id if container is not None else None
