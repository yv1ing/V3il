from http import HTTPStatus

from handler.common.http import raise_api_error
from middleware.system_user import AuthUser
from schema.common.responses import CommonResponse
from schema.threat.incidents import (
    CreateThreatIncidentSessionResponse,
    ListThreatIncidentSessionsResponse,
    QueryThreatIncidentsResponse,
    ThreatIncidentStatus,
    TransitionThreatIncidentRequest,
    UpdateThreatIncidentRequest,
)
from service.common.pagination import paginated_payload
from service.threat.incidents import (
    create_threat_incident_session,
    delete_threat_incident_session,
    get_threat_incident_for_user,
    list_threat_incident_sessions,
    query_threat_incidents_for_user,
)
from service.threat.state import transition_threat_incident, update_threat_incident
from service.threat.workspace import get_incident_timeline, get_incident_workspace


def _raise_result(result):
    if result.not_found:
        raise_api_error(HTTPStatus.NOT_FOUND, result.message or "threat incident not found")
    if result.forbidden:
        raise_api_error(HTTPStatus.FORBIDDEN, result.message or "threat incident is not accessible by user")
    if result.conflict:
        raise_api_error(HTTPStatus.CONFLICT, result.message or "threat incident state conflict")
    raise RuntimeError("threat incident mutation failed without classification")


async def get_threat_incident_handler(id: int, user: AuthUser):
    incident = await get_threat_incident_for_user(id, user_id=user.id, user_role=user.role)
    if incident is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "threat incident not found")
    return CommonResponse(data=incident)


async def query_threat_incidents_handler(*, page, size, keyword, status, environment_id, user):
    result = await query_threat_incidents_for_user(
        page=page,
        size=size,
        keyword=keyword,
        status=status,
        environment_id=environment_id,
        user_id=user.id,
        user_role=user.role,
    )
    return CommonResponse(data=QueryThreatIncidentsResponse(**paginated_payload(result, result.items)))


async def update_threat_incident_handler(id: int, request: UpdateThreatIncidentRequest, user: AuthUser):
    result = await update_threat_incident(id, request, user_id=user.id, user_role=user.role)
    if result.incident is None:
        _raise_result(result)
    return CommonResponse(message="threat incident updated", data=result.incident)


async def transition_threat_incident_handler(id: int, status: ThreatIncidentStatus, request: TransitionThreatIncidentRequest, user: AuthUser):
    result = await transition_threat_incident(id, status, request.reason, user_id=user.id, user_role=user.role)
    if result.incident is None:
        _raise_result(result)
    return CommonResponse(message=f"threat incident transitioned to {status.value}", data=result.incident)


async def create_threat_incident_session_handler(id: int, user: AuthUser):
    result = await create_threat_incident_session(id, user_id=user.id, user_role=user.role)
    if not result.session_id:
        _raise_result(result)
    return CommonResponse(data=CreateThreatIncidentSessionResponse(session_id=result.session_id))


async def list_threat_incident_sessions_handler(id: int, page: int, size: int, user: AuthUser):
    result = await list_threat_incident_sessions(id, page=page, size=size, user_id=user.id, user_role=user.role)
    if result is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "threat incident not found")
    return CommonResponse(data=ListThreatIncidentSessionsResponse(**paginated_payload(result, result.items)))


async def delete_threat_incident_session_handler(id: int, session_id: str, user: AuthUser):
    result = await delete_threat_incident_session(id, session_id, user_id=user.id, user_role=user.role)
    if result is None or not result:
        raise_api_error(HTTPStatus.NOT_FOUND, "threat incident session not found")
    return CommonResponse(message="threat incident session deleted")


async def get_threat_incident_workspace_handler(id: int, user: AuthUser):
    result = await get_incident_workspace(id, user_id=user.id, user_role=user.role)
    if result is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "threat incident not found")
    return CommonResponse(data=result)


async def get_threat_incident_timeline_handler(id: int, *, before, limit: int, user: AuthUser):
    result = await get_incident_timeline(id, before=before, limit=limit, user_id=user.id, user_role=user.role)
    if result is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "threat incident not found")
    return CommonResponse(data=result)
