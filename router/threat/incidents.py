from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response

from handler.threat.incidents import (
    ensure_threat_incident_session_handler,
    get_threat_incident_session_handler,
    get_threat_incident_handler,
    get_threat_incident_timeline_handler,
    get_threat_incident_workspace_handler,
    query_threat_incidents_handler,
    transition_threat_incident_handler,
    update_threat_incident_handler,
)
from middleware.system_user import AuthUser, require_user
from router.common.responses import COMMON_ERROR_RESPONSES, CONFLICT_RESPONSE, FORBIDDEN_RESPONSE, not_found_response
from schema.common.responses import CommonResponse
from schema.agent.sessions import AgentSessionSummarySchema
from schema.threat.incidents import (
    QueryThreatIncidentsResponse,
    THREAT_INCIDENT_ACTION_TARGETS,
    ThreatIncidentSchema,
    ThreatIncidentStatus,
    TransitionThreatIncidentRequest,
    UpdateThreatIncidentRequest,
)
from schema.threat.workspace import (
    ThreatIncidentWorkspaceSchema,
    ThreatTimelineQuery,
    ThreatTimelineResponse,
)
from service.threat.report_export import build_report_bundle
from service.common.pagination import RESOURCE_PAGE_MAX_SIZE, RESOURCE_PAGE_SIZE


router = APIRouter(prefix="/threat-incidents", tags=["threat-incidents"], dependencies=[Depends(require_user)])
errors = {**COMMON_ERROR_RESPONSES, **FORBIDDEN_RESPONSE, **CONFLICT_RESPONSE, **not_found_response("Threat incident")}


async def query_route(page: int = Query(1, ge=1), size: int = Query(RESOURCE_PAGE_SIZE, ge=1, le=RESOURCE_PAGE_MAX_SIZE), keyword: str = "", status: ThreatIncidentStatus | None = None, environment_id: int | None = Query(None, gt=0), user: AuthUser = Depends(require_user)):
    return await query_threat_incidents_handler(page=page, size=size, keyword=keyword, status=status, environment_id=environment_id, user=user)


async def get_route(id: int, user: AuthUser = Depends(require_user)):
    return await get_threat_incident_handler(id, user)


async def update_route(id: int, request: UpdateThreatIncidentRequest, user: AuthUser = Depends(require_user)):
    return await update_threat_incident_handler(id, request, user)


async def session_route(id: int, user: AuthUser = Depends(require_user)):
    return await ensure_threat_incident_session_handler(id, user)


async def get_session_route(id: int, user: AuthUser = Depends(require_user)):
    return await get_threat_incident_session_handler(id, user)


async def workspace_route(id: int, user: AuthUser = Depends(require_user)):
    return await get_threat_incident_workspace_handler(id, user)


async def timeline_route(
    id: int,
    query: Annotated[ThreatTimelineQuery, Query()],
    user: AuthUser = Depends(require_user),
):
    return await get_threat_incident_timeline_handler(id, query=query, user=user)


async def report_download_route(id: int, report_id: int, user: AuthUser = Depends(require_user)):
    try:
        bundle = await build_report_bundle(id, report_id, user_id=user.id, user_role=user.role)
    except ValueError as exc:
        from handler.common.http import raise_api_error
        raise_api_error(409, str(exc))
    if bundle is None:
        from handler.common.http import raise_api_error
        raise_api_error(404, "intelligence report not found")
    content, filename = bundle
    return Response(
        content=content,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


router.add_api_route("", query_route, methods=["GET"], response_model=CommonResponse[QueryThreatIncidentsResponse], responses=COMMON_ERROR_RESPONSES)
router.add_api_route("/{id}", get_route, methods=["GET"], response_model=CommonResponse[ThreatIncidentSchema], responses=errors)
router.add_api_route("/{id}", update_route, methods=["PATCH"], response_model=CommonResponse[ThreatIncidentSchema], responses=errors)
router.add_api_route("/{id}/workspace", workspace_route, methods=["GET"], response_model=CommonResponse[ThreatIncidentWorkspaceSchema], responses=errors)
router.add_api_route("/{id}/timeline", timeline_route, methods=["GET"], response_model=CommonResponse[ThreatTimelineResponse], responses=errors)
router.add_api_route(
    "/{id}/reports/{report_id}/download",
    report_download_route,
    methods=["GET"],
    response_class=Response,
    responses={
        200: {
            "description": "Formal intelligence report and evidence bundle.",
            "content": {"application/zip": {}},
        },
        **errors,
    },
)
for action, status in THREAT_INCIDENT_ACTION_TARGETS.items():
    async def transition_route(id: int, request: TransitionThreatIncidentRequest, user: AuthUser = Depends(require_user), target=status):
        return await transition_threat_incident_handler(id, target, request, user)
    transition_route.__name__ = f"{action.value.replace('-', '_')}_threat_incident"
    router.add_api_route(f"/{{id}}/{action.value}", transition_route, methods=["POST"], response_model=CommonResponse[ThreatIncidentSchema], responses=errors)
router.add_api_route("/{id}/session", session_route, methods=["PUT"], response_model=CommonResponse[AgentSessionSummarySchema], responses=errors)
router.add_api_route("/{id}/session", get_session_route, methods=["GET"], response_model=CommonResponse[AgentSessionSummarySchema], responses=errors)
