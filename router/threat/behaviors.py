from fastapi import APIRouter, Depends, Query

from handler.threat.behaviors import (
    assign_behavior_events_handler,
    ingest_behavior_event_batch_handler,
    query_incident_behavior_events_handler,
    query_behavior_events_handler,
)
from middleware.system_user import AuthUser, require_user
from router.common.responses import COMMON_ERROR_RESPONSES, CONFLICT_RESPONSE, FORBIDDEN_RESPONSE, not_found_response
from schema.common.responses import CommonResponse
from schema.threat.behaviors import (
    BehaviorEventCategory,
    AssignBehaviorEventsRequest,
    AssignBehaviorEventsResponse,
    ImportBehaviorEventBatchRequest,
    IngestBehaviorEventBatchResponse,
    QueryBehaviorEventsResponse,
)
from service.common.pagination import RESOURCE_PAGE_MAX_SIZE, RESOURCE_PAGE_SIZE


NOT_FOUND_RESPONSE = not_found_response("Deception environment")

router = APIRouter(
    prefix="/deception-environments/{environment_id}/behavior-events",
    tags=["behavior-events"],
    dependencies=[Depends(require_user)],
)


async def ingest_behavior_event_batch_route(
    environment_id: int,
    request: ImportBehaviorEventBatchRequest,
    user: AuthUser = Depends(require_user),
) -> CommonResponse[IngestBehaviorEventBatchResponse]:
    return await ingest_behavior_event_batch_handler(environment_id, request, user)


async def query_behavior_events_route(
    environment_id: int,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=RESOURCE_PAGE_SIZE, ge=1, le=RESOURCE_PAGE_MAX_SIZE),
    category: BehaviorEventCategory | None = Query(default=None),
    incident_id: int | None = Query(default=None, gt=0),
    keyword: str = Query(default=""),
    user: AuthUser = Depends(require_user),
) -> CommonResponse[QueryBehaviorEventsResponse]:
    return await query_behavior_events_handler(
        environment_id,
        page=page,
        size=size,
        category=category,
        incident_id=incident_id,
        keyword=keyword,
        user=user,
    )


router.add_api_route(
    "/ingest",
    ingest_behavior_event_batch_route,
    methods=["POST"],
    response_model=CommonResponse[IngestBehaviorEventBatchResponse],
    responses={**COMMON_ERROR_RESPONSES, **FORBIDDEN_RESPONSE, **CONFLICT_RESPONSE, **NOT_FOUND_RESPONSE},
)
router.add_api_route(
    "",
    query_behavior_events_route,
    methods=["GET"],
    response_model=CommonResponse[QueryBehaviorEventsResponse],
    responses={**COMMON_ERROR_RESPONSES, **NOT_FOUND_RESPONSE},
)


incident_router = APIRouter(
    prefix="/threat-incidents",
    tags=["behavior-events"],
    dependencies=[Depends(require_user)],
)


async def assign_behavior_events_route(
    id: int,
    request: AssignBehaviorEventsRequest,
    user: AuthUser = Depends(require_user),
) -> CommonResponse[AssignBehaviorEventsResponse]:
    return await assign_behavior_events_handler(id, request, user)


async def query_incident_behavior_events_route(
    id: int,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=RESOURCE_PAGE_SIZE, ge=1, le=RESOURCE_PAGE_MAX_SIZE),
    category: BehaviorEventCategory | None = Query(default=None),
    keyword: str = Query(default=""),
    user: AuthUser = Depends(require_user),
) -> CommonResponse[QueryBehaviorEventsResponse]:
    return await query_incident_behavior_events_handler(
        id,
        page=page,
        size=size,
        category=category,
        keyword=keyword,
        user=user,
    )


incident_router.add_api_route(
    "/{id}/behavior-events",
    query_incident_behavior_events_route,
    methods=["GET"],
    response_model=CommonResponse[QueryBehaviorEventsResponse],
    responses={**COMMON_ERROR_RESPONSES, **not_found_response("Threat incident")},
)


incident_router.add_api_route(
    "/{id}/behavior-events",
    assign_behavior_events_route,
    methods=["POST"],
    response_model=CommonResponse[AssignBehaviorEventsResponse],
    responses={**COMMON_ERROR_RESPONSES, **CONFLICT_RESPONSE, **NOT_FOUND_RESPONSE},
)
