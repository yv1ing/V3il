from http import HTTPStatus

from handler.common.http import raise_api_error
from middleware.system_user import AuthUser
from schema.common.responses import CommonResponse
from schema.threat.behaviors import (
    AssignBehaviorEventsRequest,
    ImportBehaviorEventBatchRequest,
    QueryBehaviorEventsResponse,
)
from service.common.pagination import paginated_payload
from service.threat.behaviors import (
    assign_behavior_events_to_incident,
    ingest_imported_behavior_event_batch,
    query_behavior_events_for_user,
    query_incident_behavior_events_for_user,
)
from service.threat.orchestration import orchestrate_behavior_events


async def ingest_behavior_event_batch_handler(
    environment_id: int,
    request: ImportBehaviorEventBatchRequest,
    user: AuthUser,
) -> CommonResponse:
    result = await ingest_imported_behavior_event_batch(
        environment_id,
        request,
        user_id=user.id,
        user_role=user.role,
    )
    if result.not_found:
        raise_api_error(HTTPStatus.NOT_FOUND, result.message or "deception environment not found")
    if result.forbidden:
        raise_api_error(HTTPStatus.FORBIDDEN, "deception environment is not accessible by user")
    if result.conflict:
        raise_api_error(HTTPStatus.CONFLICT, result.message or "behavior event ingestion conflict")
    if result.response is None:
        raise RuntimeError("behavior event ingestion failed without an error classification")
    await orchestrate_behavior_events(environment_id, list(result.new_event_ids))
    return CommonResponse(message="behavior event batch ingested", data=result.response)


async def query_behavior_events_handler(
    environment_id: int,
    *,
    page: int,
    size: int,
    category,
    incident_id: int | None,
    keyword: str,
    user: AuthUser,
) -> CommonResponse:
    events = await query_behavior_events_for_user(
        environment_id,
        page=page,
        size=size,
        category=category,
        incident_id=incident_id,
        keyword=keyword,
        user_id=user.id,
        user_role=user.role,
    )
    if events is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "deception environment not found")
    return CommonResponse(data=QueryBehaviorEventsResponse(
        **paginated_payload(events, events.items),
    ))


async def assign_behavior_events_handler(
    incident_id: int,
    request: AssignBehaviorEventsRequest,
    user: AuthUser,
) -> CommonResponse:
    try:
        result = await assign_behavior_events_to_incident(
            incident_id,
            request,
            user_id=user.id,
            user_role=user.role,
        )
    except ValueError as exc:
        raise_api_error(HTTPStatus.CONFLICT, str(exc))
    if result is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "threat incident not found")
    return CommonResponse(message="behavior events assigned", data=result)


async def query_incident_behavior_events_handler(
    incident_id: int,
    *,
    page: int,
    size: int,
    category,
    keyword: str,
    user: AuthUser,
) -> CommonResponse:
    events = await query_incident_behavior_events_for_user(
        incident_id,
        page=page,
        size=size,
        category=category,
        keyword=keyword,
        user_id=user.id,
        user_role=user.role,
    )
    if events is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "threat incident not found")
    return CommonResponse(data=QueryBehaviorEventsResponse(
        **paginated_payload(events, events.items),
    ))
