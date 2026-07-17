from http import HTTPStatus

from handler.common.http import raise_api_error
from schema.common.responses import CommonResponse
from schema.threat.investigations import (
    BlockInvestigationTaskRequest,
    CreateInvestigationEvidenceRequest,
    CreateInvestigationTaskRequest,
    QueryAuditEventsResponse,
    QueryInvestigationEvidenceResponse,
    QueryInvestigationTasksResponse,
    ReviewInvestigationTaskRequest,
    SubmitInvestigationTaskRequest,
)
from service.common.pagination import paginated_payload
from service.threat.investigations import (
    activate_investigation_task,
    block_investigation_task,
    create_investigation_evidence,
    create_investigation_task,
    query_audit_events_for_user,
    query_investigation_evidence_for_user,
    query_investigation_tasks_for_user,
    review_investigation_task,
    submit_investigation_task,
)


def _raise_result(result):
    if result.not_found:
        raise_api_error(HTTPStatus.NOT_FOUND, result.message or "investigation resource not found")
    if result.forbidden:
        raise_api_error(HTTPStatus.FORBIDDEN, result.message or "threat incident is not accessible by user")
    if result.conflict:
        raise_api_error(HTTPStatus.CONFLICT, result.message or "investigation state conflict")
    raise RuntimeError("investigation mutation failed without classification")


async def create_investigation_task_handler(incident_id, request: CreateInvestigationTaskRequest, user):
    result = await create_investigation_task(incident_id, request, user_id=user.id, user_role=user.role)
    if result.task is None:
        _raise_result(result)
    return CommonResponse(message="investigation task created", data=result.task)


async def query_investigation_tasks_handler(incident_id, *, page, size, status, keyword, user):
    result = await query_investigation_tasks_for_user(incident_id, page=page, size=size, status=status, keyword=keyword, user_id=user.id, user_role=user.role)
    if result is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "threat incident not found")
    return CommonResponse(data=QueryInvestigationTasksResponse(**paginated_payload(result, result.items)))


async def activate_investigation_task_handler(incident_id, task_id, user):
    result = await activate_investigation_task(incident_id, task_id, user_id=user.id, user_role=user.role)
    if result.task is None:
        _raise_result(result)
    return CommonResponse(message="investigation task activated", data=result.task)


async def block_investigation_task_handler(incident_id, task_id, request: BlockInvestigationTaskRequest, user):
    result = await block_investigation_task(incident_id, task_id, request.reason, user_id=user.id, user_role=user.role)
    if result.task is None:
        _raise_result(result)
    return CommonResponse(message="investigation task blocked", data=result.task)


async def submit_investigation_task_handler(incident_id, task_id, request: SubmitInvestigationTaskRequest, user):
    result = await submit_investigation_task(incident_id, task_id, request.result_summary, user_id=user.id, user_role=user.role)
    if result.task is None:
        _raise_result(result)
    return CommonResponse(message="investigation task submitted", data=result.task)


async def review_investigation_task_handler(incident_id, task_id, request: ReviewInvestigationTaskRequest, user):
    result = await review_investigation_task(incident_id, task_id, request.decision, request.reason, user_id=user.id, user_role=user.role)
    if result.task is None:
        _raise_result(result)
    return CommonResponse(message="investigation task reviewed", data=result.task)


async def create_investigation_evidence_handler(incident_id, task_id, request: CreateInvestigationEvidenceRequest, user):
    result = await create_investigation_evidence(incident_id, task_id, request, user_id=user.id, user_role=user.role)
    if result.evidence is None:
        _raise_result(result)
    return CommonResponse(message="investigation evidence created", data=result.evidence)


async def query_investigation_evidence_handler(incident_id, *, page, size, task_id, user):
    result = await query_investigation_evidence_for_user(incident_id, page=page, size=size, task_id=task_id, user_id=user.id, user_role=user.role)
    if result is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "threat incident not found")
    return CommonResponse(data=QueryInvestigationEvidenceResponse(**paginated_payload(result, result.items)))


async def query_audit_events_handler(incident_id, *, page, size, task_id, user):
    result = await query_audit_events_for_user(incident_id, page=page, size=size, task_id=task_id, user_id=user.id, user_role=user.role)
    if result is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "threat incident not found")
    return CommonResponse(data=QueryAuditEventsResponse(**paginated_payload(result, result.items)))
