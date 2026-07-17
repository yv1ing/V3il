from fastapi import APIRouter, Depends, Query

from handler.threat.investigations import (
    activate_investigation_task_handler,
    block_investigation_task_handler,
    create_investigation_evidence_handler,
    create_investigation_task_handler,
    query_audit_events_handler,
    query_investigation_evidence_handler,
    query_investigation_tasks_handler,
    review_investigation_task_handler,
    submit_investigation_task_handler,
)
from middleware.system_user import AuthUser, require_user
from router.common.responses import COMMON_ERROR_RESPONSES, CONFLICT_RESPONSE, FORBIDDEN_RESPONSE, not_found_response
from schema.common.responses import CommonResponse
from schema.threat.investigations import (
    BlockInvestigationTaskRequest,
    CreateInvestigationEvidenceRequest,
    CreateInvestigationTaskRequest,
    InvestigationEvidenceSchema,
    InvestigationTaskSchema,
    InvestigationTaskStatus,
    QueryAuditEventsResponse,
    QueryInvestigationEvidenceResponse,
    QueryInvestigationTasksResponse,
    ReviewInvestigationTaskRequest,
    SubmitInvestigationTaskRequest,
)
from service.common.pagination import RESOURCE_PAGE_MAX_SIZE, RESOURCE_PAGE_SIZE


router = APIRouter(prefix="/threat-incidents", tags=["investigation"], dependencies=[Depends(require_user)])
errors = {**COMMON_ERROR_RESPONSES, **FORBIDDEN_RESPONSE, **CONFLICT_RESPONSE, **not_found_response("Investigation task")}


async def create_task(id: int, request: CreateInvestigationTaskRequest, user: AuthUser = Depends(require_user)):
    return await create_investigation_task_handler(id, request, user)


async def query_tasks(id: int, page: int = Query(1, ge=1), size: int = Query(RESOURCE_PAGE_SIZE, ge=1, le=RESOURCE_PAGE_MAX_SIZE), status: InvestigationTaskStatus | None = None, keyword: str = "", user: AuthUser = Depends(require_user)):
    return await query_investigation_tasks_handler(id, page=page, size=size, status=status, keyword=keyword, user=user)


async def activate_task(id: int, task_id: int, user: AuthUser = Depends(require_user)):
    return await activate_investigation_task_handler(id, task_id, user)


async def block_task(id: int, task_id: int, request: BlockInvestigationTaskRequest, user: AuthUser = Depends(require_user)):
    return await block_investigation_task_handler(id, task_id, request, user)


async def submit_task(id: int, task_id: int, request: SubmitInvestigationTaskRequest, user: AuthUser = Depends(require_user)):
    return await submit_investigation_task_handler(id, task_id, request, user)


async def review_task(id: int, task_id: int, request: ReviewInvestigationTaskRequest, user: AuthUser = Depends(require_user)):
    return await review_investigation_task_handler(id, task_id, request, user)


async def create_evidence(id: int, task_id: int, request: CreateInvestigationEvidenceRequest, user: AuthUser = Depends(require_user)):
    return await create_investigation_evidence_handler(id, task_id, request, user)


async def query_evidence(id: int, page: int = Query(1, ge=1), size: int = Query(RESOURCE_PAGE_SIZE, ge=1, le=RESOURCE_PAGE_MAX_SIZE), task_id: int | None = Query(None, gt=0), user: AuthUser = Depends(require_user)):
    return await query_investigation_evidence_handler(id, page=page, size=size, task_id=task_id, user=user)


async def query_audit(id: int, page: int = Query(1, ge=1), size: int = Query(RESOURCE_PAGE_SIZE, ge=1, le=RESOURCE_PAGE_MAX_SIZE), task_id: int | None = Query(None, gt=0), user: AuthUser = Depends(require_user)):
    return await query_audit_events_handler(id, page=page, size=size, task_id=task_id, user=user)


router.add_api_route("/{id}/investigation-tasks", create_task, methods=["POST"], response_model=CommonResponse[InvestigationTaskSchema], responses=errors)
router.add_api_route("/{id}/investigation-tasks", query_tasks, methods=["GET"], response_model=CommonResponse[QueryInvestigationTasksResponse], responses=errors)
router.add_api_route("/{id}/investigation-tasks/{task_id}/activate", activate_task, methods=["POST"], response_model=CommonResponse[InvestigationTaskSchema], responses=errors)
router.add_api_route("/{id}/investigation-tasks/{task_id}/block", block_task, methods=["POST"], response_model=CommonResponse[InvestigationTaskSchema], responses=errors)
router.add_api_route("/{id}/investigation-tasks/{task_id}/submit", submit_task, methods=["POST"], response_model=CommonResponse[InvestigationTaskSchema], responses=errors)
router.add_api_route("/{id}/investigation-tasks/{task_id}/review", review_task, methods=["POST"], response_model=CommonResponse[InvestigationTaskSchema], responses=errors)
router.add_api_route("/{id}/investigation-tasks/{task_id}/evidence", create_evidence, methods=["POST"], response_model=CommonResponse[InvestigationEvidenceSchema], responses=errors)
router.add_api_route("/{id}/investigation-evidence", query_evidence, methods=["GET"], response_model=CommonResponse[QueryInvestigationEvidenceResponse], responses=errors)
router.add_api_route("/{id}/audit-events", query_audit, methods=["GET"], response_model=CommonResponse[QueryAuditEventsResponse], responses=errors)
