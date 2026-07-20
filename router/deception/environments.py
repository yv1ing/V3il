from fastapi import APIRouter, Depends, File, Form, Query, UploadFile
from pydantic import ValidationError
from fastapi.exceptions import RequestValidationError

from handler.deception.environments import (
    create_deception_environment_handler,
    create_deception_artifact_handler,
    decide_deception_revision_handler,
    execute_deception_revision_handler,
    evaluate_deception_revision_handler,
    get_deception_environment_handler,
    get_deception_environment_session_handler,
    get_deception_references_handler,
    list_deception_workloads_handler,
    plan_deception_revision_handler,
    query_deception_environments_handler,
    query_deception_artifacts_handler,
    query_deception_revisions_handler,
    recover_deception_revision_handler,
    set_deception_environment_status_handler,
    start_deception_workload_handler,
    stop_deception_workload_handler,
    update_deception_environment_handler,
)
from middleware.system_user import AuthUser, require_user
from router.common.responses import COMMON_ERROR_RESPONSES, CONFLICT_RESPONSE, FORBIDDEN_RESPONSE, not_found_response
from schema.common.responses import CommonResponse
from schema.agent.sessions import AgentSessionSummarySchema
from schema.deception.environments import (
    CreateDeceptionEnvironmentRequest,
    CreateDeceptionArtifactRequest,
    CreateDeceptionEnvironmentResponse,
    DeceptionEnvironmentSchema,
    DeceptionEnvironmentStatus,
    DeceptionAdaptationMode,
    DeceptionReferenceBundleSchema,
    DeceptionRevisionDecisionRequest,
    EvaluateDeceptionRevisionRequest,
    DeceptionRevisionSchema,
    PlanDeceptionRevisionRequest,
    QueryDeceptionEnvironmentsResponse,
    QueryDeceptionArtifactsResponse,
    QueryDeceptionRevisionsResponse,
    UpdateDeceptionEnvironmentRequest,
)
from schema.sandbox.containers import SandboxContainerEgressMode
from schema.deception.workloads import CreateObservedWorkloadRequest, ListObservedWorkloadsResponse, ObservedWorkloadSchema
from service.common.pagination import RESOURCE_PAGE_MAX_SIZE, RESOURCE_PAGE_SIZE


router = APIRouter(prefix="/deception-environments", tags=["deception-environments"], dependencies=[Depends(require_user)])
NOT_FOUND = not_found_response("Deception environment")


async def create_route(
    name: str = Form(min_length=1, max_length=255),
    description: str = Form(default="", max_length=4000),
    sandbox_container_id: int | None = Form(default=None, gt=0),
    host_id: int = Form(gt=0),
    image_id: int = Form(gt=0),
    egress_mode: SandboxContainerEgressMode = Form(),
    egress_proxy_id: int | None = Form(default=None, gt=0),
    adaptation_mode: DeceptionAdaptationMode = Form(default=DeceptionAdaptationMode.POLICY_AUTO),
    reference_urls: list[str] | None = Form(default=None),
    files: list[UploadFile] | None = File(default=None),
    user: AuthUser = Depends(require_user),
):
    try:
        request = CreateDeceptionEnvironmentRequest(
            name=name,
            description=description,
            sandbox_container_id=sandbox_container_id,
            host_id=host_id,
            image_id=image_id,
            egress_mode=egress_mode,
            egress_proxy_id=egress_proxy_id,
            adaptation_mode=adaptation_mode,
            reference_urls=reference_urls or [],
        )
    except ValidationError as exc:
        raise RequestValidationError(exc.errors()) from exc
    return await create_deception_environment_handler(request, files or [], user)


async def query_route(page: int = Query(1, ge=1), size: int = Query(RESOURCE_PAGE_SIZE, ge=1, le=RESOURCE_PAGE_MAX_SIZE), keyword: str = "", status: DeceptionEnvironmentStatus | None = None, user: AuthUser = Depends(require_user)):
    return await query_deception_environments_handler(page=page, size=size, keyword=keyword, status=status, user=user)


async def get_route(id: int, user: AuthUser = Depends(require_user)):
    return await get_deception_environment_handler(id, user)


async def references_route(id: int, user: AuthUser = Depends(require_user)):
    return await get_deception_references_handler(id, user)


async def session_route(id: int, user: AuthUser = Depends(require_user)):
    return await get_deception_environment_session_handler(id, user)


async def update_route(id: int, request: UpdateDeceptionEnvironmentRequest, user: AuthUser = Depends(require_user)):
    return await update_deception_environment_handler(id, request, user)


async def status_route(id: int, status: DeceptionEnvironmentStatus, user: AuthUser = Depends(require_user)):
    return await set_deception_environment_status_handler(id, status, user)


async def plan_route(id: int, request: PlanDeceptionRevisionRequest, user: AuthUser = Depends(require_user)):
    return await plan_deception_revision_handler(id, request, user)


async def revisions_route(id: int, page: int = Query(1, ge=1), size: int = Query(RESOURCE_PAGE_SIZE, ge=1, le=RESOURCE_PAGE_MAX_SIZE), user: AuthUser = Depends(require_user)):
    return await query_deception_revisions_handler(id, page=page, size=size, user=user)


async def approve_route(id: int, revision_id: int, request: DeceptionRevisionDecisionRequest, user: AuthUser = Depends(require_user)):
    return await decide_deception_revision_handler(id, revision_id, request, True, user)


async def reject_route(id: int, revision_id: int, request: DeceptionRevisionDecisionRequest, user: AuthUser = Depends(require_user)):
    return await decide_deception_revision_handler(id, revision_id, request, False, user)


async def execute_route(id: int, revision_id: int, user: AuthUser = Depends(require_user)):
    return await execute_deception_revision_handler(id, revision_id, user)


async def recover_route(id: int, revision_id: int, user: AuthUser = Depends(require_user)):
    return await recover_deception_revision_handler(id, revision_id, user)


async def start_workload_route(id: int, request: CreateObservedWorkloadRequest, user: AuthUser = Depends(require_user)):
    return await start_deception_workload_handler(id, request, user)


async def list_workload_route(id: int, user: AuthUser = Depends(require_user)):
    return await list_deception_workloads_handler(id, user)


async def stop_workload_route(id: int, run_id: str, user: AuthUser = Depends(require_user)):
    return await stop_deception_workload_handler(id, run_id, user)


async def create_artifact_route(id: int, request: CreateDeceptionArtifactRequest, user: AuthUser = Depends(require_user)):
    return await create_deception_artifact_handler(id, request, user)


async def artifacts_route(id: int, page: int = Query(1, ge=1), size: int = Query(RESOURCE_PAGE_SIZE, ge=1, le=RESOURCE_PAGE_MAX_SIZE), user: AuthUser = Depends(require_user)):
    return await query_deception_artifacts_handler(id, page=page, size=size, user=user)


async def evaluate_revision_route(id: int, revision_id: int, request: EvaluateDeceptionRevisionRequest, user: AuthUser = Depends(require_user)):
    return await evaluate_deception_revision_handler(id, revision_id, request, user)


errors = {**COMMON_ERROR_RESPONSES, **FORBIDDEN_RESPONSE, **CONFLICT_RESPONSE, **NOT_FOUND}
router.add_api_route("", create_route, methods=["POST"], response_model=CommonResponse[CreateDeceptionEnvironmentResponse], responses=errors)
router.add_api_route("", query_route, methods=["GET"], response_model=CommonResponse[QueryDeceptionEnvironmentsResponse], responses=COMMON_ERROR_RESPONSES)
router.add_api_route("/{id}", get_route, methods=["GET"], response_model=CommonResponse[DeceptionEnvironmentSchema], responses=errors)
router.add_api_route("/{id}/session", session_route, methods=["GET"], response_model=CommonResponse[AgentSessionSummarySchema], responses=errors)
router.add_api_route("/{id}/references", references_route, methods=["GET"], response_model=CommonResponse[DeceptionReferenceBundleSchema], responses=errors)
router.add_api_route("/{id}", update_route, methods=["PATCH"], response_model=CommonResponse[DeceptionEnvironmentSchema], responses=errors)
for action, status in (("pause", DeceptionEnvironmentStatus.PAUSED), ("resume", DeceptionEnvironmentStatus.ACTIVE), ("retire", DeceptionEnvironmentStatus.RETIRED)):
    async def action_route(id: int, user: AuthUser = Depends(require_user), target=status):
        return await status_route(id, target, user)
    action_route.__name__ = f"{action}_deception_environment"
    router.add_api_route(f"/{{id}}/{action}", action_route, methods=["POST"], response_model=CommonResponse[DeceptionEnvironmentSchema], responses=errors)
router.add_api_route("/{id}/revisions", plan_route, methods=["POST"], response_model=CommonResponse[DeceptionRevisionSchema], responses=errors)
router.add_api_route("/{id}/revisions", revisions_route, methods=["GET"], response_model=CommonResponse[QueryDeceptionRevisionsResponse], responses=errors)
router.add_api_route("/{id}/revisions/{revision_id}/approve", approve_route, methods=["POST"], response_model=CommonResponse[DeceptionRevisionSchema], responses=errors)
router.add_api_route("/{id}/revisions/{revision_id}/reject", reject_route, methods=["POST"], response_model=CommonResponse[DeceptionRevisionSchema], responses=errors)
router.add_api_route("/{id}/revisions/{revision_id}/execute", execute_route, methods=["POST"], response_model=CommonResponse[DeceptionRevisionSchema], responses=errors)
router.add_api_route("/{id}/revisions/{revision_id}/recover", recover_route, methods=["POST"], response_model=CommonResponse[DeceptionRevisionSchema], responses=errors)
router.add_api_route("/{id}/workloads", start_workload_route, methods=["POST"], response_model=CommonResponse[ObservedWorkloadSchema], responses=errors)
router.add_api_route("/{id}/workloads", list_workload_route, methods=["GET"], response_model=CommonResponse[ListObservedWorkloadsResponse], responses=errors)
router.add_api_route("/{id}/workloads/{run_id}/stop", stop_workload_route, methods=["POST"], response_model=CommonResponse[ObservedWorkloadSchema], responses=errors)
router.add_api_route("/{id}/artifacts", create_artifact_route, methods=["POST"], response_model=CommonResponse, responses=errors)
router.add_api_route("/{id}/artifacts", artifacts_route, methods=["GET"], response_model=CommonResponse[QueryDeceptionArtifactsResponse], responses=errors)
router.add_api_route("/{id}/revisions/{revision_id}/evaluation", evaluate_revision_route, methods=["POST"], response_model=CommonResponse[DeceptionRevisionSchema], responses=errors)
