from http import HTTPStatus

from fastapi import UploadFile

from handler.common.http import raise_api_error
from middleware.system_user import AuthUser
from schema.common.responses import CommonResponse
from schema.deception.environments import (
    CreateDeceptionEnvironmentRequest,
    CreateDeceptionArtifactRequest,
    CreateDeceptionEnvironmentResponse,
    DeceptionEnvironmentStatus,
    DeceptionRevisionDecisionRequest,
    EvaluateDeceptionRevisionRequest,
    PlanDeceptionRevisionRequest,
    QueryDeceptionEnvironmentsResponse,
    QueryDeceptionArtifactsResponse,
    QueryDeceptionRevisionsResponse,
    UpdateDeceptionEnvironmentRequest,
)
from schema.deception.workloads import CreateObservedWorkloadRequest
from service.common.pagination import paginated_payload
from service.deception.environments import (
    DeceptionMutationResult,
    DeceptionRevisionMutationResult,
    create_deception_environment,
    create_deception_artifact,
    decide_deception_revision,
    get_deception_environment_for_user,
    get_deception_environment_session_for_user,
    evaluate_deception_revision,
    get_deception_references_for_user,
    plan_deception_revision,
    query_deception_environments_for_user,
    query_deception_artifacts_for_user,
    query_deception_revisions_for_user,
    set_deception_environment_status,
    update_deception_environment,
)
from service.deception.references import DeceptionReferenceError
from service.deception.executions import (
    execute_deception_revision,
    recover_deception_revision_rollback,
)
from service.deception.workloads import (
    ObservedWorkloadResult,
    list_deception_workloads,
    start_deception_workload,
    stop_deception_workload,
)


def _raise_environment_error(result: DeceptionMutationResult):
    if result.not_found:
        raise_api_error(HTTPStatus.NOT_FOUND, result.message or "deception environment not found")
    if result.forbidden:
        raise_api_error(HTTPStatus.FORBIDDEN, result.message or "deception environment is not manageable by user")
    if result.conflict:
        raise_api_error(HTTPStatus.CONFLICT, result.message or "deception environment state conflict")
    raise RuntimeError("deception environment mutation failed without classification")


def _raise_revision_error(result: DeceptionRevisionMutationResult):
    if result.not_found:
        raise_api_error(HTTPStatus.NOT_FOUND, result.message or "deception revision not found")
    if result.forbidden:
        raise_api_error(HTTPStatus.FORBIDDEN, result.message or "deception environment is not manageable by user")
    if result.conflict:
        raise_api_error(HTTPStatus.CONFLICT, result.message or "deception revision state conflict")
    raise RuntimeError("deception revision mutation failed without classification")


def _raise_workload_error(result: ObservedWorkloadResult):
    if result.not_found:
        raise_api_error(HTTPStatus.NOT_FOUND, result.message or "observed workload not found")
    if result.forbidden:
        raise_api_error(HTTPStatus.FORBIDDEN, result.message or "deception environment is not manageable by user")
    if result.conflict:
        raise_api_error(HTTPStatus.CONFLICT, result.message or "observed workload state conflict")
    raise RuntimeError("observed workload operation failed without classification")


async def create_deception_environment_handler(
    request: CreateDeceptionEnvironmentRequest,
    files: list[UploadFile],
    user: AuthUser,
):
    try:
        result = await create_deception_environment(
            request,
            files,
            user_id=user.id,
            user_role=user.role,
        )
    except DeceptionReferenceError as exc:
        raise_api_error(HTTPStatus.UNPROCESSABLE_ENTITY, str(exc))
    if result.environment is None:
        _raise_environment_error(result)
    if not result.session_id or result.references is None:
        raise RuntimeError("deception environment creation did not produce its Console context")
    console_session = await get_deception_environment_session_for_user(
        result.environment.id,
        user_id=user.id,
        user_role=user.role,
    )
    if console_session is None:
        raise RuntimeError("deception environment Console session is unavailable")
    return CommonResponse(
        message="deception environment context created; continue in the Console",
        data=CreateDeceptionEnvironmentResponse(
            environment=result.environment,
            session=console_session,
            references=result.references,
        ),
    )


async def get_deception_environment_handler(id: int, user: AuthUser):
    environment = await get_deception_environment_for_user(id, user_id=user.id, user_role=user.role)
    if environment is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "deception environment not found")
    return CommonResponse(data=environment)


async def get_deception_environment_session_handler(id: int, user: AuthUser):
    console_session = await get_deception_environment_session_for_user(
        id,
        user_id=user.id,
        user_role=user.role,
    )
    if console_session is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "deception environment Console session not found")
    return CommonResponse(data=console_session)


async def get_deception_references_handler(id: int, user: AuthUser):
    references = await get_deception_references_for_user(
        id,
        user_id=user.id,
        user_role=user.role,
    )
    if references is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "deception environment not found")
    return CommonResponse(data=references)


async def query_deception_environments_handler(*, page, size, keyword, status, user):
    result = await query_deception_environments_for_user(
        page=page, size=size, keyword=keyword, status=status, user_id=user.id, user_role=user.role
    )
    return CommonResponse(data=QueryDeceptionEnvironmentsResponse(**paginated_payload(result, result.items)))


async def update_deception_environment_handler(id: int, request: UpdateDeceptionEnvironmentRequest, user: AuthUser):
    result = await update_deception_environment(id, request, user_id=user.id, user_role=user.role)
    if result.environment is None:
        _raise_environment_error(result)
    return CommonResponse(message="deception environment updated", data=result.environment)


async def set_deception_environment_status_handler(id: int, status: DeceptionEnvironmentStatus, user: AuthUser):
    result = await set_deception_environment_status(id, status, user_id=user.id, user_role=user.role)
    if result.environment is None:
        _raise_environment_error(result)
    return CommonResponse(message="deception environment status updated", data=result.environment)


async def plan_deception_revision_handler(id: int, request: PlanDeceptionRevisionRequest, user: AuthUser):
    result = await plan_deception_revision(id, request, user_id=user.id, user_role=user.role)
    if result.revision is None:
        _raise_revision_error(result)
    return CommonResponse(message="deception revision planned", data=result.revision)


async def decide_deception_revision_handler(id: int, revision_id: int, request: DeceptionRevisionDecisionRequest, approve: bool, user: AuthUser):
    result = await decide_deception_revision(
        id, revision_id, approve=approve, reason=request.reason, user_id=user.id, user_role=user.role
    )
    if result.revision is None:
        _raise_revision_error(result)
    return CommonResponse(message="deception revision approved" if approve else "deception revision rejected", data=result.revision)


async def execute_deception_revision_handler(id: int, revision_id: int, user: AuthUser):
    result = await execute_deception_revision(id, revision_id, user_id=user.id, user_role=user.role)
    if result.revision is None or result.conflict:
        _raise_revision_error(result)
    return CommonResponse(message="deception revision applied and verified", data=result.revision)


async def recover_deception_revision_handler(id: int, revision_id: int, user: AuthUser):
    result = await recover_deception_revision_rollback(
        id,
        revision_id,
        user_id=user.id,
        user_role=user.role,
    )
    if result.revision is None or result.conflict:
        _raise_revision_error(result)
    return CommonResponse(message="deception revision rollback recovered", data=result.revision)


async def query_deception_revisions_handler(id: int, *, page, size, user):
    result = await query_deception_revisions_for_user(id, page=page, size=size, user_id=user.id, user_role=user.role)
    if result is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "deception environment not found")
    return CommonResponse(data=QueryDeceptionRevisionsResponse(**paginated_payload(result, result.items)))


async def create_deception_artifact_handler(id: int, request: CreateDeceptionArtifactRequest, user: AuthUser):
    try:
        artifact = await create_deception_artifact(id, request, user_id=user.id, user_role=user.role)
    except LookupError as exc:
        raise_api_error(HTTPStatus.NOT_FOUND, str(exc))
    except PermissionError as exc:
        raise_api_error(HTTPStatus.FORBIDDEN, str(exc))
    except ValueError as exc:
        raise_api_error(HTTPStatus.CONFLICT, str(exc))
    return CommonResponse(message="deception artifact registered", data=artifact)


async def query_deception_artifacts_handler(id: int, *, page, size, user: AuthUser):
    result = await query_deception_artifacts_for_user(id, page=page, size=size, user_id=user.id, user_role=user.role)
    if result is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "deception environment not found")
    return CommonResponse(data=QueryDeceptionArtifactsResponse(**paginated_payload(result, result.items)))


async def evaluate_deception_revision_handler(id: int, revision_id: int, request: EvaluateDeceptionRevisionRequest, user: AuthUser):
    try:
        revision = await evaluate_deception_revision(id, revision_id, request, user_id=user.id, user_role=user.role)
    except LookupError as exc:
        raise_api_error(HTTPStatus.NOT_FOUND, str(exc))
    except PermissionError as exc:
        raise_api_error(HTTPStatus.FORBIDDEN, str(exc))
    except ValueError as exc:
        raise_api_error(HTTPStatus.CONFLICT, str(exc))
    return CommonResponse(message="deception engagement evaluation recorded", data=revision)


async def start_deception_workload_handler(id: int, request: CreateObservedWorkloadRequest, user: AuthUser):
    result = await start_deception_workload(id, request, user_id=user.id, user_role=user.role)
    if result.workload is None:
        _raise_workload_error(result)
    return CommonResponse(data=result.workload)


async def list_deception_workloads_handler(id: int, user: AuthUser):
    result = await list_deception_workloads(id, user_id=user.id, user_role=user.role)
    if result.workloads is None:
        _raise_workload_error(result)
    return CommonResponse(data=result.workloads)


async def stop_deception_workload_handler(id: int, run_id: str, user: AuthUser):
    result = await stop_deception_workload(id, run_id, user_id=user.id, user_role=user.role)
    if result.workload is None:
        _raise_workload_error(result)
    return CommonResponse(data=result.workload)
