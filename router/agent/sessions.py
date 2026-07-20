from fastapi import APIRouter, Depends, Path, Query, Request, Response, WebSocket
from fastapi.responses import FileResponse

from handler.agent.sessions import (
    archive_agent_session_handler,
    cancel_agent_session_tasks_handler,
    create_agent_session_turn_handler,
    download_agent_report_handler,
    get_agent_session_handler,
    handle_agent_stream,
    interrupt_agent_session_handler,
    list_agent_events_handler,
    list_agent_sessions_handler,
    list_agent_tool_invocation_recoveries_handler,
    list_sandbox_async_job_recoveries_handler,
    resolve_agent_tool_invocation_handler,
    resolve_sandbox_async_job_handler,
    submit_agent_session_turn_handler,
    update_agent_session_sandbox_container_handler,
    update_agent_session_title_handler,
)
from middleware.system_user import AuthUser, require_user
from router.common.responses import COMMON_ERROR_RESPONSES, CONFLICT_RESPONSE, not_found_response
from schema.agent.sessions import (
    AgentControlResponse,
    AgentSessionSummarySchema,
    AgentToolInvocationSchema,
    AgentTurnResponse,
    CreateAgentSessionTurnRequest,
    ListAgentEventsResponse,
    ListAgentSessionsResponse,
    ListAgentToolInvocationRecoveriesResponse,
    ResolveAgentToolInvocationRequest,
    SubmitAgentSessionTurnRequest,
    UpdateAgentSessionSandboxContainerRequest,
    UpdateAgentSessionTitleRequest,
)
from schema.sandbox.async_jobs import (
    ListSandboxAsyncJobRecoveriesResponse,
    ResolveSandboxAsyncJobRequest,
    SandboxAsyncJobSnapshot,
)
from service.common.pagination import RESOURCE_PAGE_MAX_SIZE, RESOURCE_PAGE_SIZE


router = APIRouter(prefix="/agent-sessions", tags=["agent-sessions"])


@router.get("", response_model=ListAgentSessionsResponse, responses=COMMON_ERROR_RESPONSES)
async def list_agent_sessions_route(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=RESOURCE_PAGE_SIZE, ge=1, le=RESOURCE_PAGE_MAX_SIZE),
    include_scoped: bool = Query(default=False),
    user: AuthUser = Depends(require_user),
) -> ListAgentSessionsResponse:
    return await list_agent_sessions_handler(page, size, user, include_scoped)


@router.get("/{session_id}", response_model=AgentSessionSummarySchema, responses={**COMMON_ERROR_RESPONSES, **not_found_response("Agent session")})
async def get_agent_session_route(
    session_id: str,
    user: AuthUser = Depends(require_user),
) -> AgentSessionSummarySchema:
    return await get_agent_session_handler(session_id, user)


@router.get("/{session_id}/events", response_model=ListAgentEventsResponse, responses={**COMMON_ERROR_RESPONSES, **not_found_response("Agent session")})
async def list_agent_events_route(
    session_id: str,
    before_seq: int | None = Query(default=None, ge=1),
    limit: int = Query(default=80, ge=1, le=200),
    user: AuthUser = Depends(require_user),
) -> ListAgentEventsResponse:
    return await list_agent_events_handler(session_id, user, before_seq, limit)


@router.get(
    "/{session_id}/tool-invocations/recovery",
    response_model=ListAgentToolInvocationRecoveriesResponse,
    responses={**COMMON_ERROR_RESPONSES, **not_found_response("Agent session")},
)
async def list_agent_tool_invocation_recoveries_route(
    session_id: str,
    user: AuthUser = Depends(require_user),
) -> ListAgentToolInvocationRecoveriesResponse:
    return await list_agent_tool_invocation_recoveries_handler(session_id, user)


@router.post(
    "/{session_id}/tool-invocations/{invocation_id}/resolve",
    response_model=AgentToolInvocationSchema,
    responses={**COMMON_ERROR_RESPONSES, **CONFLICT_RESPONSE, **not_found_response("Tool invocation recovery")},
)
async def resolve_agent_tool_invocation_route(
    request: Request,
    session_id: str,
    invocation_id: str,
    payload: ResolveAgentToolInvocationRequest,
    user: AuthUser = Depends(require_user),
) -> AgentToolInvocationSchema:
    return await resolve_agent_tool_invocation_handler(
        request,
        session_id,
        invocation_id,
        payload,
        user,
    )


@router.get(
    "/{session_id}/sandbox-jobs/recovery",
    response_model=ListSandboxAsyncJobRecoveriesResponse,
    responses={**COMMON_ERROR_RESPONSES, **not_found_response("Agent session")},
)
async def list_sandbox_async_job_recoveries_route(
    session_id: str,
    user: AuthUser = Depends(require_user),
) -> ListSandboxAsyncJobRecoveriesResponse:
    return await list_sandbox_async_job_recoveries_handler(session_id, user)


@router.post(
    "/{session_id}/sandbox-jobs/{job_id}/resolve",
    response_model=SandboxAsyncJobSnapshot,
    responses={**COMMON_ERROR_RESPONSES, **CONFLICT_RESPONSE, **not_found_response("Sandbox command recovery")},
)
async def resolve_sandbox_async_job_route(
    request: Request,
    session_id: str,
    job_id: str,
    payload: ResolveSandboxAsyncJobRequest,
    user: AuthUser = Depends(require_user),
) -> SandboxAsyncJobSnapshot:
    return await resolve_sandbox_async_job_handler(
        request,
        session_id,
        job_id,
        payload,
        user,
    )


@router.post("/turns", response_model=AgentTurnResponse, status_code=202, responses=COMMON_ERROR_RESPONSES)
async def create_agent_session_turn_route(
    request: Request,
    payload: CreateAgentSessionTurnRequest,
    user: AuthUser = Depends(require_user),
) -> AgentTurnResponse:
    return await create_agent_session_turn_handler(request, payload, user)


@router.post("/{session_id}/turns", response_model=AgentTurnResponse, status_code=202, responses={**COMMON_ERROR_RESPONSES, **not_found_response("Agent session")})
async def submit_agent_session_turn_route(
    request: Request,
    session_id: str,
    payload: SubmitAgentSessionTurnRequest,
    user: AuthUser = Depends(require_user),
) -> AgentTurnResponse:
    return await submit_agent_session_turn_handler(request, session_id, payload, user)


@router.post("/{session_id}/interrupt", response_model=AgentControlResponse, responses={**COMMON_ERROR_RESPONSES, **not_found_response("Agent session")})
async def interrupt_agent_session_route(
    request: Request,
    session_id: str,
    user: AuthUser = Depends(require_user),
) -> AgentControlResponse:
    return await interrupt_agent_session_handler(request, session_id, user)


@router.post("/{session_id}/cancel-all", response_model=AgentControlResponse, responses={**COMMON_ERROR_RESPONSES, **not_found_response("Agent session")})
async def cancel_agent_session_tasks_route(
    request: Request,
    session_id: str,
    user: AuthUser = Depends(require_user),
) -> AgentControlResponse:
    return await cancel_agent_session_tasks_handler(request, session_id, user)


@router.patch("/{session_id}/title", response_model=AgentSessionSummarySchema, responses={**COMMON_ERROR_RESPONSES, **not_found_response("Agent session")})
async def update_agent_session_title_route(
    session_id: str,
    payload: UpdateAgentSessionTitleRequest,
    user: AuthUser = Depends(require_user),
) -> AgentSessionSummarySchema:
    return await update_agent_session_title_handler(session_id, payload, user)


@router.patch("/{session_id}/sandbox-container", response_model=AgentSessionSummarySchema, responses={**COMMON_ERROR_RESPONSES, **CONFLICT_RESPONSE, **not_found_response("Agent session")})
async def update_agent_session_sandbox_container_route(
    session_id: str,
    payload: UpdateAgentSessionSandboxContainerRequest,
    user: AuthUser = Depends(require_user),
) -> AgentSessionSummarySchema:
    return await update_agent_session_sandbox_container_handler(session_id, payload, user)


@router.post("/{session_id}/archive", status_code=204, response_class=Response, responses={**COMMON_ERROR_RESPONSES, **CONFLICT_RESPONSE, **not_found_response("Agent chat session")})
async def archive_agent_session_route(
    session_id: str,
    user: AuthUser = Depends(require_user),
) -> Response:
    return await archive_agent_session_handler(session_id, user)


@router.get(
    "/reports/{report_id}/download",
    response_model=None,
    response_class=FileResponse,
    responses={200: {"description": "Markdown report file", "content": {"text/markdown": {"schema": {"type": "string", "format": "binary"}}}}, **COMMON_ERROR_RESPONSES},
)
async def download_agent_report_route(
    report_id: str = Path(min_length=1),
    user: AuthUser = Depends(require_user),
):
    return await download_agent_report_handler(report_id, user)


@router.websocket("/{session_id}/stream")
async def agent_session_stream(websocket: WebSocket, session_id: str, token: str = Query(default="")) -> None:
    await handle_agent_stream(websocket, session_id, token)
