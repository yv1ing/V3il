import asyncio
from http import HTTPStatus

from fastapi import Request, Response, WebSocket, WebSocketDisconnect, status as ws_status
from fastapi.responses import FileResponse
from fastapi.websockets import WebSocketState
from pydantic import TypeAdapter, ValidationError

from handler.common.http import raise_api_error
from handler.common.websocket import authenticate_ws_token, close_ws_silently
from middleware.system_user import AuthUser, resolve_current_user
from schema.agent.events import AgentAckFrame, AgentClientFrame, AgentHeartbeatFrame, AgentServerFrame
from schema.agent.sessions import (
    AgentControlResponse,
    AgentSessionSummarySchema,
    AgentTurnResponse,
    AgentToolInvocationSchema,
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
from service.agent import reports as agent_reports
from service.agent import repository
from service.agent import runtime as agent_runtime
from service.agent import tool_invocations as agent_tool_invocations
from service.agent.supervisor import AgentRuntimeSupervisor, AgentStreamSubscription
from service.common.pagination import paginated_payload
from service.sandbox import async_jobs as sandbox_async_jobs
from utils.time import utc_now


_client_frame_adapter = TypeAdapter(AgentClientFrame)
_ACCESS_CHECK_INTERVAL_SECONDS = 30


def runtime_from_request(request: Request) -> AgentRuntimeSupervisor:
    runtime = getattr(request.app.state, "agent_runtime", None)
    if not isinstance(runtime, AgentRuntimeSupervisor):
        raise RuntimeError("agent runtime is unavailable")
    return runtime


async def create_agent_session_turn_handler(
    request: Request,
    payload: CreateAgentSessionTurnRequest,
    user: AuthUser,
) -> AgentTurnResponse:
    try:
        return await agent_runtime.submit_new_chat_turn(
            supervisor=runtime_from_request(request),
            content=payload.content,
            user=user,
            sandbox_container_id=payload.sandbox_container_id,
            requested_agent_code=payload.agent_code,
        )
    except Exception as exc:
        _raise_runtime_error(exc)
        raise


async def submit_agent_session_turn_handler(
    request: Request,
    session_id: str,
    payload: SubmitAgentSessionTurnRequest,
    user: AuthUser,
) -> AgentTurnResponse:
    try:
        return await agent_runtime.submit_user_turn(
            supervisor=runtime_from_request(request),
            session_id=session_id,
            content=payload.content,
            user=user,
            requested_agent_code=payload.agent_code,
        )
    except Exception as exc:
        _raise_runtime_error(exc)
        raise


async def interrupt_agent_session_handler(
    request: Request,
    session_id: str,
    user: AuthUser,
) -> AgentControlResponse:
    try:
        return await agent_runtime.interrupt_turn(
            supervisor=runtime_from_request(request), session_id=session_id, user=user,
        )
    except Exception as exc:
        _raise_runtime_error(exc)
        raise


async def cancel_agent_session_tasks_handler(
    request: Request,
    session_id: str,
    user: AuthUser,
) -> AgentControlResponse:
    try:
        return await agent_runtime.cancel_all_tasks(
            supervisor=runtime_from_request(request), session_id=session_id, user=user,
        )
    except Exception as exc:
        _raise_runtime_error(exc)
        raise


async def archive_agent_session_handler(session_id: str, user: AuthUser) -> Response:
    try:
        archived = await repository.archive_agent_session(session_id, user.id, user.role)
    except RuntimeError as exc:
        raise_api_error(HTTPStatus.CONFLICT, str(exc))
    if not archived:
        raise_api_error(HTTPStatus.NOT_FOUND, "agent chat session not found")
    return Response(status_code=HTTPStatus.NO_CONTENT)


async def update_agent_session_title_handler(
    session_id: str,
    payload: UpdateAgentSessionTitleRequest,
    user: AuthUser,
) -> AgentSessionSummarySchema:
    summary = await repository.update_title(session_id, payload.title, user.id, user.role)
    if summary is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "agent session not found")
    return summary


async def update_agent_session_sandbox_container_handler(
    session_id: str,
    payload: UpdateAgentSessionSandboxContainerRequest,
    user: AuthUser,
) -> AgentSessionSummarySchema:
    try:
        return await agent_runtime.update_selected_sandbox_container(
            session_id=session_id,
            sandbox_container_id=payload.sandbox_container_id,
            user=user,
        )
    except Exception as exc:
        _raise_runtime_error(exc)
        raise


async def list_agent_sessions_handler(
    page: int,
    size: int,
    user: AuthUser,
    include_scoped: bool,
) -> ListAgentSessionsResponse:
    result = await repository.list_sessions(
        page=page,
        size=size,
        user_id=user.id,
        user_role=user.role,
        include_scoped=include_scoped,
    )
    return ListAgentSessionsResponse(**paginated_payload(result, result.items))


async def get_agent_session_handler(
    session_id: str,
    user: AuthUser,
) -> AgentSessionSummarySchema:
    summary = await repository.session_summary(session_id, user.id, user.role)
    if summary is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "agent session not found")
    return summary


async def list_agent_events_handler(
    session_id: str,
    user: AuthUser,
    before_seq: int | None,
    limit: int,
) -> ListAgentEventsResponse:
    result = await repository.replay_events(
        session_id=session_id,
        user_id=user.id,
        user_role=user.role,
        before_seq=before_seq,
        limit=limit,
    )
    if result is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "agent session not found")
    events, has_more, next_before_seq = result
    return ListAgentEventsResponse(
        session_id=session_id,
        items=events,
        has_more=has_more,
        next_before_seq=next_before_seq,
    )


async def list_agent_tool_invocation_recoveries_handler(
    session_id: str,
    user: AuthUser,
) -> ListAgentToolInvocationRecoveriesResponse:
    items = await agent_tool_invocations.list_recovery_required_invocations(
        session_id=session_id,
        user_id=user.id,
        user_role=user.role,
    )
    if items is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "agent session not found")
    return ListAgentToolInvocationRecoveriesResponse(session_id=session_id, items=items)


async def resolve_agent_tool_invocation_handler(
    request: Request,
    session_id: str,
    invocation_id: str,
    payload: ResolveAgentToolInvocationRequest,
    user: AuthUser,
) -> AgentToolInvocationSchema:
    try:
        result = await agent_tool_invocations.resolve_invocation(
            session_id=session_id,
            invocation_id=invocation_id,
            resolution=payload,
            user_id=user.id,
            user_role=user.role,
        )
    except agent_tool_invocations.ToolInvocationResolutionConflict as exc:
        raise_api_error(HTTPStatus.CONFLICT, str(exc))
    if result is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "tool invocation recovery not found")
    invocation, events = result
    runtime = runtime_from_request(request)
    for event in events:
        runtime.publish_durable_event(event)
    runtime.notify()
    return invocation


async def list_sandbox_async_job_recoveries_handler(
    session_id: str,
    user: AuthUser,
) -> ListSandboxAsyncJobRecoveriesResponse:
    items = await sandbox_async_jobs.list_recovery_required_jobs(
        session_id=session_id,
        user_id=user.id,
        user_role=user.role,
    )
    if items is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "agent session not found")
    return ListSandboxAsyncJobRecoveriesResponse(session_id=session_id, items=items)


async def resolve_sandbox_async_job_handler(
    request: Request,
    session_id: str,
    job_id: str,
    payload: ResolveSandboxAsyncJobRequest,
    user: AuthUser,
) -> SandboxAsyncJobSnapshot:
    try:
        result = await sandbox_async_jobs.resolve_recovery_required_job(
            session_id=session_id,
            run_id=job_id,
            resolution=payload,
            user_id=user.id,
            user_role=user.role,
        )
    except sandbox_async_jobs.SandboxJobResolutionConflict as exc:
        raise_api_error(HTTPStatus.CONFLICT, str(exc))
    if result is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "Sandbox command recovery not found")
    job, events = result
    runtime = runtime_from_request(request)
    for event in events:
        runtime.publish_durable_event(event)
    runtime.notify()
    return job


async def download_agent_report_handler(report_id: str, user: AuthUser) -> FileResponse:
    try:
        report_path = agent_reports.resolve_report_download_path(report_id)
    except ValueError as exc:
        raise_api_error(HTTPStatus.BAD_REQUEST, str(exc))
    except FileNotFoundError as exc:
        raise_api_error(HTTPStatus.NOT_FOUND, str(exc))
    session_id = agent_reports.report_session_id(report_path)
    if not session_id or await repository.get_accessible_session(session_id, user.id, user.role) is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "report file not found")
    return FileResponse(
        report_path,
        media_type="text/markdown; charset=utf-8",
        filename=agent_reports.report_download_filename(report_path),
    )


async def handle_agent_stream(websocket: WebSocket, session_id: str, token: str) -> None:
    user = await authenticate_ws_token(token)
    if user is None or await repository.get_accessible_session(session_id, user.id, user.role) is None:
        await websocket.close(code=ws_status.WS_1008_POLICY_VIOLATION)
        return
    runtime = getattr(websocket.app.state, "agent_runtime", None)
    if not isinstance(runtime, AgentRuntimeSupervisor):
        await websocket.close(code=ws_status.WS_1011_INTERNAL_ERROR)
        return
    await websocket.accept()
    subscription = await runtime.subscribe(session_id)
    reader = asyncio.create_task(
        _consume_websocket(websocket, runtime, session_id, subscription),
        name=f"agent-stream-reader-{session_id}",
    )
    forwarder = asyncio.create_task(
        _forward_frames(websocket, subscription, session_id, user),
        name=f"agent-stream-forwarder-{session_id}",
    )
    try:
        done, pending = await asyncio.wait({reader, forwarder}, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
    except WebSocketDisconnect:
        pass
    finally:
        runtime.unsubscribe(session_id, subscription)
        reader.cancel()
        forwarder.cancel()
        await asyncio.gather(reader, forwarder, return_exceptions=True)


async def _consume_websocket(
    websocket: WebSocket,
    runtime: AgentRuntimeSupervisor,
    session_id: str,
    subscription: AgentStreamSubscription,
) -> None:
    replay_initialized = False
    while True:
        raw = await websocket.receive_text()
        try:
            frame = _client_frame_adapter.validate_json(raw)
        except ValidationError:
            await close_ws_silently(websocket, code=ws_status.WS_1003_UNSUPPORTED_DATA)
            return
        if isinstance(frame, AgentAckFrame) and not replay_initialized:
            replay_initialized = True
            await runtime.replay_from(session_id, subscription, frame.durable_seq)


async def _forward_frames(websocket, subscription: AgentStreamSubscription, session_id, user) -> None:
    loop = asyncio.get_running_loop()
    next_check = loop.time() + _ACCESS_CHECK_INTERVAL_SECONDS
    while True:
        now = loop.time()
        if now >= next_check:
            current = await resolve_current_user(user)
            if current is None or await repository.get_accessible_session(
                session_id, current.id, current.role
            ) is None:
                await close_ws_silently(websocket, code=ws_status.WS_1008_POLICY_VIOLATION)
                return
            next_check = loop.time() + _ACCESS_CHECK_INTERVAL_SECONDS

        timeout = max(0.0, next_check - loop.time())
        try:
            frame = await asyncio.wait_for(subscription.queue.get(), timeout=timeout)
        except TimeoutError:
            frame = AgentHeartbeatFrame(sent_at=utc_now())
        if frame is None:
            return
        if not await _send_frame(websocket, frame):
            return


async def _send_frame(websocket: WebSocket, frame: AgentServerFrame) -> bool:
    if websocket.client_state != WebSocketState.CONNECTED or websocket.application_state != WebSocketState.CONNECTED:
        return False
    try:
        await websocket.send_text(frame.model_dump_json())
        return True
    except Exception:
        return False


def _raise_runtime_error(exc: Exception) -> None:
    if isinstance(exc, (agent_runtime.SessionNotRunnableError, agent_runtime.SandboxContainerUnavailableError, ValueError)):
        raise_api_error(HTTPStatus.BAD_REQUEST, str(exc))
    if isinstance(exc, agent_runtime.AgentUnavailableError):
        raise_api_error(HTTPStatus.BAD_REQUEST, str(exc))
    if isinstance(exc, agent_runtime.SessionBusyError):
        raise_api_error(HTTPStatus.CONFLICT, str(exc))
    if isinstance(exc, PermissionError):
        raise_api_error(HTTPStatus.NOT_FOUND, "agent session not found")
