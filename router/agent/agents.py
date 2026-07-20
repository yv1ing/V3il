from fastapi import APIRouter, Depends, Request

from handler.agent.agents import list_agents_handler
from middleware.system_user import require_user
from router.common.responses import COMMON_ERROR_RESPONSES
from schema.agent.sessions import ListAgentsResponse


router = APIRouter(prefix="/agents", tags=["agents"])


@router.get("", dependencies=[Depends(require_user)], response_model=ListAgentsResponse, responses=COMMON_ERROR_RESPONSES)
async def list_agents_route(request: Request) -> ListAgentsResponse:
    return await list_agents_handler(request)
