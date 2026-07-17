from fastapi import APIRouter, Depends, Query

from handler.threat.chains import create_attack_chain_handler, query_attack_chains_handler
from middleware.system_user import AuthUser, require_user
from router.common.responses import COMMON_ERROR_RESPONSES, CONFLICT_RESPONSE, FORBIDDEN_RESPONSE, not_found_response
from schema.common.responses import CommonResponse
from schema.threat.chains import AttackChainSchema, CreateAttackChainRequest, QueryAttackChainsResponse
from service.common.pagination import RESOURCE_PAGE_MAX_SIZE, RESOURCE_PAGE_SIZE


NOT_FOUND_RESPONSE = not_found_response("Threat incident")

router = APIRouter(
    prefix="/threat-incidents",
    tags=["attack-chains"],
    dependencies=[Depends(require_user)],
)


async def create_attack_chain_route(
    id: int,
    request: CreateAttackChainRequest,
    user: AuthUser = Depends(require_user),
) -> CommonResponse[AttackChainSchema]:
    return await create_attack_chain_handler(id, request, user)


async def query_attack_chains_route(
    id: int,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=RESOURCE_PAGE_SIZE, ge=1, le=RESOURCE_PAGE_MAX_SIZE),
    user: AuthUser = Depends(require_user),
) -> CommonResponse[QueryAttackChainsResponse]:
    return await query_attack_chains_handler(id, page=page, size=size, user=user)


router.add_api_route(
    "/{id}/attack-chains",
    create_attack_chain_route,
    methods=["POST"],
    response_model=CommonResponse[AttackChainSchema],
    responses={**COMMON_ERROR_RESPONSES, **FORBIDDEN_RESPONSE, **CONFLICT_RESPONSE, **NOT_FOUND_RESPONSE},
)
router.add_api_route(
    "/{id}/attack-chains",
    query_attack_chains_route,
    methods=["GET"],
    response_model=CommonResponse[QueryAttackChainsResponse],
    responses={**COMMON_ERROR_RESPONSES, **NOT_FOUND_RESPONSE},
)
