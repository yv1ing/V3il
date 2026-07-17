from http import HTTPStatus

from handler.common.http import raise_api_error
from middleware.system_user import AuthUser
from schema.common.responses import CommonResponse
from schema.threat.chains import CreateAttackChainRequest, QueryAttackChainsResponse
from service.common.pagination import paginated_payload
from service.threat.chains import AttackChainMutationResult, create_attack_chain, query_attack_chains_for_user


def _raise_chain_error(result: AttackChainMutationResult) -> None:
    if result.not_found:
        raise_api_error(HTTPStatus.NOT_FOUND, result.message or "threat incident not found")
    if result.forbidden:
        raise_api_error(HTTPStatus.FORBIDDEN, result.message or "threat incident is not accessible by user")
    if result.conflict:
        raise_api_error(HTTPStatus.CONFLICT, result.message or "attack chain conflict")
    raise RuntimeError("attack chain failed without an error classification")


async def create_attack_chain_handler(
    incident_id: int,
    request: CreateAttackChainRequest,
    user: AuthUser,
) -> CommonResponse:
    result = await create_attack_chain(
        incident_id,
        request,
        user_id=user.id,
        user_role=user.role,
    )
    if result.chain is None:
        _raise_chain_error(result)
    return CommonResponse(message="attack chain created", data=result.chain)


async def query_attack_chains_handler(
    incident_id: int,
    *,
    page: int,
    size: int,
    user: AuthUser,
) -> CommonResponse:
    chains = await query_attack_chains_for_user(
        incident_id,
        page=page,
        size=size,
        user_id=user.id,
        user_role=user.role,
    )
    if chains is None:
        raise_api_error(HTTPStatus.NOT_FOUND, "threat incident not found")
    return CommonResponse(data=QueryAttackChainsResponse(
        **paginated_payload(chains, chains.items),
    ))
