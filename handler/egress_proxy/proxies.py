from http import HTTPStatus

from handler.common.http import raise_api_error
from schema.common.responses import CommonResponse
from schema.egress_proxy.proxies import (
    CreateEgressProxyRequest,
    RetireEgressProxyResponse,
    EgressProxySchema,
    QueryEgressProxiesResponse,
    TestEgressProxyResponse,
    UpdateEgressProxyRequest,
)
from service.common.pagination import paginated_payload
from service.egress_proxy.proxies import (
    create_egress_proxy,
    query_egress_proxies,
    test_egress_proxy,
    update_egress_proxy,
)
from logger import get_logger


logger = get_logger(__name__)


async def create_egress_proxy_handler(request: CreateEgressProxyRequest) -> CommonResponse:
    proxy = await create_egress_proxy(
        proxy_type=request.proxy_type,
        proxy_host=request.proxy_host,
        proxy_port=request.proxy_port,
        proxy_account=request.proxy_account,
        proxy_password=request.proxy_password,
    )
    return CommonResponse(data=proxy)


async def update_egress_proxy_handler(id: int, request: UpdateEgressProxyRequest) -> CommonResponse:
    result = await update_egress_proxy(
        id=id,
        proxy_type=request.proxy_type,
        proxy_host=request.proxy_host,
        proxy_port=request.proxy_port,
        proxy_account=request.proxy_account,
        proxy_password=request.proxy_password,
    )
    if result.not_found:
        raise_api_error(HTTPStatus.NOT_FOUND, "egress proxy not found")
    if result.proxy is None or result.message:
        raise_api_error(HTTPStatus.BAD_REQUEST, result.message)
    if result.failed_container_ids:
        logger.warning(
            "egress proxy updated but failed to apply to running containers: proxy=%s containers=%s",
            id,
            result.failed_container_ids,
        )
    return CommonResponse(data=result.proxy)


async def retire_egress_proxy_handler(id: int) -> CommonResponse:
    result = await retire_egress_proxy(id)
    if result.not_found:
        raise_api_error(HTTPStatus.NOT_FOUND, "egress proxy not found")
    if not result.retired:
        raise_api_error(HTTPStatus.BAD_REQUEST, result.message)
    return CommonResponse(data=RetireEgressProxyResponse(id=id))


async def test_egress_proxy_handler(id: int) -> CommonResponse:
    result = await test_egress_proxy(id)
    if result.not_found:
        raise_api_error(HTTPStatus.NOT_FOUND, "egress proxy not found")
    return CommonResponse(data=TestEgressProxyResponse(
        id=result.id,
        success=result.success,
        status_code=result.status_code,
        elapsed_ms=result.elapsed_ms,
        message=result.message,
    ))


async def query_egress_proxies_handler(page: int, size: int, keyword: str) -> CommonResponse:
    proxies = await query_egress_proxies(page=page, size=size, keyword=keyword)
    return CommonResponse(data=QueryEgressProxiesResponse(
        **paginated_payload(
            proxies,
            proxies.items,
        ),
    ))
    retire_egress_proxy,
