from http import HTTPStatus

from handler.common.http import raise_api_error
from schema.common.responses import CommonResponse
from schema.sandbox.images import (
    CreateSandboxImageRequest,
    RetireSandboxImageResponse,
    QuerySandboxImagesResponse,
    SandboxImageSchema,
)
from service.sandbox.images import (
    create_sandbox_image,
    query_sandbox_images,
)
from service.common.pagination import paginated_payload


async def create_sandbox_image_handler(request: CreateSandboxImageRequest) -> CommonResponse:
    sandbox_image = await create_sandbox_image(
        image_name=request.image_name,
        control_proxy_port=request.control_proxy_port,
        supports_tor=request.supports_tor,
    )
    return CommonResponse(
        message="sandbox image created",
        data=sandbox_image,
    )


async def retire_sandbox_image_handler(id: int) -> CommonResponse:
    result = await retire_sandbox_image(id)
    if result.not_found:
        raise_api_error(HTTPStatus.NOT_FOUND, "sandbox image not found")
    if not result.retired:
        raise_api_error(HTTPStatus.BAD_REQUEST, result.message)
    return CommonResponse(data=RetireSandboxImageResponse(id=id))


async def query_sandbox_images_handler(page: int, size: int, keyword: str) -> CommonResponse:
    sandbox_images = await query_sandbox_images(page=page, size=size, keyword=keyword)
    return CommonResponse(data=QuerySandboxImagesResponse(
        **paginated_payload(
            sandbox_images,
            sandbox_images.items,
        ),
    ))
    retire_sandbox_image,
