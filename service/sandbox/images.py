from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import or_
from sqlmodel import select

from database import get_async_session
from model.sandbox.containers import SandboxContainer
from model.sandbox.images import SandboxImage
from schema.sandbox.images import SandboxImageSchema
from service.common.pagination import Page, RESOURCE_PAGE_SIZE, paginate_statement


@dataclass(frozen=True)
class DeleteSandboxImageResult:
    deleted: bool
    not_found: bool = False
    message: str = ""


async def create_sandbox_image(
    image_name: str,
    control_proxy_port: int,
    supports_tor: bool,
) -> SandboxImageSchema:
    now = datetime.now()
    sandbox_image = SandboxImage(
        image_name=image_name,
        control_proxy_port=control_proxy_port,
        supports_tor=supports_tor,
        created_at=now,
        updated_at=now,
    )
    async with get_async_session() as session:
        session.add(sandbox_image)
        await session.commit()
        await session.refresh(sandbox_image)
        return SandboxImageSchema.model_validate(sandbox_image)


async def delete_sandbox_image(id: int) -> DeleteSandboxImageResult:
    async with get_async_session() as session:
        sandbox_image = (await session.exec(
            select(SandboxImage).where(SandboxImage.id == id).with_for_update()
        )).one_or_none()
        if sandbox_image is None:
            return DeleteSandboxImageResult(deleted=False, not_found=True, message="sandbox image not found")

        result = await session.exec(select(SandboxContainer.id).where(SandboxContainer.image_id == id).limit(1))
        if result.first() is not None:
            return DeleteSandboxImageResult(
                deleted=False,
                message="sandbox image is used by sandbox containers",
            )

        await session.delete(sandbox_image)
        await session.commit()

    return DeleteSandboxImageResult(deleted=True)


async def query_sandbox_images(
    page: int = 1,
    size: int = RESOURCE_PAGE_SIZE,
    keyword: str = "",
) -> Page[SandboxImageSchema]:
    statement = select(SandboxImage).order_by(SandboxImage.id)

    keyword = keyword.strip()
    if keyword:
        pattern = f"%{keyword}%"
        statement = statement.where(or_(SandboxImage.image_name.ilike(pattern)))

    return await paginate_statement(
        statement,
        page=page,
        size=size,
        item_mapper=SandboxImageSchema.model_validate,
    )
