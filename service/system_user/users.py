from dataclasses import dataclass
from datetime import timedelta

import jwt
import hmac
from sqlalchemy import func, or_, text
from sqlalchemy.exc import IntegrityError
from sqlmodel import select

from config import get_config
from database import get_async_session
from logger import get_logger
from model.system_user.users import SystemUser
from schema.common.resources import ResourceLifecycleStatus
from schema.system_user.users import SystemUserRole, SystemUserSchema
from service.common.pagination import Page, RESOURCE_PAGE_SIZE, paginate_statement
from service.system_user.locking import lock_system_user_lifecycle
from utils.time import utc_now


logger = get_logger(__name__)

@dataclass(frozen=True)
class RetireSystemUserResult:
    retired: bool
    not_found: bool = False
    message: str = ""


@dataclass(frozen=True)
class UpdateSystemUserResult:
    user: SystemUserSchema | None
    not_found: bool = False
    message: str = ""


class SystemUserConflictError(ValueError):
    pass


async def create_system_user(
    username: str,
    password: str,
    email: str = "",
    role: SystemUserRole = SystemUserRole.USER,
) -> SystemUserSchema:
    now = utc_now()
    system_user = SystemUser(
        role=role,
        email=email.strip().casefold(),
        username=username.strip(),
        password=password,
        created_at=now,
        updated_at=now,
    )

    async with get_async_session() as session:
        session.add(system_user)
        try:
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            raise SystemUserConflictError("username or email already exists") from exc
        await session.refresh(system_user)
        result = SystemUserSchema.model_validate(system_user)

    logger.info("system user created: %s", result.id)
    return result


async def retire_system_user(id: int) -> RetireSystemUserResult:
    async with get_async_session() as session:
        await _lock_admin_membership(session)
        await lock_system_user_lifecycle(session, id)
        system_user = (await session.exec(
            select(SystemUser).where(
                SystemUser.id == id,
                SystemUser.status == ResourceLifecycleStatus.ACTIVE,
            ).with_for_update()
        )).first()
        if system_user is None:
            return RetireSystemUserResult(retired=False, not_found=True, message="system user not found")
        message = await _user_deletion_blocker(session, system_user)
        if message:
            return RetireSystemUserResult(retired=False, message=message)
        now = utc_now()
        system_user.status = ResourceLifecycleStatus.RETIRED
        system_user.retired_at = now
        system_user.updated_at = now
        session.add(system_user)
        await session.commit()

    logger.info("system user retired: %s", id)
    return RetireSystemUserResult(retired=True)


async def update_system_user(
    id: int,
    username: str | None = None,
    password: str | None = None,
    email: str | None = None,
    role: SystemUserRole | None = None,
) -> UpdateSystemUserResult:
    async with get_async_session() as session:
        await _lock_admin_membership(session)
        system_user = (await session.exec(
            select(SystemUser).where(
                SystemUser.id == id,
                SystemUser.status == ResourceLifecycleStatus.ACTIVE,
            ).with_for_update()
        )).first()
        if system_user is None:
            return UpdateSystemUserResult(user=None, not_found=True)

        if (
            role == SystemUserRole.USER
            and system_user.role == SystemUserRole.ADMIN
            and await _admin_count(session) <= 1
        ):
            return UpdateSystemUserResult(
                user=None,
                message="the last administrator cannot be demoted",
            )

        if role is not None:
            system_user.role = role
        if email is not None:
            system_user.email = email.strip().casefold()
        if username is not None:
            system_user.username = username.strip()
        if password is not None:
            system_user.password = password

        system_user.updated_at = utc_now()
        session.add(system_user)
        try:
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            raise SystemUserConflictError("username or email already exists") from exc
        await session.refresh(system_user)
        result = SystemUserSchema.model_validate(system_user)

    logger.info("system user updated: %s", result.id)
    return UpdateSystemUserResult(user=result)


async def query_system_user_by_username(username: str) -> SystemUserSchema | None:
    async with get_async_session() as session:
        result = await session.exec(select(SystemUser).where(
            SystemUser.username == username.strip(),
            SystemUser.status == ResourceLifecycleStatus.ACTIVE,
        ))
        user = result.first()
        return SystemUserSchema.model_validate(user) if user is not None else None


async def query_system_user_by_id(user_id: int) -> SystemUserSchema | None:
    async with get_async_session() as session:
        user = (await session.exec(select(SystemUser).where(
            SystemUser.id == user_id,
            SystemUser.status == ResourceLifecycleStatus.ACTIVE,
        ))).one_or_none()
        return SystemUserSchema.model_validate(user) if user is not None else None


async def query_system_users(
    page: int = 1,
    size: int = RESOURCE_PAGE_SIZE,
    keyword: str = "",
) -> Page[SystemUserSchema]:
    statement = select(SystemUser).where(
        SystemUser.status == ResourceLifecycleStatus.ACTIVE,
    ).order_by(SystemUser.id)

    keyword = keyword.strip()
    if keyword:
        pattern = f"%{keyword}%"
        statement = statement.where(
            or_(
                SystemUser.email.ilike(pattern),
                SystemUser.username.ilike(pattern),
            )
        )

    return await paginate_statement(
        statement,
        page=page,
        size=size,
        item_mapper=SystemUserSchema.model_validate,
    )


async def system_user_login(email: str, password: str) -> str | None:
    cfg = get_config()

    async with get_async_session() as session:
        row = (await session.exec(select(
            SystemUser.id,
            SystemUser.role,
            SystemUser.email,
            SystemUser.username,
            SystemUser.password,
        ).where(
            SystemUser.email == email.strip().casefold(),
            SystemUser.status == ResourceLifecycleStatus.ACTIVE,
        ))).one_or_none()
    if row is None:
        return None
    user_id, role, user_email, username, stored_password = row

    if not hmac.compare_digest(password, stored_password):
        return None

    return jwt.encode(
        payload={
            "id": user_id,
            "role": role,
            "email": user_email,
            "username": username,
            "sub": "v3il",
            "exp": utc_now() + timedelta(days=30),
        },
        key=cfg.system.jwt_signing_key,
        algorithm="HS256",
    )


async def _user_deletion_blocker(session, user: SystemUser) -> str:
    if user.role == SystemUserRole.ADMIN and await _admin_count(session) <= 1:
        return "the last administrator cannot be retired"
    return ""


async def _admin_count(session) -> int:
    result = await session.exec(
        select(func.count()).select_from(SystemUser).where(
            SystemUser.role == SystemUserRole.ADMIN,
            SystemUser.status == ResourceLifecycleStatus.ACTIVE,
        )
    )
    return int(result.one())


async def _lock_admin_membership(session) -> None:
    # Serializes administrator deletion/demotion decisions across backend workers.
    await session.execute(text("SELECT pg_advisory_xact_lock(8743162201)"))
