from datetime import datetime

from sqlalchemy import Column
from sqlmodel import Field, SQLModel

from schema.common.resources import ResourceLifecycleStatus
from schema.system_user.users import SystemUserRole
from utils.sqlalchemy import enum_value_type, utc_datetime_column
from utils.time import utc_now


class SystemUser(SQLModel, table=True):
    __tablename__ = "system_users"

    id: int | None = Field(default=None, primary_key=True)
    status: ResourceLifecycleStatus = Field(
        default=ResourceLifecycleStatus.ACTIVE,
        sa_column=Column(enum_value_type(ResourceLifecycleStatus, length=16), nullable=False, index=True),
    )
    role: SystemUserRole = Field(default=SystemUserRole.USER)
    email: str = Field(index=True, unique=True)
    username: str = Field(index=True, unique=True)
    password: str = Field(default="")
    created_at: datetime = Field(default_factory=utc_now, sa_column=utc_datetime_column())
    updated_at: datetime = Field(default_factory=utc_now, sa_column=utc_datetime_column())
    retired_at: datetime | None = Field(default=None, sa_column=utc_datetime_column(nullable=True))
