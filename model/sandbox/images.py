from datetime import datetime

from sqlalchemy import Column
from sqlmodel import Field, SQLModel

from schema.common.resources import ResourceLifecycleStatus
from utils.sqlalchemy import enum_value_type, utc_datetime_column
from utils.time import utc_now


class SandboxImage(SQLModel, table=True):
    __tablename__ = "sandbox_images"

    id: int | None = Field(default=None, primary_key=True)
    status: ResourceLifecycleStatus = Field(
        default=ResourceLifecycleStatus.ACTIVE,
        sa_column=Column(enum_value_type(ResourceLifecycleStatus, length=16), nullable=False, index=True),
    )
    image_name: str = Field(default="")
    control_proxy_port: int = Field(default=8000)
    supports_tor: bool = Field(default=False)
    created_at: datetime = Field(default_factory=utc_now, sa_column=utc_datetime_column())
    updated_at: datetime = Field(default_factory=utc_now, sa_column=utc_datetime_column())
    retired_at: datetime | None = Field(default=None, sa_column=utc_datetime_column(nullable=True))
