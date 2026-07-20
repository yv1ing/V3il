from datetime import datetime

from sqlalchemy import Column
from sqlmodel import Field, SQLModel

from schema.common.resources import ResourceLifecycleStatus
from schema.egress_proxy.proxies import EgressProxyType
from utils.sqlalchemy import enum_value_type, utc_datetime_column
from utils.time import utc_now


class EgressProxy(SQLModel, table=True):
    __tablename__ = "egress_proxies"

    id: int | None = Field(default=None, primary_key=True)
    status: ResourceLifecycleStatus = Field(
        default=ResourceLifecycleStatus.ACTIVE,
        sa_column=Column(enum_value_type(ResourceLifecycleStatus, length=16), nullable=False, index=True),
    )
    proxy_type: EgressProxyType = Field(default=EgressProxyType.HTTP, index=True)
    proxy_host: str = Field(default="", index=True)
    proxy_port: int = Field(default=0)
    proxy_account: str = Field(default="")
    proxy_password: str = Field(default="")
    created_at: datetime = Field(default_factory=utc_now, sa_column=utc_datetime_column())
    updated_at: datetime = Field(default_factory=utc_now, sa_column=utc_datetime_column())
    retired_at: datetime | None = Field(default=None, sa_column=utc_datetime_column(nullable=True))
