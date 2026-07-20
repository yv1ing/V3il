from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, Column, ForeignKey, Integer, JSON, UniqueConstraint
from sqlmodel import Field, SQLModel

from schema.sandbox.containers import SandboxContainerEgressMode, SandboxContainerStatus
from utils.sqlalchemy import utc_datetime_column
from utils.time import utc_now


class SandboxContainer(SQLModel, table=True):
    __tablename__ = "sandbox_containers"
    __table_args__ = (
        UniqueConstraint(
            "provisioned_for_revision_id",
            name="uq_sandbox_container_provisioned_revision",
        ),
        CheckConstraint("generation >= 0", name="ck_sandbox_container_generation"),
    )

    id: int | None = Field(default=None, primary_key=True)
    host_id: int = Field(default=0, foreign_key="managed_hosts.id", index=True, ondelete="RESTRICT")
    container_name: str = Field(default="")
    container_hash: str = Field(default="")
    owner_id: int = Field(default=0, foreign_key="system_users.id", index=True, ondelete="RESTRICT")
    image_id: int = Field(default=0, foreign_key="sandbox_images.id", index=True, ondelete="RESTRICT")
    egress_mode: SandboxContainerEgressMode = Field(default=SandboxContainerEgressMode.DIRECT, index=True)
    egress_proxy_id: int | None = Field(
        default=None,
        foreign_key="egress_proxies.id",
        index=True,
        ondelete="RESTRICT",
    )
    control_proxy_host_port: int = Field(default=0)
    control_proxy_token: str = Field(default="")
    behavior_sensor_id: str = Field(default="", index=True)
    provisioned_for_revision_id: int | None = Field(
        default=None,
        sa_column=Column(
            Integer,
            ForeignKey(
                "deception_revisions.id",
                name="fk_sandbox_container_provisioned_revision",
                ondelete="RESTRICT",
                use_alter=True,
            ),
            nullable=True,
            index=True,
        ),
    )
    port_mappings: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    status: SandboxContainerStatus = Field(default=SandboxContainerStatus.CREATED)
    generation: int = Field(default=0, ge=0, sa_column=Column(BigInteger, nullable=False))
    created_at: datetime = Field(default_factory=utc_now, sa_column=utc_datetime_column())
    updated_at: datetime = Field(default_factory=utc_now, sa_column=utc_datetime_column())
    removed_at: datetime | None = Field(default=None, sa_column=utc_datetime_column(nullable=True))
