from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, Column, DateTime, Index, JSON, UniqueConstraint
from sqlmodel import Field, SQLModel

from utils.time import utc_now


class RuntimeOutboxEvent(SQLModel, table=True):
    __tablename__ = "runtime_outbox_events"
    __table_args__ = (
        UniqueConstraint("topic", "idempotency_key", name="uq_runtime_outbox_topic_key"),
        Index("ix_runtime_outbox_dispatch", "available_at", "published_at", "id"),
        CheckConstraint("attempt_count >= 0", name="ck_runtime_outbox_attempt_count"),
    )

    id: int | None = Field(default=None, primary_key=True, sa_type=BigInteger)
    topic: str = Field(max_length=96, index=True)
    idempotency_key: str = Field(max_length=255)
    payload: dict = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
    attempt_count: int = Field(default=0)
    last_error: str = ""
    available_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    published_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class RuntimeConsumerReceipt(SQLModel, table=True):
    __tablename__ = "runtime_consumer_receipts"

    consumer: str = Field(primary_key=True, max_length=96)
    idempotency_key: str = Field(primary_key=True, max_length=255)
    processed_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class RuntimeLease(SQLModel, table=True):
    __tablename__ = "runtime_leases"
    __table_args__ = (
        CheckConstraint("owner_id <> ''", name="ck_runtime_lease_owner"),
        CheckConstraint("fencing_token > 0", name="ck_runtime_lease_fencing_token"),
        CheckConstraint("expires_at >= acquired_at", name="ck_runtime_lease_interval"),
    )

    name: str = Field(primary_key=True, max_length=96)
    owner_id: str = Field(max_length=128, index=True)
    fencing_token: int = Field(default=0, sa_column=Column(BigInteger, nullable=False))
    acquired_at: datetime = Field(sa_column=Column(DateTime(timezone=True), nullable=False))
    expires_at: datetime = Field(sa_column=Column(DateTime(timezone=True), nullable=False, index=True))
