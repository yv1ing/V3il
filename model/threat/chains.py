from sqlalchemy import Column, JSON
from sqlmodel import Field, SQLModel

from schema.threat.chains import AttackChainStatus
from utils.sqlalchemy import enum_value_type


class AttackChain(SQLModel, table=True):
    __tablename__ = "attack_chains"

    analysis_id: int = Field(foreign_key="analysis_records.id", primary_key=True, ondelete="RESTRICT")
    status: AttackChainStatus = Field(
        sa_column=Column(enum_value_type(AttackChainStatus, length=32), nullable=False, index=True)
    )
    summary: str = ""
    steps: list[dict] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    gaps: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
