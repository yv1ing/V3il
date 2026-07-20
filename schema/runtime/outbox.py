from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, Field

from schema.agent.types import AgentCancellationMode


class OutboxTopic(StrEnum):
    AGENT_RUN_READY = "agent.run.ready"
    AGENT_CONTINUATION_READY = "agent.continuation.ready"
    AGENT_RUN_CANCEL = "agent.run.cancel"
    AGENT_SESSION_CANCEL = "agent.session.cancel"
    KNOWLEDGE_PUBLICATION_READY = "knowledge.publication.ready"


class RuntimeContinuationDisposition(StrEnum):
    DELIVERED = "delivered"
    DISCARDED = "discarded"


class AgentRunReadyPayload(BaseModel):
    type: Literal[OutboxTopic.AGENT_RUN_READY] = OutboxTopic.AGENT_RUN_READY
    run_id: str
    event_id: str


class AgentContinuationReadyPayload(BaseModel):
    type: Literal[OutboxTopic.AGENT_CONTINUATION_READY] = OutboxTopic.AGENT_CONTINUATION_READY
    run_id: str
    event_id: str


class AgentSessionCancelPayload(BaseModel):
    type: Literal[OutboxTopic.AGENT_SESSION_CANCEL] = OutboxTopic.AGENT_SESSION_CANCEL
    session_id: str
    mode: AgentCancellationMode
    actor: str


class AgentRunCancelPayload(BaseModel):
    type: Literal[OutboxTopic.AGENT_RUN_CANCEL] = OutboxTopic.AGENT_RUN_CANCEL
    run_id: str
    mode: AgentCancellationMode
    actor: str


class KnowledgePublicationReadyPayload(BaseModel):
    type: Literal[OutboxTopic.KNOWLEDGE_PUBLICATION_READY] = OutboxTopic.KNOWLEDGE_PUBLICATION_READY
    report_id: int
    artifact_sha256: str


OutboxPayload = Annotated[
    AgentRunReadyPayload
    | AgentContinuationReadyPayload
    | AgentRunCancelPayload
    | AgentSessionCancelPayload
    | KnowledgePublicationReadyPayload,
    Field(discriminator="type"),
]


class RuntimeLeaseSnapshot(BaseModel):
    name: str
    owner_id: str
    fencing_token: int
    acquired_at: datetime
    expires_at: datetime
