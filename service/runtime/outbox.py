from pydantic import TypeAdapter
from sqlmodel.ext.asyncio.session import AsyncSession

from model.runtime import RuntimeOutboxEvent
from schema.runtime import OutboxPayload


_payload_adapter = TypeAdapter(OutboxPayload)


def enqueue_outbox_event(
    session: AsyncSession,
    payload: OutboxPayload,
    *,
    idempotency_key: str,
) -> RuntimeOutboxEvent:
    validated = _payload_adapter.validate_python(payload)
    event = RuntimeOutboxEvent(
        topic=str(validated.type),
        idempotency_key=idempotency_key,
        payload=validated.model_dump(mode="json"),
    )
    session.add(event)
    return event

