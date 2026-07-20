"""Transactional persistence for the durable Agent event stream."""

from sqlmodel.ext.asyncio.session import AsyncSession

from model.agent.sessions import AgentEvent, AgentSession
from schema.agent.events import AgentDurableEvent


async def append_event(
    db: AsyncSession,
    agent_session: AgentSession,
    event: AgentDurableEvent,
) -> AgentDurableEvent:
    if event.seq != agent_session.next_event_seq:
        event = event.model_copy(update={"seq": agent_session.next_event_seq})
    agent_session.next_event_seq += 1
    agent_session.updated_at = event.occurred_at
    db.add(agent_session)
    db.add(AgentEvent(
        id=event.id,
        session_id=event.session_id,
        run_id=event.run_id,
        attempt_id=event.attempt_id,
        seq=event.seq,
        event_type=str(event.type),
        payload=event.model_dump(mode="json"),
        occurred_at=event.occurred_at,
    ))
    return event
