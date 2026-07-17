from sqlmodel import select

from model.threat.behaviors import BehaviorEvent, ThreatIncidentBehaviorEvent
from service.threat.event_integrity import require_behavior_event_integrity


async def require_incident_behavior_events(
    session,
    incident_id: int,
    event_ids: list[int],
) -> dict[int, BehaviorEvent]:
    normalized_ids = list(dict.fromkeys(event_ids))
    rows = list((await session.exec(
        select(BehaviorEvent)
        .join(ThreatIncidentBehaviorEvent, ThreatIncidentBehaviorEvent.event_id == BehaviorEvent.id)
        .where(ThreatIncidentBehaviorEvent.incident_id == incident_id)
        .where(BehaviorEvent.id.in_(normalized_ids))
    )).all())
    events = {event.id: event for event in rows if event.id is not None}
    missing = [event_id for event_id in normalized_ids if event_id not in events]
    if missing:
        raise ValueError(
            "behavior events are not assigned to the threat incident: "
            + ", ".join(str(event_id) for event_id in missing[:20])
        )
    await require_behavior_event_integrity(session, list(events.values()))
    return events
