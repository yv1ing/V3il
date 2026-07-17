from typing import Any

from model.threat.investigations import AuditEvent
from schema.threat.investigations import AuditActorType, AuditEventKind


async def add_audit_event(
    session,
    *,
    kind: AuditEventKind,
    summary: str,
    incident_id: int | None = None,
    environment_id: int | None = None,
    task_id: int | None = None,
    detection_rule_id: int | None = None,
    managed_host_id: int | None = None,
    actor_type: AuditActorType = AuditActorType.SYSTEM,
    actor_code: str = "system",
    session_id: str = "",
    object_type: str = "",
    object_id: int | str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    event = AuditEvent(
        incident_id=incident_id,
        environment_id=environment_id,
        task_id=task_id,
        detection_rule_id=detection_rule_id,
        managed_host_id=managed_host_id,
        kind=kind,
        actor_type=actor_type,
        actor_code=actor_code,
        session_id=session_id,
        object_type=object_type,
        object_id="" if object_id is None else str(object_id),
        summary=summary,
        details=details or {},
    )
    session.add(event)
    await session.flush()
    return event
