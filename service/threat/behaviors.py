import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, or_
from sqlmodel import select

from database import get_async_session
from model.deception.environments import DeceptionEnvironment
from model.threat.behaviors import BehaviorEvent, BehaviorSensorCursor, ThreatIncidentBehaviorEvent
from model.threat.incidents import ThreatIncident, ThreatIncidentEnvironment
from schema.system_user.users import SystemUserRole
from schema.threat.behaviors import (
    BehaviorEventCategory,
    BehaviorEventSource,
    BehaviorEventSchema,
    AssignBehaviorEventsRequest,
    AssignBehaviorEventsResponse,
    CapturedBehaviorEvent,
    ImportBehaviorEventBatchRequest,
    IngestBehaviorEventBatchRequest,
    IngestBehaviorEventBatchResponse,
)
from schema.threat.incidents import ThreatIncidentStatus
from service.common.pagination import Page, RESOURCE_PAGE_SIZE, page_offset
from service.threat.event_integrity import (
    behavior_event_hash,
    require_behavior_event_integrity,
    sensor_event_hash,
)
from service.threat.types import CLOSED_INCIDENT_MESSAGE


@dataclass(frozen=True)
class BehaviorIngestionResult:
    response: IngestBehaviorEventBatchResponse | None
    new_event_ids: tuple[int, ...] = ()
    not_found: bool = False
    forbidden: bool = False
    conflict: bool = False
    message: str = ""


async def ingest_imported_behavior_event_batch(
    environment_id: int,
    request: ImportBehaviorEventBatchRequest,
    *,
    user_id: int,
    user_role: SystemUserRole,
) -> BehaviorIngestionResult:
    source_digest = hashlib.sha256(request.sensor_id.encode("utf-8")).hexdigest()[:32]
    sensor_id = f"import:{user_id}:{source_digest}"
    imported = IngestBehaviorEventBatchRequest(
        sensor_id=sensor_id,
        incident_id=request.incident_id,
        events=[
            CapturedBehaviorEvent(
                **event.model_dump(mode="python", exclude={"attributes"}),
                source=BehaviorEventSource.IMPORT,
                raw_reference=f"import://{user_id}/{source_digest}/{event.sequence}",
                attributes={
                    **event.attributes,
                    "import_sensor_id": request.sensor_id,
                },
            )
            for event in request.events
        ],
    )
    return await ingest_behavior_event_batch(
        environment_id,
        imported,
        user_id=user_id,
        user_role=user_role,
    )


async def ingest_behavior_event_batch(
    environment_id: int,
    request: IngestBehaviorEventBatchRequest,
    *,
    user_id: int,
    user_role: SystemUserRole,
    sensor_control_token: str | None = None,
) -> BehaviorIngestionResult:
    async with get_async_session() as session, session.begin():
        environment = (await session.exec(
            select(DeceptionEnvironment)
            .where(DeceptionEnvironment.id == environment_id)
            .with_for_update()
        )).one_or_none()
        if environment is None:
            return BehaviorIngestionResult(response=None, not_found=True, message="deception environment not found")
        if user_role != SystemUserRole.ADMIN and environment.owner_id != user_id:
            return BehaviorIngestionResult(response=None, forbidden=True)
        incident = None
        if request.incident_id is not None:
            incident = await session.get(ThreatIncident, request.incident_id)
            relation = await session.get(ThreatIncidentEnvironment, (request.incident_id, environment_id))
            if incident is None or relation is None:
                return BehaviorIngestionResult(
                    response=None,
                    conflict=True,
                    message="threat incident does not belong to the deception environment",
                )
            if incident.status == ThreatIncidentStatus.CLOSED:
                return BehaviorIngestionResult(
                    response=None,
                    conflict=True,
                    message=CLOSED_INCIDENT_MESSAGE,
                )

        cursor = (await session.exec(select(BehaviorSensorCursor).where(
            BehaviorSensorCursor.environment_id == environment_id,
            BehaviorSensorCursor.sensor_id == request.sensor_id,
        ).with_for_update())).one_or_none()
        if cursor is None:
            cursor = BehaviorSensorCursor(
                environment_id=environment_id,
                sensor_id=request.sensor_id,
                last_sequence=0,
                verification_token=sensor_control_token or "",
            )
            session.add(cursor)
        elif sensor_control_token:
            if cursor.verification_token and not hmac.compare_digest(
                cursor.verification_token,
                sensor_control_token,
            ):
                return BehaviorIngestionResult(
                    response=None,
                    conflict=True,
                    message="behavior sensor authentication token changed for an existing chain",
                )
            cursor.verification_token = sensor_control_token
        if cursor.last_sequence > 0:
            chain_head = (await session.exec(select(BehaviorEvent).where(
                BehaviorEvent.environment_id == environment_id,
                BehaviorEvent.sensor_id == request.sensor_id,
                BehaviorEvent.sequence == cursor.last_sequence,
            ).limit(1))).first()
            if chain_head is None:
                return BehaviorIngestionResult(
                    response=None,
                    conflict=True,
                    message="behavior sensor cursor points to a missing event",
                )
            if cursor.last_event_hash and cursor.last_event_hash != chain_head.event_hash:
                return BehaviorIngestionResult(
                    response=None,
                    conflict=True,
                    message="behavior sensor cursor hash does not match the persisted chain head",
                )
            cursor.last_event_hash = chain_head.event_hash
            if cursor.last_sensor_hash and cursor.last_sensor_hash != chain_head.sensor_event_hash:
                return BehaviorIngestionResult(
                    response=None,
                    conflict=True,
                    message="behavior sensor cursor HMAC does not match the persisted chain head",
                )
            cursor.last_sensor_hash = chain_head.sensor_event_hash

        sequences = [event.sequence for event in request.events]
        existing_events = list((await session.exec(select(BehaviorEvent).where(
            BehaviorEvent.environment_id == environment_id,
            BehaviorEvent.sensor_id == request.sensor_id,
            BehaviorEvent.sequence.in_(sequences),
        ))).all())
        existing_by_sequence = {event.sequence: event for event in existing_events}
        existing_ids = [event.id for event in existing_events if event.id is not None]
        existing_links = list((await session.exec(select(ThreatIncidentBehaviorEvent).where(
            ThreatIncidentBehaviorEvent.event_id.in_(existing_ids),
        ))).all()) if existing_ids else []
        incident_by_event_id = {link.event_id: link.incident_id for link in existing_links}
        expected_sequence = cursor.last_sequence + 1
        accepted_ids: list[int] = []
        new_event_ids: list[int] = []
        duplicates = 0
        latest_observed_at = cursor.last_observed_at

        for captured in request.events:
            existing = existing_by_sequence.get(captured.sequence)
            if existing is not None:
                provenance_error = _sensor_provenance_error(
                    captured,
                    expected_previous_hash=existing.sensor_previous_hash,
                    sensor_control_token=sensor_control_token,
                )
                if provenance_error or (
                    captured.sensor_previous_hash != existing.sensor_previous_hash
                    or captured.sensor_event_hash != existing.sensor_event_hash
                ):
                    return BehaviorIngestionResult(
                        response=None,
                        conflict=True,
                        message=provenance_error or (
                            f"behavior event sequence {captured.sequence} conflicts with persisted sensor provenance"
                        ),
                    )
                digest = behavior_event_hash(captured, existing.previous_event_hash)
                if existing.event_hash != digest:
                    return BehaviorIngestionResult(
                        response=None,
                        conflict=True,
                        message=f"behavior event sequence {captured.sequence} conflicts with persisted content",
                    )
                linked_incident_id = incident_by_event_id.get(existing.id or 0)
                if request.incident_id is not None:
                    if linked_incident_id is not None and linked_incident_id != request.incident_id:
                        return BehaviorIngestionResult(
                            response=None,
                            conflict=True,
                            message=f"behavior event sequence {captured.sequence} conflicts with its incident binding",
                        )
                    if linked_incident_id is None and existing.id is not None:
                        session.add(ThreatIncidentBehaviorEvent(
                            event_id=existing.id,
                            incident_id=request.incident_id,
                            correlation_method="explicit_ingest",
                            correlation_key=request.sensor_id,
                            linked_at=datetime.now(),
                        ))
                duplicates += 1
                if existing.id is not None:
                    accepted_ids.append(existing.id)
                continue
            if captured.sequence != expected_sequence:
                return BehaviorIngestionResult(
                    response=None,
                    conflict=True,
                    message=f"behavior event sequence gap: expected {expected_sequence}, received {captured.sequence}",
                )
            provenance_error = _sensor_provenance_error(
                captured,
                expected_previous_hash=cursor.last_sensor_hash,
                sensor_control_token=sensor_control_token,
            )
            if provenance_error:
                return BehaviorIngestionResult(
                    response=None,
                    conflict=True,
                    message=provenance_error,
                )
            previous_event_hash = cursor.last_event_hash
            event = BehaviorEvent(
                environment_id=environment_id,
                sensor_id=request.sensor_id,
                previous_event_hash=previous_event_hash,
                event_hash=behavior_event_hash(captured, previous_event_hash),
                ingested_at=datetime.now(),
                **captured.model_dump(),
            )
            session.add(event)
            await session.flush()
            if event.id is None:
                raise RuntimeError("behavior event id was not generated")
            accepted_ids.append(event.id)
            new_event_ids.append(event.id)
            if request.incident_id is not None:
                session.add(ThreatIncidentBehaviorEvent(
                    event_id=event.id,
                    incident_id=request.incident_id,
                    correlation_method="explicit_ingest",
                    correlation_key=request.sensor_id,
                    linked_at=datetime.now(),
                ))
            expected_sequence += 1
            cursor.last_sequence = captured.sequence
            if captured.source != BehaviorEventSource.IMPORT:
                cursor.last_sensor_hash = captured.sensor_event_hash
            cursor.last_event_hash = event.event_hash
            if latest_observed_at is None or captured.observed_at > latest_observed_at:
                latest_observed_at = captured.observed_at

        cursor.last_observed_at = latest_observed_at
        cursor.updated_at = datetime.now()
        session.add(cursor)
        if incident is not None and latest_observed_at is not None and latest_observed_at > incident.last_observed_at:
            incident.last_observed_at = latest_observed_at
            incident.updated_at = datetime.now()
            session.add(incident)

        response = IngestBehaviorEventBatchResponse(
            sensor_id=request.sensor_id,
            accepted=len(request.events) - duplicates,
            duplicates=duplicates,
            last_sequence=cursor.last_sequence,
            event_ids=accepted_ids,
        )

    return BehaviorIngestionResult(
        response=response,
        new_event_ids=tuple(new_event_ids),
    )


def _sensor_provenance_error(
    event: CapturedBehaviorEvent,
    *,
    expected_previous_hash: str,
    sensor_control_token: str | None,
) -> str:
    if event.source in {BehaviorEventSource.IMPORT, BehaviorEventSource.CONTROL_PLANE}:
        if event.sensor_previous_hash or event.sensor_event_hash:
            return f"behavior event sequence {event.sequence} cannot claim sensor provenance"
        return ""
    if not sensor_control_token:
        return f"behavior event sequence {event.sequence} is missing trusted sensor authentication"
    if event.sensor_previous_hash != expected_previous_hash:
        return f"behavior event sequence {event.sequence} previous sensor HMAC does not match"
    expected_hash = sensor_event_hash(event, sensor_control_token)
    if not hmac.compare_digest(event.sensor_event_hash, expected_hash):
        return f"behavior event sequence {event.sequence} sensor HMAC is invalid"
    return ""


async def query_behavior_events_for_user(
    environment_id: int,
    *,
    page: int = 1,
    size: int = RESOURCE_PAGE_SIZE,
    category: BehaviorEventCategory | None = None,
    incident_id: int | None = None,
    keyword: str = "",
    user_id: int,
    user_role: SystemUserRole,
) -> Page[BehaviorEventSchema] | None:
    async with get_async_session() as session:
        environment = await session.get(DeceptionEnvironment, environment_id)
        if environment is None or (
            user_role != SystemUserRole.ADMIN and environment.owner_id != user_id
        ):
            return None
        statement = (
            select(BehaviorEvent, ThreatIncidentBehaviorEvent)
            .outerjoin(ThreatIncidentBehaviorEvent, ThreatIncidentBehaviorEvent.event_id == BehaviorEvent.id)
            .where(BehaviorEvent.environment_id == environment_id)
        )
        if category is not None:
            statement = statement.where(BehaviorEvent.category == category)
        if incident_id is not None:
            statement = statement.where(ThreatIncidentBehaviorEvent.incident_id == incident_id)
        keyword = keyword.strip()
        if keyword:
            pattern = f"%{keyword}%"
            statement = statement.where(or_(
                BehaviorEvent.action.ilike(pattern),
                BehaviorEvent.summary.ilike(pattern),
                BehaviorEvent.command_line.ilike(pattern),
                BehaviorEvent.file_path.ilike(pattern),
                BehaviorEvent.source_ip.ilike(pattern),
                BehaviorEvent.destination_ip.ilike(pattern),
                BehaviorEvent.service_name.ilike(pattern),
            ))
        statement = statement.order_by(BehaviorEvent.observed_at.desc(), BehaviorEvent.id.desc())
        count_statement = select(func.count()).select_from(statement.order_by(None).subquery())
        total = int((await session.execute(count_statement)).scalar_one())
        rows = list((await session.exec(statement.offset(page_offset(page, size)).limit(size))).all())
        items = [_behavior_event_schema(event, link) for event, link in rows]
    return Page(
        page=page,
        size=size,
        total=total,
        items=items,
    )


async def query_incident_behavior_events_for_user(
    incident_id: int,
    *,
    page: int = 1,
    size: int = RESOURCE_PAGE_SIZE,
    category: BehaviorEventCategory | None = None,
    keyword: str = "",
    user_id: int,
    user_role: SystemUserRole,
) -> Page[BehaviorEventSchema] | None:
    async with get_async_session() as session:
        incident = await session.get(ThreatIncident, incident_id)
        if incident is None or (
            user_role != SystemUserRole.ADMIN and incident.owner_id != user_id
        ):
            return None
        statement = (
            select(BehaviorEvent, ThreatIncidentBehaviorEvent)
            .join(
                ThreatIncidentBehaviorEvent,
                ThreatIncidentBehaviorEvent.event_id == BehaviorEvent.id,
            )
            .where(ThreatIncidentBehaviorEvent.incident_id == incident_id)
        )
        if category is not None:
            statement = statement.where(BehaviorEvent.category == category)
        if keyword := keyword.strip():
            pattern = f"%{keyword}%"
            statement = statement.where(or_(
                BehaviorEvent.action.ilike(pattern),
                BehaviorEvent.summary.ilike(pattern),
                BehaviorEvent.command_line.ilike(pattern),
                BehaviorEvent.file_path.ilike(pattern),
                BehaviorEvent.source_ip.ilike(pattern),
                BehaviorEvent.destination_ip.ilike(pattern),
                BehaviorEvent.service_name.ilike(pattern),
            ))
        statement = statement.order_by(
            BehaviorEvent.observed_at.desc(),
            BehaviorEvent.id.desc(),
        )
        total = int((await session.execute(
            select(func.count()).select_from(statement.order_by(None).subquery())
        )).scalar_one())
        rows = list((await session.exec(
            statement.offset(page_offset(page, size)).limit(size)
        )).all())
        items = [_behavior_event_schema(event, link) for event, link in rows]
    return Page(
        page=page,
        size=size,
        total=total,
        items=items,
    )


def _behavior_event_schema(
    event: BehaviorEvent,
    link: ThreatIncidentBehaviorEvent | None,
) -> BehaviorEventSchema:
    payload = event.model_dump()
    payload["incident_id"] = link.incident_id if link is not None else None
    payload["incident_link_method"] = link.correlation_method if link is not None else ""
    payload["incident_linked_at"] = link.linked_at if link is not None else None
    payload["incident_material"] = link.is_material if link is not None else False
    payload["materiality_reason"] = link.materiality_reason if link is not None else ""
    payload["correlation_score"] = link.correlation_score if link is not None else 0
    return BehaviorEventSchema.model_validate(payload)


async def assign_behavior_events_to_incident(
    incident_id: int,
    request: AssignBehaviorEventsRequest,
    *,
    user_id: int,
    user_role: SystemUserRole,
    agent_code: str = "",
    session_id: str = "",
) -> AssignBehaviorEventsResponse | None:
    async with get_async_session() as session, session.begin():
        incident = (await session.exec(
            select(ThreatIncident).where(ThreatIncident.id == incident_id).with_for_update()
        )).one_or_none()
        if incident is None or (
            user_role != SystemUserRole.ADMIN and incident.owner_id != user_id
        ):
            return None
        if incident.status == ThreatIncidentStatus.CLOSED:
            raise ValueError(CLOSED_INCIDENT_MESSAGE)
        events = list((await session.exec(select(BehaviorEvent).where(
            BehaviorEvent.id.in_(request.event_ids),
        ))).all())
        if len(events) != len(request.event_ids):
            raise ValueError("one or more behavior events do not exist")
        if user_role != SystemUserRole.ADMIN:
            accessible_environment_ids = set((await session.exec(
                select(DeceptionEnvironment.id).where(
                    DeceptionEnvironment.id.in_({event.environment_id for event in events}),
                    DeceptionEnvironment.owner_id == user_id,
                )
            )).all())
            if any(event.environment_id not in accessible_environment_ids for event in events):
                raise ValueError("behavior events must belong to environments owned by the incident owner")
        await require_behavior_event_integrity(session, events)
        links = list((await session.exec(select(ThreatIncidentBehaviorEvent).where(
            ThreatIncidentBehaviorEvent.event_id.in_(request.event_ids),
        ).with_for_update())).all())
        link_by_event_id = {link.event_id: link for link in links}
        existing = 0
        assigned = 0
        for event in events:
            if event.id is None:
                raise RuntimeError("persisted behavior event is missing an id")
            link = link_by_event_id.get(event.id)
            if link is not None:
                if link.incident_id != incident_id:
                    raise ValueError(f"behavior event {event.id} is already assigned to another threat incident")
                existing += 1
                continue
            session.add(ThreatIncidentBehaviorEvent(
                event_id=event.id,
                incident_id=incident_id,
                linked_by_agent_code=agent_code,
                linked_from_session_id=session_id,
                correlation_method="agent_assignment" if agent_code else "user_assignment",
                correlation_key=agent_code or str(user_id),
                linked_at=datetime.now(),
            ))
            relation = await session.get(ThreatIncidentEnvironment, (incident_id, event.environment_id))
            if relation is None:
                relation = ThreatIncidentEnvironment(
                    incident_id=incident_id,
                    environment_id=event.environment_id,
                    first_observed_at=event.observed_at,
                    last_observed_at=event.observed_at,
                    correlation_method="agent_assignment" if agent_code else "user_assignment",
                    correlation_key=agent_code or str(user_id),
                )
            else:
                relation.first_observed_at = min(relation.first_observed_at, event.observed_at)
                relation.last_observed_at = max(relation.last_observed_at, event.observed_at)
            session.add(relation)
            assigned += 1
        if events:
            last_observed_at = max(event.observed_at for event in events)
            if last_observed_at > incident.last_observed_at:
                incident.last_observed_at = last_observed_at
                incident.updated_at = datetime.now()
                session.add(incident)
    return AssignBehaviorEventsResponse(
        incident_id=incident_id,
        assigned=assigned,
        existing=existing,
    )
