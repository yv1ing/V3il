import hashlib
import hmac
import json
from datetime import timezone

from sqlalchemy import and_, or_
from sqlmodel import select

from model.threat.behaviors import BehaviorEvent, BehaviorSensorCursor
from schema.threat.behaviors import CapturedBehaviorEvent, BehaviorEventSource


_OPTIONAL_SENSOR_STRING_FIELDS = (
    "source_ip",
    "destination_ip",
    "protocol",
    "process_name",
    "command_line",
    "file_path",
    "username",
    "service_name",
    "summary",
    "raw_reference",
    "network_session_id",
    "sensor_bundle_hash",
    "sensor_previous_hash",
)
_OPTIONAL_SENSOR_INTEGER_FIELDS = (
    "source_port",
    "destination_port",
    "process_id",
    "parent_process_id",
    "deception_artifact_id",
)


def behavior_event_hash(
    event: CapturedBehaviorEvent,
    previous_event_hash: str,
) -> str:
    payload = json.dumps(
        {
            "previous_event_hash": previous_event_hash,
            "event": event.model_dump(mode="json"),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def sensor_event_hash(event: CapturedBehaviorEvent, control_token: str) -> str:
    payload = event.model_dump(mode="json", exclude={"sensor_event_hash"})
    observed_at = event.observed_at.astimezone(timezone.utc)
    payload["observed_at"] = observed_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    for field_name in _OPTIONAL_SENSOR_STRING_FIELDS:
        if not payload.get(field_name):
            payload.pop(field_name, None)
    for field_name in _OPTIONAL_SENSOR_INTEGER_FIELDS:
        if payload.get(field_name) in {None, 0}:
            payload.pop(field_name, None)
    if not payload.get("attributes"):
        payload.pop("attributes", None)
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    canonical = (
        canonical
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )
    key = hashlib.sha256(f"v3il-sensor-hmac:{control_token}".encode("utf-8")).digest()
    return hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def captured_event_from_record(event: BehaviorEvent) -> CapturedBehaviorEvent:
    fields = set(CapturedBehaviorEvent.model_fields)
    return CapturedBehaviorEvent.model_validate(event.model_dump(include=fields))


async def require_behavior_event_integrity(
    session,
    events: list[BehaviorEvent],
) -> None:
    if not events:
        return
    requirements: dict[tuple[int, str], int] = {}
    requested_ids = {event.id for event in events if event.id is not None}
    for event in events:
        key = (event.environment_id, event.sensor_id)
        requirements[key] = max(requirements.get(key, 0), event.sequence)

    conditions = [
        and_(
            BehaviorEvent.environment_id == environment_id,
            BehaviorEvent.sensor_id == sensor_id,
            BehaviorEvent.sequence <= last_sequence,
        )
        for (environment_id, sensor_id), last_sequence in requirements.items()
    ]
    chain_rows = list((await session.exec(
        select(BehaviorEvent)
        .where(or_(*conditions))
        .order_by(
            BehaviorEvent.environment_id.asc(),
            BehaviorEvent.sensor_id.asc(),
            BehaviorEvent.sequence.asc(),
        )
    )).all())

    cursor_rows = list((await session.exec(
        select(BehaviorSensorCursor).where(or_(*[
            and_(
                BehaviorSensorCursor.environment_id == environment_id,
                BehaviorSensorCursor.sensor_id == sensor_id,
            )
            for environment_id, sensor_id in requirements
        ]))
    )).all())
    token_by_sensor = {
        (cursor.environment_id, cursor.sensor_id): cursor.verification_token
        for cursor in cursor_rows
    }

    rows_by_chain: dict[tuple[int, str], list[BehaviorEvent]] = {}
    for row in chain_rows:
        rows_by_chain.setdefault((row.environment_id, row.sensor_id), []).append(row)

    failures: list[str] = []
    verified_ids: set[int] = set()
    for key, last_sequence in requirements.items():
        rows = rows_by_chain.get(key, [])
        expected_sequence = 1
        previous_event_hash = ""
        previous_sensor_hash = ""
        for row in rows:
            if row.sequence != expected_sequence:
                failures.append(
                    f"sensor {row.sensor_id} chain expected sequence {expected_sequence}, received {row.sequence}"
                )
                break
            captured = captured_event_from_record(row)
            if row.previous_event_hash != previous_event_hash:
                failures.append(f"event {row.id} previous hash does not match its sensor predecessor")
                break
            expected_hash = behavior_event_hash(captured, previous_event_hash)
            if not hmac.compare_digest(row.event_hash, expected_hash):
                failures.append(f"event {row.id} content hash is invalid")
                break
            if row.source in {BehaviorEventSource.IMPORT, BehaviorEventSource.CONTROL_PLANE}:
                if row.sensor_previous_hash or row.sensor_event_hash:
                    failures.append(f"event {row.id} contains invalid sensor provenance")
                    break
            else:
                control_token = token_by_sensor.get((row.environment_id, row.sensor_id), "")
                if not control_token:
                    failures.append(f"event {row.id} sensor key is unavailable")
                    break
                if row.sensor_previous_hash != previous_sensor_hash:
                    failures.append(f"event {row.id} previous sensor HMAC does not match")
                    break
                expected_sensor_hash = sensor_event_hash(captured, control_token)
                if not hmac.compare_digest(row.sensor_event_hash, expected_sensor_hash):
                    failures.append(f"event {row.id} sensor HMAC is invalid")
                    break
                previous_sensor_hash = row.sensor_event_hash
            previous_event_hash = row.event_hash
            expected_sequence += 1
            if row.id is not None:
                verified_ids.add(row.id)
        if expected_sequence - 1 != last_sequence:
            failures.append(
                f"sensor {key[1]} chain is incomplete through sequence {last_sequence}"
            )

    missing_ids = sorted(requested_ids - verified_ids)
    if missing_ids:
        failures.append(f"requested events were not verified: {missing_ids[:20]}")
    if failures:
        raise ValueError(
            "behavior evidence integrity validation failed: "
            + "; ".join(failures[:20])
        )
