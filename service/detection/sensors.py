from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass

import httpx
from sqlmodel import select

from utils.time import utc_now

from config import get_config
from database import get_async_session
from logger import get_logger
from model.deception.environments import DeceptionEnvironment
from model.detection.rules import DetectionBundle, ManagedHostSensor
from schema.detection.rules import ManagedHostSensorStatus
from schema.system_user.users import SystemUserRole
from schema.threat.behaviors import CapturedBehaviorEvent, IngestBehaviorEventBatchRequest
from service.threat.behaviors import ingest_behavior_event_batch
from service.threat.orchestration import orchestrate_behavior_events
from service.detection.proxy import DetectionProxyTarget, detection_proxy_headers, detection_proxy_url


logger = get_logger(__name__)

_runtime_task: asyncio.Task[None] | None = None
_stop_event = asyncio.Event()
_client: httpx.AsyncClient | None = None


@dataclass(frozen=True)
class _SensorTarget:
    id: int
    host_id: int
    proxy: DetectionProxyTarget
    active_bundle_hash: str
    desired_bundle_hash: str
    last_sequence: int


async def start_zeek_sensor_runtime() -> None:
    global _runtime_task
    if _runtime_task is not None and not _runtime_task.done():
        return
    _stop_event.clear()
    _runtime_task = asyncio.create_task(_sensor_loop(), name="zeek-sensor-runtime")
    logger.info("Zeek sensor collection runtime started")


async def stop_zeek_sensor_runtime() -> None:
    global _runtime_task, _client
    task, _runtime_task = _runtime_task, None
    if task is not None:
        _stop_event.set()
        await task
    if _client is not None:
        await _client.aclose()
        _client = None
    logger.info("Zeek sensor collection runtime stopped")


async def collect_zeek_sensor_events_once() -> None:
    async with get_async_session() as session:
        rows = list((await session.exec(select(
            ManagedHostSensor.id,
            ManagedHostSensor.host_id,
            ManagedHostSensor.sensor_id,
            ManagedHostSensor.proxy_url,
            ManagedHostSensor.proxy_token,
            ManagedHostSensor.active_bundle_hash,
            ManagedHostSensor.desired_bundle_hash,
            ManagedHostSensor.last_sequence,
        ).order_by(ManagedHostSensor.id.asc()))).all())
    targets = [
        _SensorTarget(
            id=sensor_id,
            host_id=host_id,
            proxy=DetectionProxyTarget(
                sensor_id=external_sensor_id,
                proxy_url=proxy_url,
                proxy_token=proxy_token,
            ),
            active_bundle_hash=active_bundle_hash,
            desired_bundle_hash=desired_bundle_hash,
            last_sequence=last_sequence,
        )
        for (
            sensor_id,
            host_id,
            external_sensor_id,
            proxy_url,
            proxy_token,
            active_bundle_hash,
            desired_bundle_hash,
            last_sequence,
        ) in rows
        if sensor_id is not None
    ]
    if not targets:
        return
    semaphore = asyncio.Semaphore(max(1, get_config().behavior_capture.concurrency))

    async def collect(target: _SensorTarget) -> None:
        async with semaphore:
            try:
                await _collect_sensor(target)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("Zeek sensor collection failed: sensor=%s error=%s", target.proxy.sensor_id, exc)
                await _mark_sensor_issue(target.id, str(exc) or exc.__class__.__name__)

    await asyncio.gather(*(collect(target) for target in targets))


async def _sensor_loop() -> None:
    while not _stop_event.is_set():
        try:
            await collect_zeek_sensor_events_once()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Zeek sensor collection cycle failed")
        try:
            await asyncio.wait_for(_stop_event.wait(), timeout=get_config().behavior_capture.poll_interval_seconds)
        except asyncio.TimeoutError:
            pass


async def _collect_sensor(target: _SensorTarget) -> None:
    headers = detection_proxy_headers(target.proxy)
    health_response = await _http_client().get(detection_proxy_url(target.proxy, "/v1/health"), headers=headers)
    health_response.raise_for_status()
    health = health_response.json()
    if health.get("sensor_id") != target.proxy.sensor_id:
        raise RuntimeError("Zeek Adapter sensor identity mismatch")
    active_bundle_hash = str(health.get("active_bundle_hash") or "")
    accepted_bundle_hashes = {target.active_bundle_hash, target.desired_bundle_hash}
    if active_bundle_hash not in accepted_bundle_hashes:
        raise RuntimeError("Zeek Adapter active Bundle Hash differs from the control plane")

    response = await _http_client().get(
        detection_proxy_url(target.proxy, "/v1/events"),
        params={"after": target.last_sequence, "limit": 500},
        headers=headers,
    )
    response.raise_for_status()
    payload = response.json()
    if payload.get("sensor_id") != target.proxy.sensor_id:
        raise RuntimeError("Zeek event stream sensor identity mismatch")
    raw_events = payload.get("events")
    if not isinstance(raw_events, list):
        raise RuntimeError("Zeek event stream is invalid")
    expected_journal_sequence = target.last_sequence + 1
    grouped: dict[tuple[int, str], list[CapturedBehaviorEvent]] = defaultdict(list)
    last_journal_sequence = target.last_sequence
    for raw in raw_events:
        if not isinstance(raw, dict):
            raise RuntimeError("Zeek event stream contains a non-object event")
        journal_sequence = int(raw.get("journal_sequence") or 0)
        if journal_sequence != expected_journal_sequence:
            raise RuntimeError(
                f"Zeek Adapter journal gap: expected {expected_journal_sequence}, received {journal_sequence}"
            )
        expected_journal_sequence += 1
        last_journal_sequence = journal_sequence
        environment_id = int(raw.get("environment_id") or 0)
        chain_sensor_id = str(raw.get("chain_sensor_id") or "")
        event_payload = raw.get("event")
        if environment_id <= 0 or not chain_sensor_id or not isinstance(event_payload, dict):
            raise RuntimeError("Zeek event is missing its environment chain binding")
        event = CapturedBehaviorEvent.model_validate(event_payload)
        if event.sensor_bundle_hash != active_bundle_hash:
            raise RuntimeError("Zeek event Bundle Hash does not match the Adapter active bundle")
        grouped[(environment_id, chain_sensor_id)].append(event)

    for (environment_id, chain_sensor_id), events in grouped.items():
        async with get_async_session() as session:
            environment = (await session.exec(select(
                DeceptionEnvironment.host_id,
                DeceptionEnvironment.owner_id,
            ).where(DeceptionEnvironment.id == environment_id))).first()
        if environment is None or environment[0] != target.host_id:
            raise RuntimeError("Zeek event references an environment outside the Managed Host")
        await _validate_event_bundle_bindings(target.proxy.sensor_id, environment_id, events)
        result = await ingest_behavior_event_batch(
            environment_id,
            IngestBehaviorEventBatchRequest(sensor_id=chain_sensor_id, events=events),
            user_id=environment[1],
            user_role=SystemUserRole.ADMIN,
            sensor_control_token=target.proxy.proxy_token,
        )
        if result.response is None:
            raise RuntimeError(result.message or "Zeek event ingestion was rejected")
        await orchestrate_behavior_events(environment_id, list(result.new_event_ids))

    async with get_async_session() as session, session.begin():
        current = (await session.exec(select(ManagedHostSensor).where(
            ManagedHostSensor.id == target.id,
        ).with_for_update())).one_or_none()
        if current is None:
            return
        current.last_sequence = last_journal_sequence
        current.active_bundle_hash = active_bundle_hash
        current.status = ManagedHostSensorStatus.HEALTHY
        current.last_error = ""
        current.last_heartbeat_at = utc_now()
        current.updated_at = utc_now()
        session.add(current)


async def _mark_sensor_issue(sensor_id: int, error: str) -> None:
    async with get_async_session() as session, session.begin():
        sensor = await session.get(ManagedHostSensor, sensor_id)
        if sensor is None:
            return
        sensor.status = ManagedHostSensorStatus.DEGRADED
        sensor.last_error = error[:4000]
        sensor.updated_at = utc_now()
        session.add(sensor)


def _http_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=httpx.Timeout(15, connect=5), trust_env=False)
    return _client


async def _validate_event_bundle_bindings(
    sensor_id: str,
    environment_id: int,
    events: list[CapturedBehaviorEvent],
) -> None:
    bundle_hashes = {event.sensor_bundle_hash for event in events}
    if "" in bundle_hashes:
        raise RuntimeError("Zeek event is missing its immutable Bundle Hash")
    async with get_async_session() as session:
        bundles = list((await session.exec(select(
            DetectionBundle.bundle_hash,
            DetectionBundle.content,
        ).where(
            DetectionBundle.bundle_hash.in_(bundle_hashes),
        ))).all())
    by_hash = {bundle_hash: content for bundle_hash, content in bundles}
    if set(by_hash) != bundle_hashes:
        raise RuntimeError("Zeek event references an unknown immutable Bundle")
    for event in events:
        content = by_hash[event.sensor_bundle_hash]
        if not isinstance(content, dict) or content.get("sensor_id") != sensor_id:
            raise RuntimeError("Zeek event Bundle belongs to a different Sensor")
        targets = content.get("targets")
        if not isinstance(targets, list) or not any(
            isinstance(target, dict)
            and target.get("environment_id") == environment_id
            and target.get("host_port") == event.destination_port
            and str(target.get("protocol") or "tcp").casefold() == event.protocol.casefold()
            for target in targets
        ):
            raise RuntimeError("Zeek event is outside its immutable Bundle capture scope")
