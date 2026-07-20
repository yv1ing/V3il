from __future__ import annotations

import asyncio

import httpx
from sqlmodel import select

from database import get_async_session
from logger import get_logger
from model.detection.rules import DetectionBundle, ManagedHostSensor
from schema.detection.rules import ManagedHostSensorStatus
from service.detection.bundles import current_sensor_bundle
from service.detection.health import observe_sensor_bundle, request_with_lease
from service.detection.leases import detection_mutation_lease
from service.detection.proxy import DetectionProxyTarget, detection_proxy_headers, detection_proxy_url
from service.runtime.leases import RuntimeLeaseHandle, RuntimeLeaseLost
from utils.time import utc_now


logger = get_logger(__name__)
_RECONCILE_SECONDS = 5
_tasks: dict[int, asyncio.Task[None]] = {}
_reconcile_task: asyncio.Task[None] | None = None


def schedule_sensor_bundle_refresh(host_id: int) -> None:
    task = _tasks.get(host_id)
    if task is not None and not task.done():
        return
    task = asyncio.create_task(_refresh(host_id), name=f"sensor-bundle-refresh-{host_id}")
    _tasks[host_id] = task
    task.add_done_callback(lambda completed: _finished(host_id, completed))


async def start_sensor_bundle_refresh_runtime() -> int:
    global _reconcile_task
    recovered = await _schedule_all_sensor_bundle_refreshes()
    if _reconcile_task is None or _reconcile_task.done():
        _reconcile_task = asyncio.create_task(
            _reconcile_sensor_bundles(),
            name="sensor-bundle-reconciler",
        )
    return recovered


async def _schedule_all_sensor_bundle_refreshes() -> int:
    async with get_async_session() as session:
        host_ids = list((await session.exec(select(ManagedHostSensor.host_id))).all())
    for host_id in host_ids:
        schedule_sensor_bundle_refresh(host_id)
    return len(host_ids)


async def stop_sensor_bundle_refreshes() -> None:
    global _reconcile_task
    if _reconcile_task is not None:
        _reconcile_task.cancel()
        await asyncio.gather(_reconcile_task, return_exceptions=True)
        _reconcile_task = None
    tasks = list(_tasks.values())
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    _tasks.clear()


async def _reconcile_sensor_bundles() -> None:
    while True:
        try:
            await _schedule_all_sensor_bundle_refreshes()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("sensor bundle reconciliation failed")
        await asyncio.sleep(_RECONCILE_SECONDS)


async def _refresh(host_id: int) -> None:
    while True:
        try:
            async with detection_mutation_lease() as lease:
                await _refresh_owned(host_id, lease)
                return
        except RuntimeLeaseLost:
            logger.info("sensor bundle refresh yielded after lease loss: host=%s", host_id)
            await asyncio.sleep(0.5)


async def _refresh_owned(host_id: int, lease: RuntimeLeaseHandle) -> None:
    async with get_async_session() as session, session.begin():
        await lease.assert_owned(session, lock=True)
        sensor = (await session.exec(
            select(ManagedHostSensor)
            .where(ManagedHostSensor.host_id == host_id)
            .with_for_update()
        )).one_or_none()
        if sensor is None:
            return
        bundle = await current_sensor_bundle(session, sensor)
        bundle_hash = bundle["bundle_hash"]
        if await session.get(DetectionBundle, bundle_hash) is None:
            session.add(DetectionBundle(bundle_hash=bundle_hash, content=bundle))
        sensor.desired_bundle_hash = bundle_hash
        sensor.updated_at = utc_now()
        session.add(sensor)
        sensor_id = sensor.id
        if sensor_id is None:
            raise RuntimeError("managed host sensor id was not generated")
        previous_bundle_hash = sensor.active_bundle_hash
        if (
            sensor.active_bundle_hash == bundle_hash
            and sensor.status == ManagedHostSensorStatus.HEALTHY
        ):
            return
        proxy = DetectionProxyTarget(
            sensor_id=sensor.sensor_id,
            proxy_url=sensor.proxy_url,
            proxy_token=sensor.proxy_token,
        )
        headers = detection_proxy_headers(proxy)
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15, connect=5), trust_env=False) as client:
            await request_with_lease(
                client,
                lease,
                "PUT",
                detection_proxy_url(proxy, f"/v1/bundles/{bundle_hash}"),
                json=bundle,
                headers=headers,
                timeout=45,
            )
            await request_with_lease(
                client,
                lease,
                "POST",
                detection_proxy_url(proxy, f"/v1/bundles/{bundle_hash}/activate"),
                headers=headers,
            )
            health = await observe_sensor_bundle(
                client,
                proxy,
                bundle_hash,
                lease,
                observation_seconds=0,
                timeout_seconds=30,
            )
        async with get_async_session() as session, session.begin():
            await lease.assert_owned(session, lock=True)
            current = (await session.exec(
                select(ManagedHostSensor)
                .where(ManagedHostSensor.id == sensor_id)
                .with_for_update()
            )).one_or_none()
            if current is None:
                return
            now = utc_now()
            current.active_bundle_hash = health.active_bundle_hash
            current.desired_bundle_hash = health.desired_bundle_hash
            current.status = ManagedHostSensorStatus.HEALTHY
            current.last_sequence = health.sequence
            current.last_error = ""
            current.last_heartbeat_at = health.observed_at
            current.updated_at = now
            session.add(current)
    except RuntimeLeaseLost:
        raise
    except Exception as exc:
        rollback_health = None
        rollback_error = ""
        try:
            rollback_health = await _rollback_refresh(proxy, previous_bundle_hash, lease)
        except RuntimeLeaseLost:
            raise
        except Exception as rollback_exc:
            rollback_error = _error_text(rollback_exc)
        async with get_async_session() as session, session.begin():
            await lease.assert_owned(session, lock=True)
            current = (await session.exec(
                select(ManagedHostSensor)
                .where(ManagedHostSensor.id == sensor_id)
                .with_for_update()
            )).one_or_none()
            if current is None:
                raise
            now = utc_now()
            error = _error_text(exc)
            if rollback_error:
                current.status = ManagedHostSensorStatus.DEGRADED
                error = f"{error}; rollback failed: {rollback_error}"
            elif rollback_health is not None:
                current.active_bundle_hash = rollback_health.active_bundle_hash
                current.desired_bundle_hash = bundle_hash
                current.status = ManagedHostSensorStatus.DEGRADED
                current.last_sequence = rollback_health.sequence
                current.last_heartbeat_at = rollback_health.observed_at
            current.last_error = error[:4000]
            current.updated_at = now
            session.add(current)
        raise


async def _rollback_refresh(
    sensor: DetectionProxyTarget,
    bundle_hash: str,
    lease: RuntimeLeaseHandle,
):
    headers = detection_proxy_headers(sensor)
    async with httpx.AsyncClient(timeout=httpx.Timeout(15, connect=5), trust_env=False) as client:
        await request_with_lease(
            client,
            lease,
            "POST",
            detection_proxy_url(sensor, "/v1/bundles/rollback"),
            json={"bundle_hash": bundle_hash},
            headers=headers,
        )
        return await observe_sensor_bundle(
            client,
            sensor,
            bundle_hash,
            lease,
            observation_seconds=0,
            timeout_seconds=30,
        )


def _finished(host_id: int, task: asyncio.Task[None]) -> None:
    if _tasks.get(host_id) is task:
        _tasks.pop(host_id, None)
    if task.cancelled():
        return
    try:
        task.result()
    except Exception:
        logger.exception("sensor operational bundle refresh failed: host=%s", host_id)


def _error_text(exc: BaseException) -> str:
    return (str(exc) or exc.__class__.__name__)[:4000]
