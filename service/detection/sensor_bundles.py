from __future__ import annotations

import asyncio
from datetime import datetime

import httpx
from sqlmodel import select

from database import get_async_session
from logger import get_logger
from model.detection.rules import DetectionBundle, ManagedHostSensor
from schema.detection.rules import ManagedHostSensorStatus
from service.detection.coordination import detection_bundle_mutation_lock
from service.detection.proxy import DetectionProxyTarget, detection_proxy_headers, detection_proxy_url
from service.detection.bundles import current_sensor_bundle


logger = get_logger(__name__)
_tasks: dict[int, asyncio.Task[None]] = {}


def schedule_sensor_bundle_refresh(host_id: int) -> None:
    task = _tasks.get(host_id)
    if task is not None and not task.done():
        return
    task = asyncio.create_task(_refresh(host_id), name=f"sensor-bundle-refresh-{host_id}")
    _tasks[host_id] = task
    task.add_done_callback(lambda completed: _finished(host_id, completed))


async def schedule_all_sensor_bundle_refreshes() -> int:
    async with get_async_session() as session:
        host_ids = list((await session.exec(select(ManagedHostSensor.host_id))).all())
    for host_id in host_ids:
        schedule_sensor_bundle_refresh(host_id)
    return len(host_ids)


async def stop_sensor_bundle_refreshes() -> None:
    tasks = list(_tasks.values())
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    _tasks.clear()


async def _refresh(host_id: int) -> None:
    async with detection_bundle_mutation_lock():
        await _refresh_locked(host_id)


async def _refresh_locked(host_id: int) -> None:
    async with get_async_session() as session, session.begin():
        sensor = (await session.exec(select(ManagedHostSensor).where(
            ManagedHostSensor.host_id == host_id,
        ).with_for_update())).one_or_none()
        if sensor is None:
            return
        bundle = await current_sensor_bundle(session, sensor)
        bundle_hash = bundle["bundle_hash"]
        if await session.get(DetectionBundle, bundle_hash) is None:
            session.add(DetectionBundle(bundle_hash=bundle_hash, content=bundle))
        sensor.desired_bundle_hash = bundle_hash
        session.add(sensor)
        sensor_id = sensor.id
        if sensor_id is None:
            raise RuntimeError("managed host sensor id was not generated")
        previous_bundle_hash = sensor.active_bundle_hash
        proxy = DetectionProxyTarget(
            sensor_id=sensor.sensor_id,
            proxy_url=sensor.proxy_url,
            proxy_token=sensor.proxy_token,
        )
        headers = detection_proxy_headers(proxy)
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15, connect=5), trust_env=False) as client:
            response = await client.put(
                detection_proxy_url(proxy, f"/v1/bundles/{bundle_hash}"),
                json=bundle,
                headers=headers,
                timeout=45,
            )
            response.raise_for_status()
            response = await client.post(
                detection_proxy_url(proxy, f"/v1/bundles/{bundle_hash}/activate"),
                headers=headers,
            )
            response.raise_for_status()
            loop = asyncio.get_running_loop()
            deadline = loop.time() + 30
            while True:
                response = await client.get(
                    detection_proxy_url(proxy, "/v1/health"),
                    headers=headers,
                )
                response.raise_for_status()
                health = response.json()
                if health.get("sensor_id") != proxy.sensor_id:
                    raise RuntimeError("Zeek Adapter sensor identity mismatch during Bundle refresh")
                if health.get("status") in {"healthy", "ok"} and health.get("active_bundle_hash") == bundle_hash:
                    break
                if loop.time() >= deadline:
                    raise RuntimeError(str(health.get("error") or "Sensor Bundle refresh health confirmation timed out"))
                await asyncio.sleep(min(2, max(deadline - loop.time(), 0)))
        async with get_async_session() as session, session.begin():
            current = await session.get(ManagedHostSensor, sensor_id)
            if current is not None:
                now = datetime.now()
                current.active_bundle_hash = bundle_hash
                current.desired_bundle_hash = bundle_hash
                current.status = ManagedHostSensorStatus.HEALTHY
                current.last_error = ""
                current.last_heartbeat_at = now
                current.updated_at = now
                session.add(current)
    except Exception as exc:
        rollback_error = ""
        try:
            await _rollback_refresh(proxy, previous_bundle_hash)
        except Exception as rollback_exc:
            rollback_error = str(rollback_exc) or rollback_exc.__class__.__name__
        async with get_async_session() as session, session.begin():
            current = await session.get(ManagedHostSensor, sensor_id)
            if current is not None:
                current.status = ManagedHostSensorStatus.DEGRADED
                error = str(exc) or exc.__class__.__name__
                if rollback_error:
                    error = f"{error}; rollback failed: {rollback_error}"
                else:
                    current.active_bundle_hash = previous_bundle_hash
                    current.desired_bundle_hash = previous_bundle_hash
                    current.last_heartbeat_at = datetime.now()
                current.last_error = error[:4000]
                current.updated_at = datetime.now()
                session.add(current)
        raise


async def _rollback_refresh(sensor: DetectionProxyTarget, bundle_hash: str) -> None:
    headers = detection_proxy_headers(sensor)
    async with httpx.AsyncClient(timeout=httpx.Timeout(15, connect=5), trust_env=False) as client:
        response = await client.post(
            detection_proxy_url(sensor, "/v1/bundles/rollback"),
            json={"bundle_hash": bundle_hash},
            headers=headers,
        )
        response.raise_for_status()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 30
        while True:
            response = await client.get(detection_proxy_url(sensor, "/v1/health"), headers=headers)
            response.raise_for_status()
            health = response.json()
            if health.get("sensor_id") != sensor.sensor_id:
                raise RuntimeError("Zeek Adapter sensor identity mismatch during Bundle refresh rollback")
            if health.get("status") in {"healthy", "ok"} and health.get("active_bundle_hash") == bundle_hash:
                return
            if loop.time() >= deadline:
                raise RuntimeError(str(health.get("error") or "Sensor Bundle refresh rollback timed out"))
            await asyncio.sleep(min(2, max(deadline - loop.time(), 0)))


def _finished(host_id: int, task: asyncio.Task[None]) -> None:
    _tasks.pop(host_id, None)
    if task.cancelled():
        return
    try:
        task.result()
    except Exception:
        logger.exception("Sensor operational Bundle refresh failed: host=%s", host_id)
