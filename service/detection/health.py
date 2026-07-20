from __future__ import annotations

import asyncio

import httpx

from schema.detection.rules import (
    DetectionSensorHealthSnapshot,
    DetectionSensorHealthStatus,
)
from service.detection.proxy import DetectionProxyTarget, detection_proxy_headers, detection_proxy_url
from service.runtime.leases import RuntimeLeaseHandle
from utils.time import utc_now


async def request_with_lease(
    client: httpx.AsyncClient,
    lease: RuntimeLeaseHandle,
    method: str,
    url: str,
    **kwargs,
) -> httpx.Response:
    await lease.assert_owned()
    response = await client.request(method, url, **kwargs)
    response.raise_for_status()
    await lease.assert_owned()
    return response


async def read_sensor_health(
    client: httpx.AsyncClient,
    sensor: DetectionProxyTarget,
    lease: RuntimeLeaseHandle,
) -> DetectionSensorHealthSnapshot:
    response = await request_with_lease(
        client,
        lease,
        "GET",
        detection_proxy_url(sensor, "/v1/health"),
        headers=detection_proxy_headers(sensor),
    )
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError("sensor health response must be a JSON object")
    health = DetectionSensorHealthSnapshot.model_validate({**payload, "observed_at": utc_now()})
    if health.sensor_id != sensor.sensor_id:
        raise RuntimeError("Zeek Adapter sensor identity mismatch")
    return health


async def observe_sensor_bundle(
    client: httpx.AsyncClient,
    sensor: DetectionProxyTarget,
    bundle_hash: str,
    lease: RuntimeLeaseHandle,
    *,
    observation_seconds: float,
    timeout_seconds: float | None = None,
    poll_seconds: float = 2,
) -> DetectionSensorHealthSnapshot:
    loop = asyncio.get_running_loop()
    started_at = loop.time()
    deadline = started_at + (timeout_seconds if timeout_seconds is not None else observation_seconds)
    while True:
        health = await read_sensor_health(client, sensor, lease)
        matches = (
            health.status == DetectionSensorHealthStatus.HEALTHY
            and health.active_bundle_hash == bundle_hash
            and health.desired_bundle_hash == bundle_hash
            and not health.error
        )
        if matches and loop.time() - started_at >= observation_seconds:
            return health
        if loop.time() >= deadline:
            raise RuntimeError(health.error or "sensor bundle health confirmation timed out")
        await asyncio.sleep(min(poll_seconds, max(deadline - loop.time(), 0)))
