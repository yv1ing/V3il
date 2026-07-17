import json as json_module
from datetime import datetime

import httpx
from pydantic import BaseModel, ConfigDict, Field

from schema.deception.workloads import (
    CreateObservedWorkloadRequest,
    ListObservedWorkloadsResponse,
    ObservedWorkloadSchema,
)
from schema.threat.behaviors import CapturedBehaviorEvent
from service.sandbox.control_proxy import (
    resolve_sandbox_control_proxy_target,
    sandbox_control_proxy_token_headers,
)


_http_client: httpx.AsyncClient | None = None


class TelemetryEventBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sensor_id: str = Field(min_length=1, max_length=128)
    events: list[CapturedBehaviorEvent] = Field(max_length=1000)


class TelemetryObserverHealth(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    status: str
    message: str = ""
    started_at: datetime
    updated_at: datetime


class TelemetryHealth(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sensor_id: str
    sequence: int = Field(ge=0)
    journal: str
    last_error: str = ""
    observers: list[TelemetryObserverHealth]


def _get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(timeout=httpx.Timeout(30.0), trust_env=False)
    return _http_client


async def close_observer_http_client() -> None:
    global _http_client
    if _http_client is not None:
        await _http_client.aclose()
        _http_client = None


async def start_observed_workload(
    container_id: int,
    request: CreateObservedWorkloadRequest,
) -> ObservedWorkloadSchema:
    payload = await _request_json(
        container_id,
        "POST",
        "/observed-workloads",
        json={
            **request.model_dump(mode="json", exclude={"environment"}),
            "environment": {item.name: item.value for item in request.environment},
        },
    )
    return ObservedWorkloadSchema.model_validate(payload)


async def list_observed_workloads(container_id: int) -> ListObservedWorkloadsResponse:
    payload = await _request_json(container_id, "GET", "/observed-workloads")
    return ListObservedWorkloadsResponse.model_validate(payload)


async def stop_observed_workload(container_id: int, run_id: str) -> ObservedWorkloadSchema:
    payload = await _request_json(
        container_id,
        "POST",
        "/observed-workloads/stop",
        params={"run_id": run_id},
    )
    return ObservedWorkloadSchema.model_validate(payload)


async def pull_container_behavior_events(
    container_id: int,
    *,
    after: int,
    limit: int,
) -> TelemetryEventBatch:
    payload = await _request_json(
        container_id,
        "GET",
        "/telemetry/events",
        params={"after": str(after), "limit": str(limit)},
    )
    return TelemetryEventBatch.model_validate(payload)


async def pull_container_behavior_health(container_id: int) -> TelemetryHealth:
    payload = await _request_json(container_id, "GET", "/telemetry/health")
    return TelemetryHealth.model_validate(payload)


async def _request_json(
    container_id: int,
    method: str,
    path: str,
    *,
    params: dict[str, str] | None = None,
    json: dict | None = None,
) -> dict:
    target = await resolve_sandbox_control_proxy_target(container_id, require_running=True)
    if target is None:
        raise FileNotFoundError("sandbox container is not running")
    response = await _get_http_client().request(
        method,
        f"{target.base_url}{path}",
        params=params,
        json=json,
        headers=sandbox_control_proxy_token_headers(target),
    )
    if response.status_code == 404:
        raise FileNotFoundError("observed workload not found")
    if response.status_code == 400:
        raise ValueError(response.text or "sandbox observer rejected the request")
    if response.status_code >= 400:
        raise RuntimeError(response.text or "sandbox observer request failed")
    try:
        payload = response.json()
    except json_module.JSONDecodeError as exc:
        raise RuntimeError("invalid sandbox observer response") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("invalid sandbox observer response")
    return payload
