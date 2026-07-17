from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime

import httpx
from sqlmodel import select

from database import get_async_session
from logger import get_logger
from model.detection.rules import (
    DetectionBundle,
    DetectionRule,
    DetectionRuleChangeRequest,
    DetectionRuleDeployment,
    ManagedHostSensor,
)
from schema.detection.rules import (
    DetectionRuleChangeAction,
    DetectionRuleChangeStatus,
    DetectionRuleDeploymentStatus,
    ManagedHostSensorStatus,
)
from schema.threat.investigations import AuditActorType, AuditEventKind
from service.threat.audit import add_audit_event
from service.detection.coordination import detection_bundle_mutation_lock
from service.detection.proxy import DetectionProxyTarget, detection_proxy_headers, detection_proxy_url


logger = get_logger(__name__)

_HEALTH_OBSERVATION_SECONDS = 60
_HEALTH_POLL_SECONDS = 2
_tasks: dict[int, asyncio.Task[None]] = {}
_client: httpx.AsyncClient | None = None


@dataclass(frozen=True)
class _DeploymentTarget:
    sensor_row_id: int
    target_bundle_hash: str
    previous_bundle_hash: str
    proxy: DetectionProxyTarget
    bundle_content: dict | None = None


def schedule_detection_deployment(change_request_id: int) -> None:
    running = _tasks.get(change_request_id)
    if running is not None and not running.done():
        return
    task = asyncio.create_task(
        _deploy_change(change_request_id),
        name=f"detection-deployment-{change_request_id}",
    )
    _tasks[change_request_id] = task
    task.add_done_callback(lambda completed: _deployment_finished(change_request_id, completed))


async def recover_detection_deployments() -> int:
    async with get_async_session() as session:
        ids = list((await session.exec(select(DetectionRuleChangeRequest.id).where(
            DetectionRuleChangeRequest.status == DetectionRuleChangeStatus.DEPLOYING,
        ))).all())
    for change_id in ids:
        schedule_detection_deployment(change_id)
    return len(ids)


async def stop_detection_deployments() -> None:
    global _client
    tasks = list(_tasks.values())
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    _tasks.clear()
    if _client is not None:
        await _client.aclose()
        _client = None


async def _deploy_change(change_id: int) -> None:
    async with detection_bundle_mutation_lock():
        await _deploy_change_locked(change_id)


async def _deploy_change_locked(change_id: int) -> None:
    deployments = await _load_deployments(change_id)
    if not deployments:
        if await _all_deployments_active(change_id):
            await _activate_change(change_id)
            return
        rollback_errors = await _rollback_change_deployments(change_id)
        error = "approved change resumed from an incomplete deployment state"
        if rollback_errors:
            error = f"{error}; rollback failures: {'; '.join(rollback_errors)}"
        await _fail_change(change_id, error)
        return
    try:
        for deployment_id in deployments:
            await _deploy_sensor(deployment_id)
        await _activate_change(change_id)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.warning("detection deployment failed: change=%s error=%s", change_id, exc)
        rollback_errors = await _rollback_change_deployments(change_id)
        error = str(exc) or exc.__class__.__name__
        if rollback_errors:
            error = f"{error}; rollback failures: {'; '.join(rollback_errors)}"
        await _fail_change(change_id, error)


async def _load_deployments(change_id: int) -> list[int]:
    async with get_async_session() as session:
        return list((await session.exec(select(DetectionRuleDeployment.id).where(
            DetectionRuleDeployment.change_request_id == change_id,
            DetectionRuleDeployment.status.in_({
                DetectionRuleDeploymentStatus.PENDING,
                DetectionRuleDeploymentStatus.DEPLOYING,
                DetectionRuleDeploymentStatus.HEALTH_CHECK,
            }),
        ).order_by(DetectionRuleDeployment.id.asc()))).all())


async def _all_deployments_active(change_id: int) -> bool:
    async with get_async_session() as session:
        rows = list((await session.exec(select(DetectionRuleDeployment.status).where(
            DetectionRuleDeployment.change_request_id == change_id,
        ))).all())
    return bool(rows) and all(status == DetectionRuleDeploymentStatus.ACTIVE for status in rows)


async def _deploy_sensor(deployment_id: int) -> None:
    target = await _claim_deployment_target(deployment_id)
    if target.bundle_content is None:
        raise RuntimeError("deployment immutable bundle content is unavailable")

    client = _http_client()
    headers = detection_proxy_headers(target.proxy)
    response = await client.put(
        detection_proxy_url(target.proxy, f"/v1/bundles/{target.target_bundle_hash}"),
        json=target.bundle_content,
        headers=headers,
        timeout=45,
    )
    response.raise_for_status()
    response = await client.post(
        detection_proxy_url(target.proxy, f"/v1/bundles/{target.target_bundle_hash}/activate"),
        headers=headers,
    )
    response.raise_for_status()

    async with get_async_session() as session, session.begin():
        deployment = await session.get(DetectionRuleDeployment, deployment_id)
        if deployment is None:
            raise RuntimeError("deployment disappeared during activation")
        deployment.status = DetectionRuleDeploymentStatus.HEALTH_CHECK
        session.add(deployment)

    loop = asyncio.get_running_loop()
    deadline = loop.time() + _HEALTH_OBSERVATION_SECONDS
    while True:
        response = await client.get(detection_proxy_url(target.proxy, "/v1/health"), headers=headers)
        response.raise_for_status()
        payload = response.json()
        if payload.get("sensor_id") != target.proxy.sensor_id:
            raise RuntimeError("Zeek Adapter sensor identity mismatch during deployment")
        if payload.get("status") not in {"healthy", "ok"}:
            raise RuntimeError(str(payload.get("error") or "Zeek sensor health check failed"))
        if payload.get("active_bundle_hash") != target.target_bundle_hash:
            raise RuntimeError("Zeek sensor reported an unexpected active bundle")
        if loop.time() >= deadline:
            break
        await asyncio.sleep(min(_HEALTH_POLL_SECONDS, max(deadline - loop.time(), 0)))

    async with get_async_session() as session, session.begin():
        deployment = await session.get(DetectionRuleDeployment, deployment_id)
        sensor = await session.get(ManagedHostSensor, target.sensor_row_id)
        if deployment is None or sensor is None:
            raise RuntimeError("deployment state is unavailable after health check")
        now = datetime.now()
        deployment.status = DetectionRuleDeploymentStatus.ACTIVE
        deployment.health_checked_at = now
        deployment.resolved_at = now
        sensor.active_bundle_hash = target.target_bundle_hash
        sensor.desired_bundle_hash = target.target_bundle_hash
        sensor.status = ManagedHostSensorStatus.HEALTHY
        sensor.last_heartbeat_at = now
        sensor.last_error = ""
        sensor.updated_at = now
        session.add(deployment)
        session.add(sensor)


async def _claim_deployment_target(deployment_id: int) -> _DeploymentTarget:
    async with get_async_session() as session, session.begin():
        deployment = (await session.exec(select(DetectionRuleDeployment).where(
            DetectionRuleDeployment.id == deployment_id,
        ).with_for_update())).one()
        sensor = await session.get(ManagedHostSensor, deployment.sensor_id)
        bundle = await session.get(DetectionBundle, deployment.target_bundle_hash)
        if sensor is None or sensor.id is None or bundle is None:
            raise RuntimeError("deployment sensor or immutable bundle is unavailable")
        deployment.status = DetectionRuleDeploymentStatus.DEPLOYING
        deployment.started_at = deployment.started_at or datetime.now()
        session.add(deployment)
        return _DeploymentTarget(
            sensor_row_id=sensor.id,
            target_bundle_hash=deployment.target_bundle_hash,
            previous_bundle_hash=deployment.previous_bundle_hash,
            proxy=DetectionProxyTarget(
                sensor_id=sensor.sensor_id,
                proxy_url=sensor.proxy_url,
                proxy_token=sensor.proxy_token,
            ),
            bundle_content=deepcopy(bundle.content),
        )


async def _rollback_change_deployments(change_id: int) -> list[str]:
    async with get_async_session() as session:
        deployment_ids = list((await session.exec(select(DetectionRuleDeployment.id).where(
            DetectionRuleDeployment.change_request_id == change_id,
            DetectionRuleDeployment.status.in_({
                DetectionRuleDeploymentStatus.DEPLOYING,
                DetectionRuleDeploymentStatus.HEALTH_CHECK,
                DetectionRuleDeploymentStatus.ACTIVE,
            }),
        ).order_by(DetectionRuleDeployment.id.asc()))).all())
    return await _rollback_deployments(deployment_ids)


async def _rollback_deployments(deployment_ids: list[int]) -> list[str]:
    errors: list[str] = []
    for deployment_id in reversed(deployment_ids):
        try:
            target = await _load_rollback_target(deployment_id)
            if target is None:
                continue
            headers = detection_proxy_headers(target.proxy)
            response = await _http_client().post(
                detection_proxy_url(target.proxy, "/v1/bundles/rollback"),
                json={"bundle_hash": target.previous_bundle_hash},
                headers=headers,
            )
            response.raise_for_status()
            await _wait_for_active_bundle(target.proxy, target.previous_bundle_hash, timeout_seconds=30)
            async with get_async_session() as session, session.begin():
                current = await session.get(DetectionRuleDeployment, deployment_id)
                current_sensor = await session.get(ManagedHostSensor, target.sensor_row_id)
                if current is not None:
                    current.status = DetectionRuleDeploymentStatus.ROLLED_BACK
                    current.resolved_at = datetime.now()
                    session.add(current)
                if current_sensor is not None:
                    current_sensor.active_bundle_hash = target.previous_bundle_hash
                    current_sensor.desired_bundle_hash = target.previous_bundle_hash
                    current_sensor.status = ManagedHostSensorStatus.HEALTHY
                    current_sensor.last_error = ""
                    current_sensor.last_heartbeat_at = datetime.now()
                    session.add(current_sensor)
        except Exception as exc:
            error = str(exc) or exc.__class__.__name__
            errors.append(f"deployment {deployment_id}: {error}")
            logger.exception("detection deployment rollback failed: deployment=%s", deployment_id)
            async with get_async_session() as session, session.begin():
                current = await session.get(DetectionRuleDeployment, deployment_id)
                current_sensor = await session.get(ManagedHostSensor, current.sensor_id) if current else None
                if current is not None:
                    current.status = DetectionRuleDeploymentStatus.ROLLBACK_FAILED
                    current.error = error
                    current.resolved_at = datetime.now()
                    session.add(current)
                if current_sensor is not None:
                    current_sensor.status = ManagedHostSensorStatus.DEGRADED
                    current_sensor.last_error = f"Detection rollback failed: {error}"
                    current_sensor.updated_at = datetime.now()
                    session.add(current_sensor)
    return errors


async def _load_rollback_target(deployment_id: int) -> _DeploymentTarget | None:
    async with get_async_session() as session:
        row = (await session.exec(
            select(DetectionRuleDeployment, ManagedHostSensor)
            .join(ManagedHostSensor, ManagedHostSensor.id == DetectionRuleDeployment.sensor_id)
            .where(DetectionRuleDeployment.id == deployment_id)
        )).first()
        if row is None:
            return None
        deployment, sensor = row
        if sensor.id is None:
            return None
        return _DeploymentTarget(
            sensor_row_id=sensor.id,
            target_bundle_hash=deployment.target_bundle_hash,
            previous_bundle_hash=deployment.previous_bundle_hash,
            proxy=DetectionProxyTarget(
                sensor_id=sensor.sensor_id,
                proxy_url=sensor.proxy_url,
                proxy_token=sensor.proxy_token,
            ),
        )


async def _wait_for_active_bundle(
    sensor: DetectionProxyTarget,
    bundle_hash: str,
    *,
    timeout_seconds: int,
) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_seconds
    headers = detection_proxy_headers(sensor)
    while True:
        response = await _http_client().get(detection_proxy_url(sensor, "/v1/health"), headers=headers)
        response.raise_for_status()
        payload = response.json()
        if payload.get("sensor_id") != sensor.sensor_id:
            raise RuntimeError("Zeek Adapter sensor identity mismatch during rollback")
        if payload.get("status") in {"healthy", "ok"} and payload.get("active_bundle_hash") == bundle_hash:
            return
        if loop.time() >= deadline:
            raise RuntimeError(str(payload.get("error") or "Zeek rollback health confirmation timed out"))
        await asyncio.sleep(min(_HEALTH_POLL_SECONDS, max(deadline - loop.time(), 0)))


async def _activate_change(change_id: int) -> None:
    async with get_async_session() as session, session.begin():
        change = (await session.exec(select(DetectionRuleChangeRequest).where(
            DetectionRuleChangeRequest.id == change_id,
        ).with_for_update())).one_or_none()
        if change is None or change.status != DetectionRuleChangeStatus.DEPLOYING:
            return
        rule = (await session.exec(select(DetectionRule).where(
            DetectionRule.id == change.rule_id,
        ).with_for_update())).one()
        if change.action == DetectionRuleChangeAction.DISABLE:
            rule.active_version_id = None
        else:
            rule.active_version_id = change.rule_version_id
        rule.updated_at = datetime.now()
        change.status = DetectionRuleChangeStatus.ACTIVE
        change.resolved_at = datetime.now()
        previous = list((await session.exec(select(DetectionRuleChangeRequest).where(
            DetectionRuleChangeRequest.rule_id == rule.id,
            DetectionRuleChangeRequest.id != change.id,
            DetectionRuleChangeRequest.status == DetectionRuleChangeStatus.ACTIVE,
        ).with_for_update())).all())
        for item in previous:
            item.status = DetectionRuleChangeStatus.SUPERSEDED
            item.resolved_at = datetime.now()
            session.add(item)
        session.add(rule)
        session.add(change)
        await add_audit_event(
            session,
            detection_rule_id=rule.id,
            environment_id=rule.environment_id,
            kind=AuditEventKind.DETECTION,
            actor_type=AuditActorType.SYSTEM,
            actor_code="system",
            object_type="detection_rule_change",
            object_id=change.id,
            summary="Detection rule deployment activated.",
            details={"action": change.action.value, "bundle_hash": change.effective_bundle_hash},
        )


async def _fail_change(change_id: int, error: str) -> None:
    async with get_async_session() as session, session.begin():
        change = (await session.exec(select(DetectionRuleChangeRequest).where(
            DetectionRuleChangeRequest.id == change_id,
        ).with_for_update())).one_or_none()
        if change is None:
            return
        change.status = DetectionRuleChangeStatus.FAILED
        change.resolved_at = datetime.now()
        session.add(change)
        deployments = list((await session.exec(select(DetectionRuleDeployment).where(
            DetectionRuleDeployment.change_request_id == change_id,
            DetectionRuleDeployment.status.notin_({
                DetectionRuleDeploymentStatus.ACTIVE,
                DetectionRuleDeploymentStatus.ROLLED_BACK,
                DetectionRuleDeploymentStatus.ROLLBACK_FAILED,
            }),
        ))).all())
        for deployment in deployments:
            deployment.status = DetectionRuleDeploymentStatus.FAILED
            deployment.error = error
            deployment.resolved_at = datetime.now()
            session.add(deployment)
            sensor = await session.get(ManagedHostSensor, deployment.sensor_id)
            if sensor is not None:
                sensor.status = ManagedHostSensorStatus.DEGRADED
                sensor.last_error = error
                sensor.desired_bundle_hash = sensor.active_bundle_hash
                session.add(sensor)
        rule = await session.get(DetectionRule, change.rule_id)
        if rule is not None:
            await add_audit_event(
                session,
                detection_rule_id=rule.id,
                environment_id=rule.environment_id,
                kind=AuditEventKind.DETECTION,
                actor_type=AuditActorType.SYSTEM,
                actor_code="system",
                object_type="detection_rule_change",
                object_id=change.id,
                summary="Detection rule deployment failed; previous bundles retained.",
                details={"error": error},
            )


def _http_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=httpx.Timeout(15, connect=5), trust_env=False)
    return _client


def _deployment_finished(change_id: int, task: asyncio.Task[None]) -> None:
    _tasks.pop(change_id, None)
    if task.cancelled():
        return
    try:
        task.result()
    except Exception:
        logger.exception("detection deployment task crashed: change=%s", change_id)
