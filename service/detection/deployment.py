from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import dataclass

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
    DetectionSensorHealthSnapshot,
    DetectionSensorHealthStatus,
    ManagedHostSensorStatus,
)
from schema.threat.investigations import AuditActorType, AuditEventKind
from service.detection.health import observe_sensor_bundle, request_with_lease
from service.detection.leases import detection_mutation_lease
from service.detection.proxy import DetectionProxyTarget, detection_proxy_headers, detection_proxy_url
from service.runtime.leases import RuntimeLeaseHandle, RuntimeLeaseLost
from service.threat.audit import add_audit_event
from utils.time import utc_now


logger = get_logger(__name__)

_HEALTH_OBSERVATION_SECONDS = 60
_RECONCILE_SECONDS = 2
_tasks: dict[int, asyncio.Task[None]] = {}
_reconcile_task: asyncio.Task[None] | None = None
_client: httpx.AsyncClient | None = None


@dataclass(frozen=True)
class _DeploymentTarget:
    deployment_id: int
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


async def start_detection_deployment_runtime() -> int:
    global _reconcile_task
    recovered = await _schedule_deploying_changes()
    if _reconcile_task is None or _reconcile_task.done():
        _reconcile_task = asyncio.create_task(
            _reconcile_deployments(),
            name="detection-deployment-reconciler",
        )
    return recovered


async def _schedule_deploying_changes() -> int:
    async with get_async_session() as session:
        ids = list((await session.exec(
            select(DetectionRuleChangeRequest.id).where(
                DetectionRuleChangeRequest.status.in_({
                    DetectionRuleChangeStatus.DEPLOYING,
                    DetectionRuleChangeStatus.ROLLING_BACK,
                }),
            )
        )).all())
    for change_id in ids:
        schedule_detection_deployment(change_id)
    return len(ids)


async def stop_detection_deployments() -> None:
    global _client, _reconcile_task
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
    if _client is not None:
        await _client.aclose()
        _client = None


async def _reconcile_deployments() -> None:
    while True:
        try:
            await _schedule_deploying_changes()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("detection deployment reconciliation failed")
        await asyncio.sleep(_RECONCILE_SECONDS)


async def _deploy_change(change_id: int) -> None:
    while await _change_is_executable(change_id):
        try:
            async with detection_mutation_lease() as lease:
                await _deploy_change_owned(change_id, lease)
                return
        except RuntimeLeaseLost:
            logger.info("detection deployment yielded after lease loss: change=%s", change_id)
            await asyncio.sleep(0.5)


async def _deploy_change_owned(change_id: int, lease: RuntimeLeaseHandle) -> None:
    status = await _change_status(change_id, lease)
    if status == DetectionRuleChangeStatus.ROLLING_BACK:
        rollback_errors = await _rollback_change_deployments(change_id, lease)
        await _finish_change_rollback(change_id, rollback_errors, lease)
        return
    if status != DetectionRuleChangeStatus.DEPLOYING:
        return
    deployment_ids = await _load_incomplete_deployments(change_id, lease)
    if not deployment_ids:
        if await _all_deployments_active(change_id, lease):
            await _activate_change(change_id, lease)
            return
        await _begin_change_rollback(
            change_id,
            "deployment resumed without a complete set of verified sensor activations",
            lease,
        )
        rollback_errors = await _rollback_change_deployments(change_id, lease)
        await _finish_change_rollback(change_id, rollback_errors, lease)
        return
    try:
        for deployment_id in deployment_ids:
            try:
                await _deploy_sensor(deployment_id, lease)
            except RuntimeLeaseLost:
                raise
            except Exception as exc:
                await _record_deployment_error(deployment_id, _error_text(exc), lease)
                raise
        await _activate_change(change_id, lease)
    except asyncio.CancelledError:
        raise
    except RuntimeLeaseLost:
        raise
    except Exception as exc:
        logger.warning("detection deployment failed: change=%s error=%s", change_id, exc)
        error = _error_text(exc)
        await _begin_change_rollback(change_id, error, lease)
        rollback_errors = await _rollback_change_deployments(change_id, lease)
        await _finish_change_rollback(change_id, rollback_errors, lease)


async def _change_is_executable(change_id: int) -> bool:
    async with get_async_session() as session:
        status = (await session.exec(
            select(DetectionRuleChangeRequest.status).where(
                DetectionRuleChangeRequest.id == change_id,
            )
        )).one_or_none()
    return status in {
        DetectionRuleChangeStatus.DEPLOYING,
        DetectionRuleChangeStatus.ROLLING_BACK,
    }


async def _change_status(
    change_id: int,
    lease: RuntimeLeaseHandle,
) -> DetectionRuleChangeStatus | None:
    async with get_async_session() as session:
        await lease.assert_owned(session)
        return (await session.exec(select(DetectionRuleChangeRequest.status).where(
            DetectionRuleChangeRequest.id == change_id,
        ))).one_or_none()


async def _load_incomplete_deployments(
    change_id: int,
    lease: RuntimeLeaseHandle,
) -> list[int]:
    async with get_async_session() as session:
        await lease.assert_owned(session)
        return list((await session.exec(
            select(DetectionRuleDeployment.id)
            .where(
                DetectionRuleDeployment.change_request_id == change_id,
                DetectionRuleDeployment.status.in_({
                    DetectionRuleDeploymentStatus.PENDING,
                    DetectionRuleDeploymentStatus.DEPLOYING,
                    DetectionRuleDeploymentStatus.HEALTH_CHECK,
                }),
            )
            .order_by(DetectionRuleDeployment.id.asc())
        )).all())


async def _all_deployments_active(change_id: int, lease: RuntimeLeaseHandle) -> bool:
    async with get_async_session() as session:
        await lease.assert_owned(session)
        rows = list((await session.exec(
            select(DetectionRuleDeployment).where(
                DetectionRuleDeployment.change_request_id == change_id,
            )
        )).all())
    return bool(rows) and all(_deployment_is_verified_active(row) for row in rows)


async def _deploy_sensor(deployment_id: int, lease: RuntimeLeaseHandle) -> None:
    target = await _claim_deployment_target(deployment_id, lease)
    if target.bundle_content is None:
        raise RuntimeError("deployment immutable bundle content is unavailable")

    headers = detection_proxy_headers(target.proxy)
    await request_with_lease(
        _http_client(),
        lease,
        "PUT",
        detection_proxy_url(target.proxy, f"/v1/bundles/{target.target_bundle_hash}"),
        json=target.bundle_content,
        headers=headers,
        timeout=45,
    )
    await request_with_lease(
        _http_client(),
        lease,
        "POST",
        detection_proxy_url(target.proxy, f"/v1/bundles/{target.target_bundle_hash}/activate"),
        headers=headers,
    )
    await _mark_health_check(target, lease)
    health = await observe_sensor_bundle(
        _http_client(),
        target.proxy,
        target.target_bundle_hash,
        lease,
        observation_seconds=_HEALTH_OBSERVATION_SECONDS,
    )
    await _complete_activation(target, health, lease)


async def _claim_deployment_target(
    deployment_id: int,
    lease: RuntimeLeaseHandle,
) -> _DeploymentTarget:
    async with get_async_session() as session, session.begin():
        await lease.assert_owned(session, lock=True)
        deployment = (await session.exec(
            select(DetectionRuleDeployment)
            .where(DetectionRuleDeployment.id == deployment_id)
            .with_for_update()
        )).one()
        if deployment.status not in {
            DetectionRuleDeploymentStatus.PENDING,
            DetectionRuleDeploymentStatus.DEPLOYING,
            DetectionRuleDeploymentStatus.HEALTH_CHECK,
        }:
            raise RuntimeError("deployment is no longer executable")
        sensor = await session.get(ManagedHostSensor, deployment.sensor_id)
        bundle = await session.get(DetectionBundle, deployment.target_bundle_hash)
        if sensor is None or sensor.id is None or bundle is None:
            raise RuntimeError("deployment sensor or immutable bundle is unavailable")
        deployment.status = DetectionRuleDeploymentStatus.DEPLOYING
        deployment.runtime_owner_id = lease.owner_id
        deployment.lease_fencing_token = lease.fencing_token
        deployment.observed_bundle_hash = ""
        deployment.health_snapshot = None
        deployment.rollback_observed_bundle_hash = ""
        deployment.rollback_health_snapshot = None
        deployment.started_at = deployment.started_at or utc_now()
        session.add(deployment)
        return _DeploymentTarget(
            deployment_id=deployment_id,
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


async def _mark_health_check(target: _DeploymentTarget, lease: RuntimeLeaseHandle) -> None:
    async with get_async_session() as session, session.begin():
        await lease.assert_owned(session, lock=True)
        deployment = await _lock_owned_deployment(session, target.deployment_id, lease)
        deployment.status = DetectionRuleDeploymentStatus.HEALTH_CHECK
        session.add(deployment)


async def _complete_activation(
    target: _DeploymentTarget,
    health: DetectionSensorHealthSnapshot,
    lease: RuntimeLeaseHandle,
) -> None:
    async with get_async_session() as session, session.begin():
        await lease.assert_owned(session, lock=True)
        deployment = await _lock_owned_deployment(session, target.deployment_id, lease)
        sensor = (await session.exec(
            select(ManagedHostSensor)
            .where(ManagedHostSensor.id == target.sensor_row_id)
            .with_for_update()
        )).one_or_none()
        if sensor is None:
            raise RuntimeError("deployment sensor disappeared after health verification")
        if health.active_bundle_hash != target.target_bundle_hash:
            raise RuntimeError("verified sensor bundle does not match the deployment target")
        now = utc_now()
        deployment.status = DetectionRuleDeploymentStatus.ACTIVE
        deployment.observed_bundle_hash = health.active_bundle_hash
        deployment.health_snapshot = health.model_dump(mode="json")
        deployment.health_checked_at = health.observed_at
        deployment.resolved_at = now
        sensor.active_bundle_hash = health.active_bundle_hash
        sensor.desired_bundle_hash = health.desired_bundle_hash
        sensor.status = ManagedHostSensorStatus.HEALTHY
        sensor.last_sequence = health.sequence
        sensor.last_heartbeat_at = health.observed_at
        sensor.last_error = ""
        sensor.updated_at = now
        session.add(deployment)
        session.add(sensor)


async def _rollback_change_deployments(
    change_id: int,
    lease: RuntimeLeaseHandle,
) -> list[str]:
    async with get_async_session() as session:
        await lease.assert_owned(session)
        deployment_ids = list((await session.exec(
            select(DetectionRuleDeployment.id)
            .where(
                DetectionRuleDeployment.change_request_id == change_id,
                DetectionRuleDeployment.status.in_({
                    DetectionRuleDeploymentStatus.DEPLOYING,
                    DetectionRuleDeploymentStatus.HEALTH_CHECK,
                    DetectionRuleDeploymentStatus.ACTIVE,
                    DetectionRuleDeploymentStatus.ROLLING_BACK,
                    DetectionRuleDeploymentStatus.ROLLBACK_FAILED,
                }),
            )
            .order_by(DetectionRuleDeployment.id.asc())
        )).all())
    errors: list[str] = []
    for deployment_id in reversed(deployment_ids):
        try:
            await _rollback_deployment(deployment_id, lease)
        except RuntimeLeaseLost:
            raise
        except Exception as exc:
            error = _error_text(exc)
            errors.append(f"deployment {deployment_id}: {error}")
            logger.exception("detection deployment rollback failed: deployment=%s", deployment_id)
            await _record_rollback_failure(deployment_id, error, lease)
    return errors


async def _rollback_deployment(deployment_id: int, lease: RuntimeLeaseHandle) -> None:
    target = await _claim_rollback_target(deployment_id, lease)
    if target is None:
        return
    headers = detection_proxy_headers(target.proxy)
    await request_with_lease(
        _http_client(),
        lease,
        "POST",
        detection_proxy_url(target.proxy, "/v1/bundles/rollback"),
        json={"bundle_hash": target.previous_bundle_hash},
        headers=headers,
    )
    health = await observe_sensor_bundle(
        _http_client(),
        target.proxy,
        target.previous_bundle_hash,
        lease,
        observation_seconds=0,
        timeout_seconds=30,
    )
    async with get_async_session() as session, session.begin():
        await lease.assert_owned(session, lock=True)
        deployment = await _lock_owned_deployment(session, deployment_id, lease)
        sensor = (await session.exec(
            select(ManagedHostSensor)
            .where(ManagedHostSensor.id == target.sensor_row_id)
            .with_for_update()
        )).one_or_none()
        if sensor is None:
            raise RuntimeError("deployment sensor disappeared during rollback")
        now = utc_now()
        deployment.status = DetectionRuleDeploymentStatus.ROLLED_BACK
        deployment.rollback_observed_bundle_hash = health.active_bundle_hash
        deployment.rollback_health_snapshot = health.model_dump(mode="json")
        deployment.resolved_at = now
        sensor.active_bundle_hash = health.active_bundle_hash
        sensor.desired_bundle_hash = health.desired_bundle_hash
        sensor.status = ManagedHostSensorStatus.HEALTHY
        sensor.last_sequence = health.sequence
        sensor.last_error = ""
        sensor.last_heartbeat_at = health.observed_at
        sensor.updated_at = now
        session.add(deployment)
        session.add(sensor)


async def _claim_rollback_target(
    deployment_id: int,
    lease: RuntimeLeaseHandle,
) -> _DeploymentTarget | None:
    async with get_async_session() as session, session.begin():
        await lease.assert_owned(session, lock=True)
        row = (await session.exec(
            select(DetectionRuleDeployment, ManagedHostSensor)
            .join(ManagedHostSensor, ManagedHostSensor.id == DetectionRuleDeployment.sensor_id)
            .where(DetectionRuleDeployment.id == deployment_id)
            .with_for_update()
        )).first()
        if row is None:
            return None
        deployment, sensor = row
        if sensor.id is None:
            return None
        if deployment.status not in {
            DetectionRuleDeploymentStatus.DEPLOYING,
            DetectionRuleDeploymentStatus.HEALTH_CHECK,
            DetectionRuleDeploymentStatus.ACTIVE,
            DetectionRuleDeploymentStatus.ROLLING_BACK,
            DetectionRuleDeploymentStatus.ROLLBACK_FAILED,
        }:
            return None
        deployment.status = DetectionRuleDeploymentStatus.ROLLING_BACK
        deployment.runtime_owner_id = lease.owner_id
        deployment.lease_fencing_token = lease.fencing_token
        deployment.rollback_observed_bundle_hash = ""
        deployment.rollback_health_snapshot = None
        session.add(deployment)
        return _DeploymentTarget(
            deployment_id=deployment_id,
            sensor_row_id=sensor.id,
            target_bundle_hash=deployment.target_bundle_hash,
            previous_bundle_hash=deployment.previous_bundle_hash,
            proxy=DetectionProxyTarget(
                sensor_id=sensor.sensor_id,
                proxy_url=sensor.proxy_url,
                proxy_token=sensor.proxy_token,
            ),
        )


async def _activate_change(change_id: int, lease: RuntimeLeaseHandle) -> None:
    async with get_async_session() as session, session.begin():
        await lease.assert_owned(session, lock=True)
        change = (await session.exec(
            select(DetectionRuleChangeRequest)
            .where(DetectionRuleChangeRequest.id == change_id)
            .with_for_update()
        )).one_or_none()
        if change is None or change.status != DetectionRuleChangeStatus.DEPLOYING:
            return
        deployments = list((await session.exec(
            select(DetectionRuleDeployment)
            .where(DetectionRuleDeployment.change_request_id == change_id)
            .with_for_update()
        )).all())
        if not deployments or not all(_deployment_is_verified_active(item) for item in deployments):
            raise RuntimeError("change cannot activate before every sensor reports the target bundle")
        rule = (await session.exec(
            select(DetectionRule)
            .where(DetectionRule.id == change.rule_id)
            .with_for_update()
        )).one()
        if change.action == DetectionRuleChangeAction.DISABLE:
            rule.active_version_id = None
        else:
            rule.active_version_id = change.rule_version_id
        now = utc_now()
        rule.updated_at = now
        change.status = DetectionRuleChangeStatus.ACTIVE
        change.resolved_at = now
        previous = list((await session.exec(
            select(DetectionRuleChangeRequest)
            .where(
                DetectionRuleChangeRequest.rule_id == rule.id,
                DetectionRuleChangeRequest.id != change.id,
                DetectionRuleChangeRequest.status == DetectionRuleChangeStatus.ACTIVE,
            )
            .with_for_update()
        )).all())
        for item in previous:
            item.status = DetectionRuleChangeStatus.SUPERSEDED
            item.resolved_at = now
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


async def _record_deployment_error(
    deployment_id: int,
    error: str,
    lease: RuntimeLeaseHandle,
) -> None:
    async with get_async_session() as session, session.begin():
        await lease.assert_owned(session, lock=True)
        deployment = await _lock_owned_deployment(session, deployment_id, lease)
        deployment.error = error
        session.add(deployment)


async def _record_rollback_failure(
    deployment_id: int,
    error: str,
    lease: RuntimeLeaseHandle,
) -> None:
    async with get_async_session() as session, session.begin():
        await lease.assert_owned(session, lock=True)
        deployment = await _lock_owned_deployment(session, deployment_id, lease)
        sensor = (await session.exec(
            select(ManagedHostSensor)
            .where(ManagedHostSensor.id == deployment.sensor_id)
            .with_for_update()
        )).one_or_none()
        now = utc_now()
        deployment.status = DetectionRuleDeploymentStatus.ROLLBACK_FAILED
        deployment.error = error
        deployment.resolved_at = now
        session.add(deployment)
        if sensor is not None:
            sensor.status = ManagedHostSensorStatus.DEGRADED
            sensor.last_error = f"Detection rollback failed: {error}"
            sensor.updated_at = now
            session.add(sensor)


async def _begin_change_rollback(
    change_id: int,
    error: str,
    lease: RuntimeLeaseHandle,
) -> None:
    async with get_async_session() as session, session.begin():
        await lease.assert_owned(session, lock=True)
        change = (await session.exec(
            select(DetectionRuleChangeRequest)
            .where(DetectionRuleChangeRequest.id == change_id)
            .with_for_update()
        )).one_or_none()
        if change is None:
            return
        if change.status == DetectionRuleChangeStatus.ROLLING_BACK:
            return
        if change.status != DetectionRuleChangeStatus.DEPLOYING:
            return
        change.status = DetectionRuleChangeStatus.ROLLING_BACK
        change.error = error
        session.add(change)


async def _finish_change_rollback(
    change_id: int,
    rollback_errors: list[str],
    lease: RuntimeLeaseHandle,
) -> None:
    async with get_async_session() as session, session.begin():
        await lease.assert_owned(session, lock=True)
        change = (await session.exec(
            select(DetectionRuleChangeRequest)
            .where(DetectionRuleChangeRequest.id == change_id)
            .with_for_update()
        )).one_or_none()
        if change is None or change.status != DetectionRuleChangeStatus.ROLLING_BACK:
            return
        now = utc_now()
        if rollback_errors:
            change.status = DetectionRuleChangeStatus.RECOVERY_REQUIRED
            suffix = "; ".join(rollback_errors)
            change.error = f"{change.error}; rollback failures: {suffix}" if change.error else suffix
        else:
            change.status = DetectionRuleChangeStatus.FAILED
        change.resolved_at = now
        session.add(change)
        deployments = list((await session.exec(
            select(DetectionRuleDeployment)
            .where(DetectionRuleDeployment.change_request_id == change_id)
            .with_for_update()
        )).all())
        for deployment in deployments:
            if deployment.status == DetectionRuleDeploymentStatus.PENDING:
                deployment.status = DetectionRuleDeploymentStatus.FAILED
                deployment.error = f"not attempted because another sensor deployment failed: {change.error}"
                deployment.resolved_at = now
                sensor = await session.get(ManagedHostSensor, deployment.sensor_id)
                if sensor is not None and sensor.desired_bundle_hash == deployment.target_bundle_hash:
                    sensor.desired_bundle_hash = sensor.active_bundle_hash
                    sensor.updated_at = now
                    session.add(sensor)
                session.add(deployment)
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
                summary=(
                    "Detection rule rollback requires recovery."
                    if rollback_errors
                    else "Detection rule deployment failed and was rolled back."
                ),
                details={"error": change.error, "rollback_errors": rollback_errors},
            )


async def _lock_owned_deployment(
    session,
    deployment_id: int,
    lease: RuntimeLeaseHandle,
) -> DetectionRuleDeployment:
    deployment = (await session.exec(
        select(DetectionRuleDeployment)
        .where(DetectionRuleDeployment.id == deployment_id)
        .with_for_update()
    )).one_or_none()
    if deployment is None:
        raise RuntimeError("deployment no longer exists")
    if (
        deployment.runtime_owner_id != lease.owner_id
        or deployment.lease_fencing_token != lease.fencing_token
    ):
        raise RuntimeLeaseLost("deployment fencing token changed")
    return deployment


def _deployment_is_verified_active(deployment: DetectionRuleDeployment) -> bool:
    if (
        deployment.status != DetectionRuleDeploymentStatus.ACTIVE
        or deployment.observed_bundle_hash != deployment.target_bundle_hash
        or deployment.health_snapshot is None
    ):
        return False
    try:
        health = DetectionSensorHealthSnapshot.model_validate(deployment.health_snapshot)
    except ValueError:
        return False
    return (
        health.status == DetectionSensorHealthStatus.HEALTHY
        and not health.error
        and health.active_bundle_hash == deployment.target_bundle_hash
        and health.desired_bundle_hash == deployment.target_bundle_hash
    )


def _http_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=httpx.Timeout(15, connect=5), trust_env=False)
    return _client


def _deployment_finished(change_id: int, task: asyncio.Task[None]) -> None:
    if _tasks.get(change_id) is task:
        _tasks.pop(change_id, None)
    if task.cancelled():
        return
    try:
        task.result()
    except Exception:
        logger.exception("detection deployment task crashed: change=%s", change_id)


def _error_text(exc: BaseException) -> str:
    return (str(exc) or exc.__class__.__name__)[:4000]
