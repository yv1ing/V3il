import asyncio
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime

from sqlmodel import select

from config import get_config
from database import get_async_session
from logger import get_logger
from model.deception.environments import DeceptionEnvironment
from model.sandbox.containers import SandboxContainer
from model.threat.behaviors import BehaviorEvent, BehaviorSensorCursor
from schema.deception.environments import DeceptionEnvironmentStatus
from schema.sandbox.containers import SandboxContainerStatus
from schema.system_user.users import SystemUserRole
from schema.threat.behaviors import (
    BehaviorDirection,
    BehaviorEventCategory,
    BehaviorEventSource,
    BehaviorOutcome,
    CapturedBehaviorEvent,
    IngestBehaviorEventBatchRequest,
)
from service.sandbox.observer import (
    TelemetryHealth,
    pull_container_behavior_events,
    pull_container_behavior_health,
)
from service.threat.behaviors import ingest_behavior_event_batch
from service.threat.orchestration import (
    advance_idle_incidents,
    orchestrate_behavior_events,
    recover_unprocessed_behavior_events,
)


logger = get_logger(__name__)

_runtime_task: asyncio.Task[None] | None = None
_stop_event = asyncio.Event()


@dataclass(frozen=True)
class _TelemetryTarget:
    environment_id: int
    owner_id: int
    container_id: int
    behavior_sensor_id: str
    control_proxy_token: str


async def start_behavior_telemetry_runtime() -> None:
    global _runtime_task
    if _runtime_task is not None and not _runtime_task.done():
        return
    _stop_event.clear()
    _runtime_task = asyncio.create_task(_behavior_telemetry_loop(), name="behavior-telemetry-runtime")
    logger.info("behavior telemetry runtime started")


async def stop_behavior_telemetry_runtime() -> None:
    global _runtime_task
    task, _runtime_task = _runtime_task, None
    if task is None:
        return
    _stop_event.set()
    try:
        await task
    except asyncio.CancelledError:
        pass
    logger.info("behavior telemetry runtime stopped")


async def collect_behavior_telemetry_once() -> None:
    try:
        await recover_unprocessed_behavior_events()
    except Exception:
        logger.exception("unlinked threat event recovery failed")
    try:
        await advance_idle_incidents()
    except Exception:
        logger.exception("idle threat incident advancement failed")
    async with get_async_session() as session:
        rows = list((await session.exec(
            select(
                DeceptionEnvironment.id,
                DeceptionEnvironment.owner_id,
                SandboxContainer.id,
                SandboxContainer.behavior_sensor_id,
                SandboxContainer.control_proxy_token,
            )
            .join(SandboxContainer, DeceptionEnvironment.sandbox_container_id == SandboxContainer.id)
            .where(DeceptionEnvironment.status != DeceptionEnvironmentStatus.RETIRED)
            .where(SandboxContainer.status == SandboxContainerStatus.RUNNING)
            .order_by(DeceptionEnvironment.id.asc())
        )).all())
    targets = [
        _TelemetryTarget(
            environment_id=environment_id,
            owner_id=owner_id,
            container_id=container_id,
            behavior_sensor_id=behavior_sensor_id,
            control_proxy_token=control_proxy_token,
        )
        for environment_id, owner_id, container_id, behavior_sensor_id, control_proxy_token in rows
        if behavior_sensor_id
    ]
    if not targets:
        return
    semaphore = asyncio.Semaphore(get_config().behavior_capture.concurrency)

    async def collect(target: _TelemetryTarget) -> None:
        async with semaphore:
            try:
                await _collect_environment_telemetry(target)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception(
                    "behavior telemetry target collection failed: environment=%s container=%s",
                    target.environment_id,
                    target.container_id,
                )

    await asyncio.gather(*(
        collect(target)
        for target in targets
    ))


async def _behavior_telemetry_loop() -> None:
    while not _stop_event.is_set():
        try:
            await collect_behavior_telemetry_once()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("behavior telemetry collection cycle failed")
        try:
            await asyncio.wait_for(
                _stop_event.wait(),
                timeout=get_config().behavior_capture.poll_interval_seconds,
            )
        except asyncio.TimeoutError:
            pass


async def _collect_environment_telemetry(
    target: _TelemetryTarget,
) -> None:
    async with get_async_session() as session:
        after = (await session.exec(select(BehaviorSensorCursor.last_sequence).where(
            BehaviorSensorCursor.environment_id == target.environment_id,
            BehaviorSensorCursor.sensor_id == target.behavior_sensor_id,
        ))).one_or_none() or 0
    health = await _collect_sensor_health(target, after)
    if health is None:
        return
    if health.sensor_id != target.behavior_sensor_id:
        await _record_sensor_health_state(
            target,
            issue=(
                "Behavior sensor identity mismatch: "
                f"expected {target.behavior_sensor_id}, received {health.sensor_id}."
            ),
            attributes={"received_sensor_id": health.sensor_id},
        )
        return
    if health.sequence < after:
        await _record_sensor_health_state(
            target,
            issue=(
                "Behavior sensor sequence moved behind the persisted cursor: "
                f"sensor={health.sequence}, persisted={after}."
            ),
            attributes={"sensor_sequence": health.sequence, "persisted_sequence": after},
        )
        return
    issue, attributes = _sensor_health_issue(health)
    capture = get_config().behavior_capture
    for _ in range(capture.max_batches_per_poll):
        try:
            batch = await pull_container_behavior_events(
                target.container_id,
                after=after,
                limit=capture.batch_size,
            )
        except (FileNotFoundError, OSError) as exc:
            await _record_sensor_health_state(
                target,
                issue="Behavior telemetry event endpoint is unavailable.",
                attributes={"error_type": type(exc).__name__, "persisted_sequence": after},
            )
            return
        except Exception as exc:
            logger.exception(
                "behavior telemetry pull failed: environment=%s container=%s",
                target.environment_id,
                target.container_id,
            )
            await _record_sensor_health_state(
                target,
                issue="Behavior telemetry event response is invalid or unreadable.",
                attributes={"error_type": type(exc).__name__, "persisted_sequence": after},
            )
            return
        if batch.sensor_id != target.behavior_sensor_id:
            logger.error(
                "behavior sensor identity mismatch: environment=%s expected=%s received=%s",
                target.environment_id,
                target.behavior_sensor_id,
                batch.sensor_id,
            )
            await _record_sensor_health_state(
                target,
                issue=(
                    "Behavior event stream identity mismatch: "
                    f"expected {target.behavior_sensor_id}, received {batch.sensor_id}."
                ),
                attributes={"received_sensor_id": batch.sensor_id, "persisted_sequence": after},
            )
            return
        if not batch.events:
            await _record_sensor_health_state(
                target,
                issue=issue,
                attributes=attributes,
            )
            return
        result = await ingest_behavior_event_batch(
            target.environment_id,
            IngestBehaviorEventBatchRequest(sensor_id=batch.sensor_id, events=batch.events),
            user_id=target.owner_id,
            user_role=SystemUserRole.ADMIN,
            sensor_control_token=target.control_proxy_token,
        )
        if result.response is None:
            logger.error(
                "behavior telemetry ingestion rejected: environment=%s sensor=%s message=%s",
                target.environment_id,
                batch.sensor_id,
                result.message,
            )
            await _record_sensor_health_state(
                target,
                issue="Behavior telemetry ingestion was rejected.",
                attributes={
                    "persisted_sequence": after,
                    "batch_first_sequence": batch.events[0].sequence,
                    "rejection": result.message[:1000],
                },
            )
            return
        await orchestrate_behavior_events(target.environment_id, list(result.new_event_ids))
        after = result.response.last_sequence
        if len(batch.events) < capture.batch_size:
            await _record_sensor_health_state(
                target,
                issue=issue,
                attributes=attributes,
            )
            return
    await _record_sensor_health_state(
        target,
        issue=issue,
        attributes=attributes,
    )


async def _collect_sensor_health(
    target: _TelemetryTarget,
    persisted_sequence: int,
) -> TelemetryHealth | None:
    try:
        return await pull_container_behavior_health(target.container_id)
    except (FileNotFoundError, OSError) as exc:
        await _record_sensor_health_state(
            target,
            issue="Behavior sensor health endpoint is unavailable.",
            attributes={"error_type": type(exc).__name__, "persisted_sequence": persisted_sequence},
        )
    except Exception as exc:
        logger.exception(
            "behavior sensor health pull failed: environment=%s container=%s",
            target.environment_id,
            target.container_id,
        )
        await _record_sensor_health_state(
            target,
            issue="Behavior sensor health response is invalid or unreadable.",
            attributes={"error_type": type(exc).__name__, "persisted_sequence": persisted_sequence},
        )
    return None


def _sensor_health_issue(health: TelemetryHealth) -> tuple[str, dict[str, object]]:
    observers = sorted(
        (
            {
                "name": observer.name,
                "status": observer.status,
                "message": observer.message,
            }
            for observer in health.observers
        ),
        key=lambda item: str(item["name"]),
    )
    unhealthy = [
        observer
        for observer in observers
        if observer["status"] != "active"
    ]
    observed_names = {str(observer["name"]) for observer in observers}
    missing = sorted({"network", "filesystem"} - observed_names)
    if "process_kernel" not in observed_names and "process" not in observed_names:
        missing.append("process")
    attributes: dict[str, object] = {
        "sensor_sequence": health.sequence,
        "journal": health.journal,
        "observers": observers,
        "missing_observers": missing,
    }
    messages: list[str] = []
    if health.last_error:
        messages.append(f"journal error: {health.last_error}")
    if missing:
        messages.append("missing observers: " + ", ".join(missing))
    if unhealthy:
        messages.append(
            "unhealthy observers: "
            + ", ".join(f"{item['name']}={item['status']}" for item in unhealthy)
        )
    return "; ".join(messages), attributes


async def _record_sensor_health_state(
    target: _TelemetryTarget,
    *,
    issue: str,
    attributes: dict[str, object],
) -> None:
    sensor_id = f"control-plane:{target.behavior_sensor_id}"
    digest_payload = json.dumps(
        {"issue": issue, "attributes": attributes},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    health_digest = hashlib.sha256(digest_payload.encode("utf-8")).hexdigest()
    async with get_async_session() as session:
        latest_state = (await session.exec(
            select(BehaviorEvent.action, BehaviorEvent.attributes)
            .where(
                BehaviorEvent.environment_id == target.environment_id,
                BehaviorEvent.sensor_id == sensor_id,
            )
            .order_by(BehaviorEvent.sequence.desc())
            .limit(1)
        )).first()
        cursor_sequence = (await session.exec(select(BehaviorSensorCursor.last_sequence).where(
            BehaviorSensorCursor.environment_id == target.environment_id,
            BehaviorSensorCursor.sensor_id == sensor_id,
        ))).one_or_none() or 0
        if latest_state is not None:
            latest_state = (latest_state[0], dict(latest_state[1]))
    if issue:
        if latest_state is not None and latest_state[0] == "observer_degraded" and (
            latest_state[1].get("health_digest") == health_digest
        ):
            return
        action = "observer_degraded"
        outcome = BehaviorOutcome.FAILURE
        summary = issue
    else:
        if latest_state is None or latest_state[0] != "observer_degraded":
            return
        action = "observer_recovered"
        outcome = BehaviorOutcome.SUCCESS
        summary = "Behavior sensor health and observer coverage recovered."

    sequence = cursor_sequence + 1
    event = CapturedBehaviorEvent(
        sequence=sequence,
        observed_at=datetime.now(),
        category=BehaviorEventCategory.SYSTEM,
        action=action,
        source=BehaviorEventSource.CONTROL_PLANE,
        direction=BehaviorDirection.INTERNAL,
        outcome=outcome,
        summary=summary,
        raw_reference=f"control-plane://sensor-health/{target.container_id}/{sequence}",
        attributes={
            **attributes,
            "health_digest": health_digest,
            "container_id": target.container_id,
            "sensor_id": target.behavior_sensor_id,
            "observer": "sensor_health",
        },
    )
    result = await ingest_behavior_event_batch(
        target.environment_id,
        IngestBehaviorEventBatchRequest(sensor_id=sensor_id, events=[event]),
        user_id=target.owner_id,
        user_role=SystemUserRole.ADMIN,
    )
    if result.response is None:
        logger.error(
            "sensor health evidence ingestion rejected: environment=%s message=%s",
            target.environment_id,
            result.message,
        )
        return
    await orchestrate_behavior_events(target.environment_id, list(result.new_event_ids))
