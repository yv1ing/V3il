from sqlmodel import select

from database import get_async_session
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
from service.threat.behaviors import ingest_behavior_event_batch
from utils.time import utc_now


ContainerRuntimeEvidence = tuple[int, tuple[int, ...]]


async def record_container_runtime_state(
    container_id: int,
    *,
    previous_status: SandboxContainerStatus,
    observed_status: SandboxContainerStatus,
    docker_status: str,
    container_exists: bool | None,
) -> ContainerRuntimeEvidence | None:
    """Persist a deception container coverage transition as immutable evidence."""
    async with get_async_session() as session:
        row = (await session.exec(
            select(
                DeceptionEnvironment.id,
                DeceptionEnvironment.owner_id,
                DeceptionEnvironment.status,
                SandboxContainer.behavior_sensor_id,
            )
            .join(
                SandboxContainer,
                DeceptionEnvironment.sandbox_container_id == SandboxContainer.id,
            )
            .where(SandboxContainer.id == container_id)
        )).one_or_none()
        if row is None:
            return None
        environment_id, owner_id, environment_status, behavior_sensor_id = row
        if (
            environment_status == DeceptionEnvironmentStatus.RETIRED
            or not behavior_sensor_id
        ):
            return None

        sensor_id = f"control-plane:container-runtime:{behavior_sensor_id}"
        latest_state = (await session.exec(
            select(BehaviorEvent.action, BehaviorEvent.attributes)
            .where(
                BehaviorEvent.environment_id == environment_id,
                BehaviorEvent.sensor_id == sensor_id,
            )
            .order_by(BehaviorEvent.sequence.desc())
            .limit(1)
        )).first()
        if latest_state is not None:
            latest_state = (latest_state[0], dict(latest_state[1]))
        cursor_sequence = (await session.exec(select(BehaviorSensorCursor.last_sequence).where(
            BehaviorSensorCursor.environment_id == environment_id,
            BehaviorSensorCursor.sensor_id == sensor_id,
        ))).one_or_none() or 0

    if observed_status == SandboxContainerStatus.RUNNING:
        if latest_state is None or latest_state[0] != "container_runtime_unavailable":
            return None
        action = "container_runtime_recovered"
        outcome = BehaviorOutcome.SUCCESS
        summary = "Deception container runtime and behavior collection are available again."
    else:
        if (
            latest_state is not None
            and latest_state[0] == "container_runtime_unavailable"
            and latest_state[1].get("observed_status") == observed_status.value
            and latest_state[1].get("docker_status") == docker_status
            and latest_state[1].get("container_exists") == container_exists
        ):
            return None
        action = "container_runtime_unavailable"
        outcome = BehaviorOutcome.FAILURE
        summary = (
            "Deception container runtime became unavailable; behavior collection coverage "
            f"is interrupted ({previous_status.value} -> {observed_status.value})."
        )

    sequence = cursor_sequence + 1
    event = CapturedBehaviorEvent(
        sequence=sequence,
        observed_at=utc_now(),
        category=BehaviorEventCategory.SYSTEM,
        action=action,
        source=BehaviorEventSource.CONTROL_PLANE,
        direction=BehaviorDirection.INTERNAL,
        outcome=outcome,
        summary=summary,
        raw_reference=f"control-plane://container-runtime/{container_id}/{sequence}",
        attributes={
            "container_id": container_id,
            "container_exists": container_exists,
            "docker_status": docker_status,
            "previous_status": previous_status.value,
            "observed_status": observed_status.value,
            "observer": "container_runtime",
            "sensor_id": behavior_sensor_id,
        },
    )
    result = await ingest_behavior_event_batch(
        environment_id,
        IngestBehaviorEventBatchRequest(sensor_id=sensor_id, events=[event]),
        user_id=owner_id,
        user_role=SystemUserRole.ADMIN,
    )
    if result.response is None:
        raise RuntimeError(
            "container runtime evidence ingestion was rejected: "
            + (result.message or str(container_id))
        )
    return environment_id, result.new_event_ids
