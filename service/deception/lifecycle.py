from dataclasses import dataclass
from enum import StrEnum

from schema.deception.environments import (
    DeceptionContainerOwnership,
    DeceptionContainerSpec,
    DeceptionEnvironmentStatus,
    DeceptionRevisionKind,
    DeceptionRevisionStatus,
)


class DeceptionLifecycleError(ValueError):
    pass


class DeceptionContainerPlan(StrEnum):
    PROVISION = "provision"
    REUSE = "reuse"


@dataclass(frozen=True)
class DeceptionLifecycle:
    status: DeceptionEnvironmentStatus
    applied_revision_id: int | None
    active_revision_id: int | None
    container_id: int | None
    container_ownership: DeceptionContainerOwnership

    @classmethod
    def from_environment(cls, environment: object) -> "DeceptionLifecycle":
        return cls(
            status=getattr(environment, "status"),
            applied_revision_id=getattr(environment, "applied_revision_id"),
            active_revision_id=getattr(environment, "active_revision_id"),
            container_id=getattr(environment, "sandbox_container_id"),
            container_ownership=getattr(environment, "container_ownership"),
        )


@dataclass(frozen=True)
class DeceptionPlanDecision:
    kind: DeceptionRevisionKind
    container_plan: DeceptionContainerPlan
    environment_status: DeceptionEnvironmentStatus


@dataclass(frozen=True)
class DeceptionTerminalDecision:
    environment_status: DeceptionEnvironmentStatus
    applied_revision_id: int | None
    active_revision_id: int | None
    release_platform_container: bool = False


def plan_revision(lifecycle: DeceptionLifecycle) -> DeceptionPlanDecision:
    _validate_shape(lifecycle)
    if lifecycle.status == DeceptionEnvironmentStatus.RETIRED:
        raise DeceptionLifecycleError("retired environments cannot be revised")
    if lifecycle.status == DeceptionEnvironmentStatus.RECOVERY_REQUIRED:
        raise DeceptionLifecycleError("the environment requires manual recovery before another revision")
    if lifecycle.active_revision_id is not None:
        raise DeceptionLifecycleError("environment already has an active revision")

    if lifecycle.applied_revision_id is None:
        if lifecycle.status != DeceptionEnvironmentStatus.DRAFT:
            raise DeceptionLifecycleError("an environment without an applied baseline must be in draft state")
        return DeceptionPlanDecision(
            kind=DeceptionRevisionKind.INITIAL,
            container_plan=(
                DeceptionContainerPlan.REUSE
                if lifecycle.container_id is not None
                else DeceptionContainerPlan.PROVISION
            ),
            environment_status=DeceptionEnvironmentStatus.BUILDING,
        )

    if lifecycle.status != DeceptionEnvironmentStatus.ACTIVE:
        raise DeceptionLifecycleError("only active environments can plan adaptive revisions")
    if lifecycle.container_id is None:
        raise DeceptionLifecycleError("an applied environment must have a sandbox container")
    return DeceptionPlanDecision(
        kind=DeceptionRevisionKind.ADAPTIVE,
        container_plan=DeceptionContainerPlan.REUSE,
        environment_status=DeceptionEnvironmentStatus.ADAPTING,
    )


def validate_container_spec(
    decision: DeceptionPlanDecision,
    requested: DeceptionContainerSpec,
    current_mappings: list[dict[str, object]],
) -> None:
    if decision.container_plan == DeceptionContainerPlan.PROVISION:
        if requested.port_mappings:
            raise DeceptionLifecycleError(
                "a platform-provisioned initial revision must declare port requirements, not host mappings"
            )
        return
    if requested.port_requirements:
        raise DeceptionLifecycleError("a reused container cannot declare new port requirements")
    requested_mappings = sorted(
        (item.container_port, item.host_port, item.protocol)
        for item in requested.port_mappings
    )
    bound_mappings = sorted(
        (
            int(item["container_port"]),
            int(item["host_port"]),
            str(item.get("protocol") or "tcp"),
        )
        for item in current_mappings
    )
    if requested_mappings != bound_mappings:
        raise DeceptionLifecycleError("a reused container must preserve its port mappings exactly")


def require_active_revision(
    lifecycle: DeceptionLifecycle,
    revision_id: int,
    revision_status: DeceptionRevisionStatus,
    expected_status: DeceptionRevisionStatus,
) -> None:
    _validate_shape(lifecycle)
    if lifecycle.active_revision_id != revision_id:
        raise DeceptionLifecycleError("revision is not the environment's active revision")
    if revision_status != expected_status:
        raise DeceptionLifecycleError(
            f"revision must be {expected_status.value}, not {revision_status.value}"
        )


def reject_revision(lifecycle: DeceptionLifecycle, revision_id: int) -> DeceptionTerminalDecision:
    require_active_revision(
        lifecycle,
        revision_id,
        DeceptionRevisionStatus.PENDING_APPROVAL,
        DeceptionRevisionStatus.PENDING_APPROVAL,
    )
    return _restore_baseline(lifecycle)


def fail_unstarted_revision(lifecycle: DeceptionLifecycle, revision_id: int) -> DeceptionTerminalDecision:
    _validate_shape(lifecycle)
    if lifecycle.active_revision_id != revision_id:
        raise DeceptionLifecycleError("revision is not the environment's active revision")
    return _restore_baseline(lifecycle)


def apply_revision(lifecycle: DeceptionLifecycle, revision_id: int) -> DeceptionTerminalDecision:
    _validate_shape(lifecycle)
    if lifecycle.active_revision_id != revision_id:
        raise DeceptionLifecycleError("revision is not the environment's active revision")
    if lifecycle.container_id is None:
        raise DeceptionLifecycleError("an applied revision must have a sandbox container")
    return DeceptionTerminalDecision(
        environment_status=DeceptionEnvironmentStatus.ACTIVE,
        applied_revision_id=revision_id,
        active_revision_id=None,
    )


def finish_rollback(
    lifecycle: DeceptionLifecycle,
    revision_id: int,
    *,
    succeeded: bool,
) -> DeceptionTerminalDecision:
    _validate_shape(lifecycle)
    if lifecycle.active_revision_id != revision_id:
        raise DeceptionLifecycleError("revision is not the environment's active revision")
    if not succeeded:
        return DeceptionTerminalDecision(
            environment_status=DeceptionEnvironmentStatus.RECOVERY_REQUIRED,
            applied_revision_id=lifecycle.applied_revision_id,
            active_revision_id=revision_id,
        )
    return _restore_baseline(lifecycle)


def restore_interrupted_claim(lifecycle: DeceptionLifecycle, revision_id: int) -> DeceptionEnvironmentStatus:
    if lifecycle.active_revision_id != revision_id:
        raise DeceptionLifecycleError("revision is not the environment's active revision")
    return (
        DeceptionEnvironmentStatus.BUILDING
        if lifecycle.applied_revision_id is None
        else DeceptionEnvironmentStatus.ADAPTING
    )


def begin_rollback_recovery(
    lifecycle: DeceptionLifecycle,
    revision_id: int,
    revision_status: DeceptionRevisionStatus,
) -> DeceptionEnvironmentStatus:
    _validate_shape(lifecycle)
    if lifecycle.status != DeceptionEnvironmentStatus.RECOVERY_REQUIRED:
        raise DeceptionLifecycleError("the environment does not require rollback recovery")
    require_active_revision(
        lifecycle,
        revision_id,
        revision_status,
        DeceptionRevisionStatus.RECOVERY_REQUIRED,
    )
    return (
        DeceptionEnvironmentStatus.BUILDING
        if lifecycle.applied_revision_id is None
        else DeceptionEnvironmentStatus.ADAPTING
    )


def _restore_baseline(lifecycle: DeceptionLifecycle) -> DeceptionTerminalDecision:
    initial = lifecycle.applied_revision_id is None
    release = (
        initial
        and lifecycle.container_id is not None
        and lifecycle.container_ownership == DeceptionContainerOwnership.PLATFORM_MANAGED
    )
    return DeceptionTerminalDecision(
        environment_status=(
            DeceptionEnvironmentStatus.DRAFT
            if initial
            else DeceptionEnvironmentStatus.ACTIVE
        ),
        applied_revision_id=lifecycle.applied_revision_id,
        active_revision_id=None,
        release_platform_container=release,
    )


def _validate_shape(lifecycle: DeceptionLifecycle) -> None:
    transitioning_statuses = {
        DeceptionEnvironmentStatus.BUILDING,
        DeceptionEnvironmentStatus.ADAPTING,
        DeceptionEnvironmentStatus.RECOVERY_REQUIRED,
    }
    if lifecycle.applied_revision_id is not None and lifecycle.container_id is None:
        raise DeceptionLifecycleError("an applied environment must have a sandbox container")
    if lifecycle.status in transitioning_statuses and lifecycle.active_revision_id is None:
        raise DeceptionLifecycleError("a transitioning environment must have an active revision")
    if lifecycle.status not in transitioning_statuses and lifecycle.active_revision_id is not None:
        raise DeceptionLifecycleError("a stable environment cannot have an active revision")
    if lifecycle.applied_revision_id is None and lifecycle.status in {
        DeceptionEnvironmentStatus.ACTIVE,
        DeceptionEnvironmentStatus.ADAPTING,
        DeceptionEnvironmentStatus.PAUSED,
    }:
        raise DeceptionLifecycleError("an environment without a baseline cannot be active")
    if lifecycle.applied_revision_id is not None and lifecycle.status in {
        DeceptionEnvironmentStatus.DRAFT,
        DeceptionEnvironmentStatus.BUILDING,
    }:
        raise DeceptionLifecycleError("an environment with a baseline cannot be in an initial-build state")
    if (
        lifecycle.container_ownership == DeceptionContainerOwnership.PRESELECTED
        and lifecycle.container_id is None
    ):
        raise DeceptionLifecycleError("a preselected container binding cannot be empty")
    if (
        lifecycle.container_ownership == DeceptionContainerOwnership.PLATFORM_MANAGED
        and lifecycle.status == DeceptionEnvironmentStatus.DRAFT
        and lifecycle.container_id is not None
    ):
        raise DeceptionLifecycleError("a draft platform-managed environment cannot retain a container")
