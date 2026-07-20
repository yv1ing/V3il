from enum import StrEnum


class ResourceLifecycleStatus(StrEnum):
    ACTIVE = "active"
    RETIRED = "retired"


RESOURCE_LIFECYCLE_STATUS_TRANSITIONS: dict[
    ResourceLifecycleStatus,
    tuple[ResourceLifecycleStatus, ...],
] = {
    ResourceLifecycleStatus.ACTIVE: (ResourceLifecycleStatus.RETIRED,),
    ResourceLifecycleStatus.RETIRED: (),
}
