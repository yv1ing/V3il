from service.runtime.leases import runtime_lease


DETECTION_MUTATION_LEASE_NAME = "detection.bundle-mutation"


def detection_mutation_lease(*, wait_timeout_seconds: float | None = None):
    return runtime_lease(
        DETECTION_MUTATION_LEASE_NAME,
        ttl_seconds=15,
        wait_timeout_seconds=wait_timeout_seconds,
    )
