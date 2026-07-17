from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from schema.sandbox.containers import SandboxContainerEgressMode, SandboxContainerStatus


SandboxContainerProtocol = Literal["tcp", "udp"]


@dataclass(frozen=True)
class SandboxContainerSnapshot:
    id: int
    host_id: int
    container_name: str
    container_hash: str
    owner_id: int
    image_id: int
    egress_mode: SandboxContainerEgressMode
    egress_proxy_id: int | None
    control_proxy_host_port: int
    control_proxy_token: str
    behavior_sensor_id: str
    provisioned_for_revision_id: int | None
    port_mappings: tuple[dict[str, object], ...]
    status: SandboxContainerStatus
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class SandboxContainerRecord:
    container: SandboxContainerSnapshot
    image_name: str
    supports_tor: bool
    control_proxy_port: int
    owner_username: str
    host_ip_address: str
    egress_label: str = ""


@dataclass(frozen=True)
class SandboxContainerMutationResult:
    record: SandboxContainerRecord | None
    succeeded: bool
    message: str = ""
    not_found: bool = False


@dataclass(frozen=True)
class SandboxContainerCommandResult:
    output: str
    exit_code: int


@dataclass(frozen=True)
class SandboxContainerSelection:
    id: int
    generation: int


@dataclass(frozen=True)
class SandboxContainerToolBinding:
    id: int
    generation: int
