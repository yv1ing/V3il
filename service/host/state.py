from dataclasses import dataclass

from model.host.hosts import ManagedHost


@dataclass(frozen=True)
class ManagedHostConnection:
    id: int
    ip_address: str
    ssh_port: int
    host_account: str
    host_password: str
    docker_management_port: int
    docker_tls_enabled: bool
    docker_client_ca_cert: str
    docker_client_cert: str
    docker_client_key: str


def snapshot_managed_host(host: ManagedHost) -> ManagedHostConnection:
    if host.id is None:
        raise ValueError("managed host must be persisted before it can be used")
    return ManagedHostConnection(
        id=host.id,
        ip_address=host.ip_address,
        ssh_port=host.ssh_port,
        host_account=host.host_account,
        host_password=host.host_password,
        docker_management_port=host.docker_management_port,
        docker_tls_enabled=host.docker_tls_enabled,
        docker_client_ca_cert=host.docker_client_ca_cert,
        docker_client_cert=host.docker_client_cert,
        docker_client_key=host.docker_client_key,
    )
