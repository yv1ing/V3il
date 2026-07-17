from dataclasses import dataclass

from model.egress_proxy.proxies import EgressProxy
from schema.egress_proxy.proxies import EgressProxyType


@dataclass(frozen=True)
class EgressProxyConnection:
    id: int
    proxy_type: EgressProxyType
    proxy_host: str
    proxy_port: int
    proxy_account: str
    proxy_password: str


def snapshot_egress_proxy(proxy: EgressProxy) -> EgressProxyConnection:
    if proxy.id is None:
        raise ValueError("egress proxy must be persisted before it can be used")
    return EgressProxyConnection(
        id=proxy.id,
        proxy_type=proxy.proxy_type,
        proxy_host=proxy.proxy_host,
        proxy_port=proxy.proxy_port,
        proxy_account=proxy.proxy_account,
        proxy_password=proxy.proxy_password,
    )
