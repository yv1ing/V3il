from urllib.parse import quote

from service.egress_proxy.state import EgressProxyConnection


def egress_proxy_upstream(proxy: EgressProxyConnection) -> str:
    auth = ""
    if proxy.proxy_account:
        account = quote(proxy.proxy_account, safe="")
        password = quote(proxy.proxy_password, safe="")
        auth = f"{account}:{password}@"
    return f"{auth}{proxy.proxy_host}:{proxy.proxy_port}"
