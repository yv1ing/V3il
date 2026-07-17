from dataclasses import dataclass


DETECTION_PROXY_PREFIX = "/detection"


@dataclass(frozen=True)
class DetectionProxyTarget:
    sensor_id: str
    proxy_url: str
    proxy_token: str


def detection_proxy_url(sensor: DetectionProxyTarget, path: str) -> str:
    normalized_path = path if path.startswith("/") else f"/{path}"
    return f"{sensor.proxy_url.rstrip('/')}{DETECTION_PROXY_PREFIX}{normalized_path}"


def detection_proxy_headers(sensor: DetectionProxyTarget) -> dict[str, str]:
    return {"X-Sandbox-Token": sensor.proxy_token}
