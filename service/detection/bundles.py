from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from sqlmodel import select

from model.deception.environments import DeceptionArtifact, DeceptionEnvironment
from model.sandbox.containers import SandboxContainer
from model.detection.rules import DetectionRule, DetectionRuleVersion, ManagedHostSensor
from schema.detection.rules import DetectionRuleChangeAction, DetectionRuleScope


@dataclass(frozen=True)
class EffectiveBundles:
    manifest_hash: str
    sensor_bundles: dict[int, dict]


async def build_effective_bundles(
    session,
    *,
    rule: DetectionRule,
    action: DetectionRuleChangeAction,
    candidate_version: DetectionRuleVersion | None,
    target_sensor_ids: list[int],
) -> EffectiveBundles:
    sensors = list((await session.exec(
        select(ManagedHostSensor).where(ManagedHostSensor.id.in_(target_sensor_ids))
    )).all())
    by_id = {sensor.id: sensor for sensor in sensors if sensor.id is not None}
    if set(by_id) != set(target_sensor_ids):
        raise ValueError("one or more target sensors do not exist")

    active_rules = list((await session.exec(
        select(DetectionRule).where(DetectionRule.active_version_id.is_not(None))
    )).all())
    versions = list((await session.exec(select(DetectionRuleVersion))).all())
    versions_by_id = {version.id: version for version in versions if version.id is not None}
    sensor_bundles: dict[int, dict] = {}
    for sensor_id, sensor in by_id.items():
        entries: list[dict] = []
        for active_rule in active_rules:
            if active_rule.id == rule.id:
                continue
            if not await _rule_applies_to_sensor(session, active_rule, sensor):
                continue
            version = versions_by_id.get(active_rule.active_version_id)
            if version is not None:
                entries.append(_bundle_entry(active_rule, version))
        if action != DetectionRuleChangeAction.DISABLE:
            if candidate_version is None:
                raise ValueError("this change action requires a rule version")
            if not await _rule_applies_to_sensor(session, rule, sensor):
                raise ValueError("target sensor is outside the rule scope")
            entries.append(_bundle_entry(rule, candidate_version))
        entries.sort(key=lambda item: (item["type"], item["rule_id"], item["version_id"]))
        bundle = {
            "format": "v3il-detection-bundle-v1",
            "sensor_id": sensor.sensor_id,
            "capture_interface": sensor.capture_interface,
            "excluded_ports": sorted(sensor.excluded_ports),
            "targets": await _capture_targets(session, sensor.host_id),
            "artifacts": await _active_artifacts(session, sensor.host_id),
            "rules": entries,
        }
        bundle["bundle_hash"] = _hash_json(bundle)
        sensor_bundles[sensor_id] = bundle
    manifest = {
        "format": "v3il-detection-manifest-v1",
        "targets": [
            {"sensor_id": sensor_id, "bundle_hash": sensor_bundles[sensor_id]["bundle_hash"]}
            for sensor_id in sorted(sensor_bundles)
        ],
    }
    return EffectiveBundles(manifest_hash=_hash_json(manifest), sensor_bundles=sensor_bundles)


async def current_sensor_bundle(session, sensor: ManagedHostSensor) -> dict:
    active_rules = list((await session.exec(
        select(DetectionRule).where(DetectionRule.active_version_id.is_not(None))
    )).all())
    entries: list[dict] = []
    for rule in active_rules:
        if not await _rule_applies_to_sensor(session, rule, sensor):
            continue
        version = await session.get(DetectionRuleVersion, rule.active_version_id)
        if version is not None:
            entries.append(_bundle_entry(rule, version))
    entries.sort(key=lambda item: (item["type"], item["rule_id"], item["version_id"]))
    bundle = {
        "format": "v3il-detection-bundle-v1",
        "sensor_id": sensor.sensor_id,
        "capture_interface": sensor.capture_interface,
        "excluded_ports": sorted(sensor.excluded_ports),
        "targets": await _capture_targets(session, sensor.host_id),
        "artifacts": await _active_artifacts(session, sensor.host_id),
        "rules": entries,
    }
    bundle["bundle_hash"] = _hash_json(bundle)
    return bundle


async def _rule_applies_to_sensor(session, rule: DetectionRule, sensor: ManagedHostSensor) -> bool:
    if rule.scope == DetectionRuleScope.GLOBAL:
        return True
    if rule.scope == DetectionRuleScope.HOST:
        return rule.host_id == sensor.host_id
    if rule.environment_id is None:
        return False
    environment = await session.get(DeceptionEnvironment, rule.environment_id)
    return environment is not None and environment.host_id == sensor.host_id


def _bundle_entry(rule: DetectionRule, version: DetectionRuleVersion) -> dict:
    return {
        "rule_id": rule.id,
        "version_id": version.id,
        "version": version.version,
        "type": rule.type.value if hasattr(rule.type, "value") else str(rule.type),
        "scope": rule.scope.value if hasattr(rule.scope, "value") else str(rule.scope),
        "content_sha256": version.content_sha256,
        "content": version.content,
    }


def _hash_json(payload: dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


async def _capture_targets(session, host_id: int) -> list[dict]:
    rows = list((await session.exec(
        select(DeceptionEnvironment, SandboxContainer)
        .join(SandboxContainer, SandboxContainer.id == DeceptionEnvironment.sandbox_container_id)
        .where(DeceptionEnvironment.host_id == host_id)
    )).all())
    targets: list[dict] = []
    for environment, container in rows:
        for mapping in container.port_mappings:
            try:
                targets.append({
                    "environment_id": environment.id,
                    "host_port": int(mapping["host_port"]),
                    "container_port": int(mapping["container_port"]),
                    "protocol": str(mapping.get("protocol") or "tcp").lower(),
                })
            except (KeyError, TypeError, ValueError):
                continue
    return sorted(targets, key=lambda item: (item["environment_id"], item["protocol"], item["host_port"]))


async def _active_artifacts(session, host_id: int) -> list[dict]:
    rows = list((await session.exec(
        select(DeceptionArtifact, DeceptionEnvironment)
        .join(DeceptionEnvironment, DeceptionEnvironment.id == DeceptionArtifact.environment_id)
        .where(DeceptionEnvironment.host_id == host_id, DeceptionArtifact.active.is_(True))
    )).all())
    return sorted((
        {
            "id": artifact.id,
            "environment_id": artifact.environment_id,
            "kind": artifact.kind.value,
            "fingerprint": artifact.fingerprint,
        }
        for artifact, _ in rows
    ), key=lambda item: (item["environment_id"], item["id"]))
