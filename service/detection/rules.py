from __future__ import annotations

import hashlib
import json
from datetime import datetime

from sqlalchemy import func, or_
from sqlmodel import select

from database import get_async_session
from model.deception.environments import DeceptionEnvironment
from model.detection.rules import (
    DetectionRule,
    DetectionBundle,
    DetectionRuleChangeRequest,
    DetectionRuleDeployment,
    DetectionRuleVersion,
    ManagedHostSensor,
)
from model.host.hosts import ManagedHost
from schema.detection.rules import (
    ConfigureManagedHostSensorRequest,
    CreateDetectionRuleRequest,
    DetectionRuleChangeAction,
    DetectionRuleChangeRequestSchema,
    DetectionRuleChangeStatus,
    DetectionRuleSchema,
    DetectionRuleDeploymentStatus,
    DetectionRuleOrigin,
    DetectionRuleScope,
    DetectionRuleType,
    DetectionRuleVersionSchema,
    DetectionRuleVersionStatus,
    ManagedHostSensorSchema,
    ReplayDetectionRuleRequest,
    SubmitDetectionRuleChangeRequest,
)
from schema.system_user.users import SystemUserRole
from schema.threat.investigations import AuditActorType, AuditEventKind
from service.common.pagination import Page, RESOURCE_PAGE_SIZE, page_offset
from service.detection.bundles import build_effective_bundles
from service.detection.validation import validate_rule_content
from service.threat.audit import add_audit_event


_BUILTIN_RULES = (
    (
        "Port scan threshold",
        "Aggregates inbound connection attempts across destination ports.",
        {
            "signal_kind": "port_scan",
            "classification": "suspicious",
            "score": 65,
            "all": [
                {"field": "category", "operator": "eq", "value": "network"},
                {"field": "direction", "operator": "eq", "value": "inbound"},
                {"field": "action", "operator": "eq", "value": "network_connection"},
            ],
            "threshold": 20,
            "window_seconds": 60,
            "cooldown_seconds": 120,
            "group_by": ["source_ip", "destination_ip"],
            "distinct_by": ["destination_port"],
            "correlation_fields": ["source_ip", "destination_ip"],
            "material": True,
            "reason": "Inbound connection attempts crossed the scan threshold.",
        },
    ),
    (
        "Authentication brute force",
        "Detects repeated failed authentication attempts.",
        {
            "signal_kind": "authentication_brute_force",
            "classification": "suspicious",
            "score": 78,
            "all": [
                {"field": "category", "operator": "eq", "value": "authentication"},
                {"field": "outcome", "operator": "eq", "value": "failure"},
            ],
            "threshold": 5,
            "window_seconds": 120,
            "cooldown_seconds": 180,
            "group_by": ["source_ip", "service_name"],
            "correlation_fields": ["source_ip", "username", "service_name"],
            "material": True,
            "reason": "Authentication failures crossed the brute-force threshold.",
        },
    ),
    (
        "Attack payload indicators",
        "Detects common injection and traversal indicators in normalized summaries.",
        {
            "signal_kind": "attack_payload",
            "classification": "malicious",
            "score": 85,
            "any": [
                {"field": "summary", "operator": "regex", "value": "(?i)(union\\s+select|<script|\\.\\./|/etc/passwd|;\\s*(curl|wget|sh)\\b)"},
                {"field": "attributes.uri", "operator": "regex", "value": "(?i)(union(%20|\\s)+select|%2e%2e|\\.\\./|<script)"},
            ],
            "threshold": 1,
            "window_seconds": 60,
            "cooldown_seconds": 60,
            "group_by": ["source_ip", "network_session_id"],
            "correlation_fields": ["source_ip", "network_session_id"],
            "material": True,
            "reason": "Request content matched an explicit attack payload indicator.",
        },
    ),
    (
        "Deception artifact interaction",
        "Treats a registered deception artifact interaction as critical.",
        {
            "signal_kind": "deception_artifact_interaction",
            "classification": "malicious",
            "score": 95,
            "all": [{"field": "deception_artifact_id", "operator": "exists", "value": True}],
            "threshold": 1,
            "window_seconds": 300,
            "cooldown_seconds": 0,
            "group_by": ["deception_artifact_id", "source_ip"],
            "correlation_fields": ["deception_artifact_id", "source_ip"],
            "material": True,
            "reason": "A registered deception artifact was accessed.",
        },
    ),
    (
        "Post-compromise execution",
        "Treats observed command and process execution inside a deception environment as critical.",
        {
            "signal_kind": "post_compromise_execution",
            "classification": "malicious",
            "score": 95,
            "any": [
                {"field": "category", "operator": "eq", "value": "command"},
                {"field": "category", "operator": "eq", "value": "process"},
            ],
            "all": [{"field": "source_ip", "operator": "exists", "value": True}],
            "threshold": 1,
            "window_seconds": 300,
            "cooldown_seconds": 30,
            "group_by": ["source_ip", "network_session_id"],
            "correlation_fields": ["source_ip", "network_session_id"],
            "material": True,
            "reason": "Execution was observed inside the deception environment.",
        },
    ),
)


async def seed_builtin_detection_rules() -> int:
    created = 0
    async with get_async_session() as session, session.begin():
        for name, description, definition in _BUILTIN_RULES:
            existing = (await session.exec(select(DetectionRule).where(
                DetectionRule.name == name,
                DetectionRule.origin == DetectionRuleOrigin.BUILTIN,
            ))).one_or_none()
            if existing is not None:
                continue
            content = json.dumps(definition, ensure_ascii=False, sort_keys=True, indent=2)
            rule = DetectionRule(
                name=name,
                description=description,
                type=DetectionRuleType.CENTRAL_RULE,
                origin=DetectionRuleOrigin.BUILTIN,
                scope=DetectionRuleScope.GLOBAL,
                created_by_actor_type=AuditActorType.SYSTEM.value,
                created_by_actor_code="system",
            )
            session.add(rule)
            await session.flush()
            version = DetectionRuleVersion(
                rule_id=rule.id,
                version=1,
                status=DetectionRuleVersionStatus.VALIDATED,
                content=content,
                content_sha256=_sha256(content),
                validation_result=validate_rule_content(rule.type, content),
                created_by_actor_type=AuditActorType.SYSTEM.value,
                created_by_actor_code="system",
                validated_at=datetime.now(),
            )
            session.add(version)
            await session.flush()
            rule.active_version_id = version.id
            session.add(rule)
            created += 1
    return created


async def configure_sensor(request: ConfigureManagedHostSensorRequest) -> ManagedHostSensorSchema:
    async with get_async_session() as session, session.begin():
        if await session.get(ManagedHost, request.host_id) is None:
            raise LookupError("managed host not found")
        sensor = (await session.exec(
            select(ManagedHostSensor).where(ManagedHostSensor.host_id == request.host_id).with_for_update()
        )).one_or_none()
        values = request.model_dump()
        if sensor is None:
            sensor = ManagedHostSensor(**values)
        else:
            if sensor.sensor_id != request.sensor_id or sensor.proxy_token != request.proxy_token:
                raise ValueError("sensor identity and Proxy token are immutable once the evidence chain exists")
            for key, value in values.items():
                setattr(sensor, key, value)
            sensor.updated_at = datetime.now()
        session.add(sensor)
        await session.flush()
        await add_audit_event(
            session,
            kind=AuditEventKind.DETECTION,
            summary="Managed Host detection sensor configured.",
            managed_host_id=request.host_id,
            actor_type=AuditActorType.USER,
            actor_code="admin",
            object_type="managed_host_sensor",
            object_id=sensor.id,
            details={"host_id": request.host_id, "sensor_id": request.sensor_id},
        )
        result = ManagedHostSensorSchema.model_validate(sensor)
    from service.detection.sensor_bundles import schedule_sensor_bundle_refresh
    schedule_sensor_bundle_refresh(request.host_id)
    return result


async def query_sensors(*, page=1, size=RESOURCE_PAGE_SIZE, status=None, user_id: int, user_role: SystemUserRole) -> Page[ManagedHostSensorSchema]:
    async with get_async_session() as session:
        statement = select(ManagedHostSensor)
        if user_role != SystemUserRole.ADMIN:
            host_ids = select(DeceptionEnvironment.host_id).where(DeceptionEnvironment.owner_id == user_id)
            statement = statement.where(ManagedHostSensor.host_id.in_(host_ids))
        if status is not None:
            statement = statement.where(ManagedHostSensor.status == status)
        statement = statement.order_by(ManagedHostSensor.updated_at.desc())
        total = int((await session.execute(select(func.count()).select_from(statement.order_by(None).subquery()))).scalar_one())
        rows = list((await session.exec(statement.offset(page_offset(page, size)).limit(size))).all())
        items = [ManagedHostSensorSchema.model_validate(row) for row in rows]
    return Page(page=page, size=size, total=total, items=items)


async def create_rule(
    request: CreateDetectionRuleRequest,
    *,
    user_id: int,
    user_role: SystemUserRole,
    actor_type: AuditActorType = AuditActorType.USER,
    actor_code: str = "",
    source_session_id: str = "",
) -> tuple[DetectionRuleSchema, DetectionRuleVersionSchema]:
    async with get_async_session() as session, session.begin():
        await _require_scope_access(session, request.scope, request.host_id, request.environment_id, user_id, user_role)
        validation = validate_rule_content(request.type, request.content)
        rule = DetectionRule(
            name=request.name.strip(),
            description=request.description.strip(),
            type=request.type,
            origin=DetectionRuleOrigin.AGENT if actor_type == AuditActorType.AGENT else DetectionRuleOrigin.USER,
            scope=request.scope,
            host_id=request.host_id,
            environment_id=request.environment_id,
            created_by_actor_type=actor_type.value,
            created_by_actor_code=actor_code or str(user_id),
        )
        session.add(rule)
        await session.flush()
        version = DetectionRuleVersion(
            rule_id=rule.id,
            version=1,
            status=DetectionRuleVersionStatus.VALIDATED if validation["valid"] else DetectionRuleVersionStatus.VALIDATION_FAILED,
            content=request.content,
            content_sha256=_sha256(request.content),
            validation_result=validation,
            created_by_actor_type=actor_type.value,
            created_by_actor_code=actor_code or str(user_id),
            created_from_session_id=source_session_id,
            validated_at=datetime.now(),
        )
        session.add(version)
        await session.flush()
        await _audit_rule(session, rule, "Detection rule draft created.", actor_type, actor_code or str(user_id), source_session_id, {"version_id": version.id})
        return DetectionRuleSchema.model_validate(rule), DetectionRuleVersionSchema.model_validate(version)


async def create_rule_version(
    rule_id: int,
    *,
    parent_version_id: int | None,
    content: str,
    user_id: int,
    user_role: SystemUserRole,
    actor_type: AuditActorType = AuditActorType.USER,
    actor_code: str = "",
    source_session_id: str = "",
) -> DetectionRuleVersionSchema:
    async with get_async_session() as session, session.begin():
        rule = await _load_accessible_rule(session, rule_id, user_id, user_role, lock=True)
        parent = await session.get(DetectionRuleVersion, parent_version_id) if parent_version_id else None
        if parent is not None and parent.rule_id != rule_id:
            raise ValueError("parent version belongs to another rule")
        latest = (await session.exec(select(func.max(DetectionRuleVersion.version)).where(DetectionRuleVersion.rule_id == rule_id))).one() or 0
        validation = validate_rule_content(rule.type, content)
        version = DetectionRuleVersion(
            rule_id=rule_id,
            version=int(latest) + 1,
            parent_version_id=parent_version_id,
            status=DetectionRuleVersionStatus.VALIDATED if validation["valid"] else DetectionRuleVersionStatus.VALIDATION_FAILED,
            content=content,
            content_sha256=_sha256(content),
            validation_result=validation,
            created_by_actor_type=actor_type.value,
            created_by_actor_code=actor_code or str(user_id),
            created_from_session_id=source_session_id,
            validated_at=datetime.now(),
        )
        session.add(version)
        await session.flush()
        await _audit_rule(session, rule, "Detection rule version created.", actor_type, actor_code or str(user_id), source_session_id, {"version_id": version.id, "version": version.version})
        return DetectionRuleVersionSchema.model_validate(version)


async def validate_rule_version(
    rule_id: int,
    version_id: int,
    *,
    user_id: int,
    user_role: SystemUserRole,
    actor_type: AuditActorType = AuditActorType.USER,
    actor_code: str = "",
    source_session_id: str = "",
) -> DetectionRuleVersionSchema:
    async with get_async_session() as session, session.begin():
        rule = await _load_accessible_rule(session, rule_id, user_id, user_role)
        version = await _load_rule_version(session, rule_id, version_id, lock=True)
        validation = validate_rule_content(rule.type, version.content)
        version.validation_result = validation
        version.status = DetectionRuleVersionStatus.VALIDATED if validation["valid"] else DetectionRuleVersionStatus.VALIDATION_FAILED
        version.validated_at = datetime.now()
        session.add(version)
        await _audit_rule(
            session,
            rule,
            "Detection rule version validated.",
            actor_type,
            actor_code or str(user_id),
            source_session_id,
            {"version_id": version.id, "valid": validation["valid"]},
        )
        return DetectionRuleVersionSchema.model_validate(version)


async def replay_rule_version(
    rule_id: int,
    version_id: int,
    request: ReplayDetectionRuleRequest,
    *,
    user_id: int,
    user_role: SystemUserRole,
    actor_type: AuditActorType = AuditActorType.USER,
    actor_code: str = "",
    source_session_id: str = "",
) -> DetectionRuleVersionSchema:
    from service.detection.engine import replay_rule

    async with get_async_session() as session, session.begin():
        rule = await _load_accessible_rule(session, rule_id, user_id, user_role)
        version = await _load_rule_version(session, rule_id, version_id, lock=True)
        result = await replay_rule(session, rule, version, request.event_ids)
        version.replay_result = result
        session.add(version)
        await _audit_rule(
            session,
            rule,
            "Detection rule version replayed.",
            actor_type,
            actor_code or str(user_id),
            source_session_id,
            {"version_id": version.id, **result},
        )
        return DetectionRuleVersionSchema.model_validate(version)


async def submit_rule_change(
    rule_id: int,
    request: SubmitDetectionRuleChangeRequest,
    *,
    user_id: int,
    user_role: SystemUserRole,
    actor_type: AuditActorType = AuditActorType.USER,
    actor_code: str = "",
    source_session_id: str = "",
) -> DetectionRuleChangeRequestSchema:
    async with get_async_session() as session, session.begin():
        rule = await _load_accessible_rule(session, rule_id, user_id, user_role, lock=True)
        existing = (await session.exec(select(DetectionRuleChangeRequest).where(
            DetectionRuleChangeRequest.rule_id == rule_id,
            DetectionRuleChangeRequest.status.in_({
                DetectionRuleChangeStatus.PENDING_APPROVAL,
                DetectionRuleChangeStatus.DEPLOYING,
            }),
        ))).first()
        if existing is not None:
            raise ValueError("the rule already has an unresolved change request")
        version = None
        if request.rule_version_id is not None:
            version = await _load_rule_version(session, rule_id, request.rule_version_id)
        if request.action == DetectionRuleChangeAction.DISABLE:
            if rule.active_version_id is None:
                raise ValueError("the rule is not active")
            if version is not None:
                raise ValueError("disable actions cannot include a candidate version")
        else:
            if version is None:
                raise ValueError("this action requires a rule version")
            if version.status != DetectionRuleVersionStatus.VALIDATED:
                raise ValueError("only validated rule versions can be submitted")
        if request.action == DetectionRuleChangeAction.ACTIVATE and rule.active_version_id is not None:
            raise ValueError("an active rule must use replace or rollback")
        if request.action in {DetectionRuleChangeAction.REPLACE, DetectionRuleChangeAction.ROLLBACK} and rule.active_version_id is None:
            raise ValueError("an inactive rule must use activate")
        if request.action in {DetectionRuleChangeAction.REPLACE, DetectionRuleChangeAction.ROLLBACK}:
            active_version = await _load_rule_version(session, rule_id, rule.active_version_id)
            if version.id == active_version.id:
                raise ValueError("the candidate version is already active")
            if request.action == DetectionRuleChangeAction.ROLLBACK and version.version >= active_version.version:
                raise ValueError("rollback requires a validated version older than the active version")
        targets = sorted(set(request.target_sensor_ids))
        bundles = await build_effective_bundles(
            session,
            rule=rule,
            action=request.action,
            candidate_version=version,
            target_sensor_ids=targets,
        )
        await _persist_bundles(session, bundles.sensor_bundles)
        content_sha256 = version.content_sha256 if version else await _active_content_sha(session, rule)
        change = DetectionRuleChangeRequest(
            rule_id=rule_id,
            rule_version_id=version.id if version else None,
            action=request.action,
            status=DetectionRuleChangeStatus.PENDING_APPROVAL,
            content_sha256=content_sha256,
            scope=rule.scope,
            target_sensor_ids=targets,
            effective_bundle_hash=bundles.manifest_hash,
            reason=request.reason,
            requested_by_actor_type=actor_type.value,
            requested_by_actor_code=actor_code or str(user_id),
            requested_from_session_id=source_session_id,
        )
        session.add(change)
        await session.flush()
        await _audit_rule(session, rule, "Detection rule change submitted for user approval.", actor_type, actor_code or str(user_id), source_session_id, {"change_request_id": change.id, "action": change.action.value, "bundle_hash": change.effective_bundle_hash})
        return DetectionRuleChangeRequestSchema.model_validate(change)


async def decide_rule_change(
    change_id: int,
    *,
    decision: str,
    reason: str,
    user_id: int,
    user_role: SystemUserRole,
) -> DetectionRuleChangeRequestSchema:
    should_deploy = False
    async with get_async_session() as session, session.begin():
        change = (await session.exec(select(DetectionRuleChangeRequest).where(
            DetectionRuleChangeRequest.id == change_id,
        ).with_for_update())).one_or_none()
        if change is None:
            raise LookupError("detection rule change request not found")
        if change.status != DetectionRuleChangeStatus.PENDING_APPROVAL:
            raise ValueError("change request is not awaiting approval")
        rule = await _load_accessible_rule(session, change.rule_id, user_id, user_role, lock=True)
        await _require_approval_access(session, rule, user_id, user_role)
        if decision != "approve":
            change.status = DetectionRuleChangeStatus.REJECTED if decision == "reject" else DetectionRuleChangeStatus.CHANGES_REQUESTED
            change.decided_by_user_id = user_id
            change.decision_reason = reason
            change.decided_at = datetime.now()
            change.resolved_at = datetime.now()
            session.add(change)
            await _audit_rule(session, rule, f"Detection rule change {change.status.value}.", AuditActorType.USER, str(user_id), "", {"change_request_id": change.id, "reason": reason})
            return DetectionRuleChangeRequestSchema.model_validate(change)
        version = await _load_rule_version(session, rule.id, change.rule_version_id) if change.rule_version_id else None
        bundles = await build_effective_bundles(
            session,
            rule=rule,
            action=change.action,
            candidate_version=version,
            target_sensor_ids=change.target_sensor_ids,
        )
        if change.scope != rule.scope:
            raise ValueError("rule scope changed; submit a new approval request")
        if bundles.manifest_hash != change.effective_bundle_hash or (version and version.content_sha256 != change.content_sha256):
            raise ValueError("rule content, scope, targets, or effective bundle changed; submit a new approval request")
        await _persist_bundles(session, bundles.sensor_bundles)
        change.status = DetectionRuleChangeStatus.DEPLOYING
        change.decided_by_user_id = user_id
        change.decision_reason = reason
        change.decided_at = datetime.now()
        session.add(change)
        sensors = list((await session.exec(select(ManagedHostSensor).where(ManagedHostSensor.id.in_(change.target_sensor_ids)))).all())
        for sensor in sensors:
            bundle = bundles.sensor_bundles[sensor.id]
            sensor.desired_bundle_hash = bundle["bundle_hash"]
            session.add(sensor)
            session.add(DetectionRuleDeployment(
                change_request_id=change.id,
                sensor_id=sensor.id,
                status=DetectionRuleDeploymentStatus.PENDING,
                previous_bundle_hash=sensor.active_bundle_hash,
                target_bundle_hash=bundle["bundle_hash"],
                attempt=1,
            ))
        await _audit_rule(session, rule, "Detection rule change approved; deployment queued.", AuditActorType.USER, str(user_id), "", {"change_request_id": change.id, "bundle_hash": change.effective_bundle_hash})
        should_deploy = True
        result = DetectionRuleChangeRequestSchema.model_validate(change)
    if should_deploy:
        from service.detection.deployment import schedule_detection_deployment
        schedule_detection_deployment(change_id)
    return result


async def query_rules(*, page=1, size=RESOURCE_PAGE_SIZE, keyword="", type=None, scope=None, user_id: int, user_role: SystemUserRole) -> Page[DetectionRuleSchema]:
    async with get_async_session() as session:
        statement = select(DetectionRule)
        if user_role != SystemUserRole.ADMIN:
            environment_ids = select(DeceptionEnvironment.id).where(DeceptionEnvironment.owner_id == user_id)
            statement = statement.where(or_(
                DetectionRule.scope == DetectionRuleScope.GLOBAL,
                DetectionRule.environment_id.in_(environment_ids),
            ))
        if keyword.strip():
            pattern = f"%{keyword.strip()}%"
            statement = statement.where(or_(DetectionRule.name.ilike(pattern), DetectionRule.description.ilike(pattern)))
        if type is not None:
            statement = statement.where(DetectionRule.type == type)
        if scope is not None:
            statement = statement.where(DetectionRule.scope == scope)
        statement = statement.order_by(DetectionRule.updated_at.desc(), DetectionRule.id.desc())
        total = int((await session.execute(select(func.count()).select_from(statement.order_by(None).subquery()))).scalar_one())
        rows = list((await session.exec(statement.offset(page_offset(page, size)).limit(size))).all())
        items = [DetectionRuleSchema.model_validate(row) for row in rows]
    return Page(page=page, size=size, total=total, items=items)


async def query_rule_versions(rule_id: int, *, page=1, size=RESOURCE_PAGE_SIZE, user_id: int, user_role: SystemUserRole) -> Page[DetectionRuleVersionSchema]:
    async with get_async_session() as session:
        await _load_accessible_rule(session, rule_id, user_id, user_role)
        statement = select(DetectionRuleVersion).where(DetectionRuleVersion.rule_id == rule_id).order_by(DetectionRuleVersion.version.desc())
        total = int((await session.exec(select(func.count()).select_from(DetectionRuleVersion).where(DetectionRuleVersion.rule_id == rule_id))).one())
        rows = list((await session.exec(statement.offset(page_offset(page, size)).limit(size))).all())
        items = [DetectionRuleVersionSchema.model_validate(row) for row in rows]
    return Page(page=page, size=size, total=total, items=items)


async def query_rule_changes(*, page=1, size=RESOURCE_PAGE_SIZE, status=None, user_id: int, user_role: SystemUserRole) -> Page[DetectionRuleChangeRequestSchema]:
    async with get_async_session() as session:
        statement = select(DetectionRuleChangeRequest).join(DetectionRule, DetectionRule.id == DetectionRuleChangeRequest.rule_id)
        if user_role != SystemUserRole.ADMIN:
            environment_ids = select(DeceptionEnvironment.id).where(DeceptionEnvironment.owner_id == user_id)
            statement = statement.where(DetectionRule.environment_id.in_(environment_ids))
        if status is not None:
            statement = statement.where(DetectionRuleChangeRequest.status == status)
        statement = statement.order_by(DetectionRuleChangeRequest.created_at.desc())
        total = int((await session.execute(select(func.count()).select_from(statement.order_by(None).subquery()))).scalar_one())
        rows = list((await session.exec(statement.offset(page_offset(page, size)).limit(size))).all())
        items = [DetectionRuleChangeRequestSchema.model_validate(row) for row in rows]
    return Page(page=page, size=size, total=total, items=items)


async def query_deployments(change_id: int, *, page=1, size=RESOURCE_PAGE_SIZE, user_id: int, user_role: SystemUserRole) -> Page[DetectionRuleDeploymentSchema]:
    async with get_async_session() as session:
        change = await session.get(DetectionRuleChangeRequest, change_id)
        if change is None:
            raise LookupError("detection rule change request not found")
        await _load_accessible_rule(session, change.rule_id, user_id, user_role)
        statement = select(DetectionRuleDeployment).where(DetectionRuleDeployment.change_request_id == change_id).order_by(DetectionRuleDeployment.id.asc())
        total = int((await session.exec(select(func.count()).select_from(DetectionRuleDeployment).where(DetectionRuleDeployment.change_request_id == change_id))).one())
        rows = list((await session.exec(statement.offset(page_offset(page, size)).limit(size))).all())
        items = [DetectionRuleDeploymentSchema.model_validate(row) for row in rows]
    return Page(page=page, size=size, total=total, items=items)


async def _load_accessible_rule(session, rule_id: int, user_id: int, user_role: SystemUserRole, lock: bool = False) -> DetectionRule:
    statement = select(DetectionRule).where(DetectionRule.id == rule_id)
    if lock:
        statement = statement.with_for_update()
    rule = (await session.exec(statement)).one_or_none()
    if rule is None:
        raise LookupError("detection rule not found")
    if user_role == SystemUserRole.ADMIN or rule.scope == DetectionRuleScope.GLOBAL:
        return rule
    if rule.scope != DetectionRuleScope.ENVIRONMENT or rule.environment_id is None:
        raise PermissionError("detection rule is not accessible by user")
    environment = await session.get(DeceptionEnvironment, rule.environment_id)
    if environment is None or environment.owner_id != user_id:
        raise PermissionError("detection rule is not accessible by user")
    return rule


async def _require_scope_access(session, scope, host_id, environment_id, user_id, user_role):
    if scope == DetectionRuleScope.GLOBAL:
        if host_id is not None or environment_id is not None:
            raise ValueError("global rules cannot specify host or environment")
        if user_role != SystemUserRole.ADMIN:
            raise PermissionError("global rules require administrator access")
        return
    if scope == DetectionRuleScope.HOST:
        if host_id is None or environment_id is not None:
            raise ValueError("host rules require exactly one host")
        if user_role != SystemUserRole.ADMIN:
            raise PermissionError("host rules require administrator access")
        if await session.get(ManagedHost, host_id) is None:
            raise LookupError("managed host not found")
        return
    if environment_id is None or host_id is not None:
        raise ValueError("environment rules require exactly one environment")
    environment = await session.get(DeceptionEnvironment, environment_id)
    if environment is None:
        raise LookupError("deception environment not found")
    if user_role != SystemUserRole.ADMIN and environment.owner_id != user_id:
        raise PermissionError("deception environment is not accessible by user")


async def _require_approval_access(session, rule, user_id, user_role):
    if rule.origin == DetectionRuleOrigin.BUILTIN or rule.scope in {DetectionRuleScope.GLOBAL, DetectionRuleScope.HOST}:
        if user_role != SystemUserRole.ADMIN:
            raise PermissionError("this rule change requires administrator approval")
        return
    await _load_accessible_rule(session, rule.id, user_id, user_role)


async def _load_rule_version(session, rule_id, version_id, lock=False):
    statement = select(DetectionRuleVersion).where(
        DetectionRuleVersion.id == version_id,
        DetectionRuleVersion.rule_id == rule_id,
    )
    if lock:
        statement = statement.with_for_update()
    version = (await session.exec(statement)).one_or_none()
    if version is None:
        raise LookupError("detection rule version not found")
    return version


async def _active_content_sha(session, rule):
    if rule.active_version_id is None:
        return ""
    version = await session.get(DetectionRuleVersion, rule.active_version_id)
    return version.content_sha256 if version else ""


async def _persist_bundles(session, bundles: dict[int, dict]) -> None:
    for bundle in bundles.values():
        bundle_hash = bundle["bundle_hash"]
        if await session.get(DetectionBundle, bundle_hash) is None:
            session.add(DetectionBundle(bundle_hash=bundle_hash, content=bundle))


async def _audit_rule(session, rule, summary, actor_type, actor_code, source_session_id, details):
    await add_audit_event(
        session,
        detection_rule_id=rule.id,
        environment_id=rule.environment_id,
        kind=AuditEventKind.DETECTION,
        actor_type=actor_type,
        actor_code=actor_code,
        session_id=source_session_id,
        object_type="detection_rule",
        object_id=rule.id,
        summary=summary,
        details=details,
    )


def _sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()
