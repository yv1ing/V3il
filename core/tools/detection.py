from __future__ import annotations

import difflib
import json

from agents import RunContextWrapper, function_tool
from sqlmodel import select

from core.runtime.context import AgentRuntimeContext
from core.tools.investigation import investigation_error, investigation_success
from database import get_async_session
from model.deception.environments import DeceptionEnvironment
from model.detection.rules import (
    BehaviorDecision,
    DetectionRule,
    DetectionRuleChangeRequest,
    DetectionRuleDeployment,
    DetectionRuleVersion,
)
from model.threat.behaviors import BehaviorEvent
from schema.detection.rules import (
    CentralRuleDefinition,
    CreateDetectionRuleRequest,
    DetectionRuleChangeAction,
    DetectionRuleChangeRequestSchema,
    DetectionRuleDeploymentSchema,
    DetectionRuleOrigin,
    DetectionRuleScope,
    DetectionRuleSchema,
    DetectionRuleType,
    DetectionRuleVersionSchema,
    ManagedHostSensorSchema,
    ReplayDetectionRuleRequest,
    SubmitDetectionRuleChangeRequest,
    SuppressionRuleDefinition,
)
from schema.threat.investigations import AuditActorType
from service.detection.rules import (
    create_rule,
    create_rule_version,
    query_rule_versions,
    query_rules,
    query_sensors,
    replay_rule_version,
    submit_rule_change,
    validate_rule_version,
)


@function_tool
async def list_detection_rules(
    ctx: RunContextWrapper[AgentRuntimeContext],
    page: int = 1,
    rule_type: DetectionRuleType | None = None,
    scope: DetectionRuleScope | None = None,
) -> str:
    """List built-in and custom detection rules visible to the current operator.

    Args:
        page: Positive result page number; each page contains at most 50 rules.
        rule_type: Optional Zeek script, Zeek signature, central rule, or suppression filter.
        scope: Optional global, Managed Host, or deception-environment scope filter.

    Returns:
        JSON tool result containing visible logical rules and active version IDs,
        or an access/query error. This tool never changes rule state.
    """
    try:
        result = await query_rules(
            page=max(page, 1),
            size=50,
            type=rule_type,
            scope=scope,
            user_id=ctx.context.user.id,
            user_role=ctx.context.user.role,
        )
        return investigation_success({
            "page": result.page,
            "total": result.total,
            "items": [DetectionRuleSchema.model_validate(item).model_dump(mode="json") for item in result.items],
        })
    except Exception as exc:
        return investigation_error(str(exc) or "Detection rules could not be listed.")


@function_tool
async def list_detection_sensors(ctx: RunContextWrapper[AgentRuntimeContext]) -> str:
    """List visible Zeek Sensors and IDs for an exact rule activation proposal.

    Args:
        None. Visibility is derived from the current operator and Agent session.

    Returns:
        JSON tool result containing visible Sensor IDs, Managed Host bindings,
        health, and Bundle state. It exposes no deployment capability.
    """
    try:
        result = await query_sensors(
            page=1,
            size=100,
            user_id=ctx.context.user.id,
            user_role=ctx.context.user.role,
        )
        return investigation_success({
            "items": [ManagedHostSensorSchema.model_validate(item).model_dump(mode="json") for item in result.items]
        })
    except Exception as exc:
        return investigation_error(str(exc) or "Detection Sensors could not be listed.")


@function_tool
async def read_detection_rule_version(
    ctx: RunContextWrapper[AgentRuntimeContext],
    rule_id: int,
    version_id: int | None = None,
) -> str:
    """Read one immutable version of a visible detection rule.

    Args:
        rule_id: Positive logical detection rule identifier.
        version_id: Optional immutable version identifier; omit to read the latest version.

    Returns:
        JSON tool result containing content, SHA-256, validation and replay metadata,
        or an error when the rule/version is unavailable.
    """
    try:
        result = await query_rule_versions(
            rule_id,
            page=1,
            size=100,
            user_id=ctx.context.user.id,
            user_role=ctx.context.user.role,
        )
        version = next((item for item in result.items if version_id is None or item.id == version_id), None)
        if version is None:
            return investigation_error("Detection rule version not found.")
        return investigation_success({"version": DetectionRuleVersionSchema.model_validate(version).model_dump(mode="json")})
    except Exception as exc:
        return investigation_error(str(exc) or "Detection rule version could not be read.")


@function_tool
async def create_zeek_script_draft(
    ctx: RunContextWrapper[AgentRuntimeContext],
    name: str,
    content: str,
    scope: DetectionRuleScope,
    description: str = "",
    host_id: int | None = None,
    environment_id: int | None = None,
) -> str:
    """Create a new Zeek script draft and run initial safety validation.

    Args:
        name: Human-readable logical rule name.
        content: Complete Zeek script source.
        scope: Global, Managed Host, or deception-environment scope.
        description: Optional operator-facing purpose and expected behavior.
        host_id: Required only for Host scope.
        environment_id: Required only for environment scope.

    Returns:
        JSON tool result containing the logical rule and immutable draft version.
        Creating the draft never approves, enables, or deploys it.
    """
    return await _create_draft(ctx, name, description, DetectionRuleType.ZEEK_SCRIPT, scope, content, host_id, environment_id)


@function_tool
async def create_zeek_signature_draft(
    ctx: RunContextWrapper[AgentRuntimeContext],
    name: str,
    content: str,
    scope: DetectionRuleScope,
    description: str = "",
    host_id: int | None = None,
    environment_id: int | None = None,
) -> str:
    """Create a new Zeek signature draft and run initial safety validation.

    Args:
        name: Human-readable logical rule name.
        content: Complete Zeek signature source.
        scope: Global, Managed Host, or deception-environment scope.
        description: Optional operator-facing purpose and expected behavior.
        host_id: Required only for Host scope.
        environment_id: Required only for environment scope.

    Returns:
        JSON tool result containing the logical rule and immutable draft version.
        Creating the draft never approves, enables, or deploys it.
    """
    return await _create_draft(ctx, name, description, DetectionRuleType.ZEEK_SIGNATURE, scope, content, host_id, environment_id)


@function_tool
async def create_central_detection_rule_draft(
    ctx: RunContextWrapper[AgentRuntimeContext],
    name: str,
    definition: CentralRuleDefinition,
    scope: DetectionRuleScope,
    description: str = "",
    host_id: int | None = None,
    environment_id: int | None = None,
) -> str:
    """Create a deterministic central behavior-classification rule draft.

    Args:
        name: Human-readable logical rule name.
        definition: Validated conditions, score, threshold, windows, grouping and rationale.
        scope: Global, Managed Host, or deception-environment scope.
        description: Optional operator-facing purpose and expected behavior.
        host_id: Required only for Host scope.
        environment_id: Required only for environment scope.

    Returns:
        JSON tool result containing the logical rule and immutable draft version.
        The rule remains inactive until an exact user-approved change is deployed.
    """
    content = json.dumps(definition.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, indent=2)
    return await _create_draft(ctx, name, description, DetectionRuleType.CENTRAL_RULE, scope, content, host_id, environment_id)


@function_tool
async def create_suppression_rule_draft(
    ctx: RunContextWrapper[AgentRuntimeContext],
    name: str,
    definition: SuppressionRuleDefinition,
    scope: DetectionRuleScope,
    description: str = "",
    host_id: int | None = None,
    environment_id: int | None = None,
) -> str:
    """Create a deterministic, explicitly targeted suppression-rule draft.

    Args:
        name: Human-readable logical rule name.
        definition: Target rule IDs, matching conditions, and suppression reason.
        scope: Global, Managed Host, or deception-environment scope.
        description: Optional operator-facing purpose and expected behavior.
        host_id: Required only for Host scope.
        environment_id: Required only for environment scope.

    Returns:
        JSON tool result containing the logical rule and immutable draft version.
        The suppression remains inactive and cannot silently change live detection.
    """
    content = json.dumps(definition.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, indent=2)
    return await _create_draft(ctx, name, description, DetectionRuleType.SUPPRESSION, scope, content, host_id, environment_id)


@function_tool
async def update_rule_draft(
    ctx: RunContextWrapper[AgentRuntimeContext],
    rule_id: int,
    content: str,
    parent_version_id: int | None = None,
) -> str:
    """Create a new immutable version of an existing or built-in rule.

    Args:
        rule_id: Positive logical detection rule identifier.
        content: Complete replacement content; existing versions are never modified in place.
        parent_version_id: Optional parent version used to record derivation and comparison.

    Returns:
        JSON tool result containing the newly validated or validation-failed version.
        This operation never changes the active version.
    """
    try:
        version = await create_rule_version(
            rule_id,
            parent_version_id=parent_version_id,
            content=content,
            user_id=ctx.context.user.id,
            user_role=ctx.context.user.role,
            actor_type=AuditActorType.AGENT,
            actor_code=ctx.context.agent_code,
            source_session_id=ctx.context.session_id,
        )
        return investigation_success({"version": DetectionRuleVersionSchema.model_validate(version).model_dump(mode="json")})
    except Exception as exc:
        return investigation_error(str(exc) or "Detection rule draft could not be updated.")


@function_tool
async def validate_rule_draft(ctx: RunContextWrapper[AgentRuntimeContext], rule_id: int, version_id: int) -> str:
    """Run deterministic static safety validation for an immutable draft.

    Args:
        rule_id: Positive logical detection rule identifier.
        version_id: Positive immutable version identifier belonging to the rule.

    Returns:
        JSON tool result containing the version and structured validation result.
        Zeek syntax is compiled later by the isolated target Sensor before activation;
        this tool does not approve, activate, or deploy the content.
    """
    try:
        version = await validate_rule_version(
            rule_id,
            version_id,
            user_id=ctx.context.user.id,
            user_role=ctx.context.user.role,
            actor_type=AuditActorType.AGENT,
            actor_code=ctx.context.agent_code,
            source_session_id=ctx.context.session_id,
        )
        return investigation_success({"version": DetectionRuleVersionSchema.model_validate(version).model_dump(mode="json")})
    except Exception as exc:
        return investigation_error(str(exc) or "Detection rule validation failed.")


@function_tool
async def replay_rule_draft(
    ctx: RunContextWrapper[AgentRuntimeContext],
    rule_id: int,
    version_id: int,
    event_ids: list[int],
) -> str:
    """Replay a draft against selected historical behavior events offline.

    Args:
        rule_id: Positive logical detection rule identifier.
        version_id: Positive immutable version identifier belonging to the rule.
        event_ids: Positive historical BehaviorEvent IDs to evaluate.

    Returns:
        JSON tool result containing bounded match statistics on the immutable version.
        Replay Decisions are non-live and can never create Signals, Incidents, or Agent wakes.
    """
    try:
        version = await replay_rule_version(
            rule_id,
            version_id,
            ReplayDetectionRuleRequest(event_ids=event_ids),
            user_id=ctx.context.user.id,
            user_role=ctx.context.user.role,
            actor_type=AuditActorType.AGENT,
            actor_code=ctx.context.agent_code,
            source_session_id=ctx.context.session_id,
        )
        return investigation_success({"version": DetectionRuleVersionSchema.model_validate(version).model_dump(mode="json")})
    except Exception as exc:
        return investigation_error(str(exc) or "Detection rule replay failed.")


@function_tool
async def compare_rule_versions(
    ctx: RunContextWrapper[AgentRuntimeContext],
    rule_id: int,
    base_version_id: int,
    candidate_version_id: int,
) -> str:
    """Compare two immutable versions of the same detection rule.

    Args:
        rule_id: Positive logical detection rule identifier.
        base_version_id: Immutable version used as the unified-diff base.
        candidate_version_id: Immutable version compared with the base.

    Returns:
        JSON tool result containing a bounded unified diff and truncation flag,
        or an error when either version does not belong to the rule.
    """
    try:
        result = await query_rule_versions(rule_id, page=1, size=100, user_id=ctx.context.user.id, user_role=ctx.context.user.role)
        by_id = {item.id: item for item in result.items}
        base, candidate = by_id.get(base_version_id), by_id.get(candidate_version_id)
        if base is None or candidate is None:
            return investigation_error("Both versions must belong to the selected rule.")
        diff = "".join(difflib.unified_diff(
            base.content.splitlines(keepends=True),
            candidate.content.splitlines(keepends=True),
            fromfile=f"v{base.version}",
            tofile=f"v{candidate.version}",
        ))
        return investigation_success({"diff": diff[:100_000], "truncated": len(diff) > 100_000})
    except Exception as exc:
        return investigation_error(str(exc) or "Detection rule versions could not be compared.")


@function_tool
async def submit_rule_for_approval(
    ctx: RunContextWrapper[AgentRuntimeContext],
    rule_id: int,
    action: DetectionRuleChangeAction,
    target_sensor_ids: list[int],
    reason: str,
    rule_version_id: int | None = None,
) -> str:
    """Submit an exact detection-rule change for explicit user approval.

    Args:
        rule_id: Positive logical detection rule identifier.
        action: Activate, replace, disable, or rollback action being proposed.
        target_sensor_ids: Exact positive Sensor IDs covered by the proposal.
        reason: Evidence-backed operational reason for the change.
        rule_version_id: Required immutable version for every action except disable.

    Returns:
        JSON tool result containing the pending request, content SHA-256, scope,
        target Sensors and effective Bundle Hash. This tool cannot approve or deploy it.
    """
    try:
        change = await submit_rule_change(
            rule_id,
            SubmitDetectionRuleChangeRequest(
                action=action,
                rule_version_id=rule_version_id,
                target_sensor_ids=target_sensor_ids,
                reason=reason,
            ),
            user_id=ctx.context.user.id,
            user_role=ctx.context.user.role,
            actor_type=AuditActorType.AGENT,
            actor_code=ctx.context.agent_code,
            source_session_id=ctx.context.session_id,
        )
        return investigation_success({"change_request": DetectionRuleChangeRequestSchema.model_validate(change).model_dump(mode="json")})
    except Exception as exc:
        return investigation_error(str(exc) or "Detection rule change could not be submitted.")


@function_tool
async def read_rule_approval(ctx: RunContextWrapper[AgentRuntimeContext], change_request_id: int) -> str:
    """Read the user-approval state of a visible detection-rule change.

    Args:
        change_request_id: Positive rule change request identifier.

    Returns:
        JSON tool result containing the immutable approval binding and current state,
        or an access/not-found error. This tool cannot record a decision.
    """
    try:
        async with get_async_session() as session:
            change = await session.get(DetectionRuleChangeRequest, change_request_id)
            if change is None or not await _can_read_rule(session, change.rule_id, ctx.context):
                return investigation_error("Detection rule change request not found.")
        return investigation_success({"change_request": DetectionRuleChangeRequestSchema.model_validate(change).model_dump(mode="json")})
    except Exception as exc:
        return investigation_error(str(exc) or "Detection rule approval could not be read.")


@function_tool
async def read_rule_deployment(ctx: RunContextWrapper[AgentRuntimeContext], change_request_id: int) -> str:
    """Read per-Sensor deployment results for an approved rule change.

    Args:
        change_request_id: Positive approved rule change request identifier.

    Returns:
        JSON tool result containing target Bundle, attempt, health and rollback states.
        This read-only tool cannot deploy, disable, activate, or roll back a rule.
    """
    try:
        async with get_async_session() as session:
            change = await session.get(DetectionRuleChangeRequest, change_request_id)
            if change is None or not await _can_read_rule(session, change.rule_id, ctx.context):
                return investigation_error("Detection rule change request not found.")
            rows = list((await session.exec(select(DetectionRuleDeployment).where(
                DetectionRuleDeployment.change_request_id == change_request_id,
            ).order_by(DetectionRuleDeployment.id.asc()))).all())
        return investigation_success({"deployments": [DetectionRuleDeploymentSchema.model_validate(item).model_dump(mode="json") for item in rows]})
    except Exception as exc:
        return investigation_error(str(exc) or "Detection rule deployment could not be read.")


@function_tool
async def analyze_rule_matches(
    ctx: RunContextWrapper[AgentRuntimeContext],
    rule_id: int,
    limit: int = 100,
) -> str:
    """Summarize recent online Decisions that matched a visible rule.

    Args:
        rule_id: Positive logical detection rule identifier.
        limit: Maximum returned matches, bounded to 1 through 500.

    Returns:
        JSON tool result containing Decision, BehaviorEvent, environment, score,
        suppression and version provenance for evidence-backed rule tuning.
    """
    try:
        async with get_async_session() as session:
            if not await _can_read_rule(session, rule_id, ctx.context):
                return investigation_error("Detection rule not found.")
            statement = select(BehaviorDecision, BehaviorEvent).join(
                BehaviorEvent, BehaviorEvent.id == BehaviorDecision.event_id,
            ).join(DeceptionEnvironment, DeceptionEnvironment.id == BehaviorEvent.environment_id)
            if ctx.context.user.role.value != "admin":
                statement = statement.where(DeceptionEnvironment.owner_id == ctx.context.user.id)
            rows = list((await session.exec(statement.order_by(BehaviorDecision.created_at.desc()).limit(1000))).all())
        items = []
        for decision, event in rows:
            match = next((item for item in decision.matched_rule_versions if item.get("rule_id") == rule_id), None)
            if match is None:
                continue
            items.append({
                "decision_id": decision.id,
                "event_id": event.id,
                "environment_id": event.environment_id,
                "observed_at": event.observed_at,
                "classification": decision.classification.value,
                "score": decision.score,
                "suppressed": bool(match.get("suppressed")),
                "rule_version_id": match.get("version_id"),
            })
            if len(items) >= max(1, min(limit, 500)):
                break
        return investigation_success({"matches": items, "count": len(items)})
    except Exception as exc:
        return investigation_error(str(exc) or "Detection rule matches could not be analyzed.")


async def _create_draft(ctx, name, description, rule_type, scope, content, host_id, environment_id):
    try:
        rule, version = await create_rule(
            CreateDetectionRuleRequest(
                name=name,
                description=description,
                type=rule_type,
                scope=scope,
                host_id=host_id,
                environment_id=environment_id,
                content=content,
            ),
            user_id=ctx.context.user.id,
            user_role=ctx.context.user.role,
            actor_type=AuditActorType.AGENT,
            actor_code=ctx.context.agent_code,
            source_session_id=ctx.context.session_id,
        )
        return investigation_success({
            "rule": DetectionRuleSchema.model_validate(rule).model_dump(mode="json"),
            "version": DetectionRuleVersionSchema.model_validate(version).model_dump(mode="json"),
        })
    except Exception as exc:
        return investigation_error(str(exc) or "Detection rule draft could not be created.")


async def _can_read_rule(session, rule_id: int, context: AgentRuntimeContext) -> bool:
    rule = await session.get(DetectionRule, rule_id)
    if rule is None:
        return False
    if context.user.role.value == "admin" or rule.scope == DetectionRuleScope.GLOBAL:
        return True
    if rule.scope != DetectionRuleScope.ENVIRONMENT or rule.environment_id is None:
        return False
    environment = await session.get(DeceptionEnvironment, rule.environment_id)
    return environment is not None and environment.owner_id == context.user.id
