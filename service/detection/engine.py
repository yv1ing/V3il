from __future__ import annotations

import json
import hashlib
from collections import Counter
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Any

import regex
from sqlalchemy import func, or_, text
from sqlmodel import select

from database import get_async_session
from model.deception.environments import DeceptionEnvironment
from model.detection.rules import (
    BehaviorDecision,
    BehaviorSignal,
    BehaviorSignalEvent,
    DetectionBundle,
    DetectionRule,
    DetectionRuleVersion,
)
from model.threat.behaviors import BehaviorEvent
from schema.detection.rules import (
    BehaviorClassification,
    BehaviorDecisionMode,
    BehaviorDecisionSchema,
    BehaviorSignalSchema,
    BehaviorSignalStatus,
    CentralRuleDefinition,
    DetectionRuleScope,
    DetectionRuleType,
    SuppressionRuleDefinition,
)
from schema.system_user.users import SystemUserRole
from service.common.pagination import Page, RESOURCE_PAGE_SIZE, page_offset
from service.detection.validation import parsed_rule_content


_CLASSIFICATION_ORDER = {
    BehaviorClassification.EXPECTED: 0,
    BehaviorClassification.CONTEXTUAL: 1,
    BehaviorClassification.SUSPICIOUS: 2,
    BehaviorClassification.MALICIOUS: 3,
}
_SIGNAL_AGGREGATION_LOCK_NAMESPACE = 1_696_522_785


async def process_behavior_events(environment_id: int, event_ids: list[int]) -> list[int]:
    actionable: set[int] = set()
    for event_id in dict.fromkeys(event_ids):
        async with get_async_session() as session, session.begin():
            event = (await session.exec(select(BehaviorEvent).where(
                BehaviorEvent.id == event_id,
                BehaviorEvent.environment_id == environment_id,
            ).with_for_update())).one_or_none()
            if event is None:
                continue
            existing = (await session.exec(select(BehaviorDecision).where(
                BehaviorDecision.event_id == event_id,
                BehaviorDecision.mode == BehaviorDecisionMode.LIVE,
            ))).first()
            if existing is not None:
                linked = list((await session.exec(select(BehaviorSignalEvent.signal_id).where(
                    BehaviorSignalEvent.decision_id == existing.id,
                ))).all())
                actionable.update(linked)
                continue
            decision, selected = await _evaluate_event(session, event, mode=BehaviorDecisionMode.LIVE)
            session.add(decision)
            await session.flush()
            if selected is None or decision.score < 40:
                continue
            signal, threshold_reached = await _aggregate_signal(session, event, decision, selected)
            if threshold_reached and signal.id is not None:
                actionable.add(signal.id)
    return sorted(actionable)


async def replay_rule(session, rule: DetectionRule, version: DetectionRuleVersion, event_ids: list[int]) -> dict[str, Any]:
    if rule.type not in {DetectionRuleType.CENTRAL_RULE, DetectionRuleType.SUPPRESSION}:
        return {"evaluated": 0, "matched": 0, "note": "PCAP validation is completed by the Zeek deployment validator."}
    events = list((await session.exec(select(BehaviorEvent).where(BehaviorEvent.id.in_(list(dict.fromkeys(event_ids)))))).all())
    matched = 0
    score_counts: Counter[str] = Counter()
    if rule.type == DetectionRuleType.CENTRAL_RULE:
        definition = CentralRuleDefinition.model_validate(parsed_rule_content(rule.type, version.content))
        for event in events:
            if _rule_matches(definition.all, definition.any, event):
                matched += 1
                score_counts[definition.classification.value] += 1
    else:
        definition = SuppressionRuleDefinition.model_validate(parsed_rule_content(rule.type, version.content))
        for event in events:
            if _rule_matches(definition.all, [], event):
                matched += 1
    return {
        "evaluated": len(events),
        "matched": matched,
        "classifications": dict(score_counts),
        "replay_only": True,
    }


async def query_decisions(*, page=1, size=RESOURCE_PAGE_SIZE, classification=None, environment_id=None, user_id: int, user_role: SystemUserRole) -> Page[BehaviorDecisionSchema]:
    async with get_async_session() as session:
        statement = select(BehaviorDecision).join(BehaviorEvent, BehaviorEvent.id == BehaviorDecision.event_id).join(
            DeceptionEnvironment, DeceptionEnvironment.id == BehaviorEvent.environment_id,
        )
        if user_role != SystemUserRole.ADMIN:
            statement = statement.where(DeceptionEnvironment.owner_id == user_id)
        if environment_id is not None:
            statement = statement.where(BehaviorEvent.environment_id == environment_id)
        if classification is not None:
            statement = statement.where(BehaviorDecision.classification == classification)
        statement = statement.order_by(BehaviorDecision.created_at.desc())
        total = int((await session.execute(select(func.count()).select_from(statement.order_by(None).subquery()))).scalar_one())
        rows = list((await session.exec(statement.offset(page_offset(page, size)).limit(size))).all())
        items = [BehaviorDecisionSchema.model_validate(row) for row in rows]
    return Page(page=page, size=size, total=total, items=items)


async def query_signals(*, page=1, size=RESOURCE_PAGE_SIZE, status=None, environment_id=None, user_id: int, user_role: SystemUserRole) -> Page[BehaviorSignalSchema]:
    async with get_async_session() as session:
        statement = select(BehaviorSignal).join(DeceptionEnvironment, DeceptionEnvironment.id == BehaviorSignal.environment_id)
        if user_role != SystemUserRole.ADMIN:
            statement = statement.where(DeceptionEnvironment.owner_id == user_id)
        if environment_id is not None:
            statement = statement.where(BehaviorSignal.environment_id == environment_id)
        if status is not None:
            statement = statement.where(BehaviorSignal.status == status)
        statement = statement.order_by(BehaviorSignal.updated_at.desc())
        total = int((await session.execute(select(func.count()).select_from(statement.order_by(None).subquery()))).scalar_one())
        rows = list((await session.exec(statement.offset(page_offset(page, size)).limit(size))).all())
        items = [BehaviorSignalSchema.model_validate(row) for row in rows]
    return Page(page=page, size=size, total=total, items=items)


async def _evaluate_event(session, event: BehaviorEvent, *, mode: BehaviorDecisionMode):
    central, suppressions = await _load_effective_rules(session, event)
    matches: list[tuple[DetectionRule, DetectionRuleVersion, CentralRuleDefinition]] = []
    for rule, version in central:
        definition = CentralRuleDefinition.model_validate(parsed_rule_content(rule.type, version.content))
        if _rule_matches(definition.all, definition.any, event):
            matches.append((rule, version, definition))
    suppressed_versions: list[int] = []
    suppressed_rule_ids: set[int] = set()
    matched_rule_ids = {rule.id for rule, _, _ in matches}
    for _, version in suppressions:
        definition = SuppressionRuleDefinition.model_validate(parsed_rule_content(DetectionRuleType.SUPPRESSION, version.content))
        if matched_rule_ids.intersection(definition.target_rule_ids) and _rule_matches(definition.all, [], event):
            suppressed_rule_ids.update(definition.target_rule_ids)
            if version.id is not None:
                suppressed_versions.append(version.id)
    effective = [item for item in matches if item[0].id not in suppressed_rule_ids]
    effective.sort(key=lambda item: (item[2].score, _CLASSIFICATION_ORDER[item[2].classification], item[1].version), reverse=True)
    selected = effective[0] if effective else None
    if selected is None:
        classification = BehaviorClassification.CONTEXTUAL
        score = 0
        signal_kind = ""
        material = False
        reason = "Matching detection rules were suppressed." if matches else "No active detection rule matched the event."
    else:
        _, _, definition = selected
        classification = definition.classification
        score = definition.score
        signal_kind = definition.signal_kind
        material = definition.material
        reason = definition.reason
    matched_versions = [
        {
            "rule_id": rule.id,
            "version_id": version.id,
            "content_sha256": version.content_sha256,
            "score": definition.score,
            "classification": definition.classification.value,
            "suppressed": rule.id in suppressed_rule_ids,
        }
        for rule, version, definition in matches
    ]
    decision = BehaviorDecision(
        event_id=event.id,
        mode=mode,
        bundle_hash=event.sensor_bundle_hash or "active-control-plane",
        classification=classification,
        score=score,
        signal_kind=signal_kind,
        reason=reason,
        matched_rule_versions=matched_versions,
        suppression_rule_versions=suppressed_versions,
        material=material,
    )
    return decision, selected


async def _load_effective_rules(session, event: BehaviorEvent):
    entries: list[dict[str, Any]] | None = None
    if event.sensor_bundle_hash:
        bundle = await session.get(DetectionBundle, event.sensor_bundle_hash)
        if bundle is not None:
            entries = bundle.content.get("rules") if isinstance(bundle.content, dict) else None
    if isinstance(entries, list):
        version_ids = [item.get("version_id") for item in entries if isinstance(item, dict) and isinstance(item.get("version_id"), int)]
        versions = list((await session.exec(select(DetectionRuleVersion).where(DetectionRuleVersion.id.in_(version_ids)))).all()) if version_ids else []
        version_by_id = {version.id: version for version in versions}
        rule_ids = [version.rule_id for version in versions]
        rules = list((await session.exec(select(DetectionRule).where(DetectionRule.id.in_(rule_ids)))).all()) if rule_ids else []
        rule_by_id = {rule.id: rule for rule in rules}
        pairs = [(rule_by_id[version.rule_id], version) for version in versions if version.rule_id in rule_by_id]
    else:
        environment = await session.get(DeceptionEnvironment, event.environment_id)
        statement = select(DetectionRule, DetectionRuleVersion).join(
            DetectionRuleVersion, DetectionRuleVersion.id == DetectionRule.active_version_id,
        ).where(or_(
            DetectionRule.scope == DetectionRuleScope.GLOBAL,
            DetectionRule.environment_id == event.environment_id,
            DetectionRule.host_id == (environment.host_id if environment else -1),
        ))
        pairs = list((await session.exec(statement)).all())
    central = [(rule, version) for rule, version in pairs if rule.type == DetectionRuleType.CENTRAL_RULE]
    suppressions = [(rule, version) for rule, version in pairs if rule.type == DetectionRuleType.SUPPRESSION]
    return central, suppressions


async def _aggregate_signal(session, event, decision, selected):
    _, version, definition = selected
    group_values = [str(_field_value(event, field) or "") for field in definition.group_by]
    aggregation_key = json.dumps(
        {"rule_version_id": version.id, "group": group_values},
        sort_keys=True,
        separators=(",", ":"),
    )
    aggregation_lock_key = int.from_bytes(
        hashlib.sha256(f"{event.environment_id}:{aggregation_key}".encode("utf-8")).digest()[:4],
        "big",
        signed=True,
    )
    await session.execute(
        text("SELECT pg_advisory_xact_lock(:namespace, :aggregation_key)"),
        {
            "namespace": _SIGNAL_AGGREGATION_LOCK_NAMESPACE,
            "aggregation_key": aggregation_lock_key,
        },
    )
    window_start = event.observed_at - timedelta(seconds=definition.window_seconds)
    signal = (await session.exec(select(BehaviorSignal).where(
        BehaviorSignal.environment_id == event.environment_id,
        BehaviorSignal.aggregation_key == aggregation_key,
        BehaviorSignal.last_observed_at >= window_start,
        BehaviorSignal.first_observed_at <= event.observed_at + timedelta(seconds=definition.window_seconds),
        BehaviorSignal.status != BehaviorSignalStatus.CLOSED,
    ).order_by(BehaviorSignal.updated_at.desc()).with_for_update())).first()
    now = datetime.now()
    if (
        signal is not None
        and signal.status == BehaviorSignalStatus.NOTIFIED
        and (signal.cooldown_until is None or signal.cooldown_until <= now)
    ):
        signal = None
    correlation_keys = [
        f"{field}:{_field_value(event, field)}"
        for field in definition.correlation_fields
        if _field_value(event, field) not in {None, ""}
    ]
    if signal is None:
        signal = BehaviorSignal(
            environment_id=event.environment_id,
            aggregation_key=aggregation_key,
            kind=definition.signal_kind,
            classification=definition.classification,
            score=definition.score,
            correlation_keys=correlation_keys,
            event_count=0,
            threshold_count=0,
            distinct_keys=[],
            threshold=definition.threshold,
            status=BehaviorSignalStatus.OPEN,
            first_observed_at=event.observed_at,
            last_observed_at=event.observed_at,
            debounce_until=now + timedelta(seconds=15) if definition.score < 70 else now,
            cooldown_until=now + timedelta(seconds=definition.cooldown_seconds),
            created_at=now,
            updated_at=now,
        )
        session.add(signal)
        await session.flush()
    existing_link = (await session.exec(select(BehaviorSignalEvent).where(
        BehaviorSignalEvent.signal_id == signal.id,
        BehaviorSignalEvent.event_id == event.id,
    ))).one_or_none()
    if existing_link is None:
        session.add(BehaviorSignalEvent(signal_id=signal.id, event_id=event.id, decision_id=decision.id))
        signal.event_count += 1
        if definition.distinct_by:
            distinct_values = [_field_value(event, field) for field in definition.distinct_by]
            if all(value not in {None, ""} for value in distinct_values):
                distinct_key = json.dumps(
                    distinct_values,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    default=str,
                )
                if distinct_key not in signal.distinct_keys:
                    signal.distinct_keys = [*signal.distinct_keys, distinct_key]
            signal.threshold_count = len(signal.distinct_keys)
        else:
            signal.threshold_count = signal.event_count
    signal.last_observed_at = max(signal.last_observed_at, event.observed_at)
    signal.score = max(signal.score, definition.score)
    signal.correlation_keys = list(dict.fromkeys([*signal.correlation_keys, *correlation_keys]))
    signal.updated_at = now
    session.add(signal)
    threshold_reached = signal.threshold_count >= definition.threshold
    debounce_reached = signal.score >= 70 or signal.debounce_until is None or signal.debounce_until <= now
    return signal, threshold_reached and debounce_reached


def _rule_matches(all_conditions, any_conditions, event) -> bool:
    if all_conditions and not all(_condition_matches(condition, event) for condition in all_conditions):
        return False
    if any_conditions and not any(_condition_matches(condition, event) for condition in any_conditions):
        return False
    return True


def _condition_matches(condition, event) -> bool:
    actual = _field_value(event, condition.field)
    expected = condition.value
    operator = condition.operator
    if operator == "exists":
        present = actual is not None and actual != ""
        return present is bool(expected) if isinstance(expected, bool) else present
    if operator == "eq":
        return _comparable(actual) == _comparable(expected)
    if operator == "neq":
        return _comparable(actual) != _comparable(expected)
    if operator == "in":
        return isinstance(expected, list) and _comparable(actual) in {_comparable(item) for item in expected}
    if actual is None:
        return False
    text = str(actual)
    value = str(expected or "")
    if operator == "contains":
        return value.casefold() in text.casefold()
    if operator == "prefix":
        return text.casefold().startswith(value.casefold())
    if operator == "suffix":
        return text.casefold().endswith(value.casefold())
    if operator == "regex":
        try:
            return _compiled_regex(value).search(text, timeout=0.05) is not None
        except (regex.error, TimeoutError):
            return False
    return False


def _field_value(event, field: str):
    value: Any = event
    for part in field.split("."):
        if isinstance(value, dict):
            value = value.get(part)
        else:
            value = getattr(value, part, None)
        if value is None:
            return None
    return value.value if hasattr(value, "value") else value


def _comparable(value):
    if hasattr(value, "value"):
        value = value.value
    return value.casefold() if isinstance(value, str) else value


@lru_cache(maxsize=512)
def _compiled_regex(pattern: str):
    return regex.compile(pattern)
