from __future__ import annotations

from datetime import timedelta

from sqlmodel import select

from utils.time import utc_now

from config import get_config
from core.agent.constants import DEFAULT_AGENT_CODE
from database import get_async_session
from logger import get_logger
from model.agent.sessions import AgentSession
from model.deception.environments import DeceptionEnvironment
from model.detection.rules import BehaviorDecision, BehaviorSignal, BehaviorSignalEvent
from model.threat.behaviors import BehaviorEvent, ThreatIncidentBehaviorEvent
from model.threat.incidents import ThreatIncident, ThreatIncidentEnvironment
from schema.detection.rules import BehaviorDecisionMode, BehaviorSignalStatus
from schema.system_user.users import SystemUserRole
from schema.threat.incidents import ThreatConfidence, ThreatIncidentStatus, ThreatSeverity
from schema.threat.investigations import AuditActorType, AuditEventKind
from service.agent.repository import enqueue_system_run
from service.detection.engine import process_behavior_events
from service.threat.audit import add_audit_event
from service.threat.incidents import ensure_automated_threat_incident_session_in_session
from service.threat.state import transition_threat_incident


logger = get_logger(__name__)
_FINGERPRINT_ATTRIBUTE_KEYS = ("client_fingerprint", "tls_fingerprint", "ssh_key_fingerprint", "certificate_fingerprint")


async def orchestrate_behavior_events(environment_id: int, event_ids: list[int]):
    automation = get_config().threat_automation
    normalized = list(dict.fromkeys(item for item in event_ids if item > 0))
    if not automation.enabled or not normalized:
        return {}
    signal_ids = await process_behavior_events(environment_id, normalized)
    if not signal_ids:
        return {}
    assignments, _ = await _correlate_behavior_signals(
        environment_id,
        signal_ids,
        correlation_window=timedelta(seconds=automation.correlation_window_seconds),
    )
    return assignments


async def orchestrate_ready_behavior_signals(limit: int = 1000) -> int:
    now = utc_now()
    async with get_async_session() as session:
        rows = list((await session.exec(select(
            BehaviorSignal.id,
            BehaviorSignal.environment_id,
        ).where(
            BehaviorSignal.status == BehaviorSignalStatus.OPEN,
            BehaviorSignal.threshold_count >= BehaviorSignal.threshold,
            BehaviorSignal.debounce_until <= now,
        ).order_by(BehaviorSignal.updated_at.asc()).limit(limit))).all())
    grouped: dict[int, list[int]] = {}
    for signal_id, environment_id in rows:
        grouped.setdefault(environment_id, []).append(signal_id)
    resumed = 0
    window = timedelta(seconds=get_config().threat_automation.correlation_window_seconds)
    for environment_id, signal_ids in grouped.items():
        _, resumptions = await _correlate_behavior_signals(environment_id, signal_ids, correlation_window=window)
        resumed += len(resumptions)
    return resumed


async def _correlate_behavior_signals(environment_id: int, signal_ids: list[int], *, correlation_window: timedelta):
    assignments: dict[int, list[int]] = {}
    resumptions: set[str] = set()
    async with get_async_session() as session, session.begin():
        environment = (await session.exec(select(DeceptionEnvironment).where(
            DeceptionEnvironment.id == environment_id,
        ).with_for_update())).one_or_none()
        if environment is None:
            return {}, set()
        signals = list((await session.exec(select(BehaviorSignal).where(
            BehaviorSignal.environment_id == environment_id,
            BehaviorSignal.id.in_(signal_ids),
            BehaviorSignal.threshold_count >= BehaviorSignal.threshold,
        ).order_by(BehaviorSignal.first_observed_at.asc()).with_for_update())).all())
        incidents = list((await session.exec(select(ThreatIncident).where(
            ThreatIncident.status != ThreatIncidentStatus.CLOSED,
            ThreatIncident.owner_id == environment.owner_id,
        ).order_by(ThreatIncident.last_observed_at.desc()).with_for_update())).all())
        notifications: dict[int, list[BehaviorSignal]] = {}
        for signal in signals:
            event_rows = list((await session.exec(
                select(BehaviorEvent, BehaviorDecision)
                .join(BehaviorSignalEvent, BehaviorSignalEvent.event_id == BehaviorEvent.id)
                .join(BehaviorDecision, BehaviorDecision.id == BehaviorSignalEvent.decision_id)
                .where(BehaviorSignalEvent.signal_id == signal.id)
                .order_by(BehaviorEvent.observed_at.asc())
            )).all())
            if not event_rows:
                continue
            primary_event = event_rows[-1][0]
            incident = await session.get(ThreatIncident, signal.incident_id) if signal.incident_id else None
            method = "existing_signal"
            key = str(signal.id)
            if incident is None:
                incident, method, key = _match_incident(signal, primary_event, incidents, correlation_window)
            if incident is None:
                fingerprint = _signal_fingerprint(signal, primary_event)
                incident = ThreatIncident(
                    title=_incident_title(signal, primary_event),
                    status=ThreatIncidentStatus.OPEN,
                    severity=_severity_for_score(signal.score),
                    confidence=_confidence_for_score(signal.score),
                    risk_score=signal.score,
                    primary_fingerprint=fingerprint,
                    source_ips=[primary_event.source_ip] if primary_event.source_ip else [],
                    summary=f"Automatically opened from deterministic behavior signal {signal.id} ({signal.kind}).",
                    first_observed_at=signal.first_observed_at,
                    last_observed_at=signal.last_observed_at,
                    idle_deadline=signal.last_observed_at + correlation_window,
                    owner_id=environment.owner_id,
                )
                session.add(incident)
                await session.flush()
                incidents.insert(0, incident)
                method, key = "new_signal_incident", fingerprint
            signal.incident_id = incident.id
            signal.updated_at = utc_now()
            session.add(signal)
            linked_event_ids: list[int] = []
            for event, decision in event_rows:
                if event.id is None:
                    continue
                link = await session.get(ThreatIncidentBehaviorEvent, event.id)
                if link is None:
                    link = ThreatIncidentBehaviorEvent(
                        event_id=event.id,
                        incident_id=incident.id,
                        linked_by_agent_code="system",
                        correlation_method=method,
                        correlation_key=key,
                        is_material=decision.material,
                        materiality_reason=decision.reason,
                        correlation_score=signal.score,
                        linked_at=utc_now(),
                    )
                    session.add(link)
                    linked_event_ids.append(event.id)
                elif link.incident_id == incident.id and decision.material and not link.is_material:
                    link.is_material = True
                    link.materiality_reason = decision.reason
                    link.correlation_score = max(link.correlation_score, signal.score)
                    session.add(link)
            relation = await session.get(ThreatIncidentEnvironment, (incident.id, environment_id))
            if relation is None:
                relation = ThreatIncidentEnvironment(
                    incident_id=incident.id,
                    environment_id=environment_id,
                    first_observed_at=signal.first_observed_at,
                    last_observed_at=signal.last_observed_at,
                    correlation_method=method,
                    correlation_key=key,
                )
            else:
                relation.first_observed_at = min(relation.first_observed_at, signal.first_observed_at)
                relation.last_observed_at = max(relation.last_observed_at, signal.last_observed_at)
            session.add(relation)
            incident.first_observed_at = min(incident.first_observed_at, signal.first_observed_at)
            incident.last_observed_at = max(incident.last_observed_at, signal.last_observed_at)
            incident.idle_deadline = incident.last_observed_at + correlation_window
            incident.risk_score = max(incident.risk_score, signal.score)
            incident.severity = max(incident.severity, _severity_for_score(signal.score), key=_severity_rank)
            incident.confidence = max(incident.confidence, _confidence_for_score(signal.score), key=_confidence_rank)
            if primary_event.source_ip and primary_event.source_ip not in incident.source_ips:
                incident.source_ips = [*incident.source_ips, primary_event.source_ip]
            if incident.status == ThreatIncidentStatus.FINALIZING:
                incident.status = ThreatIncidentStatus.INVESTIGATING
                await add_audit_event(
                    session,
                    incident_id=incident.id,
                    environment_id=environment_id,
                    kind=AuditEventKind.INCIDENT_STATE,
                    actor_type=AuditActorType.SYSTEM,
                    actor_code="system",
                    object_type="threat_incident",
                    object_id=incident.id,
                    summary="Threat incident returned to investigation after a new material signal.",
                    details={"signal_id": signal.id},
                )
            incident.updated_at = utc_now()
            session.add(incident)
            assignments.setdefault(incident.id, []).extend(linked_event_ids)
            await add_audit_event(
                session,
                incident_id=incident.id,
                environment_id=environment_id,
                kind=AuditEventKind.CORRELATION,
                actor_type=AuditActorType.SYSTEM,
                actor_code="system",
                object_type="behavior_signal",
                object_id=signal.id,
                summary="Deterministic behavior signal linked to threat incident.",
                details={
                    "correlation_method": method,
                    "correlation_key": key,
                    "score": signal.score,
                    "classification": signal.classification.value,
                    "event_ids": [event.id for event, _ in event_rows],
                },
            )
            now = utc_now()
            ready = signal.score >= 70 or signal.debounce_until is None or signal.debounce_until <= now
            if ready and signal.notified_at is None:
                notifications.setdefault(incident.id, []).append(signal)
        for incident_id, pending_signals in notifications.items():
            incident = next(item for item in incidents if item.id == incident_id)
            result = await ensure_automated_threat_incident_session_in_session(session, incident)
            if not result.session_id:
                continue
            agent_session = (await session.exec(select(AgentSession).where(
                AgentSession.id == result.session_id,
            ).with_for_update())).one()
            signal_ids = [signal.id for signal in pending_signals]
            run = await enqueue_system_run(
                session,
                agent_session=agent_session,
                content=(
                    "New deterministic behavior signals require investigation. Treat these identifiers as trusted runtime state.\n"
                    f"incident_id: {incident_id}\n"
                    f"signal_ids: {signal_ids}\n"
                    f"highest_score: {max(signal.score for signal in pending_signals)}"
                ),
                source_key=f"behavior-signals:{incident_id}:{','.join(str(item) for item in signal_ids)}",
            )
            if run is None:
                continue
            notified_at = utc_now()
            for signal in pending_signals:
                cooldown_duration = max(
                    (signal.cooldown_until or signal.created_at) - signal.created_at,
                    timedelta(0),
                )
                signal.status = BehaviorSignalStatus.NOTIFIED
                signal.notified_at = notified_at
                signal.cooldown_until = notified_at + cooldown_duration
                signal.updated_at = notified_at
                session.add(signal)
            resumptions.add(result.session_id)
    return assignments, resumptions


def _match_incident(signal, event, incidents, window):
    recent = [
        item for item in incidents
        if item.last_observed_at >= signal.first_observed_at - window
        and item.first_observed_at <= signal.last_observed_at + window
    ]
    keys = list(dict.fromkeys([*signal.correlation_keys, _event_fingerprint(event)]))
    for key in keys:
        if key and (matched := next((item for item in recent if item.primary_fingerprint == key), None)):
            return matched, "signal_fingerprint", key
    if event.source_ip:
        candidates = [item for item in recent if event.source_ip in item.source_ips]
        if len(candidates) == 1:
            return candidates[0], "source_ip", event.source_ip
    return None, "", ""


def _signal_fingerprint(signal, event):
    strong = next((key for key in signal.correlation_keys if not key.startswith("source_ip:")), "")
    return strong or _event_fingerprint(event)


def _event_fingerprint(event):
    for key in _FINGERPRINT_ATTRIBUTE_KEYS:
        value = event.attributes.get(key)
        if isinstance(value, str) and value.strip():
            return f"{key}:{' '.join(value.split()).casefold()[:512]}"
    return f"source_ip:{event.source_ip}" if event.source_ip else ""


def _incident_title(signal, event):
    source = f" from {event.source_ip}" if event.source_ip else ""
    return f"{signal.kind.replace('_', ' ').title()}{source}"


def _severity_for_score(score):
    if score >= 90:
        return ThreatSeverity.CRITICAL
    if score >= 80:
        return ThreatSeverity.HIGH
    if score >= 70:
        return ThreatSeverity.MEDIUM
    if score >= 40:
        return ThreatSeverity.LOW
    return ThreatSeverity.INFO


def _confidence_for_score(score):
    if score >= 90:
        return ThreatConfidence.CONFIRMED
    if score >= 70:
        return ThreatConfidence.HIGH
    if score >= 40:
        return ThreatConfidence.MEDIUM
    return ThreatConfidence.LOW


def _severity_rank(value):
    return list(ThreatSeverity).index(value)


def _confidence_rank(value):
    return list(ThreatConfidence).index(value)


async def recover_unprocessed_behavior_events(limit: int = 1000):
    """Evaluate events missing a live decision, then release ready signals."""
    async with get_async_session() as session:
        rows = list((await session.exec(
            select(BehaviorEvent.id, BehaviorEvent.environment_id)
            .outerjoin(
                BehaviorDecision,
                (BehaviorDecision.event_id == BehaviorEvent.id)
                & (BehaviorDecision.mode == BehaviorDecisionMode.LIVE),
            )
            .where(BehaviorDecision.id.is_(None))
            .order_by(BehaviorEvent.ingested_at.asc())
            .limit(limit)
        )).all())
    grouped: dict[int, list[int]] = {}
    for event_id, environment_id in rows:
        grouped.setdefault(environment_id, []).append(event_id)
    recovered = 0
    for environment_id, ids in grouped.items():
        await orchestrate_behavior_events(environment_id, ids)
        recovered += len(ids)
    await orchestrate_ready_behavior_signals(limit=limit)
    return recovered


async def advance_idle_incidents() -> int:
    now = utc_now()
    async with get_async_session() as session:
        incidents = list((await session.exec(select(
            ThreatIncident.id,
            ThreatIncident.owner_id,
        ).where(
            ThreatIncident.status.in_({
                ThreatIncidentStatus.OPEN,
                ThreatIncidentStatus.INVESTIGATING,
                ThreatIncidentStatus.ENGAGING,
            }),
            ThreatIncident.idle_deadline.is_not(None),
            ThreatIncident.idle_deadline <= now,
        ).order_by(ThreatIncident.idle_deadline.asc()))).all())
    advanced = 0
    for incident_id, owner_id in incidents:
        result = await transition_threat_incident(
            incident_id,
            ThreatIncidentStatus.FINALIZING,
            "Incident correlation window expired without new attacker activity.",
            user_id=owner_id,
            user_role=SystemUserRole.ADMIN,
            audit_actor_type=AuditActorType.SYSTEM,
            audit_actor_code="system",
        )
        if result.incident is not None:
            advanced += 1
        elif result.conflict:
            logger.debug("idle threat incident remains active: incident=%s reason=%s", incident_id, result.message)
    return advanced
