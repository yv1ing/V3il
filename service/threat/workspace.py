from sqlalchemy import and_, func, or_
from sqlmodel import select

from utils.time import utc_now

from database import get_async_session
from model.deception.environments import DeceptionEnvironment, DeceptionRevision
from model.threat.analysis import AnalysisRecord, AttackerProfile, IntentAssessment, RiskAssessment
from model.threat.behaviors import BehaviorEvent, BehaviorSensorCursor, ThreatIncidentBehaviorEvent
from model.threat.chains import AttackChain
from model.threat.incidents import ThreatIncident, ThreatIncidentEnvironment
from model.threat.intelligence import IntelligenceReport
from model.threat.investigations import (
    AuditEvent,
    EvidenceBehaviorLink,
    InvestigationEvidence,
    InvestigationTask,
    InvestigationTaskEvent,
)
from schema.deception.environments import DeceptionEnvironmentSchema, DeceptionRevisionSchema
from schema.system_user.users import SystemUserRole
from schema.threat.analysis import AnalysisKind
from schema.threat.behaviors import BehaviorEventCategory, BehaviorEventSchema
from schema.threat.investigations import AuditEventSchema
from schema.threat.workspace import (
    ThreatIncidentWorkspaceSchema,
    ThreatSensorCoverageSchema,
    ThreatSensorCoverageStatus,
    ThreatTimelineItemKind,
    AuditEventTimelineItem,
    BehaviorEventTimelineItem,
    DeceptionRevisionTimelineItem,
    InvestigationEvidenceTimelineItem,
    InvestigationTaskTimelineItem,
    ThreatTimelineCursor,
    ThreatTimelineResponse,
    ThreatWorkspaceCounts,
)
from service.threat.analysis import (
    serialize_attacker_profile,
    serialize_intent_assessment,
    serialize_risk_assessment,
)
from service.threat.chains import serialize_attack_chain
from service.deception.environments import serialize_deception_revision
from service.threat.investigations import (
    serialize_investigation_evidence,
    serialize_investigation_task,
)


async def get_incident_workspace(incident_id: int, *, user_id: int, user_role: SystemUserRole):
    async with get_async_session() as session:
        incident = await session.get(ThreatIncident, incident_id)
        if incident is None or (user_role != SystemUserRole.ADMIN and incident.owner_id != user_id):
            return None
        environment_ids = list((await session.exec(select(ThreatIncidentEnvironment.environment_id).where(
            ThreatIncidentEnvironment.incident_id == incident_id
        ))).all())
        environments = list((await session.exec(select(DeceptionEnvironment).where(
            DeceptionEnvironment.id.in_(environment_ids or [-1])
        ).order_by(DeceptionEnvironment.updated_at.desc()))).all())
        current_intent = await _current_analysis(
            session,
            incident_id,
            AnalysisKind.INTENT,
            IntentAssessment,
            serialize_intent_assessment,
        )
        current_chain = await _current_analysis(
            session,
            incident_id,
            AnalysisKind.ATTACK_CHAIN,
            AttackChain,
            serialize_attack_chain,
        )
        current_profile = await _current_analysis(
            session,
            incident_id,
            AnalysisKind.ATTACKER_PROFILE,
            AttackerProfile,
            serialize_attacker_profile,
        )
        current_risk = await _current_analysis(
            session,
            incident_id,
            AnalysisKind.RISK,
            RiskAssessment,
            serialize_risk_assessment,
        )
        current_report = (await session.exec(select(IntelligenceReport).where(
            IntelligenceReport.incident_id == incident_id,
            IntelligenceReport.is_current.is_(True),
        ))).one_or_none()
        task_status_rows = list((await session.exec(select(
            InvestigationTask.status,
            func.count(InvestigationTask.id),
        ).where(InvestigationTask.incident_id == incident_id).group_by(InvestigationTask.status))).all())
        revision_status_rows = list((await session.exec(select(
            DeceptionRevision.status,
            func.count(DeceptionRevision.id),
        ).where(DeceptionRevision.environment_id.in_(environment_ids or [-1])).group_by(DeceptionRevision.status))).all())
        evidence_count = int((await session.exec(select(func.count()).select_from(InvestigationEvidence).join(
            InvestigationTask, InvestigationTask.id == InvestigationEvidence.task_id
        ).where(InvestigationTask.incident_id == incident_id))).one())
        assigned_count = int((await session.exec(select(func.count()).select_from(ThreatIncidentBehaviorEvent).where(
            ThreatIncidentBehaviorEvent.incident_id == incident_id,
            ThreatIncidentBehaviorEvent.is_material.is_(True),
        ))).one())
        scoped_count = int((await session.exec(select(func.count(func.distinct(InvestigationTaskEvent.event_id))).select_from(InvestigationTaskEvent).join(
            InvestigationTask, InvestigationTask.id == InvestigationTaskEvent.task_id
        ).where(InvestigationTask.incident_id == incident_id))).one())
        covered_count = int((await session.exec(
            select(func.count(func.distinct(EvidenceBehaviorLink.event_id)))
            .select_from(EvidenceBehaviorLink)
            .join(
                InvestigationEvidence,
                InvestigationEvidence.id == EvidenceBehaviorLink.evidence_id,
            )
            .join(InvestigationTask, InvestigationTask.id == InvestigationEvidence.task_id)
            .where(InvestigationTask.incident_id == incident_id)
        )).one())
        indicator_count = int((await session.exec(select(func.count()).select_from(AnalysisRecord).where(
            AnalysisRecord.incident_id == incident_id,
            AnalysisRecord.kind == AnalysisKind.INDICATOR,
            AnalysisRecord.is_current.is_(True),
        ))).one())
        audits = list((await session.exec(select(AuditEvent).where(
            AuditEvent.incident_id == incident_id
        ).order_by(AuditEvent.created_at.desc()).limit(20))).all())
        sensor_coverage = await _sensor_coverage(session, environment_ids)
        return ThreatIncidentWorkspaceSchema(
            incident=incident,
            environments=[DeceptionEnvironmentSchema.model_validate(item) for item in environments],
            current_intent=current_intent,
            current_attack_chain=current_chain,
            current_attacker_profile=current_profile,
            current_risk_assessment=current_risk,
            current_report=current_report,
            counts=ThreatWorkspaceCounts(
                tasks_by_status={status.value: count for status, count in task_status_rows},
                evidence_count=evidence_count,
                assigned_event_count=assigned_count,
                scoped_event_count=scoped_count,
                covered_event_count=covered_count,
                indicators_count=indicator_count,
                revisions_by_status={status.value: count for status, count in revision_status_rows},
            ),
            sensor_coverage=sensor_coverage,
            recent_audit_events=[AuditEventSchema.model_validate(item) for item in audits],
        )


async def get_incident_timeline(
    incident_id: int,
    *,
    cursor: ThreatTimelineCursor | None,
    limit: int,
    user_id: int,
    user_role: SystemUserRole,
):
    async with get_async_session() as session:
        incident = await session.get(ThreatIncident, incident_id)
        if incident is None or (user_role != SystemUserRole.ADMIN and incident.owner_id != user_id):
            return None
        environment_ids = list((await session.exec(select(ThreatIncidentEnvironment.environment_id).where(
            ThreatIncidentEnvironment.incident_id == incident_id
        ))).all())
        behavior = list((await session.exec(
            select(BehaviorEvent)
            .join(ThreatIncidentBehaviorEvent, ThreatIncidentBehaviorEvent.event_id == BehaviorEvent.id)
            .where(
                ThreatIncidentBehaviorEvent.incident_id == incident_id,
                *(_timeline_cursor_condition(
                    BehaviorEvent.observed_at,
                    BehaviorEvent.id,
                    ThreatTimelineItemKind.BEHAVIOR_EVENT,
                    cursor,
                ),),
            )
            .order_by(BehaviorEvent.observed_at.desc(), BehaviorEvent.id.desc())
            .limit(limit + 1)
        )).all())
        audits = list((await session.exec(select(AuditEvent).where(
            AuditEvent.incident_id == incident_id,
            _timeline_cursor_condition(
                AuditEvent.created_at,
                AuditEvent.id,
                ThreatTimelineItemKind.AUDIT_EVENT,
                cursor,
            ),
        ).order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc()).limit(limit + 1))).all())
        tasks = list((await session.exec(select(InvestigationTask).where(
            InvestigationTask.incident_id == incident_id,
            _timeline_cursor_condition(
                InvestigationTask.updated_at,
                InvestigationTask.id,
                ThreatTimelineItemKind.INVESTIGATION_TASK,
                cursor,
            ),
        ).order_by(InvestigationTask.updated_at.desc(), InvestigationTask.id.desc()).limit(limit + 1))).all())
        evidence = list((await session.exec(select(InvestigationEvidence).join(
            InvestigationTask, InvestigationTask.id == InvestigationEvidence.task_id
        ).where(
            InvestigationTask.incident_id == incident_id,
            _timeline_cursor_condition(
                InvestigationEvidence.created_at,
                InvestigationEvidence.id,
                ThreatTimelineItemKind.INVESTIGATION_EVIDENCE,
                cursor,
            ),
        ).order_by(InvestigationEvidence.created_at.desc(), InvestigationEvidence.id.desc()).limit(limit + 1))).all())
        revisions = list((await session.exec(select(DeceptionRevision).where(
            DeceptionRevision.environment_id.in_(environment_ids or [-1]),
            _timeline_cursor_condition(
                DeceptionRevision.created_at,
                DeceptionRevision.id,
                ThreatTimelineItemKind.DECEPTION_REVISION,
                cursor,
            ),
        ).order_by(DeceptionRevision.created_at.desc(), DeceptionRevision.id.desc()).limit(limit + 1))).all())
        items = [
            *[BehaviorEventTimelineItem(
                occurred_at=item.observed_at,
                object_id=item.id,
                environment_id=item.environment_id,
                payload=BehaviorEventSchema.model_validate(item),
            ) for item in behavior],
            *[AuditEventTimelineItem(
                occurred_at=item.created_at,
                object_id=item.id,
                environment_id=item.environment_id,
                task_id=item.task_id,
                payload=AuditEventSchema.model_validate(item),
            ) for item in audits],
            *[InvestigationTaskTimelineItem(
                occurred_at=item.updated_at,
                object_id=item.id,
                task_id=item.id,
                payload=await serialize_investigation_task(session, item),
            ) for item in tasks],
            *[InvestigationEvidenceTimelineItem(
                occurred_at=item.created_at,
                object_id=item.id,
                task_id=item.task_id,
                payload=await serialize_investigation_evidence(session, item),
            ) for item in evidence],
            *[DeceptionRevisionTimelineItem(
                occurred_at=item.created_at,
                object_id=item.id,
                environment_id=item.environment_id,
                payload=await serialize_deception_revision(session, item),
            ) for item in revisions],
        ]
        items.sort(key=_timeline_key, reverse=True)
        selected = items[:limit]
        return ThreatTimelineResponse(
            items=selected,
            next_cursor=(
                ThreatTimelineCursor(
                    occurred_at=selected[-1].occurred_at,
                    kind=selected[-1].kind,
                    object_id=selected[-1].object_id,
                )
                if len(items) > limit and selected
                else None
            ),
            has_more=len(items) > limit,
        )


def _timeline_cursor_condition(timestamp_column, id_column, kind, cursor):
    if cursor is None:
        return timestamp_column.is_not(None)
    same_timestamp_condition = (
        id_column < cursor.object_id
        if kind == cursor.kind
        else kind.value < cursor.kind.value
    )
    return or_(
        timestamp_column < cursor.occurred_at,
        and_(timestamp_column == cursor.occurred_at, same_timestamp_condition),
    )


def _timeline_key(item):
    return item.occurred_at, item.kind.value, item.object_id


async def _current_analysis(session, incident_id, kind, model, serializer):
    row = (await session.exec(
        select(AnalysisRecord, model)
        .join(model, model.analysis_id == AnalysisRecord.id)
        .where(
            AnalysisRecord.incident_id == incident_id,
            AnalysisRecord.kind == kind,
            AnalysisRecord.is_current.is_(True),
        )
    )).one_or_none()
    return await serializer(session, *row) if row else None


async def _sensor_coverage(session, environment_ids: list[int]) -> list[ThreatSensorCoverageSchema]:
    if not environment_ids:
        return []
    cursors = list((await session.exec(select(BehaviorSensorCursor).where(
        BehaviorSensorCursor.environment_id.in_(environment_ids)
    ))).all())
    transition_actions = {
        "observer_degraded",
        "observer_recovered",
        "container_runtime_unavailable",
        "container_runtime_recovered",
    }
    transition_events = list((await session.exec(select(BehaviorEvent).where(
        BehaviorEvent.environment_id.in_(environment_ids),
        BehaviorEvent.category == BehaviorEventCategory.SYSTEM,
        BehaviorEvent.action.in_(transition_actions),
    ).order_by(BehaviorEvent.observed_at.desc(), BehaviorEvent.id.desc()))).all())
    cursor_by_key = {
        (cursor.environment_id, cursor.sensor_id): cursor
        for cursor in cursors
        if not cursor.sensor_id.startswith("control-plane:")
    }
    transitions: dict[tuple[int, str], dict[str, BehaviorEvent]] = {}
    for event in transition_events:
        target_sensor_id = event.attributes.get("sensor_id")
        if not isinstance(target_sensor_id, str) or not target_sensor_id:
            target_sensor_id = event.sensor_id
        observer = event.attributes.get("observer")
        observer_key = observer if isinstance(observer, str) and observer else event.action
        transitions.setdefault((event.environment_id, target_sensor_id), {}).setdefault(observer_key, event)
    keys = sorted(set(cursor_by_key) | set(transitions))
    result: list[ThreatSensorCoverageSchema] = []
    for key in keys:
        cursor = cursor_by_key.get(key)
        observer_events = list(transitions.get(key, {}).values())
        degraded = [
            event for event in observer_events
            if event.action in {"observer_degraded", "container_runtime_unavailable"}
        ]
        if degraded:
            status = ThreatSensorCoverageStatus.DEGRADED
            summary = "; ".join(event.summary for event in degraded if event.summary)
        elif observer_events or (cursor is not None and cursor.last_observed_at is not None):
            status = ThreatSensorCoverageStatus.HEALTHY
            latest = max(observer_events, key=lambda item: item.observed_at, default=None)
            summary = latest.summary if latest is not None else "Behavior telemetry is being collected."
        else:
            status = ThreatSensorCoverageStatus.UNKNOWN
            summary = "No behavior telemetry has been observed yet."
        latest_transition = max(observer_events, key=lambda item: item.observed_at, default=None)
        updated_at = (
            cursor.updated_at
            if cursor is not None
            else latest_transition.ingested_at
            if latest_transition is not None
            else utc_now()
        )
        result.append(ThreatSensorCoverageSchema(
            environment_id=key[0],
            sensor_id=key[1],
            status=status,
            last_sequence=cursor.last_sequence if cursor is not None else 0,
            verification_token=cursor.verification_token if cursor is not None else "",
            last_observed_at=cursor.last_observed_at if cursor is not None else None,
            updated_at=updated_at,
            last_transition_at=latest_transition.observed_at if latest_transition is not None else None,
            summary=summary,
        ))
    return result
