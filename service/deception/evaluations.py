from __future__ import annotations

import asyncio
from datetime import datetime

from sqlmodel import select

from core.agent.constants import DEFAULT_AGENT_CODE
from core.runtime.context import main_agent_instance_id
from core.runtime.notification_dispatch import signal_target_notifications
from database import get_async_session
from logger import get_logger
from model.agent.sessions import AgentSessionMeta
from model.deception.environments import DeceptionEnvironment, DeceptionRevision
from model.detection.rules import BehaviorSignal, BehaviorSignalEvent
from model.threat.behaviors import ThreatIncidentBehaviorEvent
from model.threat.incidents import ThreatIncident
from schema.deception.environments import DeceptionEvaluationStatus, DeceptionRevisionKind, DeceptionRevisionStatus
from schema.system_user.users import SystemUserRole
from schema.threat.investigations import CreateInvestigationTaskRequest, InvestigationTaskPriority
from service.agent import notifications as agent_notifications
from service.agent.runtime import resume_main_agent_session
from service.threat.incidents import ensure_automated_threat_incident_session_in_session
from service.threat.investigations import create_investigation_task_in_session


logger = get_logger(__name__)
_task: asyncio.Task[None] | None = None
_stop = asyncio.Event()


async def start_deception_evaluation_runtime() -> None:
    global _task
    if _task is not None and not _task.done():
        return
    _stop.clear()
    _task = asyncio.create_task(_loop(), name="deception-evaluation-runtime")


async def stop_deception_evaluation_runtime() -> None:
    global _task
    current, _task = _task, None
    if current is None:
        return
    _stop.set()
    await current


async def create_due_deception_evaluation_tasks() -> int:
    now = datetime.now()
    async with get_async_session() as session:
        revision_ids = list((await session.exec(select(DeceptionRevision.id).where(
            DeceptionRevision.kind == DeceptionRevisionKind.ADAPTIVE,
            DeceptionRevision.status == DeceptionRevisionStatus.APPLIED,
            DeceptionRevision.evaluation_status == DeceptionEvaluationStatus.PENDING,
            DeceptionRevision.evaluation_task_id.is_(None),
            DeceptionRevision.source_incident_id.is_not(None),
            DeceptionRevision.observation_deadline <= now,
        ).order_by(DeceptionRevision.observation_deadline.asc()).limit(100))).all())
    created = 0
    for revision_id in revision_ids:
        if await _create_evaluation_task(revision_id):
            created += 1
    return created


async def _create_evaluation_task(revision_id: int) -> bool:
    target_instance_id = ""
    session_id = ""
    async with get_async_session() as session, session.begin():
        current = (await session.exec(select(DeceptionRevision).where(
            DeceptionRevision.id == revision_id,
            DeceptionRevision.kind == DeceptionRevisionKind.ADAPTIVE,
            DeceptionRevision.status == DeceptionRevisionStatus.APPLIED,
            DeceptionRevision.evaluation_status == DeceptionEvaluationStatus.PENDING,
            DeceptionRevision.evaluation_task_id.is_(None),
        ).with_for_update())).one_or_none()
        if current is None:
            return False
        environment = await session.get(DeceptionEnvironment, current.environment_id)
        incident = await session.get(ThreatIncident, current.source_incident_id)
        if environment is None or incident is None:
            return False
        signal_event_ids = list((await session.exec(
            select(BehaviorSignalEvent.event_id)
            .join(BehaviorSignal, BehaviorSignal.id == BehaviorSignalEvent.signal_id)
            .where(
                BehaviorSignal.environment_id == current.environment_id,
                BehaviorSignal.incident_id == current.source_incident_id,
                BehaviorSignal.last_observed_at >= (current.resolved_at or current.created_at),
                BehaviorSignal.last_observed_at <= current.observation_deadline,
            )
        )).all())
        material_trigger_ids = list((await session.exec(select(ThreatIncidentBehaviorEvent.event_id).where(
            ThreatIncidentBehaviorEvent.incident_id == current.source_incident_id,
            ThreatIncidentBehaviorEvent.event_id.in_(current.trigger_event_ids or [-1]),
            ThreatIncidentBehaviorEvent.is_material.is_(True),
        ))).all())
        event_ids = list(dict.fromkeys([*material_trigger_ids, *signal_event_ids]))
        if not event_ids:
            logger.warning("deception evaluation has no incident evidence: revision=%s", current.id)
            return False
        result = await create_investigation_task_in_session(
            session,
            incident.id,
            CreateInvestigationTaskRequest(
                title=f"Evaluate deception revision v{current.version}",
                priority=InvestigationTaskPriority.HIGH,
                assignee_agent_code="cde",
                objective=f"Evaluate whether revision v{current.version} achieved: {current.engagement_goal}",
                completion_criteria="Compare observed signals and artifact interactions with the recorded hypothesis and every success criterion; record an effective, ineffective, or inconclusive evaluation.",
                behavior_event_ids=event_ids,
            ),
            user_id=environment.owner_id,
            user_role=SystemUserRole.ADMIN,
            agent_code=DEFAULT_AGENT_CODE,
        )
        if result.task is None:
            logger.warning("deception evaluation task creation failed: revision=%s reason=%s", current.id, result.message)
            return False
        current.evaluation_task_id = result.task.id
        session.add(current)
        session_result = await ensure_automated_threat_incident_session_in_session(session, incident)
        if session_result.session_id:
            meta = (await session.exec(select(AgentSessionMeta).where(
                AgentSessionMeta.session_id == session_result.session_id,
            ).with_for_update())).one()
            target_instance_id = main_agent_instance_id(meta.session_id, meta.owner_id, DEFAULT_AGENT_CODE)
            await agent_notifications.enqueue_deception_evaluation_notification_in_session(
                session,
                meta=meta,
                target_agent_code=DEFAULT_AGENT_CODE,
                target_agent_instance_id=target_instance_id,
                incident_id=incident.id,
                environment_id=environment.id,
                revision_id=current.id,
                task_id=result.task.id,
            )
            session_id = meta.session_id
    if session_id:
        await signal_target_notifications(target_instance_id)
        await resume_main_agent_session(session_id)
    return True


async def _loop() -> None:
    while not _stop.is_set():
        try:
            await create_due_deception_evaluation_tasks()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("deception evaluation runtime cycle failed")
        try:
            await asyncio.wait_for(_stop.wait(), timeout=30)
        except asyncio.TimeoutError:
            pass
