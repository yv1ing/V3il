from sqlalchemy import func
from sqlmodel import select

from model.threat.analysis import AnalysisEvidenceLink, AnalysisRecord
from model.threat.investigations import InvestigationEvidence, InvestigationTask
from core.agent.constants import DEFAULT_AGENT_CODE
from schema.threat.analysis import AnalysisKind, AnalysisReviewStatus
from schema.threat.investigations import InvestigationTaskStatus


async def require_incident_evidence(
    session,
    incident_id: int,
    evidence_ids: list[int],
) -> list[InvestigationEvidence]:
    normalized = list(dict.fromkeys(evidence_ids))
    rows = list((await session.exec(
        select(InvestigationEvidence)
        .join(InvestigationTask, InvestigationTask.id == InvestigationEvidence.task_id)
        .where(
            InvestigationEvidence.id.in_(normalized),
            InvestigationTask.incident_id == incident_id,
            InvestigationTask.status != InvestigationTaskStatus.CANCELED,
        )
    )).all())
    by_id = {row.id: row for row in rows if row.id is not None}
    missing = [evidence_id for evidence_id in normalized if evidence_id not in by_id]
    if missing:
        raise ValueError(
            "evidence does not belong to an active task in this incident: "
            + ", ".join(str(item) for item in missing[:20])
        )
    return [by_id[evidence_id] for evidence_id in normalized]


async def create_analysis_record(
    session,
    *,
    incident_id: int,
    kind: AnalysisKind,
    subject_key: str,
    evidence_ids: list[int],
    agent_code: str,
    source_session_id: str,
    investigation_task_id: int | None = None,
) -> AnalysisRecord:
    await require_incident_evidence(session, incident_id, evidence_ids)
    specialist_proposal = bool(agent_code and agent_code != DEFAULT_AGENT_CODE)
    if specialist_proposal:
        if investigation_task_id is None:
            raise ValueError("specialist analysis requires an investigation task")
        task = (await session.exec(select(InvestigationTask).where(
            InvestigationTask.id == investigation_task_id,
            InvestigationTask.incident_id == incident_id,
        ).with_for_update())).one_or_none()
        if task is None or task.assignee_agent_code != agent_code:
            raise ValueError("analysis task is not assigned to this specialist")
        if task.status not in {InvestigationTaskStatus.ACTIVE, InvestigationTaskStatus.BLOCKED}:
            raise ValueError("specialist analysis requires an active or blocked task")
    latest = (await session.exec(
        select(func.max(AnalysisRecord.version)).where(
            AnalysisRecord.incident_id == incident_id,
            AnalysisRecord.kind == kind,
            AnalysisRecord.subject_key == subject_key,
        )
    )).one()
    version = int(latest or 0) + 1
    if not specialist_proposal:
        current = (await session.exec(select(AnalysisRecord).where(
            AnalysisRecord.incident_id == incident_id,
            AnalysisRecord.kind == kind,
            AnalysisRecord.subject_key == subject_key,
            AnalysisRecord.is_current.is_(True),
        ).with_for_update())).one_or_none()
        if current is not None:
            current.is_current = False
            session.add(current)

    record = AnalysisRecord(
        incident_id=incident_id,
        kind=kind,
        subject_key=subject_key,
        version=version,
        is_current=not specialist_proposal,
        investigation_task_id=investigation_task_id,
        review_status=(AnalysisReviewStatus.PENDING if specialist_proposal else AnalysisReviewStatus.ACCEPTED),
        created_by_agent_code=agent_code,
        created_from_session_id=source_session_id,
    )
    session.add(record)
    await session.flush()
    if record.id is None:
        raise RuntimeError("analysis record id was not generated")
    session.add_all([
        AnalysisEvidenceLink(analysis_id=record.id, evidence_id=evidence_id)
        for evidence_id in dict.fromkeys(evidence_ids)
    ])
    return record


async def analysis_evidence_ids(session, analysis_id: int) -> list[int]:
    return list((await session.exec(
        select(AnalysisEvidenceLink.evidence_id)
        .where(AnalysisEvidenceLink.analysis_id == analysis_id)
        .order_by(AnalysisEvidenceLink.evidence_id.asc())
    )).all())
