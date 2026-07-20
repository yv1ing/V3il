from dataclasses import dataclass
import hashlib

from sqlalchemy import func, or_
from sqlmodel import select

from database import get_async_session
from model.threat.analysis import AnalysisEvidenceLink, AnalysisRecord
from model.threat.behaviors import BehaviorEvent, ThreatIncidentBehaviorEvent
from model.detection.rules import BehaviorDecision, BehaviorSignal, BehaviorSignalEvent
from model.threat.incidents import ThreatIncident, ThreatIncidentEnvironment
from model.threat.intelligence import IntelligenceReport, IntelligenceReportArtifact, ThreatIndicator
from model.threat.chains import AttackChain
from model.threat.investigations import EvidenceBehaviorLink
from schema.system_user.users import SystemUserRole
from schema.threat.analysis import AnalysisKind
from schema.threat.incidents import ThreatIncidentStatus
from schema.threat.intelligence import (
    CreateIntelligenceReportRequest,
    CreateThreatIndicatorRequest,
    IntelligenceReportAnalysisSnapshot,
    IntelligenceReportEvidenceManifest,
    IntelligenceReportSchema,
    IntelligenceReportStatus,
    KnowledgePublicationStatus,
    ThreatIndicatorSchema,
    ThreatIndicatorType,
)
from schema.threat.investigations import AuditActorType, AuditEventKind
from schema.runtime import KnowledgePublicationReadyPayload
from service.common.pagination import Page, RESOURCE_PAGE_SIZE, page_offset
from service.threat.analysis_records import analysis_evidence_ids, create_analysis_record
from service.threat.audit import add_audit_event
from service.threat.event_integrity import require_behavior_event_integrity
from service.threat.report_readiness import final_report_analysis_error
from service.runtime import enqueue_outbox_event


@dataclass(frozen=True)
class ThreatIndicatorMutationResult:
    indicator: ThreatIndicatorSchema | None
    not_found: bool = False
    forbidden: bool = False
    conflict: bool = False
    message: str = ""


@dataclass(frozen=True)
class IntelligenceReportMutationResult:
    report: IntelligenceReportSchema | None
    not_found: bool = False
    forbidden: bool = False
    conflict: bool = False
    message: str = ""


async def create_threat_indicator(incident_id: int, request: CreateThreatIndicatorRequest, *, user_id: int, user_role: SystemUserRole, agent_code: str = "", session_id: str = "", investigation_task_id: int | None = None) -> ThreatIndicatorMutationResult:
    async with get_async_session() as session, session.begin():
        incident, error = await _lock_incident(session, incident_id, user_id, user_role)
        if error:
            return ThreatIndicatorMutationResult(indicator=None, **error)
        subject_key = f"{request.type.value}:{request.value}"
        try:
            record = await create_analysis_record(
                session,
                incident_id=incident_id,
                kind=AnalysisKind.INDICATOR,
                subject_key=subject_key,
                evidence_ids=request.evidence_ids,
                agent_code=agent_code,
                source_session_id=session_id,
                investigation_task_id=investigation_task_id,
            )
        except ValueError as exc:
            return ThreatIndicatorMutationResult(indicator=None, conflict=True, message=str(exc))
        indicator = ThreatIndicator(analysis_id=record.id, **request.model_dump(exclude={"evidence_ids"}))
        session.add(indicator)
        await session.flush()
        await add_audit_event(
            session,
            incident_id=incident_id,
            kind=AuditEventKind.ANALYSIS,
            actor_type=AuditActorType.AGENT if agent_code else AuditActorType.USER,
            actor_code=agent_code or str(user_id),
            session_id=session_id,
            object_type="indicator",
            object_id=record.id,
            summary="Threat indicator version created.",
            details={"subject_key": subject_key, "version": record.version},
        )
        schema = await serialize_threat_indicator(session, record, indicator)
    return ThreatIndicatorMutationResult(indicator=schema)


async def query_threat_indicators_for_user(incident_id: int, *, page=1, size=RESOURCE_PAGE_SIZE, type: ThreatIndicatorType | None = None, keyword: str = "", user_id: int, user_role: SystemUserRole):
    async with get_async_session() as session:
        incident = await session.get(ThreatIncident, incident_id)
        if incident is None or (user_role != SystemUserRole.ADMIN and incident.owner_id != user_id):
            return None
        statement = (
            select(AnalysisRecord, ThreatIndicator)
            .join(ThreatIndicator, ThreatIndicator.analysis_id == AnalysisRecord.id)
            .where(AnalysisRecord.incident_id == incident_id, AnalysisRecord.kind == AnalysisKind.INDICATOR)
        )
        if type is not None:
            statement = statement.where(ThreatIndicator.type == type)
        if keyword := keyword.strip():
            pattern = f"%{keyword}%"
            statement = statement.where(or_(ThreatIndicator.value.ilike(pattern), ThreatIndicator.context.ilike(pattern)))
        statement = statement.order_by(AnalysisRecord.is_current.desc(), AnalysisRecord.created_at.desc())
        total = int((await session.execute(select(func.count()).select_from(statement.order_by(None).subquery()))).scalar_one())
        rows = list((await session.exec(statement.offset(page_offset(page, size)).limit(size))).all())
        items = [await serialize_threat_indicator(session, record, indicator) for record, indicator in rows]
    return Page(page=page, size=size, total=total, items=items)


async def create_intelligence_report(incident_id: int, request: CreateIntelligenceReportRequest, *, user_id: int, user_role: SystemUserRole, agent_code: str = "", session_id: str = "") -> IntelligenceReportMutationResult:
    if agent_code == "cir" and request.status == IntelligenceReportStatus.FINAL:
        return IntelligenceReportMutationResult(
            report=None,
            conflict=True,
            message="cir may draft reports; only cso may finalize the incident report",
        )
    if agent_code and agent_code not in {"cir", "cso"}:
        return IntelligenceReportMutationResult(
            report=None,
            conflict=True,
            message="only cir and cso may create intelligence reports",
        )
    async with get_async_session() as session, session.begin():
        incident, error = await _lock_incident(session, incident_id, user_id, user_role)
        if error:
            return IntelligenceReportMutationResult(report=None, **error)
        if (
            request.status == IntelligenceReportStatus.FINAL
            and incident.status != ThreatIncidentStatus.FINALIZING
        ):
            return IntelligenceReportMutationResult(
                report=None,
                conflict=True,
                message="final reports can only be created while the incident is finalizing",
            )
        analyses = list((await session.exec(
            select(AnalysisRecord).where(
                AnalysisRecord.id.in_(request.analysis_ids),
                AnalysisRecord.incident_id == incident_id,
                AnalysisRecord.is_current.is_(True),
            ).with_for_update()
        )).all())
        if len(analyses) != len(request.analysis_ids):
            return IntelligenceReportMutationResult(report=None, conflict=True, message="reports can only reference current analysis records from the incident")
        kinds = {analysis.kind for analysis in analyses}
        required = {AnalysisKind.INTENT, AnalysisKind.ATTACK_CHAIN, AnalysisKind.ATTACKER_PROFILE, AnalysisKind.RISK}
        if request.status == IntelligenceReportStatus.FINAL and not required.issubset(kinds):
            return IntelligenceReportMutationResult(
                report=None,
                conflict=True,
                message="final reports require current intent, attack chain, attacker profile, and risk analyses",
            )
        if request.status == IntelligenceReportStatus.FINAL:
            current_analysis_ids = set((await session.exec(select(AnalysisRecord.id).where(
                AnalysisRecord.incident_id == incident_id,
                AnalysisRecord.is_current.is_(True),
            ))).all())
            if set(request.analysis_ids) != current_analysis_ids:
                return IntelligenceReportMutationResult(
                    report=None,
                    conflict=True,
                    message="final reports must snapshot every current incident analysis, including indicators",
                )
            if readiness_error := await final_report_analysis_error(session, incident_id):
                return IntelligenceReportMutationResult(
                    report=None,
                    conflict=True,
                    message=readiness_error,
                )
        snapshot = [
            IntelligenceReportAnalysisSnapshot(
                analysis_id=analysis.id,
                kind=analysis.kind,
                subject_key=analysis.subject_key,
                version=analysis.version,
            )
            for analysis in analyses
            if analysis.id is not None
        ]
        try:
            manifest = await build_intelligence_report_evidence_manifest(
                session,
                incident_id,
                [item.id for item in analyses if item.id is not None],
            )
        except ValueError as exc:
            return IntelligenceReportMutationResult(
                report=None,
                conflict=True,
                message=str(exc),
            )
        if (
            request.status == IntelligenceReportStatus.FINAL
            and manifest.covered_event_count != manifest.material_event_count
        ):
            return IntelligenceReportMutationResult(
                report=None,
                conflict=True,
                message=(
                    "final reports require every material behavior event to be represented "
                    "by evidence linked to the analysis snapshot"
                ),
            )
        current = (await session.exec(
            select(IntelligenceReport)
            .where(IntelligenceReport.incident_id == incident_id, IntelligenceReport.is_current.is_(True))
            .with_for_update()
        )).one_or_none()
        version = 1
        if current is not None:
            current.is_current = False
            session.add(current)
            version = current.version + 1
        report = IntelligenceReport(
            incident_id=incident_id,
            version=version,
            is_current=True,
            status=(
                IntelligenceReportStatus.REVIEW
                if request.status == IntelligenceReportStatus.FINAL
                else request.status
            ),
            title=request.title,
            executive_summary=request.executive_summary,
            behavior_summary=request.behavior_summary,
            deception_summary=request.deception_summary,
            conclusion=request.conclusion,
            analysis_snapshot=[item.model_dump(mode="json") for item in snapshot],
            evidence_manifest=manifest.model_dump(mode="json"),
            markdown=request.markdown,
            knowledge_status=(
                KnowledgePublicationStatus.QUEUED
                if request.status == IntelligenceReportStatus.FINAL
                else KnowledgePublicationStatus.NOT_QUEUED
            ),
            created_by_agent_code=agent_code,
            created_from_session_id=session_id,
        )
        session.add(report)
        await session.flush()
        if request.status == IntelligenceReportStatus.FINAL:
            from service.threat.report_export import build_report_bundle_in_session

            report.status = IntelligenceReportStatus.FINAL
            content, filename = await build_report_bundle_in_session(session, incident, report)
            artifact_sha256 = hashlib.sha256(content).hexdigest()
            report.artifact_sha256 = artifact_sha256
            report.artifact_media_type = "application/zip"
            report.artifact_filename = filename
            report.artifact_size = len(content)
            session.add(report)
            session.add(IntelligenceReportArtifact(
                report_id=report.id,
                sha256=artifact_sha256,
                media_type=report.artifact_media_type,
                filename=filename,
                content=content,
                byte_size=len(content),
            ))
            enqueue_outbox_event(
                session,
                KnowledgePublicationReadyPayload(
                    report_id=report.id,
                    artifact_sha256=artifact_sha256,
                ),
                idempotency_key=artifact_sha256,
            )
        await add_audit_event(
            session,
            incident_id=incident_id,
            kind=AuditEventKind.REPORT,
            actor_type=AuditActorType.AGENT if agent_code else AuditActorType.USER,
            actor_code=agent_code or str(user_id),
            session_id=session_id,
            object_type="intelligence_report",
            object_id=report.id,
            summary="Intelligence report version created.",
            details={
                "version": version,
                "status": request.status.value,
                "analysis_ids": request.analysis_ids,
                "artifact_sha256": report.artifact_sha256,
            },
        )
        schema = IntelligenceReportSchema.model_validate(report)
    return IntelligenceReportMutationResult(report=schema)


async def query_intelligence_reports_for_user(incident_id: int, *, page=1, size=RESOURCE_PAGE_SIZE, user_id: int, user_role: SystemUserRole):
    async with get_async_session() as session:
        incident = await session.get(ThreatIncident, incident_id)
        if incident is None or (user_role != SystemUserRole.ADMIN and incident.owner_id != user_id):
            return None
        statement = select(IntelligenceReport).where(IntelligenceReport.incident_id == incident_id).order_by(IntelligenceReport.version.desc())
        total = int((await session.execute(select(func.count()).select_from(statement.order_by(None).subquery()))).scalar_one())
        rows = list((await session.exec(statement.offset(page_offset(page, size)).limit(size))).all())
        items = [IntelligenceReportSchema.model_validate(row) for row in rows]
    return Page(page=page, size=size, total=total, items=items)


async def build_intelligence_report_evidence_manifest(
    session,
    incident_id: int,
    analysis_ids: list[int],
) -> IntelligenceReportEvidenceManifest:
    evidence_ids = list(dict.fromkeys((await session.exec(
        select(AnalysisEvidenceLink.evidence_id)
        .where(AnalysisEvidenceLink.analysis_id.in_(analysis_ids))
        .order_by(AnalysisEvidenceLink.evidence_id.asc())
    )).all()))
    behavior_event_ids = list(dict.fromkeys((await session.exec(
        select(EvidenceBehaviorLink.event_id)
        .where(EvidenceBehaviorLink.evidence_id.in_(evidence_ids))
        .order_by(EvidenceBehaviorLink.event_id.asc())
    )).all())) if evidence_ids else []
    environments = list((await session.exec(
        select(ThreatIncidentEnvironment.environment_id)
        .where(ThreatIncidentEnvironment.incident_id == incident_id)
        .order_by(ThreatIncidentEnvironment.environment_id.asc())
    )).all())
    events = list((await session.exec(
        select(BehaviorEvent).where(BehaviorEvent.id.in_(behavior_event_ids))
    )).all()) if behavior_event_ids else []
    await require_behavior_event_integrity(session, events)
    sensor_heads: dict[str, str] = {}
    backend_heads: dict[str, str] = {}
    for event in sorted(events, key=lambda item: (item.environment_id, item.sensor_id, item.sequence)):
        key = f"{event.environment_id}:{event.sensor_id}"
        sensor_heads[key] = event.sensor_event_hash
        backend_heads[key] = event.event_hash
    material_event_ids = set((await session.exec(
        select(ThreatIncidentBehaviorEvent.event_id).where(
            ThreatIncidentBehaviorEvent.incident_id == incident_id,
            ThreatIncidentBehaviorEvent.is_material.is_(True),
        )
    )).all())
    decision_rows = list((await session.exec(
        select(BehaviorDecision)
        .join(BehaviorSignalEvent, BehaviorSignalEvent.decision_id == BehaviorDecision.id)
        .join(BehaviorSignal, BehaviorSignal.id == BehaviorSignalEvent.signal_id)
        .where(
            BehaviorSignal.incident_id == incident_id,
            BehaviorDecision.event_id.in_(behavior_event_ids or [-1]),
        )
        .order_by(BehaviorDecision.id.asc())
    )).all())
    signal_ids = list(dict.fromkeys((await session.exec(
        select(BehaviorSignalEvent.signal_id).where(
            BehaviorSignalEvent.decision_id.in_([item.id for item in decision_rows] or [-1])
        ).order_by(BehaviorSignalEvent.signal_id.asc())
    )).all()))
    rule_version_hashes: dict[str, str] = {}
    for decision in decision_rows:
        for match in decision.matched_rule_versions:
            version_id = match.get("version_id")
            content_hash = match.get("content_sha256")
            if isinstance(version_id, int) and isinstance(content_hash, str):
                rule_version_hashes[str(version_id)] = content_hash
    gaps = list((await session.exec(
        select(AttackChain.gaps).where(AttackChain.analysis_id.in_(analysis_ids))
    )).all())
    known_gaps = list(dict.fromkeys(gap for group in gaps for gap in group))
    return IntelligenceReportEvidenceManifest(
        evidence_ids=evidence_ids,
        behavior_event_ids=behavior_event_ids,
        environment_ids=environments,
        sensor_chain_heads=sensor_heads,
        backend_chain_heads=backend_heads,
        decision_ids=[item.id for item in decision_rows],
        signal_ids=signal_ids,
        bundle_hashes=sorted({item.bundle_hash for item in decision_rows if item.bundle_hash}),
        rule_version_hashes=rule_version_hashes,
        material_event_count=len(material_event_ids),
        covered_event_count=len(material_event_ids.intersection(behavior_event_ids)),
        known_gaps=known_gaps,
    )


async def serialize_threat_indicator(session, record, indicator):
    return ThreatIndicatorSchema.model_validate({
        **record.model_dump(),
        "evidence_ids": await analysis_evidence_ids(session, record.id),
        **indicator.model_dump(exclude={"analysis_id"}),
    })


async def _lock_incident(session, incident_id, user_id, user_role):
    incident = (await session.exec(select(ThreatIncident).where(ThreatIncident.id == incident_id).with_for_update())).one_or_none()
    if incident is None:
        return None, {"not_found": True}
    if user_role != SystemUserRole.ADMIN and incident.owner_id != user_id:
        return None, {"forbidden": True}
    if incident.status == ThreatIncidentStatus.CLOSED:
        return None, {"conflict": True, "message": "closed threat incidents are immutable"}
    return incident, None
