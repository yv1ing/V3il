import hashlib
import io
import json
import zipfile

from sqlalchemy import and_, or_
from sqlmodel import select

from database import get_async_session
from model.deception.environments import DeceptionArtifact, DeceptionEnvironment, DeceptionRevision
from model.detection.rules import (
    BehaviorDecision,
    BehaviorSignal,
    BehaviorSignalEvent,
    DetectionBundle,
    DetectionRule,
    DetectionRuleChangeRequest,
    DetectionRuleDeployment,
    DetectionRuleVersion,
)
from model.sandbox.containers import SandboxContainer
from model.threat.analysis import AnalysisRecord, AttackerProfile, IntentAssessment, RiskAssessment
from model.threat.behaviors import (
    BehaviorEvent,
    BehaviorSensorCursor,
    ThreatIncidentBehaviorEvent,
)
from model.threat.chains import AttackChain
from model.threat.incidents import ThreatIncident, ThreatIncidentEnvironment
from model.threat.intelligence import IntelligenceReport, IntelligenceReportArtifact, ThreatIndicator
from model.threat.investigations import (
    AuditEvent,
    InvestigationEvidence,
    InvestigationTask,
    InvestigationTaskEvent,
)
from schema.system_user.users import SystemUserRole
from schema.threat.intelligence import IntelligenceReportStatus
from service.deception.environments import serialize_deception_revision
from service.threat.analysis import (
    serialize_attacker_profile,
    serialize_intent_assessment,
    serialize_risk_assessment,
)
from service.threat.analysis_records import analysis_evidence_ids
from service.threat.chains import serialize_attack_chain
from service.threat.event_integrity import require_behavior_event_integrity
from service.threat.intelligence import serialize_threat_indicator
from service.threat.investigations import (
    serialize_investigation_evidence,
    serialize_investigation_task,
)


async def build_report_bundle(
    incident_id: int,
    report_id: int,
    *,
    user_id: int,
    user_role: SystemUserRole,
):
    async with get_async_session() as session:
        incident = await session.get(ThreatIncident, incident_id)
        report = await session.get(IntelligenceReport, report_id)
        if incident is None or report is None or report.incident_id != incident_id:
            return None
        if user_role != SystemUserRole.ADMIN and incident.owner_id != user_id:
            return None
        if report.status != IntelligenceReportStatus.FINAL:
            raise ValueError("only final intelligence reports can be exported")
        artifact = await session.get(IntelligenceReportArtifact, report_id)
        if artifact is None:
            raise RuntimeError("final intelligence report artifact is missing")
        if hashlib.sha256(artifact.content).hexdigest() != artifact.sha256:
            raise RuntimeError("final intelligence report artifact integrity check failed")
        return artifact.content, artifact.filename


async def build_report_bundle_in_session(
    session,
    incident: ThreatIncident,
    report: IntelligenceReport,
):
    incident_id = incident.id
    if incident_id is None or report.id is None or report.incident_id != incident_id:
        raise ValueError("persisted incident and intelligence report are required")
    if report.status != IntelligenceReportStatus.FINAL:
        raise ValueError("only final intelligence reports can be snapshotted")
    analysis_ids = _snapshot_analysis_ids(report)
    incident_environment_links = list((await session.exec(
        select(ThreatIncidentEnvironment)
        .where(ThreatIncidentEnvironment.incident_id == incident_id)
        .order_by(ThreatIncidentEnvironment.environment_id.asc())
    )).all())
    environment_ids = [item.environment_id for item in incident_environment_links]
    environments = list((await session.exec(
        select(DeceptionEnvironment)
        .where(DeceptionEnvironment.id.in_(environment_ids or [-1]))
        .order_by(DeceptionEnvironment.id.asc())
    )).all())
    event_links = list((await session.exec(
        select(ThreatIncidentBehaviorEvent)
        .where(ThreatIncidentBehaviorEvent.incident_id == incident_id)
        .order_by(ThreatIncidentBehaviorEvent.linked_at.asc())
    )).all())
    events = list((await session.exec(
        select(BehaviorEvent)
        .join(
            ThreatIncidentBehaviorEvent,
            ThreatIncidentBehaviorEvent.event_id == BehaviorEvent.id,
        )
        .where(ThreatIncidentBehaviorEvent.incident_id == incident_id)
        .order_by(BehaviorEvent.observed_at.asc(), BehaviorEvent.id.asc())
    )).all())
    await require_behavior_event_integrity(session, events)
    event_ids = [item.id for item in events]
    decisions = list((await session.exec(select(BehaviorDecision).where(
        BehaviorDecision.event_id.in_(event_ids or [-1])
    ).order_by(BehaviorDecision.created_at.asc()))).all())
    signal_links = list((await session.exec(select(BehaviorSignalEvent).where(
        BehaviorSignalEvent.event_id.in_(event_ids or [-1])
    ).order_by(BehaviorSignalEvent.signal_id.asc(), BehaviorSignalEvent.event_id.asc()))).all())
    signal_ids = list(dict.fromkeys(item.signal_id for item in signal_links))
    signals = list((await session.exec(select(BehaviorSignal).where(
        BehaviorSignal.id.in_(signal_ids or [-1])
    ).order_by(BehaviorSignal.created_at.asc()))).all())
    version_ids = sorted({
        int(match["version_id"])
        for decision in decisions
        for match in decision.matched_rule_versions
        if isinstance(match.get("version_id"), int)
    })
    rule_versions = list((await session.exec(select(DetectionRuleVersion).where(
        DetectionRuleVersion.id.in_(version_ids or [-1])
    ).order_by(DetectionRuleVersion.rule_id.asc(), DetectionRuleVersion.version.asc()))).all())
    rule_ids = sorted({item.rule_id for item in rule_versions})
    detection_rules = list((await session.exec(select(DetectionRule).where(
        DetectionRule.id.in_(rule_ids or [-1])
    ).order_by(DetectionRule.id.asc()))).all())
    bundle_hashes = sorted({item.bundle_hash for item in decisions if item.bundle_hash and len(item.bundle_hash) == 64})
    detection_bundles = list((await session.exec(select(DetectionBundle).where(
        DetectionBundle.bundle_hash.in_(bundle_hashes or ["-"])
    ).order_by(DetectionBundle.created_at.asc()))).all())
    deployments = list((await session.exec(select(DetectionRuleDeployment).where(
        DetectionRuleDeployment.target_bundle_hash.in_(bundle_hashes or ["-"])
    ).order_by(DetectionRuleDeployment.started_at.asc()))).all())
    change_ids = sorted({item.change_request_id for item in deployments})
    changes = list((await session.exec(select(DetectionRuleChangeRequest).where(
        DetectionRuleChangeRequest.id.in_(change_ids or [-1])
    ).order_by(DetectionRuleChangeRequest.created_at.asc()))).all())
    tasks = list((await session.exec(
        select(InvestigationTask)
        .where(InvestigationTask.incident_id == incident_id)
        .order_by(InvestigationTask.created_at.asc(), InvestigationTask.id.asc())
    )).all())
    evidence = list((await session.exec(
        select(InvestigationEvidence)
        .join(InvestigationTask, InvestigationTask.id == InvestigationEvidence.task_id)
        .where(InvestigationTask.incident_id == incident_id)
        .order_by(InvestigationEvidence.created_at.asc(), InvestigationEvidence.id.asc())
    )).all())
    task_events = list((await session.exec(
        select(InvestigationTaskEvent)
        .join(InvestigationTask, InvestigationTask.id == InvestigationTaskEvent.task_id)
        .where(InvestigationTask.incident_id == incident_id)
        .order_by(InvestigationTaskEvent.task_id.asc(), InvestigationTaskEvent.event_id.asc())
    )).all())
    audits = list((await session.exec(
        select(AuditEvent)
        .where(AuditEvent.incident_id == incident_id)
        .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
    )).all())
    analysis_records = list((await session.exec(
        select(AnalysisRecord)
        .where(AnalysisRecord.id.in_(analysis_ids or [-1]))
        .order_by(AnalysisRecord.kind.asc(), AnalysisRecord.subject_key.asc())
    )).all())
    if {item.id for item in analysis_records} != set(analysis_ids):
        raise ValueError("report analysis snapshot references missing analysis records")
    revisions = list((await session.exec(
        select(DeceptionRevision)
        .where(DeceptionRevision.environment_id.in_(environment_ids or [-1]))
        .order_by(DeceptionRevision.environment_id.asc(), DeceptionRevision.version.asc())
    )).all())
    artifacts = list((await session.exec(select(DeceptionArtifact).where(
        DeceptionArtifact.environment_id.in_(environment_ids or [-1])
    ).order_by(DeceptionArtifact.created_at.asc()))).all())
    container_ids = {
        item.sandbox_container_id
        for item in environments
        if item.sandbox_container_id is not None
    } | {
        item.execution_container_id
        for item in revisions
        if item.execution_container_id is not None
    }
    containers = list((await session.exec(
        select(SandboxContainer)
        .where(SandboxContainer.id.in_(container_ids or {-1}))
        .order_by(SandboxContainer.id.asc())
    )).all())
    chain_requirements: dict[tuple[int, str], int] = {}
    for event in events:
        key = (event.environment_id, event.sensor_id)
        chain_requirements[key] = max(
            chain_requirements.get(key, 0),
            event.sequence,
        )
    chain_conditions = [
        and_(
            BehaviorEvent.environment_id == environment_id,
            BehaviorEvent.sensor_id == sensor_id,
            BehaviorEvent.sequence <= last_sequence,
        )
        for (environment_id, sensor_id), last_sequence in chain_requirements.items()
    ]
    chain_events = list((await session.exec(
        select(BehaviorEvent)
        .where(or_(*chain_conditions))
        .order_by(
            BehaviorEvent.environment_id.asc(),
            BehaviorEvent.sensor_id.asc(),
            BehaviorEvent.sequence.asc(),
        )
    )).all()) if chain_conditions else []
    sensor_cursors = list((await session.exec(
        select(BehaviorSensorCursor).where(or_(*[
            and_(
                BehaviorSensorCursor.environment_id == environment_id,
                BehaviorSensorCursor.sensor_id == sensor_id,
            )
            for environment_id, sensor_id in chain_requirements
        ]))
    )).all()) if chain_requirements else []
    task_payload = [
        (await serialize_investigation_task(session, item)).model_dump(mode="json")
        for item in tasks
    ]
    evidence_payload = [
        (await serialize_investigation_evidence(session, item)).model_dump(mode="json")
        for item in evidence
    ]
    revision_payload = [
        (await serialize_deception_revision(session, item)).model_dump(mode="json")
        for item in revisions
    ]
    intent_payload = await _serialize_analysis_rows(
        session,
        analysis_ids,
        IntentAssessment,
        serialize_intent_assessment,
    )
    chain_payload = await _serialize_analysis_rows(
        session,
        analysis_ids,
        AttackChain,
        serialize_attack_chain,
    )
    indicator_payload = await _serialize_analysis_rows(
        session,
        analysis_ids,
        ThreatIndicator,
        serialize_threat_indicator,
    )
    profile_payload = await _serialize_analysis_rows(
        session,
        analysis_ids,
        AttackerProfile,
        serialize_attacker_profile,
    )
    risk_payload = await _serialize_analysis_rows(
        session,
        analysis_ids,
        RiskAssessment,
        serialize_risk_assessment,
    )
    analysis_record_payload = [
        {
            **item.model_dump(mode="json"),
            "evidence_ids": await analysis_evidence_ids(session, item.id),
        }
        for item in analysis_records
    ]

    files = {
        "report.md": report.markdown.encode("utf-8"),
        "report.json": _json_bytes(report.model_dump(mode="json")),
        "incident.json": _json_bytes(incident.model_dump(mode="json")),
        "incident-environments.json": _json_bytes([
            item.model_dump(mode="json") for item in incident_environment_links
        ]),
        "environments.json": _json_bytes([
            item.model_dump(mode="json") for item in environments
        ]),
        "containers.json": _json_bytes([
            item.model_dump(mode="json") for item in containers
        ]),
        "behavior-events.ndjson": _ndjson(events),
        "behavior-chain-context.ndjson": _ndjson(chain_events),
        "sensor-verification.json": _json_bytes([
            item.model_dump(mode="json") for item in sensor_cursors
        ]),
        "event-correlations.ndjson": _ndjson(event_links),
        "behavior-decisions.ndjson": _ndjson(decisions),
        "behavior-signals.json": _json_bytes([item.model_dump(mode="json") for item in signals]),
        "behavior-signal-events.ndjson": _ndjson(signal_links),
        "detection-rules.json": _json_bytes([item.model_dump(mode="json") for item in detection_rules]),
        "detection-rule-versions.json": _json_bytes([item.model_dump(mode="json") for item in rule_versions]),
        "detection-bundles.json": _json_bytes([item.model_dump(mode="json") for item in detection_bundles]),
        "detection-rule-changes.json": _json_bytes([item.model_dump(mode="json") for item in changes]),
        "detection-deployments.json": _json_bytes([item.model_dump(mode="json") for item in deployments]),
        "investigation-tasks.json": _json_bytes(task_payload),
        "investigation-evidence.json": _json_bytes(evidence_payload),
        "investigation-task-events.json": _json_bytes([
            item.model_dump(mode="json") for item in task_events
        ]),
        "analysis-records.json": _json_bytes(analysis_record_payload),
        "intent-assessments.json": _json_bytes(intent_payload),
        "attack-chains.json": _json_bytes(chain_payload),
        "threat-indicators.json": _json_bytes(indicator_payload),
        "attacker-profiles.json": _json_bytes(profile_payload),
        "risk-assessments.json": _json_bytes(risk_payload),
        "deception-revisions.json": _json_bytes(revision_payload),
        "deception-artifacts.json": _json_bytes([item.model_dump(mode="json") for item in artifacts]),
        "audit-events.ndjson": _ndjson(audits),
        "evidence-manifest.json": _json_bytes(report.evidence_manifest),
    }
    manifest = {
        "schema_version": 2,
        "incident_id": incident_id,
        "report_id": report.id,
        "report_version": report.version,
        "environment_ids": environment_ids,
        "analysis_snapshot": report.analysis_snapshot,
        "evidence_manifest": report.evidence_manifest,
        "files": {
            name: {
                "bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            for name, content in files.items()
        },
        "created_by_agent_code": report.created_by_agent_code,
        "created_from_session_id": report.created_from_session_id,
        "created_at": report.created_at.isoformat(),
    }
    files["manifest.json"] = _json_bytes(manifest)
    archive_name = f"incident-{incident_id}-report-v{report.version}.zip"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue(), archive_name


async def _serialize_analysis_rows(session, analysis_ids, model, serializer):
    rows = list((await session.exec(
        select(AnalysisRecord, model)
        .join(model, model.analysis_id == AnalysisRecord.id)
        .where(AnalysisRecord.id.in_(analysis_ids or [-1]))
        .order_by(AnalysisRecord.subject_key.asc(), AnalysisRecord.version.asc())
    )).all())
    return [
        (await serializer(session, record, payload)).model_dump(mode="json")
        for record, payload in rows
    ]


def _snapshot_analysis_ids(report: IntelligenceReport) -> list[int]:
    try:
        return list(dict.fromkeys(
            int(item["analysis_id"])
            for item in report.analysis_snapshot
        ))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("report contains an invalid analysis snapshot") from exc


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, indent=2, default=str).encode("utf-8")


def _ndjson(rows):
    if not rows:
        return b""
    return (
        "\n".join(
            json.dumps(row.model_dump(mode="json"), ensure_ascii=False, default=str)
            for row in rows
        )
        + "\n"
    ).encode("utf-8")
