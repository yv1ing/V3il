import asyncio
import hashlib
import io
import zipfile
from dataclasses import dataclass
from datetime import timedelta

from sqlmodel import select

from database import get_async_session
from logger import get_logger
from model.runtime import RuntimeConsumerReceipt, RuntimeOutboxEvent
from model.threat.intelligence import IntelligenceReport, IntelligenceReportArtifact
from schema.runtime import KnowledgePublicationReadyPayload, OutboxTopic
from schema.threat.intelligence import IntelligenceReportStatus, KnowledgePublicationStatus
from schema.threat.investigations import AuditActorType, AuditEventKind
from service.knowledge.resources import (
    enqueue_generated_knowledge_markdown,
    wait_for_generated_knowledge_markdown,
)
from service.knowledge.runtime import request_knowledge_document_processing
from service.runtime.leases import (
    RuntimeLeaseHandle,
    RuntimeLeaseLost,
    RuntimeLeaseUnavailable,
    runtime_lease,
)
from service.threat.audit import add_audit_event
from utils.time import utc_now


logger = get_logger(__name__)

_CONSUMER = "threat-knowledge-publication"
_LEASE_NAME = "threat-knowledge-publication-runtime"
_CLAIM_SECONDS = 60
_POLL_SECONDS = 1.0
_runtime_task: asyncio.Task[None] | None = None
_stop = asyncio.Event()


@dataclass(frozen=True, slots=True)
class _ClaimedPublication:
    event_id: int
    idempotency_key: str
    payload: KnowledgePublicationReadyPayload


@dataclass(frozen=True, slots=True)
class _PublicationMaterial:
    incident_id: int
    report_version: int
    markdown: str


async def start_threat_knowledge_runtime() -> None:
    global _runtime_task
    if _runtime_task is not None and not _runtime_task.done():
        return
    _stop.clear()
    _runtime_task = asyncio.create_task(_publication_loop(), name=_CONSUMER)


async def stop_threat_knowledge_runtime() -> None:
    global _runtime_task
    task, _runtime_task = _runtime_task, None
    if task is None:
        return
    _stop.set()
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)


async def _publication_loop() -> None:
    while not _stop.is_set():
        try:
            async with runtime_lease(
                _LEASE_NAME,
                wait_timeout_seconds=1,
            ) as lease:
                while not _stop.is_set():
                    claim = await _claim_next(lease)
                    if claim is None:
                        try:
                            await asyncio.wait_for(_stop.wait(), timeout=_POLL_SECONDS)
                        except asyncio.TimeoutError:
                            pass
                        continue
                    await _publish(claim, lease)
        except asyncio.CancelledError:
            raise
        except RuntimeLeaseUnavailable:
            continue
        except RuntimeLeaseLost:
            logger.warning("knowledge publication runtime lease ownership changed")
        except Exception:
            logger.exception("intelligence report knowledge publication cycle failed")


async def _claim_next(lease: RuntimeLeaseHandle) -> _ClaimedPublication | None:
    now = utc_now()
    async with get_async_session() as db, db.begin():
        await lease.assert_owned(db, lock=True)
        event = (await db.exec(select(RuntimeOutboxEvent).where(
            RuntimeOutboxEvent.topic == OutboxTopic.KNOWLEDGE_PUBLICATION_READY,
            RuntimeOutboxEvent.published_at.is_(None),
            RuntimeOutboxEvent.available_at <= now,
        ).order_by(RuntimeOutboxEvent.id.asc()).limit(1).with_for_update(skip_locked=True))).one_or_none()
        if event is None or event.id is None:
            return None
        payload = KnowledgePublicationReadyPayload.model_validate(event.payload)
        event.attempt_count += 1
        event.available_at = now + timedelta(seconds=_CLAIM_SECONDS)
        db.add(event)
        return _ClaimedPublication(event.id, event.idempotency_key, payload)


async def _publish(claim: _ClaimedPublication, lease: RuntimeLeaseHandle) -> None:
    await lease.assert_owned()
    material, failure, already_processed = await _load_publication_material(claim)
    if already_processed:
        await _mark_event_published(claim.event_id, lease)
        return
    if failure:
        await _record_failure(claim, failure, lease)
        return
    if material is None:
        await _record_failure(claim, "knowledge publication material is unavailable", lease)
        return

    document_name = (
        f"incident-{material.incident_id}-report-v{material.report_version}-"
        f"{claim.payload.artifact_sha256[:16]}.md"
    )
    try:
        await lease.run_while_owned(
            lambda: _publish_document(document_name, material.markdown)
        )
    except RuntimeLeaseLost:
        raise
    except Exception as exc:
        await _record_failure(claim, str(exc) or "knowledge publication failed", lease)
        return

    async with get_async_session() as db, db.begin():
        await lease.assert_owned(db, lock=True)
        event = (await db.exec(select(RuntimeOutboxEvent).where(
            RuntimeOutboxEvent.id == claim.event_id
        ).with_for_update())).one_or_none()
        report = (await db.exec(select(IntelligenceReport).where(
            IntelligenceReport.id == claim.payload.report_id
        ).with_for_update())).one_or_none()
        if event is None or report is None:
            return
        report.knowledge_document_name = document_name
        report.knowledge_status = KnowledgePublicationStatus.PUBLISHED
        report.knowledge_error = ""
        event.published_at = utc_now()
        event.last_error = ""
        db.add(report)
        db.add(event)
        db.add(RuntimeConsumerReceipt(
            consumer=_CONSUMER,
            idempotency_key=claim.idempotency_key,
        ))
        await add_audit_event(
            db,
            incident_id=report.incident_id,
            kind=AuditEventKind.KNOWLEDGE,
            actor_type=AuditActorType.SYSTEM,
            actor_code="system",
            object_type="intelligence_report",
            object_id=report.id,
            summary="Final intelligence report artifact published to LightRAG.",
            details={
                "document_name": document_name,
                "report_version": report.version,
                "artifact_sha256": claim.payload.artifact_sha256,
            },
        )


async def _publish_document(document_name: str, markdown: str) -> None:
    track_id = await enqueue_generated_knowledge_markdown(document_name, markdown)
    if track_id is not None:
        request_knowledge_document_processing([track_id])
    await wait_for_generated_knowledge_markdown(document_name)


async def _load_publication_material(
    claim: _ClaimedPublication,
) -> tuple[_PublicationMaterial | None, str, bool]:
    async with get_async_session() as db:
        receipt = await db.get(RuntimeConsumerReceipt, (_CONSUMER, claim.idempotency_key))
        if receipt is not None:
            return None, "", True
        report = await db.get(IntelligenceReport, claim.payload.report_id)
        artifact = await db.get(IntelligenceReportArtifact, claim.payload.report_id)
        if report is None or artifact is None:
            return None, "final report artifact is unavailable", False
        if report.status != IntelligenceReportStatus.FINAL:
            return None, "knowledge publication requires a final report", False
        actual_sha256 = hashlib.sha256(artifact.content).hexdigest()
        if (
            actual_sha256 != claim.payload.artifact_sha256
            or artifact.sha256 != claim.payload.artifact_sha256
            or report.artifact_sha256 != claim.payload.artifact_sha256
        ):
            return None, "final report artifact integrity validation failed", False
        try:
            markdown = _report_markdown(artifact.content)
        except ValueError as exc:
            return None, str(exc), False
        return _PublicationMaterial(
            incident_id=report.incident_id,
            report_version=report.version,
            markdown=markdown,
        ), "", False


async def _record_failure(
    claim: _ClaimedPublication,
    message: str,
    lease: RuntimeLeaseHandle,
) -> None:
    error = message[:4000]
    async with get_async_session() as db, db.begin():
        await lease.assert_owned(db, lock=True)
        event = (await db.exec(select(RuntimeOutboxEvent).where(
            RuntimeOutboxEvent.id == claim.event_id
        ).with_for_update())).one_or_none()
        report = (await db.exec(select(IntelligenceReport).where(
            IntelligenceReport.id == claim.payload.report_id
        ).with_for_update())).one_or_none()
        if event is not None:
            event.last_error = error
            delay = min(3600, 2 ** min(event.attempt_count, 10))
            event.available_at = utc_now() + timedelta(seconds=delay)
            db.add(event)
        if report is not None:
            report.knowledge_status = KnowledgePublicationStatus.FAILED
            report.knowledge_error = error
            db.add(report)
            await add_audit_event(
                db,
                incident_id=report.incident_id,
                kind=AuditEventKind.KNOWLEDGE,
                actor_type=AuditActorType.SYSTEM,
                actor_code="system",
                object_type="intelligence_report",
                object_id=report.id,
                summary="Final intelligence report artifact publication failed.",
                details={
                    "error": error,
                    "report_version": report.version,
                    "artifact_sha256": claim.payload.artifact_sha256,
                },
            )


async def _mark_event_published(event_id: int, lease: RuntimeLeaseHandle) -> None:
    async with get_async_session() as db, db.begin():
        await lease.assert_owned(db, lock=True)
        event = await db.get(RuntimeOutboxEvent, event_id)
        if event is not None and event.published_at is None:
            event.published_at = utc_now()
            db.add(event)


def _report_markdown(artifact: bytes) -> str:
    try:
        with zipfile.ZipFile(io.BytesIO(artifact)) as archive:
            return archive.read("report.md").decode("utf-8")
    except (KeyError, UnicodeDecodeError, zipfile.BadZipFile) as exc:
        raise ValueError("final report artifact does not contain valid report Markdown") from exc
