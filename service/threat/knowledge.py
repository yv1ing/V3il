import asyncio
from dataclasses import dataclass

from sqlmodel import select

from database import get_async_session
from logger import get_logger
from model.threat.intelligence import IntelligenceReport
from schema.threat.intelligence import IntelligenceReportStatus, KnowledgePublicationStatus
from schema.threat.investigations import AuditActorType, AuditEventKind
from service.knowledge.resources import enqueue_generated_knowledge_markdown
from service.threat.audit import add_audit_event


logger = get_logger(__name__)
_publication_queue: asyncio.Queue[int] = asyncio.Queue()
_runtime_task: asyncio.Task[None] | None = None


@dataclass(frozen=True)
class _PublicationTarget:
    incident_id: int
    version: int
    markdown: str
    status: IntelligenceReportStatus
    knowledge_status: KnowledgePublicationStatus


async def start_threat_knowledge_runtime():
    global _runtime_task
    if _runtime_task is not None and not _runtime_task.done():
        return
    async with get_async_session() as session:
        pending = list((await session.exec(select(IntelligenceReport.id).where(
            IntelligenceReport.status == IntelligenceReportStatus.FINAL,
            IntelligenceReport.knowledge_status.in_({
                KnowledgePublicationStatus.QUEUED,
                KnowledgePublicationStatus.FAILED,
            }),
        ))).all())
    for report_id in pending:
        _publication_queue.put_nowait(report_id)
    _runtime_task = asyncio.create_task(_publication_loop(), name="threat-knowledge-publication")


async def stop_threat_knowledge_runtime():
    global _runtime_task
    task, _runtime_task = _runtime_task, None
    if task is None or task.done():
        return
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


def request_intelligence_report_publication(report_id: int):
    _publication_queue.put_nowait(report_id)


async def _publication_loop():
    while True:
        report_id = await _publication_queue.get()
        try:
            await _publish(report_id)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("intelligence report knowledge publication failed: %s", report_id)
            await _record_failure(report_id, str(exc) or "knowledge publication failed")
        finally:
            _publication_queue.task_done()


async def _publish(report_id: int):
    async with get_async_session() as session:
        row = (await session.exec(select(
            IntelligenceReport.incident_id,
            IntelligenceReport.version,
            IntelligenceReport.markdown,
            IntelligenceReport.status,
            IntelligenceReport.knowledge_status,
        ).where(IntelligenceReport.id == report_id))).first()
        report = _PublicationTarget(*row) if row is not None else None
    if (
        report is None
        or report.status != IntelligenceReportStatus.FINAL
        or report.knowledge_status == KnowledgePublicationStatus.PUBLISHED
    ):
        return
    file_name = f"incident-{report.incident_id}-report-v{report.version}.md"
    await enqueue_generated_knowledge_markdown(file_name, report.markdown)
    async with get_async_session() as session, session.begin():
        current = (await session.exec(select(IntelligenceReport).where(IntelligenceReport.id == report_id).with_for_update())).one_or_none()
        if current is None:
            return
        current.knowledge_document_name = file_name
        current.knowledge_status = KnowledgePublicationStatus.PUBLISHED
        current.knowledge_error = ""
        session.add(current)
        await add_audit_event(
            session,
            incident_id=current.incident_id,
            kind=AuditEventKind.KNOWLEDGE,
            actor_type=AuditActorType.SYSTEM,
            actor_code="system",
            object_type="intelligence_report",
            object_id=current.id,
            summary="Final intelligence report published to LightRAG.",
            details={"document_name": file_name, "report_version": current.version},
        )


async def _record_failure(report_id: int, message: str):
    async with get_async_session() as session, session.begin():
        report = await session.get(IntelligenceReport, report_id)
        if report is None:
            return
        report.knowledge_status = KnowledgePublicationStatus.FAILED
        report.knowledge_error = message[:4000]
        session.add(report)
        await add_audit_event(
            session,
            incident_id=report.incident_id,
            kind=AuditEventKind.KNOWLEDGE,
            actor_type=AuditActorType.SYSTEM,
            actor_code="system",
            object_type="intelligence_report",
            object_id=report.id,
            summary="Final intelligence report publication to LightRAG failed.",
            details={"error": report.knowledge_error, "report_version": report.version},
        )
