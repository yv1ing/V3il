from sqlalchemy import URL
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

from config import get_config
from logger import get_logger
from model.egress_proxy.proxies import EgressProxy
from model.host.hosts import ManagedHost
from model.deception.environments import DeceptionArtifact, DeceptionEnvironment, DeceptionRevision, DeceptionRevisionStep
from model.detection.rules import (
    BehaviorDecision,
    BehaviorSignal,
    BehaviorSignalEvent,
    DetectionBundle,
    DetectionRule,
    DetectionRuleChangeRequest,
    DetectionRuleDeployment,
    DetectionRuleVersion,
    ManagedHostSensor,
)
from model.sandbox.async_jobs import SandboxAsyncJob
from model.agent.sessions import (
    AgentCompaction,
    AgentContext,
    AgentContextItem,
    AgentEvent,
    AgentRun,
    AgentRunAttempt,
    AgentSegment,
    AgentSession,
    AgentToolInvocation,
)
from model.runtime import RuntimeConsumerReceipt, RuntimeLease, RuntimeOutboxEvent
from model.sandbox.containers import SandboxContainer
from model.sandbox.images import SandboxImage
from model.system_user.users import SystemUser
from model.threat.behaviors import BehaviorEvent, BehaviorSensorCursor, ThreatIncidentBehaviorEvent
from model.threat.analysis import (
    AnalysisEvidenceLink,
    AnalysisRecord,
    AttackerProfile,
    IntentAssessment,
    RiskAssessment,
)
from model.threat.chains import AttackChain
from model.threat.incidents import ThreatIncident, ThreatIncidentEnvironment
from model.threat.intelligence import IntelligenceReport, IntelligenceReportArtifact, ThreatIndicator
from model.threat.investigations import (
    AuditEvent,
    InvestigationEvidence,
    EvidenceBehaviorLink,
    EvidenceRelation,
    InvestigationTask,
    InvestigationTaskDependency,
    InvestigationTaskEvent,
)


logger = get_logger(__name__)

# registered so SQLModel.metadata picks every table up at create_all time
_registered_models = [
    SystemUser, ManagedHost, EgressProxy, SandboxImage, SandboxContainer,
    DeceptionEnvironment, DeceptionRevision, DeceptionRevisionStep, DeceptionArtifact,
    ManagedHostSensor, DetectionRule, DetectionRuleVersion,
    DetectionRuleChangeRequest, DetectionRuleDeployment, DetectionBundle,
    BehaviorDecision, BehaviorSignal, BehaviorSignalEvent,
    ThreatIncident, ThreatIncidentEnvironment, BehaviorEvent, BehaviorSensorCursor,
    ThreatIncidentBehaviorEvent,
    InvestigationTask, InvestigationTaskDependency, InvestigationTaskEvent,
    InvestigationEvidence, EvidenceBehaviorLink, EvidenceRelation, AuditEvent,
    AnalysisRecord, AnalysisEvidenceLink, IntentAssessment, AttackChain,
    ThreatIndicator, AttackerProfile, RiskAssessment, IntelligenceReport,
    IntelligenceReportArtifact,
    AgentSession, AgentContext, AgentRun, AgentRunAttempt, AgentContextItem,
    AgentToolInvocation,
    AgentSegment, AgentEvent, AgentCompaction, SandboxAsyncJob,
    RuntimeOutboxEvent, RuntimeConsumerReceipt, RuntimeLease,
]

_engine: AsyncEngine | None = None


async def create_all_tables() -> None:
    global _engine
    if _engine is None:
        raise RuntimeError("database engine is not initialized")

    async with _engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    logger.info("all tables created")


async def close_engine() -> None:
    global _engine
    if _engine is not None:
        await _engine.dispose()
        _engine = None


def init_engine() -> None:
    global _engine
    if _engine is not None:
        return

    cfg = get_config()
    db = cfg.database
    dsn = URL.create(
        "postgresql+asyncpg",
        username=db.username,
        password=db.password,
        host=db.host,
        port=db.port,
        database=db.database,
    )

    _engine = create_async_engine(
        url=dsn,
        pool_size=db.pool_size,
        max_overflow=db.max_overflow,
        pool_timeout=db.pool_timeout_seconds,
        pool_recycle=db.pool_recycle_seconds,
        pool_pre_ping=db.pool_pre_ping,
    )
    logger.info(
        "async postgres engine initialized (pool_size=%d max_overflow=%d timeout=%ds)",
        db.pool_size, db.max_overflow, db.pool_timeout_seconds,
    )


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        raise RuntimeError("database engine is not initialized")
    return _engine


def get_async_session() -> AsyncSession:
    return AsyncSession(get_engine())
