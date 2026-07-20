"""Canonical admission rules for every Agent Run source."""

from sqlalchemy import func
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from model.agent.sessions import AgentContext, AgentSession, AgentToolInvocation
from model.deception.environments import DeceptionEnvironment
from model.sandbox.async_jobs import SandboxAsyncJob
from model.sandbox.containers import SandboxContainer
from model.threat.incidents import ThreatIncident
from schema.agent.types import (
    AgentSessionStatus,
    AgentToolInvocationStatus,
    SessionType,
)
from schema.deception.environments import DeceptionEnvironmentStatus
from schema.sandbox.containers import SandboxContainerStatus
from schema.sandbox.async_jobs import SandboxAsyncJobStatus
from schema.threat.incidents import ThreatIncidentStatus


async def run_admission_block_reason(
    db: AsyncSession,
    agent_session: AgentSession,
    *,
    recovery_count: int | None = None,
    sandbox_recovery_count: int | None = None,
) -> str:
    if agent_session.status != AgentSessionStatus.ACTIVE:
        return "archived agent sessions cannot accept new runs"
    unresolved_count = (
        recovery_count
        if recovery_count is not None
        else await tool_recovery_count(db, agent_session.id)
    )
    if unresolved_count:
        return (
            f"resolve {unresolved_count} ambiguous tool invocation"
            f"{'s' if unresolved_count != 1 else ''} before admitting another Agent Run"
        )
    unresolved_sandbox_count = (
        sandbox_recovery_count
        if sandbox_recovery_count is not None
        else await sandbox_job_recovery_count(db, agent_session.id)
    )
    if unresolved_sandbox_count:
        return (
            f"resolve {unresolved_sandbox_count} ambiguous Sandbox command"
            f"{'s' if unresolved_sandbox_count != 1 else ''} before admitting another Agent Run"
        )
    if agent_session.selected_sandbox_container_id is not None:
        container = await db.get(
            SandboxContainer,
            agent_session.selected_sandbox_container_id,
        )
        if (
            container is None
            or container.status != SandboxContainerStatus.RUNNING
            or container.generation != agent_session.selected_sandbox_generation
        ):
            return "the selected sandbox container generation is unavailable"
    if agent_session.session_type == SessionType.CHAT:
        return ""
    if agent_session.session_type == SessionType.INCIDENT:
        incident = await db.get(ThreatIncident, agent_session.incident_id)
        if incident is None:
            return "the parent threat incident no longer exists"
        if incident.status == ThreatIncidentStatus.CLOSED:
            return "closed threat incidents cannot accept Agent Runs"
        return ""
    if agent_session.session_type == SessionType.ENVIRONMENT:
        environment = await db.get(DeceptionEnvironment, agent_session.environment_id)
        if environment is None:
            return "the parent deception environment no longer exists"
        if environment.status == DeceptionEnvironmentStatus.RETIRED:
            return "retired deception environments cannot accept Agent Runs"
        return ""
    return "unsupported agent session type"


async def tool_recovery_count(db: AsyncSession, session_id: str) -> int:
    return int((await db.exec(select(func.count()).select_from(AgentToolInvocation).join(
        AgentContext,
        AgentContext.id == AgentToolInvocation.context_id,
    ).where(
        AgentContext.session_id == session_id,
        AgentToolInvocation.status == AgentToolInvocationStatus.RECOVERY_REQUIRED,
    ))).one())


async def sandbox_job_recovery_count(db: AsyncSession, session_id: str) -> int:
    return int((await db.exec(select(func.count()).select_from(SandboxAsyncJob).where(
        SandboxAsyncJob.session_id == session_id,
        SandboxAsyncJob.status == SandboxAsyncJobStatus.RECOVERY_REQUIRED,
    ))).one())
