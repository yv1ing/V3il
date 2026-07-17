import json

from agents import RunContextWrapper, function_tool
from sqlmodel import select

from core.agent.constants import DEFAULT_AGENT_CODE
from core.investigation import build_investigation_context
from core.runtime.context import AgentRuntimeContext
from database import get_async_session
from model.deception.environments import DeceptionEnvironment, DeceptionRevision
from model.threat.incidents import ThreatIncident, ThreatIncidentEnvironment
from model.threat.investigations import InvestigationTask
from schema.common.tool_results import ToolResultSchema, ToolResultStatusSchema, ToolResultTypeSchema
from schema.deception.environments import (
    CreateDeceptionArtifactRequest,
    EvaluateDeceptionRevisionRequest,
    PlanDeceptionRevisionRequest,
)
from schema.deception.workloads import CreateObservedWorkloadRequest
from schema.threat.analysis import (
    CreateAttackerProfileRequest,
    CreateIntentAssessmentRequest,
    CreateRiskAssessmentRequest,
)
from schema.threat.behaviors import AssignBehaviorEventsRequest, BehaviorEventCategory
from schema.threat.chains import CreateAttackChainRequest
from schema.threat.intelligence import CreateIntelligenceReportRequest, CreateThreatIndicatorRequest
from schema.threat.incidents import ThreatIncidentStatus
from schema.threat.investigations import (
    CreateInvestigationEvidenceRequest,
    CreateInvestigationTaskRequest,
    InvestigationReviewDecision,
    InvestigationTaskStatus,
)
from service.deception.environments import (
    create_deception_artifact,
    evaluate_deception_revision,
    plan_deception_revision as create_deception_revision,
)
from service.deception.executions import (
    execute_deception_revision,
    recover_deception_revision_rollback,
)
from service.deception.workloads import start_deception_workload, stop_deception_workload
from service.threat.analysis import create_attacker_profile, create_intent_assessment, create_risk_assessment
from service.threat.behaviors import (
    assign_behavior_events_to_incident,
    query_incident_behavior_events_for_user,
)
from service.threat.chains import create_attack_chain
from service.threat.intelligence import create_intelligence_report, create_threat_indicator
from service.threat.state import transition_threat_incident
from service.threat.investigations import (
    activate_investigation_task as activate_investigation_task_service,
    block_investigation_task as block_investigation_task_service,
    create_investigation_evidence as create_investigation_evidence_service,
    create_investigation_task as create_investigation_task_service,
    query_investigation_tasks_for_user,
    review_investigation_task as review_investigation_task_service,
    submit_investigation_task as submit_investigation_task_service,
)


_PAGE_SIZE = 20


def investigation_success(payload: object) -> str:
    return ToolResultSchema(
        status=ToolResultStatusSchema.SUCCESS,
        type=ToolResultTypeSchema.INVESTIGATION,
        output=json.dumps(payload, ensure_ascii=False, default=str),
    ).model_dump_json()


def investigation_error(message: str) -> str:
    return ToolResultSchema(
        status=ToolResultStatusSchema.ERROR,
        type=ToolResultTypeSchema.INVESTIGATION,
        output=message,
    ).model_dump_json()


@function_tool
async def load_investigation_context(ctx: RunContextWrapper[AgentRuntimeContext]) -> str:
    """Refresh the authoritative threat investigation context for this session.

    Args:
        None. The current session and incident are supplied by the Agent runtime.

    Returns:
        JSON tool result containing the current incident, environment, assigned
        behavior, investigation records, and analysis state, or an error when no
        incident is bound to the session.
    """
    if ctx.context.incident_id is None:
        return investigation_error("No threat incident is bound to this session.")
    return investigation_success(await build_investigation_context(ctx.context))


@function_tool
async def update_incident_state(
    ctx: RunContextWrapper[AgentRuntimeContext],
    status: ThreatIncidentStatus,
    reason: str,
) -> str:
    """Update the current incident state and evidence-backed assessment as cso.

    Args:
        status: Explicit target state allowed by the incident state machine.
        reason: Evidence-backed reason for the transition.

    Returns:
        JSON tool result containing the updated threat incident, or an error when
        the caller is not cso or the requested transition cannot be applied.
    """
    if ctx.context.agent_code != DEFAULT_AGENT_CODE:
        return investigation_error("Only cso can update threat incident state.")
    incident_id = _incident_id(ctx)
    if incident_id is None:
        return investigation_error("No threat incident is bound to this session.")
    result = await transition_threat_incident(
        incident_id,
        status,
        reason,
        user_id=ctx.context.user.id,
        user_role=ctx.context.user.role,
        agent_code=ctx.context.agent_code,
        session_id=ctx.context.session_id,
        preserve_session_id=ctx.context.session_id,
    )
    if result.incident is None:
        return investigation_error(result.message or "Threat incident could not be updated.")
    return investigation_success({"incident": result.incident.model_dump(mode="json")})


@function_tool
async def list_investigation_tasks(
    ctx: RunContextWrapper[AgentRuntimeContext],
    status: InvestigationTaskStatus | None = None,
    keyword: str = "",
    page: int = 1,
) -> str:
    """List investigation tasks in the current incident.

    Specialists receive only their own assignments. cso receives the incident queue.

    Args:
        status: Optional task status used to filter the incident queue.
        keyword: Optional text matched against task content.
        page: One-based result page; values below one are normalized to one.

    Returns:
        JSON tool result containing pagination metadata and visible investigation
        tasks, or an error when the bound incident is unavailable.
    """
    incident_id = _incident_id(ctx)
    if incident_id is None:
        return investigation_error("No threat incident is bound to this session.")
    result = await query_investigation_tasks_for_user(
        incident_id,
        page=max(page, 1),
        size=_PAGE_SIZE,
        status=status,
        keyword=keyword,
        user_id=ctx.context.user.id,
        user_role=ctx.context.user.role,
    )
    if result is None:
        return investigation_error("Threat incident not found.")
    tasks = result.items
    if ctx.context.agent_code != DEFAULT_AGENT_CODE:
        tasks = [task for task in tasks if task.assignee_agent_code == ctx.context.agent_code]
    return investigation_success({
        "page": result.page,
        "size": result.size,
        "total": result.total,
        "tasks": [task.model_dump(mode="json") for task in tasks],
    })


@function_tool
async def create_investigation_task(
    ctx: RunContextWrapper[AgentRuntimeContext],
    task: CreateInvestigationTaskRequest,
) -> str:
    """Create a queued evidence-driven investigation task as cso.

    Args:
        task: Validated task definition including specialist assignment,
            dependencies, completion criteria, and the incident behavior event IDs
            that form the task's mandatory evidence scope.

    Returns:
        JSON tool result containing the created task, or an error when the caller
        lacks cso authority or the task violates incident workflow constraints.
    """
    if ctx.context.agent_code != DEFAULT_AGENT_CODE:
        return investigation_error("Only cso can plan investigation tasks.")
    incident_id = _incident_id(ctx)
    if incident_id is None:
        return investigation_error("No threat incident is bound to this session.")
    result = await create_investigation_task_service(
        incident_id,
        task,
        user_id=ctx.context.user.id,
        user_role=ctx.context.user.role,
        agent_code=ctx.context.agent_code,
        session_id=ctx.context.session_id,
    )
    return _task_result(result)


@function_tool
async def activate_investigation_task(
    ctx: RunContextWrapper[AgentRuntimeContext],
    task_id: int,
) -> str:
    """Activate a queued task or resume the bound blocked specialist task.

    Args:
        task_id: Positive identifier of the investigation task to activate.

    Returns:
        JSON tool result containing the updated task, or an error when assignment,
        dependency, binding, or state-transition requirements are not satisfied.
    """
    if error := _specialist_task_id_error(ctx, task_id):
        return investigation_error(error)
    incident_id = _incident_id(ctx)
    if incident_id is None:
        return investigation_error("No threat incident is bound to this session.")
    result = await activate_investigation_task_service(
        incident_id,
        task_id,
        user_id=ctx.context.user.id,
        user_role=ctx.context.user.role,
        agent_code=ctx.context.agent_code,
        session_id=ctx.context.session_id,
    )
    return _task_result(result)


@function_tool
async def block_investigation_task(
    ctx: RunContextWrapper[AgentRuntimeContext],
    task_id: int,
    reason: str,
) -> str:
    """Block the active runtime-bound task with a concrete resume condition.

    Args:
        task_id: Positive identifier of the investigation task to block.
        reason: Concrete blocker and the condition required to resume the task.

    Returns:
        JSON tool result containing the blocked task, or an error when the task is
        not active, visible, assigned, or bound to the current specialist runtime.
    """
    if error := _specialist_task_id_error(ctx, task_id):
        return investigation_error(error)
    incident_id = _incident_id(ctx)
    if incident_id is None:
        return investigation_error("No threat incident is bound to this session.")
    result = await block_investigation_task_service(
        incident_id,
        task_id,
        reason,
        user_id=ctx.context.user.id,
        user_role=ctx.context.user.role,
        agent_code=ctx.context.agent_code,
        session_id=ctx.context.session_id,
    )
    return _task_result(result)


@function_tool
async def submit_investigation_task(
    ctx: RunContextWrapper[AgentRuntimeContext],
    task_id: int,
    result_summary: str,
) -> str:
    """Submit an evidence-backed active task to cso for review.

    Args:
        task_id: Positive identifier of the investigation task to submit.
        result_summary: Concise evidence-backed result and any remaining unknowns.

    Returns:
        JSON tool result containing the submitted task, or an error when evidence,
        completion, assignment, binding, or state requirements are not satisfied.
    """
    if error := _specialist_task_id_error(ctx, task_id):
        return investigation_error(error)
    incident_id = _incident_id(ctx)
    if incident_id is None:
        return investigation_error("No threat incident is bound to this session.")
    result = await submit_investigation_task_service(
        incident_id,
        task_id,
        result_summary,
        user_id=ctx.context.user.id,
        user_role=ctx.context.user.role,
        agent_code=ctx.context.agent_code,
        session_id=ctx.context.session_id,
    )
    return _task_result(result)


@function_tool
async def review_investigation_task(
    ctx: RunContextWrapper[AgentRuntimeContext],
    task_id: int,
    decision: InvestigationReviewDecision,
    reason: str,
) -> str:
    """Accept a submitted task or return it for changes as cso.

    Args:
        task_id: Positive identifier of the submitted investigation task.
        decision: Review decision that accepts the result or requests changes.
        reason: Evidence-based review rationale and any required follow-up work.

    Returns:
        JSON tool result containing the reviewed task, or an error when the caller
        is not cso or the task cannot transition from its current state.
    """
    if ctx.context.agent_code != DEFAULT_AGENT_CODE:
        return investigation_error("Only cso can review investigation tasks.")
    incident_id = _incident_id(ctx)
    if incident_id is None:
        return investigation_error("No threat incident is bound to this session.")
    result = await review_investigation_task_service(
        incident_id,
        task_id,
        decision,
        reason,
        user_id=ctx.context.user.id,
        user_role=ctx.context.user.role,
        agent_code=ctx.context.agent_code,
        session_id=ctx.context.session_id,
    )
    return _task_result(result)


@function_tool
async def assign_behavior_events(
    ctx: RunContextWrapper[AgentRuntimeContext],
    request: AssignBehaviorEventsRequest,
) -> str:
    """Assign captured environment behavior events to the current incident.

    Args:
        request: Validated event identifiers to link to the bound threat incident.

    Returns:
        JSON tool result describing the resulting event assignment, including
        idempotent existing links, or an error for inaccessible or invalid events.
    """
    incident_id = _incident_id(ctx)
    if incident_id is None:
        return investigation_error("No threat incident is bound to this session.")
    try:
        result = await assign_behavior_events_to_incident(
            incident_id,
            request,
            user_id=ctx.context.user.id,
            user_role=ctx.context.user.role,
            agent_code=ctx.context.agent_code,
            session_id=ctx.context.session_id,
        )
    except ValueError as exc:
        return investigation_error(str(exc))
    return investigation_error("Threat incident not found.") if result is None else investigation_success(
        result.model_dump(mode="json")
    )


@function_tool
async def list_incident_behavior_events(
    ctx: RunContextWrapper[AgentRuntimeContext],
    category: BehaviorEventCategory | None = None,
    keyword: str = "",
    page: int = 1,
) -> str:
    """Page through behavior events assigned to the current threat incident.

    Args:
        category: Optional behavior category used to filter assigned events.
        keyword: Optional text matched against searchable behavior fields.
        page: One-based result page; values below one are normalized to one.

    Returns:
        JSON tool result containing pagination metadata and assigned behavior
        events, or an error when the incident or environment is unavailable.
    """
    incident_id = await _resolved_incident_id(ctx)
    if incident_id is None:
        return investigation_error("Threat incident not found.")
    result = await query_incident_behavior_events_for_user(
        incident_id,
        page=max(page, 1),
        size=_PAGE_SIZE,
        category=category,
        keyword=keyword,
        user_id=ctx.context.user.id,
        user_role=ctx.context.user.role,
    )
    if result is None:
        return investigation_error("Threat incident not found.")
    return investigation_success({
        "page": result.page,
        "size": result.size,
        "total": result.total,
        "events": [event.model_dump(mode="json") for event in result.items],
    })


@function_tool
async def record_investigation_evidence(
    ctx: RunContextWrapper[AgentRuntimeContext],
    task_id: int,
    evidence: CreateInvestigationEvidenceRequest,
) -> str:
    """Record immutable behavior-backed evidence for an investigation task.

    Args:
        task_id: Positive identifier of the task that owns the evidence.
        evidence: Validated evidence content, provenance, and supporting behavior
            event identifiers.

    Returns:
        JSON tool result containing the immutable evidence record, or an error when
        task binding, assignment, state, or evidence provenance validation fails.
    """
    if error := await _specialist_mutation_error(ctx, task_id):
        return investigation_error(error)
    incident_id = _incident_id(ctx)
    if incident_id is None:
        return investigation_error("No threat incident is bound to this session.")
    result = await create_investigation_evidence_service(
        incident_id,
        task_id,
        evidence,
        user_id=ctx.context.user.id,
        user_role=ctx.context.user.role,
        agent_code=ctx.context.agent_code,
        session_id=ctx.context.session_id,
    )
    if result.evidence is not None:
        return investigation_success({"evidence": result.evidence.model_dump(mode="json")})
    return investigation_error(result.message or "Investigation evidence could not be recorded.")


@function_tool
async def record_intent_assessment(
    ctx: RunContextWrapper[AgentRuntimeContext],
    assessment: CreateIntentAssessmentRequest,
) -> str:
    """Record an evidence-backed assessment of attacker stage and intent.

    Args:
        assessment: Validated intent hypothesis, confidence, rationale, predicted
            actions, ATT&CK techniques, and investigation evidence IDs.

    Returns:
        JSON tool result containing the immutable intent assessment, or an error
        when evidence, supersession, incident, or specialist-state validation fails.
    """
    if error := await _specialist_mutation_error(ctx):
        return investigation_error(error)
    incident_id = _incident_id(ctx)
    if incident_id is None:
        return investigation_error("No threat incident is bound to this session.")
    result = await create_intent_assessment(
        incident_id,
        assessment,
        user_id=ctx.context.user.id,
        user_role=ctx.context.user.role,
        agent_code=ctx.context.agent_code,
        session_id=ctx.context.session_id,
        investigation_task_id=ctx.context.investigation_task_id,
    )
    return investigation_error(result.message or "Intent assessment could not be recorded.") if result.assessment is None else investigation_success(
        {"assessment": result.assessment.model_dump(mode="json")}
    )


@function_tool
async def record_attack_chain(
    ctx: RunContextWrapper[AgentRuntimeContext],
    chain: CreateAttackChainRequest,
) -> str:
    """Record an ordered evidence-backed reconstruction of attacker behavior.

    Args:
        chain: Validated attack-chain summary and ordered steps with supporting
            evidence IDs, confidence, timestamps, and ATT&CK techniques.

    Returns:
        JSON tool result containing the immutable attack chain, or an error when
        its evidence, sequence, supersession, or task context is invalid.
    """
    if error := await _specialist_mutation_error(ctx):
        return investigation_error(error)
    incident_id = _incident_id(ctx)
    if incident_id is None:
        return investigation_error("No threat incident is bound to this session.")
    result = await create_attack_chain(
        incident_id,
        chain,
        user_id=ctx.context.user.id,
        user_role=ctx.context.user.role,
        agent_code=ctx.context.agent_code,
        session_id=ctx.context.session_id,
        investigation_task_id=ctx.context.investigation_task_id,
    )
    return investigation_error(result.message or "Attack chain could not be recorded.") if result.chain is None else investigation_success(
        {"attack_chain": result.chain.model_dump(mode="json")}
    )


@function_tool
async def record_threat_indicator(
    ctx: RunContextWrapper[AgentRuntimeContext],
    indicator: CreateThreatIndicatorRequest,
) -> str:
    """Record a normalized threat indicator with evidence provenance.

    Args:
        indicator: Validated indicator type, value, disposition, confidence,
            observation window, and investigation evidence IDs.

    Returns:
        JSON tool result containing the immutable normalized indicator, or an error
        when normalization, evidence, supersession, or task validation fails.
    """
    if error := await _specialist_mutation_error(ctx):
        return investigation_error(error)
    incident_id = _incident_id(ctx)
    if incident_id is None:
        return investigation_error("No threat incident is bound to this session.")
    result = await create_threat_indicator(
        incident_id,
        indicator,
        user_id=ctx.context.user.id,
        user_role=ctx.context.user.role,
        agent_code=ctx.context.agent_code,
        session_id=ctx.context.session_id,
        investigation_task_id=ctx.context.investigation_task_id,
    )
    return investigation_error(result.message or "Threat indicator could not be recorded.") if result.indicator is None else investigation_success(
        {"indicator": result.indicator.model_dump(mode="json")}
    )


@function_tool
async def record_attacker_profile(
    ctx: RunContextWrapper[AgentRuntimeContext],
    profile: CreateAttackerProfileRequest,
) -> str:
    """Record a versioned, evidence-backed attacker profile proposal.

    Args:
        profile: Validated objectives, capabilities, tooling, infrastructure,
            operational patterns, attribution limits, confidence, and evidence IDs.

    Returns:
        JSON tool result containing the immutable profile version, or an error.
        Specialist output remains non-current until cso accepts its InvestigationTask.
    """
    if error := await _specialist_mutation_error(ctx):
        return investigation_error(error)
    incident_id = _incident_id(ctx)
    if incident_id is None:
        return investigation_error("No threat incident is bound to this session.")
    result = await create_attacker_profile(
        incident_id,
        profile,
        user_id=ctx.context.user.id,
        user_role=ctx.context.user.role,
        agent_code=ctx.context.agent_code,
        session_id=ctx.context.session_id,
        investigation_task_id=ctx.context.investigation_task_id,
    )
    return investigation_error(result.message or "Attacker profile could not be recorded.") if result.profile is None else investigation_success(
        {"attacker_profile": result.profile.model_dump(mode="json")}
    )


@function_tool
async def record_risk_assessment(
    ctx: RunContextWrapper[AgentRuntimeContext],
    risk: CreateRiskAssessmentRequest,
) -> str:
    """Record a versioned, evidence-backed incident risk assessment proposal.

    Args:
        risk: Validated severity, confidence, score, rationale, stop conditions,
            response guidance, residual risk, and investigation evidence IDs.

    Returns:
        JSON tool result containing the immutable risk version, or an error.
        Specialist output does not change Incident risk until cso accepts its task.
    """
    if error := await _specialist_mutation_error(ctx):
        return investigation_error(error)
    incident_id = _incident_id(ctx)
    if incident_id is None:
        return investigation_error("No threat incident is bound to this session.")
    result = await create_risk_assessment(
        incident_id,
        risk,
        user_id=ctx.context.user.id,
        user_role=ctx.context.user.role,
        agent_code=ctx.context.agent_code,
        session_id=ctx.context.session_id,
        investigation_task_id=ctx.context.investigation_task_id,
    )
    return investigation_error(result.message or "Risk assessment could not be recorded.") if result.risk is None else investigation_success(
        {"risk_assessment": result.risk.model_dump(mode="json")}
    )


@function_tool
async def record_intelligence_report(
    ctx: RunContextWrapper[AgentRuntimeContext],
    report: CreateIntelligenceReportRequest,
) -> str:
    """Record a structured threat intelligence report for the current incident.

    Args:
        report: Validated report sections, analysis snapshot IDs, status, and
            complete Markdown output.

    Returns:
        JSON tool result containing the immutable report version, or an error when
        evidence links, final-report gates, supersession, or task validation fails.
    """
    if error := await _specialist_mutation_error(ctx):
        return investigation_error(error)
    incident_id = _incident_id(ctx)
    if incident_id is None:
        return investigation_error("No threat incident is bound to this session.")
    result = await create_intelligence_report(
        incident_id,
        report,
        user_id=ctx.context.user.id,
        user_role=ctx.context.user.role,
        agent_code=ctx.context.agent_code,
        session_id=ctx.context.session_id,
    )
    return investigation_error(result.message or "Intelligence report could not be recorded.") if result.report is None else investigation_success(
        {"report": result.report.model_dump(mode="json")}
    )


@function_tool
async def plan_deception_revision(
    ctx: RunContextWrapper[AgentRuntimeContext],
    revision: PlanDeceptionRevisionRequest,
    environment_id: int | None = None,
) -> str:
    """Plan an evidence-triggered adjustment to the deception environment.

    Args:
        revision: Validated rationale, complete resulting persona and service
            inventory, declarative changes, expected effects, execution commands,
            and optional triggering behavior event.
        environment_id: Incident environment to revise. Omit only when the runtime
            is already environment-bound or its selected container identifies it.

    Returns:
        JSON tool result containing the planned deception revision, or an error
        when the environment, trigger evidence, task state, or revision state is invalid.
    """
    if ctx.context.environment_id is None and (error := await _specialist_mutation_error(ctx)):
        return investigation_error(error)
    incident_id = await _resolved_incident_id(ctx)
    environment_id = await _deception_environment_id(
        ctx,
        incident_id,
        environment_id,
    )
    if environment_id is None:
        return investigation_error("No deception environment is available for the selected sandbox container.")
    result = await create_deception_revision(
        environment_id,
        revision,
        user_id=ctx.context.user.id,
        user_role=ctx.context.user.role,
        agent_code=ctx.context.agent_code,
        session_id=ctx.context.session_id,
        incident_id=incident_id,
        investigation_task_id=ctx.context.investigation_task_id,
    )
    return investigation_error(result.message or "Deception revision could not be planned.") if result.revision is None else investigation_success(
        {"revision": result.revision.model_dump(mode="json")}
    )


@function_tool
async def execute_planned_deception_revision(
    ctx: RunContextWrapper[AgentRuntimeContext],
    revision_id: int,
) -> str:
    """Execute, verify, and automatically roll back a planned deception revision.

    Args:
        revision_id: Positive identifier of the planned deception revision.

    Returns:
        JSON tool result containing the applied revision after every change verifies,
        or an error containing rolled-back or failed state when execution cannot finish.
    """
    if ctx.context.environment_id is None and (error := await _specialist_mutation_error(ctx)):
        return investigation_error(error)
    incident_id = await _resolved_incident_id(ctx)
    async with get_async_session() as session:
        revision_environment_id = (await session.exec(select(DeceptionRevision.environment_id).where(
            DeceptionRevision.id == revision_id
        ))).one_or_none()
    if revision_environment_id is None:
        return investigation_error("Deception revision not found.")
    environment_id = await _deception_environment_id(
        ctx,
        incident_id,
        revision_environment_id,
    )
    if environment_id is None:
        return investigation_error("No deception environment is available for the selected sandbox container.")
    result = await execute_deception_revision(
        environment_id,
        revision_id,
        user_id=ctx.context.user.id,
        user_role=ctx.context.user.role,
        agent_code=ctx.context.agent_code,
        session_id=ctx.context.session_id,
        incident_id=incident_id,
        investigation_task_id=ctx.context.investigation_task_id,
    )
    if result.revision is None:
        return investigation_error(result.message or "Deception revision could not be executed.")
    if result.conflict:
        return investigation_error(json.dumps({
            "message": result.message or "Deception revision execution did not complete.",
            "revision": result.revision.model_dump(mode="json"),
        }, ensure_ascii=False, default=str))
    return investigation_success({"revision": result.revision.model_dump(mode="json")})


@function_tool
async def recover_deception_revision(
    ctx: RunContextWrapper[AgentRuntimeContext],
    revision_id: int,
) -> str:
    """Retry the idempotent rollback for a revision that requires recovery.

    Args:
        revision_id: Positive identifier of the recovery-required active revision.

    Returns:
        JSON tool result containing the rolled-back revision, or an error preserving
        the recovery-required state when rollback still cannot finish.
    """
    if ctx.context.environment_id is None and (error := await _specialist_mutation_error(ctx)):
        return investigation_error(error)
    async with get_async_session() as session:
        revision_environment_id = (await session.exec(select(DeceptionRevision.environment_id).where(
            DeceptionRevision.id == revision_id,
        ))).one_or_none()
    if revision_environment_id is None:
        return investigation_error("Deception revision not found.")
    environment_id = await _deception_environment_id(
        ctx,
        await _resolved_incident_id(ctx),
        revision_environment_id,
    )
    if environment_id is None:
        return investigation_error("No deception environment is available for rollback recovery.")
    result = await recover_deception_revision_rollback(
        environment_id,
        revision_id,
        user_id=ctx.context.user.id,
        user_role=ctx.context.user.role,
        agent_code=ctx.context.agent_code,
        session_id=ctx.context.session_id,
    )
    if result.revision is None:
        return investigation_error(result.message or "Deception rollback recovery could not start.")
    if result.conflict:
        return investigation_error(json.dumps({
            "message": result.message or "Deception rollback recovery did not complete.",
            "revision": result.revision.model_dump(mode="json"),
        }, ensure_ascii=False, default=str))
    return investigation_success({"revision": result.revision.model_dump(mode="json")})


@function_tool
async def register_deception_artifact(
    ctx: RunContextWrapper[AgentRuntimeContext],
    environment_id: int,
    artifact: CreateDeceptionArtifactRequest,
) -> str:
    """Register an auditable lure artifact for a planned or active revision.

    Args:
        environment_id: Positive deception environment identifier.
        artifact: Validated revision binding, kind, locator, detection fingerprint,
            name, and operator-facing description.

    Returns:
        JSON tool result containing the immutable artifact identity, or an error.
        Only cde may register artifacts and registration does not approve a revision.
    """
    if error := await _specialist_mutation_error(ctx):
        return investigation_error(error)
    try:
        result = await create_deception_artifact(
            environment_id,
            artifact,
            user_id=ctx.context.user.id,
            user_role=ctx.context.user.role,
            agent_code=ctx.context.agent_code,
            session_id=ctx.context.session_id,
        )
        return investigation_success({"artifact": result.model_dump(mode="json")})
    except Exception as exc:
        return investigation_error(str(exc) or "Deception artifact could not be registered.")


@function_tool
async def record_deception_revision_evaluation(
    ctx: RunContextWrapper[AgentRuntimeContext],
    environment_id: int,
    revision_id: int,
    evaluation: EvaluateDeceptionRevisionRequest,
) -> str:
    """Record cde's evidence-backed terminal evaluation of an adaptive revision.

    Args:
        environment_id: Positive deception environment identifier.
        revision_id: Positive applied adaptive revision identifier.
        evaluation: Effective, ineffective, or inconclusive result with evidence-backed summary.

    Returns:
        JSON tool result containing the evaluated revision, or an error when the
        revision/task binding is invalid. The result is immutable once terminal.
    """
    if error := await _specialist_mutation_error(ctx):
        return investigation_error(error)
    try:
        result = await evaluate_deception_revision(
            environment_id,
            revision_id,
            evaluation,
            user_id=ctx.context.user.id,
            user_role=ctx.context.user.role,
            agent_code=ctx.context.agent_code,
            session_id=ctx.context.session_id,
            investigation_task_id=ctx.context.investigation_task_id,
        )
        return investigation_success({"revision": result.model_dump(mode="json")})
    except Exception as exc:
        return investigation_error(str(exc) or "Deception revision evaluation could not be recorded.")


@function_tool
async def start_observed_deception_workload(
    ctx: RunContextWrapper[AgentRuntimeContext],
    workload: CreateObservedWorkloadRequest,
    environment_id: int | None = None,
) -> str:
    """Start a deception workload under the container behavior sensor.

    Args:
        workload: Validated workload name, command, working directory, and runtime
            environment variables.
        environment_id: Incident environment that owns the workload.

    Returns:
        JSON tool result containing observed workload identity and process state,
        or an error when the environment, container, or task cannot start it.
    """
    if ctx.context.environment_id is None and (error := await _specialist_mutation_error(ctx)):
        return investigation_error(error)
    incident_id = await _resolved_incident_id(ctx)
    environment_id = await _deception_environment_id(
        ctx,
        incident_id,
        environment_id,
    )
    if environment_id is None:
        return investigation_error("No deception environment is available for the selected sandbox container.")
    result = await start_deception_workload(
        environment_id,
        workload,
        user_id=ctx.context.user.id,
        user_role=ctx.context.user.role,
    )
    return investigation_error(result.message or "Observed workload could not be started.") if result.workload is None else investigation_success(
        {"workload": result.workload.model_dump(mode="json")}
    )


@function_tool
async def stop_observed_deception_workload(
    ctx: RunContextWrapper[AgentRuntimeContext],
    run_id: str,
    environment_id: int | None = None,
) -> str:
    """Stop a deception workload through the container behavior sensor.

    Args:
        run_id: Persistent observed-workload identifier returned when it was started.
        environment_id: Incident environment that owns the workload.

    Returns:
        JSON tool result containing the latest observed workload state, or an error
        when the workload, environment, container, or task is unavailable.
    """
    if ctx.context.environment_id is None and (error := await _specialist_mutation_error(ctx)):
        return investigation_error(error)
    incident_id = await _resolved_incident_id(ctx)
    environment_id = await _deception_environment_id(
        ctx,
        incident_id,
        environment_id,
    )
    if environment_id is None:
        return investigation_error("No deception environment is available for the selected sandbox container.")
    result = await stop_deception_workload(
        environment_id,
        run_id,
        user_id=ctx.context.user.id,
        user_role=ctx.context.user.role,
    )
    return investigation_error(result.message or "Observed workload could not be stopped.") if result.workload is None else investigation_success(
        {"workload": result.workload.model_dump(mode="json")}
    )


def _incident_id(ctx: RunContextWrapper[AgentRuntimeContext]) -> int | None:
    return ctx.context.incident_id


async def _resolved_incident_id(ctx: RunContextWrapper[AgentRuntimeContext]) -> int | None:
    incident_id = _incident_id(ctx)
    if incident_id is None:
        return None
    async with get_async_session() as session:
        return (await session.exec(select(ThreatIncident.id).where(
            ThreatIncident.id == incident_id
        ))).one_or_none()


async def _deception_environment_id(
    ctx: RunContextWrapper[AgentRuntimeContext],
    incident_id: int | None,
    requested_environment_id: int | None,
) -> int | None:
    if ctx.context.environment_id is not None:
        if requested_environment_id not in {None, ctx.context.environment_id}:
            return None
        return ctx.context.environment_id
    if incident_id is None:
        return None
    async with get_async_session() as session:
        statement = (
            select(DeceptionEnvironment.id)
            .join(
                ThreatIncidentEnvironment,
                ThreatIncidentEnvironment.environment_id == DeceptionEnvironment.id,
            )
            .where(ThreatIncidentEnvironment.incident_id == incident_id)
        )
        if requested_environment_id is not None:
            statement = statement.where(DeceptionEnvironment.id == requested_environment_id)
        elif ctx.context.sandbox_container_id is not None:
            statement = statement.where(
                DeceptionEnvironment.sandbox_container_id == ctx.context.sandbox_container_id
            )
        return (await session.exec(
            statement.order_by(ThreatIncidentEnvironment.last_observed_at.desc()).limit(1)
        )).first()


def _specialist_task_id_error(
    ctx: RunContextWrapper[AgentRuntimeContext],
    task_id: int,
) -> str:
    if ctx.context.agent_code == DEFAULT_AGENT_CODE:
        return ""
    if ctx.context.investigation_task_id is None:
        return "No investigation task is bound to this specialist runtime."
    if ctx.context.investigation_task_id != task_id:
        return "Specialists can mutate only their runtime-bound investigation task."
    return ""


async def _specialist_mutation_error(
    ctx: RunContextWrapper[AgentRuntimeContext],
    task_id: int | None = None,
) -> str:
    if ctx.context.agent_code == DEFAULT_AGENT_CODE:
        return ""
    bound_id = ctx.context.investigation_task_id
    if bound_id is None:
        return "No investigation task is bound to this specialist runtime."
    if task_id is not None and task_id != bound_id:
        return "Specialists can mutate only their runtime-bound investigation task."
    async with get_async_session() as session:
        task = (await session.exec(select(
            InvestigationTask.incident_id,
            InvestigationTask.assignee_agent_code,
            InvestigationTask.status,
        ).where(InvestigationTask.id == bound_id))).one_or_none()
    if task is None:
        return "The runtime-bound investigation task was not found in this threat incident."
    incident_id, assignee_agent_code, status = task
    if incident_id != ctx.context.incident_id:
        return "The runtime-bound investigation task was not found in this threat incident."
    if assignee_agent_code != ctx.context.agent_code:
        return "The runtime-bound investigation task is assigned to another Agent."
    if status not in {InvestigationTaskStatus.ACTIVE, InvestigationTaskStatus.BLOCKED}:
        return "Specialist mutations require an active or blocked investigation task."
    return ""


def _task_result(result) -> str:
    if result.task is not None:
        return investigation_success({"task": result.task.model_dump(mode="json")})
    return investigation_error(result.message or "Investigation task operation failed.")
