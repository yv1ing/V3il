from dataclasses import dataclass

from agents import Tool

from core.agent.constants import DEFAULT_AGENT_CODE, SPECIALIST_AGENT_CODES
from core.tools.investigation import (
    activate_investigation_task,
    assign_behavior_events,
    block_investigation_task,
    create_investigation_task,
    execute_planned_deception_revision,
    list_incident_behavior_events,
    list_investigation_tasks,
    load_investigation_context,
    plan_deception_revision,
    record_deception_revision_evaluation,
    recover_deception_revision,
    register_deception_artifact,
    record_attack_chain,
    record_attacker_profile,
    record_intelligence_report,
    record_intent_assessment,
    record_investigation_evidence,
    record_risk_assessment,
    record_threat_indicator,
    review_investigation_task,
    start_observed_deception_workload,
    stop_observed_deception_workload,
    submit_investigation_task,
    update_incident_state,
)
from core.tools.reports import export_report
from core.tools.detection import (
    analyze_rule_matches,
    compare_rule_versions,
    create_central_detection_rule_draft,
    create_suppression_rule_draft,
    create_zeek_script_draft,
    create_zeek_signature_draft,
    list_detection_rules,
    list_detection_sensors,
    read_detection_rule_version,
    read_rule_approval,
    read_rule_deployment,
    replay_rule_draft,
    submit_rule_for_approval,
    update_rule_draft,
    validate_rule_draft,
)
from core.tools.sandbox import (
    cancel_sandbox_async_job,
    execute_async_command,
    execute_sync_command,
    load_skill,
    read_sandbox_command_output,
)


@dataclass(frozen=True, slots=True)
class ToolMount:
    tool: Tool
    requires_sandbox_container: bool = False
    requires_incident: bool = False
    requires_deception_context: bool = False


@dataclass(frozen=True, slots=True)
class SubagentMount:
    code: str


@dataclass(frozen=True, slots=True)
class AgentSpec:
    code: str
    tools: tuple[ToolMount, ...] = ()
    subagents: tuple[SubagentMount, ...] = ()


INVESTIGATION_CONTEXT_TOOLS = (
    ToolMount(load_investigation_context, requires_incident=True),
    ToolMount(list_investigation_tasks, requires_incident=True),
    ToolMount(list_incident_behavior_events, requires_incident=True),
)

INVESTIGATION_EXECUTION_TOOLS = (
    ToolMount(activate_investigation_task, requires_incident=True),
    ToolMount(block_investigation_task, requires_incident=True),
    ToolMount(submit_investigation_task, requires_incident=True),
    ToolMount(assign_behavior_events, requires_incident=True),
    ToolMount(record_investigation_evidence, requires_incident=True),
)

INVESTIGATION_GOVERNANCE_TOOLS = (
    ToolMount(create_investigation_task, requires_incident=True),
    ToolMount(review_investigation_task, requires_incident=True),
    ToolMount(update_incident_state, requires_incident=True),
)

THREAT_ANALYSIS_TOOLS = (
    ToolMount(record_intent_assessment, requires_incident=True),
    ToolMount(record_attack_chain, requires_incident=True),
    ToolMount(record_threat_indicator, requires_incident=True),
)

DECEPTION_TOOLS = (
    ToolMount(plan_deception_revision, requires_deception_context=True),
    ToolMount(execute_planned_deception_revision, requires_deception_context=True),
    ToolMount(recover_deception_revision, requires_deception_context=True),
    ToolMount(start_observed_deception_workload, requires_deception_context=True),
    ToolMount(stop_observed_deception_workload, requires_deception_context=True),
    ToolMount(register_deception_artifact, requires_deception_context=True),
    ToolMount(record_deception_revision_evaluation, requires_deception_context=True),
)

INTELLIGENCE_REPORT_TOOLS = (
    ToolMount(record_intelligence_report, requires_incident=True),
)

SANDBOX_TOOLS = (
    ToolMount(execute_sync_command, requires_sandbox_container=True),
    ToolMount(read_sandbox_command_output, requires_sandbox_container=True),
    ToolMount(execute_async_command, requires_sandbox_container=True),
    ToolMount(cancel_sandbox_async_job, requires_sandbox_container=True),
    ToolMount(load_skill, requires_sandbox_container=True),
)

DETECTION_RULE_READ_TOOLS = (
    ToolMount(list_detection_sensors),
    ToolMount(list_detection_rules),
    ToolMount(read_detection_rule_version),
    ToolMount(compare_rule_versions),
    ToolMount(read_rule_approval),
    ToolMount(read_rule_deployment),
    ToolMount(analyze_rule_matches),
)

DETECTION_RULE_AUTHORING_TOOLS = (
    ToolMount(create_zeek_script_draft),
    ToolMount(create_zeek_signature_draft),
    ToolMount(create_central_detection_rule_draft),
    ToolMount(create_suppression_rule_draft),
    ToolMount(update_rule_draft),
    ToolMount(validate_rule_draft),
    ToolMount(replay_rule_draft),
    ToolMount(submit_rule_for_approval),
)

SPECIALIST_BASE_TOOLS = (
    *SANDBOX_TOOLS,
    *INVESTIGATION_CONTEXT_TOOLS,
    *INVESTIGATION_EXECUTION_TOOLS,
)

SPECIALIST_DOMAIN_TOOLS: dict[str, tuple[ToolMount, ...]] = {
    "cth": (
        ToolMount(record_intent_assessment, requires_incident=True),
        ToolMount(record_attack_chain, requires_incident=True),
        ToolMount(record_threat_indicator, requires_incident=True),
    ),
    "cde": (
        *DECEPTION_TOOLS,
        ToolMount(record_intent_assessment, requires_incident=True),
    ),
    "cie": (
        ToolMount(record_intent_assessment, requires_incident=True),
        ToolMount(record_threat_indicator, requires_incident=True),
        ToolMount(record_attacker_profile, requires_incident=True),
    ),
    "cir": (
        ToolMount(record_risk_assessment, requires_incident=True),
        *INTELLIGENCE_REPORT_TOOLS,
    ),
}

AGENT_SPECS: tuple[AgentSpec, ...] = (
    AgentSpec(
        code=DEFAULT_AGENT_CODE,
        tools=(
            *INVESTIGATION_CONTEXT_TOOLS,
            *INVESTIGATION_EXECUTION_TOOLS,
            *INVESTIGATION_GOVERNANCE_TOOLS,
            *THREAT_ANALYSIS_TOOLS,
            ToolMount(record_attacker_profile, requires_incident=True),
            ToolMount(record_risk_assessment, requires_incident=True),
            *DECEPTION_TOOLS,
            *INTELLIGENCE_REPORT_TOOLS,
            ToolMount(export_report),
            *DETECTION_RULE_READ_TOOLS,
            *DETECTION_RULE_AUTHORING_TOOLS,
        ),
        subagents=tuple(SubagentMount(code=code) for code in SPECIALIST_AGENT_CODES),
    ),
    *(
        AgentSpec(
            code=code,
            tools=(
                *SPECIALIST_BASE_TOOLS,
                *SPECIALIST_DOMAIN_TOOLS[code],
                *DETECTION_RULE_READ_TOOLS,
                *(DETECTION_RULE_AUTHORING_TOOLS if code in {"cth", "cde", "cie"} else ()),
            ),
        )
        for code in SPECIALIST_AGENT_CODES
    ),
)
