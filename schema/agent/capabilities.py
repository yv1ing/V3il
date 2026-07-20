from enum import StrEnum

from schema.agent.types import AgentCode


class AgentCapability(StrEnum):
    INCIDENT_READ = "incident.read"
    INVESTIGATION_GOVERN = "investigation.govern"
    INVESTIGATION_EXECUTE = "investigation.execute"
    THREAT_HUNT = "threat.hunt"
    DECEPTION_ENGINEER = "deception.engineer"
    INTELLIGENCE_ANALYZE = "intelligence.analyze"
    RISK_REPORT = "risk.report"
    FINAL_REPORT = "report.finalize"
    DETECTION_READ = "detection.read"
    DETECTION_AUTHOR = "detection.author"
    SANDBOX_EXECUTE = "sandbox.execute"
    DELEGATE = "agent.delegate"
    REPORT_EXPORT = "report.export"


AGENT_CAPABILITIES: dict[AgentCode, tuple[AgentCapability, ...]] = {
    AgentCode.CSO: (
        AgentCapability.INCIDENT_READ,
        AgentCapability.INVESTIGATION_GOVERN,
        AgentCapability.FINAL_REPORT,
        AgentCapability.DETECTION_READ,
        AgentCapability.DELEGATE,
        AgentCapability.REPORT_EXPORT,
    ),
    AgentCode.CTH: (
        AgentCapability.INCIDENT_READ,
        AgentCapability.INVESTIGATION_EXECUTE,
        AgentCapability.THREAT_HUNT,
        AgentCapability.DETECTION_READ,
        AgentCapability.DETECTION_AUTHOR,
        AgentCapability.SANDBOX_EXECUTE,
    ),
    AgentCode.CDE: (
        AgentCapability.INCIDENT_READ,
        AgentCapability.INVESTIGATION_EXECUTE,
        AgentCapability.DECEPTION_ENGINEER,
        AgentCapability.DETECTION_READ,
        AgentCapability.DETECTION_AUTHOR,
        AgentCapability.SANDBOX_EXECUTE,
    ),
    AgentCode.CIE: (
        AgentCapability.INCIDENT_READ,
        AgentCapability.INVESTIGATION_EXECUTE,
        AgentCapability.INTELLIGENCE_ANALYZE,
        AgentCapability.DETECTION_READ,
        AgentCapability.DETECTION_AUTHOR,
        AgentCapability.SANDBOX_EXECUTE,
    ),
    AgentCode.CIR: (
        AgentCapability.INCIDENT_READ,
        AgentCapability.INVESTIGATION_EXECUTE,
        AgentCapability.RISK_REPORT,
        AgentCapability.DETECTION_READ,
        AgentCapability.SANDBOX_EXECUTE,
    ),
}


def require_agent_capability(agent_code: str, capability: AgentCapability) -> None:
    try:
        code = AgentCode(agent_code)
    except ValueError as exc:
        raise PermissionError(f"unknown Agent code: {agent_code}") from exc
    if capability not in AGENT_CAPABILITIES[code]:
        raise PermissionError(f"Agent {code.value} lacks capability {capability.value}")
