from schema.agent.sessions import AgentCode


DEFAULT_AGENT_CODE = AgentCode.CSO.value
SPECIALIST_AGENT_CODES = tuple(code.value for code in (
    AgentCode.CTH,
    AgentCode.CDE,
    AgentCode.CIE,
    AgentCode.CIR,
))
INVESTIGATION_AGENT_CODES = (DEFAULT_AGENT_CODE, *SPECIALIST_AGENT_CODES)
