from dataclasses import dataclass

from schema.threat.incidents import ThreatIncidentSchema


CLOSED_INCIDENT_MESSAGE = "closed threat incidents are immutable"


@dataclass(frozen=True)
class ThreatIncidentMutationResult:
    incident: ThreatIncidentSchema | None
    not_found: bool = False
    forbidden: bool = False
    conflict: bool = False
    message: str = ""
