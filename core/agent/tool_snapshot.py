from dataclasses import dataclass

from core.runtime.context import AgentRuntimeContext


@dataclass(frozen=True, slots=True)
class AgentToolSnapshot:
    sandbox_container_id: int | None = None
    sandbox_container_generation: int = 0
    sandbox_skill_metadata: tuple[str, ...] = ()
    incident_id: int | None = None
    environment_id: int | None = None

    @classmethod
    def from_context(cls, context: AgentRuntimeContext) -> "AgentToolSnapshot":
        return cls(
            sandbox_container_id=context.sandbox_container_id,
            sandbox_container_generation=context.sandbox_container_generation,
            sandbox_skill_metadata=context.sandbox_skill_metadata,
            incident_id=context.incident_id,
            environment_id=context.environment_id,
        )
