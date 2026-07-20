from enum import StrEnum


class SessionType(StrEnum):
    CHAT = "chat"
    INCIDENT = "incident"
    ENVIRONMENT = "environment"


class AgentCode(StrEnum):
    CSO = "cso"
    CTH = "cth"
    CDE = "cde"
    CIE = "cie"
    CIR = "cir"


class AgentSessionStatus(StrEnum):
    ACTIVE = "active"
    ARCHIVED = "archived"


class AgentRunStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    WAITING = "waiting"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELED = "canceled"


class AgentRunWaitReason(StrEnum):
    SANDBOX_COMMAND = "sandbox_command"
    CHILD_RUN = "child_run"
    TOOL_RECOVERY = "tool_recovery"


class AgentCancellationMode(StrEnum):
    INTERRUPT = "interrupt"
    CANCEL = "cancel"


class AgentAttemptStatus(StrEnum):
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELED = "canceled"
    INTERRUPTED = "interrupted"


class AgentContextKind(StrEnum):
    MAIN = "main"
    DELEGATION = "delegation"


class AgentContextItemStatus(StrEnum):
    ACTIVE = "active"
    REWOUND = "rewound"
    COMPACTED = "compacted"
    CLEARED = "cleared"


class AgentToolInvocationStatus(StrEnum):
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    RECOVERY_REQUIRED = "recovery_required"
    NOT_APPLIED = "not_applied"


class AgentToolInvocationResolution(StrEnum):
    CONFIRM_SUCCEEDED = "confirm_succeeded"
    CONFIRM_NOT_APPLIED = "confirm_not_applied"


class AgentTriggerKind(StrEnum):
    USER_MESSAGE = "user_message"
    DELEGATION = "delegation"
    SANDBOX_COMPLETION = "sandbox_completion"
    CHILD_RUN_COMPLETION = "child_run_completion"
    TOOL_RECOVERY = "tool_recovery"
    SYSTEM_EVENT = "system_event"


class AgentSegmentKind(StrEnum):
    TEXT = "text"
    THINKING = "thinking"


class AgentSegmentStatus(StrEnum):
    STREAMING = "streaming"
    COMPLETED = "completed"
    INTERRUPTED = "interrupted"


CANONICAL_AGENT_IDENTITIES: dict[AgentCode, tuple[str, str]] = {
    AgentCode.CSO: ("V3il", "Chief Security Officer"),
    AgentCode.CTH: ("H4wk", "Threat Investigation Engineer"),
    AgentCode.CDE: ("Ph4ntom", "Deception Defense Engineer"),
    AgentCode.CIE: ("L1ly", "Cyber Threat Intelligence Engineer"),
    AgentCode.CIR: ("J4ck", "Security Response Engineer"),
}


AGENT_SESSION_STATUS_TRANSITIONS: dict[AgentSessionStatus, tuple[AgentSessionStatus, ...]] = {
    AgentSessionStatus.ACTIVE: (AgentSessionStatus.ARCHIVED,),
    AgentSessionStatus.ARCHIVED: (),
}

AGENT_RUN_STATUS_TRANSITIONS: dict[AgentRunStatus, tuple[AgentRunStatus, ...]] = {
    AgentRunStatus.QUEUED: (AgentRunStatus.RUNNING, AgentRunStatus.CANCELED),
    AgentRunStatus.RUNNING: (
        AgentRunStatus.QUEUED,
        AgentRunStatus.WAITING,
        AgentRunStatus.SUCCEEDED,
        AgentRunStatus.FAILED,
        AgentRunStatus.CANCELED,
    ),
    AgentRunStatus.WAITING: (AgentRunStatus.QUEUED, AgentRunStatus.CANCELED),
    AgentRunStatus.SUCCEEDED: (),
    AgentRunStatus.FAILED: (),
    AgentRunStatus.CANCELED: (),
}

AGENT_ATTEMPT_STATUS_TRANSITIONS: dict[AgentAttemptStatus, tuple[AgentAttemptStatus, ...]] = {
    AgentAttemptStatus.RUNNING: (
        AgentAttemptStatus.SUCCEEDED,
        AgentAttemptStatus.FAILED,
        AgentAttemptStatus.CANCELED,
        AgentAttemptStatus.INTERRUPTED,
    ),
    AgentAttemptStatus.SUCCEEDED: (),
    AgentAttemptStatus.FAILED: (),
    AgentAttemptStatus.CANCELED: (),
    AgentAttemptStatus.INTERRUPTED: (),
}

AGENT_SEGMENT_STATUS_TRANSITIONS: dict[AgentSegmentStatus, tuple[AgentSegmentStatus, ...]] = {
    AgentSegmentStatus.STREAMING: (
        AgentSegmentStatus.COMPLETED,
        AgentSegmentStatus.INTERRUPTED,
    ),
    AgentSegmentStatus.COMPLETED: (),
    AgentSegmentStatus.INTERRUPTED: (),
}

AGENT_CONTEXT_ITEM_STATUS_TRANSITIONS: dict[
    AgentContextItemStatus,
    tuple[AgentContextItemStatus, ...],
] = {
    AgentContextItemStatus.ACTIVE: (
        AgentContextItemStatus.REWOUND,
        AgentContextItemStatus.COMPACTED,
        AgentContextItemStatus.CLEARED,
    ),
    AgentContextItemStatus.REWOUND: (AgentContextItemStatus.ACTIVE,),
    AgentContextItemStatus.COMPACTED: (),
    AgentContextItemStatus.CLEARED: (),
}

AGENT_TOOL_INVOCATION_STATUS_TRANSITIONS: dict[
    AgentToolInvocationStatus,
    tuple[AgentToolInvocationStatus, ...],
] = {
    AgentToolInvocationStatus.RUNNING: (
        AgentToolInvocationStatus.SUCCEEDED,
        AgentToolInvocationStatus.RECOVERY_REQUIRED,
    ),
    AgentToolInvocationStatus.SUCCEEDED: (),
    AgentToolInvocationStatus.RECOVERY_REQUIRED: (
        AgentToolInvocationStatus.SUCCEEDED,
        AgentToolInvocationStatus.NOT_APPLIED,
    ),
    AgentToolInvocationStatus.NOT_APPLIED: (),
}
