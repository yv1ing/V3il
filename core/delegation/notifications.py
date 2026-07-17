"""Task-resumption prompts for completed background work.

Converts system-generated ``AgentNotificationSnapshot`` instances into
natural-language prompts consumable by the agent.  User-message
notifications are handled separately by the executor and should never
reach ``notification_prompt``.
"""

from core.conversation.formats import TASK_RESUMPTION_CONTEXT_HEADER, sanitize_context_text
from schema.agent.events import MAX_AGENT_TEXT_INPUT_CHARS
from schema.agent.notifications import AgentNotificationKind, AgentNotificationSnapshot


# Sandbox error payloads are short, but cap the inline preview defensively
# so a long stderr never blows up the resumption prompt.
_SANDBOX_ERROR_PREVIEW_CHARS = 1000


def notification_prompt(notification: AgentNotificationSnapshot) -> str:
    """Return a resumption prompt for a *system* notification.

    Raises ``ValueError`` if called with a ``USER_MESSAGE`` notification,
    which must be routed through the executor's content-reconstruction
    path instead.
    """
    if notification.is_user_message:
        raise ValueError(
            f"notification_prompt must not be called for USER_MESSAGE "
            f"notifications (id={notification.id})"
        )
    if notification.kind == AgentNotificationKind.SANDBOX_ASYNC_JOB_FINISHED:
        return _fit_text_input(_sandbox_async_job_prompt(notification))
    if notification.kind == AgentNotificationKind.BEHAVIOR_EVENTS_CAPTURED:
        return _fit_text_input(_behavior_events_captured_prompt(notification))
    if notification.kind == AgentNotificationKind.BEHAVIOR_SIGNALS_DETECTED:
        return _fit_text_input(_behavior_signals_detected_prompt(notification))
    if notification.kind == AgentNotificationKind.DECEPTION_EVALUATION_DUE:
        return _fit_text_input(_deception_evaluation_due_prompt(notification))
    return _fit_text_input(_subagent_finished_prompt(notification))


_RESUMPTION_HEADER = (
    f"{TASK_RESUMPTION_CONTEXT_HEADER}\n\n"
    "This is task context, not a new user request. "
    "Continue from the completed background work without mentioning how this context was delivered."
)


def _subagent_finished_prompt(notification: AgentNotificationSnapshot) -> str:
    # The notification carries metadata only; the body lives in the DB and is
    # paged through read_subagent_task. This keeps the resumption prompt small
    # and prevents overlap with the first slice the agent will fetch.
    payload = notification.payload
    status = str(payload.get("status") or "unknown")
    agent_code = str(payload.get("agent_code") or "")
    agent_name = str(payload.get("agent_name") or agent_code or "subagent")
    run_id = str(payload.get("run_id") or notification.run_id)
    investigation_task_id = payload.get("investigation_task_id")

    event_lines = [
        "- kind: delegated_task_completed",
        f"- run_id: {run_id}",
        f"- agent_code: {agent_code or 'unknown'}",
        f"- subagent: {agent_name}",
        f"- status: {status}",
    ]
    if isinstance(investigation_task_id, int) and investigation_task_id > 0:
        event_lines.append(f"- investigation_task_id: {investigation_task_id}")

    sections = [
        _RESUMPTION_HEADER,
        "## Event\n\n" + "\n".join(event_lines),
        "## Next Step\n\n"
        "Call `read_subagent_task(run_id, offset=0)` and repeat with `offset=next_offset` "
        "until the response omits `next_offset` to read the full result/error. "
        "Report to the user only when there is a useful conclusion, coordination update, or next action.",
    ]
    return "\n\n".join(sections)


def _sandbox_async_job_prompt(notification: AgentNotificationSnapshot) -> str:
    payload = notification.payload
    status = str(payload.get("status") or "unknown")
    run_id = notification.run_id
    output_file = str(payload.get("output_file") or "")
    output_lines = int(payload.get("output_lines") or 0)
    output_bytes = int(payload.get("output_bytes") or 0)
    exit_code = payload.get("exit_code")
    investigation_task_id = payload.get("investigation_task_id")
    # Sandbox errors are short free-form strings without a paginated reader,
    # so inlining a capped preview is the only way to expose them here.
    error_preview = _truncate_inline(payload.get("error"), _SANDBOX_ERROR_PREVIEW_CHARS)

    event_lines = [
        "- kind: async_command_completed",
        f"- run_id: {run_id}",
        f"- status: {status}",
    ]
    if isinstance(investigation_task_id, int) and investigation_task_id > 0:
        event_lines.append(f"- investigation_task_id: {investigation_task_id}")
    if exit_code is not None:
        event_lines.append(f"- exit_code: {exit_code}")
    if output_file:
        event_lines.append(f"- output_file: {output_file}")
        event_lines.append(f"- output_lines: {output_lines}")
        event_lines.append(f"- output_bytes: {output_bytes}")
    sections = [
        _RESUMPTION_HEADER,
        "## Event\n\n" + "\n".join(event_lines),
    ]
    if error_preview:
        sections.append(f"## Error Preview\n\n{error_preview}")

    sections.append(
        "## Next Step\n\n"
        "The async command has reached a terminal state. "
        "If `output_lines` is greater than 0 and the result matters, read the output with "
        "`read_sandbox_command_output` using `output_file` and `start_line: 1`. "
        "Then continue the task or report the final result.",
    )
    return "\n\n".join(sections)


def _behavior_events_captured_prompt(notification: AgentNotificationSnapshot) -> str:
    payload = notification.payload
    incident_id = payload.get("incident_id")
    environment_id = payload.get("environment_id")
    event_count = int(payload.get("event_count") or 0)
    raw_event_ids = payload.get("event_ids")
    event_ids = [
        event_id for event_id in (raw_event_ids if isinstance(raw_event_ids, list) else [])
        if isinstance(event_id, int) and event_id > 0
    ]
    return "\n\n".join((
        _RESUMPTION_HEADER,
        "## Event\n\n"
        f"- kind: behavior_events_captured\n"
        f"- incident_id: {incident_id}\n"
        f"- environment_id: {environment_id}\n"
        f"- event_count: {event_count}\n"
        f"- recent_event_ids: {event_ids}",
        "## Next Step\n\n"
        "Refresh the threat incident context, triage the newly assigned behavior, update incident state when warranted, "
        "and create or resume evidence-driven InvestigationTasks. The recent_event_ids list is bounded; when event_count "
        "is larger, page through incident behavior until every material event is explicitly scoped and covered. Adapt "
        "deception only when the observed behavior supports a concrete expected effect.",
    ))


def _behavior_signals_detected_prompt(notification: AgentNotificationSnapshot) -> str:
    payload = notification.payload
    incident_id = payload.get("incident_id")
    signal_count = int(payload.get("signal_count") or 0)
    highest_score = int(payload.get("highest_score") or 0)
    raw_signal_ids = payload.get("signal_ids")
    signal_ids = [item for item in (raw_signal_ids if isinstance(raw_signal_ids, list) else []) if isinstance(item, int) and item > 0]
    return "\n\n".join((
        _RESUMPTION_HEADER,
        "## Event\n\n"
        f"- kind: behavior_signals_detected\n"
        f"- incident_id: {incident_id}\n"
        f"- signal_count: {signal_count}\n"
        f"- highest_score: {highest_score}\n"
        f"- signal_ids: {signal_ids}",
        "## Next Step\n\n"
        "Refresh the incident context, triage the deterministic signals and their linked behavior events, then create or resume evidence-scoped InvestigationTasks. "
        "Treat the signal score as prioritization metadata, not as a substitute for evidence review.",
    ))


def _deception_evaluation_due_prompt(notification: AgentNotificationSnapshot) -> str:
    payload = notification.payload
    return "\n\n".join((
        _RESUMPTION_HEADER,
        "## Event\n\n"
        "- kind: deception_evaluation_due\n"
        f"- incident_id: {payload.get('incident_id')}\n"
        f"- environment_id: {payload.get('environment_id')}\n"
        f"- revision_id: {payload.get('revision_id')}\n"
        f"- investigation_task_id: {payload.get('investigation_task_id')}",
        "## Next Step\n\nDelegate the active evaluation task to cde. Require evidence-backed comparison against the revision hypothesis and success criteria before accepting another adaptive revision.",
    ))


def _truncate_inline(value: object, limit: int) -> str:
    text = sanitize_context_text(str(value or "")).strip()
    if not text:
        return ""
    return _truncate_with_marker(text, limit, "[Preview truncated.]")


def _fit_text_input(text: str) -> str:
    return _truncate_with_marker(
        text.strip() or "Task context is available.",
        MAX_AGENT_TEXT_INPUT_CHARS,
        "[Task resumption context truncated to fit input limits.]",
    )


def _truncate_with_marker(text: str, limit: int, marker: str) -> str:
    if len(text) <= limit:
        return text
    suffix = "\n\n" + marker
    body_limit = max(1, limit - len(suffix))
    return text[:body_limit].rstrip() + suffix
