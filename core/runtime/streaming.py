import asyncio
from collections.abc import AsyncIterator
from typing import Any

from agents.stream_events import AgentUpdatedStreamEvent, RunItemStreamEvent

from config import get_config
from core.runtime.events import NormalizedStreamEvent, SdkStreamEventNormalizer


_TOOL_EVENT_IDLE_TIMEOUT_SECONDS = 450


class StreamIdleTimeout(TimeoutError):
    def __init__(self, phase: str, timeout_seconds: int) -> None:
        self.phase = phase
        self.timeout_seconds = timeout_seconds
        super().__init__(f"{phase} was idle for more than {timeout_seconds} seconds")


async def iter_normalized_stream_events(
    stream: Any,
    *,
    current_agent_name: str,
) -> AsyncIterator[NormalizedStreamEvent]:
    normalizer = SdkStreamEventNormalizer()
    sdk_events = stream.stream_events().__aiter__()
    pending_tool_calls = 0
    while True:
        timeout = _event_timeout_seconds(pending_tool_calls)
        try:
            sdk_event = await asyncio.wait_for(sdk_events.__anext__(), timeout=timeout)
        except StopAsyncIteration:
            return
        except TimeoutError as exc:
            phase = "tool execution" if pending_tool_calls else "model stream"
            raise StreamIdleTimeout(phase, timeout) from exc
        if isinstance(sdk_event, AgentUpdatedStreamEvent):
            continue
        pending_tool_calls = _next_pending_tool_calls(pending_tool_calls, sdk_event)
        event = normalizer.normalize(sdk_event, current_agent_name)
        if event is not None:
            yield event


def _event_timeout_seconds(pending_tool_calls: int) -> int:
    model_timeout = get_config().agent_runtime.model_stream_idle_timeout_seconds
    return max(model_timeout, _TOOL_EVENT_IDLE_TIMEOUT_SECONDS) if pending_tool_calls else model_timeout


def _next_pending_tool_calls(current: int, event: Any) -> int:
    if not isinstance(event, RunItemStreamEvent):
        return current
    if event.name == "tool_called":
        return current + 1
    if event.name == "tool_output" and current:
        return current - 1
    return current
