import json
from dataclasses import dataclass
from typing import Any, Literal

from agents.items import ToolCallItem, ToolCallOutputItem
from agents.stream_events import RawResponsesStreamEvent, RunItemStreamEvent
from openai.types.responses.response_error_event import ResponseErrorEvent
from openai.types.responses.response_reasoning_summary_text_delta_event import ResponseReasoningSummaryTextDeltaEvent
from openai.types.responses.response_reasoning_summary_text_done_event import ResponseReasoningSummaryTextDoneEvent
from openai.types.responses.response_reasoning_text_delta_event import ResponseReasoningTextDeltaEvent
from openai.types.responses.response_reasoning_text_done_event import ResponseReasoningTextDoneEvent
from openai.types.responses.response_text_delta_event import ResponseTextDeltaEvent
from openai.types.responses.response_text_done_event import ResponseTextDoneEvent
from pydantic import BaseModel, JsonValue


@dataclass(frozen=True, slots=True)
class StreamDelta:
    kind: Literal["text", "thinking"]
    segment_key: str
    delta: str
    text: str
    agent_name: str


@dataclass(frozen=True, slots=True)
class StreamSegmentComplete:
    kind: Literal["text", "thinking"]
    segment_key: str
    text: str
    agent_name: str


@dataclass(frozen=True, slots=True)
class StreamToolCall:
    call_id: str
    name: str
    arguments: dict[str, JsonValue]
    agent_name: str


@dataclass(frozen=True, slots=True)
class StreamToolResult:
    call_id: str
    output: str
    is_error: bool
    agent_name: str


@dataclass(frozen=True, slots=True)
class StreamError:
    code: str
    message: str
    agent_name: str


NormalizedStreamEvent = StreamDelta | StreamSegmentComplete | StreamToolCall | StreamToolResult | StreamError


class SdkStreamEventNormalizer:
    def __init__(self) -> None:
        self._texts: dict[str, str] = {}

    def normalize(self, sdk_event: Any, current_agent: str) -> NormalizedStreamEvent | None:
        if isinstance(sdk_event, RawResponsesStreamEvent):
            return self._normalize_raw(sdk_event.data, current_agent)
        if isinstance(sdk_event, RunItemStreamEvent):
            return self._normalize_item(sdk_event, current_agent)
        return None

    def _normalize_raw(self, data: Any, agent_name: str) -> NormalizedStreamEvent | None:
        if isinstance(data, ResponseTextDeltaEvent):
            return self._delta("text", _segment_key("text", data), data.delta, agent_name)
        if isinstance(data, ResponseTextDoneEvent):
            return self._complete("text", _segment_key("text", data), data.text, agent_name)
        if isinstance(data, (ResponseReasoningTextDeltaEvent, ResponseReasoningSummaryTextDeltaEvent)):
            return self._delta("thinking", _segment_key("thinking", data), data.delta, agent_name)
        if isinstance(data, (ResponseReasoningTextDoneEvent, ResponseReasoningSummaryTextDoneEvent)):
            return self._complete("thinking", _segment_key("thinking", data), data.text, agent_name)
        if isinstance(data, ResponseErrorEvent):
            return StreamError(code=data.code or "provider_error", message=data.message, agent_name=agent_name)
        return None

    def _normalize_item(self, event: RunItemStreamEvent, current_agent: str) -> NormalizedStreamEvent | None:
        item = event.item
        agent_name = item.agent.name if item.agent is not None else current_agent
        if event.name == "tool_called" and isinstance(item, ToolCallItem):
            raw = item.raw_item
            return StreamToolCall(
                call_id=_read_field(raw, "call_id") or _read_field(raw, "id") or "",
                name=_read_field(raw, "name") or item.title or "",
                arguments=_parse_arguments(_read_field(raw, "arguments")),
                agent_name=agent_name,
            )
        if event.name == "tool_output" and isinstance(item, ToolCallOutputItem):
            raw = item.raw_item
            return StreamToolResult(
                call_id=_read_field(raw, "call_id") or "",
                output=_as_text(item.output),
                is_error=str(_read_field(raw, "status") or "").lower() in {"failed", "error"},
                agent_name=agent_name,
            )
        return None

    def _delta(self, kind: Literal["text", "thinking"], key: str, delta: str, agent_name: str) -> StreamDelta:
        text = f"{self._texts.get(key, '')}{delta}"
        self._texts[key] = text
        return StreamDelta(kind=kind, segment_key=key, delta=delta, text=text, agent_name=agent_name)

    def _complete(
        self,
        kind: Literal["text", "thinking"],
        key: str,
        text: str,
        agent_name: str,
    ) -> StreamSegmentComplete:
        self._texts[key] = text
        return StreamSegmentComplete(kind=kind, segment_key=key, text=text, agent_name=agent_name)


def _segment_key(kind: str, data: Any) -> str:
    values = (
        getattr(data, "response_id", ""),
        getattr(data, "output_index", -1),
        getattr(data, "content_index", -1),
        getattr(data, "summary_index", -1),
    )
    return ":".join([kind, *(str(value) for value in values)])


def _read_field(value: Any, name: str) -> Any:
    return value.get(name) if isinstance(value, dict) else getattr(value, name, None)


def _parse_arguments(value: Any) -> dict[str, JsonValue]:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value:
        return {}
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        return {"_raw": value}
    return decoded if isinstance(decoded, dict) else {"_value": decoded}


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, BaseModel):
        return value.model_dump_json()
    return json.dumps(value, ensure_ascii=False, default=str)
