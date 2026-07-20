"""Transactional compaction for one persisted Agent context."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

import tiktoken
from agents import Agent, ModelSettings, Runner, TResponseInputItem
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from config import AgentConfig, get_config
from core.agent.models import build_openai_model
from core.conversation.formats import (
    CONTEXT_SUMMARY_ITEM_ID,
    CONTEXT_SUMMARY_SECTIONS,
    format_context_summary,
)
from core.conversation.items import tool_call_id
from database import get_async_session
from logger import get_logger
from model.agent.sessions import AgentCompaction, AgentContext, AgentContextItem
from schema.agent.types import AgentContextItemStatus
from utils.time import utc_now


logger = get_logger(__name__)

_SUMMARY_SECTIONS = "\n".join(f"## {section}" for section in CONTEXT_SUMMARY_SECTIONS)
_SUMMARY_AGENT_INSTRUCTIONS = f"""# Runtime Guidance

## Context Compression

Compress earlier Agent context items for a future continuation.

Write a concise, information-dense Markdown summary using exactly these sections:

{_SUMMARY_SECTIONS}

Write "None" for empty sections. Preserve durable facts, user requests, constraints, decisions,
code and file references, tool results, errors, pending tasks, and current state. Discard greetings,
repetitive reasoning, obsolete plans, and low-value narration. Do not invent facts. In `User Goals`,
include only user-authored goals, requests, and topics. Never place Agent conclusions, retrieved
context, tool output, or runtime continuation payloads in that section."""


@dataclass(frozen=True, slots=True)
class CompactionDecision:
    compacted: bool
    projected_tokens: int
    context_window: int
    trigger_tokens: int
    target_tokens: int


async def compact_context_if_needed(
    *,
    context_id: str,
    attempt_id: str,
    agent_config: AgentConfig,
    incoming_items: list[TResponseInputItem],
    write_fence: Callable[[AsyncSession], Awaitable[Any]],
) -> CompactionDecision:
    runtime = get_config().agent_runtime
    context_window = agent_config.context_window
    if context_window <= 0:
        return CompactionDecision(False, 0, context_window, 0, 0)

    async with get_async_session() as db:
        rows = list((await db.exec(
            select(AgentContextItem)
            .where(
                AgentContextItem.context_id == context_id,
                AgentContextItem.status == AgentContextItemStatus.ACTIVE,
            )
            .order_by(AgentContextItem.seq.asc())
        )).all())

    item_tokens = [estimate_items_tokens([row.item], agent_config.model) for row in rows]
    incoming_tokens = estimate_items_tokens(incoming_items, agent_config.model)
    projected_tokens = sum(item_tokens) + incoming_tokens
    trigger_tokens = int(context_window * runtime.context_compression_trigger_ratio)
    hard_stop_tokens = int(context_window * runtime.context_compression_hard_stop_ratio)
    target_tokens = int(context_window * runtime.context_compression_target_ratio)
    if projected_tokens < trigger_tokens:
        return CompactionDecision(
            False,
            projected_tokens,
            context_window,
            trigger_tokens,
            target_tokens,
        )

    boundary = _select_boundary(
        rows,
        item_tokens,
        projected_tokens=projected_tokens,
        incoming_tokens=incoming_tokens,
        target_tokens=target_tokens,
    )
    if boundary is None:
        _raise_at_hard_stop(
            projected_tokens,
            hard_stop_tokens,
            "Agent context is near the model limit but has no safe completed prefix to compact",
        )
        return CompactionDecision(False, projected_tokens, context_window, trigger_tokens, target_tokens)

    candidates = rows[:boundary]
    source_tokens = sum(item_tokens[:boundary])
    try:
        summary_text = await _summarize_items(
            [dict(row.item) for row in candidates],
            agent_config,
        )
    except Exception as exc:
        logger.warning("Agent context compaction failed context=%s: %s", context_id, _one_line_error(exc))
        _raise_at_hard_stop(
            projected_tokens,
            hard_stop_tokens,
            "Agent context compaction failed near the model context limit",
        )
        return CompactionDecision(False, projected_tokens, context_window, trigger_tokens, target_tokens)
    if not summary_text.strip():
        _raise_at_hard_stop(
            projected_tokens,
            hard_stop_tokens,
            "Agent context compaction produced an empty summary near the model context limit",
        )
        return CompactionDecision(False, projected_tokens, context_window, trigger_tokens, target_tokens)

    summary_item = _summary_item(summary_text)
    summary_tokens = estimate_items_tokens([summary_item], agent_config.model)
    from_seq = candidates[0].seq
    through_seq = candidates[-1].seq
    compaction_id = str(uuid4())
    async with get_async_session() as db:
        await write_fence(db)
        context = (await db.exec(select(AgentContext).where(
            AgentContext.id == context_id
        ).with_for_update())).one_or_none()
        if context is None:
            raise RuntimeError("Agent context no longer exists")
        current = list((await db.exec(select(AgentContextItem).where(
            AgentContextItem.context_id == context_id,
            AgentContextItem.status == AgentContextItemStatus.ACTIVE,
            AgentContextItem.seq >= from_seq,
            AgentContextItem.seq <= through_seq,
        ).order_by(AgentContextItem.seq.asc()).with_for_update())).all())
        if [row.seq for row in current] != [row.seq for row in candidates]:
            logger.info("Agent context changed while compaction was running: %s", context_id)
            return CompactionDecision(False, projected_tokens, context_window, trigger_tokens, target_tokens)
        retired_at = utc_now()
        for row in current:
            row.status = AgentContextItemStatus.COMPACTED
            row.retired_at = retired_at
            db.add(row)
        await db.flush()
        db.add(AgentContextItem(
            context_id=context_id,
            seq=through_seq,
            provenance_attempt_id=None,
            dedupe_key=f"compaction:{compaction_id}",
            item=summary_item,
        ))
        db.add(AgentCompaction(
            id=compaction_id,
            context_id=context_id,
            attempt_id=attempt_id,
            from_seq=from_seq,
            through_seq=through_seq,
            summary_item=summary_item,
            source_token_count=source_tokens,
            summary_token_count=summary_tokens,
        ))
        await db.commit()

    logger.info(
        "Agent context compacted context=%s seq=%d..%d items=%d tokens=%d summary_tokens=%d",
        context_id,
        from_seq,
        through_seq,
        len(candidates),
        source_tokens,
        summary_tokens,
    )
    return CompactionDecision(True, projected_tokens, context_window, trigger_tokens, target_tokens)


def estimate_items_tokens(items: list[TResponseInputItem | dict[str, Any]], model: str) -> int:
    encoding = _encoding_for_model(model)
    return sum(
        4 + len(encoding.encode(json.dumps(
            _summary_safe_value(item),
            ensure_ascii=False,
            separators=(",", ":"),
        )))
        for item in items
    )


def resolve_context_window(agent_config: AgentConfig) -> int:
    return agent_config.context_window


def _select_boundary(
    rows: list[AgentContextItem],
    item_tokens: list[int],
    *,
    projected_tokens: int,
    incoming_tokens: int,
    target_tokens: int,
) -> int | None:
    runtime = get_config().agent_runtime
    if len(rows) <= runtime.context_compression_preserve_recent_items:
        return None
    completed_end = _completed_prefix_end(rows)
    if completed_end < runtime.context_compression_min_items:
        return None

    preserve_tokens = int(target_tokens * runtime.context_compression_preserve_recent_ratio)
    preserved_count = 0
    preserved_tokens = 0
    for tokens in reversed(item_tokens):
        if (
            preserved_count >= runtime.context_compression_preserve_recent_items
            and preserved_tokens >= preserve_tokens
        ):
            break
        preserved_count += 1
        preserved_tokens += tokens
    candidate_limit = min(completed_end, len(rows) - preserved_count)
    if candidate_limit < runtime.context_compression_min_items:
        return None

    open_calls: set[str] = set()
    last_balanced: int | None = None
    removed_tokens = 0
    for index, (row, tokens) in enumerate(zip(rows[:candidate_limit], item_tokens, strict=False), start=1):
        item = row.item
        item_type = item.get("type")
        call_id = tool_call_id(item)
        if item_type == "function_call" and call_id:
            open_calls.add(call_id)
        elif item_type == "function_call_output" and call_id:
            open_calls.discard(call_id)
        removed_tokens += tokens
        if index < runtime.context_compression_min_items or open_calls:
            continue
        last_balanced = index
        estimated_after = projected_tokens - removed_tokens + runtime.context_compression_summary_max_tokens
        if estimated_after <= target_tokens:
            return index
    if incoming_tokens >= target_tokens:
        logger.debug("incoming Agent input exceeds the context compression target")
    return last_balanced


def _completed_prefix_end(rows: list[AgentContextItem]) -> int:
    for index, row in enumerate(rows):
        status = row.item.get("status")
        if status in {"in_progress", "streaming"}:
            return index
    return len(rows)


async def _summarize_items(items: list[TResponseInputItem], agent_config: AgentConfig) -> str:
    runtime = get_config().agent_runtime
    agent = Agent(
        name="Context Compressor",
        model=build_openai_model(agent_config),
        model_settings=ModelSettings(max_tokens=runtime.context_compression_summary_max_tokens),
        instructions=_SUMMARY_AGENT_INSTRUCTIONS,
    )
    try:
        payload = json.dumps(_summary_safe_value(items), ensure_ascii=False, indent=2)
        result = await Runner.run(
            starting_agent=agent,
            input=(
                "Compress the completed context items below. Return only the summary body with "
                f"the required sections.\n\n```json\n{payload}\n```"
            ),
            max_turns=1,
        )
        output = getattr(result, "final_output", "")
        return output if isinstance(output, str) else str(output or "")
    finally:
        await agent.model.close()


def _summary_item(summary_text: str) -> dict[str, Any]:
    return {
        "id": CONTEXT_SUMMARY_ITEM_ID,
        "type": "message",
        "role": "user",
        "content": [{
            "type": "input_text",
            "text": format_context_summary(summary_text),
        }],
    }


def _summary_safe_value(value: Any) -> Any:
    if isinstance(value, list):
        return [_summary_safe_value(item) for item in value]
    if not isinstance(value, dict):
        return value
    if value.get("type") == "input_image":
        media_type = _image_media_type(value.get("image_url"))
        return {
            "type": "input_image",
            "image_url": f"data:{media_type};base64,[omitted]",
            "detail": value.get("detail") or "auto",
            "note": "image bytes omitted from the compaction prompt",
        }
    return {key: _summary_safe_value(item) for key, item in value.items()}


def _image_media_type(image_url: Any) -> str:
    if not isinstance(image_url, str) or not image_url.startswith("data:"):
        return "image/*"
    header = image_url.split(",", 1)[0]
    return header.removeprefix("data:").split(";", 1)[0] or "image/*"


def _raise_at_hard_stop(projected_tokens: int, hard_stop_tokens: int, message: str) -> None:
    if hard_stop_tokens > 0 and projected_tokens >= hard_stop_tokens:
        raise RuntimeError(message)


def _one_line_error(exc: Exception) -> str:
    return " ".join(str(exc).split())[:500]


def _encoding_for_model(model: str):
    try:
        return tiktoken.encoding_for_model(model.split("/", 1)[-1])
    except Exception:
        return tiktoken.get_encoding("cl100k_base")
