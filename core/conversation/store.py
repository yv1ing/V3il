from typing import Any
from collections.abc import Awaitable, Callable

from agents.items import TResponseInputItem
from agents.memory.session_settings import SessionSettings, resolve_session_limit
from sqlalchemy import update
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from database import get_async_session
from model.agent.sessions import AgentContext, AgentContextItem
from schema.agent.types import AgentContextItemStatus
from utils.time import utc_now


class V3ilSession:
    """OpenAI Agents SDK Session backed by one isolated V3il AgentContext."""

    session_settings: SessionSettings | None = None

    def __init__(
        self,
        context_id: str,
        *,
        attempt_id: str,
        write_fence: Callable[[AsyncSession], Awaitable[Any]],
    ) -> None:
        self.session_id = context_id
        self._attempt_id = attempt_id
        self._write_fence = write_fence

    async def get_items(self, limit: int | None = None) -> list[TResponseInputItem]:
        effective_limit = resolve_session_limit(limit, self.session_settings)
        statement = select(AgentContextItem.item).where(
            AgentContextItem.context_id == self.session_id,
            AgentContextItem.status == AgentContextItemStatus.ACTIVE,
        )
        if effective_limit is None:
            statement = statement.order_by(AgentContextItem.seq.asc())
        else:
            statement = statement.order_by(AgentContextItem.seq.desc()).limit(effective_limit)
        async with get_async_session() as session:
            rows = list((await session.exec(statement)).all())
        if effective_limit is not None:
            rows.reverse()
        return [dict(item) for item in rows]

    async def get_items_for_retrieval(self, recent_limit: int) -> list[TResponseInputItem]:
        return await self.get_items(limit=recent_limit)

    async def add_items(self, items: list[TResponseInputItem]) -> None:
        if not items:
            return
        async with get_async_session() as session:
            await self._write_fence(session)
            context = (await session.exec(
                select(AgentContext)
                .where(AgentContext.id == self.session_id)
                .with_for_update()
            )).one_or_none()
            if context is None:
                raise RuntimeError("agent context no longer exists")
            next_seq = context.next_item_seq
            serialized = [(_json_item(item), _item_dedupe_key(item)) for item in items]
            dedupe_keys = [key for _, key in serialized if key]
            existing_by_key: dict[str, AgentContextItem] = {}
            if dedupe_keys:
                existing = list((await session.exec(select(AgentContextItem).where(
                    AgentContextItem.context_id == self.session_id,
                    AgentContextItem.dedupe_key.in_(dedupe_keys),
                ).with_for_update())).all())
                existing_by_key = {row.dedupe_key: row for row in existing}

            inserted = 0
            for item, dedupe_key in serialized:
                existing = existing_by_key.get(dedupe_key) if dedupe_key else None
                if existing is not None:
                    if existing.status == AgentContextItemStatus.REWOUND:
                        existing.status = AgentContextItemStatus.ACTIVE
                        existing.retired_at = None
                        session.add(existing)
                    continue
                session.add(AgentContextItem(
                    context_id=self.session_id,
                    seq=next_seq + inserted,
                    provenance_attempt_id=self._attempt_id,
                    dedupe_key=dedupe_key,
                    item=item,
                ))
                inserted += 1
            context.next_item_seq += inserted
            session.add(context)
            await session.commit()

    async def pop_item(self) -> TResponseInputItem | None:
        async with get_async_session() as session:
            await self._write_fence(session)
            row = (await session.exec(
                select(AgentContextItem)
                .where(
                    AgentContextItem.context_id == self.session_id,
                    AgentContextItem.status == AgentContextItemStatus.ACTIVE,
                )
                .order_by(AgentContextItem.seq.desc())
                .limit(1)
                .with_for_update()
            )).one_or_none()
            if row is None:
                return None
            item = dict(row.item)
            row.status = AgentContextItemStatus.REWOUND
            row.retired_at = utc_now()
            session.add(row)
            await session.commit()
            return item

    async def clear_session(self) -> None:
        async with get_async_session() as session:
            await self._write_fence(session)
            await session.execute(update(AgentContextItem).where(
                AgentContextItem.context_id == self.session_id,
                AgentContextItem.status == AgentContextItemStatus.ACTIVE,
            ).values(
                status=AgentContextItemStatus.CLEARED,
                retired_at=utc_now(),
            ))
            await session.commit()


def _json_item(item: TResponseInputItem) -> dict[str, Any]:
    if isinstance(item, dict):
        return dict(item)
    if hasattr(item, "model_dump"):
        return item.model_dump(mode="json")
    raise TypeError(f"unsupported SDK context item: {type(item).__name__}")


def _item_dedupe_key(item: TResponseInputItem | dict[str, Any]) -> str:
    value = _json_item(item)
    item_type = value.get("type")
    if item_type in {"function_call", "function_call_output"}:
        call_id = value.get("call_id") or value.get("id")
        if isinstance(call_id, str) and call_id:
            suffix = "call" if item_type == "function_call" else "output"
            return f"tool:{suffix}:{call_id}"
    item_id = value.get("id")
    return f"item:{item_id}" if isinstance(item_id, str) and item_id else ""
