from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from time import monotonic
from typing import Awaitable, Callable, TypeVar
from uuid import uuid4

from sqlalchemy.dialects.postgresql import insert
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from database import get_async_session
from model.runtime import RuntimeLease
from utils.time import utc_now


class RuntimeLeaseUnavailable(RuntimeError):
    pass


class RuntimeLeaseLost(RuntimeError):
    pass


_T = TypeVar("_T")


@dataclass
class RuntimeLeaseHandle:
    name: str
    owner_id: str
    fencing_token: int
    ttl_seconds: float
    expires_at: datetime
    _heartbeat_task: asyncio.Task[None] | None = field(default=None, init=False, repr=False)
    _lost_reason: str = field(default="", init=False, repr=False)
    _lost_event: asyncio.Event = field(default_factory=asyncio.Event, init=False, repr=False)

    async def start(self) -> None:
        if self._heartbeat_task is not None:
            return
        self._heartbeat_task = asyncio.create_task(
            self._heartbeat(),
            name=f"runtime-lease-{self.name}-{self.fencing_token}",
        )

    async def assert_owned(
        self,
        session: AsyncSession | None = None,
        *,
        lock: bool = False,
    ) -> RuntimeLease:
        if self._lost_reason:
            raise RuntimeLeaseLost(self._lost_reason)
        if session is None:
            async with get_async_session() as owned_session:
                return await self.assert_owned(owned_session, lock=lock)
        statement = select(RuntimeLease).where(RuntimeLease.name == self.name)
        if lock:
            statement = statement.with_for_update()
        lease = (await session.exec(statement)).one_or_none()
        now = utc_now()
        if (
            lease is None
            or lease.owner_id != self.owner_id
            or lease.fencing_token != self.fencing_token
            or lease.expires_at <= now
        ):
            self._mark_lost("runtime lease ownership changed or expired")
            raise RuntimeLeaseLost(self._lost_reason)
        return lease

    async def run_while_owned(self, operation_factory: Callable[[], Awaitable[_T]]) -> _T:
        await self.assert_owned()
        operation = asyncio.ensure_future(operation_factory())
        lease_lost = asyncio.create_task(
            self._lost_event.wait(),
            name=f"runtime-lease-loss-{self.name}-{self.fencing_token}",
        )
        try:
            done, _ = await asyncio.wait(
                {operation, lease_lost},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if lease_lost in done:
                operation.cancel()
                await asyncio.gather(operation, return_exceptions=True)
                raise RuntimeLeaseLost(self._lost_reason)
            return await operation
        except BaseException:
            if not operation.done():
                operation.cancel()
                await asyncio.gather(operation, return_exceptions=True)
            raise
        finally:
            lease_lost.cancel()
            await asyncio.gather(lease_lost, return_exceptions=True)

    async def close(self) -> None:
        heartbeat = self._heartbeat_task
        self._heartbeat_task = None
        if heartbeat is not None:
            heartbeat.cancel()
            await asyncio.gather(heartbeat, return_exceptions=True)
        try:
            async with get_async_session() as session, session.begin():
                lease = (await session.exec(
                    select(RuntimeLease)
                    .where(RuntimeLease.name == self.name)
                    .with_for_update()
                )).one_or_none()
                if (
                    lease is not None
                    and lease.owner_id == self.owner_id
                    and lease.fencing_token == self.fencing_token
                ):
                    lease.expires_at = utc_now()
                    session.add(lease)
        except Exception:
            # Expiration is the authoritative fallback when graceful release is unavailable.
            return

    async def _heartbeat(self) -> None:
        interval = max(1.0, self.ttl_seconds / 3)
        while True:
            await asyncio.sleep(interval)
            while True:
                remaining_seconds = (self.expires_at - utc_now()).total_seconds()
                if remaining_seconds <= 0:
                    self._mark_lost("runtime lease renewal failed before expiration")
                    return
                try:
                    await asyncio.wait_for(self._renew(), timeout=remaining_seconds)
                except asyncio.CancelledError:
                    raise
                except RuntimeLeaseLost:
                    return
                except Exception:
                    remaining_seconds = (self.expires_at - utc_now()).total_seconds()
                    if remaining_seconds <= 0:
                        self._mark_lost("runtime lease renewal failed before expiration")
                        return
                    await asyncio.sleep(min(1.0, remaining_seconds))
                    continue
                break

    async def _renew(self) -> None:
        now = utc_now()
        renewed_expires_at = now + timedelta(seconds=self.ttl_seconds)
        async with get_async_session() as session, session.begin():
            lease = (await session.exec(
                select(RuntimeLease)
                .where(RuntimeLease.name == self.name)
                .with_for_update()
            )).one_or_none()
            if (
                lease is None
                or lease.owner_id != self.owner_id
                or lease.fencing_token != self.fencing_token
                or lease.expires_at <= now
            ):
                self._mark_lost("runtime lease ownership changed or expired during renewal")
                raise RuntimeLeaseLost(self._lost_reason)
            lease.expires_at = renewed_expires_at
            session.add(lease)
        self.expires_at = renewed_expires_at

    def _mark_lost(self, reason: str) -> None:
        if not self._lost_reason:
            self._lost_reason = f"{self.name}: {reason}"
            self._lost_event.set()


async def acquire_runtime_lease(
    name: str,
    *,
    ttl_seconds: float = 15,
    wait_timeout_seconds: float | None = None,
) -> RuntimeLeaseHandle:
    if not name or len(name) > 96:
        raise ValueError("runtime lease name must contain between 1 and 96 characters")
    if ttl_seconds < 3:
        raise ValueError("runtime lease TTL must be at least 3 seconds")
    owner_id = uuid4().hex
    deadline = None if wait_timeout_seconds is None else monotonic() + wait_timeout_seconds
    while True:
        handle = await _try_acquire(name, owner_id=owner_id, ttl_seconds=ttl_seconds)
        if handle is not None:
            await handle.start()
            return handle
        if deadline is not None and monotonic() >= deadline:
            raise RuntimeLeaseUnavailable(f"runtime lease is already held: {name}")
        await asyncio.sleep(0.5)


@asynccontextmanager
async def runtime_lease(
    name: str,
    *,
    ttl_seconds: float = 15,
    wait_timeout_seconds: float | None = None,
):
    handle = await acquire_runtime_lease(
        name,
        ttl_seconds=ttl_seconds,
        wait_timeout_seconds=wait_timeout_seconds,
    )
    try:
        yield handle
    finally:
        await asyncio.shield(handle.close())


async def _try_acquire(
    name: str,
    *,
    owner_id: str,
    ttl_seconds: float,
) -> RuntimeLeaseHandle | None:
    now = utc_now()
    expires_at = now + timedelta(seconds=ttl_seconds)
    async with get_async_session() as session, session.begin():
        await session.execute(
            insert(RuntimeLease)
            .values(
                name=name,
                owner_id=owner_id,
                fencing_token=1,
                acquired_at=now,
                expires_at=expires_at,
            )
            .on_conflict_do_nothing(index_elements=["name"])
        )
        lease = (await session.exec(
            select(RuntimeLease)
            .where(RuntimeLease.name == name)
            .with_for_update()
        )).one()
        if lease.owner_id != owner_id:
            if lease.expires_at > now:
                return None
            lease.owner_id = owner_id
            lease.fencing_token += 1
            lease.acquired_at = now
        lease.expires_at = expires_at
        session.add(lease)
        fencing_token = lease.fencing_token
    return RuntimeLeaseHandle(
        name=name,
        owner_id=owner_id,
        fencing_token=fencing_token,
        ttl_seconds=ttl_seconds,
        expires_at=expires_at,
    )
