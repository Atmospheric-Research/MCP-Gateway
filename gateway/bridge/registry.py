"""Live sessions, keyed by Mcp-Session-Id. Sessions run in a task group owned by the app lifespan."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import anyio
from anyio.abc import TaskGroup

from gateway.bridge.session import BridgeSession
from gateway.config import get_settings
from gateway.models import Server

if TYPE_CHECKING:
    from gateway.oauth.resource import Principal

logger = logging.getLogger(__name__)


class SessionLimitError(Exception):
    pass


class SessionRegistry:
    def __init__(self) -> None:
        self._sessions: dict[str, BridgeSession] = {}
        self._task_group: TaskGroup | None = None
        self._admit_lock = anyio.Lock()

    @asynccontextmanager
    async def running(self) -> AsyncIterator[None]:
        async with anyio.create_task_group() as tg:
            self._task_group = tg
            try:
                yield
            finally:
                await self.close_where(lambda _s: True, reason="gateway_shutdown")
                self._task_group = None
                tg.cancel_scope.cancel()

    def get(self, session_id: str) -> BridgeSession | None:
        return self._sessions.get(session_id)

    def sessions(self) -> list[BridgeSession]:
        return list(self._sessions.values())

    async def open(
        self, server: Server, principal: Principal, *, ip: str | None, user_agent: str | None
    ) -> BridgeSession:
        """Spawn the server process and connect a transport; raises SessionLimitError at a cap."""
        if self._task_group is None:
            raise RuntimeError("Session registry is not running")
        settings = get_settings()
        async with self._admit_lock:
            live = self._sessions.values()
            if sum(s.user_id == principal.user_id for s in live) >= settings.max_sessions_per_user:
                raise SessionLimitError("Too many open sessions for this user")
            if sum(s.server_id == server.id for s in live) >= settings.max_sessions_per_server:
                raise SessionLimitError("Too many open sessions for this server")
            session = BridgeSession(server, principal, ip=ip, user_agent=user_agent, on_exit=self._forget)
            self._sessions[session.id] = session
        try:
            await self._task_group.start(session.run)
        except BaseException:
            self._forget(session)
            raise
        return session

    async def close(self, session: BridgeSession, reason: str) -> None:
        self._forget(session)
        await session.stop(reason)

    async def close_where(self, predicate: Callable[[BridgeSession], bool], reason: str) -> int:
        doomed = [s for s in self._sessions.values() if predicate(s)]
        for session in doomed:
            await self.close(session, reason)
        return len(doomed)

    def _forget(self, session: BridgeSession) -> None:
        self._sessions.pop(session.id, None)


_registry = SessionRegistry()


def get_registry() -> SessionRegistry:
    return _registry
