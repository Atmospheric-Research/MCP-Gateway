"""One MCP session: a Streamable HTTP transport facing the MCP client, wired to a fresh stdio subprocess.

Messages are forwarded verbatim at the JSON-RPC level, so every MCP feature the server speaks
(tools, resources, prompts, sampling, elicitation, progress...) works without per-method code."""

from __future__ import annotations

import logging
import shutil
import tempfile
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import anyio
from anyio.abc import TaskStatus
from mcp.server.streamable_http import StreamableHTTPServerTransport
from mcp.shared.message import ServerMessageMetadata, SessionMessage
from mcp_types import INVALID_PARAMS, ErrorData, JSONRPCError, JSONRPCNotification, JSONRPCRequest, JSONRPCResponse, RequestId

from gateway import audit
from gateway.bridge.process import open_server_log, open_upstream
from gateway.config import get_settings
from gateway.models import Server, utcnow

if TYPE_CHECKING:
    from gateway.oauth.resource import Principal

logger = logging.getLogger(__name__)


class BridgeSession:
    def __init__(
        self,
        server: Server,
        principal: Principal,
        *,
        ip: str | None,
        user_agent: str | None,
        on_exit: Callable[[BridgeSession], None],
    ):
        settings = get_settings()
        self.id = uuid4().hex
        self.server = server
        self.user_id = principal.user_id
        self.username = principal.username
        self.server_id = server.id
        self.server_slug = server.slug
        self.grant_id = principal.grant_id
        self.client_id = principal.client_id
        self.ip = ip
        self.user_agent = user_agent
        self.created_at: datetime = utcnow()
        self.last_seen: datetime = self.created_at
        self.transport = StreamableHTTPServerTransport(
            mcp_session_id=self.id, idle_timeout=settings.session_idle_timeout
        )
        self._on_exit = on_exit
        self._stop_scope = anyio.CancelScope()
        self._close_reason = "server_exited"
        # Client requests awaiting a response, oldest first. Server-originated messages that
        # aren't responses get attached to one of these so they ride an open SSE stream.
        self._in_flight: dict[str, RequestId] = {}
        self._progress: dict[Any, RequestId] = {}
        self._disabled_tools = set(server.disabled_tools or ())
        self._tools_list_ids: set[str] = set()

    def _audit_fields(self) -> dict[str, Any]:
        return {
            "user_id": self.user_id,
            "username": self.username,
            "server_slug": self.server_slug,
            "client_id": self.client_id,
            "session_id": self.id,
        }

    async def run(self, *, task_status: TaskStatus[None] = anyio.TASK_STATUS_IGNORED) -> None:
        home = Path(tempfile.mkdtemp(prefix=f"mcp-{self.server_slug}-"))
        errlog = open_server_log(self.server_slug)
        started = False
        try:
            async with open_upstream(self.server, home, errlog) as (proc_read, proc_write):
                async with self.transport.connect() as (http_read, http_write):
                    task_status.started()
                    started = True
                    await audit.record("session_start", **self._audit_fields(), ip=self.ip, user_agent=self.user_agent)
                    with self._stop_scope:
                        idle_scope = self.transport.idle_scope or anyio.CancelScope()
                        with idle_scope:
                            async with anyio.create_task_group() as tg:
                                tg.start_soon(self._client_to_server, http_read, proc_write, http_write, tg.cancel_scope)
                                tg.start_soon(self._server_to_client, proc_read, http_write, tg.cancel_scope)
                        if idle_scope.cancelled_caught:
                            self._close_reason = "idle_timeout"
        except Exception:
            if not started:
                raise
            self._close_reason = "error"
            logger.exception("Session %s for %s crashed", self.id, self.server_slug)
        finally:
            self._on_exit(self)
            with anyio.CancelScope(shield=True):
                if not self.transport.is_terminated:
                    await self.transport.terminate()
                if started:
                    await audit.record("session_end", **self._audit_fields(), reason=self._close_reason)
            errlog.close()
            shutil.rmtree(home, ignore_errors=True)

    async def stop(self, reason: str) -> None:
        self._close_reason = reason
        if not self.transport.is_terminated:
            await self.transport.terminate()
        self._stop_scope.cancel()

    def touch(self) -> None:
        self.last_seen = utcnow()

    async def _client_to_server(self, http_read, proc_write, http_write, cancel_scope: anyio.CancelScope) -> None:  # type: ignore[no-untyped-def]
        try:
            async for item in http_read:
                if isinstance(item, Exception):
                    logger.warning("Session %s: bad message from client: %s", self.id, item)
                    continue
                message = item.message
                if isinstance(message, JSONRPCRequest):
                    params = message.params or {}
                    if message.method == "tools/call" and params.get("name") in self._disabled_tools:
                        error = ErrorData(code=INVALID_PARAMS, message=f"Unknown tool: {params.get('name')}")
                        await http_write.send(SessionMessage(JSONRPCError(jsonrpc="2.0", id=message.id, error=error)))
                        continue
                    if message.method == "tools/list":
                        self._tools_list_ids.add(str(message.id))
                    self._in_flight[str(message.id)] = message.id
                    progress_token = (params.get("_meta") or {}).get("progressToken")
                    if progress_token is not None:
                        self._progress[progress_token] = message.id
                    if message.method == "tools/call":
                        await audit.record("tool_call", **self._audit_fields(), tool=params.get("name"))
                elif isinstance(message, JSONRPCNotification) and message.method == "notifications/cancelled":
                    self._settle((message.params or {}).get("requestId"))
                await proc_write.send(SessionMessage(message))
        finally:
            cancel_scope.cancel()

    async def _server_to_client(self, proc_read, http_write, cancel_scope: anyio.CancelScope) -> None:  # type: ignore[no-untyped-def]
        try:
            async for item in proc_read:
                if isinstance(item, Exception):
                    logger.warning("Session %s: bad message from %s: %s", self.id, self.server_slug, item)
                    continue
                message = item.message
                if isinstance(message, JSONRPCResponse | JSONRPCError):
                    # The transport routes responses by id on its own.
                    if isinstance(message, JSONRPCResponse) and self._tools_list_ids:
                        message = self._filter_tools(message)
                    self._settle(message.id)
                    await http_write.send(SessionMessage(message))
                    continue
                related: RequestId | None = None
                if isinstance(message, JSONRPCNotification) and message.method == "notifications/progress":
                    related = self._progress.get((message.params or {}).get("progressToken"))
                if related is None and self._in_flight:
                    related = next(reversed(self._in_flight.values()))
                await http_write.send(
                    SessionMessage(message, metadata=ServerMessageMetadata(related_request_id=related))
                )
        finally:
            cancel_scope.cancel()

    def _filter_tools(self, message: JSONRPCResponse) -> JSONRPCResponse:
        if str(message.id) not in self._tools_list_ids:
            return message
        tools = message.result.get("tools")
        if not self._disabled_tools or not isinstance(tools, list):
            return message
        kept = [t for t in tools if not (isinstance(t, dict) and t.get("name") in self._disabled_tools)]
        return message.model_copy(update={"result": {**message.result, "tools": kept}})

    def _settle(self, request_id: RequestId | None) -> None:
        if request_id is None:
            return
        self._in_flight.pop(str(request_id), None)
        self._tools_list_ids.discard(str(request_id))
        for token, rid in list(self._progress.items()):
            if str(rid) == str(request_id):
                del self._progress[token]
