"""/s/{slug}/mcp — authenticate, then hand the request to the caller's bridge session."""

import json
import logging

from mcp_types import INTERNAL_ERROR, INVALID_REQUEST, ErrorData, JSONRPCError
from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import Message, Receive, Scope, Send

from gateway.audit import client_ip
from gateway.bridge.process import ServerConfigError
from gateway.bridge.registry import SessionLimitError, get_registry
from gateway.oauth.provider import GatewayOAuthProvider
from gateway.oauth.resource import authenticate, get_enabled_server

logger = logging.getLogger(__name__)

MCP_SESSION_ID_HEADER = "mcp-session-id"
MCP_PROTOCOL_VERSION_HEADER = "mcp-protocol-version"


def jsonrpc_error(message: str, status_code: int, code: int = INVALID_REQUEST, data: object = None) -> Response:
    body = JSONRPCError(jsonrpc="2.0", id=None, error=ErrorData(code=code, message=message, data=data))
    return Response(body.model_dump_json(by_alias=True, exclude_none=True), status_code, media_type="application/json")


class MCPEndpoint:
    def __init__(self, provider: GatewayOAuthProvider):
        self.provider = provider

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        response = await self._handle(scope, receive, send)
        if response is not None:
            await response(scope, receive, send)

    async def _handle(self, scope: Scope, receive: Receive, send: Send) -> Response | None:
        request = Request(scope, receive)
        server = await get_enabled_server(scope["path_params"]["slug"])
        if server is None:
            return jsonrpc_error("Unknown MCP server", 404)

        principal = await authenticate(request, server, self.provider)
        if isinstance(principal, Response):
            return principal

        # The servers behind the gateway speak the initialize-handshake protocol; a client that
        # opened with a stateless (2026+) revision gets a version error and falls back.
        version = request.headers.get(MCP_PROTOCOL_VERSION_HEADER)
        if version is not None and version not in HANDSHAKE_PROTOCOL_VERSIONS:
            return jsonrpc_error(
                f"Unsupported protocol version: {version}", 400, data={"supported": list(HANDSHAKE_PROTOCOL_VERSIONS)}
            )

        registry = get_registry()
        session_id = request.headers.get(MCP_SESSION_ID_HEADER)
        if session_id is not None:
            session = registry.get(session_id)
            if session is None or session.user_id != principal.user_id or session.server_id != server.id:
                return jsonrpc_error("Session not found", 404)
            session.touch()
            await session.transport.handle_request(scope, receive, send)
            if session.transport.is_terminated:
                await registry.close(session, "client_closed")
            return None

        if request.method != "POST":
            return jsonrpc_error("Bad Request: Missing session ID", 400)

        # Only an initialize request may open a session; check before spawning a process.
        body = await request.body()
        try:
            message = json.loads(body)
        except ValueError:
            return jsonrpc_error("Parse error", 400, code=-32700)
        if not (isinstance(message, dict) and message.get("method") == "initialize" and "id" in message):
            return jsonrpc_error("Bad Request: Missing session ID", 400)

        try:
            session = await registry.open(
                server, principal, ip=client_ip(request), user_agent=request.headers.get("user-agent")
            )
        except SessionLimitError as e:
            return jsonrpc_error(str(e), 503, code=INTERNAL_ERROR)
        except (ServerConfigError, OSError) as e:
            logger.error("Could not start %s: %s", server.slug, e)
            return jsonrpc_error("MCP server failed to start", 502, code=INTERNAL_ERROR)

        status = await _serve_and_report_status(session.transport.handle_request, scope, _replay(body, receive), send)
        if status is None or status >= 400:
            await registry.close(session, "initialize_failed")
        return None


def _replay(body: bytes, receive: Receive) -> Receive:
    """A receive channel that yields the already-read body once, then defers to the original."""
    sent = False

    async def replay() -> Message:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()

    return replay


async def _serve_and_report_status(app, scope: Scope, receive: Receive, send: Send) -> int | None:  # type: ignore[no-untyped-def]
    status: int | None = None

    async def watch(message: Message) -> None:
        nonlocal status
        if message["type"] == "http.response.start":
            status = message["status"]
        await send(message)

    await app(scope, receive, watch)
    return status
