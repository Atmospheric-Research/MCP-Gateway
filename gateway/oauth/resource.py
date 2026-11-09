"""Resource-server side: per-server RFC 9728 metadata and bearer-token checks for /s/{slug}/mcp."""

from dataclasses import dataclass
from datetime import timedelta

from mcp.server.auth.json_response import PydanticJSONResponse
from mcp.shared.auth import ProtectedResourceMetadata
from sqlalchemy import select
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import HTTPConnection, Request
from starlette.responses import JSONResponse, Response
from starlette.types import Receive, Scope, Send

from gateway import audit
from gateway.config import get_settings
from gateway.db import session_scope
from gateway.models import Grant, Server, User, utcnow
from gateway.oauth.provider import GatewayOAuthProvider, user_can_access

_LAST_USED_RESOLUTION = timedelta(minutes=1)


@dataclass(frozen=True)
class Principal:
    user_id: int
    username: str
    server_id: int
    server_slug: str
    grant_id: int
    client_id: str


async def get_enabled_server(slug: str) -> Server | None:
    async with session_scope() as db:
        return await db.scalar(select(Server).where(Server.slug == slug, Server.enabled.is_(True)))


async def _protected_resource_metadata(request: Request) -> Response:
    settings = get_settings()
    server = await get_enabled_server(request.path_params["slug"])
    if server is None:
        return JSONResponse({"error": "not_found"}, status_code=404)
    metadata = ProtectedResourceMetadata(
        resource=settings.resource_url(server.slug),  # type: ignore[arg-type]
        authorization_servers=[settings.issuer],  # type: ignore[list-item]
        resource_name=server.name,
    )
    return PydanticJSONResponse(metadata)


async def protected_resource_metadata_app(scope: Scope, receive: Receive, send: Send) -> None:
    response = await _protected_resource_metadata(Request(scope, receive))
    await response(scope, receive, send)


protected_resource_metadata = CORSMiddleware(
    protected_resource_metadata_app, allow_origins=["*"], allow_methods=["GET", "OPTIONS"]
)


def unauthorized(slug: str, error: str | None = None, description: str | None = None) -> Response:
    params = [f'resource_metadata="{get_settings().resource_metadata_url(slug)}"']
    if error:
        params.insert(0, f'error="{error}"')
        if description:
            params.insert(1, f'error_description="{description}"')
    return JSONResponse(
        {"error": error or "unauthorized", "error_description": description or "Authentication required"},
        status_code=401,
        headers={"WWW-Authenticate": "Bearer " + ", ".join(params)},
    )


async def authenticate(conn: HTTPConnection, server: Server, provider: GatewayOAuthProvider) -> Principal | Response:
    header = conn.headers.get("authorization", "")
    scheme, _, raw_token = header.partition(" ")
    if scheme.lower() != "bearer" or not raw_token.strip():
        return unauthorized(server.slug)

    token = await provider.load_access_token(raw_token.strip())
    if token is None:
        await audit.record("mcp_auth_failed", conn=conn, server_slug=server.slug, reason="invalid_token")
        return unauthorized(server.slug, "invalid_token", "The access token is invalid, expired or revoked")
    if token.server_id != server.id:
        await audit.record(
            "mcp_auth_failed",
            conn=conn,
            user_id=token.user_id,
            server_slug=server.slug,
            client_id=token.client_id,
            reason="token_for_other_server",
        )
        return unauthorized(server.slug, "invalid_token", "The access token was issued for a different server")

    async with session_scope() as db:
        user = await db.get(User, token.user_id)
        allowed = user is not None and await user_can_access(db, user, server)
        if allowed:
            grant = await db.get(Grant, token.grant_id)
            now = utcnow()
            if grant is not None and (grant.last_used_at is None or now - grant.last_used_at > _LAST_USED_RESOLUTION):
                grant.last_used_at = now
    if not allowed or user is None:
        await audit.record(
            "mcp_access_denied", conn=conn, user_id=token.user_id, server_slug=server.slug, client_id=token.client_id
        )
        return JSONResponse(
            {"error": "access_denied", "error_description": "You do not have access to this server"}, status_code=403
        )

    return Principal(
        user_id=user.id,
        username=user.username,
        server_id=server.id,
        server_slug=server.slug,
        grant_id=token.grant_id,
        client_id=token.client_id,
    )
