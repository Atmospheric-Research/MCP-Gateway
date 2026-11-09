"""OAuth 2.1 authorization server backed by SQLite, plugged into the MCP SDK's auth routes.

Every grant is bound to exactly one MCP server, chosen by the RFC 8707 `resource` the client
sends to /authorize. Tokens are opaque and stored hashed, so revocation is immediate."""

import re
import time
from datetime import timedelta
from urllib.parse import urlsplit

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from gateway import audit
from gateway.config import Settings, get_settings
from gateway.crypto import new_token, token_hash
from gateway.db import session_scope
from gateway.models import (
    AccessTokenRow,
    AuthCode,
    Grant,
    OAuthClient,
    PendingAuthorization,
    RefreshTokenRow,
    Server,
    User,
    UserServerAccess,
    utcnow,
)

_RESOURCE_PATH = re.compile(r"^/s/(?P<slug>[a-z0-9][a-z0-9-]{0,63})(?:/mcp)?/?$")
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1"}


def slug_from_resource(resource: str | None, settings: Settings) -> str | None:
    if not resource:
        return None
    parts = urlsplit(resource)
    issuer = urlsplit(settings.issuer)
    if (parts.scheme, parts.netloc) != (issuer.scheme, issuer.netloc) or parts.query or parts.fragment:
        return None
    match = _RESOURCE_PATH.match(parts.path)
    return match["slug"] if match else None


def redirect_uri_allowed(uri: str, settings: Settings) -> bool:
    if uri in settings.allowed_redirect_uris:
        return True
    parts = urlsplit(uri)
    return settings.allow_loopback_redirects and parts.scheme == "http" and parts.hostname in _LOOPBACK_HOSTS


async def user_can_access(db: AsyncSession, user: User, server: Server) -> bool:
    if not (user.is_active and server.enabled):
        return False
    if user.is_admin:
        return True
    return await db.get(UserServerAccess, (user.id, server.id)) is not None


class GatewayAuthorizationCode(AuthorizationCode):
    user_id: int
    server_id: int


class GatewayRefreshToken(RefreshToken):
    grant_id: int


class GatewayAccessToken(AccessToken):
    grant_id: int
    user_id: int
    server_id: int


class GatewayOAuthProvider:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()

    # -- clients ---------------------------------------------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        async with session_scope() as db:
            row = await db.get(OAuthClient, client_id)
        return OAuthClientInformationFull.model_validate_json(row.info_json) if row else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        uris = [str(u) for u in client_info.redirect_uris or []]
        if not uris:
            raise RegistrationError("invalid_redirect_uri", "At least one redirect_uri is required")
        for uri in uris:
            if not redirect_uri_allowed(uri, self.settings):
                raise RegistrationError("invalid_redirect_uri", f"Redirect URI not allowed: {uri}")
        assert client_info.client_id is not None
        async with session_scope() as db:
            db.add(
                OAuthClient(
                    client_id=client_info.client_id,
                    client_name=(client_info.client_name or "")[:255] or None,
                    info_json=client_info.model_dump_json(),
                )
            )
        await audit.record(
            "client_registered", client_id=client_info.client_id, client_name=client_info.client_name, redirect_uris=uris
        )

    # -- authorization -----------------------------------------------------------------------

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        slug = slug_from_resource(params.resource, self.settings)
        if slug is None:
            raise AuthorizeError(
                "invalid_target" if params.resource else "invalid_request",
                "The resource parameter must name an MCP server URL on this gateway",
            )
        async with session_scope() as db:
            server = await db.scalar(select(Server).where(Server.slug == slug, Server.enabled.is_(True)))
            if server is None:
                raise AuthorizeError("invalid_target", "Unknown MCP server")
            request_id = new_token()
            db.add(
                PendingAuthorization(
                    id=request_id,
                    client_id=client.client_id,
                    server_id=server.id,
                    params_json=params.model_dump_json(),
                    expires_at=utcnow() + timedelta(seconds=self.settings.pending_authorization_ttl),
                )
            )
        return f"{self.settings.issuer}/consent?req={request_id}"

    async def create_authorization_code(self, db: AsyncSession, pending: PendingAuthorization, user: User) -> str:
        """Called by the consent page once the logged-in user approves."""
        params = AuthorizationParams.model_validate_json(pending.params_json)
        code = new_token()
        db.add(
            AuthCode(
                code_hash=token_hash(code),
                client_id=pending.client_id,
                user_id=user.id,
                server_id=pending.server_id,
                scopes=params.scopes or [],
                code_challenge=params.code_challenge,
                redirect_uri=str(params.redirect_uri),
                redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
                resource=params.resource or "",
                expires_at=utcnow() + timedelta(seconds=self.settings.auth_code_ttl),
            )
        )
        await db.delete(pending)
        return code

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> GatewayAuthorizationCode | None:
        async with session_scope() as db:
            row = await db.get(AuthCode, token_hash(authorization_code))
            if row is None or row.client_id != client.client_id:
                return None
            return GatewayAuthorizationCode(
                code=authorization_code,
                scopes=row.scopes,
                expires_at=row.expires_at.timestamp(),
                client_id=row.client_id,
                code_challenge=row.code_challenge,
                redirect_uri=row.redirect_uri,  # type: ignore[arg-type]
                redirect_uri_provided_explicitly=row.redirect_uri_provided_explicitly,
                resource=row.resource,
                subject=str(row.user_id),
                user_id=row.user_id,
                server_id=row.server_id,
            )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: GatewayAuthorizationCode
    ) -> OAuthToken:
        assert client.client_id is not None
        async with session_scope() as db:
            # Single use: whoever deletes the row wins.
            deleted = await db.execute(delete(AuthCode).where(AuthCode.code_hash == token_hash(authorization_code.code)))
            if not deleted.rowcount:  # type: ignore[attr-defined]
                raise TokenError("invalid_grant", "authorization code already used")
            # A fresh consent from the same client supersedes its older grants for this server.
            await db.execute(
                update(Grant)
                .where(
                    Grant.user_id == authorization_code.user_id,
                    Grant.client_id == client.client_id,
                    Grant.server_id == authorization_code.server_id,
                    Grant.revoked_at.is_(None),
                )
                .values(revoked_at=utcnow())
            )
            grant = Grant(
                user_id=authorization_code.user_id,
                client_id=client.client_id,
                server_id=authorization_code.server_id,
                scopes=authorization_code.scopes,
            )
            db.add(grant)
            await db.flush()
            token = await self._issue_tokens(db, grant)
            server = await db.get(Server, grant.server_id)
            user = await db.get(User, grant.user_id)
        await audit.record(
            "token_issued",
            user_id=grant.user_id,
            username=user.username if user else None,
            server_slug=server.slug if server else None,
            client_id=client.client_id,
            grant_id=grant.id,
        )
        return token

    async def _issue_tokens(self, db: AsyncSession, grant: Grant) -> OAuthToken:
        access, refresh = new_token(), new_token()
        now = utcnow()
        db.add(
            AccessTokenRow(
                token_hash=token_hash(access),
                grant_id=grant.id,
                expires_at=now + timedelta(seconds=self.settings.access_token_ttl),
            )
        )
        db.add(
            RefreshTokenRow(
                token_hash=token_hash(refresh),
                grant_id=grant.id,
                expires_at=now + timedelta(seconds=self.settings.refresh_token_ttl),
            )
        )
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=self.settings.access_token_ttl,
            refresh_token=refresh,
            scope=" ".join(grant.scopes) or None,
        )

    # -- refresh -----------------------------------------------------------------------------

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> GatewayRefreshToken | None:
        async with session_scope() as db:
            row = await db.get(RefreshTokenRow, token_hash(refresh_token))
            if row is None:
                return None
            grant = await db.get(Grant, row.grant_id)
            if grant is None or grant.client_id != client.client_id or grant.revoked_at is not None:
                return None
            if row.used_at is None:
                return GatewayRefreshToken(
                    token=refresh_token,
                    client_id=grant.client_id,
                    scopes=grant.scopes,
                    expires_at=int(row.expires_at.timestamp()),
                    subject=str(grant.user_id),
                    grant_id=grant.id,
                )
            if utcnow() - row.used_at <= timedelta(seconds=self.settings.refresh_reuse_grace):
                return None
            # A rotated refresh token came back after the grace window: assume it leaked.
            grant.revoked_at = utcnow()
            reused_grant = grant
        await audit.record(
            "refresh_token_reuse", user_id=reused_grant.user_id, client_id=client.client_id, grant_id=reused_grant.id
        )
        await _on_grants_revoked([reused_grant.id])
        return None

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: GatewayRefreshToken, scopes: list[str]
    ) -> OAuthToken:
        async with session_scope() as db:
            marked = await db.execute(
                update(RefreshTokenRow)
                .where(RefreshTokenRow.token_hash == token_hash(refresh_token.token), RefreshTokenRow.used_at.is_(None))
                .values(used_at=utcnow())
            )
            if not marked.rowcount:  # type: ignore[attr-defined]
                raise TokenError("invalid_grant", "refresh token already used")
            grant = await db.get(Grant, refresh_token.grant_id)
            if grant is None or grant.revoked_at is not None:
                raise TokenError("invalid_grant", "grant revoked")
            user = await db.get(User, grant.user_id)
            server = await db.get(Server, grant.server_id)
            if user is None or server is None or not await user_can_access(db, user, server):
                raise TokenError("invalid_grant", "user no longer has access to this server")
            token = await self._issue_tokens(db, grant)
        await audit.record(
            "token_refreshed",
            user_id=user.id,
            username=user.username,
            server_slug=server.slug,
            client_id=client.client_id,
            grant_id=grant.id,
        )
        return token

    # -- access tokens & revocation ------------------------------------------------------------

    async def load_access_token(self, token: str) -> GatewayAccessToken | None:
        async with session_scope() as db:
            row = await db.get(AccessTokenRow, token_hash(token))
            if row is None or row.expires_at.timestamp() < time.time():
                return None
            grant = await db.get(Grant, row.grant_id)
            if grant is None or grant.revoked_at is not None:
                return None
            server = await db.get(Server, grant.server_id)
            if server is None:
                return None
            return GatewayAccessToken(
                token=token,
                client_id=grant.client_id,
                scopes=grant.scopes,
                expires_at=int(row.expires_at.timestamp()),
                resource=self.settings.resource_url(server.slug),
                subject=str(grant.user_id),
                grant_id=grant.id,
                user_id=grant.user_id,
                server_id=grant.server_id,
            )

    async def revoke_token(self, token: GatewayAccessToken | GatewayRefreshToken) -> None:
        await revoke_grant(token.grant_id, reason="client_revocation")


async def revoke_grant(grant_id: int, *, reason: str, actor: User | None = None) -> bool:
    async with session_scope() as db:
        grant = await db.get(Grant, grant_id)
        if grant is None or grant.revoked_at is not None:
            return False
        grant.revoked_at = utcnow()
        user_id, client_id = grant.user_id, grant.client_id
        server = await db.get(Server, grant.server_id)
    await audit.record(
        "grant_revoked",
        user_id=actor.id if actor else user_id,
        username=actor.username if actor else None,
        server_slug=server.slug if server else None,
        client_id=client_id,
        grant_id=grant_id,
        grant_user_id=user_id,
        reason=reason,
    )
    await _on_grants_revoked([grant_id])
    return True


async def _on_grants_revoked(grant_ids: list[int]) -> None:
    from gateway.bridge.registry import get_registry

    await get_registry().close_where(lambda s: s.grant_id in grant_ids, reason="grant_revoked")
