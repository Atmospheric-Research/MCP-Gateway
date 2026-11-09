import logging
import time
from collections import defaultdict, deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from mcp.server.auth.routes import create_auth_routes
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from starlette.middleware.sessions import SessionMiddleware
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from gateway import audit
from gateway.bridge.registry import get_registry
from gateway.config import get_settings
from gateway.crypto import derived_key
from gateway.db import dispose_engine
from gateway.mcp_endpoint import MCPEndpoint
from gateway.migrate import upgrade_database
from gateway.oauth.provider import GatewayOAuthProvider
from gateway.oauth.resource import protected_resource_metadata
from gateway.ui.auth import CSRFError, Forbidden, LoginRequired, login_url
from gateway.ui.routes import render
from gateway.ui.routes import router as ui_router

logger = logging.getLogger(__name__)

SECURITY_HEADERS = [
    (b"content-security-policy", b"default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"),
    (b"x-frame-options", b"DENY"),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
]


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"].startswith("/s/"):
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                message["headers"] = [*message.get("headers", []), *SECURITY_HEADERS]
            await send(message)

        await self.app(scope, receive, send_with_headers)


class RegistrationRateLimit:
    """Dynamic client registration is unauthenticated by design; cap it per IP."""

    def __init__(self, app: ASGIApp, limit: int = 20, window: float = 3600):
        self.app, self.limit, self.window = app, limit, window
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["path"] == "/register" and scope["method"] == "POST":
            ip = audit.client_ip(Request(scope)) or "?"
            hits, now = self._hits[ip], time.monotonic()
            while hits and hits[0] < now - self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                response = JSONResponse({"error": "slow_down", "error_description": "Too many registrations"}, 429)
                await response(scope, receive, send)
                return
            hits.append(now)
        await self.app(scope, receive, send)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    audit.setup_audit_file()
    await anyio.to_thread.run_sync(upgrade_database)
    async with get_registry().running():
        async with anyio.create_task_group() as tg:
            tg.start_soon(audit.nightly_purge_loop)
            await audit.record("gateway_started", public_url=settings.issuer)
            try:
                yield
            finally:
                tg.cancel_scope.cancel()
    await dispose_engine()


def create_app() -> FastAPI:
    settings = get_settings()
    provider = GatewayOAuthProvider(settings)

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    app.router.routes.extend(
        create_auth_routes(
            provider,  # type: ignore[arg-type]
            # Built through AuthSettings so the path-less issuer keeps its exact form (no trailing
            # slash); clients compare it byte-for-byte with the resource metadata's entry.
            issuer_url=AuthSettings(issuer_url=settings.issuer, resource_server_url=None).issuer_url,  # type: ignore[arg-type]
            client_registration_options=ClientRegistrationOptions(enabled=True),
            revocation_options=RevocationOptions(enabled=True),
        )
    )
    app.router.routes.append(
        Route(
            "/.well-known/oauth-protected-resource/s/{slug}/mcp",
            endpoint=protected_resource_metadata,
            methods=["GET", "OPTIONS"],
        )
    )
    app.router.routes.append(Route("/s/{slug}/mcp", endpoint=MCPEndpoint(provider), methods=["GET", "POST", "DELETE"]))
    app.include_router(ui_router)
    app.mount("/static", StaticFiles(directory=Path(__file__).parent / "ui" / "static"), name="static")

    @app.exception_handler(LoginRequired)
    async def _login_required(request: Request, exc: LoginRequired) -> RedirectResponse:
        return RedirectResponse(login_url(exc.next_url), status_code=303)

    @app.exception_handler(Forbidden)
    async def _forbidden(request: Request, exc: Forbidden):  # type: ignore[no-untyped-def]
        return render(request, "message.html", None, 403, title="Forbidden", message="Administrators only.")

    @app.exception_handler(CSRFError)
    async def _csrf(request: Request, exc: CSRFError):  # type: ignore[no-untyped-def]
        return render(request, "message.html", None, 400, title="Form expired",
                      message="The form was stale or tampered with. Go back, reload the page and try again.")

    app.add_middleware(
        SessionMiddleware,
        secret_key=derived_key("ui-session"),
        session_cookie="gw_session",
        max_age=settings.ui_session_ttl,
        same_site="lax",
        https_only=settings.cookie_secure,
    )
    app.add_middleware(RegistrationRateLimit)
    app.add_middleware(SecurityHeadersMiddleware)
    return app
