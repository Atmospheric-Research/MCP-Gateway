import base64
import hashlib
import json
import re
import secrets
import shutil
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from cryptography.fernet import Fernet

ROOT = Path(__file__).resolve().parents[1]
BASE_URL = "http://localhost:8000"
REDIRECT_URI = "http://localhost:9999/callback"
PROTOCOL_VERSION = "2025-11-25"

requires_uv = pytest.mark.skipif(shutil.which("uv") is None, reason="uv is needed to spawn the example server")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(scope="session")
def uv_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("uv")


@pytest.fixture
def settings(tmp_path: Path, uv_dir: Path, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    monkeypatch.setenv("GATEWAY_PUBLIC_URL", BASE_URL)
    monkeypatch.setenv("GATEWAY_SECRET_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("GATEWAY_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("GATEWAY_UV_DIR", str(uv_dir))
    monkeypatch.setenv("GATEWAY_COOKIE_SECURE", "false")
    monkeypatch.setenv("GATEWAY_REFRESH_REUSE_GRACE", "0")

    from gateway import db
    from gateway.config import get_settings

    get_settings.cache_clear()
    shutil.copytree(ROOT / "tests" / "fixtures" / "echo-server", get_settings().uploads_dir / "echo-server",
                    ignore=shutil.ignore_patterns(".venv", "__pycache__"))
    monkeypatch.setattr(db, "_engine", None)
    monkeypatch.setattr(db, "_sessionmaker", None)
    yield get_settings()
    get_settings.cache_clear()


@pytest.fixture
async def app(settings):  # type: ignore[no-untyped-def]
    from gateway.main import create_app
    from gateway.ui.auth import login_throttle

    login_throttle._failures.clear()
    application = create_app()
    async with application.router.lifespan_context(application):
        yield application


@pytest.fixture
async def client(app) -> AsyncIterator[httpx.AsyncClient]:  # type: ignore[no-untyped-def]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL) as c:
        yield c


async def create_user(username: str, password: str, *, admin: bool = False, servers: tuple[int, ...] = ()) -> int:
    from gateway.crypto import hash_password
    from gateway.db import session_scope
    from gateway.models import User, UserServerAccess

    async with session_scope() as db:
        user = User(username=username, password_hash=hash_password(password), is_admin=admin)
        db.add(user)
        await db.flush()
        for server_id in servers:
            db.add(UserServerAccess(user_id=user.id, server_id=server_id))
    return user.id


async def create_server(slug: str, *, env: dict[str, str] | None = None, **fields: Any) -> int:
    from gateway.crypto import encrypt_env
    from gateway.db import session_scope
    from gateway.models import Server

    async with session_scope() as db:
        server = Server(**{"slug": slug, "name": slug.title(), "directory": "echo-server", "args": ["server.py"],
                           "env_encrypted": encrypt_env(env or {}), **fields})
        db.add(server)
    return server.id


def _csrf(html: str) -> str:
    match = re.search(r'name="csrf" value="([^"]+)"', html)
    assert match, "no csrf token in page"
    return match.group(1)


async def oauth_authorize(
    client: httpx.AsyncClient, username: str, password: str, slug: str, *, approve: bool = True
) -> dict[str, Any]:
    """Drive register -> authorize -> login -> consent; returns {'redirect': ..., 'client_id', 'verifier'}."""
    reg = await client.post(
        "/register",
        json={
            "redirect_uris": [REDIRECT_URI],
            "client_name": "pytest",
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        },
    )
    assert reg.status_code == 201, reg.text
    client_id = reg.json()["client_id"]
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")

    r = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "st4te",
            "resource": f"{BASE_URL}/s/{slug}/mcp",
        },
    )
    assert r.status_code == 302, r.text
    consent_path = r.headers["location"].removeprefix(BASE_URL)

    r = await client.get(consent_path)
    if r.status_code == 303:  # not signed in yet
        login_page = await client.get(r.headers["location"])
        r = await client.post(
            "/login",
            data={"csrf": _csrf(login_page.text), "username": username, "password": password,
                  "next": consent_path},
        )
        assert r.status_code == 303, r.text
        r = await client.get(r.headers["location"])
    assert r.status_code == 200, r.text
    req = parse_qs(urlsplit(consent_path).query)["req"][0]
    r = await client.post(
        "/consent", data={"csrf": _csrf(r.text), "req": req, "action": "approve" if approve else "deny"}
    )
    assert r.status_code == 303, r.text
    return {"redirect": r.headers["location"], "client_id": client_id, "verifier": verifier}


async def oauth_tokens(client: httpx.AsyncClient, username: str, password: str, slug: str) -> dict[str, Any]:
    result = await oauth_authorize(client, username, password, slug)
    query = parse_qs(urlsplit(result["redirect"]).query)
    assert query["state"] == ["st4te"]
    r = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": query["code"][0],
            "redirect_uri": REDIRECT_URI,
            "client_id": result["client_id"],
            "code_verifier": result["verifier"],
        },
    )
    assert r.status_code == 200, r.text
    return {**r.json(), "client_id": result["client_id"]}


def sse_messages(response: httpx.Response) -> list[dict[str, Any]]:
    if response.headers.get("content-type", "").startswith("application/json"):
        return [response.json()]
    return [json.loads(line[5:]) for line in response.text.splitlines() if line.startswith("data:") and line[5:].strip()]


async def mcp_post(
    client: httpx.AsyncClient, slug: str, token: str, payload: dict[str, Any], session_id: str | None = None
) -> httpx.Response:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json, text/event-stream",
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
        headers["Mcp-Protocol-Version"] = PROTOCOL_VERSION
    return await client.post(f"/s/{slug}/mcp", json=payload, headers=headers)


INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": {"name": "pytest", "version": "0"}},
}
