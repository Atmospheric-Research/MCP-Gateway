from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import delete, select

from tests.conftest import (
    BASE_URL,
    INITIALIZE,
    REDIRECT_URI,
    create_server,
    create_user,
    mcp_post,
    oauth_authorize,
    oauth_tokens,
)

pytestmark = pytest.mark.anyio
PASSWORD = "correct horse battery"


async def test_metadata_documents(client):
    await create_server("echo")
    r = await client.get("/.well-known/oauth-authorization-server")
    assert r.status_code == 200
    meta = r.json()
    assert meta["issuer"] == BASE_URL
    assert meta["registration_endpoint"] == f"{BASE_URL}/register"
    assert meta["code_challenge_methods_supported"] == ["S256"]

    r = await client.get("/.well-known/oauth-protected-resource/s/echo/mcp")
    assert r.status_code == 200
    assert r.json()["resource"] == f"{BASE_URL}/s/echo/mcp"
    assert r.json()["authorization_servers"] == [BASE_URL]

    assert (await client.get("/.well-known/oauth-protected-resource/s/nope/mcp")).status_code == 404


async def test_unauthenticated_request_is_challenged(client):
    await create_server("echo")
    r = await client.post("/s/echo/mcp", json=INITIALIZE)
    assert r.status_code == 401
    assert (
        f'resource_metadata="{BASE_URL}/.well-known/oauth-protected-resource/s/echo/mcp"'
        in r.headers["www-authenticate"]
    )
    r = await mcp_post(client, "echo", "not-a-token", INITIALIZE)
    assert r.status_code == 401
    assert 'error="invalid_token"' in r.headers["www-authenticate"]


async def test_registration_rejects_foreign_redirect_uri(client):
    r = await client.post(
        "/register",
        json={"redirect_uris": ["https://evil.example/cb"], "grant_types": ["authorization_code"],
              "response_types": ["code"], "token_endpoint_auth_method": "none"},
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_redirect_uri"


async def test_authorize_requires_known_resource(client):
    reg = await client.post(
        "/register",
        json={"redirect_uris": [REDIRECT_URI], "grant_types": ["authorization_code"], "response_types": ["code"],
              "token_endpoint_auth_method": "none"},
    )
    client_id = reg.json()["client_id"]
    for resource in (None, f"{BASE_URL}/s/missing/mcp", "https://elsewhere.example/s/echo/mcp"):
        params = {"response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT_URI,
                  "code_challenge": "x" * 43, "code_challenge_method": "S256", "state": "s"}
        if resource:
            params["resource"] = resource
        r = await client.get("/authorize", params=params)
        assert r.status_code == 302
        assert "error=" in r.headers["location"] and r.headers["location"].startswith(REDIRECT_URI)


async def test_full_token_flow_and_code_single_use(client):
    server_id = await create_server("echo")
    await create_user("alice", PASSWORD, servers=(server_id,))
    result = await oauth_authorize(client, "alice", PASSWORD, "echo")
    code = parse_qs(urlsplit(result["redirect"]).query)["code"][0]
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI,
            "client_id": result["client_id"], "code_verifier": result["verifier"]}
    r = await client.post("/token", data=form)
    assert r.status_code == 200
    tokens = r.json()
    assert tokens["token_type"].lower() == "bearer" and tokens["refresh_token"]
    r = await client.post("/token", data=form)
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


async def test_wrong_pkce_verifier_rejected(client):
    server_id = await create_server("echo")
    await create_user("alice", PASSWORD, servers=(server_id,))
    result = await oauth_authorize(client, "alice", PASSWORD, "echo")
    code = parse_qs(urlsplit(result["redirect"]).query)["code"][0]
    r = await client.post("/token", data={"grant_type": "authorization_code", "code": code,
                                          "redirect_uri": REDIRECT_URI, "client_id": result["client_id"],
                                          "code_verifier": "wrong" * 10})
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


async def test_consent_without_access_redirects_with_access_denied(client):
    await create_server("echo")
    await create_user("bob", PASSWORD)  # no access
    result = await oauth_authorize(client, "bob", PASSWORD, "echo")
    query = parse_qs(urlsplit(result["redirect"]).query)
    assert query["error"] == ["access_denied"] and "code" not in query


async def test_token_is_bound_to_its_server(client):
    echo = await create_server("echo")
    other = await create_server("other")
    await create_user("alice", PASSWORD, servers=(echo, other))
    tokens = await oauth_tokens(client, "alice", PASSWORD, "echo")
    r = await mcp_post(client, "other", tokens["access_token"], INITIALIZE)
    assert r.status_code == 401
    assert "different server" in r.json()["error_description"]


async def test_acl_removal_applies_to_live_tokens(client):
    from gateway.db import session_scope
    from gateway.models import UserServerAccess

    echo = await create_server("echo")
    user_id = await create_user("alice", PASSWORD, servers=(echo,))
    tokens = await oauth_tokens(client, "alice", PASSWORD, "echo")
    async with session_scope() as db:
        await db.execute(delete(UserServerAccess).where(UserServerAccess.user_id == user_id))
    r = await mcp_post(client, "echo", tokens["access_token"], INITIALIZE)
    assert r.status_code == 403


async def test_refresh_rotates_and_reuse_revokes_grant(client):
    from gateway.db import session_scope
    from gateway.models import Grant

    echo = await create_server("echo")
    await create_user("alice", PASSWORD, servers=(echo,))
    tokens = await oauth_tokens(client, "alice", PASSWORD, "echo")
    form = {"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": tokens["client_id"]}

    r = await client.post("/token", data=form)
    assert r.status_code == 200
    rotated = r.json()
    assert rotated["refresh_token"] != tokens["refresh_token"]

    # Presenting the old refresh token again revokes the whole grant (grace is 0 in tests).
    r = await client.post("/token", data=form)
    assert r.status_code == 400
    async with session_scope() as db:
        grant = await db.scalar(select(Grant))
        assert grant.revoked_at is not None
    r = await client.post("/token", data={**form, "refresh_token": rotated["refresh_token"]})
    assert r.status_code == 400
    r = await mcp_post(client, "echo", rotated["access_token"], INITIALIZE)
    assert r.status_code == 401


async def test_revocation_endpoint_and_ui_revoke(client):
    echo = await create_server("echo")
    await create_user("alice", PASSWORD, servers=(echo,))
    tokens = await oauth_tokens(client, "alice", PASSWORD, "echo")
    # The SDK's revocation model wants a client_secret field even for public clients.
    r = await client.post(
        "/revoke", data={"token": tokens["access_token"], "client_id": tokens["client_id"], "client_secret": ""}
    )
    assert r.status_code == 200
    assert (await mcp_post(client, "echo", tokens["access_token"], INITIALIZE)).status_code == 401

    # A new authorization from the UI side, revoked through /grants/{id}/revoke.
    from gateway.db import session_scope
    from gateway.models import Grant

    tokens = await oauth_tokens(client, "alice", PASSWORD, "echo")
    async with session_scope() as db:
        grant = await db.scalar(select(Grant).where(Grant.revoked_at.is_(None)))
    me = await client.get("/me")
    from tests.conftest import _csrf

    r = await client.post(f"/grants/{grant.id}/revoke", data={"csrf": _csrf(me.text), "back": "/me"})
    assert r.status_code == 303
    assert (await mcp_post(client, "echo", tokens["access_token"], INITIALIZE)).status_code == 401


async def test_purge_drops_only_old_audit_rows(client):
    from gateway import audit
    from gateway.db import session_scope
    from gateway.models import AuditEvent, utcnow

    async with session_scope() as db:
        db.add(AuditEvent(event="ancient", ts=utcnow() - timedelta(days=31)))
        db.add(AuditEvent(event="recent", ts=utcnow() - timedelta(days=29)))
    counts = await audit.purge()
    assert counts["audit_events"] == 1
    async with session_scope() as db:
        events = set((await db.scalars(select(AuditEvent.event))).all())
    assert "recent" in events and "ancient" not in events


async def test_login_throttle(client):
    from tests.conftest import _csrf

    await create_user("alice", PASSWORD)
    page = await client.get("/login")
    for _ in range(5):
        r = await client.post("/login", data={"csrf": _csrf(page.text), "username": "alice", "password": "nope"})
        assert r.status_code == 401
    r = await client.post("/login", data={"csrf": _csrf(page.text), "username": "alice", "password": PASSWORD})
    assert r.status_code == 429
