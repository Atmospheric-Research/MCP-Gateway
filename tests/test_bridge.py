"""End to end through the gateway into a real stdio subprocess (tests/fixtures/echo-server)."""

import pytest
from sqlalchemy import select

from tests.conftest import INITIALIZE, PROTOCOL_VERSION, create_server, create_user, mcp_post, oauth_tokens, requires_uv, sse_messages

pytestmark = [pytest.mark.anyio, requires_uv]
PASSWORD = "correct horse battery"


async def _open(client, token: str) -> str:
    r = await mcp_post(client, "echo", token, INITIALIZE)
    assert r.status_code == 200, r.text
    (init,) = sse_messages(r)
    assert init["result"]["serverInfo"]["name"] == "echo"
    session_id = r.headers["mcp-session-id"]
    r = await mcp_post(client, "echo", token, {"jsonrpc": "2.0", "method": "notifications/initialized"}, session_id)
    assert r.status_code == 202
    return session_id


async def _call(client, token: str, session_id: str, msg_id: int, tool: str, args: dict) -> dict:
    r = await mcp_post(
        client, "echo", token,
        {"jsonrpc": "2.0", "id": msg_id, "method": "tools/call", "params": {"name": tool, "arguments": args}},
        session_id,
    )
    assert r.status_code == 200, r.text
    responses = [m for m in sse_messages(r) if m.get("id") == msg_id]
    assert responses, r.text
    return responses[0]["result"]


async def test_session_lifecycle_through_bridge(client):
    from gateway.bridge.registry import get_registry
    from gateway.db import session_scope
    from gateway.models import AuditEvent

    server_id = await create_server("echo", env={"GREETING": "merhaba"})
    await create_user("alice", PASSWORD, servers=(server_id,))
    token = (await oauth_tokens(client, "alice", PASSWORD, "echo"))["access_token"]

    session_id = await _open(client, token)
    r = await mcp_post(client, "echo", token, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, session_id)
    tools = {t["name"] for m in sse_messages(r) if m.get("id") == 2 for t in m["result"]["tools"]}
    assert tools == {"echo", "whoami"}

    result = await _call(client, token, session_id, 3, "echo", {"text": "hello"})
    assert result["content"][0]["text"] == "hello"
    whoami = (await _call(client, token, session_id, 4, "whoami", {}))["content"][0]["text"]
    assert "greeting=merhaba" in whoami

    # A second session gets its own process.
    other = await _open(client, token)
    assert other != session_id
    whoami2 = (await _call(client, token, other, 5, "whoami", {}))["content"][0]["text"]
    assert whoami2.split()[0] != whoami.split()[0]

    # Session ids are bound to their owner.
    bob_id = await create_user("bob", PASSWORD, servers=(server_id,))
    assert bob_id
    client.cookies.clear()
    bob_token = (await oauth_tokens(client, "bob", PASSWORD, "echo"))["access_token"]
    r = await mcp_post(client, "echo", bob_token, {"jsonrpc": "2.0", "id": 9, "method": "tools/list"}, session_id)
    assert r.status_code == 404

    r = await client.delete(
        "/s/echo/mcp",
        headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": session_id,
                 "Mcp-Protocol-Version": PROTOCOL_VERSION},
    )
    assert r.status_code == 200
    assert get_registry().get(session_id) is None
    r = await mcp_post(client, "echo", token, {"jsonrpc": "2.0", "id": 6, "method": "tools/list"}, session_id)
    assert r.status_code == 404

    async with session_scope() as db:
        events = (await db.scalars(select(AuditEvent).where(AuditEvent.event == "tool_call"))).all()
    assert [e.detail["tool"] for e in events] == ["echo", "whoami", "whoami"]


async def test_non_initialize_without_session_spawns_nothing(client):
    from gateway.bridge.registry import get_registry

    server_id = await create_server("echo")
    await create_user("alice", PASSWORD, servers=(server_id,))
    token = (await oauth_tokens(client, "alice", PASSWORD, "echo"))["access_token"]
    r = await mcp_post(client, "echo", token, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r.status_code == 400
    assert get_registry().sessions() == []


async def test_revoking_grant_ends_live_session(client):
    from gateway.bridge.registry import get_registry
    from gateway.db import session_scope
    from gateway.models import Grant
    from gateway.oauth.provider import revoke_grant

    server_id = await create_server("echo")
    await create_user("alice", PASSWORD, servers=(server_id,))
    token = (await oauth_tokens(client, "alice", PASSWORD, "echo"))["access_token"]
    session_id = await _open(client, token)
    async with session_scope() as db:
        grant = await db.scalar(select(Grant))
    await revoke_grant(grant.id, reason="test")
    assert get_registry().get(session_id) is None


async def test_probe_lists_tools(settings):
    from gateway.bridge.probe import probe_server
    from gateway.models import Server

    result = await probe_server(Server(slug="echo", name="Echo", directory="echo-server", args=["server.py"]))
    assert result["ok"] and {t["name"] for t in result["tools"]} == {"echo", "whoami"}


@pytest.fixture
def echo_http_url():  # type: ignore[no-untyped-def]
    """tests/fixtures/echo-server served over streamable HTTP on a free local port."""
    import os
    import socket
    import subprocess
    import time

    from tests.conftest import ROOT

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen(
        ["uv", "run", "--frozen", "--directory", str(ROOT / "tests" / "fixtures" / "echo-server"), "server.py"],
        env={**os.environ, "MCP_PORT": str(port)}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 60
        while True:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                assert proc.poll() is None and time.monotonic() < deadline, "echo HTTP server did not start"
                time.sleep(0.2)
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        proc.terminate()
        proc.wait(timeout=10)


async def test_remote_server_through_bridge(client, echo_http_url):
    server_id = await create_server("remote", kind="remote", url=echo_http_url, directory="", args=[])
    await create_user("alice", PASSWORD, servers=(server_id,))
    token = (await oauth_tokens(client, "alice", PASSWORD, "remote"))["access_token"]

    r = await mcp_post(client, "remote", token, INITIALIZE)
    assert r.status_code == 200, r.text
    assert sse_messages(r)[0]["result"]["serverInfo"]["name"] == "echo"
    session_id = r.headers["mcp-session-id"]
    await mcp_post(client, "remote", token, {"jsonrpc": "2.0", "method": "notifications/initialized"}, session_id)
    r = await mcp_post(
        client, "remote", token,
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "echo", "arguments": {"text": "uzak"}}},
        session_id,
    )
    (result,) = [m for m in sse_messages(r) if m.get("id") == 2]
    assert result["result"]["content"][0]["text"] == "uzak"


async def test_remote_probe_sends_headers(settings, echo_http_url, monkeypatch):
    from gateway.bridge import process
    from gateway.bridge.probe import probe_server
    from gateway.crypto import encrypt_env
    from gateway.models import Server

    sent = {}
    real = process.create_mcp_http_client

    def spy(headers=None, **kw):  # type: ignore[no-untyped-def]
        sent.update(headers or {})
        return real(headers=headers, **kw)

    monkeypatch.setattr(process, "create_mcp_http_client", spy)
    server = Server(slug="remote", name="Remote", kind="remote", url=echo_http_url, directory="", args=[],
                    env_encrypted=encrypt_env({"Authorization": "Bearer secret"}))
    result = await probe_server(server)
    assert result["ok"] and {t["name"] for t in result["tools"]} == {"echo", "whoami"}
    assert sent == {"Authorization": "Bearer secret"}


def test_package_command_mapping(settings, tmp_path):
    from gateway.bridge.process import ServerConfigError, server_parameters
    from gateway.models import Server

    uvx = server_parameters(Server(slug="f", kind="package", args=["uvx", "mcp-server-fetch==1.0"]), tmp_path)
    assert uvx.command == settings.uv_command and uvx.args == ["tool", "run", "mcp-server-fetch==1.0"]
    assert "UV_TOOL_DIR" in uvx.env and uvx.cwd == tmp_path
    npx = server_parameters(Server(slug="m", kind="package", args=["npx", "-y", "@x/server"]), tmp_path)
    assert npx.command == "npx" and npx.args == ["-y", "@x/server"] and "npm_config_cache" in npx.env
    with pytest.raises(ServerConfigError):
        server_parameters(Server(slug="b", kind="package", args=["bash", "-c", "id"]), tmp_path)


async def test_admin_form_server_kinds(client):
    from gateway.db import session_scope
    from gateway.models import Server
    from tests.conftest import _csrf

    await create_user("root", PASSWORD, admin=True)
    page = await client.get("/login")
    r = await client.post("/login", data={"csrf": _csrf(page.text), "username": "root", "password": PASSWORD,
                                          "next": "/admin/servers"})
    assert r.status_code == 303, r.text

    async def submit(**form: str) -> int:
        page = await client.get("/admin/servers/new")
        r = await client.post("/admin/servers/new", data={"csrf": _csrf(page.text), "name": form["slug"], **form})
        return r.status_code

    assert await submit(slug="pkg", kind="package", command="uvx mcp-server-fetch") == 303
    assert await submit(slug="rem", kind="remote", url="https://example.com/mcp", env_set="Authorization=Bearer x") == 303
    assert await submit(slug="bad1", kind="package", command="bash -c id") == 400
    assert await submit(slug="bad2", kind="remote", url="http://10.0.0.5/mcp") == 400
    async with session_scope() as db:
        rows = {s.slug: s for s in (await db.scalars(select(Server))).all()}
    assert set(rows) == {"pkg", "rem"}
    assert rows["pkg"].args == ["uvx", "mcp-server-fetch"] and rows["pkg"].directory == ""
    assert rows["rem"].url == "https://example.com/mcp" and rows["rem"].kind == "remote"
    listing = await client.get("/admin/servers")
    assert "https://example.com/mcp" in listing.text and "uvx mcp-server-fetch" in listing.text
    edit = await client.get(f"/admin/servers/{rows['rem'].id}")
    assert 'value="remote" checked' in edit.text and "<code>Authorization</code>" in edit.text


async def test_disabled_tools_hidden_and_refused(client):
    from tests.conftest import _csrf

    server_id = await create_server("echo", disabled_tools=["whoami"])
    await create_user("alice", PASSWORD, servers=(server_id,))
    token = (await oauth_tokens(client, "alice", PASSWORD, "echo"))["access_token"]
    session_id = await _open(client, token)
    r = await mcp_post(client, "echo", token, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, session_id)
    assert [t["name"] for m in sse_messages(r) if m.get("id") == 2 for t in m["result"]["tools"]] == ["echo"]
    r = await mcp_post(
        client, "echo", token,
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "whoami", "arguments": {}}}, session_id,
    )
    assert [m["error"]["code"] for m in sse_messages(r) if m.get("id") == 3] == [-32602]

    # Admin form: re-enable whoami, disable echo.
    client.cookies.clear()
    await create_user("root", PASSWORD, admin=True)
    page = await client.get("/login")
    await client.post("/login", data={"csrf": _csrf(page.text), "username": "root", "password": PASSWORD, "next": "/"})
    page = await client.get(f"/admin/servers/{server_id}")
    assert 'name="tools" value="whoami"' in page.text and "data-autotest" in page.text
    # Testing caches the tool list, so it survives a reload.
    r = await client.post(f"/admin/servers/{server_id}/test", headers={"X-CSRF-Token": _csrf(page.text)})
    assert r.json()["ok"], r.text
    page = await client.get(f"/admin/servers/{server_id}")
    assert 'name="tool_enabled" value="echo" checked' in page.text and "data-autotest" not in page.text
    assert page.text.count('name="tools" value="whoami"') == 1
    r = await client.post(f"/admin/servers/{server_id}", data={
        "csrf": _csrf(page.text), "name": "Echo", "slug": "echo", "kind": "upload",
        "entry": "server.py", "enabled": "on", "tools": ["echo", "whoami"], "tool_enabled": ["whoami"],
    })
    assert r.status_code == 303, r.text
    from gateway.db import session_scope
    from gateway.models import Server
    async with session_scope() as db:
        assert (await db.get(Server, server_id)).disabled_tools == ["echo"]


async def test_admin_form_zip_upload(client, settings, tmp_path):
    import io
    import zipfile

    from gateway.bridge.process import server_parameters
    from gateway.db import session_scope
    from gateway.models import Server
    from tests.conftest import ROOT, _csrf

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for f in ("pyproject.toml", "uv.lock", "server.py"):
            zf.write(ROOT / "tests" / "fixtures" / "echo-server" / f, f"echo-server/{f}")
    await create_user("root", PASSWORD, admin=True)
    page = await client.get("/login")
    await client.post("/login", data={"csrf": _csrf(page.text), "username": "root", "password": PASSWORD, "next": "/"})

    async def submit(src: str, data: bytes) -> int:
        page = await client.get("/admin/servers/new")
        r = await client.post("/admin/servers/new", files={"archive": ("s.zip", data, "application/zip")}, data={
            "csrf": _csrf(page.text), "name": "Up", "slug": f"up{len(src)}", "kind": "upload", "src": src,
            "entry": "server.py", "enabled": "on"})
        return r.status_code

    assert await submit("../..", buf.getvalue()) == 400
    assert await submit("echo-server", b"not a zip") == 400
    assert await submit("echo-server", buf.getvalue()) == 303
    async with session_scope() as db:
        (server,) = (await db.scalars(select(Server))).all()
    assert server.kind == "uv" and server.args == ["server.py"]
    path = settings.uploads_dir.resolve() / server.directory
    assert (path / "uv.lock").exists() and server_parameters(server, tmp_path).cwd == path

    # Editing without a new zip keeps the files.
    page = await client.get(f"/admin/servers/{server.id}")
    r = await client.post(f"/admin/servers/{server.id}", data={
        "csrf": _csrf(page.text), "name": "Up2", "slug": server.slug, "kind": "upload", "entry": "server.py"})
    assert r.status_code == 303, r.text
    async with session_scope() as db:
        assert (await db.get(Server, server.id)).directory == server.directory

    # Deleting the server removes its upload, venv and log.
    from gateway.bridge.process import server_log_path
    venv = settings.server_uv_dir / "venvs" / server.slug
    venv.mkdir(parents=True)
    server_log_path(server.slug).write_text("x")
    page = await client.get(f"/admin/servers/{server.id}")
    r = await client.post(f"/admin/servers/{server.id}/delete", data={"csrf": _csrf(page.text)})
    assert r.status_code == 303
    assert not path.parent.exists() and not venv.exists() and not server_log_path(server.slug).exists()
    assert settings.uploads_dir.exists()
