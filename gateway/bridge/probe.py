"""The admin UI's "Test" button: start the server once, handshake, list its tools.

The first run also builds the server's venv, so later client sessions start fast."""

import shutil
import tempfile
from pathlib import Path
from typing import Any

import anyio
from mcp.client.session import ClientSession

from gateway.bridge.process import open_server_log, open_upstream, server_log_path
from gateway.config import get_settings
from gateway.models import Server


async def probe_server(server: Server) -> dict[str, Any]:
    home = Path(tempfile.mkdtemp(prefix=f"mcp-probe-{server.slug}-"))
    errlog = open_server_log(server.slug)
    try:
        with anyio.fail_after(get_settings().server_test_timeout):
            async with open_upstream(server, home, errlog) as (read, write):
                async with ClientSession(read, write) as session:
                    init = await session.initialize()
                    tools = await session.list_tools()
        return {
            "ok": True,
            "server_name": init.server_info.name,
            "server_version": init.server_info.version,
            "protocol_version": init.protocol_version,
            "tools": [{"name": t.name, "description": (t.description or "").strip()} for t in tools.tools],
        }
    finally:
        errlog.close()
        shutil.rmtree(home, ignore_errors=True)


def tail_server_log(slug: str, lines: int = 40) -> str:
    path = server_log_path(slug)
    if not path.exists():
        return ""
    with path.open("rb") as f:
        f.seek(0, 2)
        f.seek(max(0, f.tell() - 16384))
        return "\n".join(f.read().decode("utf-8", "replace").splitlines()[-lines:])
