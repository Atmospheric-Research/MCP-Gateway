"""How a registered server is turned into a subprocess."""

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TextIO

from mcp.client._transport import TransportStreams
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

from gateway.config import Settings, get_settings
from gateway.crypto import decrypt_env
from gateway.models import Server


class ServerConfigError(ValueError):
    pass


def resolve_directory(directory: str, settings: Settings | None = None) -> Path:
    settings = settings or get_settings()
    root = settings.uploads_dir.resolve()
    path = (root / directory).resolve()
    if root not in path.parents:
        raise ServerConfigError(f"Directory must be inside {root}")
    if not path.is_dir():
        raise ServerConfigError(f"Directory does not exist: {path}")
    return path


PACKAGE_RUNNERS = ("uvx", "npx")


def server_parameters(server: Server, home: Path, settings: Settings | None = None) -> StdioServerParameters:
    settings = settings or get_settings()
    if not server.args:
        raise ServerConfigError("Server has no entry command")
    uv_dir = settings.server_uv_dir
    env = {
        "UV_CACHE_DIR": str(uv_dir / "cache"),
        "UV_PYTHON_INSTALL_DIR": str(uv_dir / "python"),
        "UV_NO_PROGRESS": "1",
        "HOME": str(home),
        "PYTHONUNBUFFERED": "1",
    }
    if server.kind == "package":
        runner, *rest = server.args
        if runner not in PACKAGE_RUNNERS:
            raise ServerConfigError("Package command must start with uvx or npx")
        if runner == "uvx":
            command, args = settings.uv_command, ["tool", "run", *rest]
            env["UV_TOOL_DIR"] = str(uv_dir / "tools")
        else:
            command, args = "npx", rest
            env["npm_config_cache"] = str(uv_dir / "npm")
        return StdioServerParameters(command=command, args=args, env={**env, **decrypt_env(server.env_encrypted)},
                                     cwd=home)
    directory = resolve_directory(server.directory, settings)
    if "--frozen" in settings.uv_run_args and (directory / "pyproject.toml").exists() and not (directory / "uv.lock").exists():
        # --frozen never writes a lockfile, so the upload must ship one.
        raise ServerConfigError(f"{directory} has a pyproject.toml but no uv.lock; run `uv lock` there first")
    # Venvs live outside the upload so replacing the files doesn't rebuild them.
    env["UV_PROJECT_ENVIRONMENT"] = str(uv_dir / "venvs" / server.slug)
    return StdioServerParameters(
        command=settings.uv_command,
        args=[*settings.uv_run_args, "--directory", str(directory), *server.args],
        env={**env, **decrypt_env(server.env_encrypted)},
        cwd=directory,
    )


@asynccontextmanager
async def open_upstream(server: Server, home: Path, errlog: TextIO) -> AsyncIterator[TransportStreams]:
    """The (read, write) message streams to the real server: a subprocess, or a remote streamable HTTP endpoint."""
    if server.kind == "remote":
        if not server.url:
            raise ServerConfigError("Remote server has no URL")
        async with create_mcp_http_client(headers=decrypt_env(server.env_encrypted)) as http:
            async with streamable_http_client(server.url, http_client=http) as streams:
                yield streams
    else:
        async with stdio_client(server_parameters(server, home), errlog=errlog) as streams:
            yield streams


def server_log_path(slug: str, settings: Settings | None = None) -> Path:
    settings = settings or get_settings()
    log_dir = settings.log_dir / "servers"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir / f"{slug}.log"


def open_server_log(slug: str):  # type: ignore[no-untyped-def]
    path = server_log_path(slug)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
    return os.fdopen(fd, "a", encoding="utf-8", buffering=1)
