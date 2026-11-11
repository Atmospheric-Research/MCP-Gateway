# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An authenticated gateway that runs stdio MCP servers (or proxies remote ones) and exposes each as its own remote
MCP connector at `/s/<slug>/mcp`, protected by the gateway's own OAuth 2.1 server. FastAPI + SQLAlchemy (async,
SQLite) + Alembic, built on the `mcp` SDK (pinned `mcp==2.3.0`). Deployed with Docker Compose behind an external
reverse proxy that terminates TLS.

## Commands

```bash
uv sync
uv run pytest                                              # all tests
uv run pytest tests/test_oauth.py::test_full_token_flow_and_code_single_use   # one test
uv run python -m gateway create-admin <username>           # also: generate-key, purge
```

Run locally:

```bash
GATEWAY_PUBLIC_URL=http://localhost:8000 GATEWAY_COOKIE_SECURE=false GATEWAY_DATA_DIR=./data GATEWAY_SECRET_KEY=... uv run uvicorn gateway.main:create_app --factory
```

No linter or type checker is configured. `tests/test_bridge.py` needs `uv` on PATH: it copies
`tests/fixtures/echo-server` into the uploads dir and spawns it for real (skipped otherwise).

## Architecture

**Request path for `/s/{slug}/mcp`** (`gateway/mcp_endpoint.py`): look up the enabled server → `authenticate()`
in `oauth/resource.py` validates the bearer token, checks it is bound to *this* server (RFC 8707 resource) and
re-checks the user's current access on every request → route by `Mcp-Session-Id` to an existing `BridgeSession`
(must belong to the same user and server), or, for an `initialize` POST only, open a new one.

**Bridge** (`gateway/bridge/`):
- `registry.py`: the in-memory `SessionRegistry` of live sessions, run inside a task group owned by the app
  lifespan, with per-user/per-server caps. Because sessions and subprocesses live in process memory, the app must
  run as **one uvicorn worker**. Anything that changes access (grant revoke, user disable, server edit/delete)
  calls `registry.close_where(...)` to kill affected live sessions. Keep doing that when adding such actions.
- `session.py`: one `BridgeSession` = a `StreamableHTTPServerTransport` facing the client wired to an upstream.
  Messages are forwarded verbatim at JSON-RPC level (no per-method code). The only interception is filtering
  `disabled_tools` out of `tools/list`, rejecting calls to them, auditing `tools/call`, and attaching
  server-originated messages to an in-flight request so they ride an open SSE stream.
- `process.py`: turns a `Server` row into an upstream by `kind`: `uv` (uploaded zip → `uv run --frozen --directory`,
  venv kept outside the upload in `data/uv/venvs/<slug>`), `package` (`uvx`/`npx` only), `remote` (streamable
  HTTP, encrypted env vars sent as headers). Subprocesses get a minimal env and a throwaway `HOME`.

**OAuth** (`gateway/oauth/`): `provider.py` implements the `mcp` SDK's provider interface; routes come from
`mcp.server.auth.routes.create_auth_routes` in `main.py`. Tokens are opaque and stored hashed; refresh tokens
rotate with reuse detection (`refresh_reuse_grace`). `resource.py` serves per-server RFC 9728 metadata. The issuer
string must match byte-for-byte between AS and resource metadata (see the comment in `main.py`).

**UI** (`gateway/ui/`): server-rendered Jinja templates in `routes.py` for login, consent, admin and the
"my account" page. Auth helpers in `auth.py`: cookie session + `session_epoch` (bump it to log a user out
everywhere), CSRF, and a login throttle keyed by client IP and username.

**Cross-cutting:**
- `config.py`: all settings are `GATEWAY_*` env vars (pydantic-settings, `.env` read); `get_settings()` is
  `lru_cache`d, so tests call `get_settings.cache_clear()`.
- `audit.py`: every security event goes through `audit.record()` (SQLite + `data/logs/audit.jsonl`), plus the
  nightly purge loop. `client_ip()` prefers `CF-Connecting-IP`, then `X-Forwarded-For`; rate limits depend on it.
- `crypto.py`: Fernet-encrypted server env vars; keys for other purposes are derived from `GATEWAY_SECRET_KEY`.
- Migrations run automatically at startup (`migrate.upgrade_database`). There is no `alembic.ini`; config is
  built in code by `migrate.alembic_config()`. New migrations go in `gateway/migrations/versions/` with the next
  `000N_` prefix and must use batch mode (SQLite).

## Tests

`tests/conftest.py` sets env vars per test, resets the cached settings and DB engine, and drives the full app
in-process with httpx (OAuth registration → authorize → consent → token helpers). Tests are async via anyio
(asyncio backend).
