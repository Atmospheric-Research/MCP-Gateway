# MCP Gateway

An authenticated gateway that runs your stdio MCP servers and exposes each of them as its own remote MCP
connector at `https://<domain>/s/<slug>/mcp`. Any MCP client that supports remote servers with OAuth (e.g.
Claude Desktop/claude.ai, Claude Code) signs in through the gateway's OAuth 2.1 server (dynamic client registration + PKCE). Each connection gets a fresh subprocess.

```
Client ─HTTPS─> Cloudflare ─tunnel─> Traefik ─> gateway:8000 ─┬─ OAuth AS   /.well-known/oauth-authorization-server, /authorize, /token, /register, /revoke
                                                              ├─ per server /.well-known/oauth-protected-resource/s/<slug>/mcp
                                                              ├─ /s/<slug>/mcp  ── one `uv run` subprocess per MCP session
                                                              └─ admin UI   /login, /consent, /admin/*, /me
```

## Deploy

1. `cp .env.example .env`, then set `GATEWAY_PUBLIC_URL` (the https URL of your Cloudflare Tunnel hostname).
2. `docker compose run --rm gateway python -m gateway generate-key` → put the result in `GATEWAY_SECRET_KEY`.
   Keep the key safe. It encrypts server env vars and signs UI sessions.
3. `mkdir -p data && sudo chown 1000:1000 data` (the container runs as uid 1000).
4. `docker compose up -d --build`
5. `docker compose exec gateway python -m gateway create-admin <username>`
6. Sign in at `https://<domain>/login`, then go to **Servers → Add server** and upload a zipped uv project
   **with a `uv.lock`**. Entry is what follows `uv run --frozen --directory <dir>`, e.g. `server.py` or `python -m pkg`.
   Click **Test server**. It builds the venv and lists the tools, so the first client connection isn't slowed by
   dependency installs.
7. **Users**: create accounts and tick the servers each may use. Admins can use every server.

The gateway must be reachable from wherever your clients connect from. Cloud-hosted clients such as
claude.ai call it from their provider's network; local clients such as Claude Code connect from your machine.

## Server kinds

**Servers → Add server** offers three kinds:

- **Upload zip**: a zipped uv project (with `uv.lock`, max 200 MB unpacked). Give the source path inside the zip
  (empty for its root) and the entry command; it runs with `uv run --frozen --directory <dir> <entry>`. Files are
  unpacked to `./data/servers/<random>` and venvs live in `./data/uv/venvs/<slug>`. Editing without a new zip keeps
  the current files; re-uploading or deleting leaves the old files there.
- **Published package**: a command starting with `uvx` or `npx`, e.g. `uvx mcp-server-fetch==2025.4.7` or
  `npx -y @modelcontextprotocol/server-memory@2025.9.25`. Pin versions, or each session runs whatever is latest.
  Package caches live in `./data/uv`.
- **Remote URL**: an MCP server already hosted over streamable HTTP. The gateway opens one upstream session per
  client session and adds its own login, access control and audit in front. The variables you enter are sent as
  HTTP headers (e.g. `Authorization=Bearer …`). Remote servers that need their own per-user OAuth sign-in aren't
  supported.

## Adding connectors

Each server's URL is shown in the UI (Servers, or My account → Copy). Give it to any MCP client that supports
remote (streamable HTTP) servers with OAuth. For example:

- **Claude Code:** `claude mcp add --transport http <slug> https://<domain>/s/<slug>/mcp`, then `/mcp` → authenticate.
- **Claude Desktop / claude.ai:** Settings → Connectors → Add custom connector → paste the URL.

Each connection opens the gateway's login page and then a consent screen. Each URL is a separate connector with
its own grant.

## Security model

- Tokens are opaque and stored as SHA-256 hashes. Access tokens last 1 h. Refresh tokens last 30 d, rotate on
  every use, and are reuse-detected: replaying a rotated refresh token revokes the grant.
- Each grant is bound to the one server named by the RFC 8707 `resource` parameter, so a token for `/s/a/mcp`
  is rejected on `/s/b/mcp`.
- Every MCP request re-checks the user's **current** access. Removing access or disabling a user takes effect
  immediately and ends their live sessions.
- Dynamic client registration only accepts Claude's callback URLs and loopback URLs. Change this with
  `GATEWAY_ALLOWED_REDIRECT_URIS`. Registration is rate-limited per IP, and registrations that are never used are
  purged.
- A session (`Mcp-Session-Id`) can only be used by the user who opened it.
- Server env vars are Fernet-encrypted at rest. Subprocesses get a minimal environment plus a throwaway `HOME`.
- **Grants & sessions** (admin) and **My account** (everyone) list active grants with a Revoke button. Revoking
  kills the tokens and any live sessions.

## Audit log

Recorded events: logins (ok/failed/blocked), client registrations, consent, token issue/refresh/revoke,
refresh-token reuse, rejected MCP requests, session start/end, every `tools/call` (tool name only, never
arguments), and admin changes.

- **Admin → Audit log**: a filterable view backed by SQLite.
- `data/logs/audit.jsonl`: rotated at midnight, 30 files kept.
- At `GATEWAY_PURGE_HOUR` (03:00 by default, container local time; set `TZ`) the gateway deletes audit rows older
  than 30 days and expired or dead OAuth state. It also rotates the per-server stderr logs
  (`data/logs/servers/<slug>.log`) and VACUUMs the DB. Run it by hand with `python -m gateway purge`.

## Operations

- Run **one** uvicorn worker. Live sessions and their subprocesses live in process memory, so a restart ends
  sessions. Clients re-initialize on their own.
- Sessions idle for `GATEWAY_SESSION_IDLE_TIMEOUT` seconds (900 by default) are closed. Caps are
  `GATEWAY_MAX_SESSIONS_PER_USER` and `GATEWAY_MAX_SESSIONS_PER_SERVER`.
- Editing a server ends its live sessions, so clients reconnect onto the new config.
- The servers behind the gateway speak the initialize-handshake protocol (2024-11-05 … 2025-11-25). A client
  that opens with the stateless 2026-07-28 revision gets a version error, which tells it to fall back to the
  handshake.

## Development

```
uv sync
uv run pytest            # tests/test_bridge.py copies tests/fixtures/echo-server into the uploads dir and spawns it via uv
```

Run it locally with `GATEWAY_PUBLIC_URL=http://localhost:8000 GATEWAY_COOKIE_SECURE=false GATEWAY_DATA_DIR=./data
GATEWAY_SECRET_KEY=... uv run uvicorn gateway.main:create_app --factory`.
