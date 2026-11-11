# MCP Gateway

Turn your local (stdio) MCP servers into remote connectors you can use from Claude Desktop, claude.ai, Claude Code
or any other MCP client, with logins, per-user access control and an audit log in front.

- **One URL per server**: each server you add gets its own connector at `https://<domain>/s/<slug>/mcp`.
- **Real sign-in**: clients log in through the gateway's own OAuth 2.1 server. Nothing to configure on the client
  besides the URL.
- **You decide who uses what**: create users and tick which servers each one may use. Admins can use all of them.
- **Isolated sessions**: every client connection gets a fresh server process with its own throwaway home folder.

## How it works

```
MCP client ──HTTPS──> your reverse proxy / tunnel ──> gateway:8000
                                                        ├─ /login, /admin, /me   web UI
                                                        ├─ /authorize, /token…   OAuth sign-in
                                                        └─ /s/<slug>/mcp         one server process per session
```

The gateway itself speaks plain HTTP on port 8000. Put it behind something that provides HTTPS on a public
hostname (a reverse proxy, a PaaS router, or a tunnel). Cloud clients such as claude.ai connect from their
provider's network, so that hostname must be reachable from the internet.

## Quick start

You need Docker with Compose, and a hostname with HTTPS that forwards to the container's port 8000.

1. **Configure.** Copy the example env file and set your public URL:

   ```bash
   cp .env.example .env
   ```

   In `.env`, set `GATEWAY_PUBLIC_URL` to the HTTPS address clients will use, e.g. `https://mcp.example.com`.

2. **Create a secret key** and paste it into `GATEWAY_SECRET_KEY` in `.env`:

   ```bash
   docker compose run --rm gateway python -m gateway generate-key
   ```

   Back this key up. It encrypts server secrets and signs logins, and changing it makes them unreadable.

3. **Prepare the data folder.** The container runs as uid 1000 and needs to write here:

   ```bash
   mkdir -p data && sudo chown 1000:1000 data
   ```

4. **Start it:**

   ```bash
   docker compose up -d --build
   ```

   The compose file publishes no host ports; your proxy reaches the container on port 8000. To try it without a
   proxy, add `ports: ["8000:8000"]` to the `gateway` service.

5. **Create your admin account** (password: at least 12 characters):

   ```bash
   docker compose exec gateway python -m gateway create-admin <username>
   ```

6. **Sign in** at `https://<your-domain>/login`.

## Adding an MCP server

In the web UI, go to **Servers → Add server** and pick one of three kinds:

| Kind | What you provide | Good for |
|------|------------------|----------|
| **Upload zip** | A zipped uv project **including `uv.lock`** (max 200 MB unpacked), the folder inside the zip (empty for its root), and the entry command, e.g. `server.py` or `python -m pkg` | Your own servers |
| **Published package** | A `uvx` or `npx` command, e.g. `uvx mcp-server-fetch==2025.4.7` or `npx -y @modelcontextprotocol/server-memory@2025.9.25` | Servers published on PyPI or npm |
| **Remote URL** | The URL of an MCP server already hosted over streamable HTTP | Adding login and audit in front of an existing server |

Tips:

- After saving, click **Test server**. It installs dependencies and lists the tools, so the first real connection
  isn't slow. Under **Tools** you can then switch individual tools off; they're hidden from clients and refused
  if called.
- **Pin package versions.** Without a version, every new session runs whatever is latest.
- **Environment variables** you enter are stored encrypted. For remote servers they're sent as HTTP headers
  instead (e.g. `Authorization=Bearer …`).
- Remote servers that need their own per-user OAuth sign-in aren't supported.
- An uploaded zip runs as `uv run --frozen --directory <dir> <entry>`. Its files go to `data/servers/` and its
  virtualenv to `data/uv/venvs/<slug>`. Editing without a new zip keeps the current files; old files are not
  cleaned up when you re-upload or delete.

## Connecting a client

Copy a server's URL from **Servers** (or **My account → Copy**), then:

- **Claude Desktop / claude.ai:** Settings → Connectors → Add custom connector → paste the URL.
- **Claude Code:**

  ```bash
  claude mcp add --transport http <slug> https://<your-domain>/s/<slug>/mcp
  ```

  Then run `/mcp` in Claude Code and choose authenticate.

The first connection opens the gateway's login page, then a consent screen. Each server URL is a separate
connector with its own sign-in.

## Managing users and access

- **Users**: create accounts and tick the servers each user may use. Changes apply immediately: removing access
  or disabling a user also ends their open sessions.
- **Grants & sessions** (admins) and **My account** (everyone) list active sign-ins with a **Revoke** button.
- Editing a server ends its open sessions; clients reconnect to the new version on their own.
- **Audit log** (admins): a filterable history of sign-ins, consents, token activity, rejected requests, session
  start/end, admin changes and every tool call (tool name only, never the arguments).

## Configuration

Everything is set through environment variables in `.env`. Only the first two are required.

| Variable | Default | Meaning |
|----------|---------|---------|
| `GATEWAY_PUBLIC_URL` | (required) | Public HTTPS address of the gateway, no trailing slash |
| `GATEWAY_SECRET_KEY` | (required) | Key from `generate-key` |
| `GATEWAY_SESSION_IDLE_TIMEOUT` | `900` | Seconds before an idle session is closed |
| `GATEWAY_MAX_SESSIONS_PER_USER` | `10` | Open sessions allowed per user |
| `GATEWAY_MAX_SESSIONS_PER_SERVER` | `25` | Open sessions allowed per server |
| `GATEWAY_AUDIT_RETENTION_DAYS` | `30` | How long audit entries are kept |
| `GATEWAY_PURGE_HOUR` | `3` | Hour (container local time) of the nightly cleanup |
| `TZ` | UTC | Container time zone, e.g. `Europe/Istanbul` |
| `GATEWAY_ALLOWED_REDIRECT_URIS` | Claude's callback URLs | JSON list of the exact OAuth callback URLs clients may register (replaces the default; loopback URLs are allowed on top) |
| `GATEWAY_COOKIE_SECURE` | `true` | Set `false` only for local plain-HTTP testing |

## Data and maintenance

Everything lives in `./data`: the SQLite database, uploaded servers, package caches and logs.

- `data/logs/audit.jsonl`: audit log file, rotated at midnight and kept for `GATEWAY_AUDIT_RETENTION_DAYS` days.
- `data/logs/servers/<slug>.log`: each server's error output.
- Every night at `GATEWAY_PURGE_HOUR` the gateway deletes old audit entries and expired sign-in data, rotates the
  server logs and compacts the database. Run it by hand with
  `docker compose exec gateway python -m gateway purge`.
- Restarting the gateway ends open sessions; clients reconnect on their own.

## Security details

- Tokens are random strings stored only as SHA-256 hashes. Access tokens last 1 hour, refresh tokens 30 days.
  Refresh tokens rotate on every use, and replaying an old one revokes the whole sign-in.
- Each sign-in is bound to one server (RFC 8707 `resource`), so a token for `/s/a/mcp` doesn't work on `/s/b/mcp`.
- Every MCP request re-checks the user's current access.
- A session (`Mcp-Session-Id`) can only be used by the user who opened it.
- Client registration only accepts Claude's callback URLs and loopback URLs, is rate-limited per IP, and unused
  registrations are cleaned up.
- Server processes get a minimal environment plus a throwaway `HOME`.

## Limitations

- Run a **single** worker (the Dockerfile already does). Open sessions and their processes live in memory.
- Servers behind the gateway use the initialize-handshake MCP protocol (2024-11-05 … 2025-11-25). Clients that
  start with the stateless 2026-07-28 revision get a version error and fall back to the handshake automatically.

## Development

```bash
uv sync
uv run pytest
```

`tests/test_bridge.py` needs `uv` on your PATH; it spawns the example server in `tests/fixtures/echo-server`.

Run the app locally without Docker:

```bash
GATEWAY_PUBLIC_URL=http://localhost:8000 GATEWAY_COOKIE_SECURE=false GATEWAY_DATA_DIR=./data GATEWAY_SECRET_KEY=... uv run uvicorn gateway.main:create_app --factory
```
