import re
import secrets
import shlex
import zipfile
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from mcp.server.auth.provider import AuthorizationParams, construct_redirect_uri
from sqlalchemy import delete, func, select
from sqlalchemy.orm import selectinload
from starlette.datastructures import UploadFile

from gateway import audit
from gateway.bridge.probe import probe_server, tail_server_log
from gateway.bridge.process import PACKAGE_RUNNERS, ServerConfigError, resolve_directory
from gateway.bridge.registry import get_registry
from gateway.config import get_settings
from gateway.crypto import decrypt_env, encrypt_env, hash_password, verify_password
from gateway.db import session_scope
from gateway.models import AuditEvent, Grant, OAuthClient, PendingAuthorization, Server, User, UserServerAccess, utcnow
from gateway.oauth.provider import GatewayOAuthProvider, revoke_grant, user_can_access
from gateway.ui.auth import (
    csrf_token,
    find_user,
    log_in,
    login_throttle,
    require_admin,
    require_user,
    safe_next,
    verify_csrf,
)

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
MIN_PASSWORD_LENGTH = 12
AUDIT_PAGE_SIZE = 100
MAX_UPLOAD_UNZIPPED = 200 * 1024 * 1024

templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
router = APIRouter()


def render(request: Request, name: str, user: User | None, status_code: int = 200, **context: Any) -> Response:
    return templates.TemplateResponse(
        request,
        name,
        {"user": user, "csrf": csrf_token(request), "settings": get_settings(), **context},
        status_code=status_code,
    )


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def _checked(form: Any, name: str) -> bool:
    return form.get(name) in ("on", "1", "true")


# -- login ------------------------------------------------------------------------------------


@router.get("/login")
async def login_page(request: Request, next: str = "/") -> Response:
    return render(request, "login.html", None, next=safe_next(next))


@router.post("/login")
async def login_submit(request: Request) -> Response:
    await verify_csrf(request)
    form = await request.form()
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))
    next_url = safe_next(str(form.get("next", "/")))
    keys = (f"ip:{audit.client_ip(request)}", f"user:{username.lower()}")

    if login_throttle.blocked(*keys):
        await audit.record("login_blocked", conn=request, username=username)
        return render(request, "login.html", None, 429, next=next_url, error="Too many attempts. Try again later.")

    user = await find_user(username)
    if not verify_password(user.password_hash if user else None, password) or user is None or not user.is_active:
        login_throttle.fail(*keys)
        await audit.record("login_failed", conn=request, username=username)
        return render(request, "login.html", None, 401, next=next_url, error="Invalid username or password.")

    login_throttle.reset(*keys)
    log_in(request, user)
    await audit.record("login_ok", conn=request, user_id=user.id, username=user.username)
    return redirect(next_url)


@router.post("/logout")
async def logout(request: Request, user: User = Depends(require_user)) -> Response:
    await verify_csrf(request)
    request.session.clear()
    await audit.record("logout", conn=request, user_id=user.id, username=user.username)
    return redirect("/login")


@router.get("/")
async def home(user: User = Depends(require_user)) -> Response:
    return redirect("/admin/servers" if user.is_admin else "/me")


# -- consent (end of the OAuth /authorize flow) --------------------------------------------------


async def _load_pending(req: str) -> tuple[PendingAuthorization, OAuthClient, Server] | None:
    async with session_scope() as db:
        pending = await db.get(PendingAuthorization, req)
        if pending is None or pending.expires_at < utcnow():
            return None
        client = await db.get(OAuthClient, pending.client_id)
        server = await db.get(Server, pending.server_id)
    if client is None or server is None:
        return None
    return pending, client, server


@router.get("/consent")
async def consent_page(request: Request, req: str = "", user: User = Depends(require_user)) -> Response:
    loaded = await _load_pending(req)
    if loaded is None:
        return render(request, "message.html", user, 400, title="Authorization expired",
                      message="This authorization request is invalid or has expired. Start the connection again from your MCP client.")
    pending, client, server = loaded
    params = AuthorizationParams.model_validate_json(pending.params_json)
    async with session_scope() as db:
        allowed = await user_can_access(db, user, server)
    return render(request, "consent.html", user, req=req, client=client, server=server, allowed=allowed,
                  redirect_uri=str(params.redirect_uri))


@router.post("/consent")
async def consent_submit(request: Request, user: User = Depends(require_user)) -> Response:
    await verify_csrf(request)
    form = await request.form()
    loaded = await _load_pending(str(form.get("req", "")))
    if loaded is None:
        return render(request, "message.html", user, 400, title="Authorization expired",
                      message="This authorization request is invalid or has expired. Start the connection again from your MCP client.")
    pending, client, server = loaded
    params = AuthorizationParams.model_validate_json(pending.params_json)
    approve = form.get("action") == "approve"
    issuer = get_settings().issuer  # RFC 9207 mix-up protection

    async with session_scope() as db:
        # Re-read inside this transaction so a double submit can't mint two codes.
        pending = await db.get(PendingAuthorization, pending.id)
        if pending is None:
            return redirect(f"/consent?req={form.get('req', '')}")
        if approve and await user_can_access(db, user, server):
            code = await GatewayOAuthProvider().create_authorization_code(db, pending, user)
            target = construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state, iss=issuer)
            event = "consent_granted"
        else:
            await db.delete(pending)
            target = construct_redirect_uri(
                str(params.redirect_uri), error="access_denied", error_description="The user denied access",
                state=params.state, iss=issuer,
            )
            event = "consent_denied"
    await audit.record(event, conn=request, user_id=user.id, username=user.username, server_slug=server.slug,
                       client_id=client.client_id, client_name=client.client_name)
    return redirect(target)


# -- self service ---------------------------------------------------------------------------------


async def _grant_rows(where: Any) -> list[dict[str, Any]]:
    live = Counter(s.grant_id for s in get_registry().sessions())
    async with session_scope() as db:
        grants = (
            await db.scalars(
                select(Grant)
                .where(Grant.revoked_at.is_(None), where)
                .options(selectinload(Grant.user), selectinload(Grant.server), selectinload(Grant.client))
                .order_by(Grant.created_at.desc())
            )
        ).all()
    return [{"grant": g, "sessions": live.get(g.id, 0)} for g in grants]


@router.get("/me")
async def me(request: Request, user: User = Depends(require_user)) -> Response:
    async with session_scope() as db:
        query = select(Server).where(Server.enabled.is_(True)).order_by(Server.name)
        if not user.is_admin:
            query = query.join(UserServerAccess).where(UserServerAccess.user_id == user.id)
        servers = (await db.scalars(query)).all()
    grants = await _grant_rows(Grant.user_id == user.id)
    return render(request, "me.html", user, servers=servers, grants=grants, message=request.query_params.get("msg"))


@router.post("/me/password")
async def change_password(request: Request, user: User = Depends(require_user)) -> Response:
    await verify_csrf(request)
    form = await request.form()
    current, new, confirm = (str(form.get(k, "")) for k in ("current", "new", "confirm"))
    if not verify_password(user.password_hash, current):
        return redirect("/me?msg=Current+password+is+wrong")
    if len(new) < MIN_PASSWORD_LENGTH or new != confirm:
        return redirect(f"/me?msg=New+password+must+match+and+be+at+least+{MIN_PASSWORD_LENGTH}+characters")
    async with session_scope() as db:
        row = await db.get(User, user.id)
        assert row is not None
        row.password_hash = hash_password(new)
        row.session_epoch += 1
    user.session_epoch += 1
    log_in(request, user)  # keeps this browser signed in, drops all others
    await audit.record("password_changed", conn=request, user_id=user.id, username=user.username)
    return redirect("/me?msg=Password+changed")


@router.post("/grants/{grant_id}/revoke")
async def revoke(request: Request, grant_id: int, user: User = Depends(require_user)) -> Response:
    await verify_csrf(request)
    async with session_scope() as db:
        grant = await db.get(Grant, grant_id)
    if grant is not None and (user.is_admin or grant.user_id == user.id):
        await revoke_grant(grant_id, reason="ui", actor=user)
    form = await request.form()
    return redirect(safe_next(str(form.get("back", "/me"))))


# -- servers --------------------------------------------------------------------------------------


def _parse_env_lines(text: str) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not ENV_KEY_RE.match(key):
            raise ValueError(f"Invalid env line: {line.strip()[:40]}")
        env[key] = value
    return env


def _extract_upload(upload: Any, src: str) -> str:
    """Unzip an uploaded server into its own new directory; returns the absolute project path."""
    if not isinstance(upload, UploadFile) or not upload.filename:
        raise ValueError("Choose a .zip file to upload.")
    try:
        archive = zipfile.ZipFile(upload.file)
    except zipfile.BadZipFile:
        raise ValueError("The upload is not a valid zip file.") from None
    with archive:
        if sum(i.file_size for i in archive.infolist()) > MAX_UPLOAD_UNZIPPED:
            raise ValueError(f"The zip unpacks to more than {MAX_UPLOAD_UNZIPPED // 2**20} MB.")
        # shortcut: replaced or deleted uploads stay on disk (a live session may still run from them); prune by hand.
        target = get_settings().uploads_dir / secrets.token_hex(8)
        target.mkdir(parents=True)
        archive.extractall(target)  # zipfile drops absolute paths and ".." components
    path = (target / src.strip().strip("/")).resolve()
    if path != target.resolve() and target.resolve() not in path.parents:
        raise ValueError("Source path must be inside the zip.")
    directory = str(path.relative_to(get_settings().uploads_dir.resolve()))
    resolve_directory(directory)
    return directory


def _remote_url_ok(url: str) -> bool:
    parts = urlsplit(url)
    if not parts.hostname:
        return False
    return parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1", "::1"))


async def _server_from_form(request: Request, server: Server) -> str | None:
    """Apply the submitted form to `server`; returns an error message or None."""
    form = await request.form()
    slug = str(form.get("slug", "")).strip().lower()
    if not SLUG_RE.match(slug):
        return "Slug must be lowercase letters, digits and dashes."
    name = str(form.get("name", "")).strip()
    if not name:
        return "Name is required."
    kind = str(form.get("kind", "upload"))
    if kind not in ("upload", "package", "remote"):
        return "Unknown server kind."
    directory, url, args = "", None, []
    try:
        if kind == "upload":
            # An uploaded zip is stored as a "uv" server whose directory is under uploads_dir.
            kind = "uv"
            args = shlex.split(str(form.get("entry", "")))
            if not args:
                return "Entry command is required (e.g. server.py or python -m my_server)."
            archive = form.get("archive")
            if server.kind == "uv" and server.directory and not (isinstance(archive, UploadFile) and archive.filename):
                directory = server.directory  # editing without a new zip keeps the current files
            else:
                directory = _extract_upload(archive, str(form.get("src", "")))
        elif kind == "package":
            args = shlex.split(str(form.get("command", "")))
        else:
            url = str(form.get("url", "")).strip()
        env = decrypt_env(server.env_encrypted)
        for key in form.getlist("env_delete"):
            env.pop(str(key), None)
        env.update(_parse_env_lines(str(form.get("env_set", ""))))
    except (ServerConfigError, ValueError) as e:
        return str(e)
    if kind == "package" and (not args or args[0] not in PACKAGE_RUNNERS):
        return "Package command must start with uvx or npx (e.g. uvx mcp-server-fetch)."
    if kind == "remote" and not _remote_url_ok(url or ""):
        return "URL must be https:// (http:// is allowed only for localhost)."
    server.slug, server.name, server.kind, server.directory, server.url, server.args = slug, name, kind, directory, url, args
    server.description = str(form.get("description", "")).strip()
    server.enabled = _checked(form, "enabled")
    listed = {str(t) for t in form.getlist("tools")}
    enabled = {str(t) for t in form.getlist("tool_enabled")}
    server.disabled_tools = sorted((set(server.disabled_tools or ()) - listed) | (listed - enabled))
    server.env_encrypted = encrypt_env(env)
    return None


@router.get("/admin/servers")
async def servers_list(request: Request, user: User = Depends(require_admin)) -> Response:
    live = Counter(s.server_id for s in get_registry().sessions())
    async with session_scope() as db:
        servers = (await db.scalars(select(Server).options(selectinload(Server.users)).order_by(Server.name))).all()
    return render(request, "servers.html", user, servers=servers, live=live)


@router.get("/admin/servers/new")
async def server_new(request: Request, user: User = Depends(require_admin)) -> Response:
    return render(request, "server_form.html", user, server=Server(enabled=True, args=[]), env_keys=[])


@router.post("/admin/servers/new")
async def server_create(request: Request, user: User = Depends(require_admin)) -> Response:
    await verify_csrf(request)
    server = Server(enabled=True, args=[])
    error = await _server_from_form(request, server)
    if error is None:
        async with session_scope() as db:
            if await db.scalar(select(Server).where(Server.slug == server.slug)):
                error = "That slug is already used."
            else:
                db.add(server)
    if error:
        return render(request, "server_form.html", user, 400, server=server, env_keys=[], error=error)
    await audit.record("server_created", conn=request, user_id=user.id, username=user.username, server_slug=server.slug)
    return redirect(f"/admin/servers/{server.id}")


@router.get("/admin/servers/{server_id}")
async def server_edit(request: Request, server_id: int, user: User = Depends(require_admin)) -> Response:
    async with session_scope() as db:
        server = await db.get(Server, server_id)
    if server is None:
        return redirect("/admin/servers")
    return render(request, "server_form.html", user, server=server, env_keys=sorted(decrypt_env(server.env_encrypted)),
                  log_tail=tail_server_log(server.slug))


@router.post("/admin/servers/{server_id}")
async def server_update(request: Request, server_id: int, user: User = Depends(require_admin)) -> Response:
    await verify_csrf(request)
    async with session_scope() as db:
        server = await db.get(Server, server_id)
        if server is None:
            return redirect("/admin/servers")
        old_slug = server.slug
        error = await _server_from_form(request, server)
        if error is None and server.slug != old_slug and await db.scalar(
            select(Server).where(Server.slug == server.slug, Server.id != server.id)
        ):
            error = "That slug is already used."
        if error:
            await db.rollback()
            server = await db.get(Server, server_id)
            assert server is not None
            return render(request, "server_form.html", user, 400, server=server,
                          env_keys=sorted(decrypt_env(server.env_encrypted)), error=error)
    # Running sessions keep the old config; end them so clients reconnect onto the new one.
    await get_registry().close_where(lambda s: s.server_id == server_id, reason="server_updated")
    await audit.record("server_updated", conn=request, user_id=user.id, username=user.username, server_slug=server.slug,
                       previous_slug=old_slug if old_slug != server.slug else None)
    return redirect(f"/admin/servers/{server_id}")


@router.post("/admin/servers/{server_id}/delete")
async def server_delete(request: Request, server_id: int, user: User = Depends(require_admin)) -> Response:
    await verify_csrf(request)
    async with session_scope() as db:
        server = await db.get(Server, server_id)
        if server is None:
            return redirect("/admin/servers")
        slug = server.slug
        await db.delete(server)
    await get_registry().close_where(lambda s: s.server_id == server_id, reason="server_deleted")
    await audit.record("server_deleted", conn=request, user_id=user.id, username=user.username, server_slug=slug)
    return redirect("/admin/servers")


@router.post("/admin/servers/{server_id}/test")
async def server_test(request: Request, server_id: int, user: User = Depends(require_admin)) -> Response:
    await verify_csrf(request)
    async with session_scope() as db:
        server = await db.get(Server, server_id)
    if server is None:
        return JSONResponse({"ok": False, "error": "Not found"}, status_code=404)
    try:
        result = await probe_server(server)
        for tool in result["tools"]:
            tool["enabled"] = tool["name"] not in (server.disabled_tools or ())
    except Exception as e:  # surfaced to the admin verbatim, together with the server's stderr
        messages = [str(x) for x in getattr(e, "exceptions", [e])]
        result = {"ok": False, "error": f"{type(e).__name__}: {'; '.join(messages) or 'timed out'}"}
    result["log"] = tail_server_log(server.slug)
    await audit.record("server_tested", conn=request, user_id=user.id, username=user.username, server_slug=server.slug,
                       ok=result["ok"])
    return JSONResponse(result)


# -- users ----------------------------------------------------------------------------------------


@router.get("/admin/users")
async def users_list(request: Request, user: User = Depends(require_admin)) -> Response:
    async with session_scope() as db:
        users = (await db.scalars(select(User).options(selectinload(User.servers)).order_by(User.username))).all()
    return render(request, "users.html", user, users=users)


async def _all_servers() -> list[Server]:
    async with session_scope() as db:
        return list((await db.scalars(select(Server).order_by(Server.name))).all())


@router.get("/admin/users/new")
async def user_new(request: Request, user: User = Depends(require_admin)) -> Response:
    return render(request, "user_form.html", user, target=None, servers=await _all_servers(), access=set())


@router.post("/admin/users/new")
async def user_create(request: Request, user: User = Depends(require_admin)) -> Response:
    await verify_csrf(request)
    form = await request.form()
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))
    access = {int(x) for x in form.getlist("servers")}
    error = None
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{2,64}", username):
        error = "Username must be 2-64 characters: letters, digits, _ . @ -"
    elif len(password) < MIN_PASSWORD_LENGTH:
        error = f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    elif await find_user(username):
        error = "That username is taken."
    if error:
        return render(request, "user_form.html", user, 400, target=None, servers=await _all_servers(), access=access,
                      error=error, username=username)
    async with session_scope() as db:
        new_user = User(username=username, password_hash=hash_password(password), is_admin=_checked(form, "is_admin"))
        db.add(new_user)
        await db.flush()
        for server_id in access:
            db.add(UserServerAccess(user_id=new_user.id, server_id=server_id))
    await audit.record("user_created", conn=request, user_id=user.id, username=user.username,
                       target_user=username, is_admin=new_user.is_admin, servers=sorted(access))
    return redirect("/admin/users")


@router.get("/admin/users/{user_id}")
async def user_edit(request: Request, user_id: int, user: User = Depends(require_admin)) -> Response:
    async with session_scope() as db:
        target = await db.get(User, user_id, options=[selectinload(User.servers)])
    if target is None:
        return redirect("/admin/users")
    return render(request, "user_form.html", user, target=target, servers=await _all_servers(),
                  access={s.id for s in target.servers})


@router.post("/admin/users/{user_id}")
async def user_update(request: Request, user_id: int, user: User = Depends(require_admin)) -> Response:
    await verify_csrf(request)
    form = await request.form()
    access = {int(x) for x in form.getlist("servers")}
    password = str(form.get("password", ""))
    async with session_scope() as db:
        target = await db.get(User, user_id, options=[selectinload(User.servers)])
        if target is None:
            return redirect("/admin/users")
        is_self = target.id == user.id
        error = None
        if password and len(password) < MIN_PASSWORD_LENGTH:
            error = f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        if error:
            return render(request, "user_form.html", user, 400, target=target, servers=await _all_servers(),
                          access=access, error=error)
        was_active, was_admin = target.is_active, target.is_admin
        # An admin can't lock themselves out from this form.
        target.is_admin = True if is_self else _checked(form, "is_admin")
        target.is_active = True if is_self else _checked(form, "is_active")
        if password:
            target.password_hash = hash_password(password)
        if password or (was_active and not target.is_active):
            target.session_epoch += 1
        removed = {s.id for s in target.servers} - access
        await db.execute(delete(UserServerAccess).where(UserServerAccess.user_id == target.id))
        for server_id in access:
            db.add(UserServerAccess(user_id=target.id, server_id=server_id))
        username = target.username
        now_admin, now_active = target.is_admin, target.is_active

    registry = get_registry()
    if not now_active:
        await registry.close_where(lambda s: s.user_id == user_id, reason="user_disabled")
    elif not now_admin and (was_admin or removed):
        # Admins reach every server implicitly; drop whatever the new access set no longer covers.
        await registry.close_where(lambda s: s.user_id == user_id and s.server_id not in access, reason="access_removed")
    await audit.record("user_updated", conn=request, user_id=user.id, username=user.username, target_user=username,
                       is_admin=now_admin, is_active=now_active, servers=sorted(access), password_reset=bool(password))
    return redirect("/admin/users")


@router.post("/admin/users/{user_id}/delete")
async def user_delete(request: Request, user_id: int, user: User = Depends(require_admin)) -> Response:
    await verify_csrf(request)
    if user_id == user.id:
        return redirect("/admin/users")
    async with session_scope() as db:
        target = await db.get(User, user_id)
        if target is None:
            return redirect("/admin/users")
        username = target.username
        await db.delete(target)
    await get_registry().close_where(lambda s: s.user_id == user_id, reason="user_deleted")
    await audit.record("user_deleted", conn=request, user_id=user.id, username=user.username, target_user=username)
    return redirect("/admin/users")


# -- grants, sessions, audit ---------------------------------------------------------------------------


@router.get("/admin/grants")
async def grants_list(request: Request, user: User = Depends(require_admin)) -> Response:
    grants = await _grant_rows(Grant.id.is_not(None))
    sessions = sorted(get_registry().sessions(), key=lambda s: s.created_at, reverse=True)
    return render(request, "grants.html", user, grants=grants, sessions=sessions)


@router.post("/admin/sessions/{session_id}/close")
async def session_close(request: Request, session_id: str, user: User = Depends(require_admin)) -> Response:
    await verify_csrf(request)
    session = get_registry().get(session_id)
    if session is not None:
        await get_registry().close(session, reason="closed_by_admin")
        await audit.record("session_killed", conn=request, user_id=user.id, username=user.username,
                           server_slug=session.server_slug, session_id=session_id, session_user=session.username)
    return redirect("/admin/grants")


@router.get("/admin/audit")
async def audit_list(
    request: Request,
    user: User = Depends(require_admin),
    username: str = "",
    server: str = "",
    event: str = "",
    ip: str = "",
    since: str = "",
    page: int = 1,
) -> Response:
    query = select(AuditEvent)
    if username:
        query = query.where(AuditEvent.username == username)
    if server:
        query = query.where(AuditEvent.server_slug == server)
    if event:
        query = query.where(AuditEvent.event == event)
    if ip:
        query = query.where(AuditEvent.ip == ip)
    if since:
        try:
            query = query.where(AuditEvent.ts >= datetime.fromisoformat(since).astimezone())
        except ValueError:
            pass
    page = max(page, 1)
    async with session_scope() as db:
        total = await db.scalar(select(func.count()).select_from(query.subquery())) or 0
        events = (
            await db.scalars(
                query.order_by(AuditEvent.ts.desc()).offset((page - 1) * AUDIT_PAGE_SIZE).limit(AUDIT_PAGE_SIZE)
            )
        ).all()
        event_names = (await db.scalars(select(AuditEvent.event).distinct().order_by(AuditEvent.event))).all()
    return render(
        request, "audit.html", user, events=events, event_names=event_names, total=total, page=page,
        pages=max(1, -(-total // AUDIT_PAGE_SIZE)),
        filters={"username": username, "server": server, "event": event, "ip": ip, "since": since},
        retention=timedelta(days=get_settings().audit_retention_days).days,
    )
