"""Audit trail: every event goes to the audit_events table (shown in the UI) and to a JSONL
file rotated at midnight. A nightly job drops anything older than the retention window."""

import json
import logging
import logging.handlers
from datetime import datetime, timedelta
from typing import Any

import anyio
from sqlalchemy import delete, or_, select
from starlette.requests import HTTPConnection

from gateway.config import get_settings
from gateway.db import get_engine, session_scope
from gateway.models import (
    AccessTokenRow,
    AuditEvent,
    AuthCode,
    Grant,
    OAuthClient,
    PendingAuthorization,
    RefreshTokenRow,
    utcnow,
)

logger = logging.getLogger(__name__)
_file_logger = logging.getLogger("gateway.audit.file")


def setup_audit_file() -> None:
    settings = get_settings()
    settings.log_dir.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.TimedRotatingFileHandler(
        settings.log_dir / "audit.jsonl",
        when="midnight",
        backupCount=settings.audit_retention_days,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    _file_logger.handlers = [handler]
    _file_logger.setLevel(logging.INFO)
    _file_logger.propagate = False


def client_ip(conn: HTTPConnection | None) -> str | None:
    if conn is None:
        return None
    # Caddy is the only hop in front of us and sets X-Forwarded-For.
    forwarded = conn.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return conn.client.host if conn.client else None


async def record(
    event: str,
    *,
    conn: HTTPConnection | None = None,
    user_id: int | None = None,
    username: str | None = None,
    server_slug: str | None = None,
    client_id: str | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    **detail: Any,
) -> None:
    if conn is not None:
        ip = ip or client_ip(conn)
        user_agent = user_agent or conn.headers.get("user-agent")
    row = AuditEvent(
        ts=utcnow(),
        event=event,
        user_id=user_id,
        username=username,
        server_slug=server_slug,
        client_id=client_id,
        ip=ip,
        user_agent=user_agent[:255] if user_agent else None,
        detail=detail or None,
    )
    _file_logger.info(
        json.dumps(
            {
                "ts": row.ts.isoformat(),
                "event": event,
                "user_id": user_id,
                "username": username,
                "server": server_slug,
                "client_id": client_id,
                "ip": row.ip,
                "user_agent": row.user_agent,
                **detail,
            },
            default=str,
        )
    )
    try:
        with anyio.CancelScope(shield=True):
            async with session_scope() as db:
                db.add(row)
    except Exception:
        logger.exception("Failed to write audit event %s", event)


async def purge() -> dict[str, int]:
    """Drop audit rows past retention plus expired/dead OAuth state, rotate server stderr logs."""
    settings = get_settings()
    now = utcnow()
    cutoff = now - timedelta(days=settings.audit_retention_days)
    counts: dict[str, int] = {}
    async with session_scope() as db:
        statements = {
            "audit_events": delete(AuditEvent).where(AuditEvent.ts < cutoff),
            "access_tokens": delete(AccessTokenRow).where(AccessTokenRow.expires_at < now),
            "refresh_tokens": delete(RefreshTokenRow).where(
                or_(RefreshTokenRow.expires_at < now, RefreshTokenRow.used_at < now - timedelta(days=1))
            ),
            "auth_codes": delete(AuthCode).where(AuthCode.expires_at < now),
            "pending_authorizations": delete(PendingAuthorization).where(PendingAuthorization.expires_at < now),
            "revoked_grants": delete(Grant).where(Grant.revoked_at < cutoff),
            # Registrations that never produced a grant within a day (DCR is open to the internet).
            "unused_clients": delete(OAuthClient).where(
                OAuthClient.created_at < now - timedelta(days=1),
                ~OAuthClient.client_id.in_(select(Grant.client_id)),
            ),
        }
        for name, stmt in statements.items():
            result = await db.execute(stmt)
            counts[name] = result.rowcount or 0  # type: ignore[attr-defined]

    engine = get_engine()
    if engine.dialect.name == "sqlite":
        async with engine.connect() as conn:
            conn = await conn.execution_options(isolation_level="AUTOCOMMIT")
            await conn.exec_driver_sql("VACUUM")

    counts["server_logs_removed"] = _rotate_server_logs(now)
    await record("audit_purge", **counts)
    return counts


def _rotate_server_logs(now: datetime) -> int:
    """Rename each server's stderr log to <slug>.log.<date> and delete ones past retention."""
    settings = get_settings()
    log_dir = settings.log_dir / "servers"
    if not log_dir.is_dir():
        return 0
    stamp = (now - timedelta(days=1)).strftime("%Y-%m-%d")
    for current in log_dir.glob("*.log"):
        if current.stat().st_size:
            current.rename(current.with_name(f"{current.name}.{stamp}"))
    removed = 0
    oldest = (now - timedelta(days=settings.audit_retention_days)).strftime("%Y-%m-%d")
    for rotated in log_dir.glob("*.log.*"):
        if rotated.name.rsplit(".", 1)[-1] < oldest:
            rotated.unlink(missing_ok=True)
            removed += 1
    return removed


async def nightly_purge_loop() -> None:
    settings = get_settings()
    while True:
        now = datetime.now().astimezone()
        next_run = now.replace(hour=settings.purge_hour, minute=0, second=0, microsecond=0)
        if next_run <= now:
            next_run += timedelta(days=1)
        await anyio.sleep((next_run - now).total_seconds())
        try:
            counts = await purge()
            logger.info("Nightly purge: %s", counts)
        except Exception:
            logger.exception("Nightly purge failed")
