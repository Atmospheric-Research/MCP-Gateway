"""Browser login for the admin UI and the OAuth consent page."""

import secrets
import time
from collections import defaultdict, deque
from urllib.parse import quote

from fastapi import Request
from sqlalchemy import select

from gateway.db import session_scope
from gateway.models import User

LOGIN_WINDOW = 15 * 60
LOGIN_MAX_FAILURES = 5


class LoginRequired(Exception):
    def __init__(self, next_url: str):
        self.next_url = next_url


class Forbidden(Exception):
    pass


class CSRFError(Exception):
    pass


async def current_user(request: Request) -> User | None:
    uid = request.session.get("uid")
    if uid is None:
        return None
    async with session_scope() as db:
        user = await db.get(User, uid)
    if user is None or not user.is_active or request.session.get("epoch") != user.session_epoch:
        request.session.clear()
        return None
    return user


async def require_user(request: Request) -> User:
    user = await current_user(request)
    if user is None:
        raise LoginRequired(str(request.url.path) + (f"?{request.url.query}" if request.url.query else ""))
    return user


async def require_admin(request: Request) -> User:
    user = await require_user(request)
    if not user.is_admin:
        raise Forbidden()
    return user


def login_url(next_url: str) -> str:
    return f"/login?next={quote(next_url, safe='')}"


def safe_next(next_url: str | None) -> str:
    # Only same-site relative paths, never //host or scheme URLs.
    if next_url and next_url.startswith("/") and not next_url.startswith("//") and "\\" not in next_url:
        return next_url
    return "/"


def log_in(request: Request, user: User) -> None:
    request.session.clear()
    request.session["uid"] = user.id
    request.session["epoch"] = user.session_epoch
    request.session["csrf"] = secrets.token_urlsafe(32)
    request.session["at"] = int(time.time())


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if token is None:
        token = request.session["csrf"] = secrets.token_urlsafe(32)
    return token


async def verify_csrf(request: Request) -> None:
    form = await request.form()
    sent = form.get("csrf") or request.headers.get("x-csrf-token")
    expected = request.session.get("csrf")
    if not expected or not isinstance(sent, str) or not secrets.compare_digest(sent, expected):
        raise CSRFError()


async def find_user(username: str) -> User | None:
    async with session_scope() as db:
        return await db.scalar(select(User).where(User.username == username))


class LoginThrottle:
    """Per-IP and per-username failure counting; in memory, which suits a single worker."""

    def __init__(self) -> None:
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    def _recent(self, key: str) -> deque[float]:
        q = self._failures[key]
        cutoff = time.monotonic() - LOGIN_WINDOW
        while q and q[0] < cutoff:
            q.popleft()
        return q

    def blocked(self, *keys: str) -> bool:
        return any(len(self._recent(k)) >= LOGIN_MAX_FAILURES for k in keys)

    def fail(self, *keys: str) -> None:
        now = time.monotonic()
        for k in keys:
            self._recent(k).append(now)

    def reset(self, *keys: str) -> None:
        for k in keys:
            self._failures.pop(k, None)


login_throttle = LoginThrottle()
