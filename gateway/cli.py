import argparse
import asyncio
import getpass
import sys

from cryptography.fernet import Fernet


def _create_admin(username: str | None) -> int:
    from sqlalchemy import select

    from gateway.crypto import hash_password
    from gateway.db import dispose_engine, session_scope
    from gateway.migrate import upgrade_database
    from gateway.models import User

    username = username or input("Username: ").strip()
    password = getpass.getpass("Password (min 12 chars): ")
    if len(password) < 12 or password != getpass.getpass("Repeat password: "):
        print("Passwords must match and be at least 12 characters.", file=sys.stderr)
        return 1

    async def run() -> int:
        async with session_scope() as db:
            existing = await db.scalar(select(User).where(User.username == username))
            if existing:
                existing.password_hash = hash_password(password)
                existing.is_admin = existing.is_active = True
                existing.session_epoch += 1
                print(f"Updated existing user {username} (now an active admin).")
            else:
                db.add(User(username=username, password_hash=hash_password(password), is_admin=True))
                print(f"Created admin {username}.")
        await dispose_engine()
        return 0

    upgrade_database()
    return asyncio.run(run())


def _purge() -> int:
    from gateway import audit
    from gateway.db import dispose_engine

    async def run() -> None:
        audit.setup_audit_file()
        print(await audit.purge())
        await dispose_engine()

    asyncio.run(run())
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="mcp-gateway")
    sub = parser.add_subparsers(dest="command", required=True)
    admin = sub.add_parser("create-admin", help="create an admin user, or reset an existing user to admin")
    admin.add_argument("username", nargs="?")
    sub.add_parser("generate-key", help="print a new GATEWAY_SECRET_KEY")
    sub.add_parser("purge", help="run the nightly audit/token purge now")
    args = parser.parse_args()

    if args.command == "generate-key":
        print(Fernet.generate_key().decode())
        return 0
    if args.command == "create-admin":
        return _create_admin(args.username)
    if args.command == "purge":
        return _purge()
    return 2
