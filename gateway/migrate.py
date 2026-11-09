from pathlib import Path

from alembic import command
from alembic.config import Config

from gateway.config import get_settings


def alembic_config() -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    # Alembic runs synchronously; swap the async driver for the stdlib one.
    cfg.set_main_option("sqlalchemy.url", get_settings().db_url.replace("+aiosqlite", ""))
    return cfg


def upgrade_database() -> None:
    # SQLite creates the file but not its directory; the CLI can run before the server ever has.
    get_settings().data_dir.mkdir(parents=True, exist_ok=True)
    command.upgrade(alembic_config(), "head")
