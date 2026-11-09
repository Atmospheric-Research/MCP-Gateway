from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GATEWAY_", env_file=".env", extra="ignore")

    # Public origin MCP clients reach the gateway at, e.g. https://mcp.example.com (no trailing slash).
    public_url: str
    # Fernet key (urlsafe base64, 32 bytes). Encrypts server env vars and signs session cookies.
    secret_key: str

    data_dir: Path = Path("/data")
    database_url: str | None = None  # defaults to sqlite in data_dir

    uv_dir: Path | None = None  # venvs, cache and Python installs for servers; defaults to data_dir/uv
    uv_command: str = "uv"
    uv_run_args: list[str] = Field(default_factory=lambda: ["run", "--frozen"])

    access_token_ttl: int = 3600
    refresh_token_ttl: int = 30 * 24 * 3600
    auth_code_ttl: int = 300
    pending_authorization_ttl: int = 600
    # A rotated refresh token presented again within this window is refused without revoking
    # the grant (tolerates clients that race two refreshes); later reuse revokes the grant.
    refresh_reuse_grace: int = 10

    ui_session_ttl: int = 12 * 3600
    cookie_secure: bool = True

    session_idle_timeout: float = 900
    max_sessions_per_user: int = 10
    max_sessions_per_server: int = 25
    server_test_timeout: float = 120

    audit_retention_days: int = 30
    purge_hour: int = 3  # local time of the nightly purge/rotation

    # Exact redirect URIs accepted at dynamic client registration, besides loopback URIs.
    allowed_redirect_uris: list[str] = Field(
        default_factory=lambda: [
            "https://claude.ai/api/mcp/auth_callback",
            "https://claude.com/api/mcp/auth_callback",
        ]
    )
    allow_loopback_redirects: bool = True

    @property
    def issuer(self) -> str:
        return self.public_url.rstrip("/")

    @property
    def db_url(self) -> str:
        return self.database_url or f"sqlite+aiosqlite:///{self.data_dir / 'gateway.db'}"

    @property
    def server_uv_dir(self) -> Path:
        return self.uv_dir or self.data_dir / "uv"

    @property
    def uploads_dir(self) -> Path:
        """Servers uploaded as zips from the UI, one directory each."""
        return self.data_dir / "servers"

    @property
    def log_dir(self) -> Path:
        return self.data_dir / "logs"

    def resource_url(self, slug: str) -> str:
        return f"{self.issuer}/s/{slug}/mcp"

    def resource_metadata_url(self, slug: str) -> str:
        return f"{self.issuer}/.well-known/oauth-protected-resource/s/{slug}/mcp"


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
