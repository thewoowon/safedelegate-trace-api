"""Runtime configuration, loaded from environment (see .env.example).

Settings are read once at import time via a cached accessor so the rest of the app
depends on a single, typed configuration object rather than scattered os.environ reads.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Repository root (…/safedelegate-trace-api) — used to resolve bundled fixtures/schemas.
BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Typed application settings.

    DEMO_MODE and LLM_PROVIDER=mock are the default, deterministic demo path: the
    orchestrator plans from fixtures and no external AI call is required.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    demo_mode: bool = Field(default=True, alias="DEMO_MODE")
    database_url: str = Field(default="sqlite:///./safedelegate.db", alias="DATABASE_URL")

    llm_provider: str = Field(default="mock", alias="LLM_PROVIDER")
    llm_api_key: str = Field(default="", alias="LLM_API_KEY")
    llm_model: str = Field(default="", alias="LLM_MODEL")

    trace_hash_secret: str = Field(default="replace-in-deployment", alias="TRACE_HASH_SECRET")
    allowed_origins: str = Field(default="http://localhost:3000", alias="ALLOWED_ORIGINS")

    @property
    def allowed_origins_list(self) -> list[str]:
        """Parse the comma-separated ALLOWED_ORIGINS into a CORS-ready list."""
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]

    @property
    def sqlalchemy_url(self) -> str:
        """Return a SQLAlchemy-ready URL.

        Managed hosts (e.g. Railway) hand out ``postgres://`` / ``postgresql://`` URLs;
        normalize them to the psycopg 3 driver so SQLAlchemy 2 uses a maintained driver.
        """
        url = self.database_url
        if url.startswith("postgres://"):
            url = "postgresql+psycopg://" + url[len("postgres://") :]
        elif url.startswith("postgresql://"):
            url = "postgresql+psycopg://" + url[len("postgresql://") :]
        return url

    @property
    def fixtures_dir(self) -> Path:
        return BASE_DIR / "fixtures"

    @property
    def schemas_dir(self) -> Path:
        return BASE_DIR / "schemas"


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings()
