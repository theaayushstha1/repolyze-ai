"""Application configuration loaded from environment variables."""

from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Immutable application settings sourced from env vars / .env file."""

    model_config = {"env_file": ".env", "frozen": True, "extra": "ignore"}

    # Supabase
    SUPABASE_URL: str = ""
    SUPABASE_KEY: str = ""
    SUPABASE_SERVICE_ROLE_KEY: str = ""

    # Redis / Celery
    REDIS_URL: str = "redis://localhost:6379"

    # GitHub OAuth
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""

    # Google Gemini
    GEMINI_API_KEY: str = ""

    # GCP
    GCP_PROJECT_ID: str = "repolyze-ai"

    # Scan limits
    SCAN_TIMEOUT_SECONDS: int = 900
    MAX_REPO_SIZE_MB: int = 500

    # Free tier
    FREE_TIER_MONTHLY_SCANS: int = 10


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached, frozen Settings instance."""
    return Settings()
