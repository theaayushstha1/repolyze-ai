"""Supabase client singleton with lazy initialisation."""

from functools import lru_cache

from supabase import Client, create_client

from app.config import get_settings


@lru_cache(maxsize=1)
def get_supabase_client() -> Client:
    """Return a cached Supabase client instance.

    The client is created on first call using SUPABASE_URL and
    SUPABASE_KEY from application settings.

    Raises:
        ValueError: When required Supabase credentials are missing.
    """
    settings = get_settings()

    if not settings.SUPABASE_URL or not settings.SUPABASE_KEY:
        raise ValueError(
            "SUPABASE_URL and SUPABASE_KEY must be set in environment"
        )

    return create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
