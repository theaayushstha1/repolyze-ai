"""Supabase client singleton with lazy initialisation.

Uses service_role_key for backend operations (bypasses RLS).
Falls back to anon key if service role key is not set.
Returns None via try_get_client() when Supabase is not configured.
"""

import logging
from functools import lru_cache

from supabase import Client, create_client

from app.config import get_settings

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def get_supabase_client() -> Client:
    """Return a cached Supabase client using service role key.

    Raises ValueError when required credentials are missing.
    """
    settings = get_settings()

    if not settings.SUPABASE_URL or settings.SUPABASE_URL.startswith("https://placeholder"):
        raise ValueError("SUPABASE_URL not configured")

    key = settings.SUPABASE_SERVICE_ROLE_KEY or settings.SUPABASE_KEY
    if not key or key == "placeholder-key":
        raise ValueError("SUPABASE_KEY not configured")

    return create_client(settings.SUPABASE_URL, key)


def try_get_client() -> Client | None:
    """Return Supabase client or None if not configured."""
    try:
        return get_supabase_client()
    except (ValueError, Exception) as exc:
        logger.debug("Supabase not available: %s", exc)
        return None


def is_supabase_available() -> bool:
    """Check if Supabase is configured and reachable."""
    return try_get_client() is not None
