"""Supabase JWT validation as a FastAPI dependency.

Placeholder implementation. In production this will:
1. Extract the Bearer token from the Authorization header.
2. Decode and verify the JWT using the Supabase JWT secret.
3. Return the authenticated user payload.
"""

import logging
from typing import Any

from fastapi import Depends, HTTPException, Request

logger = logging.getLogger(__name__)


async def _extract_token(request: Request) -> str:
    """Pull the Bearer token from the Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid Authorization header",
        )
    return auth_header.removeprefix("Bearer ").strip()


async def get_current_user(
    token: str = Depends(_extract_token),
) -> dict[str, Any]:
    """Validate the Supabase JWT and return user claims.

    This is a **placeholder** that always returns a stub user.
    Replace with real JWT verification before deploying to production.
    """
    # TODO: Verify token signature with python-jose and Supabase secret.
    logger.warning("Auth placeholder active; returning stub user")
    return {
        "sub": "placeholder-user-id",
        "email": "placeholder@example.com",
        "role": "authenticated",
    }
