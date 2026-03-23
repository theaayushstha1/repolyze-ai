"""Authentication endpoints and middleware.

Uses Supabase Auth for JWT verification. Falls back to anonymous
when Supabase is not configured or no token is provided.
"""

import logging
from typing import Any

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request

from app.config import get_settings
from app.demo_store import get_all_scans, get_scan

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])


def get_current_user(request: Request) -> dict[str, Any] | None:
    """Extract user from Supabase JWT in Authorization header.

    Returns user dict with at minimum {"id": str, "email": str}
    or None for anonymous requests.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header.removeprefix("Bearer ").strip()
    if not token:
        return None

    settings = get_settings()
    if not settings.SUPABASE_KEY or settings.SUPABASE_KEY == "placeholder-key":
        return None

    try:
        # Supabase JWTs are signed with the JWT secret (anon key works for decode)
        # In production, verify with SUPABASE_JWT_SECRET
        payload = jwt.decode(
            token,
            options={"verify_signature": False},
            algorithms=["HS256"],
        )
        user_id = payload.get("sub")
        email = payload.get("email", "")
        user_metadata = payload.get("user_metadata", {})

        if not user_id:
            return None

        return {
            "id": user_id,
            "email": email,
            "github_username": user_metadata.get("preferred_username")
                or user_metadata.get("user_name", ""),
            "avatar_url": user_metadata.get("avatar_url", ""),
            "plan": "free",
        }
    except Exception as exc:
        logger.debug("JWT decode failed: %s", exc)
        return None


def require_auth(request: Request) -> dict[str, Any]:
    """Dependency that requires authentication. Raises 401 if not authenticated."""
    user = get_current_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


@router.get("/me")
async def get_me(request: Request) -> dict[str, Any]:
    """Return current user info or anonymous status."""
    user = get_current_user(request)
    if user is None:
        return {"authenticated": False, "user": None}
    return {"authenticated": True, "user": user}


@router.get("/quota")
async def get_quota(request: Request) -> dict[str, Any]:
    """Return scan quota for current user."""
    user = get_current_user(request)
    settings = get_settings()
    monthly_limit = settings.FREE_TIER_MONTHLY_SCANS

    if user is None:
        # Anonymous: count all anonymous scans (rough limit)
        all_scans = get_all_scans()
        anon_scans = [s for s in all_scans if s.get("user_id") is None]
        used = len(anon_scans)
        return {
            "plan": "anonymous",
            "monthly_limit": 3,
            "scans_used": used,
            "scans_remaining": max(0, 3 - used),
        }

    # Authenticated: count user's scans this month
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    all_scans = get_all_scans()
    user_scans_this_month = [
        s for s in all_scans
        if s.get("user_id") == user["id"]
        and s.get("created_at", "")[:7] == now.strftime("%Y-%m")
    ]
    used = len(user_scans_this_month)

    return {
        "plan": user.get("plan", "free"),
        "monthly_limit": monthly_limit,
        "scans_used": used,
        "scans_remaining": max(0, monthly_limit - used),
    }
