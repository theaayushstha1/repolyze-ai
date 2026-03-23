"""Health check endpoint for liveness and readiness probes."""

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/api/health")
async def health_check() -> dict[str, str]:
    """Return service health status with storage tier info."""
    from app.demo_store import get_storage_tier

    return {
        "status": "healthy",
        "service": "repolyze-ai-backend",
        "storage": get_storage_tier(),
    }
