"""Health check endpoint for liveness and readiness probes."""

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/api/health")
async def health_check() -> dict[str, str]:
    """Return service health status with storage and task tier info."""
    from app.demo_store import get_storage_tier
    from app.api.demo_router import get_task_mode

    return {
        "status": "healthy",
        "service": "repolyze-ai-backend",
        "storage": get_storage_tier(),
        "tasks": get_task_mode(),
    }
