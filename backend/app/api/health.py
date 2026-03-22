"""Health check endpoint for liveness and readiness probes."""

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/api/health")
async def health_check() -> dict[str, str]:
    """Return basic service health status."""
    return {"status": "healthy", "service": "repolyze-ai-backend"}
