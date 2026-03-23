"""Central router that aggregates all API sub-routers."""

from fastapi import APIRouter

from app.api.health import router as health_router
from app.api.auth import router as auth_router
from app.api.demo_router import router as scan_router
from app.api.a2a import router as a2a_router

api_router = APIRouter()

api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(scan_router)
api_router.include_router(a2a_router)


@api_router.get("/api/dashboard/scans")
async def dashboard_scans():
    from app.demo_store import get_all_scans
    return get_all_scans()
