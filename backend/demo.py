"""Demo server - runs without Supabase/Redis.
Usage: python demo.py
"""

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.demo_router import router as demo_router
from app.api.health import router as health_router

app = FastAPI(
    title="RepolyzeAI API (Demo Mode)",
    description="Security audit API - running in demo mode with simulated scans",
    version="0.1.0-demo",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(demo_router)

if __name__ == "__main__":
    print("\n  RepolyzeAI API (Demo Mode)")
    print("  http://localhost:8000")
    print("  http://localhost:8000/docs  (Swagger UI)\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)
