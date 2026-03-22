"""FastAPI application entry point for RepolyzeAI."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Handle application startup and shutdown lifecycle events."""
    logger.info("RepolyzeAI backend starting up")
    yield
    logger.info("RepolyzeAI backend shutting down")


def create_app() -> FastAPI:
    """Build and configure the FastAPI application instance."""
    application = FastAPI(
        title="RepolyzeAI",
        description="AI-powered repository security analysis",
        version="0.1.0",
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.include_router(api_router)

    return application


app = create_app()
