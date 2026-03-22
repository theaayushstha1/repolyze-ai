"""Celery application configuration for background task processing."""

from celery import Celery

from app.config import get_settings

settings = get_settings()

celery_app = Celery(
    "repolyze_workers",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=settings.SCAN_TIMEOUT_SECONDS,
    task_soft_time_limit=settings.SCAN_TIMEOUT_SECONDS - 60,
    worker_prefetch_multiplier=1,
    worker_concurrency=2,
)

celery_app.autodiscover_tasks(["workers"])
