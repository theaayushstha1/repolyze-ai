"""Celery tasks for repository scan processing."""

import logging
from uuid import UUID

from workers.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(
    name="workers.scan_tasks.run_scan",
    bind=True,
    max_retries=2,
    default_retry_delay=30,
)
def run_scan(self, scan_id: str) -> dict[str, str]:  # type: ignore[override]
    """Execute the full scan pipeline as a background Celery task.

    Args:
        scan_id: UUID string of the scan to process.

    Returns:
        A dict with the scan_id and final status.
    """
    logger.info("Starting scan task for %s", scan_id)

    try:
        from app.services.scan_service import run_scan_pipeline

        run_scan_pipeline(UUID(scan_id))
        return {"scan_id": scan_id, "status": "completed"}

    except Exception as exc:
        logger.exception("Scan task %s failed", scan_id)
        raise self.retry(exc=exc)
