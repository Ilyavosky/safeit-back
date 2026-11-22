from celery import Celery
from celery.schedules import crontab

from app.config import Settings

RECON_TASK_NAME = "safeit.recon.run"
CVE_SYNC_TASK_NAME = "safeit.cve.sync"
PUBLIC_ANALYSIS_TASK_NAME = "safeit.public.run"
PUBLIC_PURGE_TASK_NAME = "safeit.public.purge"
BEAT_SCHEDULE_FILE = "/tmp/celerybeat-schedule"  # noqa: S108  # nosec B108


def create_celery(settings: Settings) -> Celery:
    app = Celery("safeit", broker=settings.redis_url, backend=None)
    app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        task_ignore_result=True,
        worker_prefetch_multiplier=1,
        task_soft_time_limit=settings.recon_timeout_seconds + 60,
        task_time_limit=settings.recon_timeout_seconds + 120,
        broker_connection_retry_on_startup=True,
        broker_transport_options={"socket_connect_timeout": 3, "socket_timeout": 5},
        task_publish_retry=True,
        task_publish_retry_policy={
            "max_retries": 1,
            "interval_start": 0,
            "interval_step": 0.2,
            "interval_max": 0.5,
        },
        timezone="UTC",
        beat_schedule_filename=BEAT_SCHEDULE_FILE,
        beat_schedule=_beat_schedule(settings),
    )
    return app


def _beat_schedule(settings: Settings) -> dict[str, dict[str, object]]:
    schedule: dict[str, dict[str, object]] = {
        "public-analysis-purge-daily": {
            "task": PUBLIC_PURGE_TASK_NAME,
            "schedule": crontab(minute=45, hour=3),
        }
    }
    if settings.cve_sync_enabled:
        schedule["cve-sync-daily"] = {
            "task": CVE_SYNC_TASK_NAME,
            "schedule": crontab(minute=15, hour=settings.cve_sync_hour_utc),
        }
    return schedule
