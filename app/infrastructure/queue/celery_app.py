from celery import Celery

from app.config import Settings

RECON_TASK_NAME = "safeit.recon.run"


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
    )
    return app
