from typing import Any
from uuid import uuid4

import pytest
from kombu.exceptions import OperationalError

from app.config import Settings
from app.domain.errors_queue import QueueUnavailableError
from app.infrastructure.queue.celery_app import RECON_TASK_NAME, create_celery
from app.infrastructure.queue.celery_queue import CeleryReconQueue


class FakeCelery:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.sent: list[tuple[str, list[Any]]] = []

    def send_task(self, name: str, args: list[Any]) -> None:
        if self.error is not None:
            raise self.error
        self.sent.append((name, args))


async def test_enqueue_sends_the_named_task_with_string_arguments() -> None:
    app = FakeCelery()
    scan_id = uuid4()
    await CeleryReconQueue(app).enqueue(scan_id, "api.example.com")
    assert app.sent == [(RECON_TASK_NAME, [str(scan_id), "api.example.com"])]


@pytest.mark.parametrize("error", [OperationalError("sin redis"), ConnectionRefusedError()])
async def test_broker_failures_become_queue_unavailable(error: Exception) -> None:
    queue = CeleryReconQueue(FakeCelery(error))
    with pytest.raises(QueueUnavailableError):
        await queue.enqueue(uuid4(), None)


def test_celery_is_configured_for_json_and_bounded_time(settings: Settings) -> None:
    conf = create_celery(settings).conf
    assert conf.task_serializer == "json"
    assert list(conf.accept_content) == ["json"]
    assert conf.worker_prefetch_multiplier == 1
    assert conf.task_time_limit == settings.recon_timeout_seconds + 120
    assert conf.task_soft_time_limit < conf.task_time_limit
    assert conf.broker_url == settings.redis_url


async def test_worker_task_runs_the_recon_use_case() -> None:
    from app.infrastructure.queue import tasks

    calls: list[tuple[Any, Any]] = []

    class Runner:
        async def execute(self, scan_id: Any, only_host: Any) -> None:
            calls.append((scan_id, only_host))

    class Container:
        run_recon_scan = Runner()

    scan_id = uuid4()
    await tasks.run_recon_job(Container(), scan_id, "x.example.com")  # type: ignore[arg-type]
    assert calls == [(scan_id, "x.example.com")]
    assert tasks.celery_app.tasks[RECON_TASK_NAME].name == RECON_TASK_NAME
