from datetime import timedelta
from uuid import uuid4

from app.application.ports.clock import Clock
from app.application.ports.public_analysis import PublicAnalysisQueue, PublicAnalysisRepository
from app.application.use_cases.audit.record_action import RecordAction
from app.application.use_cases.auth.session import AuthRateLimiter
from app.domain.entities.public_analysis import PublicAnalysis
from app.domain.entities.user import User
from app.domain.errors import ConflictError, NoticeNotAcceptedError, RateLimitExceededError
from app.domain.errors_queue import QueueUnavailableError
from app.domain.services.public_scope import normalize_public_target
from app.domain.value_objects.job_status import JobStatus

NOTICE_VERSION = "2026-11"
FAILED_QUEUE_MESSAGE = "No se pudo encolar el análisis."


class StartPublicAnalysis:
    def __init__(
        self,
        analyses: PublicAnalysisRepository,
        queue: PublicAnalysisQueue,
        audit: RecordAction,
        clock: Clock,
        limiter: AuthRateLimiter,
        *,
        protected_domains: frozenset[str],
        daily_limit: int,
        retention_days: int,
        stale_after_seconds: int,
    ) -> None:
        self._analyses = analyses
        self._queue = queue
        self._audit = audit
        self._clock = clock
        self._limiter = limiter
        self._protected = protected_domains
        self._daily_limit = daily_limit
        self._retention = timedelta(days=retention_days)
        self._stale_after = timedelta(seconds=stale_after_seconds)

    async def execute(self, user: User, raw_domain: str, accepted_notice: bool) -> PublicAnalysis:
        if not accepted_notice:
            raise NoticeNotAcceptedError
        domain = normalize_public_target(raw_domain, self._protected)
        await self._limiter.check(f"public:user:{user.id}")
        now = self._clock.now()
        await self._analyses.fail_stale(user.id, now - self._stale_after)
        if await self._analyses.count_since(user.id, now - timedelta(days=1)) >= self._daily_limit:
            raise RateLimitExceededError("Alcanzaste el límite diario de análisis públicos.")
        analysis = PublicAnalysis(
            id=uuid4(),
            user_id=user.id,
            domain=domain,
            status=JobStatus.QUEUED,
            created_at=now,
            expires_at=now + self._retention,
        )
        if not await self._analyses.add_if_idle(analysis):
            raise ConflictError("Ya tienes un análisis público en curso. Espera a que termine.")
        await self._audit.execute(
            "public_analysis.started",
            user_id=user.id,
            entity="public_analysis",
            entity_id=analysis.id,
            detail={"domain": domain, "notice_accepted": True, "notice_version": NOTICE_VERSION},
        )
        try:
            await self._queue.enqueue(analysis.id)
        except QueueUnavailableError:
            failed = analysis.finish(
                JobStatus.FAILED, self._clock.now(), error=FAILED_QUEUE_MESSAGE
            )
            await self._analyses.save(failed)
            raise
        return analysis
