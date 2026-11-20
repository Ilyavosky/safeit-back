from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from redis.asyncio import Redis

from app.application.llm_budget import TokenBudget
from app.application.ports.clock import Clock
from app.application.ports.cve_catalog import CveRepository, EpssFeed, KevFeed, NvdFeed
from app.application.ports.database import DatabasePort
from app.application.ports.domain_verifier import DomainVerifier
from app.application.ports.findings_query import FindingQueryRepository
from app.application.ports.llm import (
    FindingReviewRepository,
    LlmDecisionRepository,
    LlmGateway,
    PlanSource,
)
from app.application.ports.password_hasher import PasswordHasher
from app.application.ports.public_analysis import (
    CertTransparencySource,
    PublicAnalysisQueue,
    PublicAnalysisRepository,
    PublicDns,
    PublicWebFetcher,
)
from app.application.ports.rate_limiter import RateLimiter
from app.application.ports.recon import (
    HostResolver,
    HttpProber,
    PortScanner,
    ReconQueue,
    SubdomainEnumerator,
)
from app.application.ports.recon_repositories import AssetRepository, ReconScanRepository
from app.application.ports.reports import ReportRenderer, ReportRepository
from app.application.ports.repositories import (
    AuditRepository,
    DomainRepository,
    RefreshTokenRepository,
    UserRepository,
)
from app.application.ports.testing import ProbePlanner, ScanScheduler, ToolRegistry
from app.application.ports.testing_repositories import (
    EndpointRepository,
    FindingRepository,
    ScanRepository,
    TestRunRepository,
    ToolRepository,
)
from app.application.ports.token_service import TokenService
from app.application.use_cases.audit.list_audit import ListAudit
from app.application.use_cases.audit.record_action import RecordAction
from app.application.use_cases.audit.verify_chain import VerifyAuditChain
from app.application.use_cases.auth.authenticate import AuthenticateAccessToken
from app.application.use_cases.auth.login import Login
from app.application.use_cases.auth.logout import Logout
from app.application.use_cases.auth.mfa import EnableMfa, SetupMfa, VerifyMfa
from app.application.use_cases.auth.register_user import RegisterUser
from app.application.use_cases.auth.rotate_refresh_token import RotateRefreshToken
from app.application.use_cases.auth.session import AuthRateLimiter, SessionIssuer
from app.application.use_cases.auth.update_profile import UpdateProfile
from app.application.use_cases.cve.lookup_cve import LookupCve
from app.application.use_cases.cve.sync_catalog import SyncCveCatalog
from app.application.use_cases.domains.add_domain import AddDomain
from app.application.use_cases.domains.get_domain import GetDomain
from app.application.use_cases.domains.list_domains import ListDomains
from app.application.use_cases.domains.verify_domain import VerifyDomain
from app.application.use_cases.findings.queries import GetFinding, ListFindings
from app.application.use_cases.findings.update_status import UpdateFindingStatus
from app.application.use_cases.llm.analyze_findings import AnalyzeFindings
from app.application.use_cases.llm.finalize_scan import FinalizeScan
from app.application.use_cases.llm.generate_report import GenerateReport
from app.application.use_cases.llm.plan_source import FixedPlanSource, LlmPlanSource
from app.application.use_cases.llm.recorder import DecisionRecorder
from app.application.use_cases.public.queries import (
    GetPublicAnalysis,
    ListPublicAnalyses,
    PurgeExpiredPublicAnalyses,
)
from app.application.use_cases.public.run_analysis import RunPublicAnalysis
from app.application.use_cases.public.start_analysis import StartPublicAnalysis
from app.application.use_cases.recon.assets import GetAsset, ListAssets, SetEndpointWhitelist
from app.application.use_cases.recon.run_recon import ReconLimits, RunReconScan
from app.application.use_cases.recon.start_recon import RescanAsset, StartReconScan
from app.application.use_cases.reports.dashboard import GetDashboardSummary
from app.application.use_cases.reports.get_report import GetReport, RenderReportPdf
from app.application.use_cases.reports.update_recommendation import UpdateRecommendationStatus
from app.application.use_cases.testing.read_scans import GetScan, ListScanFindings, ListTestRuns
from app.application.use_cases.testing.run_scan_tests import RunScanTests
from app.application.use_cases.testing.start_tests import StartTests
from app.config import Settings
from app.infrastructure.clock import SystemClock
from app.infrastructure.db.asset_repository import PostgresAssetRepository
from app.infrastructure.db.audit_repository import PostgresAuditRepository
from app.infrastructure.db.cve_repository import PostgresCveRepository
from app.infrastructure.db.domain_repository import PostgresDomainRepository
from app.infrastructure.db.endpoint_repository import PostgresEndpointRepository
from app.infrastructure.db.finding_query_repository import PostgresFindingQueryRepository
from app.infrastructure.db.finding_repository import PostgresFindingRepository
from app.infrastructure.db.finding_review_repository import PostgresFindingReviewRepository
from app.infrastructure.db.llm_decision_repository import PostgresLlmDecisionRepository
from app.infrastructure.db.public_analysis_repository import PostgresPublicAnalysisRepository
from app.infrastructure.db.recon_scan_repository import PostgresReconScanRepository
from app.infrastructure.db.refresh_token_repository import PostgresRefreshTokenRepository
from app.infrastructure.db.report_repository import PostgresReportRepository
from app.infrastructure.db.scan_repository import PostgresScanRepository
from app.infrastructure.db.session import PostgresDatabase
from app.infrastructure.db.test_run_repository import PostgresTestRunRepository
from app.infrastructure.db.tool_repository import PostgresToolRepository
from app.infrastructure.db.user_repository import PostgresUserRepository
from app.infrastructure.feeds.epss_client import EpssClient
from app.infrastructure.feeds.http import RetryingJsonClient
from app.infrastructure.feeds.kev_client import KevClient
from app.infrastructure.feeds.nvd_client import NvdClient
from app.infrastructure.llm.http_gateway import HttpLlmGateway
from app.infrastructure.net.safe_http import SafeHttpClient
from app.infrastructure.public.crtsh import CrtShSource
from app.infrastructure.public.dns_inspector import DnsPublicInspector
from app.infrastructure.public.web_fetcher import PublicHttpFetcher
from app.infrastructure.queue.celery_app import create_celery
from app.infrastructure.queue.celery_queue import CeleryPublicAnalysisQueue, CeleryReconQueue
from app.infrastructure.rate_limit import InMemoryRateLimiter
from app.infrastructure.rate_limit_redis import RedisRateLimiter
from app.infrastructure.recon.dns_resolver import SystemHostResolver
from app.infrastructure.recon.httpx_runner import HttpxRunner
from app.infrastructure.recon.nmap_runner import NmapRunner
from app.infrastructure.recon.subfinder_runner import SubfinderRunner
from app.infrastructure.reports.pdf_renderer import ReportlabPdfRenderer
from app.infrastructure.security.aes_gcm_cipher import AesGcmCipher
from app.infrastructure.security.jwt_service import JwtTokenService
from app.infrastructure.security.password_hasher import Argon2PasswordHasher
from app.infrastructure.security.totp import PyOtpTotpService
from app.infrastructure.testing.asyncio_scheduler import AsyncioScanScheduler
from app.infrastructure.testing.fixed_planner import FixedProbePlanner
from app.infrastructure.testing.headers_runner import HeadersRunner
from app.infrastructure.testing.nuclei_runner import NucleiRunner
from app.infrastructure.testing.process import SubprocessRunner
from app.infrastructure.testing.testssl_runner import TestsslRunner
from app.infrastructure.testing.tool_registry import StaticToolRegistry
from app.infrastructure.verification.composite import CompositeDomainVerifier
from app.infrastructure.verification.dns_txt import DnsTxtVerifier
from app.infrastructure.verification.well_known_file import WellKnownFileVerifier


@dataclass(frozen=True)
class Container:
    settings: Settings
    database: DatabasePort
    users: UserRepository
    tokens: TokenService
    authenticate: AuthenticateAccessToken
    register_user: RegisterUser
    login: Login
    verify_mfa: VerifyMfa
    setup_mfa: SetupMfa
    enable_mfa: EnableMfa
    rotate_refresh_token: RotateRefreshToken
    logout: Logout
    update_profile: UpdateProfile
    record_action: RecordAction
    list_audit: ListAudit
    verify_audit_chain: VerifyAuditChain
    add_domain: AddDomain
    get_domain: GetDomain
    list_domains: ListDomains
    verify_domain: VerifyDomain
    sync_cve_catalog: SyncCveCatalog
    lookup_cve: LookupCve
    run_scan_tests: RunScanTests
    start_tests: StartTests
    finalize_scan: FinalizeScan
    generate_report: GenerateReport
    list_findings: ListFindings
    get_finding: GetFinding
    update_finding_status: UpdateFindingStatus
    get_report: GetReport
    render_report_pdf: RenderReportPdf
    update_recommendation: UpdateRecommendationStatus
    dashboard: GetDashboardSummary
    get_scan: GetScan
    list_test_runs: ListTestRuns
    list_scan_findings: ListScanFindings
    scheduler: ScanScheduler
    run_recon_scan: RunReconScan
    start_recon_scan: StartReconScan
    start_public_analysis: StartPublicAnalysis
    run_public_analysis: RunPublicAnalysis
    get_public_analysis: GetPublicAnalysis
    list_public_analyses: ListPublicAnalyses
    purge_public_analyses: PurgeExpiredPublicAnalyses
    rescan_asset: RescanAsset
    list_assets: ListAssets
    get_asset: GetAsset
    set_endpoint_whitelist: SetEndpointWhitelist


def build_container(
    settings: Settings,
    *,
    database: DatabasePort | None = None,
    users: UserRepository | None = None,
    refresh_tokens: RefreshTokenRepository | None = None,
    domains: DomainRepository | None = None,
    audit: AuditRepository | None = None,
    domain_verifier: DomainVerifier | None = None,
    hasher: PasswordHasher | None = None,
    rate_limiter: RateLimiter | None = None,
    clock: Clock | None = None,
    cve_repository: CveRepository | None = None,
    nvd: NvdFeed | None = None,
    epss: EpssFeed | None = None,
    kev: KevFeed | None = None,
    scans: ScanRepository | None = None,
    endpoints: EndpointRepository | None = None,
    tools: ToolRepository | None = None,
    test_runs: TestRunRepository | None = None,
    findings: FindingRepository | None = None,
    tool_registry: ToolRegistry | None = None,
    planner: ProbePlanner | None = None,
    llm: LlmGateway | None = None,
    llm_decisions: LlmDecisionRepository | None = None,
    finding_review: FindingReviewRepository | None = None,
    reports: ReportRepository | None = None,
    finding_query: FindingQueryRepository | None = None,
    report_renderer: ReportRenderer | None = None,
    scheduler: ScanScheduler | None = None,
    assets: AssetRepository | None = None,
    recon_scans: ReconScanRepository | None = None,
    recon_queue: ReconQueue | None = None,
    enumerator: SubdomainEnumerator | None = None,
    resolver: HostResolver | None = None,
    port_scanner: PortScanner | None = None,
    prober: HttpProber | None = None,
    public_analyses: PublicAnalysisRepository | None = None,
    public_queue: PublicAnalysisQueue | None = None,
    public_dns: PublicDns | None = None,
    ct_source: CertTransparencySource | None = None,
    web_fetcher: PublicWebFetcher | None = None,
) -> Container:
    clock = clock or SystemClock()
    database = database or PostgresDatabase(
        dsn=settings.database_url.get_secret_value(),
        min_size=settings.db_pool_min_size,
        max_size=settings.db_pool_max_size,
    )
    users = users or PostgresUserRepository(_pool_of(database))
    refresh_tokens = refresh_tokens or PostgresRefreshTokenRepository(_pool_of(database))
    domains = domains or PostgresDomainRepository(_pool_of(database))
    audit = audit or PostgresAuditRepository(_pool_of(database))
    domain_verifier = domain_verifier or CompositeDomainVerifier(
        DnsTxtVerifier(), WellKnownFileVerifier()
    )
    cve_repository = cve_repository or PostgresCveRepository(_pool_of(database))
    scans = scans or PostgresScanRepository(_pool_of(database))
    endpoints = endpoints or PostgresEndpointRepository(_pool_of(database))
    tools = tools or PostgresToolRepository(_pool_of(database))
    test_runs = test_runs or PostgresTestRunRepository(_pool_of(database))
    findings = findings or PostgresFindingRepository(_pool_of(database))
    assets = assets or PostgresAssetRepository(_pool_of(database))
    recon_scans = recon_scans or PostgresReconScanRepository(_pool_of(database))
    public_analyses = public_analyses or PostgresPublicAnalysisRepository(_pool_of(database))
    record_action = RecordAction(audit)
    shared_limiter = rate_limiter or _default_rate_limiter(settings, clock)

    hasher = hasher or Argon2PasswordHasher()
    cipher = AesGcmCipher(settings.encryption_key.get_secret_value())
    totp = PyOtpTotpService()
    tokens = JwtTokenService(
        secret=settings.jwt_secret.get_secret_value(),
        algorithm=settings.jwt_algorithm,
        access_ttl=timedelta(minutes=settings.access_token_ttl_minutes),
        clock=clock,
    )
    feeds_http = RetryingJsonClient()
    api_key = settings.nvd_api_key.get_secret_value() if settings.nvd_api_key else None
    nvd = nvd or NvdClient(feeds_http, api_key=api_key)
    epss = epss or EpssClient(feeds_http)
    kev = kev or KevClient(feeds_http)
    lookup_cve = LookupCve(cve_repository, nvd, epss, kev, clock)
    process = SubprocessRunner()
    tool_registry = tool_registry or StaticToolRegistry(
        {
            "headers": HeadersRunner(SafeHttpClient()),
            "testssl": TestsslRunner(process, settings.testssl_bin),
            "nuclei": NucleiRunner(process, settings.nuclei_bin),
        }
    )
    planner = planner or FixedProbePlanner()
    llm_decisions = llm_decisions or PostgresLlmDecisionRepository(_pool_of(database))
    finding_review = finding_review or PostgresFindingReviewRepository(_pool_of(database))
    reports = reports or PostgresReportRepository(_pool_of(database))
    finding_query = finding_query or PostgresFindingQueryRepository(_pool_of(database))
    report_renderer = report_renderer or ReportlabPdfRenderer()
    if llm is None and settings.llm_api_key and settings.llm_model:
        llm = HttpLlmGateway(
            api_key=settings.llm_api_key.get_secret_value(),
            model=settings.llm_model,
            base_url=settings.llm_base_url,
            provider=settings.llm_provider,
            timeout_s=settings.llm_request_timeout_seconds,
        )
    budget = TokenBudget(settings.llm_max_tokens_per_scan)
    recorder = DecisionRecorder(llm_decisions, budget, clock)
    fixed_source = FixedPlanSource(planner)
    plan_source: PlanSource = (
        LlmPlanSource(llm, recorder, budget, fixed_source) if llm is not None else fixed_source
    )
    scheduler = scheduler or AsyncioScanScheduler()
    run_scan_tests = RunScanTests(
        domains=domains,
        scans=scans,
        endpoints=endpoints,
        tools=tools,
        test_runs=test_runs,
        findings=findings,
        cves=cve_repository,
        lookup_cve=lookup_cve,
        registry=tool_registry,
        plan_source=plan_source,
        cipher=cipher,
        audit=record_action,
        clock=clock,
    )
    generate_report = GenerateReport(
        domains=domains,
        review=finding_review,
        reports=reports,
        gateway=llm,
        recorder=recorder,
        budget=budget,
        audit=record_action,
        clock=clock,
    )
    finalize_scan = FinalizeScan(
        scans,
        AnalyzeFindings(
            domains=domains,
            review=finding_review,
            cves=cve_repository,
            gateway=llm,
            recorder=recorder,
            budget=budget,
            cipher=cipher,
            audit=record_action,
        ),
        generate_report,
        record_action,
        settings.llm_step_timeout_seconds,
    )
    get_report = GetReport(domains, scans, reports, finding_query)
    recon_queue = recon_queue or CeleryReconQueue(create_celery(settings))
    enumerator = enumerator or SubfinderRunner(process, settings.subfinder_bin)
    resolver = resolver or SystemHostResolver()
    port_scanner = port_scanner or NmapRunner(process, settings.nmap_bin)
    prober = prober or HttpxRunner(process, settings.httpx_bin)
    run_recon_scan = RunReconScan(
        domains=domains,
        scans=scans,
        assets=assets,
        enumerator=enumerator,
        resolver=resolver,
        scanner=port_scanner,
        prober=prober,
        audit=record_action,
        clock=clock,
        limits=ReconLimits(settings.recon_max_assets, settings.recon_timeout_seconds),
    )
    start_recon_scan = StartReconScan(
        domains,
        scans,
        recon_scans,
        recon_queue,
        record_action,
        clock,
        settings.recon_stale_after_seconds,
    )
    limiter = AuthRateLimiter(
        shared_limiter,
        attempts=settings.auth_rate_limit_attempts,
        window_seconds=settings.auth_rate_limit_window_seconds,
    )
    issuer = SessionIssuer(
        tokens,
        refresh_tokens,
        clock,
        refresh_ttl=timedelta(days=settings.refresh_token_ttl_days),
    )
    celery = create_celery(settings)
    public_queue = public_queue or CeleryPublicAnalysisQueue(celery)
    run_public_analysis = RunPublicAnalysis(
        public_analyses,
        public_dns or DnsPublicInspector(),
        enumerator,
        ct_source or CrtShSource(),
        web_fetcher or PublicHttpFetcher(),
        llm,
        clock,
    )
    start_public_analysis = StartPublicAnalysis(
        public_analyses,
        public_queue,
        record_action,
        clock,
        AuthRateLimiter(
            shared_limiter,
            attempts=settings.public_analysis_rate_limit_attempts,
            window_seconds=settings.auth_rate_limit_window_seconds,
        ),
        protected_domains=settings.public_protected_domains,
        daily_limit=settings.public_analysis_daily_limit,
        retention_days=settings.public_analysis_retention_days,
        stale_after_seconds=settings.recon_stale_after_seconds,
    )
    return Container(
        settings=settings,
        database=database,
        users=users,
        tokens=tokens,
        authenticate=AuthenticateAccessToken(users, tokens),
        register_user=RegisterUser(users, hasher, clock, limiter, record_action),
        login=Login(users, hasher, tokens, issuer, limiter, record_action),
        verify_mfa=VerifyMfa(users, tokens, totp, cipher, issuer, limiter, record_action),
        setup_mfa=SetupMfa(users, totp, cipher),
        enable_mfa=EnableMfa(users, totp, cipher, limiter),
        rotate_refresh_token=RotateRefreshToken(
            users, refresh_tokens, tokens, issuer, clock, limiter, record_action
        ),
        logout=Logout(refresh_tokens, tokens, clock, record_action),
        update_profile=UpdateProfile(users, refresh_tokens, hasher, clock, limiter, record_action),
        record_action=record_action,
        list_audit=ListAudit(audit),
        verify_audit_chain=VerifyAuditChain(audit),
        add_domain=AddDomain(domains, record_action),
        get_domain=GetDomain(domains),
        list_domains=ListDomains(domains),
        verify_domain=VerifyDomain(
            domains,
            domain_verifier,
            record_action,
            AuthRateLimiter(
                shared_limiter,
                attempts=settings.domain_verify_rate_limit_attempts,
                window_seconds=settings.auth_rate_limit_window_seconds,
            ),
            clock,
        ),
        sync_cve_catalog=SyncCveCatalog(
            cve_repository, nvd, epss, kev, clock, max_lookups=settings.cve_sync_max_lookups
        ),
        lookup_cve=lookup_cve,
        run_scan_tests=run_scan_tests,
        start_tests=StartTests(
            domains,
            endpoints,
            scans,
            run_scan_tests,
            scheduler,
            record_action,
            clock,
            finalize_scan,
        ),
        finalize_scan=finalize_scan,
        generate_report=generate_report,
        list_findings=ListFindings(domains, finding_query),
        get_finding=GetFinding(domains, finding_query),
        update_finding_status=UpdateFindingStatus(domains, finding_query, record_action),
        get_report=get_report,
        render_report_pdf=RenderReportPdf(get_report, report_renderer, record_action),
        update_recommendation=UpdateRecommendationStatus(domains, scans, reports, record_action),
        dashboard=GetDashboardSummary(domains, scans, finding_query),
        get_scan=GetScan(domains, scans),
        list_test_runs=ListTestRuns(domains, scans, test_runs),
        list_scan_findings=ListScanFindings(domains, scans, findings),
        scheduler=scheduler,
        run_recon_scan=run_recon_scan,
        start_recon_scan=start_recon_scan,
        start_public_analysis=start_public_analysis,
        run_public_analysis=run_public_analysis,
        get_public_analysis=GetPublicAnalysis(public_analyses, clock),
        list_public_analyses=ListPublicAnalyses(public_analyses),
        purge_public_analyses=PurgeExpiredPublicAnalyses(public_analyses, clock),
        rescan_asset=RescanAsset(domains, assets, start_recon_scan),
        list_assets=ListAssets(domains, assets),
        get_asset=GetAsset(domains, assets),
        set_endpoint_whitelist=SetEndpointWhitelist(domains, assets, record_action),
    )


def _pool_of(database: DatabasePort) -> Any:
    if not isinstance(database, PostgresDatabase):
        raise TypeError("Se necesita PostgresDatabase o repositorios explícitos.")
    return database.pool


def _default_rate_limiter(settings: Settings, clock: Clock) -> RateLimiter:
    if settings.is_prod:
        return RedisRateLimiter(Redis.from_url(settings.redis_url))
    return InMemoryRateLimiter(clock)
