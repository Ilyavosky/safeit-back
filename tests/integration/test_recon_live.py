import os
import shutil

import pytest

from app.infrastructure.recon.dns_resolver import SystemHostResolver
from app.infrastructure.recon.httpx_runner import HttpxRunner
from app.infrastructure.recon.nmap_runner import NmapRunner
from app.infrastructure.testing.process import SubprocessRunner

TARGET = os.environ.get("SAFEIT_LIVE_TARGET")
NMAP = os.environ.get("NMAP_BIN", "nmap")
HTTPX = os.environ.get("HTTPX_BIN", "httpx")

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(not TARGET, reason="SAFEIT_LIVE_TARGET no está definida"),
    pytest.mark.skipif(
        shutil.which(NMAP) is None or shutil.which(HTTPX) is None,
        reason="nmap o httpx no están instalados",
    ),
]


async def test_live_target_resolves_scans_and_probes() -> None:
    assert TARGET is not None
    addresses = await SystemHostResolver().resolve(TARGET)
    assert addresses
    process = SubprocessRunner()
    services = await NmapRunner(process, NMAP).scan(addresses[:1])
    assert addresses[0] in services
    probes = await HttpxRunner(process, HTTPX).probe([TARGET])
    assert all(probe.host == TARGET for probe in probes)
