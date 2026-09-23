from __future__ import annotations

import asyncio
import sys
from types import ModuleType
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import verify_compatibility as compatibility
from verify_compatibility import _attach_probe_metadata


def test_default_probe_metadata_has_no_temporary_egress_hosts():
    result = _attach_probe_metadata({"status": "blocked"}, False)

    assert result["temporaryEgressApproval"] == {
        "enabled": False,
        "scope": "single compatibility-probe process",
        "hostnames": [],
        "port": 443,
        "maxLifetimeSeconds": 0,
        "probeDeadlineSeconds": 110,
    }
    assert result["requestMetadataLimitations"]["rawNetLogCaptured"] is False
    assert result["requestMetadataLimitations"]["httpsMetadataRequiresTlsInterception"] is True
    assert result["requestMetadataLimitations"]["notCollectedFields"] == [
        "URL path",
        "HTTP method",
        "request initiator",
    ]
    assert "captureAuthorized" not in result


def test_temporary_egress_probe_never_authorizes_capture():
    result = _attach_probe_metadata({"status": "verified"}, True)

    assert result["status"] == "blocked"
    assert result["diagnosticOnly"] is True
    assert result["captureAuthorized"] is False
    assert result["failureReason"] == "temporary egress experiment cannot authorize capture"
    assert result["temporaryEgressApproval"]["hostnames"] == [
        "update.googleapis.com",
        "www.gstatic.com",
    ]
    assert result["temporaryEgressApproval"]["maxLifetimeSeconds"] == 3600
    assert result["temporaryEgressApproval"]["probeDeadlineSeconds"] == 110


def test_timed_out_experiment_is_blocked_and_cannot_authorize_capture(monkeypatch):
    async def never_finishes(*, reviewed_egress_experiment: bool):
        await asyncio.sleep(1)

    monkeypatch.setattr(compatibility, "verify", never_finishes)
    monkeypatch.setattr(compatibility, "VERIFY_TIMEOUT_SECONDS", 0.001)

    result = asyncio.run(
        compatibility._verify_with_signal_cleanup(reviewed_egress_experiment=True)
    )

    assert result["status"] == "blocked"
    assert result["cpu"]["status"] == "blocked"
    assert result["gpu"]["status"] == "blocked"
    assert result["failureReason"] == (
        "compatibility probe exceeded its 0.001-second deadline"
    )
    assert result["diagnosticOnly"] is True
    assert result["captureAuthorized"] is False
    assert result["temporaryEgressApproval"]["probeDeadlineSeconds"] == 0.001


def test_cleanup_finishes_after_repeated_cancellation():
    async def run_cancellation_scenario():
        cleanup_started = asyncio.Event()
        allow_cleanup_to_finish = asyncio.Event()
        cleanup_finished = asyncio.Event()

        async def cleanup():
            cleanup_started.set()
            await allow_cleanup_to_finish.wait()
            cleanup_finished.set()

        cleanup_task = asyncio.create_task(compatibility._await_cleanup(cleanup()))
        await cleanup_started.wait()
        cleanup_task.cancel()
        await asyncio.sleep(0)
        cleanup_task.cancel()
        allow_cleanup_to_finish.set()

        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
        else:
            raise AssertionError("cleanup wrapper should preserve cancellation")

        assert cleanup_finished.is_set()

    asyncio.run(run_cancellation_scenario())


def _run_fake_probe(
    monkeypatch,
    *,
    proxy_policy_passed: bool = True,
    observed_destination: dict[str, object] | None = None,
):
    class FakeProxy:
        instances = []

        def __init__(self, **kwargs):
            self.violations = []
            self.blocked_destinations = []
            self.connection_outcomes = []
            self.__class__.instances.append(self)

        async def start(self):
            return 18080

        async def close(self):
            return None

        def _destination_is_approved(self, hostname: str, port: int) -> bool:
            return hostname == "example.com" or hostname.endswith(".example.com")

    class FakeProfile:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def get_args(self):
            return []

    class FakePage:
        async def set_viewport_size(self, width: int, height: int):
            return None

        async def evaluate(self, expression: str):
            return True

    class FakeSession:
        def __init__(self, **kwargs):
            self.page = FakePage()

        async def start(self):
            return None

        async def get_current_page(self):
            return self.page

        async def kill(self):
            return None

    browser_use = ModuleType("browser_use")
    browser_use.__path__ = []
    browser = ModuleType("browser_use.browser")
    browser.__path__ = []
    profile_module = ModuleType("browser_use.browser.profile")
    profile_module.BrowserProfile = FakeProfile
    session_module = ModuleType("browser_use.browser.session")
    session_module.BrowserSession = FakeSession
    for name, module in (
        ("browser_use", browser_use),
        ("browser_use.browser", browser),
        ("browser_use.browser.profile", profile_module),
        ("browser_use.browser.session", session_module),
    ):
        monkeypatch.setitem(sys.modules, name, module)

    class FakeProcess:
        returncode = 0

    async def async_noop(*args, **kwargs):
        return None

    async def fake_policy_probe(proxy):
        return proxy_policy_passed

    async def fake_page_probe(page, session):
        if observed_destination is not None:
            proxy = FakeProxy.instances[-1]
            hostname = str(observed_destination["hostname"])
            port = int(observed_destination["port"])
            outcome = str(observed_destination["outcome"])
            if outcome == "blocked":
                reason = str(observed_destination["reason"])
                proxy.violations.append(reason)
                proxy.blocked_destinations.append({
                    "hostname": hostname,
                    "port": port,
                    "reason": reason,
                })
            proxy.connection_outcomes.append({
                "hostname": hostname,
                "port": port,
                "outcome": outcome,
                "count": 1,
            })
        return "Example Domain", "NVIDIA GeForce RTX 3060", True, []

    async def fake_launch_browser(*args, **kwargs):
        return FakeProcess(), "http://127.0.0.1:9222/", "Chrome/154.0", "ws://127.0.0.1:9222/devtools"

    async def fake_recording(websocket_url, page, output_path, width, height, seconds=2.5):
        output_path.write_bytes(b"synthetic recording")

    monkeypatch.setattr(compatibility, "_browser_path", lambda: Path("/opt/chromium"))
    monkeypatch.setattr(compatibility, "_browser_use_version", lambda: "0.13.10")
    monkeypatch.setattr(compatibility, "PublicSocksProxy", FakeProxy)
    monkeypatch.setattr(compatibility, "_probe_proxy_policy", fake_policy_probe)
    monkeypatch.setattr(compatibility, "_probe_page", fake_page_probe)
    monkeypatch.setattr(compatibility, "_launch_browser", fake_launch_browser)
    monkeypatch.setattr(compatibility, "_install_jank_observer", async_noop)
    monkeypatch.setattr(compatibility, "_record_browser_use_video", fake_recording)
    monkeypatch.setattr(compatibility, "_stop_process", async_noop)
    monkeypatch.setattr(compatibility, "_convert_to_webm", lambda *args: {
        "status": "valid",
        "format": "webm",
        "durationSeconds": 2.5,
    })
    monkeypatch.setattr(compatibility, "_gpu_status", lambda renderer: {
        "status": "verified",
        "renderer": renderer,
        "device": "NVIDIA GeForce RTX 3060",
    })
    monkeypatch.setattr(compatibility.asyncio, "sleep", async_noop)

    return asyncio.run(compatibility.verify())


def test_cpu_compatibility_is_separate_from_reported_socks_denials(monkeypatch):
    result = _run_fake_probe(
        monkeypatch,
        observed_destination={
            "hostname": "clients2.google.com",
            "port": 80,
            "outcome": "blocked",
            "reason": "domain-not-approved",
        },
    )

    assert result["status"] == "blocked"
    assert result["cpu"]["status"] == "verified"
    assert not {
        "egressPolicyViolations",
        "blockedDestinations",
        "connectionOutcomes",
    }.intersection(result["cpu"])
    egress_policy = result["egressPolicy"]
    assert egress_policy["status"] == "unverified"
    assert egress_policy["browserTrafficBoundary"] == "unverified"
    assert egress_policy["blockedDestinations"] == [{
        "hostname": "clients2.google.com",
        "port": 80,
        "reason": "domain-not-approved",
    }]
    assert egress_policy["requestAttribution"]["status"] == "unknown"
    assert egress_policy["requestAttribution"]["initiatorsCollected"] is False
    assert "path" not in egress_policy["blockedDestinations"][0]
    assert "initiator" not in egress_policy["blockedDestinations"][0]


def test_policy_denial_is_reported_without_becoming_a_security_violation():
    class Proxy:
        violations = ["domain-not-approved"]
        blocked_destinations = [{
            "hostname": "unexpected.example",
            "port": 443,
            "reason": "domain-not-approved",
        }]
        connection_outcomes = [{
            "hostname": "unexpected.example",
            "port": 443,
            "outcome": "blocked",
            "count": 1,
        }]

        @staticmethod
        def _destination_is_approved(hostname: str, port: int) -> bool:
            return hostname == "example.com" or hostname.endswith(".example.com")

    result = compatibility._egress_policy_result(
        Proxy(),
        proxy_policy_verified=True,
        pre_fixture_observations={"blockedDestinations": [], "connectionOutcomes": []},
    )

    assert result["status"] == "unverified"
    assert result["proxyPolicyCheck"] == "verified"
    assert result["unexpectedViolationCodes"] == []
    assert result["unauthorizedConnections"] == []
    assert result["blockedDestinations"] == Proxy.blocked_destinations


@pytest.mark.parametrize(
    ("proxy_policy_verified", "connection_outcomes", "violations"),
    [
        (False, [], []),
        (True, [{
            "hostname": "unexpected.example",
            "port": 443,
            "outcome": "connected",
            "count": 1,
        }], []),
        (True, [], ["unexpected-proxy-error"]),
    ],
)
def test_egress_policy_requires_proxy_checks_and_rejects_unapproved_success(
    proxy_policy_verified: bool,
    connection_outcomes: list[dict[str, object]],
    violations: list[str],
):
    proxy = type("Proxy", (), {
        "violations": violations,
        "blocked_destinations": [],
        "connection_outcomes": connection_outcomes,
        "_destination_is_approved": staticmethod(
            lambda hostname, port: hostname == "example.com" or hostname.endswith(".example.com")
        ),
    })()

    result = compatibility._egress_policy_result(
        proxy,
        proxy_policy_verified=proxy_policy_verified,
        pre_fixture_observations={"blockedDestinations": [], "connectionOutcomes": []},
    )

    assert result["status"] == "blocked"
    assert (
        result["proxyPolicyCheck"] != "verified"
        or result["unauthorizedConnections"]
        or result["unexpectedViolationCodes"]
    )
