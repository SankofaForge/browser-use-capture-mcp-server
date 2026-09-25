from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import verify_compatibility as compatibility
from verify_compatibility import _attach_probe_metadata


def test_webm_validation_returns_status_required_by_cpu_gate(tmp_path, monkeypatch):
    recording = tmp_path / "compatibility.webm"
    recording.write_bytes(b"synthetic webm")
    monkeypatch.setattr(compatibility.shutil, "which", lambda name: "/usr/bin/ffprobe")
    monkeypatch.setattr(
        compatibility.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout='{"format":{"format_name":"matroska,webm","duration":"1.4"}}',
        ),
    )

    result = compatibility._validate_webm(recording)

    assert result == {
        "status": "valid",
        "format": "matroska,webm",
        "durationSeconds": 1.4,
    }


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
        pid = 12345

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

    async def fake_service_checks(page, session):
        return {
            "status": "verified",
            "checks": [
                {"service": "safeBrowsing", "status": "verified", "reason": None},
                {"service": "componentUpdater", "status": "verified", "reason": None},
            ],
            "requiredDestinations": [
                {"hostname": hostname, "port": 443}
                for hostname in sorted(compatibility.COMPATIBILITY_SERVICE_HOSTS)
            ],
            "rawNetLogCaptured": False,
            "pageContentsCollected": False,
        }

    async def fake_launch_browser(*args, **kwargs):
        return FakeProcess(), "http://127.0.0.1:9222/", "Chrome/154.0", "ws://127.0.0.1:9222/devtools"

    async def fake_recording(websocket_url, page, output_path, width, height, seconds=2.5):
        output_path.write_bytes(b"synthetic recording")

    monkeypatch.setattr(compatibility, "_browser_path", lambda: Path("/opt/chromium"))
    monkeypatch.setattr(compatibility, "_browser_use_version", lambda: "0.13.10")
    monkeypatch.setattr(compatibility, "PublicSocksProxy", FakeProxy)
    monkeypatch.setattr(compatibility, "_probe_proxy_policy", fake_policy_probe)
    monkeypatch.setattr(compatibility, "_probe_page", fake_page_probe)
    monkeypatch.setattr(compatibility, "_browser_service_checks", fake_service_checks)
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


def test_namespaced_probe_requires_root_runner_service_evidence(monkeypatch):
    monkeypatch.setenv("CAPTURE_EGRESS_PROXY_HOST", "10.200.1.1")
    monkeypatch.setenv("CAPTURE_EGRESS_PROXY_PORT", "18080")
    monkeypatch.setenv("CAPTURE_EGRESS_RUN_ID", "d9d249bc-2561-4a64-b98c-6d2657a4cdee")
    monkeypatch.setenv(
        "CAPTURE_EGRESS_ATTESTATION_FILE",
        "/workspace/browser-use-capture/attestations/probe.json",
    )
    actual_os = compatibility.os
    monkeypatch.setattr(
        compatibility,
        "os",
        SimpleNamespace(
            environ=actual_os.environ,
            stat=lambda _path: SimpleNamespace(st_ino=456),
            killpg=actual_os.killpg,
        ),
    )
    monkeypatch.setattr(
        compatibility,
        "_load_egress_attestation",
        lambda *_args: ({"status": "verified", "networkNamespaceInode": 456}, {
            "compatibilityServicePolicy": "preflight-services.v1",
            "compatibilityServiceHosts": sorted(compatibility.COMPATIBILITY_SERVICE_HOSTS),
            "compatibilityServicePort": 443,
        }),
    )
    monkeypatch.setattr(compatibility, "_browser_binary_version", lambda _path: "154.0.8037.57")
    real_temporary_directory = compatibility.tempfile.TemporaryDirectory
    temporary_prefixes = []

    def capture_temporary_directory(**kwargs):
        temporary_prefixes.append(kwargs["prefix"])
        return real_temporary_directory(**kwargs)

    monkeypatch.setattr(compatibility.tempfile, "TemporaryDirectory", capture_temporary_directory)

    result = _run_fake_probe(monkeypatch)

    assert temporary_prefixes == ["buc-d9d249bc25614a64-"]
    assert result["cpu"]["status"] == "verified"
    assert "title" not in result["cpu"]
    assert result["egressPolicy"]["status"] == "unverified"
    assert result["egressPolicy"]["proxyPolicyCheck"] == "verified"
    assert result["egressPolicy"]["browserTrafficBoundary"] == "verified"
    assert result["egressPolicy"]["browserServiceReachability"] == "unverified"
    assert result["browserServiceChecks"]["status"] == "verified"
    assert result["status"] == "blocked"


def test_service_check_timeout_is_bounded_and_blocked():
    class DiagnosticsPage:
        async def goto(self, _url):
            return None

        async def evaluate(self, _expression):
            return {"available": True, "completedLookups": 0}

    class Page:
        async def goto(self, url):
            if url.startswith("https://example.com/"):
                await asyncio.sleep(1)

        async def evaluate(self, expression):
            return "standard" if "settings-security-page" in expression else None

    class Session:
        async def new_page(self):
            return DiagnosticsPage()

        async def close_page(self, _page):
            return None

    previous_timeout = compatibility.SERVICE_CHECK_TIMEOUT_SECONDS
    compatibility.SERVICE_CHECK_TIMEOUT_SECONDS = 0.001
    try:
        result = asyncio.run(compatibility._browser_service_checks(Page(), Session()))
    finally:
        compatibility.SERVICE_CHECK_TIMEOUT_SECONDS = previous_timeout
    assert result["status"] == "blocked"
    assert result["checks"][0]["reason"] == "timeout"
    assert result["checks"][1]["status"] == "blocked"


def test_service_checks_report_unavailable_settings_state(monkeypatch):
    monkeypatch.setattr(compatibility, "SERVICE_CHECK_TIMEOUT_SECONDS", 0.01)

    class Page:
        async def goto(self, _url):
            return None

        async def evaluate(self, _expression):
            return None

    result = asyncio.run(compatibility._browser_service_checks(Page(), object()))

    assert result["checks"][0]["reason"] == "settings-state-unavailable"
    assert result["status"] == "blocked"


@pytest.mark.parametrize(
    ("settings_mode", "expected_status", "expected_reason"),
    [
        ("standard", "verified", None),
        ("other", "blocked", "standard-protection-not-enabled"),
    ],
)
def test_service_checks_use_live_settings_state(
    monkeypatch, settings_mode, expected_status, expected_reason
):
    monkeypatch.setattr(compatibility, "SERVICE_CHECK_TIMEOUT_SECONDS", 0.1)
    state = {"checked": False}

    class DiagnosticsPage:
        async def goto(self, _url):
            return None

        async def evaluate(self, _expression):
            return {"available": True, "completedLookups": int(state["checked"])}

    class Page:
        async def goto(self, url):
            if url.startswith("https://example.com/"):
                state["checked"] = True

        async def evaluate(self, expression):
            if "settings-security-page" in expression:
                return settings_mode
            if ".button-check-update" in expression:
                return "test-component"
            if "already up to date" in expression:
                return "up-to-date"
            return None

    class Session:
        async def new_page(self):
            return DiagnosticsPage()

        async def close_page(self, _page):
            return None

    result = asyncio.run(compatibility._browser_service_checks(Page(), Session()))

    assert result["checks"][0]["status"] == expected_status
    assert result["checks"][0]["reason"] == expected_reason
    assert result["checks"][1]["status"] == "verified"
    assert result["status"] == expected_status


def test_service_checks_report_diagnostic_tab_failure_without_exception_text(monkeypatch):
    monkeypatch.setattr(compatibility, "SERVICE_CHECK_TIMEOUT_SECONDS", 0.01)

    class Page:
        async def goto(self, _url):
            return None

        async def evaluate(self, expression):
            return "standard" if "settings-security-page" in expression else None

    class Session:
        async def new_page(self):
            raise RuntimeError("private page contents")

    result = asyncio.run(compatibility._browser_service_checks(Page(), Session()))

    assert result["checks"][0]["reason"] == "diagnostics-tab-failed"
    assert "private page contents" not in json.dumps(result)


@pytest.mark.parametrize(
    ("component_status", "expected_reason"),
    [("update-error", "update-error"), ("not-updated", "component-not-updated")],
)
def test_service_checks_parse_diagnostics_and_classify_component_failure(
    monkeypatch, component_status, expected_reason
):
    monkeypatch.setattr(compatibility, "SERVICE_CHECK_TIMEOUT_SECONDS", 0.1)
    state = {"checked": False}

    class DiagnosticsPage:
        async def goto(self, _url):
            return None

        async def evaluate(self, _expression):
            return json.dumps({"available": True, "completedLookups": int(state["checked"])})

    class Page:
        async def goto(self, url):
            if url.startswith("https://example.com/"):
                state["checked"] = True

        async def evaluate(self, expression):
            if "settings-security-page" in expression:
                return "standard"
            if ".button-check-update" in expression:
                return "test-component"
            if "already up to date" in expression:
                return component_status
            return None

    class Session:
        async def new_page(self):
            return DiagnosticsPage()

        async def close_page(self, _page):
            return None

    result = asyncio.run(compatibility._browser_service_checks(Page(), Session()))

    assert result["checks"][0]["status"] == "verified"
    assert result["checks"][1]["reason"] == expected_reason
    assert result["status"] == "blocked"


def test_browser_service_checks_require_safe_browsing_and_up_to_date():
    events = []
    state = {"probe_completed": False, "trigger_attempts": 0}

    class DiagnosticsPage:
        async def goto(self, url):
            events.append(url)

        async def evaluate(self, _expression):
            return {"available": True, "completedLookups": int(state["probe_completed"])}

    class Page:
        async def goto(self, url):
            events.append(url)
            if url.startswith("https://example.com/"):
                state["probe_completed"] = True

        async def evaluate(self, expression):
            if "settings-security-page" in expression:
                return "standard"
            if ".button-check-update" in expression:
                state["trigger_attempts"] += 1
                if state["trigger_attempts"] == 1:
                    return None
                events.append("update-triggered")
                return "test-component"
            if "already up to date" in expression:
                return "up-to-date"
            return None

    class Session:
        async def new_page(self):
            return DiagnosticsPage()

        async def close_page(self, _page):
            return None

    result = asyncio.run(compatibility._browser_service_checks(Page(), Session()))
    assert result["status"] == "verified"
    assert [check["status"] for check in result["checks"]] == ["verified", "verified"]
    assert events.index("chrome://safe-browsing/") < events.index("https://example.com/?browser-use-safe-check=1")
    assert state["trigger_attempts"] == 2
    assert result["rawNetLogCaptured"] is False
    assert result["pageContentsCollected"] is False


def test_browser_service_checks_block_without_new_diagnostic_response():
    state = {"calls": 0}

    class DiagnosticsPage:
        async def goto(self, _url):
            return None

        async def evaluate(self, _expression):
            state["calls"] += 1
            return {"available": True, "completedLookups": 0 if state["calls"] == 1 else -1}

    class Page:
        async def goto(self, _url):
            return None

        async def evaluate(self, expression):
            if "settings-security-page" in expression:
                return "standard"
            if ".button-check-update" in expression:
                return "test-component"
            if "already up to date" in expression:
                return "other"
            return None

    class Session:
        async def new_page(self):
            return DiagnosticsPage()

        async def close_page(self, _page):
            return None

    previous_timeout = compatibility.SERVICE_CHECK_TIMEOUT_SECONDS
    compatibility.SERVICE_CHECK_TIMEOUT_SECONDS = 0.001
    try:
        result = asyncio.run(compatibility._browser_service_checks(Page(), Session()))
    finally:
        compatibility.SERVICE_CHECK_TIMEOUT_SECONDS = previous_timeout
    assert result["status"] == "blocked"
    assert result["checks"][0]["reason"] == "diagnostic-check-not-confirmed"
    assert result["checks"][1]["reason"] == "unexpected-component-status"


def test_browser_service_checks_reject_disabled_standard_protection():
    class Page:
        async def goto(self, _url):
            return None

        async def evaluate(self, expression):
            return "other" if "settings-security-page" in expression else False

    previous_timeout = compatibility.SERVICE_CHECK_TIMEOUT_SECONDS
    compatibility.SERVICE_CHECK_TIMEOUT_SECONDS = 0.001
    try:
        result = asyncio.run(compatibility._browser_service_checks(Page(), object()))
    finally:
        compatibility.SERVICE_CHECK_TIMEOUT_SECONDS = previous_timeout
    assert result["status"] == "blocked"
    assert result["checks"][0]["reason"] == "standard-protection-not-enabled"
    assert result["checks"][1]["reason"] == "update-trigger-unavailable"


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
    assert egress_policy["status"] == "blocked"
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


def test_unexpected_destination_attempt_blocks_service_preflight():
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
            return (
                hostname == "example.com" and port == 443
                or hostname in compatibility.COMPATIBILITY_SERVICE_HOSTS and port == 443
            )

    result = compatibility._egress_policy_result(
        Proxy(),
        proxy_policy_verified=True,
        pre_fixture_observations={"blockedDestinations": [], "connectionOutcomes": []},
    )

    assert result["status"] == "blocked"
    assert result["proxyPolicyCheck"] == "blocked"
    assert "unexpected-destination-attempt" in result["unexpectedViolationCodes"]
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
