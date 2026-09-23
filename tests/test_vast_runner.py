from __future__ import annotations

import asyncio
import json

import pytest

from browser_use_capture_mcp.vast_runner import VastConnection, VastRunner, VastRunnerError


def test_worker_payload_maps_legacy_fields_without_schema_leaks():
    capture = {
        "url": "https://example.com",
        "gpu": True,
        "no_scroll": True,
        "tail_lines": 800,
        "timeout_ms": 180000,
    }

    payload = VastRunner.build_worker_input(
        capture,
        "707df2a1-f11e-421c-b255-2b0181b13a27",
        "/workspace/browser-use-capture/runs/707df2a1-f11e-421c-b255-2b0181b13a27",
    )

    assert payload["scroll"] is False
    assert payload["tail_ms"] == 800
    assert not {"gpu", "no_scroll", "tail_lines"}.intersection(payload)


def test_worker_payload_rejects_cpu_only_capture():
    with pytest.raises(VastRunnerError, match="gpu=true"):
        VastRunner.build_worker_input({"gpu": False}, "run", "/workspace/run")


def test_scp_transfer_preserves_the_approved_remote_subdirectory(tmp_path):
    runner = VastRunner(package_root=tmp_path)
    runner._ssh_options = lambda: []
    source = tmp_path / "remote" / "public_socks_proxy.py"
    args = runner._scp_args(VastConnection("root", "8.8.8.8", 2222), [source], "remote")
    assert args[-1] == "root@8.8.8.8:/workspace/browser-use-capture/app/remote"
    assert str(source) in args


def test_scp_transfer_rejects_unapproved_remote_directories():
    runner = VastRunner()
    with pytest.raises(VastRunnerError, match="destination is not approved"):
        runner._scp_args(VastConnection("root", "8.8.8.8", 2222), [], "../../tmp")


def test_browser_use_runtime_disables_remote_telemetry_cloud_and_version_checks(monkeypatch):
    monkeypatch.setenv("BROWSER_USE_CHROMIUM_PATH", "/opt/google chrome/chrome")
    environment = VastRunner()._browser_environment()

    assert "ANONYMIZED_TELEMETRY=false" in environment
    assert "BROWSER_USE_CLOUD_SYNC=false" in environment
    assert "BROWSER_USE_VERSION_CHECK=false" in environment
    assert "PYTHONDONTWRITEBYTECODE=1" in environment
    assert "BROWSER_USE_CHROMIUM_PATH='/opt/google chrome/chrome'" in environment


def test_runner_requires_vast_secrets_and_remote_browser(monkeypatch):
    monkeypatch.delenv("VAST_INSTANCE_ID", raising=False)
    monkeypatch.delenv("VAST_API_KEY", raising=False)
    monkeypatch.delenv("BROWSER_USE_CHROMIUM_PATH", raising=False)
    with pytest.raises(VastRunnerError, match="VAST_INSTANCE_ID"):
        VastRunner().validate_configuration()


def test_runner_rejects_api_key_in_missing_state_without_echoing(monkeypatch):
    monkeypatch.setenv("VAST_INSTANCE_ID", "99")
    monkeypatch.delenv("VAST_API_KEY", raising=False)
    monkeypatch.setenv("BROWSER_USE_CHROMIUM_PATH", "/opt/google/chrome/chrome")
    with pytest.raises(VastRunnerError) as error:
        VastRunner().validate_configuration()
    assert "VAST_API_KEY" in str(error.value)


def test_ssh_url_resolution_keeps_api_key_out_of_arguments(monkeypatch):
    monkeypatch.setenv("VAST_INSTANCE_ID", "99")
    monkeypatch.setenv("VAST_API_KEY", "do-not-print-this-key")
    monkeypatch.setenv("BROWSER_USE_CHROMIUM_PATH", "/opt/google/chrome/chrome")
    runner = VastRunner()
    monkeypatch.setattr(runner, "validate_configuration", lambda: None)
    monkeypatch.setattr(VastRunner, "_vast_cli", staticmethod(lambda: "/usr/bin/vastai"))
    calls = []

    class Process:
        returncode = 0
        pid = 123

        async def communicate(self):
            return b"ssh://root@8.8.8.8:2222\n", b""

    async def fake_create_subprocess_exec(*args, **kwargs):
        calls.append((args, kwargs))
        return Process()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    connection = asyncio.run(runner.connection())
    assert connection == VastConnection("root", "8.8.8.8", 2222)
    assert all("do-not-print-this-key" not in argument for argument in calls[0][0])
    assert calls[0][1]["env"]["VAST_API_KEY"] == "do-not-print-this-key"


def test_remote_run_cleanup_is_restricted_to_uuid_path(monkeypatch):
    runner = VastRunner()
    seen = []

    async def fake_run_remote(connection, command, **kwargs):
        seen.append(command)
        return b"", b""

    monkeypatch.setattr(runner, "_run_remote", fake_run_remote)
    connection = VastConnection("root", "8.8.8.8", 2222)
    removed = asyncio.run(runner._remove_remote_run(connection, "/workspace/browser-use-capture/runs/not-a-uuid"))
    assert not removed
    assert seen == []
    removed = asyncio.run(runner._remove_remote_run(connection, "/workspace/browser-use-capture/runs/aa44ec52-ae57-4c73-a574-e824ac649e37"))
    assert removed
    assert "rm -rf -- '/workspace/browser-use-capture/runs/aa44ec52-ae57-4c73-a574-e824ac649e37'" in seen[0]


def test_remote_termination_waits_for_worker_cleanup(monkeypatch):
    runner = VastRunner()
    calls = []

    async def fake_run_remote(connection, command, **kwargs):
        calls.append((command, kwargs))
        return b"", b""

    monkeypatch.setattr(runner, "_run_remote", fake_run_remote)
    connection = VastConnection("root", "8.8.8.8", 2222)
    run_directory = "/workspace/browser-use-capture/runs/aa44ec52-ae57-4c73-a574-e824ac649e37"

    asyncio.run(runner._terminate_remote_run(connection, run_directory))

    command, options = calls[0]
    assert "kill -TERM" in command
    assert "seq 1 75" in command
    assert "kill -0" in command
    assert "sleep 2" not in command
    assert options["timeout"] == 90


def test_compatibility_probe_uses_short_run_scoped_temp_paths(monkeypatch):
    monkeypatch.setenv("BROWSER_USE_CHROMIUM_PATH", "/opt/google/chrome/chrome")
    runner = VastRunner()
    payload = {
        "status": "verified",
        "browserExecutable": "/opt/google/chrome/chrome",
        "browserUseVersion": "0.13.10",
        "browserVersion": "Chrome/154.0.8037.57",
        "cpu": {"status": "verified"},
        "gpu": {"status": "verified"},
    }

    async def fake_connection():
        return VastConnection("root", "8.8.8.8", 2222)

    async def fake_sync_project(connection):
        return None

    async def fake_run_remote(connection, command, **kwargs):
        assert "HOME='/tmp/bu-" in command
        assert "TMPDIR='/tmp/bu-" in command
        assert "HOME='/workspace/browser-use-capture/runs/" not in command
        return json.dumps(payload).encode(), b""

    monkeypatch.setattr(runner, "connection", fake_connection)
    monkeypatch.setattr(runner, "sync_project", fake_sync_project)
    monkeypatch.setattr(runner, "_run_remote", fake_run_remote)

    result = asyncio.run(runner.check_compatibility())

    assert result["status"] == "verified"


def test_vast_api_key_is_not_inherited_by_ssh_processes(monkeypatch):
    monkeypatch.setenv("VAST_API_KEY", "do-not-forward-to-ssh")
    runner = VastRunner()
    monkeypatch.setattr(runner, "_ssh_options", lambda: [])
    connection = VastConnection("root", "8.8.8.8", 2222)
    calls = []

    class Process:
        returncode = 0
        pid = 123

        async def communicate(self, input=None):
            return b"", b""

    async def fake_create_subprocess_exec(*args, **kwargs):
        calls.append((args, kwargs))
        return Process()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    asyncio.run(runner._run_remote(connection, "true"))
    assert "do-not-forward-to-ssh" not in repr(calls[0][0])
    assert "VAST_API_KEY" not in calls[0][1]["env"]


def test_configured_missing_ssh_identity_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setenv("SITE_MOTION_SSH_KEY", str(tmp_path / "missing-key"))
    with pytest.raises(VastRunnerError, match="identity file is unavailable"):
        VastRunner()._ssh_options()


def test_compatibility_probe_preserves_cpu_failure_when_gpu_passes():
    import sys
    from pathlib import Path

    scripts = Path(__file__).parents[1] / "scripts"
    sys.path.insert(0, str(scripts))
    from verify_compatibility import _overall_failure_reason

    assert _overall_failure_reason("blocked", {"status": "verified"}) == "one or more CPU compatibility checks failed"
    assert _overall_failure_reason(
        "blocked",
        {"status": "verified"},
        "network egress policy blocked one or more browser requests",
    ) == "network egress policy blocked one or more browser requests"


def test_ssh_url_parser_rejects_non_public_endpoints(monkeypatch):
    monkeypatch.setenv("VAST_INSTANCE_ID", "99")
    monkeypatch.setenv("VAST_API_KEY", "key")
    monkeypatch.setenv("BROWSER_USE_CHROMIUM_PATH", "/opt/google/chrome/chrome")
    runner = VastRunner()
    monkeypatch.setattr(runner, "validate_configuration", lambda: None)
    monkeypatch.setattr(VastRunner, "_vast_cli", staticmethod(lambda: "/usr/bin/vastai"))

    class Process:
        returncode = 0
        pid = 123

        async def communicate(self):
            return b"ssh://root@127.0.0.1:2222\n", b""

    async def fake_create_subprocess_exec(*args, **kwargs):
        return Process()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    with pytest.raises(VastRunnerError, match="non-public"):
        asyncio.run(runner.connection())
