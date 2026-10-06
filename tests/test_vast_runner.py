from __future__ import annotations

import asyncio
import json

import anyio
import pytest

import browser_use_capture_mcp.vast_runner as vast_runner
from browser_use_capture_mcp.vast_runner import REMOTE_RUNS, VastConnection, VastRunner, VastRunnerError


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
        "/workspace/bu/707df2a1-f11e-421c-b255-2b0181b13a27",
    )

    assert payload["scroll"] is False
    assert payload["tail_ms"] == 800
    assert payload["output_dir"] == "/workspace/bu/707df2a1-f11e-421c-b255-2b0181b13a27/artifacts"
    assert not {"gpu", "no_scroll", "tail_lines"}.intersection(payload)


def test_worker_payload_rejects_cpu_only_capture():
    with pytest.raises(VastRunnerError, match="gpu=true"):
        VastRunner.build_worker_input({"gpu": False}, "run", "/workspace/run")


def test_scp_transfer_preserves_the_approved_remote_subdirectory(tmp_path):
    runner = VastRunner(package_root=tmp_path)
    runner._ssh_options = lambda: []
    source = tmp_path / "remote" / "capture_worker.py"
    args = runner._scp_args(VastConnection("root", "8.8.8.8", 2222), [source], "remote")
    assert args[-1] == "root@8.8.8.8:/workspace/browser-use-capture/app/remote"
    assert str(source) in args


def test_scp_transfer_rejects_unapproved_remote_directories():
    runner = VastRunner()
    with pytest.raises(VastRunnerError, match="destination is not approved"):
        runner._scp_args(VastConnection("root", "8.8.8.8", 2222), [], "../../tmp")


def _complete_package_root(root):
    for relative in (
        "pyproject.toml",
        "uv.lock",
        "scripts/verify_compatibility.py",
        "remote/capture_worker.py",
    ):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture", encoding="utf-8")
    return root


def test_sync_project_classifies_ssh_refusal_as_runner_not_ready(monkeypatch, tmp_path):
    monkeypatch.setattr(vast_runner, "SSH_READINESS_TIMEOUT_SECONDS", 0)
    runner = VastRunner(package_root=_complete_package_root(tmp_path))
    calls = []

    async def fail_remote_command(connection, command, **kwargs):
        calls.append((command, kwargs["error_code"]))
        raise VastRunnerError(
            kwargs["error_code"],
            "The remote runner command failed",
            "ssh: connect to host 8.8.8.8 port 2222: Connection refused",
        )

    async def provider_state():
        return "starting", None

    runner._run_remote = fail_remote_command
    runner._provider_state = provider_state
    with pytest.raises(VastRunnerError) as raised:
        asyncio.run(runner.sync_project(VastConnection("root", "8.8.8.8", 2222)))

    assert raised.value.reason_code == "runner-not-ready"
    assert calls == [("true", "runner-not-ready")]


def test_sync_project_retries_starting_ssh_before_provisioning(monkeypatch, tmp_path):
    monkeypatch.setattr(vast_runner, "SSH_READINESS_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(vast_runner, "SSH_READINESS_RETRY_INTERVAL_SECONDS", 0.001)
    runner = VastRunner(package_root=_complete_package_root(tmp_path))
    remote_commands = []
    attempts = 0

    async def run_remote(connection, command, **kwargs):
        nonlocal attempts
        remote_commands.append(command)
        if command == "true":
            attempts += 1
            if attempts == 1:
                raise VastRunnerError(
                    kwargs["error_code"],
                    "The remote runner command failed",
                    "ssh: connect to host 8.8.8.8 port 2222: Connection refused",
                )
        return b"", b""

    async def run_local(command, **kwargs):
        return b"", b""

    runner._run_remote = run_remote
    runner._run_local = run_local
    runner._ssh_options = lambda: []
    asyncio.run(runner.sync_project(VastConnection("root", "8.8.8.8", 2222)))

    assert remote_commands[:2] == ["true", "true"]
    assert remote_commands[2].startswith("mkdir -p ")


def test_sync_project_reports_provider_state_and_ssh_diagnostic_on_timeout(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(vast_runner, "SSH_READINESS_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(vast_runner, "SSH_READINESS_RETRY_INTERVAL_SECONDS", 0.001)
    runner = VastRunner(package_root=_complete_package_root(tmp_path))
    remote_commands = []
    provider_queries = []

    async def fail_remote_command(connection, command, **kwargs):
        remote_commands.append(command)
        raise VastRunnerError(
            kwargs["error_code"],
            "The remote runner command failed",
            "ssh: connect to host 8.8.8.8 port 2222: Connection timed out",
        )

    async def provider_state():
        provider_queries.append(True)
        return "loading", None

    runner._run_remote = fail_remote_command
    runner._provider_state = provider_state
    with pytest.raises(VastRunnerError) as raised:
        asyncio.run(runner.sync_project(VastConnection("root", "8.8.8.8", 2222)))

    assert raised.value.reason_code == "runner-not-ready"
    assert "Provider state: loading" in raised.value.diagnostic
    assert "Connection timed out" in raised.value.diagnostic
    assert remote_commands and set(remote_commands) == {"true"}
    assert provider_queries == [True]


def test_sync_project_keeps_setup_failure_after_ssh_readiness(tmp_path):
    runner = VastRunner(package_root=_complete_package_root(tmp_path))
    remote_commands = []
    provider_queries = []

    async def fail_project_setup(connection, command, **kwargs):
        remote_commands.append((command, kwargs["error_code"]))
        if command != "true":
            raise VastRunnerError(
                kwargs["error_code"],
                "The remote runner command failed",
                "mkdir: permission denied",
            )
        return b"", b""

    async def provider_state():
        provider_queries.append(True)
        return "running", None

    runner._run_remote = fail_project_setup
    runner._provider_state = provider_state
    with pytest.raises(VastRunnerError) as raised:
        asyncio.run(runner.sync_project(VastConnection("root", "8.8.8.8", 2222)))

    assert raised.value.reason_code == "vast-project-provision-failed"
    assert remote_commands[0] == ("true", "runner-not-ready")
    assert remote_commands[1][1] == "vast-project-provision-failed"
    assert provider_queries == []


def test_provider_state_reads_only_the_status_field(monkeypatch):
    monkeypatch.setenv("VAST_API_KEY", "state-query-test-key")
    runner = VastRunner()
    runner.instance_id = "99"
    calls = []

    class Process:
        returncode = 0
        pid = 456

        async def communicate(self):
            return b'{"actual_status":"running","api_key":"private"}', b""

    async def create_process(*args, **kwargs):
        calls.append((args, kwargs))
        return Process()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    state, diagnostic = asyncio.run(runner._provider_state())

    assert state == "running"
    assert diagnostic is None
    assert calls[0][0][1:] == ("show", "instance", "99", "--raw")
    assert calls[0][1]["env"]["VAST_API_KEY"] == "state-query-test-key"


def test_copy_remote_files_accepts_the_run_artifacts_directory(tmp_path):
    runner = VastRunner()
    runner._ssh_options = lambda: []
    commands = []

    async def run_local(command, **_kwargs):
        commands.append(command)

    runner._run_local = run_local
    path = "/workspace/bu/707df2a1-f11e-421c-b255-2b0181b13a27/artifacts/desktop-full.webm"
    asyncio.run(runner._copy_remote_files(VastConnection("root", "8.8.8.8", 2222), [path], tmp_path))

    assert path in commands[0][commands[0].index("-P") + 2]


def test_browser_use_runtime_disables_remote_telemetry_cloud_and_version_checks(monkeypatch):
    monkeypatch.setenv("BROWSER_USE_CHROMIUM_PATH", "/opt/google chrome/chrome")
    monkeypatch.delenv("BROWSER_USE_DISABLE_SANDBOX", raising=False)
    environment = VastRunner()._browser_environment()

    assert "ANONYMIZED_TELEMETRY=false" in environment
    assert "BROWSER_USE_CLOUD_SYNC=false" in environment
    assert "BROWSER_USE_VERSION_CHECK=false" in environment
    assert "PYTHONDONTWRITEBYTECODE=1" in environment
    assert "BROWSER_USE_CHROMIUM_PATH='/opt/google chrome/chrome'" in environment
    assert "BROWSER_USE_DISABLE_SANDBOX=0" in environment
    monkeypatch.setenv("BROWSER_USE_DISABLE_SANDBOX", "1")
    assert "BROWSER_USE_DISABLE_SANDBOX=1" in VastRunner()._browser_environment()


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
    removed = asyncio.run(runner._remove_remote_run(connection, "/workspace/bu/not-a-uuid"))
    assert not removed
    assert seen == []
    removed = asyncio.run(runner._remove_remote_run(connection, "/workspace/bu/aa44ec52-ae57-4c73-a574-e824ac649e37"))
    assert removed
    assert "rm -rf -- '/workspace/bu/aa44ec52-ae57-4c73-a574-e824ac649e37'" in seen[0]


def test_remote_termination_waits_for_worker_cleanup(monkeypatch):
    runner = VastRunner()
    calls = []

    async def fake_run_remote(connection, command, **kwargs):
        calls.append((command, kwargs))
        return b"", b""

    monkeypatch.setattr(runner, "_run_remote", fake_run_remote)
    connection = VastConnection("root", "8.8.8.8", 2222)
    run_directory = "/workspace/bu/aa44ec52-ae57-4c73-a574-e824ac649e37"

    asyncio.run(runner._terminate_remote_run(connection, run_directory))

    command, options = calls[0]
    assert "kill -TERM" in command
    assert "seq 1 75" in command
    assert "kill -0" in command
    assert "sleep 2" not in command
    assert options["timeout"] == 90


def test_compatibility_probe_runs_as_unprivileged_user(monkeypatch):
    monkeypatch.setenv("BROWSER_USE_CHROMIUM_PATH", "/opt/google/chrome/chrome")
    runner = VastRunner()
    payload = {
        "status": "verified",
        "browserExecutable": "/opt/google/chrome/chrome",
        "browserUseVersion": "0.13.10",
        "browserVersion": "Chrome/154.0",
        "cpu": {"status": "verified"},
        "gpu": {"status": "verified"},
    }

    async def fake_connection():
        return VastConnection("root", "8.8.8.8", 2222)

    async def fake_sync_project(connection):
        return None

    async def fake_run_remote(connection, command, **kwargs):
        assert "runuser -u browser-capture" in command
        assert "verify_compatibility.py" in command
        assert "egress_boundary" not in command
        return json.dumps(payload).encode(), b""

    monkeypatch.setattr(runner, "connection", fake_connection)
    monkeypatch.setattr(runner, "sync_project", fake_sync_project)
    monkeypatch.setattr(runner, "_run_remote", fake_run_remote)
    assert asyncio.run(runner.check_compatibility())["status"] == "verified"


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
    monkeypatch.setenv("BROWSER_USE_CAPTURE_SSH_KEY", str(tmp_path / "missing-key"))
    with pytest.raises(VastRunnerError, match="identity file is unavailable"):
        VastRunner()._ssh_options()


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


def test_chrome_singleton_socket_fits_linux_unix_socket_path_limit():
    run_id = "707df2a1-f11e-421c-b255-2b0181b13a27"
    socket_path = f"{REMOTE_RUNS}/{run_id}/tmp/.org.chromium.Chromium.XXXXXX/SingletonSocket"
    assert len(socket_path.encode()) < 108


def test_mcp_level_cancellation_finishes_remote_cleanup(monkeypatch, tmp_path):
    runner = VastRunner()
    completed = []

    async def connection():
        return VastConnection("root", "8.8.8.8", 2222)

    async def sync_project(_connection):
        return None

    async def run_remote(_connection, command, **_kwargs):
        if "cat >" in command or "setsid bash" in command:
            return b"", b""
        if "kill -TERM" in command:
            await anyio.sleep(0.01)
            completed.append("terminated")
            return b"", b""
        if "rm -rf" in command:
            await anyio.sleep(0.01)
            completed.append("removed")
            return b"", b""
        scope.cancel()
        await anyio.sleep_forever()

    monkeypatch.setattr(runner, "connection", connection)
    monkeypatch.setattr(runner, "sync_project", sync_project)
    monkeypatch.setattr(runner, "_run_remote", run_remote)

    async def cancel_capture():
        nonlocal scope
        with anyio.CancelScope() as scope:
            await runner.capture({"name": "cancelled", "timeout_ms": 180000}, tmp_path)
        assert scope.cancelled_caught
        assert completed == ["terminated", "removed"]

    scope = None
    anyio.run(cancel_capture)


def test_mcp_level_cancellation_reaps_local_ssh_process(monkeypatch):
    runner = VastRunner()
    signals = []

    class Process:
        returncode = None
        pid = 123

        async def communicate(self, input=None):
            scope.cancel()
            await anyio.sleep_forever()

        async def wait(self):
            await anyio.sleep(0.01)
            self.returncode = -15
            return self.returncode

    process = Process()

    async def create_process(*_args, **_kwargs):
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    monkeypatch.setattr(vast_runner.os, "killpg", lambda pid, sig: signals.append((pid, sig)))

    async def cancel_command():
        nonlocal scope
        with anyio.CancelScope() as scope:
            await runner._run_local(["ssh", "fixture"], timeout=1)
        assert scope.cancelled_caught
        assert process.returncode == -15
        assert signals == [(123, vast_runner.signal.SIGTERM)]

    scope = None
    anyio.run(cancel_command)
