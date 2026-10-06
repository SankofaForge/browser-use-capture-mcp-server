"""Bounded SSH bridge for capture work on the configured Vast.ai GPU runner."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import anyio

REMOTE_ROOT = "/workspace/browser-use-capture"
REMOTE_APP = f"{REMOTE_ROOT}/app"
REMOTE_RUNS = "/workspace/bu"
REMOTE_RUNTIME = f"{REMOTE_ROOT}/runtime"
REMOTE_PYTHON_INSTALL = f"{REMOTE_RUNTIME}/pythons"
REMOTE_VENV = f"{REMOTE_RUNTIME}/venv"
REMOTE_UV_CACHE = f"{REMOTE_RUNTIME}/uv-cache"
REMOTE_PYTHON = f"{REMOTE_PYTHON_INSTALL}/cpython-3.13.15-linux-x86_64-gnu/bin/python3.13"
REMOTE_CAPTURE_USER = "browser-capture"
BROWSER_USE_RUNTIME_ENV = (
    "ANONYMIZED_TELEMETRY=false "
    "BROWSER_USE_CLOUD_SYNC=false "
    "BROWSER_USE_VERSION_CHECK=false"
)
SSH_URL_PATTERN = re.compile(r"ssh://([^@\s]+)@([^:\s]+):(\d+)")
MAX_OUTPUT_BYTES = 32 * 1024
CAPTURE_FINALIZATION_SECONDS = 300
SSH_READINESS_TIMEOUT_SECONDS = 30
SSH_READINESS_RETRY_INTERVAL_SECONDS = 1
SSH_READINESS_PROBE_TIMEOUT_SECONDS = 8
VAST_STATUS_QUERY_TIMEOUT_SECONDS = 10


class VastRunnerError(RuntimeError):
    def __init__(self, reason_code: str, message: str, diagnostic: str | None = None):
        super().__init__(message)
        self.reason_code = reason_code
        self.diagnostic = diagnostic


@dataclass(frozen=True)
class VastConnection:
    user: str
    host: str
    port: int


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def _safe_output(output: bytes | str) -> str:
    text = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else output
    text = re.sub(r"(?i)(authorization|api[_-]?key|token|secret|password|cookie)(\s*[:=]\s*)\S+", r"\1\2[REDACTED]", text)
    return text[-MAX_OUTPUT_BYTES:]


class VastRunner:
    def __init__(self, package_root: Path | None = None):
        self.package_root = package_root or Path(__file__).resolve().parents[2]
        self.instance_id = os.environ.get("VAST_INSTANCE_ID", "")
        self.browser_path = os.environ.get("BROWSER_USE_CHROMIUM_PATH", "")
        self.ssh_key = os.environ.get("BROWSER_USE_CAPTURE_SSH_KEY")

    def validate_configuration(self) -> None:
        if not re.fullmatch(r"[0-9]{1,20}", self.instance_id):
            raise VastRunnerError("vast-instance-unconfigured", "VAST_INSTANCE_ID must be a numeric instance ID")
        if not os.environ.get("VAST_API_KEY"):
            raise VastRunnerError("vast-api-key-unavailable", "VAST_API_KEY must be injected by the local secret environment")
        if not self.browser_path.startswith("/") or "\x00" in self.browser_path:
            raise VastRunnerError("browser-executable-unconfigured", "BROWSER_USE_CHROMIUM_PATH must be an absolute path on the remote runner")
        for tool in ("ssh", "scp"):
            if shutil.which(tool) is None:
                raise VastRunnerError("ssh-client-unavailable", f"The local {tool} client is unavailable")
        if self._vast_cli() is None:
            raise VastRunnerError("vast-cli-unavailable", "The Vast.ai CLI is unavailable")

    @staticmethod
    def build_worker_input(capture: dict[str, Any], run_id: str, run_directory: str) -> dict[str, Any]:
        if capture.get("gpu", True) is not True:
            raise VastRunnerError("capture-gpu-required", "Authoritative Browser Use capture requires gpu=true")
        worker_input = {
            key: value for key, value in capture.items()
            if key not in {"gpu", "no_scroll", "tail_lines"}
        }
        worker_input.update({
            "run_id": run_id,
            "output_dir": f"{run_directory}/artifacts",
            "scroll": not capture.get("no_scroll", False),
            "tail_ms": capture.get("tail_lines", 800),
        })
        return worker_input

    @staticmethod
    def _vast_cli() -> str | None:
        detected = shutil.which("vastai")
        if detected:
            return detected
        candidate = Path.home() / ".local" / "bin" / "vastai"
        return str(candidate) if candidate.is_file() and os.access(candidate, os.X_OK) else None

    def _ssh_options(self) -> list[str]:
        args = [
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=15",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=2",
        ]
        key = Path(self.ssh_key).expanduser() if self.ssh_key else Path.home() / ".ssh" / "id_ed25519"
        if not key.is_file():
            raise VastRunnerError("ssh-key-unavailable", "The configured Vast SSH identity file is unavailable")
        args.extend(["-i", str(key), "-o", "IdentitiesOnly=yes"])
        return args

    def _ssh_args(self, connection: VastConnection, command: str) -> list[str]:
        return [
            "ssh",
            *self._ssh_options(),
            "-p", str(connection.port),
            f"{connection.user}@{connection.host}",
            command,
        ]

    def _browser_environment(self) -> str:
        return (
            f"{BROWSER_USE_RUNTIME_ENV} "
            f"BROWSER_USE_DISABLE_SANDBOX={'1' if os.environ.get('BROWSER_USE_DISABLE_SANDBOX') == '1' else '0'} "
            f"PYTHONDONTWRITEBYTECODE=1 "
            f"BROWSER_USE_CHROMIUM_PATH={_shell_quote(self.browser_path)}"
        )

    def _scp_args(
        self,
        connection: VastConnection,
        sources: list[Path],
        remote_directory: str,
    ) -> list[str]:
        if remote_directory not in {"", "scripts", "remote"}:
            raise VastRunnerError("capture-worker-unavailable", "The worker transfer destination is not approved")
        return [
            "scp", "-p", *self._ssh_options(),
            "-P", str(connection.port),
            *(str(path) for path in sources),
            f"{connection.user}@{connection.host}:{REMOTE_APP}/{remote_directory}",
        ]

    async def connection(self) -> VastConnection:
        self.validate_configuration()
        process = await asyncio.create_subprocess_exec(
            self._vast_cli() or "vastai",
            "ssh-url",
            self.instance_id,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=os.environ.copy(),
            start_new_session=True,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            await self._terminate_process(process)
            raise
        if process.returncode != 0:
            raise VastRunnerError("vast-connection-unavailable", "Vast.ai could not resolve the configured SSH endpoint")
        match = SSH_URL_PATTERN.search(stdout.decode("utf-8", errors="replace"))
        if not match:
            raise VastRunnerError("vast-connection-invalid", "Vast.ai returned an invalid SSH endpoint")
        user, host, raw_port = match.groups()
        if user != "root":
            raise VastRunnerError("vast-connection-invalid", "Vast.ai returned a non-public or unexpected SSH endpoint")
        try:
            address = ipaddress.ip_address(host)
            if not address.is_global:
                raise VastRunnerError("vast-connection-invalid", "Vast.ai returned a non-public SSH endpoint")
            host = str(address)
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host) or not host.lower().endswith(".vast.ai"):
                raise VastRunnerError("vast-connection-invalid", "Vast.ai returned an unexpected SSH host")
            try:
                addresses = {item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
            except OSError as error:
                raise VastRunnerError("vast-connection-invalid", "Vast.ai SSH hostname could not be resolved safely") from error
            if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
                raise VastRunnerError("vast-connection-invalid", "Vast.ai SSH hostname resolved to a non-public address")
        port = int(raw_port)
        if not 1 <= port <= 65535:
            raise VastRunnerError("vast-connection-invalid", "Vast.ai returned an invalid SSH port")
        return VastConnection(user=user, host=host, port=port)

    @staticmethod
    async def _terminate_process(process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        with anyio.CancelScope(shield=True):
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                return
            try:
                await asyncio.wait_for(process.wait(), timeout=3)
            except asyncio.TimeoutError:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await process.wait()

    async def _run_local(
        self,
        command: list[str],
        *,
        timeout: float,
        input_data: bytes | None = None,
        error_code: str = "vast-remote-command-failed",
    ) -> tuple[bytes, bytes]:
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE if input_data is not None else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={key: value for key, value in os.environ.items() if key != "VAST_API_KEY"},
                start_new_session=True,
            )
        except OSError as error:
            raise VastRunnerError(error_code, "Could not start the required local runner command", _safe_output(str(error))) from error
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(input=input_data), timeout=timeout)
        except asyncio.TimeoutError as error:
            await self._terminate_process(process)
            raise VastRunnerError("vast-command-timeout", "The remote runner command exceeded its timeout") from error
        except asyncio.CancelledError:
            await self._terminate_process(process)
            raise
        if process.returncode != 0:
            diagnostic = _safe_output(stdout + b"\n" + stderr)
            raise VastRunnerError(error_code, "The remote runner command failed", diagnostic)
        return stdout, stderr

    async def _run_remote(
        self,
        connection: VastConnection,
        command: str,
        *,
        timeout: float = 60,
        input_data: bytes | None = None,
        error_code: str = "vast-remote-command-failed",
    ) -> tuple[bytes, bytes]:
        return await self._run_local(
            self._ssh_args(connection, command),
            timeout=timeout,
            input_data=input_data,
            error_code=error_code,
        )

    async def _provider_state(self) -> tuple[str, str | None]:
        try:
            process = await asyncio.create_subprocess_exec(
                self._vast_cli() or "vastai",
                "show",
                "instance",
                self.instance_id,
                "--raw",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=os.environ.copy(),
                start_new_session=True,
            )
        except OSError as error:
            return "unknown", _safe_output(str(error))

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=VAST_STATUS_QUERY_TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            await self._terminate_process(process)
            return "unknown", "Vast instance status query timed out"
        except asyncio.CancelledError:
            await self._terminate_process(process)
            raise

        if process.returncode != 0:
            diagnostic = _safe_output(stdout + b"\n" + stderr)
            return "unknown", diagnostic or "Vast instance status query failed"
        try:
            result = json.loads(stdout)
        except (json.JSONDecodeError, UnicodeDecodeError):
            diagnostic = _safe_output(stdout + b"\n" + stderr)
            return "unknown", diagnostic or "Vast instance status response was invalid"
        if not isinstance(result, dict):
            return "unknown", "Vast instance status response was not an object"

        state = result.get("actual_status") or result.get("cur_state") or result.get("status")
        if not isinstance(state, str) or not state.strip():
            return "unknown", "Vast instance status response did not include a state"
        return state.strip(), None

    async def _wait_for_ssh(self, connection: VastConnection) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + SSH_READINESS_TIMEOUT_SECONDS
        last_diagnostic = "SSH readiness probe did not return a diagnostic"
        while True:
            try:
                await self._run_remote(
                    connection,
                    "true",
                    timeout=SSH_READINESS_PROBE_TIMEOUT_SECONDS,
                    error_code="runner-not-ready",
                )
                return
            except asyncio.CancelledError:
                raise
            except VastRunnerError as error:
                if error.reason_code not in {"runner-not-ready", "vast-command-timeout"}:
                    raise
                last_diagnostic = error.diagnostic or str(error)

            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            await asyncio.sleep(min(SSH_READINESS_RETRY_INTERVAL_SECONDS, remaining))

        provider_state, provider_diagnostic = await self._provider_state()
        diagnostic = f"Provider state: {provider_state}; SSH diagnostic: {last_diagnostic}"
        if provider_diagnostic:
            diagnostic += f"; provider status diagnostic: {provider_diagnostic}"
        raise VastRunnerError(
            "runner-not-ready",
            "The configured Vast runner is not ready for SSH",
            _safe_output(diagnostic),
        )

    async def sync_project(self, connection: VastConnection) -> None:
        required = [
            self.package_root / "pyproject.toml",
            self.package_root / "uv.lock",
            self.package_root / "scripts" / "verify_compatibility.py",
            self.package_root / "remote" / "capture_worker.py",
        ]
        missing = [path.name for path in required if not path.is_file()]
        if missing:
            raise VastRunnerError("capture-worker-unavailable", "The local capture package is incomplete", ", ".join(missing))
        await self._wait_for_ssh(connection)
        await self._run_remote(
            connection,
            f"mkdir -p {_shell_quote(REMOTE_APP)} {_shell_quote(REMOTE_APP + '/scripts')} "
            f"{_shell_quote(REMOTE_APP + '/remote')} {_shell_quote(REMOTE_RUNS)}",
            timeout=30,
            error_code="vast-project-provision-failed",
        )
        transfer_groups = (
            ([self.package_root / "pyproject.toml", self.package_root / "uv.lock"], ""),
            ([self.package_root / "scripts" / "verify_compatibility.py"], "scripts"),
            ([self.package_root / "remote" / "capture_worker.py"], "remote"),
        )
        for sources, remote_directory in transfer_groups:
            await self._run_local(
                self._scp_args(connection, sources, remote_directory),
                timeout=90,
                error_code="vast-project-transfer-failed",
            )
        provision_capture_user = (
            f"if ! getent passwd {REMOTE_CAPTURE_USER} >/dev/null 2>&1; then "
            f"useradd --system --no-create-home --shell /usr/sbin/nologin {REMOTE_CAPTURE_USER}; fi; "
            f"test \"$(id -u {REMOTE_CAPTURE_USER})\" -gt 0 && "
            f"install -d -m 0700 -o {REMOTE_CAPTURE_USER} -g {REMOTE_CAPTURE_USER} "
            f"{_shell_quote(REMOTE_RUNS)} {_shell_quote(REMOTE_ROOT + '/state')} && "
            f"install -d -m 0755 -o root -g root {_shell_quote(REMOTE_ROOT + '/component-cache')}"
        )
        await self._run_remote(
            connection,
            provision_capture_user,
            timeout=30,
            error_code="capture-user-provision-failed",
        )
        provision_runtime = (
            f"install -d -m 0755 -o root -g root {_shell_quote(REMOTE_RUNTIME)} "
            f"{_shell_quote(REMOTE_PYTHON_INSTALL)} {_shell_quote(REMOTE_UV_CACHE)}; "
            f"UV_PYTHON_INSTALL_DIR={_shell_quote(REMOTE_PYTHON_INSTALL)} "
            f"UV_CACHE_DIR={_shell_quote(REMOTE_UV_CACHE)} "
            f"uv python install 3.13.15 --reinstall --install-dir {_shell_quote(REMOTE_PYTHON_INSTALL)}; "
            f"cd {_shell_quote(REMOTE_APP)} && "
            f"UV_PYTHON_INSTALL_DIR={_shell_quote(REMOTE_PYTHON_INSTALL)} "
            f"UV_CACHE_DIR={_shell_quote(REMOTE_UV_CACHE)} "
            f"UV_PROJECT_ENVIRONMENT={_shell_quote(REMOTE_VENV)} "
            f"uv sync --locked --extra test --no-install-project --python {_shell_quote(REMOTE_PYTHON)} && "
            f"chmod -R a+rX {_shell_quote(REMOTE_RUNTIME)}"
        )
        await self._run_remote(
            connection,
            provision_runtime,
            timeout=900,
            error_code="vast-dependencies-unavailable",
        )

    @staticmethod
    def _last_json_line(output: bytes) -> dict[str, Any]:
        for line in reversed(output.decode("utf-8", errors="replace").splitlines()):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                return payload
        raise VastRunnerError("remote-result-invalid", "The remote runner did not return a JSON result", _safe_output(output))

    async def check_compatibility(self) -> dict[str, Any]:
        connection = await self.connection()
        await self.sync_project(connection)
        probe_directory = f"{REMOTE_RUNS}/{uuid.uuid4()}"
        command = (
            f"install -d -m 0700 -o {REMOTE_CAPTURE_USER} -g {REMOTE_CAPTURE_USER} "
            f"{_shell_quote(probe_directory)} {_shell_quote(probe_directory + '/home')} "
            f"{_shell_quote(probe_directory + '/tmp')}; "
            f"cd {_shell_quote(probe_directory)} && "
            f"runuser -u {REMOTE_CAPTURE_USER} -- env "
            f"HOME={_shell_quote(probe_directory + '/home')} "
            f"TMPDIR={_shell_quote(probe_directory + '/tmp')} "
            f"{self._browser_environment()} "
            f"timeout --signal=TERM --kill-after=5s 120s {_shell_quote(REMOTE_VENV + '/bin/python')} "
            f"{_shell_quote(REMOTE_APP + '/scripts/verify_compatibility.py')}; "
            "code=$?; "
            f"rm -rf -- {_shell_quote(probe_directory)}; "
            "exit \"$code\""
        )
        try:
            stdout, _ = await self._run_remote(
                connection, command, timeout=140,
                error_code="browser-use-compatibility-unverified",
            )
            payload = self._last_json_line(stdout)
        except VastRunnerError as error:
            if error.reason_code != "browser-use-compatibility-unverified":
                raise
            payload = self._last_json_line(error.diagnostic.encode("utf-8") if error.diagnostic else b"")
        payload["vastInstanceId"] = self.instance_id
        cpu = payload.get("cpu", {})
        gpu = payload.get("gpu", {})
        if payload.get("browserExecutable") != self.browser_path:
            payload["status"] = "blocked"
            payload["failureReason"] = "compatibility result did not match configured browser executable"
        elif cpu.get("status") != "verified" or gpu.get("status") != "verified":
            payload["status"] = "blocked"
            payload["failureReason"] = payload.get("failureReason") or "CPU and GPU checks did not both pass"
        elif not payload.get("browserUseVersion") or not payload.get("browserVersion"):
            payload["status"] = "blocked"
            payload["failureReason"] = "compatibility result omitted a Browser Use or browser version"
        return payload

    async def _copy_remote_files(self, connection: VastConnection, remote_paths: list[str], local_directory: Path) -> None:
        if not remote_paths or any(
            not re.fullmatch(r"/workspace/bu/[0-9a-f-]{36}/(?:artifacts/)?[A-Za-z0-9._-]{1,120}", path)
            for path in remote_paths
        ):
            raise VastRunnerError("capture-artifact-transfer-failed", "The remote artifact list is invalid")
        command = [
            "scp", "-p", *self._ssh_options(), "-P", str(connection.port),
            *(f"{connection.user}@{connection.host}:{path}" for path in remote_paths),
            str(local_directory) + "/",
        ]
        await self._run_local(command, timeout=270, error_code="capture-artifact-transfer-failed")

    async def _terminate_remote_run(self, connection: VastConnection, run_directory: str) -> None:
        if not re.fullmatch(r"/workspace/bu/[0-9a-f-]{36}", run_directory):
            return
        pid_path = f"{run_directory}/worker.pid"
        command = (
            f"if test -s {_shell_quote(pid_path)}; then "
            f"pid=$(cat {_shell_quote(pid_path)}); "
            "case \"$pid\" in (*[!0-9]*|'') exit 2;; esac; "
            "kill -TERM -- \"-$pid\" 2>/dev/null || true; "
            "for attempt in $(seq 1 75); do "
            "kill -0 -- \"-$pid\" 2>/dev/null || exit 0; sleep 1; done; "
            "kill -KILL -- \"-$pid\" 2>/dev/null || true; fi"
        )
        try:
            await self._run_remote(connection, command, timeout=90)
        except (VastRunnerError, asyncio.CancelledError):
            pass

    async def _remove_remote_run(self, connection: VastConnection, run_directory: str) -> bool:
        if not re.fullmatch(r"/workspace/bu/[0-9a-f-]{36}", run_directory):
            return False
        try:
            await self._run_remote(connection, f"rm -rf -- {_shell_quote(run_directory)}", timeout=30)
            return True
        except (VastRunnerError, asyncio.CancelledError):
            return False

    async def capture(self, capture: dict[str, Any], local_stage: Path) -> dict[str, Any]:
        connection = await self.connection()
        await self.sync_project(connection)
        run_id = str(uuid.uuid4())
        run_directory = f"{REMOTE_RUNS}/{run_id}"
        remote_input = f"{run_directory}/input.json"
        remote_result = f"{run_directory}/result.json"
        remote_exit = f"{run_directory}/worker.exit"
        remote_pid = f"{run_directory}/worker.pid"
        artifact_directory = f"{run_directory}/artifacts"
        worker_input = self.build_worker_input(capture, run_id, run_directory)
        input_json = json.dumps(worker_input, separators=(",", ":")).encode()
        worker_command = (
            f"cd {_shell_quote(run_directory)}; "
            "set +e; "
            f"runuser -u {REMOTE_CAPTURE_USER} -- env "
            f"HOME={_shell_quote(run_directory + '/home')} "
            f"TMPDIR={_shell_quote(run_directory + '/tmp')} "
            f"{self._browser_environment()} "
            f"timeout --signal=TERM --kill-after=5s {capture['timeout_ms'] // 1000}s "
            f"{_shell_quote(REMOTE_VENV + '/bin/python')} "
            f"{_shell_quote(REMOTE_APP + '/remote/capture_worker.py')} "
            f"< {_shell_quote(remote_input)} > {_shell_quote(remote_result)} "
            f"2> {_shell_quote(run_directory + '/worker.log')}; "
            "code=$?; "
            f"printf '%s\\n' \"$code\" > {_shell_quote(remote_exit)}; "
            "exit \"$code\""
        )
        launch_command = (
            f"umask 077; setsid bash -c {_shell_quote(worker_command)} </dev/null >/dev/null 2>&1 & "
            "launcher=$!; "
            f"printf '%s\\n' \"$launcher\" > {_shell_quote(remote_pid)}; "
            "printf 'started\\n'"
        )
        try:
            await self._run_remote(
                connection,
                f"install -d -m 0700 -o {REMOTE_CAPTURE_USER} -g {REMOTE_CAPTURE_USER} "
                f"{_shell_quote(run_directory)} "
                f"{_shell_quote(run_directory + '/home')} "
                f"{_shell_quote(run_directory + '/tmp')} "
                f"{_shell_quote(run_directory + '/uv-cache')}; "
                f"cat > {_shell_quote(remote_input)}; "
                f"chown {REMOTE_CAPTURE_USER}:{REMOTE_CAPTURE_USER} {_shell_quote(remote_input)}; "
                f"chmod 0600 {_shell_quote(remote_input)}",
                timeout=30,
                input_data=input_json,
                error_code="capture-input-transfer-failed",
            )
            await self._run_remote(connection, launch_command, timeout=20, error_code="capture-launch-failed")
            wait_command = (
                f"for attempt in $(seq 1 {max(1, capture['timeout_ms'] // 1000 + CAPTURE_FINALIZATION_SECONDS + 20)}); do "
                f"test -f {_shell_quote(remote_exit)} && break; sleep 1; done; "
                f"test -f {_shell_quote(remote_exit)} || exit 124; "
                f"cat {_shell_quote(remote_exit)}; "
                f"cat {_shell_quote(remote_result)}"
            )
            stdout, _ = await self._run_remote(
                connection,
                wait_command,
                timeout=capture["timeout_ms"] / 1000 + CAPTURE_FINALIZATION_SECONDS + 30,
                error_code="capture-worker-failed",
            )
            lines = stdout.decode("utf-8", errors="replace").splitlines()
            if not lines or not lines[0].isdigit():
                raise VastRunnerError("capture-result-invalid", "The remote capture worker did not return an exit status")
            exit_code = int(lines[0])
            result = self._last_json_line("\n".join(lines[1:]).encode())
            if exit_code != 0 and result.get("status") not in {"blocked", "partial"}:
                raise VastRunnerError("capture-worker-failed", "The remote capture worker failed", _safe_output(result.get("failureReason", "")))
            artifact_names = result.get("artifacts") if isinstance(result.get("artifacts"), dict) else {}
            allowed_names = {
                "manifest": "manifest.json",
                "webm": f"{capture['name']}.webm",
                "jank": f"{capture['name']}.jank.json",
            }
            remote_paths = []
            transferred: dict[str, str] = {}
            for key, expected_name in allowed_names.items():
                reported_name = artifact_names.get(key)
                if reported_name != expected_name:
                    continue
                remote_path = f"{artifact_directory}/{expected_name}"
                exists, _ = await self._run_remote(
                    connection,
                    f"if test -f {_shell_quote(remote_path)} && test ! -L {_shell_quote(remote_path)}; then printf present; else printf absent; fi",
                    timeout=15,
                    error_code="capture-artifact-transfer-failed",
                )
                if exists.strip() == b"present":
                    remote_paths.append(remote_path)
                    transferred[key] = expected_name
            if remote_paths:
                try:
                    await self._copy_remote_files(connection, remote_paths, local_stage)
                except VastRunnerError as error:
                    transferred = {
                        key: filename for key, filename in transferred.items()
                        if (local_stage / filename).is_file() and not (local_stage / filename).is_symlink()
                    }
                    previous_reason = result.get("failureReason")
                    result["status"] = "partial"
                    result["reasonCode"] = "capture-artifact-transfer-failed"
                    result["failureReason"] = _safe_output(
                        f"{previous_reason or 'capture evidence incomplete'}; artifact transfer failed: {error}"
                    )
                    result["localArtifacts"] = transferred
                    return result
            result["localArtifacts"] = transferred
            return result
        except BaseException:
            with anyio.CancelScope(shield=True):
                await self._terminate_remote_run(connection, run_directory)
            raise
        finally:
            with anyio.CancelScope(shield=True):
                removed = await self._remove_remote_run(connection, run_directory)
            if "result" in locals() and isinstance(result, dict):
                result["remoteCleanup"] = "confirmed" if removed else "pending"
