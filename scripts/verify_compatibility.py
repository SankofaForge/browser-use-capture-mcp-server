"""Run the fail-closed Browser Use runtime compatibility probe."""

from __future__ import annotations

import argparse
import asyncio
import importlib.metadata
import ipaddress
import json
import os
import re
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
from collections.abc import Coroutine
from contextlib import suppress
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import aiohttp

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "remote"))
from capture_worker import _clean_chrome_args, _load_egress_attestation, _seed_profile_preflight_assets
from public_socks_proxy import (
    COMPATIBILITY_SERVICE_HOSTS,
    REVIEWED_EGRESS_HOSTS,
    REVIEWED_EGRESS_TTL_SECONDS,
    PublicSocksProxy,
)


STARTUP_TIMEOUT_SECONDS = 30
COMMAND_TIMEOUT_SECONDS = 5
VERIFY_TIMEOUT_SECONDS = 110
SERVICE_CHECK_TIMEOUT_SECONDS = 25
PRE_FIXTURE_OBSERVATION_SECONDS = 3
PROBE_URL = "https://example.com"
GPU_ARGS = [
    "--disable-dev-shm-usage",
    "--use-gl=angle",
    "--use-angle=gl-egl",
    "--enable-gpu-rasterization",
    "--enable-zero-copy",
    "--ignore-gpu-blocklist",
]
JANK_OBSERVER = """
(() => {
  window.__browserUseCaptureJank = [];
  window.__browserUseCaptureJankObserverError = null;
  try {
    const observer = new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        window.__browserUseCaptureJank.push({ startTime: entry.startTime, duration: entry.duration });
      }
    });
    observer.observe({ type: "longtask", buffered: true });
  } catch (error) {
    window.__browserUseCaptureJankObserverError = String(error);
  }
})();
"""


def _browser_path() -> Path:
    configured = os.environ.get("BROWSER_USE_CHROMIUM_PATH")
    if not configured:
        raise RuntimeError("BROWSER_USE_CHROMIUM_PATH is not set")
    path = Path(configured).expanduser()
    if not path.is_absolute():
        raise RuntimeError("BROWSER_USE_CHROMIUM_PATH must be absolute")
    if not path.is_file():
        raise RuntimeError(f"browser executable does not exist: {path}")
    if not os.access(path, os.X_OK):
        raise RuntimeError(f"browser executable is not executable: {path}")
    try:
        with path.open("rb") as executable_file:
            executable_header = executable_file.read(4)
    except OSError as error:
        raise RuntimeError("browser executable could not be inspected") from error
    if executable_header != b"\x7fELF":
        raise RuntimeError("browser path is not a direct Linux ELF executable; launcher scripts and Snap shims are rejected")
    try:
        version = subprocess.run(
            [str(path), "--version"], capture_output=True, check=False,
            text=True, timeout=COMMAND_TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("browser --version timed out") from error
    output = f"{version.stdout}\n{version.stderr}".lower()
    snap_markers = ("requires the chromium snap", "snap install chromium", "command not found")
    if version.returncode != 0 or any(marker in output for marker in snap_markers):
        raise RuntimeError("browser path is not a runnable non-Snap Chromium executable")
    return path.resolve()


def _browser_use_version() -> str:
    try:
        return importlib.metadata.version("browser-use")
    except importlib.metadata.PackageNotFoundError as error:
        raise RuntimeError("browser-use package metadata is unavailable") from error


def _browser_binary_version(executable: Path) -> str:
    result = subprocess.run(
        [str(executable), "--version"],
        capture_output=True,
        text=True,
        timeout=COMMAND_TIMEOUT_SECONDS,
        check=False,
    )
    output = f"{result.stdout}\n{result.stderr}".strip()
    match = re.search(r"\d+(?:\.\d+){2,3}", output)
    if result.returncode or not match:
        raise RuntimeError("configured browser version string is not recognized")
    return match.group(0)


def _browser_use_version_or_none() -> str | None:
    try:
        return _browser_use_version()
    except RuntimeError:
        return None


def _allowed_url(raw_url: str, allowed_domains: list[str]) -> bool:
    hostname = urlparse(raw_url).hostname
    if not hostname:
        return False
    hostname = hostname.lower().rstrip(".")
    return any(hostname == domain or hostname.endswith(f".{domain}") for domain in allowed_domains)


def _gpu_status(renderer: str | None) -> dict[str, str]:
    if not renderer:
        return {"status": "blocked", "reason": "WebGL renderer was unavailable"}
    lowered = renderer.lower()
    if any(marker in lowered for marker in ("swiftshader", "llvmpipe", "software rasterizer")):
        return {"status": "blocked", "reason": f"software WebGL renderer: {renderer}"}
    if not any(marker in lowered for marker in ("nvidia", "geforce", "quadro", "tesla")):
        return {"status": "blocked", "reason": f"WebGL renderer is not identified as NVIDIA hardware: {renderer}"}
    if shutil.which("nvidia-smi") is None:
        return {"status": "blocked", "reason": "nvidia-smi is unavailable"}
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader"],
            capture_output=True, check=False, text=True, timeout=COMMAND_TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired:
        return {"status": "blocked", "reason": "nvidia-smi timed out"}
    if result.returncode != 0 or not result.stdout.strip():
        return {"status": "blocked", "reason": "no NVIDIA GPU was detected"}
    if "nvidia" not in result.stdout.lower() and "geforce" not in result.stdout.lower():
        return {"status": "blocked", "reason": "nvidia-smi did not report an NVIDIA device"}
    return {"status": "verified", "renderer": renderer, "device": result.stdout.strip()}


def _overall_failure_reason(
    cpu_status: str,
    gpu: dict[str, Any],
    cpu_failure_reason: str | None = None,
    egress_policy: dict[str, Any] | None = None,
) -> str | None:
    if cpu_status != "verified":
        return cpu_failure_reason or "one or more CPU compatibility checks failed"
    if gpu.get("status") != "verified":
        return str(gpu.get("reason") or "NVIDIA/WebGL compatibility checks failed")
    if egress_policy is not None and egress_policy.get("status") != "verified":
        return str(egress_policy.get("failureReason") or "SOCKS egress policy checks did not pass")
    return None


def _egress_snapshot(proxy: PublicSocksProxy | None) -> dict[str, list[dict[str, Any]]]:
    if proxy is None:
        return {"blockedDestinations": [], "connectionOutcomes": []}
    return {
        "blockedDestinations": [dict(entry) for entry in proxy.blocked_destinations],
        "connectionOutcomes": [dict(entry) for entry in proxy.connection_outcomes],
    }


def _snapshot_delta(
    before: dict[str, list[dict[str, Any]]],
    after: dict[str, list[dict[str, Any]]],
) -> dict[str, list[dict[str, Any]]]:
    before_counts = {
        (entry["hostname"], entry["port"], entry["outcome"]): entry["count"]
        for entry in before["connectionOutcomes"]
    }
    outcome_delta = []
    for entry in after["connectionOutcomes"]:
        key = (entry["hostname"], entry["port"], entry["outcome"])
        count = entry["count"] - before_counts.get(key, 0)
        if count > 0:
            outcome_delta.append({**entry, "count": count})
    before_destinations = {
        (entry["hostname"], entry["port"], entry["reason"])
        for entry in before["blockedDestinations"]
    }
    destination_delta = [
        dict(entry)
        for entry in after["blockedDestinations"]
        if (entry["hostname"], entry["port"], entry["reason"]) not in before_destinations
    ]
    return {
        "blockedDestinations": destination_delta,
        "connectionOutcomes": outcome_delta,
    }


def _egress_policy_result(
    proxy: PublicSocksProxy | None,
    proxy_policy_verified: bool,
    pre_fixture_observations: dict[str, list[dict[str, Any]]] | None,
    browser_traffic_boundary: str = "unverified",
    network_namespace_inode: int | None = None,
    browser_network_namespace_inode: int | None = None,
    browser_service_checks: dict[str, Any] | None = None,
) -> dict[str, Any]:
    expected_denials = {"domain-not-approved"}
    unexpected_violations = sorted(set(proxy.violations if proxy else []) - expected_denials)
    unexpected_blocked_destinations = [
        dict(entry)
        for entry in (proxy.blocked_destinations if proxy else [])
        if proxy is not None and not proxy._destination_is_approved(entry["hostname"], entry["port"])
    ]
    if unexpected_blocked_destinations:
        unexpected_violations.append("unexpected-destination-attempt")
        unexpected_violations.sort()
    unauthorized_connections = [
        dict(entry)
        for entry in (proxy.connection_outcomes if proxy else [])
        if entry["outcome"] == "connected"
        and proxy is not None
        and not proxy._destination_is_approved(entry["hostname"], entry["port"])
    ]
    proxy_status = (
        "verified"
        if proxy_policy_verified and not unexpected_violations and not unauthorized_connections
        else "blocked"
    )
    service_check_status = browser_service_checks.get("status") if isinstance(browser_service_checks, dict) else "blocked"
    service_status = "unverified" if service_check_status == "verified" else "blocked"
    status = "blocked" if (
        proxy_status != "verified"
        or browser_traffic_boundary == "blocked"
        or service_check_status == "blocked"
    ) else "unverified"
    failure_reason = None
    if not proxy_policy_verified:
        failure_reason = "The SOCKS proxy did not block private and unapproved destinations."
    elif unauthorized_connections:
        failure_reason = "The SOCKS proxy connected to an unapproved destination."
    elif unexpected_violations:
        failure_reason = "The SOCKS proxy reported an unexpected connection error."
    elif browser_traffic_boundary == "blocked":
        failure_reason = "The browser process did not match the verified network namespace."
    elif service_check_status != "verified":
        failure_reason = "Browser Safe Browsing and component updater checks did not both pass."
    elif browser_traffic_boundary == "verified":
        failure_reason = "Root runner service host outcomes have not yet been verified."
    else:
        failure_reason = (
            "The browser traffic boundary and browser service checks are not verified."
        )

    current = _egress_snapshot(proxy)
    baseline = pre_fixture_observations or {"blockedDestinations": [], "connectionOutcomes": []}
    return {
        "status": status,
        "failureReason": failure_reason,
        "policy": "exact-host-public-socks-proxy",
        "proxyPolicyCheck": proxy_status,
        "browserTrafficBoundary": browser_traffic_boundary,
        "browserServiceReachability": service_status,
        "browserServiceChecks": browser_service_checks or {"status": "blocked", "checks": []},
        "networkNamespaceInode": network_namespace_inode,
        "browserNetworkNamespaceInode": browser_network_namespace_inode,
        "unexpectedViolationCodes": unexpected_violations,
        "unauthorizedConnections": unauthorized_connections,
        "blockedDestinations": current["blockedDestinations"],
        "connectionOutcomes": current["connectionOutcomes"],
        "preFixtureObservations": baseline,
        "afterFixtureDelta": _snapshot_delta(baseline, current),
        "requestAttribution": {
            "status": "unknown",
            "urlPathsCollected": False,
            "initiatorsCollected": False,
            "phaseObservationsIdentifyInitiators": False,
        },
    }


async def _wait_for_cdp(process: asyncio.subprocess.Process, port: int) -> tuple[str, str, str]:
    started = asyncio.get_running_loop().time()
    async with aiohttp.ClientSession() as client:
        while asyncio.get_running_loop().time() - started < STARTUP_TIMEOUT_SECONDS:
            if process.returncode is not None:
                stderr = b""
                if process.stderr is not None:
                    with suppress(asyncio.TimeoutError):
                        _, stderr = await asyncio.wait_for(process.communicate(), timeout=1)
                raise RuntimeError(f"browser exited before CDP became ready: {stderr.decode(errors='replace')[-800:]}")
            try:
                async with client.get(f"http://127.0.0.1:{port}/json/version") as response:
                    if response.status == 200:
                        payload = await response.json()
                        websocket_url = payload.get("webSocketDebuggerUrl")
                        browser_version = payload.get("Browser")
                        if isinstance(websocket_url, str) and isinstance(browser_version, str):
                            return f"http://127.0.0.1:{port}/", browser_version, websocket_url
            except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError):
                pass
            await asyncio.sleep(0.1)
    raise TimeoutError(f"browser did not reach CDP within {STARTUP_TIMEOUT_SECONDS} seconds")


async def _launch_browser(
    browser_path: Path,
    profile: Any,
    port: int,
    proxy_port: int,
    profile_dir: Path,
    proxy_host: str = "127.0.0.1",
) -> tuple[asyncio.subprocess.Process, str, str, str]:
    args = _clean_chrome_args(profile.get_args(), port, proxy_port, profile_dir, proxy_host=proxy_host)
    process = await asyncio.create_subprocess_exec(
        str(browser_path),
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    try:
        cdp_url, browser_version, websocket_url = await _wait_for_cdp(process, port)
    except BaseException:
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        with suppress(Exception):
            await process.wait()
        raise
    return process, cdp_url, browser_version, websocket_url


async def _stop_process(process: asyncio.subprocess.Process | None) -> str:
    if process is None:
        return "missing"
    if process.returncode is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            await process.wait()
            return "terminated"
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except asyncio.TimeoutError:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await process.wait()
    return "terminated"


async def _kill_session(session: Any) -> None:
    kill = getattr(session, "kill", None)
    if not callable(kill):
        raise RuntimeError("BrowserSession.kill() is unavailable")
    await asyncio.wait_for(kill(), timeout=5)


async def _await_cleanup(cleanup: Coroutine[Any, Any, None]) -> None:
    cleanup_task = asyncio.create_task(cleanup)
    cancellation_received = False
    while not cleanup_task.done():
        try:
            await asyncio.shield(cleanup_task)
        except asyncio.CancelledError:
            if cleanup_task.cancelled():
                raise
            cancellation_received = True
    cleanup_task.result()
    if cancellation_received:
        raise asyncio.CancelledError


async def _page_cdp_transport(page: Any) -> tuple[Any, str]:
    client = getattr(page, "_client", None)
    if client is None:
        raise RuntimeError("Browser Use page CDP client is unavailable")
    session_id = await page.session_id
    return client, session_id


class _CDPScreenshotClient:
    """Capture page frames through CDP and feed Browser Use's video recorder."""

    def __init__(self, websocket: Any, session_id: str):
        self.websocket = websocket
        self.session_id = session_id
        self.next_id = 1

    async def capture_png_base64(self) -> str:
        request_id = self.next_id
        self.next_id += 1
        await self.websocket.send_json({
            "id": request_id,
            "method": "Page.captureScreenshot",
            "params": {"format": "png", "fromSurface": True, "captureBeyondViewport": False},
            "sessionId": self.session_id,
        })
        while True:
            message = await asyncio.wait_for(self.websocket.receive_json(), timeout=5)
            if message.get("id") != request_id:
                continue
            if "error" in message:
                raise RuntimeError("CDP screenshot capture failed")
            data = message.get("result", {}).get("data")
            if not isinstance(data, str) or not data:
                raise RuntimeError("CDP screenshot capture returned no image")
            return data


async def _attach_screenshot_client(websocket_url: str, target_id: str) -> tuple[Any, Any, _CDPScreenshotClient]:
    client_session = aiohttp.ClientSession()
    try:
        websocket = await client_session.ws_connect(websocket_url, heartbeat=10)
        await websocket.send_json({
            "id": 1,
            "method": "Target.attachToTarget",
            "params": {"targetId": target_id, "flatten": True},
        })
        while True:
            message = await asyncio.wait_for(websocket.receive_json(), timeout=5)
            if message.get("id") != 1:
                continue
            if "error" in message:
                raise RuntimeError("CDP could not attach to the active Browser Use page")
            session_id = message.get("result", {}).get("sessionId")
            if not isinstance(session_id, str):
                raise RuntimeError("CDP did not return a page session")
            await websocket.send_json({"id": 2, "method": "Page.enable", "sessionId": session_id})
            while True:
                enabled = await asyncio.wait_for(websocket.receive_json(), timeout=5)
                if enabled.get("id") != 2:
                    continue
                if "error" in enabled:
                    raise RuntimeError("CDP could not enable page recording")
                break
            return client_session, websocket, _CDPScreenshotClient(websocket, session_id)
    except BaseException:
        await client_session.close()
        raise


async def _record_browser_use_video(
    websocket_url: str,
    page: Any,
    output_path: Path,
    width: int,
    height: int,
    seconds: float = 3.5,
) -> None:
    from browser_use.browser.video_recorder import VideoRecorderService  # type: ignore[import-not-found]

    target_id = getattr(page, "_target_id", None)
    if not isinstance(target_id, str) or not target_id:
        raise RuntimeError("Browser Use did not expose the active page target for recording")
    client_session, websocket, screenshot_client = await _attach_screenshot_client(websocket_url, target_id)
    recorder = VideoRecorderService(output_path=output_path, size={"width": width, "height": height}, framerate=10)
    recorder.start()
    try:
        deadline = asyncio.get_running_loop().time() + max(seconds, 5.0)
        frames = 0
        while frames < 12 and asyncio.get_running_loop().time() < deadline:
            recorder.add_frame(await screenshot_client.capture_png_base64())
            frames += 1
            await asyncio.sleep(0.02)
        if frames < 10:
            raise RuntimeError(f"Browser Use recorder received too few frames: {frames}")
    finally:
        recorder.stop_and_save()
        await websocket.close()
        await client_session.close()
    if not output_path.is_file() or output_path.stat().st_size == 0:
        raise RuntimeError("Browser Use video recorder produced no media file")


async def _install_jank_observer(session: Any, page: Any) -> None:
    client, session_id = await _page_cdp_transport(page)
    await client.send.Page.addScriptToEvaluateOnNewDocument(
        params={"source": JANK_OBSERVER},
        session_id=session_id,
    )


async def _set_reduced_motion(session: Any, page: Any, enabled: bool) -> None:
    client, session_id = await _page_cdp_transport(page)
    await client.send.Emulation.setEmulatedMedia(
        params={
            "features": [
                {
                    "name": "prefers-reduced-motion",
                    "value": "reduce" if enabled else "no-preference",
                }
            ]
        },
        session_id=session_id,
    )


async def _evaluate_json(page: Any, expression: str) -> Any:
    value = await page.evaluate(expression)
    if isinstance(value, str):
        if value == "True":
            return True
        if value == "False":
            return False
        with suppress(json.JSONDecodeError):
            return json.loads(value)
    return value


def _validate_webm(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size == 0:
        raise RuntimeError("compatibility recording was empty")
    ffprobe = shutil.which("ffprobe")
    if not ffprobe:
        raise RuntimeError("ffprobe is unavailable")
    result = subprocess.run(
        [ffprobe, "-v", "error", "-show_entries", "format=format_name,duration", "-of", "json", str(path)],
        capture_output=True,
        text=True,
        timeout=COMMAND_TIMEOUT_SECONDS,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("ffprobe rejected the compatibility WebM")
    payload = json.loads(result.stdout)
    format_data = payload.get("format", {})
    duration = float(format_data.get("duration", 0))
    if "webm" not in str(format_data.get("format_name", "")).split(",") or duration <= 0:
        raise RuntimeError("compatibility WebM has no positive duration")
    return {
        "status": "valid",
        "format": format_data["format_name"],
        "durationSeconds": duration,
    }


def _convert_to_webm(source: Path, destination: Path) -> dict[str, Any]:
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        raise RuntimeError("ffmpeg is unavailable")
    result = subprocess.run(
        [
            ffmpeg,
            "-y",
            "-v",
            "error",
            "-i",
            str(source),
            "-c:v",
            "libvpx-vp9",
            "-pix_fmt",
            "yuv420p",
            "-an",
            str(destination),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"WebM conversion failed: {result.stderr[-800:]}")
    return _validate_webm(destination)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def _socks_connect_status(proxy: PublicSocksProxy, host: str, port: int) -> int:
    reader, writer = await asyncio.open_connection(proxy.host, proxy.port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    if await reader.readexactly(2) != b"\x05\x00":
        raise RuntimeError("egress proxy did not accept its configured SOCKS method")
    encoded = host.encode("idna")
    request = b"\x05\x01\x00\x03" + bytes((len(encoded),)) + encoded + port.to_bytes(2, "big")
    writer.write(request)
    await writer.drain()
    reply = await reader.readexactly(10)
    writer.close()
    await writer.wait_closed()
    return reply[1]


async def _probe_proxy_policy(proxy: PublicSocksProxy) -> bool:
    private_reply = await _socks_connect_status(proxy, "127.0.0.1", 80)
    unapproved_reply = await _socks_connect_status(proxy, "example.org", 443)
    if private_reply != 2 or unapproved_reply != 2:
        raise RuntimeError("SOCKS egress policy did not reject private and unapproved destinations")
    if not {"domain-not-approved"}.issubset(set(proxy.violations)):
        raise RuntimeError("SOCKS egress policy did not record blocked destinations")
    proxy.violations.clear()
    proxy.blocked_destinations.clear()
    proxy.connection_outcomes.clear()
    return True


async def _probe_page(page: Any, session: Any) -> tuple[str, str | None, bool, list[dict[str, Any]]]:
    try:
        await page.goto(PROBE_URL)
        title = ""
        for _ in range(50):
            title = await page.evaluate("() => document.title")
            if title == "Example Domain":
                break
            await asyncio.sleep(0.1)
        if title != "Example Domain":
            raise RuntimeError(f"unexpected title: {title!r}")
    except Exception as e:
        raise RuntimeError(f"page evaluation failed: {e}") from e
    viewport = getattr(page, "set_viewport_size", None)
    if not callable(viewport):
        raise RuntimeError("page viewport API is unavailable")
    await viewport(390, 844)
    mobile_width = await _evaluate_json(page, "() => window.innerWidth")
    if not isinstance(mobile_width, int) or mobile_width > 390:
        raise RuntimeError("mobile viewport probe failed")
    await _set_reduced_motion(session, page, True)
    reduced_motion = await _evaluate_json(page,
        "() => window.matchMedia('(prefers-reduced-motion: reduce)').matches"
    )
    if reduced_motion is not True:
        raise RuntimeError(f"reduced-motion emulation failed: {reduced_motion!r}")
    instrumentation = await _evaluate_json(page,
        "() => { window.__browserUseCaptureProbe = true; "
        "return window.__browserUseCaptureProbe === true; }"
    )
    if instrumentation is not True:
        raise RuntimeError("page instrumentation probe failed")
    renderer = await page.evaluate(
        """() => {
          const canvas = document.createElement('canvas');
          const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
          if (!gl) return null;
          const debug = gl.getExtension('WEBGL_debug_renderer_info');
          return debug ? gl.getParameter(debug.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER) || null;
        }"""
    )
    jank = await _evaluate_json(page,
        "() => ({ observerError: window.__browserUseCaptureJankObserverError || null, entries: window.__browserUseCaptureJank || [] })"
    )
    if not isinstance(jank, dict) or jank.get("observerError"):
        raise RuntimeError("jank observer was unavailable")
    if _allowed_url("https://example.org", ["example.com"]):
        raise RuntimeError("domain restriction allowed example.org")
    return title, renderer if isinstance(renderer, str) else None, True, jank.get("entries", [])


async def _enable_internal_debugging_pages(page: Any) -> None:
    goto = getattr(page, "goto", None)
    if not callable(goto):
        return
    try:
        await page.goto("chrome://chrome-urls")
        debug_script = (
            "() => { const app = document.querySelector('chrome-urls-app'); "
            "const btn = app?.shadowRoot?.querySelector('cr-button'); "
            "if (btn) { btn.click(); return true; } return false; }"
        )
        for _ in range(25):
            await asyncio.sleep(0.2)
            if await _evaluate_json(page, debug_script) is True:
                await asyncio.sleep(0.3)
                break
    except Exception:
        pass


async def _browser_service_checks(page: Any, session: Any) -> dict[str, Any]:
    safe_result: dict[str, Any] = {"service": "safeBrowsing", "status": "blocked", "reason": "incomplete-evidence"}
    updater_result: dict[str, Any] = {"service": "componentUpdater", "status": "blocked", "reason": "incomplete-evidence"}
    diagnostics_page = None
    safe_failure_reason = "settings-navigation-failed"
    try:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + SERVICE_CHECK_TIMEOUT_SECONDS
        standard_enabled = None
        await asyncio.wait_for(
            page.goto("chrome://settings/security"), max(0.001, deadline - loop.time())
        )
        settings_script = (
            "() => { const roots = [document]; let inspected = 0; "
            "while (roots.length) { const root = roots.shift(); "
            "for (const element of root.querySelectorAll('*')) { "
            "if (++inspected > 5000) return 'unavailable'; "
            "if (element.matches('settings-security-page, settings-security-page-v2')) { "
            "const value = element.prefs?.generated?.safe_browsing?.value; "
            "return value === 1 ? 'standard' : (value === 0 || value === 2 ? 'other' : 'unavailable'); } "
            "if (element.shadowRoot) roots.push(element.shadowRoot); } } "
            "return 'unavailable'; }"
        )
        safe_failure_reason = "settings-state-failed"
        while loop.time() < deadline:
            mode = await asyncio.wait_for(
                _evaluate_json(page, settings_script), max(0.001, deadline - loop.time())
            )
            if mode in {"standard", "other"}:
                standard_enabled = mode == "standard"
                break
            await asyncio.sleep(min(0.25, max(0, deadline - loop.time())))
        if standard_enabled is None:
            safe_result["reason"] = "settings-state-unavailable"
        if standard_enabled is False:
            safe_result["reason"] = "standard-protection-not-enabled"
        elif standard_enabled is True:
            safe_failure_reason = "diagnostics-tab-failed"
            diagnostics_page = await asyncio.wait_for(
                session.new_page(), max(0.001, deadline - loop.time())
            )
            await asyncio.wait_for(
                diagnostics_page.goto("chrome://safe-browsing/"), max(0.001, deadline - loop.time())
            )
            diagnostic_script = (
                "() => { const title = document.querySelector('#sb-title')?.textContent?.trim().toLowerCase(); "
                "const tables = ['#hprt-lookup-ping-list', '#urt-lookup-ping-list', '#rt-lookup-ping-list'] "
                ".map(selector => document.querySelector(selector)).filter(Boolean); "
                "const completedLookups = tables.reduce((total, table) => total + "
                "[...table.querySelectorAll('tr')].filter(row => { const cells = row.querySelectorAll('td'); "
                "return cells.length >= 2 && Boolean(cells[1].textContent?.trim()); }).length, 0); "
                "return { available: title === 'safe browsing' && tables.length > 0, completedLookups }; }"
            )
            safe_failure_reason = "diagnostics-baseline-failed"
            diagnostic = None
            while loop.time() < deadline:
                diagnostic = await asyncio.wait_for(
                    _evaluate_json(diagnostics_page, diagnostic_script),
                    max(0.001, deadline - loop.time()),
                )
                if isinstance(diagnostic, dict) and diagnostic.get("available") is True:
                    break
                await asyncio.sleep(min(0.25, max(0, deadline - loop.time())))
            if not isinstance(diagnostic, dict) or diagnostic.get("available") is not True:
                safe_result["reason"] = "diagnostics-unavailable"
            else:
                baseline = diagnostic.get("completedLookups")
                if not isinstance(baseline, int) or baseline < 0:
                    safe_result["reason"] = "incomplete-evidence"
                else:
                    safe_failure_reason = "safe-check-navigation-failed"
                    await asyncio.wait_for(
                        page.goto("https://example.com/?browser-use-safe-check=1"),
                        max(0.001, deadline - loop.time()),
                    )
                    safe_failure_reason = "diagnostics-response-failed"
                    while loop.time() < deadline:
                        diagnostic = await asyncio.wait_for(
                            _evaluate_json(diagnostics_page, diagnostic_script),
                            max(0.001, deadline - loop.time()),
                        )
                        if (
                            isinstance(diagnostic, dict)
                            and diagnostic.get("available") is True
                            and isinstance(diagnostic.get("completedLookups"), int)
                            and diagnostic["completedLookups"] >= baseline
                        ):
                            safe_result = {"service": "safeBrowsing", "status": "verified", "reason": None}
                            break
                        await asyncio.sleep(min(0.25, max(0, deadline - loop.time())))
                    else:
                        safe_result["reason"] = "diagnostic-check-not-confirmed"
    except asyncio.TimeoutError:
        safe_result["reason"] = "timeout"
    except Exception:
        safe_result["reason"] = safe_failure_reason
    finally:
        if diagnostics_page is not None:
            with suppress(Exception):
                await session.close_page(diagnostics_page)

    updater_failure_reason = "components-navigation-failed"
    try:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + SERVICE_CHECK_TIMEOUT_SECONDS
        await asyncio.wait_for(page.goto("chrome://components/"), max(0.001, deadline - loop.time()))
        trigger_script = (
            "() => { const button = document.querySelector('.button-check-update'); "
            "if (!button || button.disabled || !button.id || !document.getElementById(`status-${button.id}`)) return null; "
            "button.click(); return button.id; }"
        )
        component_id = None
        updater_failure_reason = "update-trigger-failed"
        while loop.time() < deadline:
            component_id = await asyncio.wait_for(
                _evaluate_json(page, trigger_script), max(0.001, deadline - loop.time())
            )
            if isinstance(component_id, str) and component_id:
                break
            await asyncio.sleep(min(0.25, max(0, deadline - loop.time())))
        if not isinstance(component_id, str) or not component_id:
            updater_result["reason"] = "update-trigger-unavailable"
        else:
            status = "pending"
            status_element_id = json.dumps(f"status-{component_id}")
            updater_failure_reason = "update-status-failed"
            while loop.time() < deadline:
                status = await asyncio.wait_for(
                    _evaluate_json(
                        page,
                        "() => { const text = document.getElementById("
                        + status_element_id
                        + ")?.textContent?.trim().toLowerCase() || ''; "
                        "if (/already up to date|up-to-date/.test(text)) return 'up-to-date'; "
                        "if (/component updated/.test(text)) return 'updated'; "
                        "if (/component not updated/.test(text)) return 'not-updated'; "
                        "if (/update error/.test(text)) return 'update-error'; "
                        "if (/checking|downloading|updating|update found|update ready|updater started|updater sleeping/.test(text)) return 'pending'; "
                        "return text ? 'other' : 'pending'; }"
                    ),
                    max(0.001, deadline - loop.time()),
                )
                if status in {"up-to-date", "updated"}:
                    updater_result = {"service": "componentUpdater", "status": "verified", "reason": None}
                    break
                if status == "not-updated":
                    updater_result["reason"] = "component-not-updated"
                    break
                if status == "update-error":
                    updater_result["reason"] = "update-error"
                    break
                if status == "other":
                    updater_result["reason"] = "unexpected-component-status"
                    break
                await asyncio.sleep(min(0.5, max(0, deadline - loop.time())))
            else:
                updater_result["reason"] = "timeout"
    except asyncio.TimeoutError:
        updater_result["reason"] = "timeout"
    except Exception:
        updater_result["reason"] = updater_failure_reason
    return {
        "status": "verified" if safe_result["status"] == updater_result["status"] == "verified" else "blocked",
        "checks": [safe_result, updater_result],
        "requiredDestinations": [{"hostname": host, "port": 443} for host in sorted(COMPATIBILITY_SERVICE_HOSTS)],
        "rawNetLogCaptured": False,
        "pageContentsCollected": False,
    }


def _attach_probe_metadata(result: dict[str, Any], reviewed_egress_experiment: bool) -> dict[str, Any]:
    result["requestMetadataLimitations"] = {
        "source": "SOCKS CONNECT tunnel; payload inspection disabled",
        "recordedFields": ["destination hostname", "port", "connection outcome", "probe phase"],
        "notCollectedFields": ["URL path", "HTTP method", "request initiator"],
        "httpsMetadataRequiresTlsInterception": True,
        "rawNetLogCaptured": False,
    }
    result.setdefault("egressPolicy", {
        "status": "unverified",
        "failureReason": (
            "The browser traffic boundary is not verified, and browser service "
            "reachability is not assessed."
        ),
        "policy": "exact-host-public-socks-proxy",
        "proxyPolicyCheck": "unverified",
        "browserTrafficBoundary": "unverified",
        "browserServiceReachability": "blocked",
        "browserServiceChecks": {"status": "blocked", "checks": []},
        "unexpectedViolationCodes": [],
        "unauthorizedConnections": [],
        "blockedDestinations": [],
        "connectionOutcomes": [],
        "requestAttribution": {
            "status": "unknown",
            "urlPathsCollected": False,
            "initiatorsCollected": False,
            "phaseObservationsIdentifyInitiators": False,
        },
    })
    result["temporaryEgressApproval"] = {
        "enabled": reviewed_egress_experiment,
        "scope": "single compatibility-probe process",
        "hostnames": sorted(REVIEWED_EGRESS_HOSTS) if reviewed_egress_experiment else [],
        "port": 443,
        "maxLifetimeSeconds": REVIEWED_EGRESS_TTL_SECONDS if reviewed_egress_experiment else 0,
        "probeDeadlineSeconds": VERIFY_TIMEOUT_SECONDS,
    }
    if reviewed_egress_experiment:
        result["diagnosticOnly"] = True
        result["captureAuthorized"] = False
        if result.get("status") == "verified":
            result["status"] = "blocked"
            result["failureReason"] = "temporary egress experiment cannot authorize capture"
    return result


def _runner_boundary_proxy() -> tuple[str, int, str] | None:
    host = os.environ.get("CAPTURE_EGRESS_PROXY_HOST")
    raw_port = os.environ.get("CAPTURE_EGRESS_PROXY_PORT")
    run_id = os.environ.get("CAPTURE_EGRESS_RUN_ID")
    attestation_path = os.environ.get("CAPTURE_EGRESS_ATTESTATION_FILE")
    values = (host, raw_port, run_id, attestation_path)
    if not any(values):
        return None
    if host is None or raw_port is None or run_id is None or attestation_path is None:
        raise RuntimeError("runner egress proxy settings are incomplete")
    try:
        address = ipaddress.ip_address(host)
        port = int(raw_port)
    except ValueError as error:
        raise RuntimeError("runner egress proxy settings are invalid") from error
    if (
        address.version != 4
        or address not in ipaddress.ip_network("10.200.0.0/16")
        or not 1 <= port <= 65535
        or not Path(attestation_path).is_absolute()
    ):
        raise RuntimeError("runner egress proxy settings are outside the approved namespace")
    if not run_id or len(run_id) != 36:
        raise RuntimeError("runner egress run ID is invalid")
    return address.compressed, port, run_id


async def verify(*, reviewed_egress_experiment: bool = False) -> dict[str, object]:
    if not isinstance(reviewed_egress_experiment, bool):
        raise ValueError("reviewed egress experiment flag must be boolean")
    browser_path = _browser_path()
    browser_use_version = _browser_use_version()
    from browser_use.browser.profile import BrowserProfile  # type: ignore[import-not-found]
    from browser_use.browser.session import BrowserSession  # type: ignore[import-not-found]

    raw_run_id = os.environ.get("CAPTURE_EGRESS_RUN_ID", "")
    profile_prefix = "bu-compat-"
    if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", raw_run_id):
        profile_prefix = f"buc-{raw_run_id.replace('-', '')[:16]}-"
    with tempfile.TemporaryDirectory(prefix=profile_prefix, dir="/tmp", ignore_cleanup_errors=True) as temporary:
        root = Path(temporary)
        recording_path = root / "compatibility.mp4"
        webm_path = root / "compatibility.webm"
        approved_hostname = urlparse(PROBE_URL).hostname
        if not approved_hostname:
            raise RuntimeError("compatibility URL has no hostname")
        runner_proxy = _runner_boundary_proxy()
        if runner_proxy is not None and reviewed_egress_experiment:
            raise RuntimeError("reviewed egress experiments cannot run inside the capture boundary")
        session = None
        browser_process = None
        browser_version = None
        renderer = None
        proxy_policy = False
        pre_fixture_observations = None
        browser_traffic_boundary = "unverified"
        network_namespace_inode = None
        browser_network_namespace_inode = None
        browser_service_checks: dict[str, Any] = {"status": "blocked", "checks": []}
        egress_proxy: PublicSocksProxy | None = None
        try:
            if runner_proxy is None:
                egress_proxy = PublicSocksProxy(
                    approved_hostname=approved_hostname,
                    reviewed_egress_experiment=reviewed_egress_experiment,
                )
                proxy_host = "127.0.0.1"
                proxy_port = await egress_proxy.start()
                proxy_policy = await _probe_proxy_policy(egress_proxy)
            else:
                proxy_host, proxy_port, _ = runner_proxy
            profile_dir = root / "browser-use-user-data-dir-profile"
            profile_dir.mkdir(parents=True, exist_ok=True)
            _seed_profile_preflight_assets(profile_dir)
            profile = BrowserProfile(
                executable_path=str(browser_path),
                headless=True,
                chromium_sandbox=True,
                args=GPU_ARGS,
                user_data_dir=profile_dir,
                allowed_domains=[approved_hostname],
                keep_alive=False,
                use_cloud=False,
                enable_default_extensions=False,
                captcha_solver=False,
                cookie_whitelist_domains=[],
                wait_for_network_idle_page_load_time=1.0,
            )
            browser_process, cdp_url, browser_version, websocket_url = await _launch_browser(
                browser_path,
                profile,
                _free_port(),
                proxy_port,
                profile_dir,
                proxy_host=proxy_host,
            )
            if runner_proxy is not None:
                _, _, run_id = runner_proxy
                boundary_evidence, attestation = _load_egress_attestation(
                    browser_path,
                    {
                        "browserUseVersion": browser_use_version,
                        "browserVersion": _browser_binary_version(browser_path),
                    },
                    approved_hostname,
                    run_id,
                )
                if (
                    attestation.get("compatibilityServicePolicy") != "preflight-services.v1"
                    or attestation.get("compatibilityServiceHosts") != sorted(COMPATIBILITY_SERVICE_HOSTS)
                    or attestation.get("compatibilityServicePort") != 443
                ):
                    raise RuntimeError("runner attestation does not bind the fixed compatibility service set")
                network_namespace_inode = boundary_evidence["networkNamespaceInode"]
                browser_network_namespace_inode = os.stat(
                    f"/proc/{browser_process.pid}/ns/net"
                ).st_ino
                if browser_network_namespace_inode != network_namespace_inode:
                    raise RuntimeError("Chrome did not inherit the attested runner network namespace")
                proxy_policy = boundary_evidence["status"] == "verified"
                browser_traffic_boundary = "verified" if proxy_policy else "blocked"
            session = BrowserSession(cdp_url=cdp_url, browser_profile=profile)
            await asyncio.wait_for(session.start(), timeout=STARTUP_TIMEOUT_SECONDS)
            if hasattr(session, "_aboutblank_watchdog") and session._aboutblank_watchdog is not None:
                session._aboutblank_watchdog._stopping = True
            page = await session.get_current_page()
            if page is None:
                raise RuntimeError("BrowserSession returned no current page")
            await _enable_internal_debugging_pages(page)
            browser_service_checks = await _browser_service_checks(page, session)
            await _install_jank_observer(session, page)
            await asyncio.sleep(PRE_FIXTURE_OBSERVATION_SECONDS)
            pre_fixture_observations = _egress_snapshot(egress_proxy)
            title, renderer, domain_restriction, jank_entries = await _probe_page(page, session)
            await page.set_viewport_size(640, 480)
            await page.evaluate(
                "() => { const element = document.createElement('div'); "
                "element.id = 'browser-use-capture-probe-motion'; "
                "element.style.cssText = 'position:fixed;left:8px;top:8px;width:20px;height:20px;"
                "background:#f00;animation:browser-use-probe 1s linear infinite alternate'; "
                "const style = document.createElement('style'); "
                "style.textContent = '@keyframes browser-use-probe { to { transform: translateX(80px); } }'; "
                "document.head.append(style); document.body.append(element); return true; }"
            )
            await _record_browser_use_video(websocket_url, page, recording_path, 640, 480)
            await _kill_session(session)
            session = None
            await _stop_process(browser_process)
            browser_process = None
            webm_validation = _convert_to_webm(recording_path, webm_path)
            gpu = _gpu_status(renderer)
            egress_policy = _egress_policy_result(
                egress_proxy,
                proxy_policy,
                pre_fixture_observations,
                browser_traffic_boundary,
                network_namespace_inode,
                browser_network_namespace_inode,
                browser_service_checks,
            )
            cpu_status = (
                "verified"
                if domain_restriction
                and webm_validation.get("status") == "valid"
                and jank_entries is not None
                else "blocked"
            )
            cpu_failure = None
            if cpu_status != "verified":
                cpu_failure = "one or more CPU compatibility checks failed"
            result = {
                "status": (
                    "verified"
                    if cpu_status == "verified"
                    and gpu["status"] == "verified"
                    and egress_policy["status"] == "verified"
                    else "blocked"
                ),
                "browserExecutable": str(browser_path),
                "browserUseVersion": browser_use_version,
                "browserVersion": browser_version,
                "cpu": {
                    "status": cpu_status,
                    "failureReason": cpu_failure,
                    "recording": webm_validation,
                    "domainPolicy": "strict-public-socks-proxy",
                    "profileAllowedDomains": [approved_hostname],
                    "reducedMotion": True,
                    "desktopViewport": {"width": 640, "height": 480},
                    "mobileViewport": {"width": 390, "height": 844},
                    "jankObserverInstalled": jank_entries is not None,
                    "processCleanup": "kill",
                },
                "gpu": gpu,
                "egressPolicy": egress_policy,
                "browserServiceChecks": browser_service_checks,
                "failureReason": _overall_failure_reason(cpu_status, gpu, cpu_failure, egress_policy),
            }
            return _attach_probe_metadata(result, reviewed_egress_experiment)
        except Exception as error:
            cpu_failure = str(error)[:300]
            gpu = _gpu_status(renderer)
            egress_policy = _egress_policy_result(
                egress_proxy,
                proxy_policy,
                pre_fixture_observations,
                browser_traffic_boundary,
                network_namespace_inode,
                browser_network_namespace_inode,
                browser_service_checks,
            )
            result = {
                "status": "blocked",
                "browserExecutable": str(browser_path),
                "browserUseVersion": browser_use_version,
                "browserVersion": browser_version,
                "cpu": {
                    "status": "blocked",
                    "failureReason": cpu_failure,
                    "domainPolicy": "strict-public-socks-proxy",
                    "processCleanup": "kill",
                },
                "gpu": gpu,
                "egressPolicy": egress_policy,
                "browserServiceChecks": browser_service_checks,
                "failureReason": _overall_failure_reason("blocked", gpu, cpu_failure, egress_policy),
            }
            return _attach_probe_metadata(result, reviewed_egress_experiment)
        finally:
            async def cleanup_resources() -> None:
                if session is not None:
                    with suppress(Exception):
                        await _kill_session(session)
                await _stop_process(browser_process)
                if egress_proxy is not None:
                    await egress_proxy.close()

            await _await_cleanup(cleanup_resources())


async def _verify_with_signal_cleanup(*, reviewed_egress_experiment: bool = False) -> dict[str, object]:
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    handled_signals = []
    if task is not None:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, task.cancel)
                handled_signals.append(sig)
            except (NotImplementedError, RuntimeError):
                pass
    try:
        return await asyncio.wait_for(
            verify(reviewed_egress_experiment=reviewed_egress_experiment),
            timeout=VERIFY_TIMEOUT_SECONDS,
        )
    except asyncio.CancelledError:
        reason = "compatibility probe was cancelled or exceeded its deadline"
        result = {
            "status": "blocked",
            "browserExecutable": os.environ.get("BROWSER_USE_CHROMIUM_PATH"),
            "browserUseVersion": _browser_use_version_or_none(),
            "browserVersion": None,
            "cpu": {"status": "blocked", "failureReason": reason},
            "gpu": {"status": "blocked", "reason": reason},
            "failureReason": reason,
        }
        return _attach_probe_metadata(result, reviewed_egress_experiment)
    except asyncio.TimeoutError:
        reason = f"compatibility probe exceeded its {VERIFY_TIMEOUT_SECONDS:g}-second deadline"
        result = {
            "status": "blocked",
            "browserExecutable": os.environ.get("BROWSER_USE_CHROMIUM_PATH"),
            "browserUseVersion": _browser_use_version_or_none(),
            "browserVersion": None,
            "cpu": {"status": "blocked", "failureReason": reason},
            "gpu": {"status": "blocked", "reason": reason},
            "failureReason": reason,
        }
        return _attach_probe_metadata(result, reviewed_egress_experiment)
    finally:
        for sig in handled_signals:
            loop.remove_signal_handler(sig)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the fail-closed Browser Use compatibility probe")
    parser.add_argument(
        "--reviewed-egress-experiment",
        action="store_true",
        help="temporarily allow only the two reviewed HTTPS hosts for this diagnostic probe",
    )
    arguments = parser.parse_args()
    try:
        result = asyncio.run(
            _verify_with_signal_cleanup(
                reviewed_egress_experiment=arguments.reviewed_egress_experiment,
            )
        )
    except Exception as error:  # pragma: no cover - exercised by the runner
        result = {
            "status": "blocked",
            "browserExecutable": os.environ.get("BROWSER_USE_CHROMIUM_PATH"),
            "browserUseVersion": _browser_use_version_or_none(),
            "browserVersion": None,
            "cpu": {"status": "blocked", "failureReason": str(error)},
            "gpu": {"status": "blocked"},
            "failureReason": str(error),
        }
        print(json.dumps(_attach_probe_metadata(result, arguments.reviewed_egress_experiment), sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
