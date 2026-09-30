"""Verify Browser Use recording and hardware GPU support."""

from __future__ import annotations

import asyncio
import importlib.metadata
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
from capture_worker import _clean_chrome_args, _seed_profile_preflight_assets



STARTUP_TIMEOUT_SECONDS = 30
COMMAND_TIMEOUT_SECONDS = 5
VERIFY_TIMEOUT_SECONDS = 110
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
    profile_dir: Path,
) -> tuple[asyncio.subprocess.Process, str, str, str]:
    args = _clean_chrome_args(profile.get_args(), port, profile_dir)
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


async def verify() -> dict[str, object]:
    browser_path = _browser_path()
    browser_use_version = _browser_use_version()
    from browser_use.browser.profile import BrowserProfile
    from browser_use.browser.session import BrowserSession

    with tempfile.TemporaryDirectory(prefix="bu-compat-", dir="/tmp", ignore_cleanup_errors=True) as temporary:
        root = Path(temporary)
        recording_path = root / "compatibility.mp4"
        webm_path = root / "compatibility.webm"
        profile_dir = root / "browser-use-user-data-dir-profile"
        profile_dir.mkdir()
        _seed_profile_preflight_assets(profile_dir)
        profile = BrowserProfile(
            executable_path=str(browser_path),
            headless=True,
            chromium_sandbox=True,
            args=GPU_ARGS,
            user_data_dir=profile_dir,
            allowed_domains=["example.com"],
            keep_alive=False,
            use_cloud=False,
            enable_default_extensions=False,
            captcha_solver=False,
            cookie_whitelist_domains=[],
            wait_for_network_idle_page_load_time=1.0,
        )
        browser_process = None
        session = None
        browser_version = _browser_binary_version(browser_path)
        try:
            browser_process, cdp_url, browser_version, websocket_url = await _launch_browser(
                browser_path, profile, _free_port(), profile_dir,
            )
            session = BrowserSession(cdp_url=cdp_url, browser_profile=profile)
            await asyncio.wait_for(session.start(), timeout=STARTUP_TIMEOUT_SECONDS)
            page = await session.get_current_page()
            if page is None:
                raise RuntimeError("BrowserSession returned no current page")
            await _install_jank_observer(session, page)
            _, renderer, domain_restriction, jank_entries = await _probe_page(page, session)
            await page.set_viewport_size(640, 480)
            await _record_browser_use_video(websocket_url, page, recording_path, 640, 480)
            await _kill_session(session)
            session = None
            await _stop_process(browser_process)
            browser_process = None
            recording = _convert_to_webm(recording_path, webm_path)
            gpu = _gpu_status(renderer)
            cpu_verified = domain_restriction and jank_entries is not None and recording.get("status") == "valid"
            return {
                "status": "verified" if cpu_verified and gpu["status"] == "verified" else "blocked",
                "browserExecutable": str(browser_path),
                "browserUseVersion": browser_use_version,
                "browserVersion": browser_version,
                "cpu": {
                    "status": "verified" if cpu_verified else "blocked",
                    "recording": recording,
                    "profileAllowedDomains": ["example.com"],
                    "reducedMotion": True,
                    "desktopViewport": {"width": 640, "height": 480},
                    "mobileViewport": {"width": 390, "height": 844},
                    "jankObserverInstalled": jank_entries is not None,
                    "processCleanup": "kill",
                },
                "gpu": gpu,
                "failureReason": None if cpu_verified and gpu["status"] == "verified" else "CPU or GPU probe failed",
            }
        except Exception as error:
            return {
                "status": "blocked",
                "browserExecutable": str(browser_path),
                "browserUseVersion": browser_use_version,
                "browserVersion": browser_version,
                "cpu": {"status": "blocked", "failureReason": str(error)[:300]},
                "gpu": {"status": "blocked"},
                "failureReason": str(error)[:300],
            }
        finally:
            async def cleanup_resources() -> None:
                if session is not None:
                    with suppress(Exception):
                        await _kill_session(session)
                await _stop_process(browser_process)
            await _await_cleanup(cleanup_resources())


async def _verify_with_signal_cleanup() -> dict[str, object]:
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
        return await asyncio.wait_for(verify(), timeout=VERIFY_TIMEOUT_SECONDS)
    except (asyncio.CancelledError, asyncio.TimeoutError):
        reason = "compatibility probe was cancelled or exceeded its deadline"
        return {
            "status": "blocked",
            "browserExecutable": os.environ.get("BROWSER_USE_CHROMIUM_PATH"),
            "browserUseVersion": _browser_use_version_or_none(),
            "browserVersion": None,
            "cpu": {"status": "blocked", "failureReason": reason},
            "gpu": {"status": "blocked", "reason": reason},
            "failureReason": reason,
        }
    finally:
        for sig in handled_signals:
            loop.remove_signal_handler(sig)


def main() -> int:
    try:
        result = asyncio.run(_verify_with_signal_cleanup())
    except Exception as error:
        result = {
            "status": "blocked",
            "browserExecutable": os.environ.get("BROWSER_USE_CHROMIUM_PATH"),
            "browserUseVersion": _browser_use_version_or_none(),
            "browserVersion": None,
            "cpu": {"status": "blocked", "failureReason": str(error)},
            "gpu": {"status": "blocked"},
            "failureReason": str(error),
        }
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
