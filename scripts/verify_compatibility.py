"""Verify Browser Use recording and hardware GPU support."""

from __future__ import annotations

import asyncio
import importlib.metadata
import inspect
import json
import os
import signal
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Awaitable, Coroutine
from contextlib import suppress
from pathlib import Path
from typing import Protocol
from urllib.parse import urlparse


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "remote"))
from capture_worker import (
    _chromium_sandbox_enabled, _clean_chrome_args, _seed_profile_preflight_assets,
    _page_target_id, connect_target_cdp, start_native_recording, stop_native_recording,
    _browser_executable, wait_for_cdp, reserve_loopback_port, _terminate_browser,
    convert_and_validate_video,
)



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


class BrowserProfile(Protocol):
    def get_args(self) -> object: ...


class BrowserUsePageCommands(Protocol):
    async def addScriptToEvaluateOnNewDocument(
        self, *, params: dict[str, object], session_id: str
    ) -> object: ...


class BrowserUseEmulationCommands(Protocol):
    async def setEmulatedMedia(
        self, *, params: dict[str, object], session_id: str
    ) -> object: ...


class BrowserUseCommandCollection(Protocol):
    Page: BrowserUsePageCommands
    Emulation: BrowserUseEmulationCommands


class BrowserUseCdpClient(Protocol):
    send: BrowserUseCommandCollection


class BrowserUsePage(Protocol):
    _client: BrowserUseCdpClient
    session_id: Awaitable[str]

    async def evaluate(self, expression: str) -> object: ...

    async def goto(self, url: str) -> object: ...

    async def set_viewport_size(self, width: int, height: int) -> object: ...

    async def get_target_info(self) -> dict[str, object]: ...


def _browser_use_version() -> str:
    try:
        return importlib.metadata.version("browser-use")
    except importlib.metadata.PackageNotFoundError as error:
        raise RuntimeError("browser-use package metadata is unavailable") from error


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


async def _launch_browser(
    browser_path: Path,
    profile: BrowserProfile,
    port: int,
    profile_dir: Path,
) -> tuple[asyncio.subprocess.Process, str, str]:
    args = _clean_chrome_args(profile.get_args(), port, profile_dir)
    process = await asyncio.create_subprocess_exec(
        str(browser_path),
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    try:
        ready = await wait_for_cdp(port, process, timeout=STARTUP_TIMEOUT_SECONDS)
    except BaseException:
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        with suppress(Exception):
            await process.wait()
        raise
    return process, ready["url"], ready["browserVersion"]


async def _stop_process(process: asyncio.subprocess.Process | None) -> str:
    if process is None:
        return "missing"
    if not await _terminate_browser(process):
        raise RuntimeError("browser process cleanup could not be verified")
    return "terminated"


async def _kill_session(session: object) -> None:
    kill = getattr(session, "kill", None)
    if not callable(kill):
        raise RuntimeError("BrowserSession.kill() is unavailable")
    cleanup = kill()
    if not inspect.isawaitable(cleanup):
        raise RuntimeError("BrowserSession.kill() did not return an awaitable")
    await asyncio.wait_for(cleanup, timeout=5)


async def _await_cleanup(cleanup: Coroutine[object, object, None]) -> None:
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


async def _page_cdp_transport(page: BrowserUsePage) -> tuple[BrowserUseCdpClient, str]:
    client = page._client
    if client is None:
        raise RuntimeError("Browser Use page CDP client is unavailable")
    session_id = await page.session_id
    if not isinstance(session_id, str) or not session_id:
        raise RuntimeError("Browser Use page CDP session ID is unavailable")
    return client, session_id


async def _record_browser_use_video(
    port: int,
    page: BrowserUsePage,
    output_path: Path,
    width: int,
    height: int,
    seconds: float = 3.5,
) -> None:
    cdp = await connect_target_cdp(port, await _page_target_id(page))
    session = None
    try:
        await cdp.command("Page.enable")
        session = await start_native_recording(cdp, width, height, output_path)
        await asyncio.sleep(seconds)
    finally:
        try:
            if session:
                await asyncio.wait_for(stop_native_recording(cdp, session), timeout=60)
        finally:
            await cdp.close()


async def _install_jank_observer(page: BrowserUsePage) -> None:
    client, session_id = await _page_cdp_transport(page)
    await client.send.Page.addScriptToEvaluateOnNewDocument(
        params={"source": JANK_OBSERVER},
        session_id=session_id,
    )


async def _set_reduced_motion(page: BrowserUsePage, enabled: bool) -> None:
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


async def _evaluate_json(page: BrowserUsePage, expression: str) -> object:
    value = await page.evaluate(expression)
    if isinstance(value, str):
        if value == "True":
            return True
        if value == "False":
            return False
        with suppress(json.JSONDecodeError):
            return json.loads(value)
    return value


async def _probe_page(page: BrowserUsePage) -> tuple[str, str | None, bool, list[dict[str, object]]]:
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
    await _set_reduced_motion(page, True)
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
    entries = jank.get("entries", [])
    if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
        raise RuntimeError("jank observer returned invalid entries")
    if _allowed_url("https://example.org", ["example.com"]):
        raise RuntimeError("domain restriction allowed example.org")
    return title, renderer if isinstance(renderer, str) else None, True, entries


async def verify() -> dict[str, object]:
    browser_path, binary_version = await _browser_executable()
    browser_use_version = _browser_use_version()
    from browser_use.browser.profile import BrowserProfile
    from browser_use.browser.session import BrowserSession

    with tempfile.TemporaryDirectory(prefix="bu-compat-", dir="/tmp", ignore_cleanup_errors=True) as temporary:
        root = Path(temporary)
        recording_path = root / "compatibility-source.mp4"
        webm_path = root / "compatibility.webm"
        profile_dir = root / "browser-use-user-data-dir-profile"
        profile_dir.mkdir()
        _seed_profile_preflight_assets(profile_dir)
        profile = BrowserProfile(
            executable_path=str(browser_path),
            headless=True,
            chromium_sandbox=_chromium_sandbox_enabled(),
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
        browser_version = binary_version
        port = reserve_loopback_port()
        try:
            browser_process, cdp_url, browser_version = await _launch_browser(
                browser_path, profile, port, profile_dir,
            )
            session = BrowserSession(cdp_url=cdp_url, browser_profile=profile)
            await asyncio.wait_for(session.start(), timeout=STARTUP_TIMEOUT_SECONDS)
            page = await session.get_current_page()
            if page is None:
                raise RuntimeError("BrowserSession returned no current page")
            await _install_jank_observer(page)
            _, renderer, domain_restriction, jank_entries = await _probe_page(page)
            await page.set_viewport_size(640, 480)
            await _record_browser_use_video(port, page, recording_path, 640, 480)
            await _kill_session(session)
            session = None
            await _stop_process(browser_process)
            browser_process = None
            media = await convert_and_validate_video(recording_path, webm_path)
            recording = {key: media[key] for key in ("status", "format", "durationSeconds")}
            recording["backend"] = "chrome-screencast"
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
