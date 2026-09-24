#!/usr/bin/env python3
"""Bounded Browser Use capture worker for the remote GPU runner.

The worker accepts one normalized JSON object on stdin and writes one result
object on stdout. Browser diagnostics are sent to stderr after redaction.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib.metadata
import ipaddress
import json
import logging
import math
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit



RUNS_ROOT = Path("/workspace/browser-use-capture/runs")
EXPECTED_BROWSER_USE_VERSION = "0.13.10"
CONTRACT_VERSION = "capture-cell.v2"
JANK_SCHEMA_VERSION = "jank-report.v1"
LONG_TASK_THRESHOLD_MS = 50
CAPTURE_FPS = 12
MAX_REQUEST_BYTES = 1_000_000
MAX_TIMEOUT_MS = 270_000
NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")
SENSITIVE_VALUE_PATTERN = re.compile(
    r"((?:authorization|api[_-]?key|token|secret|password|cookie|set-cookie)\s*[:=]\s*)[^\s,;]+",
    re.IGNORECASE,
)
SENSITIVE_QUERY_KEYS = re.compile(
    r"^(?:access_token|api_key|auth|authorization|cookie|key|password|secret|session|signature|token)$",
    re.IGNORECASE,
)
CONSENT_TEXT_PATTERN = re.compile(r"cookie|consent|privacy|tracking|personal data", re.I)
REJECT_TEXT_PATTERN = re.compile(
    r"reject all|decline all|deny all|necessary only|only necessary|use necessary cookies only|"
    r"continue without accepting|refuse all|no thanks|reject|decline|deny",
    re.I,
)
ACCEPT_TEXT_PATTERN = re.compile(r"accept all|allow all|allow cookies|i agree|accept|allow|agree", re.I)
CONSENT_SCOPE_SELECTOR = (
    "[role='dialog'],[aria-modal='true'],#onetrust-banner-sdk,"
    "#CybotCookiebotDialog,#didomi-host,[id*='cookie' i],[class*='cookie' i],"
    "[id*='consent' i],[class*='consent' i],[data-testid*='consent' i]"
)
DEFAULT_CONSENT_SELECTORS = {
    "reject": (
        "#onetrust-reject-all",
        "#CybotCookiebotDialogBodyLevelButtonLevelOptinDeclineAll",
        "#didomi-notice-disagree-button",
        "[data-testid*='reject' i]",
        "[id*='reject' i]",
        "[class*='reject' i]",
    ),
    "accept": (
        "#onetrust-accept-btn-handler",
        "#CybotCookiebotDialogBodyLevelButtonAccept",
        "#didomi-notice-agree-button",
        "[data-testid*='accept' i]",
        "[id*='accept' i]",
        "[class*='accept' i]",
    ),
}
JANK_INIT_SCRIPT = r"""
(() => {
  window.__jankEntries = [];
  window.__jankObserverReady = false;
  window.__jankObserverError = null;
  try {
    if (!window.PerformanceObserver ||
        !PerformanceObserver.supportedEntryTypes ||
        !PerformanceObserver.supportedEntryTypes.includes("longtask")) {
      throw new Error("longtask PerformanceObserver is unsupported");
    }
    const observer = new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        window.__jankEntries.push({
          startTime: entry.startTime,
          duration: entry.duration
        });
      }
    });
    observer.observe({ type: "longtask", buffered: true });
    window.__jankObserverReady = true;
  } catch (error) {
    window.__jankObserverError = String(error && error.message || error);
  }
})();
"""
CONSENT_SCAN_SCRIPT = r"""
() => {
  const relevant = /cookie|consent|privacy|tracking|personal data/i;
  const known = "[role='dialog'],[aria-modal='true'],#onetrust-banner-sdk," +
    "#CybotCookiebotDialog,#didomi-host";
  const generic = "[id*='cookie' i],[class*='cookie' i],[id*='consent' i]," +
    "[class*='consent' i],[data-testid*='consent' i]";
  const visible = (element) => {
    const style = getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    return style.display !== "none" && style.visibility !== "hidden" &&
      Number(style.opacity || 1) > 0 && rect.width > 0 && rect.height > 0;
  };
  let visibleSurfaceCount = 0;
  for (const element of document.querySelectorAll(known + "," + generic)) {
    if (!visible(element)) continue;
    if (element.matches(known) ||
        relevant.test((element.innerText || "") + " " +
          (element.getAttribute("aria-label") || "") + " " +
          (element.getAttribute("aria-describedby") || ""))) {
      visibleSurfaceCount += 1;
    }
  }
  let openShadowHostCount = 0;
  for (const element of document.querySelectorAll("*")) {
    if (element.shadowRoot) openShadowHostCount += 1;
  }
  return JSON.stringify({
    visibleSurfaceCount,
    iframeCount: document.querySelectorAll("iframe").length,
    openShadowHostCount
  });
}
"""


class WorkerFailure(Exception):
    def __init__(self, reason_code: str, message: str, *, status: str = "blocked") -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.status = status


class CDPError(RuntimeError):
    pass


def _redact_text(value: object) -> str:
    text = str(value)
    text = SENSITIVE_VALUE_PATTERN.sub(r"\1[REDACTED]", text)
    try:
        parts = urlsplit(text)
        if parts.scheme and parts.netloc:
            query = [
                (key, "[REDACTED]" if SENSITIVE_QUERY_KEYS.fullmatch(key) else item)
                for key, item in parse_qsl(parts.query, keep_blank_values=True)
            ]
            text = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))
    except ValueError:
        pass
    return text[:1200]


class _RedactingLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = _redact_text(record.getMessage())
        record.args = ()
        return True


def configure_logging() -> None:
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    redactor = _RedactingLogFilter()
    for logger_name in ("browser_use", "cdp_use", "bubus"):
        logger = logging.getLogger(logger_name)
        logger.addFilter(redactor)
        logger.setLevel(logging.WARNING)
    for handler in logging.getLogger().handlers:
        handler.addFilter(redactor)


def _log(message: object) -> None:
    sys.stderr.write(_redact_text(message) + "\n")
    sys.stderr.flush()


def _required_bool(payload: dict[str, Any], key: str, default: bool) -> bool:
    value = payload.get(key, default)
    if type(value) is not bool:
        raise ValueError(f"{key} must be a boolean")
    return value


def _bounded_int(payload: dict[str, Any], key: str, default: int, low: int, high: int) -> int:
    value = payload.get(key, default)
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{key} must be an integer from {low} to {high}")
    return value


def _selector_list(payload: dict[str, Any], plural: str, singular: str | None = None) -> list[str]:
    value: Any = payload.get(plural)
    if value is None and singular:
        value = payload.get(singular)
    if value is None:
        return []
    if isinstance(value, str):
        result = [value]
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        result = value
    else:
        raise ValueError(f"{plural} must be a selector string or list of strings")
    if len(result) > 32 or any(not item.strip() or len(item) > 1000 for item in result):
        raise ValueError(f"{plural} contains an invalid selector")
    return [item.strip() for item in result]


def _canonical_run_id(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("run_id must be a canonical UUID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise ValueError("run_id must be a canonical UUID") from error
    if str(parsed) != value or parsed.version != 4:
        raise ValueError("run_id must be a canonical lowercase UUIDv4")
    return value


def _validate_proxy_gateway(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("egress_proxy_host must be a private IPv4 address")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError("egress_proxy_host must be a private IPv4 address") from error
    if address.version != 4 or not address.is_private:
        raise ValueError("egress_proxy_host must be a private IPv4 address")
    return address.compressed


def _validate_run_location(run_id: str, output_dir: Any, runs_root: Path = RUNS_ROOT) -> Path:
    if not isinstance(output_dir, str) or not Path(output_dir).is_absolute():
        raise ValueError("output_dir must be an absolute path")
    root = runs_root.resolve(strict=False)
    requested = Path(output_dir)
    if requested.exists() and requested.is_symlink():
        raise ValueError("output_dir must not be a symlink")
    expected = root / run_id
    resolved = requested.resolve(strict=False)
    if str(requested) != str(expected) or resolved != expected:
        raise ValueError("output_dir must be the run_id directory below the capture runs root")
    if requested.name != run_id or requested.parent.resolve(strict=False) != root:
        raise ValueError("output_dir must be the run_id directory below the capture runs root")
    return expected


def _safe_basename(value: Any) -> str:
    if not isinstance(value, str) or not NAME_PATTERN.fullmatch(value):
        raise ValueError("name must be a safe basename")
    if Path(value).name != value or value in {".", ".."} or "/" in value or "\\" in value:
        raise ValueError("name must be a safe basename")
    return value


def validate_request(payload: Any, *, runs_root: Path = RUNS_ROOT) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("input must be one JSON object")
    run_id = _canonical_run_id(payload.get("run_id"))
    output_dir = _validate_run_location(run_id, payload.get("output_dir"), runs_root)
    name = _safe_basename(payload.get("name", f"capture-{run_id[:8]}"))
    allowed = {
        "url", "run_id", "output_dir", "name", "width", "height", "mobile",
        "reduced_motion", "consent_mode", "consent_accept_approved",
        "consent_selectors", "consent_selector", "consent_settings_selectors",
        "consent_settings_selector", "consent_optional_selectors",
        "consent_optional_selector", "consent_save_selectors",
        "consent_save_selector", "consent_wait_ms", "consent_budget_ms",
        "consent_max_clicks", "consent_preflight", "settle_ms", "wait_fonts",
        "wait_idle", "idle_timeout_ms", "scroll", "scroll_distance",
        "scroll_step", "scroll_pause_ms", "hover_selectors", "hover_selector",
        "hover_wait_ms", "click_selectors", "click_selector", "click_wait_ms",
        "auto_discover", "auto_discover_max", "auto_discover_wait_ms",
        "tail_ms", "jank_check", "jank_threshold_ms", "timeout_ms",
        "overwrite", "gpu_check_id", "egress_proxy_host", "egress_proxy_port",
    }
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise ValueError(f"unsupported capture fields: {', '.join(unknown[:8])}")
    raw_url = payload.get("url")
    if not isinstance(raw_url, str) or len(raw_url) > 8192:
        raise ValueError("url must be an HTTP or HTTPS URL")
    consent_mode = payload.get("consent_mode", "reject")
    if consent_mode not in {"reject", "accept", "granular", "none"}:
        raise ValueError("consent_mode must be reject, accept, granular, or none")
    approved = _required_bool(payload, "consent_accept_approved", False)
    if consent_mode == "accept" and not approved:
        raise ValueError("accept consent_mode requires consent_accept_approved=true")
    settings = _selector_list(payload, "consent_settings_selectors", "consent_settings_selector")
    optional = _selector_list(payload, "consent_optional_selectors", "consent_optional_selector")
    save = _selector_list(payload, "consent_save_selectors", "consent_save_selector")
    if consent_mode == "granular" and not (settings and optional and save):
        raise ValueError("granular consent requires settings, optional, and save selectors")
    mobile = _required_bool(payload, "mobile", False)
    width = _bounded_int(payload, "width", 390 if mobile else 1920, 240, 7680)
    height = _bounded_int(payload, "height", 844 if mobile else 1080, 240, 4320)
    if mobile:
        width, height = 390, 844
    scroll_distance = payload.get("scroll_distance")
    if scroll_distance is not None and (type(scroll_distance) is not int or not 0 <= scroll_distance <= 1_000_000):
        raise ValueError("scroll_distance must be an integer from 0 to 1000000")
    timeout_ms = _bounded_int(payload, "timeout_ms", 180_000, 1000, MAX_TIMEOUT_MS)
    selectors = {
        "consent_selectors": _selector_list(payload, "consent_selectors", "consent_selector"),
        "consent_settings_selectors": settings,
        "consent_optional_selectors": optional,
        "consent_save_selectors": save,
        "hover_selectors": _selector_list(payload, "hover_selectors", "hover_selector"),
        "click_selectors": _selector_list(payload, "click_selectors", "click_selector"),
    }
    return {
        "url": raw_url,
        "run_id": run_id,
        "output_dir": output_dir,
        "name": name,
        "width": width,
        "height": height,
        "mobile": mobile,
        "reduced_motion": _required_bool(payload, "reduced_motion", False),
        "consent_mode": consent_mode,
        "consent_accept_approved": approved,
        **selectors,
        "consent_wait_ms": _bounded_int(payload, "consent_wait_ms", 1200, 0, 10_000),
        "consent_budget_ms": _bounded_int(payload, "consent_budget_ms", 8000, 0, 30_000),
        "consent_max_clicks": _bounded_int(payload, "consent_max_clicks", 6, 1, 12),
        "consent_preflight": _required_bool(payload, "consent_preflight", True),
        "settle_ms": _bounded_int(payload, "settle_ms", 1200, 0, 30_000),
        "wait_fonts": _required_bool(payload, "wait_fonts", True),
        "wait_idle": _required_bool(payload, "wait_idle", True),
        "idle_timeout_ms": _bounded_int(payload, "idle_timeout_ms", 8000, 100, 30_000),
        "scroll": _required_bool(payload, "scroll", True),
        "scroll_distance": scroll_distance,
        "scroll_step": _bounded_int(payload, "scroll_step", 100, 1, 4000),
        "scroll_pause_ms": _bounded_int(payload, "scroll_pause_ms", 60, 0, 10_000),
        "hover_wait_ms": _bounded_int(payload, "hover_wait_ms", 800, 0, 30_000),
        "click_wait_ms": _bounded_int(payload, "click_wait_ms", 1200, 0, 30_000),
        "auto_discover": _required_bool(payload, "auto_discover", False),
        "auto_discover_max": _bounded_int(payload, "auto_discover_max", 12, 1, 32),
        "auto_discover_wait_ms": _bounded_int(payload, "auto_discover_wait_ms", 700, 0, 30_000),
        "tail_ms": _bounded_int(payload, "tail_ms", 1000, 0, 30_000),
        "jank_check": _required_bool(payload, "jank_check", True),
        "jank_threshold_ms": _bounded_int(payload, "jank_threshold_ms", 200, 0, 60_000),
        "timeout_ms": timeout_ms,
        "overwrite": _required_bool(payload, "overwrite", False),
        "egress_proxy_host": _validate_proxy_gateway(payload.get("egress_proxy_host")),
        "egress_proxy_port": _bounded_int(payload, "egress_proxy_port", 0, 0, 65535),
    }


def _redacted_url(raw_url: str) -> str:
    parts = urlsplit(raw_url)
    query = [
        (key, "[REDACTED]" if SENSITIVE_QUERY_KEYS.fullmatch(key) else value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
    ]
    host = parts.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, urlencode(query), ""))


def is_public_address(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    return parsed.is_global


def validate_public_http_url(
    raw_url: str,
    resolver: Callable[..., list[tuple[Any, ...]]] | None = socket.getaddrinfo,
) -> dict[str, Any]:
    try:
        parts = urlsplit(raw_url)
        port = parts.port
    except ValueError as error:
        raise WorkerFailure("capture-url-invalid", "URL is malformed") from error
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise WorkerFailure("capture-url-invalid", "URL must use HTTP or HTTPS and include a host")
    if parts.username is not None or parts.password is not None:
        raise WorkerFailure("capture-url-invalid", "URL credentials are not allowed")
    if any(ord(char) < 32 for char in raw_url):
        raise WorkerFailure("capture-url-invalid", "URL contains a control character")
    try:
        hostname = parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        literal = ipaddress.ip_address(hostname)
    except UnicodeError as error:
        raise WorkerFailure("capture-url-invalid", "URL host is not valid IDNA") from error
    except ValueError:
        literal = None
    if not hostname:
        raise WorkerFailure("capture-url-invalid", "URL host is empty")
    if hostname == "localhost" or hostname.endswith((".localhost", ".local", ".internal", ".test", ".invalid")):
        raise WorkerFailure("capture-domain-unverified", "Local and reserved host names are not allowed")
    if port is not None and not 1 <= port <= 65535:
        raise WorkerFailure("capture-url-invalid", "URL port is invalid")
    if literal is not None:
        addresses = [literal.compressed]
        if not is_public_address(literal.compressed):
            raise WorkerFailure("capture-domain-unverified", "URL host is not a public IP address")
    elif resolver is None:
        addresses = ["resolved-and-pinned-by-approved-proxy"]
    else:
        try:
            records = resolver(hostname, port or (443 if parts.scheme == "https" else 80), type=socket.SOCK_STREAM)
        except (OSError, socket.gaierror) as error:
            raise WorkerFailure("capture-domain-unverified", "URL host could not be resolved on the capture runner") from error
        addresses = sorted({str(item[0] if len(item) == 1 else item[4][0]) for item in records})
        if not addresses or any(not is_public_address(address) for address in addresses):
            raise WorkerFailure("capture-domain-unverified", "URL host does not resolve only to public addresses")
    return {"url": raw_url, "hostname": hostname, "addresses": addresses}


def _validate_approved_domain(
    raw_url: str,
    approved_hostname: str,
    *,
    stage: str,
    resolver: Callable[..., list[tuple[Any, ...]]] | None = None,
) -> dict[str, Any]:
    try:
        candidate = urlsplit(raw_url).hostname
        normalized = candidate.encode("idna").decode("ascii").lower().rstrip(".") if candidate else ""
    except (UnicodeError, ValueError) as error:
        raise WorkerFailure("capture-url-invalid", f"URL became invalid during {stage}", status="partial") from error
    if normalized != approved_hostname:
        observed = normalized or "(no host)"
        raise WorkerFailure(
            "capture-domain-unverified",
            f"Navigation left the approved host during {stage}: observed host {observed}",
            status="partial",
        )
    validated = validate_public_http_url(raw_url, resolver=resolver)
    if validated["hostname"] != approved_hostname:
        raise WorkerFailure("capture-domain-unverified", f"Navigation left the approved host during {stage}", status="partial")
    return validated


async def _wait_for_approved_navigation(
    page: Any,
    approved_hostname: str,
    *,
    stage: str,
    timeout: float = 60,
) -> str:
    deadline = asyncio.get_running_loop().time() + timeout
    last_url = ""
    while asyncio.get_running_loop().time() < deadline:
        try:
            current_url = await page.evaluate("() => window.location.href")
            if isinstance(current_url, str):
                last_url = current_url
                if current_url.startswith(("http://", "https://")):
                    _validate_approved_domain(current_url, approved_hostname, stage=stage)
                    return current_url
                if current_url not in {"", "about:blank"}:
                    raise WorkerFailure(
                        "capture-url-invalid",
                        f"Navigation entered a non-HTTP URL during {stage}",
                        status="partial",
                    )
        except WorkerFailure:
            raise
        except Exception:
            pass
        await asyncio.sleep(0.1)
    raise WorkerFailure(
        "browser-navigation-timeout",
        f"Browser did not reach an HTTP page during {stage}; current URL was {_redact_text(last_url) or '(empty)' }",
        status="partial",
    )


def _worker_result(
    status: str,
    run_id: str | None,
    *,
    reason_code: str | None = None,
    message: str | None = None,
    manifest: str | None = None,
    artifacts: dict[str, str] | None = None,
    evidence: dict[str, Any] | None = None,
    media_validation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": status,
        "runId": run_id,
        "manifest": manifest,
        "artifacts": artifacts or {},
        "evidence": evidence or {},
        "mediaValidation": media_validation or {
            "status": "blocked" if status == "blocked" else "partial",
        },
    }
    if reason_code:
        result["reasonCode"] = reason_code
    if message:
        safe_message = _redact_text(message)
        result["message"] = safe_message
    if status != "complete":
        result["failureReason"] = _redact_text(message or reason_code or "capture evidence is incomplete")
    return result


def _parse_json_value(value: Any, label: str) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError as error:
            raise WorkerFailure("browser-evidence-invalid", f"{label} returned invalid JSON", status="partial") from error
    return value


async def _page_json(page: Any, expression: str, *, label: str = "Page.evaluate") -> Any:
    value = await page.evaluate(expression)
    return _parse_json_value(value, label)


class CDPSocket:
    """Small request multiplexer for the per-target CDP WebSocket."""

    def __init__(self, websocket: Any) -> None:
        self.websocket = websocket
        self.pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self.next_id = 0
        self.reader_task: asyncio.Task[None] | None = None
        self.in_flight_requests: set[str] = set()
        self.fetch_events: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=256)
        self.last_network_activity = asyncio.get_running_loop().time()
        self.reader_error: str | None = None

    async def start(self) -> None:
        self.reader_task = asyncio.create_task(self._read_messages())

    async def _read_messages(self) -> None:
        try:
            async for raw in self.websocket:
                message = json.loads(raw)
                message_id = message.get("id")
                if isinstance(message_id, int):
                    future = self.pending.pop(message_id, None)
                    if future and not future.done():
                        if "error" in message:
                            future.set_exception(CDPError(_redact_text(message["error"])))
                        else:
                            future.set_result(message.get("result", {}))
                    continue
                method = message.get("method")
                params = message.get("params", {})
                now = asyncio.get_running_loop().time()
                if method == "Network.requestWillBeSent":
                    request_id = params.get("requestId")
                    if request_id:
                        self.in_flight_requests.add(str(request_id))
                    self.last_network_activity = now
                elif method in {"Network.loadingFinished", "Network.loadingFailed"}:
                    request_id = params.get("requestId")
                    if request_id:
                        self.in_flight_requests.discard(str(request_id))
                    self.last_network_activity = now
                elif method == "Fetch.requestPaused":
                    await self.fetch_events.put(params)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self.reader_error = _redact_text(error)
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(CDPError("CDP WebSocket closed"))
            self.pending.clear()

    async def command(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        timeout: float = 15,
    ) -> dict[str, Any]:
        if self.reader_error:
            raise CDPError(self.reader_error)
        self.next_id += 1
        command_id = self.next_id
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self.pending[command_id] = future
        try:
            await self.websocket.send(json.dumps({"id": command_id, "method": method, "params": params or {}}))
            return await asyncio.wait_for(future, timeout=timeout)
        except BaseException:
            self.pending.pop(command_id, None)
            raise

    async def wait_for_network_idle(self, timeout_ms: int, idle_ms: int = 500) -> bool:
        deadline = asyncio.get_running_loop().time() + timeout_ms / 1000
        while asyncio.get_running_loop().time() < deadline:
            now = asyncio.get_running_loop().time()
            if not self.in_flight_requests and (now - self.last_network_activity) * 1000 >= idle_ms:
                return True
            await asyncio.sleep(0.05)
        return False

    async def close(self) -> None:
        if self.reader_task:
            self.reader_task.cancel()
            try:
                await self.reader_task
            except (asyncio.CancelledError, Exception):
                pass
        try:
            await self.websocket.close()
        except Exception:
            pass


async def _http_json(url: str, timeout: float = 2) -> Any:
    def read() -> Any:
        from urllib.request import urlopen

        with urlopen(url, timeout=timeout) as response:
            return json.loads(response.read(2_000_000).decode("utf-8"))

    return await asyncio.to_thread(read)


async def wait_for_cdp(port: int, process: asyncio.subprocess.Process, timeout: float = 30) -> dict[str, Any]:
    deadline = asyncio.get_running_loop().time() + timeout
    endpoint = f"http://127.0.0.1:{port}/json/version"
    last_error = "CDP endpoint did not become ready"
    while asyncio.get_running_loop().time() < deadline:
        if process.returncode is not None:
            raise WorkerFailure("browser-startup-failed", "Chrome exited before CDP became ready")
        try:
            result = await _http_json(endpoint, timeout=1)
            websocket_url = result.get("webSocketDebuggerUrl")
            browser_version = result.get("Browser")
            if isinstance(websocket_url, str) and isinstance(browser_version, str):
                return {"url": f"http://127.0.0.1:{port}", "browserVersion": browser_version}
        except Exception as error:
            last_error = _redact_text(error)
        await asyncio.sleep(0.2)
    raise WorkerFailure("browser-startup-timeout", f"Chrome CDP startup timed out: {last_error}")


async def _drain_stderr(stream: asyncio.StreamReader | None) -> str:
    if stream is None:
        return ""
    tail: deque[bytes] = deque(maxlen=32)
    while True:
        chunk = await stream.read(4096)
        if not chunk:
            break
        tail.append(chunk)
    return _redact_text(b"".join(tail).decode("utf-8", errors="replace"))


async def _target_websocket_url(port: int, target_id: str) -> str:
    targets = await _http_json(f"http://127.0.0.1:{port}/json/list")
    for target in targets:
        if str(target.get("id")) == target_id:
            websocket_url = target.get("webSocketDebuggerUrl")
            if isinstance(websocket_url, str) and websocket_url.startswith("ws://127.0.0.1:"):
                return websocket_url
    raise WorkerFailure("browser-target-unavailable", "Browser Use focused target was not available for CDP capture")


async def connect_target_cdp(port: int, target_id: str) -> CDPSocket:
    websocket_url = await _target_websocket_url(port, target_id)
    try:
        from websockets.asyncio.client import connect
    except ImportError as error:
        raise WorkerFailure("cdp-websocket-unavailable", "The installed websockets API is unavailable") from error
    websocket = await connect(
        websocket_url,
        origin="http://127.0.0.1",
        open_timeout=10,
        close_timeout=2,
        max_size=32 * 1024 * 1024,
        ping_interval=None,
    )
    cdp = CDPSocket(websocket)
    await cdp.start()
    return cdp


async def _browser_executable() -> tuple[Path, str]:
    raw_path = os.environ.get("BROWSER_USE_CHROMIUM_PATH")
    if not raw_path:
        raise WorkerFailure("browser-executable-unconfigured", "BROWSER_USE_CHROMIUM_PATH is required")
    executable = Path(raw_path).expanduser()
    if not executable.is_absolute() or not executable.is_file() or not os.access(executable, os.X_OK):
        raise WorkerFailure("browser-executable-invalid", "Configured Chrome path is missing or not executable")
    try:
        with executable.open("rb") as source:
            binary_header = source.read(4)
    except OSError as error:
        raise WorkerFailure("browser-executable-invalid", "Configured Chrome binary could not be read") from error
    if binary_header != b"\x7fELF":
        raise WorkerFailure("browser-executable-wrapper", "Configured Chrome path must point to a native Linux executable, not a wrapper")
    try:
        result = await asyncio.to_thread(
            subprocess.run,
            [str(executable), "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise WorkerFailure("browser-executable-invalid", "Configured Chrome could not report its version") from error
    output = f"{result.stdout}\n{result.stderr}".strip()
    if result.returncode != 0 or not output:
        raise WorkerFailure("browser-executable-invalid", "Configured Chrome did not report a version")
    if re.search(r"requires the chromium snap|snap install chromium|snapd", output, re.I):
        raise WorkerFailure("browser-executable-snap-shim", "Configured Chrome path is a Snap shim")
    if re.search(r"(?:^|\s)(?:wrapper|launcher)(?:\s|$)", output, re.I):
        raise WorkerFailure("browser-executable-wrapper", "Configured Chrome path is a wrapper")
    return executable, _redact_text(output.splitlines()[0])


def _clean_chrome_args(
    args: Any,
    port: int,
    proxy_port: int,
    profile_dir: Path,
    proxy_host: str = "127.0.0.1",
) -> list[str]:
    if not isinstance(args, (list, tuple)) or any(not isinstance(item, str) for item in args):
        raise WorkerFailure("browser-profile-invalid", "BrowserProfile.get_args() did not return argument strings")
    value_switches = {
        "--remote-debugging-port", "--remote-debugging-address", "--remote-allow-origins",
        "--proxy-server", "--proxy-bypass-list", "--host-resolver-rules", "--user-data-dir",
    }
    filtered: list[str] = []
    skip_next = False
    for item in args:
        if skip_next:
            skip_next = False
            continue
        switch = item.partition("=")[0]
        if switch in value_switches or switch in {"--no-sandbox", "--remote-debugging-pipe"}:
            skip_next = switch in value_switches and "=" not in item
            continue
        filtered.append(item)
    return [
        *filtered,
        f"--user-data-dir={profile_dir}",
        f"--remote-debugging-port={port}",
        "--remote-debugging-address=127.0.0.1",
        "--remote-allow-origins=http://127.0.0.1",
        f"--proxy-server=socks5://{proxy_host}:{proxy_port}",
        "--proxy-bypass-list=<-loopback>",
        "--disable-quic",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--disable-sync",
        "--disable-default-apps",
        "--no-default-browser-check",
        "--no-first-run",
        "data:text/html,",
    ]


def _browser_profile_options(
    *,
    executable: Path,
    profile_dir: Path,
    cdp_origin: str,
    approved_hostname: str,
    request: dict[str, Any],
) -> dict[str, Any]:
    if "browser-use-user-data-dir-" not in str(profile_dir):
        raise WorkerFailure(
            "browser-profile-invalid",
            "Temporary profile path must prevent Browser Use from copying it outside the run directory",
        )
    return {
        "executable_path": str(executable),
        "user_data_dir": str(profile_dir),
        "headless": True,
        "chromium_sandbox": True,
        "keep_alive": False,
        "cdp_url": cdp_origin,
        "use_cloud": False,
        "enable_default_extensions": False,
        "captcha_solver": False,
        "cookie_whitelist_domains": [],
        "allowed_domains": [approved_hostname],
        "window_size": {"width": request["width"], "height": request["height"]},
        "args": [
            "--disable-dev-shm-usage",
            "--use-gl=angle",
            "--use-angle=gl-egl",
            "--enable-gpu-rasterization",
            "--enable-zero-copy",
            "--ignore-gpu-blocklist",
            "--disable-background-timer-throttling",
        ],
    }
def reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def _terminate_browser(process: asyncio.subprocess.Process | None) -> bool:
    if process is None:
        return True
    try:
        if process.returncode is None:
            os.killpg(process.pid, signal.SIGTERM)
        await asyncio.wait_for(process.wait(), timeout=5)
        return True
    except ProcessLookupError:
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
            return True
        except Exception:
            return process.returncode is not None
    except asyncio.TimeoutError:
        try:
            os.killpg(process.pid, signal.SIGKILL)
            await asyncio.wait_for(process.wait(), timeout=5)
            return True
        except Exception:
            return False
    except Exception:
        return process.returncode is not None


async def cleanup_browser_lifecycle(session: Any, process: asyncio.subprocess.Process | None) -> bool:
    cleanup_ok = True
    if session is not None:
        try:
            await asyncio.wait_for(session.kill(), timeout=12)
        except Exception as error:
            cleanup_ok = False
            _log(f"BrowserSession.kill failed: {error}")
    return await _terminate_browser(process) and cleanup_ok


async def _terminate_ffmpeg(process: asyncio.subprocess.Process | None) -> bool:
    if process is None:
        return True
    if process.returncode is None:
        try:
            if process.stdin and not process.stdin.is_closing():
                process.stdin.close()
                await process.stdin.wait_closed()
        except Exception:
            pass
    try:
        await asyncio.wait_for(process.wait(), timeout=8)
        return process.returncode == 0
    except asyncio.TimeoutError:
        try:
            process.terminate()
            await asyncio.wait_for(process.wait(), timeout=3)
        except Exception:
            try:
                process.kill()
                await asyncio.wait_for(process.wait(), timeout=3)
            except Exception:
                return False
    return process.returncode == 0


def _safe_delete_tree(path: Path | None) -> bool:
    if path is None or not path.exists():
        return True
    try:
        shutil.rmtree(path)
        return not path.exists()
    except OSError:
        return False


async def start_ffmpeg_recorder(path: Path) -> tuple[asyncio.subprocess.Process, asyncio.Task[str]]:
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        raise WorkerFailure("ffmpeg-unavailable", "ffmpeg is required for WebM capture")
    process = await asyncio.create_subprocess_exec(
        ffmpeg,
        "-hide_banner", "-loglevel", "error", "-y",
        "-f", "image2pipe", "-vcodec", "mjpeg", "-framerate", str(CAPTURE_FPS), "-i", "pipe:0",
        "-an", "-c:v", "libx264", "-preset", "ultrafast", "-pix_fmt", "yuv420p",
        "-movflags", "+faststart", str(path),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    return process, asyncio.create_task(_drain_stderr(process.stderr))


async def _capture_frames(cdp: CDPSocket, process: asyncio.subprocess.Process, stop: asyncio.Event) -> int:
    if process.stdin is None:
        raise WorkerFailure("video-recording-failed", "ffmpeg has no input pipe")
    loop = asyncio.get_running_loop()
    last_frame_slot = loop.time()
    frame_count = 0
    while not stop.is_set():
        try:
            response = await cdp.command(
                "Page.captureScreenshot",
                {"format": "jpeg", "quality": 82, "fromSurface": True, "captureBeyondViewport": False, "optimizeForSpeed": True},
                timeout=10,
            )
            frame = base64.b64decode(response["data"], validate=True)
            if not frame:
                raise ValueError("empty screenshot")
        except asyncio.CancelledError:
            raise
        except Exception as error:
            raise WorkerFailure("video-recording-failed", f"CDP screenshot capture failed: {_redact_text(error)}", status="partial") from error
        now = loop.time()
        repeat = max(1, round((now - last_frame_slot) * CAPTURE_FPS))
        last_frame_slot += repeat / CAPTURE_FPS
        try:
            for _ in range(repeat):
                process.stdin.write(frame)
                await process.stdin.drain()
                frame_count += 1
        except (BrokenPipeError, ConnectionResetError) as error:
            raise WorkerFailure("video-recording-failed", "ffmpeg stopped accepting captured frames", status="partial") from error
        await asyncio.sleep(max(0, 1 / CAPTURE_FPS - (loop.time() - now)))
    return frame_count


async def convert_and_validate_video(source: Path, destination: Path) -> dict[str, Any]:
    ffmpeg = shutil.which("ffmpeg")
    ffprobe = shutil.which("ffprobe")
    if not ffmpeg or not ffprobe:
        raise WorkerFailure("media-tools-unavailable", "ffmpeg and ffprobe are required for WebM evidence")
    if not source.is_file() or source.stat().st_size == 0:
        raise WorkerFailure("video-recording-failed", "Temporary source video is missing or empty", status="partial")
    conversion = await asyncio.create_subprocess_exec(
        ffmpeg,
        "-hide_banner", "-loglevel", "error", "-y", "-i", str(source),
        "-an", "-c:v", "libvpx-vp9", "-deadline", "realtime", "-cpu-used", "4",
        "-row-mt", "1", "-pix_fmt", "yuv420p", str(destination),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    stderr_task = asyncio.create_task(_drain_stderr(conversion.stderr))
    try:
        exit_code = await asyncio.wait_for(conversion.wait(), timeout=120)
    except asyncio.TimeoutError as error:
        try:
            os.killpg(conversion.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await conversion.wait()
        raise WorkerFailure("webm-conversion-timeout", "WebM conversion timed out", status="partial") from error
    stderr = await stderr_task
    if exit_code != 0:
        raise WorkerFailure("webm-conversion-failed", f"ffmpeg could not convert the capture: {stderr}", status="partial")
    if not destination.is_file() or destination.stat().st_size == 0:
        raise WorkerFailure("webm-validation-failed", "Converted WebM is missing or empty", status="partial")
    result = await asyncio.create_subprocess_exec(
        ffprobe, "-v", "error", "-show_entries", "format=format_name,duration:stream=codec_type,width,height",
        "-of", "json", str(destination),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, probe_stderr = await asyncio.wait_for(result.communicate(), timeout=15)
    except asyncio.TimeoutError as error:
        try:
            os.killpg(result.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(result.wait(), timeout=2)
        except asyncio.TimeoutError:
            try:
                os.killpg(result.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await result.wait()
        raise WorkerFailure("webm-validation-timeout", "ffprobe timed out while validating the WebM", status="partial") from error
    if result.returncode != 0:
        raise WorkerFailure("webm-validation-failed", f"ffprobe rejected the WebM: {_redact_text(probe_stderr.decode(errors='replace'))}", status="partial")
    try:
        probe = json.loads(stdout)
        format_data = probe["format"]
        duration = float(format_data.get("duration", 0))
        streams = probe.get("streams", [])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise WorkerFailure("webm-validation-failed", "ffprobe returned incomplete JSON", status="partial") from error
    if "webm" not in str(format_data.get("format_name", "")).lower() and "matroska" not in str(format_data.get("format_name", "")).lower():
        raise WorkerFailure("webm-validation-failed", "ffprobe did not identify a WebM container", status="partial")
    video_streams = [stream for stream in streams if stream.get("codec_type") == "video"]
    if not math.isfinite(duration) or duration <= 0 or not video_streams:
        raise WorkerFailure("webm-validation-failed", "WebM has no positive duration or video stream", status="partial")
    return {
        "status": "valid",
        "durationSeconds": duration,
        "format": format_data.get("format_name"),
        "videoStreamCount": len(video_streams),
        "width": video_streams[0].get("width"),
        "height": video_streams[0].get("height"),
    }


def _artifact_record(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size == 0:
        raise WorkerFailure("artifact-invalid", f"Required evidence artifact is missing or empty: {path.name}", status="partial")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return {"path": path.name, "size": size, "sha256": digest.hexdigest()}


def _phase_bucket(long_tasks: list[dict[str, float]], phases: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    raw: dict[str, dict[str, float]] = {
        str(phase["name"]): {"count": 0, "totalBlockingTimeMs": 0.0}
        for phase in phases
    }
    for task in long_tasks:
        phase_name = str(phases[0]["name"]) if phases else "unknown"
        for phase in phases:
            if task["startTime"] >= float(phase["at"]):
                phase_name = str(phase["name"])
        bucket = raw.setdefault(phase_name, {"count": 0, "totalBlockingTimeMs": 0.0})
        bucket["count"] += 1
        bucket["totalBlockingTimeMs"] += max(0.0, task["duration"] - LONG_TASK_THRESHOLD_MS)
    return {
        name: {"count": int(bucket["count"]), "totalBlockingTimeMs": round(bucket["totalBlockingTimeMs"])}
        for name, bucket in raw.items()
    }


def build_jank_report(
    *,
    final_url: str,
    consent: dict[str, Any],
    entries: list[dict[str, Any]],
    observer_error: str | None,
    observer_ready: bool,
    phases: list[dict[str, Any]],
    threshold_ms: int,
    interaction_failures: list[dict[str, str]],
    interactions: list[dict[str, Any]],
    scroll: dict[str, Any],
) -> dict[str, Any]:
    long_tasks = []
    for item in entries:
        try:
            start_time = float(item["startTime"])
            duration = float(item["duration"])
        except (KeyError, TypeError, ValueError):
            continue
        if math.isfinite(start_time) and math.isfinite(duration) and start_time >= 0 and duration >= LONG_TASK_THRESHOLD_MS:
            long_tasks.append({"startTime": start_time, "duration": duration})
    total_blocking = round(sum(item["duration"] - LONG_TASK_THRESHOLD_MS for item in long_tasks))
    status = "partial" if (
        not observer_ready or observer_error or not consent.get("verified")
        or consent.get("blindSpots") or interaction_failures
        or scroll.get("timedOut") or scroll.get("truncated") or scroll.get("completed") is not True
    ) else "valid"
    return {
        "schemaVersion": JANK_SCHEMA_VERSION,
        "consent": consent,
        "finalUrl": _redacted_url(final_url),
        "longTaskCount": len(long_tasks),
        "totalBlockingTimeMs": total_blocking,
        "thresholdMs": threshold_ms,
        "choppy": total_blocking > threshold_ms,
        "byPhase": _phase_bucket(long_tasks, phases),
        "longTasks": long_tasks,
        "observerError": _redact_text(observer_error) if observer_error else (None if observer_ready else "observer_unavailable"),
        "interactionFailures": interaction_failures,
        "interactions": interactions,
        "scroll": scroll,
        "status": status,
    }


async def _mark_phase(page: Any, phases: list[dict[str, Any]], name: str) -> None:
    try:
        at = await page.evaluate("() => performance.now()")
        phases.append({"name": name, "at": float(at)})
    except Exception:
        pass


async def _configure_page(page: Any, cdp: CDPSocket, request: dict[str, Any]) -> None:
    await page.set_viewport_size(request["width"], request["height"])
    await cdp.command(
        "Emulation.setDeviceMetricsOverride",
        {
            "width": request["width"],
            "height": request["height"],
            "deviceScaleFactor": 1,
            "mobile": request["mobile"],
            "screenWidth": request["width"],
            "screenHeight": request["height"],
        },
    )
    await cdp.command("Emulation.setTouchEmulationEnabled", {"enabled": request["mobile"]})
    await cdp.command(
        "Emulation.setEmulatedMedia",
        {"features": [{"name": "prefers-reduced-motion", "value": "reduce" if request["reduced_motion"] else "no-preference"}]},
    )


async def _guard_document_requests(
    cdp: CDPSocket,
    approved_hostname: str,
    failures: list[dict[str, str]],
) -> None:
    while True:
        event = await cdp.fetch_events.get()
        request_id = event.get("requestId")
        url = event.get("request", {}).get("url")
        if not isinstance(request_id, str) or not isinstance(url, str):
            failures.append({"kind": "network-policy", "selector": "document", "error": "invalid paused request"})
            continue
        try:
            _validate_approved_domain(url, approved_hostname, stage="document request")
        except WorkerFailure as error:
            failures.append({"kind": "network-policy", "selector": "document", "error": error.reason_code})
            try:
                await cdp.command("Fetch.failRequest", {"requestId": request_id, "errorReason": "BlockedByClient"})
            except Exception:
                return
            continue
        try:
            await cdp.command("Fetch.continueRequest", {"requestId": request_id})
        except Exception:
            failures.append({"kind": "network-policy", "selector": "document", "error": "request guard could not continue a document"})
            return


async def _stop_request_guard(cdp: CDPSocket | None, task: asyncio.Task[None] | None) -> None:
    if task is not None:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    if cdp is not None:
        try:
            await cdp.command("Fetch.disable", timeout=2)
        except Exception:
            pass


async def _inspect_consent(page: Any, request: dict[str, Any]) -> dict[str, int]:
    result = await _page_json(page, CONSENT_SCAN_SCRIPT, label="consent scan")
    if not isinstance(result, dict):
        raise WorkerFailure("consent-unverified", "Consent scan returned an invalid result", status="partial")
    scan = {
        "visibleSurfaceCount": int(result.get("visibleSurfaceCount", 0)),
        "iframeCount": int(result.get("iframeCount", 0)),
        "openShadowHostCount": int(result.get("openShadowHostCount", 0)),
    }
    selectors = list(request["consent_selectors"])
    if request["consent_mode"] == "granular":
        selectors.extend(request["consent_settings_selectors"])
        selectors.extend(request["consent_optional_selectors"])
        selectors.extend(request["consent_save_selectors"])
    elif request["consent_mode"] in DEFAULT_CONSENT_SELECTORS:
        selectors.extend(DEFAULT_CONSENT_SELECTORS[request["consent_mode"]])
    for selector in selectors:
        try:
            elements = await page.get_elements_by_css_selector(selector)
        except Exception as error:
            raise WorkerFailure("consent-unverified", "A consent selector could not be inspected", status="partial") from error
        if any([await _element_is_visible(element) for element in elements]):
            scan["visibleSurfaceCount"] += 1
    return scan


async def _element_is_visible(element: Any) -> bool:
    try:
        return bool(await element.evaluate(
            "() => { const s=getComputedStyle(this), r=this.getBoundingClientRect(); "
            "return s.display!=='none' && s.visibility!=='hidden' && Number(s.opacity||1)>0 && r.width>0 && r.height>0; }"
        ))
    except Exception:
        return False


async def _find_selector_candidates(page: Any, selectors: list[str]) -> list[tuple[Any, str]]:
    candidates: list[tuple[Any, str]] = []
    for selector in selectors:
        try:
            for element in await page.get_elements_by_css_selector(selector):
                if await _element_is_visible(element):
                    candidates.append((element, selector))
        except Exception:
            continue
    return candidates


async def _generic_consent_buttons(page: Any, phrase: re.Pattern[str]) -> list[tuple[Any, str]]:
    candidates = []
    try:
        buttons = await page.get_elements_by_css_selector(
            "button,[role='button'],input[type='button'],input[type='submit']"
        )
    except Exception:
        return candidates
    for index, element in enumerate(buttons):
        try:
            info = await element.evaluate(
                "() => { const root=this.closest(\"[role='dialog'],[aria-modal='true'],"
                "#onetrust-banner-sdk,#CybotCookiebotDialog,#didomi-host,[id*='cookie' i],"
                "[class*='cookie' i],[id*='consent' i],[class*='consent' i],"
                "[data-testid*='consent' i]\"); "
                "return JSON.stringify({label:(this.innerText||this.value||this.getAttribute('aria-label')||'').slice(0,300),"
                "scoped:!!root,known:!!(root&&root.matches(\"[role='dialog'],[aria-modal='true'],"
                "#onetrust-banner-sdk,#CybotCookiebotDialog,#didomi-host\")),"
                "scopeText:root?((root.innerText||'')+' '+(root.getAttribute('aria-label')||'' )).slice(0,2000):''}); }"
            )
            info = _parse_json_value(info, "button metadata")
            if not isinstance(info, dict) or not await _element_is_visible(element):
                continue
            if not info.get("scoped"):
                continue
            if not info.get("known") and not CONSENT_TEXT_PATTERN.search(str(info.get("scopeText", ""))):
                continue
            if phrase.search(str(info.get("label", ""))):
                candidates.append((element, f"scoped-button-index={index}"))
        except Exception:
            continue
    return candidates


async def _click_first(
    page: Any,
    selectors: list[str],
    phrase: re.Pattern[str],
    *,
    require_scope: bool,
    timeout_ms: int,
) -> tuple[bool, str | None, str | None]:
    candidate_groups = [
        await _find_selector_candidates(page, selectors),
        await _generic_consent_buttons(page, phrase),
    ]
    last_error: tuple[str | None, str | None] = (None, None)
    for candidates in candidate_groups:
        for element, selector in candidates:
            try:
                metadata = await element.evaluate(
                    "() => JSON.stringify({label:[this.innerText,this.value,this.getAttribute('aria-label'),"
                    "this.getAttribute('title')].filter(Boolean).join(' ').slice(0,600)})"
                )
                metadata = _parse_json_value(metadata, "consent control label")
                if not isinstance(metadata, dict) or not phrase.search(str(metadata.get("label", ""))):
                    continue
            except Exception:
                continue
            if require_scope:
                try:
                    scoped = await element.evaluate(
                        "() => { const root=this.closest(\"[role='dialog'],[aria-modal='true'],"
                        "#onetrust-banner-sdk,#CybotCookiebotDialog,#didomi-host,[id*='cookie' i],"
                        "[class*='cookie' i],[id*='consent' i],[class*='consent' i],"
                        "[data-testid*='consent' i]\"); "
                        "if(!root)return false; if(root.matches(\"[role='dialog'],[aria-modal='true'],"
                        "#onetrust-banner-sdk,#CybotCookiebotDialog,#didomi-host\"))return true; "
                        "return /cookie|consent|privacy|tracking|personal data/i.test(root.innerText||''); }"
                    )
                    if not scoped:
                        continue
                except Exception:
                    continue
            try:
                await asyncio.wait_for(element.click(), timeout=max(0.25, timeout_ms / 1000))
                return True, _redact_text(selector), None
            except Exception as error:
                last_error = (_redact_text(selector), _redact_text(error))
    return False, last_error[0], last_error[1]


async def handle_consent(page: Any, request: dict[str, Any], phase: str) -> dict[str, Any]:
    mode = request["consent_mode"]
    result: dict[str, Any] = {
        "mode": mode, "phase": phase, "verified": False, "dismissed": False,
        "actionTaken": False, "outcome": "not-attempted", "selector": None,
        "attempts": [], "reason": None, "blindSpots": [], "clicks": 0, "budgetMs": 0,
    }
    if mode == "none":
        scan = await _inspect_consent(page, request)
        if scan["iframeCount"]:
            result["blindSpots"].append({"kind": "iframe-consent-not-inspected", "count": scan["iframeCount"]})
        if scan["openShadowHostCount"]:
            result["blindSpots"].append({"kind": "open-shadow-consent-not-inspected", "count": scan["openShadowHostCount"]})
        result["verified"] = scan["visibleSurfaceCount"] == 0 and not result["blindSpots"]
        result["outcome"] = "no-consent-surface" if result["verified"] else "consent-surface-present-or-unverified"
        return result

    started = time.monotonic()
    await asyncio.sleep(min(request["consent_wait_ms"], request["consent_budget_ms"]) / 1000)
    initial = await _inspect_consent(page, request)
    result["initialSurfaceCount"] = initial["visibleSurfaceCount"]
    if initial["iframeCount"]:
        result["blindSpots"].append({"kind": "iframe-consent-not-inspected", "count": initial["iframeCount"]})
    if initial["openShadowHostCount"]:
        result["blindSpots"].append({"kind": "open-shadow-consent-not-inspected", "count": initial["openShadowHostCount"]})
    if initial["visibleSurfaceCount"] == 0:
        result["verified"] = not result["blindSpots"]
        result["outcome"] = "no-consent-surface" if result["verified"] else "consent-surface-unverified"
        result["budgetMs"] = round((time.monotonic() - started) * 1000)
        return result

    if mode == "granular":
        stages = [
            ("settings", request["consent_settings_selectors"]),
            ("optional", request["consent_optional_selectors"]),
            ("save", request["consent_save_selectors"]),
        ]
        for stage_name, selectors in stages:
            candidates = await _find_selector_candidates(page, selectors)
            if not candidates:
                result["outcome"] = f"granular-{stage_name}-control-not-found"
                result["reason"] = f"granular consent {stage_name} control could not be verified"
                result["blindSpots"].append({"kind": "granular-control-not-found", "stage": stage_name})
                break
            element, selector = candidates[0]
            if stage_name == "optional":
                try:
                    state = await element.evaluate(
                        "() => { const checked=typeof this.checked==='boolean'?this.checked:"
                        "this.getAttribute('aria-checked'); return JSON.stringify({checked}); }"
                    )
                    state = _parse_json_value(state, "optional consent state")
                    checked = state.get("checked")
                    if checked in {True, "true", "mixed"}:
                        await asyncio.wait_for(element.click(), timeout=2)
                        result["clicks"] += 1
                        result["actionTaken"] = True
                    elif checked not in {False, "false"}:
                        raise ValueError("optional consent state is unknown")
                    verified_state = await element.evaluate(
                        "() => JSON.stringify(typeof this.checked==='boolean'?this.checked:this.getAttribute('aria-checked'))"
                    )
                    verified_state = _parse_json_value(verified_state, "optional consent verification")
                    if verified_state not in {False, "false", None}:
                        raise ValueError("optional consent remains enabled")
                except Exception as error:
                    result["outcome"] = "granular-optional-state-unverified"
                    result["reason"] = _redact_text(error)
                    result["blindSpots"].append({"kind": "optional-state-unverified"})
                    break
                result["attempts"].append(_redact_text(selector))
                continue
            try:
                await asyncio.wait_for(element.click(), timeout=2)
                result["clicks"] += 1
                result["actionTaken"] = True
                result["selector"] = selector
                result["attempts"].append(_redact_text(selector))
                await asyncio.sleep(0.25)
            except Exception as error:
                result["outcome"] = f"granular-{stage_name}-click-failed"
                result["reason"] = _redact_text(error)
                result["blindSpots"].append({"kind": "granular-click-failed", "stage": stage_name})
                break
    else:
        phrase = ACCEPT_TEXT_PATTERN if mode == "accept" else REJECT_TEXT_PATTERN
        selectors = [*request["consent_selectors"], *DEFAULT_CONSENT_SELECTORS[mode]]
        budget_remaining = max(0, request["consent_budget_ms"] - round((time.monotonic() - started) * 1000))
        if budget_remaining <= 0:
            result["outcome"] = "consent-budget-exhausted"
        else:
            clicked, selector, error = await _click_first(
                page, selectors, phrase, require_scope=True, timeout_ms=min(2000, budget_remaining)
            )
            if clicked:
                result["actionTaken"] = True
                result["action"] = "accepted" if mode == "accept" else "rejected"
                result["selector"] = selector
                result["attempts"].append(_redact_text(selector))
                result["clicks"] = 1
                await asyncio.sleep(0.25)
            elif error:
                result["attempts"].append(_redact_text(f"{selector or 'consent-control'}: {error}"))
                result["outcome"] = "consent-click-failed"
            else:
                result["outcome"] = "no-safe-action"

    remaining = await _inspect_consent(page, request)
    if remaining["iframeCount"] and not any(item.get("kind") == "iframe-consent-not-inspected" for item in result["blindSpots"]):
        result["blindSpots"].append({"kind": "iframe-consent-not-inspected", "count": remaining["iframeCount"]})
    if remaining["openShadowHostCount"] and not any(item.get("kind") == "open-shadow-consent-not-inspected" for item in result["blindSpots"]):
        result["blindSpots"].append({"kind": "open-shadow-consent-not-inspected", "count": remaining["openShadowHostCount"]})
    result["verified"] = (
        remaining["visibleSurfaceCount"] == 0
        and not result["blindSpots"]
        and (mode != "reject" or initial["visibleSurfaceCount"] == 0 or result.get("action") == "rejected")
    )
    result["dismissed"] = result["verified"] and result["actionTaken"]
    result["outcome"] = "dismissed" if result["dismissed"] else (
        "no-consent-surface" if result["verified"] else result.get("outcome") or "surface-remains-or-unverified"
    )
    result["budgetMs"] = round((time.monotonic() - started) * 1000)
    result["reason"] = result["reason"] or (
        "consent state verified after bounded handling" if result["verified"] else "consent state could not be verified"
    )
    return result


def combine_consent(
    mode: str,
    preflight: dict[str, Any] | None,
    recorded: dict[str, Any],
    history: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    results = [item for item in (preflight, *(history or []), recorded) if item is not None]
    blind_spots = [spot for item in results for spot in item.get("blindSpots", [])]
    verified = bool(recorded.get("verified")) and not blind_spots and all(item.get("verified") for item in results)
    reject_action = any(item.get("action") == "rejected" for item in results)
    return {
        "mode": mode,
        "verified": verified,
        "dismissed": any(bool(item.get("dismissed")) for item in results),
        "blindSpots": blind_spots,
        "actionTaken": any(item.get("actionTaken") for item in results),
        "outcome": recorded.get("outcome", "not-attempted"),
        "action": "rejected" if mode == "reject" and reject_action else recorded.get("action", "none"),
        "selector": recorded.get("selector"),
        "preflight": preflight,
        "recorded": recorded,
    }


async def _settle_page(page: Any, cdp: CDPSocket, request: dict[str, Any]) -> dict[str, Any]:
    idle_reached = True
    if request["wait_idle"]:
        idle_reached = await cdp.wait_for_network_idle(request["idle_timeout_ms"])
    fonts_ready = True
    if request["wait_fonts"]:
        try:
            fonts_ready = bool(await page.evaluate(
                "async () => await Promise.race([document.fonts.ready.then(()=>true),"
                "new Promise(resolve=>setTimeout(()=>resolve(false),8000))])"
            ))
        except Exception:
            fonts_ready = False
    await asyncio.sleep(request["settle_ms"] / 1000)
    return {"networkIdle": idle_reached, "fontsReady": fonts_ready}


async def _run_hover_click(
    page: Any,
    request: dict[str, Any],
    approved_hostname: str,
    failures: list[dict[str, str]],
    interactions: list[dict[str, Any]],
) -> None:
    for kind, selectors, wait_ms in (
        ("hover", request["hover_selectors"], request["hover_wait_ms"]),
        ("click", request["click_selectors"], request["click_wait_ms"]),
    ):
        for selector in selectors:
            try:
                elements = await page.get_elements_by_css_selector(selector)
                if not elements:
                    raise ValueError("selector matched no element")
                element = elements[0]
                if not await _element_is_visible(element):
                    raise ValueError("element is not visible")
                action = element.hover() if kind == "hover" else element.click()
                await asyncio.wait_for(action, timeout=5)
                interactions.append({"kind": kind, "selector": _redact_text(selector), "status": "completed"})
                await asyncio.sleep(wait_ms / 1000)
                if kind == "click":
                    current = await page.get_url()
                    _validate_approved_domain(current, approved_hostname, stage="manual click")
            except WorkerFailure:
                raise
            except Exception as error:
                failures.append({"kind": kind, "selector": _redact_text(selector), "error": _redact_text(error)})
                interactions.append({"kind": kind, "selector": _redact_text(selector), "status": "failed"})


async def _auto_discover(
    page: Any,
    request: dict[str, Any],
    approved_hostname: str,
    failures: list[dict[str, str]],
    interactions: list[dict[str, Any]],
) -> None:
    selector = "nav a,nav button,[role='button'],button,summary,[aria-expanded],[aria-haspopup],.dropdown-toggle,.accordion-toggle,.menu-toggle"
    try:
        elements = await page.get_elements_by_css_selector(selector)
    except Exception as error:
        failures.append({"kind": "auto-discover", "selector": _redact_text(selector), "error": _redact_text(error)})
        return
    for index, element in enumerate(elements[:request["auto_discover_max"]]):
        try:
            if not await _element_is_visible(element):
                continue
            await asyncio.wait_for(element.click(), timeout=4)
            interactions.append({"kind": "auto-discover", "index": index, "status": "completed"})
            await asyncio.sleep(request["auto_discover_wait_ms"] / 1000)
            _validate_approved_domain(await page.get_url(), approved_hostname, stage="automatic interaction")
        except WorkerFailure:
            raise
        except Exception as error:
            failures.append({"kind": "auto-discover", "selector": f"candidate-{index}", "error": _redact_text(error)})


async def _scroll_page(
    page: Any,
    request: dict[str, Any],
    approved_hostname: str,
    consent_recheck: Callable[[], Any] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    evidence: dict[str, Any] = {
        "requested": request["scroll"], "completed": not request["scroll"],
        "requestedDistance": request["scroll_distance"], "measuredDistance": None,
        "completedDistance": 0, "actualDistance": 0, "timedOut": False, "truncated": False,
    }
    consent_checks: list[dict[str, Any]] = []
    if not request["scroll"]:
        return evidence, consent_checks
    measurement = await _page_json(
        page,
        "() => { const doc=document.documentElement.scrollHeight-window.innerHeight; "
        "if(doc>400)return {distance:doc,fallback:false}; let max=0; "
        "for(const el of document.querySelectorAll('*'))max=Math.max(max,el.scrollHeight); "
        "return {distance:Math.max(max-window.innerHeight,doc),fallback:true}; }",
        label="scroll measurement",
    )
    distance = request["scroll_distance"]
    measured = max(0, int(measurement.get("distance", 0))) if isinstance(measurement, dict) else 0
    if distance is None:
        distance = measured
    distance = max(0, int(distance))
    evidence["measuredDistance"] = measured
    evidence["requestedDistance"] = distance
    if distance == 0:
        evidence["completed"] = True
        return evidence, consent_checks
    steps = max(1, (distance + request["scroll_step"] - 1) // request["scroll_step"])
    for _ in range(steps):
        try:
            before = await page.evaluate(
                "() => Math.max(window.scrollY,document.documentElement.scrollTop,document.body&&document.body.scrollTop||0)"
            )
            await asyncio.wait_for(
                page.mouse.scroll(
                    x=request["width"] // 2, y=request["height"] // 2,
                    delta_y=min(request["scroll_step"], distance - evidence["actualDistance"]),
                ),
                timeout=max(1, min(5, (request["scroll_pause_ms"] + 2000) / 1000)),
            )
            await asyncio.sleep(request["scroll_pause_ms"] / 1000)
            after = await page.evaluate(
                "() => Math.max(window.scrollY,document.documentElement.scrollTop,document.body&&document.body.scrollTop||0)"
            )
            delta = max(0, float(after) - float(before))
            evidence["actualDistance"] += delta
            evidence["completedDistance"] = evidence["actualDistance"]
            _validate_approved_domain(await page.get_url(), approved_hostname, stage="scroll")
            if consent_recheck:
                consent_checks.append(await consent_recheck())
                _validate_approved_domain(await page.get_url(), approved_hostname, stage="scroll consent handling")
        except WorkerFailure:
            raise
        except Exception:
            evidence["timedOut"] = True
            break
    evidence["truncated"] = evidence["timedOut"] or evidence["actualDistance"] + request["scroll_step"] < distance
    evidence["completed"] = not evidence["truncated"]
    return evidence, consent_checks


def _load_egress_attestation(
    executable: Path,
    runtime: dict[str, str],
    approved_host: str,
    run_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    raw_path = os.environ.get("CAPTURE_EGRESS_ATTESTATION_FILE", "")
    if not raw_path:
        raise WorkerFailure("capture-egress-attestation-missing", "The root-owned runner egress attestation is not configured")
    path = Path(raw_path)
    try:
        metadata = path.stat()
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise WorkerFailure("capture-egress-attestation-untrusted", "The egress attestation must be root-owned and not group or world writable")
        attestation = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise WorkerFailure("capture-egress-attestation-invalid", "The runner egress attestation could not be read") from error
    if not isinstance(attestation, dict):
        raise WorkerFailure("capture-egress-attestation-invalid", "The runner egress attestation must be an object")
    checked_at = attestation.get("checkedAt")
    expires_at = attestation.get("expiresAt") if isinstance(attestation, dict) else None
    try:
        checked = datetime.fromisoformat(str(checked_at).replace("Z", "+00:00"))
        expires = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
    except ValueError as error:
        raise WorkerFailure("capture-egress-attestation-invalid", "The egress attestation timestamps are invalid") from error
    expected_browser_use = runtime["browserUseVersion"]
    controls = attestation.get("controls") if isinstance(attestation.get("controls"), dict) else {}
    direct_control = controls.get("direct") if isinstance(controls.get("direct"), dict) else {}
    proxied_control = controls.get("proxied") if isinstance(controls.get("proxied"), dict) else {}
    valid = (
        attestation.get("schemaVersion") == "runner-egress-boundary.v1"
        and attestation.get("runId") == run_id
        and isinstance(attestation.get("boundaryId"), str) and bool(attestation["boundaryId"].strip())
        and attestation.get("runnerInstanceId") == os.environ.get("VAST_INSTANCE_ID")
        and attestation.get("browserExecutable") == str(executable)
        and attestation.get("browserVersion") == runtime["browserVersion"]
        and attestation.get("captureRuntime") == "browser-use"
        and attestation.get("captureRuntimeVersion") == expected_browser_use
        and attestation.get("browserUseVersion") == EXPECTED_BROWSER_USE_VERSION
        and attestation.get("approvedHost") == approved_host
        and attestation.get("networkNamespaceInode") == os.stat("/proc/self/ns/net").st_ino
        and attestation.get("directEgressBlocked") is True
        and attestation.get("proxyPolicy") == "capture-exact-host.v1"
        and direct_control.get("status") == "blocked"
        and proxied_control.get("status") == "passed"
        and checked.tzinfo is not None and expires.tzinfo is not None
        and expires > now and checked <= now
        and expires - checked <= timedelta(seconds=120)
        and now - checked <= timedelta(seconds=120)
    )
    if not valid:
        raise WorkerFailure("capture-egress-attestation-unverified", "The runner egress boundary proof is stale or does not match this capture runtime")
    return {
        "status": "verified",
        "boundaryId": attestation["boundaryId"],
        "directEgressBlocked": True,
        "approvedProxyProbe": proxied_control.get("status") == "passed",
        "proxyPolicy": "capture-exact-host.v1",
        "approvedHost": approved_host,
        "networkNamespaceInode": attestation["networkNamespaceInode"],
    }, attestation


async def _browser_runtime_versions(executable: Path) -> dict[str, str]:
    try:
        browser_use_version = importlib.metadata.version("browser-use")
    except importlib.metadata.PackageNotFoundError as error:
        raise WorkerFailure("browser-use-unavailable", "Browser Use is not installed on the capture runner") from error
    if browser_use_version != EXPECTED_BROWSER_USE_VERSION:
        raise WorkerFailure(
            "browser-use-version-mismatch",
            f"Browser Use {EXPECTED_BROWSER_USE_VERSION} is required; installed release is {browser_use_version}",
        )
    try:
        result = await asyncio.to_thread(
            subprocess.run, [str(executable), "--version"],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise WorkerFailure("browser-executable-invalid", "Configured Chrome version check failed") from error
    if result.returncode != 0:
        raise WorkerFailure("browser-executable-invalid", "Configured Chrome version check failed")
    nvidia_smi = shutil.which("nvidia-smi")
    if not nvidia_smi:
        raise WorkerFailure("capture-gpu-unavailable", "nvidia-smi is unavailable on the capture runner")
    driver = await asyncio.to_thread(
        subprocess.run, [nvidia_smi, "--query-gpu=name,driver_version", "--format=csv,noheader"],
        capture_output=True, text=True, timeout=15, check=False,
    )
    if driver.returncode != 0 or not driver.stdout.strip():
        raise WorkerFailure("capture-gpu-unavailable", "The capture runner GPU could not be verified")
    gpu_name, _, driver_version = driver.stdout.strip().partition(",")
    browser_version_text = _redact_text(result.stdout.strip() or result.stderr.strip()).splitlines()[0]
    version_match = re.search(r"\d+(?:\.\d+){2,3}", browser_version_text)
    if not version_match:
        raise WorkerFailure("browser-executable-invalid", "Configured Chrome version string is not recognized")
    return {
        "browserUseVersion": browser_use_version,
        "browserVersion": version_match.group(0),
        "gpuName": gpu_name.strip()[:100],
        "driverVersion": driver_version.strip()[:64],
    }


def _write_manifest(
    output_dir: Path,
    run_id: str,
    request: dict[str, Any],
    final_url: str,
    records: list[dict[str, Any]],
) -> str:
    source_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    manifest = {
        "contractVersion": CONTRACT_VERSION,
        "runId": run_id,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "recorder": {"version": "0.1.0", "sha256": source_hash},
        "url": _redacted_url(request["url"]),
        "finalUrl": _redacted_url(final_url),
        "viewport": {
            "width": request["width"], "height": request["height"],
            "mobile": request["mobile"], "reducedMotion": request["reduced_motion"],
        },
        "modes": {"gpu": True, "scroll": request["scroll"]},
        "files": records,
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest_path.name


async def run_capture(request: dict[str, Any]) -> dict[str, Any]:
    run_id = request["run_id"]
    output_dir: Path = request["output_dir"]
    name = request["name"]
    webm_path = output_dir / f"{name}.webm"
    jank_path = output_dir / f"{name}.jank.json"
    manifest_path = output_dir / "manifest.json"
    if output_dir.exists() and not output_dir.is_dir():
        return _worker_result("blocked", run_id, reason_code="output-dir-invalid", message="Run output path is not a directory")
    if output_dir.exists() and any(output_dir.iterdir()) and not request["overwrite"]:
        return _worker_result("blocked", run_id, reason_code="output-exists", message="Run directory is not empty")
    for path in (webm_path, jank_path, manifest_path):
        if path.exists() and path.is_symlink():
            return _worker_result("blocked", run_id, reason_code="artifact-symlink", message="Artifact path is a symlink")
    try:
        domain = validate_public_http_url(request["url"], resolver=None)
    except WorkerFailure as error:
        return _worker_result(error.status, run_id, reason_code=error.reason_code, message=str(error))
    try:
        executable, _ = await _browser_executable()
    except WorkerFailure as error:
        return _worker_result(error.status, run_id, reason_code=error.reason_code, message=str(error))
    if not request.get("egress_proxy_host") or not request.get("egress_proxy_port"):
        return _worker_result("blocked", run_id, reason_code="capture-egress-boundary-unavailable", message="A runner namespace proxy is required")
    try:
        runtime = await _browser_runtime_versions(executable)
    except WorkerFailure as error:
        return _worker_result(error.status, run_id, reason_code=error.reason_code, message=str(error))
    try:
        egress_evidence, egress_attestation = _load_egress_attestation(
            executable, runtime, domain["hostname"], run_id,
        )
    except WorkerFailure as error:
        return _worker_result(error.status, run_id, reason_code=error.reason_code, message=str(error))
    if not shutil.which("ffmpeg") or not shutil.which("ffprobe"):
        return _worker_result("blocked", run_id, reason_code="media-tools-unavailable", message="ffmpeg and ffprobe are required")

    output_dir.mkdir(parents=True, exist_ok=True)
    if not output_dir.is_dir():
        return _worker_result("blocked", run_id, reason_code="output-dir-invalid", message="Run output path is not a directory")
    allowed_existing = {webm_path.name, jank_path.name, manifest_path.name}
    unexpected = [item for item in output_dir.iterdir() if item.name not in allowed_existing]
    if unexpected:
        return _worker_result("blocked", run_id, reason_code="output-dir-not-empty", message="Run directory contains unexpected files")
    if request["overwrite"]:
        for existing in (webm_path, jank_path, manifest_path):
            if existing.exists():
                existing.unlink()
    temp_root = Path(tempfile.mkdtemp(prefix=f"bu-{run_id[:8]}-", dir="/tmp"))
    profile_dir = temp_root / "browser-use-user-data-dir-profile"
    source_video = temp_root / "capture-source.mp4"
    browser: asyncio.subprocess.Process | None = None
    browser_stderr_task: asyncio.Task[str] | None = None
    session: Any = None
    cdp: CDPSocket | None = None
    ffmpeg_process: asyncio.subprocess.Process | None = None
    ffmpeg_stderr_task: asyncio.Task[str] | None = None
    frame_task: asyncio.Task[int] | None = None
    stop_frames = asyncio.Event()
    cleanup_ok = True
    partial_reason: tuple[str, str] | None = None
    final_url = request["url"]
    preflight_consent: dict[str, Any] | None = None
    recorded_consent: dict[str, Any] = {"mode": request["consent_mode"], "verified": False, "blindSpots": []}
    consent: dict[str, Any] = {"mode": request["consent_mode"], "verified": False, "blindSpots": []}
    scroll_consent_checks: list[dict[str, Any]] = []
    consent_history: list[dict[str, Any]] = []
    jank_report: dict[str, Any] | None = None
    video_info: dict[str, Any] | None = None
    phases: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    interactions: list[dict[str, Any]] = []
    scroll_evidence: dict[str, Any] = {
        "requested": request["scroll"], "completed": not request["scroll"],
        "requestedDistance": request["scroll_distance"], "measuredDistance": None,
        "completedDistance": 0, "actualDistance": 0, "timedOut": False, "truncated": False,
    }
    observer_ready = False
    observer_error: str | None = None
    gpu_verified = False
    gpu_renderer: dict[str, Any] = {"verified": False, "renderer": None}
    settle_evidence: dict[str, bool] = {"networkIdle": False, "fontsReady": False}
    entries: list[dict[str, Any]] = []
    cdp_port = 0
    cdp_origin = ""
    profile = None
    proxy_port = request["egress_proxy_port"]
    request_guard_task: asyncio.Task[None] | None = None

    try:
        profile_dir.mkdir()
        cdp_port = reserve_loopback_port()
        cdp_origin = f"http://127.0.0.1:{cdp_port}"
        async with asyncio.timeout(request["timeout_ms"] / 1000):
            try:
                from browser_use.browser.profile import BrowserProfile
                from browser_use.browser.session import BrowserSession
            except ImportError as error:
                raise WorkerFailure("browser-use-api-unavailable", "BrowserSession and BrowserProfile APIs are unavailable") from error

            profile = BrowserProfile(
                **_browser_profile_options(
                    executable=executable,
                    profile_dir=profile_dir,
                    cdp_origin=cdp_origin,
                    approved_hostname=domain["hostname"],
                    request=request,
                )
            )
            chrome_args = _clean_chrome_args(
                profile.get_args(), cdp_port, proxy_port, profile_dir,
                proxy_host=request["egress_proxy_host"],
            )
            session = BrowserSession(cdp_url=cdp_origin, browser_profile=profile)
            browser = await asyncio.create_subprocess_exec(
                str(executable), *chrome_args,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            browser_stderr_task = asyncio.create_task(_drain_stderr(browser.stderr))
            browser_namespace_inode = os.stat(f"/proc/{browser.pid}/ns/net").st_ino
            if browser_namespace_inode != egress_attestation["networkNamespaceInode"]:
                raise WorkerFailure("capture-egress-namespace-mismatch", "Chrome did not inherit the attested network namespace")
            cdp_info = await wait_for_cdp(cdp_port, browser, timeout=30)
            if not cdp_info.get("browserVersion"):
                raise WorkerFailure("browser-startup-unverified", "Chrome CDP did not report a browser version")
            await asyncio.wait_for(session.start(), timeout=30)
            page = await session.get_current_page()
            if page is None:
                page = await session.new_page()

            if request["consent_preflight"] and request["consent_mode"] != "none":
                target_id = str(session.agent_focus_target_id or "")
                if not target_id:
                    raise WorkerFailure("browser-target-unavailable", "Browser Use did not expose its focused target")
                cdp = await connect_target_cdp(cdp_port, target_id)
                await cdp.command("Page.enable")
                await cdp.command("Fetch.enable", {"patterns": [
                    {"urlPattern": "http://*", "resourceType": "Document"},
                    {"urlPattern": "https://*", "resourceType": "Document"},
                ]})
                request_guard_task = asyncio.create_task(
                    _guard_document_requests(cdp, domain["hostname"], failures)
                )
                await cdp.command("Emulation.setDeviceMetricsOverride", {
                    "width": request["width"], "height": request["height"], "deviceScaleFactor": 1,
                    "mobile": request["mobile"], "screenWidth": request["width"], "screenHeight": request["height"],
                })
                await cdp.command("Emulation.setTouchEmulationEnabled", {"enabled": request["mobile"]})
                await cdp.command("Emulation.setEmulatedMedia", {
                    "features": [{"name": "prefers-reduced-motion", "value": "reduce" if request["reduced_motion"] else "no-preference"}]
                })
                await page.set_viewport_size(request["width"], request["height"])
                _validate_approved_domain(request["url"], domain["hostname"], stage="consent preflight")
                await asyncio.wait_for(page.goto(request["url"]), timeout=60)
                preflight_final = await _wait_for_approved_navigation(
                    page, domain["hostname"], stage="consent preflight redirect"
                )
                preflight_consent = await asyncio.wait_for(
                    handle_consent(page, request, "preflight"),
                    timeout=max(3, request["consent_budget_ms"] / 1000 + 2),
                )
                consent_history.append(preflight_consent)
                await session.close_page(page)
                await _stop_request_guard(cdp, request_guard_task)
                request_guard_task = None
                await cdp.close()
                cdp = None
                page = await session.new_page()

            target_id = str(session.agent_focus_target_id or "")
            if not target_id:
                raise WorkerFailure("browser-target-unavailable", "Browser Use did not expose its focused target")
            cdp = await connect_target_cdp(cdp_port, target_id)
            await cdp.command("Page.enable")
            await cdp.command("Network.enable")
            await cdp.command("Fetch.enable", {"patterns": [
                {"urlPattern": "http://*", "resourceType": "Document"},
                {"urlPattern": "https://*", "resourceType": "Document"},
            ]})
            request_guard_task = asyncio.create_task(
                _guard_document_requests(cdp, domain["hostname"], failures)
            )
            await _configure_page(page, cdp, request)
            await cdp.command("Page.addScriptToEvaluateOnNewDocument", {"source": JANK_INIT_SCRIPT})
            ffmpeg_process, ffmpeg_stderr_task = await start_ffmpeg_recorder(source_video)
            frame_task = asyncio.create_task(_capture_frames(cdp, ffmpeg_process, stop_frames))
            _validate_approved_domain(request["url"], domain["hostname"], stage="capture navigation")
            await asyncio.wait_for(page.goto(request["url"]), timeout=60)
            final_url = await _wait_for_approved_navigation(
                page, domain["hostname"], stage="capture redirect"
            )
            _page_state = await _page_json(
                page,
                "() => JSON.stringify({ready:window.__jankObserverReady===true,"
                "error:window.__jankObserverError||null,"
                "reduced:matchMedia('(prefers-reduced-motion: reduce)').matches,"
                "width:innerWidth,height:innerHeight,touch:navigator.maxTouchPoints>0})",
                label="page instrumentation check",
            )
            observer_ready = bool(_page_state.get("ready"))
            observer_error = _page_state.get("error")
            mode_matches = (
                bool(_page_state.get("reduced")) == request["reduced_motion"]
                and int(_page_state.get("width", 0)) == request["width"]
                and int(_page_state.get("height", 0)) == request["height"]
                and (not request["mobile"] or bool(_page_state.get("touch")))
            )
            if not mode_matches:
                failures.append({"kind": "viewport-mode", "selector": "emulation", "error": "requested viewport or motion mode was not verified"})
            if not observer_ready:
                observer_error = observer_error or "observer_not_ready"
            gpu_renderer = await _page_json(
                page,
                "() => { const c=document.createElement('canvas'); "
                "const gl=c.getContext('webgl')||c.getContext('experimental-webgl'); "
                "if(!gl)return JSON.stringify({available:false,renderer:null}); "
                "const ext=gl.getExtension('WEBGL_debug_renderer_info'); "
                "const renderer=ext?gl.getParameter(ext.UNMASKED_RENDERER_WEBGL):gl.getParameter(gl.RENDERER); "
                "return JSON.stringify({available:!!renderer,renderer:String(renderer||'')}); }",
                label="WebGL renderer check",
            )
            renderer_name = str(gpu_renderer.get("renderer") or "")
            gpu_verified = (
                bool(gpu_renderer.get("available"))
                and bool(re.search(r"nvidia|geforce|quadro|tesla|\brtx\b|\ba\d{2,3}\b|\bh\d{2,3}\b", renderer_name, re.I))
                and not bool(re.search(r"swiftshader|llvmpipe|software rasterizer|lavapipe", renderer_name, re.I))
            )
            gpu_renderer["verified"] = gpu_verified
            if not gpu_verified:
                failures.append({"kind": "gpu-renderer", "selector": "webgl", "error": "hardware-backed NVIDIA WebGL renderer was not verified"})

            recorded_consent = await asyncio.wait_for(
                handle_consent(page, request, "recorded"),
                timeout=max(3, request["consent_budget_ms"] / 1000 + 2),
            )
            consent_history.append(recorded_consent)
            current_url = await page.get_url()
            _validate_approved_domain(current_url, domain["hostname"], stage="consent handling")
            consent = combine_consent(request["consent_mode"], None, recorded_consent, consent_history[:-1])
            settle_evidence = await _settle_page(page, cdp, request)
            await _mark_phase(page, phases, "load")
            await _run_hover_click(page, request, domain["hostname"], failures, interactions)
            await _mark_phase(page, phases, "manual-interactions")
            if request["auto_discover"]:
                await _auto_discover(page, request, domain["hostname"], failures, interactions)
            await _mark_phase(page, phases, "auto-discover")
            async def recheck_consent_after_scroll() -> dict[str, Any]:
                return await asyncio.wait_for(
                    handle_consent(page, request, "after-scroll-step"),
                    timeout=max(3, request["consent_budget_ms"] / 1000 + 2),
                )

            scroll_evidence, scroll_consent_checks = await _scroll_page(
                page, request, domain["hostname"], recheck_consent_after_scroll
            )
            consent_history.extend(scroll_consent_checks)
            await _mark_phase(page, phases, "scroll")
            await asyncio.sleep(request["tail_ms"] / 1000)
            await _mark_phase(page, phases, "tail")
            final_url = await page.get_url()
            _validate_approved_domain(final_url, domain["hostname"], stage="capture interactions")
            if request["jank_check"]:
                jank_data = await _page_json(
                    page,
                    "() => JSON.stringify({entries:window.__jankEntries||[],"
                    "ready:window.__jankObserverReady===true,error:window.__jankObserverError||null})",
                    label="jank observer collection",
                )
                if not isinstance(jank_data, dict):
                    raise WorkerFailure("jank-evidence-unverified", "Jank observer returned invalid data", status="partial")
                entries = jank_data.get("entries", []) if isinstance(jank_data.get("entries"), list) else []
                observer_ready = observer_ready and bool(jank_data.get("ready"))
                observer_error = jank_data.get("error") or observer_error
            else:
                observer_error = "jank_check_disabled"
            final_consent = await asyncio.wait_for(
                handle_consent(page, request, "before-finalization"),
                timeout=max(3, request["consent_budget_ms"] / 1000 + 2),
            )
            consent_history.append(final_consent)
            consent = combine_consent(request["consent_mode"], None, final_consent, consent_history[:-1])
            jank_report = build_jank_report(
                final_url=final_url, consent=consent, entries=entries, observer_error=observer_error,
                observer_ready=observer_ready and request["jank_check"], phases=phases,
                threshold_ms=request["jank_threshold_ms"], interaction_failures=failures,
                interactions=interactions, scroll=scroll_evidence,
            )
    except TimeoutError:
        partial_reason = ("capture-timeout", "Capture exceeded its bounded timeout")
    except WorkerFailure as error:
        partial_reason = (error.reason_code, str(error))
        if error.status == "partial":
            partial_reason = (error.reason_code, str(error))
    except asyncio.CancelledError:
        partial_reason = ("capture-cancelled", "Capture was cancelled")
    except Exception as error:
        partial_reason = ("capture-worker-failed", _redact_text(error))
        _log(f"capture worker failed: {type(error).__name__}: {error}")
    finally:
        stop_frames.set()
        if frame_task:
            try:
                await asyncio.wait_for(frame_task, timeout=12)
            except Exception as error:
                partial_reason = partial_reason or ("video-recording-failed", _redact_text(error))
                if not frame_task.done():
                    frame_task.cancel()
                    await asyncio.gather(frame_task, return_exceptions=True)
        if cdp:
            await _stop_request_guard(cdp, request_guard_task)
            request_guard_task = None
            await cdp.close()
        cleanup_ok = await cleanup_browser_lifecycle(session, browser) and cleanup_ok
        if ffmpeg_process:
            ffmpeg_ok = await _terminate_ffmpeg(ffmpeg_process)
            cleanup_ok = cleanup_ok and ffmpeg_ok
            if ffmpeg_ok:
                try:
                    video_info = await convert_and_validate_video(source_video, webm_path)
                except WorkerFailure as error:
                    partial_reason = partial_reason or (error.reason_code, str(error))
        if ffmpeg_stderr_task:
            try:
                await asyncio.wait_for(ffmpeg_stderr_task, timeout=3)
            except Exception:
                cleanup_ok = False
        if browser_stderr_task:
            try:
                await asyncio.wait_for(browser_stderr_task, timeout=3)
            except Exception:
                pass
        cleanup_ok = _safe_delete_tree(temp_root) and cleanup_ok

    if jank_report is None and request["jank_check"]:
        fallback_consent = consent if isinstance(consent, dict) else {"mode": request["consent_mode"], "verified": False, "blindSpots": []}
        jank_report = build_jank_report(
            final_url=final_url, consent=fallback_consent, entries=entries,
            observer_error=observer_error or "observer_unavailable", observer_ready=False,
            phases=phases, threshold_ms=request["jank_threshold_ms"],
            interaction_failures=failures, interactions=interactions, scroll=scroll_evidence,
        )
    artifacts: dict[str, str] = {}
    records: list[dict[str, Any]] = []
    evidence: dict[str, Any] = {
        "url": _redacted_url(request["url"]),
        "finalUrl": _redacted_url(final_url),
        "viewport": {
            "width": request["width"], "height": request["height"],
            "mobile": request["mobile"], "reducedMotion": request["reduced_motion"],
        },
        "consent": {"mode": request["consent_mode"], "verified": bool(consent.get("verified"))},
        "runtime": runtime,
        "gpu": gpu_renderer,
        "egress": egress_evidence,
        "egressAttestation": egress_attestation,
        "settle": settle_evidence,
    }
    if video_info and webm_path.is_file() and webm_path.stat().st_size:
        try:
            artifacts["webm"] = webm_path.name
            records.append(_artifact_record(webm_path))
        except WorkerFailure as error:
            partial_reason = partial_reason or (error.reason_code, str(error))
    if jank_report is not None:
        try:
            jank_path.write_text(json.dumps(jank_report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            artifacts["jank"] = jank_path.name
            records.append(_artifact_record(jank_path))
        except OSError as error:
            partial_reason = partial_reason or ("jank-artifact-write-failed", _redact_text(error))
    if video_info:
        evidence["video"] = video_info
    if jank_report:
        evidence["jank"] = {
            "schemaVersion": jank_report["schemaVersion"],
            "longTaskCount": jank_report["longTaskCount"],
            "totalBlockingTimeMs": jank_report["totalBlockingTimeMs"],
            "status": jank_report["status"],
        }
    evidence["cleanupVerified"] = cleanup_ok
    if not cleanup_ok:
        partial_reason = partial_reason or ("cleanup-incomplete", "Browser or temporary-file cleanup was incomplete")
    if len(records) == 2:
        try:
            manifest_name = _write_manifest(output_dir, run_id, request, final_url, records)
            artifacts["manifest"] = manifest_name
        except OSError as error:
            partial_reason = partial_reason or ("manifest-write-failed", _redact_text(error))
    else:
        manifest_name = None
    complete = (
        manifest_name is not None and video_info is not None and jank_report is not None
        and jank_report["status"] == "valid" and consent.get("verified") is True
        and gpu_verified and cleanup_ok and partial_reason is None
    )
    if complete:
        return _worker_result(
            "complete",
            run_id,
            manifest=manifest_name,
            artifacts=artifacts,
            evidence=evidence,
            media_validation={"status": "valid", **video_info},
        )
    if partial_reason is None:
        if not artifacts.get("webm"):
            partial_reason = ("video-evidence-unavailable", "A valid WebM capture was not produced")
        elif not artifacts.get("jank"):
            partial_reason = ("jank-evidence-unavailable", "A valid jank report was not produced")
        elif not consent.get("verified"):
            partial_reason = ("consent-unverified", "Consent state could not be verified")
        else:
            partial_reason = ("evidence-partial", "One or more evidence checks did not pass")
    status = "partial" if artifacts else "blocked"
    return _worker_result(
        status, run_id, reason_code=partial_reason[0], message=partial_reason[1],
        manifest=manifest_name, artifacts=artifacts, evidence=evidence,
        media_validation=(
            {"status": "valid", **video_info}
            if video_info is not None
            else {"status": "partial" if status == "partial" else "blocked", "reason": partial_reason[1]}
        ),
    )


def _result_for_bad_input(error: BaseException, payload: Any = None) -> dict[str, Any]:
    run_id = None
    if isinstance(payload, dict):
        try:
            run_id = _canonical_run_id(payload.get("run_id"))
        except ValueError:
            pass
    return _worker_result("blocked", run_id, reason_code="capture-input-invalid", message=str(error))


async def _main_async() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        return _worker_result("blocked", None, reason_code="capture-input-too-large", message="Input exceeds the size limit")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        return _result_for_bad_input(ValueError("stdin must contain one valid JSON object"))
    try:
        request = validate_request(payload)
    except (TypeError, ValueError) as error:
        return _result_for_bad_input(error, payload)
    return await run_capture(request)


def main() -> int:
    configure_logging()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    task = loop.create_task(_main_async())
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, task.cancel)
        except (NotImplementedError, RuntimeError):
            pass
    try:
        try:
            result = loop.run_until_complete(task)
        except asyncio.CancelledError:
            result = _worker_result("blocked", None, reason_code="capture-cancelled", message="Capture was cancelled")
        except BaseException as error:
            _log(f"worker terminated: {type(error).__name__}: {error}")
            result = _worker_result("blocked", None, reason_code="capture-worker-failed", message=str(error))
        sys.stdout.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n")
        sys.stdout.flush()
        return 0
    finally:
        pending = [item for item in asyncio.all_tasks(loop) if not item.done()]
        for item in pending:
            item.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.close()


if __name__ == "__main__":
    raise SystemExit(main())
