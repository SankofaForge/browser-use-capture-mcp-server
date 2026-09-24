"""Local stdio MCP boundary for Browser Use capture on a Vast GPU runner."""

from __future__ import annotations

import asyncio
import functools
import hashlib
import ipaddress
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit, urlunsplit

from mcp.server.mcpserver import MCPServer

from browser_use_capture_mcp.vast_runner import VastRunner, VastRunnerError


CONTRACT_VERSION = "capture-cell.v2"
SERVER_VERSION = "0.2.0"
DEFAULT_OUTPUT = Path("artifacts/design-inspiration/site-motion-capture")
NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")
CAPABILITY_TTL_SECONDS = 120
CAPTURE_BRIDGE_MARGIN_SECONDS = 750
_CAPABILITY_RECORDS: dict[str, dict[str, Any]] = {}
_CAPTURE_LOCK = asyncio.Lock()
SENSITIVE_QUERY_KEYS = re.compile(
    r"^(?:access_token|api_key|auth|authorization|cookie|key|password|secret|session|signature|token)$",
    re.IGNORECASE,
)

mcp = MCPServer("browser-use-capture", version=SERVER_VERSION)


def _serialize_captures(function):
    @functools.wraps(function)
    async def serialized(*args, **kwargs):
        async with _CAPTURE_LOCK:
            return await function(*args, **kwargs)

    return serialized


def _redact(value: str) -> str:
    text = re.sub(
        r"((?:authorization|api[_-]?key|token|secret|password|cookie)\s*[:=]\s*)[^\s,;]+",
        r"\1[REDACTED]",
        str(value),
        flags=re.IGNORECASE,
    )
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
    return text


def _redact_output(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if str(key).lower() in {"url", "finalurl"} and isinstance(item, str):
                result[key] = _redact_url(item)
            else:
                result[key] = _redact_output(item)
        return result
    if isinstance(value, list):
        return [_redact_output(item) for item in value]
    if isinstance(value, str):
        return _redact(value)
    return value


def _redact_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        query = [
            (key, "[REDACTED]" if SENSITIVE_QUERY_KEYS.fullmatch(key) else item)
            for key, item in parse_qsl(parts.query, keep_blank_values=True)
        ]
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))
    except ValueError:
        return "[REDACTED URL]"


def _blocked(reason_code: str, message: str, *, diagnostic: str | None = None, **details: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "contractVersion": CONTRACT_VERSION,
        "status": "blocked",
        "reasonCode": reason_code,
        "message": _redact(message),
    }
    if diagnostic:
        payload["diagnostic"] = _redact(diagnostic)[:1200]
    payload.update(_redact_output(details))
    return payload


def _public_address(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not any((
        parsed.is_private,
        parsed.is_loopback,
        parsed.is_link_local,
        parsed.is_reserved,
        parsed.is_multicast,
        parsed.is_unspecified,
    ))


def _validate_url(raw_url: str) -> str:
    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("url must be a public HTTP or HTTPS URL without embedded credentials")
    try:
        addresses = {item[4][0] for item in __import__("socket").getaddrinfo(parsed.hostname, None)}
    except OSError as error:
        raise ValueError("url host could not be resolved safely") from error
    if not addresses or any(not _public_address(address) for address in addresses):
        raise ValueError("url must resolve only to public IP addresses")
    return raw_url


def _bounded_int(value: Any, field: str, default: int, minimum: int, maximum: int) -> int:
    if value is None:
        value = default
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{field} must be an integer from {minimum} to {maximum}")
    return value


def _bool_option(value: Any, field: str, default: bool = False) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be a boolean")
    return value


def _selector(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 300 or "\x00" in value:
        raise ValueError(f"{field} must be a selector string of at most 300 characters")
    return value


def _output_directory(value: Any) -> Path:
    if value is not None and not isinstance(value, str):
        raise ValueError("output_dir must be a path string")
    output_dir = Path(value or os.environ.get("SITE_MOTION_OUTPUT_DIR", DEFAULT_OUTPUT)).expanduser()
    if not output_dir.is_absolute():
        output_dir = Path.cwd() / output_dir
    output_dir = output_dir.resolve()
    approved_roots = [
        Path(os.environ.get("SITE_MOTION_APPROVED_OUTPUT_ROOT", Path.cwd())).expanduser().resolve(),
        Path(tempfile.gettempdir()).resolve(),
    ]
    if not any(output_dir == root or root in output_dir.parents for root in approved_roots):
        raise ValueError("output_dir must stay inside the approved workspace or temporary root")
    return output_dir


def _validate_capture_input(input_data: dict[str, Any]) -> dict[str, Any]:
    url = _validate_url(str(input_data.get("url", "")))
    consent_mode = input_data.get("consent_mode", "reject")
    if consent_mode not in {"reject", "accept", "none", "granular"}:
        raise ValueError("consent_mode must be reject, accept, none, or granular")
    consent_accept_approved = _bool_option(input_data.get("consent_accept_approved"), "consent_accept_approved")
    if consent_mode == "accept" and not consent_accept_approved:
        raise ValueError("accept consent_mode requires explicit consent_accept_approved=true")
    gpu = _bool_option(input_data.get("gpu"), "gpu", True)
    if not gpu:
        raise ValueError("Browser Use capture requires gpu=true")
    selectors = {
        "consent_selector": _selector(input_data.get("consent_selector"), "consent_selector"),
        "consent_settings_selector": _selector(input_data.get("consent_settings_selector"), "consent_settings_selector"),
        "consent_optional_selector": _selector(input_data.get("consent_optional_selector"), "consent_optional_selector"),
        "consent_save_selector": _selector(input_data.get("consent_save_selector"), "consent_save_selector"),
        "hover_selector": _selector(input_data.get("hover_selector"), "hover_selector"),
        "click_selector": _selector(input_data.get("click_selector"), "click_selector"),
    }
    if consent_mode == "granular" and any(not selectors[key] for key in (
        "consent_settings_selector", "consent_optional_selector", "consent_save_selector",
    )):
        raise ValueError("granular consent_mode requires settings, optional, and save selectors")
    name = input_data.get("name")
    if name is not None and (not isinstance(name, str) or not NAME_PATTERN.fullmatch(name)):
        raise ValueError("name must contain 1 to 81 safe file-name characters")
    scroll_distance = input_data.get("scroll_distance")
    if scroll_distance is not None:
        scroll_distance = _bounded_int(scroll_distance, "scroll_distance", 0, 0, 1000000)
    return {
        "url": url,
        "width": _bounded_int(input_data.get("width"), "width", 1920, 240, 7680),
        "height": _bounded_int(input_data.get("height"), "height", 1080, 240, 4320),
        "name": name or f"browser-use-{uuid.uuid4().hex[:12]}",
        "output_dir": _output_directory(input_data.get("output_dir")),
        "settle_ms": _bounded_int(input_data.get("settle_ms"), "settle_ms", 2000, 0, 30000),
        "scroll_distance": scroll_distance,
        "scroll_step": _bounded_int(input_data.get("scroll_step"), "scroll_step", 100, 1, 4000),
        "scroll_pause_ms": _bounded_int(input_data.get("scroll_pause_ms"), "scroll_pause_ms", 80, 0, 10000),
        "tail_lines": _bounded_int(input_data.get("tail_lines"), "tail_lines", 800, 0, 30000),
        "auto_discover": _bool_option(input_data.get("auto_discover"), "auto_discover"),
        "consent_mode": consent_mode,
        "consent_accept_approved": consent_accept_approved,
        "consent_budget_ms": _bounded_int(input_data.get("consent_budget_ms"), "consent_budget_ms", 8000, 0, 30000),
        "consent_max_clicks": _bounded_int(input_data.get("consent_max_clicks"), "consent_max_clicks", 6, 1, 12),
        "consent_wait_ms": _bounded_int(input_data.get("consent_wait_ms"), "consent_wait_ms", 1200, 0, 10000),
        "consent_preflight": _bool_option(input_data.get("consent_preflight"), "consent_preflight", True),
        "mobile": _bool_option(input_data.get("mobile"), "mobile"),
        "reduced_motion": _bool_option(input_data.get("reduced_motion"), "reduced_motion"),
        "no_scroll": _bool_option(input_data.get("no_scroll"), "no_scroll"),
        "gpu": gpu,
        "timeout_ms": _bounded_int(input_data.get("timeout_ms"), "timeout_ms", 180000, 1000, 270000),
        "overwrite": _bool_option(input_data.get("overwrite"), "overwrite"),
        **selectors,
    }


def _browser_use_compatibility_gate() -> dict[str, Any] | None:
    try:
        VastRunner().validate_configuration()
    except VastRunnerError as error:
        return _blocked(error.reason_code, str(error), diagnostic=error.diagnostic)
    return None


def _issue_capability_record(probe: dict[str, Any], runner: VastRunner) -> dict[str, Any]:
    capability_id = uuid.uuid4().hex
    _CAPABILITY_RECORDS[capability_id] = {
        "created_at": time.time(),
        "instance_id": runner.instance_id,
        "browser_path": runner.browser_path,
        "browser_use_version": probe.get("browserUseVersion"),
        "gpu": probe.get("gpu", {}).get("device"),
    }
    return {
        "contractVersion": CONTRACT_VERSION,
        "status": "verified",
        "gpu": probe["gpu"],
        "cpu": probe["cpu"],
        "egressPolicy": probe["egressPolicy"],
        "browserUseVersion": probe.get("browserUseVersion"),
        "browserVersion": probe.get("browserVersion"),
        "browserExecutable": probe.get("browserExecutable"),
        "gpu_check_id": capability_id,
        "expiresInSeconds": CAPABILITY_TTL_SECONDS,
    }


def _verified_capability(capability_id: str | None, runner: VastRunner) -> dict[str, Any] | None:
    if not capability_id:
        return _blocked("gpu-check-required", "A verified gpu_check_id is required")
    record = _CAPABILITY_RECORDS.get(capability_id)
    if record is None:
        return _blocked("gpu-check-invalid", "gpu_check_id is not recognized")
    if time.time() - record["created_at"] > CAPABILITY_TTL_SECONDS:
        _CAPABILITY_RECORDS.pop(capability_id, None)
        return _blocked("gpu-check-expired", "gpu_check_id has expired")
    if record["instance_id"] != runner.instance_id or record["browser_path"] != runner.browser_path:
        return _blocked("gpu-check-stale", "gpu_check_id does not match the configured Vast runner and browser")
    return None


def artifact_digest(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return {"path": str(path), "size": size, "sha256": digest.hexdigest()}


def validate_media(path: Path, ffprobe: str = "ffprobe") -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size == 0:
        return {"status": "blocked", "reason": "zero-byte WebM"}
    with path.open("rb") as source:
        if source.read(4) != bytes.fromhex("1a45dfa3"):
            return {"status": "blocked", "reason": "file does not have the WebM/Matroska EBML header"}
    if not shutil.which(ffprobe):
        return {"status": "blocked", "reason": "ffprobe is unavailable"}
    try:
        result = subprocess.run(
            [ffprobe, "-v", "error", "-show_entries", "format=format_name,duration:stream=codec_type", "-of", "json", str(path)],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            env={key: value for key, value in os.environ.items() if key != "VAST_API_KEY"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "blocked", "reason": "ffprobe could not validate the WebM"}
    if result.returncode != 0:
        return {"status": "blocked", "reason": "ffprobe rejected the WebM"}
    try:
        probe = json.loads(result.stdout)
        format_data = probe.get("format", {})
        duration = float(format_data.get("duration", 0))
    except (ValueError, TypeError, json.JSONDecodeError):
        return {"status": "blocked", "reason": "ffprobe returned invalid JSON"}
    video_stream_count = sum(1 for stream in probe.get("streams", []) if stream.get("codec_type") == "video")
    if "webm" not in str(format_data.get("format_name", "")).split(",") or not math.isfinite(duration) or duration <= 0 or video_stream_count < 1:
        return {"status": "blocked", "reason": "ffprobe returned no valid WebM duration"}
    return {"status": "valid", "format": format_data["format_name"], "durationSeconds": duration, "videoStreamCount": video_stream_count}


def _validate_jank_report(report: Any) -> dict[str, Any]:
    if not isinstance(report, dict) or report.get("schemaVersion") != "jank-report.v1":
        raise ValueError("jank report schema validation failed")
    if report.get("status") not in {"valid", "partial"}:
        raise ValueError("jank report has no valid completion status")
    if (
        isinstance(report.get("longTaskCount"), bool)
        or not isinstance(report.get("longTaskCount"), int)
        or report["longTaskCount"] < 0
    ):
        raise ValueError("jank report longTaskCount is invalid")
    if not isinstance(report.get("longTasks"), list):
        raise ValueError("jank report longTasks must be an array")
    if report["longTaskCount"] != len(report["longTasks"]):
        raise ValueError("jank report longTaskCount does not match its entries")
    if report.get("observerError") is not None:
        raise ValueError("jank observer failed")
    for field in ("totalBlockingTimeMs", "thresholdMs"):
        value = report.get(field)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise ValueError(f"jank report {field} is invalid")
    for item in report["longTasks"]:
        if not isinstance(item, dict):
            raise ValueError("jank report long task is invalid")
        start_time = item.get("startTime")
        duration = item.get("duration")
        if any(
            isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0
            for value in (start_time, duration)
        ):
            raise ValueError("jank report contains a non-finite long task")
    if report.get("status") == "valid":
        consent = report.get("consent")
        scroll = report.get("scroll")
        if not isinstance(consent, dict) or consent.get("verified") is not True or consent.get("blindSpots"):
            raise ValueError("valid jank report has incomplete consent evidence")
        if (
            report.get("interactionFailures") != []
            or not isinstance(scroll, dict)
            or scroll.get("completed") is not True
            or scroll.get("timedOut")
            or scroll.get("truncated")
        ):
            raise ValueError("valid jank report contains incomplete interaction or scroll evidence")
    return report


def _has_symlink_targets(targets: dict[str, Path]) -> bool:
    return any(path.is_symlink() for path in targets.values())


def _validate_remote_manifest(manifest: Any, stage_dir: Path, name: str, run_id: str) -> list[dict[str, Any]]:
    expected_names = {f"{name}.webm", f"{name}.jank.json"}
    if not isinstance(manifest, dict) or manifest.get("contractVersion") != CONTRACT_VERSION:
        raise ValueError("capture-cell.v2 manifest validation failed")
    if manifest.get("runId") != run_id or not isinstance(manifest.get("files"), list):
        raise ValueError("capture manifest run ID or files are invalid")
    if len(manifest["files"]) != len(expected_names):
        raise ValueError("capture manifest does not contain exactly the expected evidence files")
    verified: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in manifest["files"]:
        if not isinstance(entry, dict):
            raise ValueError("capture manifest file entry is invalid")
        filename = entry.get("path")
        if not isinstance(filename, str) or filename not in expected_names or filename in seen:
            raise ValueError("capture manifest contains an unexpected or duplicate artifact")
        path = stage_dir / filename
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"capture artifact is missing: {filename}")
        digest = artifact_digest(path)
        if digest["size"] <= 0 or digest["size"] != entry.get("size") or digest["sha256"] != entry.get("sha256"):
            raise ValueError(f"capture artifact hash or size mismatch: {filename}")
        verified.append({"path": filename, "size": digest["size"], "sha256": digest["sha256"]})
        seen.add(filename)
    if seen != expected_names:
        raise ValueError("capture manifest evidence files are incomplete")
    return verified


def _validate_egress_attestation(
    evidence: Any,
    *,
    capture: dict[str, Any],
    run_id: str,
    runner: VastRunner,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(evidence, dict):
        raise ValueError("runner egress evidence is missing")
    summary = evidence.get("egress")
    attestation = evidence.get("egressAttestation")
    runtime = evidence.get("runtime")
    if not isinstance(summary, dict) or not isinstance(attestation, dict) or not isinstance(runtime, dict):
        raise ValueError("runner egress attestation or runtime evidence is missing")
    try:
        checked = datetime.fromisoformat(str(attestation.get("checkedAt", "")).replace("Z", "+00:00"))
        expires = datetime.fromisoformat(str(attestation.get("expiresAt", "")).replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("runner egress attestation timestamps are invalid") from error
    now = datetime.now(timezone.utc)
    approved_host = urlsplit(capture["url"]).hostname
    if not approved_host:
        raise ValueError("capture URL has no approved hostname for egress binding")
    approved_host = approved_host.encode("idna").decode("ascii").lower().rstrip(".")
    proxy_evidence = attestation.get("proxyEvidence")
    proxy_connections = proxy_evidence.get("connectionOutcomes") if isinstance(proxy_evidence, dict) else None
    proxy_verified = (
        isinstance(proxy_evidence, dict)
        and proxy_evidence.get("violations") == []
        and isinstance(proxy_connections, list)
        and any(
            isinstance(item, dict)
            and item.get("hostname") == approved_host
            and item.get("port") == (urlsplit(capture["url"]).port or (443 if urlsplit(capture["url"]).scheme == "https" else 80))
            and item.get("outcome") == "connected"
            and item.get("count", 0) > 0
            for item in proxy_connections
        )
    )
    controls = attestation.get("controls") if isinstance(attestation.get("controls"), dict) else {}
    direct_control = controls.get("direct") if isinstance(controls.get("direct"), dict) else {}
    proxied_control = controls.get("proxied") if isinstance(controls.get("proxied"), dict) else {}
    valid = (
        attestation.get("schemaVersion") == "runner-egress-boundary.v1"
        and attestation.get("runId") == run_id
        and isinstance(attestation.get("boundaryId"), str) and bool(attestation["boundaryId"].strip())
        and attestation.get("runnerInstanceId") == runner.instance_id
        and attestation.get("browserExecutable") == runner.browser_path
        and attestation.get("browserVersion") == runtime.get("browserVersion")
        and attestation.get("captureRuntime") == "browser-use"
        and attestation.get("captureRuntimeVersion") == runtime.get("browserUseVersion")
        and attestation.get("browserUseVersion") == "0.13.10"
        and attestation.get("approvedHost") == approved_host
        and isinstance(attestation.get("networkNamespaceInode"), int)
        and attestation.get("directEgressBlocked") is True
        and attestation.get("proxyPolicy") == "capture-exact-host.v1"
        and direct_control.get("status") == "blocked"
        and proxied_control.get("status") == "passed"
        and attestation.get("cleanupVerified") is True
        and checked.tzinfo is not None and expires.tzinfo is not None
        and checked <= now
        and expires - checked <= timedelta(seconds=120)
        and expires > checked
        and proxy_verified
        and summary.get("status") == "verified"
        and summary.get("boundaryId") == attestation.get("boundaryId")
        and summary.get("directEgressBlocked") is True
        and summary.get("approvedProxyProbe") is True
        and summary.get("proxyPolicy") == "capture-exact-host.v1"
        and summary.get("approvedHost") == approved_host
        and summary.get("networkNamespaceInode") == attestation.get("networkNamespaceInode")
        and summary.get("cleanupVerified") is True
    )
    if not valid:
        raise ValueError("runner egress boundary proof is stale, unbound, or incomplete")
    return summary, attestation


async def _compatibility_result(runner: VastRunner) -> dict[str, Any]:
    try:
        probe = await runner.check_compatibility()
    except VastRunnerError as error:
        return _blocked(error.reason_code, str(error), diagnostic=error.diagnostic)
    except Exception as error:
        return _blocked("browser-use-compatibility-unverified", "The remote Browser Use compatibility probe failed", diagnostic=str(error))
    if not isinstance(probe, dict):
        return _blocked(
            "browser-use-compatibility-unverified",
            "The remote Browser Use compatibility probe returned an invalid result.",
            diagnostic="probe result must be an object",
        )
    cpu = probe.get("cpu")
    gpu = probe.get("gpu")
    egress_policy = probe.get("egressPolicy")
    cpu = cpu if isinstance(cpu, dict) else {}
    gpu = gpu if isinstance(gpu, dict) else {}
    egress_policy = egress_policy if isinstance(egress_policy, dict) else {}
    unexpected_violations = egress_policy.get("unexpectedViolationCodes")
    unauthorized_connections = egress_policy.get("unauthorizedConnections")
    egress_verified = (
        egress_policy.get("status") == "verified"
        and egress_policy.get("proxyPolicyCheck") == "verified"
        and egress_policy.get("browserTrafficBoundary") == "verified"
        and egress_policy.get("browserServiceReachability") == "verified"
        and isinstance(unexpected_violations, list)
        and not unexpected_violations
        and isinstance(unauthorized_connections, list)
        and not unauthorized_connections
    )
    if (
        probe.get("status") != "verified"
        or cpu.get("status") != "verified"
        or gpu.get("status") != "verified"
        or not egress_verified
    ):
        reason = (
            probe.get("failureReason")
            or cpu.get("failureReason")
            or gpu.get("reason")
            or egress_policy.get("failureReason")
            or "compatibility checks did not pass"
        )
        if cpu.get("status") != "verified":
            code = "browser-use-compatibility-unverified"
        elif gpu.get("status") != "verified":
            code = "capture-gpu-unavailable"
        else:
            code = "capture-egress-policy-unverified"
        return _blocked(
            code,
            "CPU, GPU, and egress checks must pass before capture.",
            diagnostic=str(reason),
            cpu=cpu,
            gpu=gpu,
            egressPolicy=egress_policy,
            browserExecutable=probe.get("browserExecutable"),
            browserUseVersion=probe.get("browserUseVersion"),
            browserVersion=probe.get("browserVersion"),
            failureReason=reason,
        )
    return _issue_capability_record(probe, runner)


@mcp.tool()
async def check_capture_gpu() -> dict[str, Any]:
    """Verify the Vast runner, pinned Browser Use session, recording, jank instrumentation, and NVIDIA WebGL renderer."""
    gate = _browser_use_compatibility_gate()
    if gate:
        return gate
    return await _compatibility_result(VastRunner())


@mcp.tool()
@_serialize_captures
async def capture_site_motion(
    url: str,
    width: int = 1920,
    height: int = 1080,
    consent_mode: str = "reject",
    consent_accept_approved: bool = False,
    consent_selector: str | None = None,
    consent_settings_selector: str | None = None,
    consent_optional_selector: str | None = None,
    consent_save_selector: str | None = None,
    consent_budget_ms: int = 8000,
    consent_max_clicks: int = 6,
    consent_wait_ms: int = 1200,
    consent_preflight: bool = True,
    name: str | None = None,
    output_dir: str | None = None,
    settle_ms: int = 2000,
    scroll_distance: int | None = None,
    scroll_step: int = 100,
    scroll_pause_ms: int = 80,
    tail_lines: int = 800,
    hover_selector: str | None = None,
    click_selector: str | None = None,
    auto_discover: bool = False,
    mobile: bool = False,
    reduced_motion: bool = False,
    no_scroll: bool = False,
    gpu: bool = True,
    timeout_ms: int = 180000,
    overwrite: bool = False,
    gpu_check_id: str | None = None,
) -> dict[str, Any]:
    """Capture one deterministic motion-evidence cell on the configured Vast GPU runner."""
    raw = locals().copy()
    raw.pop("gpu_check_id")
    try:
        capture = _validate_capture_input(raw)
    except (TypeError, ValueError) as error:
        return _blocked("capture-input-invalid", str(error))
    runner = VastRunner()
    gate = _browser_use_compatibility_gate()
    if gate:
        return _redact_output({**gate, "url": capture["url"], "consent": {"mode": capture["consent_mode"], "verified": False}})
    capability_gate = _verified_capability(gpu_check_id, runner)
    if capability_gate:
        return _redact_output({**capability_gate, "url": capture["url"], "consent": {"mode": capture["consent_mode"], "verified": False}})

    output_dir = capture["output_dir"]
    stem = capture["name"]
    targets = {
        "video": output_dir / f"{stem}.webm",
        "jank": output_dir / f"{stem}.jank.json",
        "manifest": output_dir / f"{stem}.capture-cell.v2.json",
    }
    if _has_symlink_targets(targets):
        return _blocked("capture-target-symlink", "Capture output targets must not be symbolic links")
    if not capture["overwrite"] and any(path.exists() for path in targets.values()):
        return _blocked("capture-target-exists", "One or more capture artifacts already exist; set overwrite=true to replace them")
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        stage_dir = Path(tempfile.mkdtemp(prefix=f".{stem}-{uuid.uuid4().hex[:8]}-", dir=output_dir))
    except OSError as error:
        return _blocked("capture-output-unavailable", "The approved output directory could not be prepared", diagnostic=str(error))

    result: dict[str, Any] | None = None
    try:
        result = await asyncio.wait_for(
            runner.capture(capture, stage_dir),
            timeout=capture["timeout_ms"] / 1000 + CAPTURE_BRIDGE_MARGIN_SECONDS,
        )
        if result.get("status") in {"blocked", "partial"}:
            partial_files = result.get("localArtifacts") if isinstance(result.get("localArtifacts"), dict) else {}
            partial_artifacts: dict[str, Any] = {}
            partial_run_id = result.get("runId")
            if not isinstance(partial_run_id, str) or not re.fullmatch(r"[0-9a-f-]{36}", partial_run_id):
                partial_run_id = uuid.uuid4().hex
            destinations = {
                "webm": targets["video"],
                "jank": targets["jank"],
                "manifest": output_dir / f"{stem}.worker-manifest.{partial_run_id}.partial.json",
            }
            safe_names = {"webm": f"{stem}.webm", "jank": f"{stem}.jank.json", "manifest": "manifest.json"}
            for key, filename in safe_names.items():
                source = stage_dir / filename
                if partial_files.get(key) != filename or not source.is_file() or source.is_symlink() or source.stat().st_size <= 0:
                    continue
                destination = destinations[key]
                if destination.is_symlink() or (destination.exists() and not capture["overwrite"]):
                    continue
                os.replace(source, destination)
                partial_artifacts[key] = artifact_digest(destination)
            if partial_artifacts or result.get("status") == "partial":
                return {
                    "contractVersion": CONTRACT_VERSION,
                    "status": "partial",
                    "runId": result.get("runId"),
                    "reasonCode": result.get("reasonCode", "capture-partial"),
                    "failureReason": _redact(str(result.get("failureReason", result.get("message", "capture evidence is incomplete")))),
                    "url": _redact_url(capture["url"]),
                    "consent": (
                        result.get("evidence", {}).get("consent")
                        if isinstance(result.get("evidence"), dict)
                        else None
                    ) or {"mode": capture["consent_mode"], "verified": False},
                    "cleanup": result.get("remoteCleanup", "pending"),
                    "artifacts": partial_artifacts,
                }
            return _blocked(
                str(result.get("reasonCode", "capture-blocked")),
                str(result.get("message", "The remote capture worker blocked evidence creation")),
                diagnostic=str(result.get("failureReason", "")) or None,
                url=capture["url"],
                consent=result.get("consent", {"mode": capture["consent_mode"], "verified": False}),
            )
        remote_manifest_path = stage_dir / "manifest.json"
        with remote_manifest_path.open(encoding="utf-8") as source:
            remote_manifest = json.load(source)
        run_id = result.get("runId") or remote_manifest.get("runId")
        if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f-]{36}", run_id):
            raise ValueError("remote capture returned an invalid run ID")
        files = _validate_remote_manifest(remote_manifest, stage_dir, stem, run_id)
        video_path = stage_dir / f"{stem}.webm"
        jank_path = stage_dir / f"{stem}.jank.json"
        with jank_path.open(encoding="utf-8") as source:
            jank = _validate_jank_report(json.load(source))
        worker_media = result.get("mediaValidation") or remote_manifest.get("validation", {}).get("media")
        worker_duration = worker_media.get("durationSeconds") if isinstance(worker_media, dict) else None
        worker_media_valid = (
            isinstance(worker_media, dict)
            and worker_media.get("status") == "valid"
            and "webm" in str(worker_media.get("format", "")).lower().split(",")
            and isinstance(worker_duration, (int, float))
            and not isinstance(worker_duration, bool)
            and math.isfinite(worker_duration)
            and worker_duration > 0
            and isinstance(worker_media.get("videoStreamCount"), int)
            and not isinstance(worker_media.get("videoStreamCount"), bool)
            and worker_media.get("videoStreamCount", 0) >= 1
        )
        if not worker_media_valid:
            local_media = validate_media(video_path)
            if local_media.get("status") != "valid":
                raise ValueError(f"WebM evidence validation failed: {local_media.get('reason', 'remote ffprobe evidence unavailable')}")
            worker_media = local_media
        remote_evidence = result.get("evidence") if isinstance(result.get("evidence"), dict) else {}
        try:
            egress_evidence, egress_attestation = _validate_egress_attestation(
                remote_evidence, capture=capture, run_id=run_id, runner=runner,
            )
            egress_verified = True
        except ValueError as error:
            egress_evidence = {"status": "blocked", "reason": _redact(str(error))}
            egress_attestation = {}
            egress_verified = False
        worker_gpu = remote_evidence.get("gpu") if isinstance(remote_evidence.get("gpu"), dict) else {}
        renderer = str(worker_gpu.get("renderer", ""))
        gpu_verified = (
            worker_gpu.get("verified") is True
            and bool(re.search(r"nvidia|geforce|quadro|tesla|\brtx\b|\ba\d{2,3}\b|\bh\d{2,3}\b", renderer, re.I))
            and not bool(re.search(r"swiftshader|llvmpipe|software rasterizer|lavapipe", renderer, re.I))
        )
        browser_cleanup_verified = remote_evidence.get("cleanupVerified") is True
        remote_cleanup = result.get("remoteCleanup", "pending")
        cleanup_status = "confirmed" if remote_cleanup == "confirmed" and browser_cleanup_verified else "pending"
        expected_viewport = {
            "width": 390 if capture["mobile"] else capture["width"],
            "height": 844 if capture["mobile"] else capture["height"],
            "mobile": capture["mobile"],
            "reducedMotion": capture["reduced_motion"],
        }
        reported_viewport = remote_manifest.get("viewport")
        viewport_verified = isinstance(reported_viewport, dict) and all(
            reported_viewport.get(key) == value for key, value in expected_viewport.items()
        )
        manifest = {
            **remote_manifest,
            "contractVersion": CONTRACT_VERSION,
            "cellId": f"{'mobile' if capture['mobile'] else 'desktop'}-{'reduced' if capture['reduced_motion'] else 'full'}",
            "url": _redact_url(capture["url"]),
            "finalUrl": _redact_url(jank.get("finalUrl") or capture["url"]),
            "viewport": reported_viewport if viewport_verified else expected_viewport,
            "modes": {"gpu": capture["gpu"], "scroll": not capture["no_scroll"]},
            "files": files,
            "validation": {"media": worker_media, "jank": {"status": jank["status"]}},
            "cleanup": cleanup_status,
            "status": "complete" if (
                result.get("status") == "complete"
                and worker_media.get("status") == "valid"
                and jank.get("status") == "valid"
                and jank.get("consent", {}).get("verified") is True
                and cleanup_status == "confirmed"
                and gpu_verified
                and viewport_verified
                and egress_verified
            ) else "partial",
            "evidence": {
                "gpu": {"status": "verified" if gpu_verified else "blocked"},
                "egress": egress_evidence,
                "egressAttestation": egress_attestation,
                "consent": jank.get("consent"),
                "interactionFailures": jank.get("interactionFailures", []),
                "scroll": jank.get("scroll"),
            },
        }
        manifest["files"] = files
        temporary_manifest = stage_dir / "capture-cell.v2.json"
        temporary_manifest.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        backups: dict[str, Path] = {}
        published: list[str] = []
        try:
            for key, target in targets.items():
                if target.is_file():
                    backup = stage_dir / f"previous-{target.name}"
                    shutil.copy2(target, backup)
                    backups[key] = backup
            for key in ("video", "jank", "manifest"):
                source = temporary_manifest if key == "manifest" else stage_dir / targets[key].name
                os.replace(source, targets[key])
                published.append(key)
            manifest_digest = artifact_digest(targets["manifest"])
            video_digest = artifact_digest(targets["video"])
            jank_digest = artifact_digest(targets["jank"])
        except BaseException:
            for key in reversed(published):
                backup = backups.get(key)
                if backup is not None and backup.is_file():
                    os.replace(backup, targets[key])
                else:
                    targets[key].unlink(missing_ok=True)
            raise
        return {
            "contractVersion": CONTRACT_VERSION,
            "status": manifest["status"],
            "runId": run_id,
            "url": _redact_url(capture["url"]),
            "finalUrl": manifest["finalUrl"],
            "cellId": manifest["cellId"],
            "viewport": manifest["viewport"],
            "modes": manifest["modes"],
            "consent": jank.get("consent"),
            "validation": manifest["validation"],
            "cleanup": cleanup_status,
            "egress": egress_evidence,
            "artifacts": {
                "video": {**video_digest},
                "jank": {**jank_digest},
                "manifest": {**manifest_digest},
            },
            "manifestPath": str(targets["manifest"]),
        }
    except asyncio.CancelledError:
        raise
    except (OSError, ValueError, TypeError, json.JSONDecodeError, VastRunnerError) as error:
        return _blocked(
            getattr(error, "reason_code", "capture-evidence-invalid"),
            "The capture could not be validated as complete evidence",
            diagnostic=str(error),
            url=capture["url"],
            consent={"mode": capture["consent_mode"], "verified": False},
        )
    finally:
        shutil.rmtree(stage_dir, ignore_errors=True)


def cleanup_run_directory(run_directory: Path) -> str:
    if not run_directory.exists():
        return "missing"
    shutil.rmtree(run_directory)
    return "removed"


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
