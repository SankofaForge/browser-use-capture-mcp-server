from __future__ import annotations

import asyncio
import hashlib
import json
import socket
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from browser_use_capture_mcp.server import (
    CAPABILITY_TTL_SECONDS,
    _CAPABILITY_RECORDS,
    _browser_use_compatibility_gate,
    _issue_capability_record,
    _validate_capture_input,
    _validate_egress_attestation,
    _verified_capability,
    artifact_digest,
    cleanup_run_directory,
    _has_symlink_targets,
    validate_media,
    _validate_jank_report,
)
from browser_use_capture_mcp.vast_runner import VastRunner, VastRunnerError


def _public_dns(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))],
    )


def _configured_runner(monkeypatch):
    monkeypatch.setenv("VAST_INSTANCE_ID", "52085190")
    monkeypatch.setenv("VAST_API_KEY", "test-secret-not-printed")
    monkeypatch.setenv("BROWSER_USE_CHROMIUM_PATH", "/opt/google/chrome/chrome")
    return VastRunner()


def _verified_egress_policy():
    expected_denial = {
        "hostname": "clients2.google.com",
        "port": 80,
        "reason": "domain-not-approved",
    }
    return {
        "status": "verified",
        "proxyPolicyCheck": "verified",
        "browserTrafficBoundary": "verified",
        "browserServiceReachability": "verified",
        "unexpectedViolationCodes": [],
        "blockedDestinations": [expected_denial],
        "connectionOutcomes": [{
            "hostname": "clients2.google.com",
            "port": 80,
            "outcome": "blocked",
            "count": 1,
        }],
        "unauthorizedConnections": [],
        "requestAttribution": {
            "status": "unknown",
            "urlPathsCollected": False,
            "initiatorsCollected": False,
        },
    }


def test_compatibility_gate_requires_remote_runner_configuration(monkeypatch):
    monkeypatch.delenv("VAST_INSTANCE_ID", raising=False)
    monkeypatch.setenv("VAST_API_KEY", "test-secret-not-printed")
    monkeypatch.setenv("BROWSER_USE_CHROMIUM_PATH", "/opt/google/chrome/chrome")
    result = _browser_use_compatibility_gate()
    assert result["status"] == "blocked"
    assert result["reasonCode"] == "vast-instance-unconfigured"


def test_manual_compatibility_override_is_not_authoritative(monkeypatch):
    monkeypatch.setenv("BROWSER_USE_CAPTURE_COMPATIBLE", "true")
    monkeypatch.delenv("VAST_INSTANCE_ID", raising=False)
    monkeypatch.setenv("VAST_API_KEY", "test-secret-not-printed")
    monkeypatch.setenv("BROWSER_USE_CHROMIUM_PATH", "/opt/google/chrome/chrome")
    result = _browser_use_compatibility_gate()
    assert result["status"] == "blocked"
    assert result["reasonCode"] == "vast-instance-unconfigured"


def test_missing_api_key_fails_closed(monkeypatch):
    monkeypatch.setenv("VAST_INSTANCE_ID", "52085190")
    monkeypatch.delenv("VAST_API_KEY", raising=False)
    monkeypatch.setenv("BROWSER_USE_CHROMIUM_PATH", "/opt/google/chrome/chrome")
    result = _browser_use_compatibility_gate()
    assert result["reasonCode"] == "vast-api-key-unavailable"
    assert "test-secret" not in json.dumps(result)


def test_browser_path_must_be_absolute_remote_path(monkeypatch):
    monkeypatch.setenv("VAST_INSTANCE_ID", "52085190")
    monkeypatch.setenv("VAST_API_KEY", "test-secret-not-printed")
    monkeypatch.setenv("BROWSER_USE_CHROMIUM_PATH", "google-chrome")
    result = _browser_use_compatibility_gate()
    assert result["reasonCode"] == "browser-executable-unconfigured"


def test_capture_input_preserves_options_and_defaults(monkeypatch, tmp_path: Path):
    _public_dns(monkeypatch)
    result = _validate_capture_input({
        "url": "https://example.com/landing",
        "output_dir": str(tmp_path),
        "hover_selector": "#menu",
        "click_selector": "button.primary",
        "scroll_distance": 700,
        "reduced_motion": True,
    })
    assert result["consent_mode"] == "reject"
    assert result["hover_selector"] == "#menu"
    assert result["click_selector"] == "button.primary"
    assert result["scroll_distance"] == 700
    assert result["scroll_step"] == 100
    assert result["reduced_motion"] is True


def test_accept_requires_explicit_approval(monkeypatch):
    _public_dns(monkeypatch)
    with pytest.raises(ValueError, match="consent_accept_approved"):
        _validate_capture_input({"url": "https://example.com", "consent_mode": "accept"})


def test_granular_requires_all_selectors(monkeypatch):
    _public_dns(monkeypatch)
    with pytest.raises(ValueError, match="granular"):
        _validate_capture_input({"url": "https://example.com", "consent_mode": "granular"})


def test_private_dns_answer_is_rejected(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    with pytest.raises(ValueError, match="public IP"):
        _validate_capture_input({"url": "https://example.com"})


def test_public_capture_bounds_match_remote_worker_contract(monkeypatch):
    _public_dns(monkeypatch)
    capture = _validate_capture_input({
        "url": "https://example.com",
        "width": 7680,
        "height": 4320,
        "scroll_distance": 1_000_000,
        "scroll_step": 4000,
        "scroll_pause_ms": 10000,
        "tail_lines": 30000,
        "consent_budget_ms": 30000,
        "timeout_ms": 270000,
    })
    assert capture["width"] == 7680
    assert capture["height"] == 4320
    assert capture["scroll_distance"] == 1_000_000
    assert capture["timeout_ms"] == 270000

    with pytest.raises(ValueError, match="270000"):
        _validate_capture_input({"url": "https://example.com", "timeout_ms": 270001})


def test_artifact_digest_is_stable(tmp_path: Path):
    path = tmp_path / "capture.jank.json"
    path.write_text('{"schemaVersion":"jank-report.v1"}', encoding="utf-8")
    result = artifact_digest(path)
    assert result["size"] == path.stat().st_size
    assert result["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()


def test_validate_media_rejects_empty_file(tmp_path: Path):
    path = tmp_path / "empty.webm"
    path.touch()
    assert validate_media(path) == {"status": "blocked", "reason": "zero-byte WebM"}


def test_validate_media_rejects_non_webm_header(tmp_path: Path):
    path = tmp_path / "capture.webm"
    path.write_bytes(b"fixture")
    assert validate_media(path)["reason"].startswith("file does not have")


def test_validate_media_accepts_ffprobe_webm_result(tmp_path: Path, monkeypatch):
    path = tmp_path / "capture.webm"
    path.write_bytes(bytes.fromhex("1a45dfa3") + b"fixture")
    fake = tmp_path / "ffprobe"
    fake.write_text(
        "#!/bin/sh\nprintf '%s' '{\"format\":{\"format_name\":\"matroska,webm\",\"duration\":\"2.5\"},\"streams\":[{\"codec_type\":\"video\"}]}'\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:{__import__('os').environ['PATH']}")
    result = validate_media(path)
    assert result["status"] == "valid"
    assert result["durationSeconds"] == 2.5
    assert result["videoStreamCount"] == 1


def test_validate_media_rejects_webm_without_video_stream(tmp_path: Path, monkeypatch):
    path = tmp_path / "capture.webm"
    path.write_bytes(bytes.fromhex("1a45dfa3") + b"fixture")
    fake = tmp_path / "ffprobe"
    fake.write_text(
        "#!/bin/sh\nprintf '%s' '{\"format\":{\"format_name\":\"matroska,webm\",\"duration\":\"2.5\"},\"streams\":[]}'\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:{__import__('os').environ['PATH']}")
    assert validate_media(path)["status"] == "blocked"


def test_capability_is_bound_to_runner_and_expires(monkeypatch):
    runner = _configured_runner(monkeypatch)
    probe = {
        "cpu": {"status": "verified"},
        "gpu": {"status": "verified", "device": "NVIDIA GeForce RTX"},
        "egressPolicy": _verified_egress_policy(),
        "browserUseVersion": "0.13.10",
    }
    capability = _issue_capability_record(probe, runner)
    capability_id = capability["gpu_check_id"]
    assert capability["egressPolicy"] == probe["egressPolicy"]
    assert _verified_capability(capability_id, runner) is None
    monkeypatch.setenv("VAST_INSTANCE_ID", "52085191")
    assert _verified_capability(capability_id, VastRunner())["reasonCode"] == "gpu-check-stale"
    _CAPABILITY_RECORDS[capability_id]["created_at"] = time.time() - CAPABILITY_TTL_SECONDS - 1
    monkeypatch.setenv("VAST_INSTANCE_ID", "52085190")
    assert _verified_capability(capability_id, VastRunner())["reasonCode"] == "gpu-check-expired"


def test_egress_attestation_requires_fresh_bound_namespace_and_proxy_proof(monkeypatch):
    runner = _configured_runner(monkeypatch)
    now = datetime.now(timezone.utc)
    host = "example.com"
    port = 443
    attestation = {
        "schemaVersion": "runner-egress-boundary.v1",
        "boundaryId": "boundary-123",
        "runId": "aa44ec52-ae57-4c73-a574-e824ac649e37",
        "checkedAt": now.isoformat().replace("+00:00", "Z"),
        "expiresAt": (now + timedelta(seconds=90)).isoformat().replace("+00:00", "Z"),
        "runnerInstanceId": runner.instance_id,
        "browserExecutable": runner.browser_path,
        "browserVersion": "123.4.5.6",
        "captureRuntime": "browser-use",
        "captureRuntimeVersion": "0.13.10",
        "browserUseVersion": "0.13.10",
        "approvedHost": host,
        "networkNamespaceInode": 456,
        "directEgressBlocked": True,
        "proxyPolicy": "capture-exact-host.v1",
        "controls": {"direct": {"status": "blocked"}, "proxied": {"status": "passed"}},
        "proxyEvidence": {
            "violations": [],
            "connectionOutcomes": [{"hostname": host, "port": port, "outcome": "connected", "count": 1}],
        },
        "cleanupVerified": True,
    }
    summary = {
        "status": "verified",
        "boundaryId": "boundary-123",
        "directEgressBlocked": True,
        "approvedProxyProbe": True,
        "proxyPolicy": "capture-exact-host.v1",
        "approvedHost": host,
        "networkNamespaceInode": 456,
        "cleanupVerified": True,
    }
    evidence = {"egress": summary, "egressAttestation": attestation, "runtime": {"browserUseVersion": "0.13.10", "browserVersion": "123.4.5.6"}}
    capture = {"url": "https://example.com/page"}

    checked, proof = _validate_egress_attestation(evidence, capture=capture, run_id=attestation["runId"], runner=runner)
    assert checked["approvedProxyProbe"] is True
    assert proof["networkNamespaceInode"] == 456

    attestation["controls"]["direct"]["status"] = "passed"
    with pytest.raises(ValueError, match="stale, unbound, or incomplete"):
        _validate_egress_attestation(evidence, capture=capture, run_id=attestation["runId"], runner=runner)


def test_remote_manifest_requires_exact_hashed_evidence(tmp_path: Path):
    from browser_use_capture_mcp.server import _validate_remote_manifest

    video = tmp_path / "name.webm"
    jank = tmp_path / "name.jank.json"
    video.write_bytes(b"video")
    jank.write_bytes(b"report")
    manifest = {
        "contractVersion": "capture-cell.v2",
        "runId": "aa44ec52-ae57-4c73-a574-e824ac649e37",
        "files": [
            {"path": path.name, "size": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in (video, jank)
        ],
    }
    checked = _validate_remote_manifest(manifest, tmp_path, "name", manifest["runId"])
    assert {entry["path"] for entry in checked} == {"name.webm", "name.jank.json"}
    assert "egressPolicy" not in manifest
    manifest["files"][0]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="hash or size"):
        _validate_remote_manifest(manifest, tmp_path, "name", manifest["runId"])
    manifest["files"][0]["sha256"] = hashlib.sha256(video.read_bytes()).hexdigest()
    manifest["files"][0]["size"] += 1
    with pytest.raises(ValueError, match="hash or size"):
        _validate_remote_manifest(manifest, tmp_path, "name", manifest["runId"])


def test_run_directory_cleanup_is_bounded(tmp_path: Path):
    run_directory = tmp_path / "run"
    run_directory.mkdir()
    (run_directory / "capture.webm").write_bytes(b"fixture")
    assert cleanup_run_directory(run_directory) == "removed"
    assert not run_directory.exists()


def test_capture_targets_reject_dangling_symlinks(tmp_path: Path):
    target = tmp_path / "capture.webm"
    target.symlink_to(tmp_path / "missing-target.webm")
    assert _has_symlink_targets({"video": target})


def test_capture_targets_allow_regular_files(tmp_path: Path):
    target = tmp_path / "capture.webm"
    target.write_bytes(b"capture")
    assert not _has_symlink_targets({"video": target})


def test_secret_like_diagnostics_are_redacted():
    from browser_use_capture_mcp.server import _redact

    assert _redact("api_key=never-print") == "api_key=[REDACTED]"
    assert "fragment-secret" not in _redact("https://example.com/#access_token=fragment-secret")


def test_nested_capture_urls_redact_secret_query_values():
    from browser_use_capture_mcp.server import _redact_output

    result = _redact_output({
        "url": "https://example.com/?token=secret&theme=dark",
        "nested": {"finalUrl": "https://example.com/?api_key=other#access_token=fragment-secret"},
    })
    serialized = json.dumps(result)
    assert "secret" not in serialized
    assert "other" not in serialized
    assert "fragment-secret" not in serialized
    assert "theme=dark" in serialized


def test_jank_validation_rejects_boolean_or_mismatched_counts():
    baseline = {
        "schemaVersion": "jank-report.v1",
        "status": "valid",
        "longTaskCount": 0,
        "longTasks": [],
        "observerError": None,
        "totalBlockingTimeMs": 0,
        "thresholdMs": 100,
        "consent": {"verified": True, "blindSpots": []},
        "interactionFailures": [],
        "scroll": {"completed": True, "timedOut": False, "truncated": False},
    }
    for value in (True, 1):
        invalid = {**baseline, "longTaskCount": value}
        with pytest.raises(ValueError, match="longTaskCount"):
            _validate_jank_report(invalid)


def test_jank_validation_rejects_incomplete_scroll_evidence():
    report = {
        "schemaVersion": "jank-report.v1",
        "status": "valid",
        "longTaskCount": 0,
        "longTasks": [],
        "observerError": None,
        "totalBlockingTimeMs": 0,
        "thresholdMs": 100,
        "consent": {"verified": True, "blindSpots": []},
        "interactionFailures": [],
        "scroll": {"completed": False, "timedOut": False, "truncated": False},
    }
    with pytest.raises(ValueError, match="scroll evidence"):
        _validate_jank_report(report)


def test_runner_shell_quotes_paths():
    from browser_use_capture_mcp.vast_runner import _shell_quote

    assert _shell_quote("/tmp/a'b") == "'/tmp/a'\\''b'"


def test_connection_endpoint_rejects_private_ip(monkeypatch):
    from browser_use_capture_mcp.vast_runner import SSH_URL_PATTERN

    match = SSH_URL_PATTERN.search("ssh://root@127.0.0.1:2200")
    assert match is not None
    host = match.group(2)
    assert not __import__("ipaddress").ip_address(host).is_global


def test_probe_failure_reasons_remain_structured(monkeypatch):
    from browser_use_capture_mcp.server import _compatibility_result

    class Runner:
        async def check_compatibility(self):
            return {
                "status": "blocked",
                "cpu": {"status": "verified"},
                "gpu": {"status": "blocked", "reason": "software renderer"},
                "failureReason": "software renderer",
            }

    result = __import__("asyncio").run(_compatibility_result(Runner()))
    assert result["reasonCode"] == "capture-gpu-unavailable"
    assert result["gpu"]["status"] == "blocked"


@pytest.mark.parametrize(
    "egress_policy",
    [
        None,
        ["not-an-object"],
        {"status": "unknown"},
        {"status": "unverified", "browserTrafficBoundary": "unverified"},
        {"status": "blocked", "unauthorizedConnections": [{"hostname": "bad.example", "port": 443}]},
        {"status": "verified"},
        {
            **_verified_egress_policy(),
            "proxyPolicyCheck": "blocked",
        },
        {
            **_verified_egress_policy(),
            "unexpectedViolationCodes": ["unexpected-proxy-error"],
        },
        {
            **_verified_egress_policy(),
            "unauthorizedConnections": [{
                "hostname": "bad.example",
                "port": 443,
                "outcome": "connected",
                "count": 1,
            }],
        },
        {
            **_verified_egress_policy(),
            "browserTrafficBoundary": "unverified",
        },
        {
            **_verified_egress_policy(),
            "browserServiceReachability": "not-assessed",
        },
    ],
)
def test_incomplete_egress_evidence_blocks_capability_issuance(egress_policy):
    from browser_use_capture_mcp.server import _compatibility_result

    class Runner:
        instance_id = "52085190"
        browser_path = "/opt/google/chrome/chrome"

        async def check_compatibility(self):
            probe = {
                "status": "verified",
                "cpu": {"status": "verified"},
                "gpu": {"status": "verified", "device": "NVIDIA GeForce RTX 3060"},
                "browserExecutable": self.browser_path,
                "browserUseVersion": "0.13.10",
                "browserVersion": "Chrome/154.0",
            }
            if egress_policy is not None:
                probe["egressPolicy"] = egress_policy
            return probe

    existing_capabilities = set(_CAPABILITY_RECORDS)
    result = asyncio.run(_compatibility_result(Runner()))

    assert result["status"] == "blocked"
    assert result["reasonCode"] == "capture-egress-policy-unverified"
    assert "gpu_check_id" not in result
    expected_egress_policy = egress_policy if isinstance(egress_policy, dict) else {}
    assert result["egressPolicy"] == expected_egress_policy
    assert set(_CAPABILITY_RECORDS) == existing_capabilities


def test_verified_egress_is_preserved_when_issuing_capability():
    from browser_use_capture_mcp.server import _compatibility_result

    class Runner:
        instance_id = "52085190"
        browser_path = "/opt/google/chrome/chrome"

        async def check_compatibility(self):
            return {
                "status": "verified",
                "cpu": {"status": "verified"},
                "gpu": {"status": "verified", "device": "NVIDIA GeForce RTX 3060"},
                "egressPolicy": _verified_egress_policy(),
                "browserExecutable": self.browser_path,
                "browserUseVersion": "0.13.10",
                "browserVersion": "Chrome/154.0",
            }

    runner = Runner()
    result = asyncio.run(_compatibility_result(runner))

    assert result["status"] == "verified"
    assert result["egressPolicy"]["status"] == "verified"
    assert result["egressPolicy"]["requestAttribution"]["status"] == "unknown"
    assert _verified_capability(result["gpu_check_id"], runner) is None
