from __future__ import annotations

import asyncio
import json
import socket
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "remote"))
import capture_worker as worker
import egress_boundary


def request_payload(root: Path, **overrides):
    run_id = str(uuid.uuid4())
    payload = {
        "url": "https://example.com/landing",
        "run_id": run_id,
        "output_dir": str(root / run_id),
    }
    payload.update(overrides)
    return payload


def make_request(tmp_path: Path, **overrides):
    runs_root = tmp_path / "runs"
    payload = request_payload(runs_root, **overrides)
    return worker.validate_request(payload, runs_root=runs_root)


def _records_for_address(address: str):
    def resolve(host: str, port: int, type: int):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port))
        ]

    return resolve


def test_normalizes_safe_request_with_reject_default(tmp_path: Path):
    request = make_request(tmp_path)

    assert request["consent_mode"] == "reject"
    assert request["consent_accept_approved"] is False
    assert request["width"] == 1920
    assert request["height"] == 1080
    assert request["output_dir"] == tmp_path / "runs" / request["run_id"]
    assert request["jank_check"] is True
    assert request["scroll"] is True


def test_namespace_firewall_allows_only_the_allocated_proxy_port(monkeypatch):
    commands = []
    monkeypatch.setattr(egress_boundary, "run", lambda command, **_kwargs: commands.append(command))

    egress_boundary._setup_namespace("bu-test", "bvh-test", "bvp-test", "10.200.1.1", "10.200.1.2", "buc_test", 18443)

    proxy_rule = next(command for command in commands if command[:5] == ["nft", "add", "rule", "inet", "buc_test"] and "dport" in command)
    assert proxy_rule[proxy_rule.index("dport") + 1] == "18443"
    forward_rule = next(command for command in commands if command[:5] == ["nft", "add", "rule", "inet", "buc_test"] and "forward" in command)
    assert forward_rule[-1] == "drop"


def test_namespace_inode_is_read_from_requested_network_namespace(monkeypatch):
    calls = []

    class Result:
        stdout = "123456\n"

    monkeypatch.setattr(egress_boundary, "run", lambda command, **_kwargs: calls.append(command) or Result())

    assert egress_boundary._namespace_inode("bu-1234") == 123456
    assert calls[0][:4] == ["ip", "netns", "exec", "bu-1234"]
    assert "os.stat('/proc/self/ns/net').st_ino" in calls[0][-1]


def test_link_cleanup_accepts_peer_removal_with_namespace(monkeypatch):
    commands = []

    class Result:
        def __init__(self, returncode):
            self.returncode = returncode

    monkeypatch.setattr(
        egress_boundary,
        "run",
        lambda command, **_kwargs: commands.append(command) or Result(1),
    )

    assert egress_boundary._remove_link("bvh-test") is True
    assert commands == [["ip", "link", "show", "dev", "bvh-test"]]


def test_mobile_mode_uses_reference_viewport(tmp_path: Path):
    request = make_request(tmp_path, mobile=True, width=1280, height=720)

    assert (request["width"], request["height"]) == (390, 844)
    assert request["mobile"] is True


def test_accept_mode_requires_explicit_approval(tmp_path: Path):
    with pytest.raises(ValueError, match="consent_accept_approved"):
        make_request(tmp_path, consent_mode="accept")

    request = make_request(tmp_path, consent_mode="accept", consent_accept_approved=True)
    assert request["consent_accept_approved"] is True


def test_granular_mode_requires_each_selector_group(tmp_path: Path):
    with pytest.raises(ValueError, match="granular consent"):
        make_request(tmp_path, consent_mode="granular")

    request = make_request(
        tmp_path,
        consent_mode="granular",
        consent_settings_selectors=["#settings"],
        consent_optional_selectors=["#analytics"],
        consent_save_selectors=["#save"],
    )
    assert request["consent_settings_selectors"] == ["#settings"]
    assert request["consent_optional_selectors"] == ["#analytics"]
    assert request["consent_save_selectors"] == ["#save"]


def test_run_id_must_be_canonical_uuidv4(tmp_path: Path):
    payload = request_payload(tmp_path / "runs")
    payload["run_id"] = payload["run_id"].upper()
    payload["output_dir"] = str(tmp_path / "runs" / payload["run_id"])

    with pytest.raises(ValueError, match="canonical"):
        worker.validate_request(payload, runs_root=tmp_path / "runs")


def test_output_directory_must_be_exact_run_child(tmp_path: Path):
    runs_root = tmp_path / "runs"
    run_id = str(uuid.uuid4())
    payload = request_payload(runs_root, run_id=run_id, output_dir=str(runs_root / "other" / ".." / run_id))

    with pytest.raises(ValueError, match="output_dir"):
        worker.validate_request(payload, runs_root=runs_root)


def test_output_directory_symlink_is_rejected(tmp_path: Path):
    runs_root = tmp_path / "runs"
    run_id = str(uuid.uuid4())
    outside = tmp_path / "outside"
    outside.mkdir()
    runs_root.mkdir()
    (runs_root / run_id).symlink_to(outside, target_is_directory=True)
    payload = request_payload(runs_root)
    payload["run_id"] = run_id
    payload["output_dir"] = str(runs_root / run_id)

    with pytest.raises(ValueError, match="symlink"):
        worker.validate_request(payload, runs_root=runs_root)


@pytest.mark.parametrize("name", ["../capture", "folder/capture", "folder\\capture", ".hidden", ""])
def test_name_must_be_a_safe_basename(tmp_path: Path, name: str):
    with pytest.raises(ValueError, match="basename"):
        make_request(tmp_path, name=name)


def test_unrecognized_fields_are_rejected(tmp_path: Path):
    with pytest.raises(ValueError, match="unsupported capture fields"):
        make_request(tmp_path, browser_profile="/home/ubuntu/.config/google-chrome")


def test_public_http_url_uses_the_capture_runner_resolver():
    result = worker.validate_public_http_url(
        "https://site.example/path",
        resolver=_records_for_address("1.1.1.1"),
    )

    assert result["hostname"] == "site.example"
    assert result["addresses"] == ["1.1.1.1"]


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.8", "169.254.1.2", "100.64.1.2", "192.0.2.9"])
def test_private_or_non_global_dns_answers_fail_closed(address: str):
    with pytest.raises(worker.WorkerFailure) as raised:
        worker.validate_public_http_url(
            "https://site.example",
            resolver=_records_for_address(address),
        )

    assert raised.value.reason_code == "capture-domain-unverified"


def test_mixed_public_and_private_dns_answers_fail_closed():
    def resolve(host: str, port: int, type: int):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("1.1.1.1", port)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", port)),
        ]

    with pytest.raises(worker.WorkerFailure, match="public addresses"):
        worker.validate_public_http_url("https://site.example", resolver=resolve)


def test_approved_domain_check_rejects_host_change_before_resolving_it():
    def unexpected_resolver(*_args, **_kwargs):
        raise AssertionError("unapproved host must not be resolved")

    with pytest.raises(worker.WorkerFailure) as raised:
        worker._validate_approved_domain(
            "https://outside.example/path",
            "site.example",
            stage="test navigation",
            resolver=unexpected_resolver,
        )

    assert raised.value.reason_code == "capture-domain-unverified"
    assert "outside.example" in str(raised.value)


def test_approved_domain_check_revalidates_public_dns():
    result = worker._validate_approved_domain(
        "https://site.example/path",
        "site.example",
        stage="test navigation",
        resolver=_records_for_address("1.1.1.1"),
    )

    assert result["hostname"] == "site.example"
    assert result["addresses"] == ["1.1.1.1"]


def test_navigation_waits_for_blank_page_to_leave_initial_document(monkeypatch):
    class FakePage:
        def __init__(self):
            self.urls = iter(["about:blank", "https://site.example/page"])

        async def evaluate(self, _expression):
            return next(self.urls)

    checked = []

    def validate(url: str, hostname: str, *, stage: str):
        checked.append((url, hostname, stage))

    monkeypatch.setattr(worker, "_validate_approved_domain", validate)
    result = asyncio.run(worker._wait_for_approved_navigation(
        FakePage(), "site.example", stage="test navigation", timeout=1
    ))

    assert result == "https://site.example/page"
    assert checked == [("https://site.example/page", "site.example", "test navigation")]


@pytest.mark.parametrize(
    "url",
    ["file:///etc/passwd", "javascript:alert(1)", "https://user:pass@example.com", "http://localhost"],
)
def test_url_policy_rejects_unsupported_or_unsafe_targets(url: str):
    resolver = _records_for_address("1.1.1.1")
    with pytest.raises(worker.WorkerFailure):
        worker.validate_public_http_url(url, resolver=resolver)


def test_url_and_diagnostics_redact_sensitive_query_values():
    value = "https://site.example/path?token=private&theme=dark#access_token=fragment-secret"

    assert worker._redacted_url(value) == "https://site.example/path?token=%5BREDACTED%5D&theme=dark"
    assert "fragment-secret" not in worker._redacted_url(value)
    assert "private" not in worker._redact_text(value)
    assert "fragment-secret" not in worker._redact_text(value)
    assert worker._redact_text("cookie=private") == "cookie=[REDACTED]"


def test_chrome_args_force_loopback_cdp_and_replace_profile_port(tmp_path: Path):
    args = worker._clean_chrome_args(
        [
            "--headless=new",
            "--remote-debugging-port=0",
            "--remote-debugging-address=0.0.0.0",
            "--proxy-server=http://untrusted.invalid:8080",
            "--proxy-bypass-list=*",
            "--no-sandbox",
            "--user-data-dir",
            "/persistent/profile",
        ],
        9222,
        1080,
        tmp_path / "run-profile",
    )

    assert "--headless=new" in args
    assert "--remote-debugging-port=9222" in args
    assert "--remote-debugging-address=127.0.0.1" in args
    assert not any(arg.endswith("=0") for arg in args if arg.startswith("--remote-debugging-port"))
    assert args[-1] == "data:text/html,"
    assert "--remote-allow-origins=http://127.0.0.1" in args
    assert "--proxy-server=socks5://127.0.0.1:1080" in args
    assert "--proxy-bypass-list=<-loopback>" in args
    assert "--disable-quic" in args
    assert "--force-webrtc-ip-handling-policy=disable_non_proxied_udp" in args
    assert "--disable-background-networking" not in args
    assert "--disable-component-update" not in args
    assert "--disable-sync" in args
    assert "--no-sandbox" not in args
    assert "--proxy-bypass-list=*" not in args
    assert f"--user-data-dir={tmp_path / 'run-profile'}" in args
    assert "/persistent/profile" not in args


def test_worker_results_include_bridge_completion_fields():
    complete = worker._worker_result(
        "complete",
        str(uuid.uuid4()),
        media_validation={
            "status": "valid",
            "format": "matroska,webm",
            "durationSeconds": 1.25,
        },
    )
    blocked = worker._worker_result(
        "blocked",
        None,
        reason_code="browser-startup-timeout",
        message="CDP startup timed out",
    )

    assert complete["mediaValidation"]["status"] == "valid"
    assert complete["mediaValidation"]["format"] == "matroska,webm"
    assert "failureReason" not in complete
    assert blocked["mediaValidation"]["status"] == "blocked"
    assert blocked["failureReason"] == "CDP startup timed out"


def test_browser_executable_rejects_launcher_script_before_version_check(tmp_path: Path, monkeypatch):
    launcher = tmp_path / "google-chrome"
    launcher.write_text("#!/bin/sh\nprintf 'Google Chrome 1.0\\n'\n", encoding="utf-8")
    launcher.chmod(0o755)
    monkeypatch.setenv("BROWSER_USE_CHROMIUM_PATH", str(launcher))

    with pytest.raises(worker.WorkerFailure) as raised:
        asyncio.run(worker._browser_executable())

    assert raised.value.reason_code == "browser-executable-wrapper"


def test_browser_profile_is_local_bounded_and_run_scoped(tmp_path: Path):
    request = make_request(tmp_path, mobile=True, reduced_motion=True)
    profile_dir = tmp_path / "browser-use-user-data-dir-profile"
    options = worker._browser_profile_options(
        executable=Path("/opt/google/chrome/chrome"),
        profile_dir=profile_dir,
        cdp_origin="http://127.0.0.1:9222",
        approved_hostname="example.com",
        request=request,
    )

    assert options["user_data_dir"] == str(profile_dir)
    assert options["chromium_sandbox"] is True
    assert options["allowed_domains"] == ["example.com"]
    assert options["use_cloud"] is False
    assert options["enable_default_extensions"] is False
    assert options["captcha_solver"] is False
    assert options["cookie_whitelist_domains"] == []
    assert options["window_size"] == {"width": 390, "height": 844}
    assert "--no-sandbox" not in options["args"]
    assert "is_mobile" not in options
    assert "has_touch" not in options
    assert "reduced_motion" not in options


def test_browser_profile_rejects_paths_browser_use_would_copy_outside_run(tmp_path: Path):
    request = make_request(tmp_path)

    with pytest.raises(worker.WorkerFailure, match="outside the run directory"):
        worker._browser_profile_options(
            executable=Path("/opt/google/chrome/chrome"),
            profile_dir=tmp_path / "profile",
            cdp_origin="http://127.0.0.1:9222",
            approved_hostname="example.com",
            request=request,
        )


def test_jank_report_preserves_v1_shape_and_phase_buckets():
    report = worker.build_jank_report(
        final_url="https://site.example/page",
        consent={"mode": "reject", "verified": True, "blindSpots": []},
        entries=[
            {"startTime": 10, "duration": 80},
            {"startTime": 30, "duration": 49},
            {"startTime": 130, "duration": 200},
        ],
        observer_error=None,
        observer_ready=True,
        phases=[{"name": "load", "at": 0}, {"name": "scroll", "at": 100}],
        threshold_ms=100,
        interaction_failures=[],
        interactions=[],
        scroll={"completed": True, "timedOut": False, "truncated": False},
    )

    assert report["schemaVersion"] == "jank-report.v1"
    assert report["longTaskCount"] == 2
    assert report["totalBlockingTimeMs"] == 180
    assert report["byPhase"] == {
        "load": {"count": 1, "totalBlockingTimeMs": 30},
        "scroll": {"count": 1, "totalBlockingTimeMs": 150},
    }
    assert report["choppy"] is True
    assert report["status"] == "valid"


def test_jank_report_is_partial_without_verified_observer_or_consent():
    report = worker.build_jank_report(
        final_url="https://site.example",
        consent={"mode": "reject", "verified": False, "blindSpots": [{"kind": "iframe"}]},
        entries=[],
        observer_error="observer_unavailable",
        observer_ready=False,
        phases=[],
        threshold_ms=200,
        interaction_failures=[],
        interactions=[],
        scroll={"completed": True, "timedOut": False, "truncated": False},
    )

    assert report["status"] == "partial"
    assert report["observerError"] == "observer_unavailable"
    assert report["consent"]["verified"] is False


def test_jank_report_is_partial_when_scroll_did_not_complete():
    report = worker.build_jank_report(
        final_url="https://site.example",
        consent={"mode": "reject", "verified": True, "blindSpots": []},
        entries=[],
        observer_error=None,
        observer_ready=True,
        phases=[],
        threshold_ms=200,
        interaction_failures=[],
        interactions=[],
        scroll={"completed": False, "timedOut": False, "truncated": False},
    )
    assert report["status"] == "partial"


def test_consent_aggregation_fails_closed_on_preflight_blind_spot():
    consent = worker.combine_consent(
        "reject",
        {"verified": False, "blindSpots": [{"kind": "iframe-consent-not-inspected"}]},
        {"verified": True, "blindSpots": [], "outcome": "no-consent-surface"},
    )

    assert consent["verified"] is False
    assert consent["blindSpots"][0]["kind"] == "iframe-consent-not-inspected"


def test_consent_aggregation_preserves_blind_spots_from_every_phase():
    consent = worker.combine_consent(
        "reject",
        None,
        {"verified": True, "blindSpots": [], "outcome": "dismissed", "action": "rejected"},
        [
            {"verified": False, "blindSpots": [{"kind": "iframe-consent-not-inspected"}]},
            {"verified": False, "blindSpots": [{"kind": "open-shadow-consent-not-inspected"}]},
        ],
    )

    assert consent["verified"] is False
    assert [item["kind"] for item in consent["blindSpots"]] == [
        "iframe-consent-not-inspected", "open-shadow-consent-not-inspected",
    ]


def test_explicit_consent_selector_must_have_rejecting_label():
    class FakeElement:
        def __init__(self, label):
            self.label = label
            self.clicked = False

        async def evaluate(self, expression):
            if "label:" in expression:
                return json.dumps({"label": self.label})
            return True

        async def click(self):
            self.clicked = True

    accept = FakeElement("Accept all")
    reject = FakeElement("Reject all")

    class FakePage:
        async def get_elements_by_css_selector(self, selector):
            return [accept] if selector == "#accept" else [reject]

    clicked, selector, error = asyncio.run(worker._click_first(
        FakePage(), ["#accept", "#reject"], worker.REJECT_TEXT_PATTERN,
        require_scope=False, timeout_ms=100,
    ))

    assert clicked is True
    assert selector == "#reject"
    assert error is None
    assert accept.clicked is False
    assert reject.clicked is True


def test_reject_mode_is_unverified_when_banner_disappears_without_reject_action(monkeypatch):
    scans = iter([
        {"visibleSurfaceCount": 1, "iframeCount": 0, "openShadowHostCount": 0},
        {"visibleSurfaceCount": 0, "iframeCount": 0, "openShadowHostCount": 0},
    ])

    async def inspect(*_args):
        return next(scans)

    async def click(*_args, **_kwargs):
        return False, None, None

    class FakePage:
        pass

    monkeypatch.setattr(worker, "_inspect_consent", inspect)
    monkeypatch.setattr(worker, "_click_first", click)
    request = {
        "consent_mode": "reject", "consent_wait_ms": 0, "consent_budget_ms": 500,
        "consent_selectors": [],
    }
    result = asyncio.run(worker.handle_consent(FakePage(), request, "test"))

    assert result["verified"] is False
    assert result["dismissed"] is False


def test_manual_click_cannot_escape_approved_host(tmp_path: Path):
    class FakeElement:
        async def evaluate(self, _expression):
            return True

        async def click(self):
            return None

    class FakePage:
        async def get_elements_by_css_selector(self, _selector):
            return [FakeElement()]

        async def get_url(self):
            return "https://outside.example/"

    request = make_request(tmp_path, click_selectors=["#go"], click_wait_ms=0)
    request["hover_selectors"] = []

    with pytest.raises(worker.WorkerFailure) as raised:
        asyncio.run(worker._run_hover_click(
            FakePage(), request, "site.example", [], []
        ))

    assert raised.value.reason_code == "capture-domain-unverified"


def test_manifest_keeps_capture_cell_v2_shape(tmp_path: Path):
    request = make_request(tmp_path)
    output_dir = request["output_dir"]
    output_dir.mkdir(parents=True)
    records = [
        {"path": "site.webm", "size": 12, "sha256": "a" * 64},
        {"path": "site.jank.json", "size": 20, "sha256": "b" * 64},
    ]

    name = worker._write_manifest(output_dir, request["run_id"], request, request["url"], records)
    manifest = json.loads((output_dir / name).read_text(encoding="utf-8"))

    assert name == "manifest.json"
    assert set(manifest) == {
        "contractVersion", "runId", "generatedAt", "recorder", "url",
        "finalUrl", "viewport", "modes", "files",
    }
    assert manifest["contractVersion"] == "capture-cell.v2"
    assert manifest["files"] == records
    assert "browserUse" not in json.dumps(manifest)


def test_artifact_hashes_are_stable_and_nonempty(tmp_path: Path):
    artifact = tmp_path / "capture.jank.json"
    artifact.write_bytes(b'{"longTaskCount":0}')

    record = worker._artifact_record(artifact)

    assert record["path"] == artifact.name
    assert record["size"] == artifact.stat().st_size
    assert len(record["sha256"]) == 64


def test_empty_artifact_is_rejected(tmp_path: Path):
    artifact = tmp_path / "capture.webm"
    artifact.touch()

    with pytest.raises(worker.WorkerFailure) as raised:
        worker._artifact_record(artifact)

    assert raised.value.reason_code == "artifact-invalid"


def test_temporary_tree_cleanup_is_bounded(tmp_path: Path):
    run_temp = tmp_path / "browser-profile"
    run_temp.mkdir()
    (run_temp / "profile").mkdir()
    (run_temp / "capture-source.mp4").write_bytes(b"temporary")

    assert worker._safe_delete_tree(run_temp)
    assert not run_temp.exists()


def test_session_kill_and_external_browser_termination_both_run(monkeypatch):
    class FakeSession:
        def __init__(self):
            self.killed = False

        async def kill(self):
            self.killed = True

    class FakeProcess:
        def __init__(self):
            self.pid = 12345
            self.returncode = None
            self.terminated = False

        def mark_terminated(self, _pid, _signal):
            self.terminated = True
            self.returncode = 0

        async def wait(self):
            return self.returncode

    session = FakeSession()
    process = FakeProcess()
    monkeypatch.setattr(worker.os, "killpg", process.mark_terminated)

    assert asyncio.run(worker.cleanup_browser_lifecycle(session, process))
    assert session.killed is True
    assert process.terminated is True


def test_worker_emits_one_json_object_for_invalid_run_path(tmp_path: Path):
    script = Path(__file__).parents[1] / "remote" / "capture_worker.py"
    payload = request_payload(tmp_path / "outside-runs")
    completed = subprocess.run(
        [sys.executable, str(script)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert len(completed.stdout.splitlines()) == 1
    result = json.loads(completed.stdout)
    assert result["status"] == "blocked"
    assert result["reasonCode"] == "capture-input-invalid"


def test_worker_stays_blocked_when_browser_path_is_unconfigured(tmp_path: Path, monkeypatch):
    request = make_request(tmp_path)
    request["url"] = "https://1.1.1.1/"
    monkeypatch.delenv("BROWSER_USE_CHROMIUM_PATH", raising=False)

    result = asyncio.run(worker.run_capture(request))

    assert result["status"] == "blocked"
    assert result["reasonCode"] == "browser-executable-unconfigured"
    assert result["artifacts"] == {}


def test_worker_does_not_overwrite_a_populated_run_directory(tmp_path: Path):
    request = make_request(tmp_path)
    request["output_dir"].mkdir(parents=True)
    (request["output_dir"] / "user-file.txt").write_text("preserve", encoding="utf-8")

    result = asyncio.run(worker.run_capture(request))

    assert result["status"] == "blocked"
    assert result["reasonCode"] == "output-exists"
    assert (request["output_dir"] / "user-file.txt").read_text(encoding="utf-8") == "preserve"


def test_missing_ffmpeg_is_a_structured_failure(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(worker.shutil, "which", lambda _name: None)

    with pytest.raises(worker.WorkerFailure) as raised:
        asyncio.run(worker.start_ffmpeg_recorder(tmp_path / "source.mp4"))

    assert raised.value.reason_code == "ffmpeg-unavailable"
