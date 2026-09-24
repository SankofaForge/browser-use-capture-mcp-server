#!/usr/bin/env python3
"""Root runner wrapper for a per-capture, proxy-only network namespace."""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

SCHEMA_VERSION = "runner-egress-boundary.v1"
POLICY = "capture-exact-host.v1"
MAX_AGE_SECONDS = 120
ATTESTATION_ROOT = Path("/workspace/browser-use-capture/attestations")


def run(args: list[str], *, timeout: float = 20, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    if check and result.returncode:
        raise RuntimeError(f"boundary command failed: {args[0]} ({result.returncode})")
    return result


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(value: dt.datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _write_attestation(path: Path, payload: dict) -> None:
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as target:
            json.dump(payload, target, separators=(",", ":"))
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())
        os.chown(temporary, 0, 0)
        os.chmod(temporary, 0o444)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _network_names(run_id: str) -> tuple[str, str, str, str, str]:
    token = run_id.replace("-", "")[:8]
    slot = int(token, 16) % 16384
    third = slot // 64
    fourth = (slot % 64) * 4
    gateway = f"10.200.{third}.{fourth + 1}"
    client = f"10.200.{third}.{fourth + 2}"
    return f"bu-{token}", f"bvh{token}", f"bvp{token}", gateway, client


def _setup_namespace(namespace: str, host_veth: str, peer: str, gateway: str, client: str, table: str, proxy_port: int) -> None:
    run(["ip", "netns", "add", namespace])
    run(["ip", "link", "add", host_veth, "type", "veth", "peer", "name", peer])
    run(["ip", "link", "set", peer, "netns", namespace])
    run(["ip", "addr", "add", f"{gateway}/30", "dev", host_veth])
    run(["ip", "link", "set", host_veth, "up"])
    run(["ip", "-n", namespace, "addr", "add", f"{client}/30", "dev", peer])
    run(["ip", "-n", namespace, "link", "set", peer, "name", "eth0"])
    run(["ip", "-n", namespace, "link", "set", "lo", "up"])
    run(["ip", "-n", namespace, "link", "set", "eth0", "up"])
    run(["ip", "-n", namespace, "route", "add", "default", "via", gateway])
    run(["nft", "add", "table", "inet", table])
    run(["nft", "add", "chain", "inet", table, "input", "{", "type", "filter", "hook", "input", "priority", "-200", ";", "policy", "accept", ";", "}"])
    run(["nft", "add", "rule", "inet", table, "input", "iifname", host_veth, "ip", "daddr", gateway, "tcp", "dport", str(proxy_port), "accept"])
    run(["nft", "add", "rule", "inet", table, "input", "iifname", host_veth, "drop"])
    run(["nft", "add", "chain", "inet", table, "forward", "{", "type", "filter", "hook", "forward", "priority", "-200", ";", "policy", "accept", ";", "}"])
    run(["nft", "add", "rule", "inet", table, "forward", "iifname", host_veth, "drop"])


def _namespace_inode(namespace: str) -> int:
    result = run([
        "ip", "netns", "exec", namespace, sys.executable, "-c",
        "import os; print(os.stat('/proc/self/ns/net').st_ino)",
    ])
    return int(result.stdout.strip())


def _remove_link(interface: str) -> bool:
    present = run(["ip", "link", "show", "dev", interface], check=False)
    if present.returncode:
        return True
    removed = run(["ip", "link", "del", interface], check=False)
    if removed.returncode:
        return False
    return run(["ip", "link", "show", "dev", interface], check=False).returncode != 0


def _probe(namespace: str, gateway: str, proxy_port: int, approved_host: str, approved_port: int) -> dict[str, str]:
    script = r'''import socket,sys
mode,host,port_s,approved,approved_port_s=sys.argv[1:]
port=int(port_s); approved_port=int(approved_port_s)
if mode=="direct":
    try:
        s=socket.create_connection(("1.1.1.1",443),timeout=2)
    except OSError:
        print("blocked"); raise SystemExit(0)
    else:
        s.close(); print("passed"); raise SystemExit(0)
s=socket.create_connection((host,port),timeout=4); s.settimeout(4)
s.sendall(b"\x05\x01\x00")
if s.recv(2)!=b"\x05\x00": raise SystemExit(2)
h=approved.encode("idna")
s.sendall(b"\x05\x01\x00\x03"+bytes([len(h)])+h+approved_port.to_bytes(2,"big"))
r=s.recv(4)
if len(r)!=4 or r[1]!=0: raise SystemExit(3)
if r[3]==1: s.recv(4)
elif r[3]==4: s.recv(16)
elif r[3]==3: s.recv(s.recv(1)[0])
s.recv(2); s.close(); print("passed")
'''
    try:
        result = run([
            "ip", "netns", "exec", namespace, sys.executable, "-c", script,
            "direct", gateway, str(proxy_port), approved_host, str(approved_port),
        ], timeout=8, check=False)
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        return {"direct": "unavailable", "proxied": "blocked"}
    direct = "blocked" if result.returncode == 0 and result.stdout.strip() == "blocked" else "passed"
    try:
        proxy = run([
            "ip", "netns", "exec", namespace, sys.executable, "-c", script,
            "proxied", gateway, str(proxy_port), approved_host, str(approved_port),
        ], timeout=12, check=False)
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        return {"direct": direct, "proxied": "blocked"}
    proxied = "passed" if proxy.returncode == 0 and proxy.stdout.strip() == "passed" else "blocked"
    return {"direct": direct, "proxied": proxied}


def _proxy_start(host: str, port: int, approved_host: str, ready: Path, evidence: Path) -> subprocess.Popen:
    script = Path(__file__).with_name("public_socks_proxy.py")
    process = subprocess.Popen([
        sys.executable, str(script), "serve", "--host", host, "--port", str(port),
        "--approved-host", approved_host, "--ready-file", str(ready), "--evidence-file", str(evidence),
    ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("approved host-side SOCKS proxy failed to start")
        if ready.is_file():
            return process
        time.sleep(0.05)
    raise RuntimeError("approved host-side SOCKS proxy startup timed out")


def _stop(process: subprocess.Popen | None) -> bool:
    if process is None:
        return True
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
        return process.returncode == 0
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            return False
    return process.returncode == 0


def _write_result(path: Path, result: dict) -> None:
    path.write_text(json.dumps(result, separators=(",", ":")) + "\n", encoding="utf-8")


def run_capture(args: argparse.Namespace) -> int:
    for tool in ("ip", "nft", "runuser"):
        if shutil.which(tool) is None:
            raise RuntimeError(f"required privileged runner tool is unavailable: {tool}")
    payload_path = Path(args.input)
    result_path = Path(args.result)
    input_data = json.loads(payload_path.read_text(encoding="utf-8"))
    url = urlsplit(input_data.get("url", ""))
    approved_host = (url.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
    if not approved_host:
        raise RuntimeError("capture URL has no approved hostname")
    approved_port = url.port or (443 if url.scheme == "https" else 80)
    namespace, host_veth, peer, gateway, client = _network_names(args.run_id)
    table = f"buc_{args.run_id.replace('-', '')[:8]}"
    metadata = ATTESTATION_ROOT.stat()
    if metadata.st_uid != 0 or metadata.st_mode & 0o022 or ATTESTATION_ROOT.is_symlink():
        raise RuntimeError("root-owned attestation directory is missing or writable by capture user")
    proxy_evidence = ATTESTATION_ROOT / f"{args.run_id}.proxy-evidence.json"
    proxy_ready = ATTESTATION_ROOT / f"{args.run_id}.proxy-ready"
    attestation_path = ATTESTATION_ROOT / f"{args.run_id}.attestation.json"
    proxy_process = None
    result_data: dict = {"status": "blocked", "runId": args.run_id, "reasonCode": "capture-egress-boundary-unverified", "failureReason": "runner network boundary setup did not complete", "artifacts": {}}
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("0.0.0.0", 0))
        proxy_port = sock.getsockname()[1]
    try:
        _setup_namespace(namespace, host_veth, peer, gateway, client, table, proxy_port)
        proxy_process = _proxy_start(gateway, proxy_port, approved_host, proxy_ready, proxy_evidence)
        controls = _probe(namespace, gateway, proxy_port, approved_host, approved_port)
        if controls != {"direct": "blocked", "proxied": "passed"}:
            raise RuntimeError("direct-egress denial or approved proxy control failed")
        namespace_inode = _namespace_inode(namespace)
        checked = _now()
        browser_result = run([args.browser, "--version"], timeout=10, check=False)
        if browser_result.returncode:
            raise RuntimeError("configured browser version could not be verified")
        version_text = (browser_result.stdout.strip() or browser_result.stderr.strip()).splitlines()[0]
        version_match = __import__("re").search(r"\d+(?:\.\d+){2,3}", version_text)
        if not version_match:
            raise RuntimeError("configured browser version string is not recognized")
        browser_version = version_match.group(0)
        attestation = {
            "schemaVersion": SCHEMA_VERSION,
            "boundaryId": str(uuid.uuid4()),
            "runId": args.run_id,
            "checkedAt": _iso(checked),
            "expiresAt": _iso(checked + dt.timedelta(seconds=MAX_AGE_SECONDS)),
            "runnerInstanceId": args.runner_id,
            "browserExecutable": args.browser,
            "browserVersion": browser_version,
            "captureRuntime": "browser-use",
            "captureRuntimeVersion": args.browser_use_version,
            "browserUseVersion": args.browser_use_version,
            "approvedHost": approved_host,
            "networkNamespaceInode": namespace_inode,
            "directEgressBlocked": True,
            "proxyPolicy": POLICY,
            "controls": {key: {"status": value} for key, value in controls.items()},
        }
        _write_attestation(attestation_path, attestation)
        input_data["egress_proxy_host"] = gateway
        input_data["egress_proxy_port"] = proxy_port
        payload_path.write_text(json.dumps(input_data, separators=(",", ":")), encoding="utf-8")
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(Path(args.run_directory) / "home"),
            "TMPDIR": str(Path(args.run_directory) / "tmp"),
            "UV_CACHE_DIR": str(Path(args.run_directory) / "uv-cache"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "ANONYMIZED_TELEMETRY": "false",
            "BROWSER_USE_CLOUD_SYNC": "false",
            "BROWSER_USE_VERSION_CHECK": "false",
            "BROWSER_USE_CHROMIUM_PATH": args.browser,
            "VAST_INSTANCE_ID": args.runner_id,
            "CAPTURE_EGRESS_ATTESTATION_FILE": str(attestation_path),
        }
        command = [
            "ip", "netns", "exec", namespace, "runuser", "-u", args.capture_user, "--", "env",
            *(f"{key}={value}" for key, value in env.items()),
            args.python, args.worker,
        ]
        capture = run(command, timeout=args.timeout + 240, check=False)
        try:
            result_data = json.loads(capture.stdout.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            result_data = {"status": "blocked", "runId": args.run_id, "reasonCode": "capture-result-invalid", "failureReason": "capture worker returned invalid JSON", "artifacts": {}}
        if not isinstance(result_data, dict):
            result_data = {"status": "blocked", "runId": args.run_id, "reasonCode": "capture-result-invalid", "failureReason": "capture worker returned invalid JSON", "artifacts": {}}
        try:
            after = _probe(namespace, gateway, proxy_port, approved_host, approved_port)
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            after = {"direct": "unavailable", "proxied": "blocked"}
        artifacts = result_data.get("artifacts")
        if not isinstance(artifacts, dict):
            artifacts = {}
            result_data["artifacts"] = artifacts
        artifact_name = input_data.get("name")
        if isinstance(artifact_name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,80}", artifact_name):
            for key, filename in {
                "webm": f"{artifact_name}.webm",
                "jank": f"{artifact_name}.jank.json",
                "manifest": "manifest.json",
            }.items():
                artifact_path = Path(args.run_directory) / filename
                if artifact_path.is_file() and not artifact_path.is_symlink():
                    artifacts.setdefault(key, filename)
        checked = _now()
        attestation["checkedAt"] = _iso(checked)
        attestation["expiresAt"] = _iso(checked + dt.timedelta(seconds=MAX_AGE_SECONDS))
        attestation["controls"] = {key: {"status": value} for key, value in after.items()}
        proxy_clean = _stop(proxy_process)
        proxy_process = None
        proxy_ok = False
        try:
            observed = json.loads(proxy_evidence.read_text(encoding="utf-8"))
            proxy_ok = (
                not observed.get("violations")
                and any(
                    item.get("hostname") == approved_host
                    and item.get("port") == approved_port
                    and item.get("outcome") == "connected"
                    and item.get("count", 0) > 0
                    for item in observed.get("connectionOutcomes", [])
                )
            )
        except (OSError, json.JSONDecodeError):
            observed = {}
        if after != {"direct": "blocked", "proxied": "passed"} or not proxy_ok:
            result_data["status"] = "partial" if result_data.get("artifacts") else "blocked"
            result_data["reasonCode"] = "capture-egress-policy-unverified"
            result_data["failureReason"] = "network boundary controls or exact-host proxy evidence failed"
        attestation["proxyEvidence"] = observed
        evidence = result_data.get("evidence")
        if not isinstance(evidence, dict):
            evidence = {}
            result_data["evidence"] = evidence
        nft_clean = run(["nft", "delete", "table", "inet", table], timeout=10, check=False).returncode == 0
        namespace_clean = run(["ip", "netns", "del", namespace], timeout=10, check=False).returncode == 0
        link_clean = _remove_link(host_veth)
        boundary_cleanup = proxy_clean and nft_clean and namespace_clean and link_clean
        attestation["cleanupVerified"] = boundary_cleanup
        _write_attestation(attestation_path, attestation)
        evidence["cleanupVerified"] = evidence.get("cleanupVerified") is True and boundary_cleanup
        evidence["egress"] = {
            "status": "verified" if after == {"direct": "blocked", "proxied": "passed"} and proxy_ok else "blocked",
            "boundaryId": attestation["boundaryId"],
            "directEgressBlocked": after.get("direct") == "blocked",
            "approvedProxyProbe": after.get("proxied") == "passed" and proxy_ok,
            "proxyPolicy": POLICY,
            "approvedHost": approved_host,
            "networkNamespaceInode": namespace_inode,
            "cleanupVerified": boundary_cleanup,
        }
        evidence["egressAttestation"] = attestation
        if not boundary_cleanup:
            result_data["status"] = "partial" if result_data.get("artifacts") else "blocked"
            result_data["reasonCode"] = "capture-egress-cleanup-incomplete"
            result_data["failureReason"] = "runner namespace or proxy cleanup could not be verified"
        if capture.returncode and result_data.get("status") == "complete":
            result_data["status"] = "partial"
            result_data["reasonCode"] = "capture-worker-failed"
            result_data["failureReason"] = "capture worker exited unsuccessfully"
        _write_result(result_path, result_data)
        attestation_path.unlink(missing_ok=True)
        proxy_evidence.unlink(missing_ok=True)
        proxy_ready.unlink(missing_ok=True)
        return 0
    finally:
        _stop(proxy_process)
        run(["nft", "delete", "table", "inet", table], timeout=10, check=False)
        run(["ip", "netns", "del", namespace], timeout=10, check=False)
        _remove_link(host_veth)
        for path in (attestation_path, proxy_evidence, proxy_ready):
            path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture = subparsers.add_parser("capture")
    for option in ("run-id", "run-directory", "input", "result", "runner-id", "browser", "browser-use-version", "capture-user", "python", "worker"):
        capture.add_argument(f"--{option}", required=True)
    capture.add_argument("--timeout", required=True, type=int)
    args = parser.parse_args()
    if args.command == "capture":
        try:
            return run_capture(args)
        except Exception as error:
            failure = {"status": "blocked", "reasonCode": "capture-egress-boundary-unavailable", "failureReason": str(error), "artifacts": {}}
            if getattr(args, "result", None):
                _write_result(Path(args.result), failure)
            print(json.dumps(failure))
            return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
