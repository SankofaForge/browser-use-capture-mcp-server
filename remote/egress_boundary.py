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
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from public_socks_proxy import COMPATIBILITY_SERVICE_HOSTS

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


def _boundary_capability_failure(status_text: str) -> str | None:
    match = re.search(r"^CapEff:\s*([0-9a-fA-F]+)\s*$", status_text, re.MULTILINE)
    if not match:
        return "effective Linux capabilities could not be verified"
    effective = int(match.group(1), 16)
    required = (("CAP_NET_ADMIN", 12), ("CAP_SYS_ADMIN", 21))
    missing = [name for name, bit in required if not effective & (1 << bit)]
    if not missing:
        return None
    return f"required Linux capabilities unavailable: {', '.join(missing)}"


def _safe_boundary_setup_failure(error: Exception) -> str:
    message = str(error)
    if message == "effective Linux capabilities could not be verified":
        return message
    if message.startswith("required Linux capabilities unavailable: "):
        return message[:160]
    if message in {
        "approved host-side SOCKS proxy failed to start",
        "approved host-side SOCKS proxy startup timed out",
    }:
        return message
    if re.fullmatch(r"boundary command failed: (?:ip|nft|runuser) \([0-9]{1,3}\)", message):
        return message
    return "compatibility boundary setup failed"


def _setup_namespace(
    namespace: str,
    host_veth: str,
    peer: str,
    gateway: str,
    client: str,
    table: str,
    client_table: str,
    proxy_port: int,
) -> None:
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
    run(["ip", "netns", "exec", namespace, "nft", "add", "table", "inet", client_table])
    run(["ip", "netns", "exec", namespace, "nft", "add", "chain", "inet", client_table, "output", "{", "type", "filter", "hook", "output", "priority", "-200", ";", "policy", "accept", ";", "}"])
    run(["ip", "netns", "exec", namespace, "nft", "add", "rule", "inet", client_table, "output", "ip", "daddr", gateway, "tcp", "dport", str(proxy_port), "accept"])
    run(["ip", "netns", "exec", namespace, "nft", "add", "rule", "inet", client_table, "output", "oifname", "eth0", "counter", "drop"])


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


def _namespace_egress_drop_packets(namespace: str, client_table: str) -> int | None:
    result = run(
        ["ip", "netns", "exec", namespace, "nft", "-j", "list", "chain", "inet", client_table, "output"],
        check=False,
    )
    if result.returncode:
        return None
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    packets = 0
    found_counter = False
    for entry in payload.get("nftables", []):
        rule = entry.get("rule") if isinstance(entry, dict) else None
        if not isinstance(rule, dict) or rule.get("chain") != "output":
            continue
        for expression in rule.get("expr", []):
            counter = expression.get("counter") if isinstance(expression, dict) else None
            if isinstance(counter, dict) and isinstance(counter.get("packets"), int):
                packets += counter["packets"]
                found_counter = True
    return packets if found_counter else None


def _probe(
    namespace: str,
    gateway: str,
    proxy_port: int,
    approved_host: str,
    approved_port: int,
    client_table: str,
) -> dict[str, str]:
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
    before_drops = _namespace_egress_drop_packets(namespace, client_table)
    try:
        result = run([
            "ip", "netns", "exec", namespace, sys.executable, "-c", script,
            "direct", gateway, str(proxy_port), approved_host, str(approved_port),
        ], timeout=8, check=False)
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        return {"direct": "unavailable", "proxied": "blocked"}
    after_drops = _namespace_egress_drop_packets(namespace, client_table)
    direct = (
        "blocked"
        if result.returncode == 0
        and result.stdout.strip() == "blocked"
        and before_drops is not None
        and after_drops is not None
        and after_drops > before_drops
        else "passed"
    )
    try:
        proxy = run([
            "ip", "netns", "exec", namespace, sys.executable, "-c", script,
            "proxied", gateway, str(proxy_port), approved_host, str(approved_port),
        ], timeout=12, check=False)
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        return {"direct": direct, "proxied": "blocked"}
    proxied = "passed" if proxy.returncode == 0 and proxy.stdout.strip() == "passed" else "blocked"
    return {"direct": direct, "proxied": proxied}


def _proxy_start(
    host: str,
    port: int,
    approved_host: str,
    ready: Path,
    evidence: Path,
    compatibility_service_hosts: frozenset[str] = frozenset(),
) -> subprocess.Popen:
    script = Path(__file__).with_name("public_socks_proxy.py")
    process = subprocess.Popen([
        sys.executable, str(script), "serve", "--host", host, "--port", str(port),
        "--approved-host", approved_host, "--ready-file", str(ready), "--evidence-file", str(evidence),
        *(item for hostname in sorted(compatibility_service_hosts) for item in ("--compatibility-service-host", hostname)),
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


def _read_proxy_evidence(path: Path) -> dict:
    try:
        evidence = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return evidence if isinstance(evidence, dict) else {}


def _browser_process_namespace_inodes(
    root_pid: int,
    browser_executable: str,
    proc_root: Path = Path("/proc"),
    profile_marker: str | None = None,
) -> list[int]:
    processes: dict[int, tuple[int, str, list[str]]] = {}
    for process_path in proc_root.iterdir():
        if not process_path.name.isdigit():
            continue
        try:
            stat = (process_path / "stat").read_text(encoding="utf-8")
            fields = stat.rsplit(")", 1)[1].split()
            parent_pid = int(fields[1])
            executable = str((process_path / "exe").resolve())
            arguments = [
                item.decode("utf-8", errors="replace")
                for item in (process_path / "cmdline").read_bytes().split(b"\0")
                if item
            ]
        except (OSError, IndexError, ValueError):
            continue
        processes[int(process_path.name)] = (parent_pid, executable, arguments)
    descendants = {root_pid}
    while True:
        children = {
            pid for pid, (parent_pid, _, _) in processes.items()
            if parent_pid in descendants
        }
        new_children = children - descendants
        if not new_children:
            break
        descendants.update(new_children)
    expected_executable = str(Path(browser_executable).resolve())
    inodes = []
    candidates = set(processes) if profile_marker is not None else descendants
    for pid in candidates:
        process = processes.get(pid)
        if process is None:
            continue
        _, executable, arguments = process
        if executable != expected_executable or any(argument.startswith("--type=") for argument in arguments):
            continue
        profile_path = None
        for index, argument in enumerate(arguments):
            if argument.startswith("--user-data-dir="):
                profile_path = argument.partition("=")[2]
                break
            if argument == "--user-data-dir" and index + 1 < len(arguments):
                profile_path = arguments[index + 1]
                break
        if profile_marker is not None and not (
            isinstance(profile_path, str) and profile_path.startswith(profile_marker)
        ):
            continue
        try:
            inodes.append(os.stat(proc_root / str(pid) / "ns" / "net").st_ino)
        except OSError:
            continue
    return inodes


def _run_namespaced_probe(
    command: list[str],
    *,
    timeout: float,
    browser_executable: str,
    browser_profile_marker: str,
) -> tuple[subprocess.CompletedProcess, list[int]]:
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        start_new_session=True,
    )
    observed_inodes: set[int] = set()
    deadline = time.monotonic() + timeout
    try:
        while True:
            observed_inodes.update(
                _browser_process_namespace_inodes(
                    process.pid,
                    browser_executable,
                    profile_marker=browser_profile_marker,
                )
            )
            if process.poll() is not None:
                break
            if time.monotonic() >= deadline:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                break
            time.sleep(0.1)
        stdout, _ = process.communicate(timeout=5)
    except BaseException:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        raise
    completed = subprocess.CompletedProcess(command, process.returncode, stdout=stdout)
    return completed, sorted(observed_inodes)


def _finalize_compatibility_egress(
    result: dict,
    *,
    controls_before: dict[str, str],
    controls_after: dict[str, str],
    proxy_evidence: dict,
    approved_host: str,
    approved_port: int,
    namespace_inode: int,
    browser_namespace_inodes: list[int],
    cleanup_verified: bool,
) -> dict:
    egress = result.get("egressPolicy")
    if not isinstance(egress, dict):
        egress = {}
        result["egressPolicy"] = egress
    outcomes = proxy_evidence.get("connectionOutcomes")
    outcomes = outcomes if isinstance(outcomes, list) else []
    violations = proxy_evidence.get("violations")
    violations = violations if isinstance(violations, list) else []
    blocked = proxy_evidence.get("blockedDestinations")
    blocked = blocked if isinstance(blocked, list) else []
    unexpected = sorted({str(code) for code in violations} - {"domain-not-approved"})
    def _is_approved_destination(hostname: Any, port: Any) -> bool:
        if hostname == approved_host and port == approved_port:
            return True
        if hostname == "edgedl.me.gvt1.com" and port in {80, 443}:
            return True
        return hostname in COMPATIBILITY_SERVICE_HOSTS and port == 443

    unexpected_attempts = [
        item for item in blocked
        if isinstance(item, dict)
        and not _is_approved_destination(item.get("hostname"), item.get("port"))
    ]
    if unexpected_attempts:
        unexpected.append("unexpected-destination-attempt")
        unexpected.sort()
    unauthorized = [
        dict(item)
        for item in outcomes
        if isinstance(item, dict)
        and item.get("outcome") == "connected"
        and not _is_approved_destination(item.get("hostname"), item.get("port"))
    ]
    fixture_connected = any(
        isinstance(item, dict)
        and item.get("hostname") == approved_host
        and item.get("port") == approved_port
        and item.get("outcome") == "connected"
        and isinstance(item.get("count"), int)
        and item["count"] > 0
        for item in outcomes
    )
    controls_valid = (
        controls_before == {"direct": "blocked", "proxied": "passed"}
        and controls_after == {"direct": "blocked", "proxied": "passed"}
    )
    proxy_policy = controls_valid and fixture_connected and not unexpected and not unauthorized
    browser_namespace_match = bool(browser_namespace_inodes) and all(
        inode == namespace_inode for inode in browser_namespace_inodes
    )
    browser_boundary = (
        proxy_policy
        and browser_namespace_match
        and cleanup_verified
    )
    service_checks = result.get("browserServiceChecks")
    checks = service_checks.get("checks") if isinstance(service_checks, dict) else None
    check_map = {
        item.get("service"): item
        for item in checks
        if isinstance(item, dict) and isinstance(item.get("service"), str)
    } if isinstance(checks, list) else {}
    connected_hosts = {
        item.get("hostname")
        for item in outcomes
        if isinstance(item, dict)
        and item.get("outcome") == "connected"
        and (item.get("port") == 443 or (item.get("hostname") == "edgedl.me.gvt1.com" and item.get("port") == 80))
        and isinstance(item.get("count"), int)
        and item.get("count") > 0
    }
    safe_browsing_hosts = connected_hosts.intersection({
        "www.gstatic.com",
        "ohttp-relay-safebrowsing-chrome.google.fastly-edge.com",
        "safebrowsing.googleapis.com",
    })
    safe_check = check_map.get("safeBrowsing", {}).get("status") == "verified" and bool(safe_browsing_hosts)
    updater_check = (
        check_map.get("componentUpdater", {}).get("status") == "verified"
        and "update.googleapis.com" in connected_hosts
    )
    service_verified = safe_check and updater_check and set(check_map) == {"safeBrowsing", "componentUpdater"}
    service_outcomes = [
        {"hostname": host, "port": 443, "outcome": "connected" if host in connected_hosts else "not-observed"}
        for host in sorted(COMPATIBILITY_SERVICE_HOSTS)
    ]
    egress.update({
        "status": "verified" if browser_boundary and service_verified and not unexpected_attempts else "blocked",
        "failureReason": (
            None
            if browser_boundary and service_verified and not unexpected_attempts
            else "The browser attempted an unapproved destination during preflight."
            if unexpected_attempts
            else "Browser Safe Browsing and component updater checks did not both pass."
            if browser_boundary
            else "The namespace, exact-host proxy, or cleanup evidence failed."
        ),
        "policy": POLICY,
        "proxyPolicyCheck": "verified" if proxy_policy else "blocked",
        "browserTrafficBoundary": "verified" if browser_boundary else "blocked",
        "browserServiceReachability": "verified" if service_verified else "blocked",
        "browserServiceOutcomes": service_outcomes,
        "unexpectedViolationCodes": unexpected,
        "unauthorizedConnections": unauthorized,
        "blockedDestinations": [item for item in blocked if isinstance(item, dict)],
        "connectionOutcomes": [item for item in outcomes if isinstance(item, dict)],
        "networkNamespaceInode": namespace_inode,
        "browserNetworkNamespaceInode": namespace_inode if browser_namespace_match else None,
        "browserProcessNamespaceMatch": browser_namespace_match,
        "cleanupVerified": cleanup_verified,
    })
    cpu = result.get("cpu") if isinstance(result.get("cpu"), dict) else {}
    gpu = result.get("gpu") if isinstance(result.get("gpu"), dict) else {}
    result["status"] = "verified" if (
        cpu.get("status") == "verified"
        and gpu.get("status") == "verified"
        and egress["status"] == "verified"
    ) else "blocked"
    if result["status"] == "verified":
        result["failureReason"] = None
    else:
        result["failureReason"] = (
            cpu.get("failureReason")
            or gpu.get("reason")
            or egress.get("failureReason")
        )
    return result


def _short_probe_environment(capture_user: str) -> tuple[Path, dict[str, str]]:
    root = Path(tempfile.mkdtemp(prefix="buc-", dir="/tmp"))
    try:
        os.chmod(root, 0o711)
        environment = {
            "HOME": str(root / "h"),
            "TMPDIR": str(root / "t"),
            "UV_CACHE_DIR": str(root / "u"),
        }
        run([
            "install", "-d", "-m", "0700", "-o", capture_user, "-g", capture_user,
            *environment.values(),
        ])
        return root, environment
    except BaseException:
        shutil.rmtree(root, ignore_errors=True)
        raise


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
    client_table = f"buc_c_{args.run_id.replace('-', '')[:8]}"
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
        _setup_namespace(namespace, host_veth, peer, gateway, client, table, client_table, proxy_port)
        proxy_process = _proxy_start(gateway, proxy_port, approved_host, proxy_ready, proxy_evidence)
        controls = _probe(namespace, gateway, proxy_port, approved_host, approved_port, client_table)
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
            after = _probe(namespace, gateway, proxy_port, approved_host, approved_port, client_table)
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


def run_compatibility(args: argparse.Namespace) -> dict:
    run_id = args.run_id
    run_directory = Path(args.run_directory)
    if str(uuid.UUID(run_id)) != run_id or uuid.UUID(run_id).version != 4:
        raise RuntimeError("compatibility run ID must be a canonical UUIDv4")
    if run_directory.parent != Path("/workspace/browser-use-capture/runs") or run_directory.is_symlink():
        raise RuntimeError("compatibility run directory is outside the approved runner root")
    for tool in ("ip", "nft", "runuser"):
        if shutil.which(tool) is None:
            raise RuntimeError(f"required privileged runner tool is unavailable: {tool}")
    approved_host = "example.com"
    approved_port = 443
    namespace, host_veth, peer, gateway, client = _network_names(run_id)
    table = f"buc_{run_id.replace('-', '')[:8]}"
    client_table = f"buc_c_{run_id.replace('-', '')[:8]}"
    proxy_evidence = ATTESTATION_ROOT / f"{run_id}.proxy-evidence.json"
    proxy_ready = ATTESTATION_ROOT / f"{run_id}.proxy-ready"
    attestation_path = ATTESTATION_ROOT / f"{run_id}.attestation.json"
    proxy_process = None
    probe_temp_root: Path | None = None
    namespace_created = False
    nft_created = False
    link_created = False
    controls_before: dict[str, str] = {}
    controls_after: dict[str, str] = {}
    namespace_inode = 0
    browser_namespace_inodes: list[int] = []
    observed: dict = {}
    result: dict = {}
    cleanup_verified = False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("0.0.0.0", 0))
        proxy_port = sock.getsockname()[1]
    try:
        metadata = ATTESTATION_ROOT.stat()
        if metadata.st_uid != 0 or metadata.st_mode & 0o022 or ATTESTATION_ROOT.is_symlink():
            raise RuntimeError("root-owned attestation directory is missing or writable by capture user")
        capability_failure = _boundary_capability_failure(
            Path("/proc/self/status").read_text(encoding="ascii")
        )
        if capability_failure:
            raise RuntimeError(capability_failure)
        namespace_created = True
        nft_created = True
        link_created = True
        _setup_namespace(namespace, host_veth, peer, gateway, client, table, client_table, proxy_port)
        proxy_process = _proxy_start(
            gateway, proxy_port, approved_host, proxy_ready, proxy_evidence,
            COMPATIBILITY_SERVICE_HOSTS,
        )
        controls_before = _probe(namespace, gateway, proxy_port, approved_host, approved_port, client_table)
        if controls_before != {"direct": "blocked", "proxied": "passed"}:
            raise RuntimeError("direct-egress denial or approved proxy control failed")
        namespace_inode = _namespace_inode(namespace)
        browser_result = run([args.browser, "--version"], timeout=10, check=False)
        if browser_result.returncode:
            raise RuntimeError("configured browser version could not be verified")
        version_text = (browser_result.stdout.strip() or browser_result.stderr.strip()).splitlines()[0]
        version_match = re.search(r"\d+(?:\.\d+){2,3}", version_text)
        if not version_match:
            raise RuntimeError("configured browser version string is not recognized")
        checked = _now()
        attestation = {
            "schemaVersion": SCHEMA_VERSION,
            "boundaryId": str(uuid.uuid4()),
            "runId": run_id,
            "checkedAt": _iso(checked),
            "expiresAt": _iso(checked + dt.timedelta(seconds=MAX_AGE_SECONDS)),
            "runnerInstanceId": args.runner_id,
            "browserExecutable": str(Path(args.browser).resolve()),
            "browserVersion": version_match.group(0),
            "captureRuntime": "browser-use",
            "captureRuntimeVersion": args.browser_use_version,
            "browserUseVersion": args.browser_use_version,
            "approvedHost": approved_host,
            "compatibilityServiceHosts": sorted(COMPATIBILITY_SERVICE_HOSTS),
            "compatibilityServicePort": 443,
            "compatibilityServicePolicy": "preflight-services.v1",
            "networkNamespaceInode": namespace_inode,
            "directEgressBlocked": True,
            "proxyPolicy": POLICY,
            "controls": {key: {"status": value} for key, value in controls_before.items()},
        }
        _write_attestation(attestation_path, attestation)
        probe_temp_root, probe_environment = _short_probe_environment(args.capture_user)
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            **probe_environment,
            "PYTHONDONTWRITEBYTECODE": "1",
            "ANONYMIZED_TELEMETRY": "false",
            "BROWSER_USE_CLOUD_SYNC": "false",
            "BROWSER_USE_VERSION_CHECK": "false",
            "BROWSER_USE_CHROMIUM_PATH": str(Path(args.browser).resolve()),
            "VAST_INSTANCE_ID": args.runner_id,
            "CAPTURE_EGRESS_ATTESTATION_FILE": str(attestation_path),
            "CAPTURE_EGRESS_PROXY_HOST": gateway,
            "CAPTURE_EGRESS_PROXY_PORT": str(proxy_port),
            "CAPTURE_EGRESS_RUN_ID": run_id,
        }
        command = [
            "ip", "netns", "exec", namespace, "runuser", "-u", args.capture_user, "--", "env",
            *(f"{key}={value}" for key, value in env.items()),
            args.python, args.script,
        ]
        probe, browser_namespace_inodes = _run_namespaced_probe(
            command,
            timeout=args.timeout + 60,
            browser_executable=str(Path(args.browser).resolve()),
            browser_profile_marker=f"/tmp/buc-{run_id.replace('-', '')[:16]}-",
        )
        for line in reversed(probe.stdout.splitlines()):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                result = payload
                break
        if not result:
            result = {
                "status": "blocked",
                "cpu": {"status": "blocked", "failureReason": "compatibility probe returned invalid JSON"},
                "gpu": {"status": "blocked", "reason": "compatibility probe returned invalid JSON"},
                "egressPolicy": {"browserNetworkNamespaceInode": None},
            }
        try:
            controls_after = _probe(namespace, gateway, proxy_port, approved_host, approved_port, client_table)
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            controls_after = {"direct": "unavailable", "proxied": "blocked"}
    except Exception as error:
        setup_failure = _safe_boundary_setup_failure(error)
        result = {
            "status": "blocked",
            "failureReason": setup_failure,
            "cpu": {"status": "blocked", "failureReason": setup_failure},
            "gpu": {"status": "blocked", "reason": setup_failure},
            "egressPolicy": {"browserNetworkNamespaceInode": None},
        }
    finally:
        proxy_clean = _stop(proxy_process)
        nft_clean = run(["nft", "delete", "table", "inet", table], timeout=10, check=False).returncode == 0 if nft_created else True
        namespace_clean = run(["ip", "netns", "del", namespace], timeout=10, check=False).returncode == 0 if namespace_created else True
        link_clean = _remove_link(host_veth) if link_created else True
        temp_clean = True
        if probe_temp_root is not None:
            try:
                shutil.rmtree(probe_temp_root)
            except FileNotFoundError:
                pass
            except OSError:
                temp_clean = False
        cleanup_verified = proxy_clean and nft_clean and namespace_clean and link_clean and temp_clean
        observed = _read_proxy_evidence(proxy_evidence)
        for path in (attestation_path, proxy_evidence, proxy_ready):
            path.unlink(missing_ok=True)
    return _finalize_compatibility_egress(
        result,
        controls_before=controls_before,
        controls_after=controls_after,
        proxy_evidence=observed,
        approved_host=approved_host,
        approved_port=approved_port,
        namespace_inode=namespace_inode,
        browser_namespace_inodes=browser_namespace_inodes,
        cleanup_verified=cleanup_verified,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture = subparsers.add_parser("capture")
    for option in ("run-id", "run-directory", "input", "result", "runner-id", "browser", "browser-use-version", "capture-user", "python", "worker"):
        capture.add_argument(f"--{option}", required=True)
    capture.add_argument("--timeout", required=True, type=int)
    compatibility = subparsers.add_parser("compatibility")
    for option in ("run-id", "run-directory", "runner-id", "browser", "browser-use-version", "capture-user", "python", "script"):
        compatibility.add_argument(f"--{option}", required=True)
    compatibility.add_argument("--timeout", required=True, type=int)
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
    if args.command == "compatibility":
        try:
            result = run_compatibility(args)
        except Exception:
            result = {
                "status": "blocked",
                "cpu": {"status": "blocked", "failureReason": "compatibility boundary setup failed"},
                "gpu": {"status": "blocked", "reason": "compatibility boundary setup failed"},
                "egressPolicy": {
                    "status": "blocked",
                    "failureReason": "The namespace, exact-host proxy, or cleanup evidence failed.",
                    "proxyPolicyCheck": "blocked",
                    "browserTrafficBoundary": "blocked",
                    "browserServiceReachability": "blocked",
                    "browserServiceOutcomes": [],
                    "unexpectedViolationCodes": [],
                    "unauthorizedConnections": [],
                    "blockedDestinations": [],
                    "connectionOutcomes": [],
                },
                "failureReason": "compatibility boundary setup failed",
            }
        print(json.dumps(result, sort_keys=True))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
