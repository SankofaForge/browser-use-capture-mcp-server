from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

from mcp_types.version import LATEST_HANDSHAKE_VERSION


async def _read_message(reader):
    line = await asyncio.wait_for(reader.readline(), timeout=5)
    assert line, "MCP server closed stdout before returning a JSON-RPC message"
    return json.loads(line)


async def _exchange(process, payload):
    process.stdin.write((json.dumps(payload) + "\n").encode())
    await process.stdin.drain()
    return await _read_message(process.stdout)


async def _exercise_stdio_server():
    environment = os.environ.copy()
    for key in ("VAST_INSTANCE_ID", "VAST_API_KEY", "BROWSER_USE_CHROMIUM_PATH"):
        environment.pop(key, None)
    source_root = str(Path(__file__).parents[1] / "src")
    environment["PYTHONPATH"] = os.pathsep.join(
        item for item in (source_root, environment.get("PYTHONPATH", "")) if item
    )
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "browser_use_capture_mcp.server",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=environment,
        start_new_session=True,
    )
    try:
        initialized = await _exchange(process, {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": LATEST_HANDSHAKE_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "adapter-contract-test", "version": "1"},
            },
        })
        assert initialized["id"] == 1
        assert initialized["result"]["serverInfo"]["name"] == "browser-use-capture"
        process.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        await process.stdin.drain()
        listed = await _exchange(process, {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        })
        assert listed["id"] == 2
        assert {tool["name"] for tool in listed["result"]["tools"]} == {
            "check_capture_gpu",
            "capture_site_motion",
        }
        capability = await _exchange(process, {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "check_capture_gpu", "arguments": {}},
        })
        assert capability["id"] == 3
        assert capability["result"]["structuredContent"]["status"] == "blocked"
        assert capability["result"]["structuredContent"]["reasonCode"] == "vast-instance-unconfigured"
    finally:
        process.stdin.close()
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()


def test_stdio_json_rpc_exposes_only_two_bounded_tools():
    asyncio.run(_exercise_stdio_server())
