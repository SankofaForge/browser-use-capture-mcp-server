from __future__ import annotations

import asyncio
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "remote"))
from public_socks_proxy import PublicSocksProxy


def _records(addresses: list[str]):
    def resolve(host: str, port: int, *, type: int):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port))
            for address in addresses
        ]

    return resolve


async def _request_connect(proxy: PublicSocksProxy, host: str, port: int = 443) -> bytes:
    reader, writer = await asyncio.open_connection(proxy.host, proxy.port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    assert await reader.readexactly(2) == b"\x05\x00"
    try:
        address = socket.inet_aton(host)
        request = b"\x05\x01\x00\x01" + address
    except OSError:
        encoded = host.encode("ascii")
        request = b"\x05\x01\x00\x03" + bytes((len(encoded),)) + encoded
    writer.write(request + port.to_bytes(2, "big"))
    await writer.drain()
    reply = await reader.readexactly(10)
    writer.close()
    await writer.wait_closed()
    return reply


def test_proxy_rejects_non_approved_hostname_before_dns_lookup():
    resolved = []

    def resolver(host: str, port: int, *, type: int):
        resolved.append((host, port))
        return _records(["1.1.1.1"])(host, port, type=type)

    async def run():
        proxy = PublicSocksProxy(approved_hostname="site.example", resolver=resolver)
        await proxy.start()
        try:
            reply = await _request_connect(proxy, "cdn.example", 443)
            assert reply[1] == 2
            assert proxy.violations == ["domain-not-approved"]
            assert proxy.blocked_destinations == [{
                "hostname": "cdn.example",
                "port": 443,
                "reason": "domain-not-approved",
            }]
            assert resolved == []
        finally:
            await proxy.close()

    asyncio.run(run())


def test_proxy_rejects_non_public_literal_address():
    async def run():
        proxy = PublicSocksProxy(approved_hostname="site.example")
        await proxy.start()
        try:
            reply = await _request_connect(proxy, "127.0.0.1", 80)
            assert reply[1] == 2
            assert proxy.violations == ["non-public-destination"]
        finally:
            await proxy.close()

    asyncio.run(run())


def test_proxy_rejects_mixed_public_and_private_dns_answers():
    async def run():
        proxy = PublicSocksProxy(
            approved_hostname="site.example",
            resolver=_records(["1.1.1.1", "127.0.0.1"]),
        )
        await proxy.start()
        try:
            reply = await _request_connect(proxy, "site.example", 443)
            assert reply[1] == 2
            assert proxy.violations == ["non-public-destination"]
        finally:
            await proxy.close()

    asyncio.run(run())


def test_proxy_resolves_once_and_pins_public_ip():
    calls = []

    def resolver(host: str, port: int, *, type: int):
        calls.append((host, port, type))
        return _records(["1.1.1.1", "1.0.0.1"])(host, port, type=type)

    async def run():
        proxy = PublicSocksProxy(approved_hostname="site.example", resolver=resolver)
        address, family = await proxy._resolve_public_address("site.example", 443)
        assert (address, family) == ("1.0.0.1", 4)
        assert calls == [("site.example", 443, socket.SOCK_STREAM)]

    asyncio.run(run())


def test_proxy_rejects_non_web_ports():
    async def run():
        proxy = PublicSocksProxy(approved_hostname="site.example", resolver=_records(["1.1.1.1"]))
        await proxy.start()
        try:
            reply = await _request_connect(proxy, "site.example", 2222)
            assert reply[1] == 2
            assert proxy.violations == ["domain-not-approved"]
        finally:
            await proxy.close()

    asyncio.run(run())


def test_client_disconnect_before_socks_handshake_is_not_an_egress_violation():
    async def run():
        proxy = PublicSocksProxy(approved_hostname="site.example")
        await proxy.start()
        try:
            _, writer = await asyncio.open_connection(proxy.host, proxy.port)
            writer.close()
            await writer.wait_closed()
            await asyncio.sleep(0.05)
            assert proxy.violations == []
        finally:
            await proxy.close()

    asyncio.run(run())
