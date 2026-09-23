from __future__ import annotations

import asyncio
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "remote"))
from public_socks_proxy import (
    REVIEWED_EGRESS_HOSTS,
    REVIEWED_EGRESS_TTL_SECONDS,
    EgressPolicyError,
    PublicSocksProxy,
)


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


def test_reviewed_egress_experiment_allows_only_two_exact_https_hosts():
    resolved = []

    def resolver(host: str, port: int, *, type: int):
        resolved.append((host, port))
        return _records(["1.1.1.1"])(host, port, type=type)

    async def run():
        proxy = PublicSocksProxy(
            approved_hostname="site.example",
            reviewed_egress_experiment=True,
            resolver=resolver,
        )
        for hostname in REVIEWED_EGRESS_HOSTS:
            assert await proxy._resolve_public_address(hostname, 443) == ("1.1.1.1", 4)
        for hostname, port in (
            ("www.gstatic.com", 80),
            ("update.googleapis.com", 80),
            ("sub.www.gstatic.com", 443),
            ("accounts.google.com", 443),
        ):
            try:
                await proxy._resolve_public_address(hostname, port)
            except EgressPolicyError as error:
                assert error.reason_code == "domain-not-approved"
            else:
                raise AssertionError(f"unexpectedly approved {hostname}:{port}")
        assert set(resolved) == {(hostname, 443) for hostname in REVIEWED_EGRESS_HOSTS}

    asyncio.run(run())


def test_reviewed_egress_experiment_expires_after_one_hour():
    now = [100.0]

    async def run():
        proxy = PublicSocksProxy(
            approved_hostname="site.example",
            reviewed_egress_experiment=True,
            resolver=_records(["1.1.1.1"]),
            clock=lambda: now[0],
        )
        assert await proxy._resolve_public_address("www.gstatic.com", 443) == ("1.1.1.1", 4)
        now[0] += REVIEWED_EGRESS_TTL_SECONDS
        try:
            await proxy._resolve_public_address("www.gstatic.com", 443)
        except EgressPolicyError as error:
            assert error.reason_code == "domain-not-approved"
        else:
            raise AssertionError("reviewed egress approval remained active after expiry")

    asyncio.run(run())


def test_reviewed_egress_flag_defaults_to_disabled():
    async def run():
        proxy = PublicSocksProxy(approved_hostname="site.example")
        await proxy.start()
        try:
            reply = await _request_connect(proxy, "www.gstatic.com", 443)
            assert reply[1] == 2
            assert proxy.connection_outcomes == [{
                "hostname": "www.gstatic.com",
                "port": 443,
                "outcome": "blocked",
                "count": 1,
            }]
            assert not {"path", "method", "initiator"}.intersection(proxy.connection_outcomes[0])
        finally:
            await proxy.close()

    asyncio.run(run())


def test_connection_outcomes_are_aggregated_without_request_data():
    proxy = PublicSocksProxy(approved_hostname="site.example")

    proxy._record_connection_outcome("WWW.GSTATIC.COM.", 443, "connected")
    proxy._record_connection_outcome("www.gstatic.com", 443, "connected")

    assert proxy.connection_outcomes == [{
        "hostname": "www.gstatic.com",
        "port": 443,
        "outcome": "connected",
        "count": 2,
    }]


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
