"""Local SOCKS5 egress proxy that pins connections to public DNS answers."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import socket
import time
from collections.abc import Callable
from typing import Any


REVIEWED_EGRESS_HOSTS = frozenset({"www.gstatic.com", "update.googleapis.com"})
REVIEWED_EGRESS_TTL_SECONDS = 60 * 60


class EgressPolicyError(RuntimeError):
    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code


class PublicSocksProxy:
    def __init__(
        self,
        *,
        approved_hostname: str,
        reviewed_egress_experiment: bool = False,
        resolver: Callable[..., list[tuple[Any, ...]]] = socket.getaddrinfo,
        clock: Callable[[], float] = time.monotonic,
        host: str = "127.0.0.1",
    ) -> None:
        self.resolver = resolver
        self.host = host
        try:
            self.approved_hostname = approved_hostname.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError as error:
            raise ValueError("approved hostname is invalid") from error
        if not self.approved_hostname:
            raise ValueError("approved hostname is required")
        if not isinstance(reviewed_egress_experiment, bool):
            raise ValueError("reviewed egress experiment flag must be boolean")
        self._clock = clock
        self.reviewed_egress_experiment = reviewed_egress_experiment
        self._reviewed_egress_expires_at = (
            self._clock() + REVIEWED_EGRESS_TTL_SECONDS
            if reviewed_egress_experiment
            else None
        )
        self.port = 0
        self.server: asyncio.Server | None = None
        self.violations: list[str] = []
        self.blocked_destinations: list[dict[str, Any]] = []
        self.connection_outcomes: list[dict[str, Any]] = []
        self._handlers: set[asyncio.Task[Any]] = set()

    async def start(self) -> int:
        if self.server is not None:
            return self.port
        self.server = await asyncio.start_server(self._handle_client, self.host, 0, limit=65536)
        sockets = self.server.sockets or []
        if not sockets:
            raise RuntimeError("SOCKS proxy did not bind a socket")
        self.port = int(sockets[0].getsockname()[1])
        return self.port

    async def close(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
        handlers = [task for task in self._handlers if task is not asyncio.current_task()]
        for task in handlers:
            task.cancel()
        if handlers:
            await asyncio.gather(*handlers, return_exceptions=True)

    def _record_violation(self, reason_code: str) -> None:
        if reason_code not in self.violations and len(self.violations) < 100:
            self.violations.append(reason_code)

    def _record_blocked_destination(self, host: str, port: int, reason_code: str) -> None:
        try:
            normalized_host = host.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError:
            normalized_host = "invalid-host"
        entry = {"hostname": normalized_host[:253], "port": port, "reason": reason_code}
        if entry not in self.blocked_destinations and len(self.blocked_destinations) < 100:
            self.blocked_destinations.append(entry)

    def _record_connection_outcome(self, host: str, port: int, outcome: str) -> None:
        try:
            normalized_host = host.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError:
            normalized_host = "invalid-host"
        for entry in self.connection_outcomes:
            if (
                entry["hostname"] == normalized_host
                and entry["port"] == port
                and entry["outcome"] == outcome
            ):
                entry["count"] += 1
                return
        if len(self.connection_outcomes) < 100:
            self.connection_outcomes.append({
                "hostname": normalized_host[:253],
                "port": port,
                "outcome": outcome,
                "count": 1,
            })

    def _destination_is_approved(self, hostname: str, port: int) -> bool:
        if hostname == self.approved_hostname:
            return port in {80, 443}
        return (
            self.reviewed_egress_experiment
            and hostname in REVIEWED_EGRESS_HOSTS
            and port == 443
            and self._reviewed_egress_expires_at is not None
            and self._clock() < self._reviewed_egress_expires_at
        )

    async def _resolve_public_address(self, host: str, port: int) -> tuple[str, int]:
        try:
            normalized_host = host.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError as error:
            raise EgressPolicyError("invalid-destination-host") from error
        if not normalized_host or normalized_host == "localhost" or normalized_host.endswith((".localhost", ".local", ".internal")):
            raise EgressPolicyError("non-public-destination")
        try:
            literal = ipaddress.ip_address(normalized_host)
        except ValueError:
            literal = None
        if literal is not None:
            if not literal.is_global:
                raise EgressPolicyError("non-public-destination")
            if not self._destination_is_approved(normalized_host, port):
                raise EgressPolicyError("domain-not-approved")
            addresses = [literal]
        else:
            if not self._destination_is_approved(normalized_host, port):
                raise EgressPolicyError("domain-not-approved")
            try:
                records = await asyncio.wait_for(
                    asyncio.to_thread(
                        self.resolver,
                        normalized_host,
                        port,
                        type=socket.SOCK_STREAM,
                    ),
                    timeout=5,
                )
            except Exception as error:
                raise EgressPolicyError("dns-resolution-failed") from error
            addresses = []
            for record in records:
                try:
                    addresses.append(ipaddress.ip_address(record[4][0].split("%", 1)[0]))
                except (IndexError, ValueError):
                    raise EgressPolicyError("invalid-dns-answer")
        if not addresses or any(not address.is_global for address in addresses):
            raise EgressPolicyError("non-public-destination")
        address = sorted(addresses, key=lambda item: (item.version, item.packed))[0]
        return address.compressed, address.version

    async def _read_destination(self, reader: asyncio.StreamReader) -> tuple[str, int]:
        version, command, reserved, address_type = await reader.readexactly(4)
        if version != 5 or reserved != 0:
            raise EgressPolicyError("invalid-socks-request")
        if command != 1:
            raise EgressPolicyError("unsupported-socks-command")
        if address_type == 1:
            host = str(ipaddress.IPv4Address(await reader.readexactly(4)))
        elif address_type == 4:
            host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
        elif address_type == 3:
            length = (await reader.readexactly(1))[0]
            if length == 0:
                raise EgressPolicyError("invalid-destination-host")
            try:
                host = (await reader.readexactly(length)).decode("ascii")
            except UnicodeDecodeError as error:
                raise EgressPolicyError("invalid-destination-host") from error
        else:
            raise EgressPolicyError("invalid-socks-address-type")
        port = int.from_bytes(await reader.readexactly(2), "big")
        if not 1 <= port <= 65535:
            raise EgressPolicyError("invalid-destination-port")
        return host, port

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._handlers.add(task)
        upstream_writer: asyncio.StreamWriter | None = None
        try:
            version, method_count = await asyncio.wait_for(reader.readexactly(2), timeout=5)
            if version != 5 or not 1 <= method_count <= 32:
                raise EgressPolicyError("invalid-socks-handshake")
            methods = await asyncio.wait_for(reader.readexactly(method_count), timeout=5)
            if 0 not in methods:
                writer.write(b"\x05\xff")
                await writer.drain()
                raise EgressPolicyError("unsupported-socks-authentication")
            writer.write(b"\x05\x00")
            await writer.drain()
            host: str | None = None
            port: int | None = None
            try:
                host, port = await asyncio.wait_for(self._read_destination(reader), timeout=5)
                address, version = await self._resolve_public_address(host, port)
            except EgressPolicyError as error:
                self._record_violation(error.reason_code)
                if host is not None and port is not None:
                    self._record_blocked_destination(host, port, error.reason_code)
                    self._record_connection_outcome(host, port, "blocked")
                await self._reply(writer, self._reply_code(error.reason_code))
                return
            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        address,
                        port,
                        family=socket.AF_INET6 if version == 6 else socket.AF_INET,
                    ),
                    timeout=10,
                )
            except (OSError, asyncio.TimeoutError):
                self._record_violation("public-connect-failed")
                self._record_connection_outcome(host, port, "connect-failed")
                await self._reply(writer, 4)
                return
            self._record_connection_outcome(host, port, "connected")
            await self._reply(writer, 0)
            await self._relay(reader, writer, upstream_reader, upstream_writer)
        except asyncio.CancelledError:
            raise
        except EgressPolicyError as error:
            self._record_violation(error.reason_code)
        except asyncio.IncompleteReadError:
            pass
        except (asyncio.LimitOverrunError, OSError, asyncio.TimeoutError):
            self._record_violation("incomplete-socks-request")
        finally:
            if upstream_writer is not None:
                upstream_writer.close()
                with contextlib.suppress(Exception):
                    await upstream_writer.wait_closed()
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            if task is not None:
                self._handlers.discard(task)

    @staticmethod
    async def _reply(writer: asyncio.StreamWriter, code: int) -> None:
        writer.write(bytes((5, code, 0, 1, 0, 0, 0, 0, 0, 0)))
        await writer.drain()

    @staticmethod
    def _reply_code(reason_code: str) -> int:
        if reason_code in {"non-public-destination", "invalid-destination-host", "invalid-dns-answer", "domain-not-approved"}:
            return 2
        if reason_code == "unsupported-socks-command":
            return 7
        if reason_code == "invalid-socks-address-type":
            return 8
        return 4

    @staticmethod
    async def _relay(
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
    ) -> None:
        async def copy_stream(source: asyncio.StreamReader, destination: asyncio.StreamWriter) -> None:
            while chunk := await source.read(65536):
                destination.write(chunk)
                await destination.drain()

        tasks = {
            asyncio.create_task(copy_stream(client_reader, upstream_writer)),
            asyncio.create_task(copy_stream(upstream_reader, client_writer)),
        }
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*done, *pending, return_exceptions=True)
