"""Allowlisting egress proxy for clearnet sources.

The crawler has no route to the internet. Onion traffic leaves through Tor; the
few clearnet feeds that refuse Tor exits leave through this proxy, which only
tunnels HTTPS to hostnames the operator listed in EGRESS_ALLOW_HOSTS. Changing
that list means editing .env and restarting this container - the application
cannot widen its own egress.

    python -m app.egress_proxy
"""
import asyncio
import ipaddress
import logging
import socket

from app.config import get_settings

log = logging.getLogger("egress")
IDLE_TIMEOUT = 90
MAX_BYTES = 32 * 1024 * 1024


def allowed(host: str, allow: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for entry in allow:
        if entry.startswith("."):
            if host == entry[1:] or host.endswith(entry):
                return True
        elif host == entry:
            return True
    return False


async def _resolve_public(host: str) -> str | None:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return None
    addresses = [info[4][0] for info in infos]
    # Every answer must be public: an allowlisted name must not be able to point inwards.
    if not addresses or not all(ipaddress.ip_address(a).is_global for a in addresses):
        return None
    return addresses[0]


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, budget: list[int]) -> None:
    try:
        while budget[0] > 0:
            data = await asyncio.wait_for(reader.read(65536), IDLE_TIMEOUT)
            if not data:
                break
            budget[0] -= len(data)
            writer.write(data)
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    allow = get_settings().egress_allow_list

    async def deny(status: str, why: str, target: str = "") -> None:
        log.warning("DENY %s %s", target, why)
        writer.write(f"HTTP/1.1 {status}\r\nX-Egress-Reason: {why}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())
        await writer.drain()
        writer.close()

    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
        writer.close()
        return
    try:
        method, target, _ = head.split(b"\r\n", 1)[0].decode("latin-1").split(" ", 2)
    except ValueError:
        return await deny("400 Bad Request", "malformed request")
    if method != "CONNECT":
        return await deny("405 Method Not Allowed", "only HTTPS tunnels are proxied", target)
    host, _, port = target.rpartition(":")
    if port != "443":
        return await deny("403 Forbidden", "only port 443 is allowed", target)
    if not allowed(host, allow):
        return await deny("403 Forbidden", "host is not in EGRESS_ALLOW_HOSTS", target)
    address = await _resolve_public(host)
    if not address:
        return await deny("502 Bad Gateway", "host did not resolve to a public address", target)
    try:
        up_reader, up_writer = await asyncio.wait_for(asyncio.open_connection(address, 443), 20)
    except (asyncio.TimeoutError, OSError):
        return await deny("504 Gateway Timeout", "upstream connection failed", target)

    log.info("ALLOW %s -> %s", target, address)
    writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
    await writer.drain()
    budget = [MAX_BYTES]
    await asyncio.gather(_pipe(reader, up_writer, budget), _pipe(up_reader, writer, budget))


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s egress %(message)s")
    allow = get_settings().egress_allow_list
    log.info("allowlist (%d hosts): %s", len(allow), ", ".join(allow) or "(empty - all direct egress denied)")
    server = await asyncio.start_server(handle, "0.0.0.0", 8888, limit=16384)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
