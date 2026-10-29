"""HTTP token verification: user serves a token at /.well-known/vulnscope-verify.txt.

The request is made from inside the API container, next to Postgres and Redis, so it is guarded
against server-side request forgery (SSRF):
- the host must resolve only to public addresses, and the connection goes to the exact address
  that was checked (the hostname is kept for the Host header and TLS SNI, so the certificate is
  still verified), so DNS can't answer differently a second time (DNS rebinding);
- redirects are never followed, no proxy is used, and nothing is decompressed (the 1 KB cap
  applies to the bytes actually received);
- the whole check, DNS included, has one deadline, enforced on every socket read and write, so
  a server trickling headers or body bytes can't hold it open;
- failures don't reveal what a host resolves to (the endpoint needs no proof of ownership).
"""

import ipaddress
import ssl
import time
from collections.abc import Callable, Iterable
from typing import Any
from urllib.parse import urlsplit

import dns.exception
import dns.resolver
import httpcore
import httpx

from app.models.enums import TargetType
from app.verification.hosts import is_ip, target_host
from app.verification.outcome import Outcome

WELL_KNOWN_PATH = "/.well-known/vulnscope-verify.txt"
DEADLINE_SECONDS = 10.0  # the whole check: DNS, connect, headers, and body
READ_TIMEOUT_SECONDS = 3.0  # no single read waits longer than this (or than the time left)
MAX_BYTES = 1024
# One message for "doesn't resolve" and "resolves to a non-public address": anyone can call the
# check endpoint, so it must not become a way to map internal hostnames and addresses.
NOT_CHECKABLE = "VulnScope only fetches verification tokens from hosts with public addresses"
_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")

# Resolves a host to every IP address it maps to, within the given number of seconds.
AddressLookup = Callable[[str, float], list[str]]


def token_url(target_type: TargetType, value: str) -> str:
    """Where the token must be served: the target's own origin for a url, https for a domain,
    and plain http for an ip (bare IPs rarely have certificates)."""
    if target_type is TargetType.URL:
        parts = urlsplit(value)
        return f"{parts.scheme}://{parts.netloc}{WELL_KNOWN_PATH}"
    host = target_host(target_type, value)
    if target_type is TargetType.DOMAIN:
        return f"https://{host}{WELL_KNOWN_PATH}"
    if target_type is TargetType.IP and host is not None:
        literal = f"[{host}]" if ":" in host else host
        return f"http://{literal}{WELL_KNOWN_PATH}"
    raise ValueError(f"{target_type} targets have no HTTP token URL")


def is_public_address(address: str) -> bool:
    """A globally routable unicast address. IPv4 addresses embedded in IPv6 (::ffff:a.b.c.d and
    the 64:ff9b:: NAT64 prefix) are judged by their IPv4 part, which is what they reach."""
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        elif ip in _NAT64:
            ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return ip.is_global and not ip.is_multicast


def lookup_addresses(host: str, timeout: float) -> list[str]:
    """A and AAAA records via dnspython, which (unlike socket.getaddrinfo) honours a timeout."""
    if is_ip(host):
        return [host]
    deadline = time.monotonic() + timeout
    addresses: list[str] = []
    for record_type in ("A", "AAAA"):
        try:
            answer = dns.resolver.resolve(
                host, record_type, lifetime=max(deadline - time.monotonic(), 0.1)
            )
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        addresses.extend(rdata.to_text() for rdata in answer)
    return addresses


def pinned_request(url: str, address: str) -> tuple[str, dict[str, str], dict[str, str]]:
    """The URL to connect to (host replaced by the vetted address), plus the Host header and
    TLS SNI that keep the request, and certificate verification, about the original host."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    literal = f"[{address}]" if ":" in address else address
    netloc = f"{literal}:{parts.port}" if parts.port else literal
    host_header = parts.netloc.rsplit("@", 1)[-1]  # host[:port] as the user wrote it
    return parts._replace(netloc=netloc).geturl(), {"Host": host_header}, {"sni_hostname": host}


class _DeadlineStream(httpcore.NetworkStream):
    """A connection whose every read, write, and TLS handshake is bounded by a shared deadline."""

    def __init__(self, stream: httpcore.NetworkStream, deadline: float) -> None:
        self._stream = stream
        self._deadline = deadline

    def _bound(self, timeout: float | None) -> float:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise httpcore.ReadTimeout("verification deadline reached")
        return remaining if timeout is None else min(timeout, remaining)

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return self._stream.read(max_bytes, self._bound(timeout))

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self._stream.write(buffer, self._bound(timeout))

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.NetworkStream:
        stream = self._stream.start_tls(ssl_context, server_hostname, self._bound(timeout))
        return _DeadlineStream(stream, self._deadline)

    def close(self) -> None:
        self._stream.close()

    def get_extra_info(self, info: str) -> Any:
        return self._stream.get_extra_info(info)


class _DeadlineBackend(httpcore.NetworkBackend):
    """Hands out _DeadlineStreams, so the deadline covers connecting, headers, and body alike."""

    def __init__(self, inner: httpcore.NetworkBackend, deadline: float) -> None:
        self._inner = inner
        self._deadline = deadline

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.NetworkStream:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise httpcore.ConnectTimeout("verification deadline reached")
        bounded = remaining if timeout is None else min(timeout, remaining)
        stream = self._inner.connect_tcp(host, port, bounded, local_address, socket_options)
        return _DeadlineStream(stream, self._deadline)

    def sleep(self, seconds: float) -> None:
        self._inner.sleep(seconds)


def check(
    url: str,
    token: str,
    backend: httpcore.NetworkBackend | None = None,
    lookup: AddressLookup | None = None,
) -> Outcome:
    deadline = time.monotonic() + DEADLINE_SECONDS
    host = urlsplit(url).hostname or ""
    try:
        addresses = (lookup or lookup_addresses)(host, DEADLINE_SECONDS)
    except (dns.exception.DNSException, OSError):
        addresses = []
    if not addresses or not all(is_public_address(a) for a in addresses):
        return Outcome.fail(f"{url} can't be checked: {NOT_CHECKABLE}")

    target, headers, extensions = pinned_request(url, addresses[0])
    request_headers = [
        (b"Host", headers["Host"].encode()),
        (b"Accept-Encoding", b"identity"),  # ask for the raw file; httpcore never decompresses
        (b"User-Agent", b"VulnScope ownership check"),
    ]
    timeouts = {"connect": DEADLINE_SECONDS, "read": READ_TIMEOUT_SECONDS}
    timeouts |= {"write": READ_TIMEOUT_SECONDS, "pool": DEADLINE_SECONDS}
    pool = httpcore.ConnectionPool(
        ssl_context=httpx.create_ssl_context(),  # verifies certificates (certifi)
        network_backend=_DeadlineBackend(backend or httpcore.SyncBackend(), deadline),
        max_connections=1,
        retries=0,
    )
    try:
        with (
            pool,
            pool.stream(
                "GET",
                target,
                headers=request_headers,
                extensions={**extensions, "timeout": timeouts},
            ) as response,
        ):
            if response.status != 200:
                note = " (redirects are not followed)" if 300 <= response.status < 400 else ""
                return Outcome.fail(f"{url} answered HTTP {response.status}{note}")
            body = b""
            for chunk in response.iter_stream():
                body += chunk
                if len(body) > MAX_BYTES:
                    return Outcome.fail(f"{url} returned more than {MAX_BYTES} bytes")
    except httpcore.TimeoutException:
        if time.monotonic() >= deadline:
            return Outcome.fail(f"{url} took longer than {DEADLINE_SECONDS:.0f}s")
        return Outcome.fail(f"could not fetch {url}: it stopped responding")
    except (httpcore.NetworkError, httpcore.ProtocolError, httpcore.UnsupportedProtocol) as exc:
        return Outcome.fail(f"could not fetch {url}: {type(exc).__name__}")
    if body.decode("utf-8", "replace").strip() == token:
        return Outcome.ok(f"{url} serves the token")
    return Outcome.fail(f"{url} doesn't contain the token")
