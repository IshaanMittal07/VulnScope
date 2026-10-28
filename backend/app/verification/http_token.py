"""HTTP token verification: user serves a token at /.well-known/vulnscope-verify.txt.

The request is made from inside the API container, next to Postgres and Redis, so it is guarded
against server-side request forgery (SSRF): the host must resolve only to public addresses,
redirects are never followed, no proxy is used, and the response is capped and timed out.
"""

import ipaddress
import socket
from collections.abc import Callable
from urllib.parse import urlsplit

import httpx

from app.models.enums import TargetType
from app.verification.hosts import target_host
from app.verification.outcome import Outcome

WELL_KNOWN_PATH = "/.well-known/vulnscope-verify.txt"
TIMEOUT_SECONDS = 5.0
MAX_BYTES = 1024
_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")

# Resolves a host to every IP address it maps to.
AddressLookup = Callable[[str, int], list[str]]


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


def lookup_addresses(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    return [str(info[4][0]) for info in infos]


def check(
    url: str,
    token: str,
    client: httpx.Client | None = None,
    lookup: AddressLookup | None = None,
) -> Outcome:
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        addresses = (lookup or lookup_addresses)(host, port)
    except OSError:
        return Outcome.fail(f"{host} does not resolve")
    blocked = sorted({a for a in addresses if not is_public_address(a)})
    if not addresses or blocked:
        return Outcome.fail(
            f"{host} resolves to a non-public address ({', '.join(blocked) or 'none'}); "
            "VulnScope only fetches verification tokens from public addresses"
        )

    owned = client is None
    http = client or httpx.Client(timeout=TIMEOUT_SECONDS, trust_env=False)
    try:
        with http.stream("GET", url, follow_redirects=False) as response:
            if response.status_code != 200:
                note = " (redirects are not followed)" if response.is_redirect else ""
                return Outcome.fail(f"{url} answered HTTP {response.status_code}{note}")
            body = b""
            for chunk in response.iter_bytes():
                body += chunk
                if len(body) > MAX_BYTES:
                    return Outcome.fail(f"{url} returned more than {MAX_BYTES} bytes")
    except httpx.HTTPError as exc:
        return Outcome.fail(f"could not fetch {url}: {type(exc).__name__}")
    finally:
        if owned:
            http.close()
    if body.decode("utf-8", "replace").strip() == token:
        return Outcome.ok(f"{url} serves the token")
    return Outcome.fail(f"{url} doesn't contain the token")
