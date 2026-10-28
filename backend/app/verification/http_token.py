"""HTTP token verification: user serves a token at /.well-known/vulnscope-verify.txt.

The request is made from inside the API container, next to Postgres and Redis, so it is guarded
against server-side request forgery (SSRF):
- the host must resolve only to public addresses, and the connection goes to the exact address
  that was checked (the hostname is kept for the Host header and TLS SNI, so the certificate is
  still verified), so DNS can't answer differently a second time (DNS rebinding);
- redirects are never followed and no proxy is used;
- the response is capped, and the whole check, DNS included, has a deadline.
"""

import ipaddress
import time
from collections.abc import Callable
from urllib.parse import urlsplit

import dns.exception
import dns.resolver
import httpx

from app.models.enums import TargetType
from app.verification.hosts import is_ip, target_host
from app.verification.outcome import Outcome

WELL_KNOWN_PATH = "/.well-known/vulnscope-verify.txt"
DEADLINE_SECONDS = 10.0  # the whole check: DNS, connect, headers, and body
READ_TIMEOUT_SECONDS = 3.0  # a stalled read gives up after this, then the deadline is checked
MAX_BYTES = 1024
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


def check(
    url: str,
    token: str,
    client: httpx.Client | None = None,
    lookup: AddressLookup | None = None,
) -> Outcome:
    deadline = time.monotonic() + DEADLINE_SECONDS
    host = urlsplit(url).hostname or ""
    try:
        addresses = (lookup or lookup_addresses)(host, DEADLINE_SECONDS)
    except dns.exception.Timeout:
        return Outcome.fail(f"DNS lookup of {host} timed out")
    except (dns.exception.DNSException, OSError):
        return Outcome.fail(f"{host} does not resolve")
    blocked = sorted({a for a in addresses if not is_public_address(a)})
    if not addresses or blocked:
        return Outcome.fail(
            f"{host} resolves to a non-public address ({', '.join(blocked) or 'none'}); "
            "VulnScope only fetches verification tokens from public addresses"
        )

    target, headers, extensions = pinned_request(url, addresses[0])
    remaining = max(deadline - time.monotonic(), 0.1)
    timeout = httpx.Timeout(min(READ_TIMEOUT_SECONDS, remaining), connect=remaining)
    owned = client is None
    http = client or httpx.Client(trust_env=False)
    try:
        with http.stream(
            "GET",
            target,
            headers=headers,
            extensions=extensions,
            timeout=timeout,
            follow_redirects=False,
        ) as response:
            if response.status_code != 200:
                note = " (redirects are not followed)" if response.is_redirect else ""
                return Outcome.fail(f"{url} answered HTTP {response.status_code}{note}")
            body = b""
            for chunk in response.iter_bytes():
                body += chunk
                if len(body) > MAX_BYTES:
                    return Outcome.fail(f"{url} returned more than {MAX_BYTES} bytes")
                if time.monotonic() > deadline:  # a slow trickle can't hold the check open
                    return Outcome.fail(f"{url} took longer than {DEADLINE_SECONDS:.0f}s")
    except httpx.HTTPError as exc:
        return Outcome.fail(f"could not fetch {url}: {type(exc).__name__}")
    finally:
        if owned:
            http.close()
    if body.decode("utf-8", "replace").strip() == token:
        return Outcome.ok(f"{url} serves the token")
    return Outcome.fail(f"{url} doesn't contain the token")
