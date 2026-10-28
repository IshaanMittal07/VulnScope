"""The three ownership checks, with DNS and HTTP replaced by fakes: no network needed."""

import gzip
import socket
import time
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

import dns.exception
import dns.resolver
import httpcore
import pytest

from app.models.enums import TargetType
from app.verification import dns_txt, http_token, lab

TOKEN = "kQ3vX_example-token-from-secrets-token_urlsafe-32"


# --- lab -------------------------------------------------------------------------------------


@pytest.mark.parametrize("host", ["juice-shop", "dvwa"])
def test_lab_hosts_pass_in_lab_mode(host: str) -> None:
    assert lab.check(host, lab_mode=True).verified


@pytest.mark.parametrize(
    "host",
    [
        "juice-shop.evil.com",  # merely contains a lab name
        "evil.juice-shop",
        "my-juice-shop",
        "juice-shop-fake",
        "dvwa.example.com",
        "juice_shop",
        "example.com",
        None,
    ],
)
def test_only_exact_lab_hostnames_pass(host: str | None) -> None:
    outcome = lab.check(host, lab_mode=True)
    assert not outcome.verified
    assert "not a lab target" in outcome.reason


def test_lab_hosts_fail_when_lab_mode_is_off() -> None:
    outcome = lab.check("juice-shop", lab_mode=False)
    assert not outcome.verified
    assert "LAB_MODE=false" in outcome.reason


# --- DNS TXT ---------------------------------------------------------------------------------


def test_dns_record_name() -> None:
    assert dns_txt.record_name("shop.example.com") == "_vulnscope.shop.example.com"


def test_dns_matching_txt_record_passes() -> None:
    looked_up: list[str] = []

    def lookup(name: str) -> list[str]:
        looked_up.append(name)
        return ["v=spf1 -all", TOKEN]

    assert dns_txt.check("example.com", TOKEN, lookup).verified
    assert looked_up == ["_vulnscope.example.com"]


def test_dns_other_txt_records_fail() -> None:
    outcome = dns_txt.check("example.com", TOKEN, lambda name: ["something-else", TOKEN + "x"])
    assert not outcome.verified
    assert "don't match" in outcome.reason


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (dns.resolver.NXDOMAIN, "no DNS record found"),
        (dns.resolver.NoAnswer, "has no TXT record"),
        (dns.exception.Timeout, "timed out"),
        (dns.resolver.NoNameservers, "failed: NoNameservers"),
    ],
)
def test_dns_lookup_errors_fail_cleanly(error: type[Exception], reason: str) -> None:
    def lookup(name: str) -> list[str]:
        raise error  # raising the class instantiates it, as dnspython's resolver would

    outcome = dns_txt.check("example.com", TOKEN, lookup)
    assert not outcome.verified
    assert reason in outcome.reason


# --- HTTP token: where the token must be served -----------------------------------------------


@pytest.mark.parametrize(
    ("target_type", "value", "url"),
    [
        (
            TargetType.URL,
            "https://shop.example.com:8443/login?x=1",
            "https://shop.example.com:8443/.well-known/vulnscope-verify.txt",
        ),
        (TargetType.DOMAIN, "example.com", "https://example.com/.well-known/vulnscope-verify.txt"),
        (TargetType.IP, "203.0.113.7", "http://203.0.113.7/.well-known/vulnscope-verify.txt"),
        (TargetType.IP, "2001:db8::1", "http://[2001:db8::1]/.well-known/vulnscope-verify.txt"),
    ],
)
def test_token_url(target_type: TargetType, value: str, url: str) -> None:
    assert http_token.token_url(target_type, value) == url


# --- HTTP token: SSRF guard ------------------------------------------------------------------


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.18.0.3",  # a Docker network, where Postgres and Redis live
        "192.168.1.5",
        "169.254.169.254",  # cloud metadata endpoint
        "100.64.0.1",
        "0.0.0.0",  # noqa: S104 (an address the guard must block, not a bind address)
        "224.0.0.1",  # multicast: Python calls it global, but it is not a web server
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1",  # IPv4-mapped loopback
        "::ffff:10.0.0.1",
        "64:ff9b::7f00:1",  # NAT64 for 127.0.0.1: Python calls it global
    ],
)
def test_non_public_addresses_are_blocked(address: str) -> None:
    assert not http_token.is_public_address(address)


@pytest.mark.parametrize(
    "address", ["8.8.8.8", "93.184.216.34", "2606:4700::1111", "::ffff:8.8.8.8"]
)
def test_public_addresses_are_allowed(address: str) -> None:
    assert http_token.is_public_address(address)


# --- HTTP token: fetching the file -----------------------------------------------------------
# The fetch runs on fake connections that replay raw HTTP bytes and record what was sent, so the
# tests cover exactly what reaches the network: the address dialled, the bytes written, TLS SNI,
# and how reads are bounded.

URL = "https://example.com/.well-known/vulnscope-verify.txt"


def public(host: str, timeout: float) -> list[str]:
    return ["93.184.216.34"]


def http_response(status: str, body: bytes = b"", headers: tuple[str, ...] = ()) -> list[bytes]:
    head = [f"HTTP/1.1 {status}", f"Content-Length: {len(body)}", *headers]
    return ["\r\n".join(head).encode() + b"\r\n\r\n", body]


class FakeStream(httpcore.NetworkStream):
    def __init__(self, network: "FakeNetwork") -> None:
        self.network = network

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        self.network.read_timeouts.append(timeout)
        self.network.clock[0] += self.network.seconds_per_read
        return self.network.chunks.pop(0) if self.network.chunks else b""

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self.network.written += buffer

    def start_tls(
        self, ssl_context: Any, server_hostname: str | None = None, timeout: float | None = None
    ) -> httpcore.NetworkStream:
        self.network.sni.append(server_hostname)
        return self

    def close(self) -> None:
        pass

    def get_extra_info(self, info: str) -> Any:
        return None


class FakeNetwork(httpcore.NetworkBackend):
    """Replays `chunks` for reads. Each read advances a fake clock by `seconds_per_read`."""

    def __init__(self, chunks: list[bytes], seconds_per_read: float = 0.0) -> None:
        self.chunks = list(chunks)
        self.seconds_per_read = seconds_per_read
        self.clock = [1000.0]
        self.dialled: list[tuple[str, int]] = []
        self.written = b""
        self.sni: list[str | None] = []
        self.read_timeouts: list[float | None] = []

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.NetworkStream:
        self.dialled.append((host, port))
        return FakeStream(self)

    def sleep(self, seconds: float) -> None:
        pass


def fake(monkeypatch: pytest.MonkeyPatch, network: FakeNetwork) -> FakeNetwork:
    monkeypatch.setattr(time, "monotonic", lambda: network.clock[0])  # undone after the test
    return network


def test_http_serving_the_token_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    network = fake(monkeypatch, FakeNetwork(http_response("200 OK", f"{TOKEN}\n".encode())))

    assert http_token.check(URL, TOKEN, network, public).verified
    assert network.dialled == [("93.184.216.34", 443)]


@pytest.mark.parametrize(
    ("url", "address", "dialled", "host_header"),
    [
        (URL, "93.184.216.34", ("93.184.216.34", 443), "example.com"),
        (
            "https://shop.example.com:8443/.well-known/vulnscope-verify.txt",
            "93.184.216.34",
            ("93.184.216.34", 8443),
            "shop.example.com:8443",
        ),
        (
            "http://example.com/.well-known/vulnscope-verify.txt",
            "2606:2800:220:1:248:1893:25c8:1946",
            ("2606:2800:220:1:248:1893:25c8:1946", 80),
            "example.com",
        ),
    ],
)
def test_http_connects_to_the_vetted_address_not_the_name(
    monkeypatch: pytest.MonkeyPatch,
    url: str,
    address: str,
    dialled: tuple[str, int],
    host_header: str,
) -> None:
    """DNS rebinding: the connection goes to the exact address the guard approved, so a second DNS
    answer can't redirect it. The hostname stays in the Host header and TLS SNI, so the server
    sees the right site and its certificate is still checked against the real name."""
    network = fake(monkeypatch, FakeNetwork(http_response("200 OK", TOKEN.encode())))

    assert http_token.check(url, TOKEN, network, lambda host, timeout: [address]).verified

    assert network.dialled == [dialled]
    assert f"\r\nHost: {host_header}\r\n".encode() in network.written
    expected_sni = [urlsplit(url).hostname] if url.startswith("https://") else []
    assert network.sni == expected_sni
    assert b"\r\nAccept-Encoding: identity\r\n" in network.written


def test_http_never_decompresses_so_a_gzip_bomb_hits_the_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bomb = gzip.compress(b"\0" * (8 * 1024 * 1024))  # 8 MB of zeros in about 8 KB
    response = http_response("200 OK", bomb, ("Content-Encoding: gzip",))
    network = fake(monkeypatch, FakeNetwork(response))

    outcome = http_token.check(URL, TOKEN, network, public)

    assert not outcome.verified
    assert "more than 1024 bytes" in outcome.reason


def test_http_slow_headers_hit_the_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Header bytes arriving every 2 s (inside the 3 s read timeout) used to stall forever."""
    trickle = [bytes([c]) for c in b"HTTP/1.1 200 OK\r\nX-Slow: " + b"a" * 5000]
    network = fake(monkeypatch, FakeNetwork(trickle, seconds_per_read=2.0))

    outcome = http_token.check(URL, TOKEN, network, public)

    assert not outcome.verified
    assert "took longer than 10s" in outcome.reason
    assert network.clock[0] - 1000.0 <= http_token.DEADLINE_SECONDS + 2.0  # one read at most
    # Every read was offered no more than the time left (and never more than 3 s).
    assert all(t is not None and t <= 3.0 for t in network.read_timeouts)


def test_http_slow_body_hits_the_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    head = b"HTTP/1.1 200 OK\r\nContent-Length: 900\r\n\r\n"
    network = fake(monkeypatch, FakeNetwork([head] + [b"x"] * 900, seconds_per_read=2.0))

    outcome = http_token.check(URL, TOKEN, network, public)

    assert not outcome.verified
    assert "took longer than 10s" in outcome.reason
    assert network.clock[0] - 1000.0 <= http_token.DEADLINE_SECONDS + 2.0


def test_ip_hosts_need_no_dns_lookup() -> None:
    assert http_token.lookup_addresses("203.0.113.7", 1.0) == ["203.0.113.7"]


@pytest.mark.parametrize(
    ("response", "reason"),
    [
        (http_response("200 OK", b"not-the-token"), "doesn't contain the token"),
        (http_response("404 Not Found"), "answered HTTP 404"),
        (http_response("200 OK", b"x" * 2000), "more than 1024 bytes"),
    ],
)
def test_http_wrong_answers_fail(
    monkeypatch: pytest.MonkeyPatch, response: list[bytes], reason: str
) -> None:
    network = fake(monkeypatch, FakeNetwork(response))

    outcome = http_token.check(URL, TOKEN, network, public)

    assert not outcome.verified
    assert reason in outcome.reason


def test_http_redirects_are_not_followed(monkeypatch: pytest.MonkeyPatch) -> None:
    # A redirect could point the server at an internal address after the guard has passed.
    redirect = http_response("302 Found", headers=("Location: http://169.254.169.254/token",))
    network = fake(monkeypatch, FakeNetwork(redirect))

    outcome = http_token.check(URL, TOKEN, network, public)

    assert not outcome.verified
    assert "redirects are not followed" in outcome.reason
    assert network.dialled == [("93.184.216.34", 443)]  # only the one, vetted connection


def test_http_connection_errors_fail_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    class Refusing(FakeNetwork):
        def connect_tcp(self, *args: Any, **kwargs: Any) -> httpcore.NetworkStream:
            raise httpcore.ConnectError("connection refused")

    network = fake(monkeypatch, Refusing([]))

    outcome = http_token.check(URL, TOKEN, network, public)

    assert not outcome.verified
    assert "could not fetch" in outcome.reason


@pytest.mark.parametrize("addresses", [["10.0.0.5"], ["93.184.216.34", "127.0.0.1"], []], ids=str)
def test_http_hosts_resolving_to_private_addresses_are_never_fetched(
    monkeypatch: pytest.MonkeyPatch, addresses: list[str]
) -> None:
    network = fake(monkeypatch, FakeNetwork(http_response("200 OK", TOKEN.encode())))

    outcome = http_token.check(URL, TOKEN, network, lambda host, timeout: addresses)

    assert not outcome.verified
    assert outcome.reason.endswith(http_token.NOT_CHECKABLE)
    assert network.dialled == []  # the guard stopped it before any connection


def test_http_failures_dont_reveal_what_a_host_resolves_to(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Anyone can call the check endpoint, so it must not map internal names or addresses."""

    def unresolvable(host: str, timeout: float) -> list[str]:
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    def timing_out(host: str, timeout: float) -> list[str]:
        raise dns.exception.Timeout

    reasons = {
        http_token.check(URL, TOKEN, FakeNetwork([]), lookup).reason
        for lookup in (
            unresolvable,
            timing_out,
            lambda host, timeout: ["172.18.0.2"],  # a Docker network address
            lambda host, timeout: [],
        )
    }

    assert reasons == {f"{URL} can't be checked: {http_token.NOT_CHECKABLE}"}
    assert "172.18" not in next(iter(reasons))
