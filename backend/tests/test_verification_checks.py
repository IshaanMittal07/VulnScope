"""The three ownership checks, with DNS and HTTP replaced by fakes: no network needed."""

import socket

import dns.exception
import dns.resolver
import httpx
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

URL = "https://example.com/.well-known/vulnscope-verify.txt"


def public(host: str, port: int) -> list[str]:
    return ["93.184.216.34"]


def fetch_with(handler: httpx.MockTransport) -> tuple[httpx.Client, list[httpx.Request]]:
    sent: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return handler.handle_request(request)

    return httpx.Client(transport=httpx.MockTransport(recording)), sent


def test_http_serving_the_token_passes() -> None:
    client, sent = fetch_with(httpx.MockTransport(lambda r: httpx.Response(200, text=f"{TOKEN}\n")))

    assert http_token.check(URL, TOKEN, client, public).verified
    assert [str(r.url) for r in sent] == [URL]


@pytest.mark.parametrize(
    ("response", "reason"),
    [
        (httpx.Response(200, text="not-the-token"), "doesn't contain the token"),
        (httpx.Response(404), "answered HTTP 404"),
        (httpx.Response(200, text="x" * 2000), "more than 1024 bytes"),
    ],
)
def test_http_wrong_answers_fail(response: httpx.Response, reason: str) -> None:
    client, _ = fetch_with(httpx.MockTransport(lambda r: response))

    outcome = http_token.check(URL, TOKEN, client, public)

    assert not outcome.verified
    assert reason in outcome.reason


def test_http_redirects_are_not_followed() -> None:
    # A redirect could point the server at an internal address after the guard has passed.
    redirect = httpx.Response(302, headers={"Location": "http://169.254.169.254/token"})
    client, sent = fetch_with(httpx.MockTransport(lambda r: redirect))

    outcome = http_token.check(URL, TOKEN, client, public)

    assert not outcome.verified
    assert "redirects are not followed" in outcome.reason
    assert len(sent) == 1


def test_http_connection_errors_fail_cleanly() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client, _ = fetch_with(httpx.MockTransport(refuse))

    outcome = http_token.check(URL, TOKEN, client, public)

    assert not outcome.verified
    assert "could not fetch" in outcome.reason


@pytest.mark.parametrize("addresses", [["10.0.0.5"], ["93.184.216.34", "127.0.0.1"], []], ids=str)
def test_http_hosts_resolving_to_private_addresses_are_never_fetched(
    addresses: list[str],
) -> None:
    client, sent = fetch_with(httpx.MockTransport(lambda r: httpx.Response(200, text=TOKEN)))

    outcome = http_token.check(URL, TOKEN, client, lambda host, port: addresses)

    assert not outcome.verified
    assert "non-public address" in outcome.reason
    assert sent == []  # the guard stopped it before any request


def test_http_unresolvable_host_fails_cleanly() -> None:
    def lookup(host: str, port: int) -> list[str]:
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    client, sent = fetch_with(httpx.MockTransport(lambda r: httpx.Response(200, text=TOKEN)))

    outcome = http_token.check(URL, TOKEN, client, lookup)

    assert not outcome.verified
    assert "does not resolve" in outcome.reason
    assert sent == []
