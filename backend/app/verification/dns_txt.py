"""DNS TXT verification: user publishes a random token at _vulnscope.<domain>."""

from collections.abc import Callable

import dns.exception
import dns.resolver

from app.verification.outcome import Outcome

RECORD_PREFIX = "_vulnscope"
TIMEOUT_SECONDS = 5.0

# Looks up a name's TXT records and returns each one's text (its strings joined).
TxtLookup = Callable[[str], list[str]]


def record_name(domain: str) -> str:
    return f"{RECORD_PREFIX}.{domain}"


def lookup_txt(name: str) -> list[str]:
    answer = dns.resolver.resolve(name, "TXT", lifetime=TIMEOUT_SECONDS)
    return [b"".join(rdata.strings).decode("utf-8", "replace") for rdata in answer]


def check(domain: str, token: str, lookup: TxtLookup | None = None) -> Outcome:
    name = record_name(domain)
    try:
        values = (lookup or lookup_txt)(name)
    except dns.resolver.NXDOMAIN:
        return Outcome.fail(f"no DNS record found at {name}")
    except dns.resolver.NoAnswer:
        return Outcome.fail(f"{name} has no TXT record")
    except dns.exception.Timeout:
        return Outcome.fail(f"DNS lookup of {name} timed out")
    except dns.exception.DNSException as exc:
        return Outcome.fail(f"DNS lookup of {name} failed: {type(exc).__name__}")
    if token in values:
        return Outcome.ok(f"TXT record at {name} matches the token")
    return Outcome.fail(f"TXT record(s) at {name} don't match the token")
