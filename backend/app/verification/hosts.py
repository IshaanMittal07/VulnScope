"""The host a target points at, and whether a target's value fits its type.

Verification proves control of a *host*, so every method starts here.
"""

import ipaddress
import re
from urllib.parse import urlsplit

from app.models.enums import TargetType

# RFC 1123 hostname, lowercase: dot-separated labels of letters, digits and inner hyphens.
_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_HOSTNAME = re.compile(rf"(?=.{{1,253}}$){_LABEL}(\.{_LABEL})*")


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def is_hostname(value: str) -> bool:
    """A DNS name (not an IP address). Case-insensitive; no trailing dot, port, or path."""
    return not is_ip(value) and _HOSTNAME.fullmatch(value.lower()) is not None


def value_error(target_type: TargetType, value: str) -> str | None:
    """Why `value` isn't a valid target of this type, or None if it is."""
    if target_type is TargetType.URL:
        try:
            parts = urlsplit(value)
            parts.port  # noqa: B018 (raises ValueError for a bad port)
        except ValueError:
            return "url must be a valid http(s) URL"
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return "url must be an http(s) URL with a host, e.g. https://example.com"
        if parts.username is not None or parts.password is not None:
            return "url must not contain credentials"
        if not (is_hostname(parts.hostname) or is_ip(parts.hostname)):
            return "url has an invalid host"
    elif target_type is TargetType.DOMAIN:
        if not is_hostname(value):
            return "domain must be a hostname such as example.com (no scheme, port, or path)"
    elif target_type is TargetType.IP:
        if not is_ip(value):
            return "ip must be a single IPv4 or IPv6 address, not a range"
    return None


def target_host(target_type: TargetType, value: str) -> str | None:
    """The lowercase host a valid target points at; None for types with no host (repo)."""
    if target_type is TargetType.URL:
        return urlsplit(value).hostname  # already lowercase, IPv6 brackets removed
    if target_type is TargetType.DOMAIN:
        return value.lower()
    if target_type is TargetType.IP:
        return str(ipaddress.ip_address(value))
    return None
