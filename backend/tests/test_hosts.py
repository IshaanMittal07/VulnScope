"""Target values must fit their type, and each type maps to the host that verification checks."""

import pytest
from pydantic import ValidationError

from app.models.enums import TargetType
from app.schemas import TargetCreate
from app.verification.hosts import is_hostname, target_host, value_error


@pytest.mark.parametrize(
    ("target_type", "value", "host"),
    [
        (TargetType.URL, "http://juice-shop:3000", "juice-shop"),
        (TargetType.URL, "https://Example.COM/login?next=/", "example.com"),
        (TargetType.URL, "http://[2001:db8::1]:8080/", "2001:db8::1"),
        (TargetType.URL, "http://203.0.113.7", "203.0.113.7"),
        (TargetType.DOMAIN, "Shop.Example.com", "shop.example.com"),
        (TargetType.IP, "203.0.113.7", "203.0.113.7"),
        (TargetType.IP, "2001:DB8::1", "2001:db8::1"),
    ],
)
def test_valid_values_and_their_host(target_type: TargetType, value: str, host: str) -> None:
    assert value_error(target_type, value) is None
    assert target_host(target_type, value) == host


@pytest.mark.parametrize(
    ("target_type", "value"),
    [
        (TargetType.URL, "juice-shop:3000"),  # no scheme
        (TargetType.URL, "ftp://example.com"),
        (TargetType.URL, "https://"),
        (TargetType.URL, "http://admin:hunter2@example.com"),  # credentials
        (TargetType.URL, "http://example.com:99999"),  # bad port
        (TargetType.URL, "http://exa_mple.com"),
        (TargetType.URL, "http://exa\nmple.com"),  # urlsplit would drop the newline
        (TargetType.URL, "http://example.com\t/"),
        (TargetType.URL, "http://example.com/a b"),
        (TargetType.URL, "http://example.com/\x00"),
        (TargetType.DOMAIN, " example.com"),
        (TargetType.IP, "203.0.113.7\r\n"),
        (TargetType.REPO, "https://github.com/acme/app\n"),
        (TargetType.DOMAIN, "https://example.com"),
        (TargetType.DOMAIN, "example.com/path"),
        (TargetType.DOMAIN, "example.com:443"),
        (TargetType.DOMAIN, "203.0.113.7"),  # that's an ip target
        (TargetType.DOMAIN, "-bad-.example.com"),
        (TargetType.DOMAIN, "juice-shop."),  # trailing dot
        (TargetType.IP, "10.0.0.0/8"),  # a range, not one host
        (TargetType.IP, "example.com"),
        (TargetType.IP, "999.1.1.1"),
    ],
)
def test_invalid_values_are_rejected(target_type: TargetType, value: str) -> None:
    assert value_error(target_type, value) is not None
    with pytest.raises(ValidationError):
        TargetCreate.model_validate(
            {"name": "t", "target_type": target_type, "value": value, "data_types": ["general"]}
        )


def test_repo_targets_have_no_host() -> None:
    assert value_error(TargetType.REPO, "https://github.com/acme/app") is None
    assert target_host(TargetType.REPO, "https://github.com/acme/app") is None


def test_ip_addresses_are_not_hostnames() -> None:
    assert is_hostname("juice-shop")
    assert not is_hostname("203.0.113.7")
