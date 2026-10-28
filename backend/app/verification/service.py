"""Ownership challenges: create one for a target, and check it.

Every method produces an OwnershipVerification row holding a random token from `secrets`. It
starts pending, becomes verified once its check passes, and expires 24 hours after creation.
Checking an expired challenge marks it expired; a failed check leaves it pending so the user can
fix their DNS record or file and try again. A verified challenge authorizes one scan (Phase 4,
POST /scans), which marks it used.
"""

import secrets
from datetime import UTC, datetime, timedelta

from app.config import get_settings
from app.models import OwnershipVerification, Target
from app.models.enums import TargetType, VerificationMethod, VerificationStatus
from app.verification import dns_txt, http_token, lab
from app.verification.hosts import is_hostname, target_host
from app.verification.outcome import Outcome

TOKEN_TTL = timedelta(hours=24)

# Which target types each method can prove. A repo has no host to check (until Phase 5).
APPLICABLE: dict[VerificationMethod, frozenset[TargetType]] = {
    VerificationMethod.DNS_TXT: frozenset({TargetType.URL, TargetType.DOMAIN}),
    VerificationMethod.HTTP_TOKEN: frozenset({TargetType.URL, TargetType.DOMAIN, TargetType.IP}),
    VerificationMethod.LAB: frozenset({TargetType.URL, TargetType.DOMAIN}),
}


class NotApplicableError(Exception):
    """This method can't verify this target."""


class LabModeOffError(Exception):
    """Lab verification was requested while LAB_MODE=false."""


def new_token() -> str:
    return secrets.token_urlsafe(32)  # 256 bits of randomness, URL- and DNS-safe


def create_challenge(target: Target, method: VerificationMethod) -> OwnershipVerification:
    host = target_host(target.target_type, target.value)
    if target.target_type not in APPLICABLE[method]:
        raise NotApplicableError(f"{method} can't verify a {target.target_type} target")
    if method is VerificationMethod.DNS_TXT and not is_hostname(host or ""):
        raise NotApplicableError("dns_txt needs a domain name, not an IP address")
    if method is VerificationMethod.LAB:
        if not get_settings().lab_mode:
            raise LabModeOffError(
                "lab mode is off (LAB_MODE=false), so lab verification is disabled"
            )
        result = lab.check(host, lab_mode=True)
        if not result.verified:
            raise NotApplicableError(result.reason)
    return OwnershipVerification(
        target=target,
        method=method,
        token=new_token(),
        status=VerificationStatus.PENDING,
        expires_at=datetime.now(UTC) + TOKEN_TTL,
    )


def instructions(verification: OwnershipVerification, target: Target) -> str:
    token = verification.token
    host = target_host(target.target_type, target.value)
    if verification.method is VerificationMethod.DNS_TXT:
        return (
            f"Create a DNS TXT record named {dns_txt.record_name(host or '')} with the value "
            f"{token}, then call the check endpoint. It can take a few minutes to propagate."
        )
    if verification.method is VerificationMethod.HTTP_TOKEN:
        url = http_token.token_url(target.target_type, target.value)
        return (
            f"Serve a plain-text file at {url} containing only {token}, "
            "then call the check endpoint."
        )
    return f"No token needed: {host} is a lab target. Call the check endpoint to confirm."


def run_check(verification: OwnershipVerification, target: Target) -> Outcome:
    host = target_host(target.target_type, target.value)
    if verification.method is VerificationMethod.DNS_TXT:
        return dns_txt.check(host or "", verification.token)
    if verification.method is VerificationMethod.HTTP_TOKEN:
        url = http_token.token_url(target.target_type, target.value)
        return http_token.check(url, verification.token)
    return lab.check(host, get_settings().lab_mode)


def check_challenge(verification: OwnershipVerification, target: Target) -> Outcome:
    """Run the challenge's check and update its status. Caller commits."""
    now = datetime.now(UTC)
    if verification.used_at is not None:
        return Outcome.fail("this verification was already used for a scan; create a new one")
    if verification.status is VerificationStatus.VERIFIED and now < verification.expires_at:
        return Outcome.ok("already verified")
    if verification.status is VerificationStatus.EXPIRED or now >= verification.expires_at:
        verification.status = VerificationStatus.EXPIRED
        return Outcome.fail("this verification expired; create a new one")
    outcome = run_check(verification, target)
    if outcome.verified:
        verification.status = VerificationStatus.VERIFIED
        verification.verified_at = now
    return outcome
