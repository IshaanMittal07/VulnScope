"""Lab verification: allows only the local Juice Shop / DVWA hostnames when LAB_MODE=true."""

from app.verification.outcome import Outcome

# The service names in docker-compose.lab.yml. Matched exactly: "juice-shop.evil.com" or
# "my-juice-shop" are not lab targets.
LAB_HOSTS = frozenset({"juice-shop", "dvwa"})


def check(host: str | None, lab_mode: bool) -> Outcome:
    if not lab_mode:
        return Outcome.fail("lab mode is off (LAB_MODE=false), so lab verification is disabled")
    if host not in LAB_HOSTS:
        return Outcome.fail(f"{host} is not a lab target; only {', '.join(sorted(LAB_HOSTS))} are")
    return Outcome.ok(f"{host} is a lab target and lab mode is on")
