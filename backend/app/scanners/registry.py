"""Maps service types (web, host, repo/container) to the scanners that apply to them.

Each adapter registers itself with @register and decides in applies_to() which targets it can
scan (for example Nmap needs a host, testssl.sh a web address, Trivy an image or repository).
"""

from app.scanners.base import Scanner, ScanTarget

_SCANNERS: dict[str, type[Scanner]] = {}


def register[S: type[Scanner]](scanner: S) -> S:
    """Class decorator: make an adapter available to the pipeline, in registration order."""
    if scanner.name in _SCANNERS:
        raise ValueError(f"scanner {scanner.name!r} is already registered")
    _SCANNERS[scanner.name] = scanner
    return scanner


def all_scanners() -> list[Scanner]:
    return [scanner() for scanner in _SCANNERS.values()]


def scanners_for(target: ScanTarget) -> list[Scanner]:
    return [scanner for scanner in all_scanners() if scanner.applies_to(target)]


# Time the scanning stage needs beyond the scanners themselves (database work, starting tools).
STAGE_OVERHEAD_SECONDS = 300


def stage_timeout_seconds() -> int:
    """The scanning stage runs every scanner one after another, so its RQ job must be allowed
    their timeouts added together, plus some overhead."""
    return sum(scanner.timeout_seconds for scanner in _SCANNERS.values()) + STAGE_OVERHEAD_SECONDS
