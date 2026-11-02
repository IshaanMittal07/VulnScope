"""Nmap adapter: port and service discovery, parses XML output into raw findings.

One raw finding per open port, with what service detection (-sV) found. The worker runs as a
normal user, so this is a TCP connect scan (-sT), which needs no root privileges.
"""

from pathlib import Path
from xml.etree.ElementTree import Element

from defusedxml import ElementTree

from app.scanners.base import RawFinding, Scanner, ScanTarget, safe_argument
from app.scanners.registry import register

NMAP_SERVICES = Path("/usr/share/nmap/nmap-services")
TOP_PORTS = 1000


def top_tcp_ports(count: int, services_file: Path = NMAP_SERVICES) -> list[int]:
    """Nmap's own "--top-ports" list: the TCP ports with the highest open-frequency.

    Built here because Nmap treats "-p" plus "--top-ports" as an intersection, while the scan
    needs the top ports *plus* the target's own port (e.g. :3000 or :8443).
    """
    ranked: list[tuple[float, int]] = []
    for line in services_file.read_text().splitlines():
        fields = line.split()
        if len(fields) < 3 or line.startswith("#"):
            continue
        port, _, protocol = fields[1].partition("/")
        if protocol == "tcp":
            ranked.append((float(fields[2]), int(port)))
    ranked.sort(key=lambda entry: (-entry[0], entry[1]))
    return [port for _, port in ranked[:count]]


@register
class Nmap(Scanner):
    name = "nmap"
    timeout_seconds = 900

    def applies_to(self, target: ScanTarget) -> bool:
        return target.host is not None

    def ports(self, target: ScanTarget) -> list[int]:
        ports = set(top_tcp_ports(TOP_PORTS))
        if target.port is not None:
            ports.add(target.port)
        return sorted(ports)

    def command(self, target: ScanTarget, workdir: Path) -> list[str]:
        if target.host is None:  # applies_to() rules this out; never scan without a host
            raise ValueError("nmap needs a host")
        return [
            "nmap",
            "-sT",  # TCP connect scan: no root needed
            "-sV",  # identify the service and version on each open port
            "-Pn",  # don't ping first; many hosts drop pings
            "-n",  # no reverse DNS
            "-T4",
            "-p",
            "T:" + ",".join(str(port) for port in self.ports(target)),
            "-oX",
            str(workdir / "nmap.xml"),
            safe_argument(target.host),
        ]

    def parse(self, target: ScanTarget, workdir: Path) -> list[RawFinding]:
        return parse_xml((workdir / "nmap.xml").read_text(), target.host or "")


def parse_xml(xml: str, fallback_host: str) -> list[RawFinding]:
    root = ElementTree.fromstring(xml)
    findings: list[RawFinding] = []
    for host in root.iter("host"):
        name = _host_name(host) or fallback_host
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            findings.append(_open_port(port, state, name))
    return findings


def _host_name(host: Element) -> str | None:
    hostname = host.find("hostnames/hostname[@type='user']")
    if hostname is not None:
        return hostname.get("name")
    address = host.find("address")
    return address.get("addr") if address is not None else None


def _open_port(port: Element, state: Element, host: str) -> RawFinding:
    number = port.get("portid", "?")
    protocol = port.get("protocol", "tcp")
    service = port.find("service")
    details = {
        key: service.get(key)
        for key in ("name", "product", "version", "extrainfo", "method", "conf")
        if service is not None and service.get(key)
    }
    cpes = [cpe.text for cpe in port.iter("cpe") if cpe.text]
    label = " ".join(filter(None, [details.get("product"), details.get("version")]))
    service_name = details.get("name", "unknown")
    title = f"Open port {number}/{protocol} ({service_name}{', ' + label if label else ''})"
    fingerprint = service.get("servicefp") if service is not None else None
    return RawFinding(
        scanner="nmap",
        title=title,
        severity="info",
        location=f"{host}:{number}",
        description=f"Nmap found {number}/{protocol} open and identified it as {service_name}.",
        evidence=label or None,
        data={
            "port": int(number) if number.isdigit() else number,
            "protocol": protocol,
            "reason": state.get("reason"),
            "service": details,
            "cpe": cpes,
            **({"fingerprint": fingerprint[:2000]} if fingerprint else {}),
        },
    )
