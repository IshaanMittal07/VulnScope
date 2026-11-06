"""Nmap adapter: parses real lab output, builds a safe command, and never needs Nmap installed."""

from pathlib import Path

import pytest
from defusedxml import EntitiesForbidden

from app.models.enums import TargetType
from app.scanners import nmap
from app.scanners.base import ScanTarget, UnsafeArgumentError
from app.scanners.nmap import Nmap, parse_xml, top_tcp_ports

FIXTURES = Path(__file__).parent / "fixtures" / "nmap"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


def _host_xml(ports: str, host: str = "") -> str:
    return f"<nmaprun><host>{host}<ports>{ports}</ports></host></nmaprun>"


def _target(host: str | None, port: int | None = None) -> ScanTarget:
    return ScanTarget(TargetType.IP, host or "", host, port, None)


# --- parsing the real lab fixtures -------------------------------------------------------------


def test_juice_shop_reports_its_one_open_port() -> None:
    findings = parse_xml(_fixture("juice-shop.xml"), "fallback")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.scanner == "nmap"
    assert finding.severity == "info"
    assert finding.location == "juice-shop:3000"
    assert finding.data["port"] == 3000
    assert finding.data["protocol"] == "tcp"
    assert finding.data["reason"] == "syn-ack"


def test_juice_shop_keeps_the_fingerprint_when_nmap_cannot_name_the_service() -> None:
    finding = parse_xml(_fixture("juice-shop.xml"), "fallback")[0]

    # Nmap guesses "ppp" from the port table; the fingerprint is the real evidence.
    assert finding.data["service"] == {"name": "ppp", "method": "table", "conf": "3"}
    assert finding.title == "Open port 3000/tcp (ppp)"
    assert finding.evidence is None
    assert finding.data["cpe"] == []
    assert "OWASP\\x20Juice\\x20Shop" in finding.data["fingerprint"]
    assert len(finding.data["fingerprint"]) <= 2000


def test_dvwa_reports_apache_with_version_and_cpe() -> None:
    findings = parse_xml(_fixture("dvwa.xml"), "fallback")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.location == "dvwa:80"
    assert finding.title == "Open port 80/tcp (http, Apache httpd 2.4.68)"
    assert finding.evidence == "Apache httpd 2.4.68"
    assert finding.data["service"] == {
        "name": "http",
        "product": "Apache httpd",
        "version": "2.4.68",
        "extrainfo": "(Debian)",
        "method": "probed",
        "conf": "10",
    }
    assert finding.data["cpe"] == ["cpe:/a:apache:http_server:2.4.68"]
    assert "fingerprint" not in finding.data


# --- parsing edge cases ------------------------------------------------------------------------


def test_only_open_ports_become_findings() -> None:
    xml = _host_xml(
        '<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/></port>'
        '<port protocol="tcp" portid="23"><state state="closed" reason="conn-refused"/></port>'
        '<port protocol="tcp" portid="25"><state state="filtered" reason="no-response"/></port>'
        '<port protocol="tcp" portid="26"></port>',
        '<address addr="10.0.0.5" addrtype="ipv4"/>',
    )

    findings = parse_xml(xml, "fallback")

    assert [f.location for f in findings] == ["10.0.0.5:22"]
    assert findings[0].data["service"] == {}
    assert findings[0].title == "Open port 22/tcp (unknown)"


def test_host_name_falls_back_to_address_then_to_the_target() -> None:
    open_port = '<port protocol="tcp" portid="80"><state state="open"/></port>'
    with_address = _host_xml(open_port, '<address addr="10.0.0.5" addrtype="ipv4"/>')
    bare = _host_xml(open_port)

    assert parse_xml(with_address, "fallback")[0].location == "10.0.0.5:80"
    assert parse_xml(bare, "fallback")[0].location == "fallback:80"


def test_no_hosts_means_no_findings() -> None:
    assert parse_xml("<nmaprun></nmaprun>", "fallback") == []


def test_xml_entity_attacks_are_refused() -> None:
    # Banners in the XML come from the target, so the parser must not expand entities.
    bomb = (
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaaaaaaaa">'
        '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><nmaprun>&b;</nmaprun>'
    )

    with pytest.raises(EntitiesForbidden):
        parse_xml(bomb, "fallback")


def test_parse_reads_the_xml_file_from_the_workdir(tmp_path: Path) -> None:
    (tmp_path / "nmap.xml").write_text(_fixture("dvwa.xml"))

    findings = Nmap().parse(_target("dvwa", 80), tmp_path)

    assert [f.location for f in findings] == ["dvwa:80"]


# --- port list ---------------------------------------------------------------------------------


def test_top_tcp_ports_ranks_by_frequency_and_ignores_udp_and_comments(tmp_path: Path) -> None:
    services = tmp_path / "nmap-services"
    services.write_text(
        "# Nmap services file\n"
        "http\t80/tcp\t0.484143\t# World Wide Web\n"
        "domain\t53/udp\t0.213496\n"
        "ssh\t22/tcp\t0.182286\n"
        "telnet\t23/tcp\t0.221265\n"
        "https\t443/tcp\t0.208669\n"
        "short-line\n"
        "tie\t21/tcp\t0.182286\n"
    )

    assert top_tcp_ports(10, services) == [80, 23, 443, 21, 22]
    assert top_tcp_ports(2, services) == [80, 23]


# --- command -----------------------------------------------------------------------------------


@pytest.fixture
def fake_top_ports(monkeypatch: pytest.MonkeyPatch) -> None:
    # The real nmap-services file only exists in the worker image.
    monkeypatch.setattr(nmap, "top_tcp_ports", lambda count: [22, 80, 443])


@pytest.mark.usefixtures("fake_top_ports")
def test_command_is_an_argument_list_with_the_targets_port_added(tmp_path: Path) -> None:
    argv = Nmap().command(_target("juice-shop", 3000), tmp_path)

    assert argv == [
        "nmap",
        "-sT",
        "-sV",
        "-Pn",
        "-n",
        "-T4",
        "-p",
        "T:22,80,443,3000",
        "-oX",
        str(tmp_path / "nmap.xml"),
        "juice-shop",
    ]


@pytest.mark.usefixtures("fake_top_ports")
def test_ports_are_not_duplicated_when_the_target_port_is_already_a_top_port() -> None:
    assert Nmap().ports(_target("dvwa", 80)) == [22, 80, 443]
    assert Nmap().ports(_target("10.0.0.5")) == [22, 80, 443]


@pytest.mark.usefixtures("fake_top_ports")
def test_command_refuses_a_host_nmap_would_read_as_an_option(tmp_path: Path) -> None:
    with pytest.raises(UnsafeArgumentError):
        Nmap().command(_target("-oN/etc/passwd"), tmp_path)


def test_command_refuses_to_run_without_a_host(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="needs a host"):
        Nmap().command(_target(None), tmp_path)


def test_applies_only_to_targets_with_a_host() -> None:
    assert Nmap().applies_to(_target("juice-shop", 3000))
    assert not Nmap().applies_to(ScanTarget(TargetType.REPO, "https://x/y.git", None, None, None))
