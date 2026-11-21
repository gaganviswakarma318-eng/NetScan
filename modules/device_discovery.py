import ipaddress
import shutil
import subprocess
import xml.etree.ElementTree as ET

from modules.network_info import is_rfc1918_network


def _require_nmap() -> str:
    executable = shutil.which("nmap")
    if executable is None:
        raise RuntimeError("Nmap is required. Install it with: sudo apt install nmap")
    return executable


def _run_nmap(arguments: list[str]) -> ET.Element:
    try:
        result = subprocess.run(
            arguments,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Nmap timed out while scanning the local network.") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or f"exit status {result.returncode}"
        raise RuntimeError(f"Nmap failed: {detail}")
    try:
        return ET.fromstring(result.stdout)
    except ET.ParseError as exc:
        raise RuntimeError("Nmap returned an invalid XML response.") from exc


def _host_records(root: ET.Element) -> list[dict]:
    hosts = []
    for item in root.findall("host"):
        status = item.find("status")
        address = next(
            (
                address.get("addr")
                for address in item.findall("address")
                if address.get("addrtype") == "ipv4"
            ),
            None,
        )
        if status is None or status.get("state") != "up" or address is None:
            continue
        mac_element = next(
            (
                address
                for address in item.findall("address")
                if address.get("addrtype") == "mac"
            ),
            None,
        )
        hostname_element = item.find("./hostnames/hostname")
        hosts.append(
            {
                "ip": address,
                "mac": mac_element.get("addr") if mac_element is not None else None,
                "hostname": (
                    hostname_element.get("name")
                    if hostname_element is not None
                    else None
                ),
                "open_ports": [],
            }
        )
    return hosts


def discover_devices(network: ipaddress.IPv4Network) -> list[dict]:
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("Only IPv4 networks are supported.")
    if not is_rfc1918_network(network):
        raise ValueError("Only RFC 1918 private IPv4 networks can be scanned.")
    if network.num_addresses > 256:
        raise ValueError("Network exceeds the 256-address scan limit.")
    root = _run_nmap(
        [_require_nmap(), "-sn", "-n", "-oX", "-", str(network)]
    )
    return _host_records(root)