import ipaddress

from modules.device_discovery import _require_nmap, _run_nmap
from modules.network_info import is_rfc1918_address
from modules.service_detection import service_name


SCANNED_TCP_PORTS = (
    21,
    22,
    23,
    53,
    80,
    110,
    139,
    143,
    443,
    445,
    554,
    631,
    993,
    995,
    1883,
    3306,
    3389,
    5432,
    5900,
    8080,
    8443,
    9100,
)


def scan_ports(hosts: list[dict]) -> list[dict]:
    if not hosts:
        return hosts
    if len(hosts) > 256:
        raise ValueError("Host list exceeds the 256-address scan limit.")

    addresses = []
    for host in hosts:
        address = ipaddress.ip_address(host["ip"])
        if not isinstance(address, ipaddress.IPv4Address) or not is_rfc1918_address(
            address
        ):
            raise ValueError(f"Refusing to scan non-private address: {address}")
        addresses.append(str(address))

    arguments = [
        _require_nmap(),
        "-sT",
        "-sV",
        "--version-light",
        "-Pn",
        "-n",
        "-p",
        ",".join(str(port) for port in SCANNED_TCP_PORTS),
        "-oX",
        "-",
        *addresses,
    ]
    root = _run_nmap(arguments)
    results = {}
    for scanned_host in root.findall("host"):
        address = next(
            (
                item.get("addr")
                for item in scanned_host.findall("address")
                if item.get("addrtype") == "ipv4"
            ),
            None,
        )
        if address is not None:
            results[address] = scanned_host

    for host in hosts:
        host["open_ports"] = []
        scanned_host = results.get(host["ip"])
        if scanned_host is None:
            continue
        for port in scanned_host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            host["open_ports"].append(
                {
                    "port": int(port.get("portid")),
                    "protocol": port.get("protocol", "tcp"),
                    "service": (
                        service.get("name")
                        if service is not None
                        else service_name(int(port.get("portid")))
                    ),
                    "product": service.get("product") if service is not None else None,
                    "version": service.get("version") if service is not None else None,
                }
            )
    return hosts