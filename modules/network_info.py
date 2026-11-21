import fcntl
import ipaddress
import socket
import struct


_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_MAX_NETWORK_ADDRESSES = 256


class NetworkInfoError(RuntimeError):
    pass


def is_rfc1918_address(address: ipaddress.IPv4Address) -> bool:
    return any(address in network for network in _PRIVATE_NETWORKS)


def is_rfc1918_network(network: ipaddress.IPv4Network) -> bool:
    return any(network.subnet_of(private) for private in _PRIVATE_NETWORKS)


def select_scan_network(
    interface_network: ipaddress.IPv4Network, requested_network: str | None = None
) -> ipaddress.IPv4Network:
    if requested_network is None:
        network = interface_network
    else:
        try:
            network = ipaddress.ip_network(requested_network, strict=False)
        except ValueError as exc:
            raise NetworkInfoError(f"Invalid network CIDR: {requested_network}") from exc
        if not isinstance(network, ipaddress.IPv4Network):
            raise NetworkInfoError("Only IPv4 networks are supported.")
        if not network.subnet_of(interface_network):
            raise NetworkInfoError(
                f"Selected network {network} is outside the connected network "
                f"{interface_network}."
            )

    if not is_rfc1918_network(network):
        raise NetworkInfoError("Only RFC 1918 private IPv4 networks can be scanned.")
    if network.num_addresses > _MAX_NETWORK_ADDRESSES:
        raise NetworkInfoError(
            f"Selected network {network} exceeds the 256-address scan limit."
        )
    return network


def _interface_ipv4(sock: socket.socket, name: str, request: int) -> str:
    request_data = struct.pack("256s", name.encode("ascii")[:15])
    response = fcntl.ioctl(sock.fileno(), request, request_data)
    return socket.inet_ntoa(response[20:24])


def get_local_network() -> ipaddress.IPv4Network:
    if not hasattr(fcntl, "ioctl"):
        raise NetworkInfoError("Automatic interface detection requires Linux.")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route_socket:
            route_socket.connect(("192.0.2.1", 80))
            local_ip = ipaddress.IPv4Address(route_socket.getsockname()[0])

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as interface_socket:
            for _, name in socket.if_nameindex():
                try:
                    address = _interface_ipv4(interface_socket, name, 0x8915)
                    if ipaddress.IPv4Address(address) == local_ip:
                        netmask = _interface_ipv4(interface_socket, name, 0x891B)
                        network = ipaddress.ip_network(
                            f"{local_ip}/{netmask}", strict=False
                        )
                        break
                except OSError:
                    continue
            else:
                raise NetworkInfoError(
                    f"Could not find the network interface for local address {local_ip}."
                )
    except OSError as exc:
        raise NetworkInfoError(f"Could not determine the local IPv4 network: {exc}") from exc

    if not is_rfc1918_network(network):
        raise NetworkInfoError(
            f"Detected network {network} is not an RFC 1918 private IPv4 network."
        )
    return network