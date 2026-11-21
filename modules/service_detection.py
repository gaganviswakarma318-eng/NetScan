import socket


def service_name(port: int, protocol: str = "tcp") -> str | None:
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return None