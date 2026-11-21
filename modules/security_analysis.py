from datetime import datetime, timezone


_PORT_GUIDANCE = {
    21: (
        "FTP is exposed; prefer encrypted file transfer and disable it if unused."
    ),
    23: ("Telnet is unencrypted; disable it and use SSH for remote administration."),
    445: ("SMB is exposed; restrict access to trusted devices and keep it updated."),
    3389: ("Remote Desktop is exposed; restrict access and require strong authentication."),
    5900: ("VNC is exposed; restrict access and require strong authentication."),
}


def analyze_hosts(network, hosts: list[dict]) -> dict:
    assessed_hosts = []
    for host in hosts:
        observations = [
            {
                "severity": "medium",
                "port": port["port"],
                "message": _PORT_GUIDANCE[port["port"]],
            }
            for port in host.get("open_ports", [])
            if port["port"] in _PORT_GUIDANCE
        ]
        assessed_hosts.append(
            {
                **host,
                "observations": observations,
            }
        )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "network": str(network),
        "scope": "authorized private local IPv4 network",
        "hosts": assessed_hosts,
        "disclaimer": (
            "Open ports are observations, not proof of vulnerability. "
            "Only assess systems you own or are explicitly authorized to scan."
        ),
    }