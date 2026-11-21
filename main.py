import argparse
from pathlib import Path
import sys

from modules.device_discovery import discover_devices
from modules.network_info import (
    NetworkInfoError,
    get_local_network,
    select_scan_network,
)
from modules.port_scanner import scan_ports
from modules.report_generator import save_report
from modules.security_analysis import analyze_hosts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inventory devices on this computer's private local network."
    )
    parser.add_argument(
        "--confirm-authorized",
        action="store_true",
        help="confirm that you are authorized to scan this local network",
    )
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=Path("reports"),
        help="directory for the JSON report (default: reports)",
    )
    parser.add_argument(
        "--network",
        help="optional IPv4 CIDR contained within the connected private network",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if not args.confirm_authorized:
        print(
            "Refusing to scan without authorization confirmation. "
            "Use --confirm-authorized only for a network you own or are "
            "explicitly authorized to assess.",
            file=sys.stderr,
        )
        return 2

    try:
        network = select_scan_network(get_local_network(), args.network)
        print(f"Discovering devices on {network} ...")
        hosts = discover_devices(network)
        if hosts:
            print(f"Checking the fixed, limited TCP port list on {len(hosts)} device(s) ...")
            hosts = scan_ports(hosts)
        else:
            print("No active devices found.")

        report = analyze_hosts(network, hosts)
        report_path = save_report(report, args.reports_dir)
    except (NetworkInfoError, RuntimeError, OSError, ValueError) as exc:
        print(f"NetScan failed: {exc}", file=sys.stderr)
        return 1

    print(f"Found {len(hosts)} active device(s). Report saved to {report_path}")
    for host in hosts:
        ports = ", ".join(str(port["port"]) for port in host["open_ports"]) or "none"
        print(f"  {host['ip']}  MAC: {host['mac'] or 'unknown'}  Open TCP ports: {ports}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())