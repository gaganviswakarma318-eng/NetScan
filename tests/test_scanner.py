import ipaddress
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from modules.device_discovery import _host_records, discover_devices
from modules.network_info import NetworkInfoError, select_scan_network
from modules.port_scanner import scan_ports
from modules.report_generator import save_report
from modules.security_analysis import analyze_hosts


class DeviceDiscoveryTests(unittest.TestCase):
    def test_extracts_active_ipv4_hosts_and_optional_mac(self):
        root = ET.fromstring(
            """<nmaprun>
              <host><status state="up"/>
                <address addr="192.168.1.10" addrtype="ipv4"/>
                <address addr="aa:bb:cc:dd:ee:ff" addrtype="mac"/>
                <hostnames><hostname name="printer.local"/></hostnames>
              </host>
              <host><status state="down"/>
                <address addr="192.168.1.11" addrtype="ipv4"/>
              </host>
            </nmaprun>"""
        )
        self.assertEqual(
            _host_records(root),
            [
                {
                    "ip": "192.168.1.10",
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "hostname": "printer.local",
                    "open_ports": [],
                }
            ],
        )

    def test_rejects_large_network_before_invoking_nmap(self):
        with patch("modules.device_discovery._run_nmap") as run:
            with self.assertRaises(ValueError):
                discover_devices(ipaddress.ip_network("10.0.0.0/16"))
        run.assert_not_called()

    def test_rejects_public_network_before_invoking_nmap(self):
        with patch("modules.device_discovery._run_nmap") as run:
            with self.assertRaises(ValueError):
                discover_devices(ipaddress.ip_network("8.8.8.0/24"))
        run.assert_not_called()


class NetworkSelectionTests(unittest.TestCase):
    def test_allows_only_bounded_subnets_of_connected_private_network(self):
        connected = ipaddress.ip_network("172.16.0.0/20")
        self.assertEqual(
            select_scan_network(connected, "172.16.4.0/24"),
            ipaddress.ip_network("172.16.4.0/24"),
        )
        with self.assertRaises(NetworkInfoError):
            select_scan_network(connected, "172.16.0.0/23")
        with self.assertRaises(NetworkInfoError):
            select_scan_network(connected, "172.17.0.0/24")
        with self.assertRaises(NetworkInfoError):
            select_scan_network(connected, "8.8.8.0/24")


class PortScanTests(unittest.TestCase):
    def test_parses_open_ports_and_rejects_non_private_host(self):
        xml = ET.fromstring(
            """<nmaprun><host>
              <address addr="192.168.1.10" addrtype="ipv4"/>
              <ports><port protocol="tcp" portid="23">
                <state state="open"/>
                <service name="telnet" product="test service"/>
              </port><port protocol="tcp" portid="80">
                <state state="closed"/>
              </port></ports>
            </host></nmaprun>"""
        )
        hosts = [{"ip": "192.168.1.10", "mac": None, "open_ports": []}]
        with patch("modules.port_scanner._run_nmap", return_value=xml):
            self.assertEqual(
                scan_ports(hosts)[0]["open_ports"],
                [
                    {
                        "port": 23,
                        "protocol": "tcp",
                        "service": "telnet",
                        "product": "test service",
                        "version": None,
                    }
                ],
            )

        with self.assertRaises(ValueError):
            scan_ports([{"ip": "203.0.113.10", "open_ports": []}])


class SecurityAnalysisTests(unittest.TestCase):
    def test_flags_plaintext_and_remote_administration_ports(self):
        report = analyze_hosts(
            "192.168.1.0/24",
            [
                {
                    "ip": "192.168.1.10",
                    "open_ports": [
                        {"port": 23},
                        {"port": 80},
                        {"port": 3389},
                    ],
                }
            ],
        )
        self.assertEqual(
            [item["port"] for item in report["hosts"][0]["observations"]],
            [23, 3389],
        )
        self.assertIn("not proof of vulnerability", report["disclaimer"])

    def test_saves_json_report(self):
        with TemporaryDirectory() as directory:
            path = save_report({"hosts": []}, Path(directory))
            self.assertEqual(path.suffix, ".json")
            self.assertEqual(path.read_text(encoding="utf-8"), '{\n  "hosts": []\n}\n')


if __name__ == "__main__":
    unittest.main()
