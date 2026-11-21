# NetScan

NetScan is an educational network-inventory CLI for authorized checks of the
private IPv4 network used by the local machine. It discovers active hosts,
checks a fixed set of common TCP ports, records Nmap's basic service labels,
and writes a JSON report.

## Safety and scope

- Use NetScan only on networks you own or are explicitly authorized to assess.
- It selects the local machine's routed IPv4 network automatically; it does not
  accept arbitrary targets or public networks.
- The detected network must be RFC 1918 private space and contain no more than
  256 addresses. Larger networks are rejected.
- If the connected network is larger than 256 addresses, `--network CIDR` can
  select a smaller range, but only when it is wholly contained within the
  connected private network.
- Discovery is limited to Nmap host discovery. The follow-up is a TCP connect
  scan of 22 fixed common ports, with light service identification. It does
  not run vulnerability scripts or exploit checks.
- MAC addresses are reported only when Nmap can observe them on the local link.
- A missing MAC address or a host not found does not mean the device is absent.
- Open ports are observations, not confirmation of a vulnerability.

## Requirements

- Python 3.10 or later
- Nmap

On Ubuntu, install Nmap with `sudo apt install nmap`. No Python packages are
required.

## Run

From the project directory:

```bash
python3 main.py --confirm-authorized
```

Reports are written to `reports/` by default. Choose a different destination
with `--reports-dir PATH`. If needed, choose a local subnetwork with
`--network 192.168.1.0/24`; the range must be inside the connected interface
network and contain at most 256 addresses. The authorization flag is required
for every scan.

## Tests

Run the offline unit tests with:

```bash
python3 -m unittest discover -s tests -v
```
