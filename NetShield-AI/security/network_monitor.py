import ipaddress
import socket

try:
    from scapy.all import ARP, Ether, srp
    from scapy.error import Scapy_Exception
except ImportError:
    ARP = Ether = srp = None
    Scapy_Exception = OSError


DISCLAIMER = (
    "Network discovery is limited to the current private IPv4 /24 network and "
    "requires authorization. A device not shown is not proof that it is absent."
)


def _local_network():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("192.0.2.1", 1))
            local_ip = sock.getsockname()[0]
    except OSError as exc:
        raise RuntimeError(f"Could not identify the active network interface: {exc}") from exc
    address = ipaddress.ip_address(local_ip)
    if (
        not isinstance(address, ipaddress.IPv4Address)
        or not address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_multicast
    ):
        raise RuntimeError("Could not identify a private IPv4 network interface.")
    return str(ipaddress.ip_network(f"{local_ip}/24", strict=False))


def _get_hostname(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except (OSError, socket.herror):
        return "Unavailable"


def _demo_devices():
    return [
        {"ip": "192.168.1.1", "mac": "02:00:00:00:00:01", "hostname": "Demo gateway"},
        {"ip": "192.168.1.10", "mac": "02:00:00:00:00:10", "hostname": "Demo laptop"},
        {"ip": "192.168.1.24", "mac": "02:00:00:00:00:24", "hostname": "Demo unknown device"},
    ]


def scan_network(mode="demo", authorized=False):
    if mode not in {"demo", "live"}:
        raise ValueError("Network mode must be 'demo' or 'live'.")
    if mode == "live" and not authorized:
        raise PermissionError("Confirm that you own or are authorized to scan this network.")

    if mode == "demo":
        network = "DEMO DATA ONLY"
        devices = _demo_devices()
    else:
        network = _local_network()
        if ARP is None or Ether is None or srp is None:
            raise RuntimeError("Live network discovery requires Scapy. Install dependencies and retry.")
        try:
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
            answered = srp(packet, timeout=2, verbose=False)[0]
        except (OSError, Scapy_Exception) as exc:
            raise RuntimeError(f"Live network discovery failed: {exc}") from exc
        devices = [
            {
                "ip": response.psrc,
                "mac": response.hwsrc,
                "hostname": _get_hostname(response.psrc),
            }
            for _, response in answered
        ]

    return {
        "mode": mode,
        "network": network,
        "total_devices": len(devices),
        "devices": [
            {
                **device,
                "classification": "DEMO" if mode == "demo" else "UNVERIFIED",
                "status": "DEMO" if mode == "demo" else "UNVERIFIED",
            }
            for device in devices
        ],
        "disclaimer": DISCLAIMER,
    }
