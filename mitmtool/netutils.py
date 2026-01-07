import ipaddress
import re
import subprocess
from typing import Dict, List, Optional, Tuple

from scapy.all import ARP, Ether, srp, conf


def _run_ipconfig() -> str:
    """
    Run 'ipconfig' and return output text (Windows).
    """
    return subprocess.check_output(
        ["ipconfig"],
        text=True,
        encoding="utf-8",
        errors="ignore"
    )


def get_active_ipv4_mask_gateway_windows() -> Tuple[str, str, str]:
    """
    Find the active Windows adapter by choosing the adapter block
    that has a Default Gateway AND an IPv4 Address.
    Returns: (ipv4, subnet_mask, gateway)

    Raises ValueError if parsing fails.
    """
    text = _run_ipconfig()

    # Split output into blocks separated by blank lines
    blocks = re.split(r"\r?\n\r?\n", text)

    ipv4_re = re.compile(r"IPv4 Address[^\:]*:\s*([0-9\.]+)")
    mask_re = re.compile(r"Subnet Mask[^\:]*:\s*([0-9\.]+)")
    gw_re = re.compile(r"Default Gateway[^\:]*:\s*([0-9\.]+)")

    for block in blocks:
        gw_match = gw_re.search(block)
        if not gw_match:
            continue

        ipv4_match = ipv4_re.search(block)
        mask_match = mask_re.search(block)
        if ipv4_match and mask_match:
            ipv4 = ipv4_match.group(1).strip()
            mask = mask_match.group(1).strip()
            gateway = gw_match.group(1).strip()
            return ipv4, mask, gateway

    raise ValueError("Could not detect active IPv4 adapter with Default Gateway (ipconfig parsing failed).")


def compute_network_cidr(ipv4: str, mask: str) -> str:
    """
    Example:
      ipv4='192.168.178.155', mask='255.255.255.0' -> '192.168.178.0/24'
    """
    net = ipaddress.IPv4Network((ipv4, mask), strict=False)
    return str(net)


def autodetect_network_windows() -> Tuple[str, str, str]:
    """
    Returns:
      (network_cidr, ipv4, gateway)

    Example:
      ('192.168.178.0/24', '192.168.178.155', '192.168.178.1')
    """
    ipv4, mask, gateway = get_active_ipv4_mask_gateway_windows()
    network = compute_network_cidr(ipv4, mask)
    return network, ipv4, gateway


def scan_network(network_cidr: str, iface: Optional[str] = None, timeout: int = 4) -> List[Dict[str, str]]:
    """
    ARP scan a CIDR and return list of devices:
      [{'ip': '...', 'mac': '...'}, ...]
    """
    if iface is None:
        iface = conf.iface  # scapy's default interface

    arp = ARP(pdst=network_cidr)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    pkt = ether / arp

    ans, _ = srp(pkt, timeout=timeout, iface=iface, verbose=0)

    devices: List[Dict[str, str]] = []
    for _, rcv in ans:
        devices.append({"ip": rcv.psrc, "mac": rcv.hwsrc})
    return devices
