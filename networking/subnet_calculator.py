#!/usr/bin/env python3
"""
Subnet Calculator & Network Toolkit
=====================================
A command-line tool for network analysis and subnetting.

Features:
  - Subnet calculation (network, broadcast, host range, mask)
  - CIDR to subnet mask conversion and vice versa
  - Subnet splitting (VLSM)
  - IP class identification
  - Private/public IP detection
  - Supernetting
  - Batch subnet analysis from file

Author : Matthew Vaishnav — CST, Conestoga College
Usage  : python subnet_calculator.py --ip 192.168.1.0/24
         python subnet_calculator.py --ip 10.0.0.0 --mask 255.255.0.0
         python subnet_calculator.py --split 192.168.1.0/24 --subnets 4
         python subnet_calculator.py --demo
"""

import ipaddress
import argparse
from typing import List


# ── Colors ────────────────────────────────────────────────────────────────────

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
NC = "\033[0m"


# ── Core Functions ────────────────────────────────────────────────────────────


def analyze_network(cidr: str) -> dict:
    """Full analysis of a network in CIDR notation."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        ip = ipaddress.ip_address(cidr.split("/")[0])
    except ValueError as e:
        return {"error": str(e)}

    hosts = list(net.hosts())
    total_hosts = net.num_addresses
    usable_hosts = len(hosts)

    return {
        "input_ip": str(ip),
        "network_address": str(net.network_address),
        "broadcast_address": str(net.broadcast_address),
        "subnet_mask": str(net.netmask),
        "wildcard_mask": str(net.hostmask),
        "cidr_prefix": net.prefixlen,
        "total_addresses": total_hosts,
        "usable_hosts": usable_hosts,
        "first_host": str(hosts[0]) if hosts else "N/A",
        "last_host": str(hosts[-1]) if hosts else "N/A",
        "ip_version": net.version,
        "is_private": ip.is_private,
        "is_multicast": ip.is_multicast,
        "is_loopback": ip.is_loopback,
        "ip_class": get_ip_class(str(ip)),
        "binary_mask": format_binary_mask(str(net.netmask)),
        "hex_network": hex(int(net.network_address)),
    }


def get_ip_class(ip: str) -> str:
    """Identify IP class (A/B/C/D/E)."""
    first_octet = int(ip.split(".")[0])
    if 1 <= first_octet <= 126:
        return "Class A (Large networks — 16M hosts)"
    elif first_octet == 127:
        return "Loopback (127.0.0.0/8)"
    elif 128 <= first_octet <= 191:
        return "Class B (Medium networks — 65K hosts)"
    elif 192 <= first_octet <= 223:
        return "Class C (Small networks — 254 hosts)"
    elif 224 <= first_octet <= 239:
        return "Class D (Multicast)"
    elif 240 <= first_octet <= 255:
        return "Class E (Reserved/Experimental)"
    return "Unknown"


def format_binary_mask(mask: str) -> str:
    """Convert subnet mask to binary representation."""
    octets = mask.split(".")
    binary = ".".join(format(int(o), "08b") for o in octets)
    return binary


def split_network(cidr: str, num_subnets: int) -> List[dict]:
    """Split a network into equal subnets (VLSM)."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        return [{"error": str(e)}]

    # Calculate bits needed
    import math

    bits_needed = math.ceil(math.log2(num_subnets))
    new_prefix = net.prefixlen + bits_needed

    if new_prefix > 30:
        return [{"error": f"Cannot split /{net.prefixlen} into {num_subnets} subnets — prefix too long"}]

    subnets = list(net.subnets(new_prefix=new_prefix))[:num_subnets]
    result = []

    for i, subnet in enumerate(subnets):
        hosts = list(subnet.hosts())
        result.append(
            {
                "subnet_number": i + 1,
                "network": str(subnet),
                "mask": str(subnet.netmask),
                "first_host": str(hosts[0]) if hosts else "N/A",
                "last_host": str(hosts[-1]) if hosts else "N/A",
                "broadcast": str(subnet.broadcast_address),
                "usable_hosts": len(hosts),
            }
        )

    return result


def mask_to_cidr(mask: str) -> int:
    """Convert dotted subnet mask to CIDR prefix length."""
    return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen


def cidr_to_mask(prefix: int) -> str:
    """Convert CIDR prefix to dotted subnet mask."""
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)


def check_ip_in_range(ip: str, cidr: str) -> bool:
    """Check if an IP address belongs to a network."""
    return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)


# ── Display Functions ─────────────────────────────────────────────────────────


def print_analysis(data: dict):
    """Pretty print network analysis."""
    if "error" in data:
        print(f"\n  {RED}❌ Error: {data['error']}{NC}\n")
        return

    print(f"\n  {BOLD}{CYAN}{'═'*55}{NC}")
    print(f"  {BOLD}{CYAN}  Network Analysis — {data['input_ip']}/{data['cidr_prefix']}{NC}")
    print(f"  {BOLD}{CYAN}{'═'*55}{NC}\n")

    fields = [
        ("Network Address",   data["network_address"],   GREEN),
        ("Broadcast Address", data["broadcast_address"],  YELLOW),
        ("Subnet Mask",       data["subnet_mask"],        NC),
        ("Wildcard Mask",     data["wildcard_mask"],      NC),
        ("CIDR Prefix",       f"/{data['cidr_prefix']}",  NC),
        ("Binary Mask",       data["binary_mask"],         NC),
        ("First Host",        data["first_host"],          GREEN),
        ("Last Host",         data["last_host"],           GREEN),
        ("Usable Hosts",      f"{data['usable_hosts']:,}", CYAN),
        ("Total Addresses",   f"{data['total_addresses']:,}", NC),
        ("IP Class",          data["ip_class"],            NC),
        ("Private Range",     "Yes ✅" if data["is_private"] else "No (Public) 🌐", NC),
        ("Multicast",         "Yes" if data["is_multicast"] else "No",              NC),
        ("Loopback",          "Yes" if data["is_loopback"] else "No",               NC),
        ("Hex Network",       data["hex_network"],         NC),
    ]

    for label, value, color in fields:
        print(f"  {BOLD}{label:<20}{NC} {color}{value}{NC}")

    print(f"\n  {BOLD}{CYAN}{'═'*55}{NC}\n")


def print_subnets(subnets: List[dict], original: str):
    """Pretty print subnet split results."""
    if subnets and "error" in subnets[0]:
        print(f"\n  {RED}❌ {subnets[0]['error']}{NC}\n")
        return

    print(f"\n  {BOLD}{CYAN}{'═'*70}{NC}")
    print(f"  {BOLD}{CYAN}  Subnet Split — {original} → {len(subnets)} subnets{NC}")
    print(f"  {BOLD}{CYAN}{'═'*70}{NC}")
    print(f"\n  {'#':<4} {'Network':<20} {'Mask':<16} {'First Host':<16} {'Last Host':<16} {'Hosts'}")
    print(f"  {'─'*70}")

    for s in subnets:
        if "error" in s:
            continue
        print(
            f"  {s['subnet_number']:<4} "
            f"{GREEN}{s['network']:<20}{NC} "
            f"{s['mask']:<16} "
            f"{s['first_host']:<16} "
            f"{s['last_host']:<16} "
            f"{CYAN}{s['usable_hosts']:,}{NC}"
        )

    print(f"\n  {BOLD}{CYAN}{'═'*70}{NC}\n")


# ── Demo ──────────────────────────────────────────────────────────────────────


def run_demo():
    print(f"\n  {BOLD}{CYAN}🌐 Subnet Calculator — Demo Mode{NC}")
    print(f"  {BOLD}Matthew Vaishnav | CST, Conestoga College{NC}\n")

    # Demo networks
    demo_networks = [
        "192.168.1.0/24",
        "10.0.0.0/8",
        "172.16.50.128/26",
    ]

    for net in demo_networks:
        data = analyze_network(net)
        print_analysis(data)

    # Demo subnet split
    print(f"\n  {BOLD}Splitting 192.168.1.0/24 into 4 subnets:{NC}")
    subnets = split_network("192.168.1.0/24", 4)
    print_subnets(subnets, "192.168.1.0/24")

    # Demo mask conversions
    print(f"  {BOLD}Mask Conversions:{NC}")
    print(f"  255.255.255.0  → /{mask_to_cidr('255.255.255.0')}")
    print(f"  255.255.0.0    → /{mask_to_cidr('255.255.0.0')}")
    print(f"  /24            → {cidr_to_mask(24)}")
    print(f"  /22            → {cidr_to_mask(22)}")

    # Demo IP range check
    print(f"\n  {BOLD}IP Range Check:{NC}")
    tests = [
        ("192.168.1.50", "192.168.1.0/24"),
        ("10.0.0.1", "192.168.1.0/24"),
        ("172.16.0.5", "172.16.0.0/12"),
    ]
    for ip, net in tests:
        result = check_ip_in_range(ip, net)
        icon = "✅" if result else "❌"
        print(f"  {icon} {ip} in {net}: {result}")
    print()


# ── Main ──────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Subnet Calculator & Network Toolkit — Matthew Vaishnav"
    )
    parser.add_argument("--ip", help="IP address or CIDR (e.g. 192.168.1.0/24)")
    parser.add_argument("--mask", help="Subnet mask (e.g. 255.255.255.0)")
    parser.add_argument("--split", help="Network to split (CIDR)")
    parser.add_argument("--subnets", type=int, help="Number of subnets to split into")
    parser.add_argument("--check", nargs=2, metavar=("IP", "CIDR"), help="Check if IP is in network")
    parser.add_argument("--convert-mask", help="Convert dotted mask to CIDR (e.g. 255.255.255.0)")
    parser.add_argument("--convert-cidr", type=int, help="Convert CIDR prefix to dotted mask (e.g. 24)")
    parser.add_argument("--demo", action="store_true", help="Run demo")
    args = parser.parse_args()

    if args.demo or len(vars(args)) == 0:
        run_demo()
        return

    if args.ip:
        cidr = args.ip
        if "/" not in cidr and args.mask:
            prefix = mask_to_cidr(args.mask)
            cidr = f"{cidr}/{prefix}"
        elif "/" not in cidr:
            cidr = f"{cidr}/24"
        data = analyze_network(cidr)
        print_analysis(data)

    if args.split and args.subnets:
        subnets = split_network(args.split, args.subnets)
        print_subnets(subnets, args.split)

    if args.check:
        ip, net = args.check
        result = check_ip_in_range(ip, net)
        icon = "✅" if result else "❌"
        print(f"\n  {icon} {ip} is {'in' if result else 'NOT in'} {net}\n")

    if args.convert_mask:
        print(f"\n  {args.convert_mask} → /{mask_to_cidr(args.convert_mask)}\n")

    if args.convert_cidr:
        print(f"\n  /{args.convert_cidr} → {cidr_to_mask(args.convert_cidr)}\n")


if __name__ == "__main__":
    main()
