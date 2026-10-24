#!/usr/bin/env python3
"""Read-only service and client-resolver verification; no controller mutation."""
import argparse
import ipaddress
import json
import socket


def tcp(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout):
            return True
    except OSError:
        return False


def verify(host, dns_name, timeout=3, expected_ip=None):
    checks = {"controller_tcp_443": tcp(host, 443, timeout)}
    addresses = []
    try:
        family = socket.AF_INET if expected_ip is not None else socket.AF_UNSPEC
        rows = socket.getaddrinfo(dns_name, 443, family=family, type=socket.SOCK_STREAM)
        addresses = sorted({row[4][0] for row in rows if row[0] == socket.AF_INET})
        checks["dns_resolution"] = bool(rows)
    except OSError:
        checks["dns_resolution"] = False
    if expected_ip is not None:
        expected_ip = str(ipaddress.IPv4Address(expected_ip))
        checks["dns_expected_ipv4_only"] = addresses == [expected_ip]
    return {**checks, "dns_ipv4_addresses": addresses, "expected_ipv4": expected_ip,
            "verified": all(checks.values()),
            "note": "Uses this client's configured resolver and cache; does not test every VLAN, proxy backend, or certificate."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="controller host for TCP 443 check")
    parser.add_argument("--dns-name", default="example.com")
    parser.add_argument("--timeout", type=float, default=3)
    parser.add_argument("--expected-ip", help="require exactly this IPv4 A answer from this client's resolver")
    args = parser.parse_args()
    if args.expected_ip:
        try:
            ipaddress.IPv4Address(args.expected_ip)
        except ipaddress.AddressValueError:
            parser.error("--expected-ip must be an IPv4 address")
    results = verify(args.host, args.dns_name, args.timeout, args.expected_ip)
    print(json.dumps(results, indent=2))
    raise SystemExit(0 if results["verified"] else 2)


if __name__ == "__main__":
    main()
