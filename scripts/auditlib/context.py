from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any


ROLE_PATTERNS = {
    "proxmox": ("Proxmox infrastructure", "Administrative Interface"),
    "homeassistant": ("Home Assistant", "Application Service"),
    "home assistant": ("Home Assistant", "Application Service"),
    "n8n": ("n8n automation", "Application Service"),
    "nginx": ("Nginx Proxy Manager", "Reverse Proxy / Public Web Entry"),
    "proxy": ("reverse proxy", "Reverse Proxy / Public Web Entry"),
    "udm": ("UDM management", "Administrative Interface"),
    "unifi": ("UniFi management", "Administrative Interface"),
    "adguard": ("DNS infrastructure", "Application Service"),
    "dns": ("DNS infrastructure", "Application Service"),
    "vpn": ("VPN listener", "VPN"),
}


def reference_roles(root: Path) -> list[str]:
    path = root / "references" / "protected-resources.yaml"
    if not path.exists():
        return []
    roles = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"\s*-\s+(.+?)\s*$", line)
        if match:
            roles.append(match.group(1))
    return roles


def match_role(*values: Any) -> tuple[str, str, bool]:
    text = " ".join(str(v or "") for v in values).lower()
    for needle, (role, exposure_class) in ROLE_PATTERNS.items():
        if needle in text:
            return role, exposure_class, role in {
                "Proxmox infrastructure", "Home Assistant", "Nginx Proxy Manager",
                "UDM management", "UniFi management", "DNS infrastructure",
            }
    return "unknown", "Unknown", False


def network_for_ip(ip: str, networks: list[dict[str, Any]]) -> tuple[str, int | None]:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown", None
    for network in networks:
        subnet = network.get("ip_subnet") or network.get("subnet")
        if not subnet:
            continue
        try:
            candidate = ipaddress.ip_network(str(subnet), strict=False)
        except ValueError:
            continue
        if address in candidate:
            vlan = network.get("vlan", network.get("vlan_id", 1))
            return str(network.get("name") or f"VLAN {vlan}"), int(vlan or 1)
    return "unknown", None


def device_for_ip(ip: str, devices: list[dict[str, Any]]) -> dict[str, Any] | None:
    for device in devices:
        candidates = {str(device.get(k)) for k in ("ip", "ipAddress", "lan_ip", "adopt_ip") if device.get(k)}
        if ip in candidates:
            return device
    return None
