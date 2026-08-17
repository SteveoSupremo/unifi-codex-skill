from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from unifi_common import Finding
from .exposure import assess_port_forwards, exposure_findings
from .firewall import firewall_findings
from .models import PortForwardAssessment

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

DATASETS = {
    "Sites": "site", "Networks": "networks", "Devices": "devices",
    "Legacy firewall": "firewall_rules", "Traffic rules": "traffic_rules",
    "Port forwards": "port_forwards", "Firewall zones": "firewall_zones",
    "Firewall policies": "firewall_policies", "UPnP exposure": "upnp_exposure",
    "Clients": "clients", "Wi-Fi": "wlans", "WAN interfaces": "wan_interfaces",
    "VPN": "vpn", "IDS/IPS": "ids_ips",
}

UNKNOWNS = [
    "Public reachability was not externally tested; a configured forward does not prove Internet reachability.",
    "Application authentication was not tested.",
    "TLS configuration was not inspected.",
    "Reverse-proxy downstream mappings were not inspected.",
    "Effective stateful firewall behavior may not be fully represented by collected rule objects.",
    "UPnP mappings were not collected.",
    "VPN posture is unavailable unless a VPN dataset was collected.",
]


@dataclass
class AuditResult:
    scope: str
    findings: list[Finding]
    port_forwards: list[PortForwardAssessment]
    coverage: dict[str, str]
    unknowns: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {"schema_version": 2, "scope": self.scope,
            "findings": [f.as_dict() for f in self.findings],
            "port_forward_assessments": [a.as_dict() for a in self.port_forwards],
            "coverage": self.coverage, "important_unknowns": self.unknowns,
            "live_mutation": False}


def coverage(data: dict[str, Any]) -> dict[str, str]:
    result = {}
    statuses = data.get("collection_status") or {}
    for label, key in DATASETS.items():
        if key == "vpn" and isinstance(data.get("vpn"), dict):
            vpn_states = [statuses.get("vpn_servers", {}).get("status"), statuses.get("vpn_site_to_site", {}).get("status")]
            if all(state == "unavailable" for state in vpn_states):
                result[label] = "unavailable/not collected"
            elif any(state == "partial" for state in vpn_states):
                result[label] = "partially available"
            else:
                result[label] = "available"
        elif statuses.get(key, {}).get("status") == "unavailable" or key not in data or data.get(key) is None:
            result[label] = "unavailable/not collected"
        elif statuses.get(key, {}).get("status") == "partial":
            result[label] = "partially available"
        elif isinstance(data[key], (list, dict)) and not data[key]:
            result[label] = "available (empty)"
        else:
            result[label] = "available"
    return result


def analyze_inventory(data: dict[str, Any], scope: str) -> AuditResult:
    assessments = assess_port_forwards(data) if scope in ("all", "exposure", "firewall") else []
    findings: list[Finding] = []
    if scope in ("all", "exposure"):
        findings.extend(exposure_findings(assessments))
    if scope in ("all", "firewall"):
        findings.extend(firewall_findings(data))
    if scope in ("all", "network"):
        expected = {1:"192.168.1.0/24",2:"192.168.2.0/24",3:"192.168.3.0/24",4:"192.168.6.0/24",5:"192.168.7.0/24",99:"192.168.99.0/24"}
        seen = {int(n.get("vlan", n.get("vlan_id", 1))): n.get("ip_subnet", n.get("subnet")) for n in data.get("networks", []) if str(n.get("vlan", n.get("vlan_id", 1))).isdigit()}
        for vlan, subnet in expected.items():
            if vlan not in seen:
                findings.append(Finding("medium", "Desired-state drift", f"VLAN {vlan} not observed", f"Expected {subnet}", "Topology may differ or collection may be incomplete.", "medium", "VERIFY controller site and network inventory.", "reported", False, "REVIEW"))
    if scope in ("all", "performance", "wifi", "health") and not data.get("status"):
        findings.append(Finding("informational", "Telemetry", "Health telemetry unavailable", "No status data supplied.", "Performance cannot be assessed without evidence.", "high", "Collect read-only health/device statistics.", "not_available", False, "UNKNOWN — INVESTIGATE"))
    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    unknowns = list(UNKNOWNS)
    if "vpn" in data:
        unknowns = [u for u in unknowns if not u.startswith("VPN posture")]
    return AuditResult(scope, findings, assessments, coverage(data), unknowns)
