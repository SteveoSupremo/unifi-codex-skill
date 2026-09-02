from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from unifi_common import Finding
from .exposure import assess_port_forwards, exposure_findings
from .firewall import firewall_analysis
from .models import PortForwardAssessment
from .posture import ids_ips_posture, upnp_posture, vpn_posture

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
    normalized_firewall_policies: list[dict[str, Any]] = field(default_factory=list)
    segmentation: list[dict[str, Any]] = field(default_factory=list)
    firewall_policy_findings: list[Finding] = field(default_factory=list)
    vpn_posture: dict[str, Any] = field(default_factory=dict)
    ids_ips_posture: dict[str, Any] = field(default_factory=dict)
    upnp_posture: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"schema_version": 2, "scope": self.scope,
            "findings": [f.as_dict() for f in self.findings],
            "port_forward_assessments": [a.as_dict() for a in self.port_forwards],
            "normalized_firewall_policies": self.normalized_firewall_policies,
            "effective_segmentation": self.segmentation,
            "firewall_policy_findings": [f.as_dict() for f in self.firewall_policy_findings],
            "vpn_management_access": self.vpn_posture,
            "ids_ips_posture": self.ids_ips_posture,
            "upnp_dynamic_exposure": self.upnp_posture,
            "coverage": self.coverage, "important_unknowns": self.unknowns,
            "live_mutation": False}


def coverage(data: dict[str, Any]) -> dict[str, str]:
    result = {}
    statuses = data.get("collection_status") or {}
    for label, key in DATASETS.items():
        if key == "vpn" and isinstance(data.get("vpn"), dict):
            vpn_states = [statuses.get("vpn_servers", {}).get("status"), statuses.get("vpn_site_to_site", {}).get("status")]
            if all(state == "unavailable" for state in vpn_states):
                result[label] = "unsupported/unavailable"
            elif any(state == "partial" for state in vpn_states):
                result[label] = "collected, partially analyzed"
            else:
                result[label] = "collected and analyzed"
        elif statuses.get(key, {}).get("status") == "unavailable" or key not in data or data.get(key) is None:
            result[label] = "unsupported/unavailable" if statuses.get(key) else "unavailable"
        elif statuses.get(key, {}).get("status") == "partial":
            result[label] = "collected, partially analyzed"
        elif isinstance(data[key], (list, dict)) and not data[key]:
            result[label] = "collected, empty"
        else:
            analyzed={"Networks","Devices","Port forwards","Firewall zones","Firewall policies","Clients","VPN","IDS/IPS","UPnP exposure"}
            result[label] = "collected and analyzed" if label in analyzed else "collected, partially analyzed"
    return result


def analyze_inventory(data: dict[str, Any], scope: str) -> AuditResult:
    assessments = assess_port_forwards(data) if scope in ("all", "exposure", "firewall") else []
    findings: list[Finding] = []
    if scope in ("all", "exposure"):
        findings.extend(exposure_findings(assessments))
    policies=[]; segmentation=[]; policy_findings=[]
    if scope in ("all", "firewall"):
        policies,segmentation,policy_findings=firewall_analysis(data); findings.extend(policy_findings)
    if scope in ("all", "network"):
        expected = {1:"192.168.1.0/24",2:"192.168.2.0/24",3:"192.168.3.0/24",4:"192.168.6.0/24",5:"192.168.7.0/24",99:"192.168.99.0/24"}
        seen = {int(n.get("vlan", n.get("vlan_id", 1))): n.get("ip_subnet", n.get("subnet")) for n in data.get("networks", []) if str(n.get("vlan", n.get("vlan_id", 1))).isdigit()}
        for vlan, subnet in expected.items():
            if vlan not in seen:
                findings.append(Finding("medium", "Desired-state drift", f"VLAN {vlan} not observed", f"Expected {subnet}", "Topology may differ or collection may be incomplete.", "medium", "VERIFY controller site and network inventory.", "reported", False, "REVIEW"))
    if scope in ("all", "performance", "wifi", "health") and not data.get("status"):
        findings.append(Finding("informational", "Telemetry", "Health telemetry unavailable", "No status data supplied.", "Performance cannot be assessed without evidence.", "high", "Collect read-only health/device statistics.", "not_available", False, "UNKNOWN — INVESTIGATE"))
    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    vpn=vpn_posture(data); ids=ids_ips_posture(data); upnp=upnp_posture(data)
    unknowns = list(UNKNOWNS)
    if vpn.get("status","").startswith("collected"):
        unknowns = [u for u in unknowns if not u.startswith("VPN posture")]
    if upnp.get("status","").startswith("collected"):
        unknowns = [u for u in unknowns if not u.startswith("UPnP mappings")]
    return AuditResult(scope, findings, assessments, coverage(data), unknowns,
        [p.as_dict() for p in policies],segmentation,policy_findings,vpn,ids,upnp)
