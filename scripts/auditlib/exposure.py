from __future__ import annotations

from collections import defaultdict
from typing import Any

from unifi_common import Finding, ROOT
from .context import device_for_ip, match_role, network_for_ip, reference_roles
from .models import PortForwardAssessment


PORT_SERVICES = {
    "8006": ("possible Proxmox management", "Administrative Interface"),
    "8123": ("possible Home Assistant", "Application Service"),
    "5678": ("possible n8n", "Application Service"),
    "443": ("HTTPS", "Reverse Proxy / Public Web Entry"),
    "80": ("HTTP / ACME candidate", "Reverse Proxy / Public Web Entry"),
    "22": ("possible SSH", "Administrative Interface"),
    "3389": ("possible RDP", "Administrative Interface"),
    "5900": ("possible VNC", "Administrative Interface"),
}


def _source_scope(rule: dict[str, Any]) -> tuple[str, str]:
    if rule.get("src_limiting_enabled") is True:
        src = rule.get("src") or rule.get("source") or rule.get("source_ip")
        return (f"restricted ({src})" if src and str(src).lower() != "any" else "restricted", "reported")
    if rule.get("src_limiting_enabled") is False:
        return "Any / unrestricted", "reported"
    if "src" in rule and str(rule.get("src")).lower() == "any":
        return "Any / unrestricted", "reported"
    return "unknown from collected evidence", "not_available"


def _severity(a: PortForwardAssessment) -> tuple[str, str]:
    unrestricted = a.source_restriction == "Any / unrestricted"
    if a.exposure_class == "Administrative Interface":
        return ("high", "HARDEN") if unrestricted else ("medium", "KEEP / VERIFY")
    if a.exposure_class in ("Application Service", "Reverse Proxy / Public Web Entry"):
        return ("medium", "REVIEW") if unrestricted or a.source_restriction.startswith("unknown") else ("low", "KEEP / VERIFY")
    if a.exposure_class == "VPN":
        return ("medium", "VERIFY") if unrestricted else ("low", "KEEP / VERIFY")
    return ("high", "UNKNOWN — INVESTIGATE") if a.protected_resource else ("medium", "UNKNOWN — INVESTIGATE")


def assess_port_forwards(data: dict[str, Any]) -> list[PortForwardAssessment]:
    networks = data.get("networks") or []
    devices = data.get("clients") or []
    devices = list(devices) + list(data.get("devices") or [])
    protected_roles = reference_roles(ROOT)
    policy_count = len(data.get("firewall_rules") or []) + len(data.get("traffic_rules") or [])
    assessments: list[PortForwardAssessment] = []
    for rule in data.get("port_forwards") or []:
        if not rule.get("enabled", True):
            continue
        ip = str(rule.get("fwd") or rule.get("forward_ip") or "unknown")
        port = str(rule.get("fwd_port") or rule.get("dst_port") or "unknown")
        wan_port = str(rule.get("dst_port") or rule.get("src_port") or "unknown")
        device = device_for_ip(ip, devices)
        device_name = "unknown"
        if device:
            device_name = str(device.get("name") or device.get("hostname") or device.get("mac") or "unknown")
        role, role_class, protected = match_role(rule.get("name"), device_name)
        role_text = f"{role} {rule.get('name','')} {device_name}".lower()
        if any(item.lower() in role_text or role.lower() in item.lower() for item in protected_roles if role != "unknown"):
            protected = True
        service, port_class = PORT_SERVICES.get(port, ("unknown", "Unknown"))
        exposure_class = role_class if role_class != "Unknown" else port_class
        network, vlan = network_for_ip(ip, networks)
        protected = protected or vlan in {1, 4}
        source, source_evidence = _source_scope(rule)
        evidence = [f"UniFi reports enabled {rule.get('proto','unknown')} WAN {wan_port} to {ip}:{port}."]
        if device:
            evidence.append(f"Destination correlates with UniFi device {device_name}.")
        if network != "unknown":
            evidence.append(f"Destination IP correlates with network {network}.")
        if role != "unknown":
            evidence.append(f"Rule/device naming is consistent with {role}.")
        if service != "unknown":
            evidence.append(f"Port {port} is {service}; port number alone is not proof.")
        evidence.append(f"Source restriction is {source} ({source_evidence}).")
        confidence = "high" if device and role != "unknown" else "medium" if role != "unknown" or service != "unknown" else "low"
        a = PortForwardAssessment(
            name=str(rule.get("name") or "unnamed"), protocol=str(rule.get("proto") or "unknown"),
            wan_port=wan_port, internal_ip=ip, internal_port=port,
            destination_name=device_name, destination_role=role, network=network,
            source_restriction=source, likely_service=service, exposure_class=exposure_class,
            evidence=evidence, confidence=confidence, protected_resource=protected,
            firewall_correlation=(
                "No explicit NAT-to-policy relationship was proven from collected firewall/traffic-rule objects."
                if policy_count else
                "Collected firewall and traffic-rule datasets are empty; port-forward-generated or zone policy handling is unknown."
            ),
        )
        a.evidence.append(a.firewall_correlation)
        a.severity, a.action_class = _severity(a)
        assessments.append(a)

    by_host: dict[str, list[PortForwardAssessment]] = defaultdict(list)
    for a in assessments:
        by_host[a.internal_ip].append(a)
    for host_assessments in by_host.values():
        ports = {a.internal_port for a in host_assessments}
        if {"80", "443"}.issubset(ports):
            for a in host_assessments:
                if a.internal_port in {"80", "443"}:
                    a.exposure_class = "Reverse Proxy / Public Web Entry"
                    a.destination_role = "likely public web gateway"
                    a.likely_service = "likely reverse proxy / HTTPS + ACME pattern"
                    a.evidence.append("TCP 80 and 443 terminate at the same host; the port 80/443 pair is consistent with a reverse proxy or HTTPS + ACME gateway.")
                    a.confidence = "high" if "encrypt" in " ".join(x.name.lower() for x in host_assessments) else "medium"
                    a.protected_resource = True
                    a.severity, a.action_class = _severity(a)
    return assessments


def exposure_findings(assessments: list[PortForwardAssessment]) -> list[Finding]:
    findings = []
    proxy_hosts = {a.internal_ip for a in assessments if a.exposure_class == "Reverse Proxy / Public Web Entry"}
    for a in assessments:
        bypass = bool(proxy_hosts and a.internal_ip not in proxy_hosts and a.exposure_class in {"Administrative Interface", "Application Service"})
        if bypass:
            a.evidence.append("This direct WAN path terminates on a different host than the apparent 80/443 web gateway; complete DNS/proxy architecture was not inspected.")
        why = {
            "Administrative Interface": "Direct management-plane exposure can provide privileged infrastructure access.",
            "Application Service": "A direct application path requires authentication, patching, and access-control review.",
            "Reverse Proxy / Public Web Entry": "A public web gateway may be intentional, but the inventory does not prove TLS, authentication, patching, or downstream protections.",
            "VPN": "A VPN listener can be an intentional administrative entry point but still requires configuration review.",
            "Unknown": "Unknown WAN exposure cannot be risk-ranked precisely without identifying the service and controls.",
        }[a.exposure_class]
        recommendation = {
            "HARDEN": "HARDEN / candidate for removal from direct WAN exposure. Prefer authenticated VPN or another strongly controlled management path.",
            "REVIEW": "REVIEW the documented purpose, authentication, TLS/proxy path, patching, and whether direct exposure is required.",
            "KEEP / VERIFY": "KEEP / VERIFY the intended source restriction and service protections.",
            "UNKNOWN — INVESTIGATE": "UNKNOWN — INVESTIGATE the owning service and access controls; do not remove from passive evidence alone.",
        }.get(a.action_class, "VERIFY the intended listener and protections.")
        findings.append(Finding(
            a.severity, "WAN exposure", f"{a.exposure_class}: {a.name}", " ".join(a.evidence), why,
            a.confidence, recommendation, "correlated" if len(a.evidence) > 2 else "reported", False,
            a.action_class, a.as_dict(),
        ))
    return findings
