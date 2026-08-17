from __future__ import annotations

from typing import Any

from unifi_common import Finding


def _first(rule: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in rule and rule[key] not in (None, ""):
            return rule[key]
    return None


def _normalized(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(map(str, value)).lower()
    return str(value or "unknown").lower()


def firewall_findings(data: dict[str, Any]) -> list[Finding]:
    legacy_present = "firewall_rules" in data
    traffic_present = "traffic_rules" in data
    rules = list(data.get("firewall_rules") or []) + list(data.get("traffic_rules") or [])
    findings: list[Finding] = []
    if not legacy_present and not traffic_present:
        return [Finding("informational", "Firewall coverage", "Firewall policy dataset unavailable",
            "Neither legacy firewall rules nor traffic rules were collected.",
            "Effective segmentation cannot be determined without policy objects.", "high",
            "Collect applicable read-only firewall policy families.", "not_available", False,
            "UNKNOWN — INVESTIGATE")]

    network_by_id = {str(n.get("_id")): str(n.get("name")) for n in data.get("networks") or [] if n.get("_id")}
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        action = _normalized(_first(rule, "action", "rule_action"))
        if action not in {"accept", "allow"}:
            continue
        src_raw = _first(rule, "src_networkconf_id", "source_network_id", "source", "src", "src_address", "matching_target")
        dst_raw = _first(rule, "dst_networkconf_id", "destination_network_id", "destination", "dst", "dst_address")
        src = network_by_id.get(str(src_raw), _normalized(src_raw))
        dst = network_by_id.get(str(dst_raw), _normalized(dst_raw))
        protocol = _normalized(_first(rule, "protocol", "proto"))
        ports = _normalized(_first(rule, "dst_port", "destination_port", "port"))
        direction = _normalized(_first(rule, "ruleset", "direction", "zone"))
        name = str(rule.get("name") or rule.get("description") or "unnamed")
        text = f"{name} {src}".lower()
        dst_text = str(dst).lower()
        src_any = src in ("unknown", "any", "all", "0.0.0.0/0", "::/0")
        dst_any = dst in ("unknown", "any", "all", "0.0.0.0/0", "::/0")
        title = severity = why = None
        category = "Firewall rule quality"
        if src_any and dst_any:
            title, severity, why = f"Any → Any allow candidate: {name}", "high", "An unrestricted allow can undermine segmentation."
        elif "guest" in text and (dst_any or any(x in dst_text for x in ("private", "rfc1918", "default", "family", "server", "iot"))):
            title, severity, why = f"Guest → private allow candidate: {name}", "high", "Guest access to private networks conflicts with the isolation policy unless narrowly required."
            category = "Segmentation"
        elif "iot" in text and (dst_any or any(x in dst_text for x in ("default", "family", "server", "management"))):
            title, severity, why = f"IoT → trusted network allow candidate: {name}", "high", "Broad IoT access to trusted or server networks should be limited to documented flows."
            category = "Segmentation"
        elif src_any or dst_any:
            title, severity, why = f"Broad allow candidate: {name}", "medium", "A broad source or destination may weaken intended segmentation."
        if title:
            evidence = f"action={action}; source={src}; destination={dst}; protocol={protocol}; ports={ports}; direction/zone={direction}."
            findings.append(Finding(severity, category, title, evidence, why, "medium",
                "REVIEW the complete rule semantics and ordering; this is a candidate for review, not a removal instruction.",
                "reported", False, "REVIEW", {"name":name,"action":action,"source":src,"destination":dst,"protocol":protocol,"ports":ports,"direction":direction}))
    if not rules:
        findings.append(Finding("informational", "Segmentation", "Unable to determine effective segmentation from collected rule families",
            "Collected legacy firewall and traffic-rule datasets are empty.",
            "Absence of collected rules does not prove traffic is allowed or blocked.", "high",
            "Collect official zone/policy objects or applicable rule families read-only.", "not_available", False,
            "UNKNOWN — INVESTIGATE"))
    return findings
