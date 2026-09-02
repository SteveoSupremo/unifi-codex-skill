#!/usr/bin/env python3
"""Read-only, context-aware UniFi audit CLI."""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any

from auditlib import AuditResult, analyze_inventory
from unifi_common import ROOT, redact


def analyze(data: dict[str, Any], scope: str):
    """Backward-compatible finding API used by older callers."""
    return analyze_inventory(data, scope).findings


def _executive_summary(result: AuditResult) -> str:
    if not result.port_forwards:
        return f"{len(result.findings)} finding(s). No changes were made."
    counts: dict[str, int] = {}
    for item in result.port_forwards:
        counts[item.exposure_class] = counts.get(item.exposure_class, 0) + 1
    parts = [f"{len(result.port_forwards)} enabled WAN forward(s) observed"]
    labels = {
        "Administrative Interface": "infrastructure-management service(s)",
        "Application Service": "application service(s) directly",
        "Reverse Proxy / Public Web Entry": "likely public web/reverse-proxy entry point(s)",
        "VPN": "VPN listener(s)", "Unknown": "unknown service(s)",
    }
    parts.extend(f"{count} {labels[k]}" for k, count in counts.items())
    if result.normalized_firewall_policies:
        parts.append(f"{len(result.normalized_firewall_policies)} official firewall policies analyzed")
    known=sum(1 for row in result.segmentation if row.get("state")!="UNKNOWN")
    if result.segmentation: parts.append(f"{known}/{len(result.segmentation)} requested segmentation relationships classified from explicit ordered policy evidence")
    return ". ".join(parts) + ". A configured forward does not prove external reachability. No changes were made."


def markdown(result_or_scope, findings=None) -> str:
    """Render Version 2 results; accept the Version 1 signature for compatibility."""
    if isinstance(result_or_scope, AuditResult):
        result = result_or_scope
    else:
        result = AuditResult(str(result_or_scope), findings or [], [], {}, [])
    lines = [f"# UniFi {result.scope.title()} Audit", "",
        f"Generated: {dt.datetime.now(dt.timezone.utc).isoformat()}", "",
        "## Executive Summary", "", _executive_summary(result), ""]
    lines += ["## Effective Segmentation Summary", ""]
    if result.segmentation:
        lines += ["| Relationship | Zones | State | Evidence |","| --- | --- | --- | --- |"]
        for row in result.segmentation:
            lines.append(f"| {row['relationship']} | {row['source_zone']} → {row['destination_zone']} | {row['state']} | {row['evidence']} |")
    else: lines.append("Unable to determine effective segmentation from collected official policies.")
    lines += ["", "## Firewall Policy Findings", ""]
    if result.firewall_policy_findings:
        for finding in result.firewall_policy_findings:
            lines += [f"### {finding.title}","",f"- Severity: {finding.severity.title()}",f"- Evidence ({finding.evidence_type}): {finding.evidence}",f"- Why it matters: {finding.why}",f"- Recommendation: {finding.recommendation}",f"- Safe to automate: {'yes' if finding.safe_to_automate else 'no'}",""]
    else: lines += ["No security-relevant official policy candidates were identified from normalized fields.",""]
    lines += ["## VPN / Management Access","",result.vpn_posture.get("summary","VPN posture unavailable."),""]
    for server in result.vpn_posture.get("servers",[]): lines.append(f"- {server['name']}: type={server['type']}, enabled={server['enabled']}")
    if result.vpn_posture.get("caution"): lines += ["",result.vpn_posture["caution"],""]
    lines += ["## IDS/IPS Posture","",result.ids_ips_posture.get("summary","IDS/IPS posture unavailable."),""]
    if result.ids_ips_posture.get("material_settings"): lines.append("- Material settings: "+", ".join(f"{k}={v}" for k,v in result.ids_ips_posture["material_settings"].items()))
    if result.ids_ips_posture.get("caution"): lines += ["",result.ids_ips_posture["caution"],""]
    lines += ["## UPnP / Dynamic Exposure","",result.upnp_posture.get("summary","UPnP evidence unavailable."),""]
    if result.upnp_posture.get("caution"): lines += [result.upnp_posture["caution"],""]
    if result.port_forwards:
        lines += ["## WAN Exposure Detail", "",
            "| Name | WAN | Proto | Destination | Role | Source Scope | Classification | Severity |",
            "| --- | ---: | --- | --- | --- | --- | --- | --- |"]
        for a in result.port_forwards:
            destination = f"{a.internal_ip}:{a.internal_port} ({a.network})"
            lines.append(f"| {a.name} | {a.wan_port} | {a.protocol} | {destination} | {a.destination_role} | {a.source_restriction} | {a.exposure_class} | {a.severity.title()} |")
        lines.append("")
        lines.append("Policy correlation:")
        lines.append("")
        for a in result.port_forwards: lines.append(f"- {a.name}: {a.firewall_correlation}")
        lines.append("")
    for severity in ("critical", "high", "medium", "low", "informational"):
        group = [finding for finding in result.findings if finding.severity == severity and finding not in result.firewall_policy_findings]
        if group:
            lines += [f"## {severity.title()}", ""]
            for finding in group:
                lines += [f"### {finding.title}", "", f"- Category: {finding.category}",
                    f"- Evidence ({finding.evidence_type}): {finding.evidence}",
                    f"- Why it matters: {finding.why}", f"- Confidence: {finding.confidence}",
                    f"- Recommended action: {finding.action_class}", f"- Recommendation: {finding.recommendation}",
                    f"- Safe to automate: {'yes' if finding.safe_to_automate else 'no'}", ""]
    lines += ["## Audit Coverage", ""]
    for name, state in result.coverage.items():
        lines.append(f"- {name}: {state}")
    lines += ["", "## Important Unknowns", ""]
    lines.extend(f"- {unknown}" for unknown in result.unknowns)
    lines += ["", "## Items Requiring Human Decision", "",
        "All configuration recommendations require human review and separate authorization. Passive evidence never authorizes removal or mutation.", "",
        "`live_mutation = false`", ""]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("scope", choices=["network", "firewall", "exposure", "performance", "wifi", "health", "all"])
    parser.add_argument("--input", required=True, type=Path, help="sanitized inventory JSON")
    parser.add_argument("--report", action="store_true", help="write an ignored Markdown report")
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="print machine-readable JSON")
    output.add_argument("--json-output", type=Path, help="write machine-readable JSON")
    args = parser.parse_args()
    data = redact(json.loads(args.input.read_text(encoding="utf-8")))
    result = analyze_inventory(data, args.scope)
    if args.json or args.json_output:
        text = json.dumps(redact(result.as_dict()), indent=2, sort_keys=True) + "\n"
        if args.json_output:
            args.json_output.write_text(text, encoding="utf-8")
            print(args.json_output)
        else:
            print(text, end="")
        return
    text = markdown(result)
    if args.report:
        (ROOT / "reports").mkdir(exist_ok=True)
        path = ROOT / "reports" / f"{dt.date.today().isoformat()}-{args.scope}-audit.md"
        path.write_text(text, encoding="utf-8")
        print(path)
    else:
        print(text)


if __name__ == "__main__":
    main()
